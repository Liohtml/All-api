//! Learning against the live site. One routine, run trigger -> match -> learn, serves three jobs:
//! add (create), recapture (heal), and the tier-3 read. Rescan is the browserless heal.
use crate::browser::{Intercept, Matcher, ProfileInUse, TriggerOptions, chrome_available, run_trigger};
use crate::classify::{Class, Observed, bot_wall, judge};
use crate::codec::{escape_template, fill_template, get_at, set_at, step_key, template_refs, walk};
use crate::extract::{cap_output, extract};
use crate::http::{HttpRequest, MAX_REDIRECTS, SendOptions, SharedFetcher, build_request, default_fetcher, is_redirect, own_match, send};
use crate::learn::{ASSET_EXT, Args, LearnInput, Learned, capture_pages, check_examples, hash_like, learn_operation, matches};
use crate::secrets::scan_secrets;
use crate::session::{
    Session, cookie_header_for, home, load_session, merge_capture, parse_cookie_header, prune_captures, read_json, safe_name, site_of,
    write_private,
};
use crate::spec::{Escape, Format, Match, Operation, ResponseSpec, Site, Slot, Volatile};
use crate::store::{Strategy, append_heal, clear_stale, load_site, remember_tier, update_site};
use crate::types::{CaptureResult, Exchange, StepAction, StoredCookie, TriggerStep};
use crate::util::{as_text, decode_loose, decode_uri_component, encode_uri_component, iso_now, json, json_unquote, now_ms, parse_url, re};
use anyhow::{Result, anyhow, bail};
use futures_util::future::BoxFuture;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

pub fn profile_dir() -> PathBuf {
    home().join("profile")
}

/// One transport try, judged. `ambiguous`: no response came back, so a write may have run.
#[derive(Clone, Debug, Default)]
pub struct Attempt {
    pub tier: u8,
    pub class: Class,
    pub reason: String,
    pub status: Option<u16>,
    pub data: Option<Value>,
    pub ambiguous: bool,
    /// the args may be the problem (data missing, or a bare 403); see Classified.missing
    pub missing: bool,
    /// the first answer was a redirect, so the server took the request (a write ran)
    pub redirected: bool,
    /// a specific `next` for the agent (a local problem, not the site's)
    pub hint: Option<String>,
    /// what the caller should know whatever the outcome (a repeat of the write was stopped)
    pub note: Option<String>,
}

impl Attempt {
    pub fn new(tier: u8, class: Class, reason: &str) -> Attempt {
        Attempt { tier, class, reason: reason.to_string(), ..Default::default() }
    }
}

pub const PROFILE_HINT: &str = "another api-anything process (an MCP server?) holds the browser profile; it lets go after a few seconds idle: wait, or stop it, then retry once";

/// Fill `{param}` in a trigger. URL parts are percent-encoded; step values are typed as given.
pub fn fill_trigger(t: &crate::spec::Trigger, args: &Args) -> crate::spec::Trigger {
    let enc: Args = args.iter().map(|(k, v)| (k.clone(), Value::String(encode_uri_component(&as_text(v))))).collect();
    let step = |s: &TriggerStep| TriggerStep {
        action: s.action,
        selector: s.selector.as_ref().map(|x| fill_template(x, args)),
        value: s.value.as_ref().map(|x| fill_template(x, if s.action == StepAction::Goto { &enc } else { args })),
        ms: s.ms,
    };
    crate::spec::Trigger {
        url: fill_template(&t.url, &enc),
        soft_from: t.soft_from.as_ref().map(|x| fill_template(x, &enc)),
        steps: t.steps.as_ref().map(|ss| ss.iter().map(step).collect()),
    }
}

const SAFE_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];
fn safe(method: &str) -> bool {
    SAFE_METHODS.contains(&method.to_uppercase().as_str())
}
// Once the steps run, only these may still load: they can't carry a write the way an image ping,
// a link, a GET form, a JSONP script or an iframe can...
const INERT: [&str; 3] = ["stylesheet", "font", "media"];

/// ...unless it is the site's own endpoint in disguise (`<link rel=stylesheet href=/api/vote?id=..>`):
/// same-site, and not a static asset path (no asset extension, or a query carrying an example value).
fn inert_load(e: &Exchange, site: Option<&str>, values: &[String]) -> bool {
    let Some(u) = parse_url(&e.request.url) else { return true };
    let Some(site) = site else { return true };
    if site_of(u.host_str().unwrap_or("")) != site {
        return true;
    }
    let query = decode_loose(&crate::util::search_of(&u), true).to_lowercase();
    ASSET_EXT.is_match(u.path()) && !values.iter().any(|v| v.len() >= 3 && query.contains(&v.to_lowercase()))
}

/// While learning a write: abort every unsafe request, and once the UI steps run, every request
/// but stylesheets, fonts and media that are really assets. A known write's own match is aborted
/// whatever its method. WebSocket messages the page sends are dropped by the browser layer.
pub fn write_guard(m: Option<Match>, url: Option<&str>, args: Option<&Args>) -> Intercept {
    let site = url.and_then(parse_url).map(|u| site_of(u.host_str().unwrap_or("")));
    let values: Vec<String> = args.map(|a| a.values().map(as_text).collect()).unwrap_or_default();
    let m = m.filter(|m| !m.is_empty());
    Arc::new(move |e: &Exchange, acting: bool, _via: Option<&Exchange>| {
        !safe(&e.request.method)
            || (acting && !(INERT.contains(&e.resource_type.as_str()) && inert_load(e, site.as_deref(), &values)))
            || m.as_ref().map(|m| matches(m, &e.request)).unwrap_or(false)
    })
}

/// A read's trigger must not write either: once the steps run, unsafe requests other than the op's
/// own are aborted. Every hop of a chain that started with the op's own unsafe request is the op's own too.
fn read_guard(m: Match) -> Intercept {
    let own = move |e: &Exchange, m: &Match| !safe(&e.request.method) && !m.is_empty() && matches(m, &e.request);
    Arc::new(move |e: &Exchange, acting: bool, via: Option<&Exchange>| {
        acting && e.resource_type != "websocket" && !safe(&e.request.method) && !own(e, &m) && !via.map(|v| own(v, &m)).unwrap_or(false)
    })
}

#[derive(Default, Clone, Copy, Debug)]
pub struct Stopped {
    pub repeats: u32,
    pub resends: u32,
}

/// A write's tier-3 run is the page sending it for real, so its own request may leave once: every
/// further request matching the op is aborted, and so is the server's redirect of the one that left
/// when it would send the write on.
fn send_once(m: Match) -> (Intercept, Arc<Mutex<(bool, Stopped)>>) {
    let state = Arc::new(Mutex::new((false, Stopped::default())));
    let s2 = state.clone();
    let guard: Intercept = Arc::new(move |e: &Exchange, _acting: bool, via: Option<&Exchange>| {
        if e.resource_type == "websocket" || m.is_empty() {
            return false;
        }
        let own = matches(&m, &e.request);
        let mut st = s2.lock().unwrap();
        if let Some(v) = via {
            if matches(&m, &v.request) {
                if !own && safe(&e.request.method) {
                    return false;
                }
                st.1.resends += 1;
                return true;
            }
        }
        if !own {
            return false;
        }
        if st.0 {
            st.1.repeats += 1;
        }
        let repeat = st.0;
        st.0 = true;
        repeat
    });
    (guard, state)
}

/// Values of the op's session: refs as the browser just sent them.
fn session_values_of(op: &Operation, e: &Exchange) -> IndexMap<String, String> {
    let mut out = IndexMap::new();
    for s in &op.slots {
        let mut refs: Vec<String> = Vec::new();
        if let Some(r) = &s.reference {
            refs.push(r.clone());
        }
        if let Some(t) = &s.template {
            for r in template_refs(t) {
                if !refs.contains(&r) {
                    refs.push(r);
                }
            }
        }
        let refs: Vec<String> = refs.into_iter().filter(|r| r.starts_with("session:")).collect();
        if refs.is_empty() {
            continue;
        }
        let Ok(Some(v)) = get_at(&e.request, &s.at) else { continue };
        for r in refs {
            let part = match (&v, &s.template) {
                (Value::String(leaf), Some(t)) => ref_part(t, &r, leaf, s.escape),
                (Value::String(leaf), None) => Some(leaf.clone()),
                _ => None,
            };
            if let Some(p) = part.filter(|p| !p.is_empty()) {
                out.insert(r[8..].to_string(), p);
            }
        }
    }
    out
}

/// The text a templated ref holds inside a leaf: the template's other holes match anything.
fn ref_part(template: &str, reference: &str, leaf: &str, escape: Option<Escape>) -> Option<String> {
    let mut re_src = String::from("^");
    for part in crate::codec::template_parts(template) {
        match part {
            crate::codec::TemplatePart::Brace(b) => re_src.push_str(&regex::escape(&b)),
            crate::codec::TemplatePart::Hole(h) if h == reference => re_src.push_str("(.*?)"),
            crate::codec::TemplatePart::Hole(_) => re_src.push_str(".*?"),
            crate::codec::TemplatePart::Text(t) => re_src.push_str(&regex::escape(&t)),
        }
    }
    re_src.push('$');
    let r = re(&format!("(?s){re_src}"));
    let m = r.captures(leaf)?;
    let found = m.get(1)?.as_str().to_string();
    Some(match escape {
        Some(Escape::Url) => decode_uri_component(&found).unwrap_or(found),
        Some(Escape::Json) => json_unquote(&found).unwrap_or(found),
        None => found,
    })
}

#[derive(Debug)]
pub struct TriggerRun {
    pub capture: CaptureResult,
    /// the request matching op.match that answers this run (see pick_hit)
    pub matched: Option<Exchange>,
    /// the trigger landed on a sign-in page instead of the content
    pub login_wall: Option<String>,
    /// a write's own request was sent again by the page this many times, and stopped each time
    pub repeats: u32,
    /// a write's own request was answered with a redirect that would have sent it again, and was stopped
    pub resends: u32,
}

fn carries_args(op: &Operation, e: &Exchange, args: &Args) -> bool {
    let host = parse_url(&e.request.url).map(|u| u.host_str().unwrap_or("").to_string()).unwrap_or_default();
    let cookies: Vec<StoredCookie> = parse_cookie_header(e.request.headers.get("cookie").map(|s| s.as_str()).unwrap_or(""))
        .into_iter()
        .map(|(n, v)| StoredCookie::new(&n, &v, &host))
        .collect();
    let Ok(expected) = build_request(op, args, &Session::with(cookies, session_values_of(op, e))) else { return false };
    static NOT_EVIDENCE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^header:(referer|origin|cookie)$"));
    op.params.iter().all(|p| {
        if args.get(&p.name).is_none() && p.default.is_none() {
            return !p.required;
        }
        let slots: Vec<&Slot> = op
            .slots
            .iter()
            .filter(|s| {
                (s.param.as_deref() == Some(p.name.as_str())
                    || s.template.as_ref().map(|t| t.contains(&format!("{{{}}}", p.name))).unwrap_or(false))
                    && !NOT_EVIDENCE.is_match(&s.at[0])
            })
            .collect();
        !slots.is_empty()
            && slots.iter().all(|s| match (get_at(&e.request, &s.at), get_at(&expected, &s.at)) {
                (Ok(Some(a)), Ok(Some(b))) => as_text(&a) == as_text(&b),
                (Ok(None), Ok(None)) => true,
                _ => false,
            })
    })
}

/// The matching exchange that is this run's answer: one carrying the run's args and judged ok, the latest on a tie.
fn pick_hit(op: &Operation, hits: &[Exchange], args: &Args) -> Option<Exchange> {
    let answered: Vec<&Exchange> = hits.iter().filter(|e| (e.response.is_some() || e.aborted) && carries_args(op, e, args)).collect();
    let score = |e: &Exchange| if e.aborted || judge_exchange(op, e).map(|a| a.class == Class::Ok).unwrap_or(false) { 1 } else { 0 };
    let mut best: Option<&Exchange> = None;
    for e in answered {
        if best.map(|b| score(e) >= score(b)).unwrap_or(true) {
            best = Some(e);
        }
    }
    best.cloned()
}

/// The final page of a run, when it is a sign-in page the trigger was redirected to.
pub fn login_wall(capture: &CaptureResult, trigger_url: &str) -> Option<String> {
    let f = parse_url(&capture.final_url)?;
    let t = parse_url(trigger_url)?;
    if f.path() == t.path() {
        return None;
    }
    let doc =
        capture.exchanges.iter().rfind(|e| e.resource_type == "document" && e.response.as_ref().map(|r| r.body.is_some()).unwrap_or(false));
    static PASSWORD: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"(?i)type=["']?password"#));
    static LOGIN: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)(log|sign)[-_]?in|/accounts/login|/i/flow/login"));
    let password = doc.map(|d| PASSWORD.is_match(d.body())).unwrap_or(false);
    if password || LOGIN.is_match(f.path()) { Some(f.path().to_string()) } else { None }
}

/// Run an op's trigger with args in the shared profile and refresh the session from it.
pub async fn run_op_trigger(site: &str, op: &Operation, args: &Args, intercept: bool) -> Result<TriggerRun> {
    let t = fill_trigger(&op.trigger, args);
    let m = op.matcher.clone();
    let is_hit: Matcher = {
        let m = m.clone();
        Arc::new(move |e: &Exchange| matches(&m, &e.request))
    };
    // A write's tier-3 run is the UI sending it for real, once; learning or healing one intercepts it.
    let once = if !intercept && !op.read_only { Some(send_once(m.clone())) } else { None };
    let guard: Intercept = match &once {
        Some((g, _)) => g.clone(),
        None => {
            if intercept {
                write_guard(Some(m.clone()), Some(&t.url), Some(args))
            } else {
                read_guard(m.clone())
            }
        }
    };
    let mut o = TriggerOptions::new(&t.url, &profile_dir());
    o.steps = t.steps.clone();
    o.soft_from = t.soft_from.clone();
    o.intercept = Some(guard);
    o.matcher = Some(is_hit.clone());
    let capture = run_trigger(o).await?;
    let hits: Vec<Exchange> = capture.exchanges.iter().filter(|e| is_hit(e)).cloned().collect();
    // a real write's answer is a request that left: a repeat that was stopped answers nothing
    let sent: Vec<Exchange> = if intercept || op.read_only { hits.clone() } else { hits.iter().filter(|e| !e.aborted).cloned().collect() };
    let matched = pick_hit(op, &sent, args);
    // Session values don't depend on the args: refresh them from the op's own request even when the
    // page asked for other args, whose answer is never returned.
    let source = matched.clone().or_else(|| hits.iter().find(|e| e.response.as_ref().map(|r| r.status < 400).unwrap_or(false)).cloned());
    let _ = merge_capture(site, &capture.cookies, &source.as_ref().map(|s| session_values_of(op, s)).unwrap_or_default(), now_ms());
    let wall = if matched.as_ref().map(|m| m.response.is_some()).unwrap_or(false) { None } else { login_wall(&capture, &t.url) };
    let stopped = once.as_ref().map(|(_, s)| s.lock().unwrap().1).unwrap_or_default();
    Ok(TriggerRun { capture, matched, login_wall: wall, repeats: stopped.repeats, resends: stopped.resends })
}

/// A tier-3 result: the site's own request, answered.
pub fn judge_exchange(op: &Operation, e: &Exchange) -> Option<Attempt> {
    let r = e.response.as_ref()?;
    let j = judge(
        op,
        &Observed {
            status: r.status,
            headers: r.headers.clone(),
            body: r.body.clone().unwrap_or_default(),
            url: Some(e.request.url.clone()),
        },
    );
    Some(Attempt {
        tier: 3,
        status: Some(r.status),
        class: j.class,
        reason: j.reason,
        missing: j.missing,
        data: j.data,
        ..Default::default()
    })
}

/* ------------------------------------------------------------ captures */

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureFile {
    pub id: String,
    pub at: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<TriggerStep>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_from: Option<String>,
    /// writes were intercepted during this run
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub write: bool,
    #[serde(flatten)]
    pub result: CaptureResult,
}

fn capture_file(id: &str) -> Result<PathBuf> {
    Ok(home().join("captures").join(format!("{}.json", safe_name(id)?)))
}

static LAST_ID: Mutex<String> = Mutex::new(String::new());

fn base36(mut n: u64) -> String {
    const D: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if n == 0 {
        return "0".to_string();
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push(D[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

fn save_capture(
    url: &str,
    steps: Option<&Vec<TriggerStep>>,
    soft_from: Option<&str>,
    write: bool,
    r: CaptureResult,
) -> Result<CaptureFile> {
    let mut id = format!("c{}", base36(now_ms() as u64));
    {
        let mut last = LAST_ID.lock().unwrap();
        while id.as_str() <= last.as_str() {
            let n = u64::from_str_radix(&last[1..], 36).unwrap_or(0) + 1;
            id = format!("c{}", base36(n));
        }
        *last = id.clone();
    }
    let file = CaptureFile {
        id: id.clone(),
        at: iso_now(),
        url: url.to_string(),
        steps: steps.cloned(),
        soft_from: soft_from.map(|s| s.to_string()),
        write,
        result: r,
    };
    write_private(&capture_file(&id)?, &json(&serde_json::to_value(&file)?))?;
    prune_captures(now_ms());
    Ok(file)
}

pub struct CapturePageOptions {
    pub url: String,
    pub steps: Option<Vec<TriggerStep>>,
    pub soft_from: Option<String>,
    pub write: bool,
    pub args: Option<Args>,
}

/// Run a page, keep everything it sent under ~/.api-anything/captures/<id>.json (0600: it holds cookies).
pub async fn capture_page(o: CapturePageOptions) -> Result<CaptureFile> {
    let mut t = TriggerOptions::new(&o.url, &profile_dir());
    t.steps = o.steps.clone();
    t.soft_from = o.soft_from.clone();
    if o.write {
        t.intercept = Some(write_guard(None, Some(&o.url), o.args.as_ref()));
    }
    let r = run_trigger(t).await?;
    save_capture(&o.url, o.steps.as_ref(), o.soft_from.as_deref(), o.write, r)
}

pub fn load_capture(id: &str) -> Result<CaptureFile> {
    let v = read_json(&capture_file(id)?)?.ok_or_else(|| anyhow!("no capture \"{id}\""))?;
    serde_json::from_value(v).map_err(|e| anyhow!("capture \"{id}\" is corrupt ({e}); delete it"))
}

/* ----------------------------------------------------------------- add */

#[derive(Clone, Debug, Default)]
pub struct Recipe {
    pub extract: Option<String>,
    pub pick: Option<Vec<String>>,
    pub html: Option<crate::spec::HtmlRecipe>,
    pub embedded: Option<crate::spec::Embedded>,
}

impl Recipe {
    fn any(&self) -> bool {
        self.extract.is_some() || self.pick.is_some() || self.html.is_some() || self.embedded.is_some()
    }
}

pub struct FromCapture {
    pub capture: CaptureFile,
    pub id: Option<u64>,
}

pub struct AddInput {
    pub site: String,
    pub op: String,
    /// url may be relative to an existing site's baseUrl; optional with `from` (derived from the capture)
    pub trigger: Option<crate::spec::Trigger>,
    pub examples: Vec<Args>,
    pub matcher: Option<Match>,
    pub write: bool,
    pub description: Option<String>,
    pub response: Option<Recipe>,
    /// header names a human confirmed are public constants: kept literal instead of session refs
    pub public: Option<Vec<String>>,
    /// learn from a saved capture instead of running the trigger; id = the request to learn
    pub from: Option<FromCapture>,
    /// a second saved capture, made with examples[1], for the two-run diff
    pub from2: Option<CaptureFile>,
    pub fetcher: Option<SharedFetcher>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Preview {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    pub first: Value,
}

pub struct AddResult {
    pub operation: Operation,
    pub warnings: Vec<String>,
    pub path: String,
    /// the trigger runs, saved as captures (add --from <id> re-learns from them without Chrome)
    pub captures: Vec<String>,
    /// what a call would have returned, judged on the captured response
    pub preview: Option<Preview>,
    /// an op of that name existed and was overwritten
    pub replaced: bool,
}

/// Put `{name}` back where an example value sits in a literal step (a typed value, a selector).
fn templatize(text: &str, args: &Args) -> String {
    let mut out = escape_template(text);
    for (k, v) in args {
        let s = as_text(v);
        if s.len() >= 3 {
            out = out.split(&escape_template(&s)).collect::<Vec<_>>().join(&format!("{{{k}}}"));
        }
    }
    out
}

/// Put `{name}` back where an example value sits in a captured page URL: the query value under a key
/// named like the param, else every query value and path segment equal to it, else a substring of
/// the path or query. The host stays literal.
pub fn templatize_url(url: &str, args: &Args) -> String {
    let (no_hash, hash) = match url.find('#') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, ""),
    };
    let (base, pairs_raw) = match no_hash.find('?') {
        Some(i) => (&no_hash[..i], Some(&no_hash[i + 1..])),
        None => (no_hash, None),
    };
    let from = base.find("//").map(|i| i + 2).unwrap_or(0);
    let path_at = base[from..].find('/').map(|i| i + from);
    let origin = match path_at {
        Some(i) => &base[..i],
        None => base,
    };
    let lit = |t: &str| escape_template(t);
    let mut segs: Vec<String> = match path_at {
        Some(i) => base[i..].split('/').map(lit).collect(),
        None => vec![],
    };
    let mut pairs: Option<Vec<String>> = pairs_raw.map(|p| p.split('&').map(lit).collect());
    for (k, v) in args {
        let want = as_text(v).to_lowercase();
        if want.len() < 3 {
            continue;
        }
        let hole = format!("{{{k}}}");
        let value_of = |p: &str| decode_loose(&p[p.find('=').map(|i| i + 1).unwrap_or(p.len())..], true).to_lowercase();
        let key_of = |p: &str| decode_loose(&p[..p.find('=').unwrap_or(0)], true).to_lowercase();
        let in_query = |p: &str| p.contains('=') && value_of(p) == want;
        let in_path = |seg: &str| decode_loose(seg, false).to_lowercase() == want;
        let named = pairs.as_ref().map(|ps| ps.iter().any(|p| in_query(p) && key_of(p) == k.to_lowercase())).unwrap_or(false);
        if pairs.as_ref().map(|ps| ps.iter().any(|p| in_query(p))).unwrap_or(false) || segs.iter().any(|s| in_path(s)) {
            pairs = pairs.map(|ps| {
                ps.into_iter()
                    .map(|p| {
                        if in_query(&p) && (!named || key_of(&p) == k.to_lowercase()) {
                            format!("{}={hole}", &p[..p.find('=').unwrap_or(0)])
                        } else {
                            p
                        }
                    })
                    .collect()
            });
            if !named {
                segs = segs.into_iter().map(|s| if in_path(&s) { hole.clone() } else { s }).collect();
            }
        } else {
            let raw = as_text(v);
            let mut forms: Vec<String> = Vec::new();
            for f in [encode_uri_component(&raw), encode_uri_component(&raw).replace("%20", "+"), raw.clone()] {
                if !forms.contains(&f) {
                    forms.push(f);
                }
            }
            let alt = re(&format!("(?i){}", forms.iter().map(|f| regex::escape(&lit(f))).collect::<Vec<_>>().join("|")));
            segs = segs.into_iter().map(|s| alt.replace_all(&s, hole.as_str()).into_owned()).collect();
            pairs = pairs.map(|ps| {
                ps.into_iter()
                    .map(|p| match p.find('=') {
                        Some(i) => format!("{}{}", &p[..i + 1], alt.replace_all(&p[i + 1..], hole.as_str())),
                        None => p,
                    })
                    .collect()
            });
        }
    }
    format!("{}{}{}{}", lit(origin), segs.join("/"), pairs.map(|p| format!("?{}", p.join("&"))).unwrap_or_default(), lit(hash))
}

/// How a capture was made, as a trigger: `{name}` where the example values sit in its URL and steps.
pub fn capture_trigger(c: &CaptureFile, args: &Args) -> crate::spec::Trigger {
    let step = |s: &TriggerStep| TriggerStep {
        action: s.action,
        selector: s.selector.as_ref().filter(|x| !x.is_empty()).map(|x| templatize(x, args)).or_else(|| s.selector.clone()),
        value: s
            .value
            .as_ref()
            .filter(|x| !x.is_empty())
            .map(|x| if s.action == StepAction::Goto { templatize_url(x, args) } else { templatize(x, args) })
            .or_else(|| s.value.clone()),
        ms: s.ms,
    };
    crate::spec::Trigger {
        url: templatize_url(&c.url, args),
        soft_from: c.soft_from.clone(),
        steps: c.steps.as_ref().map(|ss| ss.iter().map(step).collect()),
    }
}

/// The args a trigger has no `{name}` for, in its URL, its soft-navigation page or its steps.
pub fn unplaced(t: &crate::spec::Trigger, args: &Args) -> Vec<String> {
    let mut texts: Vec<String> = vec![t.url.clone(), t.soft_from.clone().unwrap_or_default()];
    for s in t.steps.iter().flatten() {
        texts.push(s.selector.clone().unwrap_or_default());
        texts.push(s.value.clone().unwrap_or_default());
    }
    args.keys().filter(|k| !texts.iter().any(|x| x.contains(&format!("{{{k}}}")))).cloned().collect()
}

pub fn put_operation(site: &Site, op: Operation) -> Site {
    let mut out = site.clone();
    out.operations.retain(|o| o.name != op.name);
    out.operations.push(op);
    out
}

/// learn_operation, but a failure on a page that was a bot wall says so (the recipe or the pick is not the problem).
fn learn_or_explain(site: &str, run: &CaptureResult, input: &LearnInput) -> Result<Learned> {
    match learn_operation(input) {
        Ok(l) => Ok(l),
        Err(e) => {
            // Only the page's own documents: an ad's or widget's iframe (a reCAPTCHA frame) is not the page.
            let docs: Vec<&Exchange> = run.exchanges.iter().filter(|x| x.resource_type == "document" && x.response.is_some()).collect();
            let own = docs.first().and_then(|d| parse_url(&d.request.url)).map(|u| site_of(u.host_str().unwrap_or("")));
            let doc =
                docs.iter().rfind(|x| parse_url(&x.request.url).map(|u| Some(site_of(u.host_str().unwrap_or(""))) == own).unwrap_or(false));
            let wall = doc.and_then(|d| d.response.as_ref()).and_then(|r| {
                bot_wall(
                    &Observed { status: r.status, headers: r.headers.clone(), body: r.body.clone().unwrap_or_default(), url: None },
                    false,
                    None,
                )
            });
            if let Some(wall) = wall {
                bail!(
                    "the page served a bot challenge ({wall}): ask the user to run api-anything login {site} and clear it, then add again (learning said: {e})"
                );
            }
            Err(e)
        }
    }
}

/// The recipe finds data in this body (a non-empty list, or a value).
fn resolves(spec: &ResponseSpec, body: Option<&str>) -> bool {
    let Some(body) = body else { return false };
    if body.is_empty() {
        return false;
    }
    match extract(spec, body) {
        Ok(Some(Value::Array(a))) => !a.is_empty(),
        Ok(Some(Value::Null)) => false,
        Ok(Some(_)) => true,
        _ => false,
    }
}

fn preview_of(data: Option<&Value>) -> Preview {
    let (count, first) = match data {
        Some(Value::Array(a)) => (Some(a.len()), a.first().cloned().unwrap_or(Value::Null)),
        Some(v) => (None, v.clone()),
        None => (None, Value::Null),
    };
    Preview { count, first: cap_output(&first, 600).data }
}

/// A learned response spec with the caller's recipe on top; an html or embedded recipe sets the format.
fn with_recipe(learned: &ResponseSpec, r: &Recipe) -> ResponseSpec {
    let mut out = learned.clone();
    if r.extract.is_some() {
        out.extract = r.extract.clone();
    }
    if r.pick.is_some() {
        out.pick = r.pick.clone();
    }
    if r.html.is_some() {
        out.html = r.html.clone();
        out.format = Format::Html;
    }
    if r.embedded.is_some() {
        out.embedded = r.embedded.clone();
        out.format = Format::Embedded;
    }
    out
}

/// Learning's warnings, minus "the response is HTML: add a recipe" when one was given.
fn recipe_warnings(warnings: Vec<String>, r: &Recipe) -> Vec<String> {
    warnings.into_iter().filter(|w| !((r.html.is_some() || r.embedded.is_some()) && w.starts_with("response is HTML"))).collect()
}

struct Saved {
    operation: Operation,
    warnings: Vec<String>,
    path: String,
    preview: Option<Preview>,
    replaced: bool,
}

/// The end of every add: judge the op on the answer it was learned from, then save it.
fn save_operation(
    site: &str,
    operation: Operation,
    exchange: Option<&Exchange>,
    mut warnings: Vec<String>,
    session: &Session,
    again: Option<&str>,
) -> Result<Saved> {
    let mut preview: Option<Preview> = None;
    if let Some(res) = exchange.and_then(|e| e.response.as_ref().map(|r| (e, r))) {
        let (e, r) = res;
        let j = judge(
            &operation,
            &Observed {
                status: r.status,
                headers: r.headers.clone(),
                body: r.body.clone().unwrap_or_default(),
                url: Some(e.request.url.clone()),
            },
        );
        if j.class == Class::Ok {
            preview = Some(preview_of(j.data.as_ref()));
        } else if matches!(j.class, Class::Blocked | Class::Auth | Class::Rate) {
            // a bot wall or a login page is not fixed by editing the recipe
            let what = if j.class == Class::Rate { "a throttled answer" } else { "a challenge or sign-in page" };
            let next = if j.class == Class::Rate {
                "wait a few minutes, then add again".to_string()
            } else {
                format!("ask the user to run api-anything login {site} (and clear any challenge), then add again")
            };
            warnings.push(format!("the captured response is {}: {}. The op was learned from {what}: {next}", j.class, j.reason));
        } else {
            warnings.push(format!(
                "on the captured response this op says {}: {}. Fix --extract/--pick/--html/--embedded and re-run add --from {} (no browser needed)",
                j.class,
                j.reason,
                again.unwrap_or("<id>")
            ));
        }
    }
    let allowed: HashSet<String> = operation.public.clone().unwrap_or_default().iter().map(|h| format!("$.request.headers.{h}")).collect();
    let secrets = scan_secrets(&serde_json::to_value(&operation)?, session, &allowed).secrets;
    if !secrets.is_empty() {
        bail!("refusing to save a spec containing a credential: {}", secrets.join("; "));
    }
    // Re-read under the lock: another add or a heal may have saved this site since we started.
    let replaced = Arc::new(Mutex::new(false));
    let r2 = replaced.clone();
    let op_name = operation.name.clone();
    let op2 = operation.clone();
    let site_name = site.to_string();
    let path = update_site(site, move |current| {
        *r2.lock().unwrap() = current.as_ref().map(|c| c.operations.iter().any(|o| o.name == op_name)).unwrap_or(false);
        let fresh = Site {
            name: site_name.clone(),
            display_name: None,
            base_url: crate::util::origin_str(&op2.trigger.url).unwrap_or_default(),
            description: None,
            login_cookies: None,
            operations: vec![],
        };
        Ok(put_operation(&current.unwrap_or(fresh), op2))
    })?;
    clear_stale(site, &operation.name);
    let replaced = *replaced.lock().unwrap();
    Ok(Saved { operation, warnings, path, preview, replaced })
}

/// One trigger run of an add, saved as a capture; returns it with the URL it loaded.
async fn run_for_add(trigger: crate::spec::Trigger, a: Args, write: bool, m: Option<Match>) -> Result<(CaptureFile, String)> {
    let t = fill_trigger(&trigger, &a);
    let mut o = TriggerOptions::new(&t.url, &profile_dir());
    o.steps = t.steps.clone();
    o.soft_from = t.soft_from.clone();
    if write {
        o.intercept = Some(write_guard(m, Some(&t.url), Some(&a)));
    }
    let r = run_trigger(o).await?;
    let saved = save_capture(&t.url, t.steps.as_ref(), t.soft_from.as_deref(), write, r)?;
    Ok((saved, t.url))
}

pub async fn add_operation(input: AddInput) -> Result<AddResult> {
    let site_name = safe_name(&input.site)?;
    let existing = load_site(&site_name)?.map(|r| r.site);
    let old = existing.as_ref().and_then(|s| s.operations.iter().find(|o| o.name == input.op)).cloned();
    let ex2 = input.examples.get(1).cloned();
    let mut ex1 = input.examples.first().cloned().unwrap_or_default();
    // An existing op added again from a capture with no --example (a recipe being fixed) is the same
    // learning as any add, with what the command leaves out taken from the stored op.
    let prior = if old.is_some() && input.from.is_some() && ex1.is_empty() { old.clone() } else { None };
    if let Some(p) = &prior {
        if !p.params.is_empty() {
            let bare: Vec<&String> = p.params.iter().filter(|x| x.example.is_none()).map(|x| &x.name).collect();
            if !bare.is_empty() {
                bail!(
                    "{} has no stored example for {}: pass --example with the values capture {} was made with",
                    input.op,
                    bare.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                    input.from.as_ref().map(|f| f.capture.id.clone()).unwrap_or_default()
                );
            }
            ex1 = p.params.iter().map(|x| (x.name.clone(), x.example.clone().unwrap_or(Value::Null))).collect();
        }
    }
    // Before any browser run: learned as a read, a write is sent while learning it, and then on every call.
    if let Some(o) = &old {
        if !o.read_only && !input.write {
            bail!(
                "{} is a write: learning it again needs --write{}",
                input.op,
                if input.from.is_some() { ", and a capture made with --write" } else { "" }
            );
        }
    }
    // before any browser run: a too-short or duplicate example would only fail after it
    check_examples(&ex1, "example", ex2.as_ref())?;
    if let Some(e2) = &ex2 {
        check_examples(e2, "example 2", Some(&ex1))?;
    }
    for c in [input.from.as_ref().map(|f| &f.capture), input.from2.as_ref()].into_iter().flatten() {
        if input.write && !c.write {
            bail!("capture {} ran without --write, so any write in it was already sent; capture again with --write", c.id);
        }
    }
    let mut trigger = input.trigger.clone().or_else(|| input.from.as_ref().map(|f| capture_trigger(&f.capture, &ex1)));
    let Some(mut trigger_v) = trigger.take() else { bail!("a trigger url is needed (or --from a capture)") };
    if trigger_v.url.starts_with('/') {
        let Some(e) = &existing else { bail!("relative trigger {} needs an existing site; use a full URL", trigger_v.url) };
        trigger_v.url = format!("{}{}", e.base_url.trim_end_matches('/'), trigger_v.url);
    }
    let trigger = trigger_v;
    let missing = unplaced(&trigger, &ex1);

    let run1: CaptureResult;
    let run2: Option<CaptureResult>;
    let mut captures: Vec<String> = Vec::new();
    if let Some(f) = &input.from {
        run1 = f.capture.result.clone();
        run2 = input.from2.as_ref().map(|c| c.result.clone());
    } else {
        let run = |a: Args| run_for_add(trigger.clone(), a, input.write, input.matcher.clone());
        let (saved1, url1) = run(ex1.clone()).await?;
        captures.push(saved1.id.clone());
        let r1 = saved1.result;
        if let Some(wall) = login_wall(&r1, &url1) {
            bail!(
                "the trigger landed on a sign-in page ({wall}): the site needs an account. Ask the user to run: api-anything login {site_name}; then add again"
            );
        }
        run1 = r1;
        let (saved2, _) = run(ex2.clone().unwrap_or_else(|| ex1.clone())).await?;
        captures.push(saved2.id.clone());
        run2 = Some(saved2.result);
    }
    let flags = input.response.clone().unwrap_or_default();
    let kept = prior.as_ref().map(|p| p.response.clone());
    let r: Recipe = match (&kept, flags.any()) {
        (Some(k), false) => Recipe { extract: k.extract.clone(), pick: k.pick.clone(), html: k.html.clone(), embedded: k.embedded.clone() },
        _ => flags,
    };
    let spec = ResponseSpec {
        format: if r.html.is_some() {
            Format::Html
        } else if r.embedded.is_some() {
            Format::Embedded
        } else {
            Format::Json
        },
        extract: r.extract.clone(),
        pick: r.pick.clone(),
        html: r.html.clone(),
        embedded: r.embedded.clone(),
        ..Default::default()
    };
    let mut storage: IndexMap<String, String> = IndexMap::new();
    if let Some(s) = run2.as_ref().and_then(|x| x.storage.clone()) {
        storage.extend(s);
    }
    if let Some(s) = run1.storage.clone() {
        storage.extend(s);
    }
    let mut li = LearnInput::new(
        run1.exchanges.clone(),
        if run2.is_some() { vec![ex1.clone(), ex2.clone().unwrap_or_else(|| ex1.clone())] } else { vec![ex1.clone()] },
        &input.op,
        trigger.clone(),
        !input.write,
    );
    li.pages = Some(capture_pages(&run1));
    li.exchanges2 = run2.as_ref().map(|x| x.exchanges.clone());
    li.cookies = run2.as_ref().unwrap_or(&run1).cookies.clone();
    li.storage = Some(storage);
    li.matcher = input.matcher.clone();
    li.id = input.from.as_ref().and_then(|f| f.id);
    li.login_cookies = existing.as_ref().and_then(|e| e.login_cookies.clone());
    li.public = input.public.clone();
    // With a response recipe, the request it resolves on is the answer (not a beacon echoing the page URL).
    if r.html.is_some() || r.embedded.is_some() || r.extract.is_some() {
        let spec2 = spec.clone();
        li.accepts = Some(Box::new(move |e: &Exchange| resolves(&spec2, e.response.as_ref().and_then(|r| r.body.as_deref()))));
    }
    // said when the stored examples do not fit the capture
    let stored = || {
        format!(
            "No --example was given, so {}'s stored ones were used ({}): pass --example with the values capture {} was made with",
            input.op,
            ex1.iter().map(|(k, v)| format!("{k}={}", as_text(v))).collect::<Vec<_>>().join(", "),
            input.from.as_ref().map(|f| f.capture.id.clone()).unwrap_or_default()
        )
    };
    let learned = match learn_or_explain(&site_name, &run1, &li) {
        Ok(l) => l,
        Err(e) => {
            if prior.as_ref().map(|p| p.params.is_empty()).unwrap_or(true) {
                return Err(e);
            }
            bail!("{e}. {}", stored());
        }
    };
    // A stored value may sit in the capture by chance: bound there, the param would fill the wrong place from then on.
    let places = |o: &Operation| {
        let mut v: Vec<String> = o
            .slots
            .iter()
            .filter(|s| s.is_param())
            .map(|s| format!("{} at {}", s.param.as_deref().unwrap_or(""), s.at.join(" > ")))
            .collect();
        v.sort();
        v.join("; ")
    };
    if let Some(p) = &prior {
        if !p.params.is_empty() && places(p) != places(&learned.operation) {
            bail!(
                "request {} carries the stored example values in other places ({}) than {} takes them ({}). {}",
                learned.exchange.id,
                places(&learned.operation),
                input.op,
                places(p),
                stored()
            );
        }
    }
    // What a --write capture aborted, its guard stopped as a write: that is the evidence, not the method.
    if let Some(f) = &input.from {
        if !input.write && learned.exchange.aborted && f.capture.write {
            bail!(
                "capture {} was made with --write and intercepted request {} as a write: learning it needs --write",
                f.capture.id,
                learned.exchange.id
            );
        }
    }
    if let (Some(c2), Some(e2)) = (&input.from2, &learned.exchange2) {
        if !input.write && e2.aborted && c2.write {
            bail!("capture {} was made with --write and intercepted request {} as a write: learning it needs --write", c2.id, e2.id);
        }
    }
    let mut warnings = recipe_warnings(learned.warnings.clone(), &r);
    if !missing.is_empty() {
        warnings.push(format!(
            "the trigger has no {{{}}}: tier-3 runs and heals would load the example's page; put the param in --trigger",
            missing.join("}, {")
        ));
    }
    // Learned again with nothing new said about it, an op keeps what this one capture cannot tell: its
    // description, and a tier an earlier two-run diff raised (--description "" clears the first).
    let description = input.description.clone().or_else(|| prior.as_ref().and_then(|p| p.description.clone())).filter(|d| !d.is_empty());
    let mut operation = learned.operation.clone();
    operation.description = description;
    if let Some(p) = &prior {
        if run2.is_none() && p.min_tier > operation.min_tier {
            operation.min_tier = p.min_tier;
        }
    }
    operation.response = with_recipe(&learned.operation.response, &r);
    let session = merge_capture(&site_name, &run2.as_ref().unwrap_or(&run1).cookies, &learned.session_values, now_ms())?;

    // Values that differ between two page loads are often session-scoped ids, not per-request
    // signatures. One replay of run 1's template with example 2's args tells them apart.
    if operation.min_tier == 3 && operation.read_only && run2.is_some() {
        let opts = SendOptions { site: site_name.clone(), fetcher: input.fetcher.clone(), timeout_ms: None, min_interval_ms: None };
        if let Ok(sent) = send(&operation, ex2.as_ref().unwrap_or(&ex1), &session, &opts).await {
            let j = judge(
                &operation,
                &Observed { status: sent.status, headers: sent.headers.clone(), body: sent.body.clone(), url: Some(sent.url.clone()) },
            );
            if j.class == Class::Ok {
                operation.min_tier = 1;
                warnings.push(
                    "...but run 1's template replays fine with example 2's args, so those values are session-scoped: minTier 1".to_string(),
                );
            }
        }
    }

    let again = captures.first().cloned().or_else(|| input.from.as_ref().map(|f| f.capture.id.clone()));
    let saved = save_operation(&site_name, operation, Some(&learned.exchange), warnings, &session, again.as_deref())?;
    remember_tier(&site_name, &saved.operation.name, None);
    Ok(AddResult {
        operation: saved.operation,
        warnings: saved.warnings,
        path: saved.path,
        captures,
        preview: saved.preview,
        replaced: saved.replaced,
    })
}

/* ---------------------------------------------------------------- rescan */

fn charset_of(c: crate::spec::Charset) -> (&'static str, &'static str) {
    // [token chars, chars that must not touch the token]
    match c {
        crate::spec::Charset::Digits => ("0-9", "0-9A-Za-z_"),
        crate::spec::Charset::Hex => ("0-9a-fA-F", "0-9A-Za-z_"),
        crate::spec::Charset::Base64url => ("A-Za-z0-9_-", "A-Za-z0-9_-"),
        crate::spec::Charset::Base64 => ("A-Za-z0-9+/=", "A-Za-z0-9+/="),
    }
}
const NEAR: usize = 300;

/// Whether text between a token and its anchor (read left to right) keeps them in one group: no
/// bracket closes the group the scan started in, and no `;` ends a statement at that level.
fn same_group(between: &str) -> bool {
    let mut depth = 0i32;
    for c in between.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            ';' if depth == 0 => return false,
            _ => {}
        }
    }
    true
}

struct Found {
    token: String,
    d: usize,
    same: bool,
    prose: bool,
}

/// The token of the recorded shape next to the anchor. The anchor must stand as its own name, an
/// occurrence in code beats one in prose, a token in the anchor's own group beats a nearer one
/// across a module boundary, and a tie between two tokens is no answer. `strict` (writes): only a
/// token that is the one candidate.
fn nearest_token(texts: &[String], v: &Volatile, strict: bool) -> Option<String> {
    let (chars, bound) = charset_of(v.shape.charset);
    let token_re = crate::util::fre(&format!("(?<![{bound}])[{chars}]{{{}}}(?![{bound}])", v.shape.length));
    let anchor_re = crate::util::fre(&format!(r"(?<![A-Za-z0-9$]){}(?![A-Za-z0-9$])", regex::escape(&v.anchor)));
    let mut found: Vec<Found> = Vec::new();
    let is_ws = |s: &str, i: Option<usize>| i.and_then(|i| s[i..].chars().next()).map(|c| c.is_whitespace()).unwrap_or(false);
    for text in texts {
        for a in anchor_re.find_iter(text).flatten() {
            let i = a.start();
            let anchor_end = a.end();
            let from =
                text[..i].char_indices().rev().nth(NEAR.saturating_sub(1)).map(|(k, _)| k).unwrap_or(0).max(i.saturating_sub(NEAR * 4));
            let from = floor_char(text, from);
            let to = ceil_char(text, (anchor_end + NEAR).min(text.len()));
            let before = text[..i].chars().last().map(|c| c.is_whitespace()).unwrap_or(false);
            let prose = before || is_ws(text, Some(anchor_end).filter(|e| *e < text.len()));
            for m in token_re.find_iter(&text[from..to]).flatten() {
                let token = m.as_str().to_string();
                if v.shape.charset != crate::spec::Charset::Digits && !hash_like(&token) {
                    continue;
                }
                let start = from + m.start();
                let end = start + token.len();
                if end > i && start < anchor_end {
                    continue; // overlaps the anchor itself
                }
                let between = if end <= i { &text[end..i] } else { &text[anchor_end..start] };
                found.push(Found { token, d: between.len(), same: same_group(between), prose });
            }
        }
    }
    let code: Vec<&Found> =
        if found.iter().any(|f| !f.prose) { found.iter().filter(|f| !f.prose).collect() } else { found.iter().collect() };
    let pool: Vec<&Found> = if code.iter().any(|f| f.same) {
        code.into_iter().filter(|f| f.same).collect()
    } else if strict {
        vec![]
    } else {
        code
    };
    if strict {
        let distinct: HashSet<&String> = pool.iter().map(|f| &f.token).collect();
        return if distinct.len() == 1 { distinct.into_iter().next().cloned() } else { None };
    }
    let best = pool.iter().map(|f| f.d).min()?;
    let tied: HashSet<&String> = pool.iter().filter(|f| f.d == best).map(|f| &f.token).collect();
    if tied.len() == 1 { tied.into_iter().next().cloned() } else { None }
}

fn floor_char(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}
fn ceil_char(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// A page's text and where it ended up, for the rescan. Redirects are taken by hand so that `off`
/// is asked about every address before it is fetched: one it rules out is not fetched.
async fn fetch_text(
    mut url: String,
    headers: &dyn Fn(&str) -> crate::types::Headers,
    fetcher: &SharedFetcher,
    off: &dyn Fn(&str) -> bool,
) -> (String, String) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(15_000);
    let mut hops = 0;
    while hops <= MAX_REDIRECTS && !off(&url) {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let req = HttpRequest { url: url.clone(), method: "GET".into(), headers: headers(&url), body: None };
        let Ok(Ok(r)) = tokio::time::timeout(left, fetcher.fetch(req, left)).await else { break };
        let location = if is_redirect(r.status) { r.headers.get("location").cloned() } else { None };
        let Some(location) = location.filter(|l| !l.is_empty()) else {
            let text = if (200..300).contains(&r.status) {
                crate::http::decode_body(&r.body, r.headers.get("content-type").map(|s| s.as_str()).unwrap_or(""))
            } else {
                String::new()
            };
            return (text, url);
        };
        url = crate::util::resolve_url(&location, &url).unwrap_or(location);
        hops += 1;
    }
    (String::new(), url)
}

pub struct Rescanned {
    pub operation: Operation,
    pub diff: String,
}

/// Browserless heal: fetch the trigger document and the scripts it references, and swap in the
/// token of each volatile's shape nearest its anchor. None when nothing new was found. For a write,
/// no address that is the write itself is fetched, at first or after a redirect.
pub async fn rescan(site: &str, op: &Operation, args: &Args, fetcher: Option<SharedFetcher>) -> Result<Option<Rescanned>> {
    if op.volatile.is_empty() {
        return Ok(None);
    }
    let session = load_session(site)?;
    let url = fill_trigger(&op.trigger, args).url;
    let fetcher = fetcher.unwrap_or_else(default_fetcher);
    let ua = op.request.headers.get("user-agent").cloned();
    let cookies = session.cookies.clone();
    let headers = move |u: &str| {
        let mut h = crate::types::Headers::new();
        if let Some(ua) = &ua {
            h.insert("user-agent".into(), ua.clone());
        }
        let cookie = cookie_header_for(&cookies, u, now_ms());
        if !cookie.is_empty() {
            h.insert("cookie".into(), cookie);
        }
        h
    };
    let the_write = |u: &str| !op.read_only && matches(&own_match(op), &crate::learn::bare_request("GET", u));
    let (doc, doc_url) = fetch_text(url, &headers, &fetcher, &the_write).await;
    if doc.is_empty() {
        return Ok(None);
    }
    // relative to the document's final URL: a redirect (a locale prefix) moves where "../static" points
    static SCRIPT: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"(?i)<script\b[^>]*\bsrc=["']([^"']+)["']"#));
    static LINK: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"(?i)<link\b[^>]*\bhref=["']([^"']+\.m?js(?:\?[^"']*)?)["']"#));
    let mut refs: Vec<String> = Vec::new();
    for m in SCRIPT.captures_iter(&doc).chain(LINK.captures_iter(&doc)) {
        if let Some(u) = crate::util::resolve_url(&m[1], &doc_url) {
            if !refs.contains(&u) {
                refs.push(u);
            }
        }
    }
    // only scripts the document references directly; ids in lazily loaded chunks need recapture.
    let mut texts = vec![doc];
    let futures: Vec<_> = refs.into_iter().take(40).map(|s| fetch_text(s, &headers, &fetcher, &the_write)).collect();
    for (text, _) in futures_util::future::join_all(futures).await {
        texts.push(text);
    }

    let types: HashMap<String, crate::codec::LeafType> = walk(&op.request).into_iter().map(|l| (step_key(&l.at), l.kind)).collect();
    let mut request = op.request.clone();
    let mut changes: Vec<String> = Vec::new();
    for v in &op.volatile {
        let old = crate::codec::get_text(&op.request, &v.at);
        let Some(token) = nearest_token(&texts, v, !op.read_only) else { continue };
        if token == old {
            continue;
        }
        let numeric = types.get(&step_key(&v.at)) == Some(&crate::codec::LeafType::Number);
        let value = if numeric { crate::util::number_from_text(&token) } else { Value::String(token.clone()) };
        request = set_at(&request, &v.at, &value)?;
        changes.push(format!("{}: {old} -> {token}", v.at.join(" > ")));
    }
    if changes.is_empty() {
        return Ok(None);
    }
    let mut operation = op.clone();
    operation.request = request;
    Ok(Some(Rescanned { operation, diff: changes.join("; ") }))
}

/* -------------------------------------------------------------- recapture */

/// The wire template with these args filled in, so the example values an op was learned with don't count as a change.
fn template(op: &Operation, args: &Args) -> String {
    let req = build_request(op, args, &Session::empty()).unwrap_or_else(|_| op.request.clone());
    json(&serde_json::json!([req, op.slots, op.volatile]))
}

fn summarize(a: &Operation, b: &Operation) -> String {
    let mut parts: Vec<String> = Vec::new();
    if a.request.url != b.request.url {
        let path = |u: &str| parse_url(u).map(|x| x.path().to_string()).unwrap_or_default();
        parts.push(format!("url {} -> {}", path(&a.request.url), path(&b.request.url)));
    }
    let mut names: Vec<String> = a.request.headers.keys().cloned().collect();
    for k in b.request.headers.keys() {
        if !names.contains(k) {
            names.push(k.clone());
        }
    }
    let headers: Vec<String> = names.into_iter().filter(|n| a.request.headers.get(n) != b.request.headers.get(n)).collect();
    if !headers.is_empty() {
        parts.push(format!("headers {}", headers.join(",")));
    }
    if a.request.body != b.request.body {
        parts.push("body".to_string());
    }
    if json(&serde_json::to_value(&a.slots).unwrap_or(Value::Null)) != json(&serde_json::to_value(&b.slots).unwrap_or(Value::Null)) {
        parts.push(format!("slots {} -> {}", a.slots.len(), b.slots.len()));
    }
    if parts.is_empty() { "template unchanged".to_string() } else { parts.join("; ") }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum HealResult {
    Healed {
        strategy: Strategy,
        operation: Operation,
        attempt: Attempt,
    },
    Identical {
        reason: String,
        fallback: Option<Attempt>,
    },
    Failed {
        reason: String,
        /// the last validation replay, if one ran
        attempt: Option<Attempt>,
        /// reads: the site's own response from the recapture run (the tier-3 answer)
        fallback: Option<Attempt>,
        /// nothing was learned about the op: not a reason to mark the op stale
        transient: bool,
    },
}

impl HealResult {
    pub fn attempt(&self) -> Option<&Attempt> {
        match self {
            HealResult::Healed { attempt, .. } => Some(attempt),
            HealResult::Identical { .. } => None,
            HealResult::Failed { attempt, .. } => attempt.as_ref(),
        }
    }
    pub fn fallback(&self) -> Option<&Attempt> {
        match self {
            HealResult::Identical { fallback, .. } | HealResult::Failed { fallback, .. } => fallback.as_ref(),
            _ => None,
        }
    }
}

// A check answered with these says nothing about the candidate: stop, and don't spend a browser run on it.
fn stops(c: Class) -> bool {
    matches!(c, Class::Rate | Class::Blocked | Class::Auth)
}

fn save_healed(site: &str, op: Operation, strategy: Strategy, diff: String, attempt: Attempt) -> HealResult {
    let allowed: HashSet<String> = op.public.clone().unwrap_or_default().iter().map(|h| format!("$.request.headers.{h}")).collect();
    let session = load_session(site).unwrap_or_default();
    let secrets = scan_secrets(&serde_json::to_value(&op).unwrap_or(Value::Null), &session, &allowed).secrets;
    if !secrets.is_empty() {
        return HealResult::Failed {
            reason: format!("refusing to save a healed spec containing a credential: {}", secrets.join("; ")),
            attempt: None,
            fallback: None,
            transient: false,
        };
    }
    let op2 = op.clone();
    let site2 = site.to_string();
    if let Err(e) = update_site(site, move |current| {
        let Some(c) = current else { bail!("site \"{site2}\" disappeared during heal") };
        Ok(put_operation(&c, op2))
    }) {
        return HealResult::Failed { reason: e.to_string(), attempt: None, fallback: None, transient: false };
    }
    let _ = append_heal(&crate::store::HealEntry { site: site.to_string(), op: op.name.clone(), strategy, diff }, now_ms());
    clear_stale(site, &op.name);
    HealResult::Healed { strategy, operation: op, attempt }
}

/// Args the learner can locate: every param present, values distinct and 3+ chars.
fn learnable(op: &Operation, a: &Args) -> bool {
    if op.params.iter().any(|p| a.get(&p.name).is_none()) {
        return false;
    }
    check_examples(a, "args", None).is_ok()
}

pub type Validate = Arc<dyn Fn(Operation) -> BoxFuture<'static, Attempt> + Send + Sync>;

pub struct HealOptions {
    pub validate: Validate,
    pub fetcher: Option<SharedFetcher>,
    pub login_cookies: Option<Vec<String>>,
    pub browser: bool,
}

/// Rescan, then recapture; a candidate is saved only after `validate` (a replay) says ok.
/// A write's validation is the write itself, so a write gets exactly one validation in total.
pub async fn heal_operation(site: &str, op: &Operation, args: &Args, o: HealOptions) -> HealResult {
    let mut budget = if op.read_only { 2 } else { 1 };
    let mut last: Option<Attempt> = None;
    let call_args = crate::http::with_defaults(op, args);

    let scanned = rescan(site, op, &call_args, o.fetcher.clone()).await.ok().flatten();
    let swapped =
        |reason: &str| format!("rescan swapped {}, replay said {reason}", scanned.as_ref().map(|s| s.diff.clone()).unwrap_or_default());
    if let Some(s) = &scanned {
        budget -= 1;
        let a = (o.validate)(s.operation.clone()).await;
        if a.class == Class::Ok {
            return save_healed(site, s.operation.clone(), Strategy::Rescan, s.diff.clone(), a);
        }
        if stops(a.class) {
            let reason = swapped(&a.reason);
            return HealResult::Failed { attempt: Some(a), transient: true, reason, fallback: None };
        }
        if budget == 0 {
            let reason = swapped(&a.reason);
            return HealResult::Failed { attempt: Some(a), reason, fallback: None, transient: false };
        }
        last = Some(a);
    }
    let tried = match &last {
        Some(a) => swapped(&a.reason),
        None => "rescan found nothing new".to_string(),
    };
    if !o.browser {
        return HealResult::Failed {
            attempt: last,
            reason: format!("{tried}; recapture needs the browser (maxTier 1)"),
            fallback: None,
            transient: false,
        };
    }
    if !chrome_available() {
        return HealResult::Failed {
            attempt: last,
            reason: format!("{tried}; recapture needs Google Chrome"),
            fallback: None,
            transient: false,
        };
    }

    let examples_raw: Args = op.params.iter().filter_map(|p| p.example.clone().map(|e| (p.name.clone(), e))).collect();
    let examples = crate::http::with_defaults(op, &examples_raw);
    let use_call_args = learnable(op, &call_args) || !learnable(op, &examples);
    let learn_args = if use_call_args { call_args.clone() } else { examples.clone() };
    let run = match run_op_trigger(site, op, &learn_args, !op.read_only).await {
        Ok(r) => r,
        Err(e) => {
            let reason = format!("the browser run failed: {}", crate::util::first_line(&e.to_string()));
            // another process holds the profile: nothing about the op was learned
            if e.downcast_ref::<ProfileInUse>().is_some() {
                let mut a = Attempt::new(3, Class::Error, &reason);
                a.hint = Some(PROFILE_HINT.to_string());
                return HealResult::Failed { attempt: Some(a), transient: true, reason, fallback: None };
            }
            return HealResult::Failed { attempt: last, reason, fallback: None, transient: false };
        }
    };
    if run.matched.is_none() {
        if let Some(wall) = &run.login_wall {
            let reason = format!("the trigger landed on a sign-in page ({wall})");
            return HealResult::Failed { transient: true, attempt: Some(Attempt::new(3, Class::Auth, &reason)), reason, fallback: None };
        }
    }
    if !run.capture.exchanges.iter().any(|e| matches(&op.matcher, &e.request)) {
        return HealResult::Failed {
            attempt: last,
            reason: format!("the trigger fired no request matching {}", json(&serde_json::to_value(&op.matcher).unwrap_or(Value::Null))),
            fallback: None,
            transient: false,
        };
    }
    let seen = run.matched.as_ref().and_then(|m| judge_exchange(op, m));
    if let Some(s) = &seen {
        if stops(s.class) {
            let reason = format!("the site's own request says {}: {}", s.class, s.reason);
            return HealResult::Failed { attempt: Some(s.clone()), transient: true, reason, fallback: None };
        }
    }
    // The site's own answer is this call's answer only when the trigger ran with this call's args.
    let fallback = if op.read_only && use_call_args { seen.clone() } else { None };
    let mut li = LearnInput::new(run.capture.exchanges.clone(), vec![learn_args.clone()], &op.name, op.trigger.clone(), op.read_only);
    li.pages = Some(capture_pages(&run.capture));
    li.cookies = run.capture.cookies.clone();
    li.storage = run.capture.storage.clone();
    li.matcher = Some(op.matcher.clone());
    li.login_cookies = o.login_cookies.clone();
    li.public = op.public.clone();
    let learned = match learn_operation(&li) {
        Ok(l) => l,
        Err(e) => return HealResult::Failed { attempt: last, fallback, reason: format!("re-learning failed: {e}"), transient: false },
    };
    // A deploy that adds an auth/anti-bot header: its value is needed to validate (and later send) the candidate.
    let _ = merge_capture(site, &[], &learned.session_values, now_ms());
    // An arg equal to a constant the old template had there ("search" in /api/search) is not a param position.
    let old_leaves: HashMap<String, String> = walk(&op.request).into_iter().map(|l| (step_key(&l.at), l.value.to_lowercase())).collect();
    let old_slots: HashSet<String> = op.slots.iter().map(|s| step_key(&s.at)).collect();
    let mut fresh = learned.operation.clone();
    fresh.slots.retain(|sl| {
        if !sl.is_param() {
            return true;
        }
        let k = step_key(&sl.at);
        if old_slots.contains(&k) {
            return true;
        }
        let now = crate::codec::get_text(&learned.operation.request, &sl.at).to_lowercase();
        old_leaves.get(&k) != Some(&now)
    });
    // The interface (params, trigger, match, what to extract) is the caller's contract; only the wire template heals.
    let mut candidate = fresh.clone();
    candidate.description = op.description.clone();
    candidate.params = op.params.clone();
    candidate.trigger = op.trigger.clone();
    candidate.matcher = op.matcher.clone();
    candidate.read_only = op.read_only;
    candidate.public = op.public.clone();
    candidate.min_tier = op.min_tier.max(fresh.min_tier);
    candidate.response = ResponseSpec {
        format: op.response.format,
        extract: op.response.extract.clone(),
        pick: op.response.pick.clone(),
        html: op.response.html.clone(),
        embedded: op.response.embedded.clone(),
        ..fresh.response.clone()
    };
    let mut lost: Vec<String> = Vec::new();
    for s in &op.slots {
        if let Some(p) = &s.param {
            if !lost.contains(p) && !candidate.slots.iter().any(|c| c.param.as_deref() == Some(p.as_str())) {
                lost.push(p.clone());
            }
        }
    }
    if !lost.is_empty() {
        return HealResult::Failed {
            attempt: last,
            fallback,
            reason: format!("re-learning found no place for {}; not saved", lost.join(", ")),
            transient: false,
        };
    }
    // A moved parameter can heal; an inferred suffix/prefix is not proof of the caller's meaning.
    static HOLE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\{(?:cookie|session):[^{}]+\}"));
    let encoding =
        |s: &Slot| json(&serde_json::json!([s.template.as_ref().map(|t| HOLE.replace_all(t, "{credential}").into_owned()), s.escape]));
    static NOT_EVIDENCE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^header:(referer|origin|cookie)$"));
    let changed = candidate.slots.iter().find(|s| {
        s.is_param() && !NOT_EVIDENCE.is_match(&s.at[0]) && !op.slots.iter().any(|old| old.param == s.param && encoding(old) == encoding(s))
    });
    if let Some(c) = changed {
        return HealResult::Failed {
            attempt: last,
            fallback,
            reason: format!("re-learning changed the encoding of {}; re-add the operation to confirm it", c.param.as_deref().unwrap_or("")),
            transient: false,
        };
    }
    if template(&candidate, &learn_args) == template(op, &learn_args) {
        return HealResult::Identical { fallback, reason: "re-learning produced a byte-identical template".to_string() };
    }
    let a = (o.validate)(candidate.clone()).await;
    if a.class == Class::Ok {
        return save_healed(site, candidate.clone(), Strategy::Recapture, summarize(op, &candidate), a);
    }
    let transient = stops(a.class);
    let reason = format!("recaptured template failed replay: {}", a.reason);
    HealResult::Failed { attempt: Some(a), fallback, transient, reason }
}

/// The op's stored example args, with defaults filled.
pub fn examples_of(op: &Operation) -> Args {
    op.params.iter().filter_map(|p| p.example.clone().map(|e| (p.name.clone(), e))).collect::<Map<String, Value>>()
}
