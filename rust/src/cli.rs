//! api-anything CLI. Compact JSON on stdout; every failure also prints one `next:` line on stderr.
use crate::browser::{ProfileInUse, chrome_available, close_browser, login as login_window};
use crate::classify::{Observed, bot_wall, empty_results, login_path, sign_in_form};
use crate::execute::{CallOptions, call, heal};
use crate::extract::{cap_output, extract, get_path, inner_json, pick, returned_fields, split_pick};
use crate::heal::{AddInput, CaptureFile, CapturePageOptions, FromCapture, PROFILE_HINT, Recipe, add_operation, capture_page, capture_trigger, fill_trigger, load_capture, profile_dir, unplaced};
use crate::http::{Args, build_request};
use crate::import::AmbiguousProfile;
use crate::learn::{Candidate, RankOptions, capture_pages, page_urls, rank_candidates};
use crate::login::{ImportOptions, cookie_names, import_session, is_logged_in, logout, resolve_login_target};
use crate::mcp::{VERSION, serve_stdio};
use crate::outline::{Outline, outline};
use crate::session::{Session, load_session, save_session, session_file, with_lock};
use crate::spec::{Format, HtmlRecipe, Match, Operation, ResponseSpec, Trigger};
use crate::store::{export_site, list_sites, load_site, site_notes};
use crate::types::{Exchange, StepAction, TriggerStep};
use crate::util::{json, json_pretty, re, take_chars};
use anyhow::{Result, anyhow};
use indexmap::IndexMap;
use serde_json::{Map, Value, json as j};

/// capture/inspect --outline: the scout's summary of one exchange's response.
fn outline_of(e: Option<&Exchange>, values: &[String]) -> Option<Outline> {
    let r = e?.response.as_ref()?;
    let body = r.body.as_deref()?;
    outline(&r.content_type, body, values).filter(|o| !o.is_empty())
}

/// A multi-line error (a schema report) on one line, so JSON output keeps all of it.
fn one_line(m: &str) -> String {
    let s = re(r"(^|\s*\n\s*)(✖\s*)?").replace_all(m, " ");
    let s = re(r"\s*→\s*(at\s+)?").replace_all(&s, " at ");
    s.trim().to_string()
}

fn help(cmd: &str) -> &'static str {
    match cmd {
        "login" => r#"api-anything login <site|url> [--profile "Chrome/Profile 1"] [--window] [--cookies <file>]
  By default imports the site's cookies from your everyday browser (you are almost always already
  signed in there, so no password and no re-doing 2FA). Prints which profile was used and the cookie
  NAMES only (plus the profile's display name and Google account). The imported session is the SAME
  one as your browser: if the site logs it out, both go.
  <site|url>  a site name (linkedin), a domain (linkedin.com, www.linkedin.com) or a URL
  --profile   the browser profile to import from, e.g. "Chrome/Profile 1". Needed when several
              profiles are signed in to the site (possibly different people's accounts): login
              then lists them with their names and emails instead of guessing. The choice is
              remembered: a later automatic re-import uses the same profile.
  --window    open a visible Chrome window to sign in by hand (an independent session); also the
              automatic fallback when nothing is importable. This is where you solve 2FA/captchas.
  --cookies   import a cookies.txt (Netscape) or JSON export (Cookie-Editor / Playwright), for CI"#,
        "logout" => "api-anything logout <site>\n  Clears the stored cookie jar and this site's cookies in api-anything's Chrome profile.",
        "capture" => r#"api-anything capture <url> [--steps <json>] [--soft-from <url>] [--example k=v]... [--write] [--limit n] [--outline]
  Loads the page in Chrome and lists the requests it made, noise filtered and ranked (requests carrying
  the --example values first). Saves everything as a capture id for: add --from <id> --pick-request <n>,
  and for: inspect <id> <n>. Captures hold cookie values; the newest 20 are kept, none past 24 h.
  --steps      JSON array of {action: click|fill|press|wait|goto, selector?, value?, ms?}
  --soft-from  load this page first, then navigate in-app to <url> (SPAs only fire their data XHRs that way)
  --write      abort every non-GET request, and every xhr/fetch sent during --steps, before it leaves the browser
  --outline    for the top 3 candidates, summarize the response instead of making you inspect it: where the
               example values are, a suggested --extract and --pick fields with samples, JSON the page
               embeds (a ready --embedded regex), and a repeated HTML list as a ready --html recipe
  Output: capture (the id), candidates, next (what to do). blocked: the bot challenge the site served.
  pageStatus: the page's own HTTP error, when a request it loaded is recommended all the same."#,
        "inspect" => r#"api-anything inspect <captureId> [<requestId>] [--extract <path>] [--pick a,b] [--html <json>] [--embedded <regex>] [--outline --example k=v]
  No browser. Without a request id, lists every request in the capture. With one, shows its request and
  response through add's recipe flags, so a recipe is tried here first: --extract (also spelled --path),
  --pick, --html, --embedded. A path, selector or regex that finds nothing fails (exit 1). An empty
  list at a path is a result, and so is an --html items selector "<container> <item>" whose container
  is on the page with no item in it (data: [], with a note).
  --outline summarizes the response (as capture --outline does) instead of printing it."#,
        "add" => r#"api-anything add <site> <op> --trigger <url-template> --example k=v [--example2 k=v] [options]
  Runs the trigger twice in Chrome (with --example, then --example2 or --example again), picks the request
  carrying the example values, and saves the learned operation to ~/.api-anything/sites/<site>.json.
  --trigger       page URL with {param} placeholders, e.g. https://site.com/u/{name}
  --steps <json>  UI steps after load, [{action: click|fill|press|wait|goto, selector?, value?, ms?}];
                  {param} is filled in selector/value
  --soft-from     neutral page to load first, then navigate in-page to the trigger
  --match k=v     pin the request: method=, host=, path= (* = one segment), operationName= (or JSON)
  --from <id> --pick-request <n>   learn from a saved capture instead of running the trigger (no browser).
                  Every add saves its own runs as captures, so a wrong recipe is fixed this way: add the op
                  again --from the capture it was learned from, with the recipe flags (--extract, --pick,
                  --html, --embedded). With no --example the op's stored examples are used, so the capture
                  must carry them; from a capture made with other values, pass those with --example
  --from2 <id>    a second capture, made with the --example2 values, for the two-run diff; with --from,
                  --example2 needs it: capture the page again with those values
  --extract <path>  dot/bracket path into the response; [*] collects from every array item (sections[*].items)
  --pick a,b.c,name=x.y  fields kept per item; name=path renames the key, name=path~regex keeps regex group 1
  --html <json>   {"items":"<css>","fields":{"name":"<css>[@attr]"}} for server-rendered pages;
                  "all:<css>[@attr]" returns every match as a list (genres, tags)
  --embedded <regex>  JSON inside the page: group 1 marks where the JSON value starts; then --extract
  --public <name,...>  a header, or a credential-like field such as api_key, whose value is the same for every
                  visitor (a web app's bearer): kept literal unless the value is in a cookie or the page's
                  storage. A per-session field (token, csrf) stays a reference. Only when it is not the user's
  --write         the op changes state: it is learned from intercepted, aborted requests only. A request a
                  --write capture aborted, or an existing write learned again, needs --write: neither is
                  ever saved as a read
  --description <text>  what the op is for; an op added again with no --example keeps the one it had ("" clears it)
  Output: preview (what a call returns, from the captured response), warnings (read them), captures.
  replaced: an op of that name was learned again."#,
        "call" => "api-anything call <site> <op> [k=v ...] [--json <args-object>] [--allow-writes] [--max-tier 1|2|3] [--dry]\n  Calls an operation: {ok, class, data, tier, healed?, ms, next?}. --dry prints the request with credentials redacted.",
        "verify" => "api-anything verify [site]\n  Calls every read operation with its stored example args, healing as needed.",
        "sites" => "api-anything sites\n  Lists known sites (user specs in ~/.api-anything/sites win over bundled ones).",
        "ops" => "api-anything ops <site>\n  Lists a site's operations and params (with each param's format), and the site's notes: caveats,\n  arg formats and login advice from <site>.md beside its spec.",
        "heal" => "api-anything heal <site> <op> [k=v ...]\n  Forces a heal (rescan, then recapture) even when the op is marked stale. Reads only.",
        "export" => "api-anything export <site> [--out <file>] [--keep-examples] [--force]\n  Writes a shareable spec: examples and response shapes stripped, and refused if a live cookie or\n  session value is inside. --keep-examples keeps param examples you confirmed are public (so verify works).",
        "mcp" => "api-anything mcp [--allow-writes]\n  Serves list_sites, list_operations, call_operation and login over stdio MCP. MCP cannot create\n  operations (use capture/add here), and its login only refreshes a session a human imported here.",
        _ => "",
    }
}

fn usage() -> String {
    format!(
        "api-anything {VERSION}: turn a website into operations an agent can call.

  api-anything login <site|url> [--profile ... | --window | --cookies <file>]
  api-anything logout <site>
  api-anything capture <url> [--steps ...]
  api-anything add <site> <op> --trigger <url-template> --example k=v [--example2 k=v] [--write]
  api-anything call <site> <op> [k=v ...] [--allow-writes]
  api-anything inspect <captureId> [<requestId>]
  api-anything verify [site] | sites | ops <site> | heal <site> <op> | export <site> | mcp

api-anything <command> --help for details. Data lives in ~/.api-anything (API_ANYTHING_HOME overrides)."
    )
}

fn out(v: &Value) {
    println!("{}", json(v));
}

/// A command's failure: the message, what to do next, and extra fields for the JSON line.
#[derive(Debug)]
pub struct Fail {
    pub message: String,
    pub next: String,
    pub extra: Map<String, Value>,
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Fail {}

fn fail(message: impl Into<String>, next: impl Into<String>) -> anyhow::Error {
    Fail { message: message.into(), next: next.into(), extra: Map::new() }.into()
}

fn fail_with(message: impl Into<String>, next: impl Into<String>, extra: Map<String, Value>) -> anyhow::Error {
    Fail { message: message.into(), next: next.into(), extra }.into()
}

fn kv(list: &[String]) -> Result<IndexMap<String, String>> {
    let mut args = IndexMap::new();
    for item in list {
        let Some(eq) = item.find('=').filter(|i| *i >= 1) else { return Err(fail(format!("expected k=v, got \"{item}\""), "write args as name=value")) };
        args.insert(item[..eq].to_string(), item[eq + 1..].to_string());
    }
    Ok(args)
}

fn str_args(m: &IndexMap<String, String>) -> Args {
    m.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect()
}

/* ------------------------------------------------------------ arguments */

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Bool,
    Str,
    Multi,
}

const OPTIONS: &[(&str, Kind)] = &[
    ("help", Kind::Bool),
    ("version", Kind::Bool),
    ("example", Kind::Multi),
    ("example2", Kind::Multi),
    ("trigger", Kind::Str),
    ("steps", Kind::Str),
    ("soft-from", Kind::Str),
    ("match", Kind::Multi),
    ("from", Kind::Str),
    ("pick-request", Kind::Str),
    ("from2", Kind::Str),
    ("embedded", Kind::Str),
    ("public", Kind::Str),
    ("path", Kind::Str),
    ("keep-examples", Kind::Bool),
    ("extract", Kind::Str),
    ("pick", Kind::Str),
    ("html", Kind::Str),
    ("write", Kind::Bool),
    ("description", Kind::Str),
    ("json", Kind::Str),
    ("allow-writes", Kind::Bool),
    ("max-tier", Kind::Str),
    ("dry", Kind::Bool),
    ("limit", Kind::Str),
    ("out", Kind::Str),
    ("force", Kind::Bool),
    ("window", Kind::Bool),
    ("cookies", Kind::Str),
    ("profile", Kind::Str),
    ("outline", Kind::Bool),
];

#[derive(Default, Debug)]
pub struct Parsed {
    bools: Vec<String>,
    strs: IndexMap<String, String>,
    multis: IndexMap<String, Vec<String>>,
    pos: Vec<String>,
    steps: Option<Vec<TriggerStep>>,
}

impl Parsed {
    fn flag(&self, name: &str) -> bool {
        self.bools.iter().any(|b| b == name)
    }
    fn get(&self, name: &str) -> Option<&str> {
        self.strs.get(name).map(|s| s.as_str())
    }
    fn multi(&self, name: &str) -> Option<&Vec<String>> {
        self.multis.get(name)
    }
    fn given(&self) -> Vec<String> {
        let mut v: Vec<String> = self.bools.clone();
        v.extend(self.strs.keys().cloned());
        v.extend(self.multis.keys().cloned());
        v
    }
}

/// `parseArgs` with the options table: strict, long options only, `--k v` and `--k=v`.
fn parse_args(argv: &[String]) -> Result<Parsed> {
    let mut p = Parsed::default();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            p.pos.extend(argv[i + 1..].iter().cloned());
            break;
        }
        if a == "-h" {
            p.bools.push("help".into());
            i += 1;
            continue;
        }
        if let Some(rest) = a.strip_prefix("--") {
            let (name, inline) = match rest.find('=') {
                Some(eq) => (&rest[..eq], Some(rest[eq + 1..].to_string())),
                None => (rest, None),
            };
            let Some((_, kind)) = OPTIONS.iter().find(|(n, _)| *n == name) else { return Err(anyhow!("Unknown option '--{name}'. To specify a positional argument starting with a '-', place it at the end of the command after '--', as in '-- \"--{name}\"")) };
            match kind {
                Kind::Bool => {
                    if !p.bools.iter().any(|b| b == name) {
                        p.bools.push(name.to_string());
                    }
                    i += 1;
                }
                Kind::Str | Kind::Multi => {
                    let value = match inline {
                        Some(v) => v,
                        None => {
                            i += 1;
                            argv.get(i).cloned().ok_or_else(|| anyhow!("Option '--{name} <value>' argument missing"))?
                        }
                    };
                    if *kind == Kind::Str {
                        p.strs.insert(name.to_string(), value);
                    } else {
                        p.multis.entry(name.to_string()).or_default().push(value);
                    }
                    i += 1;
                }
            }
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            return Err(anyhow!("Unknown option '{a}'"));
        }
        p.pos.push(a.clone());
        i += 1;
    }
    Ok(p)
}

fn json_flag<T: serde::de::DeserializeOwned>(text: Option<&str>, flag: &str, command: &str) -> Result<Option<T>> {
    let Some(text) = text else { return Ok(None) };
    let why = |m: String| fail(format!("--{flag}: {}", one_line(&m)), format!("api-anything {command} --help shows --{flag}"));
    let v: Value = serde_json::from_str(text).map_err(|e| why(e.to_string()))?;
    // the schema's report says where the issue is, as zod's "→ at [0].selector" does
    serde_path_to_error::deserialize(v).map(Some).map_err(|e| {
        let path = e.path().to_string();
        let at = if path == "." { String::new() } else { format!(" at {path}") };
        why(format!("{}{at}", e.inner()))
    })
}

/// --steps. An unknown action is named here, with the ones that exist.
fn steps_of(text: Option<&str>, command: &str) -> Result<Option<Vec<TriggerStep>>> {
    let Some(text) = text else { return Ok(None) };
    let given: Value = json_flag::<Value>(Some(text), "steps", command)?.unwrap_or(Value::Null);
    if let Value::Array(items) = &given {
        for s in items {
            if let Some(a) = s.get("action").and_then(|a| a.as_str()) {
                if !StepAction::ALL.contains(&a) {
                    let upload = if a.to_lowercase().contains("upload") { " (file uploads are not supported)" } else { "" };
                    return Err(fail(format!("--steps: unknown action \"{a}\"{upload}; the actions are {}", StepAction::ALL.join(", ")), format!("api-anything {command} --help shows --steps")));
                }
            }
        }
    }
    json_flag::<Vec<TriggerStep>>(Some(text), "steps", command)
}

fn need_chrome() -> Result<()> {
    if !chrome_available() {
        return Err(fail("Google Chrome is not installed", "install Google Chrome, then retry"));
    }
    Ok(())
}

fn require_site(name: Option<&str>) -> Result<crate::store::Resolved> {
    let Some(name) = name else { return Err(fail("missing <site>", "api-anything sites")) };
    load_site(name)?.ok_or_else(|| fail(format!("no site \"{name}\""), "api-anything sites lists what exists; api-anything add creates one"))
}

fn examples_of(op: &Operation) -> Args {
    crate::heal::examples_of(op)
}

/* ------------------------------------------------------------- commands */

async fn run_window(site: &str, url: &str, login_cookies: Option<&[String]>, reason: Option<&str>) -> Result<i32> {
    need_chrome()?;
    eprintln!("{}Sign in to {url} in the Chrome window, then close it or press Enter here.", reason.map(|r| format!("{r} ")).unwrap_or_default());
    let cookies = login_window(url, &profile_dir(), true).await?;
    let file = session_file(site)?;
    let c2 = cookies.clone();
    with_lock(&file, || {
        let mut s = load_session(site)?;
        s.cookies = c2;
        s.source = Some("window".into());
        save_session(site, &s)
    })?;
    out(&j!({ "ok": true, "site": site, "source": "window", "cookies": cookie_names(&cookies), "loggedIn": is_logged_in(&cookies, login_cookies) }));
    Ok(0)
}

async fn cmd_login(p: &Parsed) -> Result<i32> {
    let Some(target) = p.pos.first() else { return Err(fail("missing <site|url>", "api-anything login <site|url>")) };
    let t = resolve_login_target(target).map_err(|e| fail(e.to_string(), "api-anything sites lists known sites; or pass a domain (linkedin.com) or a full https:// URL"))?;
    if p.flag("window") {
        return run_window(&t.site, &t.url, t.login_cookies.as_deref(), None).await;
    }
    let imported = match import_session(&t.site, &t.url, ImportOptions { login_cookies: t.login_cookies.clone(), profile: p.get("profile").map(|s| s.to_string()), file: p.get("cookies").map(|s| s.to_string()), push_profile: true }).await {
        Ok(i) => i,
        Err(e) => {
            if let Some(a) = e.downcast_ref::<AmbiguousProfile>() {
                let mut extra = Map::new();
                extra.insert("candidates".into(), serde_json::to_value(&a.candidates)?);
                return Err(fail_with(a.to_string(), format!("ask the user which account to use, then: api-anything login {} --profile \"<Browser/Profile>\" (one of candidates[].profile)", t.site), extra));
            }
            return Err(e);
        }
    };
    let Some(imported) = imported else {
        if let Some(f) = p.get("cookies") {
            return Err(fail(format!("no cookies for {} in {f}", t.site), "check the export is for the right site"));
        }
        if let Some(pr) = p.get("profile") {
            return Err(fail(format!("no importable cookies in profile \"{pr}\""), format!("run: api-anything login {} (scans every profile), or --window", t.site)));
        }
        return run_window(&t.site, &t.url, t.login_cookies.as_deref(), Some("No signed-in session found in your browsers.")).await;
    };
    let mut v = Map::new();
    v.insert("ok".into(), j!(true));
    v.insert("site".into(), j!(t.site));
    v.insert("source".into(), j!(imported.source));
    if imported.source != "file" {
        v.insert("profile".into(), j!(format!("{}/{}", imported.browser, imported.profile)));
    }
    if let Some(n) = &imported.name {
        v.insert("profileName".into(), j!(n));
    }
    if let Some(e) = &imported.email {
        v.insert("account".into(), j!(e));
    }
    v.insert("cookies".into(), j!(cookie_names(&imported.cookies)));
    v.insert("loggedIn".into(), j!(is_logged_in(&imported.cookies, t.login_cookies.as_deref())));
    out(&Value::Object(v));
    Ok(0)
}

async fn cmd_logout(p: &Parsed) -> Result<i32> {
    let Some(site) = p.pos.first() else { return Err(fail("missing <site>", "api-anything logout <site>")) };
    logout(site).await?;
    out(&j!({ "ok": true, "site": site, "loggedOut": true }));
    Ok(0)
}

fn positive(text: Option<&str>, flag: &str, command: &str) -> Result<Option<usize>> {
    let Some(t) = text else { return Ok(None) };
    if !re(r"^[1-9]\d*$").is_match(t) {
        return Err(fail(format!("--{flag} must be a positive integer, got \"{t}\""), format!("api-anything {command} --help")));
    }
    Ok(t.parse().ok())
}

struct PageSays {
    stop: Option<String>,
    also: Option<String>,
    status: Option<u16>,
}

/// What the page a capture ended on says about learning from it.
fn page_says(c: &CaptureFile, ranked: &[Candidate], values: &[String]) -> PageSays {
    let none = PageSays { stop: None, also: None, status: None };
    let pages: Vec<String> = capture_pages(&c.result).iter().map(|u| u.split('#').next().unwrap_or("").to_string()).collect();
    // the main frame's last document: a widget's iframe is a document too
    let Some(page) = c.result.exchanges.iter().filter(|e| e.resource_type == "document" && e.response.is_some() && pages.contains(&e.request.url)).last() else { return none };
    let Some(res) = &page.response else { return none };
    let status = res.status;
    let body = res.body.clone().unwrap_or_default();
    // A login path is where sign-in pages live, and where a public /docs/login/... page may too: it takes the form as well.
    if login_path(&c.result.final_url) && sign_in_form(&body) {
        return PageSays { stop: Some(format!("the page is a sign-in page: ask the user to run api-anything login <site>, then capture again (api-anything inspect {} {} shows the page, if it is what you wanted)", c.id, page.id)), also: None, status: None };
    }
    // What would be learned from: the candidates' answers. A beacon that echoes the page is not one.
    let asked: Vec<String> = values.iter().filter(|x| x.len() >= 3).map(|x| x.to_lowercase()).collect();
    let answers: Vec<String> = ranked.iter().map(|r| c.result.exchanges.iter().find(|e| e.id == r.id).map(|e| e.body().to_lowercase()).unwrap_or_default()).collect();
    let unseen = !asked.is_empty() && !answers.iter().any(|a| asked.iter().any(|x| a.contains(x)));
    let also = if !sign_in_form(&body) {
        None
    } else if unseen {
        Some(format!("none of the example values is in what these requests returned, and the page shows a sign-in form: check the example values (api-anything inspect {} <id> shows a response); if the data is missing, ask the user to run api-anything login <site>, then capture again", c.id))
    } else {
        Some("the page also shows a sign-in form: if the data you want is missing, ask the user to run api-anything login <site> first".to_string())
    };
    // An error is a dead end when the erroring page is itself what would be recommended.
    if status >= 400 && ranked.first().map(|r| r.id).unwrap_or(page.id) == page.id {
        return PageSays { stop: Some(format!("the page answered HTTP {status}: check the URL, then capture again{}", also.map(|a| format!("; {a}")).unwrap_or_default())), also: None, status: None };
    }
    PageSays { also, status: if status >= 400 { Some(status) } else { None }, stop: None }
}

fn wall_of(e: Option<&Exchange>) -> Option<String> {
    let r = e?.response.as_ref()?;
    bot_wall(&Observed { status: r.status, headers: r.headers.clone(), body: r.body.clone().unwrap_or_default(), url: None }, false, None)
}

async fn cmd_capture(p: &Parsed) -> Result<i32> {
    let Some(url) = p.pos.first() else { return Err(fail("missing <url>", "api-anything capture <url>")) };
    need_chrome()?;
    let limit = positive(p.get("limit"), "limit", "capture")?.unwrap_or(15);
    let examples = kv(p.multi("example").map(|v| v.as_slice()).unwrap_or(&[]))?;
    let args = str_args(&examples);
    let c = capture_page(CapturePageOptions { url: url.clone(), steps: p.steps.clone(), soft_from: p.get("soft-from").map(|s| s.to_string()), write: p.flag("write"), args: Some(args.clone()) }).await?;
    let ranked = rank_candidates(&c.result.exchanges, &args, RankOptions { all: false, pages: Some(page_urls(&c.result.exchanges, &capture_pages(&c.result))), second: None });
    let values: Vec<String> = examples.values().cloned().collect();
    let candidates: Vec<Value> = ranked
        .iter()
        .take(limit)
        .enumerate()
        .map(|(i, x)| {
            let mut v = Map::new();
            v.insert("id".into(), j!(x.id));
            v.insert("kind".into(), j!(x.resource_type));
            v.insert("method".into(), j!(x.method));
            v.insert("url".into(), j!(if x.url.chars().count() > 160 { format!("{}...", take_chars(&x.url, 157)) } else { x.url.clone() }));
            if let Some(s) = x.status {
                v.insert("status".into(), j!(s));
            }
            if let Some(ct) = x.content_type.as_ref().filter(|c| !c.is_empty()) {
                v.insert("type".into(), j!(ct.split(';').next().unwrap_or("")));
            }
            if let Some(o) = &x.operation_name {
                v.insert("operationName".into(), j!(o));
            }
            if !x.hits.is_empty() {
                v.insert("carries".into(), j!(x.hits));
            }
            v.insert("size".into(), j!(x.size));
            if p.flag("outline") && i < 3 {
                if let Some(o) = outline_of(c.result.exchanges.iter().find(|e| e.id == x.id), &values) {
                    v.insert("outline".into(), serde_json::to_value(o).unwrap_or(Value::Null));
                }
            }
            Value::Object(v)
        })
        .collect();
    let top = ranked.first();
    let html = top.map(|t| t.content_type.as_deref().unwrap_or("").to_lowercase().contains("html")).unwrap_or(false);
    // a bot wall is not fixed by picking another request or writing a recipe
    let doc = c.result.exchanges.iter().filter(|e| e.resource_type == "document" && e.response.is_some()).last();
    let top_ex = top.and_then(|t| c.result.exchanges.iter().find(|e| e.id == t.id));
    let wall = wall_of(doc).or_else(|| wall_of(top_ex));
    let page = if wall.is_some() { PageSays { stop: None, also: None, status: None } } else { page_says(&c, &ranked, &values) };
    let learn = if html {
        format!("the best candidate is the HTML page (server-rendered): api-anything inspect {} {} to read it, then add <site> <op> --from {} --pick-request {} --example k=v with --html '<recipe>' or --embedded '<regex>'", c.id, top.unwrap().id, c.id, top.unwrap().id)
    } else {
        format!("api-anything add <site> <op> --from {} --pick-request <id> --example k=v (api-anything inspect {} <id> shows a response)", c.id, c.id)
    };
    let mut v = Map::new();
    v.insert("capture".into(), j!(c.id));
    v.insert("finalUrl".into(), j!(c.result.final_url));
    v.insert("requests".into(), j!(c.result.exchanges.len()));
    v.insert("candidates".into(), Value::Array(candidates));
    if let Some(w) = &wall {
        v.insert("blocked".into(), j!(w));
    }
    if let Some(s) = page.status {
        v.insert("pageStatus".into(), j!(s));
    }
    let next = match (&wall, &page.stop, &page.also) {
        (Some(w), _, _) => format!("the site served a bot challenge ({w}): ask the user to run api-anything login <site> (clear the challenge in the window), then capture again"),
        (None, Some(s), _) => s.clone(),
        (None, None, Some(a)) => format!("{learn}; {a}"),
        _ => learn,
    };
    v.insert("next".into(), j!(next));
    out(&Value::Object(v));
    Ok(0)
}

/// JSON inside strings parsed in place, so the default view shows the data instead of an envelope around one long string.
fn unlayer(v: &Value, layers: usize) -> Value {
    match v {
        Value::String(s) => match if layers < 5 { inner_json(s) } else { None } {
            Some(inner) if inner.is_object() || inner.is_array() => unlayer(&inner, layers + 1),
            _ => v.clone(),
        },
        Value::Array(a) => Value::Array(a.iter().map(|x| unlayer(x, layers)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), unlayer(x, layers))).collect()),
        _ => v.clone(),
    }
}

fn cmd_inspect(p: &Parsed) -> Result<i32> {
    let Some(id) = p.pos.first() else { return Err(fail("missing <captureId>", "api-anything inspect --help")) };
    let c = load_capture(id)?;
    let Some(req_id) = p.pos.get(1) else {
        let requests: Vec<Value> = c
            .result
            .exchanges
            .iter()
            .map(|e| {
                let mut v = Map::new();
                v.insert("id".into(), j!(e.id));
                v.insert("kind".into(), j!(e.resource_type));
                v.insert("method".into(), j!(e.request.method));
                v.insert("url".into(), j!(take_chars(&e.request.url, 160)));
                if let Some(r) = &e.response {
                    v.insert("status".into(), j!(r.status));
                    v.insert("type".into(), j!(r.content_type.split(';').next().unwrap_or("")));
                    v.insert("size".into(), j!(r.body.as_ref().map(|b| crate::util::js_len(b)).unwrap_or(0)));
                }
                if e.aborted {
                    v.insert("aborted".into(), j!(true));
                }
                Value::Object(v)
            })
            .collect();
        out(&j!({ "capture": c.id, "url": c.url, "requests": requests }));
        return Ok(0);
    };
    let Some(e) = req_id.parse::<u64>().ok().and_then(|n| c.result.exchanges.iter().find(|x| x.id == n)) else { return Err(fail(format!("no request {req_id} in capture {id}"), format!("api-anything inspect {id}"))) };
    if p.flag("outline") {
        let values: Vec<String> = kv(p.multi("example").map(|v| v.as_slice()).unwrap_or(&[]))?.values().cloned().collect();
        let mut v = j!({ "id": e.id, "request": { "method": e.request.method, "url": e.request.url } });
        if let Some(o) = outline_of(Some(e), &values) {
            v["outline"] = serde_json::to_value(o)?;
        }
        out(&v);
        return Ok(0);
    }
    let html: Option<HtmlRecipe> = json_flag(p.get("html"), "html", "inspect")?;
    let path = p.get("extract").or_else(|| p.get("path"));
    let body = e.body().to_string();
    // A recipe that finds nothing says so: no data field, or [] from a selector, reads as "no results".
    let nothing = |what: &str| fail(format!("{what} in request {}'s response", e.id), format!("api-anything inspect {id} {} --outline --example k=v suggests a recipe; with no recipe flag it prints the whole response", e.id));
    let mut data: Value = Value::String(body.clone());
    let mut note: Option<String> = None;
    if let Some(h) = &html {
        data = extract(&ResponseSpec { format: Format::Html, html: Some(h.clone()), ..Default::default() }, &body)?.unwrap_or(Value::Null);
        if data.as_array().map(|a| a.is_empty()).unwrap_or(true) {
            // a results page with no results is an answer, as a call would give it; a selector that is not there is not
            if !empty_results(&body, &h.items) {
                return Err(nothing(&format!("the --html items selector \"{}\" matched nothing", h.items)));
            }
            note = Some(format!("no items: the container of \"{}\" is on the page and empty, so this is a page with no results", h.items));
        }
    } else if let Some(regex) = p.get("embedded") {
        data = extract(&ResponseSpec { format: Format::Embedded, embedded: Some(crate::spec::Embedded { regex: regex.to_string() }), ..Default::default() }, &body)?.ok_or_else(|| nothing("the --embedded regex found no JSON"))?;
    } else if !e.response.as_ref().map(|r| r.content_type.to_lowercase().contains("html")).unwrap_or(false) {
        if let Ok(Some(d)) = extract(&ResponseSpec::default(), &body) {
            data = d; // not JSON: show the text
        }
    }
    if let Some(path) = path {
        // an empty list at the path is a result; a path that is not there is not
        data = get_path(&data, Some(path)).ok_or_else(|| nothing(&format!("nothing at \"{path}\"")))?;
    }
    if let Some(pk) = p.get("pick") {
        data = pick(&data, &split_pick(pk))?;
    }
    let sent = e.request.body.as_deref();
    let form = sent.map(|s| re(r"(?i)x-www-form-urlencoded").is_match(e.request.headers.get("content-type").map(|c| c.as_str()).unwrap_or("")) && !crate::util::is_json_text(s)).unwrap_or(false);
    let shown_body = sent.map(|s| {
        if form {
            let pairs: Map<String, Value> = url::form_urlencoded::parse(s.as_bytes()).map(|(k, v)| (k.into_owned(), Value::String(v.into_owned()))).collect();
            unlayer(&Value::Object(pairs), 0)
        } else {
            unlayer(&Value::String(s.to_string()), 0)
        }
    });
    let mut v = Map::new();
    v.insert("id".into(), j!(e.id));
    let mut request = j!({ "method": e.request.method, "url": e.request.url });
    if let Some(b) = shown_body {
        request["body"] = cap_output(&b, 4000).data;
    }
    v.insert("request".into(), request);
    match &e.response {
        Some(r) => {
            v.insert("status".into(), j!(r.status));
            v.insert("type".into(), j!(r.content_type));
        }
        None => {
            v.insert("aborted".into(), j!(e.aborted));
        }
    }
    let capped = cap_output(&unlayer(&data, 0), 20_000);
    v.insert("data".into(), capped.data);
    if let Some(t) = capped.truncated {
        v.insert("truncated".into(), j!(t));
    }
    if let Some(n) = note {
        v.insert("note".into(), j!(n));
    }
    out(&Value::Object(v));
    Ok(0)
}

/// One shell word, quoted: a space, a quote or JSON in a hint's command pastes as a single argument.
fn sh(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The command that repeats how capture `c` was made, with the second example's values where the first's sit.
fn capture_again(c: &CaptureFile, ex1: &IndexMap<String, String>, ex2: &IndexMap<String, String>, write: bool) -> Option<String> {
    let made = capture_trigger(c, &str_args(ex1));
    if ex2.is_empty() || ex1.keys().any(|k| !ex2.contains_key(k)) || !unplaced(&made, &str_args(ex2)).is_empty() {
        return None;
    }
    let t = fill_trigger(&made, &str_args(ex2));
    let mut parts = vec![format!("api-anything capture {}", sh(&t.url))];
    if let Some(sf) = &t.soft_from {
        parts.push(format!("--soft-from {}", sh(sf)));
    }
    if let Some(steps) = &t.steps {
        parts.push(format!("--steps {}", sh(&json(&serde_json::to_value(steps).ok()?))));
    }
    if write {
        parts.push("--write".into());
    }
    for (k, x) in ex2 {
        parts.push(format!("--example {}", sh(&format!("{k}={x}"))));
    }
    Some(parts.join(" "))
}

async fn cmd_add(p: &Parsed) -> Result<i32> {
    let (Some(site), Some(name)) = (p.pos.first(), p.pos.get(1)) else { return Err(fail("missing <site> <op>", "api-anything add --help")) };
    if p.get("trigger").is_none() && p.get("from").is_none() {
        return Err(fail("missing --trigger (or --from <captureId>)", "api-anything add --help"));
    }
    let ex1 = kv(p.multi("example").map(|v| v.as_slice()).unwrap_or(&[]))?;
    let ex2 = match p.multi("example2") {
        Some(v) => Some(kv(v)?),
        None => None,
    };
    let match_text: Option<String> = match p.multi("match") {
        Some(m) if m.len() == 1 && m[0].trim().starts_with('{') => Some(m[0].clone()),
        Some(m) => Some(json(&Value::Object(kv(m)?.into_iter().map(|(k, v)| (k, Value::String(v))).collect()))),
        None => None,
    };
    let matcher: Option<Match> = json_flag(match_text.as_deref(), "match", "add")?;
    let html: Option<HtmlRecipe> = json_flag(p.get("html"), "html", "add")?;
    if p.get("from").is_none() {
        need_chrome()?;
    }
    if p.get("from2").is_some() && ex2.is_none() {
        return Err(fail("--from2 needs --example2 (the values that capture was made with)", "api-anything add --help"));
    }
    if let (Some(from), Some(e2), None) = (p.get("from"), &ex2, p.get("from2")) {
        let c = load_capture(from)?;
        let write = c.write || p.flag("write");
        let again = capture_again(&c, &ex1, e2, write);
        let next = match again {
            Some(a) => format!("capture the page again with the second example's values: {a}"),
            None => {
                let how: Vec<&str> = [Some("its url"), c.soft_from.as_ref().map(|_| "--soft-from"), c.steps.as_ref().map(|_| "--steps"), if write { Some("--write") } else { None }].into_iter().flatten().collect();
                format!("the first example's values are not in capture {}'s url or steps, so the command cannot be written out: capture that page again the way {} was made ({}), with the second example's values", c.id, c.id, how.join(", "))
            }
        };
        return Err(fail("--example2 with --from needs --from2: a capture holds one run", format!("{next}; then run this add again with --from2 <the new capture's id>")));
    }
    let trigger = p.get("trigger").map(|t| Trigger { url: t.to_string(), steps: p.steps.clone(), soft_from: p.get("soft-from").map(|s| s.to_string()) });
    let mut examples = vec![str_args(&ex1)];
    if let Some(e2) = &ex2 {
        examples.push(str_args(e2));
    }
    let recipe = Recipe {
        extract: p.get("extract").map(|s| s.to_string()),
        pick: p.get("pick").map(split_pick),
        html,
        embedded: p.get("embedded").map(|r| crate::spec::Embedded { regex: r.to_string() }),
    };
    let r = add_operation(AddInput {
        site: site.clone(),
        op: name.clone(),
        trigger,
        examples,
        matcher,
        write: p.flag("write"),
        description: p.get("description").map(|s| s.to_string()),
        response: Some(recipe),
        public: p.get("public").map(|s| s.split(',').map(|x| x.trim().to_lowercase()).collect()),
        from: match p.get("from") {
            Some(f) => Some(FromCapture { capture: load_capture(f)?, id: p.get("pick-request").and_then(|n| n.parse().ok()) }),
            None => None,
        },
        from2: match p.get("from2") {
            Some(f) => Some(load_capture(f)?),
            None => None,
        },
        fetcher: None,
    })
    .await?;
    let op = &r.operation;
    let mut v = Map::new();
    v.insert("ok".into(), j!(true));
    v.insert("site".into(), j!(site));
    v.insert("op".into(), j!(op.name));
    if r.replaced {
        v.insert("replaced".into(), j!(true));
    }
    v.insert("request".into(), j!(format!("{} {}", op.request.method, op.request.url.split('?').next().unwrap_or(""))));
    v.insert("params".into(), j!(op.params.iter().map(|x| format!("{}:{}", x.name, x.kind.name())).collect::<Vec<_>>()));
    v.insert("readOnly".into(), j!(op.read_only));
    v.insert("minTier".into(), j!(op.min_tier));
    v.insert("match".into(), serde_json::to_value(&op.matcher)?);
    if let Some(e) = &op.response.extract {
        v.insert("extract".into(), j!(e));
    }
    if let Some(pv) = &r.preview {
        v.insert("preview".into(), serde_json::to_value(pv)?);
    }
    v.insert("warnings".into(), j!(r.warnings));
    if !r.captures.is_empty() {
        v.insert("captures".into(), j!(r.captures));
    }
    v.insert("saved".into(), j!(r.path));
    v.insert("next".into(), j!(format!("api-anything call {site} {} {}", op.name, op.params.iter().map(|x| format!("{}=...", x.name)).collect::<Vec<_>>().join(" ")).trim()));
    out(&Value::Object(v));
    Ok(0)
}

async fn cmd_call(p: &Parsed) -> Result<i32> {
    let (Some(site), Some(name)) = (p.pos.first(), p.pos.get(1)) else { return Err(fail("missing <site> <op>", "api-anything call --help")) };
    if let Some(t) = p.get("max-tier") {
        if !["1", "2", "3"].contains(&t) {
            return Err(fail(format!("--max-tier must be 1, 2 or 3, got \"{t}\""), "pass --max-tier 1, 2 or 3"));
        }
    }
    let mut args: Args = json_flag::<Map<String, Value>>(p.get("json"), "json", "call")?.unwrap_or_default();
    for (k, v) in kv(&p.pos[2..])? {
        args.insert(k, Value::String(v));
    }
    if p.flag("dry") {
        let r = require_site(Some(site))?;
        let Some(op) = r.site.operations.iter().find(|o| &o.name == name) else { return Err(fail(format!("no operation \"{name}\" on {site}"), format!("api-anything ops {site}"))) };
        let real = load_session(site)?;
        // Placeholders in place of every credential, so --dry output is safe to paste anywhere.
        let redacted = Session {
            cookies: real.cookies.iter().map(|c| crate::types::StoredCookie { value: format!("<{}>", c.name), ..c.clone() }).collect(),
            values: real.values.keys().map(|k| (k.clone(), format!("<{k}>"))).collect(),
            source: None,
            updated_at: None,
        };
        out(&j!({ "ok": true, "dry": true, "request": build_request(op, &args, &redacted)? }));
        return Ok(0);
    }
    let max_tier = p.get("max-tier").and_then(|t| t.parse().ok());
    let r = call(site, name, args, CallOptions { allow_writes: p.flag("allow-writes"), max_tier, ..Default::default() }).await;
    out(&serde_json::to_value(&r)?);
    if !r.ok {
        eprintln!("next: {}", r.next.clone().unwrap_or_default());
    }
    Ok(if r.ok { 0 } else { 1 })
}

async fn cmd_verify(p: &Parsed) -> Result<i32> {
    let names = match p.pos.first() {
        Some(n) => vec![require_site(Some(n))?.site.name],
        None => list_sites(),
    };
    let mut results: Vec<Value> = Vec::new();
    for name in names {
        let ops = match require_site(Some(&name)) {
            Ok(r) => r.site.operations,
            Err(e) => {
                results.push(j!({ "site": name, "ok": false, "error": e.to_string() }));
                continue;
            }
        };
        for op in ops {
            if !op.read_only {
                continue;
            }
            let args = examples_of(&op);
            let missing: Vec<String> = op.params.iter().filter(|x| x.required && args.get(&x.name).is_none() && x.default.is_none()).map(|x| x.name.clone()).collect();
            if !missing.is_empty() {
                results.push(j!({ "site": name, "op": op.name, "ok": false, "skipped": format!("no example for {}", missing.join(", ")) }));
                continue;
            }
            let r = call(&name, &op.name, args, CallOptions::default()).await;
            let mut v = Map::new();
            v.insert("site".into(), j!(name));
            v.insert("op".into(), j!(op.name));
            v.insert("ok".into(), j!(r.ok));
            v.insert("class".into(), j!(r.class));
            if let Some(t) = r.tier {
                v.insert("tier".into(), j!(t));
            }
            if r.healed == Some(true) {
                v.insert("healed".into(), j!(true));
            }
            if !r.ok {
                v.insert("reason".into(), j!(r.reason));
                v.insert("next".into(), j!(r.next));
            }
            v.insert("ms".into(), j!(r.ms));
            results.push(Value::Object(v));
        }
    }
    let ok = results.iter().all(|r| r.get("ok") == Some(&Value::Bool(true)));
    out(&j!({ "ok": ok, "results": results }));
    if !ok {
        eprintln!("next: follow each failing op's own next hint once, then report what still fails");
    }
    Ok(if ok { 0 } else { 1 })
}

fn cmd_sites() -> Result<i32> {
    let list: Vec<Value> = list_sites()
        .into_iter()
        .map(|name| match load_site(&name) {
            Ok(Some(r)) => {
                let mut v = j!({ "name": name, "source": r.source, "operations": r.site.operations.len() });
                if let Some(d) = &r.site.description {
                    v["description"] = j!(d);
                }
                v
            }
            Ok(None) => j!({ "name": name, "error": format!("no site \"{name}\"") }),
            Err(e) => j!({ "name": name, "error": e.to_string() }),
        })
        .collect();
    out(&Value::Array(list));
    Ok(0)
}

fn cmd_ops(p: &Parsed) -> Result<i32> {
    let r = require_site(p.pos.first().map(|s| s.as_str()))?;
    let site = r.site;
    let notes = site_notes(&site.name);
    let about = |x: &crate::spec::Param| -> Vec<String> {
        let mut v = Vec::new();
        if let Some(d) = &x.description {
            v.push(d.clone());
        }
        if let Some(e) = &x.example {
            v.push(format!("e.g. {}", json(e)));
        }
        if let Some(h) = &x.hint {
            v.push(h.clone());
        } else if let Some(pat) = &x.pattern {
            v.push(format!("matches /{pat}/"));
        }
        v
    };
    let operations: Vec<Value> = site
        .operations
        .iter()
        .map(|o| {
            let mut v = Map::new();
            v.insert("name".into(), j!(o.name));
            if let Some(d) = &o.description {
                v.insert("description".into(), j!(d));
            }
            v.insert("readOnly".into(), j!(o.read_only));
            if let Some(rf) = returned_fields(&o.response) {
                v.insert("returns".into(), j!(rf));
            }
            v.insert(
                "params".into(),
                j!(o.params.iter().map(|x| {
                    let a = about(x);
                    format!("{}:{}{}{}", x.name, x.kind.name(), if x.required { "" } else { "?" }, if a.is_empty() { String::new() } else { format!(" ({})", a.join("; ")) })
                }).collect::<Vec<_>>()),
            );
            if o.min_tier > 1 {
                v.insert("minTier".into(), j!(o.min_tier));
            }
            v.insert("trigger".into(), j!(o.trigger.url));
            Value::Object(v)
        })
        .collect();
    let mut v = j!({ "site": site.name, "baseUrl": site.base_url, "operations": operations });
    if let Some(n) = notes {
        v["notes"] = j!(n);
    }
    out(&v);
    Ok(0)
}

async fn cmd_heal(p: &Parsed) -> Result<i32> {
    let (Some(site), Some(name)) = (p.pos.first(), p.pos.get(1)) else { return Err(fail("missing <site> <op>", "api-anything heal <site> <op>")) };
    let r = require_site(Some(site))?;
    let mut args: Args = r.site.operations.iter().find(|o| &o.name == name).map(examples_of).unwrap_or_default();
    for (k, v) in kv(&p.pos[2..])? {
        args.insert(k, Value::String(v));
    }
    let res = heal(site, name, args, CallOptions::default()).await;
    out(&serde_json::to_value(&res)?);
    if !res.ok {
        eprintln!("next: {}", res.next.clone().unwrap_or_default());
    }
    Ok(if res.ok { 0 } else { 1 })
}

fn cmd_export(p: &Parsed) -> Result<i32> {
    let name = p.pos.first().map(|s| s.as_str());
    require_site(name)?;
    let r = export_site(name.unwrap_or(""), p.flag("keep-examples"))?;
    if !r.secrets.is_empty() && !p.flag("force") {
        let mut extra = Map::new();
        extra.insert("secrets".into(), j!(r.secrets));
        return Err(fail_with(format!("refusing to export: {} live credential(s) in the spec", r.secrets.len()), "remove them (re-add the op or edit the spec); --force only if a human confirmed they are public", extra));
    }
    for w in &r.warnings {
        eprintln!("warning: {w}");
    }
    let text = format!("{}\n", json_pretty(&serde_json::to_value(&r.spec)?, 2));
    match p.get("out") {
        Some(file) => {
            std::fs::write(file, &text)?;
            out(&j!({ "ok": true, "out": file, "warnings": r.warnings.len() }));
        }
        None => print!("{text}"),
    }
    Ok(0)
}

async fn cmd_mcp(p: &Parsed) -> Result<i32> {
    serve_stdio(p.flag("allow-writes")).await?;
    Ok(-1) // keep serving
}

/// Each command and the flags it takes: run() refuses any other, so none is silently ignored.
const COMMANDS: &[(&str, &[&str])] = &[
    ("login", &["profile", "window", "cookies"]),
    ("logout", &[]),
    ("capture", &["steps", "soft-from", "example", "write", "limit", "outline"]),
    ("inspect", &["path", "extract", "pick", "html", "embedded", "outline", "example"]),
    ("add", &["trigger", "example", "example2", "steps", "soft-from", "match", "from", "pick-request", "from2", "extract", "pick", "html", "embedded", "public", "write", "description"]),
    ("call", &["json", "allow-writes", "max-tier", "dry"]),
    ("verify", &[]),
    ("sites", &[]),
    ("ops", &[]),
    ("heal", &[]),
    ("export", &["out", "keep-examples", "force"]),
    ("mcp", &["allow-writes"]),
];

async fn run(argv: &[String]) -> Result<i32> {
    let mut p = parse_args(argv)?;
    if p.flag("version") {
        println!("{VERSION}");
        return Ok(0);
    }
    let cmd = p.pos.first().cloned();
    let spec = cmd.as_ref().and_then(|c| COMMANDS.iter().find(|(n, _)| n == c));
    let Some((name, flags)) = spec else {
        println!("{}", usage());
        if cmd.is_none() || p.flag("help") {
            return Ok(0);
        }
        eprintln!("next: unknown command \"{}\"; see the list above", cmd.unwrap_or_default());
        return Ok(1);
    };
    if p.flag("help") {
        println!("{}", help(name));
        return Ok(0);
    }
    let extra: Vec<String> = p.given().into_iter().filter(|k| !flags.contains(&k.as_str())).collect();
    if !extra.is_empty() {
        return Err(fail(format!("{name} does not take --{}", extra.join(", --")), format!("api-anything {name} --help lists its flags")));
    }
    p.steps = steps_of(p.get("steps"), name)?;
    p.pos.remove(0);
    match *name {
        "login" => cmd_login(&p).await,
        "logout" => cmd_logout(&p).await,
        "capture" => cmd_capture(&p).await,
        "inspect" => cmd_inspect(&p),
        "add" => cmd_add(&p).await,
        "call" => cmd_call(&p).await,
        "verify" => cmd_verify(&p).await,
        "sites" => cmd_sites(),
        "ops" => cmd_ops(&p),
        "heal" => cmd_heal(&p).await,
        "export" => cmd_export(&p),
        "mcp" => cmd_mcp(&p).await,
        _ => unreachable!(),
    }
}

/// The CLI's entry: runs the command, closes the browser, and returns the exit code.
pub async fn main_with(argv: Vec<String>) -> i32 {
    match run(&argv).await {
        Ok(code) => {
            if code >= 0 {
                close_browser().await;
            }
            code.max(0)
        }
        Err(e) => {
            close_browser().await;
            let f = e.downcast_ref::<Fail>();
            let mut v = Map::new();
            v.insert("ok".into(), j!(false));
            v.insert("error".into(), j!(one_line(&e.to_string())));
            if let Some(f) = f {
                for (k, x) in &f.extra {
                    v.insert(k.clone(), x.clone());
                }
            }
            out(&Value::Object(v));
            let next = match f {
                Some(f) => f.next.clone(),
                None if e.downcast_ref::<ProfileInUse>().is_some() => PROFILE_HINT.to_string(),
                None => crate::util::squash_ws(&format!("api-anything {} --help", argv.first().cloned().unwrap_or_default())),
            };
            eprintln!("next: {next}");
            1
        }
    }
}
