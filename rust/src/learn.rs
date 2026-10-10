//! Captured exchanges + example args -> an Operation (DESIGN.md "Learning", steps 1-8).
//! Only example-arg values become params; everything else is kept verbatim.
use crate::codec::{
    Leaf, Step, TemplatePart, covers, escape_str, escape_template, fill_slot_template, fill_template, get_at, header_name, last_token,
    leaf_name, set_text, step_key, template_parts, template_refs, walk,
};
use crate::extract::{infer_shape, inner_json, parse_body, xssi_of};
use crate::secrets::{
    SESSION_FIELD, SESSION_HEADER, URLISH, credential_name, high_entropy, is_credential, opaque_token, scan_secrets, strip_quotes,
};
use crate::session::{Session, logged_in, parse_cookie_header};
use crate::spec::{
    Charset, Escape, Format, Match, Operation, Param, ParamType, Request, ResponseSpec, Shape, Slot, Transform, Trigger, Volatile,
};
use crate::types::{CaptureResult, Exchange, StoredCookie};
use crate::util::{as_text, decode_uri_component, encode_uri_component, iso_now, js_len, json, json_escape, now_ms, parse_url, re};
use anyhow::{Result, anyhow, bail};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::LazyLock;

pub type Args = Map<String, Value>;

pub type Accepts = Box<dyn Fn(&Exchange) -> bool>;

pub struct LearnInput {
    pub exchanges: Vec<Exchange>,
    /// the second trigger run, made with examples[1]
    pub exchanges2: Option<Vec<Exchange>>,
    /// one or two example arg sets
    pub examples: Vec<Args>,
    pub cookies: Vec<StoredCookie>,
    pub matcher: Option<Match>,
    /// exchange id to learn from, when the agent already chose one
    pub id: Option<u64>,
    pub name: String,
    pub trigger: Trigger,
    pub read_only: bool,
    pub login_cookies: Option<Vec<String>>,
    /// header or field names a human marked as public constants: kept literal, never session refs
    pub public: Option<Vec<String>>,
    /// the page origin's localStorage/sessionStorage at capture time: a request repeating a value is a session: ref
    pub storage: Option<IndexMap<String, String>>,
    /// when several requests carry the values, prefer one this accepts (the response recipe resolves on it)
    pub accepts: Option<Accepts>,
    /// where the page was during the capture (capture_pages): an echo of these is not evidence
    pub pages: Option<Vec<String>>,
}

impl LearnInput {
    pub fn new(exchanges: Vec<Exchange>, examples: Vec<Args>, name: &str, trigger: Trigger, read_only: bool) -> LearnInput {
        LearnInput {
            exchanges,
            exchanges2: None,
            examples,
            cookies: vec![],
            matcher: None,
            id: None,
            name: name.to_string(),
            trigger,
            read_only,
            login_cookies: None,
            public: None,
            storage: None,
            accepts: None,
            pages: None,
        }
    }
    fn args1(&self) -> &Args {
        &self.examples[0]
    }
    fn args2(&self) -> Option<&Args> {
        self.examples.get(1)
    }
}

#[derive(Debug)]
pub struct Learned {
    pub operation: Operation,
    /// the captured request it was learned from
    pub exchange: Exchange,
    /// run 2's request the two-run diff read, when it found one
    pub exchange2: Option<Exchange>,
    pub warnings: Vec<String>,
    /// literal values of session: refs, for the session store; never written to the spec
    pub session_values: IndexMap<String, String>,
}

pub fn args_of(pairs: &[(&str, &str)]) -> Args {
    pairs.iter().map(|(k, v)| (k.to_string(), Value::String(v.to_string()))).collect()
}

/* ------------------------------------------------------------------ noise */

pub static ASSET_EXT: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(r"(?i)\.(js|mjs|cjs|jsx|ts|css|scss|png|jpe?g|gif|svg|webp|avif|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|wasm|map|pdf|zip)$")
});
const DENY_RESOURCE: [&str; 12] = [
    "image",
    "font",
    "stylesheet",
    "script",
    "media",
    "manifest",
    "texttrack",
    "websocket",
    "eventsource",
    "preflight",
    "ping",
    "cspviolationreport",
];
static DENY_MIME: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(r"(?i)^(image|font|video|audio)/|^text/(css|javascript)|^application/(javascript|x-javascript|font|octet-stream|wasm)")
});
static ANALYTICS: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(
        r"(?i)google-analytics\.com|googletagmanager\.com|doubleclick\.net|sentry\.io|/sentry/|segment\.(io|com)|mixpanel\.com|amplitude\.com|hotjar\.com|facebook\.com/tr|clarity\.ms|nr-data\.net|datadoghq|/(collect|beacon|log_event|telemetry|jot|csp-report|client_event|tracking|logging)(/|\?|$)",
    )
});
static MEDIA_MIME: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^(image|font|video|audio)/"));
// Pages and APIs can end in .js (github.com/vercel/next.js, /repos/chart.js): the extension only means an asset for subresources.
const DATA_RESOURCE: [&str; 3] = ["document", "xhr", "fetch"];

fn is_noise(e: &Exchange) -> bool {
    if e.request.method.eq_ignore_ascii_case("OPTIONS") {
        return true;
    }
    if DENY_RESOURCE.contains(&e.resource_type.to_lowercase().as_str()) {
        return true;
    }
    let Some(url) = parse_url(&e.request.url) else { return true };
    if (!DATA_RESOURCE.contains(&e.resource_type.as_str()) && ASSET_EXT.is_match(url.path())) || ANALYTICS.is_match(&e.request.url) {
        return true;
    }
    if e.aborted {
        return false;
    }
    let Some(r) = &e.response else { return true };
    if (300..400).contains(&r.status) {
        return true;
    }
    // Media is never data, even fetched by XHR (video segments); otherwise XHR/fetch are data by
    // definition: Instagram's GraphQL answers JSON as text/javascript.
    if MEDIA_MIME.is_match(&r.content_type) {
        return true;
    }
    e.resource_type != "xhr" && e.resource_type != "fetch" && DENY_MIME.is_match(&r.content_type)
}

/* ------------------------------------------------------------- candidates */

#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub resource_type: String,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub operation_name: Option<String>,
    /// params whose example value the request carries
    pub hits: Vec<String>,
    pub size: usize,
    pub score: i64,
}

// The page URL rides along in these on every XHR, so they say nothing about which request carries the args.
const NOT_EVIDENCE: [&str; 3] = ["header:cookie", "header:referer", "header:origin"];

fn not_evidence(at: &[Step]) -> bool {
    NOT_EVIDENCE.contains(&at[0].as_str())
}

/// Lower-cased and percent-decoded (up to 3 layers, + as a space): a location reads the same in any leaf.
fn norm(s: &str) -> String {
    let mut out = s.to_lowercase();
    for _ in 0..3 {
        let Some(next) = decode_uri_component(&out.replace('+', " ")) else { break };
        if next == out {
            break;
        }
        out = next;
    }
    out.replace('+', " ")
}

/// Every URL a run's page had: its main frame's locations (pushState included) and where it ended.
pub fn capture_pages(c: &CaptureResult) -> Vec<String> {
    let mut out: Vec<String> = c.locations.clone().unwrap_or_default();
    out.push(c.final_url.clone());
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

/// The pages a capture ran on: its documents, every Referer, and any extra (the filled trigger, capture_pages).
pub fn page_urls(exchanges: &[Exchange], extra: &[String]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for u in extra {
        if seen.insert(u.clone()) {
            urls.push(u.clone());
        }
    }
    for e in exchanges {
        if e.resource_type == "document" && seen.insert(e.request.url.clone()) {
            urls.push(e.request.url.clone());
        }
        if let Some(r) = e.request.headers.get("referer") {
            if seen.insert(r.clone()) {
                urls.push(r.clone());
            }
        }
    }
    urls
}

#[derive(Clone, Debug, Default)]
pub struct Locations {
    abs: Vec<String>,
    rel: Vec<String>,
}

/// What a page's location looks like when a script echoes it (normalized): absolute forms (href,
/// origin) anywhere in a leaf, relative ones (path, search) at its start.
fn locations(pages: &[String]) -> Locations {
    let mut abs: Vec<String> = Vec::new();
    let mut rel: Vec<String> = Vec::new();
    for p in pages {
        let Some(u) = parse_url(p) else { continue };
        let origin = crate::util::origin_of(&u);
        let path = u.path().to_string();
        let search = crate::util::search_of(&u);
        for s in [format!("{origin}{path}{search}"), format!("{origin}{path}"), origin.clone()] {
            let n = norm(&s);
            if !abs.contains(&n) {
                abs.push(n);
            }
        }
        for s in [format!("{path}{search}"), path.clone(), search.clone()] {
            if s.len() > 1 {
                let n = norm(&s);
                if !rel.contains(&n) {
                    rel.push(n);
                }
            }
        }
    }
    Locations { abs, rel }
}

/// A leaf that holds the page's own location around the value (analytics `context.page.url`, an
/// x-page-path header, `src=`/`redirect=` params) is an echo, not evidence.
fn echoes(text: &str, v: &str, locs: &Locations) -> bool {
    let want = norm(v);
    let t = norm(text);
    let of = |l: &String| l.len() > want.len() && l.contains(&want);
    locs.abs.iter().any(|l| of(l) && t.contains(l.as_str())) || locs.rel.iter().any(|l| of(l) && t.starts_with(l.as_str()))
}

fn flags(v: &Value) -> bool {
    static WORD: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^\w{0,8}$"));
    match v {
        Value::Null | Value::Bool(_) => true,
        Value::String(s) => WORD.is_match(s),
        Value::Object(o) => o.values().all(flags),
        Value::Array(a) => a.iter().all(flags),
        Value::Number(_) => false,
    }
}

/// A 2xx that carries no data: empty, or a tiny body of flags (`{"success":true}`, `OK`): a beacon's answer.
fn is_ack(e: &Exchange) -> bool {
    let Some(r) = &e.response else { return false };
    if !(200..300).contains(&r.status) {
        return false;
    }
    let body = r.body.as_deref().unwrap_or("").trim();
    if js_len(body) > 100 {
        return false;
    }
    match try_parse(Some(body)) {
        Some(data) => flags(&data),
        None => flags(&Value::String(body.to_string())),
    }
}

/// An answer without data that does not carry an example value either: however small, an answer with one is data.
fn dataless(e: &Exchange, args: &Args) -> bool {
    let answer = e.body().to_lowercase();
    is_ack(e) && !example_values(args).iter().any(|(_, v)| js_len(v) >= 3 && answer.contains(v.as_str()))
}

/// A data answer: a captured 2xx that is not data-less. A request nobody answered, or an error, is not one.
fn has_data(e: &Exchange, args: &Args) -> bool {
    let status = e.status().unwrap_or(0);
    (200..300).contains(&status) && !dataless(e, args)
}

/// The text an example is searched by; an array example by its first element.
fn example_text(v: Option<&Value>) -> String {
    match v {
        None => String::new(),
        Some(Value::Array(a)) => {
            let pick = a.iter().find(|x| js_len(&as_text(x)) >= 3).or(a.first());
            pick.map(as_text).unwrap_or_default().to_lowercase()
        }
        Some(v) => as_text(v).to_lowercase(),
    }
}

fn example_values(args: &Args) -> Vec<(String, String)> {
    args.iter().map(|(k, v)| (k.clone(), example_text(Some(v)))).collect()
}

/// Under 3 characters: found by substring in one capture, such a value is ambiguous ("US", page 2).
fn is_short(v: &Value) -> bool {
    js_len(&as_text(v)) < 3
}

/// The params placed by whole leaf only: those with a short example in either set.
fn short_params(args: &Args, other: Option<&Args>) -> HashSet<String> {
    args.iter()
        .filter(|(p, v)| is_short(v) || other.and_then(|o| o.get(p.as_str())).map(is_short).unwrap_or(false))
        .map(|(p, _)| p.clone())
        .collect()
}

/// The second trigger run and the example it was made with.
pub struct Second<'a> {
    pub exchanges: &'a [Exchange],
    pub args: &'a Args,
}

struct Endpoint {
    head: String,
    segs: Vec<String>,
}

fn endpoint(e: &Exchange) -> Endpoint {
    let u = parse_url(&e.request.url);
    let host = u.as_ref().map(|u| u.host_str().unwrap_or("").to_string()).unwrap_or_else(|| "undefined".to_string());
    let path = u.as_ref().map(|u| u.path().to_string()).unwrap_or_default();
    Endpoint { head: format!("{} {host}", e.request.method.to_uppercase()), segs: path.split('/').map(norm).collect() }
}

struct Run2Request {
    ep: Endpoint,
    leaves: HashMap<String, String>,
}

/// Whether a request carries a short example: only as a whole leaf, and with a second run only
/// where the same endpoint holds the other example at the same place there.
struct ShortCarrier {
    examples: Vec<(String, String)>,
    other: HashMap<String, String>,
    run2: Vec<Run2Request>,
    has_second: bool,
}

impl ShortCarrier {
    fn new(examples: &[(String, String)], short: &[(String, String)], second: Option<&Second>) -> ShortCarrier {
        let other: HashMap<String, String> =
            examples.iter().map(|(k, _)| (k.clone(), example_text(second.and_then(|s| s.args.get(k))))).collect();
        let run2 = if short.is_empty() {
            vec![]
        } else {
            second
                .map(|s| s.exchanges)
                .unwrap_or(&[])
                .iter()
                .map(|e| Run2Request {
                    ep: endpoint(e),
                    leaves: walk(&e.request).into_iter().map(|l| (step_key(&l.at), l.value.to_lowercase())).collect(),
                })
                .collect()
        };
        ShortCarrier { examples: examples.to_vec(), other, run2, has_second: second.is_some() }
    }

    // a short example is the whole segment, a longer one may sit inside it (/@nasa)
    fn follows(&self, a: &str, b: &str) -> bool {
        a == b
            || self.examples.iter().any(|(k, x)| {
                let y = self.other.get(k).cloned().unwrap_or_default();
                if js_len(x) < 3 || js_len(&y) < 3 { a == x && b == y } else { a.split(x.as_str()).collect::<Vec<_>>().join(&y) == b }
            })
    }

    fn carries(&self, e: &Exchange, leaves: &[&Leaf], k: &str, v: &str) -> bool {
        let whole: Vec<&&Leaf> = leaves.iter().filter(|l| l.value.to_lowercase() == v).collect();
        if !self.has_second {
            return !whole.is_empty();
        }
        let ep = endpoint(e);
        let same: Vec<&Run2Request> = self
            .run2
            .iter()
            .filter(|r| {
                r.ep.head == ep.head && r.ep.segs.len() == ep.segs.len() && ep.segs.iter().zip(&r.ep.segs).all(|(s, t)| self.follows(s, t))
            })
            .collect();
        let want = self.other.get(k).cloned().unwrap_or_default();
        whole.iter().any(|l| same.iter().any(|r| r.leaves.get(&step_key(&l.at)) == Some(&want)))
    }
}

fn try_parse(body: Option<&str>) -> Option<Value> {
    let b = body?;
    if b.is_empty() {
        return None;
    }
    parse_body(b, None).ok()
}

#[derive(Default)]
pub struct RankOptions<'a> {
    /// the caller already chose the pool (a match), so only preflights are dropped
    pub all: bool,
    /// the capture's page URLs (default: its documents and Referers); a value found only in an echo of them is no hit
    pub pages: Option<Vec<String>>,
    /// the other run, which says where a short example (under 3 characters) is carried
    pub second: Option<Second<'a>>,
}

/// Noise-filtered requests, best first: carries the example values, succeeded, returned JSON.
/// A data-less answer (a beacon's ack) ranks below every real answer.
pub fn rank_candidates(exchanges: &[Exchange], args: &Args, o: RankOptions) -> Vec<Candidate> {
    let examples = example_values(args);
    let short = short_params(args, o.second.as_ref().map(|s| s.args));
    let values: Vec<&(String, String)> = examples.iter().filter(|(k, _)| !short.contains(k)).collect();
    let short_examples: Vec<(String, String)> = examples.iter().filter(|(k, _)| short.contains(k)).cloned().collect();
    let carrier = ShortCarrier::new(&examples, &short_examples, o.second.as_ref());
    let locs = locations(&o.pages.clone().unwrap_or_else(|| page_urls(exchanges, &[])));
    let mut out: Vec<Candidate> = exchanges
        .iter()
        .filter(|e| if o.all { !e.request.method.eq_ignore_ascii_case("OPTIONS") } else { !is_noise(e) })
        .map(|e| {
            let all_leaves: Vec<Leaf> = walk(&e.request).into_iter().filter(|l| !not_evidence(&l.at)).collect();
            let leaves = |v: &str| -> Vec<&Leaf> { all_leaves.iter().filter(|l| !echoes(&l.value, v, &locs)).collect() };
            let has = |v: &str, ls: &[&Leaf]| ls.iter().any(|l| l.value.to_lowercase().contains(v));
            // a URL-valued example (a link preview's ?url=) is evidence in a URL-valued leaf
            let direct = |v: &str| -> Vec<&Leaf> {
                leaves(v).into_iter().filter(|l| !l.container && (!URLISH.is_match(&l.value) || URLISH.is_match(v))).collect()
            };
            let hits: Vec<String> = examples
                .iter()
                .filter(|(k, v)| if short.contains(k) { carrier.carries(e, &direct(v), k, v) } else { has(v, &direct(v)) })
                .map(|(k, _)| k.clone())
                .collect();
            let url_hits = values.iter().filter(|(k, v)| !hits.contains(k) && has(v, &leaves(v))).count();
            let body = e.body();
            let parsed = try_parse(Some(body));
            let is_json = parsed.as_ref().map(|p| p.is_object() || p.is_array()).unwrap_or(false);
            let status = e.status();
            let lower = if values.is_empty() { String::new() } else { body.to_lowercase() };
            let score = hits.len() as f64 * 1000.0
                + url_hits as f64 * 50.0
                + if e.aborted { 600.0 } else { 0.0 }
                + if status.map(|s| (200..300).contains(&s)).unwrap_or(false) { 300.0 } else { 0.0 }
                + if is_json { 400.0 } else { 0.0 }
                + if e.resource_type == "xhr" || e.resource_type == "fetch" { 100.0 } else { 0.0 }
                + if values.iter().any(|(_, v)| lower.contains(v.as_str())) { 200.0 } else { 0.0 }
                + (js_len(body) as f64 / 1000.0).min(100.0);
            Candidate {
                id: e.id,
                method: e.request.method.to_uppercase(),
                url: e.request.url.clone(),
                resource_type: e.resource_type.clone(),
                status,
                content_type: e.response.as_ref().map(|r| r.content_type.clone()),
                operation_name: operation_name_of(&e.request),
                hits,
                size: js_len(body),
                // a read's answer is data: an ack with hits still ranks below any real answer with one
                score: (if is_ack(e) { score / 10.0 } else { score }).round() as i64,
            }
        })
        .collect();
    out.sort_by_key(|c| std::cmp::Reverse(c.score));
    out
}

/* ------------------------------------------------------------------ match */

fn try_get(req: &Request, at: &[&str]) -> Option<Value> {
    let steps: Vec<String> = at.iter().map(|s| s.to_string()).collect();
    get_at(req, &steps).ok().flatten()
}

static GQL_NAME: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?:^|\})\s*(?:query|mutation|subscription)\s+([A-Za-z_]\w*)"));

/// GraphQL-ish operation name from the body (a batch's first op too), form, query, or Meta's
/// friendly-name header; else the name in the query text (`query SearchProducts(...)`).
pub fn operation_name_of(req: &Request) -> Option<String> {
    let fields: [&[&str]; 6] = [
        &["body", "json:/operationName"],
        &["body", "json:/0/operationName"],
        &["form:fb_api_req_friendly_name"],
        &["form:operationName"],
        &["query:operationName"],
        &["header:x-fb-friendly-name"],
    ];
    for at in fields {
        if let Some(Value::String(v)) = try_get(req, at) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    let queries: [&[&str]; 4] = [&["body", "json:/query"], &["body", "json:/0/query"], &["form:query"], &["query:query"]];
    for at in queries {
        if let Some(Value::String(v)) = try_get(req, at) {
            if let Some(m) = GQL_NAME.captures(&v) {
                return Some(m[1].to_string());
            }
        }
    }
    None
}

/// camelCase/PascalCase/snake/kebab words ("UserByScreenName") are names, not hashes.
fn wordy(s: &str) -> bool {
    if s.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    // split on _ or - and before each capital
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c == '_' || c == '-' {
            words.push(std::mem::take(&mut cur));
        } else if c.is_ascii_uppercase() {
            words.push(std::mem::take(&mut cur));
            cur.push(c);
        } else {
            cur.push(c);
        }
    }
    words.push(cur);
    static WORD: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Z]?[a-z]+$"));
    words.iter().all(|w| w.is_empty() || WORD.is_match(w))
}

/// Long random-looking token: a queryId/hash, never a word. A digit is not required (~2% of base64url ids lack one).
pub fn hash_like(s: &str) -> bool {
    static CHARS: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_-]+$"));
    s.len() >= 16 && CHARS.is_match(s) && s.chars().any(|c| c.is_ascii_alphabetic()) && !wordy(s)
}

pub fn matches(m: &Match, req: &Request) -> bool {
    let Some(u) = parse_url(&req.url) else { return false };
    if let Some(method) = &m.method {
        if !method.eq_ignore_ascii_case(&req.method) {
            return false;
        }
    }
    if let Some(host) = &m.host {
        if host.to_lowercase() != u.host_str().unwrap_or("").to_lowercase() {
            return false;
        }
    }
    if let Some(path) = &m.path {
        let want: Vec<&str> = path.split('/').collect();
        let got: Vec<&str> = u.path().split('/').collect();
        if want.len() != got.len() || want.iter().zip(&got).any(|(w, g)| *w != "*" && w != g) {
            return false;
        }
    }
    if let Some(name) = &m.operation_name {
        if operation_name_of(req).as_deref() != Some(name.as_str()) {
            return false;
        }
    }
    true
}

/// A bare request (method and address) to match against.
pub fn bare_request(method: &str, url: &str) -> Request {
    Request { method: method.to_string(), url: url.to_string(), headers: IndexMap::new(), body: None }
}

/// Stable identity, with filled and hash-like path segments wildcarded.
fn build_match(req: &Request, slots: &[Slot]) -> Match {
    let filled: HashSet<usize> =
        slots.iter().filter(|s| s.at.len() == 1 && s.at[0].starts_with("path:")).filter_map(|s| s.at[0][5..].parse().ok()).collect();
    let u = parse_url(&req.url).expect("a learned request has a URL");
    static DIGITS: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^\d{6,}$"));
    let path =
        u.path()
            .split('/')
            .enumerate()
            .map(|(i, seg)| {
                if i > 0 && (filled.contains(&(i - 1)) || hash_like(seg) || DIGITS.is_match(seg)) {
                    "*".to_string()
                } else {
                    seg.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("/");
    Match {
        method: Some(req.method.to_uppercase()),
        host: Some(u.host_str().unwrap_or("").to_string()),
        path: Some(path),
        operation_name: operation_name_of(req),
    }
}

/* --------------------------------------------------------------- learning */

// Conditional headers (a revalidating browser's If-None-Match) would turn every replay into a 304.
// The body is stored decoded, so its content-encoding goes too.
static DROP_HEADER: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r"(?i)^(:.*|host|content-length|connection|cookie|accept-encoding|content-encoding|if-[a-z-]+)$"));
// Headers the browser computes itself: an example inside them is a coincidence ("apple" in the
// user-agent, "app" in application/json), and they never carry a nonce of the site's.
pub static BROWSER_HEADER: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(
        r"(?i)^(user-agent|accept(-[a-z-]+)?|content-(type|language)|sec-[a-z0-9-]+|if-[a-z-]+|priority|dnt|upgrade-insecure-requests|cache-control|pragma|x-requested-with)$",
    )
});
fn url_header(at: &[Step]) -> bool {
    at[0] == "header:referer" || at[0] == "header:origin"
}
static URL_SHAPED: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^([a-z][a-z0-9+.-]*://|/)\S*$"));
static VOLATILE_KEY: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r"(?i)^(doc_?id|query_?id|document_?id|sha256_?hash|query_?hash|persisted_?query_?hash|hash)$"));

fn key(at: &[Step]) -> String {
    step_key(at)
}

/// Example values are distinct and can be located. A short one can only with `other`, the other
/// example set, holding a different value for the same param.
pub fn check_examples(args: &Args, label: &str, other: Option<&Args>) -> Result<()> {
    let mut seen: HashMap<String, String> = HashMap::new();
    for (name, v) in args {
        let s = as_text(v).to_lowercase();
        let other_same = match other.and_then(|o| o.get(name)) {
            None => true,
            Some(ov) => as_text(ov).to_lowercase() == s,
        };
        if is_short(v) && other_same {
            bail!(
                "{label} {name}={}: example values need at least 3 characters to be located. A shorter one needs a second example with a different value, run on its own page (--example2 {name}=..., and --from2 when learning from captures): it is then placed where a whole leaf follows the two",
                json(v)
            );
        }
        if let Some(dup) = seen.get(&s) {
            bail!("{label}: {dup} and {name} share the value {}; example values must be distinct", json(v));
        }
        seen.insert(s, name.clone());
    }
    Ok(())
}

/// Both example sets can be located; the second should name the same params as the first.
fn check_example_sets(input: &LearnInput, warnings: &mut Vec<String>) -> Result<()> {
    let args1 = input.args1();
    let args2 = input.args2();
    // a second example without its run proves nothing about a short value
    let has_run = input.exchanges2.is_some();
    check_examples(args1, "example", if has_run { args2 } else { None })?;
    let Some(args2) = args2 else { return Ok(()) };
    check_examples(args2, "example 2", if has_run { Some(args1) } else { None })?;
    let mut k1: Vec<&String> = args1.keys().collect();
    k1.sort();
    let mut k2: Vec<&String> = args2.keys().collect();
    k2.sort();
    if k1 != k2 {
        warnings.push("example 2 names different params than example 1".to_string());
    }
    Ok(())
}

/// Step 6: the captured headers verbatim, minus the ones a replay must not send (DROP_HEADER).
pub fn headers_of(e: &Exchange) -> IndexMap<String, String> {
    e.request.headers.iter().filter(|(k, _)| !DROP_HEADER.is_match(k)).map(|(k, v)| (k.to_lowercase(), v.clone())).collect()
}

/// The captured request as the template every later step reads: verbatim, with step 6's headers.
fn template_of(e: &Exchange) -> Request {
    Request { method: e.request.method.to_uppercase(), url: e.request.url.clone(), headers: headers_of(e), body: e.request.body.clone() }
}

fn pick_exchange<'a>(
    input: &LearnInput,
    exchanges: &'a [Exchange],
    args: &Args,
    pages: &[String],
    warnings: &mut Vec<String>,
) -> Result<&'a Exchange> {
    if let Some(id) = input.id {
        return exchanges.iter().find(|x| x.id == id).ok_or_else(|| anyhow!("no captured request with id {id}"));
    }
    let pool: Vec<Exchange> = match &input.matcher {
        Some(m) => exchanges.iter().filter(|e| matches(m, &e.request)).cloned().collect(),
        None => exchanges.to_vec(),
    };
    let second = match (&input.exchanges2, input.args2()) {
        (Some(ex2), Some(a2)) => Some(Second { exchanges: ex2, args: a2 }),
        _ => None,
    };
    let ranked: Vec<Candidate> =
        rank_candidates(&pool, args, RankOptions { all: input.matcher.is_some(), pages: Some(pages.to_vec()), second })
            .into_iter()
            .filter(|c| input.matcher.is_some() || !c.hits.is_empty())
            .collect();
    if ranked.is_empty() {
        return Err(match &input.matcher {
            Some(m) => anyhow!("no captured request matches {}", json(&serde_json::to_value(m).unwrap_or(Value::Null))),
            None => anyhow!("no captured request carries the example values; check the trigger, or pass match/id"),
        });
    }
    let by_id = |id: u64| exchanges.iter().find(|e| e.id == id).expect("a ranked candidate is in the pool");
    // A response recipe (--html/--embedded/--extract) names the answer: a beacon echoing the page URL doesn't resolve it.
    if let Some(accepts) = &input.accepts {
        if let Some(c) = ranked.iter().find(|c| accepts(by_id(c.id))) {
            return Ok(by_id(c.id));
        }
    }
    let top = &ranked[0];
    if let Some(next) = ranked.get(1) {
        if next.score == top.score {
            warnings.push(format!(
                "ambiguous: requests #{} and #{} rank equally; learned #{}, pass id or match to choose",
                top.id, next.id, top.id
            ));
        }
    }
    Ok(by_id(top.id))
}

/// Step 1: the exchange to learn from, and the pages the capture ran on.
fn pick_request<'a>(input: &'a LearnInput, args: &Args, warnings: &mut Vec<String>) -> Result<(&'a Exchange, Vec<String>)> {
    let enc: Args = args.iter().map(|(k, v)| (k.clone(), Value::String(encode_uri_component(&as_text(v))))).collect();
    let mut extra = vec![fill_template(&input.trigger.url, &enc)];
    extra.extend(input.pages.clone().unwrap_or_default());
    let pages = page_urls(&input.exchanges, &extra);
    let ex = pick_exchange(input, &input.exchanges, args, &pages, warnings)?;
    // A read's answer is data. Picked by rank alone, a data-less 2xx is a beacon's ack whose echo of the
    // page went unrecognized; learning it would answer every call with {"success":true}.
    if input.read_only && dataless(ex, args) && input.id.is_none() && input.matcher.is_none() {
        let body = ex.body().trim();
        bail!(
            "the request that carries the example values (#{} {} {}) answers without data ({}): an analytics beacon's ack, not the op's answer. Pick the data request (capture, then add --from <id> --pick-request <n>), or learn the page itself with --html or --embedded",
            ex.id,
            ex.request.method,
            crate::util::take_chars(&ex.request.url, 120),
            json(&Value::String(crate::util::take_chars(body, 60).to_string()))
        );
    }
    Ok((ex, pages))
}

/// A JSON object that repeats a key has occurrences no step path reaches: a slot there fills or
/// blanks the first one only. A repeated key that is none of those, and holds none, is a constant.
fn refuse_repeated_keys(leaves: &[Leaf], placed: &[Vec<Step>]) -> Result<()> {
    for at in leaves.iter().flat_map(|l| l.repeated.iter()) {
        if !placed.iter().any(|p| key(p) == key(at) || covers(at, p)) {
            continue;
        }
        bail!(
            "the request has a JSON object that repeats a key ({}) where a param or a session value goes: only the key's first occurrence can be filled, so a value in a later one would stay in the spec as captured. Not learned; pick a request without the repeated key",
            at.join(" > ")
        );
    }
    Ok(())
}

/// Pointers inside a JSON text whose value equals want (an array or object example).
fn json_pointers(root: &Value, want: &str, ptr: &str) -> Vec<String> {
    if json(root) == want {
        return vec![ptr.to_string()];
    }
    match root {
        Value::Object(o) => {
            o.iter().flat_map(|(k, c)| json_pointers(c, want, &format!("{ptr}/{}", crate::codec::escape_token(k)))).collect()
        }
        Value::Array(a) => a.iter().enumerate().flat_map(|(i, c)| json_pointers(c, want, &format!("{ptr}/{i}"))).collect(),
        _ => vec![],
    }
}

#[derive(Clone, Debug)]
struct Hit {
    leaf: Leaf,
    /// the text found in the leaf: the example, or its percent-encoded form
    text: String,
    encoded: bool,
}

/// How the arg is escaped inside a templated leaf: URL-valued leaves take it percent-encoded, JSON
/// string literals escaped. Referer/Origin are always URLs, so filling implies "url" there.
fn escape_of(leaf: &Leaf, hits: &[Hit]) -> Option<Escape> {
    if url_header(&leaf.at) {
        return None;
    }
    if hits.iter().any(|h| h.encoded) {
        return Some(Escape::Url);
    }
    // A URL leaf takes the arg percent-encoded, unless the example sits there raw in a form encoding
    // would change: "/facebook/react" in a route resolver's path keeps its slash.
    if URL_SHAPED.is_match(&leaf.value) && hits.iter().all(|h| encode_uri_component(&h.text) == h.text) {
        return Some(Escape::Url);
    }
    let low = leaf.value.to_lowercase();
    let i = low.find(&hits[0].text).unwrap_or(0);
    let before = &leaf.value[..i.min(leaf.value.len())];
    static QUOTE: LazyLock<fancy_regex::Regex> = LazyLock::new(|| crate::util::fre(r#"(?<!\\)""#));
    let quotes = QUOTE.find_iter(before).count();
    if quotes % 2 == 1 { Some(Escape::Json) } else { None }
}

fn digits_only(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// `text` holds `t` with no digit touching it on either side.
fn inside_digits(text: &str, t: &str) -> bool {
    let mut from = 0;
    while let Some(i) = crate::util::find_from(text, t, from) {
        let before = text[..i].chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false);
        let after = text[i + t.len()..].chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false);
        if !before && !after {
            return true;
        }
        from = i + 1;
    }
    false
}

/// `text` holds `x` standing alone between non-alphanumerics.
fn stands_alone(text: &str, x: &str) -> bool {
    let mut from = 0;
    while let Some(i) = crate::util::find_from(text, x, from) {
        let before = text[..i].chars().last().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false);
        let after = text[i + x.len()..].chars().next().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false);
        if !before && !after {
            return true;
        }
        from = i + 1;
    }
    false
}

struct Found {
    exact: Vec<Leaf>,
    part: Vec<Hit>,
}

/// Where a scalar example sits: the leaves equal to it, and the string leaves holding it (raw or
/// percent-encoded) inside other text.
fn scalar_hits(name: &str, raw: &Value, leaves: &[Leaf], whole: bool) -> Result<Found> {
    let v = as_text(raw).to_lowercase();
    let literal = v == "true" || v == "false" || v == "null";
    let digits = digits_only(&v);
    let enc = encode_uri_component(&as_text(raw)).to_lowercase();
    let mut forms: Vec<String> = Vec::new();
    for f in [enc.clone(), enc.replace("%20", "+")] {
        if f != v && !forms.contains(&f) {
            forms.push(f);
        }
    }
    // digits inside a longer number (a timestamp, a cache-buster) are not the arg
    let inside = |text: &str, t: &str| if digits { inside_digits(text, t) } else { text.contains(t) };
    let mut exact: Vec<Leaf> = Vec::new();
    let mut part: Vec<Hit> = Vec::new();
    for leaf in leaves {
        let header = header_name(&leaf.at);
        if let Some(h) = &header {
            if h == "cookie" || BROWSER_HEADER.is_match(h) {
                continue;
            }
        }
        let text = leaf.value.to_lowercase();
        if text == v {
            exact.push(leaf.clone());
            continue;
        }
        // a short value is never a part of a leaf: only the whole-leaf match the second run can prove
        if leaf.container || !leaf.is_string() || literal || whole {
            continue;
        }
        if let Some(h) = &header {
            if !url_header(&leaf.at) && !h.starts_with("x-") {
                continue;
            }
        }
        // a short example ("SFO") turns up by chance inside a random token: there it must stand alone
        let within = |t: &str, x: &str| if js_len(&v) <= 4 && high_entropy(&leaf.value) { stands_alone(t, x) } else { inside(t, x) };
        if within(&text, &v) {
            part.push(Hit { leaf: leaf.clone(), text: v.clone(), encoded: false });
        } else if let Some(f) = forms.iter().find(|x| within(&text, x)) {
            part.push(Hit { leaf: leaf.clone(), text: f.clone(), encoded: true });
        }
    }
    if literal && !exact.is_empty() {
        // X-style GraphQL sends dozens of true flags, and a lone one may be any flag: bind only the one named like the param
        let named: Vec<Leaf> = exact.iter().filter(|l| last_token(&l.at).to_lowercase() == name.to_lowercase()).cloned().collect();
        if named.is_empty() {
            bail!(
                "example value for \"{name}\" ({}) matches {} flag(s) ({}), none with the key \"{name}\"; name the param after its key so it binds to one",
                json(raw),
                exact.len(),
                exact.iter().map(|l| l.at.join(" > ")).collect::<Vec<_>>().join("; ")
            );
        }
        exact = named;
    }
    Ok(Found { exact, part })
}

/// The slot for one leaf that holds param values inside other text. Each hit's text is `param\0found text`.
fn templated_slot(hits: &[Hit]) -> Slot {
    let leaf = &hits[0].leaf;
    let split = |t: &str| -> (String, String) {
        let i = t.find('\0').unwrap_or(0);
        (t[..i].to_string(), t[i + 1..].to_string())
    };
    let mut by_text: IndexMap<String, String> = IndexMap::new();
    for h in hits {
        let (param, text) = split(&h.text);
        by_text.insert(text, param);
    }
    // one alternation, longest first, so "nasa" never splits "nasagov"
    let mut texts: Vec<&String> = by_text.keys().collect();
    texts.sort_by_key(|t| std::cmp::Reverse(t.len()));
    let alts: Vec<String> =
        texts.iter().map(|t| if digits_only(t) { format!(r"(?<!\d){t}(?!\d)") } else { regex::escape(&escape_template(t)) }).collect();
    let alt = crate::util::fre(&format!("(?i){}", alts.join("|")));
    let escaped = escape_template(&leaf.value);
    let template = alt
        .replace_all(&escaped, |c: &fancy_regex::Captures| {
            format!("{{{}}}", by_text.get(&c[0].to_lowercase()).cloned().unwrap_or_default())
        })
        .into_owned();
    let plain: Vec<Hit> = hits.iter().map(|h| Hit { leaf: h.leaf.clone(), text: split(&h.text).1, encoded: h.encoded }).collect();
    let escape = escape_of(leaf, &plain);
    Slot {
        param: Some(by_text.values().next().cloned().unwrap_or_default()),
        at: leaf.at.clone(),
        template: Some(template),
        escape,
        ..Default::default()
    }
}

type Disproved = IndexMap<String, String>;

fn pair_key(param: &str, at: &[Step]) -> String {
    format!("{param}\0{}", key(at))
}

fn disproved_for(d: &Disproved, param: &str) -> Vec<String> {
    d.iter().filter(|(k, _)| k.starts_with(&format!("{param}\0"))).map(|(_, why)| why.clone()).collect()
}

fn not_found(name: &str, raw: Option<&Value>, disproved: &[String], whole: bool) -> anyhow::Error {
    let head = if !disproved.is_empty() {
        let shown: Vec<&String> = disproved.iter().take(4).collect();
        format!(
            "example 2 disproves \"{name}\": {}{}. Nothing else in the learned request holds it, so the param would change nothing. ",
            shown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("; "),
            if disproved.len() > 4 { format!("; and {} more", disproved.len() - 4) } else { String::new() }
        )
    } else {
        format!(
            "example value for \"{name}\" ({}) is not in the learned request{}, so the param would change nothing. ",
            raw.map(json).unwrap_or_else(|| "null".to_string()),
            if whole { " as a whole leaf (with an example under 3 characters, a param is never placed inside a longer one)" } else { "" }
        )
    };
    anyhow!("{head}Pick the request that carries it (capture, then add --from <id> --pick-request <n>), or drop the param")
}

struct ParamSlots {
    slots: Vec<Slot>,
    types: HashMap<String, ParamType>,
}

/// Step 2: slots for the example args. An exact leaf is a slot; a leaf holding the value inside other text
/// (never a number, flag or browser header) is a templated slot.
fn param_slots(
    leaves: &[Leaf],
    args: &Args,
    locs: &Locations,
    warnings: &mut Vec<String>,
    disproved: &Disproved,
    short: &HashSet<String>,
) -> Result<ParamSlots> {
    let mut slots: Vec<Slot> = Vec::new();
    let mut types: HashMap<String, ParamType> = HashMap::new();
    let mut found: IndexMap<String, Found> = IndexMap::new();
    let open = |name: &str, l: &Leaf| !disproved.contains_key(&pair_key(name, &l.at));
    for (name, raw) in args {
        if raw.is_object() || raw.is_array() {
            // an array/object example binds to the JSON container equal to it
            let want = json(raw);
            let mut at: Vec<Vec<Step>> = Vec::new();
            for l in leaves.iter().filter(|l| l.container) {
                if let Ok(parsed) = serde_json::from_str::<Value>(&l.value) {
                    for p in json_pointers(&parsed, &want, "") {
                        let mut a = l.at.clone();
                        a.push(format!("json:{p}"));
                        at.push(a);
                    }
                }
            }
            if at.is_empty() {
                return Err(not_found(name, Some(raw), &[], false));
            }
            for a in at {
                slots.push(Slot::param(name, a));
            }
            types.insert(name.clone(), if raw.is_array() { ParamType::Array } else { ParamType::Object });
            continue;
        }
        let f = scalar_hits(name, raw, leaves, short.contains(name))?;
        found.insert(
            name.clone(),
            Found {
                exact: f.exact.into_iter().filter(|l| open(name, l)).collect(),
                part: f.part.into_iter().filter(|h| open(name, &h.leaf)).collect(),
            },
        );
    }
    // A leaf that equals one param's value belongs to that param, even if another's value is inside it.
    let exact_keys: HashSet<String> = found.values().flat_map(|f| f.exact.iter().map(|l| key(&l.at))).collect();
    let mut partial: IndexMap<String, Vec<Hit>> = IndexMap::new();
    for (name, f) in &found {
        let part: Vec<&Hit> = f.part.iter().filter(|h| !exact_keys.contains(&key(&h.leaf.at))).collect();
        let v = as_text(&args[name]).to_lowercase();
        let places: Vec<String> = f
            .exact
            .iter()
            .chain(part.iter().map(|h| &h.leaf))
            .filter(|l| !not_evidence(&l.at) && !echoes(&l.value, &v, locs))
            .map(|l| l.at.join(" > "))
            .collect();
        if places.is_empty() {
            return Err(not_found(name, args.get(name), &disproved_for(disproved, name), short.contains(name)));
        }
        if places.len() > 1 {
            warnings.push(format!("\"{name}\" appears in {} places, all will be filled: {}", places.len(), places.join("; ")));
        }
        for leaf in &f.exact {
            slots.push(Slot::param(name, leaf.at.clone()));
            match leaf.kind {
                crate::codec::LeafType::Number => {
                    types.insert(name.clone(), ParamType::Number);
                }
                crate::codec::LeafType::Boolean => {
                    types.insert(name.clone(), ParamType::Boolean);
                }
                _ => {}
            }
        }
        for h in part {
            partial.entry(key(&h.leaf.at)).or_default().push(Hit {
                leaf: h.leaf.clone(),
                text: format!("{name}\0{}", h.text),
                encoded: h.encoded,
            });
        }
    }
    for hits in partial.values() {
        slots.push(templated_slot(hits));
    }
    Ok(ParamSlots { slots, types })
}

/* ------------------------------------------------------ session references */

/// A script every visitor gets byte for byte: a GET whose answer shared caches may keep (not private
/// or no-store), fetched without the user's cookies or marked public/immutable.
fn static_bundle(e: &Exchange) -> bool {
    if e.resource_type != "script" || !e.request.method.eq_ignore_ascii_case("GET") {
        return false;
    }
    let Some(r) = &e.response else { return false };
    let cc = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("cache-control")).map(|(_, v)| v.to_lowercase()).unwrap_or_default();
    if cc.contains("private") || cc.contains("no-store") {
        return false;
    }
    static PUBLIC: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\bpublic\b|immutable"));
    e.request.headers.get("cookie").is_none() || PUBLIC.is_match(&cc)
}

#[derive(Clone, Debug)]
struct Live {
    reference: String,
    transform: Option<Transform>,
    /// a session: ref's value, for the session store
    value: Option<String>,
    /// a stored value that is a credential by the rules in secrets.rs, not a setting the page happens to keep
    secret: Option<bool>,
}

// What to do instead when a request cannot be learned without keeping a credential.
const ANOTHER_REQUEST: &str =
    "learn another request for this data (capture, then add --from <id> --pick-request <n>), or the page itself with --html or --embedded";

/// The cookies the request itself sent, in the jar's shape: live even where the capture's jar lacks them.
fn sent_cookies(e: &Exchange) -> Vec<StoredCookie> {
    let host = parse_url(&e.request.url).map(|u| u.host_str().unwrap_or("").to_string()).unwrap_or_default();
    parse_cookie_header(e.request.headers.get("cookie").map(|s| s.as_str()).unwrap_or(""))
        .into_iter()
        .map(|(name, value)| StoredCookie::new(&name, &value, &host))
        .collect()
}

/// Live session values (8+ chars) a request may repeat: cookies (raw, unquoted, URL-decoded) and the
/// page's localStorage/sessionStorage, including string leaves of a JSON entry.
fn live_values(cookies: &[StoredCookie], storage: Option<&IndexMap<String, String>>) -> IndexMap<String, Live> {
    let mut out: IndexMap<String, Live> = IndexMap::new();
    // The first entry to hold a text names it. Any stored entry that holds it as a credential makes
    // it one, whatever the order of the entries.
    fn put(out: &mut IndexMap<String, Live>, v: &str, live: Live) {
        match out.get_mut(v) {
            None if v.len() >= 8 => {
                out.insert(v.to_string(), live);
            }
            Some(held) if held.value.is_some() && live.secret == Some(true) => held.secret = Some(true),
            _ => {}
        }
    }
    // Every cookie as stored first: a text one cookie holds exactly is not another's unquoted or
    // decoded form, which could not fill a hole.
    for c in cookies {
        put(&mut out, &c.value, Live { reference: format!("cookie:{}", c.name), transform: None, value: None, secret: None });
    }
    for c in cookies {
        let decoded = decode_uri_component(&c.value).unwrap_or_else(|| c.value.clone());
        put(
            &mut out,
            &strip_quotes(&c.value),
            Live { reference: format!("cookie:{}", c.name), transform: Some(Transform::StripQuotes), value: None, secret: None },
        );
        put(
            &mut out,
            &decoded,
            Live { reference: format!("cookie:{}", c.name), transform: Some(Transform::UrlDecode), value: None, secret: None },
        );
    }
    // Apps keep settings and saved requests in storage too. A stored value is a credential under a
    // credential's name or when it is random-looking; a JSON text is judged by its key and its leaves.
    let is_json = |v: &str| crate::util::is_json_text(v);
    let secret = |v: &str, names: &[&str]| names.iter().any(|n| is_credential(n, v)) || (!is_json(v) && high_entropy(v));
    if let Some(storage) = storage {
        for (name, value) in storage {
            put(
                &mut out,
                value,
                Live {
                    reference: format!("session:{name}"),
                    transform: None,
                    value: Some(value.clone()),
                    secret: Some(secret(value, &[name])),
                },
            );
            fn visit(out: &mut IndexMap<String, Live>, v: &Value, k: &str, name: &str, secret: &dyn Fn(&str, &[&str]) -> bool) {
                match v {
                    Value::String(s) => {
                        let leaf = k.rsplit('/').next().unwrap_or("");
                        put(
                            out,
                            s,
                            Live {
                                reference: format!("session:{name}/{k}"),
                                transform: None,
                                value: Some(s.clone()),
                                secret: Some(secret(s, &[name, leaf])),
                            },
                        );
                    }
                    Value::Object(o) => {
                        for (kk, c) in o {
                            visit(out, c, &if k.is_empty() { kk.clone() } else { format!("{k}/{kk}") }, name, secret);
                        }
                    }
                    Value::Array(a) => {
                        for (i, c) in a.iter().enumerate() {
                            visit(out, c, &if k.is_empty() { i.to_string() } else { format!("{k}/{i}") }, name, secret);
                        }
                    }
                    _ => {}
                }
            }
            if is_json(value) {
                if let Some(parsed) = try_parse(Some(value)) {
                    visit(&mut out, &parsed, "", name, &secret);
                }
            }
        }
    }
    out
}

/// What the session-reference passes build together. Each pass skips the positions an earlier one
/// took and names its refs against the values already found, so they run in order over one state.
struct Refs {
    /// the param slots, then each ref in the order found
    slots: Vec<Slot>,
    /// positions that have a slot
    taken: HashSet<String>,
    /// live values by their text; a credential a pass finds by name or issue joins them
    live: IndexMap<String, Live>,
    /// literal values of session: refs by name, for the session store
    session_values: IndexMap<String, String>,
}

impl Refs {
    /// The ref a session: value goes by, recorded for the session store: the name asked for, or a
    /// per-position one when that name already holds another value. One name never means two values.
    fn session_ref(&mut self, reference: &str, value: &str, at: &[Step]) -> String {
        let base = &reference[8..];
        let mut name = base.to_string();
        let mut n = 1;
        while self.session_values.get(&name).map(|v| v != value).unwrap_or(false) {
            name = format!("{base}@{}{}", encode_uri_component(&key(at)), if n > 1 { format!(".{n}") } else { String::new() });
            n += 1;
        }
        self.session_values.insert(name.clone(), value.to_string());
        // Newly discovered credentials need the same compound-copy cleanup as cookies/storage.
        let known = self.live.get(value).cloned();
        if !known.as_ref().map(|k| k.reference.starts_with("cookie:")).unwrap_or(false) {
            self.live.insert(
                value.to_string(),
                Live {
                    reference: format!("session:{name}"),
                    transform: None,
                    value: Some(value.to_string()),
                    secret: Some(known.and_then(|k| k.secret).unwrap_or(true)),
                },
            );
        }
        format!("session:{name}")
    }

    /// The ref a live value's hole in a template takes: the name it has by now, which a collision may have changed.
    fn hole_ref(&mut self, l: &Live, at: &[Step]) -> String {
        match &l.value {
            None => l.reference.clone(),
            Some(v) => {
                let reference = self.live.get(v).map(|x| x.reference.clone()).unwrap_or_else(|| l.reference.clone());
                self.session_ref(&reference, v, at)
            }
        }
    }

    /// Give a position its ref; a session: value is recorded under the ref's final name.
    fn add_ref(&mut self, at: &[Step], mut slot: Slot, value: Option<&str>) {
        if let (Some(v), Some(r)) = (value, slot.reference.clone()) {
            if r.starts_with("session:") {
                slot.reference = Some(self.session_ref(&r, v, at));
            }
        }
        slot.at = at.to_vec();
        self.slots.push(slot);
        self.taken.insert(key(at));
    }
}

/// Pass 1: a leaf equal to a live cookie or storage value, whatever the leaf is called.
fn live_refs(refs: &mut Refs, leaves: &[Leaf], public_names: &HashSet<String>) {
    for leaf in leaves {
        let Some(l) = refs.live.get(&leaf.value).cloned() else { continue };
        // string leaves only: a ref is filled with a string, which would retype a JSON number
        if !leaf.is_string() || refs.taken.contains(&key(&leaf.at)) {
            continue;
        }
        // a stored setting is a credential after all where the request sends it under a credential's name
        let name = leaf_name(&leaf.at);
        if l.value.is_some() && !public_names.contains(&name.to_lowercase()) && is_credential(&name, &leaf.value) {
            if let Some(held) = refs.live.get_mut(&leaf.value) {
                held.secret = Some(true);
            }
        }
        let slot = Slot { reference: Some(l.reference.clone()), transform: l.transform, ..Default::default() };
        refs.add_ref(&leaf.at.clone(), slot, l.value.as_deref());
    }
}

/// A key the site ships in its own JS to every visitor (a public API key) is a constant, not a credential.
struct SecretTest {
    scripts: Vec<String>,
    public_names: HashSet<String>,
    shipped: indexmap::IndexSet<String>,
}

impl SecretTest {
    fn new(exchanges: &[Exchange], public_names: &HashSet<String>) -> SecretTest {
        let scripts = exchanges
            .iter()
            .filter(|e| static_bundle(e))
            .filter_map(|e| e.response.as_ref()?.body.clone())
            .filter(|b| !b.is_empty())
            .collect();
        SecretTest { scripts, public_names: public_names.clone(), shipped: indexmap::IndexSet::new() }
    }
    /// Asked about a shipped value, it says no and notes the name in `shipped`, for the op's public list.
    fn secret_named(&mut self, name: &str, value: &str) -> bool {
        if self.public_names.contains(&name.to_lowercase()) || !credential_name(name) || !high_entropy(value) {
            return false;
        }
        if !self.scripts.iter().any(|b| b.contains(value)) {
            return true;
        }
        self.shipped.insert(name.to_lowercase());
        false
    }
}

/// Pass 2: per-session fields and credential-named random values in the path, query, form and JSON.
fn field_refs(refs: &mut Refs, leaves: &[Leaf], test: &mut SecretTest) {
    for leaf in leaves {
        if leaf.container || !leaf.is_string() || leaf.at[0].starts_with("header:") || refs.taken.contains(&key(&leaf.at)) {
            continue;
        }
        let name = last_token(&leaf.at);
        if (SESSION_FIELD.is_match(&name) && leaf.value.len() >= 8) || test.secret_named(&name, &leaf.value) {
            refs.add_ref(&leaf.at.clone(), Slot::reference(&format!("session:{name}"), vec![]), Some(&leaf.value));
        }
    }
}

/// Pass 3: auth and anti-bot headers, credential-named ones, and a header repeating a value the earlier passes found.
fn header_refs(refs: &mut Refs, leaves: &[Leaf], test: &mut SecretTest) {
    let field_of: HashMap<String, String> = refs.session_values.iter().map(|(k, v)| (v.clone(), k.clone())).collect();
    for leaf in leaves {
        let name = if leaf.at.len() == 1 { header_name(&leaf.at) } else { None };
        let Some(name) = name else { continue };
        if refs.taken.contains(&key(&leaf.at)) {
            continue;
        }
        // Meta's x-fb-lsd repeats the lsd field: one credential, one ref.
        let same = if leaf.value.len() >= 8 { field_of.get(&leaf.value).cloned() } else { None };
        if same.is_none() && !SESSION_HEADER.is_match(&name) && (BROWSER_HEADER.is_match(&name) || !test.secret_named(&name, &leaf.value)) {
            continue;
        }
        let reference = format!("session:{}", same.clone().unwrap_or(name));
        let value = if same.is_some() { None } else { Some(leaf.value.as_str()) };
        refs.add_ref(&leaf.at.clone(), Slot::reference(&reference, vec![]), value);
    }
}

/// Pass 4: server-issued values. `issued` holds the answers the page had before this request.
fn issued_refs(refs: &mut Refs, leaves: &[Leaf], issued: &[String]) {
    for leaf in leaves {
        if leaf.container || !leaf.is_string() || refs.taken.contains(&key(&leaf.at)) || !high_entropy(&leaf.value) {
            continue;
        }
        let header = header_name(&leaf.at);
        let name = leaf_name(&leaf.at);
        if leaf.at[0].starts_with("path:") || VOLATILE_KEY.is_match(&name) {
            continue;
        }
        if let Some(h) = &header {
            if url_header(&leaf.at) || BROWSER_HEADER.is_match(h) {
                continue;
            }
        }
        let escaped = json_escape(&leaf.value);
        if !issued.iter().any(|b| b.contains(&leaf.value) || b.contains(&escaped)) {
            continue;
        }
        // A bootstrap token belongs to this operation and request position, not every field named t.
        let reference = refs
            .live
            .get(&leaf.value)
            .map(|l| l.reference.clone())
            .unwrap_or_else(|| format!("session:{name}@{}", encode_uri_component(&key(&leaf.at))));
        refs.add_ref(&leaf.at.clone(), Slot::reference(&reference, vec![]), Some(&leaf.value));
    }
}

/// A hole is filled with the value as stored: only a ref slot's own value can be unquoted or
/// URL-decoded first. A cookie held in that form where it could only be a hole has no safe
/// representation, so the request is refused rather than learned with the cookie left in it.
fn refuse_hole(l: &Live, at: &[Step]) -> anyhow::Error {
    anyhow!(
        "{} holds {} {} beside other text filled at call time, where a credential can only be refilled as stored: it would stay in the spec. Not learned: {ANOTHER_REQUEST}",
        at.join(" > "),
        l.reference,
        if l.transform == Some(Transform::StripQuotes) { "without its quotes" } else { "URL-decoded" }
    )
}

/// Pass 5, in a param's templated leaf: each live value it holds becomes a `{cookie:x}`/`{session:x}`
/// hole in the param's own template. Returns the request with those values taken out of the leaf.
fn hole_refs(refs: &mut Refs, own: &mut Slot, long: &[(String, Live)], mut request: Request) -> Result<Request> {
    for (v, l) in long {
        // With no escape of its own, the leaf may still hold the value encoded (x-ctx: user={q};auth=<%-encoded>):
        // the slot then takes that escape, so the hole is refilled the same way.
        let tries: Vec<Option<Escape>> = match own.escape {
            Some(e) => vec![Some(e)],
            None => vec![None, Some(Escape::Url), Some(Escape::Json)],
        };
        let template = own.template.clone().unwrap_or_default();
        let Some(esc) = tries.iter().find(|e| template.contains(&escape_template(&escape_str(v, **e)))).copied() else { continue };
        if l.transform.is_some() {
            return Err(refuse_hole(l, &own.at));
        }
        let form = escape_str(v, esc);
        if esc.is_some() && own.escape.is_none() {
            own.escape = esc;
        }
        let hole = refs.hole_ref(l, &own.at);
        own.template = Some(template.split(&escape_template(&form)).collect::<Vec<_>>().join(&format!("{{{hole}}}")));
        let current = crate::codec::get_text(&request, &own.at);
        request = set_text(&request, &own.at, &current.split(form.as_str()).collect::<Vec<_>>().join(""))?;
    }
    Ok(request)
}

/// Pass 5, in a leaf no slot has: the live values it holds become holes of one templated ref, named after the first found.
fn templated_ref(refs: &mut Refs, leaf: &Leaf, long: &[(String, Live)]) -> Result<()> {
    let mut template = escape_template(&leaf.value);
    let mut primary: Option<(String, Live, Option<Escape>)> = None;
    for (v, l) in long {
        let forms: [(String, Option<Escape>); 3] =
            [(v.clone(), None), (encode_uri_component(v), Some(Escape::Url)), (json_escape(v), Some(Escape::Json))];
        let form =
            forms.iter().find(|(f, esc)| template.contains(&escape_template(f)) && primary.as_ref().map(|p| p.2 == *esc).unwrap_or(true));
        let Some((f, esc)) = form else { continue };
        // the first value found is the slot's own, so a later one that needs a transform is refused
        if primary.is_some() && l.transform.is_some() {
            return Err(refuse_hole(l, &leaf.at));
        }
        let reference = refs.hole_ref(l, &leaf.at);
        template = template.split(&escape_template(f)).collect::<Vec<_>>().join(&format!("{{{reference}}}"));
        if primary.is_none() {
            primary = Some((reference, l.clone(), *esc));
        }
    }
    let Some((reference, l, escape)) = primary else { return Ok(()) };
    refs.add_ref(
        &leaf.at.clone(),
        Slot { reference: Some(reference), transform: l.transform, template: Some(template), escape, ..Default::default() },
        None,
    );
    Ok(())
}

/// Pass 5: live values embedded in longer leaves.
fn embedded_refs(refs: &mut Refs, leaves: &[Leaf], mut request: Request) -> Result<Request> {
    let long: Vec<(String, Live)> = refs.live.iter().filter(|(v, _)| v.len() >= 16).map(|(v, l)| (v.clone(), l.clone())).collect();
    for leaf in leaves {
        if leaf.container || !leaf.is_string() {
            continue;
        }
        let k = key(&leaf.at);
        // A param's templated leaf can carry one too (next=/search?q={q}&auth=<cookie>): its template gets a ref hole.
        let own_idx = if refs.taken.contains(&k) {
            refs.slots.iter().position(|s| s.is_param() && s.template.is_some() && key(&s.at) == k)
        } else {
            None
        };
        if let Some(i) = own_idx {
            let mut own = refs.slots[i].clone();
            request = hole_refs(refs, &mut own, &long, request)?;
            refs.slots[i] = own;
        } else if !refs.taken.contains(&k) {
            templated_ref(refs, leaf, &long)?;
        }
    }
    Ok(request)
}

/// In a param's templated leaf, the text left around the holes may be a credential beside the arg.
fn refuse_leftover_text(slots: &[Slot], leaves: &[Leaf]) -> Result<()> {
    for leaf in leaves {
        let at = &leaf.at;
        let Some(own) = slots.iter().find(|s| s.is_param() && s.template.is_some() && key(&s.at) == key(at)) else { continue };
        // The literal pieces between the holes, braces unescaped.
        let mut pieces: Vec<String> = vec![String::new()];
        for part in template_parts(own.template.as_deref().unwrap_or("")) {
            match part {
                TemplatePart::Hole(_) => pieces.push(String::new()),
                TemplatePart::Brace(b) => pieces.last_mut().unwrap().push_str(&b),
                TemplatePart::Text(t) => pieces.last_mut().unwrap().push_str(&t),
            }
        }
        let name = leaf_name(at);
        let named = (SESSION_FIELD.is_match(&name) || SESSION_HEADER.is_match(&name)) && pieces.concat().len() >= 8;
        // the separators next to a hole are not part of the token
        let token = pieces.iter().map(|p| p.trim_matches(|c: char| !c.is_ascii_alphanumeric()).to_string()).find(|p| opaque_token(p));
        if !named && token.is_none() {
            continue;
        }
        let why = if named {
            format!("by the leaf's name, {name}")
        } else {
            format!("an unbroken random-looking run of {} characters", token.unwrap().len())
        };
        bail!(
            "{} holds a param inside text that is a credential ({why}): that text cannot be a reference and would stay in the spec. Not learned. If it is the same for every visitor, mark the field or header with --public {name}; otherwise {ANOTHER_REQUEST}",
            at.join(" > ")
        );
    }
    Ok(())
}

/// Slots do not overlap. A container that is a session value is sent whole from the session, so none
/// of it is in the spec: the refs inside it are dropped. A param inside it could not be filled, and
/// the learn is refused. `held`: every cookie and stored value, as the passes began.
fn sent_whole(refs: &mut Refs, held: &HashSet<String>) -> Result<()> {
    let inside =
        |whole: &Slot, s: &Slot| s.at.len() > whole.at.len() && whole.at.iter().enumerate().all(|(i, step)| s.at.get(i) == Some(step));
    let wholes: Vec<Slot> = refs.slots.iter().filter(|s| s.is_ref()).cloned().collect();
    for whole in &wholes {
        if let Some(param) = refs.slots.iter().find(|s| s.is_param() && inside(whole, s)) {
            let where_ = whole.at.join(" > ");
            // a cookie or a stored value is a ref under a name marked public too: no way on there
            let r = whole.ref_str();
            let live = r.starts_with("cookie:") || refs.session_values.get(&r[8.min(r.len())..]).map(|v| held.contains(v)).unwrap_or(false);
            let vouch = if live {
                String::new()
            } else {
                format!("if the rest of {where_} is the same for every visitor, mark it with --public {}; otherwise ", leaf_name(&whole.at))
            };
            bail!(
                "{where_} is a session value ({r}), sent whole from the session at call time, so the param {} inside it ({}) could not be filled. Not learned: {vouch}{ANOTHER_REQUEST}",
                param.param.as_deref().unwrap_or(""),
                param.at.join(" > ")
            );
        }
        refs.slots.retain(|s| !inside(whole, s));
    }
    let used: HashSet<String> = refs
        .slots
        .iter()
        .flat_map(|s| {
            let mut v: Vec<String> = s.reference.iter().cloned().collect();
            v.extend(template_refs(s.template.as_deref().unwrap_or("")));
            v
        })
        .collect();
    refs.session_values.retain(|name, _| used.contains(&format!("session:{name}")));
    Ok(())
}

struct SessionRefsOut {
    request: Request,
    slots: Vec<Slot>,
    session_values: IndexMap<String, String>,
    public_names: Vec<String>,
}

/// Step 4: session refs: live cookie/storage values anywhere, per-session fields, credential-named
/// values, auth headers. Returns the template with every ref'd leaf blanked, the slots with the
/// refs appended, the session: values for the session store, and the names the op lists as public.
fn session_refs(input: &LearnInput, ex: &Exchange, captured: &Request, leaves: &[Leaf], params: &[Slot]) -> Result<SessionRefsOut> {
    let mut cookies = input.cookies.clone();
    cookies.extend(sent_cookies(ex));
    let live = live_values(&cookies, input.storage.as_ref());
    // The final check refuses only a copy no pass could make a ref. A stored value that is a credential
    // by its storage key's name alone, and neither random-looking nor shaped like a token, is no ground to refuse.
    let name_only: HashSet<String> = live
        .iter()
        .filter(|(value, l)| l.secret == Some(true) && !high_entropy(value) && crate::secrets::shape_warnings(value).is_empty())
        .map(|(v, _)| v.clone())
        .collect();
    // Stored credentials, whether or not a pass makes them refs: the final check looks for each one.
    let stored: IndexMap<String, String> = live
        .iter()
        .filter(|(value, l)| l.secret == Some(true) && !name_only.contains(*value))
        .map(|(value, l)| (format!("storage:{}", &l.reference[8..]), value.clone()))
        .collect();
    let held: HashSet<String> = live.keys().cloned().collect();
    let mut refs =
        Refs { slots: params.to_vec(), taken: params.iter().map(|s| key(&s.at)).collect(), live, session_values: IndexMap::new() };
    let public_names: HashSet<String> = input.public.clone().unwrap_or_default().iter().map(|h| h.to_lowercase()).collect();
    let open: Vec<Leaf> = leaves.iter().filter(|l| !public_names.contains(&leaf_name(&l.at).to_lowercase())).cloned().collect();
    live_refs(&mut refs, leaves, &public_names);
    let mut test = SecretTest::new(&input.exchanges, &public_names);
    field_refs(&mut refs, leaves, &mut test);
    header_refs(&mut refs, &open, &mut test);
    let issued: Vec<String> = input
        .exchanges
        .iter()
        .filter(|e| e.id < ex.id && !static_bundle(e))
        .filter_map(|e| e.response.as_ref()?.body.clone())
        .filter(|b| !b.is_empty())
        .collect();
    issued_refs(&mut refs, &open, &issued);
    let mut request = embedded_refs(&mut refs, leaves, captured.clone())?;
    refuse_leftover_text(&refs.slots, &open)?;
    // A stored setting a leaf repeated is a ref, so it stays fresh; that does not make it a credential.
    // Taken before a container's inner refs are dropped: what they held is still looked for.
    let values: IndexMap<String, String> = refs
        .session_values
        .iter()
        .filter(|(_, v)| refs.live.get(*v).and_then(|l| l.secret) != Some(false) && !name_only.contains(*v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    sent_whole(&mut refs, &held)?;
    let placed: Vec<Vec<Step>> = refs.slots.iter().map(|s| s.at.clone()).collect();
    refuse_repeated_keys(leaves, &placed)?;
    // A ref'd leaf's value lives in the session, not the spec: blank it.
    for s in &refs.slots {
        if s.is_ref() {
            request = set_text(&request, &s.at, "")?;
        }
    }
    refuse_leftover(&request, &refs.slots, &Known { cookies, values, stored })?;
    // the caller's names in the order given, then the shipped ones in the order met (a `Set` in TS)
    let mut listed: Vec<String> = Vec::new();
    for h in input.public.clone().unwrap_or_default().iter().map(|h| h.to_lowercase()).chain(test.shipped.iter().cloned()) {
        if !listed.contains(&h) {
            listed.push(h);
        }
    }
    Ok(SessionRefsOut { request, slots: refs.slots, session_values: refs.session_values, public_names: listed })
}

/// The scan's hits (`whole`, by JSON path) said by position: the leaf that holds each value is the
/// field a user would mark public. The deepest leaf names a hit, not the containers around it.
fn placed(request: &Request, live: &Session, whole: &[String]) -> Vec<String> {
    let split = |hit: &str| -> (String, String) {
        let i = hit.find(" holds the live ").unwrap_or(hit.len());
        (hit[2.min(i)..i].to_string(), hit[i..].to_string())
    };
    let leaves = walk(request);
    let at: HashMap<String, Vec<Step>> = leaves.iter().map(|l| (l.at.join(" > "), l.at.clone())).collect();
    let texts: Value = Value::Object(leaves.iter().map(|l| (l.at.join(" > "), Value::String(l.value.clone()))).collect());
    let hits: Vec<(String, String)> = scan_secrets(&texts, live, &HashSet::new()).secrets.iter().map(|h| split(h)).collect();
    let deepest: Vec<&(String, String)> = hits
        .iter()
        .filter(|(where_, what)| {
            !hits.iter().any(|(w, x)| x == what && at.get(where_).zip(at.get(w)).map(|(a, b)| covers(a, b)).unwrap_or(false))
        })
        .collect();
    let mut out: Vec<String> = deepest.iter().map(|(w, x)| format!("{w}{x}")).collect();
    for hit in whole {
        let (where_, what) = split(hit);
        if let Some(rest) = where_.strip_prefix("templates.") {
            out.push(format!("the template for {rest}{what}"));
        } else if !deepest.iter().any(|(_, x)| *x == what) {
            out.push(format!("$.{where_}{what}"));
        }
    }
    out
}

/// What the final check looks for.
struct Known {
    cookies: Vec<StoredCookie>,
    /// the session: values that are credentials, by name
    values: IndexMap<String, String>,
    /// stored values that are credentials, whether or not a pass made them refs
    stored: IndexMap<String, String>,
}

/// The check behind every pass: no cookie, no credential a pass recorded and no stored credential
/// may be left in the stored request or a slot template, in any encoding the save-time scan reads.
fn refuse_leftover(request: &Request, slots: &[Slot], known: &Known) -> Result<()> {
    let example = |at: &[Step]| slots.iter().any(|s| s.is_param() && (key(&s.at) == key(at) || covers(&s.at, at)));
    let templates: Value =
        Value::Object(slots.iter().filter_map(|s| s.template.as_ref().map(|t| (s.at.join(" > "), Value::String(t.clone())))).collect());
    let look = |live: &Session, exempt: &dyn Fn(&[Step]) -> bool| -> Vec<String> {
        let mut rest = request.clone();
        let mut gone: Vec<Vec<Step>> = Vec::new();
        for leaf in walk(request) {
            if !exempt(&leaf.at) || gone.iter().any(|g| covers(g, &leaf.at)) {
                continue;
            }
            if let Ok(r) = set_text(&rest, &leaf.at, "") {
                rest = r;
            }
            gone.push(leaf.at.clone());
        }
        let value = serde_json::json!({ "request": rest, "templates": templates });
        let whole = scan_secrets(&value, live, &HashSet::new()).secrets;
        if whole.is_empty() { vec![] } else { placed(&rest, live, &whole) }
    };
    let mut secrets = look(&Session::with(known.cookies.clone(), known.values.clone()), &|_| false);
    secrets.extend(look(&Session::with(vec![], known.stored.clone()), &example));
    if !secrets.is_empty() {
        bail!(
            "refusing to learn a request that would keep a credential in the spec: {}. No name marked public waives one. Not learned: {ANOTHER_REQUEST}",
            secrets.join("; ")
        );
    }
    Ok(())
}

/// Session values are stored per site. Two operations may use different tokens under the same
/// field/header name, so newly learned references include the operation name. Old specs still work.
fn scope_refs(slots: &[Slot], op_name: &str) -> Vec<Slot> {
    let scope = |r: &str| {
        if let Some(rest) = r.strip_prefix("session:") {
            format!("session:{}/{rest}", encode_uri_component(op_name))
        } else {
            r.to_string()
        }
    };
    slots
        .iter()
        .map(|s| {
            let mut slot = s.clone();
            if let Some(r) = &slot.reference {
                slot.reference = Some(scope(r));
            }
            if let Some(t) = &slot.template {
                let mut t = t.clone();
                for r in template_refs(&t) {
                    t = t.split(&format!("{{{r}}}")).collect::<Vec<_>>().join(&format!("{{{}}}", scope(&r)));
                }
                slot.template = Some(t);
            }
            slot
        })
        .collect()
}

fn shape_of(s: &str) -> Shape {
    static HEX: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^[0-9a-f]+$"));
    static B64URL: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_-]+$"));
    let charset = if digits_only(s) {
        Charset::Digits
    } else if HEX.is_match(s) {
        Charset::Hex
    } else if B64URL.is_match(s) {
        Charset::Base64url
    } else {
        Charset::Base64
    };
    Shape { charset, length: s.len() as u64 }
}

/// Step 5: hash-like literals no slot has, each with its shape and a stable anchor next to it.
fn volatile_anchors(req: &Request, leaves: &[Leaf], slots: &[Slot]) -> Vec<Volatile> {
    let op_name = operation_name_of(req);
    let taken: HashSet<String> = slots.iter().map(|s| key(&s.at)).collect();
    let mut out: Vec<Volatile> = Vec::new();
    // A body queryId repeating the path id shares the path's anchor; "queryId" itself is too generic to rescan by.
    let mut anchor_of: HashMap<String, String> = HashMap::new();
    let segs: Vec<String> = parse_url(&req.url).map(|u| u.path().split('/').skip(1).map(|s| s.to_string()).collect()).unwrap_or_default();
    static LONG_DIGITS: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^\d{8,}$"));
    for leaf in leaves {
        if leaf.container || taken.contains(&key(&leaf.at)) || leaf.at[0].starts_with("header:") {
            continue;
        }
        // inside a container sent whole from the session there is nothing to rescan
        if slots.iter().any(|s| s.is_ref() && covers(&s.at, &leaf.at)) {
            continue;
        }
        let first = &leaf.at[0];
        if leaf.at.len() == 1 && first.starts_with("path:") {
            if !hash_like(&leaf.value) {
                continue;
            }
            let i: usize = first[5..].parse().unwrap_or(0);
            let anchor =
                op_name.clone().or_else(|| segs.get(i + 1).cloned()).or_else(|| if i > 0 { segs.get(i - 1).cloned() } else { None });
            if let Some(anchor) = anchor {
                out.push(Volatile { at: leaf.at.clone(), shape: shape_of(&leaf.value), anchor: anchor.clone() });
                anchor_of.insert(leaf.value.clone(), anchor);
            }
        } else if VOLATILE_KEY.is_match(&last_token(&leaf.at)) && (hash_like(&leaf.value) || LONG_DIGITS.is_match(&leaf.value)) {
            let anchor = op_name.clone().or_else(|| anchor_of.get(&leaf.value).cloned()).unwrap_or_else(|| last_token(&leaf.at));
            out.push(Volatile { at: leaf.at.clone(), shape: shape_of(&leaf.value), anchor });
        }
    }
    out
}

/// Path to the richest array carrying an example value, else the object holding it, else the biggest array.
pub fn suggest_extract(root: &Value, values: &[String]) -> Option<String> {
    let carries = |v: &Value| {
        let s = json(v).to_lowercase();
        values.iter().any(|x| s.contains(x))
    };
    static WORD: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[\w$-]+$"));
    let mut best_array: Option<(String, f64)> = None;
    let mut any_array: Option<(String, usize)> = None;
    let mut holder: Option<(String, usize)> = None;
    let mut queue: VecDeque<(Value, String, usize)> = VecDeque::from([(root.clone(), String::new(), 0)]);
    while let Some((v, path, depth)) = queue.pop_front() {
        if depth > 8 || !(v.is_object() || v.is_array()) {
            continue;
        }
        let children: Vec<(String, Value)> = match &v {
            Value::Array(a) => a.iter().take(50).enumerate().map(|(i, c)| (format!("{path}[{i}]"), c.clone())).collect(),
            Value::Object(o) => o
                .iter()
                .map(|(k, c)| {
                    let p = if WORD.is_match(k) {
                        if path.is_empty() { k.clone() } else { format!("{path}.{k}") }
                    } else {
                        format!("{path}[{}]", json(&Value::String(k.clone())))
                    };
                    (p, c.clone())
                })
                .collect(),
            _ => vec![],
        };
        if let Value::Array(a) = &v {
            // a top-level list of results is itself the answer: "" (the whole response) beats any item in it
            if path.is_empty() && a.len() > 1 && a.iter().any(|x| x.is_object() || x.is_array()) && carries(&v) {
                return Some(String::new());
            }
            if !path.is_empty() {
                if any_array.as_ref().map(|(_, n)| a.len() > *n).unwrap_or(true) {
                    any_array = Some((path.clone(), a.len()));
                }
                let rank = a.len() as f64 + if a.iter().any(|x| x.is_object() || x.is_array()) { 1e6 } else { 0.0 };
                if a.len() > 1 && best_array.as_ref().map(|(_, r)| rank > *r).unwrap_or(true) && carries(&v) {
                    best_array = Some((path.clone(), rank));
                }
            }
        }
        for (p, c) in children {
            let inner = match &c {
                Value::String(s) => inner_json(s).filter(|i| i.is_object() || i.is_array()),
                _ => None,
            };
            if let Some(inner) = inner {
                queue.push_back((inner, p, depth + 1));
            } else if c.is_object() || c.is_array() {
                queue.push_back((c, p, depth + 1));
            } else if !path.is_empty()
                && !c.is_null()
                && values.contains(&as_text(&c).to_lowercase())
                && holder.as_ref().map(|(_, d)| depth > *d).unwrap_or(true)
            {
                holder = Some((path.clone(), depth));
            }
        }
    }
    best_array.map(|(p, _)| p).or_else(|| holder.map(|(p, _)| p)).or_else(|| any_array.map(|(p, _)| p))
}

fn learn_response(e: &Exchange, values: &[String], warnings: &mut Vec<String>) -> ResponseSpec {
    let Some(r) = &e.response else { return ResponseSpec::default() };
    let body = r.body.as_deref().unwrap_or("");
    let xssi_prefix = xssi_of(body);
    let data = try_parse(Some(body));
    if let Some(data) = data.filter(|d| d.is_object() || d.is_array()) {
        let extract = suggest_extract(&data, values);
        return ResponseSpec {
            format: Format::Json,
            content_type: Some(r.content_type.clone()),
            xssi_prefix: xssi_prefix.map(|p| p.to_string()),
            extract: extract.filter(|e| !e.is_empty()),
            shape: Some(infer_shape(&data, 200)),
            ..Default::default()
        };
    }
    warnings.push(if r.content_type.to_lowercase().contains("html") {
        "response is HTML: add --html '{\"items\":\"<css>\",\"fields\":{...}}' for a list, or --embedded '<regex>' for JSON inside the page"
            .to_string()
    } else {
        format!("response is {} text, returned raw", if r.content_type.is_empty() { "untyped" } else { &r.content_type })
    });
    ResponseSpec { format: Format::Html, content_type: Some(r.content_type.clone()), ..Default::default() }
}

/// Two-run diff: positions that change without an arg change are nonces (unless they look like
/// counters). A param's place that stays as it was although the param changed is noted in `disproved`.
#[allow(clippy::too_many_arguments)]
fn diff_runs(
    req1: &Request,
    req2: &Request,
    slots: &[Slot],
    args1: &Args,
    args2: &Args,
    warnings: &mut Vec<String>,
    disproved: &mut Disproved,
    short_params: &HashSet<String>,
) -> Vec<String> {
    let by_slot: HashMap<String, &Slot> = slots.iter().map(|s| (key(&s.at), s)).collect();
    let second: HashMap<String, Leaf> = walk(req2).into_iter().map(|l| (key(&l.at), l)).collect();
    let values2: Vec<String> = example_values(args2).into_iter().map(|(_, v)| v).collect();
    let text = |v: Option<&Value>| v.map(|x| as_text(x).to_lowercase()).unwrap_or_default();
    let changed: Vec<String> = args2.keys().filter(|p| text(args2.get(*p)) != text(args1.get(*p))).cloned().collect();
    let mut nonces: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for leaf in walk(req1) {
        if leaf.container || leaf.at[0] == "header:cookie" {
            continue;
        }
        let k = key(&leaf.at);
        let slot = by_slot.get(&k).copied();
        let other = second.get(&k);
        if slot.map(|s| s.is_ref()).unwrap_or(false) {
            continue;
        }
        if let Some(h) = header_name(&leaf.at) {
            if BROWSER_HEADER.is_match(&h) {
                continue;
            }
        }
        // A short example is placed only where run 2 proves it: a whole leaf holding example 2's value.
        let short =
            slot.map(|s| s.is_param() && s.template.is_none() && short_params.contains(s.param.as_deref().unwrap_or(""))).unwrap_or(false);
        let Some(other) = other else {
            if short {
                disproved.insert(
                    pair_key(slot.unwrap().param.as_deref().unwrap_or(""), &leaf.at),
                    format!("{} is not in run 2's request", leaf.at.join(" > ")),
                );
            }
            missing.push(leaf.at.join(" > "));
            continue;
        };
        if let Some(s) = slot.filter(|s| s.is_param()) {
            let pname = s.param.as_deref().unwrap_or("");
            let want = match &s.template {
                Some(t) => fill_slot_template(t, args2, s.escape),
                None => as_text(args2.get(pname).unwrap_or(&Value::Null)),
            };
            // a credential hole matches whatever run 2's session held
            static HOLE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\{(?:cookie|session):[^{}]+\}"));
            let same = re(&format!("(?is)^{}$", HOLE.split(&want).map(regex::escape).collect::<Vec<_>>().join(".*?")));
            if same.is_match(&other.value) {
                continue;
            }
            if other.value == leaf.value || short {
                // The leaf stayed as it was although the arg changed: a constant that only held example 1.
                let fills = |p: &str| match &s.template {
                    None => p == pname,
                    Some(t) => fill_template(t, &args_of(&[(p, "\0")])).contains('\0'),
                };
                let where_ = format!("{} is {}", leaf.at.join(" > "), json(&Value::String(leaf.value.clone())));
                let went = |p: &str| {
                    format!(
                        "{p} went from {} to {}",
                        json(args1.get(p).unwrap_or(&Value::Null)),
                        json(args2.get(p).unwrap_or(&Value::Null))
                    )
                };
                for p in changed.iter().filter(|p| fills(p)) {
                    disproved.insert(
                        pair_key(p, &leaf.at),
                        if other.value == leaf.value {
                            format!("{where_} in both runs, though {}", went(p))
                        } else {
                            format!("{where_}, then {}, while {}", json(&Value::String(other.value.clone())), went(p))
                        },
                    );
                }
                continue;
            }
            // The text around the arg changed too: a signature inside the leaf (a signed URL in a param).
            // a credential hole is run-specific too: a wildcard like the args
            let literals: Vec<String> = match &s.template {
                Some(t) => {
                    let mut holes: Vec<String> = args2.keys().cloned().collect();
                    holes.extend(template_refs(t));
                    let vars: Args = holes.iter().map(|k| (k.clone(), Value::String("\0".to_string()))).collect();
                    fill_slot_template(t, &vars, s.escape).split('\0').map(|x| x.to_string()).collect()
                }
                None => vec![],
            };
            if literals.iter().any(|l| !l.is_empty() && !other.value.to_lowercase().contains(&l.to_lowercase())) {
                nonces.push(leaf.at.join(" > "));
            } else {
                warnings.push(format!(
                    "run 2 has {} at {}, expected {}",
                    json(&Value::String(other.value.clone())),
                    leaf.at.join(" > "),
                    json(&Value::String(want))
                ));
            }
            continue;
        }
        if other.value == leaf.value {
            continue;
        }
        let where_ = leaf.at.join(" > ");
        if values2.iter().any(|v| other.value.to_lowercase().contains(v.as_str())) {
            warnings.push(format!("{where_} follows the args in run 2 but did not match example 1; check its format"));
        } else if (digits_only(&leaf.value) && digits_only(&other.value)) || js_len(&leaf.value).max(js_len(&other.value)) <= 4 {
            // digits-only or tiny values read as counters/timestamps (_reqid, __req), not signatures
            warnings.push(format!("{where_} varies between runs (counter or timestamp?); kept constant"));
        } else {
            nonces.push(where_);
        }
    }
    if !missing.is_empty() {
        warnings.push(format!(
            "run 2 lacks {} position(s) of run 1, e.g. {}",
            missing.len(),
            missing.iter().take(3).cloned().collect::<Vec<_>>().join("; ")
        ));
    }
    nonces
}

struct Diffed {
    min_tier: u8,
    exchange2: Option<Exchange>,
}

/// Step 3: the tier a nonce forces. 3 when a position changes between the runs without an arg
/// change (a nonce or signature), else 1. `request` and `slots` are run 1's, refs included.
#[allow(clippy::too_many_arguments)]
fn two_run_diff(
    input: &LearnInput,
    first: &Exchange,
    request: &Request,
    slots: &[Slot],
    matcher: &Match,
    warnings: &mut Vec<String>,
    disproved: &mut Disproved,
    short: &HashSet<String>,
) -> Result<Diffed> {
    let args1 = input.args1();
    let (Some(exchanges2), Some(args2)) = (&input.exchanges2, input.args2()) else {
        warnings.push("learned from one example; a second example set separates params from nonces".to_string());
        return Ok(Diffed { min_tier: 1, exchange2: None });
    };
    let pool: Vec<Exchange> = exchanges2.iter().filter(|e| matches(matcher, &e.request)).cloned().collect();
    let by_id = |c: &Candidate| pool.iter().find(|e| e.id == c.id).expect("a candidate is in the pool").clone();
    let ranked = rank_candidates(&pool, args2, RankOptions { all: true, pages: None, second: None });
    // Run 2's request is chosen on the evidence run 1's (`first`) was: what the recipe reads, when it
    // reads run 1's, and for a read an answer that is data, when run 1's is.
    let recipe_reads_first = input.accepts.as_ref().map(|a| a(first)).unwrap_or(false);
    let reads = |e: &Exchange| if recipe_reads_first { input.accepts.as_ref().map(|a| a(e)).unwrap_or(true) } else { true };
    let data = input.read_only && has_data(first, args1);
    let answers: Vec<&Candidate> = ranked.iter().filter(|c| reads(&by_id(c)) && (!data || has_data(&by_id(c), args2))).collect();
    let path = parse_url(&request.url).map(|u| u.path().to_string()).unwrap_or_default();
    let top = answers
        .iter()
        .find(|c| !c.hits.is_empty() && parse_url(&c.url).map(|u| u.path() == path).unwrap_or(false))
        .copied()
        .or_else(|| answers.first().copied())
        .or_else(|| ranked.first());
    // A short example is placed only where run 2 proves it, so a run 2 that proves nothing fails it.
    let unproven = |why: &str| -> Result<()> {
        if !short.is_empty() {
            let mut names: Vec<&String> = short.iter().collect();
            names.sort();
            bail!(
                "{why}, so nothing confirms where the short example of {} goes. Check that the second example loads the same kind of page, or pass --match",
                names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
        Ok(())
    };
    let Some(top) = top else {
        unproven(&format!("run 2 produced no request matching {}", json(&serde_json::to_value(matcher).unwrap_or(Value::Null))))?;
        warnings.push("run 2 produced no matching request; skipped the two-run diff".to_string());
        return Ok(Diffed { min_tier: 1, exchange2: None });
    };
    if answers.is_empty() {
        unproven("run 2's matching request does not answer like run 1's")?;
        warnings.push(
            "run 2's matching request does not answer like run 1's (no data, or not what the recipe reads): it disproves nothing"
                .to_string(),
        );
    }
    let exchange2 = by_id(top);
    let req2 = Request {
        method: exchange2.request.method.clone(),
        url: exchange2.request.url.clone(),
        headers: headers_of(&exchange2),
        body: exchange2.request.body.clone(),
    };
    // a request that is not run 1's counterpart still shows nonces, but is no evidence against a slot
    let mut scratch: Disproved = IndexMap::new();
    let proof: &mut Disproved = if answers.is_empty() { &mut scratch } else { disproved };
    let nonces = diff_runs(request, &req2, slots, args1, args2, warnings, proof, short);
    if nonces.is_empty() {
        return Ok(Diffed { min_tier: 1, exchange2: Some(exchange2) });
    }
    warnings.push(format!("changes between runs without an arg change (nonce/signature), so minTier 3: {}", nonces.join("; ")));
    Ok(Diffed { min_tier: 3, exchange2: Some(exchange2) })
}

pub fn learn_operation(input: &LearnInput) -> Result<Learned> {
    learn(input, &IndexMap::new())
}

/// DESIGN.md "Learning", step by step. The two-run diff (3) comes after the session refs (4),
/// because a session value that differs between the runs is not a nonce, and after the match, which
/// finds run 2's request and is built from the template once its credentials are blanked.
fn learn(input: &LearnInput, disproved: &Disproved) -> Result<Learned> {
    let args1 = input.args1();
    // a short example is expected to equal leaves that are not its own: only the other disproofs are news
    let short = short_params(args1, input.args2());
    let mut warnings: Vec<String> = disproved
        .iter()
        .filter(|(pair, _)| !short.contains(&pair[..pair.find('\0').unwrap_or(pair.len())]))
        .map(|(_, why)| format!("{why}: kept constant, not filled"))
        .collect();
    check_example_sets(input, &mut warnings)?;

    // 1. pick the request (6: its headers are kept, minus the ones a replay must not send)
    let (exchange, pages) = pick_request(input, args1, &mut warnings)?;
    let captured = template_of(exchange);
    let leaves = walk(&captured);

    // 2. params. A request the agent picked by id is its call: an echo-shaped leaf there is evidence.
    let locs = if input.id.is_some() { Locations::default() } else { locations(&pages) };
    let param = param_slots(&leaves, args1, &locs, &mut warnings, disproved, &short)?;

    // 4. session refs
    let SessionRefsOut { request, slots, session_values, public_names } = session_refs(input, exchange, &captured, &leaves, &param.slots)?;

    // 5. volatile anchors
    let volatile = volatile_anchors(&request, &leaves, &slots);
    refuse_repeated_keys(&leaves, &volatile.iter().map(|v| v.at.clone()).collect::<Vec<_>>())?;

    // match: stable identity, with param and hash-like path segments wildcarded
    let matcher = input.matcher.clone().unwrap_or_else(|| build_match(&request, &slots));

    // 3. two-run diff. A place run 2 disproved was never the param's: learn again without it.
    let mut found: Disproved = disproved.clone();
    let diffed = two_run_diff(input, exchange, &request, &slots, &matcher, &mut warnings, &mut found, &short)?;
    if found.len() > disproved.len() {
        return learn(input, &found);
    }

    // 8. response
    let values: Vec<String> = args1.values().map(|v| as_text(v).to_lowercase()).collect();
    let response = learn_response(exchange, &values, &mut warnings);

    let params: Vec<Param> = args1
        .iter()
        .map(|(name, example)| Param {
            kind: param.types.get(name).copied().unwrap_or(ParamType::String),
            example: Some(example.clone()),
            ..Param::new(name)
        })
        .collect();

    let operation = Operation {
        name: input.name.clone(),
        description: None,
        request,
        slots: scope_refs(&slots, &input.name),
        volatile,
        trigger: input.trigger.clone(),
        matcher,
        response,
        params,
        read_only: input.read_only,
        public: if public_names.is_empty() { None } else { Some(public_names) },
        min_tier: diffed.min_tier,
        // 7. whether the session it was learned in was signed in
        learned_logged_in: logged_in(&input.cookies, input.login_cookies.as_deref(), now_ms()),
        learned_at: Some(iso_now()),
    };
    let operation = crate::spec::check_operation(&operation)?;
    Ok(Learned {
        operation,
        exchange: exchange.clone(),
        exchange2: diffed.exchange2,
        warnings,
        session_values: session_values.iter().map(|(k, v)| (format!("{}/{k}", encode_uri_component(&input.name)), v.clone())).collect(),
    })
}
