//! Tier 1: fill the stored template and send it with a plain HTTP client.
use crate::codec::{fill_slot_template, set_at, template_refs, walk};
use crate::learn::{bare_request, matches};
use crate::session::{Session, cookie_header_for, cookie_value, parse_set_cookie};
use crate::spec::{Escape, Match, Operation, Param, ParamType, Request, Slot, Transform};
use crate::types::{Headers, StoredCookie};
use crate::util::{as_text, decode_uri_component, encode_uri_component, json, json_escape, now_ms, number_from_text, parse_url, past_safe_integer, re};
use anyhow::{Result, anyhow, bail};
use futures_util::future::BoxFuture;
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

pub type Args = Map<String, Value>;

#[derive(Clone, Debug)]
pub struct Sent {
    pub status: u16,
    pub headers: Headers,
    pub body: String,
    /// final URL after redirects
    pub url: String,
    pub ms: u64,
    /// the first answer was a redirect: the server took the request (a write's POST ran)
    pub redirected: bool,
    /// cookies the answers set (every hop), for the jar
    pub set_cookies: Vec<StoredCookie>,
}

/// One HTTP request on the wire, as a fetcher sends it.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: Headers,
    pub body: Option<String>,
}

/// What came back: the status, every header (set-cookie kept as a list), the raw body and the final URL.
#[derive(Clone, Debug, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Headers,
    pub set_cookie: Vec<String>,
    pub body: Vec<u8>,
    pub url: String,
}

/// The transport a tier-1 send goes through; tests inject one that answers from memory.
pub trait Fetcher: Send + Sync {
    fn fetch(&self, req: HttpRequest, timeout: Duration) -> BoxFuture<'_, Result<HttpResponse>>;
}

pub type SharedFetcher = Arc<dyn Fetcher>;

/// The real client: no automatic redirects, no cookie store, compressed bodies decoded.
pub struct ReqwestFetcher {
    client: reqwest::Client,
}

impl Default for ReqwestFetcher {
    fn default() -> Self {
        ReqwestFetcher::new()
    }
}

impl ReqwestFetcher {
    pub fn new() -> ReqwestFetcher {
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("an HTTP client");
        ReqwestFetcher { client }
    }
}

/// A network error's cause, named the way Node names it, so an agent reads the same reason.
fn name_cause(e: &reqwest::Error) -> String {
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    let mut deepest = e.to_string();
    let mut code: Option<&str> = None;
    while let Some(s) = src {
        deepest = s.to_string();
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            code = match io.kind() {
                std::io::ErrorKind::ConnectionRefused => Some("ECONNREFUSED"),
                std::io::ErrorKind::ConnectionReset => Some("ECONNRESET"),
                std::io::ErrorKind::TimedOut => Some("ETIMEDOUT"),
                _ => None,
            };
        }
        src = std::error::Error::source(s);
    }
    let low = deepest.to_lowercase();
    if code.is_none() && (low.contains("dns") || low.contains("resolve") || low.contains("name or service not known")) {
        code = Some("ENOTFOUND");
    }
    match code {
        Some(c) => format!("fetch failed: {c} ({deepest})"),
        None => format!("fetch failed: {deepest}"),
    }
}

impl Fetcher for ReqwestFetcher {
    fn fetch(&self, req: HttpRequest, timeout: Duration) -> BoxFuture<'_, Result<HttpResponse>> {
        Box::pin(async move {
            let method = reqwest::Method::from_bytes(req.method.as_bytes()).map_err(|_| anyhow!("bad method {}", req.method))?;
            let mut r = self.client.request(method, &req.url).timeout(timeout);
            for (k, v) in &req.headers {
                r = r.header(k.as_str(), v.as_str());
            }
            if let Some(b) = req.body {
                r = r.body(b);
            }
            let res = r.send().await.map_err(|e| {
                if e.is_timeout() { anyhow!("__timeout__") } else { anyhow!("{}", name_cause(&e)) }
            })?;
            let status = res.status().as_u16();
            let url = res.url().to_string();
            let mut headers = Headers::new();
            let mut set_cookie = Vec::new();
            for (k, v) in res.headers().iter() {
                let name = k.as_str().to_lowercase();
                let value = String::from_utf8_lossy(v.as_bytes()).into_owned();
                if name == "set-cookie" {
                    set_cookie.push(value.clone());
                }
                match headers.get_mut(&name) {
                    Some(old) => {
                        old.push_str(", ");
                        old.push_str(&value);
                    }
                    None => {
                        headers.insert(name, value);
                    }
                }
            }
            let body = res.bytes().await.map_err(|e| if e.is_timeout() { anyhow!("__timeout__") } else { anyhow!("{}", name_cause(&e)) })?.to_vec();
            Ok(HttpResponse { status, headers, set_cookie, body, url })
        })
    }
}

static DEFAULT_FETCHER: LazyLock<SharedFetcher> = LazyLock::new(|| Arc::new(ReqwestFetcher::new()));

pub fn default_fetcher() -> SharedFetcher {
    DEFAULT_FETCHER.clone()
}

#[derive(Clone, Default)]
pub struct SendOptions {
    /// pacing key; normally the site name
    pub site: String,
    pub fetcher: Option<SharedFetcher>,
    pub timeout_ms: Option<u64>,
    /// minimum gap between requests to one site (default 1 s)
    pub min_interval_ms: Option<u64>,
}

static NUMERIC: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^-?\d+(\.\d+)?([eE][+-]?\d+)?$"));
static INTEGER: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^-?\d+$"));

/// Coerce an arg to the param's declared type. A numeric string past the largest safe integer is
/// never rounded: plain digits are kept exact, and any other form is refused.
fn coerce(p: &Param, v: &Value) -> Result<Value> {
    let bad = || anyhow!("param \"{}\" must be {}, got {}", p.name, p.kind.name(), json(v));
    match p.kind {
        ParamType::Number => {
            if let Value::Number(_) = v {
                return Ok(v.clone());
            }
            if let Value::String(s) = v {
                if NUMERIC.is_match(s) {
                    if !past_safe_integer(s) {
                        let f: f64 = s.parse().map_err(|_| bad())?;
                        return Ok(if f.fract() == 0.0 && f.abs() < 1e21 {
                            number_from_text(&format!("{}", f as i128))
                        } else {
                            serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
                        });
                    }
                    if INTEGER.is_match(s) {
                        return Ok(number_from_text(s));
                    }
                    let f: f64 = s.parse().unwrap_or(0.0);
                    bail!(
                        "param \"{}\" would lose precision: {} is past 2^53 and would be sent as {}; write the integer as plain digits",
                        p.name,
                        json(v),
                        js_number(f)
                    );
                }
            }
            Err(bad())
        }
        ParamType::Boolean => match v {
            Value::Bool(_) => Ok(v.clone()),
            Value::String(s) if s == "true" => Ok(Value::Bool(true)),
            Value::String(s) if s == "false" => Ok(Value::Bool(false)),
            _ => Err(bad()),
        },
        ParamType::Object | ParamType::Array => match v {
            Value::String(s) => serde_json::from_str::<Value>(s).map_err(|_| bad()),
            _ => Ok(v.clone()),
        },
        ParamType::String => Ok(match v {
            Value::String(_) => v.clone(),
            Value::Object(_) | Value::Array(_) => Value::String(json(v)),
            Value::Null => Value::String("null".to_string()),
            other => Value::String(as_text(other)),
        }),
    }
}

/// A number as JavaScript prints it (`String(1e21)` is "1e+21").
fn js_number(f: f64) -> String {
    if f.is_infinite() {
        return if f > 0.0 { "Infinity".to_string() } else { "-Infinity".to_string() };
    }
    if f.fract() == 0.0 && f.abs() < 1e21 {
        format!("{}", f as i128)
    } else if f.abs() >= 1e21 {
        let s = format!("{f:e}");
        s.replace('e', "e+")
    } else {
        f.to_string()
    }
}

pub fn resolve_ref(reference: &str, session: &Session, url: &str) -> Option<String> {
    let i = reference.find(':').map(|i| i + 1).unwrap_or(0);
    let name = &reference[i..];
    if reference.starts_with("cookie:") { cookie_value(&session.cookies, name, Some(url), now_ms()) } else { session.values.get(name).cloned() }
}

pub fn transform(v: &str, t: Option<Transform>) -> String {
    match t {
        Some(Transform::StripQuotes) => crate::secrets::strip_quotes(v),
        Some(Transform::UrlDecode) => decode_uri_component(v).unwrap_or_else(|| v.to_string()),
        None => v.to_string(),
    }
}

/// A slot a cookie or session value fills, whole or as a hole in its template.
pub fn holds_ref(s: &Slot) -> bool {
    s.is_ref() || s.template.as_ref().map(|t| !template_refs(t).is_empty()).unwrap_or(false)
}

/// The args a call runs with at every tier: a param the caller left out takes its default.
pub fn with_defaults(op: &Operation, args: &Args) -> Args {
    let mut out = Args::new();
    for p in &op.params {
        let v = args.get(&p.name).filter(|v| !v.is_null()).or(p.default.as_ref());
        if let Some(v) = v {
            out.insert(p.name.clone(), v.clone());
        }
    }
    out
}

/// A filled header whose value holds a line break or a NUL: no request can carry it, so none was sent.
#[derive(Debug)]
pub struct BadHeader(pub String);

impl std::fmt::Display for BadHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the {} header was filled with a value that holds a line break, which no request can carry", self.0)
    }
}
impl std::error::Error for BadHeader {}

static REFERER_OR_ORIGIN: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^header:(referer|origin)$"));

/// The fully materialized request: params, cookie/session refs, and the jar's Cookie header.
pub fn build_request(op: &Operation, args: &Args, session: &Session) -> Result<Request> {
    let given = with_defaults(op, args);
    let mut vals: Args = Args::new();
    for p in &op.params {
        let Some(v) = given.get(&p.name) else {
            if p.required {
                bail!("missing required param \"{}\"", p.name);
            }
            continue;
        };
        let c = coerce(p, v)?;
        if let Some(pat) = &p.pattern {
            let whole = crate::util::js_regex(&format!("^(?:{pat})$")).map_err(|e| anyhow!("param \"{}\" has a bad pattern: {e}", p.name))?;
            if !whole.is_match(&as_text(&c)).unwrap_or(false) {
                bail!(
                    "param \"{}\" must be {}, got {}",
                    p.name,
                    p.hint.clone().unwrap_or_else(|| format!("a value matching /{pat}/")),
                    json(v)
                );
            }
        }
        vals.insert(p.name.clone(), c);
    }

    let mut req = Request { method: op.request.method.to_uppercase(), url: op.request.url.clone(), headers: op.request.headers.clone(), body: op.request.body.clone() };
    let mut leaf_types: Option<HashMap<String, crate::codec::LeafType>> = None;
    req.headers.shift_remove("cookie");
    for slot in &op.slots {
        let name = slot.param.clone().or_else(|| slot.reference.clone()).unwrap_or_default();
        let mut v: Option<Value> = match &slot.param {
            Some(p) => vals.get(p).cloned(),
            None => resolve_ref(slot.ref_str(), session, &op.request.url).map(Value::String),
        };
        let Some(mut value) = v.take() else {
            // A missing session value: drop the header rather than send it blank.
            if slot.is_ref() && slot.at.len() == 1 {
                if let Some(h) = slot.at[0].strip_prefix("header:") {
                    req.headers.shift_remove(&h.to_lowercase());
                }
            }
            continue;
        };
        if slot.is_ref() {
            value = Value::String(transform(&as_text(&value), slot.transform));
        }
        if let Some(t) = &slot.template {
            // A Referer/Origin is a URL: specs learned before `escape` existed still get the arg percent-encoded.
            let escape = slot.escape.or_else(|| if slot.is_param() && REFERER_OR_ORIGIN.is_match(&slot.at[0]) { Some(Escape::Url) } else { None });
            let mut vars: Args = Args::new();
            for r in template_refs(t) {
                vars.insert(r.clone(), Value::String(resolve_ref(&r, session, &op.request.url).unwrap_or_default()));
            }
            for (k, x) in &vals {
                vars.insert(k.clone(), x.clone());
            }
            vars.insert(name.clone(), value);
            value = Value::String(fill_slot_template(t, &vars, escape));
        } else if !value.is_string() && !value.is_object() && !value.is_array() && slot.at.last().map(|s| s.starts_with("json:")).unwrap_or(false) {
            let types = leaf_types.get_or_insert_with(|| walk(&op.request).into_iter().map(|l| (crate::codec::step_key(&l.at), l.kind)).collect());
            // the same number can sit in a JSON string ("id":"12345") and a JSON number (ids:[12345]); each leaf keeps its type
            if types.get(&crate::codec::step_key(&slot.at)) == Some(&crate::codec::LeafType::String) {
                value = Value::String(as_text(&value));
            }
        }
        req = set_at(&req, &slot.at, &value)?;
    }

    // Header values must be bytes: a value that is not ASCII goes percent-encoded, as a browser sends a URL.
    for (_, h) in req.headers.iter_mut() {
        if !h.is_ascii() {
            let mut out = String::new();
            let mut run = String::new();
            for c in h.chars() {
                if c.is_ascii() {
                    if !run.is_empty() {
                        out.push_str(&encode_uri_component(&run));
                        run.clear();
                    }
                    out.push(c);
                } else {
                    run.push(c);
                }
            }
            if !run.is_empty() {
                out.push_str(&encode_uri_component(&run));
            }
            *h = out;
        }
    }
    let cookie = cookie_header_for(&session.cookies, &req.url, now_ms());
    if !cookie.is_empty() {
        req.headers.insert("cookie".to_string(), cookie);
    }
    // a client would refuse it quoting the value, which may be a session's: name the header only
    for (k, h) in &req.headers {
        if h.contains(['\r', '\n', '\0']) {
            return Err(BadHeader(k.clone()).into());
        }
    }
    Ok(req)
}

static LAST_SEND: LazyLock<Mutex<HashMap<String, f64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Reserve the next send slot for a site, then wait for it; concurrent callers queue up.
async fn pace(site: &str, min_interval_ms: u64) {
    let at = {
        let mut last = LAST_SEND.lock().unwrap();
        let now = now_ms();
        let at = now.max(last.get(site).copied().unwrap_or(0.0) + min_interval_ms as f64);
        last.insert(site.to_string(), at);
        at
    };
    let now = now_ms();
    if at > now {
        tokio::time::sleep(Duration::from_millis((at - now) as u64)).await;
    }
}

pub fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

// What describes a body, and goes with it when a redirect makes the request a GET.
const BODY_HEADERS: [&str; 5] = ["content-encoding", "content-language", "content-length", "content-location", "content-type"];

/// How many redirects one request is taken through, per tier.
pub const TIER1_REDIRECTS: usize = 5;
pub const MAX_REDIRECTS: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalKind {
    /// one too many
    Limit,
    /// it would have sent a write a second time
    Again,
}

/// A redirect the policy does not take: nothing was sent to its target.
#[derive(Debug)]
pub struct RedirectRefused {
    pub message: String,
    pub kind: Option<RefusalKind>,
}

impl std::fmt::Display for RedirectRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for RedirectRefused {}

/// What tells an op's own request: its `match`, or with none its template's method and address.
pub fn own_match(op: &Operation) -> Match {
    if !op.matcher.is_empty() {
        return op.matcher.clone();
    }
    let u = parse_url(&op.request.url);
    Match {
        method: Some(op.request.method.clone()),
        host: u.as_ref().map(|u| u.host_str().unwrap_or("").to_string()),
        path: u.as_ref().map(|u| u.path().to_string()),
        operation_name: None,
    }
}

/// The redirect policy of tiers 1 and 2: the request a redirect asks for next, or a refusal.
/// 303 after anything but a GET or HEAD, and 301/302 after a POST, make a bodiless GET. A write is
/// sent once, so no redirect is taken that would send it again. On an origin change the credential
/// headers go, and a hop that would still carry a session's value there is not taken.
pub fn next_hop(op: &Operation, session: &Session, from: &Request, status: u16, location: &str, taken: usize, limit: usize) -> Result<Request> {
    let base = parse_url(&from.url).ok_or_else(|| anyhow!("bad url {}", from.url))?;
    let next = base.join(location).map_err(|_| anyhow!("bad redirect location {location}"))?;
    let next_origin = crate::util::origin_of(&next);
    if taken >= limit {
        return Err(RedirectRefused { message: format!("stopped after {limit} redirects, the last one to {next_origin}"), kind: Some(RefusalKind::Limit) }.into());
    }
    let refused = |why: &str| RedirectRefused { message: format!("not following the HTTP {status} redirect to {next_origin}: {why}"), kind: None };
    if next.scheme() != "http" && next.scheme() != "https" {
        return Err(refused("it is not an http(s) address").into());
    }
    // The Fetch standard's two cases; a GET stays what it was, headers and all.
    let to_get = (status == 303 && from.method != "GET" && from.method != "HEAD") || ((status == 301 || status == 302) && from.method == "POST");
    let method = if to_get { "GET".to_string() } else { from.method.clone() };
    let carries_on = !to_get && from.method != "GET" && from.method != "HEAD";
    if !op.read_only && (carries_on || matches(&own_match(op), &bare_request(&method, next.as_str()))) {
        return Err(RedirectRefused { message: format!("not following the HTTP {status} redirect to {next_origin}: it would send this write again"), kind: Some(RefusalKind::Again) }.into());
    }
    let cross = next_origin != crate::util::origin_of(&base);
    // The slots that hold a cookie:/session: value, by the layer their path starts in ("header:x-csrf", "form[1]:tok").
    struct Held<'a> {
        s: &'a Slot,
        refs: Vec<String>,
        layer: String,
    }
    static LAYER: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[a-z]+"));
    let held: Vec<Held> = op
        .slots
        .iter()
        .filter(|s| holds_ref(s))
        .map(|s| {
            let mut refs: Vec<String> = s.reference.iter().cloned().collect();
            refs.extend(template_refs(s.template.as_deref().unwrap_or("")));
            Held { s, refs, layer: LAYER.find(&s.at[0]).map(|m| m.as_str().to_string()).unwrap_or_default() }
        })
        .collect();
    let mut secret: HashSet<String> = HashSet::from(["authorization".to_string(), "cookie".to_string()]);
    for h in &held {
        if h.layer == "header" {
            secret.insert(h.s.at[0][7..].to_lowercase());
        }
    }
    let drop = |name: &str| (to_get && BODY_HEADERS.contains(&name)) || (cross && secret.contains(name));
    let headers: Headers = from.headers.iter().filter(|(k, _)| !drop(&k.to_lowercase())).map(|(k, v)| (k.clone(), v.clone())).collect();
    let body = if to_get { None } else { from.body.clone() };
    if cross {
        let in_body = body.is_some() && held.iter().any(|h| h.layer == "body" || h.layer == "form");
        // every slot's, a header's too: the header is dropped, and the site may still have copied what it held
        let carried: Vec<String> = held
            .iter()
            .flat_map(|h| {
                h.refs.iter().filter_map(|r| {
                    let v = resolve_ref(r, session, &op.request.url)?;
                    if v.len() >= 4 { Some(if h.s.ref_str() == r { transform(&v, h.s.transform) } else { v }) } else { None }
                }).collect::<Vec<_>>()
            })
            .collect();
        // a search, not a proof: the address is percent- and form-decoded until nothing changes,
        // every reading kept, and the value looked for as it is, as a JSON string's contents, and in base64.
        static PCT: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)(%[0-9a-f]{2})+"));
        let unpct = |u: &str| PCT.replace_all(u, |m: &regex::Captures| decode_uri_component(&m[0]).unwrap_or_else(|| m[0].to_string())).into_owned();
        let mut readings: Vec<String> = vec![next.to_string()];
        let mut i = 0;
        while i < readings.len() && readings.len() <= 64 {
            let u = readings[i].clone();
            for r in [unpct(&u), unpct(&u.replace('+', " "))] {
                if !readings.contains(&r) {
                    readings.push(r);
                }
            }
            i += 1;
        }
        let forms = |v: &str| {
            let j = json_escape(v);
            vec![v.to_string(), j.clone(), j.replace('/', "\\/"), crate::util::b64_encode(v.as_bytes()).trim_end_matches('=').to_string(), crate::util::b64url_encode(v.as_bytes())]
        };
        if in_body || carried.iter().any(|v| forms(v).iter().any(|f| readings.iter().any(|u| u.contains(f.as_str())))) {
            return Err(refused("the request would carry this session's values to another origin").into());
        }
    }
    Ok(Request { url: next.to_string(), method, headers, body })
}

/// Send the filled template. Redirects are followed by hand, each hop decided by `next_hop`.
pub async fn send(op: &Operation, args: &Args, session: &Session, opts: &SendOptions) -> Result<Sent> {
    let req = build_request(op, args, session)?;
    pace(&opts.site, opts.min_interval_ms.unwrap_or(1000)).await;
    let timeout_ms = opts.timeout_ms.unwrap_or(30_000);
    let fetcher = opts.fetcher.clone().unwrap_or_else(default_fetcher);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut hop = Request { body: if req.method == "GET" || req.method == "HEAD" { None } else { req.body.clone() }, ..req.clone() };
    let t0 = now_ms();
    // Cookies set along the way (a consent or session bootstrap hop) ride on the next hop, as in a browser.
    let mut jar = session.cookies.clone();
    let mut set_cookies: Vec<StoredCookie> = Vec::new();
    let mut redirected: Option<bool> = None;
    let timeout_err = || anyhow!("{}: no response within {timeout_ms} ms", op.name);
    let mut hops = 0usize;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(timeout_err());
        }
        let http = HttpRequest { url: hop.url.clone(), method: hop.method.clone(), headers: hop.headers.clone(), body: hop.body.clone() };
        let res = match tokio::time::timeout(left, fetcher.fetch(http, left)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) if e.to_string() == "__timeout__" => return Err(timeout_err()),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(timeout_err()),
        };
        for line in &res.set_cookie {
            let Some(c) = parse_set_cookie(line, &hop.url, now_ms()) else { continue };
            set_cookies.push(c.clone());
            jar.retain(|x| !(x.name == c.name && x.domain.eq_ignore_ascii_case(&c.domain) && x.path == c.path));
            jar.push(c);
        }
        let location = res.headers.get("location").cloned();
        let is_redir = is_redirect(res.status) && location.as_ref().map(|l| !l.is_empty()).unwrap_or(false);
        if redirected.is_none() {
            redirected = Some(is_redir);
        }
        if let (true, Some(location)) = (is_redir, &location) {
            hop = next_hop(op, session, &hop, res.status, location, hops, TIER1_REDIRECTS)?;
            // the jar's cookies for the new address, whichever origin it is
            hop.headers.shift_remove("cookie");
            let cookie = cookie_header_for(&jar, &hop.url, now_ms());
            if !cookie.is_empty() {
                hop.headers.insert("cookie".to_string(), cookie);
            }
            hops += 1;
            continue;
        }
        let content_type = res.headers.get("content-type").cloned().unwrap_or_default();
        let text = decode_body(&res.body, &content_type);
        return Ok(Sent {
            status: res.status,
            headers: res.headers,
            body: text,
            url: if res.url.is_empty() { hop.url.clone() } else { res.url },
            ms: (now_ms() - t0).round() as u64,
            redirected: redirected.unwrap_or(false),
            set_cookies,
        });
    }
}

/// Decode with the declared charset (header, else an HTML <meta>), else UTF-8. A BOM is dropped.
pub fn decode_body(buf: &[u8], content_type: &str) -> String {
    static CHARSET: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"(?i)charset=["']?([\w.:-]+)"#));
    static META: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"(?i)<meta[^>]+charset=["']?([\w.:-]+)"#));
    let mut charset = CHARSET.captures(content_type).map(|m| m[1].to_string());
    if charset.is_none() && content_type.to_lowercase().contains("html") {
        let head: String = buf.iter().take(2048).map(|b| *b as char).collect();
        charset = META.captures(&head).map(|m| m[1].to_string());
    }
    let enc = charset.and_then(|c| encoding_rs::Encoding::for_label(c.as_bytes())).unwrap_or(encoding_rs::UTF_8);
    let (text, _, _) = enc.decode(buf);
    text.into_owned()
}

pub fn headers_from(pairs: &[(&str, &str)]) -> Headers {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// An ordered map from a JSON object literal, for callers building args by hand.
pub fn args_from(v: Value) -> Args {
    match v {
        Value::Object(o) => o,
        _ => Args::new(),
    }
}

pub fn headers_index(h: &Headers) -> IndexMap<String, String> {
    h.clone()
}
