//! Classify every response, never by status code alone. See DESIGN.md "Failure classifier".
use crate::extract::{extract, extract_html, get_path, infer_shape, parse_body};
use crate::html::{Doc, query_first};
use crate::spec::{Format, Operation};
use crate::types::Headers;
use crate::util::{iso_at, parse_date_ms, parse_url, re, squash_ws, take_chars};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Ok,
    Drift,
    Auth,
    Rate,
    Blocked,
    Input,
    #[default]
    Error,
    /// a write without allowWrites: never from the classifier
    Refused,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Class::Ok => "ok",
            Class::Drift => "drift",
            Class::Auth => "auth",
            Class::Rate => "rate",
            Class::Blocked => "blocked",
            Class::Input => "input",
            Class::Error => "error",
            Class::Refused => "refused",
        }
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Classified {
    pub class: Class,
    pub reason: String,
    /// drift: the response came back fine but without the data (extract path, selector or embedded
    /// JSON missing). blocked: a bare 403 with no wall or login markers, which is also how a site
    /// refuses one entity. Bad args look the same either way, so the caller checks the example args
    /// before healing or climbing tiers.
    pub missing: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Observed {
    pub status: u16,
    pub headers: Headers,
    pub body: String,
    /// final URL after redirects, when known
    pub url: Option<String>,
}

struct Challenge {
    vendor: &'static str,
    page: Option<regex::Regex>,
    sdk: Option<regex::Regex>,
}

// [vendor, interstitial, integration]. The interstitial pattern is the challenge page's own
// structure. The integration pattern is a script a vendor also puts on ordinary pages: it only
// counts on an answer whose status is a challenge's own.
static CHALLENGES: LazyLock<Vec<Challenge>> = LazyLock::new(|| {
    let c = |vendor, page: Option<&str>, sdk: Option<&str>| Challenge {
        vendor,
        page: page.map(|p| re(&format!("(?i){p}"))),
        sdk: sdk.map(|p| re(&format!("(?i){p}"))),
    };
    vec![
        c(
            "Cloudflare",
            Some(r"<title>Just a moment\.\.\.</title>|cf-chl-|_cf_chl_opt|Attention Required! \| Cloudflare"),
            Some(r"challenges\.cloudflare\.com"),
        ),
        c("Akamai", Some(r"bm-verify|/_sec/cp_challenge|errors\.edgesuite\.net"), None),
        c("DataDome", Some(r"captcha-delivery\.com"), Some(r"datadome")),
        c("PerimeterX", Some(r"px-captcha|Press & Hold"), Some(r"_pxAppId|perimeterx")),
        c(
            "AWS WAF",
            Some(r"awsWafCookieDomainList|gokuProps|<title>Human Verification</title>"),
            Some(r#"AwsWafIntegration|\.awswaf\.com|/__challenge_[\w-]+/[^"']*challenge\.js"#),
        ),
        c("Amazon", Some(r"automated access to Amazon data|/errors/validateCaptcha"), None),
        c("Imperva", Some(r"Incapsula incident"), Some(r"_Incapsula_Resource")),
        c("Kasada", None, Some(r"/[0-9a-f]{8}-[0-9a-f-]{27}/[0-9a-f]{8}-[0-9a-f-]{27}/ips\.js")),
        // a proof-of-work page that solves itself and resubmits (Reddit)
        c("JS challenge", Some(r#"name=["']?js_challenge|[?&]js_challenge=1"#), None),
        c("reCAPTCHA", Some(r"Prove your humanity"), None),
    ]
});
// A CAPTCHA widget is the challenge on a bare page, and a guard on the login when it sits in a sign-in form.
static CAPTCHA_WIDGET: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)google\.com/recaptcha|g-recaptcha|hcaptcha\.com"));
// What bot walls answer with: 202 (AWS WAF's JS challenge), 403, 405 (AWS WAF's CAPTCHA), 429, 503.
const CHALLENGE_STATUS: [u16; 5] = [202, 403, 405, 429, 503];
// An interstitial's title gives it away even when the page is too big for the body scan.
static CHALLENGE_TITLE: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(r"(?i)<title[^>]*>[^<]*(prove your humanity|human verification|just a moment|attention required|are you a (human|robot)|verify you are (a )?human|robot check)")
});

const LOGIN_SAID_SRC: &str = r#""require_login"\s*:\s*true|login_required|not logged in|(log|sign) ?in to continue|please (log|sign) ?in|authentication required|bad authentication|could not authenticate|bad guest token|invalid session|session (has )?expired"#;
static LOGIN_SAID: LazyLock<regex::Regex> = LazyLock::new(|| re(&format!("(?i){LOGIN_SAID_SRC}")));
static LOGIN: LazyLock<regex::Regex> =
    LazyLock::new(|| re(&format!(r#"(?i){LOGIN_SAID_SRC}|type=["']password["']|accounts\.google\.com/ServiceLogin"#)));

static PASSWORD_FIELD: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"(?i)type=["']?password"#));
static SIGN_IN_FORM: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(r#"(?i)<input[^>]*name=["']?(user(name)?|e-?mail|login|session_key)\b|autocomplete=["']?(current-password|username)|<form[^>]*action=["']?[^"'>\s]*(log_?in|sign_?in|sign-in|session)"#)
});

/// A sign-in form: a password field next to a username field, a current-password hint, or a form posting to a login path.
pub fn sign_in_form(body: &str) -> bool {
    PASSWORD_FIELD.is_match(body) && SIGN_IN_FORM.is_match(body)
}

static LOGIN_URL: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r"(?i)/(login|signin|sign_in|sign-in|accounts/login|i/flow/login|onboarding|ServiceLogin)(/|$|\?)"));

/// The URL's path is a sign-in page's, whether it was asked for or redirected to.
pub fn login_path(url: &str) -> bool {
    parse_url(url).map(|u| LOGIN_URL.is_match(u.path())).unwrap_or(false)
}

/// A document that is a login page. Only what the page says or shows counts.
fn login_page(body: &str) -> bool {
    LOGIN_SAID.is_match(body) || sign_in_form(body)
}

static RATE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)rate.?limit|too many requests|please wait a few minutes|slow down"));
static DRIFT: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(r"(?i)PersistedQueryNotFound|persisted query not found|must be defined|cannot be null|query not found|unknown (field|argument|operation)|cannot query field")
});
// A CSRF *failure*, not a page that merely carries a token. The gap stays inside one message: no quote or tag.
static CSRF_FAILED: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(r#"(?i)(csrf|xsrf)[^"<>\n]{0,40}?(missing|invalid|mismatch|incorrect|expired|fail|not (set|found|valid|match))|(invalid|missing|bad|expired|can'?t verify|could not verify|requires? an? (valid|matching))[^"<>\n]{0,30}?(csrf|xsrf|authenticity)|InvalidAuthenticityToken"#)
});
// Instagram sends "require_login": false on its rate-limit answers, so the key alone means nothing.
static REQUIRE_LOGIN: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"(?i)"require_login"\s*:\s*true|login_required"#));

fn snippet(s: &str) -> String {
    take_chars(&squash_ws(s), 160).to_string()
}

fn ok(reason: &str) -> Classified {
    Classified { class: Class::Ok, reason: reason.to_string(), missing: false }
}
fn is(c: Class, reason: String) -> Classified {
    Classified { class: c, reason, missing: false }
}
fn missing(reason: String) -> Classified {
    Classified { class: Class::Drift, reason, missing: true }
}

/// The vendor challenging here. `rides`: the marker also sits on ordinary pages, so a sign-in form explains it.
fn challenge(body: &str, status: u16) -> Option<(&'static str, bool)> {
    let head = take_chars(body, 200_000);
    let first = CHALLENGES.iter().find(|c| {
        c.page.as_ref().map(|p| p.is_match(head)).unwrap_or(false)
            || (CHALLENGE_STATUS.contains(&status) && c.sdk.as_ref().map(|s| s.is_match(head)).unwrap_or(false))
    });
    // one interstitial marker anywhere on the page settles it, whichever vendor is named first
    if let Some(f) = first {
        let any_page = CHALLENGES.iter().any(|c| c.page.as_ref().map(|p| p.is_match(head)).unwrap_or(false));
        return Some((f.vendor, !any_page));
    }
    if CAPTCHA_WIDGET.is_match(head) { Some(("reCAPTCHA", true)) } else { None }
}

fn header<'a>(h: &'a Headers, name: &str) -> Option<&'a String> {
    h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v)
}

static HTML_START: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^\s*<(!doctype|html)"));

fn is_html(r: &Observed) -> bool {
    let ct = header(&r.headers, "content-type").map(|s| s.to_lowercase()).unwrap_or_default();
    ct.contains("html") || HTML_START.is_match(&r.body)
}

/// The bot wall this response is, if any ("Cloudflare challenge page (HTTP 403)"). `has_data`: the
/// op's recipe finds its data on this page, so a title alone is an ordinary page.
pub fn bot_wall(r: &Observed, wants_json: bool, has_data: Option<&dyn Fn() -> bool>) -> Option<String> {
    let body = &r.body;
    let html = is_html(r);
    if header(&r.headers, "cf-mitigated").map(|v| v == "challenge").unwrap_or(false) {
        return Some("Cloudflare challenge (cf-mitigated)".to_string());
    }
    // Kasada's headers ride on its sites' ordinary answers too: only its challenge status is a wall, and
    // not on a sign-in form (an interstitial's markers on that page are still caught below).
    let kasada = r.headers.keys().any(|k| k.to_lowercase().starts_with("x-kpsdk"));
    if kasada && CHALLENGE_STATUS.contains(&r.status) && !sign_in_form(body) {
        return Some(format!("Kasada challenge (HTTP {})", r.status));
    }
    if r.status >= 400 || (html && (wants_json || crate::util::js_len(body) < 64_000)) {
        if let Some((vendor, rides)) = challenge(body, r.status) {
            // A widget on a sign-in form asks for a login, which no transport tier gets past. An
            // interstitial's own markers are a wall whatever form the page carries.
            if !(rides && sign_in_form(body)) {
                return Some(format!("{vendor} challenge page (HTTP {})", r.status));
            }
        }
    }
    if html && CHALLENGE_TITLE.is_match(take_chars(body, 20_000)) && !has_data.map(|f| f()).unwrap_or(false) {
        return Some(format!("challenge page (HTTP {})", r.status));
    }
    None
}

/// The html/embedded recipe finds data here (a non-empty list, or a value). Never fails.
fn recipe_finds(op: &Operation, body: &str) -> bool {
    match op.response.format {
        Format::Html => op.response.html.as_ref().map(|h| extract_html(body, h).map(|r| !r.is_empty()).unwrap_or(false)).unwrap_or(false),
        Format::Embedded => match extract(&op.response, body) {
            Ok(Some(Value::Array(a))) => !a.is_empty(),
            Ok(Some(_)) => true,
            _ => false,
        },
        Format::Json => false,
    }
}

/// An items selector's container: the part before its last compound ("ul.results li.r" -> "ul.results",
/// "#search > div.item" -> "#search"). None for a single compound or a selector list.
fn container_of(selector: &str) -> Option<(String, String)> {
    let s = selector.trim();
    let chars: Vec<char> = s.chars().collect();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut cut: i64 = -1;
    for (i, &c) in chars.iter().enumerate() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        } else if c == '[' || c == '(' {
            depth += 1;
        } else if c == ']' || c == ')' {
            depth -= 1;
        } else if depth == 0 && c == ',' {
            return None;
        } else if depth == 0 && (c.is_whitespace() || c == '>' || c == '+' || c == '~') {
            cut = i as i64;
        }
    }
    if cut <= 0 {
        return None;
    }
    let container: String = chars[..cut as usize].iter().collect();
    let container = container.trim_end_matches(|c: char| c.is_whitespace() || c == '>' || c == '+' || c == '~').trim().to_string();
    let item: String = chars[cut as usize + 1..].iter().collect();
    let item = item.trim().to_string();
    if container.is_empty() || item.is_empty() { None } else { Some((container, item)) }
}

/// A results page with no results: the items' container is on the page and holds nothing of the
/// items' tag (any element, when the selector names no tag). Items there under another class
/// are a renamed selector (drift), not zero results.
pub fn empty_results(body: &str, items: &str) -> bool {
    let Some((container, item)) = container_of(items) else { return false };
    static TAG: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^[a-z][a-z0-9-]*"));
    let doc = Doc::parse(body);
    let Ok(Some(bx)) = doc.select_first(&container) else { return false };
    let tag = TAG.find(&item).map(|m| m.as_str().to_string()).unwrap_or_else(|| "*".to_string());
    matches!(query_first(bx, &tag), Ok(None))
}

/// " (retry after 120 s)" from a Retry-After header in seconds or as an HTTP date.
fn retry_after(headers: &Headers) -> String {
    let Some(v) = header(headers, "retry-after").map(|v| v.trim().to_string()) else { return String::new() };
    if v.is_empty() {
        return String::new();
    }
    if v.chars().all(|c| c.is_ascii_digit()) {
        return format!(" (the server says retry after {v} s)");
    }
    match parse_date_ms(&v) {
        Some(t) => format!(" (the server says retry after {})", iso_at(t)),
        None => String::new(),
    }
}

/// A GraphQL errors array's verdict; `input` for a not-found entity.
fn graphql_errors(errors: &[Value], extra: &str) -> Classified {
    let msg = errors
        .iter()
        .map(|e| match e.get("message") {
            Some(Value::String(s)) => s.clone(),
            Some(m) if !m.is_null() => crate::util::as_text(m),
            _ => crate::util::json(e),
        })
        .collect::<Vec<_>>()
        .join("; ");
    let types = errors
        .iter()
        .map(|e| {
            let t = e.get("type").or_else(|| e.get("extensions").and_then(|x| x.get("code")));
            match t {
                Some(Value::String(s)) => s.clone(),
                Some(v) if !v.is_null() => crate::util::as_text(v),
                _ => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    static NOT_FOUND: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)not found|could not resolve|does not exist|no such"));
    static NF_TYPE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)NOT_FOUND"));
    if DRIFT.is_match(&msg) {
        return is(Class::Drift, format!("GraphQL: {}", snippet(&msg)));
    }
    if LOGIN.is_match(&msg) {
        return is(Class::Auth, format!("GraphQL: {}", snippet(&msg)));
    }
    if RATE.is_match(&msg) {
        return is(Class::Rate, format!("GraphQL: {}", snippet(&msg)));
    }
    if NF_TYPE.is_match(&types) || NOT_FOUND.is_match(&msg) {
        return is(Class::Input, format!("GraphQL: {}", snippet(&msg)));
    }
    is(Class::Error, format!("GraphQL errors{extra}: {}", snippet(&msg)))
}

/// Learned shape and value, scoped to the extract path when it resolves: other subtrees may come and go.
fn shape_scope(op: &Operation, data: &Value) -> (indexmap::IndexMap<String, String>, Option<Value>) {
    let shape = op.response.shape.clone().unwrap_or_default();
    let Some(ex) = &op.response.extract else { return (shape, Some(data.clone())) };
    static IDX: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\[(\d+|\*)\]"));
    static QUOTED: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"\["((?:[^"\\]|\\.)*)"\]"#));
    let prefix = IDX.replace_all(ex, "[]");
    let prefix = QUOTED.replace_all(&prefix, |m: &regex::Captures| format!(".{}", json_unquote_or(&m[1])));
    let prefix = prefix.trim_start_matches('.').to_string();
    let mut expected = indexmap::IndexMap::new();
    // a trailing [*] returns the items themselves, as a list: compare them as "[]..." like any list
    let items = ex.ends_with("[*]");
    for (k, t) in &shape {
        if items && (k == &prefix || k.starts_with(&format!("{prefix}.")) || k.starts_with(&format!("{prefix}[]"))) {
            expected.insert(format!("[]{}", &k[prefix.len()..]), t.clone());
        } else if k.starts_with(&format!("{prefix}.")) {
            expected.insert(k[prefix.len() + 1..].to_string(), t.clone());
        } else if k.starts_with(&format!("{prefix}[]")) {
            expected.insert(k[prefix.len()..].to_string(), t.clone());
        }
    }
    (expected, get_path(data, Some(ex)))
}

fn json_unquote_or(s: &str) -> String {
    crate::util::json_unquote(s).unwrap_or_else(|| s.to_string())
}

/// Share of the learned shape still present with the same type; null matches anything.
fn shape_kept(expected: &indexmap::IndexMap<String, String>, data: Option<&Value>) -> f64 {
    let now = match data {
        Some(d) => infer_shape(d, 2000),
        None => indexmap::IndexMap::new(),
    };
    let kept = expected
        .iter()
        .filter(|(p, t)| match now.get(*p) {
            Some(n) => n == *t || n == "null" || *t == "null",
            None => false,
        })
        .count();
    kept as f64 / expected.len() as f64
}

fn mentions_param(op: &Operation, body: &str) -> bool {
    let mut names: Vec<String> = op.params.iter().map(|p| p.name.clone()).collect();
    for s in &op.slots {
        if s.param.is_none() {
            continue;
        }
        // the nearest named step: json:/legs/0/origin/airports/0 names "airports", not "0"
        let tokens: Vec<String> = s
            .at
            .iter()
            .flat_map(|st| match st.strip_prefix("json:") {
                Some(p) => p.split('/').map(|t| t.to_string()).collect::<Vec<_>>(),
                None => vec![st[st.find(':').map(|i| i + 1).unwrap_or(0)..].to_string()],
            })
            .collect();
        if let Some(name) = tokens.iter().rev().find(|t| !t.is_empty() && !t.chars().all(|c| c.is_ascii_digit())) {
            names.push(name.clone());
        }
    }
    names.iter().any(|n| !n.is_empty() && re(&format!(r"(?i)\b{}\b", regex::escape(n))).is_match(body))
}

/// What `judge` says when the op's own recipe (a selector, a regex) cannot run: TS throws from
/// `classify` and `judge` catches it as this error.
fn recipe_failed(e: &anyhow::Error) -> Classified {
    is(Class::Error, format!("the op's response recipe failed: {}", crate::util::first_line(&e.to_string())))
}

pub fn classify(op: &Operation, r: &Observed) -> Classified {
    let body = r.body.as_str();
    let html = is_html(r);
    let wants_json = op.response.format == Format::Json;

    let finds = || recipe_finds(op, body);
    if let Some(wall) = bot_wall(r, wants_json, Some(&finds)) {
        return is(Class::Blocked, wall);
    }

    let wait = retry_after(&r.headers);
    if r.status == 429 {
        return is(Class::Rate, format!("HTTP 429{wait}"));
    }
    if r.status >= 400 && REQUIRE_LOGIN.is_match(body) {
        return is(Class::Auth, format!("HTTP {}: {}", r.status, snippet(body)));
    }
    if r.status >= 400 && RATE.is_match(body) {
        return is(Class::Rate, format!("HTTP {}{wait}: {}", r.status, snippet(body)));
    }
    // Laravel answers a stale CSRF token with 419, Rails with 422 InvalidAuthenticityToken.
    if r.status == 419 || ((r.status == 400 || r.status == 422) && CSRF_FAILED.is_match(body)) {
        return is(Class::Auth, format!("HTTP {}: CSRF check failed: {}", r.status, snippet(body)));
    }
    if r.status == 401 {
        return is(Class::Auth, format!("HTTP 401: {}", snippet(body)));
    }
    if r.status == 403 {
        return if LOGIN.is_match(body) || CSRF_FAILED.is_match(body) {
            is(Class::Auth, format!("HTTP 403 with login markers: {}", snippet(body)))
        } else {
            Classified { class: Class::Blocked, reason: format!("HTTP 403 with no login or challenge markers: {}", snippet(body)), missing: true }
        };
    }
    if let Some(u) = r.url.as_ref().and_then(|u| parse_url(u)) {
        let own = parse_url(&op.request.url).map(|o| LOGIN_URL.is_match(o.path())).unwrap_or(false);
        if LOGIN_URL.is_match(u.path()) && !own {
            return is(Class::Auth, format!("redirected to {}", u.path()));
        }
    }
    if r.status == 404 || r.status == 410 {
        // With the param in the path, 404 usually means that entity doesn't exist. With a rotating id
        // in the path too (Next.js /_next/data/<buildId>/...), it may be a deploy: let the caller check.
        // A read's 404 is ambiguous either way (/api/user?name=nosuch): the example args tell.
        if !op.slots.iter().any(|s| s.param.is_some() && s.at[0].starts_with("path:")) {
            return if op.read_only {
                missing(format!("HTTP {} on a templated API path", r.status))
            } else {
                is(Class::Drift, format!("HTTP {} on a templated API path", r.status))
            };
        }
        return if op.volatile.iter().any(|v| v.at[0].starts_with("path:")) {
            missing(format!("HTTP {}", r.status))
        } else {
            is(Class::Input, format!("HTTP {}: not found", r.status))
        };
    }
    if r.status == 400 && DRIFT.is_match(body) {
        return is(Class::Drift, format!("HTTP 400 schema error: {}", snippet(body)));
    }
    // a 400/422 form page (a signup's "username taken") shows a password field; only the wording counts
    if (r.status == 400 || r.status == 422) && LOGIN_SAID.is_match(body) {
        return is(Class::Auth, format!("HTTP {} with login markers: {}", r.status, snippet(body)));
    }
    if r.status == 400 && mentions_param(op, body) {
        return is(Class::Input, format!("HTTP 400: {}", snippet(body)));
    }
    if !(200..300).contains(&r.status) {
        return is(Class::Error, format!("HTTP {}: {}", r.status, snippet(body)));
    }

    let data: Option<Value> = match parse_body(body, op.response.xssi_prefix.as_deref()) {
        Ok(d) => Some(d),
        Err(_) => {
            if !op.read_only {
                let ct = op.response.content_type.as_deref().unwrap_or("");
                if html && !ct.to_lowercase().contains("html") && sign_in_form(body) {
                    return is(Class::Auth, "a sign-in form where the write's answer was expected".to_string());
                }
                return ok(&format!("HTTP {}, {}", r.status, if body.trim().is_empty() { "empty body" } else { "non-JSON body" }));
            }
            if wants_json {
                if html && LOGIN.is_match(body) {
                    return is(Class::Auth, "HTML login page where JSON was expected".to_string());
                }
                if body.trim().is_empty() {
                    return missing(format!("HTTP {} with an empty body", r.status));
                }
                return is(
                    Class::Drift,
                    if html { "HTML where JSON was expected".to_string() } else { format!("response is not JSON: {}", snippet(body)) },
                );
            }
            None
        }
    };
    let d = data.as_ref();
    if !op.read_only {
        if let Some(obj) = d.and_then(|v| v.as_object()) {
            if obj.get("ok") == Some(&Value::Bool(false)) || obj.get("success") == Some(&Value::Bool(false)) {
                return is(Class::Error, "the service rejected the write (ok/success is false)".to_string());
            }
        }
    }
    let errors: Option<&Vec<Value>> = d.and_then(|v| v.get("errors")).and_then(|e| e.as_array()).filter(|a| !a.is_empty());
    if let Some(errs) = errors {
        let data_field = d.and_then(|v| v.get("data"));
        if data_field.map(|x| x.is_null()).unwrap_or(true) {
            return graphql_errors(errs, " with null data");
        }
        // Partial data: errors next to a null target (a rate limit, a not-found user) are the answer, not a successful null.
        if let Some(ex) = &op.response.extract {
            let target = d.and_then(|v| get_path(v, Some(ex)));
            if target.map(|t| t.is_null()).unwrap_or(true) {
                return graphql_errors(errs, &format!(" and a null \"{ex}\""));
            }
        }
    }
    if !op.read_only {
        return ok("ok");
    }

    if op.response.format == Format::Html {
        let Some(h) = &op.response.html else { return ok("ok") };
        // a bad selector in the spec: an error (TS throws here and `judge` reports it), not drift
        match extract_html(body, h) {
            Ok(rows) if !rows.is_empty() => return ok("ok"),
            Ok(_) => {}
            Err(e) => return recipe_failed(&e),
        }
        if login_page(body) {
            return is(Class::Auth, "login page instead of content".to_string());
        }
        if empty_results(body, &h.items) {
            return ok("no results");
        }
        return missing(format!("selector \"{}\" matched nothing", h.items));
    }
    if op.response.format == Format::Embedded {
        match extract(&op.response, body) {
            Ok(Some(_)) => return ok("ok"),
            Ok(None) => {}
            Err(e) => return recipe_failed(&e),
        }
        return if login_page(body) {
            is(Class::Auth, "login page instead of content".to_string())
        } else {
            missing("embedded data not found".to_string())
        };
    }

    // An empty list where the results go is a search with no results, not missing data.
    let data = data.unwrap_or(Value::Null);
    let target = match &op.response.extract {
        Some(ex) => get_path(&data, Some(ex)),
        None => Some(data.clone()),
    };
    if matches!(&target, Some(Value::Array(a)) if a.is_empty()) {
        return ok("no results");
    }
    let mut gone: Option<String> = None;
    let scope = op.response.shape.as_ref().map(|_| shape_scope(op, &data));
    if op.response.extract.is_some() && target.is_none() {
        gone = Some(format!("extract path \"{}\" missing", op.response.extract.as_deref().unwrap_or("")));
    } else if let Some((expected, value)) = &scope {
        if expected.len() >= 4 && shape_kept(expected, value.as_ref()) < 0.5 {
            gone = Some("response shape changed (under half of the learned key paths remain)".to_string());
        }
    }
    let Some(gone) = gone else { return ok("ok") };
    // Instagram answers "login_required" and "please wait" as 200 JSON; only trust the wording when the data is gone.
    if REQUIRE_LOGIN.is_match(body) {
        return is(Class::Auth, format!("{gone}: {}", snippet(body)));
    }
    if RATE.is_match(body) {
        return is(Class::Rate, format!("{gone}: {}", snippet(body)));
    }
    if LOGIN.is_match(body) {
        return is(Class::Auth, format!("{gone}: {}", snippet(body)));
    }
    missing(gone)
}

#[derive(Clone, Debug)]
pub struct Judged {
    pub class: Class,
    pub reason: String,
    pub missing: bool,
    /// extracted and picked; only when ok
    pub data: Option<Value>,
}

impl Judged {
    fn from(c: Classified) -> Judged {
        Judged { class: c.class, reason: c.reason, missing: c.missing, data: None }
    }
}

/// classify, then extract when ok. Never fails: a bad selector or regex in the spec is an error.
pub fn judge(op: &Operation, r: &Observed) -> Judged {
    let c = classify(op, r);
    if c.class != Class::Ok {
        return Judged::from(c);
    }
    match extract(&op.response, &r.body) {
        Ok(data) => Judged { data, ..Judged::from(c) },
        Err(e) => {
            // a write's non-JSON answer: hand back its text
            if !op.read_only {
                let text = r.body.trim();
                let data = if text.is_empty() { Value::Null } else { Value::String(take_chars(&r.body, 1000).to_string()) };
                return Judged { data: Some(data), ..Judged::from(c) };
            }
            Judged::from(is(Class::Drift, format!("extract failed: {}", crate::util::first_line(&e.to_string()))))
        }
    }
}
