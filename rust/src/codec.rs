//! Read and write values inside a captured request through its decoded layers.
//!
//! A step path like ["form:f.req", "json:/1", "json:/0/1/0/0"] means: take form field f.req, parse it
//! as JSON, take /1 (a string), parse that as JSON, take /0/1/0/0. `set_at` re-encodes only the layers
//! on that path and splices the result back, so every other byte (key order, whitespace, RestLi
//! parens, big integers, the site's own percent-encoding) stays identical.
//!
//! Root steps: path:<i> (i-th segment after the leading slash), query:<key>, header:<name>,
//! form:<key> (urlencoded body), body. A repeated key's later occurrences are query[<n>]:<key> and
//! form[<n>]:<key> (n counts from 0). Below them json:<RFC 6901 pointer>, and b64 (the current
//! string is base64 of JSON, as some apps pack their state into one query param).
use crate::spec::{Escape, Request};
use crate::util::{
    as_text, b64_decode_lenient_str, b64_encode, b64url_encode, decode_loose, encode_uri_component, is_json_text,
    json, json_escape, re,
};
use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

pub type Step = String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafType {
    String,
    Number,
    Boolean,
    Null,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Leaf {
    pub at: Vec<Step>,
    /// decoded text; JSON numbers/booleans/null as their source text
    pub value: String,
    pub kind: LeafType,
    /// the string was itself JSON and its leaves follow in the walk
    pub container: bool,
    /// on a container: the keys objects in its JSON repeat. Step paths reach such a key's first occurrence only.
    pub repeated: Vec<Vec<Step>>,
}

impl Leaf {
    pub fn is_string(&self) -> bool {
        self.kind == LeafType::String
    }
    pub fn key(&self) -> String {
        step_key(&self.at)
    }
}

/// A step path as one string, for sets and maps (`JSON.stringify(at)`).
pub fn step_key(at: &[Step]) -> String {
    json(&Value::Array(at.iter().map(|s| Value::String(s.clone())).collect()))
}

pub fn join_steps(at: &[Step]) -> String {
    at.join(" > ")
}

/* ------------------------------------------------------------- JSON spans */

fn is_ws(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'\n' || c == b'\r'
}

fn skip_ws(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && is_ws(s[i]) {
        i += 1;
    }
    i
}

fn literal_end(s: &[u8], i: usize) -> Option<usize> {
    for lit in [&b"true"[..], &b"false"[..], &b"null"[..]] {
        if s[i..].starts_with(lit) {
            return Some(i + lit.len());
        }
    }
    let mut j = i;
    if j < s.len() && s[j] == b'-' {
        j += 1;
    }
    let digits = |s: &[u8], mut j: usize| {
        let start = j;
        while j < s.len() && s[j].is_ascii_digit() {
            j += 1;
        }
        if j > start { Some(j) } else { None }
    };
    j = digits(s, j)?;
    if j < s.len() && s[j] == b'.' {
        if let Some(k) = digits(s, j + 1) {
            j = k;
        }
    }
    if j < s.len() && (s[j] == b'e' || s[j] == b'E') {
        let mut k = j + 1;
        if k < s.len() && (s[k] == b'+' || s[k] == b'-') {
            k += 1;
        }
        if let Some(k) = digits(s, k) {
            j = k;
        }
    }
    Some(j)
}

/// Index just past the JSON value that starts at i (a byte offset).
pub fn json_value_end(text: &str, mut i: usize) -> Result<usize> {
    let s = text.as_bytes();
    let c = s.get(i).copied();
    if c == Some(b'"') {
        i += 1;
        while i < s.len() {
            if s[i] == b'\\' {
                i += 1;
            } else if s[i] == b'"' {
                return Ok(i + 1);
            }
            i += 1;
        }
        bail!("unterminated JSON string");
    }
    if c == Some(b'{') || c == Some(b'[') {
        let mut depth = 0usize;
        while i < s.len() {
            let ch = s[i];
            if ch == b'"' {
                i = json_value_end(text, i)? - 1;
            } else if ch == b'{' || ch == b'[' {
                depth += 1;
            } else if ch == b'}' || ch == b']' {
                depth -= 1;
                if depth == 0 {
                    return Ok(i + 1);
                }
            }
            i += 1;
        }
        bail!("unterminated JSON container");
    }
    literal_end(s, i).ok_or_else(|| anyhow!("unexpected JSON at {i}"))
}

/// Visit each member/element of the container at i as (key, valueStart). Return true to stop.
fn each_child(text: &str, mut i: usize, f: &mut dyn FnMut(String, usize) -> Result<bool>) -> Result<()> {
    let s = text.as_bytes();
    let obj = s[i] == b'{';
    let close = if obj { b'}' } else { b']' };
    i = skip_ws(s, i + 1);
    if i < s.len() && s[i] == close {
        return Ok(());
    }
    let mut idx = 0usize;
    loop {
        let mut key = idx.to_string();
        if obj {
            let key_end = json_value_end(text, i)?;
            key = serde_json::from_str::<String>(&text[i..key_end]).map_err(|_| anyhow!("bad JSON key at {i}"))?;
            i = skip_ws(s, key_end);
            if i >= s.len() || s[i] != b':' {
                bail!("expected ':' at {i}");
            }
            i = skip_ws(s, i + 1);
        }
        if f(key, i)? {
            return Ok(());
        }
        i = skip_ws(s, json_value_end(text, i)?);
        if i < s.len() && s[i] == b',' {
            i = skip_ws(s, i + 1);
        } else if i < s.len() && s[i] == close {
            return Ok(());
        } else {
            bail!("expected ',' or '{}' at {i}", close as char);
        }
        idx += 1;
    }
}

fn unescape_token(t: &str) -> String {
    t.replace("~1", "/").replace("~0", "~")
}

pub fn escape_token(t: &str) -> String {
    t.replace('~', "~0").replace('/', "~1")
}

/// [start, end) of the value at an RFC 6901 pointer.
fn locate(text: &str, pointer: &str) -> Result<(usize, usize)> {
    if !pointer.is_empty() && !pointer.starts_with('/') {
        bail!("bad JSON pointer \"{pointer}\"");
    }
    let s = text.as_bytes();
    let mut start = skip_ws(s, 0);
    let tokens: Vec<String> =
        if pointer.is_empty() { vec![] } else { pointer[1..].split('/').map(unescape_token).collect() };
    for token in tokens {
        let mut found: Option<usize> = None;
        if start < s.len() && (s[start] == b'{' || s[start] == b'[') {
            each_child(text, start, &mut |key, at| {
                if key != token {
                    return Ok(false);
                }
                found = Some(at);
                Ok(true)
            })?;
        }
        start = found.ok_or_else(|| anyhow!("JSON pointer \"{pointer}\" not found"))?;
    }
    Ok((start, json_value_end(text, start)?))
}

fn fix_big_ints(v: Value) -> Value {
    match v {
        Value::Number(n) => {
            let t = n.to_string();
            let plain = !t.contains(['.', 'e', 'E']);
            let big = if plain {
                let d = t.trim_start_matches('-');
                d.len() > 16 || (d.len() == 16 && d > "9007199254740991")
            } else {
                match t.parse::<f64>() {
                    Ok(f) => f.is_finite() && f.fract() == 0.0 && f.abs() > 9007199254740991.0,
                    Err(_) => false,
                }
            };
            if big { Value::String(t) } else { Value::Number(n) }
        }
        Value::Array(a) => Value::Array(a.into_iter().map(fix_big_ints).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, x)| (k, fix_big_ints(x))).collect()),
        other => other,
    }
}

/// JSON.parse that keeps integers beyond 2^53 as their exact digit strings.
pub fn parse_json(text: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(text)?;
    Ok(fix_big_ints(v))
}

/// Encode a value as a JSON leaf, keeping its native type.
fn to_json(v: &Value) -> String {
    json(v)
}

/* ------------------------------------------------------ percent-encoding */

/// Percent-encode like the original raw text did: chars it left literal stay literal, and vice versa.
fn encode_like(value: &str, original: &str, plus_is_space: bool) -> String {
    let enc = encode_uri_component(value);
    let bytes = enc.as_bytes();
    let mut out = String::with_capacity(enc.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &enc[i + 1..i + 3];
            if let Ok(code) = u8::from_str_radix(hex, 16) {
                if code < 0x80 {
                    let ch = code as char;
                    if !"%&=#+ ".contains(ch) && original.contains(ch) {
                        out.push(ch);
                        i += 3;
                        continue;
                    }
                }
            }
            out.push_str(&enc[i..i + 3]);
            i += 3;
            continue;
        }
        let ch = bytes[i] as char;
        if "!'()*~".contains(ch) {
            let pct = format!("%{:02X}", bytes[i]);
            if original.to_uppercase().contains(&pct) {
                out.push_str(&pct);
            } else {
                out.push(ch);
            }
        } else {
            out.push(ch);
        }
        i += 1;
    }
    if plus_is_space && original.contains('+') { out.replace("%20", "+") } else { out }
}

/* ------------------------------------------------------------ root layers */

#[derive(Clone, Debug)]
struct SplitUrl {
    origin: String,
    segments: Vec<String>,
    query: Option<String>,
    hash: String,
}

fn split_url(url: &str) -> SplitUrl {
    let (no_hash, hash) = match url.find('#') {
        Some(i) => (&url[..i], url[i..].to_string()),
        None => (url, String::new()),
    };
    let (base, query) = match no_hash.find('?') {
        Some(i) => (&no_hash[..i], Some(no_hash[i + 1..].to_string())),
        None => (no_hash, None),
    };
    let scheme_end = base.find("//");
    let from = scheme_end.map(|i| i + 2).unwrap_or(0);
    let path_at = base[from..].find('/').map(|i| i + from);
    let origin = match path_at {
        Some(i) => base[..i].to_string(),
        None => base.to_string(),
    };
    let segments = match path_at {
        Some(i) => base[i + 1..].split('/').map(|s| s.to_string()).collect(),
        None => vec![],
    };
    SplitUrl { origin, segments, query, hash }
}

fn join_url(u: &SplitUrl) -> String {
    let path = if u.segments.is_empty() { String::new() } else { format!("/{}", u.segments.join("/")) };
    let query = match &u.query {
        Some(q) => format!("?{q}"),
        None => String::new(),
    };
    format!("{}{}{}{}", u.origin, path, query, u.hash)
}

#[derive(Clone, Debug)]
struct Pair {
    raw_key: String,
    raw_value: String,
    key: String,
}

fn parse_pairs(raw: &str) -> Vec<Pair> {
    if raw.is_empty() {
        return vec![];
    }
    raw.split('&')
        .map(|p| {
            let (raw_key, raw_value) = match p.find('=') {
                Some(eq) => (&p[..eq], &p[eq + 1..]),
                None => (p, ""),
            };
            Pair { raw_key: raw_key.to_string(), raw_value: raw_value.to_string(), key: decode_loose(raw_key, true) }
        })
        .collect()
}

/// The n-th pair with that key.
fn nth_pair(pairs: &[Pair], key: &str, n: usize) -> Option<usize> {
    let mut n = n as i64;
    for (i, p) in pairs.iter().enumerate() {
        if p.key == key {
            if n == 0 {
                return Some(i);
            }
            n -= 1;
        }
    }
    None
}

/// Rewrite one pair (the n-th with that key) in a raw a=b&c=d string; untouched pairs keep their bytes.
fn set_pair(raw: &str, key: &str, value: &str, n: usize) -> String {
    let mut parts: Vec<String> = if raw.is_empty() { vec![] } else { raw.split('&').map(|s| s.to_string()).collect() };
    let pairs = parse_pairs(raw);
    match nth_pair(&pairs, key, n) {
        None => parts.push(format!("{}={}", encode_uri_component(key), encode_like(value, raw, true))),
        Some(idx) => {
            let p = &pairs[idx];
            let original = if p.raw_value.is_empty() { raw } else { &p.raw_value };
            parts[idx] = format!("{}={}", p.raw_key, encode_like(value, original, true));
        }
    }
    parts.join("&")
}

pub fn content_type_of(req: &Request) -> String {
    req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone()).unwrap_or_default()
}

pub fn is_form_body(req: &Request) -> bool {
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)application/x-www-form-urlencoded"));
    RE.is_match(&content_type_of(req))
}

fn parse_step(step: &str) -> (String, String, usize) {
    let (kind, arg) = match step.find(':') {
        Some(i) => (&step[..i], &step[i + 1..]),
        None => (step, ""),
    };
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^(query|form)\[(\d+)\]$"));
    if let Some(m) = RE.captures(kind) {
        return (m[1].to_string(), arg.to_string(), m[2].parse().unwrap_or(0));
    }
    (kind.to_string(), arg.to_string(), 0)
}

/// The text at a root step.
fn root_get(req: &Request, step: &str) -> Result<Option<String>> {
    let (kind, arg, n) = parse_step(step);
    Ok(match kind.as_str() {
        "path" => {
            let u = split_url(&req.url);
            let i: usize = arg.parse().unwrap_or(usize::MAX);
            u.segments.get(i).map(|raw| decode_loose(raw, false))
        }
        "query" => {
            let u = split_url(&req.url);
            let pairs = parse_pairs(u.query.as_deref().unwrap_or(""));
            nth_pair(&pairs, &arg, n).map(|i| decode_loose(&pairs[i].raw_value, true))
        }
        "header" => req.headers.get(&arg.to_lowercase()).cloned(),
        "form" => {
            let pairs = parse_pairs(req.body.as_deref().unwrap_or(""));
            nth_pair(&pairs, &arg, n).map(|i| decode_loose(&pairs[i].raw_value, true))
        }
        "body" => req.body.clone(),
        _ => bail!("step \"{step}\" is not a request layer (path, query, header, form, body)"),
    })
}

/// Write text back at a root step.
fn root_put(req: &Request, step: &str, v: &str) -> Result<Request> {
    let (kind, arg, n) = parse_step(step);
    let mut out = req.clone();
    match kind.as_str() {
        "path" => {
            let mut u = split_url(&req.url);
            let i: usize = arg.parse().unwrap_or(usize::MAX);
            let Some(raw) = u.segments.get(i).cloned() else {
                bail!("no path segment {arg} in {}", req.url);
            };
            u.segments[i] = encode_like(v, &raw, false);
            out.url = join_url(&u);
        }
        "query" => {
            let mut u = split_url(&req.url);
            u.query = Some(set_pair(u.query.as_deref().unwrap_or(""), &arg, v, n));
            out.url = join_url(&u);
        }
        "header" => {
            out.headers.insert(arg.to_lowercase(), v.to_string());
        }
        "form" => out.body = Some(set_pair(req.body.as_deref().unwrap_or(""), &arg, v, n)),
        "body" => out.body = Some(v.to_string()),
        _ => bail!("step \"{step}\" is not a request layer (path, query, header, form, body)"),
    }
    Ok(out)
}

fn json_pointer(step: &str) -> Result<String> {
    let (kind, arg, _) = parse_step(step);
    if kind != "json" {
        bail!("step \"{step}\" must be json:<pointer> below the request layer");
    }
    Ok(arg)
}

/* ----------------------------------------------------------------- public */

/// The value at a step path: a parsed JSON leaf, or the text of a non-JSON layer. None when the
/// root layer has nothing there.
pub fn get_at(req: &Request, steps: &[Step]) -> Result<Option<Value>> {
    let Some((first, rest)) = steps.split_first() else { bail!("empty step path") };
    let Some(mut text) = root_get(req, first)? else { return Ok(None) };
    for (i, step) in rest.iter().enumerate() {
        if step == "b64" {
            text = from_b64(&text);
            continue;
        }
        let (a, b) = locate(&text, &json_pointer(step)?)?;
        let v = parse_json(&text[a..b])?;
        if i == rest.len() - 1 {
            return Ok(Some(v));
        }
        match v {
            Value::String(s) => text = s,
            _ => bail!("{step} is not a JSON string, cannot descend"),
        }
    }
    Ok(Some(Value::String(text)))
}

/// `get_at` as text, "" when nothing is there or the walk fails.
pub fn get_text(req: &Request, steps: &[Step]) -> String {
    match get_at(req, steps) {
        Ok(Some(v)) => as_text(&v),
        _ => String::new(),
    }
}

static B64: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9+/_-]{16,}={0,2}$"));

pub fn from_b64(s: &str) -> String {
    b64_decode_lenient_str(s)
}

/// Encode like the original: base64url when it used - or _, padding only when it had some.
fn to_b64_like(text: &str, original: &str) -> String {
    let url = original.contains(['-', '_']);
    let mut out = if url { b64url_encode(text.as_bytes()) } else { b64_encode(text.as_bytes()) };
    if original.ends_with('=') {
        while out.len() % 4 != 0 {
            out.push('=');
        }
        out
    } else {
        out.trim_end_matches('=').to_string()
    }
}

fn set_nested(text: &str, steps: &[Step], value: &Value) -> Result<String> {
    let (step, rest) = steps.split_first().expect("a step");
    if step == "b64" {
        let inner = if rest.is_empty() { as_text(value) } else { set_nested(&from_b64(text), rest, value)? };
        return Ok(to_b64_like(&inner, text));
    }
    let (a, b) = locate(text, &json_pointer(step)?)?;
    let replacement = if rest.is_empty() {
        to_json(value)
    } else {
        let inner: Value = serde_json::from_str(&text[a..b])?;
        let Value::String(inner) = inner else { bail!("{step} is not a JSON string, cannot descend") };
        json(&Value::String(set_nested(&inner, rest, value)?))
    };
    Ok(format!("{}{}{}", &text[..a], replacement, &text[b..]))
}

/// Return a copy of req with value written at steps. A whole JSON leaf keeps the value's native type.
pub fn set_at(req: &Request, steps: &[Step], value: &Value) -> Result<Request> {
    let Some((first, rest)) = steps.split_first() else { bail!("empty step path") };
    if rest.is_empty() {
        return root_put(req, first, &as_text(value));
    }
    let Some(text) = root_get(req, first)? else { bail!("nothing at {first}") };
    root_put(req, first, &set_nested(&text, rest, value)?)
}

pub fn set_text(req: &Request, steps: &[Step], value: &str) -> Result<Request> {
    set_at(req, steps, &Value::String(value.to_string()))
}

static TEMPLATE_HOLE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\{\{|\}\}|\{([^{}]+)\}"));

/// Replace `{name}` for names present in vars; anything else (e.g. minified GraphQL `{id}`) stays.
/// `{{` and `}}` are literal braces, so a learned template can hold text like `{name}` verbatim.
pub fn fill_template(template: &str, vars: &Map<String, Value>) -> String {
    TEMPLATE_HOLE
        .replace_all(template, |c: &regex::Captures| match c.get(1) {
            None => c[0][..1].to_string(),
            Some(k) => match vars.get(k.as_str()) {
                Some(v) => as_text(v),
                None => c[0].to_string(),
            },
        })
        .into_owned()
}

/// `fill_template` with string vars.
pub fn fill_template_str(template: &str, vars: &[(&str, &str)]) -> String {
    let map: Map<String, Value> = vars.iter().map(|(k, v)| (k.to_string(), Value::String(v.to_string()))).collect();
    fill_template(template, &map)
}

static REF_HOLE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\{\{|\}\}|\{((?:cookie|session):[^{}]+)\}"));

/// The `{cookie:x}`/`{session:x}` holes of a template: a param's leaf can carry a credential too.
pub fn template_refs(template: &str) -> Vec<String> {
    REF_HOLE.captures_iter(template).filter_map(|c| c.get(1).map(|m| m.as_str().to_string())).collect()
}

/// Literal text as a template: every brace doubled.
pub fn escape_template(text: &str) -> String {
    text.replace('{', "{{").replace('}', "}}")
}

pub fn escape_value(v: &Value, escape: Option<Escape>) -> String {
    let s = as_text(v);
    match escape {
        Some(Escape::Url) => encode_uri_component(&s),
        Some(Escape::Json) => json_escape(&s),
        None => s,
    }
}

pub fn escape_str(s: &str, escape: Option<Escape>) -> String {
    escape_value(&Value::String(s.to_string()), escape)
}

/// `fill_template` with every var escaped for the leaf's encoding layer.
pub fn fill_slot_template(template: &str, vars: &Map<String, Value>, escape: Option<Escape>) -> String {
    if escape.is_none() {
        return fill_template(template, vars);
    }
    let escaped: Map<String, Value> =
        vars.iter().map(|(k, v)| (k.clone(), Value::String(escape_value(v, escape)))).collect();
    fill_template(template, &escaped)
}

/// The pieces of a template between its holes, each hole as a (name) marker: literal text and
/// `{{`/`}}` keep their place as text.
pub fn template_parts(template: &str) -> Vec<TemplatePart> {
    let mut out = Vec::new();
    let mut last = 0;
    for m in TEMPLATE_HOLE.find_iter(template) {
        if m.start() > last {
            out.push(TemplatePart::Text(template[last..m.start()].to_string()));
        }
        let t = m.as_str();
        if t == "{{" || t == "}}" {
            out.push(TemplatePart::Brace(t[..1].to_string()));
        } else {
            out.push(TemplatePart::Hole(t[1..t.len() - 1].to_string()));
        }
        last = m.end();
    }
    if last < template.len() {
        out.push(TemplatePart::Text(template[last..].to_string()));
    }
    out
}

#[derive(Clone, Debug, PartialEq)]
pub enum TemplatePart {
    Text(String),
    Brace(String),
    Hole(String),
}

/* ------------------------------------------------------------------- walk */

fn visit_json(
    s: &str,
    i: usize,
    ptr: &str,
    at: &[Step],
    out: &mut Vec<Leaf>,
    repeated: &mut Vec<Vec<Step>>,
) -> Result<()> {
    let b = s.as_bytes();
    let c = b[i];
    if c == b'{' || c == b'[' {
        let mut seen: HashSet<String> = HashSet::new();
        return each_child(s, i, &mut |key, child| {
            let p = format!("{ptr}/{}", escape_token(&key));
            // noted where the object is walked: a repeated key may hold no leaf at all ({} twice)
            if c == b'{' && seen.contains(&key) {
                let mut full = at.to_vec();
                full.push(format!("json:{p}"));
                repeated.push(full);
            }
            seen.insert(key);
            visit_json(s, child, &p, at, out, repeated)?;
            Ok(false)
        });
    }
    let span = &s[i..json_value_end(s, i)?];
    let mut steps = at.to_vec();
    steps.push(format!("json:{ptr}"));
    if c == b'"' {
        let value: String = serde_json::from_str(span)?;
        let idx = out.len();
        out.push(Leaf { at: steps, value, kind: LeafType::String, container: false, repeated: vec![] });
        walk_inner(idx, out);
    } else {
        let kind = match c {
            b't' | b'f' => LeafType::Boolean,
            b'n' => LeafType::Null,
            _ => LeafType::Number,
        };
        out.push(Leaf { at: steps, value: span.to_string(), kind, container: false, repeated: vec![] });
    }
    Ok(())
}

/// Walk the leaves of s, the JSON text held at `at`, into out. False when s is not JSON.
fn walk_json_string(s: &str, at: &[Step], out: &mut Vec<Leaf>, repeated: &mut Vec<Vec<Step>>) -> bool {
    let b = s.as_bytes();
    let start = skip_ws(b, 0);
    if start >= b.len() || (b[start] != b'{' && b[start] != b'[') {
        return false;
    }
    if serde_json::from_str::<serde::de::IgnoredAny>(s).is_err() {
        return false;
    }
    let before = out.len();
    if visit_json(s, start, "", at, out, repeated).is_err() {
        out.truncate(before);
        repeated.clear();
        return false;
    }
    true
}

/// A string leaf that holds JSON, directly or base64-encoded, is a container: its leaves follow it in out.
fn walk_inner(idx: usize, out: &mut Vec<Leaf>) {
    let s = out[idx].value.clone();
    let at = out[idx].at.clone();
    let mut repeated = Vec::new();
    if walk_json_string(&s, &at, out, &mut repeated) {
        out[idx].container = true;
        out[idx].repeated = repeated;
    } else if B64.is_match(&s) {
        let text = from_b64(&s);
        // only a clean round trip counts: a hash or token decodes to bytes that are not JSON text
        let clean = is_json_text(&text)
            && b64_encode(text.as_bytes()).trim_end_matches('=') == s.replace('-', "+").replace('_', "/").trim_end_matches('=');
        let mut at2 = at.clone();
        at2.push("b64".to_string());
        if clean && walk_json_string(&text, &at2, out, &mut repeated) {
            out[idx].container = true;
            out[idx].repeated = repeated;
        }
    }
}

fn add_leaf(at: Vec<Step>, value: String, out: &mut Vec<Leaf>) {
    let idx = out.len();
    out.push(Leaf { at, value, kind: LeafType::String, container: false, repeated: vec![] });
    walk_inner(idx, out);
}

fn walk_pairs(kind: &str, raw: &str, out: &mut Vec<Leaf>) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for p in parse_pairs(raw) {
        let n = *seen.get(&p.key).unwrap_or(&0);
        seen.insert(p.key.clone(), n + 1);
        let step = if n > 0 { format!("{kind}[{n}]:{}", p.key) } else { format!("{kind}:{}", p.key) };
        add_leaf(vec![step], decode_loose(&p.raw_value, true), out);
    }
}

/// Every decoded leaf of the request with its step path, including JSON inside strings, recursively.
pub fn walk(req: &Request) -> Vec<Leaf> {
    let mut out = Vec::new();
    let u = split_url(&req.url);
    for (i, seg) in u.segments.iter().enumerate() {
        if !seg.is_empty() {
            add_leaf(vec![format!("path:{i}")], decode_loose(seg, false), &mut out);
        }
    }
    // A repeated key (tag=a&tag=b) is walked at every occurrence: query:tag, query[1]:tag, ...
    walk_pairs("query", u.query.as_deref().unwrap_or(""), &mut out);
    for (name, value) in req.headers.iter() {
        add_leaf(vec![format!("header:{}", name.to_lowercase())], value.clone(), &mut out);
    }
    if let Some(body) = &req.body {
        if !body.is_empty() {
            // Some clients (Algolia's) send a JSON body labeled form-urlencoded to skip the CORS preflight.
            if is_form_body(req) && !is_json_text(body) {
                walk_pairs("form", body, &mut out);
            } else {
                add_leaf(vec!["body".to_string()], body.clone(), &mut out);
            }
        }
    }
    out
}

/// The leaf's name at the end of its path (json:/a/b -> b; query:q -> q; header:x -> x).
pub fn last_token(at: &[Step]) -> String {
    let s = at.last().map(|s| s.as_str()).unwrap_or("");
    if let Some(rest) = s.strip_prefix("json:") {
        rest.rsplit('/').next().unwrap_or("").to_string()
    } else {
        match s.find(':') {
            Some(i) => s[i + 1..].to_string(),
            None => s.to_string(),
        }
    }
}

pub fn header_name(at: &[Step]) -> Option<String> {
    at.first().and_then(|s| s.strip_prefix("header:")).map(|s| s.to_string())
}

/// The name a leaf goes by: its header, field, query key or JSON key.
pub fn leaf_name(at: &[Step]) -> String {
    header_name(at).unwrap_or_else(|| last_token(at))
}

/// A slot at `at` takes in the leaf: the leaf is deeper in its layers, or below its JSON pointer.
pub fn covers(at: &[Step], leaf: &[Step]) -> bool {
    let last = at.len() - 1;
    let deeper = leaf.get(last) == at.get(last) && leaf.len() > at.len();
    let below = at[last].starts_with("json:")
        && leaf.get(last).map(|l| l.starts_with(&format!("{}/", at[last]))).unwrap_or(false);
    at[..last].iter().enumerate().all(|(i, step)| leaf.get(i) == Some(step)) && (deeper || below)
}
