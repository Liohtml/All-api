//! Small helpers that give the core the JavaScript semantics the design was written against:
//! `encodeURIComponent`, `decodeURIComponent`, `JSON.stringify`, string lengths in UTF-16 units.
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

/// `encodeURIComponent`: everything but `A-Z a-z 0-9 - _ . ! ~ * ' ( )` is percent-encoded.
const COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}')
    .add(0x7f);

pub fn encode_uri_component(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT).to_string()
}

/// `decodeURIComponent`: a malformed escape (a lone `%`, or bytes that are not UTF-8) is an error.
pub fn decode_uri_component(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() || !bytes[i + 1].is_ascii_hexdigit() || !bytes[i + 2].is_ascii_hexdigit() {
                return None;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    percent_decode_str(s).decode_utf8().ok().map(|c| c.into_owned())
}

/// Decode, or keep the raw text when it is not a valid encoding (`+` as a space when asked).
pub fn decode_loose(raw: &str, plus_is_space: bool) -> String {
    let text = if plus_is_space { raw.replace('+', " ") } else { raw.to_string() };
    decode_uri_component(&text).unwrap_or(text)
}

/// `JSON.stringify(v)`: compact, keys in insertion order.
pub fn json(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
}

/// `JSON.stringify(v, null, n)`.
pub fn json_pretty(v: &Value, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(pad.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    serde::Serialize::serialize(v, &mut ser).ok();
    String::from_utf8(out).unwrap_or_default()
}

/// `JSON.stringify(s).slice(1, -1)`: the inside of a JSON string literal.
pub fn json_escape(s: &str) -> String {
    let q = serde_json::to_string(s).unwrap_or_default();
    q[1..q.len() - 1].to_string()
}

/// Text for a non-JSON layer: strings as they are, containers as JSON, null as nothing.
pub fn as_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Object(_) | Value::Array(_) => json(v),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
    }
}

/// A string's length as JavaScript counts it (UTF-16 code units).
pub fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `s.slice(0, n)` counted in characters, never cutting a character in two.
pub fn take_chars(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// The byte offset of the first `pat` in `s` at or after `from` (a byte offset).
pub fn find_from(s: &str, pat: &str, from: usize) -> Option<usize> {
    if from > s.len() {
        return None;
    }
    s[from..].find(pat).map(|i| i + from)
}

/// Case-insensitive `includes`.
pub fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(&needle.to_lowercase())
}

pub fn now_ms() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64() * 1000.0).unwrap_or(0.0)
}

pub fn iso_now() -> String {
    iso_at(now_ms())
}

/// `new Date(ms).toISOString()`.
pub fn iso_at(ms: f64) -> String {
    let secs = (ms / 1000.0).floor() as i64;
    let nanos = ((ms - secs as f64 * 1000.0) * 1_000_000.0).round().max(0.0) as u32;
    match chrono::DateTime::from_timestamp(secs, nanos) {
        Some(t) => t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        None => "1970-01-01T00:00:00.000Z".to_string(),
    }
}

/// `Date.parse`: an HTTP date, an RFC 3339 date, or an RFC 2822 date, in ms since the epoch.
pub fn parse_date_ms(s: &str) -> Option<f64> {
    let s = s.trim();
    if let Ok(t) = httpdate::parse_http_date(s) {
        return t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs_f64() * 1000.0);
    }
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(t.timestamp_millis() as f64);
    }
    if let Ok(t) = chrono::DateTime::parse_from_rfc2822(s) {
        return Some(t.timestamp_millis() as f64);
    }
    if let Ok(t) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(t.and_utc().timestamp_millis() as f64);
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis() as f64);
    }
    None
}

/* -------------------------------------------------------------------- URLs */

pub fn parse_url(s: &str) -> Option<Url> {
    Url::parse(s).ok()
}

/// `new URL(s).origin` ("null" for an opaque origin, as in a browser).
pub fn origin_of(u: &Url) -> String {
    u.origin().ascii_serialization()
}

pub fn origin_str(s: &str) -> Option<String> {
    parse_url(s).map(|u| origin_of(&u))
}

/// `new URL(s).hostname`, lower-cased by the parser.
pub fn hostname(u: &Url) -> String {
    u.host_str().unwrap_or("").to_string()
}

/// `new URL(s).search`: `?a=b`, or nothing.
pub fn search_of(u: &Url) -> String {
    match u.query() {
        Some(q) => format!("?{q}"),
        None => String::new(),
    }
}

/// `new URL(location, base).href`.
pub fn resolve_url(location: &str, base: &str) -> Option<String> {
    let b = parse_url(base)?;
    b.join(location).ok().map(|u| u.to_string())
}

/// The first line of a multi-line message.
pub fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

/// `s.replace(/\s+/g, " ").trim()`.
pub fn squash_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
            }
            in_ws = true;
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out.trim().to_string()
}

/// A lenient base64 decoder, like `Buffer.from(s, "base64")`: both alphabets, padding optional,
/// anything else skipped, a trailing lone character dropped.
pub fn b64_decode_lenient(input: &[u8]) -> Vec<u8> {
    let mut sextets = Vec::with_capacity(input.len());
    for &c in input {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        sextets.push(v);
    }
    let mut out = Vec::with_capacity(sextets.len() * 3 / 4);
    for chunk in sextets.chunks(4) {
        match chunk.len() {
            4 => {
                out.push((chunk[0] << 2) | (chunk[1] >> 4));
                out.push((chunk[1] << 4) | (chunk[2] >> 2));
                out.push((chunk[2] << 6) | chunk[3]);
            }
            3 => {
                out.push((chunk[0] << 2) | (chunk[1] >> 4));
                out.push((chunk[1] << 4) | (chunk[2] >> 2));
            }
            2 => out.push((chunk[0] << 2) | (chunk[1] >> 4)),
            _ => {}
        }
    }
    out
}

pub fn b64_decode_lenient_str(s: &str) -> String {
    String::from_utf8_lossy(&b64_decode_lenient(s.as_bytes())).into_owned()
}

/// Standard base64 with padding, as `Buffer.toString("base64")`.
pub fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// URL-safe base64 without padding, as `Buffer.toString("base64url")`.
pub fn b64url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn is_json_text(s: &str) -> bool {
    matches!(s.trim_start().chars().next(), Some('[') | Some('{'))
}

/// `regex` for a JavaScript-style pattern, case-insensitive when asked; `fancy_regex` supports lookarounds.
pub fn re(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).unwrap_or_else(|e| panic!("bad regex {pattern}: {e}"))
}

pub fn fre(pattern: &str) -> fancy_regex::Regex {
    fancy_regex::Regex::new(pattern).unwrap_or_else(|e| panic!("bad regex {pattern}: {e}"))
}

/// A spec's pattern is written for JavaScript, where `[` inside a character class is literal
/// (`[^[]*`); the regex crates read it as a nested class, so it is escaped before compiling.
pub fn js_pattern(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut chars = p.chars().peekable();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                out.push(c);
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            }
            '[' if in_class => out.push_str("\\["),
            '[' => {
                in_class = true;
                out.push(c);
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Compile a user-supplied, JavaScript-style pattern.
#[allow(clippy::result_large_err)]
pub fn js_regex(p: &str) -> Result<fancy_regex::Regex, fancy_regex::Error> {
    fancy_regex::Regex::new(&js_pattern(p))
}

/// Whether a user-supplied pattern is a valid regular expression.
pub fn valid_regex(p: &str) -> bool {
    js_regex(p).is_ok()
}

/// JSON-decode `"<escaped>"`: what `JSON.parse('"' + s + '"')` gives.
pub fn json_unquote(escaped: &str) -> Option<String> {
    serde_json::from_str::<String>(&format!("\"{escaped}\"")).ok()
}

/// A JSON number from its exact digits (a big integer stays exact).
pub fn number_from_text(text: &str) -> Value {
    serde_json::from_str::<serde_json::Number>(text).map(Value::Number).unwrap_or(Value::Null)
}

/// Whether a decimal or exponent literal's exact value is past the largest safe integer (2^53 - 1) in size.
pub fn past_safe_integer(v: &str) -> bool {
    let re = re(r"^-?(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$");
    let Some(m) = re.captures(v) else { return false };
    let int = m.get(1).map(|x| x.as_str()).unwrap_or("");
    let frac = m.get(2).map(|x| x.as_str()).unwrap_or("");
    let exp: i64 = m.get(3).map(|x| x.as_str().parse().unwrap_or(0)).unwrap_or(0);
    let digits = format!("{int}{frac}");
    let digits = digits.trim_start_matches('0');
    let shift = exp - frac.len() as i64;
    // The limit has 16 digits: a value with more is past it, one with fewer is under it, and only 16 needs comparing.
    let places = digits.len() as i64 + shift;
    if digits.is_empty() || places != 16 {
        return !digits.is_empty() && places > 16;
    }
    let max: u128 = 9_007_199_254_740_991;
    let d: u128 = digits.parse().unwrap_or(u128::MAX);
    if shift >= 0 { d * 10u128.pow(shift as u32) > max } else { d > max * 10u128.pow((-shift) as u32) }
}
