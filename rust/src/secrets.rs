//! What counts as a credential, and the scan that finds one in a spec. Learning uses these to turn
//! credentials into references and to check none is left; the store uses them before a save or an export.
use crate::codec::Step;
use crate::session::Session;
use crate::util::{b64_decode_lenient, b64_encode, decode_uri_component, re};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::LazyLock;

pub static SESSION_HEADER: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(
        r"(?i)^(authorization|x-[a-z0-9-]*token|x-csrf[a-z0-9-]*|x-xsrf[a-z0-9-]*|x-goog-batchexecute-bgr|x-client-transaction-id|x-fb-lsd|x-ig-www-claim)$",
    )
});
// Per-session credentials sent in forms, queries or JSON bodies: Google's `at`, Meta's fb_dtsg/lsd,
// Rails', ASP.NET's anti-CSRF fields, and OAuth-style access tokens.
pub static SESSION_FIELD: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(
        r"(?i)^(at|fb_dtsg|lsd|authenticity_token|__RequestVerificationToken|_?csrf(_?token)?|_?xsrf(_?token)?|csrfmiddlewaretoken|(access_?)?token|session_?id)$",
    )
});

pub fn header_name(at: &[Step]) -> Option<String> {
    crate::codec::header_name(at)
}
pub fn last_token(at: &[Step]) -> String {
    crate::codec::last_token(at)
}
/// The name a leaf goes by: its header, field, query key or JSON key.
pub fn leaf_name(at: &[Step]) -> String {
    crate::codec::leaf_name(at)
}

/// A word that names a credential: api_key, authToken, x-session-id, sid, X-Amz-Signature.
fn credential_word(w: &str) -> bool {
    if w.is_empty() || !w.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return false;
    }
    if w.starts_with("auth") && !w.starts_with("author") {
        return true;
    }
    if w.starts_with("sess") || w == "sid" {
        return true;
    }
    let base = w.strip_suffix('s').unwrap_or(w);
    for suffix in ["token", "secret", "key", "signature", "password", "passwd", "pwd", "credential", "bearer"] {
        if w.ends_with(suffix) || base.ends_with(suffix) {
            return true;
        }
    }
    false
}

/// A key or header named like a credential, judged by its words (authToken -> auth, token; "author" is not).
pub fn credential_name(name: &str) -> bool {
    static CAMEL: LazyLock<regex::Regex> = LazyLock::new(|| re(r"([a-z0-9])([A-Z])"));
    let spaced = CAMEL.replace_all(name, "$1 $2").to_lowercase();
    spaced.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit())).any(credential_word)
}

pub static URLISH: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^[a-z][a-z0-9+.-]*://"));

/// Random-looking: 16+ chars, no spaces, not a URL, two character classes, 3+ bits of entropy per char.
pub fn high_entropy(v: &str) -> bool {
    if v.len() < 16 || v.chars().any(char::is_whitespace) || URLISH.is_match(v) {
        return false;
    }
    let classes =
        [v.chars().any(|c| c.is_ascii_lowercase()), v.chars().any(|c| c.is_ascii_uppercase()), v.chars().any(|c| c.is_ascii_digit())]
            .iter()
            .filter(|x| **x)
            .count();
    if classes < 2 {
        return false;
    }
    let mut counts: std::collections::HashMap<char, f64> = std::collections::HashMap::new();
    let mut total = 0.0;
    for c in v.chars() {
        *counts.entry(c).or_insert(0.0) += 1.0;
        total += 1.0;
    }
    let mut bits = 0.0;
    for k in counts.values() {
        let p = k / total;
        bits -= p * p.log2();
    }
    bits >= 3.0
}

/// A literal a spec must not hold: a per-session field or header, or a random value under a credential's name.
pub fn is_credential(name: &str, value: &str) -> bool {
    ((SESSION_FIELD.is_match(name) || SESSION_HEADER.is_match(name)) && value.len() >= 8) || (credential_name(name) && high_entropy(value))
}

/// A token and nothing else, under any name: one unbroken run of 16+ characters of the hex or
/// URL-safe base64 alphabet that is random-looking. Words and numbers joined by - or _ are not one,
/// however long (a slug, page-1-sort-relevance), and any other character breaks the run.
pub fn opaque_token(text: &str) -> bool {
    static RUN: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_-]{16,}$"));
    static WORD: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Za-z]*\d*$"));
    let worded = text.split(['-', '_']).all(|part| WORD.is_match(part));
    RUN.is_match(text) && high_entropy(text) && !worded
}

/* ------------------------------------------------------------------- scan */

static JWT: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"));
static HEX_BLOB: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\b[0-9a-fA-F]{32,}\b"));
// "/" left out: every long URL path would match
static BASE64_BLOB: LazyLock<regex::Regex> = LazyLock::new(|| re(r"[A-Za-z0-9+_-]{40,}={0,2}"));
static BEARER: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^Bearer\s+\S{20,}"));
// identifiers like __relay_internal__pv__appviewerisloggedinprovider are long too; tokens mix case and digits
fn random(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_digit()) && s.chars().any(|c| c.is_ascii_lowercase()) && s.chars().any(|c| c.is_ascii_uppercase())
}

static PCT_RUN: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?:%[0-9a-fA-F]{2})+"));

/// Decode every %XX run on its own, so one stray "%" doesn't hide the rest.
pub fn pct_decode(s: &str, plus: bool) -> String {
    let text = if plus { s.replace('+', " ") } else { s.to_string() };
    PCT_RUN.replace_all(&text, |m: &regex::Captures| decode_uri_component(&m[0]).unwrap_or_else(|| m[0].to_string())).into_owned()
}

static JSON_ESC: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"\\(u[0-9a-fA-F]{4}|["\\/bfnrt])"#));

pub fn json_unescape(s: &str) -> String {
    JSON_ESC
        .replace_all(s, |m: &regex::Captures| {
            let c = &m[1];
            if c.len() > 1 {
                let code = u32::from_str_radix(&c[1..], 16).unwrap_or(0xfffd);
                char::from_u32(code).map(|ch| ch.to_string()).unwrap_or_else(|| "\u{fffd}".to_string())
            } else {
                match c {
                    "b" => "\u{8}".to_string(),
                    "f" => "\u{c}".to_string(),
                    "n" => "\n".to_string(),
                    "r" => "\r".to_string(),
                    "t" => "\t".to_string(),
                    other => other.to_string(),
                }
            }
        })
        .into_owned()
}

static B64_RUN: LazyLock<regex::Regex> = LazyLock::new(|| re(r"[A-Za-z0-9+/_-]{16,}={0,2}"));

/// Base64 (or base64url) runs that decode to text.
fn base64_texts(s: &str) -> Vec<String> {
    B64_RUN
        .find_iter(s)
        .map(|m| String::from_utf8_lossy(&b64_decode_lenient(m.as_str().as_bytes())).into_owned())
        .filter(|t| !t.is_empty() && !t.chars().any(|c| c == '\u{fffd}' || (c as u32) <= 8 || ((c as u32) >= 0x0e && (c as u32) <= 0x1f)))
        .collect()
}

/// A test for text that holds `value` base64-encoded, whatever stands before or after it: the
/// value's own encoding at each of the three byte offsets and in both alphabets, confirmed by
/// decoding the text there (another value can share the characters: "xqbcdef" with "abcdef").
pub struct InBase64 {
    bytes: Vec<u8>,
    places: Vec<(String, usize, usize, usize)>,
}

impl InBase64 {
    pub fn new(value: &str) -> InBase64 {
        let bytes = value.as_bytes().to_vec();
        let mut places = Vec::new();
        for lead in 0..3usize {
            let mut padded = vec![0u8; lead];
            padded.extend_from_slice(&bytes);
            let whole = b64_encode(&padded).trim_end_matches('=').to_string();
            // the first characters hold the bytes in front, and the last one bits of the byte that follows
            let skip = [0, 2, 3][lead];
            let end = if (lead + bytes.len()) % 3 != 0 { whole.len().saturating_sub(1) } else { whole.len() };
            let core = whole[skip.min(end)..end].to_string();
            let url = core.replace('+', "-").replace('/', "_");
            let mut cores = vec![core.clone()];
            if url != core {
                cores.push(url);
            }
            for c in cores {
                places.push((c, lead, skip, whole.len()));
            }
        }
        InBase64 { bytes, places }
    }

    pub fn test(&self, text: &str) -> bool {
        let tb = text.as_bytes();
        for (core, lead, skip, length) in &self.places {
            if core.is_empty() {
                continue;
            }
            let mut from = 0;
            while let Some(i) = crate::util::find_from(text, core, from) {
                from = i + 1;
                if i < *skip {
                    continue;
                }
                let start = i - skip;
                let end = (start + length).min(tb.len());
                let there = b64_decode_lenient(&tb[start..end]);
                if there.len() >= lead + self.bytes.len() && there[*lead..lead + self.bytes.len()] == self.bytes[..] {
                    return true;
                }
            }
        }
        false
    }
}

/// Every text a spec string may hide a value in: percent-decoded (+ as a space or not),
/// JSON-unescaped (`\/`, `+`) and base64 runs decoded, in any order, up to 3 layers deep.
pub fn decodings(v: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![v.to_string()];
    let mut seen: HashSet<String> = HashSet::from([v.to_string()]);
    let mut frontier = vec![v.to_string()];
    for _ in 0..3 {
        if frontier.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for f in &frontier {
            let mut ds = vec![pct_decode(f, false), pct_decode(f, true), json_unescape(f)];
            ds.extend(base64_texts(f));
            for d in ds {
                if seen.contains(&d) {
                    continue;
                }
                seen.insert(d.clone());
                out.push(d.clone());
                next.push(d);
            }
        }
        frontier = next;
    }
    out
}

static IPV4: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"));
static IPV6: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}$"));

/// A literal IP address (a client's remoteHost the page reported): the user's, not the site's.
fn ip_address(v: &str) -> bool {
    (IPV4.is_match(v) && !(v.starts_with("127.") || v.starts_with("0.") || v.ends_with(".0")))
        || (IPV6.is_match(v) && (v.contains("::") || v.split(':').count() >= 5) && v != "::1")
}

/// An IP address anywhere in a leaf: the whole value, "ip:port", an x-forwarded-for list, "ip=.."
/// text. A version string is not one: "Chrome/120.0.0.0" follows a letter or "/", and ends in .0.
pub fn ip_in(v: &str) -> Option<String> {
    static RUN: LazyLock<regex::Regex> = LazyLock::new(|| re(r"[0-9A-Fa-f:.]+"));
    static PORT: LazyLock<regex::Regex> = LazyLock::new(|| re(r":\d{1,5}$"));
    for m in RUN.find_iter(v) {
        let before = v[..m.start()].chars().last();
        let mut t = m.as_str().trim_matches(|c| c == '.' || c == ':').to_string();
        if t.contains('.') {
            t = PORT.replace(&t, "").into_owned(); // ip:port
        }
        if t.contains('.') && before.map(|c| c.is_alphanumeric() || c == '_' || c == '/').unwrap_or(false) {
            continue; // a version: v1.2.3.4, Chrome/1.2.3.4
        }
        if ip_address(&t) {
            return Some(t);
        }
    }
    None
}

pub struct Scan {
    pub secrets: Vec<String>,
    pub warnings: Vec<String>,
}

struct Live {
    label: String,
    value: String,
    encoded: InBase64,
}

/// `secrets`: exact hits of live jar/session values (6+ chars, raw, unquoted or URL-decoded). Each
/// is looked for in the text and in what the text decodes to (three layers of percent-encoding,
/// JSON escapes and whole base64 runs), and by its own base64 encoding at any byte offset, confirmed
/// by decoding there. A hit is the value itself, so callers fail closed. `warnings`: regex heuristics, which do misfire.
/// `allowed`: JSON paths a human marked public (an op's `public` headers); skipped.
pub fn scan_secrets(value: &Value, session: &Session, allowed: &HashSet<String>) -> Scan {
    let mut live: Vec<Live> = Vec::new();
    let mut add = |label: String, v: &str| {
        let mut forms: Vec<String> = vec![v.to_string()];
        let unq = strip_quotes(v);
        if !forms.contains(&unq) {
            forms.push(unq);
        }
        let dec = pct_decode(v, false);
        if !forms.contains(&dec) {
            forms.push(dec);
        }
        for f in forms {
            if f.chars().count() >= 6 {
                live.push(Live { label: label.clone(), encoded: InBase64::new(&f), value: f });
            }
        }
    };
    for c in &session.cookies {
        add(format!("cookie {}", c.name), &c.value);
    }
    for (k, v) in &session.values {
        add(format!("session value {k}"), v);
    }
    let mut secrets: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    visit(value, "$", &live, allowed, &mut secrets, &mut warnings);
    Scan { secrets: dedup(secrets), warnings: dedup(warnings) }
}

/// `v.replace(/^"|"$/g, "")`: one quote off each end.
pub fn strip_quotes(v: &str) -> String {
    let mut s = v;
    if let Some(r) = s.strip_prefix('"') {
        s = r;
    }
    if let Some(r) = s.strip_suffix('"') {
        s = r;
    }
    s.to_string()
}

fn dedup(v: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    v.into_iter().filter(|s| seen.insert(s.clone())).collect()
}

fn visit(v: &Value, path: &str, live: &[Live], allowed: &HashSet<String>, secrets: &mut Vec<String>, warnings: &mut Vec<String>) {
    if allowed.contains(path) {
        return;
    }
    match v {
        Value::String(s) => {
            let forms = if live.is_empty() { vec![] } else { decodings(s) };
            for l in live {
                if forms.iter().any(|f| f.contains(&l.value) || l.encoded.test(f)) {
                    secrets.push(format!("{path} holds the live {}", l.label));
                }
            }
            let text = pct_decode(s, false); // percent-encoded bodies hide the blob's shape
            let checks: [(&str, &regex::Regex); 4] =
                [("a JWT", &JWT), ("a bearer token", &BEARER), ("a long hex blob", &HEX_BLOB), ("a long base64 blob", &BASE64_BLOB)];
            for (why, r) in checks {
                let hit = r.find_iter(&text).map(|m| m.as_str()).find(|m| why != "a long base64 blob" || random(m));
                if let Some(m) = hit {
                    let head: String = m.chars().take(24).collect();
                    warnings.push(format!("{path} looks like {why} ({head}...); check it is public"));
                    break;
                }
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                visit(x, &format!("{path}[{i}]"), live, allowed, secrets, warnings);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                visit(x, &format!("{path}.{k}"), live, allowed, secrets, warnings);
            }
        }
        _ => {}
    }
}

/// The warnings alone, for a value with no live session.
pub fn shape_warnings(value: &str) -> Vec<String> {
    scan_secrets(&Value::String(value.to_string()), &Session::empty(), &HashSet::new()).warnings
}
