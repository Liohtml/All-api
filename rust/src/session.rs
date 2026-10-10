//! Per-site cookie jar and session values under ~/.api-anything (0700 dirs, 0600 files).
use crate::types::{SameSite, StoredCookie};
use crate::util::{iso_now, json_pretty, now_ms, parse_date_ms, parse_url, re};
use anyhow::{Result, anyhow, bail};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    #[serde(default)]
    pub cookies: Vec<StoredCookie>,
    /// values of session: refs (auth/anti-bot headers), refreshed by every capture
    #[serde(default)]
    pub values: IndexMap<String, String>,
    /// where the cookies came from: "<browser>:<profile>" (import), "window", or "file"; drives self-heal re-import
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl Session {
    pub fn empty() -> Session {
        Session::default()
    }
    pub fn with(cookies: Vec<StoredCookie>, values: IndexMap<String, String>) -> Session {
        Session { cookies, values, source: None, updated_at: None }
    }
}

pub fn home() -> PathBuf {
    match std::env::var("API_ANYTHING_HOME") {
        Ok(h) if !h.is_empty() => PathBuf::from(h),
        _ => dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".api-anything"),
    }
}

/// Site names become file names; refuse anything that could leave the directory. Lower-cased, so
/// "EDGE" and "edge" are one site on every file system (and share one state).
pub fn safe_name(name: &str) -> Result<String> {
    if !crate::spec::site_name_ok(name) || name.contains("..") {
        bail!("invalid site name \"{name}\"");
    }
    Ok(name.to_lowercase())
}

pub fn ensure_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Atomic write with 0600.
pub fn write_private(file: &Path, text: &str) -> Result<()> {
    if let Some(dir) = file.parent() {
        ensure_dir(dir)?;
    }
    let tmp = file.with_file_name(format!(
        "{}.{}.tmp",
        file.file_name().and_then(|f| f.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    fs::write(&tmp, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, file)?;
    Ok(())
}

/// A JSON file, or the fallback when there is none. A corrupt file is an error naming it.
pub fn read_json(file: &Path) -> Result<Option<Value>> {
    let text = match fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| anyhow!("{} is corrupt ({}); fix or delete it", file.display(), e))
}

/// Run f holding an exclusive lock file next to `file`, so a read-modify-write in one process
/// never drops another process's update. A lock older than 10 s is a crashed holder's and is taken over.
pub fn with_lock<T>(file: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    if let Some(dir) = file.parent() {
        ensure_dir(dir)?;
    }
    let lock = file.with_file_name(format!("{}.lock", file.file_name().and_then(|f| f.to_str()).unwrap_or("file")));
    let deadline = now_ms() + 10_000.0;
    let mut held = false;
    while !held {
        match fs::OpenOptions::new().write(true).create_new(true).open(&lock) {
            Ok(_) => held = true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Ok(meta) = fs::metadata(&lock) {
                    let age = meta
                        .modified()
                        .ok()
                        .and_then(|m| m.elapsed().ok())
                        .map(|d| d.as_millis() as f64)
                        .unwrap_or(0.0);
                    if age > 10_000.0 {
                        let _ = fs::remove_file(&lock);
                    }
                }
                // after 10 s of contention go ahead unlocked rather than hang a call
                if now_ms() > deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(e.into()),
        }
    }
    let out = f();
    if held {
        let _ = fs::remove_file(&lock);
    }
    out
}

const CAPTURE_TTL_MS: f64 = 24.0 * 60.0 * 60_000.0;
const CAPTURES_KEPT: usize = 20;

/// Captures hold every response body and the run's cookie values, and one page can be tens of MB:
/// keep the newest 20, none older than 24 h. Runs after each new capture.
pub fn prune_captures(now: f64) {
    let dir = home().join("captures");
    let Ok(entries) = fs::read_dir(&dir) else { return };
    let mut files: Vec<(PathBuf, f64)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .filter_map(|e| {
            let at = e.metadata().ok()?.modified().ok()?;
            let ms = at.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs_f64() * 1000.0;
            Some((e.path(), ms))
        })
        .collect();
    files.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    for (i, (file, at)) in files.iter().enumerate() {
        if i >= CAPTURES_KEPT || now - at > CAPTURE_TTL_MS {
            let _ = fs::remove_file(file);
        }
    }
}

pub fn session_file(site: &str) -> Result<PathBuf> {
    Ok(home().join("sessions").join(format!("{}.json", safe_name(site)?)))
}

pub fn load_session(site: &str) -> Result<Session> {
    let file = session_file(site)?;
    let Some(v) = read_json(&file)? else { return Ok(Session::empty()) };
    let bad = || anyhow!("{} is not a session file; delete it and log in again", file.display());
    let Value::Object(o) = &v else { return Err(bad()) };
    if let Some(c) = o.get("cookies") {
        if !c.is_array() {
            return Err(bad());
        }
    }
    serde_json::from_value::<Session>(v).map_err(|_| bad())
}

pub fn save_session(site: &str, s: &Session) -> Result<()> {
    let mut out = s.clone();
    out.updated_at = Some(iso_now());
    write_private(&session_file(site)?, &json_pretty(&serde_json::to_value(&out)?, 1))
}

pub fn expired(c: &StoredCookie, now: f64) -> bool {
    c.expires > 0.0 && c.expires * 1000.0 <= now
}

fn cookie_key(c: &StoredCookie) -> String {
    format!("{}\0{}\0{}", c.name, c.domain.to_lowercase(), c.path)
}

/// Merge a browser run's cookies and session values into the stored session and save it.
pub fn merge_capture(site: &str, cookies: &[StoredCookie], values: &IndexMap<String, String>, now: f64) -> Result<Session> {
    let file = session_file(site)?;
    with_lock(&file, || {
        let s = load_session(site)?;
        let mut jar: IndexMap<String, StoredCookie> = s.cookies.iter().map(|c| (cookie_key(c), c.clone())).collect();
        for c in cookies {
            jar.insert(cookie_key(c), c.clone());
        }
        let mut merged_values = s.values.clone();
        for (k, v) in values {
            merged_values.insert(k.clone(), v.clone());
        }
        let merged = Session {
            cookies: jar.into_values().filter(|c| !expired(c, now)).collect(),
            values: merged_values,
            source: s.source.clone(),
            updated_at: None,
        };
        save_session(site, &merged)?;
        Ok(merged)
    })
}

fn domain_match(host: &str, domain: &str) -> bool {
    let d = domain.to_lowercase();
    // A domain cookie has a leading dot; without it the cookie is host-only.
    if let Some(bare) = d.strip_prefix('.') {
        return host == bare || host.ends_with(&d);
    }
    host == d
}

fn path_match(req_path: &str, cookie_path: &str) -> bool {
    if req_path == cookie_path {
        return true;
    }
    req_path.starts_with(cookie_path)
        && (cookie_path.ends_with('/') || req_path.as_bytes().get(cookie_path.len()) == Some(&b'/'))
}

fn secure_ok(u: &url::Url) -> bool {
    let host = u.host_str().unwrap_or("");
    u.scheme() == "https" || host == "localhost" || host == "127.0.0.1"
}

/// RFC 6265 domain/path/secure/expiry matching, longest path first.
pub fn cookies_for(cookies: &[StoredCookie], url: &str, now: f64) -> Vec<StoredCookie> {
    let Some(u) = parse_url(url) else { return vec![] };
    let host = u.host_str().unwrap_or("").to_lowercase();
    let secure = secure_ok(&u);
    let path = if u.path().is_empty() { "/" } else { u.path() };
    let mut out: Vec<StoredCookie> = cookies
        .iter()
        .filter(|c| domain_match(&host, &c.domain) && path_match(path, if c.path.is_empty() { "/" } else { &c.path }))
        .filter(|c| (!c.secure || secure) && !expired(c, now))
        .cloned()
        .collect();
    out.sort_by_key(|c| std::cmp::Reverse(if c.path.is_empty() { 1 } else { c.path.len() }));
    out
}

pub fn cookie_header_for(cookies: &[StoredCookie], url: &str, now: f64) -> String {
    cookies_for(cookies, url, now).iter().map(|c| format!("{}={}", c.name, c.value)).collect::<Vec<_>>().join("; ")
}

/// The registrable domain ("site") of a host, by the Public Suffix List including its private
/// section (github.io, run.app, amazonaws.com hosts), so a cookie ref, a Set-Cookie Domain or a
/// browser import never reaches another site. An IP, localhost or a bare suffix is its own site.
pub fn site_of(host: &str) -> String {
    let h = host.to_lowercase();
    registrable(&h).unwrap_or(h)
}

/// The registrable domain of a host, or none for an IP, a bare suffix or a name with no dot.
pub fn registrable(host: &str) -> Option<String> {
    let h = host.to_lowercase();
    if h.is_empty() || h.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let d = psl::domain_str(&h)?;
    if d == h && !h.contains('.') {
        return None;
    }
    // a host that is itself a suffix (s3.amazonaws.com, localhost) is nobody's registrable domain
    if psl::suffix_str(&h).map(|s| s == h).unwrap_or(false) {
        return None;
    }
    Some(d.to_string())
}

/// Value for a cookie: ref. Prefers a cookie that would be sent to url; else one from the same site
/// (page JS on www.site.com echoes its cookies to api.site.com), never another site's, and a Secure
/// cookie only over https.
pub fn cookie_value(cookies: &[StoredCookie], name: &str, url: Option<&str>, now: f64) -> Option<String> {
    let live: Vec<&StoredCookie> = cookies.iter().filter(|c| c.name == name && !expired(c, now)).collect();
    let Some(url) = url else { return live.first().map(|c| c.value.clone()) };
    if let Some(c) = cookies_for(cookies, url, now).into_iter().find(|c| c.name == name) {
        return Some(c.value);
    }
    let u = parse_url(url)?;
    let site = site_of(&u.host_str().unwrap_or("").to_lowercase());
    let secure = secure_ok(&u);
    live.into_iter()
        .find(|c| site_of(c.domain.trim_start_matches('.')) == site && (!c.secure || secure))
        .map(|c| c.value.clone())
}

/// One Set-Cookie line, scoped per RFC 6265 to the URL that set it; None if it may not be set there.
pub fn parse_set_cookie(line: &str, url: &str, now: f64) -> Option<StoredCookie> {
    let mut parts = line.split(';');
    let pair = parts.next().unwrap_or("");
    let eq = pair.find('=')?;
    if eq < 1 {
        return None;
    }
    let u = parse_url(url)?;
    let host = u.host_str().unwrap_or("").to_lowercase();
    let path = u.path();
    let dir = &path[..path.rfind('/').unwrap_or(0)];
    let mut c = StoredCookie {
        name: pair[..eq].trim().to_string(),
        value: pair[eq + 1..].trim().to_string(),
        domain: host.clone(),
        path: if dir.starts_with('/') { dir.to_string() } else { "/".to_string() },
        expires: -1.0,
        http_only: false,
        secure: false,
        same_site: None,
    };
    let mut max_age: Option<f64> = None;
    for attr in parts {
        let (k, v) = match attr.find('=') {
            Some(i) => (attr[..i].trim().to_lowercase(), attr[i + 1..].trim().to_string()),
            None => (attr.trim().to_lowercase(), String::new()),
        };
        match k.as_str() {
            "domain" if !v.is_empty() => {
                let d = v.trim_start_matches('.').to_lowercase();
                // never a cookie for another site, or for a public suffix
                let site = site_of(&host);
                if (host != d && !host.ends_with(&format!(".{d}"))) || (d != site && !d.ends_with(&format!(".{site}"))) {
                    return None;
                }
                // a host that is itself a suffix (s3.amazonaws.com, localhost) gets a host-only cookie, as in a browser
                if registrable(&d).is_some() {
                    c.domain = format!(".{d}");
                }
            }
            "path" if v.starts_with('/') => c.path = v,
            "max-age" => {
                if re(r"^-?\d+$").is_match(&v) {
                    max_age = v.parse().ok();
                }
            }
            "expires" => {
                if let Some(ms) = parse_date_ms(&v) {
                    c.expires = ms / 1000.0;
                }
            }
            "secure" => c.secure = true,
            "httponly" => c.http_only = true,
            "samesite" => {
                c.same_site = match v.to_lowercase().as_str() {
                    "strict" => Some(SameSite::Strict),
                    "lax" => Some(SameSite::Lax),
                    "none" => Some(SameSite::None),
                    _ => c.same_site,
                }
            }
            _ => {}
        }
    }
    // max-age wins over expires; 0 or less deletes (an expired cookie drops out of the jar)
    if let Some(m) = max_age {
        c.expires = if m <= 0.0 { 1.0 } else { now / 1000.0 + m };
    }
    Some(c)
}

/// Parse a raw Cookie header ("a=1; b=\"x\"") into a name -> value map.
pub fn parse_cookie_header(raw: &str) -> IndexMap<String, String> {
    let mut out = IndexMap::new();
    for part in raw.split(';') {
        let Some(eq) = part.find('=') else { continue };
        let name = part[..eq].trim();
        if !name.is_empty() {
            out.insert(name.to_string(), part[eq + 1..].trim().to_string());
        }
    }
    out
}

// name heuristic for "logged in"; a site's spec can pin exact names via loginCookies.
pub static AUTH_COOKIE: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(r"(?i)^(auth_token|sessionid|session_id|li_at|sid|ssid|__secure-\dpsid|user_session|reddit_session|remember_\w+|\w*_session|\w*_sess)$")
});

pub fn logged_in(cookies: &[StoredCookie], login_cookies: Option<&[String]>, now: f64) -> bool {
    let live: Vec<&StoredCookie> = cookies.iter().filter(|c| !expired(c, now) && !c.value.is_empty()).collect();
    if let Some(names) = login_cookies {
        if !names.is_empty() {
            return names.iter().all(|n| live.iter().any(|c| &c.name == n));
        }
    }
    live.iter().any(|c| {
        (AUTH_COOKIE.is_match(&c.name) && c.value.len() >= 8) || (c.name == "logged_in" && c.value == "yes")
    })
}
