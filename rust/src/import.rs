//! Import a site's cookies from the user's everyday browser, so `login` needs no password:
//! they are almost always already signed in there (2FA/captcha done by the human).
//!
//! Chromium family: cookie DB names are plaintext (so the right profile is chosen with no
//! decryption and no Keychain prompt); values are AES-128-CBC under a key derived from the
//! browser's Safe Storage password. Firefox: plaintext moz_cookies. Only the chosen profile is
//! decrypted, so at most one macOS Keychain dialog appears.
use crate::session::{AUTH_COOKIE, site_of};
use crate::types::{SameSite, StoredCookie};
use crate::util::parse_url;
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// One installed browser to scan. Tests inject these via API_ANYTHING_BROWSER_ROOTS.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BrowserRoot {
    /// display name, also the Keychain service prefix: "<name> Safe Storage"
    pub name: String,
    pub family: Family,
    /// user-data dir (chromium) or profiles dir (firefox)
    pub root: String,
    /// overrides the OS key lookup (test injection; also Linux "peanuts")
    #[serde(default)]
    pub password: Option<String>,
    /// PBKDF2 iterations (chromium): macOS 1003, Linux v10 1
    #[serde(default)]
    pub iterations: Option<u32>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Chromium,
    Firefox,
}

#[derive(Clone, Debug)]
pub struct ImportedSession {
    pub cookies: Vec<StoredCookie>,
    /// "<browser-lower>:<profile>", e.g. "chrome:Profile 1"; recorded so a heal re-imports the same one
    pub source: String,
    pub browser: String,
    pub profile: String,
    /// the profile's display name and Google account, from Chrome's Local State
    pub name: Option<String>,
    pub email: Option<String>,
}

/// One browser profile a human can pick with --profile.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ProfileChoice {
    /// the --profile value: "Chrome/Profile 1"
    pub profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// Several profiles hold the site's login: importing one would be a guess between accounts.
#[derive(Debug)]
pub struct AmbiguousProfile {
    pub site: String,
    pub candidates: Vec<ProfileChoice>,
}

impl std::fmt::Display for AmbiguousProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let list = self
            .candidates
            .iter()
            .map(|c| {
                let who: Vec<&str> = [c.name.as_deref(), c.email.as_deref()].into_iter().flatten().collect();
                format!("\"{}\"{}", c.profile, if who.is_empty() { String::new() } else { format!(" ({})", who.join(", ")) })
            })
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{} browser profiles are signed in to {}; pick one: {list}", self.candidates.len(), self.site)
    }
}
impl std::error::Error for AmbiguousProfile {}

const CHROMIUM_MAC: [(&str, &str); 7] = [
    ("Chrome", "Google/Chrome"),
    ("Chrome Beta", "Google/Chrome Beta"),
    ("Brave", "BraveSoftware/Brave-Browser"),
    ("Edge", "Microsoft Edge"),
    ("Arc", "Arc/User Data"),
    ("Chromium", "Chromium"),
    ("Vivaldi", "Vivaldi"),
];

// The Keychain service is "<x> Safe Storage" where x differs from the display name for a few.
fn safe_storage(name: &str) -> &str {
    match name {
        "Brave" => "Brave",
        "Edge" => "Microsoft Edge",
        "Arc" => "Arc",
        "Chromium" => "Chromium",
        "Vivaldi" => "Vivaldi",
        other => other,
    }
}

/// Installed browsers on this OS, or the injected set for tests.
pub fn browser_roots() -> Result<Vec<BrowserRoot>> {
    if let Ok(injected) = std::env::var("API_ANYTHING_BROWSER_ROOTS") {
        if !injected.is_empty() {
            return serde_json::from_str(&injected).map_err(|e| anyhow!("API_ANYTHING_BROWSER_ROOTS: {e}"));
        }
    }
    let mut out = Vec::new();
    let home = std::env::var("HOME").unwrap_or_default();
    if cfg!(target_os = "macos") {
        let support = Path::new(&home).join("Library").join("Application Support");
        for (name, rel) in CHROMIUM_MAC {
            let root = support.join(rel);
            if root.exists() {
                out.push(BrowserRoot {
                    name: name.into(),
                    family: Family::Chromium,
                    root: root.display().to_string(),
                    password: None,
                    iterations: None,
                });
            }
        }
        let ff = support.join("Firefox").join("Profiles");
        if ff.exists() {
            out.push(BrowserRoot {
                name: "Firefox".into(),
                family: Family::Firefox,
                root: ff.display().to_string(),
                password: None,
                iterations: None,
            });
        }
    } else if cfg!(target_os = "linux") {
        let config = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .filter(|c| !c.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(&home).join(".config"));
        for (name, rel) in
            [("Chrome", "google-chrome"), ("Chromium", "chromium"), ("Brave", "BraveSoftware/Brave-Browser"), ("Edge", "microsoft-edge")]
        {
            let root = config.join(rel);
            // Linux v10 is AES under a fixed password; v11 (secret-tool) is not attempted here.
            if root.exists() {
                out.push(BrowserRoot {
                    name: name.into(),
                    family: Family::Chromium,
                    root: root.display().to_string(),
                    password: Some("peanuts".into()),
                    iterations: Some(1),
                });
            }
        }
        let ff = Path::new(&home).join(".mozilla").join("firefox");
        if ff.exists() {
            out.push(BrowserRoot {
                name: "Firefox".into(),
                family: Family::Firefox,
                root: ff.display().to_string(),
                password: None,
                iterations: None,
            });
        }
    }
    // Windows chromium uses app-bound encryption (DPAPI + more): not supported; login falls back to --window.
    Ok(out)
}

/// The `security` Keychain lookup for a browser's Safe Storage password (may show a macOS dialog).
fn keychain_password(name: &str) -> Result<String> {
    let service = format!("{} Safe Storage", safe_storage(name));
    let out = std::process::Command::new("security").args(["find-generic-password", "-w", "-s", &service]).output();
    match out {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).trim().to_string()),
        Ok(o) => bail!(
            "could not read the \"{service}\" password from the macOS Keychain ({})",
            crate::util::first_line(&String::from_utf8_lossy(&o.stderr))
        ),
        Err(e) => bail!("could not read the \"{service}\" password from the macOS Keychain ({e})"),
    }
}

/// Copy a locked DB (plus -wal/-journal) to a temp dir and open it read-only.
fn with_db<T>(db_path: &Path, f: impl FnOnce(&rusqlite::Connection) -> Result<T>) -> Result<T> {
    let dir = tempfile::Builder::new().prefix("aa-cookies-").tempdir()?;
    let copy = dir.path().join(db_path.file_name().unwrap_or_default());
    std::fs::copy(db_path, &copy)?;
    for ext in ["-wal", "-journal", "-shm"] {
        let side = PathBuf::from(format!("{}{ext}", db_path.display()));
        if side.exists() {
            let _ = std::fs::copy(&side, PathBuf::from(format!("{}{ext}", copy.display())));
        }
    }
    let db = rusqlite::Connection::open_with_flags(&copy, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let out = f(&db);
    drop(db);
    out
}

/// A chromium profile's cookie DB is <profile>/Network/Cookies (modern) or <profile>/Cookies.
fn chromium_cookie_db(profile_dir: &Path) -> Option<PathBuf> {
    [profile_dir.join("Network").join("Cookies"), profile_dir.join("Cookies")].into_iter().find(|p| p.exists())
}

struct Candidate {
    browser: String,
    profile: String,
    family: Family,
    root: BrowserRoot,
    db_path: PathBuf,
    /// cookie names present for the site (plaintext, no decryption)
    names: HashSet<String>,
}

fn safe_readdir(dir: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else { return vec![] };
    let mut out: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    out.sort();
    out
}

/// true when a cookie's host_key/host belongs to the site's registrable domain.
pub fn belongs(host: &str, site: &str) -> bool {
    let h = host.trim_start_matches('.').to_lowercase();
    h == site || h.ends_with(&format!(".{site}")) || site_of(&h) == site
}

fn names_in(db_path: &Path, table: &str, host_col: &str, site: &str) -> Result<HashSet<String>> {
    with_db(db_path, |db| {
        let mut stmt = db.prepare(&format!("SELECT {host_col}, name FROM {table}"))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = HashSet::new();
        for row in rows.flatten() {
            if belongs(&row.0, site) {
                out.insert(row.1);
            }
        }
        Ok(out)
    })
}

/// Every profile of every browser that holds at least one cookie for the site's registrable domain.
fn candidates_for(site: &str) -> Result<Vec<Candidate>> {
    let mut out = Vec::new();
    for root in browser_roots()? {
        for entry in safe_readdir(&root.root) {
            let (db, table, host_col) = match root.family {
                Family::Firefox => {
                    (Some(Path::new(&root.root).join(&entry).join("cookies.sqlite")).filter(|p| p.exists()), "moz_cookies", "host")
                }
                Family::Chromium => (chromium_cookie_db(&Path::new(&root.root).join(&entry)), "cookies", "host_key"),
            };
            let Some(db) = db else { continue };
            let Ok(names) = names_in(&db, table, host_col, site) else { continue };
            if !names.is_empty() {
                out.push(Candidate {
                    browser: root.name.clone(),
                    profile: entry,
                    family: root.family,
                    root: root.clone(),
                    db_path: db,
                    names,
                });
            }
        }
    }
    Ok(out)
}

const CHROME_EPOCH_OFFSET: f64 = 11644473600.0; // seconds between 1601-01-01 and 1970-01-01

fn same_site_of(n: i64) -> Option<SameSite> {
    match n {
        0 => Some(SameSite::None),
        1 => Some(SameSite::Lax),
        2 => Some(SameSite::Strict),
        _ => None,
    }
}

pub fn derive_key(password: &str, iterations: u32) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), b"saltysalt", iterations, &mut key);
    key
}

/// Decrypt one chromium encrypted_value; meta.version >= 24 prefixes 32 bytes (SHA-256 of host_key).
fn decrypt_chromium(raw: &[u8], key: &[u8; 16], meta_version: i64) -> Option<String> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    if raw.is_empty() {
        return Some(String::new());
    }
    if !(raw.starts_with(b"v10") || raw.starts_with(b"v11")) {
        return Some(String::from_utf8_lossy(raw).into_owned()); // unencrypted (older Linux)
    }
    let iv = [0x20u8; 16];
    let dec = cbc::Decryptor::<aes::Aes128>::new(key.into(), &iv.into());
    let mut buf = raw[3..].to_vec();
    let out = dec.decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf).ok()?; // wrong key: skip this cookie
    let out = if meta_version >= 24 { out.get(32..).unwrap_or(&[]) } else { out };
    Some(String::from_utf8_lossy(out).into_owned())
}

fn read_chromium(root: &BrowserRoot, db_path: &Path, site: &str) -> Result<Vec<StoredCookie>> {
    let iterations = root.iterations.unwrap_or(if cfg!(target_os = "linux") { 1 } else { 1003 });
    let password = match &root.password {
        Some(p) => p.clone(),
        None => keychain_password(&root.name)?,
    };
    let key = derive_key(&password, iterations);
    with_db(db_path, |db| {
        let meta_version: i64 = db
            .query_row("SELECT value FROM meta WHERE key = 'version'", [], |r| {
                r.get::<_, String>(0).or_else(|_| r.get::<_, i64>(0).map(|n| n.to_string()))
            })
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut stmt =
            db.prepare("SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, samesite FROM cookies")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2).unwrap_or_default(),
                r.get::<_, Vec<u8>>(3).unwrap_or_default(),
                r.get::<_, String>(4).unwrap_or_default(),
                r.get::<_, i64>(5).unwrap_or(0),
                r.get::<_, i64>(6).unwrap_or(0),
                r.get::<_, i64>(7).unwrap_or(0),
                r.get::<_, i64>(8).unwrap_or(-1),
            ))
        })?;
        let mut out = Vec::new();
        for (host_key, name, value, encrypted, path, expires_utc, secure, http_only, same_site) in rows.flatten() {
            if !belongs(&host_key, site) {
                continue;
            }
            let value = if !value.is_empty() { Some(value) } else { decrypt_chromium(&encrypted, &key, meta_version) };
            let Some(value) = value.filter(|v| !v.is_empty()) else { continue };
            out.push(StoredCookie {
                name,
                value,
                domain: host_key,
                path: if path.is_empty() { "/".into() } else { path },
                expires: if expires_utc > 0 { (expires_utc as f64 / 1_000_000.0 - CHROME_EPOCH_OFFSET).floor() } else { -1.0 },
                http_only: http_only != 0,
                secure: secure != 0,
                same_site: same_site_of(same_site),
            });
        }
        Ok(out)
    })
}

fn read_firefox(db_path: &Path, site: &str) -> Result<Vec<StoredCookie>> {
    with_db(db_path, |db| {
        let mut stmt = db.prepare("SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite FROM moz_cookies")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2).unwrap_or_default(),
                r.get::<_, String>(3).unwrap_or_default(),
                r.get::<_, i64>(4).unwrap_or(0),
                r.get::<_, i64>(5).unwrap_or(0),
                r.get::<_, i64>(6).unwrap_or(0),
                r.get::<_, i64>(7).unwrap_or(0),
            ))
        })?;
        Ok(rows
            .flatten()
            .filter(|r| belongs(&r.0, site))
            .map(|(host, name, value, path, expiry, secure, http_only, same_site)| StoredCookie {
                name,
                value,
                domain: host,
                path: if path.is_empty() { "/".into() } else { path },
                expires: if expiry > 0 { expiry as f64 } else { -1.0 }, // Firefox expiry is unix seconds
                http_only: http_only != 0,
                secure: secure != 0,
                same_site: same_site_of(same_site),
            })
            .collect())
    })
}

#[derive(Clone, Debug, PartialEq)]
pub struct ImportPin {
    pub browser: Option<String>,
    pub profile: String,
}

/// Parse `--profile "Chrome/Profile 1"` or a session source "chrome:Profile 1" into a pin.
pub fn parse_pin(text: &str) -> ImportPin {
    let sep = if text.contains('/') { '/' } else { ':' };
    match text.find(sep) {
        None => ImportPin { browser: None, profile: text.to_string() },
        Some(i) => ImportPin { browser: Some(text[..i].to_string()), profile: text[i + 1..].to_string() },
    }
}

fn matches_pin(c: &Candidate, pin: &ImportPin) -> bool {
    c.profile == pin.profile && pin.browser.as_ref().map(|b| c.browser.eq_ignore_ascii_case(b)).unwrap_or(true)
}

/// A chromium profile's display name and signed-in Google account, from the browser's "Local State".
fn profile_info(c: &Candidate) -> (Option<String>, Option<String>) {
    if c.family != Family::Chromium {
        return (None, None);
    }
    let Ok(text) = std::fs::read_to_string(Path::new(&c.root.root).join("Local State")) else { return (None, None) };
    let Ok(state) = serde_json::from_str::<Value>(&text) else { return (None, None) };
    let info = state.pointer(&format!("/profile/info_cache/{}", c.profile.replace('~', "~0").replace('/', "~1")));
    let s = |k: &str| info.and_then(|i| i.get(k)).and_then(|v| v.as_str()).filter(|v| !v.is_empty()).map(|v| v.to_string());
    (s("name"), s("user_name"))
}

/// Import the site's cookies from the everyday browser: the one profile that holds the site's
/// `login_cookies` (for an unknown site, auth-looking cookies, else any cookies for it), or the
/// pinned one. Never a guess: when several profiles qualify, it fails with AmbiguousProfile.
/// None when nothing is importable (the caller falls back to the window flow).
pub fn import_from_browsers(url: &str, login_cookies: Option<&[String]>, pin: Option<&ImportPin>) -> Result<Option<ImportedSession>> {
    let host = parse_url(url).map(|u| u.host_str().unwrap_or("").to_lowercase()).unwrap_or_default();
    let site = site_of(&host);
    let mut candidates = candidates_for(&site)?;
    if let Some(pin) = pin {
        candidates.retain(|c| matches_pin(c, pin));
        if candidates.is_empty() {
            bail!(
                "no browser profile \"{}{}\" has cookies for {site}",
                pin.browser.as_ref().map(|b| format!("{b}/")).unwrap_or_default(),
                pin.profile
            );
        }
    }
    let signed_in: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| match login_cookies {
            Some(l) if !l.is_empty() => l.iter().all(|n| c.names.contains(n)),
            _ => c.names.iter().any(|n| AUTH_COOKIE.is_match(n)),
        })
        .map(|(i, _)| i)
        .collect();
    let pool: Vec<usize> = if signed_in.is_empty() { (0..candidates.len()).collect() } else { signed_in };
    if pool.len() > 1 {
        let choices = pool
            .iter()
            .map(|&i| {
                let (name, email) = profile_info(&candidates[i]);
                ProfileChoice { profile: format!("{}/{}", candidates[i].browser, candidates[i].profile), name, email }
            })
            .collect();
        return Err(AmbiguousProfile { site, candidates: choices }.into());
    }
    let Some(&i) = pool.first() else { return Ok(None) };
    let chosen = &candidates[i];
    let cookies = match chosen.family {
        Family::Chromium => read_chromium(&chosen.root, &chosen.db_path, &site)?,
        Family::Firefox => read_firefox(&chosen.db_path, &site)?,
    };
    if cookies.is_empty() {
        return Ok(None);
    }
    let (name, email) = profile_info(chosen);
    Ok(Some(ImportedSession {
        cookies,
        source: format!("{}:{}", chosen.browser.to_lowercase(), chosen.profile),
        browser: chosen.browser.clone(),
        profile: chosen.profile.clone(),
        name,
        email,
    }))
}

/* --------------------------------------------------------------- file import */

/// Parse a cookies.txt (Netscape) or JSON array (Cookie-Editor / Playwright shape) export.
pub fn cookies_from_file(text: &str, url: &str) -> Result<Vec<StoredCookie>> {
    let trimmed = text.trim();
    let host = parse_url(url).map(|u| u.host_str().unwrap_or("").to_string()).unwrap_or_default();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        let parsed: Value = serde_json::from_str(trimmed)?;
        let arr = match &parsed {
            Value::Array(a) => a.clone(),
            Value::Object(o) => o.get("cookies").and_then(|c| c.as_array()).cloned().unwrap_or_default(),
            _ => vec![],
        };
        return Ok(arr.iter().map(|c| normalize_json(c, &host)).collect());
    }
    // Netscape columns: domain, includeSubdomains, path, secure, expiry, name, value.
    // A leading "#HttpOnly_" on the domain marks an http-only cookie (curl/yt-dlp convention).
    Ok(trimmed
        .lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty() && (!l.starts_with('#') || l.starts_with("#HttpOnly_")))
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .filter(|f| f.len() >= 7)
        .map(|f| StoredCookie {
            name: f[5].to_string(),
            value: f[6].to_string(),
            domain: f[0].trim_start_matches("#HttpOnly_").to_string(),
            path: if f[2].is_empty() { "/".into() } else { f[2].to_string() },
            expires: f[4].parse::<f64>().ok().filter(|n| *n != 0.0).unwrap_or(-1.0),
            http_only: f[0].starts_with("#HttpOnly_"),
            secure: f[3].eq_ignore_ascii_case("TRUE"),
            same_site: None,
        })
        .collect())
}

fn normalize_json(c: &Value, host: &str) -> StoredCookie {
    let s = |k: &str| c.get(k).map(crate::util::as_text);
    let exp = c.get("expires").or_else(|| c.get("expirationDate")).and_then(|v| v.as_f64());
    StoredCookie {
        name: s("name").unwrap_or_else(|| "undefined".into()),
        value: s("value").unwrap_or_else(|| "undefined".into()),
        domain: s("domain").unwrap_or_else(|| host.to_string()),
        path: s("path").unwrap_or_else(|| "/".into()),
        expires: exp.map(|e| e.floor()).unwrap_or(-1.0),
        http_only: c.get("httpOnly").and_then(|v| v.as_bool()).unwrap_or(false),
        secure: c.get("secure").and_then(|v| v.as_bool()).unwrap_or(false),
        same_site: match c.get("sameSite").and_then(|v| v.as_str()) {
            Some("Strict") => Some(SameSite::Strict),
            Some("Lax") => Some(SameSite::Lax),
            Some("None") => Some(SameSite::None),
            _ => None,
        },
    }
}
