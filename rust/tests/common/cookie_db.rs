//! Build synthetic browser cookie DBs for the import tests, matching what real browsers write.
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use api_anything::import::derive_key;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct CookieRow {
    pub host_key: String,
    pub name: String,
    pub value: String,
    pub path: Option<String>,
    pub expires_utc: Option<i64>,
    pub secure: bool,
    pub http_only: bool,
    pub samesite: Option<i64>,
}

/// `{ host_key, name, value }` with the other columns at their defaults.
pub fn row(host_key: &str, name: &str, value: &str) -> CookieRow {
    CookieRow {
        host_key: host_key.to_string(),
        name: name.to_string(),
        value: value.to_string(),
        path: None,
        expires_utc: None,
        secure: false,
        http_only: false,
        samesite: None,
    }
}

pub struct ChromiumOptions {
    pub password: String,
    pub iterations: Option<u32>,
    pub meta_version: Option<i64>,
}

/// `{ password }` with the platform default iterations and meta version 24.
pub fn chromium(password: &str) -> ChromiumOptions {
    ChromiumOptions { password: password.to_string(), iterations: None, meta_version: None }
}

fn encrypt(value: &str, key: &[u8; 16], meta_version: i64, host_key: &str) -> Vec<u8> {
    let iv = [0x20u8; 16];
    let enc = cbc::Encryptor::<aes::Aes128>::new(key.into(), &iv.into());
    let mut plain: Vec<u8> = Vec::new();
    if meta_version >= 24 {
        plain.extend_from_slice(&Sha256::digest(host_key.as_bytes()));
    }
    plain.extend_from_slice(value.as_bytes());
    let cipher = enc.encrypt_padded_vec_mut::<aes::cipher::block_padding::Pkcs7>(&plain);
    let mut out = b"v10".to_vec();
    out.extend_from_slice(&cipher);
    out
}

/// Write <profile_dir>/Network/Cookies as modern Chrome does, with v10-encrypted values.
pub fn make_chromium_db(profile_dir: &Path, rows: &[CookieRow], o: &ChromiumOptions) {
    let meta_version = o.meta_version.unwrap_or(24);
    // the platform default src/import.rs derives with, so each OS tests its own path
    let iterations = o.iterations.unwrap_or(if cfg!(target_os = "linux") { 1 } else { 1003 });
    let key = derive_key(&o.password, iterations);
    fs::create_dir_all(profile_dir.join("Network")).unwrap();
    let db = Connection::open(profile_dir.join("Network").join("Cookies")).unwrap();
    db.execute_batch("DROP TABLE IF EXISTS meta; DROP TABLE IF EXISTS cookies").unwrap();
    db.execute_batch("CREATE TABLE meta(key TEXT, value TEXT)").unwrap();
    db.execute("INSERT INTO meta VALUES('version', ?)", params![meta_version.to_string()]).unwrap();
    db.execute_batch(
        "CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER)",
    )
    .unwrap();
    let mut stmt = db.prepare("INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?)").unwrap();
    for r in rows {
        // expires_utc can exceed JS safe-integer range; an i64 stores it exactly.
        stmt.execute(params![
            r.host_key,
            r.name,
            "",
            encrypt(&r.value, &key, meta_version, &r.host_key),
            r.path.clone().unwrap_or_else(|| "/".to_string()),
            r.expires_utc.unwrap_or(0),
            if r.secure { 1 } else { 0 },
            if r.http_only { 1 } else { 0 },
            r.samesite.unwrap_or(-1),
        ])
        .unwrap();
    }
    drop(stmt);
    db.close().unwrap();
}

/// Write <profile_dir>/cookies.sqlite as Firefox does (moz_cookies is plaintext).
pub fn make_firefox_db(profile_dir: &Path, rows: &[CookieRow]) {
    fs::create_dir_all(profile_dir).unwrap();
    let db = Connection::open(profile_dir.join("cookies.sqlite")).unwrap();
    db.execute_batch(
        "CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER)",
    )
    .unwrap();
    let mut stmt = db.prepare("INSERT INTO moz_cookies VALUES(?,?,?,?,?,?,?,?)").unwrap();
    for r in rows {
        stmt.execute(params![
            r.host_key,
            r.name,
            r.value,
            r.path.clone().unwrap_or_else(|| "/".to_string()),
            r.expires_utc.unwrap_or(0),
            if r.secure { 1 } else { 0 },
            if r.http_only { 1 } else { 0 },
            r.samesite.unwrap_or(0),
        ])
        .unwrap();
    }
    drop(stmt);
    db.close().unwrap();
}
