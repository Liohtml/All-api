//! Cookie import from a synthetic encrypted Chromium DB, a Firefox DB, and file exports. No real
//! browser, no Keychain: API_ANYTHING_BROWSER_ROOTS injects roots and the Safe Storage password.
mod common;
use api_anything::import::{AmbiguousProfile, BrowserRoot, Family, ImportPin, cookies_from_file, import_from_browsers};
use api_anything::types::StoredCookie;
use common::cookie_db::{CookieRow, chromium, make_chromium_db, make_firefox_db, row};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

/// API_ANYTHING_BROWSER_ROOTS is one process-wide variable: the tests take turns, like node's
/// sequential tests in one file do.
static ROOTS: Mutex<()> = Mutex::new(());

fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("aa-import-").tempdir().unwrap()
}

fn inject(roots: &[BrowserRoot]) -> MutexGuard<'static, ()> {
    let guard = ROOTS.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: serialized by ROOTS; nothing else in this binary reads the variable concurrently
    unsafe { std::env::set_var("API_ANYTHING_BROWSER_ROOTS", serde_json::to_string(roots).unwrap()) };
    guard
}

fn chrome(root: &Path, password: Option<&str>) -> BrowserRoot {
    BrowserRoot {
        name: "Chrome".into(),
        family: Family::Chromium,
        root: root.display().to_string(),
        password: password.map(|p| p.to_string()),
        iterations: None,
    }
}

fn li() -> CookieRow {
    row(".linkedin.com", "li_at", "AQEDreallylongtokenvalue")
}
fn js() -> CookieRow {
    row(".linkedin.com", "JSESSIONID", "\"ajax:1234567890\"")
}

fn names(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| x.to_string()).collect()
}

fn set_mtime(path: &Path, at: SystemTime) {
    fs::File::options().write(true).open(path).unwrap().set_modified(at).unwrap();
}

fn pin(browser: Option<&str>, profile: &str) -> ImportPin {
    ImportPin { browser: browser.map(|b| b.to_string()), profile: profile.to_string() }
}

#[test]
fn decrypts_a_v10_chromium_cookie_meta_version_24_strips_the_host_key_hash() {
    let root = tmp();
    make_chromium_db(&root.path().join("Default"), &[li(), js()], &chromium_with("s3cret-keychain-pw", Some(24)));
    let _g = inject(&[chrome(root.path(), Some("s3cret-keychain-pw"))]);

    let r = import_from_browsers("https://www.linkedin.com", Some(&names(&["li_at", "JSESSIONID"])), None).unwrap().expect("an import");
    assert_eq!(r.source, "chrome:Default");
    let by_name = |n: &str| r.cookies.iter().find(|c| c.name == n).map(|c| c.value.clone());
    assert_eq!(by_name("li_at").as_deref(), Some("AQEDreallylongtokenvalue"));
    assert_eq!(by_name("JSESSIONID").as_deref(), Some("\"ajax:1234567890\""), "quotes preserved for the csrf transform");
}

fn chromium_with(password: &str, meta_version: Option<i64>) -> common::cookie_db::ChromiumOptions {
    let mut o = chromium(password);
    o.meta_version = meta_version;
    o
}

#[test]
fn a_real_world_expires_utc_beyond_js_safe_integer_range_is_read_without_throwing() {
    let root = tmp();
    let mut r = row(".linkedin.com", "li_at", "AQEDtoken12345678");
    r.expires_utc = Some(13399829086694638);
    make_chromium_db(&root.path().join("Default"), &[r], &chromium("pw"));
    let _g = inject(&[chrome(root.path(), Some("pw"))]);
    let r = import_from_browsers("https://linkedin.com", None, None).unwrap();
    let c = r.as_ref().and_then(|r| r.cookies.iter().find(|x| x.name == "li_at"));
    assert_eq!(c.map(|c| c.value.as_str()), Some("AQEDtoken12345678"));
    let c = c.unwrap();
    assert!(c.expires > 1_700_000_000.0 && c.expires.is_finite(), "expires should be a sane unix time, got {}", c.expires);
}

#[test]
fn meta_version_below_24_does_not_strip_a_prefix() {
    let root = tmp();
    make_chromium_db(&root.path().join("Default"), &[row(".x.com", "auth_token", "0123456789abcdef")], &chromium_with("pw", Some(18)));
    let _g = inject(&[chrome(root.path(), Some("pw"))]);
    let r = import_from_browsers("https://x.com", None, None).unwrap();
    assert_eq!(
        r.as_ref().and_then(|r| r.cookies.iter().find(|c| c.name == "auth_token")).map(|c| c.value.as_str()),
        Some("0123456789abcdef")
    );
}

#[test]
fn chooses_the_profile_that_has_all_login_cookies_not_merely_the_most_recent_one() {
    let root = tmp();
    make_chromium_db(&root.path().join("Default"), &[row(".linkedin.com", "bcookie", "somebrowseridxxxx")], &chromium("pw"));
    make_chromium_db(&root.path().join("Profile 2"), &[li(), js()], &chromium("pw"));
    // Make Default the most recently used, so only the loginCookies rule picks Profile 2.
    set_mtime(&root.path().join("Default").join("Network").join("Cookies"), SystemTime::now());
    set_mtime(&root.path().join("Profile 2").join("Network").join("Cookies"), SystemTime::now() - Duration::from_millis(100000));
    let _g = inject(&[chrome(root.path(), Some("pw"))]);

    let r = import_from_browsers("https://www.linkedin.com", Some(&names(&["li_at", "JSESSIONID"])), None).unwrap();
    assert_eq!(r.map(|r| r.source).as_deref(), Some("chrome:Profile 2"));
}

#[test]
fn two_signed_in_profiles_refuses_to_guess_not_the_most_recently_used_listing_each_profiles_name_and_google_account() {
    let root = tmp();
    make_chromium_db(&root.path().join("Default"), &[row(".reddit.com", "reddit_session", "oldsessionvalue1")], &chromium("pw"));
    make_chromium_db(&root.path().join("Profile 1"), &[row(".reddit.com", "reddit_session", "newsessionvalue2")], &chromium("pw"));
    set_mtime(&root.path().join("Default").join("Network").join("Cookies"), SystemTime::now() - Duration::from_millis(100000));
    set_mtime(&root.path().join("Profile 1").join("Network").join("Cookies"), SystemTime::now());
    fs::write(
        root.path().join("Local State"),
        serde_json::json!({
            "profile": {
                "info_cache": {
                    "Default": { "name": "Work", "user_name": "someone.else@example.com" },
                    "Profile 1": { "name": "Me", "user_name": "me@example.com" },
                },
            },
        })
        .to_string(),
    )
    .unwrap();
    let _g = inject(&[chrome(root.path(), Some("pw"))]);

    let err = import_from_browsers("https://reddit.com", None, None).err();
    let err = err.expect("expected a refusal, got an import");
    let a = err.downcast_ref::<AmbiguousProfile>().unwrap_or_else(|| panic!("expected a refusal, got {err}"));
    let mut candidates = a.candidates.clone();
    candidates.sort_by(|x, y| x.profile.cmp(&y.profile));
    assert_eq!(
        serde_json::to_value(&candidates).unwrap(),
        serde_json::json!([
            { "profile": "Chrome/Default", "name": "Work", "email": "someone.else@example.com" },
            { "profile": "Chrome/Profile 1", "name": "Me", "email": "me@example.com" },
        ])
    );
    // a known site's loginCookies narrow it the same way: both hold them, so still no guess
    let e = import_from_browsers("https://reddit.com", Some(&names(&["reddit_session"])), None).expect_err("a refusal");
    assert!(e.downcast_ref::<AmbiguousProfile>().is_some(), "{e}");
    // the human's pick is honoured, and the chosen profile's name comes back for printing
    let r = import_from_browsers("https://reddit.com", None, Some(&pin(Some("Chrome"), "Profile 1"))).unwrap().expect("an import");
    assert_eq!(r.source, "chrome:Profile 1");
    assert_eq!(r.cookies.first().map(|c| c.value.as_str()), Some("newsessionvalue2"));
    assert_eq!(r.name.as_deref(), Some("Me"));
    assert_eq!(r.email.as_deref(), Some("me@example.com"));
}

#[test]
fn one_profile_signed_in_another_with_only_tracking_cookies_the_signed_in_one_no_question_asked() {
    let root = tmp();
    make_chromium_db(&root.path().join("Default"), &[row(".reddit.com", "csv", "trackingcookie1")], &chromium("pw"));
    make_chromium_db(&root.path().join("Profile 1"), &[row(".reddit.com", "reddit_session", "realsessionvalue")], &chromium("pw"));
    let _g = inject(&[chrome(root.path(), Some("pw"))]);
    assert_eq!(import_from_browsers("https://www.reddit.com", None, None).unwrap().map(|r| r.source).as_deref(), Some("chrome:Profile 1"));
}

#[test]
fn profile_pin_overrides_selection_a_missing_pin_throws() {
    let root = tmp();
    make_chromium_db(&root.path().join("Default"), &[li(), js()], &chromium("pw"));
    make_chromium_db(&root.path().join("Profile 2"), &[row(".linkedin.com", "li_at", "differentprofilexx")], &chromium("pw"));
    let _g = inject(&[chrome(root.path(), Some("pw"))]);

    assert_eq!(
        import_from_browsers("https://linkedin.com", None, Some(&pin(None, "Profile 2")))
            .unwrap()
            .and_then(|r| r.cookies.first().map(|c| c.value.clone()))
            .as_deref(),
        Some("differentprofilexx")
    );
    let e = import_from_browsers("https://linkedin.com", None, Some(&pin(Some("chrome"), "Nope"))).expect_err("a missing pin throws");
    assert!(e.to_string().contains("no browser profile"), "{e}");
}

#[test]
fn only_the_sites_own_cookies_are_read() {
    let root = tmp();
    make_chromium_db(&root.path().join("Default"), &[li(), row(".evil.com", "li_at", "shouldnotappearxx")], &chromium("pw"));
    let _g = inject(&[chrome(root.path(), Some("pw"))]);
    let r = import_from_browsers("https://linkedin.com", None, None).unwrap().expect("an import");
    assert_eq!(r.cookies.iter().map(|c| c.domain.as_str()).collect::<Vec<_>>(), vec![".linkedin.com"]);
}

#[test]
fn a_wrong_safe_storage_password_skips_cookies_rather_than_failing() {
    let root = tmp();
    make_chromium_db(&root.path().join("Default"), &[li()], &chromium("the-real-pw"));
    let _g = inject(&[chrome(root.path(), Some("the-wrong-pw"))]);
    // decryption yields garbage or fails per-cookie; the import returns None (nothing usable).
    let r = import_from_browsers("https://linkedin.com", None, None).unwrap();
    assert!(r.map(|r| r.cookies.iter().all(|c| c.value != "AQEDreallylongtokenvalue")).unwrap_or(true));
}

#[test]
fn firefox_plaintext_moz_cookies() {
    let root = tmp();
    let mut r = row("www.linkedin.com", "li_at", "firefoxtokenvalue");
    r.expires_utc = Some(2000000000);
    make_firefox_db(&root.path().join("abc.default-release"), &[r]);
    let _g = inject(&[BrowserRoot {
        name: "Firefox".into(),
        family: Family::Firefox,
        root: root.path().display().to_string(),
        password: None,
        iterations: None,
    }]);
    let r = import_from_browsers("https://linkedin.com", None, None).unwrap().expect("an import");
    assert_eq!(r.source, "firefox:abc.default-release");
    assert_eq!(r.cookies.first().map(|c| c.value.as_str()), Some("firefoxtokenvalue"));
    assert_eq!(r.cookies.first().map(|c| c.expires), Some(2000000000.0));
}

#[test]
fn cookies_from_file_parses_netscape_and_json_exports() {
    let netscape = [
        "# Netscape HTTP Cookie File",
        "#HttpOnly_.linkedin.com\tTRUE\t/\tTRUE\t2000000000\tli_at\tAQEDtoken",
        "www.linkedin.com\tFALSE\t/\tFALSE\t0\tlang\ten",
    ]
    .join("\n");
    let parsed = cookies_from_file(&netscape, "https://linkedin.com").unwrap();
    let li_at = parsed.iter().find(|c| c.name == "li_at").unwrap();
    assert_eq!(
        (li_at.value.as_str(), li_at.path.as_str(), li_at.secure, li_at.http_only, li_at.expires),
        ("AQEDtoken", "/", true, true, 2000000000.0)
    );
    assert!(!parsed.iter().find(|c| c.name == "lang").unwrap().secure);

    let json = serde_json::json!([
        {
            "name": "li_at",
            "value": "AQEDjson",
            "domain": ".linkedin.com",
            "path": "/",
            "secure": true,
            "httpOnly": true,
            "expirationDate": 1999999999.5,
        },
    ])
    .to_string();
    let from_json = cookies_from_file(&json, "https://linkedin.com").unwrap();
    assert_eq!(
        from_json[0],
        StoredCookie {
            name: "li_at".into(),
            value: "AQEDjson".into(),
            domain: ".linkedin.com".into(),
            path: "/".into(),
            expires: 1999999999.0,
            http_only: true,
            secure: true,
            same_site: None,
        }
    );
}
