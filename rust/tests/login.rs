//! Round-2 regressions for login: never guess between browser profiles (two people's accounts),
//! accept domains as targets, keep MCP login to human-chosen sources, scope sites by the Public
//! Suffix List, and prune captures.
mod common;
use api_anything::browser::close_browser;
use api_anything::import::{BrowserRoot, Family};
use api_anything::login::{ImportOptions, import_session, reimport_if_browser, resolve_login_target};
use api_anything::mcp::Server;
use api_anything::session::{cookie_value, load_session, parse_set_cookie, prune_captures, save_session, site_of};
use api_anything::types::StoredCookie;
use api_anything::util::now_ms;
use common::Home;
use common::cookie_db::{chromium, make_chromium_db, row};
use serde_json::{Map, Value, json};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

/// API_ANYTHING_HOME and API_ANYTHING_BROWSER_ROOTS are process-wide: the tests take turns, each
/// under a fresh home, like the TS file's `newHome()`.
static LOCK: Mutex<()> = Mutex::new(());

struct Fresh {
    _guard: MutexGuard<'static, ()>,
    home: Home,
    _browser: Option<tempfile::TempDir>,
}

fn new_home() -> Fresh {
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    fs::create_dir_all(home.path().join("sites")).unwrap();
    // SAFETY: serialized by LOCK; a previous test's injected roots must not leak into this one
    unsafe { std::env::remove_var("API_ANYTHING_BROWSER_ROOTS") };
    Fresh { _guard: guard, home, _browser: None }
}

/// Two Chrome profiles, both signed in to LinkedIn as different people, with Local State names.
fn two_linkedin_profiles(f: &mut Fresh) -> String {
    let dir = tempfile::Builder::new().prefix("browser-").tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let li = |v: &str| {
        vec![row(".linkedin.com", "li_at", &format!("AQED{v}")), row(".www.linkedin.com", "JSESSIONID", &format!("\"ajax:{v}\""))]
    };
    make_chromium_db(&root.join("Default"), &li("someone-else-token"), &chromium("pw"));
    make_chromium_db(&root.join("Profile 2"), &li("my-own-token-value"), &chromium("pw"));
    fs::write(
        root.join("Local State"),
        json!({
            "profile": {
                "info_cache": {
                    "Default": { "name": "Other Person", "user_name": "other@example.com" },
                    "Profile 2": { "name": "Sam Rivera", "user_name": "me@example.com" },
                },
            },
        })
        .to_string(),
    )
    .unwrap();
    let roots = vec![BrowserRoot {
        name: "Chrome".into(),
        family: Family::Chromium,
        root: root.display().to_string(),
        password: Some("pw".into()),
        iterations: None,
    }];
    // SAFETY: serialized by LOCK
    unsafe { std::env::set_var("API_ANYTHING_BROWSER_ROOTS", serde_json::to_string(&roots).unwrap()) };
    f._browser = Some(dir);
    root.display().to_string()
}

struct Run {
    code: Option<i32>,
    out: String,
    err: String,
}

fn run_cli(home: &Path, args: &[&str]) -> Run {
    let o = Command::new(env!("CARGO_BIN_EXE_api-anything")).args(args).env("API_ANYTHING_HOME", home).output().unwrap();
    Run {
        code: o.status.code(),
        out: String::from_utf8_lossy(&o.stdout).into_owned(),
        err: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn names(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| x.to_string()).collect()
}

fn li_cookies() -> Option<Vec<String>> {
    Some(names(&["li_at", "JSESSIONID"]))
}

/* ------------------------------------------------------------ 1-3: login */

#[test]
fn login_linkedin_com_www_linkedin_com_a_url_resolve_to_the_bundled_linkedin_site_unknown_domains_become_their_own_site() {
    let _f = new_home();
    for t in ["linkedin", "linkedin.com", "www.linkedin.com", "LinkedIn.com"] {
        let r = resolve_login_target(t).unwrap();
        assert_eq!(r.site, "linkedin", "{t}");
        assert_eq!(r.url, "https://www.linkedin.com", "{t}");
        assert_eq!(r.login_cookies, li_cookies(), "{t}");
    }
    let r = resolve_login_target("https://www.linkedin.com/login").unwrap();
    assert_eq!((r.site.as_str(), r.url.as_str(), r.login_cookies), ("linkedin", "https://www.linkedin.com/login", li_cookies()));
    let r = resolve_login_target("www.example.org").unwrap();
    assert_eq!((r.site.as_str(), r.url.as_str(), r.login_cookies), ("example.org", "https://www.example.org", None));
    let e = resolve_login_target("nosuchsite").err().expect("an unknown name fails");
    assert!(e.to_string().contains("no site \"nosuchsite\""), "{e}");
}

#[test]
fn cli_two_profiles_signed_in_to_the_site_ok_false_with_each_profiles_name_and_account_and_a_profile_next() {
    let mut f = new_home();
    two_linkedin_profiles(&mut f);
    let home = f.home.path().to_path_buf();
    let r = run_cli(&home, &["login", "linkedin.com"]);
    assert_eq!(r.code, Some(1), "{}{}", r.out, r.err);
    let out: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(out["ok"], json!(false));
    let by_profile: Map<String, Value> =
        out["candidates"].as_array().unwrap().iter().map(|c| (c["profile"].as_str().unwrap().to_string(), c.clone())).collect();
    assert_eq!(by_profile["Chrome/Default"], json!({ "profile": "Chrome/Default", "name": "Other Person", "email": "other@example.com" }));
    assert_eq!(by_profile["Chrome/Profile 2"], json!({ "profile": "Chrome/Profile 2", "name": "Sam Rivera", "email": "me@example.com" }));
    let next = regex::Regex::new(r#"next: .*api-anything login linkedin --profile "<Browser/Profile>""#).unwrap();
    assert!(next.is_match(&r.err), "{}", r.err);
    assert!(!home.join("sessions").join("linkedin.json").exists(), "nothing imported on a guess");
}

#[tokio::test]
async fn the_chosen_profile_is_remembered_a_self_heal_re_import_takes_it_even_though_another_profile_is_signed_in_too() {
    let mut f = new_home();
    two_linkedin_profiles(&mut f);
    let e = import_session(
        "linkedin",
        "https://www.linkedin.com",
        ImportOptions { login_cookies: li_cookies(), profile: None, file: None, push_profile: false },
    )
    .await
    .expect_err("two signed-in profiles are refused");
    assert!(e.to_string().contains("2 browser profiles are signed in"), "{e}");
    let r = import_session(
        "linkedin",
        "https://www.linkedin.com",
        ImportOptions { login_cookies: li_cookies(), profile: Some("Chrome/Profile 2".into()), file: None, push_profile: false },
    )
    .await
    .unwrap();
    assert_eq!(r.and_then(|r| r.name).as_deref(), Some("Sam Rivera"));
    assert_eq!(load_session("linkedin").unwrap().source.as_deref(), Some("chrome:Profile 2"));
    let mut s = load_session("linkedin").unwrap();
    s.cookies = vec![]; // the site logged the jar out
    save_session("linkedin", &s).unwrap();
    assert!(reimport_if_browser("linkedin", "https://www.linkedin.com", li_cookies().as_deref()).await);
    assert_eq!(
        cookie_value(&load_session("linkedin").unwrap().cookies, "li_at", None, now_ms()).as_deref(),
        Some("AQEDmy-own-token-value")
    );
    close_browser().await;
}

#[tokio::test]
async fn mcp_login_import_only_refreshes_a_known_sites_human_chosen_source_never_an_arbitrary_domain() {
    let mut f = new_home();
    two_linkedin_profiles(&mut f);
    let server = Server::new(false);
    let login = |args: Value| async {
        let Value::Object(a) = args else { unreachable!() };
        server.call_tool("login", &a).await.value
    };
    // an injected "log in to evil.example" or a known site with no human-run login: refused, points at the CLI
    for args in
        [json!({ "url": "https://accounts.evil.example/" }), json!({ "site": "linkedin" }), json!({ "site": "linkedin", "mode": "import" })]
    {
        let r = login(args).await;
        assert_eq!(r["ok"], json!(false), "{r}");
        assert!(r["next"].as_str().unwrap_or("").contains("api-anything login"), "{r}");
    }
    assert!(!f.home.path().join("sessions").join("linkedin.json").exists());
    // after the human picked Profile 2 in the CLI, the agent may refresh exactly that one
    import_session(
        "linkedin",
        "https://www.linkedin.com",
        ImportOptions { login_cookies: li_cookies(), profile: Some("Chrome/Profile 2".into()), file: None, push_profile: false },
    )
    .await
    .unwrap();
    let mut s = load_session("linkedin").unwrap();
    s.cookies = vec![];
    save_session("linkedin", &s).unwrap();
    let r = login(json!({ "site": "linkedin" })).await;
    assert_eq!(r["ok"], json!(true), "{r}");
    assert_eq!(r["profile"], json!("Chrome/Profile 2"));
    assert_eq!(
        cookie_value(&load_session("linkedin").unwrap().cookies, "li_at", None, now_ms()).as_deref(),
        Some("AQEDmy-own-token-value")
    );
    close_browser().await;
}

/* ------------------------------------------------------------ 9: public suffixes */

#[test]
fn site_of_follows_the_public_suffix_list_private_section_included() {
    assert_ne!(site_of("api.victim.run.app"), "run.app");
    assert_eq!(site_of("foo.supabase.co"), "foo.supabase.co");
    assert_eq!(site_of("abc.execute-api.us-east-1.amazonaws.com"), "abc.execute-api.us-east-1.amazonaws.com");
    assert_eq!(site_of("www.bbc.co.uk"), "bbc.co.uk");
    assert_eq!(site_of("alice.github.io"), "alice.github.io");
    assert_eq!(site_of("www.linkedin.com"), "linkedin.com");
    assert_eq!(site_of("127.0.0.1"), "127.0.0.1");
    assert_eq!(site_of("localhost"), "localhost");
}

#[test]
fn a_set_cookie_for_a_shared_suffix_is_refused_and_a_cookie_ref_never_crosses_it() {
    let now = now_ms();
    for (host, d) in [
        ("a.run.app", "run.app"),
        ("x.supabase.co", "supabase.co"),
        ("y.readthedocs.io", "readthedocs.io"),
        ("z.ngrok.app", "ngrok.app"),
        ("q.notion.site", "notion.site"),
    ] {
        assert_eq!(parse_set_cookie(&format!("sid=1; Domain={d}"), &format!("https://{host}/"), now), None, "{d}");
    }
    let jar = vec![StoredCookie {
        name: "csrftoken".into(),
        value: "OTHER-SITE-SECRET".into(),
        domain: ".victim.run.app".into(),
        path: "/".into(),
        expires: -1.0,
        http_only: false,
        secure: true,
        same_site: None,
    }];
    assert_eq!(cookie_value(&jar, "csrftoken", Some("https://attacker.run.app/x"), now), None);
    assert_eq!(cookie_value(&jar, "csrftoken", Some("https://api.victim.run.app/x"), now).as_deref(), Some("OTHER-SITE-SECRET"));
}

/* ------------------------------------------------------------ 14: captures */

#[test]
fn captures_the_newest_20_are_kept_none_older_than_24_h() {
    let f = new_home();
    let dir = f.home.path().join("captures");
    fs::create_dir_all(&dir).unwrap();
    let now = SystemTime::now();
    let now_ms_at = now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64() * 1000.0;
    let set_mtime = |p: &Path, at: SystemTime| fs::File::options().write(true).open(p).unwrap().set_modified(at).unwrap();
    for i in 0..25u64 {
        let file = dir.join(format!("c{i}.json"));
        fs::write(&file, "{}").unwrap();
        set_mtime(&file, now - Duration::from_millis(i * 60_000));
    }
    let old = dir.join("cold.json");
    fs::write(&old, "{}").unwrap();
    set_mtime(&old, now - Duration::from_millis(25 * 3_600_000));
    prune_captures(now_ms_at);
    let mut left: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    left.sort();
    assert_eq!(left.len(), 20);
    assert!(!left.iter().any(|n| n == "cold.json"));
    assert!(left.iter().any(|n| n == "c0.json") && !left.iter().any(|n| n == "c24.json"));
}
