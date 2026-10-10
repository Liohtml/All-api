mod common;
use api_anything::session::{
    Session, cookie_header_for, cookie_value, home, load_session, logged_in, merge_capture,
    parse_cookie_header, safe_name,
};
use api_anything::types::StoredCookie;
use api_anything::util::now_ms;
use common::{Home, j};
use indexmap::IndexMap;
use serde_json::json;

/// `c(name, value, domain, extra)`: a session cookie on "/", neither secure nor httpOnly, then the overrides.
fn c(name: &str, value: &str, domain: &str) -> StoredCookie {
    common::cookie(name, value, domain)
}
fn secure(mut k: StoredCookie) -> StoredCookie {
    k.secure = true;
    k
}
fn http_only(mut k: StoredCookie) -> StoredCookie {
    k.http_only = true;
    k
}
fn at(mut k: StoredCookie, path: &str) -> StoredCookie {
    k.path = path.to_string();
    k
}
fn expires(mut k: StoredCookie, secs: f64) -> StoredCookie {
    k.expires = secs;
    k
}
fn values(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}
fn cookie_values(s: &Session) -> Vec<String> {
    s.cookies.iter().map(|k| k.value.clone()).collect()
}
fn s(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| x.to_string()).collect()
}

#[test]
fn rfc_6265_domain_path_secure_and_expiry_matching() {
    let now = 1_800_000_000_000.0;
    let jar = vec![
        secure(c("auth_token", "AAA", ".x.com")),
        c("host_only", "B", "x.com"),
        at(c("scoped", "C", ".x.com"), "/i/api"),
        expires(c("expired", "D", ".x.com"), now / 1000.0 - 1.0),
        expires(c("future", "E", ".x.com"), now / 1000.0 + 60.0),
        c("other", "F", ".example.com"),
    ];
    assert_eq!(
        cookie_header_for(&jar, "https://x.com/i/api/graphql", now),
        "scoped=C; auth_token=AAA; host_only=B; future=E"
    );
    assert_eq!(
        cookie_header_for(&jar, "https://api.x.com/1.1/x.json", now),
        "auth_token=AAA; future=E",
        "host-only cookie not sent to a subdomain"
    );
    assert_eq!(
        cookie_header_for(&jar, "http://x.com/i/apiary", now),
        "host_only=B; future=E",
        "no secure cookie over http, /i/api does not match /i/apiary"
    );
    assert_eq!(cookie_header_for(&jar, "https://notx.com/", now), "");
    assert_eq!(
        cookie_header_for(
            &[secure(c("s", "1", "localhost"))],
            "http://localhost:8080/",
            now_ms()
        ),
        "s=1"
    );
}

#[test]
fn cookie_value_prefers_a_cookie_that_would_be_sent_to_the_url() {
    let jar = vec![c("ct0", "wrong", ".other.com"), c("ct0", "right", ".x.com")];
    assert_eq!(
        cookie_value(&jar, "ct0", Some("https://x.com/i/api"), now_ms()).as_deref(),
        Some("right")
    );
    assert_eq!(
        cookie_value(&jar, "ct0", None, now_ms()).as_deref(),
        Some("wrong")
    );
    assert_eq!(cookie_value(&jar, "nope", None, now_ms()), None);
}

#[test]
fn parse_cookie_header_keeps_quotes_for_transforms() {
    assert_eq!(
        j(&parse_cookie_header(
            r#"li_at=abc; JSESSIONID="ajax:123"; bad"#
        )),
        json!({"li_at": "abc", "JSESSIONID": "\"ajax:123\""})
    );
}

#[test]
fn logged_in_heuristic_and_explicit_login_cookies() {
    let guest = vec![
        c("guest_id", "v1%3A17000000", ".x.com"),
        c("gt", "1840000000000000000", ".x.com"),
        c("__cf_bm", "xxxxxxxxxxxx", ".x.com"),
    ];
    assert!(!logged_in(&guest, None, now_ms()));
    let mut with_auth = guest.clone();
    with_auth.push(c("auth_token", "0123456789abcdef", ".x.com"));
    assert!(logged_in(&with_auth, None, now_ms()));
    assert!(logged_in(
        &[c("sessionid", "1234567890%3Aabc", ".instagram.com")],
        None,
        now_ms()
    ));
    assert!(!logged_in(
        &[c("li_at", "AQEDAxxxxxxxx", ".linkedin.com")],
        Some(&s(&["li_at", "JSESSIONID"])),
        now_ms()
    ));
    assert!(
        !logged_in(
            &[expires(c("auth_token", "0123456789abcdef", ".x.com"), 1.0)],
            None,
            now_ms()
        ),
        "expired does not count"
    );
}

#[test]
fn session_store_api_anything_home_override_0700_dirs_0600_files_merge_by_name_domain_path() {
    use std::os::unix::fs::PermissionsExt;
    let h = Home::new();
    assert_eq!(home(), h.path());
    assert_eq!(load_session("x").unwrap(), Session::empty());
    merge_capture(
        "x",
        &[
            c("ct0", "one", ".x.com"),
            expires(c("old", "gone", ".x.com"), 1.0),
        ],
        &values(&[("authorization", "Bearer A")]),
        now_ms(),
    )
    .unwrap();
    let s = merge_capture(
        "x",
        &[c("ct0", "two", ".x.com")],
        &values(&[("x-guest-token", "123")]),
        now_ms(),
    )
    .unwrap();
    assert_eq!(cookie_values(&s), vec!["two"]);
    assert_eq!(
        j(&s.values),
        json!({"authorization": "Bearer A", "x-guest-token": "123"})
    );
    assert_eq!(cookie_values(&load_session("x").unwrap()), vec!["two"]);
    let file = home().join("sessions").join("x.json");
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(home().join("sessions"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let err = load_session("../etc").unwrap_err().to_string();
    assert!(err.contains("invalid site name"), "{err}");
    assert!(safe_name("a/b").is_err());
}

#[test]
fn cookie_value_never_hands_a_cookie_to_another_site_nor_a_secure_one_over_http() {
    let bank = vec![http_only(secure(c(
        "sid",
        "SECURE-ONLY-SESSION",
        ".bank.test",
    )))];
    assert_eq!(
        cookie_value(&bank, "sid", Some("http://evil.test/"), now_ms()),
        None
    );
    assert_eq!(
        cookie_value(&bank, "sid", Some("http://www.bank.test/"), now_ms()),
        None,
        "Secure cookie over http"
    );
    let host = vec![c("csrftoken", "tok123456", "www.site.test")];
    assert_eq!(
        cookie_value(
            &host,
            "csrftoken",
            Some("https://api.site.test/v1"),
            now_ms()
        )
        .as_deref(),
        Some("tok123456"),
        "same site: page JS echoes it to its API host"
    );
}
