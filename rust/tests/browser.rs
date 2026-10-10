//! Port of test/browser.test.ts: the fixture site over plain HTTP, then the browser layer against it.
mod common;
use api_anything::browser::{PageFetchOptions, TriggerOptions, close_browser, page_fetch, run_trigger};
use api_anything::types::Headers;
use common::Home;
use common::fixture::{Fixture, PUBLIC_BEARER};
use regex::Regex;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

// the browser keeps what it learned about the installed Chrome under the home: not the user's own
static HOME: LazyLock<Home> = LazyLock::new(Home::new);

fn chrome() -> bool {
    LazyLock::force(&HOME);
    if std::env::var("API_ANYTHING_CHROME").is_err() {
        let p = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
        if std::path::Path::new(p).exists() {
            unsafe { std::env::set_var("API_ANYTHING_CHROME", p) };
        }
    }
    api_anything::browser::chrome_available()
}

/// The browser tests share one fixture and one profile, in order, like the `describe("browser")` block:
/// the fixture lives on its own runtime so it outlives each test's.
static FX: LazyLock<Fixture> = LazyLock::new(|| {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let f = Fixture::start().await;
            tx.send(f).unwrap();
            std::future::pending::<()>().await;
        });
    });
    rx.recv().unwrap()
});
static PROFILE: LazyLock<tempfile::TempDir> = LazyLock::new(|| tempfile::tempdir().unwrap());

/// The browser tests run one at a time, in file order: one shared Chrome, and later tests use what
/// earlier ones captured.
static STAGE: AtomicUsize = AtomicUsize::new(0);
struct Turn(usize);
impl Drop for Turn {
    fn drop(&mut self) {
        STAGE.store(self.0, Ordering::SeqCst);
    }
}
async fn turn(n: usize) -> Turn {
    while STAGE.load(Ordering::SeqCst) != n - 1 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Turn(n)
}

static GQL_URL: Mutex<String> = Mutex::new(String::new());
static CSRF: Mutex<String> = Mutex::new(String::new());

fn client() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

fn re(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

fn profile() -> std::path::PathBuf {
    PROFILE.path().to_path_buf()
}

/* ------------------------------------------------------ fixture site (plain http) */

#[tokio::test]
async fn stale_query_id_and_old_bundle_404_after_rotate() {
    let fx = Fixture::start().await;
    let c = client();
    let before = fx.state();
    fx.rotate();
    assert_ne!(fx.state().user_query_id, before.user_query_id);
    assert!(re(r"^[\w-]{22}$").is_match(&fx.state().user_query_id));
    let stale = c.get(format!("{}/api/graphql/{}/UserByName?variables=%7B%7D", fx.url, before.user_query_id)).send().await.unwrap();
    assert_eq!(stale.status(), 404);
    assert_eq!(stale.text().await.unwrap(), "");
    assert_eq!(c.get(format!("{}/static/app.{}.js", fx.url, before.build)).send().await.unwrap().status(), 404);
    let js = c.get(format!("{}/static/app.{}.js", fx.url, fx.state().build)).send().await.unwrap().text().await.unwrap();
    assert!(js.contains(&format!("{{queryId:\"{}\",operationName:\"UserByName\"", fx.state().user_query_id)));
    fx.close();
}

#[tokio::test]
async fn login_wall_rate_limit_html_list() {
    let fx = Fixture::start().await;
    let c = client();
    let wall = c.get(format!("{}/private", fx.url)).send().await.unwrap();
    assert_eq!(wall.status(), 200);
    assert!(re("html").is_match(wall.headers().get("content-type").map(|v| v.to_str().unwrap()).unwrap_or("")));
    let ok: Value = serde_json::from_str(&c.get(format!("{}/private", fx.url)).header("cookie", "session=abc").send().await.unwrap().text().await.unwrap()).unwrap();
    assert_eq!(ok, json!({ "data": { "secret": "only for you" } }));
    let mut codes = vec![];
    for _ in 0..3 {
        codes.push(c.get(format!("{}/api/limited", fx.url)).send().await.unwrap().status().as_u16());
    }
    assert_eq!(codes, [200, 200, 429]);
    assert!(re(r#"<li class="user"><a class="name" href="/u/alice">alice</a>"#).is_match(&c.get(format!("{}/list", fx.url)).send().await.unwrap().text().await.unwrap()));
    fx.close();
}

/* -------------------------------------------------------------------- browser */

#[tokio::test]
async fn run_trigger_captures_the_graph_ql_read_with_wire_headers_and_bodies() {
    let _t = turn(1).await;
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let fx = &*FX;
    let r = run_trigger(TriggerOptions::new(&format!("{}/u/alice", fx.url), &profile())).await.unwrap();
    let gql = r.exchanges.iter().find(|e| e.request.url.contains("/UserByName?")).expect("UserByName exchange captured");
    let ct0 = r.cookies.iter().find(|c| c.name == "ct0").unwrap();
    assert_eq!(gql.request.headers.get("x-csrf-token"), Some(&ct0.value));
    assert!(re("ct0=").is_match(gql.request.headers.get("cookie").map(|s| s.as_str()).unwrap_or("")));
    assert_eq!(gql.request.headers.get("x-app-version").map(|s| s.as_str()), Some("2026.09.27-a1b2c3"));
    assert_eq!(gql.request.headers.get("sec-fetch-site").map(|s| s.as_str()), Some("same-origin"));
    assert!(!re("HeadlessChrome").is_match(gql.request.headers.get("user-agent").map(|s| s.as_str()).unwrap_or("")));
    assert!(!re("Headless").is_match(gql.request.headers.get("sec-ch-ua").map(|s| s.as_str()).unwrap_or("")), "{:?}", gql.request.headers.get("sec-ch-ua"));
    assert_eq!(gql.status(), Some(200));
    let body: Value = serde_json::from_str(gql.body()).unwrap();
    assert_eq!(body["data"]["user"]["name"], json!("alice"));

    let doc = r.exchanges.iter().find(|e| e.resource_type == "document");
    assert!(re(&format!(r"/static/app\.{}\.js", fx.state().build)).is_match(doc.map(|d| d.body()).unwrap_or("")));
    assert_eq!(r.final_url, format!("{}/u/alice", fx.url));
    *GQL_URL.lock().unwrap() = gql.request.url.clone();
    *CSRF.lock().unwrap() = ct0.value.clone();
}

#[tokio::test]
async fn soft_from_reaches_the_target_by_an_in_page_navigation() {
    let _t = turn(2).await;
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let fx = &*FX;
    let mut o = TriggerOptions::new(&format!("{}/u/bob", fx.url), &profile());
    o.soft_from = Some(format!("{}/", fx.url));
    let r = run_trigger(o).await.unwrap();
    let gql = r.exchanges.iter().find(|e| e.request.url.contains("/UserByName?"));
    let url = gql.map(|g| g.request.url.clone()).unwrap_or_default();
    assert!(re(r#""name":"bob""#).is_match(&api_anything::util::decode_uri_component(&url).unwrap_or_default()));
    assert_eq!(r.final_url, format!("{}/u/bob", fx.url));
}

#[tokio::test]
async fn soft_from_on_a_client_routed_spa_stays_in_the_app_through_its_own_link_or_history_popstate() {
    let _t = turn(3).await;
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let fx = &*FX;
    for name in ["bob", "dave"] {
        // bob has a link the app rendered; dave has none, so only the history API can route there
        let mut o = TriggerOptions::new(&format!("{}/spa/{name}", fx.url), &profile());
        o.soft_from = Some(format!("{}/spa/alice", fx.url));
        let r = run_trigger(o).await.unwrap();
        assert_eq!(r.exchanges.iter().filter(|e| e.resource_type == "document").count(), 1, "{name}: no second page load");
        assert!(r.exchanges.iter().any(|e| e.request.url.ends_with(&format!("/api/spa/user?name={name}"))), "{name}: the route's XHR fired");
        assert_eq!(r.final_url, format!("{}/spa/{name}", fx.url));
    }
}

#[tokio::test]
async fn write_interception_covers_service_workers_and_gets_sent_by_a_ui_action() {
    let _t = turn(4).await;
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let fx = &*FX;
    let hits = || fx.calls().iter().filter(|c| c.path == "/api/sw-write" || c.path.starts_with("/api/follow")).count();
    let guard: api_anything::browser::Intercept = Arc::new(|e, acting, _via| e.request.method != "GET" || (acting && ["xhr", "fetch"].contains(&e.resource_type.as_str())));
    // A worker installed on an earlier visit would proxy fetches past page routing; api-anything blocks workers.
    let mut o = TriggerOptions::new(&format!("{}/sw", fx.url), &profile());
    o.intercept = Some(guard.clone());
    run_trigger(o).await.unwrap();
    let mut o = TriggerOptions::new(&format!("{}/sw", fx.url), &profile());
    o.intercept = Some(guard.clone());
    let sw = run_trigger(o).await.unwrap();
    let mut o = TriggerOptions::new(&format!("{}/follow/alice", fx.url), &profile());
    o.steps = Some(serde_json::from_value(json!([{ "action": "click", "selector": "#follow" }])).unwrap());
    o.intercept = Some(guard.clone());
    let follow = run_trigger(o).await.unwrap();
    assert_eq!(hits(), 0, "no write reached the server");
    assert!(sw.exchanges.iter().any(|e| e.request.url.ends_with("/api/sw-write") && e.aborted));
    assert!(follow.exchanges.iter().any(|e| e.request.url.ends_with("/api/follow?user=alice") && e.aborted));
}

#[tokio::test]
async fn intercept_aborts_the_write_before_it_reaches_the_server() {
    let _t = turn(5).await;
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let fx = &*FX;
    let mut o = TriggerOptions::new(&format!("{}/compose", fx.url), &profile());
    o.steps = Some(
        serde_json::from_value(json!([
            { "action": "fill", "selector": "#text", "value": "hello world" },
            { "action": "click", "selector": "#post" }
        ]))
        .unwrap(),
    );
    o.intercept = Some(Arc::new(|e, _acting, _via| e.request.method == "POST" && e.request.url.contains("/CreatePost")));
    let r = run_trigger(o).await.unwrap();
    let w = r.exchanges.iter().find(|e| e.request.url.contains("/CreatePost")).unwrap();
    assert!(w.aborted);
    assert!(w.response.is_none());
    let body: Value = serde_json::from_str(w.request.body.as_deref().unwrap_or("")).unwrap();
    assert_eq!(body["variables"], json!({ "text": "hello world" }));
    assert_eq!(fx.calls().iter().filter(|c| c.path.contains("CreatePost")).count(), 0);
}

#[tokio::test]
async fn layered_form_encoding_and_per_request_signatures_come_through() {
    let _t = turn(6).await;
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let fx = &*FX;
    let s = run_trigger(TriggerOptions::new(&format!("{}/search?q=pizza", fx.url), &profile())).await.unwrap();
    let rpc = s.exchanges.iter().find(|e| e.request.url.contains("/api/rpc"));
    assert_eq!(rpc.map(|r| r.resource_type.as_str()), Some("xhr"));
    assert!(re("pizza").is_match(&api_anything::util::decode_uri_component(rpc.and_then(|r| r.request.body.as_deref()).unwrap_or("")).unwrap_or_default()));
    assert!(rpc.map(|r| r.body().starts_with(")]}'")).unwrap_or(false));

    fx.set_require_signature(true);
    let f = run_trigger(TriggerOptions::new(&format!("{}/feed", fx.url), &profile())).await.unwrap();
    let feed = f.exchanges.iter().find(|e| e.request.url.ends_with("/api/signed/feed"));
    assert_eq!(feed.and_then(|f| f.status()), Some(200));
    let feed = feed.unwrap();
    let mut headers = Headers::new();
    headers.insert("x-sig".into(), feed.request.headers.get("x-sig").cloned().unwrap_or_default());
    let replay = page_fetch(PageFetchOptions {
        origin: fx.url.clone(),
        url: feed.request.url.clone(),
        method: "GET".into(),
        headers,
        body: None,
        profile_dir: profile(),
        headless: true,
        timeout_ms: None,
        retry_on_navigation: false,
        redirect: None,
    })
    .await
    .unwrap();
    assert_eq!(replay.status, 403, "a reused signature is rejected");
    fx.set_require_signature(false);
}

#[tokio::test]
async fn page_fetch_runs_fetch_on_the_site_origin_with_the_profiles_cookies() {
    let _t = turn(7).await;
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let fx = &*FX;
    let mut headers = Headers::new();
    headers.insert("x-csrf-token".into(), CSRF.lock().unwrap().clone());
    headers.insert("authorization".into(), PUBLIC_BEARER.into());
    let r = page_fetch(PageFetchOptions {
        origin: fx.url.clone(),
        url: GQL_URL.lock().unwrap().clone(),
        method: "GET".into(),
        headers,
        body: None,
        profile_dir: profile(),
        headless: true,
        timeout_ms: None,
        retry_on_navigation: false,
        redirect: None,
    })
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    let body: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(body["data"]["user"]["name"], json!("alice"));
    assert!(re("json").is_match(r.headers.get("content-type").map(|s| s.as_str()).unwrap_or("")));
    let _ms: u64 = r.ms;
    let call = fx.calls().last().cloned();
    assert!(!re("HeadlessChrome").is_match(&call.and_then(|c| c.headers.get("user-agent").cloned()).unwrap_or_else(|| "undefined".into())));
}

/// The TS test drives `headlessUserAgent()`, the probe Playwright needs because it takes the user
/// agent at launch time, and its `chrome-ua.json` cache. Over CDP the override is applied to each
/// page from the running Chrome's own version string, so there is no probe and nothing to cache:
/// what remains observable is the user agent a headless run sends.
#[tokio::test]
async fn the_headless_user_agent_is_asked_of_chrome_once_per_installed_chrome_then_read_from_disk() {
    let _t = turn(8).await;
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let fx = &*FX;
    let r = run_trigger(TriggerOptions::new(&format!("{}/u/alice", fx.url), &profile())).await.unwrap();
    let gql = r.exchanges.iter().find(|e| e.request.url.contains("/UserByName?")).expect("UserByName exchange captured");
    let probed = gql.request.headers.get("user-agent").cloned().unwrap_or_default();
    assert!(re(r"Chrome/\d").is_match(&probed), "{probed}");
    assert!(!re("Headless").is_match(&probed), "{probed}");
    // the same user agent reaches the server from a page fetch
    let sent = fx.calls().last().and_then(|c| c.headers.get("user-agent").cloned()).unwrap_or_default();
    assert_eq!(sent, probed);
    close_browser().await;
}
