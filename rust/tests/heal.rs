//! Port of test/heal.test.ts: heal edge cases against small local servers: which args a recapture
//! learns from, what a failed heal leaves behind, what validates a candidate, and that call()
//! never fails outright.
mod common;
use api_anything::browser::close_browser;
use api_anything::classify::Class;
use api_anything::execute::{CallOptions, call};
use api_anything::heal::{AddInput, Recipe, add_operation};
use api_anything::http::{Fetcher, HttpRequest, HttpResponse};
use api_anything::spec::{Trigger, parse_site};
use api_anything::store::{load_site, save_site, stale_mark};
use api_anything::types::Headers;
use api_anything::util::now_ms;
use axum::body::Body;
use axum::http::request::Parts;
use axum::response::Response;
use common::{Home, args, j};
use futures_util::future::BoxFuture;
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

static HOME: LazyLock<Home> = LazyLock::new(Home::new);
/// The TS tests share one search server state (`version`, `pageLoads`) and run one after the other.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static VERSION: Mutex<&str> = Mutex::new("v1");
static PAGE_LOADS: AtomicUsize = AtomicUsize::new(0);

fn chrome() -> bool {
    if std::env::var("API_ANYTHING_CHROME").is_err() {
        let p = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
        if std::path::Path::new(p).exists() {
            unsafe { std::env::set_var("API_ANYTHING_CHROME", p) };
        }
    }
    api_anything::browser::chrome_available()
}

const SKIP: &str = "Google Chrome not installed: skipped";

async fn start() -> tokio::sync::MutexGuard<'static, ()> {
    let _ = &*HOME;
    LOCK.lock().await
}

fn fast() -> CallOptions {
    CallOptions { min_interval_ms: Some(0), ..Default::default() }
}

fn set_version(v: &'static str) {
    *VERSION.lock().unwrap() = v;
}

fn page_loads() -> usize {
    PAGE_LOADS.load(Ordering::SeqCst)
}

type ServerHandler = Arc<dyn Fn(&Parts, &str) -> Response + Send + Sync>;

/// A small HTTP server on 127.0.0.1 answering every request with `h`; returns its base URL.
async fn serve(h: ServerHandler) -> String {
    let app = axum::Router::new().fallback(move |req: axum::http::Request<Body>| {
        let h = h.clone();
        async move {
            let (parts, body) = req.into_parts();
            let bytes = axum::body::to_bytes(body, 16 * 1024 * 1024).await.unwrap_or_default();
            h(&parts, &String::from_utf8_lossy(&bytes))
        }
    });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://127.0.0.1:{port}")
}

fn res(status: u16, content_type: &str, body: &str) -> Response {
    Response::builder().status(status).header("content-type", content_type).body(Body::from(body.to_string())).unwrap()
}

fn params(p: &Parts) -> HashMap<String, String> {
    url::form_urlencoded::parse(p.uri.query().unwrap_or("").as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
}

/// A search API that renames q -> term after a deploy; the page JS follows along.
async fn search() -> String {
    serve(Arc::new(|p: &Parts, _body: &str| {
        let version = *VERSION.lock().unwrap();
        let key = match version {
            "v1" => "q",
            "v2" => "term",
            _ => "gone",
        };
        let q = params(p);
        if p.uri.path().starts_with("/api/") {
            if !q.contains_key(key) {
                return res(400, "application/json", "{\"error\":\"unknown argument\"}");
            }
            return res(200, "application/json", &json!({ "results": [{ "q": q.get(key), "page": q.get("page") }, { "q": "x" }] }).to_string());
        }
        PAGE_LOADS.fetch_add(1, Ordering::SeqCst);
        if version == "v3" {
            return res(200, "text/html", "<html><body>search is down</body></html>");
        }
        res(
            200,
            "text/html",
            &format!(
                "<html><body><script>const p=new URLSearchParams(location.search);\nfetch(\"/api/search?{key}=\"+encodeURIComponent(p.get(\"q\"))+\"&page=\"+encodeURIComponent(p.get(\"page\")||\"1\"))</script></body></html>"
            ),
        )
    }))
    .await
}

fn add_search(site: &str, base: &str) -> AddInput {
    AddInput {
        site: site.into(),
        op: "search".into(),
        trigger: Some(Trigger { url: format!("{base}/s?q={{q}}&page={{page}}"), steps: None, soft_from: None }),
        examples: vec![args(json!({"q": "hello", "page": "100"})), args(json!({"q": "world", "page": "200"}))],
        matcher: None,
        write: false,
        description: None,
        response: Some(Recipe { extract: Some("results".into()), ..Default::default() }),
        public: None,
        from: None,
        from2: None,
        fetcher: None,
    }
}

#[tokio::test]
async fn recapture_with_an_omitted_optional_arg_keeps_every_params_slot_defaults_filled() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = start().await;
    let base = search().await;
    set_version("v1");
    add_operation(add_search("s1", &base)).await.unwrap();
    let mut site = load_site("s1").unwrap().unwrap().site;
    site.operations[0].params[1].required = false;
    site.operations[0].params[1].default = Some(json!("100"));
    save_site(&site).unwrap();
    set_version("v2");
    let r = call("s1", "search", args(json!({"q": "cats"})), fast()).await;
    assert_eq!(r.healed, Some(true), "{}", j(&r));
    let op = load_site("s1").unwrap().unwrap().site.operations.remove(0);
    let names: BTreeSet<String> = op.slots.iter().filter_map(|s| s.param.clone()).collect();
    assert_eq!(names.into_iter().collect::<Vec<_>>(), vec!["page", "q"]);
    let later = call("s1", "search", args(json!({"q": "dogs", "page": "250"})), fast()).await;
    assert_eq!(later.data.as_ref().unwrap()[0], json!({ "q": "dogs", "page": "250" }));
    close_browser().await;
}

#[tokio::test]
async fn recapture_with_a_short_arg_page_2_learns_from_the_ops_examples_instead() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = start().await;
    let base = search().await;
    set_version("v1");
    add_operation(add_search("s2", &base)).await.unwrap();
    set_version("v2");
    let r = call("s2", "search", args(json!({"q": "cats", "page": "2"})), fast()).await;
    assert_eq!(r.healed, Some(true), "{}", j(&r));
    assert_eq!(r.data.as_ref().unwrap()[0], json!({ "q": "cats", "page": "2" }));
    close_browser().await;
}

#[tokio::test]
async fn a_failed_heal_marks_the_op_stale_so_the_next_call_skips_the_browser() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = start().await;
    let base = search().await;
    set_version("v2");
    add_operation(add_search("s3", &base)).await.unwrap();
    set_version("v3"); // the page no longer fires the request: nothing can heal
    let loads = page_loads();
    let failed = call("s3", "search", args(json!({"q": "cats", "page": "3"})), fast()).await;
    assert!(!failed.ok);
    assert!(failed.reason.as_deref().unwrap_or("").contains("heal failed"));
    assert!(stale_mark("s3", "search", now_ms()).is_some(), "a failed heal leaves a stale mark");
    let between = page_loads();
    let again = call("s3", "search", args(json!({"q": "cats", "page": "4"})), fast()).await;
    assert!(!again.ok);
    assert!(again.reason.as_deref().unwrap_or("").contains("stale"));
    assert!(between > loads);
    assert_eq!(page_loads(), between, "no browser run while stale (the trigger never answered either)");
    close_browser().await;
}

#[tokio::test]
async fn a_tier_3_ops_heal_candidate_is_validated_by_replaying_it_not_by_rerunning_the_sites_trigger() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = start().await;
    const QID: &str = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7H";
    const DECOY: &str = "Qq1Rr2Ss3Tt4Uu5Vv6Ww7X";
    let api_paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let n = Arc::new(AtomicUsize::new(0));
    let (ap, n2) = (api_paths.clone(), n.clone());
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        if p.uri.path().starts_with("/api/") {
            ap.lock().unwrap().push(p.uri.path().to_string());
            let body = if n2.fetch_add(1, Ordering::SeqCst) == 0 { json!({ "hiccup": true }) } else { json!({ "user": { "name": "bob" } }) };
            return res(200, "application/json", &body.to_string());
        }
        res(
            200,
            "text/html",
            &format!(
                "<html><body><script>var unrelated={{id:\"{DECOY}\",operationName:\"User\"}};\nfetch(\"/api/\"+\"{}\"+\"{}\"+\"/User?name=\"+location.pathname.split(\"/\")[2]);</script></body></html>",
                &QID[..11],
                &QID[11..]
            ),
        )
    }))
    .await;
    save_site(
        &parse_site(&json!({
            "name": "m",
            "baseUrl": base,
            "operations": [{
                "name": "user",
                "readOnly": true,
                "minTier": 3,
                "request": { "method": "GET", "url": format!("{base}/api/{QID}/User?name=alice"), "headers": {} },
                "slots": [{ "param": "name", "at": ["query:name"] }],
                "volatile": [{ "at": ["path:1"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "User" }],
                "trigger": { "url": format!("{base}/u/{{name}}") },
                "match": { "method": "GET", "path": "/api/*/User" },
                "params": [{ "name": "name" }],
                "response": { "extract": "user" },
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    call("m", "user", args(json!({"name": "bob"})), fast()).await;
    let paths = api_paths.lock().unwrap().clone();
    assert!(paths.contains(&format!("/api/{DECOY}/User")), "the candidate itself was sent: {}", j(&paths));
    close_browser().await;
}

/// `fetchImpl = async () => new Response("", { status: 404 })`
struct NotFound;

impl Fetcher for NotFound {
    fn fetch(&self, _req: HttpRequest, _timeout: Duration) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        let mut headers = Headers::new();
        headers.insert("content-type".into(), "text/plain;charset=UTF-8".into());
        Box::pin(async move { Ok(HttpResponse { status: 404, headers, set_cookie: vec![], body: vec![], url: String::new() }) })
    }
}

#[tokio::test]
async fn call_never_throws_when_the_heals_browser_run_fails() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = start().await;
    save_site(
        &parse_site(&json!({
            "name": "d",
            "baseUrl": "http://127.0.0.1:9",
            "operations": [{
                "name": "get",
                "readOnly": true,
                "request": { "method": "GET", "url": "http://api.d.test/v1/thing?q=abc", "headers": {} },
                "slots": [{ "param": "q", "at": ["query:q"] }],
                "trigger": { "url": "http://127.0.0.1:9/page?q={q}" },
                "params": [{ "name": "q" }],
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    let r = call("d", "get", args(json!({"q": "abc"})), CallOptions { fetcher: Some(Arc::new(NotFound)), ..fast() }).await;
    assert!(!r.ok);
    assert_eq!(r.class, Class::Drift);
    assert!(r.reason.as_deref().unwrap_or("").contains("heal failed"));
    close_browser().await;
}
