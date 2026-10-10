//! test/edge/live-a.test.ts: offline repros of what live runs against YouTube, Airbnb, Reddit,
//! Amazon, Product Hunt and Booking.com showed. Each test is a regression for a bug that was fixed.
//! Chrome tests skip without Chrome.
mod common;
use api_anything::classify::{Class, Observed, classify};
use api_anything::execute::{CallOptions, call};
use api_anything::extract::cap_output;
use api_anything::heal::{AddInput, Recipe, add_operation, profile_dir};
use api_anything::learn::{LearnInput, learn_operation};
use api_anything::session::{Session, save_session};
use api_anything::spec::{HtmlRecipe, Match, Operation, Site, Trigger, parse_match, parse_operation};
use api_anything::store::{load_site, save_site};
use api_anything::types::Headers;
use common::{Home, args, exs, j};
use live::LiveFixture;
use serde_json::{Value, json};
use std::future::Future;
use std::sync::{LazyLock, Mutex};

/* ------------------------------------------------------------ the fixture */

/// Port of test/edge/live-a.fixture.ts: offline stand-ins for patterns seen live on YouTube,
/// Airbnb, Reddit, Amazon and Booking.com. Each route mimics one real-world behaviour the
/// framework mishandled.
mod live {
    #![allow(dead_code)]
    use axum::body::Body;
    use axum::extract::{Request, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use base64::Engine;
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    pub struct Hit {
        pub method: String,
        pub path: String,
        pub headers: HashMap<String, String>,
        /// raw header bytes as they came off the wire, latin1-decoded
        pub raw_referer: Option<String>,
        pub body: String,
    }

    struct Inner {
        hits: Mutex<Vec<Hit>>,
        /// /status pages answer "temporarily unavailable" (no results, for every query)
        down: AtomicBool,
    }

    pub struct LiveFixture {
        pub url: String,
        inner: Arc<Inner>,
        task: tokio::task::JoinHandle<()>,
    }

    fn esc(s: &str) -> String {
        s.chars().map(|c| if "&<>\"".contains(c) { format!("&#{};", c as u32) } else { c.to_string() }).collect()
    }

    // Booking.com's AWS WAF interstitial: 202, a small page that loads challenge.js, sets a cookie and
    // reloads the same URL with &chal_t=... appended.
    fn waf_page(target: &str) -> String {
        format!(
            "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title></title>\n<script type=\"text/javascript\">window.awsWafCookieDomainList = ['127.0.0.1'];</script>\n<script type=\"text/javascript\" src=\"/__challenge_h78IRKX3kpQxScCExxShBNwRUlb/d8c14d4960ca/challenge.js\"></script>\n<script>document.cookie=\"aws-waf-token=ok; path=/\";location.replace({});</script>\n</head><body><noscript>JavaScript is disabled</noscript></body></html>",
            serde_json::Value::String(target.to_string())
        )
    }

    fn send(status: u16, kind: &str, text: String) -> Response {
        Response::builder().status(status).header("content-type", kind).body(Body::from(text)).unwrap()
    }
    fn html(markup: &str, status: u16) -> Response {
        send(
            status,
            "text/html; charset=utf-8",
            format!("<!doctype html><html><head><meta charset=\"utf-8\"><title>Fixture</title></head><body>{markup}</body></html>"),
        )
    }

    async fn handle(State(inner): State<Arc<Inner>>, req: Request) -> Response {
        let method = req.method().to_string();
        let p = req.uri().path().to_string();
        let search = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
        let query: HashMap<String, String> = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let headers: HashMap<String, String> =
            req.headers().iter().map(|(k, v)| (k.as_str().to_lowercase(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
        let raw_referer = req.headers().get("referer").map(|v| v.as_bytes().iter().map(|&b| b as char).collect::<String>());
        let gz = headers.get("content-encoding").map(|e| e.to_lowercase().contains("gzip")).unwrap_or(false);
        let raw = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024).await.unwrap_or_default();
        let body = if gz {
            let mut out = Vec::new();
            match flate2::read::GzDecoder::new(&raw[..]).read_to_end(&mut out) {
                Ok(_) => String::from_utf8_lossy(&out).into_owned(),
                Err(_) => raw.iter().map(|&b| b as char).collect(),
            }
        } else {
            String::from_utf8_lossy(&raw).into_owned()
        };
        inner.hits.lock().unwrap().push(Hit {
            method,
            path: format!("{p}{search}"),
            headers: headers.clone(),
            raw_referer,
            body: body.clone(),
        });
        let q = query.get("q").cloned().unwrap_or_default();
        let cookie = headers.get("cookie").cloned().unwrap_or_default();

        match p.as_str() {
            // Amazon/Reddit shape: server-rendered list, plus a telemetry beacon (JSON in, JSON out) carrying the page URL and title.
            "/shop" => html(
                &format!(
                    "<ul>{}</ul><script>fetch(\"/svc/events\",{{method:\"POST\",headers:{{\"content-type\":\"application/json\"}},body:JSON.stringify({{events:[{{page:{{url:location.href,title:\"Results for \"+new URLSearchParams(location.search).get(\"q\")}}}}]}})}})</script>",
                    [1, 2].iter().map(|n| format!("<li class=\"r\">{} result {n}</li>", esc(&q))).collect::<String>()
                ),
                200,
            ),
            "/svc/events" => send(200, "application/json", "{\"ok\":1}".into()),
            // An API whose query rides base64-encoded inside the JSON body (the learner can't see it);
            // only the referer shows the search term in the clear.
            "/b64" => html(
                "<div id=\"out\"></div><script>fetch(\"/api/b64\",{method:\"POST\",headers:{\"content-type\":\"application/json\"},body:JSON.stringify({payload:btoa(JSON.stringify({query:new URLSearchParams(location.search).get(\"q\")}))})}).then(r=>r.json()).then(v=>{document.getElementById(\"out\").textContent=JSON.stringify(v)})</script>",
                200,
            ),
            "/api/b64" => {
                let decoded = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("payload").and_then(|p| p.as_str()).map(|s| s.to_string()))
                    .and_then(|p| base64::engine::general_purpose::STANDARD.decode(p).ok())
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .and_then(|v| v.get("query").and_then(|q| q.as_str()).map(|s| s.to_string()));
                match decoded {
                    Some(query) => send(200, "application/json", serde_json::json!({ "results": [{ "title": format!("{query} result") }] }).to_string()),
                    None => send(400, "application/json", "{\"error\":\"bad payload\"}".into()),
                }
            }
            // YouTube innertube shape: the page POSTs a gzip-compressed JSON body with content-encoding: gzip.
            "/gz" => html(
                "<div id=\"out\"></div><script>(async()=>{const q=new URLSearchParams(location.search).get(\"q\");const s=new Blob([JSON.stringify({context:{client:{clientName:\"WEB\"}},query:q})]).stream().pipeThrough(new CompressionStream(\"gzip\"));const b=await new Response(s).arrayBuffer();const r=await fetch(\"/api/gz\",{method:\"POST\",headers:{\"content-type\":\"application/json\",\"content-encoding\":\"gzip\"},body:b});document.getElementById(\"out\").textContent=JSON.stringify(await r.json())})()</script>",
                200,
            ),
            "/api/gz" => match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(v) => send(200, "application/json", serde_json::json!({ "results": [{ "title": format!("{} video", v.get("query").and_then(|q| q.as_str()).unwrap_or("undefined")) }] }).to_string()),
                Err(_) => send(400, "application/json", "{\"error\":\"bad request body\"}".into()),
            },
            // Airbnb shape: a JSON API whose referer carries the search term (a templated header).
            "/api/find" => send(200, "application/json", serde_json::json!({ "results": [format!("{q} one"), format!("{q} two")] }).to_string()),
            // Booking.com shape: without the WAF cookie, a 202 interstitial that reloads with &chal_t=.
            "/hotels" => {
                if !cookie.contains("aws-waf-token=ok") {
                    send(202, "text/html", waf_page(&format!("{p}{search}&chal_t=1790531654141&force_referer=")))
                } else {
                    html(&[1, 2].iter().map(|n| format!("<div class=\"card\">{} hotel {n}</div>", esc(&q))).collect::<String>(), 200)
                }
            }
            // A site whose search is down for every query (200 "try again later" page, no results).
            "/status" => {
                if inner.down.load(Ordering::SeqCst) {
                    html("<p>Service temporarily unavailable. Please try again later.</p>", 200)
                } else if q.starts_with("zz") {
                    html("<p>No results.</p>", 200)
                } else {
                    html(&[1, 2].iter().map(|n| format!("<div class=\"item\">{} item {n}</div>", esc(&q))).collect::<String>(), 200)
                }
            }
            _ => (StatusCode::NOT_FOUND, [("content-type", "text/plain")], "not found").into_response(),
        }
    }

    impl LiveFixture {
        pub async fn start() -> LiveFixture {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let inner = Arc::new(Inner { hits: Mutex::new(vec![]), down: AtomicBool::new(false) });
            let app = axum::Router::new().fallback(handle).with_state(inner.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            LiveFixture { url: format!("http://127.0.0.1:{port}"), inner, task }
        }
        pub fn hits(&self) -> Vec<Hit> {
            self.inner.hits.lock().unwrap().clone()
        }
        pub fn clear_hits(&self) {
            self.inner.hits.lock().unwrap().clear();
        }
        pub fn set_down(&self, down: bool) {
            self.inner.down.store(down, Ordering::SeqCst);
        }
        pub fn close(&self) {
            self.task.abort();
        }
    }
}

/* ------------------------------------------------------------ harness */

static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
/// One home and one shared browser for the binary: the tests take turns, as node's do in one file.
static LOCK: Mutex<()> = Mutex::new(());
static HOME: LazyLock<Home> = LazyLock::new(Home::new);
static FX: tokio::sync::OnceCell<LiveFixture> = tokio::sync::OnceCell::const_new();

fn run<F: Future>(f: F) -> F::Output {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    LazyLock::force(&HOME);
    RT.block_on(f)
}

fn chrome() -> bool {
    if std::env::var("API_ANYTHING_CHROME").is_err() {
        let p = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
        if std::path::Path::new(p).exists() {
            unsafe { std::env::set_var("API_ANYTHING_CHROME", p) };
        }
    }
    let ok = api_anything::browser::chrome_available();
    if !ok {
        eprintln!("Google Chrome not installed: skipped");
    }
    ok
}

/// `before` + `beforeEach`: the fixture, with state.json and heals.jsonl gone, no hits, and the site up.
async fn fx() -> &'static LiveFixture {
    let fx = FX.get_or_init(LiveFixture::start).await;
    let _ = std::fs::remove_file(HOME.path().join("state.json"));
    let _ = std::fs::remove_file(HOME.path().join("heals.jsonl"));
    fx.clear_hits();
    fx.set_down(false);
    fx
}

fn fast() -> CallOptions {
    CallOptions { min_interval_ms: Some(0), ..Default::default() }
}

fn tier1() -> CallOptions {
    CallOptions { min_interval_ms: Some(0), max_tier: Some(1), ..Default::default() }
}

#[derive(serde::Deserialize)]
struct Heal {
    op: String,
    #[allow(dead_code)]
    strategy: String,
    #[allow(dead_code)]
    diff: String,
}

fn heals() -> Vec<Heal> {
    std::fs::read_to_string(HOME.path().join("heals.jsonl"))
        .map(|t| t.trim().lines().filter(|l| !l.is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect())
        .unwrap_or_default()
}

fn op_of(site: &str, name: &str) -> Operation {
    load_site(site).unwrap().unwrap().site.operations.into_iter().find(|o| o.name == name).unwrap()
}

fn set_min_tier(site: &str, name: &str, min_tier: u8) {
    let mut s: Site = load_site(site).unwrap().unwrap().site;
    for o in &mut s.operations {
        if o.name == name {
            o.min_tier = min_tier;
        }
    }
    save_site(&s).unwrap();
}

async fn forget_browser_and_jar(site: &str) {
    let _h = api_anything::browser::hold();
    let b = api_anything::browser::open_browser(&profile_dir(), true).await.unwrap();
    let p = b.new_page(None).await.unwrap();
    p.send("Network.clearBrowserCookies", json!({})).await.unwrap();
    let _ = p.close().await;
    save_session(site, &Session::empty()).unwrap();
}

fn trigger(url: &str) -> Trigger {
    Trigger { url: url.to_string(), steps: None, soft_from: None }
}

fn matcher(v: Value) -> Match {
    parse_match(&v).unwrap()
}

fn html_recipe(items: &str, fields: Value) -> Recipe {
    Recipe { html: Some(HtmlRecipe { items: items.to_string(), fields: serde_json::from_value(fields).unwrap() }), ..Default::default() }
}

fn add(site: &str, op: &str, trigger_url: &str, examples: Vec<Value>, matcher: Option<Match>, response: Option<Recipe>) -> AddInput {
    AddInput {
        site: site.into(),
        op: op.into(),
        trigger: Some(trigger(trigger_url)),
        examples: examples.into_iter().map(args).collect(),
        matcher,
        write: false,
        description: None,
        response,
        public: None,
        from: None,
        from2: None,
        fetcher: None,
    }
}

fn re(p: &str) -> regex::Regex {
    regex::Regex::new(p).unwrap()
}

fn path_of(url: &str) -> String {
    url::Url::parse(url).unwrap().path().to_string()
}

/* -------------------------------------------------- referer template with non-Latin-1 args */

const SITE: &str = "hdr";

/// The describe's `before`: an op whose referer carries the search term.
fn hdr_site(fx: &LiveFixture) {
    let learned = learn_operation(&LearnInput::new(
        exs(json!([{
            "id": 1,
            "resourceType": "fetch",
            "request": {
                "method": "GET",
                "url": format!("{}/api/find?q=kittens", fx.url),
                "headers": { "accept": "application/json", "referer": format!("{}/find/kittens", fx.url) },
            },
            "response": {
                "status": 200,
                "headers": { "content-type": "application/json" },
                "contentType": "application/json",
                "body": "{\"results\":[\"kittens one\",\"kittens two\"]}",
            },
        }])),
        vec![args(json!({ "q": "kittens" }))],
        "find",
        trigger(&format!("{}/find/{{q}}", fx.url)),
        true,
    ))
    .unwrap();
    save_site(&Site {
        name: SITE.into(),
        display_name: None,
        base_url: fx.url.clone(),
        description: None,
        login_cookies: None,
        operations: vec![learned.operation],
    })
    .unwrap();
}

#[test]
fn learning_makes_the_referer_a_templated_slot_precondition_passes_today() {
    run(async {
        let fx = fx().await;
        hdr_site(fx);
        let op = op_of(SITE, "find");
        let slot = op.slots.iter().find(|s| s.at[0] == "header:referer");
        assert_eq!(slot.and_then(|s| s.template.clone()), Some(format!("{}/find/{{q}}", fx.url)));
    });
}

#[test]
fn an_ascii_value_with_a_space_is_sent_and_answered_passes_today() {
    run(async {
        let fx = fx().await;
        hdr_site(fx);
        let r = call(SITE, "find", args(json!({ "q": "new york" })), tier1()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.data, Some(json!(["new york one", "new york two"])));
    });
}

#[test]
fn a_cjk_value_must_not_crash_tier_1_with_a_byte_string_error() {
    run(async {
        let fx = fx().await;
        hdr_site(fx);
        let r = call(SITE, "find", args(json!({ "q": "東京" })), tier1()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.data, Some(json!(["東京 one", "東京 two"])));
    });
}

#[test]
fn a_latin_1_value_sao_paulo_goes_into_the_referer_percent_encoded_as_a_browser_sends_it() {
    run(async {
        let fx = fx().await;
        hdr_site(fx);
        let r = call(SITE, "find", args(json!({ "q": "São Paulo" })), tier1()).await;
        assert!(r.ok, "{}", j(&r));
        let hit = fx.hits().into_iter().find(|h| h.path.starts_with("/api/find"));
        assert_eq!(hit.and_then(|h| h.raw_referer), Some(format!("{}/find/S%C3%A3o%20Paulo", fx.url)));
    });
}

/* ------------------------------------------------------------- classifier: bot walls */

fn wall_op(format: &str) -> Operation {
    parse_operation(&json!({
        "name": "search",
        "request": { "method": "GET", "url": "https://shop.example/s?k=kettle", "headers": {} },
        "slots": [{ "param": "k", "at": ["query:k"] }],
        "trigger": { "url": "https://shop.example/s?k={k}" },
        "match": { "method": "GET", "host": "shop.example", "path": "/s" },
        "response": if format == "html" { json!({ "format": format, "html": { "items": "div.result", "fields": { "t": "" } } }) } else { json!({ "format": format, "extract": "results" }) },
        "params": [{ "name": "k", "type": "string", "required": true, "example": "kettle" }],
        "readOnly": true,
    }))
    .unwrap()
}

fn observed(status: u16, content_type: &str, body: &str) -> Observed {
    let mut headers = Headers::new();
    headers.insert("content-type".into(), content_type.into());
    Observed { status, headers, body: body.to_string(), url: None }
}

#[test]
fn a_cloudflare_interstitial_is_blocked_passes_today() {
    let c = classify(&wall_op("html"), &observed(403, "text/html", "<html><title>Just a moment...</title></html>"));
    assert_eq!(c.class, Class::Blocked);
}

#[test]
fn booking_coms_aws_waf_interstitial_202_aws_waf_cookie_domain_list_challenge_js_is_blocked_not_drift() {
    let body = concat!(
        "<!DOCTYPE html><html lang=\"en\"><head><title></title><script>window.awsWafCookieDomainList = ['booking.com'];</script>",
        "<script src=\"https://www.booking.com/__challenge_h78IRKX3kpQxScCExxShBNwRUlb/d8c14d4960ca/a18a4859af9c/challenge.js\"></script></head><body></body></html>"
    );
    for f in ["html", "json"] {
        let c = classify(&wall_op(f), &observed(202, "text/html", body));
        assert_eq!(c.class, Class::Blocked, "{f}: {:?}", c);
    }
}

#[test]
fn amazons_automated_access_wall_503_is_blocked_not_error() {
    let body = "<!-- To discuss automated access to Amazon data please contact api-services-support@amazon.com. For information about migrating to our APIs refer to our Marketplace APIs --><!doctype html><html><head><title>Sorry! Something went wrong!</title></head><body></body></html>";
    let c = classify(&wall_op("html"), &observed(503, "text/html", body));
    assert_eq!(c.class, Class::Blocked, "{c:?}");
}

#[test]
fn reddits_200_js_proof_of_work_page_auto_submitted_solution_form_js_challenge_is_blocked_not_drift() {
    let body = concat!(
        "<!DOCTYPE html><html lang=\"en\"><head><title>Reddit</title><script>document.addEventListener(\"DOMContentLoaded\",async function(){var e=document.forms[0],n=(e.onsubmit=function(t){return!0},await(async e=>e+e)(\"8e41418a7cbe71e1\"));e.elements.namedItem(\"solution\").value=n,e.requestSubmit()},{once:!0});</script></head>",
        "<body><main><form method=\"get\"><input type=\"hidden\" name=\"js_challenge\" value=\"1\"><input type=\"hidden\" name=\"solution\"></form></main></body></html>"
    );
    let c = classify(&wall_op("html"), &observed(200, "text/html", body));
    assert_eq!(c.class, Class::Blocked, "{c:?}");
}

#[test]
fn a_large_64_kb_reddit_prove_your_humanity_recaptcha_page_on_an_html_op_is_blocked() {
    let body = format!(
        "<!doctype html><html><head><title>Reddit - Prove your humanity</title></head><body>{}<div class=\"g-recaptcha\"></div></body></html>",
        "<div>x</div>".repeat(8000)
    );
    assert!(body.len() > 64_000);
    let c = classify(&wall_op("html"), &observed(200, "text/html", &body));
    assert_eq!(c.class, Class::Blocked, "{c:?}");
}

/* ------------------------------------------------------------------ capOutput */

#[test]
fn inspect_call_output_whose_first_item_alone_exceeds_the_cap_is_not_returned_empty() {
    let big = json!([{ "blob": "x".repeat(25_000) }, { "blob": "y" }]);
    let r = cap_output(&big, 20_000);
    assert!(r.data.is_array());
    assert!(r.data.as_array().map(|a| !a.is_empty()).unwrap_or(false), "data is empty: {:?}", r.truncated);
}

/* ------------------------------------------------------------------ Chrome probes */

#[test]
fn add_with_html_learns_the_html_document_not_a_json_telemetry_beacon_that_echoes_the_page_url() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = add_operation(add(
            "shop",
            "search",
            &format!("{}/shop?q={{q}}", fx.url),
            vec![json!({ "q": "kettle" }), json!({ "q": "toaster" })],
            None,
            Some(html_recipe("li.r", json!({ "title": "" }))),
        ))
        .await
        .unwrap();
        assert_eq!(path_of(&r.operation.request.url), "/shop", "learned {} {}", r.operation.request.method, r.operation.request.url);
        assert_eq!(r.operation.request.method, "GET");
        let c = call("shop", "search", args(json!({ "q": "blender" })), fast()).await;
        assert!(c.ok, "{}", j(&c));
        assert_eq!(c.data, Some(json!([{ "title": "blender result 1" }, { "title": "blender result 2" }])));
    });
}

#[test]
fn add_from_with_the_document_pinned_learns_an_html_op_that_answers_new_args_passes_today() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = add_operation(add(
            "shop2",
            "search",
            &format!("{}/shop?q={{q}}", fx.url),
            vec![json!({ "q": "kettle" }), json!({ "q": "toaster" })],
            Some(matcher(json!({ "method": "GET", "path": "/shop" }))),
            Some(html_recipe("li.r", json!({ "title": "" }))),
        ))
        .await
        .unwrap();
        assert_eq!(path_of(&r.operation.request.url), "/shop");
        let c = call("shop2", "search", args(json!({ "q": "blender" })), fast()).await;
        assert!(c.ok, "{}", j(&c));
        assert_eq!(c.tier, Some(1));
    });
}

#[test]
fn a_gzip_compressed_request_body_youtube_innertube_content_encoding_gzip_is_learned_as_a_tier_1_body_slot() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = add_operation(add(
            "gz",
            "search",
            &format!("{}/gz?q={{q}}", fx.url),
            vec![json!({ "q": "kittens" }), json!({ "q": "puppies" })],
            Some(matcher(json!({ "method": "POST", "path": "/api/gz" }))),
            None,
        ))
        .await
        .unwrap();
        // Today: the body is captured as lossy UTF-8, q is found only in the referer, and the changing
        // gzip bytes read as a nonce, so minTier 3 (a browser run per call). With a trigger whose URL
        // lacks q (YouTube's search box), add fails outright.
        assert!(r.operation.slots.iter().any(|s| s.param.as_deref() == Some("q") && s.at[0] == "body"), "{}", j(&r.operation.slots));
        assert_eq!(r.operation.min_tier, 1, "{}", r.warnings.join("\n"));
        let c = call("gz", "search", args(json!({ "q": "otters" })), fast()).await;
        assert!(c.ok, "{}", j(&c));
        assert_eq!(c.tier, Some(1));
        assert_eq!(c.data, Some(json!([{ "title": "otters video" }])));
    });
}

#[test]
fn a_param_found_only_in_the_referer_never_yields_an_op_that_returns_the_examples_data_for_new_args() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let learned = match add_operation(add(
            "b64",
            "search",
            &format!("{}/b64?q={{q}}", fx.url),
            vec![json!({ "q": "kittens" })],
            Some(matcher(json!({ "method": "POST", "path": "/api/b64" }))),
            None,
        ))
        .await
        {
            Ok(_) => true,
            Err(e) => {
                // the correct outcome: "example value ... is not in the learned request"
                assert!(re("not in the learned request").is_match(&e.to_string()), "{e}");
                false
            }
        };
        if learned {
            let c = call("b64", "search", args(json!({ "q": "otters" })), fast()).await;
            // Today: ok:true, tier 1, data [{title:"kittens result"}] -- the example's data, silently.
            assert!(!c.data.clone().unwrap_or(Value::Null).to_string().contains("kittens"), "silent wrong data: {}", j(&c));
        }
    });
}

#[test]
fn at_tier_3_the_challenge_interstitial_that_precedes_the_real_page_is_not_taken_as_the_answer_booking_com() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        add_operation(add(
            "hotels",
            "search",
            &format!("{}/hotels?q={{q}}", fx.url),
            vec![json!({ "q": "Lisbon" }), json!({ "q": "Porto" })],
            Some(matcher(json!({ "method": "GET", "path": "/hotels" }))),
            Some(html_recipe("div.card", json!({ "name": "" }))),
        ))
        .await
        .unwrap();
        set_min_tier("hotels", "search", 3);
        forget_browser_and_jar("hotels").await;
        let r = call("hotels", "search", args(json!({ "q": "Madrid" })), fast()).await;
        // Today: class "input" ("the thing probably does not exist") for a perfectly valid city.
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.data, Some(json!([{ "name": "Madrid hotel 1" }, { "name": "Madrid hotel 2" }])));
    });
}

#[test]
fn a_waf_interstitial_at_tier_1_is_not_drift_no_heal_is_logged_and_challenge_params_are_not_baked_into_the_template() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        // The TypeScript suite runs this after the tier-3 test, whose Madrid run left the WAF cookie in
        // the profile, so the add below learns from the real page; cargo orders tests by name, so that
        // precondition is put back here.
        api_anything::browser::add_cookies_to_profile(
            &[api_anything::types::StoredCookie::new("aws-waf-token", "ok", "127.0.0.1")],
            &profile_dir(),
        )
        .await
        .unwrap();
        add_operation(add(
            "hotels2",
            "search",
            &format!("{}/hotels?q={{q}}", fx.url),
            vec![json!({ "q": "Lisbon" }), json!({ "q": "Porto" })],
            Some(matcher(json!({ "method": "GET", "path": "/hotels" }))),
            Some(html_recipe("div.card", json!({ "name": "" }))),
        ))
        .await
        .unwrap();
        forget_browser_and_jar("hotels2").await;
        let r = call("hotels2", "search", args(json!({ "q": "Madrid" })), fast()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(heals().iter().filter(|h| h.op == "search").count(), 0, "a bot challenge is not drift");
        assert!(!op_of("hotels2", "search").request.url.contains("chal_t"), "{}", op_of("hotels2", "search").request.url);
    });
}

#[test]
fn when_even_the_example_args_get_no_data_the_verdict_is_not_input_the_site_is_down_not_the_args() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        add_operation(add(
            "status",
            "search",
            &format!("{}/status?q={{q}}", fx.url),
            vec![json!({ "q": "alpha" }), json!({ "q": "bravo" })],
            Some(matcher(json!({ "method": "GET", "path": "/status" }))),
            Some(html_recipe("div.item", json!({ "name": "" }))),
        ))
        .await
        .unwrap();
        fx.set_down(true);
        let with_example = call("status", "search", args(json!({ "q": "alpha" })), fast()).await;
        assert_ne!(with_example.class, Class::Input, "the op's own example args got: {}", j(&with_example));
        let with_new = call("status", "search", args(json!({ "q": "charlie" })), fast()).await;
        assert_ne!(with_new.class, Class::Input, "examples fail too, so the args are not the problem: {}", j(&with_new));
    });
}

#[test]
fn a_no_results_query_while_the_example_still_answers_is_input_passes_today() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        fx.set_down(false);
        add_operation(add(
            "status2",
            "search",
            &format!("{}/status?q={{q}}", fx.url),
            vec![json!({ "q": "alpha" }), json!({ "q": "bravo" })],
            Some(matcher(json!({ "method": "GET", "path": "/status" }))),
            Some(html_recipe("div.item", json!({ "name": "" }))),
        ))
        .await
        .unwrap();
        let ok = call("status2", "search", args(json!({ "q": "delta" })), fast()).await;
        assert!(ok.ok, "{}", j(&ok));
        let none = call("status2", "search", args(json!({ "q": "zzqxv" })), fast()).await;
        assert_eq!(none.class, Class::Input, "{}", j(&none));
        assert_eq!(heals().len(), 0);
    });
}
