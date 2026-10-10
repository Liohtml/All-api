//! test/edge/live-b.test.ts: deterministic repros of what live real-site creation (IMDb, GitHub,
//! eBay, Yelp, Zillow, Kayak, Skyscanner, Craigslist, Wikipedia) exposed. Bodies and request shapes
//! are trimmed copies of what those sites served on 2026-09-27. The one Chrome probe skips without Chrome.
mod common;
use api_anything::classify::{Class, Observed, classify};
use api_anything::execute::{CallOptions, call};
use api_anything::heal::{AddInput, CaptureFile, CapturePageOptions, FromCapture, Recipe, add_operation, capture_page};
use api_anything::learn::{LearnInput, RankOptions, learn_operation, rank_candidates};
use api_anything::spec::{Embedded, Format, HtmlRecipe, Operation, Trigger};
use api_anything::types::{CaptureResult, Exchange, Headers};
use common::{Home, args, j};
use etag::Fixture;
use serde_json::{Value, json};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/* ------------------------------------------------------------ the fixture */

/// Port of test/edge/live-b.fixture.ts: /s?q=<q> is a server-rendered search page with a stable,
/// content-derived ETag that answers 304 to a matching If-None-Match (GitHub's logged-out pages do
/// exactly this).
mod etag {
    #![allow(dead_code)]
    use axum::body::Body;
    use axum::extract::{Request, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct Inner {
        /// If-None-Match values the server received, in order
        conditional: Mutex<Vec<String>>,
    }

    pub struct Fixture {
        pub url: String,
        inner: Arc<Inner>,
        task: tokio::task::JoinHandle<()>,
    }

    async fn handle(State(inner): State<Arc<Inner>>, req: Request) -> Response {
        if req.uri().path() == "/s" {
            let query: HashMap<String, String> = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
            let q = query.get("q").cloned().unwrap_or_default();
            let etag = format!("W/\"v1-{}\"", q.bytes().map(|b| format!("{b:02x}")).collect::<String>());
            let inm = req.headers().get("if-none-match").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            if let Some(inm) = &inm {
                inner.conditional.lock().unwrap().push(inm.clone());
            }
            if inm.as_deref() == Some(etag.as_str()) {
                return Response::builder().status(304).header("etag", etag).header("cache-control", "no-cache").body(Body::empty()).unwrap();
            }
            return Response::builder()
                .status(200)
                .header("content-type", "text/html; charset=utf-8")
                .header("etag", etag)
                .header("cache-control", "no-cache")
                .body(Body::from(format!(
                    "<!doctype html><html><body><ul><li class=\"r\"><a href=\"/x/{q}\">result for {q}</a></li><li class=\"r\"><a href=\"/y/{q}\">more {q}</a></li></ul></body></html>"
                )))
                .unwrap();
        }
        (StatusCode::NOT_FOUND, [("content-type", "text/plain")], "not found").into_response()
    }

    impl Fixture {
        pub async fn start() -> Fixture {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let inner = Arc::new(Inner { conditional: Mutex::new(vec![]) });
            let app = axum::Router::new().fallback(handle).with_state(inner.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Fixture { url: format!("http://127.0.0.1:{port}"), inner, task }
        }
        pub fn conditional(&self) -> Vec<String> {
            self.inner.conditional.lock().unwrap().clone()
        }
        pub fn close(&self) {
            self.task.abort();
        }
    }
}

/* ------------------------------------------------------------ harness */

static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
static LOCK: Mutex<()> = Mutex::new(());
static HOME: LazyLock<Home> = LazyLock::new(Home::new);

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

const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36";
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct ExSpec<'a> {
    url: &'a str,
    method: Option<&'a str>,
    kind: Option<&'a str>,
    req_headers: Option<Value>,
    req_body: Option<&'a str>,
    status: Option<u16>,
    kind_type: Option<&'a str>,
    body: Option<String>,
    headers: Option<Value>,
}

fn ex(o: ExSpec) -> Exchange {
    let kind_type = o.kind_type.unwrap_or("application/json");
    let mut req_headers = json!({ "user-agent": UA, "accept": "*/*" });
    if let Some(Value::Object(extra)) = o.req_headers {
        for (k, v) in extra {
            req_headers[k] = v;
        }
    }
    let mut res_headers = json!({ "content-type": kind_type });
    if let Some(Value::Object(extra)) = o.headers {
        for (k, v) in extra {
            res_headers[k] = v;
        }
    }
    let mut request = json!({ "method": o.method.unwrap_or("GET"), "url": o.url, "headers": req_headers });
    if let Some(b) = o.req_body {
        request["body"] = json!(b);
    }
    common::ex(json!({
        "id": NEXT_ID.fetch_add(1, Ordering::SeqCst),
        "resourceType": o.kind.unwrap_or("document"),
        "request": request,
        "response": { "status": o.status.unwrap_or(200), "headers": res_headers, "body": o.body.unwrap_or_default(), "contentType": kind_type },
    }))
}

fn capture(url: &str, exchanges: Vec<Exchange>) -> CaptureFile {
    CaptureFile {
        id: format!("c-live-b-{}", NEXT_ID.fetch_add(1, Ordering::SeqCst)),
        at: api_anything::util::iso_now(),
        url: url.to_string(),
        steps: None,
        soft_from: None,
        write: false,
        result: CaptureResult { exchanges, cookies: vec![], final_url: url.to_string(), storage: None, locations: None },
    }
}

fn html_doc(url: &str, body: &str, status: u16, req_headers: Option<Value>) -> Exchange {
    ex(ExSpec { url, kind_type: Some("text/html; charset=utf-8"), body: Some(body.to_string()), status: Some(status), req_headers, ..Default::default() })
}

fn trigger(url: &str) -> Trigger {
    Trigger { url: url.to_string(), steps: None, soft_from: None }
}

fn html_recipe(items: &str, fields: Value) -> HtmlRecipe {
    HtmlRecipe { items: items.to_string(), fields: serde_json::from_value(fields).unwrap() }
}

fn html_op(url: &str, a: Value, items: &str) -> Operation {
    let values: Vec<String> = a.as_object().unwrap().values().map(|v| v.as_str().unwrap_or("").to_string()).collect();
    let mut op = learn_operation(&LearnInput::new(vec![html_doc(url, &format!("<ul><li class=\"r\">{}</li></ul>", values.join(" ")), 200, None)], vec![args(a)], "page", trigger(url), true)).unwrap().operation;
    op.response.format = Format::Html;
    op.response.html = Some(html_recipe(items, json!({ "t": "" })));
    op
}

fn observed(status: u16, content_type: &str, body: &str) -> Observed {
    let mut headers = Headers::new();
    headers.insert("content-type".into(), content_type.into());
    Observed { status, headers, body: body.to_string(), url: None }
}

fn from_capture(site: &str, op: &str, examples: Vec<Value>, response: Recipe, c: CaptureFile) -> AddInput {
    AddInput { site: site.into(), op: op.into(), trigger: None, examples: examples.into_iter().map(args).collect(), matcher: None, write: false, description: None, response: Some(response), public: None, from: Some(FromCapture { capture: c, id: None }), from2: None, fetcher: None }
}

fn re(p: &str) -> regex::Regex {
    regex::Regex::new(p).unwrap()
}

/* ------------------------------------------------------------- bot walls */

// IMDb (AWS WAF, 2026-09-27): first a 202 JS challenge, then a 405 "Human Verification" CAPTCHA.
const AWS_WAF_202: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title></title>
<script type="text/javascript">window.awsWafCookieDomainList = ['imdb.com']; window.gokuProps = {"key":"AQIDAH","iv":"CgAFeDJ3","context":"Qut7eVe"};</script>
<script src="https://fb423e1ef94f.6277d64d.us-east-1.token.awswaf.com/fb423e1ef94f/c3382d439950/916d943f6a58/challenge.js"></script>
</head><body><div id="challenge-container"></div>
<script type="text/javascript">AwsWafIntegration.saveReferrer(); AwsWafIntegration.getToken().then(() => { window.location.reload(true); });</script>
<noscript><h1>JavaScript is disabled</h1>In order to continue, we need to verify that you're not a robot. This requires JavaScript. Enable JavaScript and then reload the page.</noscript>
</body></html>"#;
const AWS_WAF_405: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Human Verification</title>
<script type="text/javascript">window.awsWafCookieDomainList = ['imdb.com']; window.gokuProps = {"key":"AQIDAH","iv":"CgAGhDLu","context":"x24rUs"};</script>
<script src="https://fb423e1ef94f.6277d64d.us-east-1.token.awswaf.com/fb423e1ef94f/c3382d439950/916d943f6a58/challenge.js"></script>
<script src="https://fb423e1ef94f.6277d64d.us-east-1.captcha.awswaf.com/fb423e1ef94f/c3382d439950/916d943f6a58/captcha.js"></script>
</head><body><div id="captcha-container"></div>
<noscript><h1>JavaScript is disabled</h1>In order to continue, you need to verify that you're not a robot by solving a CAPTCHA puzzle.</noscript>
</body></html>"#;
const DATADOME_403: &str = r#"<html lang="en"><head><title>yelp.com</title><style>#cmsg{animation: A 1.5s;}</style></head><body style="margin:0"><p id="cmsg">Please enable JS and disable any ad blocker</p><script data-cfasync="false">var dd={'rt':'c','cid':'AHrlqAAAAAMA','hsh':'3BD2468B','t':'bv','s':45183,'e':'x','host':'geo.captcha-delivery.com','cookie':'x'}</script><script data-cfasync="false" src="https://ct.captcha-delivery.com/c.js"></script></body></html>"#;
const PERIMETERX_403: &str = r#"<!DOCTYPE html><html lang="en"><head><title>Access to this page has been denied</title></head><body><div id="px-captcha"></div><script>window._pxAppId = 'PXHYx10rg3';</script><p>Press &amp; Hold to confirm you are a human (and not a bot).</p></body></html>"#;

fn title_op() -> Operation {
    html_op("https://www.imdb.com/title/tt1375666/", json!({ "id": "tt1375666" }), "h1")
}

#[test]
fn aws_waf_405_human_verification_captcha_page_imdb_is_blocked_not_error() {
    let c = classify(&title_op(), &observed(405, "text/html; charset=UTF-8", AWS_WAF_405));
    assert_eq!(c.class, Class::Blocked, "{}", c.reason);
}

#[test]
fn aws_waf_202_js_challenge_page_imdb_is_blocked_not_drift() {
    let c = classify(&title_op(), &observed(202, "text/html; charset=UTF-8", AWS_WAF_202));
    assert_eq!(c.class, Class::Blocked, "{}", c.reason);
}

#[test]
fn regression_data_dome_403_yelp_and_perimeter_x_403_zillow_skyscanner_are_blocked() {
    let title = title_op();
    assert_eq!(classify(&title, &observed(403, "text/html", DATADOME_403)).class, Class::Blocked);
    assert_eq!(classify(&title, &observed(403, "text/html", PERIMETERX_403)).class, Class::Blocked);
}

#[test]
fn add_on_a_page_that_served_a_bot_challenge_does_not_tell_the_agent_to_fix_its_recipe() {
    run(async {
        let url = "https://www.yelp.com/search?find_desc=pizza&find_loc=SF";
        let r = add_operation(from_capture(
            "yelp-edge",
            "search",
            vec![json!({ "q": "pizza" })],
            Recipe { html: Some(html_recipe("[data-testid=serp-ia-card]", json!({ "name": "h3 a" }))), ..Default::default() },
            capture(url, vec![html_doc(url, DATADOME_403, 403, None)]),
        ))
        .await
        .unwrap();
        let w = r.warnings.iter().find(|x| re("blocked").is_match(x)).unwrap_or_else(|| panic!("a blocked warning: {}", r.warnings.join(" | ")));
        assert!(!re("Fix --extract").is_match(w), "a bot wall is not fixed by editing --extract/--html");
        assert!(re("login").is_match(w), "points at api-anything login to clear the challenge");
    });
}

/* --------------------------------------------------------------- picking */

#[test]
fn a_document_whose_url_ends_in_js_github_com_mrdoob_three_js_is_a_candidate_not_an_asset() {
    let doc = html_doc("https://github.com/mrdoob/three.js", "<html><body><strong itemprop=name><a>three.js</a></strong></body></html>", 200, None);
    let ranked = rank_candidates(std::slice::from_ref(&doc), &args(json!({ "owner": "mrdoob", "repo": "three.js" })), RankOptions::default());
    assert_eq!(ranked.iter().map(|c| c.id).collect::<Vec<_>>(), vec![doc.id]);
}

#[test]
fn add_from_with_repo_next_js_learns_the_document() {
    run(async {
        let url = "https://github.com/vercel/next.js";
        let r = add_operation(from_capture(
            "gh-edge",
            "repo",
            vec![json!({ "owner": "vercel", "repo": "next.js" })],
            Recipe { html: Some(html_recipe("#hdr", json!({ "name": "a" }))), ..Default::default() },
            capture(url, vec![html_doc(url, "<div id=\"hdr\"><a>next.js</a></div>", 200, None)]),
        ))
        .await
        .unwrap();
        assert_eq!(r.operation.request.url, url);
    });
}

#[test]
fn regression_a_plain_document_path_still_ranks() {
    let doc = html_doc("https://github.com/microsoft/playwright", "<html>playwright</html>", 200, None);
    assert_eq!(rank_candidates(std::slice::from_ref(&doc), &args(json!({ "repo": "playwright" })), RankOptions::default()).first().map(|c| c.id), Some(doc.id));
}

#[test]
fn with_embedded_add_picks_the_document_the_recipe_resolves_on_not_a_post_whose_multipart_body_merely_contains_the_value_as_a_substring_github_search() {
    run(async {
        let url = "https://github.com/search?q=playwright&type=repositories";
        let results = json!({ "payload": { "blackbirdSearchRoute": { "results": [{ "hl_name": "microsoft/<em>playwright</em>", "followers": 96753 }] } } });
        let doc = html_doc(url, &format!("<html><body><script type=\"application/json\" data-target=\"react-app.embeddedData\">{results}</script></body></html>"), 200, None);
        let b = "----WebKitFormBoundaryeZEwOAxK1zXOg1LT";
        let sponsor = ex(ExSpec {
            url: "https://github.com/sponsors/batch_deferred_sponsor_buttons",
            method: Some("POST"),
            kind: Some("fetch"),
            req_headers: Some(json!({ "content-type": format!("multipart/form-data; boundary={b}"), "referer": url })),
            req_body: Some(&format!("--{b}\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nGET\r\n--{b}\r\nContent-Disposition: form-data; name=\"items[item-85809106][repo_name]\"\r\n\r\ninvisible_playwright_mcp\r\n--{b}--\r\n")),
            body: Some(json!({ "item-85809106": "<button>Sponsor</button>".repeat(200) }).to_string()),
            ..Default::default()
        });
        let r = add_operation(from_capture(
            "gh-edge",
            "search",
            vec![json!({ "q": "playwright" })],
            Recipe { embedded: Some(Embedded { regex: "data-target=\"react-app.embeddedData\">(\\{)".into() }), extract: Some("payload.blackbirdSearchRoute.results".into()), ..Default::default() },
            capture(url, vec![doc, sponsor]),
        ))
        .await
        .unwrap();
        assert_eq!(r.operation.request.method, "GET", "{}", r.warnings.join(" | "));
        assert_eq!(r.operation.request.url, url);
        assert!(r.preview.is_some(), "preview resolves: {}", r.warnings.join(" | "));
    });
}

/* ----------------------------------------------------------- conditional */

#[test]
fn if_none_match_if_modified_since_from_a_revalidating_browser_are_not_stored_in_the_template() {
    let url = "https://github.com/search?q=playwright&type=repositories";
    let op = learn_operation(&LearnInput::new(
        vec![html_doc(url, "<ul><li class=r>playwright</li></ul>", 200, Some(json!({ "if-none-match": "W/\"25f941cd5c0f1f789be9542912883d9d\"", "if-modified-since": "Sat, 26 Sep 2026 10:00:00 GMT" })))],
        vec![args(json!({ "q": "playwright" }))],
        "search",
        trigger("https://github.com/search?q={q}&type=repositories"),
        true,
    ))
    .unwrap()
    .operation;
    assert_eq!(op.request.headers.get("if-none-match"), None);
    assert_eq!(op.request.headers.get("if-modified-since"), None);
}

#[test]
fn verify_the_example_args_still_answers_ok_at_tier_1() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = Fixture::start().await;
        capture_page(CapturePageOptions { url: format!("{}/s?q=alpha", fx.url), steps: None, soft_from: None, write: false, args: None }).await.unwrap();
        let r = add_operation(AddInput {
            site: "etag".into(),
            op: "search".into(),
            trigger: Some(trigger(&format!("{}/s?q={{q}}", fx.url))),
            examples: vec![args(json!({ "q": "alpha" })), args(json!({ "q": "bravo" }))],
            matcher: None,
            write: false,
            description: None,
            response: Some(Recipe { html: Some(html_recipe("li.r", json!({ "t": "a" }))), ..Default::default() }),
            public: None,
            from: None,
            from2: None,
            fetcher: None,
        })
        .await
        .unwrap();
        let res = call("etag", "search", args(json!({ "q": "alpha" })), CallOptions { min_interval_ms: Some(0), max_tier: Some(1), ..Default::default() }).await;
        assert!(res.ok, "{}; stored if-none-match={:?}; server saw {:?}", j(&res), r.operation.request.headers.get("if-none-match"), fx.conditional());
        api_anything::browser::close_browser().await;
        fx.close();
    });
}

/* ------------------------------------------------------------ drift shape */

// Normalized responses key entities by id (Kayak's legs/segments/airports, X's globalObjects).
fn learn_from(body: Value) -> Operation {
    learn_operation(&LearnInput::new(
        vec![ex(ExSpec { url: "https://api.example.com/search?q=sfo", kind: Some("fetch"), body: Some(body.to_string()), ..Default::default() })],
        vec![args(json!({ "q": "sfo" }))],
        "search",
        trigger("https://example.com/s/{q}"),
        true,
    ))
    .unwrap()
    .operation
}

fn entity(code: &str) -> Value {
    json!({ "code": code, "name": format!("{code} airport"), "city": "x", "lat": 1, "lng": 2, "tz": "z" })
}

#[test]
fn an_id_keyed_entity_map_with_different_ids_for_new_args_is_not_a_shape_change() {
    let op = learn_from(json!({
        "results": [{ "id": "r1", "from": "SFO", "to": "JFK" }],
        "airports": { "SFO": entity("SFO"), "JFK": entity("JFK") },
    }));
    let c = classify(
        &op,
        &observed(
            200,
            "application/json",
            &json!({
                "results": [{ "id": "r9", "from": "BOS", "to": "SEA" }],
                "airports": { "BOS": entity("BOS"), "SEA": entity("SEA") },
            })
            .to_string(),
        ),
    );
    assert_eq!(c.class, Class::Ok, "{}", c.reason);
}

#[test]
fn regression_a_real_shape_change_the_data_moved_is_still_drift() {
    let op = learn_from(json!({ "results": [{ "id": "r1", "from": "SFO", "to": "JFK", "price": 1, "carrier": "UA" }] }));
    let c = classify(&op, &observed(200, "application/json", &json!({ "data": { "items": [{ "a": 1 }] } }).to_string()));
    assert_eq!(c.class, Class::Drift);
}

/* -------------------------------------------------------------- 400 input */

#[test]
fn a_400_that_names_no_param_is_error_even_when_a_slot_ends_in_an_array_index_json_legs_0() {
    let op = learn_operation(&LearnInput::new(
        vec![ex(ExSpec {
            url: "https://www.kayak.com/i/api/search/dynamic/flights/poll",
            method: Some("POST"),
            kind: Some("fetch"),
            req_headers: Some(json!({ "content-type": "application/json" })),
            req_body: Some(&json!({ "legs": [{ "origin": { "airports": ["SFO"] } }] }).to_string()),
            body: Some(json!({ "results": [{ "from": "SFO" }] }).to_string()),
            ..Default::default()
        })],
        vec![args(json!({ "origin": "SFO" }))],
        "flights",
        trigger("https://www.kayak.com/flights/{origin}-JFK"),
        true,
    ))
    .unwrap()
    .operation;
    assert_eq!(op.slots.iter().find(|s| s.param.is_some()).map(|s| s.at.clone()), Some(vec!["body".to_string(), "json:/legs/0/origin/airports/0".to_string()]));
    let c = classify(&op, &observed(400, "application/json", &json!({ "error": "upstream failure", "retry": 0 }).to_string()));
    assert_eq!(c.class, Class::Error, "{}", c.reason);
}

#[test]
fn regression_wikipedia_style_404_on_a_templated_path_is_input() {
    let op = html_op("https://en.wikipedia.org/wiki/Platypus", json!({ "title": "Platypus" }), "#content");
    assert_eq!(classify(&op, &observed(404, "text/html", "<html>Wikipedia does not have an article with this exact name.</html>")).class, Class::Input);
}
