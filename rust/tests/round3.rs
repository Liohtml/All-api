//! Port of test/edge/round3.test.ts. Round-3 regressions: challenge verify POSTs under a read's
//! guard, SPA locations and beacon acks, server-issued credentials, echo evidence on an explicit
//! pick, tier-2 navigation retries, zero results on HTML recipes, encoded cookies in param
//! templates, embedded IPs, soft challenge titles, disguised GET writes, and the agent surface (MCP
//! next hints, site notes, inspect, param patterns).
mod common;
use api_anything::browser::{PageFetchOptions, TriggerOptions, close_browser, page_fetch, run_trigger};
use api_anything::classify::{Observed, classify};
use api_anything::execute::{CallOptions, call};
use api_anything::heal::{AddInput, CapturePageOptions, add_operation, capture_page, profile_dir, run_op_trigger};
use api_anything::http::{Fetcher, HttpRequest, HttpResponse, build_request};
use api_anything::learn::{LearnInput, Learned, learn_operation};
use api_anything::mcp::{Server, mcp_next};
use api_anything::session::Session;
use api_anything::spec::{Operation, Trigger, parse_site};
use api_anything::store::{export_site, load_site, save_site};
use api_anything::types::{Exchange, Headers, StoredCookie};
use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use common::{Home, args, j, no_session};
use futures_util::future::BoxFuture;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

/// One runtime for the whole binary, like node's one event loop: the shared Chrome belongs to the
/// runtime that launched it, so every test runs on this one.
static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
/// API_ANYTHING_HOME is one variable for the process: the tests that set it take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn chrome() -> bool {
    if std::env::var("API_ANYTHING_CHROME").is_err() {
        let p = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
        if std::path::Path::new(p).exists() {
            unsafe { std::env::set_var("API_ANYTHING_CHROME", p) };
        }
    }
    api_anything::browser::chrome_available()
}

fn skip() {
    eprintln!("Google Chrome not installed: skipped");
}

/// `newHome()`: a fresh home with its `sites` dir, set for the process.
fn new_home() -> Home {
    let h = Home::new();
    std::fs::create_dir_all(h.path().join("sites")).unwrap();
    h
}

fn re(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_BODY: &str = r#"{"results":[{"id":1},{"id":2}]}"#;

fn ex_full(kind: &str, req: Value, body: &str, content_type: &str, res_headers: Value) -> Exchange {
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let mut request = json!({ "method": "GET", "headers": {} });
    for (k, v) in req.as_object().unwrap() {
        request[k] = v.clone();
    }
    common::ex(
        json!({ "id": id, "resourceType": kind, "request": request, "response": { "status": 200, "headers": res_headers, "contentType": content_type, "body": body } }),
    )
}

fn ex(kind: &str, req: Value, body: &str, content_type: &str) -> Exchange {
    ex_full(kind, req, body, content_type, json!({}))
}

fn exj(kind: &str, req: Value, body: &str) -> Exchange {
    ex(kind, req, body, "application/json")
}

fn exd(kind: &str, req: Value) -> Exchange {
    exj(kind, req, DEFAULT_BODY)
}

fn learn_with(exchanges: Vec<Exchange>, examples: Vec<Value>, extra: impl FnOnce(&mut LearnInput)) -> anyhow::Result<Learned> {
    let mut input = LearnInput::new(
        exchanges,
        examples.into_iter().map(args).collect(),
        "op",
        Trigger { url: "https://site.test/".into(), steps: None, soft_from: None },
        true,
    );
    extra(&mut input);
    learn_operation(&input)
}

fn learn(exchanges: Vec<Exchange>, examples: Vec<Value>) -> anyhow::Result<Learned> {
    learn_with(exchanges, examples, |_| {})
}

/* ----------------------------------------------------------- a local server */

#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: String,
}

impl Req {
    fn param(&self, k: &str) -> Option<&str> {
        self.query.get(k).map(|s| s.as_str())
    }
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Resp {
    Resp { status, headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), body: body.to_string() }
}

fn html(body: &str) -> Resp {
    resp(
        200,
        &[("content-type", "text/html; charset=utf-8")],
        &format!("<!doctype html><html><head><title>t</title></head><body>{body}</body></html>"),
    )
}

type Handler = Arc<dyn Fn(Req) -> BoxFuture<'static, Resp> + Send + Sync>;

fn sync_handler<F: Fn(Req) -> Resp + Send + Sync + 'static>(f: F) -> Handler {
    Arc::new(move |r| {
        let out = f(r);
        Box::pin(async move { out })
    })
}

struct Served {
    base: String,
    task: tokio::task::JoinHandle<()>,
}

impl Served {
    fn close(&self) {
        self.task.abort();
    }
}

/// `listen(handler, host)`: a server on an ephemeral port, its base URL naming `host`.
async fn listen(h: Handler, host: &str) -> Served {
    let app = axum::Router::new().fallback(move |req: Request<Body>| {
        let h = h.clone();
        async move {
            let method = req.method().to_string();
            let uri = req.uri().clone();
            let headers: HashMap<String, String> =
                req.headers().iter().map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string())).collect();
            let body = axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await.unwrap_or_default();
            let query: HashMap<String, String> =
                url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
            let r =
                h(Req { method, path: uri.path().to_string(), query, headers, body: String::from_utf8_lossy(&body).into_owned() }).await;
            let mut b = Response::builder().status(r.status);
            for (k, v) in &r.headers {
                b = b.header(k.as_str(), v.as_str());
            }
            b.body(Body::from(r.body)).unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Served { base: format!("http://{host}:{port}"), task }
}

/// A fetcher answering from a closure, counting its calls (the TS `fetchImpl`).
struct Answering {
    n: AtomicUsize,
    f: Box<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>,
}

impl Answering {
    fn new(f: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static) -> Arc<Answering> {
        Arc::new(Answering { n: AtomicUsize::new(0), f: Box::new(f) })
    }
    fn count(&self) -> usize {
        self.n.load(Ordering::SeqCst)
    }
}

impl Fetcher for Answering {
    fn fetch(&self, req: HttpRequest, _timeout: Duration) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        self.n.fetch_add(1, Ordering::SeqCst);
        let r = (self.f)(&req);
        Box::pin(async move { Ok(r) })
    }
}

fn response(body: &str, status: u16, content_type: &str, url: &str) -> HttpResponse {
    let mut headers = Headers::new();
    headers.insert("content-type".into(), content_type.into());
    HttpResponse { status, headers, set_cookie: vec![], body: body.as_bytes().to_vec(), url: url.to_string() }
}

fn query_of(url: &str, k: &str) -> Option<String> {
    url::Url::parse(url).ok()?.query_pairs().find(|(a, _)| a == k).map(|(_, v)| v.into_owned())
}

/* ------------------------------------------------ 2: SPA locations, acks */

mod a_beacon_that_echoes_the_spas_push_state_location_is_not_learned {
    use super::*;

    fn page() -> Exchange {
        ex("document", json!({ "url": "https://site.test/" }), "<html><input id=q></html>", "text/html")
    }
    fn data() -> Exchange {
        exd(
            "fetch",
            json!({
                "method": "POST",
                "url": "https://site.test/api/graphql",
                "headers": { "content-type": "application/json" },
                "body": json!({ "id": "a1b2c3", "v": "bm90aW9u" }).to_string()
            }),
        )
    }
    fn beacon(res: &str) -> Exchange {
        exj(
            "fetch",
            json!({
                "method": "POST",
                "url": "https://events.other.test/v1/p",
                "headers": { "content-type": "text/plain", "referer": "https://site.test/" },
                "body": json!({ "properties": { "search": "?q=notion" }, "context": { "page": { "url": "https://site.test/search?q=notion" } } }).to_string()
            }),
            res,
        )
    }

    #[test]
    fn the_pages_live_location_push_state_final_url_makes_the_beacons_leaves_echoes() {
        let b = beacon(r#"{"id":"evt_0192837465"}"#);
        // control: with only the document and the Referer, the echo goes unseen
        assert_eq!(learn(vec![page(), data(), b.clone()], vec![json!({ "q": "notion" })]).unwrap().exchange.id, b.id);
        let err = learn_with(vec![page(), data(), b.clone()], vec![json!({ "q": "notion" })], |i| {
            i.pages = Some(vec!["https://site.test/search?q=notion".into()])
        })
        .err()
        .expect("throws")
        .to_string();
        assert!(re("no captured request carries the example values").is_match(&err), "{err}");
    }

    #[test]
    fn a_read_whose_chosen_answer_is_a_data_less_ack_is_refused_unless_the_request_was_picked_by_id() {
        let b = beacon(r#"{"success":true}"#);
        let err = learn(vec![page(), data(), b.clone()], vec![json!({ "q": "notion" })]).err().expect("throws").to_string();
        assert!(re("answers without data .*--pick-request.*--html or --embedded").is_match(&err), "{err}");
        assert_eq!(
            learn_with(vec![page(), data(), b.clone()], vec![json!({ "q": "notion" })], |i| i.id = Some(b.id)).unwrap().exchange.id,
            b.id
        );
        // an answer carrying the example is data, however small
        let small = exj("fetch", json!({ "url": "https://site.test/api/user?name=alice" }), r#"{"user":{"name":"alice"}}"#);
        assert_eq!(learn(vec![small.clone()], vec![json!({ "name": "alice" })]).unwrap().exchange.id, small.id);
    }
}

/* ------------------------------------------------ 3: server-issued creds */

mod a_token_an_earlier_response_issued_is_a_session_ref_whatever_its_name {
    use super::*;

    const TOK: &str = "Zx81kLmN0pQrStUv2wXyZ3aBcD";
    fn boot() -> Exchange {
        exj("fetch", json!({ "url": "https://site.test/api/bootstrap" }), &json!({ "t": TOK }).to_string())
    }

    fn check(req: Value) {
        let Learned { operation: op, session_values, .. } =
            learn(vec![boot(), exd("fetch", req)], vec![json!({ "q": "kittens" })]).unwrap();
        assert!(!serde_json::to_string(&op).unwrap().contains(TOK), "the token is literal in the spec");
        let r = op.slots.iter().find(|s| s.is_ref()).unwrap();
        assert!(re("^session:op/").is_match(r.ref_str()), "{}", r.ref_str());
        assert_eq!(session_values.get(&r.ref_str()[8..]).map(|s| s.as_str()), Some(TOK));
        let fresh = common::session(vec![], &[(&r.ref_str()[8..], "Fresh0Token1Value2Xyz345")]);
        let built = build_request(&op, &args(json!({ "q": "cats" })), &fresh).unwrap();
        assert!(serde_json::to_string(&built).unwrap().contains("Fresh0Token1Value2Xyz345"), "a refreshed value is sent");
    }

    #[test]
    fn a_query_param_named_t() {
        check(json!({ "url": format!("https://api.site.test/v1/search?q=kittens&t={TOK}") }));
    }

    #[test]
    fn a_neutral_header() {
        check(json!({ "url": "https://api.site.test/v1/search?q=kittens", "headers": { "x-ctx": TOK } }));
    }

    #[test]
    fn a_later_response_does_not_count_and_a_persisted_query_hash_stays_a_volatile_anchor() {
        let hash = "e0f2a1b3c4d5e6f708192a3b4c5d6e7f";
        let req = exd("fetch", json!({ "url": format!("https://api.site.test/v1/search?q=kittens&hash={hash}") }));
        let op = learn(
            vec![exj("fetch", json!({ "url": "https://site.test/api/meta" }), &json!({ "hash": hash }).to_string()), req],
            vec![json!({ "q": "kittens" })],
        )
        .unwrap()
        .operation;
        assert_eq!(op.slots.iter().filter(|s| s.is_ref()).count(), 0);
        assert_eq!(op.volatile.len(), 1);
        let later = learn(
            vec![
                exd("fetch", json!({ "url": format!("https://api.site.test/v1/search?q=kittens&t={TOK}") })),
                exj("fetch", json!({ "url": "https://site.test/api/after" }), &json!({ "t": TOK }).to_string()),
            ],
            vec![json!({ "q": "kittens" })],
        )
        .unwrap();
        assert_eq!(later.operation.slots.iter().filter(|s| s.is_ref()).count(), 0);
    }

    #[test]
    fn a_key_in_a_per_user_script_sent_with_the_session_cookie_is_not_public_one_in_a_static_bundle_is() {
        let key = "Uk7pQ2mZ9xVb4NcR8sLd3Tg6";
        let api = || exd("fetch", json!({ "url": "https://api.site.test/v1/search?q=kittens", "headers": { "x-api-key": key } }));
        let per_user = ex(
            "script",
            json!({ "url": "https://site.test/api/me/config.js", "headers": { "cookie": "sess=abc" } }),
            &format!("window.__CFG__={{user:\"alice\",apiKey:\"{key}\"}};"),
            "application/javascript",
        );
        let op = learn(vec![per_user, api()], vec![json!({ "q": "kittens" })]).unwrap().operation;
        assert_eq!(op.public, None);
        assert!(!serde_json::to_string(&op).unwrap().contains(key));
        let bundle = ex_full(
            "script",
            json!({ "url": "https://site.test/static/main.3f9a.js", "headers": { "cookie": "sess=abc" } }),
            &format!("var k=\"{key}\";"),
            "application/javascript",
            json!({ "cache-control": "public, max-age=31536000, immutable" }),
        );
        let shipped = learn(vec![bundle, api()], vec![json!({ "q": "kittens" })]).unwrap().operation;
        assert_eq!(shipped.public, Some(vec!["x-api-key".to_string()]));
        assert_eq!(shipped.request.headers.get("x-api-key").map(|s| s.as_str()), Some(key));
    }

    #[test]
    fn bearer_and_pwd_name_credentials() {
        for q in [format!("bearer={TOK}"), format!("pwd={TOK}")] {
            let op = learn(
                vec![exd("fetch", json!({ "url": format!("https://api.site.test/v1/search?q=kittens&{q}") }))],
                vec![json!({ "q": "kittens" })],
            )
            .unwrap()
            .operation;
            assert!(!serde_json::to_string(&op).unwrap().contains(TOK), "{q}");
        }
    }
}

/* ----------------------------------------------- 4: echo on explicit pick */

#[test]
fn a_route_resolver_whose_only_arg_is_the_page_path_learns_when_picked_by_id() {
    let exs = {
        vec![
            ex("document", json!({ "url": "https://site.test/facebook/react" }), "<html><div id=app></div></html>", "text/html"),
            exj(
                "fetch",
                json!({
                    "method": "POST",
                    "url": "https://site.test/api/route",
                    "headers": { "content-type": "application/json", "referer": "https://site.test/facebook/react" },
                    "body": json!({ "path": "/facebook/react", "locale": "en" }).to_string()
                }),
                r#"{"data":{"repo":{"name":"react","stars":1}}}"#,
            ),
        ]
    };
    let trigger = Trigger { url: "https://site.test/{repo}".into(), steps: None, soft_from: None };
    let t = trigger.clone();
    let err = learn_with(exs.clone(), vec![json!({ "repo": "facebook/react" })], |i| i.trigger = t).err().expect("throws").to_string();
    assert!(re("no captured request carries").is_match(&err), "{err}");
    let picked = exs[1].id;
    let op = learn_with(exs, vec![json!({ "repo": "facebook/react" })], |i| {
        i.trigger = trigger;
        i.id = Some(picked);
    })
    .unwrap()
    .operation;
    let body: Value = serde_json::from_str(
        build_request(&op, &args(json!({ "repo": "vercel/next.js" })), &no_session()).unwrap().body.as_deref().unwrap(),
    )
    .unwrap();
    assert_eq!(body, json!({ "path": "/vercel/next.js", "locale": "en" }));
}

/* ------------------------------------------ 7: encoded cookie, no escape */

#[test]
fn a_param_template_finds_a_percent_encoded_cookie_in_a_leaf_with_no_escape_of_its_own() {
    let token = "q2Fz/9kLmT0vX+Yb7NcW1pRe/Hs3JuQa8Df+Lg6ZoVy4=";
    let enc = api_anything::util::encode_uri_component;
    let cookies = vec![StoredCookie::new("tok", token, "127.0.0.1")];
    let e = exj(
        "fetch",
        json!({ "url": "http://127.0.0.1/api/data", "headers": { "cookie": format!("tok={token}"), "x-ctx": format!("user=alice;auth={}", enc(token)) } }),
        r#"{"data":{"name":"alice"}}"#,
    );
    let mut input = LearnInput::new(
        vec![e],
        vec![args(json!({ "name": "alice" }))],
        "op",
        Trigger { url: "http://127.0.0.1/p?name={name}".into(), steps: None, soft_from: None },
        true,
    );
    input.cookies = cookies.clone();
    let op = learn_operation(&input).unwrap().operation;
    assert!(!serde_json::to_string(&op).unwrap().contains(&enc(token)), "the encoded cookie is literal in the spec");
    let fresh = "ZZFz/9kLmT0vX+Yb7NcW1pRe/Hs3JuQa8Df+Lg6ZoVy4=";
    let mut c = cookies[0].clone();
    c.value = fresh.into();
    let r = build_request(&op, &args(json!({ "name": "bob" })), &Session::with(vec![c], Default::default())).unwrap();
    assert_eq!(r.headers.get("x-ctx").map(|s| s.as_str()), Some(format!("user=bob;auth={}", enc(fresh)).as_str()));
}

/* ------------------------------------------------ 8: embedded IP export */

#[test]
fn export_flags_an_ip_inside_a_longer_leaf_not_a_version_string() {
    RT.block_on(async {
        let _s = SERIAL.lock().await;
        let _home = new_home();
        let warn = |name: &str, body: &str, headers: Value| -> Vec<String> {
            let mut h = json!({ "content-type": "application/json" });
            for (k, v) in headers.as_object().unwrap() {
                h[k] = v.clone();
            }
            save_site(
                &parse_site(&json!({
                    "name": name,
                    "baseUrl": "https://s.test",
                    "operations": [{
                        "name": "op",
                        "readOnly": true,
                        "request": { "method": "POST", "url": "https://s.test/api", "headers": h, "body": body },
                        "trigger": { "url": "https://s.test/" }
                    }]
                }))
                .unwrap(),
            )
            .unwrap();
            export_site(name, false).unwrap().warnings.into_iter().filter(|w| re("IP address").is_match(w)).collect()
        };
        assert_eq!(warn("a", &json!({ "addr": "73.162.10.4:51234" }).to_string(), json!({})).len(), 1);
        assert_eq!(warn("b", "{}", json!({ "x-forwarded-for": "73.162.10.4, 10.0.0.1" })).len(), 1);
        assert_eq!(warn("c", &json!({ "ctx": "ip=73.162.10.4&geo=US" }).to_string(), json!({})).len(), 1);
        assert_eq!(warn("d", &json!({ "remoteHost": "73.162.10.4" }).to_string(), json!({})).len(), 1);
        assert_eq!(
            warn(
                "e",
                &json!({ "ua": "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36", "v": "v1.2.3.4", "at": "2026-09-27T12:30:45.123Z" })
                    .to_string(),
                json!({})
            ),
            Vec::<String>::new()
        );
    })
}

/* ------------------------------------------- 6, 9: classifier (HTML pages) */

mod html_recipes {
    use super::*;

    fn op(items: &str) -> Operation {
        parse_site(&json!({
            "name": "s",
            "baseUrl": "https://s.test",
            "operations": [{
                "name": "op",
                "readOnly": true,
                "request": { "method": "GET", "url": "https://s.test/s?q=kittens", "headers": {} },
                "slots": [{ "param": "q", "at": ["query:q"] }],
                "params": [{ "name": "q", "example": "kittens" }],
                "trigger": { "url": "https://s.test/s?q={q}" },
                "response": { "format": "html", "html": { "items": items, "fields": { "t": "" } } }
            }]
        }))
        .unwrap()
        .operations
        .remove(0)
    }
    fn page_titled(body: &str, title: &str) -> Observed {
        let mut headers = Headers::new();
        headers.insert("content-type".into(), "text/html".into());
        Observed { status: 200, headers, body: format!("<html><head><title>{title}</title></head><body>{body}</body></html>"), url: None }
    }
    fn page(body: &str) -> Observed {
        page_titled(body, "Search")
    }

    #[test]
    fn a_page_titled_like_a_robot_check_is_not_a_wall_when_the_recipe_finds_its_items() {
        let r = classify(&op("li.r"), &page_titled(&"<li class=r>x</li>".repeat(50), "Robot check-in: how our warehouse robots work"));
        assert_eq!(j(&r.class), json!("ok"), "{}", r.reason);
        assert_eq!(
            j(&classify(&op("li.r"), &page_titled("<p>solve this</p>", "Robot check")).class),
            json!("blocked"),
            "without the data the title still counts"
        );
    }

    #[test]
    fn zero_results_the_items_container_is_there_and_empty() {
        assert_eq!(j(&classify(&op("ul.results li.r"), &page("<h1>No results for zzqx</h1><ul class=results></ul>")).class), json!("ok"));
        let renamed = classify(&op("ul.results li.r"), &page("<ul class=results><li class=result>a</li></ul>"));
        assert_eq!(j(&renamed.class), json!("drift"), "items under another class are a renamed selector");
        assert!(renamed.missing);
        assert!(classify(&op("li.r"), &page("<ul></ul>")).missing, "no container in the selector: the example replay decides");
        assert!(
            classify(&op("#search > .item"), &page("<div id=search><p>No results</p></div>")).missing,
            "no tag: any element in the container is not emptiness"
        );
        assert_eq!(j(&classify(&op("#search > .item"), &page("<div id=search></div>")).class), json!("ok"));
    }

    #[test]
    fn call_an_empty_results_page_is_ok_with_one_request_no_example_replay() {
        RT.block_on(async {
            let _s = SERIAL.lock().await;
            let _home = new_home();
            let mut o = j(&op("ul.results li.r"));
            o["request"] = json!({ "method": "GET", "url": "https://z.test/s?q=kittens", "headers": {} });
            save_site(&parse_site(&json!({ "name": "z", "baseUrl": "https://z.test", "operations": [o] })).unwrap()).unwrap();
            let fetcher = Answering::new(|u| {
                let q = query_of(&u.url, "q").unwrap_or_default();
                response(
                    &if q == "zzqx" {
                        "<html><body><ul class=results></ul></body></html>".to_string()
                    } else {
                        format!("<html><body><ul class=results><li class=r>{q}</li></ul></body></html>")
                    },
                    200,
                    "text/html",
                    &u.url,
                )
            });
            let r = call(
                "z",
                "op",
                args(json!({ "q": "zzqx" })),
                CallOptions { fetcher: Some(fetcher.clone()), max_tier: Some(1), min_interval_ms: Some(0), ..Default::default() },
            )
            .await;
            assert!(r.ok, "{}", serde_json::to_string(&r).unwrap());
            assert_eq!(r.data, Some(json!([])));
            assert_eq!(fetcher.count(), 1);
        })
    }
}

/* ------------------------------------ 11a, 11f: call-level input answers */

mod input_answers {
    use super::*;

    fn base_json() -> Value {
        json!({
            "name": "p",
            "baseUrl": "https://p.test",
            "operations": [{
                "name": "op",
                "readOnly": true,
                "request": { "method": "GET", "url": "https://p.test/api/profile?id=alice&date=2027-04-15", "headers": {} },
                "slots": [
                    { "param": "id", "at": ["query:id"] },
                    { "param": "date", "at": ["query:date"] }
                ],
                "params": [
                    { "name": "id", "example": "alice" },
                    { "name": "date", "example": "2027-04-15", "pattern": "\\d{4}-\\d{2}-\\d{2}", "hint": "a date as YYYY-MM-DD" }
                ],
                "trigger": { "url": "https://p.test/{id}" },
                "response": { "format": "json", "extract": "profile" }
            }]
        })
    }
    fn base() -> api_anything::spec::Site {
        parse_site(&base_json()).unwrap()
    }
    fn json_res(v: Value, status: u16, url: &str) -> HttpResponse {
        response(&v.to_string(), status, "application/json", url)
    }

    #[test]
    fn an_arg_that_fails_the_params_pattern_is_input_with_the_hint_and_nothing_is_sent() {
        RT.block_on(async {
            let _s = SERIAL.lock().await;
            let _home = new_home();
            save_site(&base()).unwrap();
            let fetcher = Answering::new(|u| json_res(json!({ "profile": {} }), 200, &u.url));
            let r = call(
                "p",
                "op",
                args(json!({ "id": "bob", "date": "Oct 21" })),
                CallOptions { fetcher: Some(fetcher.clone()), max_tier: Some(1), min_interval_ms: Some(0), ..Default::default() },
            )
            .await;
            assert_eq!(j(&r.class), json!("input"), "{}", serde_json::to_string(&r).unwrap());
            assert!(
                re(r#"param "date" must be a date as YYYY-MM-DD, got "Oct 21""#).is_match(r.reason.as_deref().unwrap_or("")),
                "{:?}",
                r.reason
            );
            assert_eq!(fetcher.count(), 0);
            let mut bad = base_json();
            bad["operations"][0]["params"] = json!([{ "name": "id", "pattern": "([" }]);
            let err = parse_site(&bad).err().expect("throws").to_string();
            assert!(re("valid regular expression").is_match(&err), "{err}");
        })
    }

    #[test]
    fn a_missing_entitys_bare_403_answers_input_fast_and_never_calls_it_a_bot_wall() {
        RT.block_on(async {
            let _s = SERIAL.lock().await;
            let _home = new_home();
            save_site(&base()).unwrap();
            let fetcher = Answering::new(|u| {
                if u.url.contains("alice") {
                    json_res(json!({ "profile": { "name": "Alice" } }), 200, &u.url)
                } else {
                    json_res(json!({ "message": "This profile can't be accessed", "status": 403 }), 403, &u.url)
                }
            });
            let r = call(
                "p",
                "op",
                args(json!({ "id": "zzqx-no-such-person", "date": "2027-04-15" })),
                CallOptions { fetcher: Some(fetcher.clone()), min_interval_ms: Some(0), ..Default::default() },
            )
            .await;
            assert_eq!(j(&r.class), json!("input"), "{}", serde_json::to_string(&r).unwrap());
            assert_eq!(r.tier, Some(1));
            assert_eq!(fetcher.count(), 2);
            assert!(!re("bot wall").is_match(r.reason.as_deref().unwrap_or("")));
        })
    }
}

/* -------------------------------------- 11c, 11d, 11e: the agent surface */

mod agent_surface {
    use super::*;

    #[test]
    fn mcp_next_hints_name_mcp_tools_and_cli_only_commands_say_so() {
        assert_eq!(
            mcp_next("check the args against: api-anything ops linkedin; do not heal or re-add"),
            "check the args against: list_operations {\"site\":\"linkedin\"}; do not heal or re-add"
        );
        assert!(re(r#"^the login tool \{"site":"x"\}"#).is_match(&mcp_next("ask the user to run: api-anything login x; then retry once")));
        assert!(
            re(r"is a CLI: run it in your shell, as npx -y github:goodnight000/api-anything when the command is not installed; with no shell, ask the user\)$")
                .is_match(&mcp_next("api-anything heal x getUser; if that fails, re-learn it with api-anything add x getUser ..."))
        );
        assert_eq!(mcp_next("api-anything sites lists what exists"), "list_sites lists what exists");
        assert!(!re("rerun").is_match(&mcp_next(
            "only if the user asked for this write: rerun with --allow-writes (MCP: start the server with --allow-writes)"
        )));
    }

    #[test]
    fn over_mcp_call_operations_next_and_list_operations_notes_and_param_hints() {
        RT.block_on(async {
            let _s = SERIAL.lock().await;
            let home = new_home();
            save_site(
                &parse_site(&json!({
                    "name": "notes",
                    "baseUrl": "https://n.test",
                    "operations": [{
                        "name": "get",
                        "readOnly": true,
                        "request": { "method": "GET", "url": "https://n.test/api?d=2027-04-15", "headers": {} },
                        "slots": [{ "param": "d", "at": ["query:d"] }],
                        "params": [{ "name": "d", "pattern": "\\d{4}-\\d{2}-\\d{2}", "hint": "a date as YYYY-MM-DD" }],
                        "trigger": { "url": "https://n.test/" }
                    }]
                }))
                .unwrap(),
            )
            .unwrap();
            std::fs::write(home.path().join("sites").join("notes.md"), "# notes\nAirport codes only, not metro codes.\n").unwrap();
            let server = Server::new(false);
            let ops = server.call_tool("list_operations", &args(json!({ "site": "notes" }))).await.value;
            assert!(re("Airport codes only").is_match(ops["notes"].as_str().unwrap_or("")), "{ops}");
            assert_eq!(ops["operations"][0]["params"][0]["hint"], json!("a date as YYYY-MM-DD"));
            let bad =
                server.call_tool("call_operation", &args(json!({ "site": "notes", "op": "get", "args": { "d": "tomorrow" } }))).await.value;
            assert_eq!(bad["class"], json!("input"));
            assert_eq!(bad["next"], json!("check the args against: list_operations {\"site\":\"notes\"}"));
            assert_eq!(load_site("notes").unwrap().unwrap().site.name, "notes");
        })
    }

    #[test]
    fn ops_prints_the_notes_and_each_params_format_inspect_decodes_layered_bodies_by_default() {
        RT.block_on(async {
            let _s = SERIAL.lock().await;
            let home = new_home();
            let home_path = home.path().to_path_buf();
            let cli = |argv: Vec<String>| {
                let home_path = home_path.clone();
                async move {
                    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-anything")).args(&argv).env("API_ANYTHING_HOME", &home_path).output().await.unwrap();
                    (if out.status.success() { 0 } else { 1 }, String::from_utf8_lossy(&out.stdout).into_owned())
                }
            };
            save_site(
                &parse_site(&json!({
                    "name": "notes",
                    "baseUrl": "https://n.test",
                    "operations": [{
                        "name": "get",
                        "readOnly": true,
                        "request": { "method": "GET", "url": "https://n.test/api?d=2027-04-15", "headers": {} },
                        "slots": [{ "param": "d", "at": ["query:d"] }],
                        "params": [{ "name": "d", "example": "2027-04-15", "hint": "a date as YYYY-MM-DD", "pattern": "\\d{4}-\\d{2}-\\d{2}" }],
                        "trigger": { "url": "https://n.test/" }
                    }]
                }))
                .unwrap(),
            )
            .unwrap();
            std::fs::write(home.path().join("sites").join("notes.md"), "Airport codes only.\n").unwrap();
            let (_, out) = cli(vec!["ops".into(), "notes".into()]).await;
            let ops: Value = serde_json::from_str(&out).unwrap_or_else(|_| panic!("{out}"));
            assert_eq!(ops["notes"], json!("Airport codes only."));
            assert_eq!(ops["operations"][0]["params"], json!(["d:string (e.g. \"2027-04-15\"; a date as YYYY-MM-DD)"]));

            let payload = json!([[["SFO", "JFK", 209]], [["SFO", "EWR", 254]]]).to_string();
            let f_req = json!([null, json!([["SFO"], ["JFK"]]).to_string()]).to_string();
            std::fs::create_dir_all(home.path().join("captures")).unwrap();
            let capture = json!({
                "id": "cbatch",
                "at": api_anything::util::iso_now(),
                "url": "https://g.test/",
                "finalUrl": "https://g.test/",
                "cookies": [],
                "exchanges": [{
                    "id": 1,
                    "resourceType": "xhr",
                    "request": {
                        "method": "POST",
                        "url": "https://g.test/_/data/batchexecute?rt=c",
                        "headers": { "content-type": "application/x-www-form-urlencoded;charset=UTF-8" },
                        "body": format!("f.req={}&at=x", api_anything::util::encode_uri_component(&f_req))
                    },
                    "response": {
                        "status": 200,
                        "headers": {},
                        "contentType": "application/json",
                        "body": format!(")]}}'\n\n{}", json!([["wrb.fr", "rpc", payload, null]]))
                    }
                }]
            });
            std::fs::write(home.path().join("captures").join("cbatch.json"), capture.to_string()).unwrap();
            let (_, out) = cli(vec!["inspect".into(), "cbatch".into(), "1".into()]).await;
            let shown: Value = serde_json::from_str(&out).unwrap_or_else(|_| panic!("{out}"));
            assert_eq!(shown["data"], json!([["wrb.fr", "rpc", serde_json::from_str::<Value>(&payload).unwrap(), null]]));
            assert_eq!(shown["request"]["body"], json!({ "f.req": [null, [["SFO"], ["JFK"]]], "at": "x" }));
        })
    }
}

/* ---------------------------------------------------------------- browser */

mod browser {
    use super::*;

    #[test]
    fn t1_a_reads_tier_3_run_lets_a_js_challenge_post_its_proof_then_guards_the_real_page() {
        RT.block_on(async {
            let _s = SERIAL.lock().await;
            if !chrome() {
                return skip();
            }
            let _home = new_home();
            let verifies = Arc::new(AtomicUsize::new(0));
            let tracks = Arc::new(AtomicUsize::new(0));
            let (v2, t2) = (verifies.clone(), tracks.clone());
            let s = listen(
                sync_handler(move |u| {
                    if u.path == "/hotels" {
                        if !re("aws-waf-token=ok").is_match(u.headers.get("cookie").map(|s| s.as_str()).unwrap_or("")) {
                            // AWS WAF-style: the page solves a proof, POSTs it, and reloads once the token cookie is set
                            return resp(
                                202,
                                &[("content-type", "text/html")],
                                &(r#"<!doctype html><html><head><title></title><script>window.awsWafCookieDomainList=[];window.gokuProps={"key":"k"};</script>"#.to_string()
                                    + r#"<script>setTimeout(()=>fetch("/__challenge_ab12/mp_verify",{method:"POST",body:"proof"}).then(r=>r.ok&&location.reload()),300)</script></head><body></body></html>"#),
                            );
                        }
                        let q = u.param("q").unwrap_or("");
                        return html(&format!(
                            r#"<div>{q} hotels</div><script>fetch("/api/list?q={}");fetch("/api/track",{{method:"POST",body:"x"}})</script>"#,
                            api_anything::util::encode_uri_component(q)
                        ));
                    }
                    if u.path == "/__challenge_ab12/mp_verify" && u.method == "POST" {
                        v2.fetch_add(1, Ordering::SeqCst);
                        return resp(200, &[("set-cookie", "aws-waf-token=ok; Path=/"), ("content-type", "text/plain")], "ok");
                    }
                    if u.path == "/api/track" {
                        t2.fetch_add(1, Ordering::SeqCst);
                        return resp(204, &[], "");
                    }
                    if u.path == "/api/list" {
                        return resp(200, &[("content-type", "application/json")], &json!({ "items": [{ "name": format!("{} 1", u.param("q").unwrap_or("null")) }] }).to_string());
                    }
                    resp(404, &[], "")
                }),
                "127.0.0.1",
            )
            .await;
            let base = s.base.clone();
            let op: Operation = parse_site(&json!({
                "name": "hot",
                "baseUrl": base,
                "operations": [{
                    "name": "list",
                    "readOnly": true,
                    "request": { "method": "GET", "url": format!("{base}/api/list?q=Madrid"), "headers": {} },
                    "slots": [{ "param": "q", "at": ["query:q"] }],
                    "params": [{ "name": "q", "example": "Madrid" }],
                    "trigger": { "url": format!("{base}/hotels?q={{q}}") },
                    "match": { "method": "GET", "path": "/api/list" },
                    "response": { "format": "json", "extract": "items" }
                }]
            }))
            .unwrap()
            .operations
            .remove(0);
            let run = run_op_trigger("hot", &op, &args(json!({ "q": "Porto" })), false).await.unwrap();
            assert!(verifies.load(Ordering::SeqCst) >= 1, "the challenge's verify POST reached the server");
            assert_eq!(
                run.matched.as_ref().and_then(|m| m.status()),
                Some(200),
                "{}",
                json!(run.capture.exchanges.iter().map(|e| json!([e.request.method, e.request.url, e.status(), e.aborted])).collect::<Vec<_>>())
            );
            assert!(re("Porto 1").is_match(run.matched.as_ref().map(|m| m.body()).unwrap_or("")));
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(tracks.load(Ordering::SeqCst), 0, "once the real page loaded, an unsafe request that is not the op's own was aborted");
            close_browser().await;
            s.close();
        })
    }

    #[test]
    fn t2_a_capture_records_the_spas_push_state_location_so_add_refuses_the_analytics_beacon() {
        RT.block_on(async {
            let _s = SERIAL.lock().await;
            if !chrome() {
                return skip();
            }
            let _home = new_home();
            let beacons: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
            let b2 = beacons.clone();
            let b = listen(
                sync_handler(move |u| {
                    if u.method == "POST" {
                        b2.lock().unwrap().push(u.body.clone());
                    }
                    resp(200, &[("content-type", "application/json"), ("access-control-allow-origin", "*"), ("access-control-allow-headers", "*")], r#"{"success":true}"#)
                }),
                "localhost",
            )
            .await;
            let b_base = b.base.clone();
            let a = listen(
                sync_handler(move |u| {
                    if u.path == "/api/graphql" {
                        let v: Value = serde_json::from_str(&u.body).unwrap_or(Value::Null);
                        let q = String::from_utf8_lossy(&api_anything::util::b64_decode_lenient(v["v"].as_str().unwrap_or("").as_bytes())).into_owned();
                        return resp(200, &[("content-type", "application/json")], &json!({ "data": { "results": [{ "name": format!("{q} one") }, { "name": format!("{q} two") }] } }).to_string());
                    }
                    html(&format!(
                        r#"<input id=q><div id=out></div><script>document.getElementById('q').addEventListener('keydown', async (e) => {{ if (e.key !== 'Enter') return; const q = e.target.value;
          const r = await fetch('/api/graphql', {{ method: 'POST', headers: {{'content-type':'application/json'}}, body: JSON.stringify({{ id: 'a1b2c3', v: btoa(q) }}) }});
          document.getElementById('out').textContent = JSON.stringify(await r.json());
          history.pushState({{}}, '', '/search?q=' + encodeURIComponent(q));
          fetch('{b_base}/v1/p', {{ method: 'POST', headers: {{'content-type':'text/plain'}}, body: JSON.stringify({{ event: 'search', properties: {{ search: location.search }}, context: {{ page: {{ url: location.href }} }} }}) }});
        }});</script>"#
                    ))
                }),
                "127.0.0.1",
            )
            .await;
            let steps: Vec<api_anything::types::TriggerStep> = serde_json::from_value(json!([
                { "action": "fill", "selector": "#q", "value": "{q}" },
                { "action": "press", "selector": "#q", "value": "Enter" }
            ]))
            .unwrap();
            let mut o = TriggerOptions::new(&format!("{}/", a.base), &profile_dir());
            o.steps = Some(
                serde_json::from_value(json!([
                    { "action": "fill", "selector": "#q", "value": "notion" },
                    { "action": "press", "selector": "#q", "value": "Enter" }
                ]))
                .unwrap(),
            );
            let run = run_trigger(o).await.unwrap();
            assert!(run.locations.as_ref().map(|l| l.contains(&format!("{}/search?q=notion", a.base))).unwrap_or(false), "{}", json!(run.locations));
            let err = add_operation(AddInput {
                site: "spa".into(),
                op: "search".into(),
                trigger: Some(Trigger { url: format!("{}/", a.base), steps: Some(steps), soft_from: None }),
                examples: vec![args(json!({ "q": "notion" })), args(json!({ "q": "figma" }))],
                matcher: None,
                write: false,
                description: None,
                response: None,
                public: None,
                from: None,
                from2: None,
                fetcher: None,
            })
            .await
            .err()
            .expect("rejects")
            .to_string();
            assert!(re("no captured request carries|answers without data").is_match(&err), "{err}");
            assert!(load_site("spa").unwrap().is_none(), "nothing was saved");
            close_browser().await;
            a.close();
            b.close();
        })
    }

    #[test]
    fn t5_a_tier_2_read_retries_once_when_the_origin_page_navigates_mid_fetch_a_write_never_does() {
        RT.block_on(async {
            let _s = SERIAL.lock().await;
            if !chrome() {
                return skip();
            }
            let _home = new_home();
            let h: Handler = Arc::new(|u: Req| {
                Box::pin(async move {
                    if u.path == "/api/slow" {
                        tokio::time::sleep(Duration::from_millis(700)).await;
                        return resp(200, &[("content-type", "application/json")], r#"{"ok":1}"#);
                    }
                    // the origin page navigates itself once, shortly after load (an interstitial's redirect)
                    html(r#"<script>if(!sessionStorage.getItem("n")){sessionStorage.setItem("n","1");setTimeout(()=>location.href="/?again=1",150)}</script>"#)
                })
            });
            let s = listen(h, "127.0.0.1").await;
            let base = s.base.clone();
            let other = base.replace("127.0.0.1", "localhost");
            let fetch = |origin: String, retry: bool| PageFetchOptions {
                origin: origin.clone(),
                url: format!("{origin}/api/slow"),
                method: "GET".into(),
                headers: Headers::new(),
                body: None,
                profile_dir: profile_dir(),
                headless: true,
                timeout_ms: None,
                retry_on_navigation: retry,
                redirect: None,
            };
            // Playwright words this "Execution context was destroyed"; over CDP the evaluation fails with
            // "Inspected target navigated or closed". Either way the read's answer is the navigation, not a retry.
            let err = page_fetch(fetch(base.clone(), false)).await.err().expect("rejects").to_string();
            assert!(re("Execution context was destroyed|Inspected target navigated").is_match(&err), "{err}");
            let r = page_fetch(fetch(other, true)).await.unwrap();
            assert_eq!(r.status, 200);
            assert_eq!(r.body, r#"{"ok":1}"#);
            close_browser().await;
            s.close();
        })
    }

    #[test]
    fn t10_learning_a_write_aborts_a_stylesheet_font_or_media_load_pointed_at_the_sites_own_endpoint() {
        RT.block_on(async {
            let _s = SERIAL.lock().await;
            if !chrome() {
                return skip();
            }
            let _home = new_home();
            let votes: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
            let css = Arc::new(AtomicUsize::new(0));
            let (v2, c2) = (votes.clone(), css.clone());
            let s = listen(
                sync_handler(move |u| {
                    if u.path == "/api/vote" {
                        v2.lock().unwrap().push(u.query.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&"));
                        return resp(200, &[("content-type", "text/plain")], "ok");
                    }
                    if u.path == "/static/app.css" {
                        c2.fetch_add(1, Ordering::SeqCst);
                        return resp(200, &[("content-type", "text/css")], "body{color:#111}");
                    }
                    html(&("<button id=go onclick=\"".to_string()
                        + "const l=document.createElement('link');l.rel='stylesheet';l.href='/api/vote?how=css';document.head.appendChild(l);"
                        + "new Audio('/api/vote?how=audio').load();"
                        + "new FontFace('x','url(/api/vote?how=font)').load().catch(()=>{});"
                        + "const s=document.createElement('link');s.rel='stylesheet';s.href='/static/app.css';document.head.appendChild(s)\">go</button>"))
                }),
                "127.0.0.1",
            )
            .await;
            capture_page(CapturePageOptions {
                url: format!("{}/p", s.base),
                steps: Some(serde_json::from_value(json!([{ "action": "click", "selector": "#go" }, { "action": "wait", "ms": 1000 }])).unwrap()),
                soft_from: None,
                write: true,
                args: None,
            })
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(*votes.lock().unwrap(), Vec::<String>::new(), "a disguised GET write reached the server");
            assert_eq!(css.load(Ordering::SeqCst), 1, "a real stylesheet still loads");
            close_browser().await;
            s.close();
        })
    }
}
