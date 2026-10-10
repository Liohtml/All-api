//! test/execute.test.ts: the ladder's rules with an injected fetch and maxTier 1 (no browser):
//! writes, heal guards, rate. Plus the call() half of release.test.ts's rejected-write test.
mod common;
use api_anything::classify::Class;
use api_anything::execute::{CallOptions, call};
use api_anything::heal::{AddInput, FromCapture, Recipe, add_operation};
use api_anything::http::{Fetcher, HttpRequest, HttpResponse};
use api_anything::spec::Site;
use api_anything::store::{save_site, stale_mark};
use api_anything::types::Headers;
use api_anything::util::now_ms;
use common::{Home, args, j, site};
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::Duration;

static HOME: LazyLock<Home> = LazyLock::new(Home::new);
/// One home for the binary, so the tests take turns like node's sequential tests in one file do.
static LOCK: Mutex<()> = Mutex::new(());

const QID: &str = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7H";
const NEW: &str = "Zz9Yy8Xx7Ww6Vv5Uu4Tt3S";

fn the_site() -> Site {
    site(json!({
        "name": "t",
        "baseUrl": "https://t.test",
        "operations": [
            {
                "name": "user",
                "readOnly": true,
                "request": {"method": "GET", "url": format!("https://t.test/api/{QID}/User?name=alice"), "headers": {}},
                "slots": [{"param": "name", "at": ["query:name"]}],
                "volatile": [{"at": ["path:1"], "shape": {"charset": "base64url", "length": 22}, "anchor": "User"}],
                "trigger": {"url": "https://t.test/u/{name}"},
                "params": [{"name": "name"}],
                "response": {"extract": "user"},
            },
            {
                "name": "post",
                "readOnly": false,
                "request": {
                    "method": "POST",
                    "url": "https://t.test/api/post",
                    "headers": {"content-type": "application/json"},
                    "body": "{\"text\":\"x\"}",
                },
                "slots": [{"param": "text", "at": ["body", "json:/text"]}],
                "trigger": {"url": "https://t.test/compose"},
                "params": [{"name": "text"}],
            },
        ],
    }))
}

type Handler = Box<dyn Fn(&HttpRequest) -> anyhow::Result<HttpResponse> + Send + Sync>;

/// The TS `fake(h)`: answers from `h` and keeps every (url, method) it was handed.
struct Fake {
    seen: Mutex<Vec<(String, String)>>,
    handler: Handler,
}

impl Fetcher for Fake {
    fn fetch(&self, req: HttpRequest, _timeout: Duration) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        self.seen.lock().unwrap().push((req.url.clone(), req.method.clone()));
        let r = (self.handler)(&req);
        Box::pin(async move { r })
    }
}

fn fake(h: impl Fn(&HttpRequest) -> anyhow::Result<HttpResponse> + Send + Sync + 'static) -> Arc<Fake> {
    Arc::new(Fake { seen: Mutex::new(vec![]), handler: Box::new(h) })
}

fn seen(f: &Fake) -> usize {
    f.seen.lock().unwrap().len()
}

fn response(status: u16, headers: &[(&str, &str)], body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Headers>(),
        set_cookie: vec![],
        body: body.as_bytes().to_vec(),
        url: String::new(),
    }
}

/// `new Response(text)`: undici gives a string body text/plain.
fn text(status: u16, body: &str) -> HttpResponse {
    response(status, &[("content-type", "text/plain;charset=UTF-8")], body)
}

/// The TS `json(v, status)`.
fn json_res(v: Value, status: u16) -> HttpResponse {
    response(status, &[("content-type", "application/json")], &v.to_string())
}

fn opts(f: &Arc<Fake>, allow_writes: bool) -> CallOptions {
    CallOptions { allow_writes, fetcher: Some(f.clone()), max_tier: Some(1), min_interval_ms: Some(0), timeout_ms: None }
}

fn heals() -> Vec<Value> {
    match std::fs::read_to_string(HOME.path().join("heals.jsonl")) {
        Ok(s) => s.trim().lines().map(|l| serde_json::from_str(l).unwrap()).collect(),
        Err(_) => vec![],
    }
}

fn query_param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url).ok()?.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
}

static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());

/// The TS `beforeEach`, then the test on the shared runtime: the lock is held in sync code only.
fn run<F: std::future::Future<Output = ()>>(f: F) {
    let _g = fresh();
    RT.block_on(f);
}

fn fresh() -> MutexGuard<'static, ()> {
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _ = std::fs::remove_file(HOME.path().join("state.json"));
    let _ = std::fs::remove_file(HOME.path().join("heals.jsonl"));
    save_site(&the_site()).unwrap();
    guard
}

#[test]
fn writes_refused_without_allow_writes_5xx_and_network_errors_are_ambiguous_and_never_retried() {
    run(async {
        let f = fake(|_| Ok(json_res(json!({}), 200)));
        assert_eq!(call("t", "post", args(json!({"text": "hi"})), opts(&f, false)).await.class, Class::Refused);
        assert_eq!(seen(&f), 0);

        let f = fake(|_| Ok(json_res(json!({"error": "boom"}), 502)));
        let r = call("t", "post", args(json!({"text": "hi"})), opts(&f, true)).await;
        assert!(!r.ok);
        assert_eq!(seen(&f), 1);
        assert!(r.next.as_deref().unwrap_or("").contains("may have gone through"), "{r:?}");

        let f = fake(|_| Err(anyhow::anyhow!("fetch failed")));
        let n = call("t", "post", args(json!({"text": "hi"})), opts(&f, true)).await;
        assert_eq!(n.class, Class::Error);
        assert_eq!(seen(&f), 1);
        assert!(n.next.as_deref().unwrap_or("").contains("may have gone through"), "{n:?}");
    });
}

/// The handler of the drift test: the trigger page, its bundle naming `current`, and the API under it.
fn drift_handler(current: Arc<Mutex<String>>) -> Arc<Fake> {
    fake(move |req| {
        let current = current.lock().unwrap().clone();
        let url = req.url.as_str();
        if url == "https://t.test/u/bob" {
            return Ok(response(200, &[("content-type", "text/html")], "<script src=\"/app.js\"></script>"));
        }
        if url == "https://t.test/app.js" {
            return Ok(text(200, &format!("r=[{{id:\"{current}\",name:\"User\"}}]")));
        }
        if url.contains(&format!("/api/{current}/User")) {
            return Ok(json_res(json!({"user": {"name": query_param(url, "name")}}), 200));
        }
        Ok(text(404, ""))
    })
}

#[test]
fn drift_heals_by_rescan_and_retries_once_drifting_again_within_10_min_marks_it_stale_instead() {
    run(async {
        let current = Arc::new(Mutex::new(QID.to_string()));
        let h = drift_handler(current.clone());
        *current.lock().unwrap() = NEW.to_string();
        let r = call("t", "user", args(json!({"name": "bob"})), opts(&h, false)).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.healed, Some(true));
        assert_eq!(r.data, Some(json!({"name": "bob"})));
        assert_eq!(heals().iter().map(|x| x["strategy"].clone()).collect::<Vec<_>>(), vec![json!("rescan")]);

        *current.lock().unwrap() = "Qq1Ww2Ee3Rr4Tt5Yy6Uu7I".to_string();
        // the bundle now serves an id the template does not have, but the op was healed seconds ago
        let again = call("t", "user", args(json!({"name": "bob"})), opts(&h, false)).await;
        assert_eq!(again.class, Class::Drift);
        assert!(again.reason.as_deref().unwrap_or("").contains("stale"), "{again:?}");
        assert!(stale_mark("t", "user", now_ms()).is_some());
        assert_eq!(heals().len(), 1, "not re-healed");
    });
}

#[test]
fn a_byte_identical_rescan_is_not_a_heal_rate_is_reported_without_heal_or_retry() {
    run(async {
        let h = fake(|req| {
            let url = req.url.as_str();
            if url.ends_with("/u/bob") {
                return Ok(text(200, &format!("<script>r={{id:\"{QID}\",name:\"User\"}}</script>")));
            }
            if url.contains("/api/") {
                return Ok(text(404, ""));
            }
            Ok(text(404, ""))
        });
        let r = call("t", "user", args(json!({"name": "bob"})), opts(&h, false)).await;
        assert!(!r.ok);
        assert_eq!(heals().len(), 0);

        let f = fake(|_| Ok(json_res(json!({"message": "Too many requests"}), 429)));
        let rate = call("t", "user", args(json!({"name": "bob"})), opts(&f, false)).await;
        assert_eq!(rate.class, Class::Rate);
        assert_eq!(seen(&f), 1);
        assert!(rate.next.as_deref().unwrap_or("").contains("do not retry"), "{rate:?}");
    });
}

#[test]
fn no_data_for_an_arg_while_the_example_still_returns_data_is_input_not_drift_no_heal_one_extra_request() {
    run(async {
        save_site(&site(json!({
            "name": "nf",
            "baseUrl": "https://t.test",
            "operations": [
                {
                    "name": "user",
                    "readOnly": true,
                    "request": {"method": "GET", "url": "https://t.test/api/User?name=alice", "headers": {}},
                    "slots": [{"param": "name", "at": ["query:name"]}],
                    "trigger": {"url": "https://t.test/u/{name}"},
                    "params": [{"name": "name", "example": "alice"}],
                    "response": {"extract": "data.user"},
                },
            ],
        })))
        .unwrap();
        let h = fake(|req| {
            let name = query_param(&req.url, "name");
            Ok(if name.as_deref() == Some("alice") {
                json_res(json!({"data": {"user": {"name": name}}}), 200)
            } else {
                json_res(json!({"data": {}}), 200)
            })
        });
        let r = call("nf", "user", args(json!({"name": "zzqq_no_such_user"})), opts(&h, false)).await;
        assert_eq!(r.class, Class::Input, "{}", j(&r));
        assert!(r.reason.as_deref().unwrap_or("").contains("example args still return data"), "{r:?}");
        assert!(r.next.as_deref().unwrap_or("").contains("do not heal"), "{r:?}");
        assert_eq!(seen(&h), 2);
        assert_eq!(heals().len(), 0);

        // when the example fails too, it is drift and the heal runs
        let f = fake(|_| Ok(json_res(json!({"data": {}}), 200)));
        let d = call("nf", "user", args(json!({"name": "bob"})), opts(&f, false)).await;
        assert_eq!(d.class, Class::Drift);
        assert!(seen(&f) >= 2);
    });
}

#[test]
fn a_write_answered_204_html_or_plain_text_is_ok_sent_once() {
    run(async {
        let answers: Vec<HttpResponse> =
            vec![response(204, &[], ""), response(200, &[("content-type", "text/html")], "<html>Posted!</html>"), text(200, "OK")];
        for res in answers {
            let f = fake(move |_| Ok(res.clone()));
            let r = call("t", "post", args(json!({"text": "hi"})), opts(&f, true)).await;
            assert!(r.ok, "{}", j(&r));
            assert_eq!(seen(&f), 1);
        }
    });
}

#[test]
fn add_from_a_capture_judges_the_op_on_the_captured_response_a_wrong_extract_is_a_warning_a_right_one_a_preview() {
    run(async {
        let capture = || {
            serde_json::from_value(json!({
                "id": "cfake1",
                "at": "",
                "url": "https://t.test/u/nasa",
                "cookies": [],
                "finalUrl": "https://t.test/u/nasa",
                "exchanges": [
                    {
                        "id": 7,
                        "resourceType": "fetch",
                        "request": {"method": "GET", "url": "https://t.test/api/User?screen_name=nasa", "headers": {}},
                        "response": {
                            "status": 200,
                            "headers": {},
                            "contentType": "application/json",
                            "body": "{\"data\":{\"user_result\":{\"name\":\"NASA\",\"followers\":9}}}",
                        },
                    },
                ],
            }))
            .expect("a capture literal")
        };
        let input = |recipe: Recipe| AddInput {
            site: "addfrom".into(),
            op: "u".into(),
            trigger: None,
            examples: vec![args(json!({"screen_name": "nasa"}))],
            matcher: None,
            write: false,
            description: None,
            response: Some(recipe),
            public: None,
            from: Some(FromCapture { capture: capture(), id: Some(7) }),
            from2: None,
            fetcher: None,
        };
        let bad = add_operation(input(Recipe { extract: Some("data.user.result".into()), ..Default::default() })).await.unwrap();
        let wanted =
            regex::Regex::new(r#"on the captured response this op says drift: extract path "data.user.result" missing.*add --from cfake1"#)
                .unwrap();
        assert!(bad.warnings.iter().any(|w| wanted.is_match(w)), "{}", bad.warnings.join("\n"));
        assert!(bad.preview.is_none());
        assert_eq!(bad.operation.trigger.url, "https://t.test/u/{screen_name}");
        let good = add_operation(input(Recipe {
            extract: Some("data.user_result".into()),
            pick: Some(vec!["name".into()]),
            ..Default::default()
        }))
        .await
        .unwrap();
        assert_eq!(j(&good.preview), json!({"first": {"name": "NASA"}}));
        assert!(good.replaced);
    });
}

/// test/release.test.ts, the call() half.
#[test]
fn a_write_rejected_inside_an_http_200_response_is_not_success_and_is_never_retried() {
    run(async {
        let spec = |response: Value| {
            site(json!({
                "name": "rejected-write",
                "baseUrl": "https://site.test",
                "operations": [
                    {
                        "name": "send",
                        "readOnly": false,
                        "request": {"method": "POST", "url": "https://site.test/send", "headers": {}, "body": "{}"},
                        "trigger": {"url": "https://site.test/compose"},
                        "response": response,
                    },
                ],
            }))
        };
        save_site(&spec(json!({}))).unwrap();
        for format in ["json", "html", "embedded"] {
            save_site(&spec(json!({"format": format}))).unwrap();
            for payload in [json!({"ok": false, "error": "recipient unavailable"}), json!({"success": false, "message": "not permitted"})] {
                let f = fake(move |_| Ok(json_res(payload.clone(), 200)));
                let result = call(
                    "rejected-write",
                    "send",
                    args(json!({})),
                    CallOptions {
                        allow_writes: true,
                        min_interval_ms: Some(0),
                        fetcher: Some(f.clone()),
                        max_tier: None,
                        timeout_ms: None,
                    },
                )
                .await;
                assert!(!result.ok, "{format}: {}", j(&result));
                assert_eq!(seen(&f), 1);
            }
        }
    });
}
