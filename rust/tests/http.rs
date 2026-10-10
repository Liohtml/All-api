mod common;
use api_anything::http::{
    Args, Fetcher, HttpRequest, HttpResponse, MAX_REDIRECTS, RedirectRefused, SendOptions, build_request, default_fetcher, next_hop, send,
};
use api_anything::session::Session;
use api_anything::spec::{Operation, Request};
use api_anything::types::Headers;
use api_anything::util::{b64_encode, b64url_encode, json_escape, now_ms};
use axum::body::Body;
use axum::response::Response;
use common::{args, cookie, enc, j, op as parse_op, session};
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn op(over: Value) -> Operation {
    let mut v = json!({
        "name": "reply",
        "request": {
            "method": "post",
            "url": "https://x.com/i/api/graphql/ID/CreateTweet",
            "headers": {"content-type": "application/json", "x-csrf-token": "", "authorization": "", "csrf-token": ""},
            "body": "{\"variables\":{\"tweet_text\":\"hi\",\"reply\":{\"in_reply_to_tweet_id\":\"1\"},\"count\":20,\"dark\":false},\"queryId\":\"ID\"}",
        },
        "slots": [
            {"param": "text", "at": ["body", "json:/variables/tweet_text"]},
            {"param": "tweet_id", "at": ["body", "json:/variables/reply/in_reply_to_tweet_id"]},
            {"param": "count", "at": ["body", "json:/variables/count"]},
            {"param": "dark", "at": ["body", "json:/variables/dark"]},
            {"ref": "cookie:ct0", "at": ["header:x-csrf-token"]},
            {"ref": "cookie:JSESSIONID", "transform": "strip-quotes", "at": ["header:csrf-token"]},
            {"ref": "session:authorization", "at": ["header:authorization"]},
        ],
        "params": [
            {"name": "text"},
            {"name": "tweet_id"},
            {"name": "count", "type": "number", "default": 20},
            {"name": "dark", "type": "boolean", "required": false},
        ],
        "trigger": {"url": "https://x.com/compose"},
        "readOnly": false,
    });
    if let (Value::Object(base), Value::Object(over)) = (&mut v, over) {
        for (k, x) in over {
            base.insert(k, x);
        }
    }
    parse_op(v)
}

fn x_session() -> Session {
    session(
        vec![cookie("ct0", "csrf123", ".x.com"), cookie("JSESSIONID", "\"ajax:42\"", ".x.com"), cookie("elsewhere", "no", ".other.com")],
        &[("authorization", "Bearer PUBLIC")],
    )
}

fn empty() -> Session {
    session(vec![], &[])
}

/// A fetcher that answers from memory and keeps every request it was handed.
struct MemFetcher {
    seen: Mutex<Vec<HttpRequest>>,
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static str,
}

impl Fetcher for MemFetcher {
    fn fetch(&self, req: HttpRequest, _timeout: Duration) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        self.seen.lock().unwrap().push(req);
        let headers: Headers = self.headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let body = self.body.as_bytes().to_vec();
        let status = self.status;
        Box::pin(async move { Ok(HttpResponse { status, headers, set_cookie: vec![], body, url: String::new() }) })
    }
}

/// The real client, with the moment each request left recorded.
struct TimedFetcher {
    calls: Mutex<Vec<f64>>,
}

impl Fetcher for TimedFetcher {
    fn fetch(&self, req: HttpRequest, timeout: Duration) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        self.calls.lock().unwrap().push(now_ms());
        Box::pin(async move { default_fetcher().fetch(req, timeout).await })
    }
}

/// A small HTTP server on `host`, answering every request with `f`; returns its base URL.
async fn serve<F, Fut>(host: &str, f: F) -> String
where
    F: Fn(axum::http::Request<Body>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response> + Send + 'static,
{
    let app = axum::Router::new().fallback(f);
    let listener = tokio::net::TcpListener::bind((host, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{host}:{port}")
}

fn text(status: u16, content_type: &str, body: String) -> Response {
    Response::builder().status(status).header("content-type", content_type).body(Body::from(body)).unwrap()
}

fn redirect(status: u16, location: &str) -> Response {
    Response::builder().status(status).header("location", location).body(Body::empty()).unwrap()
}

fn header_map(h: &axum::http::HeaderMap) -> Headers {
    h.iter().map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string())).collect()
}

fn opts(site: &str, min_interval_ms: u64, fetcher: Option<Arc<dyn Fetcher>>) -> SendOptions {
    SendOptions { site: site.to_string(), fetcher, timeout_ms: None, min_interval_ms: Some(min_interval_ms) }
}

#[test]
fn build_request_fills_params_with_native_types_refs_with_transforms_and_scopes_cookies() {
    let req = build_request(
        &op(json!({})),
        &args(json!({"text": "He said \"hi\"", "tweet_id": "2085462611575857621", "count": "1234567890123456789", "dark": "false"})),
        &x_session(),
    )
    .unwrap();
    assert_eq!(req.method, "POST");
    assert_eq!(
        req.body.as_deref(),
        Some(
            "{\"variables\":{\"tweet_text\":\"He said \\\"hi\\\"\",\"reply\":{\"in_reply_to_tweet_id\":\"2085462611575857621\"},\"count\":1234567890123456789,\"dark\":false},\"queryId\":\"ID\"}"
        )
    );
    assert_eq!(req.headers.get("x-csrf-token").map(String::as_str), Some("csrf123"));
    assert_eq!(req.headers.get("csrf-token").map(String::as_str), Some("ajax:42"));
    assert_eq!(req.headers.get("authorization").map(String::as_str), Some("Bearer PUBLIC"));
    assert_eq!(req.headers.get("cookie").map(String::as_str), Some("ct0=csrf123; JSESSIONID=\"ajax:42\""));
}

#[test]
fn build_request_defaults_missing_required_params_bad_types_missing_session_values_drop_the_header() {
    let req = build_request(&op(json!({})), &args(json!({"text": "a", "tweet_id": "5"})), &empty()).unwrap();
    assert!(req.body.as_deref().unwrap().contains("\"count\":20,\"dark\":false"));
    assert!(!req.headers.contains_key("authorization"));
    assert!(!req.headers.contains_key("x-csrf-token"));
    assert_eq!(req.headers.get("cookie"), None);
    let e = build_request(&op(json!({})), &args(json!({"text": "a"})), &x_session()).unwrap_err();
    assert!(e.to_string().contains("missing required param \"tweet_id\""), "{e}");
    let e = build_request(&op(json!({})), &args(json!({"text": "a", "tweet_id": "1", "dark": "yes"})), &x_session()).unwrap_err();
    assert!(e.to_string().contains("must be boolean"), "{e}");
}

#[test]
fn a_number_past_2_53_goes_exactly_as_plain_digits_a_form_that_would_be_rounded_is_refused_saying_why() {
    let count_re = regex::Regex::new(r#""count":([^,]+),"#).unwrap();
    let sent = |count: &str| -> anyhow::Result<String> {
        let req = build_request(&op(json!({})), &args(json!({"text": "a", "tweet_id": "5", "count": count})), &x_session())?;
        Ok(count_re.captures(req.body.as_deref().unwrap()).map(|m| m[1].to_string()).unwrap_or_default())
    };
    assert_eq!(sent("9007199254740993").unwrap(), "9007199254740993");
    assert_eq!(sent("1.5e3").unwrap(), "1500");
    assert_eq!(sent("-0.25").unwrap(), "-0.25");
    let lose = regex::Regex::new(r#"param "count" would lose precision: .* past 2\^53.* plain digits"#).unwrap();
    for v in ["9007199254740993e0", "-9007199254740993e0", "9007199254740993.0", "1e400"] {
        let e = sent(v).unwrap_err();
        assert!(lose.is_match(&e.to_string()), "{v}: {e}");
    }
    // the boundary is decided on the digits: a hair past the limit rounds down to it in a double
    for v in ["9007199254740991.1", "90071992547409911e-1", "-9007199254740991.1", "9007199254740992e0"] {
        let e = sent(v).unwrap_err();
        assert!(e.to_string().contains("would lose precision"), "{v}: {e}");
    }
    // exactly at the limit, in any form, is sent as the limit
    for v in ["9007199254740991", "9007199254740991.0", "9007199254740991e0", "90071992547409910e-1"] {
        assert_eq!(sent(v).unwrap(), "9007199254740991", "{v}");
    }
    assert_eq!(sent("-9007199254740991").unwrap(), "-9007199254740991");
    assert_eq!(sent("1e-400").unwrap(), "0");
    // a mantissa longer than any number is still judged by its value, not its length
    assert_eq!(sent(&format!("0.{}1", "0".repeat(500))).unwrap(), "0");
    let e = sent(&format!("1{}e-401", "0".repeat(500))).unwrap_err();
    assert!(e.to_string().contains("would lose precision"), "{e}");
}

#[test]
fn template_slots_fill_a_substring_of_the_leaf() {
    let search = parse_op(json!({
        "name": "search",
        "request": {"method": "GET", "url": "https://a.test/s?q=from%3Anasa%20lang%3Aen&n=1", "headers": {}},
        "slots": [{"param": "user", "at": ["query:q"], "template": "from:{user} lang:en"}],
        "params": [{"name": "user"}],
        "trigger": {"url": "https://a.test/"},
        "readOnly": true,
    }));
    assert_eq!(
        build_request(&search, &args(json!({"user": "esa"})), &empty()).unwrap().url,
        "https://a.test/s?q=from%3Aesa%20lang%3Aen&n=1"
    );
}

#[tokio::test]
async fn send_injectable_fetch_returns_status_headers_body_url_ms() {
    let fetcher = Arc::new(MemFetcher {
        seen: Mutex::new(vec![]),
        status: 200,
        headers: vec![("content-type", "application/json")],
        body: "{\"ok\":true}",
    });
    let r = send(&op(json!({})), &args(json!({"text": "a", "tweet_id": "5"})), &x_session(), &opts("t1", 0, Some(fetcher.clone())))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "{\"ok\":true}");
    assert_eq!(r.headers.get("content-type").map(String::as_str), Some("application/json"));
    let seen = fetcher.seen.lock().unwrap();
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].headers.get("x-csrf-token").map(String::as_str), Some("csrf123"));
    let _ms: u64 = r.ms;
}

#[tokio::test]
async fn send_against_a_local_server_get_has_no_body_per_site_pacing_timeout() {
    let base = serve("127.0.0.1", |req: axum::http::Request<Body>| async move {
        let path = req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
        if path.starts_with("/slow") {
            tokio::time::sleep(Duration::from_millis(500)).await;
            return text(200, "text/plain", "late".to_string());
        }
        let cookie = req.headers().get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        text(200, "text/plain", format!("{} {path} {cookie}", req.method()))
    })
    .await;
    let get = parse_op(json!({
        "name": "g",
        "request": {"method": "GET", "url": format!("{base}/items?id=1"), "headers": {}},
        "slots": [{"param": "id", "at": ["query:id"]}],
        "params": [{"name": "id"}],
        "trigger": {"url": base},
        "readOnly": true,
    }));
    let local = session(vec![cookie("sid", "abc", "127.0.0.1")], &[]);
    // pacing is measured where fetch is called, so server/network jitter can't flake it
    let timed = Arc::new(TimedFetcher { calls: Mutex::new(vec![]) });
    let a = send(&get, &args(json!({"id": "123"})), &local, &opts("pace", 150, Some(timed.clone()))).await.unwrap();
    let b = send(&get, &args(json!({"id": "456"})), &local, &opts("pace", 150, Some(timed.clone()))).await.unwrap();
    assert_eq!(a.body, "GET /items?id=123 sid=abc");
    assert_eq!(b.body, "GET /items?id=456 sid=abc");
    let calls = timed.calls.lock().unwrap().clone();
    assert!(calls[1] - calls[0] >= 149.0, "paced {} ms apart", calls[1] - calls[0]);
    assert_eq!(a.url, format!("{base}/items?id=123"));

    let mut slow = get.clone();
    slow.request.url = format!("{base}/slow?id=1");
    let e = send(
        &slow,
        &args(json!({"id": "1"})),
        &local,
        &SendOptions { site: "slow".to_string(), fetcher: None, timeout_ms: Some(50), min_interval_ms: Some(0) },
    )
    .await
    .unwrap_err();
    assert!(e.to_string().contains("no response within 50 ms"), "{e}");
}

#[tokio::test]
async fn send_a_cross_origin_redirect_drops_cookie_derived_and_session_headers_same_origin_keeps_them() {
    let seen: Arc<Mutex<Headers>> = Arc::new(Mutex::new(Headers::new()));
    let seen2 = seen.clone();
    let other = serve("127.0.0.1", move |req: axum::http::Request<Body>| {
        let seen = seen2.clone();
        async move {
            *seen.lock().unwrap() = header_map(req.headers());
            text(200, "application/json", "{\"landed\":true}".to_string())
        }
    })
    .await;
    let other_url = format!("{other}/landing");
    let same_headers: Arc<Mutex<Headers>> = Arc::new(Mutex::new(Headers::new()));
    let same2 = same_headers.clone();
    let other_url2 = other_url.clone();
    let base = serve("localhost", move |req: axum::http::Request<Body>| {
        let same = same2.clone();
        let other_url = other_url2.clone();
        async move {
            let path = req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
            if path == "/away" {
                return redirect(302, &other_url);
            }
            if path == "/here" {
                return redirect(307, "/final");
            }
            *same.lock().unwrap() = header_map(req.headers());
            text(200, "application/json", "{}".to_string())
        }
    })
    .await;
    let me = |path: &str| {
        parse_op(json!({
            "name": "me",
            "readOnly": true,
            "request": {"method": "GET", "url": format!("{base}{path}"), "headers": {"x-csrf-token": "", "x-keep": "1"}},
            "slots": [{"ref": "cookie:ct0", "at": ["header:x-csrf-token"]}],
            "trigger": {"url": base},
        }))
    };
    let local = session(vec![cookie("ct0", "SECRET-CSRF-COOKIE-VALUE", "localhost")], &[]);
    let r = send(&me("/away"), &Args::new(), &local, &opts("redir", 0, None)).await.unwrap();
    assert_eq!(r.body, "{\"landed\":true}");
    assert_eq!(r.url, other_url);
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.get("x-csrf-token"), None);
        assert_eq!(seen.get("cookie"), None);
        assert_eq!(seen.get("x-keep").map(String::as_str), Some("1"));
    }
    send(&me("/here"), &Args::new(), &local, &opts("redir", 0, None)).await.unwrap();
    let same = same_headers.lock().unwrap();
    assert_eq!(same.get("x-csrf-token").map(String::as_str), Some("SECRET-CSRF-COOKIE-VALUE"));
    assert_eq!(same.get("cookie").map(String::as_str), Some("ct0=SECRET-CSRF-COOKIE-VALUE"));
}

#[test]
fn a_redirect_to_another_origin_is_refused_when_its_location_repeats_a_headers_value_however_it_is_encoded() {
    let get = op(json!({
        "readOnly": true,
        "request": {"method": "get", "url": "https://x.com/me", "headers": {"authorization": ""}},
    }));
    // a space and a literal plus, a quote and a backslash: what form and JSON encoding each treat their own way
    let v = "SECRET/a b+\"c\\d-1234";
    let held = session(vec![], &[("authorization", v)]);
    let from = Request {
        url: "https://x.com/me".to_string(),
        method: "GET".to_string(),
        headers: [("authorization".to_string(), v.to_string())].into_iter().collect(),
        body: None,
    };
    let form = url::form_urlencoded::Serializer::new(String::new()).append_pair("t", v).finish()[2..].to_string();
    let quoted = format!("\"{}\"", json_escape(v));
    let copies = [
        enc(v),
        enc(&enc(v)),
        form.clone(),
        enc(&quoted),
        enc(&quoted.replace('/', "\\/")),
        // a return address inside a return address: three decodes deep, and a form-encoded one inside a percent-encoded one
        enc(&format!("/a?next={}", enc(&format!("/b?t={}", enc(v))))),
        enc(&format!("/a?next={}", enc(&format!("/b?t={form}")))),
        b64_encode(v.as_bytes()),
        b64url_encode(v.as_bytes()),
    ];
    let prefix = "not following the HTTP 302 redirect to https://evil.example: ";
    for copy in &copies {
        let e = next_hop(&get, &held, &from, 302, &format!("https://evil.example/landing?t={copy}"), 0, MAX_REDIRECTS).unwrap_err();
        assert!(e.downcast_ref::<RedirectRefused>().is_some(), "{copy}: {e}");
        assert!(e.to_string().starts_with(prefix), "{copy}: {e}");
    }
    assert_eq!(
        next_hop(&get, &held, &from, 302, &format!("/landing?t={}", enc(v)), 0, MAX_REDIRECTS).unwrap().url,
        format!("https://x.com/landing?t={}", enc(v))
    );
    assert_eq!(j(&next_hop(&get, &held, &from, 302, "https://evil.example/landing", 0, MAX_REDIRECTS).unwrap().headers), json!({}));
}
