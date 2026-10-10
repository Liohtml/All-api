//! Port of test/edge/learner-r2.test.ts: round-2 regressions for the learner. Location echoes,
//! beacons, credentials under any name or encoding, rescan association, flag binding, concurrent
//! spec writes and trigger templating. The one browser test (web storage) is left out.
mod common;
use api_anything::heal::{AddInput, CaptureFile, FromCapture, add_operation, put_operation, rescan, templatize_url};
use api_anything::http::{Fetcher, HttpRequest, HttpResponse, SharedFetcher, build_request};
use api_anything::learn::{LearnInput, Learned, learn_operation};
use api_anything::secrets::scan_secrets;
use api_anything::session::Session;
use api_anything::spec::{Match, Operation, Request, Trigger};
use api_anything::store::{export_site, load_site, save_site, update_site};
use api_anything::types::{Exchange, Headers, StoredCookie};
use api_anything::util::{b64_encode, b64url_encode, iso_now};
use common::{Home, args, enc, ex, j, no_session, site};
use futures_util::future::BoxFuture;
use indexmap::IndexMap;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use url::Url;

static HOME: LazyLock<Home> = LazyLock::new(Home::new);

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn xhr_res(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>, res_body: &str, content_type: &str) -> Exchange {
    let mut req = json!({"method": method, "url": url, "headers": headers.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<_, _>>()});
    if let Some(b) = body {
        req["body"] = json!(b);
    }
    ex(json!({"id": NEXT_ID.fetch_add(1, Ordering::SeqCst), "resourceType": "fetch", "request": req,
        "response": {"status": 200, "headers": {}, "contentType": content_type, "body": res_body}}))
}

/// `xhr({...}, resBody)` with a JSON answer; the default is `{results:[{id:1},{id:2}]}`.
fn xhr_json(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>, res_body: Value) -> Exchange {
    xhr_res(method, url, headers, body, &res_body.to_string(), "application/json")
}

fn xhr(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>) -> Exchange {
    xhr_json(method, url, headers, body, json!({"results": [{"id": 1}, {"id": 2}]}))
}

fn get(url: &str) -> Exchange {
    xhr("GET", url, &[], None)
}

fn get_with(url: &str, headers: &[(&str, &str)]) -> Exchange {
    xhr("GET", url, headers, None)
}

fn post_json(url: &str, headers: &[(&str, &str)], body: Value) -> Exchange {
    let mut h = vec![("content-type", "application/json")];
    h.extend_from_slice(headers);
    xhr("POST", url, &h, Some(&body.to_string()))
}

fn doc(url: &str, body: &str) -> Exchange {
    let mut e = xhr_res("GET", url, &[], None, body, "text/html");
    e.resource_type = "document".into();
    e
}

fn script(url: &str, body: &str) -> Exchange {
    let mut e = xhr_res("GET", url, &[], None, body, "application/javascript");
    e.resource_type = "script".into();
    e
}

fn trigger(url: &str) -> Trigger {
    Trigger { url: url.to_string(), steps: None, soft_from: None }
}

fn input(exchanges: Vec<Exchange>, examples: Vec<Value>) -> LearnInput {
    LearnInput::new(exchanges, examples.into_iter().map(args).collect(), "op", trigger("https://site.test/"), true)
}

fn learn(exchanges: Vec<Exchange>, examples: Vec<Value>) -> Learned {
    learn_operation(&input(exchanges, examples)).unwrap()
}

fn err(i: &LearnInput) -> String {
    format!("Error: {}", learn_operation(i).unwrap_err())
}

fn assert_match(text: &str, pattern: &str, what: &str) {
    assert!(regex::Regex::new(pattern).unwrap().is_match(text), "{what}: {text:?} does not match /{pattern}/");
}

fn cookie(name: &str, value: &str) -> StoredCookie {
    let mut c = StoredCookie::new(name, value, "site.test");
    c.http_only = true;
    c
}

fn storage(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn with_values(cookies: Vec<StoredCookie>, values: &IndexMap<String, String>) -> Session {
    Session::with(cookies, values.clone())
}

fn jar(cookies: Vec<StoredCookie>) -> Session {
    Session::with(cookies, IndexMap::new())
}

fn built(op: &Operation, a: Value, s: &Session) -> Request {
    build_request(op, &args(a), s).unwrap()
}

fn m(v: Value) -> Match {
    serde_json::from_value(v).unwrap()
}

fn spec_text(op: &Operation) -> String {
    serde_json::to_string(op).unwrap()
}

fn q(req: &Request, k: &str) -> Option<String> {
    Url::parse(&req.url).unwrap().query_pairs().find(|(a, _)| a == k).map(|(_, v)| v.into_owned())
}

fn save_as(name: &str, base_url: &str, op: &Operation) {
    let _ = &*HOME;
    save_site(&site(json!({"name": name, "baseUrl": base_url, "operations": [j(op)]}))).unwrap();
}

/* ------------------------------------------------- LC-01: location echoes */

fn page() -> Exchange {
    doc("https://site.test/facebook/react", "<html></html>")
}

fn echo_refused(e: Exchange) {
    let mut i = input(vec![page(), e], vec![json!({"repo": "facebook/react"})]);
    i.matcher = Some(m(json!({"path": "/repos/*/*"})));
    assert_match(&err(&i), "not in the learned request", "an echo of the page's location");
}

#[test]
fn location_echo_analytics_context_page_url_in_the_body() {
    echo_refused(post_json("https://api.site.test/repos/facebook/react", &[], json!({"context": {"page": {"url": "https://site.test/facebook/react"}}})));
}

#[test]
fn location_echo_an_x_page_path_header() {
    echo_refused(get_with("https://api.site.test/repos/facebook/react", &[("x-page-path", "/facebook/react")]));
}

#[test]
fn location_echo_a_src_query_param_holding_the_page_url() {
    echo_refused(get(&format!("https://api.site.test/repos/facebook/react?src={}", enc("https://site.test/facebook/react"))));
}

#[test]
fn location_echo_a_twice_encoded_redirect_param() {
    echo_refused(get(&format!("https://api.site.test/repos/facebook/react?redirect={}", enc(&enc("https://site.test/facebook/react")))));
}

#[test]
fn the_page_url_is_also_known_from_the_filled_trigger_when_the_capture_has_no_document() {
    let e = get_with("https://api.site.test/repos/facebook/react", &[("x-page-path", "/facebook/react")]);
    let mut i = input(vec![e], vec![json!({"repo": "facebook/react"})]);
    i.matcher = Some(m(json!({"path": "/repos/*/*"})));
    i.trigger = trigger("https://site.test/{repo}");
    assert_match(&err(&i), "not in the learned request", "filled trigger");
}

#[test]
fn control_a_request_that_carries_the_value_itself_still_learns_and_its_echo_follows_the_arg() {
    let e = get_with("https://api.site.test/search?q=react", &[("x-page-path", "/search?q=react")]);
    let op = learn(vec![doc("https://site.test/search?q=react", "<html></html>"), e], vec![json!({"q": "react"})]).operation;
    let r = built(&op, json!({"q": "vue"}), &no_session());
    assert_eq!(q(&r, "q").as_deref(), Some("vue"));
    assert_eq!(r.headers["x-page-path"], "/search?q=vue");
}

/* --------------------------------------------------- Product Hunt beacons */

#[test]
fn a_segment_style_beacon_echoing_the_page_is_not_learned_over_the_ssr_document_product_hunt() {
    let page = doc("https://www.site.test/search?q=notion", &format!("<html><body>{}</body></html>", "<li class=\"p\">Notion</li>".repeat(50)));
    let beacon = xhr_json(
        "POST",
        "https://e.site.test/v1/p",
        &[("content-type", "application/json"), ("referer", "https://www.site.test/search?q=notion")],
        Some(
            &json!({
                "type": "page",
                "properties": {"path": "/search", "search": "?q=notion", "url": "https://www.site.test/search?q=notion"},
                "context": {"page": {"search": "?q=notion", "url": "https://www.site.test/search?q=notion"}}
            })
            .to_string(),
        ),
        json!({"success": true}),
    );
    let mut i = input(vec![page.clone(), beacon], vec![json!({"q": "notion"})]);
    i.trigger = trigger("https://www.site.test/search?q={q}");
    let r = learn_operation(&i).unwrap();
    assert_eq!(r.exchange.id, page.id, "learned {}", r.exchange.request.url);
}

#[test]
fn an_ack_answer_success_true_ranks_below_a_real_answer_even_when_it_carries_the_value_exactly() {
    let page = doc("https://www.site.test/search?q=notion", &format!("<html>{}</html>", "<p>notion</p>".repeat(40)));
    let beacon = xhr_json(
        "POST",
        "https://e.site.test/v1/t",
        &[("content-type", "application/json")],
        Some(&json!({"event": "search", "properties": {"term": "notion"}}).to_string()),
        json!({"success": true}),
    );
    assert_eq!(learn(vec![page.clone(), beacon], vec![json!({"q": "notion"})]).exchange.id, page.id);
}

/* -------------------------------------------- LC-03: credentials, any name */

const TOKEN: &str = "Zx81kLmN0pQrStUv2wXyZ3aBcD";

fn credential_stays_out(e: Exchange, name: &str) {
    let learned = learn(vec![e], vec![json!({"q": "kittens"})]);
    let op = &learned.operation;
    assert!(!spec_text(op).contains(TOKEN), "the token is literal in the spec");
    assert_eq!(learned.session_values.get(&format!("op/{name}")).map(String::as_str), Some(TOKEN), "its value goes to the session store");
    let sent = serde_json::to_string(&built(op, json!({"q": "cats"}), &with_values(vec![], &learned.session_values))).unwrap();
    assert!(sent.contains(TOKEN), "a call sends it from the session store");
}

#[test]
fn credential_auth_token_query() {
    credential_stays_out(get(&format!("https://api.site.test/v1/search?q=kittens&auth_token={TOKEN}")), "auth_token");
}

#[test]
fn credential_api_key_query() {
    credential_stays_out(get(&format!("https://api.site.test/v1/search?q=kittens&api_key={TOKEN}")), "api_key");
}

#[test]
fn credential_sid_query() {
    credential_stays_out(get(&format!("https://api.site.test/v1/search?q=kittens&sid={TOKEN}")), "sid");
}

#[test]
fn credential_refresh_token_json() {
    credential_stays_out(post_json("https://api.site.test/v1/search", &[], json!({"q": "kittens", "refresh_token": TOKEN})), "refresh_token");
}

#[test]
fn credential_auth_token_camel_json() {
    credential_stays_out(post_json("https://api.site.test/v1/search", &[], json!({"q": "kittens", "authToken": TOKEN})), "authToken");
}

#[test]
fn credential_id_token_form() {
    credential_stays_out(
        xhr("POST", "https://api.site.test/v1/search", &[("content-type", "application/x-www-form-urlencoded")], Some(&format!("q=kittens&id_token={TOKEN}"))),
        "id_token",
    );
}

#[test]
fn credential_x_api_key_header() {
    credential_stays_out(get_with("https://api.site.test/v1/search?q=kittens", &[("x-api-key", TOKEN)]), "x-api-key");
}

#[test]
fn credential_x_session_id_header() {
    credential_stays_out(get_with("https://api.site.test/v1/search?q=kittens", &[("x-session-id", TOKEN)]), "x-session-id");
}

#[test]
fn a_value_the_page_keeps_in_local_storage_inside_a_json_entry_under_a_plain_name_is_a_session_ref() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2lnbmF0dXJl";
    let auth = json!({"access_token": jwt, "expires_at": 1}).to_string();
    let e = post_json("https://api.site.test/v1/search", &[("x-user", jwt)], json!({"q": "kittens", "u": format!("v1:{jwt}")}));
    let mut i = input(vec![e], vec![json!({"q": "kittens"})]);
    i.storage = Some(storage(&[("sb-proj-auth", &auth), ("theme", "dark")]));
    let learned = learn_operation(&i).unwrap();
    let op = &learned.operation;
    assert!(!spec_text(op).contains(jwt));
    let refs: Vec<Value> = op.slots.iter().filter(|s| s.is_ref()).map(|s| json!([s.ref_str(), s.at.join(" > ")])).collect();
    assert_eq!(refs, vec![json!(["session:op/sb-proj-auth/access_token", "header:x-user"]), json!(["session:op/sb-proj-auth/access_token", "body > json:/u"])]);
    assert_eq!(learned.session_values["op/sb-proj-auth/access_token"], jwt);
    let r = built(op, json!({"q": "cats"}), &with_values(vec![], &learned.session_values));
    assert_eq!(r.headers["x-user"], jwt);
    assert_eq!(serde_json::from_str::<Value>(r.body.as_ref().unwrap()).unwrap(), json!({"q": "cats", "u": format!("v1:{jwt}")}));
}

#[test]
fn a_credential_named_key_the_site_ships_in_its_own_js_is_public_kept_literal_listed_and_export_allows_it() {
    let key = "d306zoyjsyarp7ifhu67rjxn52tv0t20";
    let e = get_with("https://api.site.test/v1/search?q=kittens", &[("x-site-api-key", key)]);
    let op = learn(vec![script("https://site.test/main.js", &format!("var cfg={{apiKey:\"{key}\"}};")), e], vec![json!({"q": "kittens"})]).operation;
    assert_eq!(op.request.headers["x-site-api-key"], key);
    assert_eq!(j(&op.public), json!(["x-site-api-key"]));
    save_as("shipped", "https://site.test", &op);
    assert_eq!(export_site("shipped", false).unwrap().secrets, Vec::<String>::new());
}

#[test]
fn public_hashes_traceparent_and_client_versions_are_not_credentials() {
    let hash = "e0f2a1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";
    let trace = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let e = get_with(
        &format!(
            "https://site.test/api/v3/StaysSearch/{hash}?operationName=StaysSearch&variables={}&extensions={}",
            enc(r#"{"q":"paris"}"#),
            enc(&json!({"persistedQuery": {"version": 1, "sha256Hash": hash}}).to_string())
        ),
        &[("traceparent", trace), ("x-client-version", "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"), ("x-client-request-id", "0x9f8e7d6c5b4a39281706f5e4d3c2b1a0")],
    );
    let op = learn(vec![e], vec![json!({"q": "paris"})]).operation;
    assert_eq!(op.slots.iter().filter(|s| s.is_ref()).map(j).collect::<Vec<_>>(), Vec::<Value>::new());
    assert_eq!(op.request.headers["traceparent"], trace);
    assert!(op.request.url.contains(hash));
}

#[test]
fn export_refuses_a_credential_named_literal_in_a_hand_written_spec_and_allows_it_once_marked_public() {
    let op = learn(vec![get("https://api.site.test/v1/search?q=kittens")], vec![json!({"q": "kittens"})]).operation;
    let mut leaky = op.clone();
    leaky.request.url = format!("https://api.site.test/v1/search?q=kittens&api_key={TOKEN}");
    leaky.request.headers = [("x-auth-token".to_string(), TOKEN.to_string())].into_iter().collect();
    save_as("leaky", "https://api.site.test", &leaky);
    let r = export_site("leaky", false).unwrap();
    assert_eq!(r.secrets.len(), 2, "{}", r.secrets.join("\n"));
    assert!(r.secrets.iter().any(|s| s.contains("api_key")) && r.secrets.iter().any(|s| s.contains("x-auth-token")));
    let mut public = leaky.clone();
    public.public = Some(vec!["api_key".into(), "x-auth-token".into()]);
    save_as("leaky", "https://api.site.test", &public);
    assert_eq!(export_site("leaky", false).unwrap().secrets, Vec::<String>::new());
}

/* ------------------------------------------- cookies in every encoding */

const COOKIE: &str = "q2Fz/9kLmT0vX+Yb7NcW1pRe/Hs3JuQa8Df+Lg6ZoVy4=";

#[test]
fn a_cookie_inside_a_twice_encoded_next_url_is_a_templated_ref_refilled_at_the_same_depth() {
    let url = format!("https://site.test/api/data?name=alice&next={}", enc(&format!("/cb?auth={}", enc(COOKIE))));
    let cookies = || vec![cookie("tok", COOKIE)];
    let e = get_with(&url, &[("cookie", &format!("tok={COOKIE}"))]);
    let mut i = LearnInput::new(vec![e], vec![args(json!({"name": "alice"}))], "op", trigger("https://site.test/p?name={name}"), true);
    i.cookies = cookies();
    let op = learn_operation(&i).unwrap().operation;
    let spec = spec_text(&op);
    for f in [COOKIE.to_string(), enc(COOKIE), enc(&enc(COOKIE))] {
        assert!(!spec.contains(&f), "cookie in the spec as {f}");
    }
    assert_eq!(built(&op, json!({"name": "alice"}), &jar(cookies())).url, url);
}

#[test]
fn a_leaf_holding_both_an_arg_and_a_credential_next_search_q_arg_auth_cookie_keeps_the_credential_a_ref() {
    let next = |q: &str, tok: &str| enc(&format!("/search?q={q}&auth={}", enc(tok)));
    let url = |q: &str, tok: &str| format!("https://site.test/api/data?name={q}&next={}", next(q, tok));
    const COOKIE2: &str = "Zx9/Qw8vLm7+Kj6HgF5dS4aP3oI2uY1t";
    let mut i = LearnInput::new(
        vec![get_with(&url("alice", COOKIE), &[("cookie", &format!("tok={COOKIE}"))])],
        vec![args(json!({"name": "alice"})), args(json!({"name": "bob"}))],
        "op",
        trigger("https://site.test/p?name={name}"),
        true,
    );
    i.exchanges2 = Some(vec![get_with(&url("bob", COOKIE2), &[("cookie", &format!("tok={COOKIE2}"))])]);
    i.cookies = vec![cookie("tok", COOKIE)];
    let learned = learn_operation(&i).unwrap();
    let op = &learned.operation;
    let spec = spec_text(op);
    for f in [COOKIE.to_string(), enc(COOKIE), enc(&enc(COOKIE))] {
        assert!(!spec.contains(&f), "cookie in the spec as {f}");
    }
    assert_eq!(op.min_tier, 1, "the session hole is no nonce: {}", learned.warnings.join("; "));
    assert!(!learned.warnings.iter().any(|w| w.contains("run 2 has")), "{}", learned.warnings.join("; "));
    assert_eq!(built(op, json!({"name": "carol"}), &jar(vec![cookie("tok", COOKIE2)])).url, url("carol", COOKIE2));
    // a session value in the same place is refilled from the session store
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2lnbmF0dXJl";
    let mut i = input(vec![get(&format!("https://site.test/api/data?name=alice&next={}", next("alice", jwt)))], vec![json!({"name": "alice"})]);
    i.storage = Some(storage(&[("at", jwt)]));
    i.trigger = trigger("https://site.test/p?name={name}");
    let s = learn_operation(&i).unwrap();
    assert!(!spec_text(&s.operation).contains(&enc(jwt)));
    assert_eq!(s.session_values["op/at"], jwt);
    assert_eq!(
        built(&s.operation, json!({"name": "bob"}), &with_values(vec![], &s.session_values)).url,
        format!("https://site.test/api/data?name=bob&next={}", next("bob", jwt))
    );
}

#[test]
fn the_secret_scan_finds_a_live_value_percent_encoded_once_or_twice_json_escaped_u_escaped_and_base64d() {
    let tok = "ab/cd+ef12=";
    let s = jar(vec![cookie("sid", tok)]);
    let t = json!({"t": tok}).to_string();
    let forms: Vec<(&str, String)> = vec![
        ("pct", format!("https://s.test/api?x={}", enc(tok))),
        ("doublePct", format!("https://s.test/api?next={}", enc(&format!("/cb?t={}", enc(tok))))),
        ("jsonEscapedThenPct", format!("https://s.test/api?v={}", enc(&t.replace('/', "\\/")))),
        ("base64", format!("https://s.test/api?state={}", b64_encode(t.as_bytes()))),
        ("base64url", format!("https://s.test/api?state={}", b64url_encode(t.as_bytes()))),
        ("unicodeEscape", json!({"t": tok.replace('+', "\\u002b")}).to_string()),
        ("strayPercent", format!("100% of https://s.test/api?x={}", enc(tok))),
    ];
    for (k, v) in forms {
        assert!(!scan_secrets(&json!({"url": v}), &s, &HashSet::new()).secrets.is_empty(), "missed {k}");
    }
    assert_eq!(scan_secrets(&json!({"url": "https://s.test/api?x=abcdef"}), &s, &HashSet::new()).secrets, Vec::<String>::new(), "control");
}

#[test]
fn export_flags_a_literal_ip_address_innertube_remote_host_not_versions_or_loopback() {
    let body = json!({
        "context": {"client": {"remoteHost": "203.0.113.7", "clientVersion": "2.20260927.01.00", "ip6": "2001:db8::7"}},
        "query": "kittens"
    });
    let op = learn(
        vec![post_json("https://www.site.test/youtubei/v1/search", &[("user-agent", "Chrome/140.0.0.0"), ("x-forwarded-for", "127.0.0.1")], body)],
        vec![json!({"query": "kittens"})],
    )
    .operation;
    save_as("ip", "https://www.site.test", &op);
    let ips: Vec<String> = export_site("ip", false).unwrap().warnings.into_iter().filter(|w| w.contains("IP address")).collect();
    assert_eq!(ips.len(), 2, "{}", ips.join("\n"));
    assert!(ips[0].contains("203.0.113.7") && ips[1].contains("2001:db8::7"));
}

/* ------------------------------------------------------- LC-07: one flag */

#[test]
fn a_boolean_example_never_binds_to_a_lone_flag_under_another_key() {
    let e = post_json("https://api.site.test/gql", &[], json!({"variables": {"screen_name": "nasa", "withVoice": true}}));
    assert_match(&err(&input(vec![e], vec![json!({"screen_name": "nasa", "includeReplies": true})])), r#"none with the key "includeReplies""#, "lone flag");
    let own = post_json("https://api.site.test/gql", &[], json!({"variables": {"screen_name": "nasa", "includeReplies": true}}));
    let op = learn(vec![own], vec![json!({"screen_name": "nasa", "includeReplies": true})]).operation;
    assert_eq!(op.slots.iter().find(|s| s.param.as_deref() == Some("includeReplies")).map(|s| s.at.clone()), Some(vec!["body".to_string(), "json:/variables/includeReplies".to_string()]));
}

/* ---------------------------------------------- HEAL-2/3: rescan variants */

/// The TS `fetchImpl` closures: a fetcher that answers from memory.
struct FnFetcher(Arc<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>);

impl Fetcher for FnFetcher {
    fn fetch(&self, req: HttpRequest, _timeout: Duration) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        let r = (self.0)(&req);
        Box::pin(async move { Ok(r) })
    }
}

fn fetch_impl(f: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static) -> SharedFetcher {
    Arc::new(FnFetcher(Arc::new(f)))
}

/// `new Response(body, { status, headers: { "content-type": ... } })`; a bare `new Response(text)` is text/plain.
fn response(status: u16, content_type: &str, body: &str) -> HttpResponse {
    let mut headers = Headers::new();
    headers.insert("content-type".into(), content_type.into());
    HttpResponse { status, headers, set_cookie: vec![], body: body.as_bytes().to_vec(), url: String::new() }
}

/// The `run(bundle, readOnly)` of the "rescan associates the token with the anchor's own module" describe.
async fn rescan_run(bundle: &str, read_only: bool) -> Option<String> {
    let _ = &*HOME;
    let bundle = bundle.to_string();
    let fetcher = fetch_impl(move |req: &HttpRequest| {
        if req.url.ends_with("/app.js") {
            response(200, "text/plain;charset=UTF-8", &bundle)
        } else {
            response(200, "text/plain;charset=UTF-8", "<html><script src=\"/app.js\"></script></html>")
        }
    });
    let op = site(json!({
        "name": "s",
        "baseUrl": "https://s.example",
        "operations": [{
            "name": "q",
            "readOnly": read_only,
            "request": { "method": "POST", "url": "https://s.example/graphql/query", "headers": {}, "body": format!("doc_id={}&fb_api_req_friendly_name=ProfileQuery", "1".repeat(16)) },
            "volatile": [{ "at": ["form:doc_id"], "shape": { "charset": "digits", "length": 16 }, "anchor": "ProfileQuery" }],
            "trigger": { "url": "https://s.example/p" },
        }],
    }))
    .operations
    .remove(0);
    rescan("s", &op, &args(json!({})), Some(fetcher)).await.unwrap().map(|r| r.diff.split("-> ").nth(1).unwrap().to_string())
}

const DOC_A: &str = "2222222222222222";
const DOC_B: &str = "3333333333333333";
const DOC_C: &str = "4444444444444444";

#[tokio::test]
async fn rescan_associates_the_token_with_the_anchors_own_module_meta_modules_with_use_strict_inside() {
    let bundle = format!(
        "__d(\"FeedQuery_instagramRelayOperation\",[],(function(a,b,c,d,e,f){{\"use strict\";e.exports=\"{DOC_A}\"}}),null);__d(\"ProfileQuery_instagramRelayOperation\",[],(function(a,b,c,d,e,f){{\"use strict\";e.exports=\"{DOC_B}\"}}),null);"
    );
    assert_eq!(rescan_run(&bundle, true).await.as_deref(), Some(DOC_B));
    assert_eq!(rescan_run(&bundle, false).await.as_deref(), Some(DOC_B));
}

#[tokio::test]
async fn rescan_associates_the_token_with_the_anchors_own_module_the_anchor_also_named_in_another_statement_a_log_message_next_to_another_id()
 {
    let bundle = format!(
        "log(\"ProfileQuery failed\",{{doc:\"{DOC_C}\"}});__d(\"ProfileQuery_instagramRelayOperation\",[],(function(a,b,c,d,e,f){{e.exports=\"{DOC_B}\"}}),null);"
    );
    assert_eq!(rescan_run(&bundle, true).await.as_deref(), Some(DOC_B));
    assert_eq!(rescan_run(&bundle, false).await.as_deref(), Some(DOC_B));
}

#[tokio::test]
async fn rescan_associates_the_token_with_the_anchors_own_module_an_array_of_records_id_first_the_anchors_own_record() {
    assert_eq!(
        rescan_run(
            &format!(
                "[{{id:\"{DOC_A}\",name:\"FeedQuery\"}},{{id:\"{DOC_B}\",name:\"ProfileQuery\"}},{{id:\"{DOC_C}\",name:\"StoryQuery\"}}]"
            ),
            true
        )
        .await
        .as_deref(),
        Some(DOC_B)
    );
}

/* ----------------------------------------------- EC-19: concurrent writes */

#[tokio::test]
async fn an_add_saves_under_the_site_lock_with_a_fresh_read_so_a_concurrent_adds_op_survives() {
    let _ = &*HOME;
    // Run 1 and run 2 differ in a nonce, so add replays the template once (an await) before saving;
    // another add lands during that replay.
    let capture = |q: &str, nonce: &str| -> CaptureFile {
        let url = format!("https://site.test/search?q={q}");
        serde_json::from_value(json!({
            "id": format!("c{}", NEXT_ID.fetch_add(1, Ordering::SeqCst)),
            "at": iso_now(),
            "url": url,
            "exchanges": [get(&format!("https://site.test/api/search?q={q}&n={nonce}"))],
            "cookies": [],
            "finalUrl": url,
        }))
        .unwrap()
    };
    let mut i = input(vec![get("https://site.test/api/user?name=alice")], vec![json!({"name": "alice"})]);
    i.name = "user".into();
    let other: Operation = learn_operation(&i).unwrap().operation;
    let fetcher = fetch_impl(move |_req: &HttpRequest| {
        let o = other.clone();
        update_site("race", move |s| {
            Ok(put_operation(&s.unwrap_or_else(|| site(json!({"name": "race", "baseUrl": "https://site.test", "operations": []}))), o))
        })
        .unwrap();
        response(200, "application/json", &json!({"results": [{"id": 1}, {"id": 2}]}).to_string())
    });
    let r = add_operation(AddInput {
        site: "race".into(),
        op: "search".into(),
        trigger: None,
        examples: vec![args(json!({"q": "hello"})), args(json!({"q": "world"}))],
        matcher: None,
        write: false,
        description: None,
        response: None,
        public: None,
        from: Some(FromCapture { capture: capture("hello", "Zq81kPq0aB3dF7"), id: None }),
        from2: Some(capture("world", "Mm4nR7sT1uV5wX")),
        fetcher: Some(fetcher),
    })
    .await
    .unwrap();
    assert!(!r.replaced);
    let mut names: Vec<String> = load_site("race").unwrap().unwrap().site.operations.iter().map(|o| o.name.clone()).collect();
    names.sort();
    assert_eq!(names, vec!["search", "user"]);
}

/* ------------------------------------------------- LC-02: trigger template */

#[test]
fn a_value_equal_to_a_path_segment_and_to_a_query_value_under_another_key_templates_both() {
    assert_eq!(templatize_url("https://s.test/u/nasa?tab=nasa", &args(json!({"name": "nasa"}))), "https://s.test/u/{name}?tab={name}");
    assert_eq!(
        templatize_url("https://s.test/r/python/search?q=python", &args(json!({"q": "python"}))),
        "https://s.test/r/python/search?q={q}",
        "a key named like the param is its position"
    );
}
