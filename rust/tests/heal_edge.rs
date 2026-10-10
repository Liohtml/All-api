//! Port of test/edge/heal.test.ts: edge-case probes for self-healing (src/heal.rs, src/execute.rs).
//! The first half injects a fetcher with maxTier 1 (no browser); the second half runs recapture
//! against small local servers in the installed Chrome. Tests that fail assert the correct
//! behaviour and name the bug they expose.
mod common;
use api_anything::classify::Class;
use api_anything::execute::{CallOptions, call, heal};
use api_anything::heal::{AddInput, Recipe, add_operation, rescan};
use api_anything::http::{Fetcher, HttpRequest, HttpResponse, SharedFetcher};
use api_anything::session::{Session, load_session, save_session};
use api_anything::spec::{Operation, Site, Trigger, parse_site, parse_steps};
use api_anything::store::{Bundled, STALE_TTL_MS, Source, Strategy, load_site, load_site_from, mark_stale, save_site, stale_mark};
use api_anything::types::Headers;
use api_anything::util::now_ms;
use axum::body::Body;
use axum::http::request::Parts;
use axum::response::Response;
use common::{Home, args, j};
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use url::Url;

static HOME: LazyLock<Home> = LazyLock::new(Home::new);
/// The TS file runs its tests one after the other under one home, and `beforeEach` wipes the state.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Debug)]
struct Seen {
    url: String,
    method: String,
}
static SEEN: Mutex<Vec<Seen>> = Mutex::new(Vec::new());

fn seen() -> Vec<Seen> {
    SEEN.lock().unwrap().clone()
}

fn clear_seen() {
    SEEN.lock().unwrap().clear();
}

type Handler = Arc<dyn Fn(&str, &HttpRequest) -> HttpResponse + Send + Sync>;

/// The TS `fake(h)`: a fetcher that answers from `h` and records every request in `seen`.
struct Fake(Handler);

impl Fetcher for Fake {
    fn fetch(&self, req: HttpRequest, _timeout: Duration) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        SEEN.lock().unwrap().push(Seen { url: req.url.clone(), method: req.method.clone() });
        let r = (self.0)(&req.url, &req);
        Box::pin(async move { Ok(r) })
    }
}

fn fake(h: impl Fn(&str, &HttpRequest) -> HttpResponse + Send + Sync + 'static) -> SharedFetcher {
    Arc::new(Fake(Arc::new(h)))
}

fn response(status: u16, content_type: Option<&str>, body: &str, extra: &[(&str, &str)]) -> HttpResponse {
    let mut headers = Headers::new();
    if let Some(ct) = content_type {
        headers.insert("content-type".into(), ct.into());
    }
    for (k, v) in extra {
        headers.insert(k.to_string(), v.to_string());
    }
    HttpResponse { status, headers, set_cookie: vec![], body: body.as_bytes().to_vec(), url: String::new() }
}

/// `json(v, status)`
fn json_res(v: Value, status: u16) -> HttpResponse {
    response(status, Some("application/json"), &v.to_string(), &[])
}

/// `html(s, status)`
fn html(s: &str, status: u16) -> HttpResponse {
    response(status, Some("text/html"), s, &[])
}

/// `new Response(s)`: Node gives a string body `text/plain;charset=UTF-8`.
fn text(s: &str) -> HttpResponse {
    response(200, Some("text/plain;charset=UTF-8"), s, &[])
}

/// `new Response("", { status })`
fn empty(status: u16) -> HttpResponse {
    response(status, Some("text/plain;charset=UTF-8"), "", &[])
}

/// `new Response(null, { status, headers: { location } })`
fn redirect(status: u16, location: &str) -> HttpResponse {
    response(status, None, "", &[("location", location)])
}

fn tier1(h: impl Fn(&str, &HttpRequest) -> HttpResponse + Send + Sync + 'static) -> CallOptions {
    CallOptions { fetcher: Some(fake(h)), max_tier: Some(1), min_interval_ms: Some(0), ..Default::default() }
}

fn with_writes(mut o: CallOptions) -> CallOptions {
    o.allow_writes = true;
    o
}

fn heals() -> Vec<Value> {
    match fs::read_to_string(HOME.path().join("heals.jsonl")) {
        Ok(t) => t.trim().split('\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect(),
        Err(_) => vec![],
    }
}

fn strategies() -> Vec<String> {
    heals().iter().map(|h| h["strategy"].as_str().unwrap().to_string()).collect()
}

fn last_diff() -> String {
    heals().last().and_then(|h| h["diff"].as_str().map(|s| s.to_string())).unwrap_or_default()
}

fn set_state(patch: impl FnOnce(&mut Value)) {
    let file = HOME.path().join("state.json");
    let s: Value = fs::read_to_string(&file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}));
    let mut full = json!({
        "stale": s.get("stale").cloned().unwrap_or(json!({})),
        "tier": s.get("tier").cloned().unwrap_or(json!({})),
        "healedAt": s.get("healedAt").cloned().unwrap_or(json!({})),
    });
    patch(&mut full);
    fs::write(&file, full.to_string()).unwrap();
}

fn re(s: &str, pattern: &str) -> bool {
    regex::Regex::new(pattern).unwrap().is_match(s)
}

fn stale(site: &str, op: &str) -> Option<api_anything::store::StaleMark> {
    stale_mark(site, op, now_ms())
}

fn query(u: &Url, k: &str) -> Option<String> {
    u.query_pairs().find(|(a, _)| a == k).map(|(_, v)| v.into_owned())
}

const OLD: &str = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7H";
const NEW: &str = "Zz9Yy8Xx7Ww6Vv5Uu4Tt3S";
const NEWER: &str = "Qq1Ww2Ee3Rr4Tt5Yy6Uu7I";

/// X-style: queryId in the path, operationName as the next segment. `extra` overrides op fields.
fn user_site(name: &str, extra: Value) -> Site {
    let mut op = json!({
        "name": "user",
        "readOnly": true,
        "request": { "method": "GET", "url": format!("https://t.test/api/{OLD}/User?name=alice"), "headers": {} },
        "slots": [{ "param": "name", "at": ["query:name"] }],
        "volatile": [{ "at": ["path:1"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "User" }],
        "trigger": { "url": "https://t.test/u/{name}" },
        "match": { "method": "GET", "path": "/api/*/User" },
        "params": [{ "name": "name", "example": "alice" }],
        "response": { "extract": "user" },
    });
    if let (Value::Object(o), Value::Object(e)) = (&mut op, extra) {
        for (k, v) in e {
            o.insert(k, v);
        }
    }
    parse_site(&json!({ "name": name, "baseUrl": "https://t.test", "operations": [op] })).unwrap()
}

/// A site whose bundle names the current id and whose API answers only that id.
fn rotating_handler(
    cur: impl Fn() -> String + Send + Sync + 'static,
) -> impl Fn(&str, &HttpRequest) -> HttpResponse + Send + Sync + 'static {
    move |url: &str, _req: &HttpRequest| {
        if url.starts_with("https://t.test/u/") {
            return html("<html><script src=\"/static/main.js\"></script></html>", 200);
        }
        if url == "https://t.test/static/main.js" {
            return text(&format!("var ops=[{{queryId:\"{}\",operationName:\"User\",operationType:\"query\"}}];", cur()));
        }
        let u = Url::parse(url).unwrap();
        if u.path() == format!("/api/{}/User", cur()) {
            return json_res(json!({ "user": { "name": query(&u, "name") } }), 200);
        }
        if u.path().starts_with("/api/") {
            return empty(404);
        }
        empty(404)
    }
}

/// `beforeEach`: a clean state, heal log and session store, and no request seen yet.
async fn fresh() -> tokio::sync::MutexGuard<'static, ()> {
    let g = LOCK.lock().await;
    let home = HOME.path();
    let _ = fs::remove_file(home.join("state.json"));
    let _ = fs::remove_file(home.join("heals.jsonl"));
    let _ = fs::remove_dir_all(home.join("sessions"));
    clear_seen();
    g
}

fn first_op(site: &str) -> Operation {
    load_site(site).unwrap().unwrap().site.operations.remove(0)
}

/* ------------------------------------------------ heal without a browser (maxTier 1) */

#[tokio::test]
async fn single_rotation_heals_by_rescan_the_stored_template_is_sent_first() {
    let _g = fresh().await;
    save_site(&user_site("rot1", json!({}))).unwrap();
    let r = call("rot1", "user", args(json!({"name": "bob"})), tier1(rotating_handler(|| NEW.to_string()))).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(r.healed, Some(true));
    assert_eq!(r.data, Some(json!({"name": "bob"})));
    assert!(seen()[0].url.contains(&format!("/api/{OLD}/User")), "healing is reactive: the stored template goes first");
    assert!(first_op("rot1").request.url.contains(NEW));
}

#[tokio::test]
async fn repeated_rotation_a_second_rotation_more_than_10_min_after_the_first_heal_heals_again() {
    let _g = fresh().await;
    save_site(&user_site("rot2", json!({}))).unwrap();
    let cur = Arc::new(Mutex::new(NEW.to_string()));
    let c = cur.clone();
    let current = move || c.lock().unwrap().clone();
    assert_eq!(call("rot2", "user", args(json!({"name": "bob"})), tier1(rotating_handler(current.clone()))).await.healed, Some(true));
    set_state(|s| s["healedAt"]["rot2/user"] = json!(now_ms() - 11.0 * 60_000.0));
    *cur.lock().unwrap() = NEWER.to_string();
    let r = call("rot2", "user", args(json!({"name": "bob"})), tier1(rotating_handler(current))).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(r.healed, Some(true));
    assert_eq!(strategies(), vec!["rescan", "rescan"]);
}

#[tokio::test]
async fn an_expired_stale_mark_no_longer_blocks_a_heal_a_live_one_does() {
    let _g = fresh().await;
    save_site(&user_site("ttl", json!({}))).unwrap();
    set_state(|s| s["stale"]["ttl/user"] = json!({ "until": now_ms() + 60_000.0, "reason": "test" }));
    let blocked = call("ttl", "user", args(json!({"name": "bob"})), tier1(rotating_handler(|| NEW.to_string()))).await;
    assert!(!blocked.ok);
    assert!(re(blocked.reason.as_deref().unwrap_or(""), "stale until"));
    assert_eq!(heals().len(), 0);
    set_state(|s| s["stale"]["ttl/user"] = json!({ "until": now_ms() - 1.0, "reason": "test" }));
    let r = call("ttl", "user", args(json!({"name": "bob"})), tier1(rotating_handler(|| NEW.to_string()))).await;
    assert_eq!(r.healed, Some(true), "{}", j(&r));
    assert_eq!(stale("ttl", "user"), None, "a successful heal clears the mark");
}

/// The "other process" of the next test: this binary, run again on one test with the marker set.
#[test]
fn xproc_helper_mark_stale() {
    if std::env::var("HEAL_EDGE_MARK_STALE").is_ok() {
        mark_stale("xproc", "user", "set by another process", STALE_TTL_MS, now_ms(), None);
    }
}

#[tokio::test]
async fn a_stale_mark_written_by_another_process_is_honoured_by_this_one() {
    let _g = fresh().await;
    save_site(&user_site("xproc", json!({}))).unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["xproc_helper_mark_stale", "--exact"])
        .env("HEAL_EDGE_MARK_STALE", "1")
        .env("API_ANYTHING_HOME", HOME.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let r = call("xproc", "user", args(json!({"name": "bob"})), tier1(rotating_handler(|| NEW.to_string()))).await;
    assert!(!r.ok);
    assert!(re(r.reason.as_deref().unwrap_or(""), "set by another process"));
    assert_eq!(heals().len(), 0);
}

#[tokio::test]
async fn forced_heal_ignores_a_stale_mark_and_clears_it_on_success() {
    let _g = fresh().await;
    save_site(&user_site("force", json!({}))).unwrap();
    mark_stale("force", "user", "old failure", STALE_TTL_MS, now_ms(), None);
    let r = heal("force", "user", args(json!({"name": "alice"})), tier1(rotating_handler(|| NEW.to_string()))).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(r.strategy, Some(Strategy::Rescan));
    assert_eq!(stale("force", "user"), None);
}

#[tokio::test]
async fn path_and_body_query_ids_rotate_together_both_are_swapped_the_body_keeps_its_encoding() {
    let _g = fresh().await;
    save_site(
        &parse_site(&json!({
            "name": "both",
            "baseUrl": "https://t.test",
            "operations": [{
                "name": "user",
                "readOnly": true,
                "request": {
                    "method": "POST",
                    "url": format!("https://t.test/api/{OLD}/User"),
                    "headers": { "content-type": "application/json" },
                    "body": format!("{{\"queryId\":\"{OLD}\",\"variables\":{{\"name\":\"alice\"}}}}"),
                },
                "slots": [{ "param": "name", "at": ["body", "json:/variables/name"] }],
                "volatile": [
                    { "at": ["path:1"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "User" },
                    { "at": ["body", "json:/queryId"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "User" },
                ],
                "trigger": { "url": "https://t.test/u/{name}" },
                "params": [{ "name": "name", "example": "alice" }],
                "response": { "extract": "user" },
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    let h = |url: &str, req: &HttpRequest| {
        if url.starts_with("https://t.test/u/") {
            return html("<script src=\"/main.js\"></script>", 200);
        }
        if url.ends_with("/main.js") {
            return text(&format!("{{queryId:\"{NEW}\",operationName:\"User\"}}"));
        }
        let body: Value = serde_json::from_str(req.body.as_deref().unwrap_or("{}")).unwrap();
        if url.ends_with(&format!("/api/{NEW}/User")) && body["queryId"] == json!(NEW) {
            return json_res(json!({ "user": { "name": body["variables"]["name"] } }), 200);
        }
        empty(404)
    };
    let r = call("both", "user", args(json!({"name": "bob"})), tier1(h)).await;
    assert!(r.ok, "{}", j(&r));
    let op = first_op("both");
    assert_eq!(op.request.body.as_deref(), Some(format!("{{\"queryId\":\"{NEW}\",\"variables\":{{\"name\":\"alice\"}}}}").as_str()));
}

#[tokio::test]
async fn a_numeric_doc_id_in_a_json_body_is_swapped_as_a_json_number_not_a_string() {
    let _g = fresh().await;
    const OLD_DOC: &str = "1111111111111111";
    const NEW_DOC: &str = "9876543210987654";
    save_site(
        &parse_site(&json!({
            "name": "numdoc",
            "baseUrl": "https://t.test",
            "operations": [{
                "name": "q",
                "readOnly": true,
                "request": {
                    "method": "POST",
                    "url": "https://t.test/api/graphql",
                    "headers": { "content-type": "application/json" },
                    "body": format!("{{\"doc_id\":{OLD_DOC},\"variables\":{{\"name\":\"alice\"}}}}"),
                },
                "slots": [{ "param": "name", "at": ["body", "json:/variables/name"] }],
                "volatile": [{ "at": ["body", "json:/doc_id"], "shape": { "charset": "digits", "length": 16 }, "anchor": "ProfileQuery" }],
                "trigger": { "url": "https://t.test/u/{name}" },
                "params": [{ "name": "name", "example": "alice" }],
                "response": { "extract": "user" },
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    let h = |url: &str, req: &HttpRequest| {
        if url.starts_with("https://t.test/u/") {
            return html(&format!("<script>var ProfileQuery={{docId:{NEW_DOC}}}</script>"), 200);
        }
        let body = req.body.clone().unwrap_or_default();
        if body.contains(&format!("\"doc_id\":{NEW_DOC}")) {
            let parsed: Value = serde_json::from_str(&body).unwrap();
            return json_res(json!({ "user": { "name": parsed["variables"]["name"] } }), 200);
        }
        json_res(json!({ "errors": [{ "message": "PersistedQueryNotFound" }], "data": null }), 400)
    };
    let r = call("numdoc", "q", args(json!({"name": "bob"})), tier1(h)).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(
        first_op("numdoc").request.body.as_deref(),
        Some(format!("{{\"doc_id\":{NEW_DOC},\"variables\":{{\"name\":\"alice\"}}}}").as_str())
    );
}

// Was a bug: nearestToken() matches the anchor as a raw substring, so "Followers" also hits
// "FollowersYouKnow"; on a distance tie the first occurrence in the bundle wins. The wrong
// queryId answers 200 with the same shape, so validation passes and wrong data is saved.
#[tokio::test]
async fn anchor_that_is_a_prefix_of_another_operations_name_the_rescan_must_take_the_exact_operations_query_id() {
    let _g = fresh().await;
    const RIGHT: &str = "Rr1Ii2Gg3Hh4Tt5Ff6Oo7L";
    const YOU_KNOW: &str = "Yy1Oo2Uu3Kk4Nn5Oo6Ww7Z";
    save_site(
        &parse_site(&json!({
            "name": "fol",
            "baseUrl": "https://t.test",
            "operations": [{
                "name": "followers",
                "readOnly": true,
                "request": { "method": "GET", "url": format!("https://t.test/graphql/{OLD}/Followers?userId=12345678"), "headers": {} },
                "slots": [{ "param": "userId", "at": ["query:userId"] }],
                "volatile": [{ "at": ["path:1"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "Followers" }],
                "trigger": { "url": "https://t.test/u/{userId}/followers" },
                "match": { "method": "GET", "path": "/graphql/*/Followers" },
                "params": [{ "name": "userId", "example": "12345678" }],
                "response": {
                    "extract": "data.user.timeline.users",
                    "shape": {
                        "data": "object",
                        "data.user": "object",
                        "data.user.timeline": "object",
                        "data.user.timeline.users": "array",
                        "data.user.timeline.users[]": "object",
                        "data.user.timeline.users[].name": "string",
                    },
                },
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    let list = |names: &[&str]| {
        json_res(
            json!({ "data": { "user": { "timeline": { "users": names.iter().map(|n| json!({ "name": n })).collect::<Vec<_>>() } } } }),
            200,
        )
    };
    let h = move |url: &str, _req: &HttpRequest| {
        if url.contains("/u/") {
            return html("<script src=\"/main.js\"></script>", 200);
        }
        if url.ends_with("/main.js") {
            return text(&format!(
                "e.exports={{queryId:\"{YOU_KNOW}\",operationName:\"FollowersYouKnow\",operationType:\"query\"}};e.exports={{queryId:\"{RIGHT}\",operationName:\"Followers\",operationType:\"query\"}};"
            ));
        }
        if url.contains(&format!("/graphql/{RIGHT}/")) {
            return list(&["everyone", "who", "follows"]);
        }
        if url.contains(&format!("/graphql/{YOU_KNOW}/")) {
            return list(&["only-mutuals"]);
        }
        empty(404)
    };
    let r = call("fol", "followers", args(json!({"userId": "87654321"})), tier1(h)).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(
        r.data,
        Some(json!([{ "name": "everyone" }, { "name": "who" }, { "name": "follows" }])),
        "healed onto the wrong operation: {}",
        last_diff()
    );
}

// Was a bug: Meta-style bundles put each doc_id in its own module right after the previous module's
// doc_id, so the previous operation's id sits ~14 chars before the anchor while the op's own id is
// ~64 chars after it. The rescan takes the neighbour's id; validation passes on a same-shaped answer.
#[tokio::test]
async fn meta_style_module_layout_the_rescan_must_take_the_doc_id_of_the_anchors_own_module_not_the_previous_modules() {
    let _g = fresh().await;
    const OLD_DOC: &str = "1111111111111111";
    const FEED_DOC: &str = "2222222222222222";
    const PROFILE_DOC: &str = "3333333333333333";
    save_site(
        &parse_site(&json!({
            "name": "meta",
            "baseUrl": "https://m.test",
            "operations": [{
                "name": "profile",
                "readOnly": true,
                "request": {
                    "method": "POST",
                    "url": "https://m.test/api/graphql/",
                    "headers": { "content-type": "application/x-www-form-urlencoded" },
                    "body": format!("doc_id={OLD_DOC}&fb_api_req_friendly_name=PolarisProfileQuery&variables={}", common::enc("{\"username\":\"alice\"}")),
                },
                "slots": [{ "param": "username", "at": ["form:variables", "json:/username"] }],
                "volatile": [{ "at": ["form:doc_id"], "shape": { "charset": "digits", "length": 16 }, "anchor": "PolarisProfileQuery" }],
                "trigger": { "url": "https://m.test/{username}/" },
                "match": { "method": "POST", "path": "/api/graphql/", "operationName": "PolarisProfileQuery" },
                "params": [{ "name": "username", "example": "alice" }],
                "response": {
                    "extract": "data.user",
                    "shape": { "data": "object", "data.user": "object", "data.user.username": "string", "data.user.full_name": "string" },
                },
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    let h = |url: &str, req: &HttpRequest| {
        let body = req.body.clone().unwrap_or_default();
        if body.is_empty() {
            if url.ends_with(".js") {
                return text(&format!(
                    "__d(\"PolarisFeedQuery_instagramRelayOperation\",[],(function(a,b,c,d,e,f){{e.exports=\"{FEED_DOC}\"}}),null);__d(\"PolarisProfileQuery_instagramRelayOperation\",[],(function(a,b,c,d,e,f){{e.exports=\"{PROFILE_DOC}\"}}),null);"
                ));
            }
            return html("<script src=\"/rsrc/bundle.js\"></script>", 200);
        }
        let form: HashMap<String, String> =
            url::form_urlencoded::parse(body.as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        let vars: Value = serde_json::from_str(form.get("variables").unwrap()).unwrap();
        let username = vars["username"].clone();
        if form.get("doc_id").map(|s| s.as_str()) == Some(PROFILE_DOC) {
            return json_res(
                json!({ "data": { "user": { "username": username, "full_name": format!("{} (profile)", username.as_str().unwrap()) } } }),
                200,
            );
        }
        if form.get("doc_id").map(|s| s.as_str()) == Some(FEED_DOC) {
            return json_res(json!({ "data": { "user": { "username": username, "feed": [{ "id": "p1" }] } } }), 200);
        }
        json_res(json!({ "errors": [{ "message": "PersistedQueryNotFound" }], "data": null }), 400)
    };
    let r = call("meta", "profile", args(json!({"username": "bob"})), tier1(h)).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(
        r.data,
        Some(json!({ "username": "bob", "full_name": "bob (profile)" })),
        "healed onto the neighbour's doc_id: {}",
        last_diff()
    );
}

// Was a bug: a write's rescan candidate is validated by performing it. With the anchor
// matched as a substring, "CreateTweet" resolves to CreateTweetDownvote's queryId, and that other
// mutation is sent for real.
#[tokio::test]
async fn write_heal_a_rescan_guess_must_never_send_a_different_mutation() {
    let _g = fresh().await;
    const RIGHT: &str = "Cc1Rr2Ee3Aa4Tt5Ee6Tt7W";
    const DOWNVOTE: &str = "Dd1Oo2Ww3Nn4Vv5Oo6Tt7E";
    save_site(
        &parse_site(&json!({
            "name": "wr",
            "baseUrl": "https://w.test",
            "operations": [{
                "name": "createTweet",
                "readOnly": false,
                "request": {
                    "method": "POST",
                    "url": format!("https://w.test/graphql/{OLD}/CreateTweet"),
                    "headers": { "content-type": "application/json" },
                    "body": format!("{{\"variables\":{{\"tweet_text\":\"hello\"}},\"queryId\":\"{OLD}\"}}"),
                },
                "slots": [{ "param": "text", "at": ["body", "json:/variables/tweet_text"] }],
                "volatile": [
                    { "at": ["path:1"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "CreateTweet" },
                    { "at": ["body", "json:/queryId"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "CreateTweet" },
                ],
                "trigger": { "url": "https://w.test/compose" },
                "match": { "method": "POST", "path": "/graphql/*/CreateTweet" },
                "params": [{ "name": "text", "example": "hello" }],
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    let executed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let ex = executed.clone();
    let h = move |url: &str, req: &HttpRequest| {
        if url == "https://w.test/compose" {
            return html("<script src=\"/main.js\"></script>", 200);
        }
        if url.ends_with("/main.js") {
            return text(&format!(
                "e.exports={{queryId:\"{DOWNVOTE}\",operationName:\"CreateTweetDownvote\",operationType:\"mutation\"}};e.exports={{queryId:\"{RIGHT}\",operationName:\"CreateTweet\",operationType:\"mutation\"}};"
            ));
        }
        if req.method == "POST" && url.contains(&format!("/graphql/{DOWNVOTE}/")) {
            ex.lock().unwrap().push("CreateTweetDownvote".into());
            return json_res(json!({ "data": { "downvoted": true } }), 200);
        }
        if req.method == "POST" && url.contains(&format!("/graphql/{RIGHT}/")) {
            ex.lock().unwrap().push("CreateTweet".into());
            return json_res(json!({ "data": { "create_tweet": { "id": "1" } } }), 200);
        }
        empty(404)
    };
    call("wr", "createTweet", args(json!({"text": "hi there"})), with_writes(tier1(h))).await;
    let others: Vec<String> = executed.lock().unwrap().iter().filter(|x| x.as_str() != "CreateTweet").cloned().collect();
    assert_eq!(others, Vec::<String>::new(), "a mutation other than the op's own was performed");
}

#[tokio::test]
async fn a_write_is_sent_at_most_once_by_the_heal_the_one_validation_after_a_definite_404() {
    let _g = fresh().await;
    const RIGHT: &str = "Cc1Rr2Ee3Aa4Tt5Ee6Tt7W";
    save_site(
        &parse_site(&json!({
            "name": "wr1",
            "baseUrl": "https://w.test",
            "operations": [{
                "name": "post",
                "readOnly": false,
                "request": {
                    "method": "POST",
                    "url": format!("https://w.test/graphql/{OLD}/CreatePost"),
                    "headers": { "content-type": "application/json" },
                    "body": "{\"text\":\"hello\"}",
                },
                "slots": [{ "param": "text", "at": ["body", "json:/text"] }],
                "volatile": [{ "at": ["path:1"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "CreatePost" }],
                "trigger": { "url": "https://w.test/compose" },
                "params": [{ "name": "text", "example": "hello" }],
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    let h = |url: &str, req: &HttpRequest| {
        if url == "https://w.test/compose" {
            return html(&format!("<script>x={{queryId:\"{RIGHT}\",operationName:\"CreatePost\"}}</script>"), 200);
        }
        if req.method == "POST" && url.contains(RIGHT) {
            return empty(502);
        }
        empty(404)
    };
    let r = call("wr1", "post", args(json!({"text": "hi there"})), with_writes(tier1(h))).await;
    assert!(!r.ok);
    assert_eq!(
        seen().iter().filter(|s| s.method == "POST").count(),
        2,
        "the stored template (404) and one validation; the ambiguous 502 is not retried"
    );
    assert!(re(r.next.as_deref().unwrap_or(""), "may have (gone through|run)"));
}

// Was a bug: the rescan looks for clues by fetching the trigger page with plain fetch. When the trigger is the
// write's own address (a GET vote link), that fetch is the write: performed before any validation, uncounted,
// with none of the browser's interception.
fn vote_op(base: &str, trigger: &str) -> Value {
    json!({
        "name": "vote",
        "readOnly": false,
        "request": { "method": "GET", "url": format!("{base}/vote?id=1&auth={OLD}"), "headers": {} },
        "slots": [{ "param": "id", "at": ["query:id"] }],
        "volatile": [{ "at": ["query:auth"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "auth" }],
        "trigger": { "url": format!("{base}{trigger}") },
        "match": { "method": "GET", "path": "/vote" },
        "params": [{ "name": "id", "example": "1" }],
    })
}

#[tokio::test]
async fn write_heal_the_rescan_does_not_fetch_a_page_that_is_the_write_itself_a_get_vote_link_as_its_own_trigger() {
    let _g = fresh().await;
    save_site(
        &parse_site(&json!({ "name": "wget", "baseUrl": "https://w.test", "operations": [vote_op("https://w.test", "/vote?id={id}")] }))
            .unwrap(),
    )
    .unwrap();
    let votes: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let v = votes.clone();
    let h = move |url: &str, _req: &HttpRequest| {
        let u = Url::parse(url).unwrap();
        if u.path() != "/vote" || query(&u, "auth").as_deref() == Some(OLD) {
            return empty(404);
        }
        v.lock().unwrap().push(api_anything::util::search_of(&u));
        html("<p>voted</p>", 200)
    };
    let r = call("wget", "vote", args(json!({"id": "7"})), with_writes(tier1(h))).await;
    assert_eq!(*votes.lock().unwrap(), Vec::<String>::new(), "the heal performed the write while looking for clues");
    assert!(!r.ok);
    assert_eq!(
        seen().iter().map(|s| api_anything::util::search_of(&Url::parse(&s.url).unwrap())).collect::<Vec<_>>(),
        vec![format!("?id=7&auth={OLD}")],
        "only the stored template was sent"
    );
}

/* ----------------------------------------------------------- local servers */

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

fn res(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
    let mut r = Response::builder().status(status);
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    r.body(Body::from(body.to_string())).unwrap()
}

fn send_json(v: Value, status: u16) -> Response {
    res(status, &[("content-type", "application/json")], &v.to_string())
}

fn send_html(s: &str, status: u16) -> Response {
    res(status, &[("content-type", "text/html")], s)
}

fn send_js(s: &str) -> Response {
    res(200, &[("content-type", "application/javascript")], s)
}

fn params(p: &Parts) -> HashMap<String, String> {
    url::form_urlencoded::parse(p.uri.query().unwrap_or("").as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
}

fn header(p: &Parts, name: &str) -> String {
    p.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

#[tokio::test]
async fn write_heal_the_rescan_does_not_follow_a_redirect_to_the_write_itself_a_reads_still_follows() {
    let _g = fresh().await;
    let votes = Arc::new(AtomicUsize::new(0));
    let v = votes.clone();
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let path = p.uri.path();
        if path == "/go" {
            return res(302, &[("location", "/vote?id=7")], "");
        }
        if path != "/vote" {
            return res(404, &[], "");
        }
        v.fetch_add(1, Ordering::SeqCst);
        res(200, &[("content-type", "text/html")], &format!("<script>x={{auth:\"{NEW}\"}}</script>"))
    }))
    .await;
    let op =
        parse_site(&json!({ "name": "wgo", "baseUrl": base, "operations": [vote_op(&base, "/go?id={id}")] })).unwrap().operations.remove(0);
    assert!(rescan("wgo", &op, &args(json!({"id": "7"})), None).await.unwrap().is_none());
    assert_eq!(votes.load(Ordering::SeqCst), 0, "the heal performed the write by following a redirect to it");
    // the same pages for a read are only pages: fetched, redirect and all
    let mut read_op = op.clone();
    read_op.read_only = true;
    let read = rescan("wgo", &read_op, &args(json!({"id": "7"})), None).await.unwrap();
    assert_eq!(read.map(|r| r.diff), Some(format!("query:auth: {OLD} -> {NEW}")));
}

#[tokio::test]
async fn a_reads_rescan_follows_a_long_chain_of_redirects_and_takes_only_a_redirect_status_for_one() {
    let _g = fresh().await;
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let n: i64 = params(p).get("n").and_then(|s| s.parse().ok()).unwrap_or(0);
        let page = format!("<script>x={{queryId:\"{NEW}\",operationName:\"User\"}}</script>");
        if p.uri.path() == "/u/far" && n < 6 {
            return res(302, &[("location", &format!("/u/far?n={}", n + 1))], "");
        }
        // not a redirect, whatever its Location says
        if p.uri.path() == "/u/cached" {
            return res(304, &[("location", "/u/far?n=6")], "");
        }
        res(200, &[("content-type", "text/html")], &page)
    }))
    .await;
    let mut op = user_site("far6", json!({})).operations.remove(0);
    op.trigger = Trigger { url: format!("{base}/u/{{name}}"), steps: None, soft_from: None };
    assert_eq!(
        rescan("far6", &op, &args(json!({"name": "far"})), None).await.unwrap().map(|r| r.diff),
        Some(format!("path:1: {OLD} -> {NEW}"))
    );
    assert!(rescan("far6", &op, &args(json!({"name": "cached"})), None).await.unwrap().is_none());
}

// Was a bug: a write whose heal failed is marked stale; the next drift's `next` tells the agent to
// force `api-anything heal`, which refuses every write.
#[tokio::test]
async fn a_stale_writes_next_hint_does_not_point_at_api_anything_heal_which_refuses_writes() {
    let _g = fresh().await;
    save_site(
        &parse_site(&json!({
            "name": "wst",
            "baseUrl": "https://w.test",
            "operations": [{
                "name": "post",
                "readOnly": false,
                "request": { "method": "POST", "url": format!("https://w.test/graphql/{OLD}/CreatePost"), "headers": {}, "body": "{\"text\":\"hello\"}" },
                "slots": [{ "param": "text", "at": ["body", "json:/text"] }],
                "volatile": [{ "at": ["path:1"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "CreatePost" }],
                "trigger": { "url": "https://w.test/compose" },
                "params": [{ "name": "text", "example": "hello" }],
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    mark_stale("wst", "post", "heal failed earlier", STALE_TTL_MS, now_ms(), None);
    let r = call("wst", "post", args(json!({"text": "hi there"})), with_writes(tier1(|_url: &str, _req: &HttpRequest| empty(404)))).await;
    assert!(!r.ok);
    let forced = heal("wst", "post", args(json!({"text": "hi there"})), CallOptions::default()).await;
    assert_eq!(forced.class, Class::Refused);
    assert!(!re(r.next.as_deref().unwrap_or(""), "api-anything heal"), "next: {:?}", r.next);
}

#[tokio::test]
async fn logged_out_401_graphql_auth_errors_and_a_login_redirect_are_auth_never_healed() {
    let _g = fresh().await;
    save_site(&user_site("auth", json!({}))).unwrap();
    let responses: Vec<Arc<dyn Fn() -> HttpResponse + Send + Sync>> = vec![
        Arc::new(|| json_res(json!({ "errors": [{ "message": "unauthorized" }] }), 401)),
        Arc::new(|| json_res(json!({ "errors": [{ "message": "Could not authenticate you" }], "data": null }), 200)),
        Arc::new(|| redirect(302, "https://t.test/login?next=/api")),
        Arc::new(|| html("<html><form><input type=\"password\"></form></html>", 200)),
    ];
    for response in responses {
        clear_seen();
        let rot = rotating_handler(|| NEW.to_string());
        let h = move |url: &str, req: &HttpRequest| {
            if url.contains("/api/") {
                response()
            } else if url.contains("/login") {
                html("<html><form><input type=\"password\"></form></html>", 200)
            } else {
                rot(url, req)
            }
        };
        let r = call("auth", "user", args(json!({"name": "bob"})), tier1(h)).await;
        assert_eq!(r.class, Class::Auth, "{}", j(&r));
        assert_eq!(heals().len(), 0);
        assert!(!seen().iter().any(|s| s.url.contains("/u/") || s.url.ends_with(".js")), "no rescan when logged out: {:?}", seen());
    }
}

// Was a bug: DESIGN step 7 records learnedLoggedIn so a changed session state is recognised,
// but nothing reads it. An op learned logged in, called with a jar that holds no login cookie,
// gets "no data" (the site hides it from guests), is healed as drift, and is told to heal/re-add,
// never to log in.
#[tokio::test]
async fn op_learned_logged_in_jar_now_logged_out_data_missing_the_failure_points_at_login_instead_of_heal_re_add() {
    let _g = fresh().await;
    let mut site = user_site(
        "lo",
        json!({
            "learnedLoggedIn": true,
            "volatile": [],
            "request": { "method": "GET", "url": "https://t.test/api/Feed?name=alice", "headers": {} },
            "match": { "method": "GET", "path": "/api/Feed" },
        }),
    );
    site.login_cookies = Some(vec!["sessionid".into()]);
    save_site(&site).unwrap();
    save_session("lo", &Session::empty()).unwrap();
    let r = call(
        "lo",
        "user",
        args(json!({"name": "bob"})),
        tier1(
            |url: &str, _req: &HttpRequest| {
                if url.contains("/api/") { json_res(json!({ "data": {} }), 200) } else { html("<html></html>", 200) }
            },
        ),
    )
    .await;
    assert!(!r.ok);
    assert!(r.class == Class::Auth || re(r.next.as_deref().unwrap_or(""), "login"), "logged-out failure does not mention login: {}", j(&r));
}

#[tokio::test]
async fn rate_limited_on_the_first_try_reported_as_rate_no_heal_one_request() {
    let _g = fresh().await;
    save_site(&user_site("rate0", json!({}))).unwrap();
    let r = call(
        "rate0",
        "user",
        args(json!({"name": "bob"})),
        tier1(|_url: &str, _req: &HttpRequest| json_res(json!({ "message": "Too many requests" }), 429)),
    )
    .await;
    assert_eq!(r.class, Class::Rate);
    assert_eq!(seen().len(), 1);
    assert_eq!(stale("rate0", "user"), None);
}

// Was a bug: the example-args replay that tells "no such user" from drift can itself be rate
// limited; that 429 is ignored and the heal runs anyway (fetching the page and up to 40 bundles).
#[tokio::test]
async fn rate_limited_during_the_example_args_replay_stop_and_report_rate_do_not_heal() {
    let _g = fresh().await;
    save_site(&user_site("rate1", json!({}))).unwrap();
    let n = Arc::new(AtomicUsize::new(0));
    let rot = rotating_handler(|| NEW.to_string());
    let h = move |url: &str, req: &HttpRequest| {
        if url.contains("/api/") {
            return if n.fetch_add(1, Ordering::SeqCst) == 0 {
                json_res(json!({ "nothing": true }), 200)
            } else {
                json_res(json!({ "message": "Too many requests" }), 429)
            };
        }
        rot(url, req)
    };
    let r = call("rate1", "user", args(json!({"name": "bob"})), tier1(h)).await;
    assert!(
        !seen().iter().any(|s| s.url.contains("/u/") || s.url.ends_with(".js")),
        "heal ran while rate limited: {}",
        seen().iter().map(|s| s.url.clone()).collect::<Vec<_>>().join(", ")
    );
    assert_eq!(r.class, Class::Rate, "{}", j(&r));
}

// Was a bug: when the rescan candidate's replay is rate limited, the failure reason says the rescan
// "found nothing new", which is false and hides that the candidate was never really checked.
#[tokio::test]
async fn rate_limited_while_validating_a_rescan_candidate_class_rate_and_the_reason_does_not_claim_the_rescan_found_nothing() {
    let _g = fresh().await;
    save_site(&user_site("rate2", json!({}))).unwrap();
    let rot = rotating_handler(|| NEW.to_string());
    let h = move |url: &str, req: &HttpRequest| {
        if url.contains(&format!("/api/{NEW}/")) {
            return json_res(json!({ "message": "Too many requests" }), 429);
        }
        rot(url, req)
    };
    let r = call("rate2", "user", args(json!({"name": "bob"})), tier1(h)).await;
    assert_eq!(r.class, Class::Rate, "{}", j(&r));
    assert!(!re(r.reason.as_deref().unwrap_or(""), "found nothing new"));
}

#[tokio::test]
async fn status_404_with_the_param_in_the_path_and_a_volatile_in_the_path_example_replay_separates_not_found_from_drift() {
    let _g = fresh().await;
    let site = parse_site(&json!({
        "name": "nd",
        "baseUrl": "https://t.test",
        "operations": [{
            "name": "user",
            "readOnly": true,
            "request": { "method": "GET", "url": format!("https://t.test/_next/data/{OLD}/u/alice.json"), "headers": {} },
            "slots": [{ "param": "name", "at": ["path:4"], "template": "{name}.json" }],
            "volatile": [{ "at": ["path:2"], "shape": { "charset": "base64url", "length": 22 }, "anchor": "buildId" }],
            "trigger": { "url": "https://t.test/u/{name}" },
            "params": [{ "name": "name", "example": "alice" }],
            "response": { "extract": "pageProps.user" },
        }],
    }))
    .unwrap();
    save_site(&site).unwrap();
    let build = Arc::new(Mutex::new(OLD.to_string()));
    let b = build.clone();
    let path_re = regex::Regex::new(r"^/_next/data/([^/]+)/u/([^/]+)\.json$").unwrap();
    let h = move |url: &str, _req: &HttpRequest| {
        let build = b.lock().unwrap().clone();
        if url.starts_with("https://t.test/u/") {
            return html(&format!("<script id=\"__NEXT_DATA__\">{{\"buildId\":\"{build}\"}}</script>"), 200);
        }
        let u = Url::parse(url).unwrap();
        if let Some(m) = path_re.captures(u.path()) {
            if m[1] == build && ["alice", "bob"].contains(&&m[2]) {
                return json_res(json!({ "pageProps": { "user": { "name": &m[2] } } }), 200);
            }
        }
        response(404, Some("text/plain;charset=UTF-8"), "not found", &[])
    };
    let nf = call("nd", "user", args(json!({"name": "nosuchuser"})), tier1(h.clone())).await;
    assert_eq!(nf.class, Class::Input, "{}", j(&nf));
    assert_eq!(heals().len(), 0);
    *build.lock().unwrap() = NEW.to_string();
    let r = call("nd", "user", args(json!({"name": "bob"})), tier1(h)).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(r.healed, Some(true));
}

#[tokio::test]
async fn the_heal_log_carries_no_credential_and_is_0600_the_healed_spec_is_written_whole_with_no_temp_file_left() {
    use std::os::unix::fs::PermissionsExt;
    let _g = fresh().await;
    const SECRET_COOKIE: &str = "s3cr3tAuthTokenValue0123456789";
    const SECRET_CSRF: &str = "csrfValue0123456789abcdef";
    save_site(&user_site(
        "sec",
        json!({
            "request": { "method": "GET", "url": format!("https://t.test/api/{OLD}/User?name=alice"), "headers": { "x-csrf-token": "" } },
            "slots": [{ "param": "name", "at": ["query:name"] }, { "ref": "cookie:ct0", "at": ["header:x-csrf-token"] }],
        }),
    ))
    .unwrap();
    let session: Session = serde_json::from_value(json!({
        "cookies": [
            { "name": "auth_token", "value": SECRET_COOKIE, "domain": ".t.test", "path": "/", "expires": -1, "httpOnly": true, "secure": true },
            { "name": "ct0", "value": SECRET_CSRF, "domain": ".t.test", "path": "/", "expires": -1, "httpOnly": false, "secure": true },
        ],
        "values": {},
    }))
    .unwrap();
    save_session("sec", &session).unwrap();
    let r = call("sec", "user", args(json!({"name": "bob"})), tier1(rotating_handler(|| NEW.to_string()))).await;
    assert_eq!(r.healed, Some(true), "{}", j(&r));
    let log = fs::read_to_string(HOME.path().join("heals.jsonl")).unwrap();
    let spec = fs::read_to_string(HOME.path().join("sites").join("sec.json")).unwrap();
    for s in [SECRET_COOKIE, SECRET_CSRF] {
        assert!(!log.contains(s), "heal log holds a credential");
        assert!(!spec.contains(s), "healed spec holds a credential");
    }
    assert_eq!(fs::metadata(HOME.path().join("heals.jsonl")).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(HOME.path().join("sites").join("sec.json")).unwrap().permissions().mode() & 0o777, 0o600);
    let tmp: Vec<String> = fs::read_dir(HOME.path().join("sites"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|f| f.ends_with(".tmp"))
        .collect();
    assert_eq!(tmp, Vec::<String>::new());
    parse_site(&serde_json::from_str(&spec).unwrap()).unwrap();
}

#[tokio::test]
async fn heal_of_a_bundled_spec_writes_a_user_copy_that_wins_afterwards_the_bundled_file_is_untouched() {
    let _g = fresh().await;
    let bundled = concat!(env!("CARGO_MANIFEST_DIR"), "/../sites/x.json");
    let before = fs::read(bundled).unwrap();
    let loaded = load_site("x").unwrap().unwrap();
    let op = loaded.site.operations.iter().find(|o| o.name == "getUser").unwrap().clone();
    assert_eq!(loaded.source, Source::Bundled);
    let oldx = Url::parse(&op.request.url).unwrap().path().split('/').nth(2).unwrap().to_string();
    const NEWX: &str = "Nn1Ee2Ww3Xx4Qq5Uu6Ee7R";
    // a body with every learned key path, so the shape check sees a healthy answer
    let mut body = json!({});
    for (path, ty) in op.response.shape.clone().unwrap_or_default() {
        if path.contains("[]") {
            continue;
        }
        let keys: Vec<&str> = path.split('.').collect();
        let mut o = &mut body;
        for k in &keys[..keys.len() - 1] {
            if o.get(*k).is_none() {
                o[*k] = json!({});
            }
            o = &mut o[*k];
        }
        let last = keys[keys.len() - 1];
        if o.get(last).is_none() {
            o[last] = match ty.as_str() {
                "object" => json!({}),
                "array" => json!([]),
                "number" => json!(1),
                "boolean" => json!(true),
                "null" => Value::Null,
                _ => json!("x"),
            };
        }
    }
    let body2 = body.clone();
    let ox = oldx.clone();
    let h = move |url: &str, _req: &HttpRequest| {
        if url == "https://x.com/nasa" {
            return html("<script src=\"https://abs.twimg.com/responsive-web/client-web/main.abc.js\"></script>", 200);
        }
        if url.ends_with("main.abc.js") {
            return text(&format!("e.exports={{queryId:\"{NEWX}\",operationName:\"UserByScreenName\",operationType:\"query\"}}"));
        }
        if url.contains(&format!("/graphql/{NEWX}/UserByScreenName")) {
            return json_res(body2.clone(), 200);
        }
        if url.contains(&format!("/graphql/{ox}/")) {
            return empty(404);
        }
        empty(404)
    };
    let r = call("x", "getUser", args(json!({"screen_name": "nasa"})), tier1(h)).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(r.healed, Some(true));
    let after = load_site("x").unwrap().unwrap();
    assert_eq!(after.source, Source::User);
    assert!(after.site.operations.iter().find(|o| o.name == "getUser").unwrap().request.url.contains(NEWX));
    assert_eq!(
        after.site.operations.len(),
        load_site_from("x", &Bundled::Dir(HOME.path().join("no-such-dir"))).unwrap().unwrap().site.operations.len(),
        "the user copy keeps every other op"
    );
    assert_eq!(fs::read(bundled).unwrap(), before, "bundled spec modified");
}

#[tokio::test]
async fn concurrent_heals_of_one_op_in_one_process_both_answer_correctly_and_leave_one_consistent_spec() {
    let _g = fresh().await;
    save_site(&user_site("conc", json!({}))).unwrap();
    let (a, b) = tokio::join!(
        call("conc", "user", args(json!({"name": "bob"})), tier1(rotating_handler(|| NEW.to_string()))),
        call("conc", "user", args(json!({"name": "carol"})), tier1(rotating_handler(|| NEW.to_string())))
    );
    assert_eq!([a.ok, b.ok], [true, true], "{}", j(&[&a, &b]));
    assert_eq!([a.data.clone(), b.data.clone()], [Some(json!({ "name": "bob" })), Some(json!({ "name": "carol" }))]);
    assert!(first_op("conc").request.url.contains(NEW));
    assert!(!heals().is_empty());
}

// Was a bug: rescan resolves script src against the trigger URL, not the document's final URL, so
// a redirected page (locale prefix, trailing-slash or app-path redirects) with a relative src loses its bundle.
#[tokio::test]
async fn rescan_resolves_script_paths_against_the_redirected_document_url() {
    let _g = fresh().await;
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let path = p.uri.path();
        if path == "/u/bob" {
            return res(302, &[("location", "/en/app/u/bob")], "");
        }
        if path == "/en/app/u/bob" {
            return res(200, &[("content-type", "text/html")], "<script src=\"../static/main.js\"></script>");
        }
        if path == "/en/app/static/main.js" {
            return res(200, &[], &format!("x={{queryId:\"{NEW}\",operationName:\"User\"}}"));
        }
        res(404, &[], "")
    }))
    .await;
    let mut op = user_site("redir", json!({})).operations.remove(0);
    op.trigger = Trigger { url: format!("{base}/u/{{name}}"), steps: None, soft_from: None };
    let r = rescan("redir", &op, &args(json!({"name": "bob"})), None).await.unwrap();
    assert_eq!(r.map(|r| r.diff), Some(format!("path:1: {OLD} -> {NEW}")));
}

#[tokio::test]
async fn rescan_ignores_a_token_that_overlaps_or_is_the_anchor_and_a_token_farther_than_300_chars() {
    let _g = fresh().await;
    let op = user_site("far", json!({})).operations.remove(0);
    let h = |url: &str, _req: &HttpRequest| {
        if url.starts_with("https://t.test/u/") {
            return html(&format!("<script>x={{queryId:\"{NEW}\",pad:\"{}\",operationName:\"User\"}}</script>", "-".repeat(400)), 200);
        }
        empty(404)
    };
    assert!(rescan("far", &op, &args(json!({"name": "bob"})), Some(fake(h))).await.unwrap().is_none());
}

/* ------------------------------------------------------------------ browser */

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

fn fast() -> CallOptions {
    CallOptions { min_interval_ms: Some(0), ..Default::default() }
}

fn add(site: &str, op: &str, trigger: Trigger, examples: Vec<Value>, extract: Option<&str>, write: bool) -> AddInput {
    AddInput {
        site: site.into(),
        op: op.into(),
        trigger: Some(trigger),
        examples: examples.into_iter().map(args).collect(),
        matcher: None,
        write,
        description: None,
        response: extract.map(|e| Recipe { extract: Some(e.into()), ..Default::default() }),
        public: None,
        from: None,
        from2: None,
        fetcher: None,
    }
}

fn trigger(url: String) -> Trigger {
    Trigger { url, steps: None, soft_from: None }
}

/// the TS `encodeURIComponent(location.pathname.split("/")[2])` page script, fetching the API for the page's own user
fn user_page_script(path: &str) -> String {
    format!("<html><body><script>fetch(\"{path}\"+encodeURIComponent(location.pathname.split(\"/\")[2]))</script></body></html>")
}

fn document_load(p: &Parts) -> bool {
    header(p, "sec-fetch-dest") == "document"
}

#[tokio::test]
async fn query_id_only_in_a_lazily_loaded_chunk_rescan_finds_nothing_recapture_heals() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = fresh().await;
    let qid = Arc::new(Mutex::new(OLD.to_string()));
    let q = qid.clone();
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let qid = q.lock().unwrap().clone();
        let path = p.uri.path();
        if path.starts_with("/u/") {
            return send_html("<html><body><script type=\"module\" src=\"/main.js\"></script></body></html>", 200);
        }
        if path == "/main.js" {
            return send_js("import(\"/chunk-user.js\").then(m=>m.load(location.pathname.split(\"/\")[2]));");
        }
        if path == "/chunk-user.js" {
            return send_js(&format!("export function load(n){{fetch(\"/api/{qid}/User?name=\"+encodeURIComponent(n))}}"));
        }
        if path == format!("/api/{qid}/User") {
            return send_json(json!({ "user": { "name": params(p).get("name") } }), 200);
        }
        send_json(json!({}), 404)
    }))
    .await;
    add_operation(add(
        "lazy",
        "user",
        trigger(format!("{base}/u/{{name}}")),
        vec![json!({"name": "alice"}), json!({"name": "bobby"})],
        Some("user"),
        false,
    ))
    .await
    .unwrap();
    assert_eq!(first_op("lazy").volatile.len(), 1);
    *qid.lock().unwrap() = NEW.to_string();
    let r = call("lazy", "user", args(json!({"name": "carol"})), fast()).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(r.healed, Some(true));
    assert_eq!(strategies(), vec!["recapture"]);
    let again = call("lazy", "user", args(json!({"name": "dave"})), fast()).await;
    assert_eq!(again.tier, Some(1));
    assert_eq!(again.data, Some(json!({ "name": "dave" })));
    api_anything::browser::close_browser().await;
}

#[tokio::test]
async fn rotation_while_the_anchor_moved_away_from_the_id_rescan_picks_a_wrong_nearby_hash_recapture_still_heals() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = fresh().await;
    const DECOY: &str = "Dd9Ee8Cc7Oo6Yy5Hh4Aa3S";
    let qid = Arc::new(Mutex::new(OLD.to_string()));
    let q = qid.clone();
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let qid = q.lock().unwrap().clone();
        let path = p.uri.path();
        if path.starts_with("/u/") {
            return send_html("<html><body><script src=\"/main.js\"></script></body></html>", 200);
        }
        if path == "/main.js" {
            // after the deploy, the op name sits next to an unrelated chunk hash; the id is far away
            let registry = if qid == OLD {
                format!("{{queryId:\"{qid}\",operationName:\"User\"}}")
            } else {
                format!("{{chunk:\"{DECOY}\",operationName:\"User\"}};{}var ids={{a:\"{qid}\"}}", " ".repeat(600))
            };
            let id = if qid == OLD { format!("\"{qid}\"") } else { "ids.a".to_string() };
            // the path is assembled so the op name never sits next to the id in the source
            return send_js(&format!("var reg={registry};fetch(\"/api/\"+{id}+\"/\"+reg.operationName+\"?name=\"+encodeURIComponent(location.pathname.split(\"/\")[2]));"));
        }
        if path == format!("/api/{qid}/User") {
            return send_json(json!({ "user": { "name": params(p).get("name") } }), 200);
        }
        send_json(json!({}), 404)
    }))
    .await;
    add_operation(add(
        "moved",
        "user",
        trigger(format!("{base}/u/{{name}}")),
        vec![json!({"name": "alice"}), json!({"name": "bobby"})],
        Some("user"),
        false,
    ))
    .await
    .unwrap();
    *qid.lock().unwrap() = NEW.to_string();
    let r = call("moved", "user", args(json!({"name": "carol"})), fast()).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(r.healed, Some(true));
    assert_eq!(strategies(), vec!["recapture"]);
    assert!(!first_op("moved").request.url.contains(DECOY));
    api_anything::browser::close_browser().await;
}

// Was a bug: recapture learns the new template's session refs but throws away their values
// (learnOperation's sessionValues); runOpTrigger only stores values for the OLD op's refs. A
// deploy that adds or renames an auth/anti-bot header (x-*-token, x-csrf-*) can then never heal:
// the validation replay drops the header because the session store has no value for it.
#[tokio::test]
async fn recapture_of_a_template_that_gained_a_session_header_stores_that_headers_value_so_validation_can_send_it() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = fresh().await;
    const TOKEN: &str = "pageToken-5f2a9c1e7b3d";
    let version = Arc::new(AtomicUsize::new(1));
    let v = version.clone();
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let version = v.load(Ordering::SeqCst);
        let path = p.uri.path();
        if path.starts_with("/u/") {
            let js = if version == 1 {
                "fetch(\"/api/User?name=\"+encodeURIComponent(location.pathname.split(\"/\")[2]))".to_string()
            } else {
                format!("fetch(\"/api/User?name=\"+encodeURIComponent(location.pathname.split(\"/\")[2]),{{headers:{{\"x-api-token\":\"{TOKEN}\"}}}})")
            };
            return send_html(&format!("<html><body><script>{js}</script></body></html>"), 200);
        }
        if path == "/api/User" {
            if version == 2 && header(p, "x-api-token") != TOKEN {
                return send_json(json!({ "error": "unknown operation" }), 404);
            }
            return send_json(json!({ "user": { "name": params(p).get("name") } }), 200);
        }
        send_json(json!({}), 404)
    }))
    .await;
    add_operation(add(
        "hdr",
        "user",
        trigger(format!("{base}/u/{{name}}")),
        vec![json!({"name": "alice"}), json!({"name": "bobby"})],
        Some("user"),
        false,
    ))
    .await
    .unwrap();
    version.store(2, Ordering::SeqCst);
    let r = call("hdr", "user", args(json!({"name": "carol"})), fast()).await;
    assert!(r.ok, "{}", j(&r));
    let op = first_op("hdr");
    assert_eq!(r.healed, Some(true), "{}\nslots now: {}\nsession values: {}", j(&r), j(&op.slots), j(&load_session("hdr").unwrap().values));
    let later = call("hdr", "user", args(json!({"name": "dave"})), fast()).await;
    assert_eq!(later.tier, Some(1), "{}", j(&later));
    assert_eq!(later.data, Some(json!({ "name": "dave" })));
    api_anything::browser::close_browser().await;
}

// Was a bug: a renamed response field (user -> account) is response drift, not bad args: the
// example args fail too. The recapture learns the same request, so the heal says "identical" and
// call() reports class "input" with "check the args", and nothing tells the agent to fix --extract.
#[tokio::test]
async fn response_field_renamed_reported_as_drift_with_a_re_add_hint_not_as_input() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = fresh().await;
    let renamed = Arc::new(AtomicBool::new(false));
    let rn = renamed.clone();
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let path = p.uri.path();
        if path.starts_with("/u/") {
            return send_html(&user_page_script("/api/User?name="), 200);
        }
        if path == "/api/User" {
            let who = json!({ "name": params(p).get("name"), "followers": 3 });
            return send_json(if rn.load(Ordering::SeqCst) { json!({ "account": who }) } else { json!({ "user": who }) }, 200);
        }
        send_json(json!({}), 404)
    }))
    .await;
    add_operation(add(
        "ren",
        "user",
        trigger(format!("{base}/u/{{name}}")),
        vec![json!({"name": "alice"}), json!({"name": "bobby"})],
        Some("user"),
        false,
    ))
    .await
    .unwrap();
    renamed.store(true, Ordering::SeqCst);
    let r = call("ren", "user", args(json!({"name": "carol"})), fast()).await;
    assert!(!r.ok);
    assert_ne!(r.class, Class::Input, "field rename reported as bad args: {}", j(&r));
    assert!(re(r.next.as_deref().unwrap_or(""), "add"));
    api_anything::browser::close_browser().await;
}

#[tokio::test]
async fn the_trigger_page_now_404s_and_fires_nothing_heal_fails_op_is_stale_next_call_runs_no_browser() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = fresh().await;
    let gone = Arc::new(AtomicBool::new(false));
    let page_loads = Arc::new(AtomicUsize::new(0));
    let (g, pl) = (gone.clone(), page_loads.clone());
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let path = p.uri.path();
        if path.starts_with("/u/") {
            if document_load(p) {
                pl.fetch_add(1, Ordering::SeqCst);
            }
            if g.load(Ordering::SeqCst) {
                return send_html("<html><body>Not found</body></html>", 404);
            }
            return send_html(&user_page_script(&format!("/api/{OLD}/User?name=")), 200);
        }
        if !g.load(Ordering::SeqCst) && path == format!("/api/{OLD}/User") {
            return send_json(json!({ "user": { "name": params(p).get("name") } }), 200);
        }
        send_json(json!({}), 404)
    }))
    .await;
    add_operation(add(
        "p404",
        "user",
        trigger(format!("{base}/u/{{name}}")),
        vec![json!({"name": "alice"}), json!({"name": "bobby"})],
        Some("user"),
        false,
    ))
    .await
    .unwrap();
    gone.store(true, Ordering::SeqCst);
    let r = call("p404", "user", args(json!({"name": "carol"})), fast()).await;
    assert!(!r.ok);
    assert!(re(r.reason.as_deref().unwrap_or(""), "heal failed"));
    assert!(stale("p404", "user").is_some());
    let loads = page_loads.load(Ordering::SeqCst);
    let again = call("p404", "user", args(json!({"name": "dave"})), fast()).await;
    assert!(!again.ok);
    assert!(re(again.reason.as_deref().unwrap_or(""), "stale"));
    assert_eq!(page_loads.load(Ordering::SeqCst), loads);
    api_anything::browser::close_browser().await;
}

#[tokio::test]
async fn write_drift_heals_by_recapture_without_the_write_leaving_the_browser_exactly_one_send_executes() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = fresh().await;
    let qid = Arc::new(Mutex::new(OLD.to_string()));
    let executed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let (q, ex) = (qid.clone(), executed.clone());
    let base = serve(Arc::new(move |p: &Parts, body: &str| {
        let qid = q.lock().unwrap().clone();
        let path = p.uri.path();
        if path == "/compose" {
            return send_html(
                &format!("<html><body><input id=\"t\"><button id=\"go\">Post</button><script>document.getElementById(\"go\").onclick=()=>fetch(\"/api/{qid}/CreatePost\",{{method:\"POST\",headers:{{\"content-type\":\"application/json\"}},body:JSON.stringify({{text:document.getElementById(\"t\").value}})}})</script></body></html>"),
                200,
            );
        }
        if p.method == "POST" && path == format!("/api/{qid}/CreatePost") {
            let v: Value = serde_json::from_str(body).unwrap();
            ex.lock().unwrap().push(v["text"].as_str().unwrap_or("").to_string());
            return send_json(json!({ "ok": 1 }), 200);
        }
        send_json(json!({}), 404)
    }))
    .await;
    let steps =
        parse_steps(&json!([{ "action": "fill", "selector": "#t", "value": "{text}" }, { "action": "click", "selector": "#go" }])).unwrap();
    add_operation(add(
        "wb",
        "post",
        Trigger { url: format!("{base}/compose"), steps: Some(steps), soft_from: None },
        vec![json!({"text": "first post"})],
        None,
        true,
    ))
    .await
    .unwrap();
    assert_eq!(*executed.lock().unwrap(), Vec::<String>::new(), "learning a write must not send it");
    *qid.lock().unwrap() = NEW.to_string();
    let r = call("wb", "post", args(json!({"text": "second post"})), with_writes(fast())).await;
    assert!(r.ok, "{}", j(&r));
    assert_eq!(r.healed, Some(true));
    assert_eq!(*executed.lock().unwrap(), vec!["second post"], "only the validation send executed");
    api_anything::browser::close_browser().await;
}

// Was a bug: a rate-limited validation doesn't stop the heal: a read spends its second try on a
// browser recapture against the rate-limiting site, then the op is marked stale for 30 minutes.
#[tokio::test]
async fn rate_limited_while_validating_the_rescan_candidate_no_browser_recapture_and_no_stale_mark() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = fresh().await;
    let qid = Arc::new(Mutex::new(OLD.to_string()));
    let page_loads = Arc::new(AtomicUsize::new(0));
    let (q, pl) = (qid.clone(), page_loads.clone());
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let qid = q.lock().unwrap().clone();
        let path = p.uri.path();
        if path.starts_with("/u/") {
            if document_load(p) {
                pl.fetch_add(1, Ordering::SeqCst); // browser loads only, not the rescan's fetch
            }
            return send_html(
                &format!("<html><body><script>var r={{queryId:\"{qid}\",operationName:\"User\"}};fetch(\"/api/{qid}/User?name=\"+encodeURIComponent(location.pathname.split(\"/\")[2]))</script></body></html>"),
                200,
            );
        }
        if path == format!("/api/{qid}/User") {
            if qid == NEW {
                return send_json(json!({ "message": "Too many requests" }), 429);
            }
            return send_json(json!({ "user": { "name": params(p).get("name") } }), 200);
        }
        send_json(json!({}), 404)
    }))
    .await;
    add_operation(add(
        "rateb",
        "user",
        trigger(format!("{base}/u/{{name}}")),
        vec![json!({"name": "alice"}), json!({"name": "bobby"})],
        Some("user"),
        false,
    ))
    .await
    .unwrap();
    *qid.lock().unwrap() = NEW.to_string();
    let loads = page_loads.load(Ordering::SeqCst);
    let r = call("rateb", "user", args(json!({"name": "carol"})), fast()).await;
    assert_eq!(r.class, Class::Rate, "{}", j(&r));
    assert_eq!(
        page_loads.load(Ordering::SeqCst) - loads,
        0,
        "a browser run was spent on a rate-limited site; stale mark: {}",
        j(&stale("rateb", "user"))
    );
    assert_eq!(stale("rateb", "user"), None, "rate limiting marked the op stale for 30 min");
    api_anything::browser::close_browser().await;
}

// Was a bug: Chrome locks a profile to one process. While another api-anything process (the
// MCP server keeps its context open until stdin closes) holds ~/.api-anything/profile, a heal's
// recapture in this process cannot launch: the call fails and the op is marked stale for 30 min
// with tier 3 disabled, though nothing about the site is wrong.
#[tokio::test]
async fn a_heal_in_a_second_process_while_this_process_holds_the_browser_profile_still_heals() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = fresh().await;
    let version = Arc::new(AtomicUsize::new(1));
    let v = version.clone();
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let key = if v.load(Ordering::SeqCst) == 1 { "q" } else { "term" };
        let path = p.uri.path();
        if path == "/s" {
            return send_html(&format!("<html><body><script>fetch(\"/api/search?{key}=\"+encodeURIComponent(new URLSearchParams(location.search).get(\"q\")))</script></body></html>"), 200);
        }
        if path == "/api/search" {
            let q = params(p);
            if !q.contains_key(key) {
                return send_json(json!({ "error": "unknown argument" }), 404);
            }
            return send_json(json!({ "results": [{ "q": q.get(key) }, { "q": "x" }] }), 200);
        }
        send_json(json!({}), 404)
    }))
    .await;
    // this process opens the shared profile, as a running MCP server does
    add_operation(add(
        "xp",
        "search",
        trigger(format!("{base}/s?q={{q}}")),
        vec![json!({"q": "hello"}), json!({"q": "world"})],
        Some("results"),
        false,
    ))
    .await
    .unwrap();
    version.store(2, Ordering::SeqCst);
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-anything"))
        .args(["call", "xp", "search", "q=cats"])
        .env("API_ANYTHING_HOME", HOME.path())
        .env("API_ANYTHING_CHROME", std::env::var("API_ANYTHING_CHROME").unwrap_or_default())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let out = tokio::time::timeout(Duration::from_millis(120_000), child.wait_with_output())
        .await
        .expect("the second process finished in time")
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(!stdout.trim().is_empty(), "{}", String::from_utf8_lossy(&out.stderr));
    let r: Value = serde_json::from_str(stdout.trim().split('\n').next_back().unwrap()).unwrap();
    assert_eq!(r["ok"], json!(true), "{r}\nstale mark: {}", j(&stale("xp", "search")));
    assert_eq!(stale("xp", "search"), None, "op marked stale: {}", j(&stale("xp", "search")));
    api_anything::browser::close_browser().await;
}

// Was a bug: recapture learns from the call's own args whenever they are 3+ chars and distinct.
// An arg that equals a constant part of the request (q="search" vs the path /api/search) becomes a
// slot there too; the replay with the same args passes, so the template is saved and every later
// call with other args sends its query into the URL path.
#[tokio::test]
async fn recapture_with_a_call_arg_that_collides_with_a_constant_q_search_in_api_search_does_not_template_the_constant() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = fresh().await;
    let version = Arc::new(AtomicUsize::new(1));
    let v = version.clone();
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let key = if v.load(Ordering::SeqCst) == 1 { "q" } else { "term" };
        let path = p.uri.path();
        if path == "/s" {
            return send_html(&format!("<html><body><script>fetch(\"/api/search?{key}=\"+encodeURIComponent(new URLSearchParams(location.search).get(\"q\")))</script></body></html>"), 200);
        }
        let q = params(p);
        if path == "/api/search" && q.contains_key(key) {
            return send_json(json!({ "results": [{ "q": q.get(key) }, { "q": "x" }] }), 200);
        }
        send_json(json!({ "error": "not found" }), 404)
    }))
    .await;
    add_operation(add(
        "coll",
        "search",
        trigger(format!("{base}/s?q={{q}}")),
        vec![json!({"q": "hello"}), json!({"q": "world"})],
        Some("results"),
        false,
    ))
    .await
    .unwrap();
    version.store(2, Ordering::SeqCst);
    let healed = call("coll", "search", args(json!({"q": "search"})), fast()).await;
    assert!(healed.ok, "{}", j(&healed));
    let later = call("coll", "search", args(json!({"q": "cats"})), fast()).await;
    let slots = j(&first_op("coll").slots);
    assert!(later.ok, "{}\nslots after the heal: {slots}", j(&later));
    assert_eq!(later.tier, Some(1), "slots after the heal: {slots}");
    assert_eq!(later.data.as_ref().unwrap()[0], json!({ "q": "cats" }));
    api_anything::browser::close_browser().await;
}

// Was a bug: the example-args replay only runs for "missing" drift. A REST API that answers 404
// for an unknown entity named in the query (/api/user?name=nosuch) is drift, so the heal runs a
// browser recapture; the site renders its own 404 page without firing the API, so the heal
// "fails" and the op is marked stale for 30 min (tier 3 off) because a user does not exist.
#[tokio::test]
async fn status_404_for_an_unknown_entity_in_a_query_param_input_via_the_example_replay_no_browser_run_no_stale_mark() {
    if !chrome() {
        eprintln!("{SKIP}");
        return;
    }
    let _g = fresh().await;
    let page_loads = Arc::new(AtomicUsize::new(0));
    let pl = page_loads.clone();
    let known = ["alice", "bobby", "carol"];
    let base = serve(Arc::new(move |p: &Parts, _body: &str| {
        let path = p.uri.path();
        if let Some(rest) = path.strip_prefix("/u/") {
            if document_load(p) {
                pl.fetch_add(1, Ordering::SeqCst);
            }
            let name = api_anything::util::decode_uri_component(rest).unwrap_or_default();
            if !known.contains(&name.as_str()) {
                return send_html("<html><body>This account does not exist</body></html>", 404);
            }
            return send_html(&format!("<html><body><script>fetch(\"/api/user?name={name}\")</script></body></html>"), 200);
        }
        if path == "/api/user" {
            let q = params(p);
            let name = q.get("name").cloned().unwrap_or_default();
            return if known.contains(&name.as_str()) {
                send_json(json!({ "user": { "name": name } }), 200)
            } else {
                send_json(json!({ "error": "user not found" }), 404)
            };
        }
        send_json(json!({}), 404)
    }))
    .await;
    add_operation(add(
        "nf404",
        "user",
        trigger(format!("{base}/u/{{name}}")),
        vec![json!({"name": "alice"}), json!({"name": "bobby"})],
        Some("user"),
        false,
    ))
    .await
    .unwrap();
    let loads = page_loads.load(Ordering::SeqCst);
    let r = call("nf404", "user", args(json!({"name": "nosuchuser"})), fast()).await;
    assert!(!r.ok);
    assert_eq!(r.class, Class::Input, "{}", j(&r));
    assert_eq!(stale("nf404", "user"), None, "an unknown user marked the op stale: {}", j(&stale("nf404", "user")));
    assert_eq!(page_loads.load(Ordering::SeqCst) - loads, 0, "a browser run was spent on a not-found lookup");
    api_anything::browser::close_browser().await;
}
