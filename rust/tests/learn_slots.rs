//! Port of test/edge/learn-slots.test.ts: regressions for the learner's slots. Credentials that
//! reached the spec or were stored under the wrong name, and params the second example proves or
//! disproves. The Rust crate has no heal module yet, so the `addOperation` halves of the TS tests
//! are run through `learn_operation` with the same inputs (`add_like`), and the "nothing is saved"
//! directory checks are left out.
mod common;
use api_anything::http::build_request;
use api_anything::learn::{LearnInput, Learned, learn_operation, matches};
use api_anything::secrets::scan_secrets;
use api_anything::session::Session;
use api_anything::spec::{Match, Operation, Request, Trigger};
use api_anything::store::{export_site, save_site};
use api_anything::types::{Exchange, StoredCookie};
use api_anything::util::{b64_decode_lenient_str, b64_encode, search_of};
use common::{Home, args, enc, ex, j, no_session, site};
use indexmap::IndexMap;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

static HOME: LazyLock<Home> = LazyLock::new(Home::new);

const A: &str = "Zx81kLmN0pQrStUv2wXyZ3aBcD";
const B: &str = "Ys92jKnM1qRsTuVw3xYzA4bCdE";
const SID: &str = "q2Fz9kLmT0vXYb7NcW1pReHs3JuQa8Df";
const OPAQUE: &str = "k7Qm9xLp3Rv8Tz1Wn5Ys6Ub4Hc2Jd0Fa";
const LOCAL: &str = "http://127.0.0.1/api/search";

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::SeqCst)
}

fn xhr_res(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>, res_body: Value) -> Exchange {
    let mut req = json!({"method": method, "url": url, "headers": headers.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<_, _>>()});
    if let Some(b) = body {
        req["body"] = json!(b);
    }
    ex(json!({"id": next_id(), "resourceType": "fetch", "request": req,
        "response": {"status": 200, "headers": {}, "contentType": "application/json", "body": res_body.to_string()}}))
}

fn xhr(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>) -> Exchange {
    xhr_res(method, url, headers, body, json!({"results": [{"id": 1}, {"id": 2}]}))
}

fn get(url: &str) -> Exchange {
    xhr("GET", url, &[], None)
}

fn get_with(url: &str, headers: &[(&str, &str)]) -> Exchange {
    xhr("GET", url, headers, None)
}

/// `post(body, headers)`: a JSON POST to the search endpoint.
fn post(body: &str, headers: &[(&str, &str)]) -> Exchange {
    let mut h = vec![("content-type", "application/json")];
    h.extend_from_slice(headers);
    xhr("POST", "https://api.site.test/v1/search", &h, Some(body))
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

/// `String(err)` of a rejected learn: what the TS regexes are matched against.
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

/// a cookie of the host these requests go to: a replay finds it in the jar
fn here(name: &str, value: &str) -> StoredCookie {
    let mut c = cookie(name, value);
    c.domain = "127.0.0.1".into();
    c
}

fn storage(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
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

fn body_json(r: &Request) -> Value {
    serde_json::from_str(r.body.as_ref().unwrap()).unwrap()
}

fn spec_text(op: &Operation) -> String {
    serde_json::to_string(op).unwrap()
}

fn last(op: &Operation) -> Value {
    j(op.slots.last().unwrap())
}

fn m(v: Value) -> Match {
    serde_json::from_value(v).unwrap()
}

/// `JSON.stringify` of an object with keys in the given order (dynamic keys included).
fn obj(pairs: &[(&str, Value)]) -> Value {
    Value::Object(pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
}

/* ------------------------------------------------------- repeated keys */

#[test]
fn a_repeated_json_key_is_refused_where_a_slot_would_go_in_any_occurrence_and_is_a_constant_otherwise() {
    let sid_cookie = || vec![cookie("sid", SID)];
    let refused: Vec<(&str, String, Vec<StoredCookie>, Option<IndexMap<String, String>>)> = vec![
        // a credential by its name, in both occurrences and in the later one only
        ("token", format!(r#"{{"q":"nasa","token":"{A}","token":"{B}"}}"#), vec![], None),
        ("token", format!(r#"{{"q":"nasa","token":"x","token":"{B}"}}"#), vec![], None),
        // the later occurrence is an object: its leaves are not at the first one's path either
        ("auth", format!(r#"{{"q":"nasa","auth":1,"auth":{{"token":"{B}"}}}}"#), vec![], None),
        // a cookie and a stored value, whichever occurrence holds it
        ("n", format!(r#"{{"q":"nasa","n":"{SID}","n":"x"}}"#), sid_cookie(), None),
        ("n", format!(r#"{{"q":"nasa","n":"x","n":"{SID}"}}"#), sid_cookie(), None),
        ("n", r#"{"q":"nasa","n":1,"n":"solarized-dark"}"#.into(), vec![], Some(storage(&[("theme", "solarized-dark")]))),
        // the param itself, and a second copy of it
        ("q", r#"{"q":"nasa","q":"other"}"#.into(), vec![], None),
        ("k", r#"{"q":"nasa","k":"x","k":"nasa"}"#.into(), vec![], None),
        // a persisted-query id: a rescan would rewrite the first occurrence only
        ("doc_id", r#"{"q":"nasa","doc_id":"1234567890123","doc_id":"1234567890124"}"#.into(), vec![], None),
    ];
    for (name, body, cookies, st) in refused {
        let mut i = input(vec![post(&body, &[])], vec![json!({"q": "nasa"})]);
        i.cookies = cookies;
        i.storage = st;
        assert_match(&err(&i), &format!(r"repeats a key \(body > json:/{name}\) where a param or a session value goes"), &body);
    }
    // in JSON inside a string too
    let vars = json!({"q": "nasa", "vars": format!(r#"{{"token":"x","token":"{B}"}}"#)}).to_string();
    assert_match(&err(&input(vec![post(&vars, &[])], vec![json!({"q": "nasa"})])), r"repeats a key \(body > json:/vars > json:/token\)", "vars");
    // a repeated key that is no slot and holds none is sent as captured, byte for byte
    for body in [r#"{"q":"nasa","limit":1,"limit":2}"#, r#"{"q":"nasa","meta":{},"meta":{"a":[1]},"x":"y","x":"y"}"#] {
        let mut i = input(vec![post(body, &[])], vec![json!({"q": "nasa"})]);
        i.public = Some(strs(&["limit"]));
        let op = learn_operation(&i).unwrap().operation;
        assert_eq!(j(&op.slots), json!([{"param": "q", "at": ["body", "json:/q"]}]));
        assert_eq!(built(&op, json!({"q": "mars"}), &no_session()).body.as_deref(), Some(body.replacen("nasa", "mars", 1).as_str()));
    }
    // control: a repeated query key has a position of its own
    let op = learn(vec![get(&format!("https://api.site.test/v1/search?q=nasa&t={A}&t={B}"))], vec![json!({"q": "nasa"})]).operation;
    assert_eq!(search_of(&Url::parse(&built(&op, json!({"q": "mars"}), &no_session()).url).unwrap()), format!("?q=mars&t={A}&t={B}"));
}

/* ------------------------------------------------------------- public */

#[test]
fn a_name_marked_public_keeps_no_per_session_field_no_cookie_and_no_stored_value_literal() {
    const NEXT: &str = "Zx9Qw8vLm7Kj6HgF5dS4aP3oI2uY1tRe";
    let e = || {
        get_with(
            // token: a per-session field by name; sv: equal to a stored credential; theme: equal to a stored setting
            &format!("https://api.site.test/v1/search?q=kittens&token={A}&sv={B}&theme=solarized-dark"),
            // x-app: equal to a cookie; x-ctx: a cookie inside a longer leaf
            &[("x-app", SID), ("x-ctx", &format!("v1:{SID}")), ("cookie", &format!("sid={SID}"))],
        )
    };
    let base = || {
        let mut i = input(vec![e()], vec![json!({"q": "kittens"})]);
        i.cookies = vec![cookie("sid", SID)];
        i.storage = Some(storage(&[("cached", B), ("theme", "solarized-dark")]));
        i
    };
    let names = ["sv", "theme", "token", "x-app", "x-ctx"];
    // control: each of the five is a reference when nobody says otherwise
    let mut refs: Vec<String> = learn_operation(&base()).unwrap().operation.slots.iter().filter(|s| s.is_ref()).map(|s| s.at[0].split(':').nth(1).unwrap().to_string()).collect();
    refs.sort();
    assert_eq!(refs, strs(&names));
    let mut i = base();
    i.public = Some(strs(&names));
    let learned = learn_operation(&i).unwrap();
    let op = &learned.operation;
    // Every one of them is a reference under a public name too, as it was before this file's fixes:
    // the mark keeps a header by its name and a credential-like name literal, nothing else.
    assert_eq!(
        j(&op.slots),
        json!([
            {"param": "q", "at": ["query:q"]},
            {"ref": "session:op/cached", "at": ["query:sv"]},
            {"ref": "session:op/theme", "at": ["query:theme"]},
            {"ref": "cookie:sid", "at": ["header:x-app"]},
            {"ref": "session:op/token", "at": ["query:token"]},
            {"ref": "cookie:sid", "at": ["header:x-ctx"], "template": "v1:{cookie:sid}"}
        ])
    );
    assert_eq!(j(&learned.session_values), json!({"op/cached": B, "op/theme": "solarized-dark", "op/token": A}));
    assert_eq!(j(&op.public), json!(names));
    for live in [SID, A, B] {
        assert!(!spec_text(op).contains(live), "{live} is in the spec");
    }
    // ...so a replay follows the jar after the cookie rotates
    let r = built(op, json!({"q": "cats"}), &with_values(vec![cookie("sid", NEXT)], &learned.session_values));
    assert_eq!(r.url, format!("https://api.site.test/v1/search?q=cats&token={A}&sv={B}&theme=solarized-dark"));
    assert_eq!([r.headers["x-app"].as_str(), r.headers["x-ctx"].as_str()], [NEXT, &format!("v1:{NEXT}")]);
}

/* ------------------------------------------------ the add-shaped learn */

/// The learn an `add --from <capture>` runs: the capture's one exchange, its page, cookies, storage
/// and the caller's public names, with the test file's trigger and example.
fn add_like(e: Exchange, cookies: Vec<StoredCookie>, st: Option<IndexMap<String, String>>, public: Option<Vec<String>>) -> Result<Learned, anyhow::Error> {
    let mut i = LearnInput::new(vec![e], vec![args(json!({"q": "kittens"}))], "op", trigger("http://127.0.0.1/?q={q}"), true);
    i.pages = Some(strs(&["http://127.0.0.1/?q=kittens"]));
    i.cookies = cookies;
    i.storage = st;
    i.public = public;
    learn_operation(&i)
}

fn add_err(e: Exchange, cookies: Vec<StoredCookie>, st: Option<IndexMap<String, String>>, public: Option<Vec<String>>) -> String {
    format!("Error: {}", add_like(e, cookies, st, public).unwrap_err())
}

/// Save the learned op as a site of its own, as `add` would, so the export can be checked.
fn save_as(name: &str, base_url: &str, op: &Operation) {
    let _ = &*HOME;
    save_site(&site(json!({"name": name, "baseUrl": base_url, "operations": [j(op)]}))).unwrap();
}

#[test]
fn a_per_session_field_marked_public_is_saved_and_exported_as_a_reference_with_no_cookie_or_storage_behind_it() {
    let short = "aB3dEf9hK2";
    let requests: Vec<(&str, Exchange)> = vec![
        ("query:token", get(&format!("{LOCAL}?q=kittens&token={short}"))),
        ("form:token", xhr("POST", LOCAL, &[("content-type", "application/x-www-form-urlencoded")], Some(&format!("q=kittens&token={short}")))),
        ("body > json:/token", xhr("POST", LOCAL, &[("content-type", "application/json")], Some(&json!({"q": "kittens", "token": short}).to_string()))),
        // a short stored value inside the field: too short to cut out, so the whole field is the reference
        ("query:token", get(&format!("{LOCAL}?q=kittens&token=prefix:{short}:suffix"))),
    ];
    for (at, request) in requests {
        let st = if request.request.url.contains("prefix") { Some(storage(&[("cache", short)])) } else { None };
        let name = format!("public-token-{}", next_id());
        let op = add_like(request, vec![], st, Some(strs(&["token"]))).unwrap().operation;
        assert_eq!(last(&op), json!({"ref": "session:op/token", "at": at.split(" > ").collect::<Vec<_>>()}), "{at}");
        save_as(&name, "http://127.0.0.1", &op);
        let exported = export_site(&name, false).unwrap();
        for spec in [spec_text(&op), serde_json::to_string(&exported.spec).unwrap()] {
            assert!(!spec.contains(short), "{at}: the token is in the saved or exported spec");
        }
    }
}

/* ------------------------------------------------ a hole has no transform */

#[test]
fn a_cookie_sitting_unquoted_or_url_decoded_next_to_an_arg_in_one_leaf_is_refused_not_left_literal() {
    let bare = "ajax:4815162342108151623";
    let encoded = "eyJpdiI6IkFCQ0RFRkdISUpLTE1OT1AiLCJ2YWx1ZSI6Ing9In0%3D";
    let decoded = api_anything::util::decode_uri_component(encoded).unwrap();
    let cookies = || vec![cookie("JSESSIONID", &format!("\"{bare}\"")), cookie("XSRF-TOKEN", encoded), cookie("sid", SID)];
    let run = |ctx: &str| {
        let mut i = input(vec![get_with("https://api.site.test/v1/search?q=nasa", &[("x-ctx", ctx)])], vec![json!({"q": "nasa"})]);
        i.cookies = cookies();
        i
    };

    assert_match(&err(&run(&format!("user=nasa;auth={bare}"))), r"header:x-ctx holds cookie:JSESSIONID without its quotes.*credential.*Not learned: learn another request .*--pick-request", "unquoted");
    assert_match(&err(&run(&format!("user=nasa;xsrf={decoded}"))), r"header:x-ctx holds cookie:XSRF-TOKEN URL-decoded.*credential", "decoded");
    // the same in a leaf no param is in: only one of its credentials can be transformed when filled
    assert_match(&err(&run(&format!("{bare}:{decoded}"))), r"header:x-ctx holds cookie:XSRF-TOKEN URL-decoded", "both");

    // control: a copy as stored is a hole, and an unquoted copy alone in its leaf is a ref with a transform
    for ctx in [format!("user=nasa;auth=\"{bare}\";s={SID}"), format!("v1:{bare}")] {
        let op = learn_operation(&run(&ctx)).unwrap().operation;
        assert!(!spec_text(&op).contains(bare) && !spec_text(&op).contains(SID), "{}", j(&op.slots));
        assert_eq!(built(&op, json!({"q": "nasa"}), &jar(cookies())).headers["x-ctx"], ctx);
    }

    // another cookie holds the same text as stored: it fills the hole exactly, whatever the jar's order
    let both = || vec![cookie("quoted", &format!("\"{SID}\"")), cookie("raw", SID)];
    let mut i = input(vec![get_with("https://api.site.test/v1/search?q=nasa", &[("x-ctx", &format!("q=nasa;auth={SID}"))])], vec![json!({"q": "nasa"})]);
    i.cookies = both();
    let exact = learn_operation(&i).unwrap().operation;
    assert_eq!(last(&exact), json!({"param": "q", "at": ["header:x-ctx"], "template": "q={q};auth={cookie:raw}"}));
    assert_eq!(built(&exact, json!({"q": "mars"}), &jar(both())).headers["x-ctx"], format!("q=mars;auth={SID}"));
}

/* --------------------------------------------------- one name, one value */

#[test]
fn a_stored_value_found_inside_a_longer_leaf_never_takes_over_another_credentials_name() {
    // storage calls A "token"; the request's own token field holds B, and A rides inside other leaves
    let bodies = [
        json!({"q": "kittens", "token": B, "ctx": format!("v1:{A}"), "again": format!("v2:{A}")}),
        json!({"q": "kittens", "token": B, "next": format!("/search?q=kittens&t={A}")}),
    ];
    for body in bodies {
        let mut i = input(vec![post(&body.to_string(), &[])], vec![json!({"q": "kittens"})]);
        i.storage = Some(storage(&[("token", A)]));
        let learned = learn_operation(&i).unwrap();
        let op = &learned.operation;
        assert!(!spec_text(op).contains(A) && !spec_text(op).contains(B));
        let mut values: Vec<&String> = learned.session_values.values().collect();
        values.sort();
        assert_eq!(values, vec![B, A], "each value is stored once, under its own name");
        let r = built(op, json!({"q": "kittens"}), &with_values(vec![], &learned.session_values));
        assert_eq!(body_json(&r), body);
    }
}

/* ------------------------------------------------------- no overlapping */

// A container that is a session value (a JSON header named like a credential, a JSON value a cookie
// or the page's storage holds) is sent whole from the session. Nothing of it is in the spec: not a
// key, not a short leaf, in no encoding.
fn csrf(value: Value, url: &str) -> Exchange {
    get_with(url, &[("x-csrf-token", &value.to_string())])
}
fn csrf_local(value: Value) -> Exchange {
    csrf(value, &format!("{LOCAL}?q=kittens"))
}
fn posted(body: &str, url: &str) -> Exchange {
    xhr("POST", url, &[("content-type", "application/json")], Some(body))
}
fn saved_body() -> String {
    json!({"q": "kittens", "stamp": "aB3dE"}).to_string()
}
fn body_cookie() -> Vec<StoredCookie> {
    vec![cookie("last", &enc(&saved_body()))]
}

fn learn_with(e: Exchange, cookies: Vec<StoredCookie>, st: Option<IndexMap<String, String>>, public: Option<Vec<String>>) -> Result<Learned, anyhow::Error> {
    let mut i = input(vec![e], vec![json!({"q": "kittens"})]);
    i.cookies = cookies;
    i.storage = st;
    i.public = public;
    learn_operation(&i)
}

fn learn_err(e: Exchange, cookies: Vec<StoredCookie>, st: Option<IndexMap<String, String>>, public: Option<Vec<String>>) -> String {
    format!("Error: {}", learn_with(e, cookies, st, public).unwrap_err())
}

#[test]
fn a_param_inside_a_container_that_is_a_session_value_refuses_the_learn_and_nothing_is_saved() {
    let short = || vec![cookie("sess", "aB3dE")];
    let whole = obj(&[("q", json!("kittens")), (OPAQUE, json!("v1"))]);
    // keys that would keep the cookie's text in the spec if any part of the container were serialized:
    // the cookie as it is, percent-encoded, in base64, with text after it, in base64 twice
    let keys = ["aB3dE", "%61%42%33%64%45", "YUIzZEU=", "aB3dEx", "aB3dE:1", "aB3dEabcd", "%61%42%33%64%45x", "YUIzZEV4", "WVVJelpFVT0="];
    let mut cases: Vec<(String, Exchange, Vec<StoredCookie>, Option<IndexMap<String, String>>)> =
        keys.iter().map(|k| (format!("the key {k}"), csrf_local(obj(&[("q", json!("kittens")), (k, json!("v1"))])), short(), None)).collect();
    cases.push(("an opaque key".into(), csrf_local(whole), vec![], None));
    cases.push(("a short cookie beside the param".into(), csrf_local(json!({"q": "kittens", "stamp": "aB3dE"})), short(), None));
    for (what, e, cookies, st) in cases {
        let at = if e.request.body.is_some() { "body" } else { "header:x-csrf-token" };
        let refusal = format!(
            r"^Error: {at} is a session value \(.*\), sent whole .* the param q inside it \({at} > json:/q\) could not be filled.* --public {}; otherwise learn another request",
            at.replace("header:", "")
        );
        assert_match(&learn_err(e.clone(), cookies.clone(), st.clone(), None), &refusal, &what);
        assert_match(&add_err(e, cookies, st, None), &refusal, &what);
    }
}

// --public is the caller's word about a name. It turns off the rules that go by the name, so a
// container that was a session value by its header's name stays as captured. A cookie or a stored
// value is a reference under any name, whatever the value looks like.
#[test]
fn marked_public_a_container_that_is_in_no_cookie_and_no_storage_stays_as_captured_and_its_param_is_filled() {
    let short = vec![cookie("sess", "aB3dE")];
    let header = add_like(csrf_local(json!({"q": "kittens", "aB3dE": "v1"})), short, None, Some(strs(&["x-csrf-token"]))).unwrap();
    assert_eq!(j(&header.operation.slots), json!([{"param": "q", "at": ["query:q"]}, {"param": "q", "at": ["header:x-csrf-token", "json:/q"]}]));
    assert_eq!(built(&header.operation, json!({"q": "puppies"}), &no_session()).headers["x-csrf-token"], r#"{"q":"puppies","aB3dE":"v1"}"#);
}

#[test]
fn under_a_public_name_a_stored_value_is_a_reference_whatever_it_looks_like() {
    // none of these reads as a credential by its storage key or its shape: that is no proof it is none
    let bearer = format!("Bearer {A}");
    let cases: Vec<(&str, &str, &str, &str)> = vec![
        ("authorization", &bearer, &bearer, "cache"),
        ("x-app", "aB3dEf9hK2", "aB3dEf9hK2", "cache"),
        ("x-app", r#"{"token":"aB3dE4x"}"#, r#"{"token":"aB3dE4x"}"#, "cache"),
        ("x-app", "aB3dEf9hK2", r#"{"access":"aB3dEf9hK2"}"#, "cache/access"),
        // a setting the page keeps is one too, as it is under any other name
        ("x-theme", "solarized-dark", "solarized-dark", "cache"),
    ];
    for (name, header_value, cache, reference) in cases {
        let e = || get_with(&format!("{LOCAL}?q=kittens"), &[(name, header_value)]);
        let st = || Some(storage(&[("cache", cache)]));
        let public = || Some(strs(&[name]));
        let learned = learn_with(e(), vec![], st(), public()).unwrap();
        let added = add_like(e(), vec![], st(), public()).unwrap();
        for op in [&learned.operation, &added.operation] {
            assert_eq!(last(op), json!({"ref": format!("session:op/{reference}"), "at": [format!("header:{name}")]}), "{cache}");
            assert_eq!(op.request.headers[name], "");
            assert!(!spec_text(op).contains(&header_value.replace('"', "\\\"")), "{cache} is in the spec");
            assert_eq!(built(op, json!({"q": "puppies"}), &with_values(vec![], &learned.session_values)).headers[name], header_value);
        }
    }
}

#[test]
fn a_live_cookie_inside_a_public_container_is_a_reference_and_one_no_pass_can_make_a_reference_is_refused() {
    let jar_a = || vec![here("sid", A)];
    let rotated = jar(vec![here("sid", B)]);
    // a public header: the param and the cookie beside it are both filled, the rest is as captured
    let value = json!({"q": "kittens", "token": A, "flag": true});
    for learned in [
        learn_with(csrf_local(value.clone()), jar_a(), None, Some(strs(&["x-csrf-token"]))).unwrap(),
        add_like(csrf_local(value.clone()), jar_a(), None, Some(strs(&["x-csrf-token"]))).unwrap(),
    ] {
        let op = &learned.operation;
        assert_eq!(
            j(&op.slots),
            json!([
                {"param": "q", "at": ["query:q"]},
                {"param": "q", "at": ["header:x-csrf-token", "json:/q"]},
                {"ref": "cookie:sid", "at": ["header:x-csrf-token", "json:/token"]}
            ])
        );
        assert!(!spec_text(op).contains(A), "the cookie is in the spec");
        assert_eq!(built(op, json!({"q": "puppies"}), &rotated).headers["x-csrf-token"], json!({"q": "puppies", "token": B, "flag": true}).to_string());
    }

    // too short to be a reference, or in base64: the caller's word does not let a live cookie stay
    let stuck: Vec<(Value, StoredCookie)> = vec![(json!({"stamp": "aB3dE4x"}), here("sess", "aB3dE4x")), (json!({"stamp": b64_encode(A.as_bytes())}), here("sess", A))];
    for (inner, c) in stuck {
        let mut v = json!({"q": "kittens"});
        for (k, x) in inner.as_object().unwrap() {
            v[k] = x.clone();
        }
        let e = csrf_local(v);
        let refusal = r"keep a credential in the spec: header:x-csrf-token > json:/stamp holds the live cookie sess\.";
        assert_match(&learn_err(e.clone(), vec![c.clone()], None, Some(strs(&["x-csrf-token"]))), refusal, "learn");
        assert_match(&add_err(e, vec![c], None, Some(strs(&["x-csrf-token"]))), refusal, "add");
    }
}

#[test]
fn a_container_that_is_a_cookie_or_a_stored_value_as_a_whole_is_sent_whole_under_a_public_name_too() {
    let state = json!({"q": "kittens", "lang": "en"});
    // a cookie as the page decodes it, in a header and as a body; a body the page keeps in storage,
    // under a credential's name or any other
    let cases: Vec<(&str, Exchange, Vec<StoredCookie>, Option<IndexMap<String, String>>)> = vec![
        ("header:x-csrf-token", csrf_local(state.clone()), vec![cookie("ctx", &enc(&state.to_string()))], None),
        ("body", posted(&saved_body(), LOCAL), body_cookie(), None),
        ("body", posted(&saved_body(), LOCAL), vec![], Some(storage(&[("token", &saved_body())]))),
        ("body", posted(&saved_body(), LOCAL), vec![cookie("sess", "aB3dE")], Some(storage(&[("savedRequest", &saved_body())]))),
    ];
    for (at, e, cookies, st) in cases {
        // marking it public would change nothing, so the refusal does not offer that
        let refusal = format!(
            r"^Error: {at} is a session value \(.*\), sent whole .* the param q inside it \({at} > json:/q\) could not be filled\. Not learned: learn another request"
        );
        for public in [None, Some(strs(&[&at.replace("header:", "")]))] {
            let what = format!("{at} {public:?}");
            assert_match(&learn_err(e.clone(), cookies.clone(), st.clone(), public.clone()), &refusal, &what);
            assert_match(&add_err(e.clone(), cookies.clone(), st.clone(), public), &refusal, &what);
        }
    }
}

#[test]
fn a_container_that_is_a_session_value_with_only_refs_inside_is_one_ref_and_none_of_its_text_is_in_the_spec() {
    let cookies = || vec![cookie("sid", SID), cookie("sess", "aB3dE")];
    let absent = |op: &Operation, texts: &[&str]| {
        for text in texts {
            assert!(!spec_text(op).contains(text), "{text} is in the spec");
        }
    };

    // a header named like a credential: a cookie, an opaque key and a short cookie inside it
    let value = obj(&[("sid", json!(SID)), (OPAQUE, json!("leafValue42")), ("innerKey9", json!({"stamp": "aB3dE"}))]);
    let header = learn_with(csrf_local(value.clone()), cookies(), None, None).unwrap();
    assert_eq!(j(&header.operation.slots), json!([{"param": "q", "at": ["query:q"]}, {"ref": "session:op/x-csrf-token", "at": ["header:x-csrf-token"]}]));
    assert_eq!(header.operation.request.headers["x-csrf-token"], "");
    assert_eq!(j(&header.session_values), json!({"op/x-csrf-token": value.to_string()}));
    absent(&header.operation, &[SID, OPAQUE, "leafValue42", "innerKey9", "stamp", "aB3dE"]);
    let s = with_values(cookies(), &header.session_values);
    assert_eq!(built(&header.operation, json!({"q": "puppies"}), &s).headers["x-csrf-token"], value.to_string());

    // a body the page's storage holds whole: a live field, a per-session field and a query id under an opaque key
    let body = obj(&[("sid", json!(SID)), ("csrf", json!("Ab3dEf9h")), (OPAQUE, json!({"doc_id": "123456789012"}))]).to_string();
    let stored = learn_with(posted(&body, &format!("{LOCAL}?q=kittens")), cookies(), Some(storage(&[("savedRequest", &body)])), None).unwrap();
    assert_eq!(j(&stored.operation.slots), json!([{"param": "q", "at": ["query:q"]}, {"ref": "session:op/savedRequest", "at": ["body"]}]));
    assert_eq!(stored.operation.request.body.as_deref(), Some(""));
    assert_eq!(j(&stored.operation.volatile), json!([]));
    assert_eq!(j(&stored.session_values), json!({"op/savedRequest": body}));
    absent(&stored.operation, &[SID, OPAQUE, "Ab3dEf9h", "doc_id", "123456789012"]);
    assert_eq!(built(&stored.operation, json!({"q": "puppies"}), &with_values(cookies(), &stored.session_values)).body.as_deref(), Some(body.as_str()));
}

#[test]
fn a_body_that_is_no_session_value_takes_a_param_as_it_always_did() {
    // the same body as the saved one, with no copy in storage: an ordinary request body
    let op = learn_with(posted(&saved_body(), LOCAL), vec![cookie("sess", "aB3dE")], None, None).unwrap().operation;
    assert_eq!(j(&op.slots), json!([{"param": "q", "at": ["body", "json:/q"]}]));
    assert_eq!(built(&op, json!({"q": "puppies"}), &no_session()).body.as_deref(), Some(r#"{"q":"puppies","stamp":"aB3dE"}"#));
}

#[test]
fn a_path_segment_that_is_a_reference_is_a_wildcard_in_the_match_as_a_params_is() {
    // the session id rides in the path, with a dot so it does not look like a hash on its own
    let first = "u1.q2Fz9kLmT0vXYb7NcW1pReHs3JuQa8Df";
    let next = "u1.Zx9Qw8vLm7Kj6HgF5dS4aP3oI2uY1tRe";
    let run = |sid: &str, q: &str| vec![get_with(&format!("https://api.site.test/api/{sid}/search?q={q}"), &[("cookie", &format!("sid={sid}"))])];
    let captured = run(first, "kittens");
    let mut i = input(captured.clone(), vec![json!({"q": "kittens"}), json!({"q": "puppies"})]);
    i.cookies = vec![cookie("sid", first)];
    i.exchanges2 = Some(run(next, "puppies"));
    let learned = learn_operation(&i).unwrap();
    let op = &learned.operation;
    assert_eq!(j(op.slots.iter().find(|s| s.is_ref()).unwrap()), json!({"ref": "cookie:sid", "at": ["path:1"]}));
    assert_eq!(op.matcher.path.as_deref(), Some("/api/*/search"));
    assert!(matches(&op.matcher, &captured[0].request), "the match must fit the request it was learned from");
    assert!(!learned.warnings.iter().any(|w| w.contains("no matching request")), "{}", learned.warnings.join("\n"));
    assert_eq!(built(op, json!({"q": "cats"}), &jar(vec![cookie("sid", next)])).url, format!("https://api.site.test/api/{next}/search?q=cats"));
}

/* ------------------------------------------------- query-id field names */

#[test]
fn a_cookie_or_stored_value_is_a_reference_under_a_persisted_query_field_name_too() {
    let body = |fields: &[(&str, Value)]| {
        let mut pairs = vec![("q", json!("kittens"))];
        pairs.extend(fields.iter().cloned());
        vec![xhr("POST", "http://localhost/v1/search", &[("content-type", "application/json")], Some(&obj(&pairs).to_string()))]
    };
    let with = |exchanges: Vec<Exchange>, st: Option<IndexMap<String, String>>, cookies: Vec<StoredCookie>| {
        let mut i = input(exchanges, vec![json!({"q": "kittens"})]);
        i.storage = st;
        i.cookies = cookies;
        i
    };
    // A token the page stores and sends as queryId reads exactly like a query id it caches there:
    // the field's name decides nothing about a value that is known to be live.
    for name in ["queryId", "doc_id", "sha256Hash", "hash"] {
        let at = json!(["body", format!("json:/{name}")]);
        let inside = learn_operation(&with(body(&[(name, json!(format!("v1:{A}")))]), Some(storage(&[("token", A)])), vec![])).unwrap();
        assert!(!spec_text(&inside.operation).contains(A), "{name}: the stored token stayed in the spec");
        assert_eq!(last(&inside.operation), json!({"ref": "session:op/token", "at": at, "template": "v1:{session:op/token}"}));
        assert_eq!(j(&inside.session_values), json!({"op/token": A}));
        assert_eq!(serde_json::from_str::<Value>(inside.operation.request.body.as_ref().unwrap()).unwrap()[name], json!(""));

        let whole = learn_operation(&with(body(&[(name, json!(A))]), Some(storage(&[("token", A)])), vec![])).unwrap();
        assert_eq!(last(&whole.operation), json!({"ref": "session:op/token", "at": at}));
        let jar_ = learn_operation(&with(body(&[(name, json!(format!("v1:{A}")))]), None, vec![cookie("sid", A)])).unwrap();
        assert_eq!(last(&jar_.operation), json!({"ref": "cookie:sid", "at": at, "template": "v1:{cookie:sid}"}));
        // too short to template: the check refuses it there as anywhere else
        assert_match(&err(&with(body(&[(name, json!("v1:secret123"))]), None, vec![cookie("sess", "secret123")])), &format!("body > json:/{name} holds the live cookie sess"), name);
    }

    // so a hash the app keeps in storage is a reference as well, whatever it is kept as
    let hash = "e0f2a1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";
    let persisted = || [("extensions", json!({"persistedQuery": {"version": 1, "sha256Hash": hash}}))];
    let stores: Vec<(IndexMap<String, String>, &str)> = vec![
        (storage(&[("pq:Search", hash)]), "session:op/pq:Search"),
        (storage(&[("apollo-cache", &json!({"Search": {"id": hash}}).to_string())]), "session:op/apollo-cache/Search/id"),
    ];
    for (st, reference) in stores {
        let op = learn_operation(&with(body(&persisted()), Some(st), vec![])).unwrap().operation;
        assert_eq!(last(&op), json!({"ref": reference, "at": ["body", "json:/extensions/persistedQuery/sha256Hash"]}));
        assert_eq!(j(&op.volatile), json!([]));
        assert!(!spec_text(&op).contains(hash));
    }
    // control: a query id that is in no cookie and no storage stays a volatile anchor
    let plain = learn_operation(&with(body(&persisted()), Some(storage(&[("theme", "dark-mode")])), vec![])).unwrap().operation;
    assert_eq!(j(&plain.slots), json!([{"param": "q", "at": ["body", "json:/q"]}]));
    assert_eq!(plain.volatile.iter().map(|v| v.at.clone()).collect::<Vec<_>>(), vec![strs(&["body", "json:/extensions/persistedQuery/sha256Hash"])]);
    assert!(plain.request.body.as_ref().unwrap().contains(hash), "the hash stays in the template for the cheap heal to swap");
}

/* ------------------------------------------- the check behind every pass */

fn run_fields(fields: &[(&str, Value)], cookies: Vec<StoredCookie>, st: Option<IndexMap<String, String>>, public: Option<Vec<String>>) -> Result<Learned, anyhow::Error> {
    let mut pairs = vec![("q", json!("kittens"))];
    pairs.extend(fields.iter().cloned());
    learn_with(post(&obj(&pairs).to_string(), &[]), cookies, st, public)
}

fn run_err(fields: &[(&str, Value)], cookies: Vec<StoredCookie>, st: Option<IndexMap<String, String>>, public: Option<Vec<String>>) -> String {
    format!("Error: {}", run_fields(fields, cookies, st, public).unwrap_err())
}

#[test]
fn learning_refuses_a_request_it_could_not_clear_of_a_live_value_in_any_encoding_the_save_scan_reads() {
    let cases: Vec<(&str, StoredCookie, (&str, Value))> = vec![
        ("a cookie too short to template, inside a longer leaf", cookie("sess", "secret123"), ("ctx", json!("v1:secret123"))),
        ("a cookie in base64", cookie("sid", SID), ("state", json!(b64_encode(format!("sid={SID}").as_bytes())))),
        ("a cookie percent-encoded twice", cookie("sid", &format!("{SID}/=")), ("next", json!(enc(&format!("/cb?s={}", enc(&format!("{SID}/="))))))),
    ];
    for (label, c, field) in cases {
        let pattern = format!(r"keep a credential in the spec: body > json:/{} holds the live cookie {}\.", field.0, c.name);
        assert_match(&run_err(&[field], vec![c], None, None), &pattern, label);
    }
    // a session value the learner found by name counts too, where no pass reaches its second copy
    let fields = || [("csrf", json!("Ab3dEf9h")), ("ctx", json!("v1:Ab3dEf9h"))];
    assert_match(&run_err(&fields(), vec![], None, None), r"keep a credential in the spec: body > json:/ctx holds the live session value csrf\.", "by name");
    // ...and marking the per-session name public changes nothing: it is a reference all the same
    assert_match(&run_err(&fields(), vec![], None, Some(strs(&["csrf", "ctx"]))), r"body > json:/ctx holds the live session value csrf\. No name marked public waives one", "public");
    // a cookie is one under any name: the header that holds it is refused though marked public
    let held = get_with("https://api.site.test/v1/search?q=kittens", &[("x-ctx", "v1:secret123")]);
    assert_match(
        &learn_err(held, vec![cookie("sess", "secret123")], None, Some(strs(&["x-ctx"]))),
        r"keep a credential in the spec: header:x-ctx holds the live cookie sess\. No name marked public waives one",
        "header",
    );
}

fn found(field: &str, text: &str, value: &str) -> bool {
    !scan_secrets(&obj(&[(field, json!(text))]), &jar(vec![cookie("sid", value)]), &HashSet::new()).secrets.is_empty()
}

fn b64(s: &str) -> String {
    b64_encode(s.as_bytes())
}

#[test]
fn the_scan_finds_a_base64_copy_whatever_sits_before_it_and_of_a_value_too_short_to_decode_on_its_own() {
    const T: &str = "k7Qm9xLp3Rv8Tz1Wn5Ys6Ub4Hc2Jd0Fa";
    let found = |text: &str, value: &str| found("state", text, value);

    // six characters encode to eight, under the length at which a run is decoded as one
    assert_eq!(b64("aB3dE4"), "YUIzZEU0");
    assert!(found("YUIzZEU0", "aB3dE4"), "the short value's own encoding");
    // text in front of the encoding shifts what decoding the whole run gives
    assert!(found(&format!("prefix{}", b64(T)), T), "after a prefix");
    // the value at each byte offset inside encoded text, in both alphabets
    for lead in ["", "x", "xy"] {
        let inside = b64(&format!("{lead}aB3dE4??>>tail"));
        assert!(found(&inside, "aB3dE4??>>"), "standard alphabet, offset {}: {inside}", lead.len());
        assert!(found(&inside.replace('+', "-").replace('/', "_"), "aB3dE4??>>"), "URL-safe alphabet, offset {}", lead.len());
    }
    // control: other base64 text, and the encoding of a different value
    assert!(!found(&b64("nothing to see here, move along"), "aB3dE4"));
    assert!(!found(&b64("aB3dE5"), "aB3dE4"));

    // and learning refuses both of the reviewer's cases
    for (value, state) in [("aB3dE4", "YUIzZEU0".to_string()), (T, format!("prefix{}", b64(T)))] {
        assert_match(&run_err(&[("state", json!(state))], vec![cookie("sid", value)], None, None), r"keep a credential in the spec: body > json:/state holds the live cookie sid\.", value);
    }
}

#[test]
fn the_scan_reports_a_base64_copy_only_when_the_bytes_there_are_the_values() {
    let found = |text: &str, value: &str| found("cursor", text, value);

    // "xqbcdef" shares every character of abcdef's encoding that does not touch a neighbour: only
    // the first byte's top bits differ, and those sit in a character the value shares with what precedes it
    assert_eq!(b64_decode_lenient_str("eHFiY2RlZg=="), "xqbcdef");
    assert!(!found("eHFiY2RlZg==", "abcdef"), "another value with the same middle");
    // ...and learning the request that carries such a cursor is no longer refused
    let op = run_fields(&[("cursor", json!("eHFiY2RlZg=="))], vec![cookie("sid", "abcdef")], None, None).unwrap().operation;
    assert_eq!(serde_json::from_str::<Value>(op.request.body.as_ref().unwrap()).unwrap()["cursor"], json!("eHFiY2RlZg=="));

    // every byte beside the value changed in turn: the value itself is found, a neighbour of it never
    let value = "aB3dE4-z";
    for lead in 0..3 {
        for tail in 0..3 {
            let around = |v: &str| b64(&format!("{}{v}{}", &"xy"[..lead], &"pq"[..tail]));
            assert!(found(&format!("id={}&n=1", around(value)), value), "missed at offset {lead}, {tail} byte(s) after");
            for i in 0..value.len() {
                let flipped = ((value.as_bytes()[i] ^ 0x10) as char).to_string();
                let other = format!("{}{}{}", &value[..i], flipped, &value[i + 1..]);
                assert!(!found(&around(&other), value), "flagged {other} at offset {lead}, {tail} byte(s) after");
            }
        }
    }
}

#[test]
fn the_check_knows_a_stored_credential_that_no_pass_made_a_reference_and_no_stored_setting() {
    const T: &str = "k7Qm9xLp3Rv8Tz1Wn5Ys6Ub4Hc2Jd0Fa";
    let run = |fields: &[(&str, Value)], st: &[(&str, &str)], public: Option<Vec<String>>| run_fields(fields, vec![], Some(storage(st)), public);
    let run_err = |fields: &[(&str, Value)], st: &[(&str, &str)], public: Option<Vec<String>>| format!("Error: {}", run(fields, st, public).unwrap_err());
    let body_of = |l: &Learned| serde_json::from_str::<Value>(l.operation.request.body.as_ref().unwrap()).unwrap();

    // under a credential's name, and random-looking inside a JSON entry under an ordinary one
    assert_match(&run_err(&[("state", json!(b64(T)))], &[("token", T)], None), r"keep a credential in the spec: body > json:/state holds the live session value storage:token\.", "token");
    assert_match(
        &run_err(&[("state", json!(b64(T)))], &[("cache", &json!({"user": {"id": T}}).to_string())], None),
        r"body > json:/state holds the live session value storage:cache/user/id\.",
        "cache",
    );
    // A stored value that is one by its storage key's name alone is no ground to refuse a copy no
    // pass could make a reference: the text stays as captured, whichever entry holds it first. The
    // line falls at the value: a short token under `csrf` passes with the theme under `token`.
    let orders: Vec<Vec<(&str, &str)>> = vec![
        vec![("saved", "ordinary-value"), ("token", "ordinary-value")],
        vec![("token", "ordinary-value"), ("saved", "ordinary-value")],
        vec![("saved", "ordinary-value"), ("auth", r#"{"token":"ordinary-value"}"#)],
    ];
    for st in orders {
        let kept = run(&[("state", json!(b64("ordinary-value")))], &st, None).unwrap();
        assert_eq!(body_of(&kept)["state"], json!(b64("ordinary-value")), "{st:?}");
    }
    let short = run(&[("ctx", json!("v1:Ab3dEf9h"))], &[("csrf", "Ab3dEf9h")], None).unwrap();
    assert_eq!(body_of(&short)["ctx"], json!("v1:Ab3dEf9h"));
    // ...and where the same value can be a reference it is one, as before
    let referenced = run(&[("ctx", json!("ordinary-value")), ("state", json!(b64("ordinary-value")))], &[("token", "ordinary-value")], None).unwrap();
    assert_eq!(last(&referenced.operation), json!({"ref": "session:op/token", "at": ["body", "json:/ctx"]}));

    // a setting is no credential, wherever else it turns up
    let prefs = json!({"locale": "en-US-posix", "tz": "Europe/Berlin"}).to_string();
    let settings = [("theme", "dark-mode"), ("prefs", prefs.as_str())];
    let plain = run(&[("style", json!("dark-mode-v2")), ("state", json!(b64("en-US-posix|Europe/Berlin")))], &settings, None).unwrap();
    assert_eq!(j(&plain.operation.slots), json!([{"param": "q", "at": ["body", "json:/q"]}]));
    // ...also once a leaf that equals it has made it a reference: refreshable is not the same as secret
    let locale = "europe-berlin-posix";
    let sent = run(&[("locale", json!(locale)), ("state", json!(b64(locale)))], &[("locale", locale)], None).unwrap();
    assert_eq!(j(&sent.operation.slots), json!([{"param": "q", "at": ["body", "json:/q"]}, {"ref": "session:op/locale", "at": ["body", "json:/locale"]}]));
    assert_eq!(body_of(&sent)["state"], json!(b64(locale)));
    // but under a credential's name in the request the same stored text is one
    assert_match(&run_err(&[("token", json!(locale)), ("state", json!(b64(locale)))], &[("locale", locale)], None), "holds the live session value locale", "named token");

    // a name marked public exempts no stored credential...
    assert_match(&run_err(&[("state", json!(b64(T)))], &[("token", T)], Some(strs(&["state"]))), r"body > json:/state holds the live session value storage:token\.", "public state");
    // ...and no stored setting from being a ref, but the name it is sent under no longer makes it a credential
    let waived = run(&[("token", json!(locale)), ("state", json!(b64(locale)))], &[("locale", locale)], Some(strs(&["token"]))).unwrap();
    assert_eq!(last(&waived.operation), json!({"ref": "session:op/locale", "at": ["body", "json:/token"]}));
    assert_eq!(body_of(&waived)["state"], json!(b64(locale)));
    // exempt by position: the caller's own example
    const ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    let mut i = input(vec![get(&format!("https://api.site.test/v1/items/{ID}"))], vec![json!({"id": ID})]);
    i.storage = Some(storage(&[("lastViewed", ID)]));
    let viewed = learn_operation(&i).unwrap();
    assert_eq!(j(&viewed.operation.slots), json!([{"param": "id", "at": ["path:2"]}]));
    // a query-id field name exempts nothing: a stored hash sent there is a ref, and a copy of it elsewhere is found
    let hash = "e0f2a1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";
    assert_match(
        &run_err(&[("extensions", json!({"persistedQuery": {"sha256Hash": hash}})), ("state", json!(b64(hash)))], &[("pq:Search", hash)], None),
        "body > json:/state holds the live session value .*pq:Search",
        "hash",
    );

    // a container that is a session value is looked for whole, wherever else a copy of it sits
    let whole = json!({"n": "ab", "m": "cd"}).to_string();
    let copied = post(&json!({"q": "kittens", "state": b64(&whole)}).to_string(), &[("x-csrf-token", &whole)]);
    assert_match(&learn_err(copied, vec![], None, None), r"body > json:/state holds the live session value x-csrf-token\.", "whole");
}

#[test]
fn an_encoded_copy_of_a_setting_stored_under_a_credentials_key_is_kept_of_a_token_or_a_cookie_refused() {
    const T: &str = "k7Qm9xLp3Rv8Tz1Wn5Ys6Ub4Hc2Jd0Fa";
    let sent = |value: &str| get(&format!("{LOCAL}?q=kittens&ctx={}", enc(&b64(value))));
    let settings: Vec<Vec<(&str, &str)>> = vec![vec![("token", "solarized-dark")], vec![("cache", r#"{"token":"solarized-dark"}"#)]];
    for st in settings {
        let name = format!("setting-{}", next_id());
        let op = add_like(sent("solarized-dark"), vec![], Some(storage(&st)), Some(strs(&["ctx"]))).unwrap().operation;
        assert_eq!(j(&op.slots), json!([{"param": "q", "at": ["query:q"]}]));
        save_as(&name, "http://127.0.0.1", &op);
        assert_eq!(export_site(&name, false).unwrap().secrets, Vec::<String>::new());
        assert_eq!(built(&op, json!({"q": "puppies"}), &no_session()).url, format!("{LOCAL}?q=puppies&ctx={}", enc(&b64("solarized-dark"))));
    }
    // the same shape with a value that looks like a credential itself, and with a cookie
    let refused: Vec<(&str, Vec<StoredCookie>, Option<IndexMap<String, String>>, &str)> = vec![
        (T, vec![], Some(storage(&[("token", T)])), "session value storage:token"),
        (T, vec![], Some(storage(&[("cache", &json!({"token": T}).to_string())])), "session value storage:cache/token"),
        ("solarized-dark", vec![cookie("theme", "solarized-dark")], None, "cookie theme"),
    ];
    for (value, cookies, st, what) in refused {
        assert_match(&add_err(sent(value), cookies, st, Some(strs(&["ctx"]))), &format!(r"query:ctx holds the live {what}\."), what);
    }
}

/* --------------------------------------------- the text beside a param */

#[test]
fn the_text_beside_a_param_in_its_leaf_is_judged_by_the_leafs_name_as_a_whole_leaf_would_be() {
    const T: &str = "k7Qm9xLp3Rv8Tz1Wn5Ys6Ub4Hc2Jd0Fa";
    let search = "https://api.site.test/v1/search?q=";
    // A credential beside the arg cannot be a reference: no later capture could tell where the arg
    // ends and the credential begins. So every shape of it is refused, with the position and what to do.
    let refused: Vec<(&str, Exchange)> = vec![
        ("header:x-csrf-token", get_with(&format!("{search}kittens"), &[("x-csrf-token", &format!("kittens.{T}"))])),
        ("query:token", get(&format!("{search}kittens&token=kittens.{T}"))),
        ("query:api_key", get(&format!("{search}kittens&api_key={T}:kittens"))),
        ("query:token", get(&format!("{search}kittens&token=a1B2c3D4.kittens.{T}"))),
        ("query:token", get(&format!("{search}kittens&token=kittens{T}"))),
        ("query:token", get(&format!("{search}kittens&token=https://sso.site.test/{T}/kittens"))),
    ];
    let token_request = refused[1].1.clone();
    for (at, request) in refused {
        let name = &at[at.find(':').unwrap() + 1..];
        let url = request.request.url.clone();
        assert_match(
            &err(&input(vec![request], vec![json!({"q": "kittens"})])),
            &format!("^Error: {at} holds a param inside text that is a credential .* --public {name}; otherwise learn another request"),
            &url,
        );
    }
    // ...and the caller's word that the text is public lets it stay
    let mut i = input(vec![token_request], vec![json!({"q": "kittens"})]);
    i.public = Some(strs(&["token"]));
    let marked = learn_operation(&i).unwrap();
    assert_eq!(last(&marked.operation), json!({"param": "q", "at": ["query:token"], "template": format!("{{q}}.{T}")}));
    assert_eq!(j(&marked.session_values), json!({}));

    // an opaque token is one under any name: a UUID beside the arg, under a name that says nothing
    assert_match(
        &err(&input(vec![get(&format!("{search}kittens&ctx=kittens|550e8400-e29b-41d4-a716-446655440000"))], vec![json!({"q": "kittens"})])),
        r"^Error: query:ctx holds a param inside text that is a credential \(an unbroken random-looking run",
        "uuid",
    );

    // every character of the text counts, a NUL the value carries included: nine here, not the seven around them
    assert_match(
        &err(&input(vec![post(&json!({"q": "kittens", "token": "kittens.aB\0cD\0eF"}).to_string(), &[])], vec![json!({"q": "kittens"})])),
        r"^Error: body > json:/token holds a param inside text that is a credential \(by the leaf's name, token\)",
        "nul",
    );
    // control: seven characters, NULs counted, are under the rule's eight
    let short = learn(vec![post(&json!({"q": "kittens", "token": "kittens.a\0c\0eF"}).to_string(), &[])], vec![json!({"q": "kittens"})]);
    assert_eq!(short.operation.slots.last().unwrap().template.as_deref(), Some("{q}.a\0c\0eF"));
}

#[test]
fn structured_text_beside_a_param_is_no_credential_whatever_the_leaf_is_called() {
    // a name that reads like a credential's, and text long and mixed enough to look random as a whole
    let keys = [
        "search:kittens:page1",
        "query:kittens:page:1:sort:relevance",
        "search:kittens:locale:en-US:v2",
        "search:kittens:page1:sort:updated",
        // words and numbers joined by - or _ are structure too, and so is a path
        "kittens-care-guide-2024-v2",
        "list_kittens_sorted_by_price_desc_v2",
        "/v2/items/kittens/reviews/page/1",
    ];
    for cache_key in keys {
        let learned = learn(vec![post(&json!({"q": "kittens", "cache_key": cache_key}).to_string(), &[])], vec![json!({"q": "kittens"})]);
        let slot = learned.operation.slots.last().unwrap();
        assert_eq!(
            json!([slot.param, slot.at.join(" > "), slot.template]),
            json!(["q", "body > json:/cache_key", cache_key.replacen("kittens", "{q}", 1)]),
            "{cache_key}"
        );
        assert_eq!(j(&learned.session_values), json!({}));
        assert_eq!(body_json(&built(&learned.operation, json!({"q": "tigers"}), &no_session())), json!({"q": "tigers", "cache_key": cache_key.replacen("kittens", "tigers", 1)}));
    }
}

#[test]
fn beside_a_param_under_an_ordinary_name_a_known_live_value_too_short_to_template_is_refused_by_the_check() {
    let ctx = |value: &str| get_with("https://api.site.test/v1/search?q=kittens", &[("x-ctx", &format!("kittens.{value}"))]);
    assert_match(
        &learn_err(ctx("secret123"), vec![cookie("sess", "secret123")], None, None),
        r"keep a credential in the spec: header:x-ctx holds the live cookie sess; the template for header:x-ctx holds the live cookie sess\.",
        "cookie",
    );
    // a short stored value that is one by its key's name alone stays, as it did before the check existed
    assert_eq!(learn_with(ctx("Ab3dEf9h"), vec![], Some(storage(&[("csrf", "Ab3dEf9h")])), None).unwrap().operation.slots.len(), 2);
    // control: the same leaf with nothing known in it learns
    assert_eq!(learn_with(ctx("Ab3dEf9h"), vec![], None, None).unwrap().operation.slots.len(), 2);
}

/* ------------------------------------------- what example 2 disproves */

fn answer(q: &str) -> Value {
    json!({"results": [{"title": format!("{q} one")}, {"title": format!("{q} two")}]})
}

fn two(exchanges: Vec<Exchange>, examples: Vec<Value>, exchanges2: Vec<Exchange>) -> LearnInput {
    let mut i = input(exchanges, examples);
    i.exchanges2 = Some(exchanges2);
    i
}

#[test]
fn a_place_the_second_example_disproves_is_kept_as_the_constant_it_is_not_filled() {
    // "search" is the endpoint's own path segment and the first query; only the query follows in run 2
    let run = |q: &str, headers: &[(&str, &str)]| vec![xhr_res("GET", &format!("https://site.test/api/search?q={q}"), headers, None, answer(q))];
    let learned = learn_operation(&two(run("search", &[]), vec![json!({"q": "search"}), json!({"q": "kitten"})], run("kitten", &[]))).unwrap();
    let op = &learned.operation;
    assert_eq!(j(&op.slots), json!([{"param": "q", "at": ["query:q"]}]));
    assert_eq!(op.matcher.path.as_deref(), Some("/api/search"), "the segment is no param, so the match names it");
    assert_eq!(built(op, json!({"q": "puppy"}), &no_session()).url, "https://site.test/api/search?q=puppy");
    assert!(learned.warnings.iter().any(|w| w.contains("path:1 is \"search\" in both runs")), "{}", learned.warnings.join("\n"));

    // inside a longer leaf too: the header holds "search" by coincidence and never changes
    let app = [("x-app", "websearch-v2")];
    let templated = learn_operation(&two(run("search", &app), vec![json!({"q": "search"}), json!({"q": "kitten"})], run("kitten", &app))).unwrap();
    assert_eq!(j(&templated.operation.slots), json!([{"param": "q", "at": ["query:q"]}]));
    assert_eq!(built(&templated.operation, json!({"q": "puppy"}), &no_session()).headers["x-app"], "websearch-v2");

    // a sibling endpoint with the richer answer fits the first match (/api/*) too: run 2 is read on run 1's own path
    let both = |q: &str| {
        let mut v = run(q, &[]);
        v.push(xhr_res("GET", &format!("https://site.test/api/suggest?q={q}"), &[], None, json!({"suggestions": vec![json!({"text": format!("{q} and more")}); 40]})));
        v
    };
    let first = both("search");
    let mut i = two(first.clone(), vec![json!({"q": "search"}), json!({"q": "kitten"})], both("kitten"));
    i.id = Some(first[0].id);
    let picked = learn_operation(&i).unwrap();
    assert_eq!(j(&picked.operation.slots), json!([{"param": "q", "at": ["query:q"]}]));

    // control: one example cannot tell, so both places are filled, with a warning
    let one = learn(run("search", &[]), vec![json!({"q": "search"})]);
    assert_eq!(one.operation.slots.len(), 2);
}

#[test]
fn a_param_whose_every_place_the_second_example_disproves_is_a_failure_to_learn() {
    let run = || vec![xhr_res("GET", "https://site.test/api/search?sort=new", &[], None, answer("search"))];
    assert_match(
        &err(&two(run(), vec![json!({"q": "search"}), json!({"q": "kitten"})], run())),
        r#"example 2 disproves "q": path:1 is "search" in both runs.*would change nothing"#,
        "disproved",
    );
}

#[test]
fn run_2s_request_is_chosen_on_run_1s_evidence_a_request_that_does_not_answer_like_it_disproves_nothing() {
    // the path segment is the param; in run 2 the page also pings the first path, which only acknowledges
    let run1 = || vec![xhr_res("GET", "https://site.test/api/alpha?q=alpha", &[], None, answer("alpha"))];
    let second = |stale: Value| vec![xhr_res("GET", "https://site.test/api/alpha?q=bravo", &[], None, stale), xhr_res("GET", "https://site.test/api/bravo?q=bravo", &[], None, answer("bravo"))];
    let recipe = || -> Box<dyn Fn(&Exchange) -> bool> { Box::new(|e: &Exchange| e.body().contains("\"results\"")) };
    let cases: Vec<(Value, Option<Box<dyn Fn(&Exchange) -> bool>>)> = vec![
        (json!({"success": true}), None),
        (json!({"success": true}), Some(recipe())),
        // data, but not what the recipe reads
        (json!({"related": [{"name": "bravo and friends"}, {"name": "bravo again"}]}), Some(recipe())),
    ];
    for (stale, accepts) in cases {
        let mut i = two(run1(), vec![json!({"q": "alpha"}), json!({"q": "bravo"})], second(stale));
        i.accepts = accepts;
        let op = learn_operation(&i).unwrap().operation;
        assert_eq!(j(&op.slots), json!([{"param": "q", "at": ["path:1"]}, {"param": "q", "at": ["query:q"]}]));
        assert_eq!(op.matcher.path.as_deref(), Some("/api/*"));
        assert_eq!(built(&op, json!({"q": "charlie"}), &no_session()).url, "https://site.test/api/charlie?q=charlie");
    }
    // a run 2 with nothing that answers like run 1 is no grounds for dropping a slot
    let alone = learn_operation(&two(run1(), vec![json!({"q": "alpha"}), json!({"q": "bravo"})], second(json!({"success": true}))[..1].to_vec())).unwrap();
    assert_eq!(alone.operation.slots.len(), 2);
    assert!(
        alone.warnings.iter().any(|w| regex::Regex::new(r"run 2's matching request .* disproves nothing").unwrap().is_match(w)),
        "{}",
        alone.warnings.join("\n")
    );
}

#[test]
fn a_run_2_request_with_no_answer_or_an_error_for_one_is_no_data_answer_and_disproves_nothing() {
    let run1 = || vec![xhr_res("GET", "https://site.test/api/kittens?q=kittens", &[], None, answer("kittens"))];
    let stale = get("https://site.test/api/kittens?q=puppies");
    let fresh = xhr_res("GET", "https://site.test/api/puppies?q=puppies", &[], None, answer("puppies"));
    let mut unanswered = stale.clone();
    unanswered.response = None;
    let mut failed = stale.clone();
    {
        let r = failed.response.as_mut().unwrap();
        r.status = 404;
        r.body = Some(r#"{"error":"no such list"}"#.into());
    }
    for old in [unanswered, failed] {
        let op = learn_operation(&two(run1(), vec![json!({"q": "kittens"}), json!({"q": "puppies"})], vec![old.clone(), fresh.clone()])).unwrap().operation;
        assert_eq!(j(&op.slots), json!([{"param": "q", "at": ["path:1"]}, {"param": "q", "at": ["query:q"]}]));
        assert_eq!(built(&op, json!({"q": "tigers"}), &no_session()).url, "https://site.test/api/tigers?q=tigers");
        // alone, it may show a nonce but takes no slot away
        let alone = learn_operation(&two(run1(), vec![json!({"q": "kittens"}), json!({"q": "puppies"})], vec![old])).unwrap();
        assert_eq!(alone.operation.slots.len(), 2);
    }
}

#[test]
fn a_read_the_caller_pinned_whose_own_answer_is_a_flag_is_its_own_counterpart_in_run_2() {
    // "is this liked?" answers {"liked":true}: no data by the ranking's lights, and the op all the same
    let liked = |id: u64| vec![xhr_res("GET", &format!("https://site.test/api/liked?id={id}&v=42"), &[], None, json!({"liked": true}))];
    let mut i = two(liked(42), vec![json!({"id": 42}), json!({"id": 43})], liked(43));
    i.matcher = Some(m(json!({"path": "/api/liked"})));
    let learned = learn_operation(&i).unwrap();
    assert_eq!(j(&learned.operation.slots), json!([{"param": "id", "at": ["query:id"]}]));
    assert!(!learned.warnings.iter().any(|w| w.contains("disproves nothing")), "{}", learned.warnings.join("\n"));
}

/* ------------------------------------------------------ short examples */

// The visitor's own country rides along as gl=US on every request, whatever country is asked for.
fn by_country(c: &str) -> Vec<Exchange> {
    vec![
        xhr_res("GET", "https://api.site.test/v1/geo?gl=US", &[], None, json!({"stores": vec![json!({"city": "Springfield", "open": true}); 60]})),
        xhr_res("GET", &format!("https://api.site.test/v1/top?country={c}&gl=US&lang=en-{c}"), &[], None, answer(&format!("top in {c}"))),
    ]
}

fn pathname(url: &str) -> String {
    Url::parse(url).unwrap().path().to_string()
}

#[test]
fn a_short_example_is_placed_where_a_whole_leaf_equals_it_and_follows_a_different_second_example() {
    let learned = learn_operation(&two(by_country("US"), vec![json!({"q": "US"}), json!({"q": "CA"})], by_country("CA"))).unwrap();
    assert_eq!(pathname(&learned.exchange.request.url), "/v1/top", "the request whose leaf follows, not the bigger one");
    assert_eq!(j(&learned.operation.slots), json!([{"param": "q", "at": ["query:country"]}]));
    assert_eq!(built(&learned.operation, json!({"q": "DE"}), &no_session()).url, "https://api.site.test/v1/top?country=DE&gl=US&lang=en-US");

    // a page number: a JSON number beside another 2 that is no page
    let page = |n: u64| vec![post(&json!({"q": "kittens", "page": n, "size": 2}).to_string(), &[])];
    let paged = learn_operation(&two(page(2), vec![json!({"q": "kittens", "page": 2}), json!({"q": "kittens", "page": 3})], page(3))).unwrap();
    assert_eq!(j(&paged.operation.slots), json!([{"param": "q", "at": ["body", "json:/q"]}, {"param": "page", "at": ["body", "json:/page"]}]));
    assert_eq!(paged.operation.params.iter().find(|p| p.name == "page").unwrap().kind.name(), "number");
    assert_eq!(built(&paged.operation, json!({"q": "cats", "page": 7}), &no_session()).body.as_deref(), Some(r#"{"q":"cats","page":7,"size":2}"#));
    assert_eq!(paged.operation.min_tier, 1, "{}", paged.warnings.join("\n"));
}

#[test]
fn the_evidence_for_a_short_example_is_the_same_endpoint_in_run_2_not_any_request_to_the_host() {
    let records = |n: usize, of: &str| json!({"items": (0..n).map(|i| json!({"id": i, "of": of})).collect::<Vec<_>>()});
    // the feed always asks for US and answers with more; only /top follows the example
    let run = |c: &str| {
        vec![
            xhr_res("GET", "https://api.site.test/api/feed?country=US", &[], None, records(100, "US")),
            xhr_res("GET", &format!("https://api.site.test/api/top?country={c}"), &[], None, records(2, c)),
        ]
    };
    let learned = learn_operation(&two(run("US"), vec![json!({"country": "US"}), json!({"country": "CA"})], run("CA"))).unwrap();
    assert_eq!(pathname(&learned.exchange.request.url), "/api/top");
    assert_eq!(j(&learned.operation.slots), json!([{"param": "country", "at": ["query:country"]}]));

    // the same endpoint, allowing for path segments that are params themselves
    let posts = |user: &str, page: u64| vec![xhr_res("GET", &format!("https://api.site.test/v1/users/{user}/posts?page={page}"), &[], None, records(3, user))];
    let paged = learn_operation(&two(posts("alice", 2), vec![json!({"user": "alice", "page": 2}), json!({"user": "bobby", "page": 3})], posts("bobby", 3))).unwrap();
    assert_eq!(j(&paged.operation.slots), json!([{"param": "user", "at": ["path:2"]}, {"param": "page", "at": ["query:page"]}]));
    let top = |c: &str| vec![xhr_res("GET", &format!("https://api.site.test/v1/top/{c}"), &[], None, records(3, c))];
    let segment = learn_operation(&two(top("US"), vec![json!({"country": "US"}), json!({"country": "CA"})], top("CA"))).unwrap();
    assert_eq!(j(&segment.operation.slots), json!([{"param": "country", "at": ["path:2"]}]));
}

#[test]
fn a_short_example_without_that_evidence_is_refused_with_a_hint_to_pass_a_second_one() {
    let hint = r#"q="US": example values need at least 3 characters.*second example"#;
    assert_match(&err(&input(by_country("US"), vec![json!({"q": "US"})])), hint, "one");
    assert_match(&err(&two(by_country("US"), vec![json!({"q": "US"}), json!({"q": "us"})], by_country("US"))), hint, "same");
    assert_match(&err(&input(by_country("US"), vec![json!({"q": "US"}), json!({"q": "CA"})])), hint, "a second example needs its run");
    // a second run in which no leaf follows: every US is somebody else's
    let mut i = two(by_country("US"), vec![json!({"q": "US"}), json!({"q": "CA"})], by_country("US"));
    i.matcher = Some(m(json!({"path": "/v1/top"})));
    assert_match(&err(&i), r#"example 2 disproves "q": query:country is "US" in both runs.*query:gl is "US" in both runs"#, "both runs");
    // a second run without the request: nothing confirms the place
    let mut i = two(by_country("US"), vec![json!({"q": "US"}), json!({"q": "CA"})], vec![]);
    i.matcher = Some(m(json!({"path": "/v1/top"})));
    assert_match(&err(&i), "run 2 produced no request matching .*short example of q", "no request");
    // inside a longer leaf only: a short value is never a part of one
    let lang = |c: &str| vec![get(&format!("https://api.site.test/v1/top?lang=en-{c}"))];
    let mut i = two(lang("US"), vec![json!({"q": "US"}), json!({"q": "CA"})], lang("CA"));
    i.matcher = Some(m(json!({"path": "/v1/top"})));
    assert_match(&err(&i), r#""q" \("US"\) is not in the learned request.*whole leaf"#, "inside");
}

#[test]
fn a_short_example_in_either_set_asks_whole_leaf_evidence_of_both() {
    // only the second example is short: it must not be placed inside en-US by way of the first
    let lang = |c: &str| vec![get(&format!("https://api.site.test/v1/top?lang=en-{c}"))];
    assert_match(&err(&two(lang("USA"), vec![json!({"q": "USA"}), json!({"q": "US"})], lang("US"))), "no captured request carries the example values", "none");
    let mut i = two(lang("USA"), vec![json!({"q": "USA"}), json!({"q": "US"})], lang("US"));
    i.matcher = Some(m(json!({"path": "/v1/top"})));
    assert_match(&err(&i), r#""q" \("USA"\) is not in the learned request.*whole leaf"#, "matched");
    assert_match(
        &err(&input(lang("USA"), vec![json!({"q": "USA"}), json!({"q": "US"})])),
        r#"example 2 q="US": example values need at least 3 characters.*second example"#,
        "a short second example needs its run too",
    );
    // control: whole leaves in both runs
    let whole = |c: &str| vec![get(&format!("https://api.site.test/v1/top?country={c}&lang=en-{c}"))];
    let op = learn_operation(&two(whole("USA"), vec![json!({"q": "USA"}), json!({"q": "US"})], whole("US"))).unwrap().operation;
    assert_eq!(j(&op.slots), json!([{"param": "q", "at": ["query:country"]}]));
}
