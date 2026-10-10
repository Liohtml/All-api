//! Port of test/edge/learn-codec.test.ts: edge cases for learning and codecs. Each test is a
//! regression for a bug that was fixed. The `fillTrigger` / `addOperation` tests have no Rust
//! counterpart yet (no heal module) and are left out.
mod common;
use api_anything::codec::{get_at, set_at, walk};
use api_anything::http::build_request;
use api_anything::learn::{LearnInput, Learned, learn_operation, matches};
use api_anything::spec::{Match, Operation, Request, Trigger, parse_site};
use api_anything::types::{Exchange, Headers};
use api_anything::util::{b64_decode_lenient_str, b64_encode, search_of};
use common::{args, cookie, enc, ex, j, no_session, session};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

const MAC_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const SEC_CH_UA: &str = r#""Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140""#;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// `xhr({...})` with the default JSON answer `{results:[{id:1},{id:2}]}`.
fn xhr(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>) -> Exchange {
    xhr_res(method, url, headers, body, &json!({"results": [{"id": 1}, {"id": 2}]}).to_string(), "application/json")
}

fn xhr_res(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>, res_body: &str, content_type: &str) -> Exchange {
    let mut req = json!({"method": method, "url": url, "headers": headers.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<_, _>>()});
    if let Some(b) = body {
        req["body"] = json!(b);
    }
    ex(json!({"id": NEXT_ID.fetch_add(1, Ordering::SeqCst), "resourceType": "fetch", "request": req,
        "response": {"status": 200, "headers": {}, "contentType": content_type, "body": res_body}}))
}

fn get(url: &str) -> Exchange {
    xhr("GET", url, &[], None)
}

fn trigger(url: &str) -> Trigger {
    Trigger { url: url.to_string(), steps: None, soft_from: None }
}

/// The TS `learn(exchanges, examples, extra)` defaults; set the extras on the result.
fn input(exchanges: Vec<Exchange>, examples: Vec<Value>) -> LearnInput {
    LearnInput::new(exchanges, examples.into_iter().map(args).collect(), "op", trigger("https://site.test/"), true)
}

fn learn(exchanges: Vec<Exchange>, examples: Vec<Value>) -> Learned {
    learn_operation(&input(exchanges, examples)).unwrap()
}

fn learn_err(i: &LearnInput) -> String {
    learn_operation(i).unwrap_err().to_string()
}

/// Build the request a call with args would send (no session).
fn built(op: &Operation, a: Value) -> Request {
    build_request(op, &args(a), &no_session()).unwrap()
}

/// `new URL(req.url).searchParams.get(k)`
fn q(req: &Request, k: &str) -> Option<String> {
    Url::parse(&req.url).unwrap().query_pairs().find(|(a, _)| a == k).map(|(_, v)| v.into_owned())
}

fn pathname(url: &str) -> String {
    Url::parse(url).unwrap().path().to_string()
}

fn s(at: &str) -> Vec<String> {
    at.split(',').map(|x| x.to_string()).collect()
}

fn m(v: Value) -> Match {
    serde_json::from_value(v).unwrap()
}

/// `new Headers(h)` would not throw: every value is a ByteString without line breaks or NULs.
fn headers_ok(h: &Headers) -> bool {
    h.values().all(|v| v.chars().all(|c| (c as u32) <= 0xff && c != '\n' && c != '\r' && c != '\0'))
}

/// `new Headers(h).get(name)`: the values of every spelling of the name, joined.
fn hget(h: &Headers, name: &str) -> String {
    h.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect::<Vec<_>>().join(", ")
}

/* ------------------------------------------------------ passing regressions */

#[test]
fn round_trip_unicode_emoji_rtl_spaces_and_url_special_chars_in_query_path_form_and_json() {
    let tricky = vec!["café ☕ 🚀".to_string(), "مرحبا بالعالم".into(), "a&b=c#d%e+f".into(), "say \"hi\" 'there'".into(), "x".repeat(5000), "a/b?c".into()];
    let e = xhr(
        "POST",
        "https://site.test/api/users/nasa/search?q=nasa&x=1",
        &[("content-type", "application/x-www-form-urlencoded")],
        Some(&format!("vars={}&plain=nasa", enc(&json!({"term": "nasa", "n": 1}).to_string()))),
    );
    let mut i = input(vec![e.clone()], vec![json!({"q": "nasa"})]);
    i.id = Some(e.id);
    let op = learn_operation(&i).unwrap().operation;
    for v in tricky {
        let r = built(&op, json!({"q": v}));
        assert_eq!(q(&r, "q").as_deref(), Some(v.as_str()));
        assert_eq!(q(&r, "x").as_deref(), Some("1"));
        assert_eq!(get_at(&r, &s("path:2")).unwrap().unwrap(), json!(v));
        assert_eq!(pathname(&r.url).split('/').count(), 5, "a value with / stays in one path segment");
        assert_eq!(get_at(&r, &s("form:plain")).unwrap().unwrap(), json!(v));
        let vars: Value = serde_json::from_str(get_at(&r, &s("form:vars")).unwrap().unwrap().as_str().unwrap()).unwrap();
        assert_eq!(vars, json!({"term": v, "n": 1}));
    }
}

#[test]
fn case_difference_example_nasa_locates_the_sent_nasa_and_the_callers_case_is_sent() {
    let op = learn(vec![get("https://site.test/api/search?q=nasa")], vec![json!({"q": "NASA"})]).operation;
    assert_eq!(j(&op.slots), json!([{"param": "q", "at": ["query:q"]}]));
    assert_eq!(q(&built(&op, json!({"q": "SpaceX"})), "q").as_deref(), Some("SpaceX"));
}

#[test]
fn substring_template_keeps_surrounding_text_and_the_args_special_chars_x_search_style() {
    let op = learn(vec![get(&format!("https://site.test/api/search?q={}", enc("from:nasa lang:en {x}")))], vec![json!({"query": "nasa"})]).operation;
    assert_eq!(q(&built(&op, json!({"query": "a&b {c} 🚀"})), "q").as_deref(), Some("from:a&b {c} 🚀 lang:en {x}"));
}

#[test]
fn the_same_value_in_url_and_body_both_filled_warned() {
    let e = xhr("POST", "https://site.test/api/search?q=nasa", &[("content-type", "application/json")], Some(&json!({"query": "nasa", "page": 1}).to_string()));
    let learned = learn(vec![e], vec![json!({"q": "nasa"})]);
    let r = built(&learned.operation, json!({"q": "mars"}));
    assert_eq!(q(&r, "q").as_deref(), Some("mars"));
    assert_eq!(serde_json::from_str::<Value>(r.body.as_ref().unwrap()).unwrap(), json!({"query": "mars", "page": 1}));
    assert!(learned.warnings.iter().any(|w| w.contains("2 places")));
}

#[test]
fn text_plain_json_body_is_walked_as_json_numeric_json_leaf_gets_type_number_and_native_encoding() {
    let e = xhr("POST", "https://site.test/api/items", &[("content-type", "text/plain;charset=UTF-8")], Some(r#"{"id":1840000000000000001,"q":"rover"}"#));
    let op = learn(vec![e], vec![json!({"id": "1840000000000000001", "q": "rover"})]).operation;
    assert_eq!(op.params.iter().find(|p| p.name == "id").unwrap().kind.name(), "number");
    let r = built(&op, json!({"id": "1840000000000000999", "q": "lander"}));
    assert_eq!(r.body.as_deref(), Some(r#"{"id":1840000000000000999,"q":"lander"}"#));
}

#[test]
fn multipart_form_data_body_the_values_part_is_templated_boundary_kept() {
    let b = "----WebKitFormBoundaryAbC123";
    let body = format!("--{b}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nnasa\r\n--{b}\r\nContent-Disposition: form-data; name=\"n\"\r\n\r\n10\r\n--{b}--\r\n");
    let ct = format!("multipart/form-data; boundary={b}");
    let e = xhr("POST", "https://site.test/api/upload", &[("content-type", &ct)], Some(&body));
    let op = learn(vec![e], vec![json!({"q": "nasa"})]).operation;
    let r = built(&op, json!({"q": "mars {x} rover"}));
    assert_eq!(r.body.as_deref(), Some(body.replacen("nasa", "mars {x} rover", 1).as_str()));
    assert_eq!(r.headers["content-type"], ct);
}

#[test]
fn google_flights_style_json_inside_a_form_field_inside_json_a_value_in_several_roles() {
    let inner = json!([null, [[[["JFK", 0]], [["LAX", 0]], null, 0, null, null, "2026-10-01"], [[["LAX", 0]], [["JFK", 0]]]]]).to_string();
    let freq = json!([null, inner]).to_string();
    let e = xhr_res(
        "POST",
        "https://www.google.com/_/FlightsFrontendUi/data/travel.frontend.flights.FlightsFrontendService/GetShoppingResults?f.sid=-123&_reqid=4&rt=c",
        &[("content-type", "application/x-www-form-urlencoded;charset=UTF-8")],
        Some(&format!("f.req={}&", enc(&freq))),
        ")]}'\n[1]",
        "application/json",
    );
    let op = learn(vec![e], vec![json!({"origin": "JFK", "dest": "LAX", "date": "2026-10-01"})]).operation;
    let r = built(&op, json!({"origin": "SFO", "dest": "CDG", "date": "2026-12-24"}));
    let outer: Value = serde_json::from_str(get_at(&r, &s("form:f.req")).unwrap().unwrap().as_str().unwrap()).unwrap();
    let got: Value = serde_json::from_str(outer[1].as_str().unwrap()).unwrap();
    assert_eq!(got, json!([null, [[[["SFO", 0]], [["CDG", 0]], null, 0, null, null, "2026-12-24"], [[["CDG", 0]], [["SFO", 0]]]]]));
    assert!(r.body.as_ref().unwrap().ends_with('&'), "trailing empty pair kept byte-identical");
}

#[test]
fn persisted_query_sha256_in_extensions_volatile_with_the_operation_name_anchor_never_in_match() {
    let hash = format!("{}0123456789abcdef0123456789abcdef0123456789ab", "a".repeat(20));
    let e = get(&format!(
        "https://site.test/graphql?operationName=SearchQuery&variables={}&extensions={}",
        enc(r#"{"q":"nasa"}"#),
        enc(&json!({"persistedQuery": {"version": 1, "sha256Hash": hash}}).to_string())
    ));
    let op = learn(vec![e], vec![json!({"q": "nasa"})]).operation;
    let vol: Vec<Value> = op.volatile.iter().map(|v| json!([v.at, v.anchor])).collect();
    assert_eq!(vol, vec![json!([["query:extensions", "json:/persistedQuery/sha256Hash"], "SearchQuery"])]);
    assert_eq!(j(&op.matcher), json!({"method": "GET", "host": "site.test", "path": "/graphql", "operationName": "SearchQuery"}));
}

#[test]
fn laravel_angular_xsrf_header_mirrors_the_url_decoded_cookie_cookie_ref_with_url_decode_blanked_in_the_spec() {
    let raw = "eyJpdiI6IkFCQ0RFRkdISUpLTE1OT1AiLCJ2YWx1ZSI6Ing9In0%3D";
    let decoded = api_anything::util::decode_uri_component(raw).unwrap();
    let e = get_with("https://site.test/api/search?q=nasa", &[("x-xsrf-token", &decoded), ("cookie", &format!("XSRF-TOKEN={raw}"))]);
    let mut i = input(vec![e], vec![json!({"q": "nasa"})]);
    let mut c = cookie("XSRF-TOKEN", raw, "site.test");
    c.secure = true;
    i.cookies = vec![c];
    let op = learn_operation(&i).unwrap().operation;
    assert_eq!(j(op.slots.iter().find(|s| s.is_ref()).unwrap()), json!({"ref": "cookie:XSRF-TOKEN", "transform": "url-decode", "at": ["header:x-xsrf-token"]}));
    assert_eq!(op.request.headers["x-xsrf-token"], "");
}

fn get_with(url: &str, headers: &[(&str, &str)]) -> Exchange {
    xhr("GET", url, headers, None)
}

#[test]
fn match_picks_the_right_one_among_near_duplicate_requests_autocomplete_vs_search() {
    let suggest = xhr_res(
        "GET",
        "https://site.test/api/suggest?q=nasa",
        &[],
        None,
        &json!({"s": [{"x": "nasa"}, {"x": "nasa tv"}, {"x": "nasa live"}, {"x": "nasa jobs"}]}).to_string(),
        "application/json",
    );
    let search = xhr_res("GET", "https://site.test/api/search?q=nasa", &[], None, &json!({"r": [{"id": 1}]}).to_string(), "application/json");
    let mut i = input(vec![suggest, search], vec![json!({"q": "nasa"})]);
    i.matcher = Some(m(json!({"path": "/api/search"})));
    let op = learn_operation(&i).unwrap().operation;
    assert_eq!(pathname(&op.request.url), "/api/search");
}

/* -------------------------------------------------------------------- bugs */

#[test]
fn a_value_found_only_in_the_referer_header_is_not_in_the_request_would_silently_return_the_examples_data() {
    // GitHub-style owner/repo spans two path segments; the only single leaf holding it is the Referer.
    let e = get_with("https://api.site.test/repos/facebook/react", &[("referer", "https://site.test/facebook/react"), ("accept", "application/json")]);
    let mut i = input(vec![e], vec![json!({"repo": "facebook/react"})]);
    i.matcher = Some(m(json!({"path": "/repos/*/*"})));
    let err = learn_err(&i);
    assert!(err.contains("not in the learned request"), "{err}");
}

#[test]
fn a_subdomain_arg_found_only_in_origin_referer_is_not_in_the_request() {
    let e = get_with("https://api.tumblr.test/v2/blog/info", &[("origin", "https://nasa.tumblr.test"), ("referer", "https://nasa.tumblr.test/")]);
    let mut i = input(vec![e.clone()], vec![json!({"blog": "nasa"})]);
    i.id = Some(e.id);
    let err = learn_err(&i);
    assert!(err.contains("not in the learned request"), "{err}");
}

#[test]
fn an_example_value_inside_the_user_agent_sec_ch_ua_does_not_template_those_headers() {
    let e = get_with("https://shop.test/api/search?q=apple", &[("user-agent", MAC_UA), ("sec-ch-ua", SEC_CH_UA), ("accept", "application/json")]);
    let op = learn(vec![e], vec![json!({"q": "apple"})]).operation;
    let r = built(&op, json!({"q": "pear"}));
    assert_eq!(q(&r, "q").as_deref(), Some("pear"));
    assert_eq!(r.headers["user-agent"], MAC_UA);

    let e2 = get_with("https://shop.test/api/search?q=google", &[("user-agent", MAC_UA), ("sec-ch-ua", SEC_CH_UA)]);
    let r2 = built(&learn(vec![e2], vec![json!({"q": "google"})]).operation, json!({"q": "bing"}));
    assert_eq!(r2.headers["sec-ch-ua"], SEC_CH_UA);
}

#[test]
fn a_3_letter_example_like_app_does_not_rewrite_accept_content_type() {
    let e = xhr("POST", "https://site.test/api/search", &[("accept", "application/json"), ("content-type", "application/json")], Some(r#"{"q":"app"}"#));
    let r = built(&learn(vec![e], vec![json!({"q": "app"})]).operation, json!({"q": "shoes"}));
    assert_eq!(r.body.as_deref(), Some(r#"{"q":"shoes"}"#));
    assert_eq!(r.headers["content-type"], "application/json");
    assert_eq!(r.headers["accept"], "application/json");
}

#[test]
fn a_numeric_example_does_not_template_digits_inside_unrelated_numbers_timestamps_nor_retype_them() {
    let e = xhr("POST", "https://site.test/api/list?_=1727380100123", &[("content-type", "application/json")], Some(r#"{"limit":100,"since":1727380100456}"#));
    let op = learn(vec![e], vec![json!({"limit": "100"})]).operation;
    let r = built(&op, json!({"limit": "20"}));
    assert_eq!(r.body.as_deref(), Some(r#"{"limit":20,"since":1727380100456}"#));
    assert_eq!(q(&r, "_").as_deref(), Some("1727380100123"));
}

#[test]
fn a_boolean_example_true_binds_to_its_own_leaf_not_every_true_flag_in_the_request() {
    let variables = json!({"userId": "nasa", "includeReplies": true}).to_string();
    let features = json!({"verified_enabled": true, "media_enabled": true}).to_string();
    let e = get(&format!("https://site.test/graphql/Tweets?variables={}&features={}", enc(&variables), enc(&features)));
    let op = learn(vec![e], vec![json!({"userId": "nasa", "includeReplies": "true"})]).operation;
    let r = built(&op, json!({"userId": "nasa", "includeReplies": "false"}));
    assert_eq!(serde_json::from_str::<Value>(&q(&r, "variables").unwrap()).unwrap(), json!({"userId": "nasa", "includeReplies": false}));
    assert_eq!(
        serde_json::from_str::<Value>(&q(&r, "features").unwrap()).unwrap(),
        json!({"verified_enabled": true, "media_enabled": true}),
        "unrelated feature flags must not follow the arg"
    );
}

#[test]
fn one_example_value_inside_anothers_leaf_the_exact_leaf_keeps_its_own_param() {
    let op = learn(vec![get("https://site.test/api/search?q=new+york+pizza&city=new+york")], vec![json!({"q": "new york pizza", "city": "new york"})]).operation;
    let r = built(&op, json!({"q": "tacos", "city": "boston"}));
    assert_eq!(q(&r, "city").as_deref(), Some("boston"));
    assert_eq!(q(&r, "q").as_deref(), Some("tacos"));
}

#[test]
fn two_params_sharing_a_prefix_inside_one_leaf_are_both_templated() {
    let op = learn(vec![get(&format!("https://site.test/api/search?q={}", enc("from:nasa to:nasagov")))], vec![json!({"from": "nasa", "to": "nasagov"})]).operation;
    assert_eq!(q(&built(&op, json!({"from": "esa", "to": "spacex"})), "q").as_deref(), Some("from:esa to:spacex"));
}

#[test]
fn the_same_numeric_value_as_a_json_string_and_a_json_number_keeps_each_leafs_own_type() {
    let e = xhr("POST", "https://site.test/api/user", &[("content-type", "application/json")], Some(r#"{"id":"12345","ids":[12345]}"#));
    let r = built(&learn(vec![e], vec![json!({"id": "12345"})]).operation, json!({"id": "777"}));
    assert_eq!(r.body.as_deref(), Some(r#"{"id":"777","ids":[777]}"#));
}

#[test]
fn a_url_carried_inside_a_query_param_keeps_its_own_encoding_layer_arg_with_and_equals() {
    let op = learn(vec![get(&format!("https://site.test/api/go?next={}", enc("/search?q=nasa&page=1")))], vec![json!({"q": "nasa"})]).operation;
    let next = q(&built(&op, json!({"q": "a&page=9"})), "next").unwrap();
    let inner = Url::parse("https://site.test").unwrap().join(&next).unwrap();
    assert_eq!(inner.query_pairs().find(|(k, _)| k == "q").map(|(_, v)| v.into_owned()).as_deref(), Some("a&page=9"));
    assert_eq!(inner.query_pairs().filter(|(k, _)| k == "page").map(|(_, v)| v.into_owned()).collect::<Vec<_>>().join(","), "1");
}

#[test]
fn an_inline_graphql_string_literal_escapes_quotes_in_the_arg() {
    let e = xhr("POST", "https://site.test/graphql", &[("content-type", "application/json")], Some(&json!({"query": "{ search(q: \"nasa\") { id } }"}).to_string()));
    let op = learn(vec![e], vec![json!({"q": "nasa"})]).operation;
    let body: Value = serde_json::from_str(built(&op, json!({"q": "say \"hi\""})).body.as_ref().unwrap()).unwrap();
    assert_eq!(body["query"], json!("{ search(q: \"say \\\"hi\\\"\") { id } }"));
}

#[test]
fn a_twice_url_encoded_value_is_located_and_refilled_at_the_same_encoding_depth() {
    let e = get("https://site.test/api/search?state=q%3Dnew%2520york");
    let mut i = input(vec![e.clone()], vec![json!({"q": "new york"})]);
    i.id = Some(e.id);
    let op = learn_operation(&i).unwrap().operation;
    assert_eq!(search_of(&Url::parse(&built(&op, json!({"q": "los angeles"})).url).unwrap()), "?state=q%3Dlos%2520angeles");
}

#[test]
fn base64_encoded_json_in_a_query_param_is_a_decoded_layer() {
    let state = b64_encode(json!({"q": "nasa", "page": 1}).to_string().as_bytes());
    let e = get(&format!("https://site.test/api/search?s={}", enc(&state)));
    let mut i = input(vec![e.clone()], vec![json!({"q": "nasa"})]);
    i.id = Some(e.id);
    let op = learn_operation(&i).unwrap().operation;
    let sv = q(&built(&op, json!({"q": "mars"})), "s").unwrap();
    assert_eq!(serde_json::from_str::<Value>(&b64_decode_lenient_str(&sv)).unwrap(), json!({"q": "mars", "page": 1}));
}

#[test]
fn batched_graphql_array_body_gets_an_operation_name_in_its_match_so_it_does_not_match_other_graphql_ops() {
    let body = |op: &str, v: Value| json!([{"operationName": op, "variables": v, "query": format!("query {op} {{ x }}")}]).to_string();
    let e = xhr("POST", "https://site.test/graphql", &[("content-type", "application/json")], Some(&body("SearchProducts", json!({"q": "nasa"}))));
    let op = learn(vec![e], vec![json!({"q": "nasa"})]).operation;
    let other = Request { method: "POST".into(), url: "https://site.test/graphql".into(), headers: Headers::new(), body: Some(body("CartCount", json!({}))) };
    assert!(!matches(&op.matcher, &other), "match {} also accepts CartCount", j(&op.matcher));
}

#[test]
fn graphql_post_without_operation_name_field_match_uses_the_querys_operation_name() {
    let body = |name: &str, v: Value| json!({"query": format!("query {name}($q: String) {{ search(q: $q) {{ id }} }}"), "variables": v}).to_string();
    let e = xhr("POST", "https://site.test/graphql", &[("content-type", "application/json")], Some(&body("SearchProducts", json!({"q": "nasa"}))));
    let op = learn(vec![e], vec![json!({"q": "nasa"})]).operation;
    let other = Request { method: "POST".into(), url: "https://site.test/graphql".into(), headers: Headers::new(), body: Some(body("CartCount", json!({}))) };
    assert!(!matches(&op.matcher, &other), "match {} also accepts CartCount", j(&op.matcher));
}

/* ------------------------------------------------------------ codec basics */

#[test]
fn codec_walk_get_at_set_at_agree_for_every_leaf_of_a_mixed_request() {
    let req = Request {
        method: "POST".into(),
        url: "https://site.test/a/b%20c/d?x=1&y=%7B%22k%22%3A%5B1%2C%22v%22%5D%7D&z=".into(),
        headers: [("content-type", "application/x-www-form-urlencoded"), ("x-a", "h")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        body: Some("f=%5B%22a%22%2C%7B%22b%22%3A%22c%22%7D%5D&g=2".into()),
    };
    for leaf in walk(&req) {
        let got = get_at(&req, &leaf.at).unwrap().unwrap();
        let text = match &got {
            Value::String(t) => t.clone(),
            other => serde_json::to_string(other).unwrap(),
        };
        assert_eq!(text, leaf.value, "{}", leaf.at.join(" > "));
        if !leaf.container {
            assert_eq!(set_at(&req, &leaf.at, &got).unwrap(), req, "identity set at {}", leaf.at.join(" > "));
        }
    }
}

/* ------------------------------------------------------------------ batch 2 */

#[test]
fn a_referer_templated_with_the_arg_stays_a_valid_percent_encoded_header_for_non_ascii_args() {
    let e = get_with("https://site.test/api/search?q=nasa", &[("referer", "https://site.test/search?q=nasa")]);
    let op = learn(vec![e], vec![json!({"q": "nasa"})]).operation;
    let r = built(&op, json!({"q": "東京 café"}));
    assert_eq!(q(&r, "q").as_deref(), Some("東京 café"));
    assert!(headers_ok(&r.headers), "fetch rejects a non-ByteString header value");
    let referer = Url::parse(&r.headers["referer"]).unwrap();
    assert_eq!(referer.query_pairs().find(|(k, _)| k == "q").map(|(_, v)| v.into_owned()).as_deref(), Some("東京 café"));
}

#[test]
fn bundled_google_flights_spec_a_non_latin_1_city_goes_into_the_referer_percent_encoded() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../sites/google-flights.json")).unwrap();
    let site = parse_site(&serde_json::from_str(&text).unwrap()).unwrap();
    let op = site.operations.iter().find(|o| o.name == "search").unwrap();
    let r = built(op, json!({"origin": "東京", "destination": "São Paulo", "date": "2026-12-01"}));
    assert!(headers_ok(&r.headers));
    // the bundled op may carry no referer at all; then, as in the TS test, there is nothing to reject
    let referer = r.headers.get("referer").map(String::as_str).unwrap_or("");
    assert!(!referer.contains(' '), "referer is not a valid URL: {referer}");
}

#[test]
fn a_json_api_whose_path_ends_in_js_github_vercel_next_js_npm_chart_js_is_not_dropped_as_an_asset() {
    let e = xhr_res("GET", "https://api.github.test/repos/vercel/next.js", &[], None, &json!({"full_name": "vercel/next.js", "stargazers_count": 1}).to_string(), "application/json");
    let mut i = input(vec![e], vec![json!({"repo": "next.js"})]);
    i.matcher = Some(m(json!({"path": "/repos/vercel/*"})));
    let op = learn_operation(&i).unwrap().operation;
    assert_eq!(op.request.url, "https://api.github.test/repos/vercel/next.js");
}

#[test]
fn a_path_segment_that_carries_the_arg_as_a_substring_handle_is_wildcarded_in_match_passes() {
    let run = |h: &str| vec![xhr_res("GET", &format!("https://site.test/api/users/@{h}/profile.json"), &[], None, &json!({"user": {"name": h}}).to_string(), "application/json")];
    let mut i = LearnInput::new(run("nasa"), vec![args(json!({"handle": "nasa"})), args(json!({"handle": "spacex"}))], "op", trigger("https://site.test/@{handle}"), true);
    i.exchanges2 = Some(run("spacex"));
    let learned = learn_operation(&i).unwrap();
    assert_eq!(learned.operation.matcher.path.as_deref(), Some("/api/users/*/profile.json"));
    assert!(!learned.warnings.iter().any(|w| w.contains("no matching request")), "{}", learned.warnings.join("\n"));
}

#[test]
fn a_nonce_inside_a_templated_leaf_is_still_detected_by_the_two_run_diff_min_tier_3() {
    let run = |v: &str, sig: &str| vec![get(&format!("https://site.test/api/go?u={}", enc(&format!("/search?q={v}&sig={sig}"))))];
    let mut i = LearnInput::new(run("nasa", "Zx81kPq0aB3dF7gH2jK9"), vec![args(json!({"q": "nasa"})), args(json!({"q": "spacex"}))], "op", trigger("https://site.test/?q={q}"), true);
    i.exchanges2 = Some(run("spacex", "Qm4nR7sT1uV5wX8yZ2aB"));
    assert_eq!(learn_operation(&i).unwrap().operation.min_tier, 3);
}

#[test]
fn control_a_nonce_in_its_own_leaf_is_detected_by_the_two_run_diff_passes() {
    let run = |v: &str, sig: &str| vec![get(&format!("https://site.test/api/search?q={v}&sig={sig}"))];
    let mut i = LearnInput::new(run("nasa", "Zx81kPq0aB3dF7gH2jK9"), vec![args(json!({"q": "nasa"})), args(json!({"q": "spacex"}))], "op", trigger("https://site.test/?q={q}"), true);
    i.exchanges2 = Some(run("spacex", "Qm4nR7sT1uV5wX8yZ2aB"));
    assert_eq!(learn_operation(&i).unwrap().operation.min_tier, 3);
}

#[test]
fn an_array_example_library_add_binds_to_the_json_array_leaf_with_type_array() {
    let e = xhr("POST", "https://site.test/api/search", &[("content-type", "application/json")], Some(r#"{"tags":["nasa","mars"],"n":10}"#));
    let op = learn(vec![e], vec![json!({"tags": ["nasa", "mars"]})]).operation;
    assert_eq!(op.params[0].kind.name(), "array");
    assert_eq!(built(&op, json!({"tags": ["esa"]})).body.as_deref(), Some(r#"{"tags":["esa"],"n":10}"#));
}

#[test]
fn an_access_token_token_field_is_a_session_ref_never_literal_in_the_spec() {
    let secret = "EAAGm0PX4ZCpsBAKZCZBw7hjk2ZAn9ZCqZB8ZAzT";
    let slack = "xoxc-1234567890-1234567890-abcdef0123456789";
    let e = xhr(
        "POST",
        &format!("https://site.test/api/graphql?access_token={secret}"),
        &[("content-type", "application/x-www-form-urlencoded")],
        Some(&format!("token={slack}&variables={}", enc(r#"{"q":"nasa"}"#))),
    );
    let spec = serde_json::to_string(&learn(vec![e], vec![json!({"q": "nasa"})]).operation).unwrap();
    assert!(!spec.contains(secret), "access_token query value is literal in the spec");
    assert!(!spec.contains(slack), "token form value is literal in the spec");
}

#[test]
fn metas_x_fb_lsd_header_same_token_as_the_lsd_form_field_which_is_refd_is_not_literal_in_the_spec() {
    let lsd = "AVqbxe3J_YcQ1nKp";
    let e = xhr(
        "POST",
        "https://www.site.test/api/graphql/",
        &[("content-type", "application/x-www-form-urlencoded"), ("x-fb-lsd", lsd), ("x-fb-friendly-name", "SearchQuery")],
        Some(&format!("lsd={lsd}&fb_api_req_friendly_name=SearchQuery&variables={}", enc(r#"{"q":"nasa"}"#))),
    );
    let op = learn(vec![e], vec![json!({"q": "nasa"})]).operation;
    assert_eq!(op.slots.iter().find(|s| s.ref_str() == "session:op/lsd").map(|s| s.at.clone()), Some(vec!["form:lsd".to_string()]), "control: the form field is a ref");
    assert!(!serde_json::to_string(&op).unwrap().contains(lsd), "x-fb-lsd header keeps the lsd token literally");
}

#[test]
fn a_url_valued_example_link_preview_archive_lookup_locates_its_request() {
    let e = xhr_res("GET", &format!("https://tool.test/api/preview?url={}", enc("https://example.com/page")), &[], None, &json!({"title": "x", "links": [1, 2]}).to_string(), "application/json");
    let mut doc = xhr_res("GET", "https://tool.test/?u=https://example.com/page", &[], None, "<html></html>", "text/html");
    doc.resource_type = "document".into();
    let op = learn(vec![doc, e], vec![json!({"url": "https://example.com/page"})]).operation;
    assert_eq!(pathname(&op.request.url), "/api/preview");
}

#[test]
fn empty_string_and_very_long_args_at_call_time_passes() {
    let e = xhr("POST", "https://site.test/api/search?q=nasa", &[("content-type", "application/json")], Some(r#"{"q":"nasa"}"#));
    let op = learn(vec![e], vec![json!({"q": "nasa"})]).operation;
    let r = built(&op, json!({"q": ""}));
    assert_eq!(search_of(&Url::parse(&r.url).unwrap()), "?q=");
    assert_eq!(r.body.as_deref(), Some(r#"{"q":""}"#));
    let long = "ü".repeat(20000);
    assert_eq!(q(&built(&op, json!({"q": long})), "q").as_deref(), Some(long.as_str()));
}

#[test]
fn a_hand_written_spec_with_mixed_case_header_names_does_not_send_duplicated_joined_headers() {
    let site = parse_site(&json!({
        "name": "h",
        "baseUrl": "https://s.test",
        "operations": [{
            "name": "o",
            "readOnly": true,
            "trigger": {"url": "https://s.test/"},
            "request": {"method": "GET", "url": "https://s.test/api?q=x", "headers": {"X-CSRF-Token": "", "X-Search": "x"}},
            "params": [{"name": "q"}],
            "slots": [
                {"param": "q", "at": ["query:q"]},
                {"param": "q", "at": ["header:X-Search"]},
                {"ref": "session:tok", "at": ["header:x-csrf-token"]}
            ]
        }]
    }))
    .unwrap();
    let r = build_request(&site.operations[0], &args(json!({"q": "nasa"})), &session(vec![], &[("tok", "SECRET123")])).unwrap();
    assert_eq!(hget(&r.headers, "x-csrf-token"), "SECRET123");
    assert_eq!(hget(&r.headers, "x-search"), "nasa");
}

#[test]
fn a_repeated_query_key_tag_a_tag_b_locates_an_example_in_its_second_occurrence() {
    let e = get("https://s.test/api/search?tag=mars&tag=nasa");
    let mut i = input(vec![e.clone()], vec![json!({"tag": "nasa"})]);
    i.id = Some(e.id);
    assert!(learn_operation(&i).is_ok());
}

#[test]
fn example_equal_to_the_endpoints_own_path_segment_binds_it_with_a_warning_documented_kept_as_regression() {
    let learned = learn(vec![get("https://s.test/api/search?q=search")], vec![json!({"q": "search"})]);
    assert!(learned.warnings.iter().any(|w| w.contains("2 places")));
    assert_eq!(pathname(&built(&learned.operation, json!({"q": "nasa"})).url), "/api/nasa");
}
