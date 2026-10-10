mod common;
use api_anything::codec::get_at;
use api_anything::http::build_request;
use api_anything::learn::{LearnInput, RankOptions, learn_operation, matches, rank_candidates};
use api_anything::spec::{Match, Trigger};
use api_anything::types::{Exchange, StoredCookie};
use common::{args, cookie, enc, ex, exs, j, session};
use serde_json::{Value, json};

fn x_cookies() -> Vec<StoredCookie> {
    vec![cookie("ct0", "c0ffee0123456789abcdef", ".x.com"), cookie("auth_token", "a1b2c3d4e5f60718293a", ".x.com"), cookie("gt", "1840000000000000001", ".x.com")]
}
const BEARER: &str = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7";

fn x_exchanges(handle: &str, txn: &str, id0: u64) -> Vec<Exchange> {
    let variables = json!({"screen_name": handle, "withSafetyMode": true}).to_string();
    let features = json!({"hidden_profile_subscriptions_enabled": true}).to_string();
    exs(json!([
        {"id": id0, "resourceType": "document", "request": {"method": "GET", "url": format!("https://x.com/{handle}"), "headers": {"user-agent": "Mozilla/5.0 Chrome/153.0.0.0"}},
         "response": {"status": 200, "headers": {}, "body": format!("<html><title>{handle} / X</title></html>"), "contentType": "text/html; charset=utf-8"}},
        {"id": id0 + 1, "resourceType": "script", "request": {"method": "GET", "url": "https://abs.twimg.com/responsive-web/main.abc.js", "headers": {}},
         "response": {"status": 200, "headers": {}, "body": "var x", "contentType": "application/javascript"}},
        {"id": id0 + 2, "resourceType": "xhr", "request": {"method": "POST", "url": format!("https://www.google-analytics.com/g/collect?v=2&dl=https%3A%2F%2Fx.com%2F{handle}"), "headers": {}},
         "response": {"status": 204, "headers": {}, "contentType": ""}},
        {"id": id0 + 3, "resourceType": "xhr", "request": {"method": "GET",
            "url": format!("https://x.com/i/api/graphql/Gb-d6r0vxPOADdG62OEBpQ/UserByScreenName?variables={}&features={}", enc(&variables), enc(&features)),
            "headers": {":authority": "x.com", "accept": "*/*", "accept-encoding": "gzip, deflate, br, zstd", "authorization": BEARER,
                "cookie": "ct0=c0ffee0123456789abcdef; auth_token=a1b2c3d4e5f60718293a; gt=1840000000000000001",
                "x-csrf-token": "c0ffee0123456789abcdef", "x-guest-token": "1840000000000000001", "x-client-transaction-id": txn,
                "x-twitter-auth-type": "OAuth2Session", "referer": format!("https://x.com/{handle}"), "sec-fetch-site": "same-origin", "user-agent": "Mozilla/5.0 Chrome/153.0.0.0"}},
         "response": {"status": 200, "headers": {}, "contentType": "application/json; charset=utf-8",
            "body": json!({"data": {"user": {"result": {"rest_id": "11348282", "legacy": {"screen_name": handle.to_uppercase(), "name": "Name", "followers_count": 1}}}}}).to_string()}}
    ]))
}

fn trigger(url: &str) -> Trigger {
    Trigger { url: url.to_string(), steps: None, soft_from: None }
}

fn input(exchanges: Vec<Exchange>, examples: Vec<Value>, name: &str, url: &str, read_only: bool) -> LearnInput {
    LearnInput::new(exchanges, examples.into_iter().map(args).collect(), name, trigger(url), read_only)
}

#[test]
fn x_like_graphql_get() {
    let mut i = input(x_exchanges("nasa", "txnAAAAAAAAAAAAAAAAAAAAAAA", 1), vec![json!({"screen_name": "nasa"}), json!({"screen_name": "spacex"})], "getUser", "https://x.com/{screen_name}", true);
    i.exchanges2 = Some(x_exchanges("spacex", "txnBBBBBBBBBBBBBBBBBBBBBBB", 10));
    i.cookies = x_cookies();
    let learned = learn_operation(&i).unwrap();
    let op = &learned.operation;
    assert!(op.request.url.starts_with("https://x.com/i/api/graphql/Gb-d6r0vxPOADdG62OEBpQ/UserByScreenName?"));
    let params: Vec<Value> = op.slots.iter().filter(|s| s.is_param()).map(j).collect();
    assert_eq!(params, vec![json!({"param": "screen_name", "at": ["query:variables", "json:/screen_name"]}), json!({"param": "screen_name", "at": ["header:referer"], "template": "https://x.com/{screen_name}"})]);
    let mut refs: Vec<(String, String)> = op.slots.iter().filter(|s| s.is_ref()).map(|s| (s.ref_str().to_string(), s.at.join(","))).collect();
    refs.sort();
    assert_eq!(
        refs,
        vec![
            ("cookie:ct0".to_string(), "header:x-csrf-token".to_string()),
            ("cookie:gt".to_string(), "header:x-guest-token".to_string()),
            ("session:getUser/authorization".to_string(), "header:authorization".to_string()),
            ("session:getUser/x-client-transaction-id".to_string(), "header:x-client-transaction-id".to_string()),
        ]
    );
    assert_eq!(j(&learned.session_values), json!({"getUser/authorization": BEARER, "getUser/x-client-transaction-id": "txnAAAAAAAAAAAAAAAAAAAAAAA"}));
    let mut keys: Vec<&String> = op.request.headers.keys().collect();
    keys.sort();
    assert_eq!(keys, vec!["accept", "authorization", "referer", "sec-fetch-site", "user-agent", "x-client-transaction-id", "x-csrf-token", "x-guest-token", "x-twitter-auth-type"]);
    let serialized = serde_json::to_string(op).unwrap();
    for secret in ["c0ffee0123456789abcdef", "a1b2c3d4e5f60718293a", "1840000000000000001", "1Zv7", "txnAAAA"] {
        assert!(!serialized.contains(secret), "spec must not hold {secret}");
    }
    assert_eq!(j(&op.volatile), json!([{"at": ["path:3"], "shape": {"charset": "base64url", "length": 22}, "anchor": "UserByScreenName"}]));
    assert_eq!(j(&op.matcher), json!({"method": "GET", "host": "x.com", "path": "/i/api/graphql/*/UserByScreenName"}));
    assert_eq!(op.min_tier, 1);
    assert!(op.learned_logged_in);
    assert_eq!(j(&op.params), json!([{"name": "screen_name", "type": "string", "required": true, "example": "nasa"}]));
    assert_eq!(j(&op.response.format), json!("json"));
    assert_eq!(op.response.extract.as_deref(), Some("data.user.result.legacy"));
    assert_eq!(op.response.shape.as_ref().unwrap()["data.user.result.rest_id"], "string");
    assert!(!learned.warnings.iter().any(|w| w.contains("nonce") || w.contains("ambiguous") || w.contains("run 2 has")), "{:?}", learned.warnings);

    let req = build_request(op, &args(json!({"screen_name": "esa"})), &session(x_cookies(), &learned.session_values.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>())).unwrap();
    assert_eq!(get_at(&req, &["query:variables".to_string(), "json:".to_string()]).unwrap().unwrap(), json!({"screen_name": "esa", "withSafetyMode": true}));
    assert_eq!(req.headers["referer"], "https://x.com/esa");
    assert_eq!(req.headers["x-csrf-token"], "c0ffee0123456789abcdef");
    assert_eq!(req.headers["x-guest-token"], "1840000000000000001");
    assert_eq!(req.headers["authorization"], BEARER);
    assert!(req.headers["cookie"].contains("auth_token=a1b2c3d4e5f60718293a"));
}

#[test]
fn rank_candidates_drops_noise() {
    let ranked = rank_candidates(&x_exchanges("nasa", "t", 1), &args(json!({"screen_name": "nasa"})), RankOptions::default());
    assert_eq!(ranked.iter().map(|c| c.id).collect::<Vec<_>>(), vec![4, 1]);
    assert_eq!(ranked[0].hits, vec!["screen_name"]);
    assert_eq!(ranked[1].resource_type, "document");
    assert_eq!(rank_candidates(&x_exchanges("nasa", "t", 1), &args(json!({})), RankOptions::default()).iter().map(|c| c.id).collect::<Vec<_>>(), vec![4, 1]);
}

#[test]
fn matches_uses_stable_identity_only() {
    let exs = x_exchanges("nasa", "t", 1);
    let req = &exs[3].request;
    let m = |v: Value| -> Match { serde_json::from_value(v).unwrap() };
    assert!(matches(&m(json!({"method": "GET", "host": "x.com", "path": "/i/api/graphql/*/UserByScreenName"})), req));
    assert!(!matches(&m(json!({"path": "/i/api/graphql/*/UserTweets"})), req));
    assert!(!matches(&m(json!({"method": "POST"})), req));
    assert!(!matches(&m(json!({"operationName": "UserByScreenName"})), req), "operationName comes from the body/form, not the path");
}

fn flights(origin: &str, dest: &str, reqid: &str, id: u64, bgr: &str) -> Exchange {
    let inner = json!([[null, null, null, "HKUJcc"], [null, null, 1, [
        [[[[origin, 0]]], [[[dest, 0]]], null, 0, null, null, "2026-11-12"],
        [[[[dest, 0]]], [[[origin, 0]]], null, 0, null, null, "2026-11-16"]
    ]]]).to_string();
    ex(json!({
        "id": id, "resourceType": "xhr",
        "request": {"method": "POST",
            "url": format!("https://www.google.com/_/FlightsFrontendUi/data/travel.frontend.flights.FlightsFrontendService/GetShoppingResults?f.sid=-5170&bl=boq_travel-frontend-flights-ui_20260922.02_p0&hl=en-US&_reqid={reqid}&rt=c"),
            "headers": {"content-type": "application/x-www-form-urlencoded;charset=UTF-8", "x-goog-batchexecute-bgr": bgr, "x-same-domain": "1"},
            "body": format!("f.req={}&", enc(&json!([null, inner]).to_string()))},
        "response": {"status": 200, "headers": {}, "contentType": "application/json; charset=utf-8",
            "body": format!(")]}}'\n\n120\n[[\"wrb.fr\",null,\"[[\\\"United\\\",\\\"{dest}\\\"]]\"]]\n")}
    }))
}

#[test]
fn google_flights_triple_encoded_form_params() {
    let mut i = input(vec![flights("SFO", "JFK", "4521", 1, "[\";u6W4pcHQ-one\"]")], vec![json!({"origin": "SFO", "destination": "JFK"}), json!({"origin": "OAK", "destination": "LAX"})], "search", "https://www.google.com/travel/flights?q={origin}+to+{destination}", true);
    i.exchanges2 = Some(vec![flights("OAK", "LAX", "8837", 2, "[\";u6W4pcHQ-two\"]")]);
    let learned = learn_operation(&i).unwrap();
    let op = &learned.operation;
    let by_param = |p: &str| op.slots.iter().filter(|s| s.param.as_deref() == Some(p)).map(|s| s.at[2..].join(",")).collect::<Vec<_>>();
    assert_eq!(by_param("origin"), vec!["json:/1/3/0/0/0/0/0", "json:/1/3/1/1/0/0/0"]);
    assert_eq!(by_param("destination"), vec!["json:/1/3/0/1/0/0/0", "json:/1/3/1/0/0/0/0"]);
    assert!(learned.warnings.iter().any(|w| w.contains("\"destination\" appears in 2 places")));
    assert!(learned.warnings.iter().any(|w| w.contains("query:_reqid varies between runs")));
    assert_eq!(op.min_tier, 1);
    assert_eq!(j(&learned.session_values), json!({"search/x-goog-batchexecute-bgr": "[\";u6W4pcHQ-one\"]"}));
    assert_eq!(op.response.xssi_prefix.as_deref(), Some(")]}'"));

    let req = build_request(op, &args(json!({"origin": "SEA", "destination": "BOS"})), &session(vec![], &[("search/x-goog-batchexecute-bgr", "[\";u6W4pcHQ-one\"]")])).unwrap();
    let body = req.body.clone().unwrap();
    let freq = url::form_urlencoded::parse(body.as_bytes()).find(|(k, _)| k == "f.req").unwrap().1.into_owned();
    let outer: Value = serde_json::from_str(&freq).unwrap();
    let inner: Value = serde_json::from_str(outer[1].as_str().unwrap()).unwrap();
    assert_eq!(inner[1][3][0][0], json!([[["SEA", 0]]]));
    assert_eq!(inner[1][3][0][1], json!([[["BOS", 0]]]));
    assert_eq!(inner[1][3][1][0], json!([[["BOS", 0]]]));
    assert_eq!(inner[1][3][1][1], json!([[["SEA", 0]]]));
    assert_eq!(req.headers["x-goog-batchexecute-bgr"], "[\";u6W4pcHQ-one\"]");
}

#[test]
fn high_entropy_value_that_changes_without_an_arg_change_is_a_nonce() {
    let e = |q: &str, sig: &str, id: u64| ex(json!({"id": id, "resourceType": "fetch", "request": {"method": "GET", "url": format!("https://shop.test/api/search?q={q}&sig={sig}"), "headers": {}},
        "response": {"status": 200, "headers": {}, "contentType": "application/json", "body": format!("{{\"items\":[{{\"name\":\"{q} one\"}},{{\"name\":\"{q} two\"}}]}}")}}));
    let mut i = input(vec![e("kettle", "f3a9c1d2e4b5a6c7", 1)], vec![json!({"q": "kettle"}), json!({"q": "toaster"})], "search", "https://shop.test/?q={q}", true);
    i.exchanges2 = Some(vec![e("toaster", "0b1c2d3e4f5a6b7c", 2)]);
    let learned = learn_operation(&i).unwrap();
    assert_eq!(learned.operation.min_tier, 3);
    assert!(learned.warnings.iter().any(|w| w.contains("nonce") && w.contains("query:sig")));
    assert_eq!(learned.operation.response.extract.as_deref(), Some("items"));
}

#[test]
fn linkedin_style_quoted_jsessionid() {
    let i = input(
        exs(json!([{"id": 1, "resourceType": "fetch", "request": {"method": "GET",
            "url": "https://www.linkedin.com/voyager/api/graphql?variables=(start:0,query:(keywords:rustacean))&queryId=voyagerSearchDashClusters.52fec77d08aa4598c8a056ca6bce6c11",
            "headers": {"csrf-token": "ajax:4815162342", "cookie": "JSESSIONID=\"ajax:4815162342\"; li_at=AQEDAxxxxxxxxxx"}},
            "response": {"status": 200, "headers": {}, "contentType": "application/vnd.linkedin.normalized+json+2.1", "body": "{\"included\":[{\"title\":\"rustacean\"}]}"}}])),
        vec![json!({"keywords": "rustacean"})],
        "searchPeople",
        "https://www.linkedin.com/search/results/people/?keywords={keywords}",
        true,
    );
    let op = learn_operation(&i).unwrap().operation;
    assert_eq!(j(op.slots.iter().find(|s| s.is_ref()).unwrap()), json!({"ref": "cookie:JSESSIONID", "transform": "strip-quotes", "at": ["header:csrf-token"]}));
    assert_eq!(j(&op.slots[0]), json!({"param": "keywords", "at": ["query:variables"], "template": "(start:0,query:(keywords:{keywords}))"}));
    assert_eq!(op.request.headers["csrf-token"], "");
    let req = build_request(&op, &args(json!({"keywords": "zig"})), &session(vec![cookie("JSESSIONID", "\"ajax:1\"", ".linkedin.com")], &[])).unwrap();
    assert!(req.url.contains("variables=(start:0,query:(keywords:zig))&queryId="), "{}", req.url);
    assert_eq!(req.headers["csrf-token"], "ajax:1");
}

#[test]
fn instagram_style_form_post() {
    let variables = "{\"first\":12345,\"username\":\"nasa\",\"id\":2085462611575857621}";
    let body = format!("av=0&__user=0&fb_api_req_friendly_name=PolarisProfilePostsTabContentQuery&variables={}&doc_id=27553725110923321", enc(variables));
    let i = input(
        exs(json!([{"id": 7, "resourceType": "xhr", "request": {"method": "POST", "url": "https://www.instagram.com/api/graphql",
            "headers": {"content-type": "application/x-www-form-urlencoded", "x-ig-app-id": "936619743392459", "x-fb-lsd": "AVqbxe3J_YA"}, "body": body},
            "response": {"status": 200, "headers": {}, "contentType": "text/javascript; charset=utf-8", "body": "{\"data\":{\"user\":{\"edges\":[{\"n\":1},{\"n\":2}]}}}"}}])),
        vec![json!({"username": "nasa", "first": 12345, "id": "2085462611575857621"})],
        "posts",
        "https://www.instagram.com/{username}/",
        true,
    );
    let op = learn_operation(&i).unwrap().operation;
    assert_eq!(j(&op.volatile), json!([{"at": ["form:doc_id"], "shape": {"charset": "digits", "length": 17}, "anchor": "PolarisProfilePostsTabContentQuery"}]));
    assert_eq!(j(&op.matcher), json!({"method": "POST", "host": "www.instagram.com", "path": "/api/graphql", "operationName": "PolarisProfilePostsTabContentQuery"}));
    let types: Vec<(String, String)> = op.params.iter().map(|p| (p.name.clone(), p.kind.name().to_string())).collect();
    assert_eq!(types, vec![("username".into(), "string".into()), ("first".into(), "number".into()), ("id".into(), "number".into())]);
    assert_eq!(op.request.headers["x-ig-app-id"], "936619743392459");
    let req = build_request(&op, &args(json!({"username": "esa", "first": "12", "id": "1999999999999999999"})), &session(vec![], &[])).unwrap();
    let body = req.body.unwrap();
    let vars = url::form_urlencoded::parse(body.as_bytes()).find(|(k, _)| k == "variables").unwrap().1.into_owned();
    assert_eq!(vars, "{\"first\":12,\"username\":\"esa\",\"id\":1999999999999999999}");
}

#[test]
fn html_document_op_and_an_aborted_write_both_learn() {
    let doc = learn_operation(&input(
        exs(json!([{"id": 1, "resourceType": "document", "request": {"method": "GET", "url": "https://news.ycombinator.com/from?site=github.com", "headers": {}},
            "response": {"status": 200, "headers": {}, "contentType": "text/html; charset=utf-8", "body": "<tr class=athing>github.com</tr>"}}])),
        vec![json!({"site": "github.com"})],
        "fromSite",
        "https://news.ycombinator.com/from?site={site}",
        true,
    ))
    .unwrap();
    assert_eq!(j(&doc.operation.response.format), json!("html"));
    assert!(doc.warnings.iter().any(|w| w.starts_with("response is HTML")));

    let write = learn_operation(&input(
        exs(json!([{"id": 3, "resourceType": "fetch", "aborted": true, "request": {"method": "POST", "url": "https://x.com/i/api/graphql/znCaGhOrM6q7DbrQdOYgPw/CreateTweet",
            "headers": {"content-type": "application/json"}, "body": "{\"variables\":{\"tweet_text\":\"hello from api-anything\"},\"queryId\":\"znCaGhOrM6q7DbrQdOYgPw\"}"}}])),
        vec![json!({"text": "hello from api-anything"})],
        "post",
        "https://x.com/compose/post",
        false,
    ))
    .unwrap();
    assert_eq!(j(&write.operation.slots), json!([{"param": "text", "at": ["body", "json:/variables/tweet_text"]}]));
    assert!(!write.operation.read_only);
    assert_eq!(j(&write.operation.response), json!({"format": "json"}));
    assert!(!write.operation.learned_logged_in);
}

#[test]
fn example_validation_and_pick_errors() {
    let base = |examples: Vec<Value>| input(x_exchanges("nasa", "t", 1), examples, "g", "https://x.com/{screen_name}", true);
    let err = |i: LearnInput| learn_operation(&i).unwrap_err().to_string();
    assert!(err(base(vec![json!({"screen_name": "na"})])).contains("at least 3 characters"));
    assert!(err(base(vec![json!({"a": "nasa", "b": "NASA"})])).contains("must be distinct"));
    assert!(err(base(vec![json!({"screen_name": "nobody-here"})])).contains("no captured request carries"));
    let mut by99 = base(vec![json!({"screen_name": "nasa"})]);
    by99.id = Some(99);
    assert!(err(by99).contains("no captured request with id 99"));
    let mut by1 = base(vec![json!({"screen_name": "nasa"})]);
    by1.id = Some(1);
    let learned = learn_operation(&by1).unwrap();
    assert_eq!(learned.operation.request.url, "https://x.com/nasa");
    assert_eq!(j(&learned.operation.slots), json!([{"param": "screen_name", "at": ["path:0"]}]));
    assert_eq!(learned.operation.matcher.path.as_deref(), Some("/*"));
}

#[test]
fn per_session_form_tokens_become_session_refs_and_a_public_header_can_stay_literal() {
    const AT: &str = "AJpMio3qL0x-Vw8nZ2rT9kYb4HsE:1727430000000";
    const DTSG: &str = "NAcNq8Yx2b3LmPq:17:1727430000";
    let body = format!("f.req={}&at={}&fb_dtsg={}&", enc(&json!([[["rpc1", json!(["paris"]).to_string(), null, "generic"]]]).to_string()), enc(AT), enc(DTSG));
    let exchanges = exs(json!([{"id": 1, "resourceType": "xhr", "request": {"method": "POST", "url": "https://www.google.test/_/rpc?rpcids=rpc1",
        "headers": {"content-type": "application/x-www-form-urlencoded", "authorization": BEARER}, "body": body},
        "response": {"status": 200, "headers": {}, "contentType": "application/json", "body": "[[\"paris\",1]]"}}]));
    let base = || input(exchanges.clone(), vec![json!({"city": "paris"})], "s", "https://www.google.test/s?q={city}", true);
    let learned = learn_operation(&base()).unwrap();
    let op = &learned.operation;
    assert!(op.slots.iter().any(|s| s.ref_str() == "session:s/at" && s.at[0] == "form:at"));
    assert!(op.slots.iter().any(|s| s.ref_str() == "session:s/fb_dtsg"));
    assert_eq!(learned.session_values["s/at"], AT);
    let b = op.request.body.clone().unwrap();
    assert!(!b.contains(&enc(AT)) && !b.contains(&enc(DTSG)), "{b}");
    assert_eq!(op.request.headers["authorization"], "", "authorization is a session ref by default");

    let mut with_public = base();
    with_public.public = Some(vec!["Authorization".to_string()]);
    let pub_op = learn_operation(&with_public).unwrap().operation;
    assert_eq!(pub_op.request.headers["authorization"], BEARER);
    assert_eq!(j(&pub_op.public), json!(["authorization"]));
    assert!(!pub_op.slots.iter().any(|s| s.ref_str() == "session:s/authorization"));
}

#[test]
fn an_example_value_not_in_the_chosen_request_is_an_error() {
    let mut i = input(
        exs(json!([{"id": 1, "resourceType": "fetch", "request": {"method": "GET", "url": "https://a.test/api/feed", "headers": {}},
            "response": {"status": 200, "headers": {}, "contentType": "application/json", "body": "{\"items\":[{\"q\":\"sqlite\"}]}"}}])),
        vec![json!({"q": "sqlite"})],
        "s",
        "https://a.test/?q={q}",
        true,
    );
    i.id = Some(1);
    let err = learn_operation(&i).unwrap_err().to_string();
    assert!(err.contains("\"q\" (\"sqlite\") is not in the learned request"), "{err}");
}

#[test]
fn a_learned_template_keeps_the_leafs_own_name_text() {
    let body = json!({"query": "query{repository(owner:\"octocat\",name:\"hello-world\"){name}}"}).to_string();
    let l = learn_operation(&input(
        exs(json!([{"id": 1, "resourceType": "fetch", "request": {"method": "POST", "url": "https://g.test/graphql", "headers": {"content-type": "application/json"}, "body": body},
            "response": {"status": 200, "headers": {}, "contentType": "application/json", "body": "{\"data\":{\"repository\":{\"name\":\"hello-world\"}}}"}}])),
        vec![json!({"owner": "octocat", "name": "hello-world"})],
        "repo",
        "https://g.test/{owner}/{name}",
        true,
    ))
    .unwrap();
    let out = build_request(&l.operation, &args(json!({"owner": "torvalds", "name": "linux"})), &session(vec![], &[])).unwrap().body.unwrap();
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["query"], json!("query{repository(owner:\"torvalds\",name:\"linux\"){name}}"));
}

#[test]
fn telemetry_that_logs_the_page_url_does_not_count() {
    let e = |id: u64, url: &str, body: Option<&str>| {
        let mut req = json!({"method": if body.is_some() { "POST" } else { "GET" }, "url": url, "headers": {}});
        if let Some(b) = body {
            req["body"] = json!(b);
        }
        ex(json!({"id": id, "resourceType": "xhr", "request": req, "response": {"status": 200, "headers": {}, "contentType": "application/json", "body": "{}"}}))
    };
    let ranked = rank_candidates(
        &[e(1, "https://x.test/1.1/viewer_context.json", Some(&json!({"page": "https://x.test/nasa"}).to_string())), e(2, "https://api.x.test/User?screen_name=nasa", None)],
        &args(json!({"screen_name": "nasa"})),
        RankOptions::default(),
    );
    assert_eq!(ranked.iter().map(|c| (c.id, c.hits.clone())).collect::<Vec<_>>(), vec![(2, vec!["screen_name".to_string()]), (1, vec![])]);
    let mut video = e(3, "https://video.test/seg-1.m4s?nasa", None);
    video.response = Some(serde_json::from_value(json!({"status": 200, "headers": {}, "contentType": "video/mp4", "body": "x"})).unwrap());
    assert!(rank_candidates(&[video], &args(json!({"screen_name": "nasa"})), RankOptions::default()).is_empty(), "media fetched by XHR is noise");
}

#[test]
fn a_short_example_found_by_chance_inside_a_random_header_token_is_not_a_slot() {
    let i = input(
        exs(json!([{"id": 1, "resourceType": "xhr", "request": {"method": "GET", "url": "https://g.test/api/calendar?origin=SFO&dest=JFK",
            "headers": {"x-goog-batchexecute-bgr": "q7ZkSFOb2Xw9LmT4pRvN8cYd", "x-route": "k9Qz2Lw7Rt4Xy8/SFO/Mn3Vb6"}},
            "response": {"status": 200, "headers": {}, "contentType": "application/json", "body": "{\"days\":[{\"from\":\"SFO\",\"price\":80},{\"from\":\"SFO\",\"price\":95}]}"}}])),
        vec![json!({"origin": "SFO"})],
        "cal",
        "https://g.test/",
        true,
    );
    let op = learn_operation(&i).unwrap().operation;
    let mut at: Vec<String> = op.slots.iter().filter(|s| s.param.as_deref() == Some("origin")).map(|s| s.at[0].clone()).collect();
    at.sort();
    assert_eq!(at, vec!["header:x-route", "query:origin"]);
}

#[test]
fn a_response_that_is_itself_a_list_of_results_is_learned_whole() {
    let list = json!([{"bookId": "1", "title": "Dune"}, {"bookId": "2", "title": "Dune Messiah"}]);
    let learned = learn_operation(&input(
        exs(json!([{"id": 1, "resourceType": "xhr", "request": {"method": "GET", "url": "https://books.example/auto_complete?format=json&q=dune", "headers": {}},
            "response": {"status": 200, "headers": {}, "contentType": "application/json", "body": list.to_string()}}])),
        vec![json!({"q": "dune"})],
        "search",
        "https://books.example/auto_complete?format=json&q={q}",
        true,
    ))
    .unwrap();
    assert_eq!(learned.operation.response.extract, None);
}
