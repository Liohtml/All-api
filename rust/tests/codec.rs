use api_anything::codec::{fill_template, get_at, parse_json, set_at, set_text, walk};
use api_anything::spec::Request;
use indexmap::IndexMap;
use serde_json::{Value, json};

fn get(url: &str) -> Request {
    Request { method: "GET".into(), url: url.into(), headers: IndexMap::new(), body: None }
}
fn post(url: &str, headers: &[(&str, &str)], body: &str) -> Request {
    Request {
        method: "POST".into(),
        url: url.into(),
        headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        body: Some(body.into()),
    }
}
fn s(x: &str) -> Vec<String> {
    x.split(',').map(|s| s.to_string()).collect()
}
fn got(req: &Request, at: &str) -> Value {
    get_at(req, &s(at)).unwrap().unwrap()
}

#[test]
fn path_segments_get_decodes_set_encodes_only_that_segment() {
    let r = get("https://x.com/i/api/graphql/Gb-d6r0vxPOADdG62OEBpQ/UserByScreenName?x=1#frag");
    assert_eq!(got(&r, "path:3"), json!("Gb-d6r0vxPOADdG62OEBpQ"));
    assert_eq!(got(&r, "path:4"), json!("UserByScreenName"));
    let r2 = set_text(&r, &s("path:3"), "NEWID").unwrap();
    assert_eq!(r2.url, "https://x.com/i/api/graphql/NEWID/UserByScreenName?x=1#frag");
    assert_eq!(set_text(&get("https://a.com/u/x"), &s("path:1"), "a b/c").unwrap().url, "https://a.com/u/a%20b%2Fc");
    assert_eq!(r.url, "https://x.com/i/api/graphql/Gb-d6r0vxPOADdG62OEBpQ/UserByScreenName?x=1#frag");
}

#[test]
fn query_raw_pairs_kept_byte_identical() {
    let r = get("https://a.com/s?q=old&cursor=&z=%7E(a%3Ab)&sort=top");
    assert_eq!(got(&r, "query:cursor"), json!(""));
    assert_eq!(got(&r, "query:z"), json!("~(a:b)"));
    let r2 = set_text(&r, &s("query:q"), "new value").unwrap();
    assert_eq!(r2.url, "https://a.com/s?q=new%20value&cursor=&z=%7E(a%3Ab)&sort=top");
    assert_eq!(set_text(&r, &s("query:extra"), "1").unwrap().url, "https://a.com/s?q=old&cursor=&z=%7E(a%3Ab)&sort=top&extra=1");
    assert_eq!(set_text(&get("https://a.com/s?q=a+b"), &s("query:q"), "c d").unwrap().url, "https://a.com/s?q=c+d");
}

#[test]
fn restli_parens_and_colons_stay_literal() {
    let raw = "(count:20,start:0,query:(keywords:alice,flagshipSearchIntent:SEARCH_SRP))";
    let r = get(&format!("https://www.linkedin.com/voyager/api/graphql?variables={raw}&queryId=voyagerSearchDashClusters.abc"));
    assert_eq!(got(&r, "query:variables"), json!(raw));
    let r2 = set_text(&r, &s("query:variables"), &raw.replace("alice", "bob smith")).unwrap();
    assert_eq!(
        r2.url,
        "https://www.linkedin.com/voyager/api/graphql?variables=(count:20,start:0,query:(keywords:bob%20smith,flagshipSearchIntent:SEARCH_SRP))&queryId=voyagerSearchDashClusters.abc"
    );
    let enc = get("https://a.com/?v=%28a%29");
    assert_eq!(set_text(&enc, &s("query:v"), "(b)").unwrap().url, "https://a.com/?v=%28b%29");
}

#[test]
fn x_like_variables_json_in_the_query() {
    let variables = r#"{"screen_name":"nasa","withSafetyMode":true,"count":20}"#;
    let features = r#"{"a":true,"b":false}"#;
    let enc = api_anything::util::encode_uri_component;
    let r = get(&format!("https://x.com/i/api/graphql/ID/UserByScreenName?variables={}&features={}", enc(variables), enc(features)));
    assert_eq!(got(&r, "query:variables,json:/screen_name"), json!("nasa"));
    assert_eq!(got(&r, "query:variables,json:/count"), json!(20));
    let r2 = set_text(&r, &s("query:variables,json:/screen_name"), "say \"hi\" OR x").unwrap();
    let u = url::Url::parse(&r2.url).unwrap();
    let v: String = u.query_pairs().find(|(k, _)| k == "variables").unwrap().1.into_owned();
    assert_eq!(v, r#"{"screen_name":"say \"hi\" OR x","withSafetyMode":true,"count":20}"#);
    assert!(r2.url.ends_with(&format!("&features={}", enc(features))), "untouched pair keeps its bytes");
}

#[test]
fn native_type_kept_when_a_whole_json_leaf_is_replaced() {
    let r = post("https://a.com/g", &[("content-type", "application/json")], r#"{"v":{"n":1,"s":"x","b":false}}"#);
    assert_eq!(set_at(&r, &s("body,json:/v/n"), &json!(42)).unwrap().body.unwrap(), r#"{"v":{"n":42,"s":"x","b":false}}"#);
    assert_eq!(set_at(&r, &s("body,json:/v/n"), &json!("42")).unwrap().body.unwrap(), r#"{"v":{"n":"42","s":"x","b":false}}"#);
    assert_eq!(set_at(&r, &s("body,json:/v/b"), &json!(true)).unwrap().body.unwrap(), r#"{"v":{"n":1,"s":"x","b":true}}"#);
    assert_eq!(set_at(&r, &s("body,json:/v/s"), &json!(["a", 1])).unwrap().body.unwrap(), r#"{"v":{"n":1,"s":["a",1],"b":false}}"#);
    let err = set_at(&r, &s("body,json:/v/missing"), &json!(1)).unwrap_err().to_string();
    assert!(err.contains("not found"), "{err}");
}

#[test]
fn nineteen_digit_snowflake_ids_never_lose_precision() {
    let body = r#"{"tweet_id":2085462611575857621,"reply":{"in_reply_to_tweet_id":"2085462611575857621"},"n":1.50}"#;
    let r = post("https://x.com/i/api/graphql/ID/CreateTweet", &[], body);
    assert_eq!(got(&r, "body,json:/tweet_id"), json!("2085462611575857621"));
    let r2 = set_text(&r, &s("body,json:/reply/in_reply_to_tweet_id"), "1999999999999999999").unwrap();
    assert_eq!(r2.body.unwrap(), r#"{"tweet_id":2085462611575857621,"reply":{"in_reply_to_tweet_id":"1999999999999999999"},"n":1.50}"#);
    let big = api_anything::util::number_from_text("2085462611575857699");
    let r3 = set_at(&r, &s("body,json:/tweet_id"), &big).unwrap();
    assert_eq!(r3.body.unwrap(), r#"{"tweet_id":2085462611575857699,"reply":{"in_reply_to_tweet_id":"2085462611575857621"},"n":1.50}"#);
    let leaves = walk(&r);
    let leaf = leaves.iter().find(|l| l.at.join(",") == "body,json:/tweet_id").unwrap();
    assert_eq!(leaf.value, "2085462611575857621");
    assert_eq!(leaf.kind, api_anything::codec::LeafType::Number);
    assert_eq!(parse_json(r#"{"a":12345678901234567890,"b":5}"#).unwrap(), json!({"a": "12345678901234567890", "b": 5}));
}

fn flights_request(origin: &str, dest: &str) -> Request {
    let inner = serde_json::to_string(&json!([
        [null, null, null, "HKUJcc"],
        [
            null,
            null,
            1,
            null,
            [],
            1,
            [1, 0, 0, 0],
            null,
            null,
            null,
            null,
            null,
            null,
            [
                [[[[origin, 0]]], [[[dest, 0]]], null, 0, null, null, "2026-11-12"],
                [[[[dest, 0]]], [[[origin, 0]]], null, 0, null, null, "2026-11-16"]
            ]
        ]
    ]))
    .unwrap();
    let outer = serde_json::to_string(&json!([null, inner])).unwrap();
    let body = format!("f.req={}&at=AFoo%3A1700000000000&", api_anything::util::encode_uri_component(&outer));
    post(
        "https://www.google.com/_/FlightsFrontendUi/data/GetShoppingResults?f.sid=-123&bl=boq_x&hl=en-US&_reqid=4521&rt=c",
        &[("content-type", "application/x-www-form-urlencoded;charset=UTF-8"), ("x-goog-ext-259736195-jspb", r#"["en-US","US","USD"]"#)],
        &body,
    )
}

#[test]
fn google_flights_triple_encoded_f_req() {
    let r = flights_request("SFO", "JFK");
    let leaves = walk(&r);
    let sfo: Vec<Vec<String>> = leaves.iter().filter(|l| l.value == "SFO").map(|l| l.at.clone()).collect();
    assert_eq!(sfo, vec![s("form:f.req,json:/1,json:/1/13/0/0/0/0/0"), s("form:f.req,json:/1,json:/1/13/1/1/0/0/0")]);
    assert!(leaves.iter().find(|l| l.at.join(",") == "form:f.req").unwrap().container);
    assert!(leaves.iter().any(|l| l.at.join(",") == "header:x-goog-ext-259736195-jspb,json:/2" && l.value == "USD"));
    let r2 = set_text(&r, &sfo[0], "OAK").unwrap();
    let body = r2.body.clone().unwrap();
    let freq = url::form_urlencoded::parse(body.as_bytes()).find(|(k, _)| k == "f.req").unwrap().1.into_owned();
    let outer: Value = serde_json::from_str(&freq).unwrap();
    let inner: Value = serde_json::from_str(outer[1].as_str().unwrap()).unwrap();
    assert_eq!(inner[1][13][0][0][0][0][0], json!("OAK"));
    assert_eq!(inner[1][13][1][1][0][0][0], json!("SFO"), "the other SFO is untouched");
    assert_eq!(inner[1][13][0][1][0][0][0], json!("JFK"));
    assert!(body.ends_with("&at=AFoo%3A1700000000000&"), "other form pairs keep their bytes");
    assert_eq!(r2.url, flights_request("SFO", "JFK").url);
    assert_eq!(get_at(&r2, &sfo[0]).unwrap().unwrap(), json!("OAK"));
}

#[test]
fn header_and_whole_body_steps() {
    let r = post("https://a.com/", &[("x-csrf-token", "")], "raw");
    assert_eq!(set_text(&r, &s("header:X-CSRF-Token"), "abc").unwrap().headers["x-csrf-token"], "abc");
    assert_eq!(set_text(&r, &s("header:x-new"), "1").unwrap().headers["x-new"], "1");
    assert_eq!(set_text(&r, &s("body"), "new").unwrap().body.unwrap(), "new");
    assert!(set_at(&r, &s("json:/a"), &json!(1)).unwrap_err().to_string().contains("not a request layer"));
}

#[test]
fn fill_template_fills_known_names_only() {
    let vars = json!({"query": "cats"});
    assert_eq!(fill_template("from:{query} lang:en {viewer{id}}", vars.as_object().unwrap()), "from:cats lang:en {viewer{id}}");
    let vars = json!({"cookie:ct0": "tok"});
    assert_eq!(fill_template("Bearer {cookie:ct0}", vars.as_object().unwrap()), "Bearer tok");
}

#[test]
fn walk_path_query_headers_form_and_json_in_json_leaves() {
    let r = post(
        "https://a.com/api/users/nasa?vars=%7B%22id%22%3A%22x1%22%7D",
        &[("content-type", "application/json")],
        r#"{"variables":{"q":"hello","inner":"{\"deep\":[1,\"two\"]}"},"flag":null}"#,
    );
    let leaves = walk(&r);
    let by = |at: &str| leaves.iter().find(|l| l.at.join(" ") == at).unwrap();
    assert_eq!(by("path:2").value, "nasa");
    assert_eq!(by("query:vars json:/id").value, "x1");
    assert_eq!(by("body json:/variables/q").value, "hello");
    assert_eq!(by("body json:/variables/inner json:/deep/1").value, "two");
    assert_eq!(by("body json:/flag").kind, api_anything::codec::LeafType::Null);
    let deep = set_text(&r, &s("body,json:/variables/inner,json:/deep/1"), "three").unwrap();
    assert_eq!(deep.body.unwrap(), r#"{"variables":{"q":"hello","inner":"{\"deep\":[1,\"three\"]}"},"flag":null}"#);
}

#[test]
fn json_pointer_escapes() {
    let r = post("https://a.com/", &[], r#"{"a/b":{"c~d":"v"}}"#);
    let leaves = walk(&r);
    let leaf = leaves.iter().find(|l| l.value == "v").unwrap();
    assert_eq!(leaf.at, s("body,json:/a~1b/c~0d"));
    assert_eq!(set_text(&r, &leaf.at, "w").unwrap().body.unwrap(), r#"{"a/b":{"c~d":"w"}}"#);
}

#[test]
fn a_json_body_labeled_form_urlencoded_is_walked_as_json() {
    let r = post(
        "https://app-dsn.algolia.net/1/indexes/Item_dev/query",
        &[("content-type", "application/x-www-form-urlencoded")],
        r#"{"query":"sqlite","hitsPerPage":30}"#,
    );
    let leaves = walk(&r);
    let leaf = leaves.iter().find(|l| l.value == "sqlite").unwrap();
    assert_eq!(leaf.at, s("body,json:/query"));
    assert_eq!(set_text(&r, &leaf.at, "duckdb").unwrap().body.unwrap(), r#"{"query":"duckdb","hitsPerPage":30}"#);
    let mut form = r.clone();
    form.body = Some("q=sqlite&n=1".into());
    assert_eq!(walk(&form).iter().find(|l| l.value == "sqlite").unwrap().at, s("form:q"));
}

#[test]
fn fill_template_doubled_braces_are_literal() {
    let vars = json!({"name": "linux"});
    assert_eq!(fill_template(r#"query{{repo(name:"{name}"){{name}}}}"#, vars.as_object().unwrap()), r#"query{repo(name:"linux"){name}}"#);
    let vars = json!({"name": "x"});
    assert_eq!(fill_template("{{{name}}}", vars.as_object().unwrap()), "{x}");
}
