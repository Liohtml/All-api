//! Bundled site specs: their recipes against trimmed copies of the live responses, their param rules, and their notes.
mod common;
use api_anything::classify::{Class, Observed, judge};
use api_anything::execute::{CallOptions, call};
use api_anything::http::{Fetcher, HttpRequest, HttpResponse, build_request};
use api_anything::learn::Args;
use api_anything::spec::{Operation, Param, parse_site};
use api_anything::store::{list_sites, site_notes};
use api_anything::types::Headers;
use api_anything::util::{js_len, js_regex};
use common::{Home, args, j, no_session};
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

fn raw(site: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("sites").join(format!("{site}.json"));
    serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap()
}
fn op(site: &str, name: &str) -> Operation {
    parse_site(&raw(site)).unwrap().operations.into_iter().find(|o| o.name == name).unwrap()
}
// the parsed spec's params: the schema keeps pattern and hint
fn raw_params(site: &str, name: &str) -> Vec<Param> {
    op(site, name).params
}
// a clean home, so call() runs the bundled spec
static HOME: LazyLock<Home> = LazyLock::new(Home::new);

/// A fetcher answering from a closure, counting what it was asked.
struct FnFetcher {
    sent: AtomicUsize,
    answer: Box<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>,
}

impl FnFetcher {
    fn new(f: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static) -> Arc<FnFetcher> {
        Arc::new(FnFetcher { sent: AtomicUsize::new(0), answer: Box::new(f) })
    }
    fn sent(&self) -> usize {
        self.sent.load(Ordering::SeqCst)
    }
}

impl Fetcher for FnFetcher {
    fn fetch(&self, req: HttpRequest, _timeout: Duration) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        let r = (self.answer)(&req);
        Box::pin(async move { Ok(r) })
    }
}

/// `new Response(body, { headers })`: a 200 with the given content type (none when empty).
fn response(body: &str, content_type: &str) -> HttpResponse {
    let mut headers = Headers::new();
    if !content_type.is_empty() {
        headers.insert("content-type".into(), content_type.into());
    }
    HttpResponse { status: 200, headers, set_cookie: vec![], body: body.as_bytes().to_vec(), url: String::new() }
}

async fn call_bundled(site: &str, name: &str, a: Args, fetcher: Arc<FnFetcher>) -> api_anything::execute::CallResult {
    LazyLock::force(&HOME);
    call(site, name, a, CallOptions { fetcher: Some(fetcher), max_tier: Some(1), min_interval_ms: Some(0), ..Default::default() }).await
}

fn ok(o: &Operation, body: &str, content_type: &str) -> Vec<Value> {
    let mut headers = Headers::new();
    headers.insert("content-type".into(), content_type.into());
    let jd = judge(o, &Observed { status: 200, headers, body: body.to_string(), url: None });
    assert_eq!(jd.class, Class::Ok, "{}", jd.reason);
    jd.data.unwrap().as_array().cloned().unwrap()
}
fn ok_json(o: &Operation, body: &str) -> Vec<Value> {
    ok(o, body, "application/json")
}
// A spec's param pattern is a whole-value JS regex.
fn accepts(p: &Param, v: &str) -> bool {
    js_regex(p.pattern.as_deref().unwrap()).unwrap().is_match(v).unwrap()
}
fn parsed_url(s: &str) -> url::Url {
    url::Url::parse(s).unwrap()
}
fn query(u: &url::Url, k: &str) -> Option<String> {
    u.query_pairs().find(|(a, _)| a == k).map(|(_, v)| v.into_owned())
}

// ---------------------------------------------------------------- google-flights

// one real "other flights" item (SFO->EWR via ATL), legs and booking token trimmed; a nonstop has null stops
fn via_atl() -> Value {
    json!([[129, "ATL", "ATL", null, "Hartsfield-Jackson Atlanta International Airport", "Atlanta"]])
}
fn flight(price: u32, to: &str, stops: Value) -> Value {
    json!([
        ["F9", ["Frontier"], [], "SFO", [2026, 10, 21], [22, 14], to, [2026, 10, 22], [10, 33], 559, 1, null, 0, stops],
        [[null, price], "tok"],
    ])
}
fn flights_page(top: Vec<Value>, other: Vec<Value>) -> String {
    let data = json!([
        [null, [[1, 2, 3]]],
        [[[[["SFO", 0], "San Francisco International Airport"]], [[["/m/02_286", 4], "New York"]]]],
        [top],
        [other],
    ]);
    format!(
        "<html><script nonce=\"x\">AF_initDataCallback({{key: 'ds:0', hash: '1', data:[[null,null,0,\"x\"]], sideChannel: {{}}}});</script>\
<script nonce=\"x\">AF_initDataCallback({{key: 'ds:1', hash: '9', data:{}, sideChannel: {{}}}});</script></html>",
        data
    )
}
const HTML_UTF8: &str = "text/html; charset=utf-8";

#[test]
fn google_flights_search_top_read_the_results_the_page_embeds_so_a_metro_code_like_nyc_returns_flights() {
    let body = flights_page(vec![flight(219, "EWR", via_atl())], vec![flight(149, "EWR", via_atl()), flight(204, "LGA", Value::Null)]);
    let other = ok(&op("google-flights", "search"), &body, HTML_UTF8);
    assert_eq!(other.iter().map(|f| json!([f["price"], f["to"]])).collect::<Vec<_>>(), vec![json!([149, "EWR"]), json!([204, "LGA"])]);
    assert_eq!(
        other[0],
        json!({
            "airline": ["Frontier"],
            "price": 149,
            "from": "SFO",
            "to": "EWR",
            "departureTime": [22, 14],
            "arrivalDate": [2026, 10, 22],
            "arrivalTime": [10, 33],
            "durationMinutes": 559,
            "via": ["ATL"],
        })
    );
    assert!(other[1].get("via").is_none(), "a nonstop flight has no via");
    assert_eq!(ok(&op("google-flights", "top"), &body, HTML_UTF8).iter().map(|f| f["price"].clone()).collect::<Vec<_>>(), vec![json!(219)]);
}

#[test]
fn google_flights_search_sends_the_places_as_free_text_in_q_which_google_resolves_nyc_a_city_name() {
    for name in ["search", "top"] {
        let u = parsed_url(
            &build_request(
                &op("google-flights", name),
                &args(json!({ "origin": "SFO", "destination": "New York", "date": "2026-10-21" })),
                &no_session(),
            )
            .unwrap()
            .url,
        );
        assert_eq!(u.path(), "/travel/flights");
        assert_eq!(query(&u, "q").as_deref(), Some("Flights from SFO to New York on 2026-10-21 one way"));
        assert_eq!(query(&u, "curr").as_deref(), Some("USD"));
    }
}

#[test]
fn google_flights_price_calendar_one_call_gives_the_cheapest_fare_per_date_in_the_range() {
    let o = op("google-flights", "priceCalendar");
    let req = build_request(
        &o,
        &args(json!({ "origin": "BOS", "destination": "MIA", "start": "2026-11-01", "end": "2026-11-30" })),
        &no_session(),
    )
    .unwrap();
    let body = req.body.clone().unwrap();
    let f_req = url::form_urlencoded::parse(body.as_bytes()).find(|(k, _)| k == "f.req").map(|(_, v)| v.into_owned()).unwrap();
    let outer: Value = serde_json::from_str(&f_req).unwrap();
    let inner: Value = serde_json::from_str(outer[1].as_str().unwrap()).unwrap();
    assert_eq!(inner[1][13][0][0], json!([[["BOS", 0]]]));
    assert_eq!(inner[1][13][0][1], json!([[["MIA", 0]]]));
    assert_eq!(inner[2], json!(["2026-11-01", "2026-11-30"]));
    assert_eq!(inner[1][13][0][6], json!("2026-11-01"));
    // learning matched "SFO" inside the random x-goog-batchexecute-bgr blob; that header is a session value only
    assert!(!o.slots.iter().any(|s| s.param.is_some() && s.at[0] == "header:x-goog-batchexecute-bgr"));
    let payload = json!([
        [null, [[1]], 0, "x", "y"],
        [["2026-11-01", null, [[null, 185], "t1"], 1], ["2026-11-02", null, [[null, 120], "t2"], 1], ["2026-11-03", null, null, 1],],
    ]);
    let body = format!(")]}}'\n\n123\n{}\n", json!([["wrb.fr", null, payload.to_string()]]));
    assert_eq!(
        Value::Array(ok_json(&o, &body)),
        json!([
            { "date": "2026-11-01", "price": 185 },
            { "date": "2026-11-02", "price": 120 },
            { "date": "2026-11-03" },
        ])
    );
}

#[test]
fn google_flights_params_carry_a_pattern_and_a_hint_the_calendar_refuses_metro_codes_it_cant_search() {
    for name in ["search", "top", "priceCalendar"] {
        for p in raw_params("google-flights", name) {
            assert!(p.pattern.is_some() && p.hint.is_some(), "{name}.{} needs pattern and hint", p.name);
            js_regex(p.pattern.as_deref().unwrap()).unwrap();
        }
    }
    let ps = raw_params("google-flights", "search");
    let (origin, date) = (&ps[0], &ps[2]);
    for v in ["SFO", "NYC", "New York", "São Paulo"] {
        assert!(accepts(origin, v), "{v}");
    }
    assert!(!accepts(origin, "2026-10-21"));
    assert!(accepts(date, "2027-04-15"));
    for v in ["Oct 21", "2027-4-15", "04/15/2027"] {
        assert!(!accepts(date, v), "{v}");
    }
    let ps = raw_params("google-flights", "priceCalendar");
    let (cal_origin, start) = (&ps[0], &ps[2]);
    for v in ["JFK", "LGA", "EWR", "LHR"] {
        assert!(accepts(cal_origin, v), "{v}");
    }
    for v in ["NYC", "LON", "TYO", "jfk", "New York", "JFKX"] {
        assert!(!accepts(cal_origin, v), "{v}");
    }
    assert!(cal_origin.hint.as_deref().unwrap().contains("JFK, LGA or EWR"));
    assert!(!accepts(start, "next month"));
}

#[tokio::test]
async fn google_flights_search_with_a_malformed_date_is_input_with_the_params_hint_and_nothing_is_sent() {
    let fetcher = FnFetcher::new(|_| response("", ""));
    let r = call_bundled(
        "google-flights",
        "search",
        args(json!({ "origin": "SFO", "destination": "NYC", "date": "tomorrowish-bad" })),
        fetcher.clone(),
    )
    .await;
    assert_eq!(r.class, Class::Input, "{}", j(&r));
    let want =
        regex::Regex::new(r#"param "date" must be a departure date as YYYY-MM-DD, e\.g\. 2027-04-15, got "tomorrowish-bad""#).unwrap();
    assert!(want.is_match(r.reason.as_deref().unwrap_or("")), "{:?}", r.reason);
    assert_eq!(fetcher.sent(), 0);
    let kw = call_bundled("linkedin", "searchCompanies", args(json!({ "keywords": "rust, zurich" })), fetcher.clone()).await;
    assert_eq!(kw.class, Class::Input, "{}", j(&kw));
    assert_eq!(fetcher.sent(), 0);
}

#[tokio::test]
async fn google_flights_search_for_a_past_date_googles_explore_page_with_a_sign_in_link_to_service_login_is_input_not_auth() {
    let explore = "<html><head><title>Explore</title></head><body><a href=\"https://accounts.google.com/ServiceLogin?hl=en-US&continue=https://www.google.com/travel/explore\">Sign in</a>\
<script nonce=\"x\">AF_initDataCallback({key: 'ds:0', hash: '1', data:[[null,null,0,\"x\"]], sideChannel: {}});</script></body></html>"
        .to_string();
    let results = flights_page(vec![flight(219, "EWR", via_atl())], vec![flight(149, "EWR", via_atl())]);
    let dates: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let seen = dates.clone();
    let fetcher = FnFetcher::new(move |req| {
        let q = query(&parsed_url(&req.url), "q").unwrap_or_default();
        // q.slice(-18, -8): the date inside "... on YYYY-MM-DD one way"
        let chars: Vec<char> = q.chars().collect();
        let n = chars.len();
        seen.lock().unwrap().push(chars[n.saturating_sub(18)..n.saturating_sub(8)].iter().collect());
        response(if q.contains("2020-01-01") { &explore } else { &results }, HTML_UTF8)
    });
    let r = call_bundled("google-flights", "search", args(json!({ "origin": "SFO", "destination": "NYC", "date": "2020-01-01" })), fetcher)
        .await;
    assert_eq!(r.class, Class::Input, "{}", j(&r));
    assert_eq!(*dates.lock().unwrap(), vec!["2020-01-01".to_string(), "2027-04-15".to_string()]);
}

// ---------------------------------------------------------------- youtube

fn video(id: &str) -> Value {
    json!({
        "videoRenderer": {
            "videoId": id,
            "title": { "runs": [{ "text": format!("t{id}") }] },
            "ownerText": { "runs": [{ "text": "c" }] },
            "viewCountText": { "simpleText": "1 view" },
        },
    })
}

#[test]
fn youtube_search_with_the_ad_layout_visitor_info1_live_set_still_returns_every_video_and_no_empty_items() {
    let data = json!({
        "contents": {
            "twoColumnSearchResultsRenderer": {
                "primaryContents": {
                    "sectionListRenderer": {
                        "contents": [
                            {
                                "itemSectionRenderer": {
                                    "contents": [{ "searchPyvRenderer": { "ads": [] } }, { "shelfRenderer": {} }, video("a"), video("b")],
                                },
                            },
                            { "adSlotRenderer": { "slotId": "1" } },
                            { "itemSectionRenderer": { "contents": [video("c"), { "reelShelfRenderer": {} }, video("d")] } },
                            { "continuationItemRenderer": {} },
                        ],
                    },
                },
            },
        },
    });
    let got = ok(&op("youtube", "search"), &format!("<script>var ytInitialData = {data};</script>"), "text/html");
    assert_eq!(got.iter().map(|v| v["id"].clone()).collect::<Vec<_>>(), vec![json!("a"), json!("b"), json!("c"), json!("d")]);
    assert_eq!(got[0], json!({ "id": "a", "title": "ta", "channel": "c", "views": "1 view" }));
}

// ---------------------------------------------------------------- linkedin

fn entity(title: &str, url: &str) -> Value {
    json!({
        "itemUnion": {
            "entityResult": {
                "title": { "text": title },
                "primarySubtitle": { "text": "sub" },
                "secondarySubtitle": { "text": "sec" },
                "navigationUrl": url,
            },
        },
    })
}
fn clusters(elements: Vec<Value>) -> String {
    json!({ "elements": elements, "paging": { "count": 10, "start": 0 } }).to_string()
}

#[test]
fn linkedin_search_people_search_companies_collect_results_from_whichever_cluster_holds_them() {
    let upsell = json!({ "items": [{ "itemUnion": { "fifComponentCard": {} } }] });
    let feedback = json!({ "items": [{ "itemUnion": { "feedbackCard": { "entityUrn": "x" } } }] });
    let people = ok_json(
        &op("linkedin", "searchPeople"),
        &clusters(vec![
            upsell.clone(),
            json!({ "items": [entity("Reid Hoffman", "https://www.linkedin.com/in/reidhoffman?miniProfileUrn=x")] }),
            feedback.clone(),
        ]),
    );
    assert_eq!(
        people.iter().map(|p| json!([p["name"], p["url"], p["publicId"]])).collect::<Vec<_>>(),
        vec![json!(["Reid Hoffman", "https://www.linkedin.com/in/reidhoffman?miniProfileUrn=x", "reidhoffman"])]
    );
    // no upsell card (a Premium account): the people are cluster 0 and still found
    assert_eq!(
        ok_json(&op("linkedin", "searchPeople"), &clusters(vec![json!({ "items": [entity("A", "u")] }), feedback.clone()])).len(),
        1
    );
    let companies = ok_json(
        &op("linkedin", "searchCompanies"),
        &clusters(vec![
            json!({ "items": [{ "itemUnion": { "simpleTextV2": {} } }] }),
            json!({ "items": [entity("Anthropic", "https://www.linkedin.com/company/anthropicresearch/")] }),
        ]),
    );
    assert_eq!(
        companies[0],
        json!({
            "name": "Anthropic",
            "subtitle": "sub",
            "followers": "sec",
            "url": "https://www.linkedin.com/company/anthropicresearch/",
            "universalName": "anthropicresearch",
        })
    );
    // no matches: LinkedIn answers no clusters at all
    assert_eq!(ok_json(&op("linkedin", "searchCompanies"), &clusters(vec![])), Vec::<Value>::new());
    // results that moved out of entityResult are drift, not an empty "no results"
    let moved = judge(
        &op("linkedin", "searchCompanies"),
        &Observed {
            status: 200,
            headers: Headers::new(),
            body: clusters(vec![feedback, json!({ "items": [{ "itemUnion": { "newResult": {} } }] })]),
            url: None,
        },
    );
    assert_ne!(moved.class, Class::Ok);
}

#[test]
fn linkedin_search_keywords_are_percent_encoded_once_inside_the_rest_li_query_a_double_encoded_space_finds_no_company() {
    for name in ["searchPeople", "searchCompanies"] {
        let url = build_request(&op("linkedin", name), &args(json!({ "keywords": "boston dynamics" })), &no_session()).unwrap().url;
        assert!(url.contains("query=(keywords:boston%20dynamics,flagshipSearchIntent:SEARCH_SRP,"), "{url}");
        let ps = raw_params("linkedin", name);
        let kw = &ps[0];
        assert!(accepts(kw, "conan o'brien") && accepts(kw, "Noah Hüsser"));
        for v in ["rust engineer, zurich", "a:b", "x (y)"] {
            assert!(!accepts(kw, v), "{v} would break the Rest.li query");
        }
    }
}

// ---------------------------------------------------------------- notes

#[test]
fn bundled_notes_what_every_ops_and_list_operations_call_sends_for_a_site_stays_short() {
    LazyLock::force(&HOME);
    for site in list_sites() {
        let sent = site_notes(&site).unwrap_or_default();
        assert!(
            js_len(&sent) <= 2000,
            "{site}.md sends {} characters to every caller: move what only a maintainer needs under \"## Maintainer notes\"",
            js_len(&sent)
        );
    }
}
