mod common;
use api_anything::browser::{TriggerOptions, close_browser, run_trigger};
use common::fixture::Fixture;
use std::sync::Arc;

fn chrome() -> bool {
    if std::env::var("API_ANYTHING_CHROME").is_err() {
        let p = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
        if std::path::Path::new(p).exists() {
            unsafe { std::env::set_var("API_ANYTHING_CHROME", p) };
        }
    }
    api_anything::browser::chrome_available()
}

#[tokio::test]
async fn captures_a_page_and_its_xhr() {
    if !chrome() {
        eprintln!("no Chrome: skipped");
        return;
    }
    let f = Fixture::start().await;
    let home = tempfile::tempdir().unwrap();
    let profile = home.path().join("profile");
    let mut o = TriggerOptions::new(&format!("{}/u/alice", f.url), &profile);
    o.timeout_ms = Some(20_000);
    let r = run_trigger(o).await.unwrap();
    let kinds: Vec<String> = r.exchanges.iter().map(|e| format!("{} {} {}", e.resource_type, e.request.method, e.request.url)).collect();
    eprintln!("{kinds:#?}");
    let gql = r.exchanges.iter().find(|e| e.request.url.contains("/api/graphql/")).expect("the graphql xhr");
    assert_eq!(gql.resource_type, "fetch");
    assert!(gql.request.headers.get("x-csrf-token").map(|v| !v.is_empty()).unwrap_or(false), "{:?}", gql.request.headers);
    assert!(gql.request.headers.contains_key("cookie"), "{:?}", gql.request.headers);
    let body = gql.body();
    assert!(body.contains("\"name\":\"alice\""), "{body}");
    assert!(r.cookies.iter().any(|c| c.name == "ct0"));
    assert!(r.final_url.ends_with("/u/alice"));
    assert!(r.locations.as_ref().unwrap().iter().any(|l| l.ends_with("/u/alice")));
    let doc = r.exchanges.iter().find(|e| e.resource_type == "document").unwrap();
    assert!(doc.body().contains("<div id=\"app\">"));

    // a write guard aborts the POST before it leaves
    let mut o = TriggerOptions::new(&format!("{}/compose", f.url), &profile);
    o.steps = Some(serde_json::from_value(serde_json::json!([{"action": "fill", "selector": "#text", "value": "hello"}, {"action": "click", "selector": "#post"}])).unwrap());
    o.intercept = Some(Arc::new(|e, _acting, _via| e.request.method != "GET"));
    o.timeout_ms = Some(20_000);
    let before = f.calls().len();
    let r = run_trigger(o).await.unwrap();
    let post = r.exchanges.iter().find(|e| e.request.method == "POST").expect("the aborted post");
    assert!(post.aborted);
    assert!(post.request.body.as_deref().unwrap_or("").contains("\"text\":\"hello\""), "{:?}", post.request.body);
    assert!(!f.calls()[before..].iter().any(|c| c.method == "POST"), "the write never reached the server");
    close_browser().await;
}
