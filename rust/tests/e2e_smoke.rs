mod common;
use api_anything::browser::close_browser;
use api_anything::execute::{CallOptions, call};
use api_anything::heal::{AddInput, add_operation};
use api_anything::spec::Trigger;
use common::fixture::Fixture;
use common::{Home, args};
use serde_json::json;

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
async fn learn_call_and_heal_against_the_fixture() {
    if !chrome() {
        eprintln!("no Chrome: skipped");
        return;
    }
    let _home = Home::new();
    let f = Fixture::start().await;
    let r = add_operation(AddInput {
        site: "fix".into(),
        op: "getUser".into(),
        trigger: Some(Trigger { url: format!("{}/u/{{name}}", f.url), steps: None, soft_from: None }),
        examples: vec![args(json!({"name": "alice"})), args(json!({"name": "bob"}))],
        matcher: None,
        write: false,
        description: None,
        response: None,
        public: None,
        from: None,
        from2: None,
        fetcher: None,
    })
    .await
    .unwrap();
    eprintln!("warnings: {:?}", r.warnings);
    eprintln!("slots: {}", serde_json::to_string(&r.operation.slots).unwrap());
    assert_eq!(r.operation.min_tier, 1);
    assert!(r.operation.slots.iter().any(|s| s.ref_str() == "cookie:ct0"), "{:?}", r.operation.slots);
    assert_eq!(r.operation.response.extract.as_deref(), Some("data.user.posts"));
    assert_eq!(r.captures.len(), 2);

    let c = call("fix", "getUser", args(json!({"name": "carol"})), CallOptions { max_tier: Some(1), min_interval_ms: Some(0), ..Default::default() }).await;
    assert!(c.ok, "{c:?}");
    assert_eq!(c.tier, Some(1));
    assert_eq!(c.data.as_ref().unwrap()[0]["text"], json!("hello from carol"));

    // the site rotates its query id: the rescan heal swaps the new one in without a browser
    f.rotate();
    let h = call("fix", "getUser", args(json!({"name": "dave"})), CallOptions { max_tier: Some(1), min_interval_ms: Some(0), ..Default::default() }).await;
    assert!(h.ok, "{h:?}");
    assert_eq!(h.healed, Some(true));
    assert_eq!(h.data.as_ref().unwrap()[0]["text"], json!("hello from dave"));
    close_browser().await;
}
