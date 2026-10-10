mod common;
use common::fixture::Fixture;

#[tokio::test]
async fn fixture_serves_pages_and_api() {
    let f = Fixture::start().await;
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let home = client.get(format!("{}/", f.url)).send().await.unwrap();
    assert_eq!(home.status(), 200);
    assert!(home.headers().get("set-cookie").is_some());
    let text = home.text().await.unwrap();
    assert!(text.contains(&format!("/static/app.{}.js", f.state().build)));
    let js = client.get(format!("{}/static/app.{}.js", f.url, f.state().build)).send().await.unwrap().text().await.unwrap();
    assert!(js.contains(&f.state().user_query_id));
    let r = client.get(format!("{}/api/scoped?q=alice", f.url)).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), r#"{"data":{"results":["alice one","alice two"]}}"#);
    assert_eq!(f.calls().len(), 1);
    let r = client.get(format!("{}/login", f.url)).send().await.unwrap();
    assert_eq!(r.status(), 302);
    f.close();
}
