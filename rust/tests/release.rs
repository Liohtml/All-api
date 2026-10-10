//! test/release.test.ts: the parts that exercise the library (learning, replay, judging, add). The
//! call-level and Chrome-driven tests have no Rust counterpart here.
mod common;
use api_anything::classify::{Class, Observed, judge};
use api_anything::heal::{AddInput, CaptureFile, FromCapture, add_operation};
use api_anything::http::build_request;
use api_anything::learn::{LearnInput, Learned, learn_operation};
use api_anything::session::Session;
use api_anything::spec::Trigger;
use api_anything::store::load_site;
use api_anything::types::{Exchange, Headers};
use api_anything::util::iso_now;
use common::{Home, args, ex, site};
use indexmap::IndexMap;
use serde_json::{Value, json};
use std::sync::LazyLock;

static HOME: LazyLock<Home> = LazyLock::new(Home::new);

const A: &str = "Zx81kLmN0pQrStUv2wXyZ3aBcD";
const B: &str = "Ys92jKnM1qRsTuVw3xYzA4bCdE";

fn exchange(id: u64, body: Value, response: Value) -> Exchange {
    ex(json!({
        "id": id,
        "resourceType": "fetch",
        "request": {
            "method": "POST",
            "url": "https://site.test/api",
            "headers": {"content-type": "application/json"},
            "body": body.to_string(),
        },
        "response": {"status": 200, "headers": {}, "contentType": "application/json", "body": response.to_string()},
    }))
}

fn learned(body: Value, name: &str) -> Learned {
    let input = LearnInput::new(
        vec![
            exchange(1, json!({}), json!({"a": A, "b": B})),
            exchange(2, body, json!({"results": ["kittens"]})),
        ],
        vec![args(json!({"q": "kittens"}))],
        name,
        Trigger {
            url: "https://site.test/?q={q}".into(),
            steps: None,
            soft_from: None,
        },
        true,
    );
    learn_operation(&input).unwrap()
}

fn body_of(l: &Learned, q: &str, session: &Session) -> Value {
    let req = build_request(&l.operation, &args(json!({"q": q})), session).unwrap();
    serde_json::from_str(req.body.as_deref().unwrap()).unwrap()
}

#[test]
fn distinct_issued_tokens_survive_learn_and_replay_including_another_operations_session_values() {
    let body = json!({"q": "kittens", "one": {"v": A}, "two": {"v": B}});
    let first = learned(body.clone(), "search");
    let other = learned(
        json!({"q": "kittens", "one": {"v": B}, "two": {"v": A}}),
        "other",
    );
    let mut values: IndexMap<String, String> = first.session_values.clone();
    values.extend(other.session_values.clone());
    let session = Session::with(vec![], values);
    assert_eq!(body_of(&first, "kittens", &session), body);
    assert_eq!(
        body_of(&other, "puppies", &session),
        json!({"q": "puppies", "one": {"v": B}, "two": {"v": A}})
    );
}

#[test]
fn issued_credentials_are_removed_from_every_compound_copy_and_refresh_on_replay() {
    let body = json!({
        "q": "kittens",
        "t": A,
        "ctx": format!("prefix:{A}"),
        "both": format!("{A}:{B}"),
        "other": B,
        "next": format!("https://site.test/?q=kittens&t={A}"),
    });
    let l = learned(body, "search");
    let serialized = serde_json::to_string(&l.operation).unwrap();
    for token in [A, B] {
        assert!(
            !serialized.contains(token),
            "credential in serialized operation"
        );
    }
    let values: IndexMap<String, String> = l
        .session_values
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                if v == A {
                    "fresh-A".to_string()
                } else {
                    "fresh-B".to_string()
                },
            )
        })
        .collect();
    let replay = body_of(&l, "puppies", &Session::with(vec![], values));
    assert_eq!(
        replay,
        json!({
            "q": "puppies",
            "t": "fresh-A",
            "ctx": "prefix:fresh-A",
            "both": "fresh-A:fresh-B",
            "other": "fresh-B",
            "next": "https://site.test/?q=puppies&t=fresh-A",
        })
    );
}

/// The `judge` half of "a write rejected inside an HTTP 200 response is not success and is never
/// retried"; the `call` half needs the execute module.
#[test]
fn a_write_rejected_inside_an_http_200_response_is_not_success_and_is_never_retried() {
    let mut s = site(json!({
        "name": "rejected-write",
        "baseUrl": "https://site.test",
        "operations": [
            {
                "name": "send",
                "readOnly": false,
                "request": {"method": "POST", "url": "https://site.test/send", "headers": {}, "body": "{}"},
                "trigger": {"url": "https://site.test/compose"},
                "response": {"format": "json", "extract": "receipt.id"},
            },
        ],
    }));
    let op = s.operations.remove(0);
    let obs = |status: u16, body: &str| Observed {
        status,
        headers: Headers::new(),
        body: body.to_string(),
        url: None,
    };
    assert_eq!(
        judge(&op, &obs(200, r#"{"accepted":true}"#)).class,
        Class::Ok
    );
    assert_eq!(judge(&op, &obs(204, "")).class, Class::Ok);
}

#[tokio::test]
async fn add_refuses_to_save_a_spec_containing_a_credential_it_cannot_remove() {
    let _ = &*HOME;
    let token = "secret123"; // shorter than compound-token templating supports
    let e = exchange(1, json!({"q": "kittens", "ctx": format!("prefix:{token}")}), json!({"results": ["kittens"]}));
    let capture: CaptureFile = serde_json::from_value(json!({
        "id": "test",
        "at": iso_now(),
        "url": "https://site.test/?q=kittens",
        "finalUrl": "https://site.test/?q=kittens",
        "exchanges": [e],
        "cookies": [{ "name": "session", "value": token, "domain": "site.test", "path": "/", "expires": -1, "httpOnly": true, "secure": true }],
    }))
    .unwrap();
    let err = add_operation(AddInput {
        site: "secret".into(),
        op: "search".into(),
        trigger: None,
        examples: vec![args(json!({"q": "kittens"}))],
        matcher: None,
        write: false,
        description: None,
        response: None,
        public: None,
        from: Some(FromCapture { capture, id: Some(1) }),
        from2: None,
        fetcher: None,
    })
    .await
    .err()
    .expect("add refuses")
    .to_string();
    assert!(err.to_lowercase().contains("credential"), "{err}");
    assert!(load_site("secret").unwrap().is_none());
}
