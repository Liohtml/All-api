mod common;
use api_anything::classify::{Class, Classified, Observed, classify, judge};
use api_anything::extract::{cap_output, pick};
use api_anything::spec::Operation;
use api_anything::types::Headers;
use common::{j, site};
use serde_json::{Value, json};
use std::time::Instant;

/// `op(over)`: the X-like read with any fields overridden, through the schema.
fn op(over: Value) -> Operation {
    let mut base = json!({
        "name": "getUser",
        "request": {"method": "GET", "url": "https://x.com/i/api/graphql/ID/UserByScreenName?variables=%7B%7D", "headers": {}},
        "slots": [{"param": "screen_name", "at": ["query:variables", "json:/screen_name"]}],
        "trigger": {"url": "https://x.com/{screen_name}"},
        "params": [{"name": "screen_name"}],
        "response": {"format": "json", "extract": "data.user"},
        "readOnly": true,
    });
    merge(&mut base, over);
    common::op(base)
}

fn merge(base: &mut Value, over: Value) {
    if let (Value::Object(b), Value::Object(o)) = (base, over) {
        for (k, v) in o {
            b.insert(k, v);
        }
    }
}

fn headers(pairs: &[(&str, &str)]) -> Headers {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn json_obs(status: u16, body: Value) -> Observed {
    let body = match body {
        Value::String(s) => s,
        v => v.to_string(),
    };
    Observed { status, headers: headers(&[("content-type", "application/json")]), body, url: None }
}

fn html_obs(status: u16, body: &str) -> Observed {
    Observed { status, headers: headers(&[("content-type", "text/html; charset=utf-8")]), body: body.to_string(), url: None }
}

fn with_url(mut o: Observed, url: &str) -> Observed {
    o.url = Some(url.to_string());
    o
}

fn cls(o: &Operation, r: &Observed) -> Class {
    classify(o, r).class
}

fn classified(class: Class, reason: &str, missing: bool) -> Classified {
    Classified { class, reason: reason.to_string(), missing }
}

#[test]
fn ok_2xx_json_with_the_extract_path_present() {
    assert_eq!(classify(&op(json!({})), &json_obs(200, json!({"data": {"user": {"name": "NASA"}}}))), classified(Class::Ok, "ok", false));
    assert_eq!(
        cls(&op(json!({"response": {"format": "json", "xssiPrefix": ")]}'", "extract": "a"}})), &json_obs(200, json!(")]}'\n{\"a\":1}"))),
        Class::Ok
    );
}

#[test]
fn drift_404_on_templated_api_path_persisted_query_errors_missing_extract_shape_change() {
    let o = op(json!({}));
    assert_eq!(cls(&o, &json_obs(404, json!({"message": "Query not found"}))), Class::Drift);
    assert_eq!(cls(&o, &json_obs(200, json!({"errors": [{"message": "PersistedQueryNotFound"}], "data": null}))), Class::Drift);
    assert_eq!(cls(&o, &json_obs(400, json!({"errors": [{"message": "The following features cannot be null: x"}]}))), Class::Drift);
    assert_eq!(cls(&o, &json_obs(200, json!({"data": {}}))), Class::Drift);
    let shaped = op(json!({
        "response": {
            "format": "json",
            "shape": {"a": "object", "a.b": "string", "a.c": "number", "a.d": "array", "a.e": "boolean"},
        },
    }));
    assert_eq!(cls(&shaped, &json_obs(200, json!({"a": {"b": "x", "c": 1, "d": [], "e": null}}))), Class::Ok);
    assert_eq!(cls(&shaped, &json_obs(200, json!({"z": {"y": 1}}))), Class::Drift);
    assert_eq!(cls(&o, &html_obs(200, "<!doctype html><title>x</title><div>app</div>")), Class::Drift, "HTML where JSON expected");
    assert_eq!(cls(&o, &json_obs(200, json!("not json at all"))), Class::Drift);
}

#[test]
fn a_404_with_the_param_in_the_url_path_is_input_the_entity_does_not_exist() {
    let by_path = op(json!({"slots": [{"param": "screen_name", "at": ["path:0"]}]}));
    assert_eq!(cls(&by_path, &json_obs(404, json!({}))), Class::Input);
}

#[test]
fn auth_401_403_with_login_markers_require_login_html_login_page_login_redirect_graphql_auth_error() {
    let o = op(json!({}));
    assert_eq!(cls(&o, &json_obs(401, json!({"errors": [{"code": 32, "message": "Could not authenticate you"}]}))), Class::Auth);
    assert_eq!(cls(&o, &json_obs(403, json!({"message": "login_required"}))), Class::Auth);
    assert_eq!(
        cls(
            &o,
            &json_obs(401, json!({"message": "Please wait a few minutes before you try again.", "require_login": true, "status": "fail"}))
        ),
        Class::Auth,
        "Instagram require_login wins over the rate wording"
    );
    assert_eq!(cls(&o, &html_obs(200, r#"<html><form><input type="password" name="pass"></form></html>"#)), Class::Auth);
    assert_eq!(cls(&o, &with_url(json_obs(200, json!({"data": {"user": {}}})), "https://x.com/i/flow/login?redirect=1")), Class::Auth);
    assert_eq!(cls(&o, &json_obs(200, json!({"errors": [{"message": "Bad guest token"}], "data": null}))), Class::Auth);
}

#[test]
fn rate_429_and_rate_limit_wording_on_errors() {
    let o = op(json!({}));
    assert_eq!(cls(&o, &json_obs(429, json!({}))), Class::Rate);
    assert_eq!(cls(&o, &json_obs(420, json!({"message": "Rate limit exceeded"}))), Class::Rate);
}

#[test]
fn blocked_vendor_challenge_pages_even_at_200_cf_mitigated_bare_403() {
    let o = op(json!({}));
    assert_eq!(
        cls(
            &o,
            &html_obs(
                403,
                "<html><head><title>Just a moment...</title></head><script src=/cdn-cgi/challenge-platform/h/b/cf-chl-x></script></html>"
            )
        ),
        Class::Blocked
    );
    assert_eq!(cls(&o, &html_obs(200, r#"<html><script src="https://ct.captcha-delivery.com/c.js"></script></html>"#)), Class::Blocked);
    assert_eq!(cls(&o, &json_obs(403, json!({"url": "https://geo.captcha-delivery.com/captcha/?initialCid=x"}))), Class::Blocked);
    assert_eq!(cls(&o, &html_obs(200, r#"<div id="px-captcha"></div>"#)), Class::Blocked);
    assert_eq!(cls(&o, &html_obs(200, "<html><title>Reddit - Prove your humanity</title></html>")), Class::Blocked);
    assert_eq!(cls(&o, &html_obs(403, "<H1>Access Denied</H1> Reference #18.1 https://errors.edgesuite.net/18.1")), Class::Blocked);
    let mut cf = json_obs(403, json!(""));
    cf.headers = headers(&[("cf-mitigated", "challenge")]);
    assert_eq!(cls(&o, &cf), Class::Blocked);
    assert_eq!(cls(&o, &json_obs(403, json!(""))), Class::Blocked);
    let reason = classify(&o, &html_obs(200, "<html><title>Just a moment...</title></html>")).reason;
    assert!(reason.contains("Cloudflare"), "{reason}");
}

#[test]
fn a_large_legit_html_page_that_mentions_recaptcha_is_not_blocked() {
    let page = op(json!({"response": {"format": "html", "html": {"items": "tr.athing", "fields": {"t": "a"}}}, "slots": []}));
    // html5ever drops a <tr> outside a <table> (node-html-parser keeps it): the rows sit in a table here
    let body = format!(
        r#"<html><script src="https://www.google.com/recaptcha/api.js"></script><table>{}</table></html>"#,
        "<tr class=athing><td><a>x</a></td></tr>".repeat(3000)
    );
    assert_eq!(cls(&page, &html_obs(200, &body)), Class::Ok);
    assert_eq!(cls(&page, &html_obs(200, "<html><p>nothing here</p></html>")), Class::Drift);
}

#[test]
fn a_sign_in_form_that_embeds_a_captcha_widget_is_auth_a_captcha_page_with_no_sign_in_form_is_blocked() {
    let widget =
        r#"<script src="https://www.google.com/recaptcha/api.js" async defer></script><div class="g-recaptcha" data-sitekey="k"></div>"#;
    let sign_in = format!(
        r#"<!doctype html><html><head><title>Sign in</title></head><body><form action="/session" method="post"><input name="username"><input type="password" name="password">{widget}<button>Sign in</button></form></body></html>"#
    );
    let interstitial = format!(
        r#"<!doctype html><html><head><title>One more step</title></head><body><form action="/verify" method="post">{widget}</form></body></html>"#
    );
    let listed = op(json!({"response": {"format": "html", "html": {"items": "li.r", "fields": {"t": ""}}}}));
    let write = op(json!({"readOnly": false, "response": {"format": "json"}}));
    // an interstitial's own markers win over any form on the page (a hidden or unrelated login form)
    let walled = r#"<!doctype html><html><head><title>One more step</title></head><body><script src="https://geo.captcha-delivery.com/captcha/"></script><form name="js_challenge"><input name="username"><input type="password" name="password"></form></body></html>"#;
    // a script that rides on ordinary pages, named first, must not hide another vendor's interstitial
    let both = walled.replace("<body>", r#"<body><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>"#);
    assert_eq!(cls(&op(json!({})), &html_obs(403, &both)), Class::Blocked);
    // Kasada's headers ride on its sites' ordinary answers: a 403 sign-in form with them asks for a login
    let kasada = |body: &str| Observed {
        status: 403,
        headers: headers(&[("content-type", "text/html"), ("x-kpsdk-ct", "t")]),
        body: body.to_string(),
        url: None,
    };
    assert_eq!(cls(&op(json!({})), &kasada(&sign_in)), Class::Auth);
    assert_eq!(cls(&op(json!({})), &kasada(walled)), Class::Blocked);
    for o in [op(json!({})), listed, write] {
        for status in [200u16, 403] {
            let fmt = j(&o.response.format);
            assert_eq!(cls(&o, &html_obs(status, &sign_in)), Class::Auth, "{fmt} {status}");
            assert_eq!(cls(&o, &html_obs(status, &interstitial)), Class::Blocked, "{fmt} {status}");
            assert_eq!(cls(&o, &html_obs(status, walled)), Class::Blocked, "walled {fmt} {status}");
        }
    }
}

#[test]
fn input_400_naming_a_param_error_5xx_and_unexplained_graphql_errors() {
    let o = op(json!({}));
    assert_eq!(cls(&o, &json_obs(400, json!({"error": "screen_name is invalid"}))), Class::Input);
    assert_eq!(cls(&o, &json_obs(400, json!({"error": "something odd"}))), Class::Error);
    assert_eq!(cls(&o, &json_obs(503, json!("upstream"))), Class::Error);
    assert_eq!(cls(&o, &json_obs(200, json!({"errors": [{"message": "User has been suspended"}], "data": null}))), Class::Error);
}

#[test]
fn embedded_missing_data_is_drift_present_is_ok() {
    let emb = op(json!({"response": {"format": "embedded", "embedded": {"regex": "data:(\\[)"}}}));
    assert_eq!(cls(&emb, &html_obs(200, "<script>x({data:[1,2]})</script>")), Class::Ok);
    assert_eq!(cls(&emb, &html_obs(200, "<script>nothing</script>")), Class::Drift);
}

#[test]
fn auth_and_rate_signals_win_over_drift_when_the_data_is_gone_x_code_215_instagram_200_json_csrf_403() {
    let o = op(json!({}));
    assert_eq!(cls(&o, &json_obs(400, json!({"errors": [{"message": "Bad Authentication data", "code": 215}]}))), Class::Auth);
    assert_eq!(
        cls(&o, &json_obs(403, json!({"errors": [{"code": 353, "message": "This request requires a matching csrf cookie and header."}]}))),
        Class::Auth
    );
    assert_eq!(cls(&o, &json_obs(200, json!({"message": "login_required", "require_login": true, "status": "fail"}))), Class::Auth);
    assert_eq!(
        cls(
            &o,
            &json_obs(200, json!({"message": "Please wait a few minutes before you try again.", "require_login": false, "status": "fail"}))
        ),
        Class::Rate
    );
    assert_eq!(cls(&o, &json_obs(200, json!({"errors": [{"message": "Rate limit exceeded"}], "data": {}}))), Class::Rate);
    assert_eq!(
        cls(&o, &json_obs(200, json!({"data": {"user": {"bio": "I rate limit my coffee"}}}))),
        Class::Ok,
        "wording alone does not matter when the data is there"
    );
}

#[test]
fn login_wording_on_400_403_and_422_is_auth_a_422_validation_error_or_form_page_is_not() {
    let o = op(json!({}));
    for status in [400u16, 403, 422] {
        assert_eq!(cls(&o, &json_obs(status, json!({"message": "Bad Authentication data"}))), Class::Auth, "HTTP {status}");
    }
    assert_eq!(cls(&o, &json_obs(422, json!({"errors": {"email": ["is invalid"]}}))), Class::Error);
    assert_eq!(cls(&o, &json_obs(422, json!({"error": "screen_name is invalid"}))), Class::Error);
    // a signup's "username taken" page shows a password field; only the wording counts
    let taken =
        r#"<form action="/users"><p>Username has already been taken</p><input name="username"><input type="password" name="pw"></form>"#;
    assert_eq!(cls(&op(json!({"readOnly": false})), &html_obs(422, taken)), Class::Error);
}

#[test]
fn missing_data_is_drift_flagged_missing_so_the_caller_can_check_the_example_args_first() {
    assert_eq!(
        classify(&op(json!({})), &json_obs(200, json!({"data": {}}))),
        classified(Class::Drift, "extract path \"data.user\" missing", true)
    );
    // a read's 404 on a query-param API may be "no such user": the example args tell (edge EC-09)
    assert!(
        classify(&op(json!({})), &json_obs(404, json!(""))).missing,
        "a read's 404 on a templated API path is checked against the examples"
    );
    assert!(!classify(&op(json!({"readOnly": false})), &json_obs(404, json!(""))).missing, "a write's 404 is plain drift");
    // Next.js /_next/data/<buildId>/u/<name>.json: 404 after a deploy is not "no such user"
    let next = op(json!({
        "slots": [{"param": "screen_name", "at": ["path:4"], "template": "{screen_name}.json"}],
        "volatile": [{"at": ["path:2"], "shape": {"charset": "base64url", "length": 21}, "anchor": "u"}],
    }));
    assert_eq!(classify(&next, &html_obs(404, "<html>404</html>")), classified(Class::Drift, "HTTP 404", true));
}

#[test]
fn a_writes_2xx_is_ok_whatever_the_body_judge_hands_back_the_text_a_bad_recipe_is_an_error_not_a_throw() {
    let write = op(json!({"readOnly": false, "response": {"format": "json"}}));
    let plain = Observed { status: 200, headers: Headers::new(), body: "OK".to_string(), url: None };
    for r in [json_obs(204, json!("")), html_obs(200, "<html><body>Liked!</body></html>"), plain.clone()] {
        assert_eq!(cls(&write, &r), Class::Ok, "{}", r.body);
    }
    let judged = judge(&write, &plain);
    assert_eq!(judged.class, Class::Ok);
    assert_eq!(judged.reason, "HTTP 200, non-JSON body");
    assert!(!judged.missing);
    assert_eq!(judged.data, Some(json!("OK")));
    // the write ran; a landing page with a change-password form is not a login wall (edge EC-05)
    assert_eq!(cls(&write, &html_obs(200, r#"<form><input type="password"></form>"#)), Class::Ok);
    assert_eq!(cls(&write, &json_obs(200, json!({"errors": [{"message": "denied"}], "data": null}))), Class::Error);
    let bad = op(json!({"response": {"format": "html", "html": {"items": "li[", "fields": {}}}}));
    assert_eq!(judge(&bad, &html_obs(200, "<li>x</li>")).class, Class::Error);
}

#[test]
fn a_logged_out_page_that_only_links_a_sign_in_page_is_not_auth_a_sign_in_form_or_a_servicelogin_redirect_is() {
    let link =
        r#"<html><body><a href="https://accounts.google.com/ServiceLogin?hl=en">Sign in</a><div>Explore destinations</div></body></html>"#;
    let embedded = op(json!({
        "request": {"method": "GET", "url": "https://www.google.com/travel/flights?q=x", "headers": {}},
        "response": {"format": "embedded", "embedded": {"regex": "key: 'ds:1'[^[]*data:(\\[)"}},
    }));
    let listed = op(json!({
        "request": {"method": "GET", "url": "https://s.test/search?q=x", "headers": {}},
        "response": {"format": "html", "html": {"items": "li.r", "fields": {"t": ""}}},
    }));
    for o in [embedded, listed] {
        let c = classify(&o, &html_obs(200, link));
        assert_eq!(c.class, Class::Drift, "{}", c.reason);
        assert!(c.missing);
        let form = r#"<html><form action="/signin"><input name="email"><input type="password" name="pw"></form></html>"#;
        assert_eq!(cls(&o, &html_obs(200, form)), Class::Auth);
        assert_eq!(cls(&o, &with_url(html_obs(200, link), "https://accounts.google.com/ServiceLogin?continue=x")), Class::Auth);
        assert_eq!(cls(&o, &html_obs(200, "<html><p>Please sign in to continue</p></html>")), Class::Auth);
    }
}

#[test]
fn an_extract_ending_in_star_returns_the_items_the_learned_shape_is_compared_per_item() {
    let items = op(json!({
        "response": {
            "format": "json",
            "extract": "[*]",
            "shape": {"[]": "object", "[].id": "string", "[].title": "string", "[].rating": "string", "[].count": "number"},
        },
    }));
    assert_eq!(
        cls(
            &items,
            &json_obs(
                200,
                json!([
                    {"id": "1", "title": "Dune", "rating": "4.29", "count": 10},
                    {"id": "2", "title": "Emma", "rating": "4.0", "count": 3},
                ])
            )
        ),
        Class::Ok
    );
    assert_eq!(cls(&items, &json_obs(200, json!([{"other": 1}, {"other": 2}]))), Class::Drift);
    let nested = op(json!({
        "response": {
            "format": "json",
            "extract": "results[*]",
            "shape": {
                "results": "array",
                "results[]": "object",
                "results[].a": "string",
                "results[].b": "number",
                "results[].c": "boolean",
            },
        },
    }));
    assert_eq!(cls(&nested, &json_obs(200, json!({"results": [{"a": "x", "b": 1, "c": true}]}))), Class::Ok);
}

// ---------------------------------------------------------------- test/edge/round2-classify.test.ts

fn keyed(n: usize, f: impl Fn(usize) -> Value, prefix: &str) -> Value {
    Value::Object((0..n).map(|i| (format!("{prefix}{i}"), f(i))).collect())
}

/// "the cap is a hard guarantee and the note is true"
fn cap_case(value: Value) {
    let t0 = Instant::now();
    let r = cap_output(&value, 20_000);
    let ms = t0.elapsed().as_millis();
    let n = r.data.to_string().len();
    assert!(n <= 20_000, "{n} chars");
    assert!(n > 15_000, "kept only {n} chars");
    assert!(ms < 1000, "{ms} ms");
    let note = r.truncated.clone().unwrap_or_default();
    assert!(note.contains(&format!("cut to {n} of {} chars", value.to_string().len())), "{note}");
    let keys = value.as_object().unwrap().len();
    assert!(note.contains(&format!("showing {} of {keys} keys", r.data.as_object().unwrap().len())), "{note}");
}

#[test]
fn output_the_cap_is_a_hard_guarantee_and_the_note_is_true_10k_numeric_members() {
    cap_case(keyed(10_000, |i| json!(1_234_567_890 + i), "k"));
}

#[test]
fn output_the_cap_is_a_hard_guarantee_and_the_note_is_true_5k_short_strings() {
    cap_case(keyed(5_000, |i| json!(format!("short value {i}")), "k"));
}

#[test]
fn output_the_cap_is_a_hard_guarantee_and_the_note_is_true_id_keyed_map() {
    cap_case(json!({"data": keyed(3_000, |i| json!({"id": i, "name": format!("user {i}"), "bio": "x".repeat(20)}), "u")}));
}

#[test]
fn output_the_cap_is_a_hard_guarantee_and_the_note_is_true_deep_wide() {
    cap_case(json!({"a": {"b": {"c": keyed(20_000, |i| json!(i), "z")}}}));
}

#[test]
fn output_pick_drops_items_that_come_out_empty_shelves_ads_logo_entities() {
    let items = json!([{"title": "a", "id": 1}, {"shelf": {"x": 1}}, {"title": "b"}, {"logo": "l"}]);
    assert_eq!(pick(&items, &["title".to_string(), "id".to_string()]).unwrap(), json!([{"title": "a", "id": 1}, {"title": "b"}]));
}

/// round2's `op(over)`: the search read on c.test, through `parseSite`.
fn op2(over: Value) -> Operation {
    let mut o = json!({
        "name": "o",
        "readOnly": true,
        "request": {"method": "GET", "url": "https://c.test/api/search?q=alice", "headers": {}},
        "slots": [{"param": "q", "at": ["query:q"]}],
        "params": [{"name": "q", "example": "alice"}],
        "trigger": {"url": "https://c.test/s?q={q}"},
        "response": {"format": "json", "extract": "results"},
    });
    merge(&mut o, over);
    site(json!({"name": "c", "baseUrl": "https://c.test", "operations": [o]})).operations.remove(0)
}

const HTML: &str = "text/html; charset=utf-8";

fn obs(status: u16, body: &str, ct: &str, extra: &[(&str, &str)]) -> Observed {
    let mut h = headers(&[("content-type", ct)]);
    for (k, v) in extra {
        h.insert(k.to_string(), v.to_string());
    }
    Observed { status, headers: h, body: body.to_string(), url: None }
}

#[test]
fn classifier_a_400_422_form_page_that_merely_carries_a_csrf_token_is_not_auth_an_explicit_csrf_failure_is() {
    let write = op2(json!({
        "readOnly": false,
        "request": {"method": "POST", "url": "https://c.test/users", "headers": {}, "body": "u=alice"},
        "slots": [{"param": "q", "at": ["form:u"]}],
    }));
    let rails = r#"<!doctype html><html><head><meta name="csrf-param" content="authenticity_token"><meta name="csrf-token" content="Zm9vYmFy"></head><body><div id="error_explanation">Username has already been taken</div><form action="/users" method="post"><input type="hidden" name="authenticity_token" value="Zm9vYmFy"><input name="user[username]"><input type="password" name="user[password]"></form></body></html>"#;
    let django = r#"<html><body><form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="abc123"><ul class="errorlist"><li>This field is required.</li></ul><input name="username"><input type="password" name="password1"></form></body></html>"#;
    assert_ne!(classify(&write, &obs(422, rails, HTML, &[])).class, Class::Auth);
    assert_ne!(classify(&write, &obs(400, django, HTML, &[])).class, Class::Auth);
    assert_ne!(
        classify(
            &write,
            &obs(400, r#"{"error":"name is invalid","allowedHeaders":"content-type, x-csrf-token"}"#, "application/json", &[])
        )
        .class,
        Class::Auth
    );
    for body in [
        r#"{"error":"CSRF token mismatch"}"#,
        "CSRF verification failed. Request aborted.",
        "ActionController::InvalidAuthenticityToken",
        r#"{"message":"Invalid CSRF token"}"#,
    ] {
        assert_eq!(classify(&write, &obs(422, body, "text/plain", &[])).class, Class::Auth, "{body}");
        assert_eq!(classify(&write, &obs(403, body, "text/plain", &[])).class, Class::Auth, "{body}");
    }
    assert_eq!(classify(&write, &obs(419, "Page Expired", HTML, &[])).class, Class::Auth);
}

#[test]
fn classifier_a_vendors_script_on_an_ordinary_page_is_not_a_bot_wall_its_interstitial_is() {
    let page = op2(json!({"response": {"format": "html", "html": {"items": "li", "fields": {"t": ""}}}}));
    let aws_sdk = r#"<!doctype html><html><head><title>Results</title><script src="https://abcd.us-east-1.token.awswaf.com/abcd/e5f6/challenge.js"></script></head><body><ul><li>one</li><li>two</li></ul></body></html>"#;
    assert_eq!(classify(&page, &obs(200, aws_sdk, HTML, &[])).class, Class::Ok);
    let dd404 = r#"<!doctype html><html><head><title>Not found</title><script src="https://js.datadome.co/tags.js"></script></head><body>No such user</body></html>"#;
    assert_ne!(
        classify(
            &op2(json!({
                "slots": [{"param": "q", "at": ["path:1"]}],
                "request": {"method": "GET", "url": "https://c.test/u/alice", "headers": {}},
            })),
            &obs(404, dd404, HTML, &[])
        )
        .class,
        Class::Blocked
    );
    assert_eq!(
        classify(
            &op2(json!({})),
            &obs(200, r#"{"results":[{"id":1}]}"#, "application/json", &[("x-kpsdk-ct", "abc"), ("x-kpsdk-r", "1-x")])
        )
        .class,
        Class::Ok,
        "Kasada headers on a 2xx with data"
    );
    // the real walls still are
    assert_eq!(classify(&op2(json!({})), &obs(429, "<html></html>", HTML, &[("x-kpsdk-ct", "abc")])).class, Class::Blocked);
    assert_eq!(
        classify(
            &op2(json!({})),
            &obs(
                403,
                r#"<html><script src="https://js.datadome.co/tags.js"></script><iframe src="https://geo.captcha-delivery.com/captcha/?initialCid=x"></iframe></html>"#,
                HTML,
                &[]
            )
        )
        .class,
        Class::Blocked
    );
    assert_eq!(
        classify(
            &page,
            &obs(
                202,
                r#"<html><script>window.awsWafCookieDomainList=[];window.gokuProps={}</script><script src="https://x.token.awswaf.com/x/challenge.js"></script></html>"#,
                HTML,
                &[]
            )
        )
        .class,
        Class::Blocked
    );
    assert_eq!(
        classify(&page, &obs(405, r#"<html><script src="https://x.captcha.awswaf.com/x/captcha.js"></script></html>"#, HTML, &[])).class,
        Class::Blocked,
        "an SDK marker on a challenge status"
    );
}

#[test]
fn classifier_a_write_answered_200_with_a_sign_in_form_where_json_was_learned_is_auth_a_change_password_page_is_still_ok() {
    let write = op2(json!({
        "readOnly": false,
        "request": {"method": "POST", "url": "https://c.test/api/like", "headers": {}, "body": "{\"q\":\"alice\"}"},
        "slots": [{"param": "q", "at": ["body", "json:/q"]}],
        "response": {"format": "json"},
    }));
    let sign_in = r#"<!doctype html><html><body><form action="/login" method="post"><input name="email"><input type="password" name="password"><button>Sign in</button></form></body></html>"#;
    assert_eq!(classify(&write, &obs(200, sign_in, HTML, &[])).class, Class::Auth);
    assert_eq!(
        classify(&write, &obs(200, r#"<!doctype html><h1>Settings saved</h1><form><input type="password" name="new"></form>"#, HTML, &[]))
            .class,
        Class::Ok
    );
    // an op whose learned answer is itself a page: its 2xx page is the answer
    let mut page_write = write.clone();
    page_write.response.content_type = Some("text/html".to_string());
    assert_eq!(classify(&page_write, &obs(200, sign_in, HTML, &[])).class, Class::Ok);
}

#[test]
fn classifier_an_empty_result_list_is_ok_no_results_not_drift() {
    let o = op2(json!({
        "response": {
            "format": "json",
            "extract": "results",
            "shape": {
                "results": "array",
                "results[]": "object",
                "results[].id": "number",
                "results[].name": "string",
                "results[].url": "string",
                "total": "number",
            },
        },
    }));
    assert_eq!(classify(&o, &obs(200, r#"{"results":[],"total":0}"#, "application/json", &[])).class, Class::Ok);
    assert_eq!(classify(&o, &obs(200, r#"{"total":0}"#, "application/json", &[])).class, Class::Drift, "a missing target is still missing");
}
