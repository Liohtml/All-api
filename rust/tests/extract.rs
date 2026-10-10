mod common;
use api_anything::extract::{
    cap_output, extract, extract_embedded, extract_html, get_path, infer_shape, parse_body, pick, returned_fields, split_pick,
};
use api_anything::spec::{HtmlRecipe, ResponseSpec, parse_operation};
use common::j;
use indexmap::IndexMap;
use serde_json::{Value, json};

fn res(v: Value) -> ResponseSpec {
    serde_json::from_value(v).expect("a response spec literal")
}
fn recipe(v: Value) -> HtmlRecipe {
    serde_json::from_value(v).expect("an html recipe literal")
}
fn s(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| x.to_string()).collect()
}
fn path(obj: &Value, p: &str) -> Option<Value> {
    get_path(obj, Some(p))
}
fn rows(r: Vec<IndexMap<String, Value>>) -> Value {
    Value::Array(r.into_iter().map(|m| Value::Object(m.into_iter().collect())).collect())
}

#[test]
fn returned_fields_the_keys_a_result_item_carries_from_the_pick_or_an_html_recipes_fields() {
    assert_eq!(
        returned_fields(&res(json!({"format": "json", "pick": ["bookId", "author=author.name", "id=url~/show/(\\d+)", "node.code"]}))),
        Some(s(&["bookId", "author", "id", "node.code"]))
    );
    let html = json!({"items": "li", "fields": {"title": "a", "url": "a@href"}});
    assert_eq!(returned_fields(&res(json!({"format": "html", "html": html}))), Some(s(&["title", "url"])));
    // an extract path reshapes the items, and a JSON op ignores an HTML recipe: neither returns those fields
    assert_eq!(returned_fields(&res(json!({"format": "html", "html": html, "extract": "[0].title"}))), None);
    assert_eq!(returned_fields(&res(json!({"format": "json", "html": html}))), None);
    assert_eq!(returned_fields(&res(json!({"format": "json"}))), None);
}

#[test]
fn parse_body_strips_xssi_and_keeps_big_integers_exact() {
    assert_eq!(parse_body(")]}'\n{\"id\":2085462611575857621,\"n\":3}", None).unwrap(), json!({"id": "2085462611575857621", "n": 3}));
    assert_eq!(parse_body("while(1);[1]", Some("while(1);")).unwrap(), json!([1]));
    assert!(parse_body("<html>", None).is_err());
}

#[test]
fn parse_body_reads_google_rt_c_length_prefixed_chunks() {
    let body = ")]}'\n\n27\n[[\"wrb.fr\",null,\"[1,2]\"]]\n12\n[[\"di\",42]]\n";
    assert_eq!(parse_body(body, None).unwrap(), json!([[["wrb.fr", null, "[1,2]"]], [["di", 42]]]));
    // a final empty chunk ends the framing: its length is not data, on one line or after a multi-line value
    assert_eq!(parse_body(")]}'\n7\n{\"a\":1}\n0\n", None).unwrap(), json!([{"a": 1}]));
    assert_eq!(parse_body(")]}'\n12\n{\n \"a\": 1\n}\n0\n", None).unwrap(), json!([{"a": 1}]));
}

#[test]
fn get_path_dots_brackets_index_only_paths_dashed_keys_quoted_keys() {
    let o = json!({"a": {"foo-bar": [{"c": 1}]}, "x.y": 2, "arr": [[0, [5, 6]]]});
    assert_eq!(path(&o, "a.foo-bar[0].c"), Some(json!(1)));
    assert_eq!(path(&o, "[\"x.y\"]"), Some(json!(2)));
    assert_eq!(path(&o["arr"], "[0][1][1]"), Some(json!(6)));
    assert_eq!(path(&o, "a.missing.c"), None);
    assert_eq!(path(&json!("str"), "length"), None);
}

#[test]
fn get_path_star_results_split_across_sections_an_ad_section_first_are_all_collected() {
    // YouTube with a visitor cookie: section 0 holds an ad, a shelf and one video, then an ad slot, then the main list
    let v = |id: &str| json!({"videoRenderer": {"videoId": id}});
    let page = json!({
        "contents": [
            {"itemSectionRenderer": {"contents": [{"searchPyvRenderer": {}}, {"shelfRenderer": {}}, v("a")]}},
            {"adSlotRenderer": {}},
            {"itemSectionRenderer": {"contents": [v("b"), v("c")]}},
        ],
    });
    let p = "contents[*].itemSectionRenderer.contents";
    assert_eq!(path(&page, p).unwrap().as_array().unwrap().len(), 5);
    assert_eq!(
        extract(&res(json!({"format": "json", "extract": p, "pick": ["id=videoRenderer.videoId"]})), &page.to_string()).unwrap(),
        Some(json!([{"id": "a"}, {"id": "b"}, {"id": "c"}]))
    );
    assert_eq!(path(&json!({"contents": []}), p), Some(json!([])), "no sections: no results");
    assert_eq!(path(&json!({"contents": [{"adSlotRenderer": {}}]}), p), None, "sections, none with the path: moved, not empty");
    assert_eq!(path(&json!({"contents": {}}), p), None);
    assert_eq!(path(&json!({"a": [{"b": 1}, {"c": 2}, {"b": 3}]}), "a[*].b"), Some(json!([1, 3])));
}

#[test]
fn pick_projects_per_item_and_per_object() {
    let items = json!([
        {"id": 1, "user": {"name": "a", "bio": "long"}, "x": 1},
        {"id": 2, "user": {"name": "b"}},
    ]);
    assert_eq!(
        pick(&items, &s(&["id", "user.name"])).unwrap(),
        json!([
            {"id": 1, "user.name": "a"},
            {"id": 2, "user.name": "b"},
        ])
    );
    assert_eq!(pick(&json!({"id": 1, "y": 2}), &s(&["id", "nope"])).unwrap(), json!({"id": 1}));
}

#[test]
fn html_recipe_via_selectors_text_and_attr() {
    let html = r#"<table>
    <tr class="athing" id="1"><td><span class="titleline"><a href="https://a.example">First  story</a></span></td></tr>
    <tr class="athing" id="2"><td><span class="titleline"><a href="item?id=2">Second &amp; more</a></span></td></tr>
  </table>"#;
    let got = extract_html(
        html,
        &recipe(json!({
            "items": "tr.athing",
            "fields": {"id": "@id", "title": ".titleline > a", "url": ".titleline > a@href", "none": ".nope"},
        })),
    )
    .unwrap();
    assert_eq!(
        rows(got),
        json!([
            {"id": "1", "title": "First story", "url": "https://a.example"},
            {"id": "2", "title": "Second & more", "url": "item?id=2"},
        ])
    );
}

#[test]
fn embedded_regex_group_1_marks_the_json_start_the_scanner_finds_its_end() {
    let doc = r#"<script>AF_initDataCallback({key: 'ds:1', hash: '2', data:[["United",[1,2]],"x]y"], sideChannel: {}});</script>"#;
    assert_eq!(extract_embedded(doc, "key: 'ds:1'.*?data:(\\[)").unwrap(), Some(json!([["United", [1, 2]], "x]y"])));
    assert_eq!(extract_embedded(doc, "key: 'ds:9'.*?data:(\\[)").unwrap(), None);
    assert_eq!(
        extract(&res(json!({"format": "embedded", "embedded": {"regex": "data:(\\[)"}, "extract": "[0][0]"})), doc).unwrap(),
        Some(json!("United"))
    );
}

#[test]
fn extract_json_plus_extract_plus_pick_html_without_recipe_returns_the_raw_body() {
    let body = r#")]}'{"data":{"items":[{"id":1,"t":"a","junk":1}]}}"#;
    assert_eq!(
        extract(&res(json!({"format": "json", "xssiPrefix": ")]}'", "extract": "data.items", "pick": ["id", "t"]})), body).unwrap(),
        Some(json!([{"id": 1, "t": "a"}]))
    );
    assert_eq!(extract(&res(json!({"format": "json", "extract": "data.nope"})), body).unwrap(), None);
    assert_eq!(extract(&res(json!({"format": "html"})), "<p>x</p>").unwrap(), Some(json!("<p>x</p>")));
}

#[test]
fn cap_output_truncates_arrays_at_item_boundaries_and_notes_it() {
    let big: Vec<Value> = (0..100).map(|i| json!({"i": i, "pad": "x".repeat(50)})).collect();
    let out = cap_output(&Value::Array(big), 1000);
    assert!(out.data.is_array());
    assert!(out.data.to_string().len() <= 1000);
    let note = out.truncated.unwrap();
    assert!(regex::Regex::new(r"showing \d+ of 100 items").unwrap().is_match(&note), "{note}");
    let small = cap_output(&json!({"a": 1}), 20_000);
    assert_eq!(small.data, json!({"a": 1}));
    assert_eq!(small.truncated, None);
    // an object stays an object, its long string shortened (edge EC-14)
    let s = cap_output(&json!({"s": "y".repeat(50)}), 20);
    assert_eq!(s.data, json!({"s": "y".repeat(12)}));
    assert!(s.truncated.as_deref().unwrap().contains("cut to 20"), "{:?}", s.truncated);
    assert_eq!(cap_output(&json!("z".repeat(50)), 20).data, json!("z".repeat(18)));
}

#[test]
fn infer_shape_records_key_paths_and_types_first_array_item_only() {
    assert_eq!(
        j(&infer_shape(&json!({"data": {"users": [{"id": "1", "n": 2}, {"other": true}], "ok": null}}), 200)),
        json!({
            "data": "object",
            "data.users": "array",
            "data.users[]": "object",
            "data.users[].id": "string",
            "data.users[].n": "number",
            "data.ok": "null",
        })
    );
}

#[test]
fn get_path_steps_into_json_encoded_strings_batchexecute_payloads() {
    let body = json!([["wrb.fr", "search", json!([[["a", 1], ["b", 2]]]).to_string()]]);
    assert_eq!(path(&body, "[0][2][0][1]"), Some(json!(["b", 2])));
    assert_eq!(path(&body, "[0][1][0]"), None, "a plain string is not indexed");
}

#[test]
fn parse_body_metas_for_prefix_repeated_before_each_chunk_gives_an_array() {
    assert_eq!(parse_body("for (;;);{\"a\":1}", None).unwrap(), json!({"a": 1}));
    assert_eq!(parse_body("for (;;);{\"a\":1}\nfor (;;);{\"b\":2}", None).unwrap(), json!([{"a": 1}, {"b": 2}]));
    assert_eq!(parse_body("while(1);[1,2]", None).unwrap(), json!([1, 2]));
}

#[test]
fn pick_name_equals_path_renames_the_output_key() {
    assert_eq!(
        pick(
            &json!([{"node": {"code": "A", "caption": {"text": "hi"}}}]),
            &s(&["code=node.code", "caption=node.caption.text", "node.code"]),
        )
        .unwrap(),
        json!([{"code": "A", "caption": "hi", "node.code": "A"}])
    );
    assert_eq!(pick(&json!({"[1][0][1]": 1}), &[]).unwrap(), json!({}));
    assert_eq!(pick(&json!([[["UA"], [0, 209]]]), &s(&["price=[1][1]"])).unwrap(), json!([{"price": 209}]));
}

#[test]
fn pick_name_equals_path_tilde_regex_keeps_group_1_or_the_whole_match_of_a_string_no_match_drops_the_field() {
    let items = json!([
        {"u": "https://www.linkedin.com/in/satyanadella?miniProfileUrn=x"},
        {"u": "https://www.linkedin.com/company/openai/"},
        {"u": 7},
    ]);
    assert_eq!(
        pick(&items, &s(&["id=u~/in/([^/?]+)", "co=u~/company/([^/?]+)", "host=u~linkedin\\.com"])).unwrap(),
        json!([
            {"id": "satyanadella", "host": "linkedin.com"},
            {"co": "openai", "host": "linkedin.com"},
        ])
    );
    assert_eq!(pick(&json!({"a": {"b": "v-12"}}), &s(&["a.b~\\d+"])).unwrap(), json!({"a.b": "12"}));
    let err = parse_operation(&json!({
        "name": "x", "request": {"method": "GET", "url": "https://x/"}, "trigger": {"url": "https://x/"}, "readOnly": true,
        "response": {"pick": ["id=u~/in/(["]},
    }))
    .unwrap_err()
    .to_string();
    assert!(err.contains("regex after ~"), "{err}");
}

#[test]
fn pick_splits_on_commas_but_not_inside_a_regexs_brackets_nor_an_escaped_comma() {
    assert_eq!(split_pick("bookId,title,author=author.name"), s(&["bookId", "title", "author=author.name"]));
    assert_eq!(split_pick("count=rating~—\\s([0-9,]+),year=x~(\\d{4})"), s(&["count=rating~—\\s([0-9,]+)", "year=x~(\\d{4})"]));
    assert_eq!(split_pick("a~x\\,y, b"), s(&["a~x,y", "b"]));
}

#[test]
fn an_html_field_with_all_returns_every_match_as_a_list_empty_when_there_is_none() {
    let body = r#"<main><h1>Circe</h1><ul class="genres"><li><a>Fantasy</a></li><li><a>Mythology</a></li><li><a>Fiction</a></li></ul><a class="tag" href="/t/1">x</a><a class="tag" href="/t/2">y</a></main>"#;
    assert_eq!(
        rows(
            extract_html(
                body,
                &recipe(json!({
                    "items": "main",
                    "fields": {"title": "h1", "genres": "all:ul.genres a", "tags": "all:a.tag@href", "none": "all:.missing"},
                })),
            )
            .unwrap()
        ),
        json!([{"title": "Circe", "genres": ["Fantasy", "Mythology", "Fiction"], "tags": ["/t/1", "/t/2"], "none": []}])
    );
}
