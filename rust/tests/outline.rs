mod common;
use api_anything::extract::{extract_embedded, extract_html};
use api_anything::html::Doc;
use api_anything::outline::{outline, sig};
use api_anything::spec::HtmlRecipe;
use common::j;
use serde_json::{Value, json};

fn row(id: &str, title: &str, rating: &str, badge: &str) -> String {
    format!(
        r#"<li><div class="Book" data-testid="book-item-kca://book/{id}"><a class="BookCard__link" href="/book/show/{id}">cover</a><span data-testid="item-title"><a href="/book/show/{id}">{title}</a></span><span class="Stats css-1x2y3z"><strong>{rating}</strong></span>{badge}</div></li>"#
    )
}

fn page() -> String {
    format!(
        r#"<html><head><title>Search</title></head><body><h1>Results for dune</h1><ul data-testid="results">{}{}{}{}</ul></body></html>"#,
        row(
            "1001",
            "Dune",
            "4.27",
            r#"<span class="Badge">Choice winner</span>"#
        ),
        row("1002", "Dune Messiah", "3.89", ""),
        row("1003", "Children of Dune", "3.96", ""),
        row("1004", "Dune: House Atreides", "3.8", ""),
    )
}

fn s(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| x.to_string()).collect()
}

fn recipe(items: &str, fields: &indexmap::IndexMap<String, String>) -> HtmlRecipe {
    HtmlRecipe {
        items: items.to_string(),
        fields: fields.clone(),
    }
}

/// The string values of a row, like `Object.values(row)` on strings.
fn values(row: &indexmap::IndexMap<String, Value>) -> Vec<String> {
    row.values()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect()
}

#[test]
fn scout_a_repeated_html_list_carrying_the_example_becomes_a_working_html_recipe() {
    let page = page();
    let o = outline("text/html", &page, &s(&["dune"]));
    let list = o
        .as_ref()
        .and_then(|o| o.list.as_ref())
        .unwrap_or_else(|| panic!("{}", json!(j(&o))));
    assert_eq!(list.count, 4);
    let items = extract_html(&page, &recipe(&list.items, &list.fields)).unwrap();
    assert_eq!(
        items.len(),
        4,
        "the items selector finds every result and nothing else"
    );
    let vals = values(&items[1]);
    assert!(
        vals.contains(&"Dune Messiah".to_string())
            && vals.contains(&"3.89".to_string())
            && vals.contains(&"/book/show/1002".to_string()),
        "{}",
        json!(j(&items[1]))
    );
    assert!(
        !list.sample.values().any(|v| v == "Choice winner"),
        "a field only one item has is left out"
    );
}

#[test]
fn scout_ids_inside_data_testid_and_build_hashed_classes_are_never_used_as_selectors() {
    let doc =
        Doc::parse(r#"<div data-testid="book-item-kca://book/77" class="css-9q8w7e Book"></div>"#);
    let el = doc.select_first("div").unwrap().unwrap();
    assert_eq!(sig(&el), "div.Book");
    assert!(
        !json!(j(&outline("text/html", &page(), &s(&["dune"]))))
            .to_string()
            .contains("kca://")
    );
}

#[test]
fn scout_json_gets_the_examples_path_a_suggested_extract_and_pickable_fields_with_samples() {
    let body = json!({
        "meta": {"q": "sqlite"},
        "hits": [
            {"title": "SQLite is great", "points": 10, "author": {"name": "a"}},
            {"title": "Other", "points": 3, "author": {"name": "b"}},
        ],
    })
    .to_string();
    let o = outline("application/json", &body, &s(&["sqlite"]))
        .unwrap()
        .json
        .unwrap();
    assert_eq!(o.extract.as_deref(), Some("hits"));
    let at = o.at.as_ref().unwrap();
    assert!(at.contains(&"hits[0].title".to_string()), "{at:?}");
    assert_eq!(
        j(&o.fields),
        json!({"title": "\"SQLite is great\"", "points": "10", "author.name": "\"a\""})
    );
}

#[test]
fn scout_json_a_page_embeds_comes_with_an_embedded_regex_that_extracts_it_and_id_keyed_paths_are_flagged()
 {
    let next = json!({
        "props": {"pageProps": {"apolloState": {"Book:kca://book/ABC123": {"title": "Project Hail Mary", "pages": 476}}}},
    });
    let ld = json!({
        "@context": "https://schema.org",
        "@type": "Book",
        "name": "Project Hail Mary",
        "numberOfPages": 476,
        "author": [{"@type": "Person", "name": "Andy Weir"}],
    });
    let html = format!(
        r#"<html><head><script type="application/ld+json">{}</script><script id="__NEXT_DATA__" type="application/json">{}</script></head><body><h1>Project Hail Mary</h1></body></html>"#,
        ld, next
    );
    let o = outline("text/html", &html, &s(&["project hail mary"])).unwrap();
    let embedded = o.embedded.as_ref().unwrap();
    assert_eq!(embedded.len(), 2);
    for e in embedded {
        assert!(
            extract_embedded(&html, &e.regex).unwrap().is_some(),
            "{}",
            e.regex
        );
    }
    let ld_out = embedded
        .iter()
        .find(|e| e.regex.starts_with("application/ld"))
        .unwrap();
    assert_eq!(extract_embedded(&html, &ld_out.regex).unwrap(), Some(ld));
    assert_eq!(
        ld_out.outline.extract, None,
        "no extract path when no array holds the example: the whole object"
    );
    assert!(ld_out.outline.fields.contains_key("numberOfPages"));
    let next_out = embedded
        .iter()
        .find(|e| e.regex.contains("__NEXT_DATA__"))
        .unwrap();
    assert_eq!(
        next_out.outline.varying_keys,
        Some(s(&["Book:kca://book/ABC123"]))
    );
}

#[test]
fn scout_values_only_an_icons_aria_label_carries_and_a_detail_pages_repeated_list_as_an_all_field()
{
    let review = |who: &str, stars: u32| {
        format!(
            r#"<article class="ReviewCard"><span class="ReviewerProfile__name">{who}</span><span class="RatingStars" aria-label="Rating {stars} out of 5" role="img"></span><p class="ReviewText">loved it, {who}</p></article>"#
        )
    };
    let reviews = format!(
        r#"<html><body><div class="Reviews">{}{}{}</div></body></html>"#,
        review("Ann", 5),
        review("Bo", 3),
        review("Cy", 4)
    );
    let list = outline("text/html", &reviews, &s(&["loved it"]))
        .unwrap()
        .list
        .unwrap();
    let rows = extract_html(&reviews, &recipe(&list.items, &list.fields)).unwrap();
    assert!(
        rows.iter()
            .enumerate()
            .all(|(i, r)| values(r).contains(&format!("Rating {} out of 5", [5, 3, 4][i]))),
        "{}",
        json!(j(&list))
    );

    let book = r#"<html><body><h1 data-testid="bookTitle">Circe</h1><div data-testid="genresList"><a class="Genre">Fantasy</a><a class="Genre">Mythology</a><a class="Genre">Fiction</a></div></body></html>"#;
    let labels = outline("text/html", book, &[]).unwrap().labels.unwrap();
    assert_eq!(labels[r#"[data-testid="bookTitle"]"#], "\"Circe\"");
    let field = labels.keys().find(|k| k.starts_with("all:")).unwrap();
    let mut fields = indexmap::IndexMap::new();
    fields.insert("genres".to_string(), field.clone());
    assert_eq!(
        extract_html(book, &recipe("body", &fields)).unwrap()[0]["genres"],
        json!(["Fantasy", "Mythology", "Fiction"])
    );
}
