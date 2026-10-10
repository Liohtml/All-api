//! The explorer's scout: a compact summary of what one captured response holds, so an agent can
//! choose a request and a response recipe without reading the body. Deterministic, no LLM, no
//! site-specific rules: JSON outlines, JSON embedded in a page (JSON-LD, __NEXT_DATA__, state
//! assignments), and repeated HTML items that carry an example value.
use crate::extract::{extract_embedded, get_path, inner_json, parse_body};
use crate::html::{Doc, attr, element_children, first_is, parent, query_all, tag, text_of};
use crate::learn::suggest_extract;
use crate::util::{json, json_unquote, re};
use indexmap::IndexMap;
use scraper::ElementRef;
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::sync::LazyLock;

#[derive(Clone, Debug, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JsonOutline {
    /// paths where an example value appears
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<Vec<String>>,
    /// suggested --extract
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extract: Option<String>,
    /// field path (under extract, per item) -> sample value, for --pick
    pub fields: IndexMap<String, String>,
    /// object keys on the way to an example that look like ids: a path through them won't generalize
    #[serde(skip_serializing_if = "Option::is_none")]
    pub varying_keys: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct HtmlList {
    pub items: String,
    pub count: usize,
    pub fields: IndexMap<String, String>,
    pub sample: IndexMap<String, String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct EmbeddedOutline {
    pub regex: String,
    #[serde(flatten)]
    pub outline: JsonOutline,
}

#[derive(Clone, Debug, Serialize, Default, PartialEq)]
pub struct Outline {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<JsonOutline>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded: Option<Vec<EmbeddedOutline>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list: Option<HtmlList>,
    /// a page with no repeated list: short labelled texts (css -> sample) for --html '{"items":"body",...}'
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<IndexMap<String, String>>,
}

impl Outline {
    pub fn is_empty(&self) -> bool {
        self.json.is_none() && self.embedded.is_none() && self.list.is_none() && self.labels.is_none()
    }
}

const MAX_FIELDS: usize = 30;

fn clip(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() > n { format!("{}…", chars[..n - 1].iter().collect::<String>()) } else { s.to_string() }
}

fn sample(v: &Value) -> String {
    match v {
        Value::String(s) => json(&Value::String(clip(&crate::util::squash_ws(s), 60))),
        Value::Array(a) => format!("array({})", a.len()),
        Value::Object(o) => {
            let keys: Vec<&String> = o.keys().collect();
            let shown: Vec<&str> = keys.iter().take(6).map(|k| k.as_str()).collect();
            format!("{{{}{}}}", shown.join(","), if keys.len() > 6 { ",…" } else { "" })
        }
        other => crate::util::as_text(other),
    }
}

static WORD_KEY: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Za-z_$][\w$-]*$"));

fn step(path: &str, k: &str) -> String {
    if WORD_KEY.is_match(k) {
        if path.is_empty() { k.to_string() } else { format!("{path}.{k}") }
    } else {
        format!("{path}[{}]", json(&Value::String(k.to_string())))
    }
}

// an id-like key: digits, or a URN/URL-ish value (Apollo's "Book:kca://book/...", "User:123")
static ID_LIKE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\d{3,}|[:/]"));
fn id_like(k: &str) -> bool {
    ID_LIKE.is_match(k)
}

/// Paths (get_path syntax) to string leaves containing an example value, stepping into JSON strings.
fn find_paths(root: &Value, values: &[String], max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut queue: VecDeque<(Value, String, usize)> = VecDeque::from([(root.clone(), String::new(), 0)]);
    while let Some((v, path, depth)) = queue.pop_front() {
        if out.len() >= max {
            break;
        }
        if let Value::String(s) = &v {
            match inner_json(s) {
                Some(inner) if inner.is_object() || inner.is_array() => queue.push_back((inner, path, depth)),
                _ => {
                    let low = s.to_lowercase();
                    if values.iter().any(|x| low.contains(x)) {
                        out.push(path);
                    }
                }
            }
            continue;
        }
        if depth > 12 {
            continue;
        }
        match &v {
            Value::Array(a) => {
                for (i, c) in a.iter().take(100).enumerate() {
                    queue.push_back((c.clone(), format!("{path}[{i}]"), depth + 1));
                }
            }
            Value::Object(o) => {
                for (k, c) in o {
                    queue.push_back((c.clone(), step(&path, k), depth + 1));
                }
            }
            _ => {}
        }
    }
    out
}

/// Leaf paths of one item (arrays as [*]) with samples.
fn fields_of(item: Option<&Value>) -> IndexMap<String, String> {
    let mut out = IndexMap::new();
    fn visit(v: &Value, path: &str, depth: usize, out: &mut IndexMap<String, String>) {
        if out.len() >= MAX_FIELDS {
            return;
        }
        if let Value::String(s) = v {
            if let Some(inner) = inner_json(s) {
                if (inner.is_object() || inner.is_array()) && depth < 4 {
                    return visit(&inner, path, depth, out);
                }
            }
        }
        if (v.is_object() || v.is_array()) && depth < 4 {
            if let Value::Array(a) = v {
                if !path.is_empty() {
                    out.insert(path.to_string(), sample(v));
                }
                if let Some(first) = a.first() {
                    if first.is_object() || first.is_array() {
                        visit(first, &format!("{path}[*]"), depth + 1, out);
                    }
                }
                return;
            }
            if let Value::Object(o) = v {
                for (k, c) in o {
                    visit(c, &step(path, k), depth + 1, out);
                }
            }
            return;
        }
        if !path.is_empty() {
            out.insert(path.to_string(), sample(v));
        }
    }
    if let Some(item) = item {
        visit(item, "", 0, &mut out);
    }
    out
}

static QUOTED_KEY: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"\["((?:[^"\\]|\\.)*)"\]"#));

pub fn outline_json(root: &Value, values: &[String]) -> JsonOutline {
    let at = find_paths(root, values, 5);
    // suggest_extract falls back to the biggest array; for an outline, only a path holding the example counts
    let suggested = suggest_extract(root, values);
    let carries = |v: Option<&Value>| match v {
        Some(v) => {
            let s = json(v).to_lowercase();
            values.iter().any(|x| s.contains(x))
        }
        None => false,
    };
    let extract = suggested.filter(|s| carries(get_path(root, Some(s)).as_ref()));
    let target = get_path(root, extract.as_deref());
    let item = match &target {
        Some(Value::Array(a)) => a.first().cloned(),
        other => other.clone(),
    };
    let fields = fields_of(item.as_ref());
    let mut varying: Vec<String> = Vec::new();
    for p in &at {
        for m in QUOTED_KEY.captures_iter(p) {
            let k = json_unquote(&m[1]).unwrap_or_else(|| m[1].to_string());
            if id_like(&k) && !varying.contains(&k) {
                varying.push(k);
            }
        }
    }
    JsonOutline {
        at: if at.is_empty() { None } else { Some(at) },
        extract,
        fields,
        varying_keys: if varying.is_empty() { None } else { Some(varying.into_iter().take(3).collect()) },
    }
}

/// Regexes (for --embedded, group 1 at the JSON's start) for JSON blocks a page embeds.
pub fn embedded_blocks(body: &str) -> Vec<String> {
    static SCRIPT: LazyLock<regex::Regex> = LazyLock::new(|| re(r"<script\b([^>]*)>\s*([\[{])"));
    static ID: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"\bid="([^"]+)""#));
    static LD: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)application/ld\+json"));
    static APP_JSON: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)application/json"));
    static TYPE: LazyLock<regex::Regex> = LazyLock::new(|| re(r#""@type"\s*:\s*"([^"]+)""#));
    static WINDOW: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\bwindow\.([A-Za-z_$][\w$]*)\s*=\s*([\[{])"));
    let mut out: Vec<String> = Vec::new();
    for m in SCRIPT.captures_iter(body) {
        let attrs = &m[1];
        let id = ID.captures(attrs).map(|c| c[1].to_string());
        let start = m.get(0).unwrap().start();
        if LD.is_match(attrs) {
            let end = body.char_indices().map(|(i, _)| i).find(|i| *i >= start + 400).unwrap_or(body.len());
            let head = &body[start..end];
            let t = TYPE.captures(head).map(|c| c[1].to_string());
            let look = t.map(|t| format!(r#"(?=[^<]*?"@type"\s*:\s*"{}")"#, regex::escape(&t))).unwrap_or_default();
            out.push(format!(r"application/ld\+json[^>]*>\s*(\{{){look}"));
        } else if let Some(id) = id {
            if APP_JSON.is_match(attrs) {
                out.push(format!(r#"id="{}"[^>]*>\s*([\[{{])"#, regex::escape(&id)));
            }
        }
    }
    for m in WINDOW.captures_iter(body) {
        out.push(format!(r"window\.{}\s*=\s*([\[{{])", regex::escape(&m[1])));
    }
    let mut seen = HashSet::new();
    out.into_iter().filter(|s| seen.insert(s.clone())).collect()
}

// ---------------------------------------------------------------- HTML lists

const SKIP: [&str; 8] = ["script", "style", "noscript", "head", "title", "meta", "svg", "template"];

fn skipped(t: &str) -> bool {
    SKIP.contains(&t)
}

// class names a build tool generated (css-1x2y3z, sc-abc, Foo__bar_3kd9f) change between deploys
fn stable_class(c: &str) -> bool {
    static NAME: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Za-z][\w-]*$"));
    static GEN: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^(css|sc|jsx|svelte|tw)-"));
    static DIGITS: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\d{3,}"));
    static HASHY: LazyLock<fancy_regex::Regex> = LazyLock::new(|| crate::util::fre(r"(?i)[_-](?=(?:[a-z]*\d){2})[a-z0-9]{5,}$"));
    NAME.is_match(c) && !GEN.is_match(c) && !DIGITS.is_match(c) && !HASHY.is_match(c).unwrap_or(false)
}

// a data-testid that embeds a record id ("book-item-kca://book/...") differs per record
fn stable_testid(t: Option<&str>) -> Option<&str> {
    t.filter(|t| !t.is_empty() && !ID_LIKE.is_match(t))
}

fn classes(el: &ElementRef) -> Vec<String> {
    attr(el, "class").unwrap_or("").split_whitespace().map(|s| s.to_string()).collect()
}

/// A short selector for an element: its data-testid, else tag.firstStableClass, else tag.
pub fn sig(el: &ElementRef) -> String {
    if let Some(tid) = stable_testid(attr(el, "data-testid")) {
        return format!("[data-testid=\"{tid}\"]");
    }
    match classes(el).into_iter().find(|c| stable_class(c)) {
        Some(cls) => format!("{}.{cls}", tag(el)),
        None => tag(el),
    }
}

fn labelled(el: &ElementRef) -> bool {
    stable_testid(attr(el, "data-testid")).is_some() || classes(el).iter().any(|c| stable_class(c))
}

/// Words of a name: split on non-alphanumerics and on a lower-to-upper boundary.
fn words(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev: Option<char> = None;
    for c in raw.chars() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            if let Some(p) = prev {
                if p.is_ascii_lowercase() && c.is_ascii_uppercase() && !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            cur.push(c);
        }
        prev = Some(c);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn name_for(el: &ElementRef, used: &mut HashSet<String>, at: Option<&str>) -> String {
    let raw = stable_testid(attr(el, "data-testid"))
        .map(|s| s.to_string())
        .or_else(|| classes(el).into_iter().rfind(|c| stable_class(c)))
        .unwrap_or_else(|| tag(el));
    // the last two words name it: "book-item-ratings-count" -> ratingsCount, "BookStats__rating" -> bookStatsRating
    let ws = words(&raw);
    let ws: Vec<String> = ws.into_iter().rev().take(2).collect::<Vec<_>>().into_iter().rev().collect();
    let mut base: String = ws
        .iter()
        .enumerate()
        .map(|(i, w)| {
            if i == 0 {
                w.to_lowercase()
            } else {
                let mut c = w.chars();
                match c.next() {
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    None => String::new(),
                }
            }
        })
        .collect();
    if base.is_empty() {
        base = tag(el);
    }
    match at {
        Some("href") => base.push_str("Url"),
        Some("src") => base.push_str("Image"),
        Some("aria-label") => base.push_str("Label"),
        _ => {}
    }
    let mut name = base.clone();
    let mut n = 2;
    while used.contains(&name) {
        name = format!("{base}{n}");
        n += 1;
    }
    used.insert(name.clone());
    name
}

/// A selector that finds `el` first inside `item`: its own label, else its nearest labelled ancestor's plus its tag.
fn selector_in<'a>(item: ElementRef<'a>, el: ElementRef<'a>) -> Option<(String, ElementRef<'a>)> {
    let own = sig(&el);
    if labelled(&el) && first_is(item, &own, &el) {
        return Some((own, el));
    }
    let mut a = parent(&el);
    while let Some(anc) = a {
        if anc.id() == item.id() {
            break;
        }
        if labelled(&anc) {
            let css = format!("{} {}", sig(&anc), own);
            if first_is(item, &css, &el) {
                return Some((css, anc));
            }
        }
        a = parent(&anc);
    }
    None
}

fn has_own_text(el: &ElementRef) -> bool {
    el.children().any(|c| c.value().as_text().map(|t| !t.trim().is_empty()).unwrap_or(false))
}

/// Fields inside one item: short texts and links, each with a selector that finds that element first.
fn item_fields<'a>(item: ElementRef<'a>, items: &[ElementRef<'a>]) -> (IndexMap<String, String>, IndexMap<String, String>) {
    let mut fields: IndexMap<String, String> = IndexMap::new();
    let mut sample_out: IndexMap<String, String> = IndexMap::new();
    let mut used: HashSet<String> = HashSet::new();
    let mut seen: HashSet<String> = HashSet::new();
    let descendants: Vec<ElementRef<'a>> = item.descendants().skip(1).filter_map(ElementRef::wrap).collect();
    let mut add = |el: ElementRef<'a>, at: Option<&str>| {
        if fields.len() >= 14 {
            return;
        }
        let Some((css, named)) = selector_in(item, el) else { return };
        let sel = match at {
            Some(a) => format!("{css}@{a}"),
            None => css.clone(),
        };
        let value = match at {
            Some(a) => attr(&el, a).map(|s| s.to_string()),
            None => Some(text_of(&el)),
        };
        let Some(value) = value else { return };
        if seen.contains(&sel) || value.is_empty() || value.chars().count() > 160 {
            return;
        }
        // a field most items lack is a badge or an ad, not data
        let have = items.iter().filter(|it| matches!(query_all(**it, &css, false), Ok(v) if !v.is_empty())).count();
        if (have as f64) < items.len() as f64 / 2.0 {
            return;
        }
        seen.insert(sel.clone());
        let name = name_for(&named, &mut used, at);
        fields.insert(name.clone(), sel);
        sample_out.insert(name, clip(&value, 80));
    };
    for el in descendants {
        let t = tag(&el);
        if skipped(&t) || t == "button" {
            continue;
        }
        if t == "a" && attr(&el, "href").is_some() {
            add(el, Some("href"));
        }
        if t == "img" && attr(&el, "src").is_some() {
            add(el, Some("src"));
        }
        // icons carry values only in their label: "Rating 4 out of 5"
        if let Some(label) = attr(&el, "aria-label") {
            if label.chars().count() <= 80 && label.chars().any(|c| c.is_ascii_digit()) && label != text_of(&el) {
                add(el, Some("aria-label"));
            }
        }
        if has_own_text(&el) {
            add(el, None);
        }
    }
    (fields, sample_out)
}

/// The repeated item (3+ siblings alike) that holds an example value, as an --html recipe.
pub fn outline_html_list(doc: &Doc, values: &[String]) -> Option<HtmlList> {
    let all = doc.all();
    let hits: Vec<ElementRef> = all
        .iter()
        .copied()
        .filter(|el| {
            if skipped(&tag(el)) {
                return false;
            }
            let t = text_of(el).to_lowercase();
            values.iter().any(|v| t.contains(v))
                && !element_children(el).iter().any(|c| {
                    let ct = text_of(c).to_lowercase();
                    values.iter().any(|v| ct.contains(v))
                })
        })
        .collect();
    for hit in hits.into_iter().take(20) {
        let mut a = Some(hit);
        let mut depth = 0;
        while let Some(el) = a {
            if depth >= 14 {
                break;
            }
            let Some(p) = parent(&el) else { break };
            if tag(&p).is_empty() {
                break;
            }
            let s = sig(&el);
            let siblings: Vec<ElementRef> = element_children(&p).into_iter().filter(|c| sig(c) == s).collect();
            if siblings.len() < 3 {
                a = Some(p);
                depth += 1;
                continue;
            }
            let gp = parent(&p);
            let mut options = vec![s.clone(), format!("{} > {s}", sig(&p))];
            if let Some(g) = gp {
                if !tag(&g).is_empty() {
                    options.push(format!("{} > {} > {s}", sig(&g), sig(&p)));
                }
            }
            let items = options.into_iter().find(|o| matches!(doc.select(o), Ok(v) if v.len() == siblings.len()));
            let Some(items) = items else {
                a = Some(p);
                depth += 1;
                continue;
            };
            let (fields, sample) = item_fields(el, &siblings);
            return Some(HtmlList { items, count: siblings.len(), fields, sample });
        }
    }
    None
}

/// Labelled short texts on a page with no list (a detail page): css -> sample. A labelled element
/// holding 3+ alike children (a book's genres) also gets an "all:" field listing every child.
fn outline_labels(doc: &Doc) -> IndexMap<String, String> {
    let mut out: IndexMap<String, String> = IndexMap::new();
    let Ok(tagged) = doc.select("[data-testid]") else { return out };
    for el in tagged {
        if out.len() >= 30 {
            break;
        }
        let css = sig(&el);
        if stable_testid(attr(&el, "data-testid")).is_none() || out.contains_key(&css) || !first_is(doc.root(), &css, &el) {
            continue;
        }
        let t = text_of(&el);
        if !t.is_empty() && t.chars().count() <= 160 {
            out.insert(css.clone(), json(&Value::String(clip(&t, 80))));
        }
        let mut counts: IndexMap<String, Vec<String>> = IndexMap::new();
        for d in el.descendants().skip(1).filter_map(ElementRef::wrap) {
            let s = sig(&d);
            let txt = text_of(&d);
            if s != tag(&d) && !txt.is_empty() && txt.chars().count() <= 60 {
                counts.entry(s).or_default().push(txt);
            }
        }
        let mut best: Vec<(&String, &Vec<String>)> = counts.iter().filter(|(_, v)| v.len() >= 3).collect();
        best.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
        if let Some((child, texts)) = best.first() {
            let shown: Vec<Value> = texts.iter().take(4).map(|x| Value::String(clip(x, 30))).collect();
            out.insert(format!("all:{css} {child}"), json(&Value::Array(shown)));
        }
    }
    out
}

/// Outline a response body. `examples` are the example values (matched case-insensitively).
pub fn outline(content_type: &str, body: &str, examples: &[String]) -> Option<Outline> {
    let values: Vec<String> = examples.iter().map(|v| v.to_lowercase()).filter(|v| v.chars().count() >= 3).collect();
    if !content_type.to_lowercase().contains("html") {
        let data = parse_body(body, None).ok()?;
        if data.is_object() || data.is_array() {
            return Some(Outline { json: Some(outline_json(&data, &values)), ..Default::default() });
        }
        return None;
    }
    let mut embedded: Vec<EmbeddedOutline> = Vec::new();
    for regex in embedded_blocks(body) {
        let Ok(Some(data)) = extract_embedded(body, &regex) else { continue };
        if !(data.is_object() || data.is_array()) {
            continue;
        }
        let o = outline_json(&data, &values);
        // JSON-LD is small and schema.org-stable, so it is always worth showing; other blocks only when they carry an example
        if o.at.is_some() || regex.starts_with("application/ld") {
            embedded.push(EmbeddedOutline { regex, outline: o });
        }
    }
    let doc = Doc::parse(body);
    let list = if values.is_empty() { None } else { outline_html_list(&doc, &values) };
    let labels = if list.is_some() { None } else { Some(outline_labels(&doc)) };
    Some(Outline {
        json: None,
        embedded: if embedded.is_empty() { None } else { Some(embedded.into_iter().take(4).collect()) },
        list,
        labels: labels.filter(|l| !l.is_empty()),
    })
}
