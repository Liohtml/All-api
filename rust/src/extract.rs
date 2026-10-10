//! Turn a response body into the compact value an agent sees: parse, extract, pick, cap.
use crate::codec::{json_value_end, parse_json};
use crate::html::{Doc, attr, query_all, text_of};
use crate::spec::{Format, HtmlRecipe, ResponseSpec};
use crate::util::{is_json_text, js_len, js_regex, json, json_unquote, re};
use anyhow::{Result, anyhow, bail};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::sync::LazyLock;

pub const XSSI: &str = ")]}'";
// Anti-JSON-hijacking prefixes: Google's, Meta's /ajax/* and older Google/Facebook APIs.
const PREFIXES: [&str; 3] = [XSSI, "for (;;);", "while(1);"];

/// The XSSI prefix a body starts with, if any.
pub fn xssi_of(body: &str) -> Option<&'static str> {
    let t = body.trim_start();
    PREFIXES.iter().copied().find(|p| t.starts_with(p))
}

/// Strip the XSSI prefix and parse JSON losslessly. Google `rt=c` length-prefixed chunks, and
/// Meta-style bodies that repeat the prefix before each JSON value, become an array.
pub fn parse_body(body: &str, xssi_prefix: Option<&str>) -> Result<Value> {
    let mut text = body.trim_start();
    let prefix = xssi_prefix.or_else(|| xssi_of(text)).unwrap_or("");
    if !prefix.is_empty() && text.starts_with(prefix) {
        text = &text[prefix.len()..];
    }
    let text = text.trim();
    static CHUNKED: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^\d+[ \t]*\r?\n"));
    if CHUNKED.is_match(text) {
        return parse_chunks(text);
    }
    let parts: Vec<&str> = if prefix.is_empty() { vec![text] } else { text.split(prefix).collect() };
    if parts.len() > 1 {
        parts.iter().map(|p| parse_json(p.trim())).collect::<Result<Vec<_>>>().map(Value::Array)
    } else {
        parse_json(text)
    }
}

fn parse_chunks(text: &str) -> Result<Value> {
    static HEAD: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^\s*\d+[ \t]*\r?\n\s*"));
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let Some(m) = HEAD.find(&text[i..]) else { break };
        i += m.end();
        // Chunk lengths count bytes or UTF-16 units depending on the server; scanning the JSON is exact.
        let end = json_value_end(text, i)?;
        out.push(parse_json(&text[i..end])?);
        i = end;
    }
    Ok(Value::Array(out))
}

/// A string holding JSON (Google's batchexecute nests payloads this way), parsed; else None.
pub fn inner_json(s: &str) -> Option<Value> {
    if !is_json_text(s) {
        return None;
    }
    parse_json(s).ok()
}

static PATH_STEP: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"\[(\d+)\]|\[(\*)\]|\["((?:[^"\\]|\\.)*)"\]|[^.\[\]]+"#));

enum PathStep {
    Key(String),
    Star,
}

fn path_steps(path: &str) -> Vec<PathStep> {
    PATH_STEP
        .captures_iter(path)
        .map(|m| {
            if m.get(2).is_some() {
                PathStep::Star
            } else if let Some(i) = m.get(1) {
                PathStep::Key(i.as_str().to_string())
            } else if let Some(q) = m.get(3) {
                PathStep::Key(json_unquote(q.as_str()).unwrap_or_else(|| q.as_str().to_string()))
            } else {
                PathStep::Key(m[0].to_string())
            }
        })
        .collect()
}

fn walk_path(cur: &Value, steps: &[PathStep], i: usize) -> Option<Value> {
    let mut cur = cur.clone();
    let mut i = i;
    while i < steps.len() {
        if let Value::String(s) = &cur {
            cur = inner_json(s)?;
        }
        match &steps[i] {
            PathStep::Star => {
                let Value::Array(items) = &cur else { return None };
                let found: Vec<Value> = items.iter().filter_map(|x| walk_path(x, steps, i + 1)).collect();
                // items present but none has the rest of the path: the path moved, not "no results"
                if !items.is_empty() && found.is_empty() {
                    return None;
                }
                let mut flat = Vec::new();
                for f in found {
                    match f {
                        Value::Array(a) => flat.extend(a),
                        other => flat.push(other),
                    }
                }
                return Some(Value::Array(flat));
            }
            PathStep::Key(key) => {
                cur = match &cur {
                    Value::Object(o) => o.get(key)?.clone(),
                    Value::Array(a) => a.get(key.parse::<usize>().ok()?)?.clone(),
                    _ => return None,
                };
            }
        }
        i += 1;
    }
    Some(cur)
}

/// Resolve "a.b[0].c", "[1][0][2]", `a["x.y"]`, stepping into JSON-encoded strings. None if any step is missing.
/// `[*]` maps the rest of the path over an array and flattens one level, skipping items where it is
/// missing (`sections[*].items`: every section's items, whichever section holds them).
pub fn get_path(obj: &Value, path: Option<&str>) -> Option<Value> {
    match path {
        None | Some("") => Some(obj.clone()),
        Some(p) => walk_path(obj, &path_steps(p), 0),
    }
}

/// --pick fields: commas separate them, except inside [], {} or () of a regex, or escaped as \,
pub fn split_pick(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && chars.get(i + 1) == Some(&',') {
            cur.push(',');
            i += 2;
            continue;
        }
        if c == '\\' {
            cur.push(c);
            if let Some(n) = chars.get(i + 1) {
                cur.push(*n);
            }
            i += 2;
            continue;
        }
        if "[{(".contains(c) {
            depth += 1;
        }
        if "]})".contains(c) {
            depth = (depth - 1).max(0);
        }
        if c == ',' && depth == 0 {
            out.push(cur.trim().to_string());
            cur.clear();
            i += 1;
            continue;
        }
        cur.push(c);
        i += 1;
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

pub struct PickEntry {
    pub name: String,
    pub path: String,
    pub re: Option<fancy_regex::Regex>,
}

pub fn pick_entry(p: &str) -> Result<PickEntry> {
    static NAMED: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^([\w$-]+)=(.+)$"));
    let (name, rest) = match NAMED.captures(p) {
        Some(m) => (Some(m[1].to_string()), m[2].to_string()),
        None => (None, p.to_string()),
    };
    let (path, re_text) = match rest.find('~') {
        Some(cut) => (rest[..cut].to_string(), Some(rest[cut + 1..].to_string())),
        None => (rest.clone(), None),
    };
    let re = match re_text {
        Some(t) => Some(js_regex(&t).map_err(|e| anyhow!("Invalid regular expression: /{t}/: {e}"))?),
        None => None,
    };
    Ok(PickEntry { name: name.unwrap_or_else(|| path.clone()), path, re })
}

/// The keys an item of the result can carry, when the recipe names them: the pick's, else the fields
/// of an HTML recipe whose items come back as they are (no extract path reshaping them).
pub fn returned_fields(r: &ResponseSpec) -> Option<Vec<String>> {
    if let Some(pick) = &r.pick {
        if !pick.is_empty() {
            return Some(pick.iter().map(|p| pick_entry(p).map(|e| e.name).unwrap_or_else(|_| p.clone())).collect());
        }
    }
    if r.format == Format::Html && r.extract.is_none() {
        if let Some(h) = &r.html {
            return Some(h.fields.keys().cloned().collect());
        }
    }
    None
}

fn pick_one(item: &Value, named: &[PickEntry]) -> Value {
    if !item.is_object() && !item.is_array() {
        return item.clone();
    }
    let mut out = Map::new();
    for e in named {
        let mut v = get_path(item, Some(&e.path));
        if let Some(r) = &e.re {
            v = match &v {
                Some(Value::String(s)) => r.captures(s).ok().flatten().map(|c| {
                    Value::String(c.get(1).or_else(|| c.get(0)).map(|m| m.as_str().to_string()).unwrap_or_default())
                }),
                _ => None,
            };
        }
        if let Some(v) = v {
            out.insert(e.name.clone(), v);
        }
    }
    Value::Object(out)
}

/// Keep only the given paths, per item for arrays. `name=path` renames the output key, and
/// `name=path~regex` keeps the part of a string that the regex's group 1 (or whole match) finds;
/// a non-string or no match drops the field.
pub fn pick(value: &Value, paths: &[String]) -> Result<Value> {
    let named: Vec<PickEntry> = paths.iter().map(|p| pick_entry(p)).collect::<Result<_>>()?;
    let Value::Array(items) = value else { return Ok(pick_one(value, &named)) };
    // an item with none of the fields (a shelf, an ad, a logo entity) is not a result: drop it, not {}
    Ok(Value::Array(
        items
            .iter()
            .map(|x| pick_one(x, &named))
            .filter(|x| !matches!(x, Value::Object(o) if o.is_empty()))
            .collect(),
    ))
}

/// `fields` values are "<css>" (text) or "<css>@attr"; an empty css means the item itself.
/// An "all:" prefix returns every match as a list (a book's genres, a post's tags), [] when none.
pub fn extract_html(body: &str, recipe: &HtmlRecipe) -> Result<Vec<IndexMap<String, Value>>> {
    static ATTR: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^(.*?)@([\w:-]+)$"));
    let doc = Doc::parse(body);
    let items = doc.select(&recipe.items)?;
    let mut out = Vec::new();
    for el in items {
        let mut row: IndexMap<String, Value> = IndexMap::new();
        for (name, field) in &recipe.fields {
            let all = field.starts_with("all:");
            let sel = if all { &field[4..] } else { field.as_str() };
            let (css, at) = match ATTR.captures(sel) {
                Some(m) => (m[1].trim().to_string(), Some(m[2].to_string())),
                None => (sel.trim().to_string(), None),
            };
            let value = |t: &scraper::ElementRef| -> Option<String> {
                match &at {
                    Some(a) => attr(t, a).map(|s| s.to_string()),
                    None => Some(text_of(t)),
                }
            };
            if all {
                let targets = if css.is_empty() { vec![el] } else { query_all(el, &css, false)? };
                let vs: Vec<Value> =
                    targets.iter().filter_map(value).filter(|v| !v.is_empty()).map(Value::String).collect();
                row.insert(name.clone(), Value::Array(vs));
            } else {
                let target = if css.is_empty() { Some(el) } else { query_all(el, &css, false)?.into_iter().next() };
                if let Some(v) = target.and_then(|t| value(&t)) {
                    row.insert(name.clone(), Value::String(v));
                }
            }
        }
        out.push(row);
    }
    Ok(out)
}

/// JSON embedded in a document; the regex's group 1 marks where the JSON value starts.
pub fn extract_embedded(body: &str, regex: &str) -> Result<Option<Value>> {
    let r = js_regex(regex).map_err(|e| anyhow!("Invalid regular expression: /{regex}/: {e}"))?;
    let Some(m) = r.captures(body)? else { return Ok(None) };
    let Some(g) = m.get(1) else { return Ok(None) };
    let start = g.start();
    if let Ok(end) = json_value_end(body, start) {
        if let Ok(v) = parse_json(&body[start..end]) {
            return Ok(Some(v));
        }
    }
    Ok(parse_json(g.as_str()).ok())
}

fn rows_value(rows: Vec<IndexMap<String, Value>>) -> Value {
    Value::Array(rows.into_iter().map(|r| Value::Object(r.into_iter().collect())).collect())
}

/// Body -> extracted value per the op's response spec. None when the extract path is missing.
pub fn extract(res: &ResponseSpec, body: &str) -> Result<Option<Value>> {
    let mut data: Option<Value> = match res.format {
        Format::Html => Some(match &res.html {
            Some(h) => rows_value(extract_html(body, h)?),
            None => Value::String(body.to_string()),
        }),
        Format::Embedded => match &res.embedded {
            Some(e) => extract_embedded(body, &e.regex)?,
            None => None,
        },
        Format::Json => Some(parse_body(body, res.xssi_prefix.as_deref())?),
    };
    if let (Some(path), Some(d)) = (&res.extract, &data) {
        data = get_path(d, Some(path));
    }
    if let (Some(p), Some(d)) = (&res.pick, &data) {
        if !p.is_empty() {
            data = Some(pick(d, p)?);
        }
    }
    Ok(data)
}

pub fn size(v: &Value) -> usize {
    js_len(&json(v))
}

// A member at most this big is kept whole or dropped, never shortened: a number or a short string can't be.
const ATOM: usize = 200;

/// v in at most `budget` JSON chars: strings cut, arrays cut at an item boundary (never below one
/// item while one fits), objects keep their members in order with the biggest ones shortened to a
/// common cap, then drop trailing members. None when not even an empty container fits.
fn cut(v: &Value, budget: usize, total: usize) -> Option<Value> {
    if total <= budget {
        return Some(v.clone());
    }
    if let Value::String(s) = v {
        let chars: Vec<char> = s.chars().collect();
        let mut n = budget.saturating_sub(2).min(chars.len());
        let mut cur: String = chars[..n].iter().collect();
        while !cur.is_empty() && size(&Value::String(cur.clone())) > budget {
            let over = size(&Value::String(cur.clone())) - budget;
            n = n.saturating_sub(over.max(1));
            cur = chars[..n].iter().collect();
        }
        return if size(&Value::String(cur.clone())) <= budget { Some(Value::String(cur)) } else { None };
    }
    if budget < 2 {
        return None;
    }
    if let Value::Array(items) = v {
        let mut out: Vec<Value> = Vec::new();
        let mut used = 2;
        for item in items {
            let n = size(item);
            if used + n + usize::from(!out.is_empty()) > budget {
                if out.is_empty() {
                    if let Some(one) = cut(item, budget - 2, n) {
                        out.push(one);
                    }
                }
                break;
            }
            out.push(item.clone());
            used += n + usize::from(out.len() > 1);
        }
        return Some(Value::Array(out));
    }
    if let Value::Object(o) = v {
        let entries: Vec<(&String, &Value)> = o.iter().collect();
        // one pass for every member's size: "key":value
        let cost: Vec<(usize, usize)> = entries.iter().map(|(k, x)| (size(&Value::String((*k).clone())) + 1, size(x))).collect();
        // Water-fill: the largest cap (>= ATOM) at which every member fits, members above it shortened.
        let room = budget as i64 - 2 - (entries.len() as i64 - 1).max(0);
        let mut sorted: Vec<i64> = cost.iter().map(|c| (c.0 + c.1) as i64).collect();
        sorted.sort();
        let mut cap = i64::MAX;
        let mut below = 0i64;
        for i in 0..sorted.len() {
            let left = (sorted.len() - i) as i64;
            if below + sorted[i] * left > room {
                cap = (ATOM as i64).min(budget as i64 - 2).max((room - below).div_euclid(left));
                break;
            }
            below += sorted[i];
        }
        let mut out = Map::new();
        let mut used: i64 = 2;
        for (i, (k, x)) in entries.iter().enumerate() {
            let c = cost[i];
            let value = if (c.0 + c.1) as i64 <= cap {
                Some((*x).clone())
            } else {
                cut(x, (cap - c.0 as i64).max(0) as usize, c.1)
            };
            let Some(value) = value else { continue };
            let vsize = if &value == *x { c.1 } else { size(&value) };
            let n = (c.0 + vsize) as i64 + if used > 2 { 1 } else { 0 };
            // once the members stop fitting the rest are dropped; the note counts them
            if used + n > budget as i64 {
                break;
            }
            out.insert((*k).clone(), value);
            used += n;
        }
        return Some(Value::Object(out));
    }
    None
}

pub struct Capped {
    pub data: Value,
    pub truncated: Option<String>,
}

/// Hard cap on what goes back to the agent: the result is never over max_chars. Arrays are cut at an
/// item boundary, and an item too big on its own is cut rather than dropped, so the output never
/// reads as "no results". Strings are cut as strings; objects stay objects (their biggest members
/// shortened, then trailing members dropped), never cut JSON text. The note says what was cut.
pub fn cap_output(value: &Value, max_chars: usize) -> Capped {
    let total = size(value);
    if total <= max_chars {
        return Capped { data: value.clone(), truncated: None };
    }
    let data = cut(value, max_chars, total).unwrap_or(Value::Null);
    let hint = "narrow with pick or extract";
    if let (Value::Array(all), Value::Array(kept)) = (value, &data) {
        let n = kept.len();
        let whole = n > 0 && kept[n - 1] == all[n - 1];
        let cut_note = if n > 0 && !whole { " (the last one cut to fit)" } else { "" };
        return Capped {
            data: data.clone(),
            truncated: Some(format!("showing {n} of {} items{cut_note} (cap {max_chars} chars); {hint}", all.len())),
        };
    }
    if let (Value::Object(all), Value::Object(kept)) = (value, &data) {
        let shortened = kept.iter().filter(|(k, v)| all.get(*k) != Some(v)).count();
        let short_note = if shortened > 0 { format!(", {shortened} of them shortened") } else { String::new() };
        return Capped {
            data: data.clone(),
            truncated: Some(format!(
                "cut to {} of {total} chars (cap {max_chars}): showing {} of {} keys{short_note}; {hint}",
                size(&data),
                kept.len(),
                all.len()
            )),
        };
    }
    Capped { truncated: Some(format!("cut to {} of {total} chars (cap {max_chars}); {hint}", size(&data))), data }
}

// numeric ids, short upper-case codes (SFO, US), and ids with digits (item-85809106, u_123)
static ID_KEY: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^(\d+|[A-Z0-9]{2,5}|[\w:.-]*\d[\w:.-]*)$"));

pub fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
    }
}

/// Key paths -> types (first array item only; an id-keyed map as "*"), for drift detection.
pub fn infer_shape(value: &Value, max_paths: usize) -> IndexMap<String, String> {
    let mut out = IndexMap::new();
    fn visit(v: &Value, path: &str, depth: usize, out: &mut IndexMap<String, String>, max: usize) {
        if out.len() >= max {
            return;
        }
        if !path.is_empty() {
            out.insert(path.to_string(), type_name(v).to_string());
        }
        if depth >= 6 {
            return;
        }
        match v {
            Value::Array(a) => {
                if let Some(first) = a.first() {
                    visit(first, &format!("{path}[]"), depth + 1, out, max);
                }
            }
            Value::Object(o) => {
                // An id-keyed map (airports: {SFO: {...}}) has different keys for other args: its keys are "*".
                if !o.is_empty() && o.iter().all(|(k, c)| ID_KEY.is_match(k) && (c.is_object() || c.is_array())) {
                    let p = if path.is_empty() { "*".to_string() } else { format!("{path}.*") };
                    visit(o.values().next().unwrap(), &p, depth + 1, out, max);
                } else {
                    for (k, c) in o {
                        let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                        visit(c, &p, depth + 1, out, max);
                    }
                }
            }
            _ => {}
        }
    }
    visit(value, "", 0, &mut out, max_paths);
    out
}

/// A shape's paths in the JSON walk's order, for callers that need plain `bail!` on a bad recipe.
pub fn require_json(body: &str) -> Result<Value> {
    if body.trim().is_empty() {
        bail!("empty body");
    }
    parse_body(body, None)
}
