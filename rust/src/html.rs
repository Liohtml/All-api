//! HTML querying on top of `scraper`, with the relative selectors (`+ tr .score`, `> a`) that a
//! recipe's fields may use against an item, and whitespace-squashed text like a browser's `textContent`.
use anyhow::{Result, anyhow};
use scraper::{ElementRef, Html, Selector};
use std::collections::HashSet;

pub struct Doc {
    pub html: Html,
}

impl Doc {
    pub fn parse(body: &str) -> Doc {
        Doc { html: Html::parse_document(body) }
    }
    pub fn root(&self) -> ElementRef<'_> {
        self.html.root_element()
    }
    /// Every element of the document, in document order (`querySelectorAll("*")` on the root).
    pub fn all(&self) -> Vec<ElementRef<'_>> {
        self.root().descendants().filter_map(ElementRef::wrap).collect()
    }
    pub fn select(&self, css: &str) -> Result<Vec<ElementRef<'_>>> {
        query_all(self.root(), css, true)
    }
    pub fn select_first(&self, css: &str) -> Result<Option<ElementRef<'_>>> {
        Ok(self.select(css)?.into_iter().next())
    }
}

pub fn tag(el: &ElementRef) -> String {
    el.value().name().to_lowercase()
}

pub fn attr<'a>(el: &ElementRef<'a>, name: &str) -> Option<&'a str> {
    el.value().attr(name)
}

/// The element's text with runs of whitespace as one space, trimmed.
pub fn text_of(el: &ElementRef) -> String {
    let raw: String = el.text().collect();
    crate::util::squash_ws(&raw)
}

pub fn element_children<'a>(el: &ElementRef<'a>) -> Vec<ElementRef<'a>> {
    el.children().filter_map(ElementRef::wrap).collect()
}

pub fn parent<'a>(el: &ElementRef<'a>) -> Option<ElementRef<'a>> {
    el.parent().and_then(ElementRef::wrap)
}

fn next_element_sibling<'a>(el: &ElementRef<'a>) -> Option<ElementRef<'a>> {
    el.next_siblings().find_map(ElementRef::wrap)
}

fn parse_selector(css: &str) -> Result<Selector> {
    Selector::parse(css).map_err(|e| anyhow!("invalid selector \"{css}\": {e}"))
}

/// Split a selector at its first top-level combinator: the first compound, and the rest with the
/// combinator that joins it (' ', '>', '+' or '~'). None for a selector list.
fn split_first(sel: &str) -> Option<(String, Option<(char, String)>)> {
    let s = sel.trim();
    let chars: Vec<char> = s.chars().collect();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        } else if c == '[' || c == '(' {
            depth += 1;
        } else if c == ']' || c == ')' {
            depth -= 1;
        } else if depth == 0 && c == ',' {
            return None;
        } else if depth == 0 && (c.is_whitespace() || c == '>' || c == '+' || c == '~') {
            let first: String = chars[..i].iter().collect();
            let mut comb = ' ';
            let mut j = i;
            while j < chars.len() && (chars[j].is_whitespace() || chars[j] == '>' || chars[j] == '+' || chars[j] == '~') {
                if !chars[j].is_whitespace() {
                    comb = chars[j];
                }
                j += 1;
            }
            let rest: String = chars[j..].iter().collect();
            return Some((first.trim().to_string(), if rest.is_empty() { None } else { Some((comb, rest)) }));
        }
        i += 1;
    }
    Some((s.to_string(), None))
}

fn related<'a>(scope: ElementRef<'a>, comb: char) -> Vec<ElementRef<'a>> {
    match comb {
        '>' => element_children(&scope),
        '+' => next_element_sibling(&scope).into_iter().collect(),
        '~' => scope.next_siblings().filter_map(ElementRef::wrap).collect(),
        _ => scope.descendants().skip(1).filter_map(ElementRef::wrap).collect(),
    }
}

fn dedupe<'a>(els: Vec<ElementRef<'a>>) -> Vec<ElementRef<'a>> {
    let mut seen = HashSet::new();
    els.into_iter().filter(|e| seen.insert(e.id())).collect()
}

fn query_relative<'a>(scope: ElementRef<'a>, comb: char, rest: &str) -> Result<Vec<ElementRef<'a>>> {
    let (first, tail) = split_first(rest).ok_or_else(|| anyhow!("a selector list cannot follow a combinator: {rest}"))?;
    let sel = parse_selector(&first)?;
    let candidates: Vec<ElementRef<'a>> = related(scope, comb).into_iter().filter(|e| sel.matches(e)).collect();
    match tail {
        None => Ok(candidates),
        Some((c, rest)) => {
            let mut out = Vec::new();
            for cand in candidates {
                out.extend(query_relative(cand, c, &rest)?);
            }
            Ok(dedupe(out))
        }
    }
}

/// `scope.querySelectorAll(css)`: descendants matching, in document order. A selector that starts
/// with a combinator is relative to the scope. `root`: the scope is the document's root, so a
/// plain selector may match any element.
pub fn query_all<'a>(scope: ElementRef<'a>, css: &str, root: bool) -> Result<Vec<ElementRef<'a>>> {
    let s = css.trim();
    if s.is_empty() {
        return Ok(vec![]);
    }
    if let Some(c) = s.chars().next() {
        if c == '>' || c == '+' || c == '~' {
            return query_relative(scope, c, s[1..].trim());
        }
    }
    let sel = parse_selector(s)?;
    if root {
        return Ok(scope.select(&sel).collect());
    }
    Ok(scope.select(&sel).collect())
}

pub fn query_first<'a>(scope: ElementRef<'a>, css: &str) -> Result<Option<ElementRef<'a>>> {
    Ok(query_all(scope, css, false)?.into_iter().next())
}

/// `scope.querySelector(css) === el`.
pub fn first_is(scope: ElementRef<'_>, css: &str, el: &ElementRef<'_>) -> bool {
    matches!(query_first(scope, css), Ok(Some(f)) if f.id() == el.id())
}
