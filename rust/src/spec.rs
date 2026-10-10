//! Site spec schema: one JSON file per site, validated on load. Unknown fields are stripped.
use crate::types::{Headers, TriggerStep};
use crate::util::valid_regex;
use anyhow::{Result, anyhow};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A step through decoded request layers; see codec.rs.
pub fn valid_step(step: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^(path:\d+|(query|form)(\[\d+\])?:.+|header:.+|json:(/.*)?|b64|body)$").unwrap())
        .is_match(step)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Request {
    pub method: String,
    pub url: String,
    // Lower-cased when parsed, as the codec writes them: a hand-written "X-CSRF-Token" would otherwise be sent twice.
    #[serde(default)]
    pub headers: Headers,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Transform {
    #[serde(rename = "strip-quotes")]
    StripQuotes,
    #[serde(rename = "url-decode")]
    UrlDecode,
}

/// How a value is written inside a templated leaf: "url" percent-encodes it (the leaf is a URL, so
/// the arg sits one encoding layer deeper: a referer, a next= path), "json" escapes it for a JSON
/// string literal (an inline GraphQL `search(q: "{q}")`).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Escape {
    Url,
    Json,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Slot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub at: Vec<String>,
    /// the leaf's text with `{param}` where the value goes (value is a substring of the leaf)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<Transform>,
    /// with a template: how the value is escaped inside the leaf
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escape: Option<Escape>,
}

impl Slot {
    pub fn param(name: &str, at: Vec<String>) -> Slot {
        Slot { param: Some(name.to_string()), at, ..Default::default() }
    }
    pub fn reference(reference: &str, at: Vec<String>) -> Slot {
        Slot { reference: Some(reference.to_string()), at, ..Default::default() }
    }
    pub fn is_param(&self) -> bool {
        self.param.is_some()
    }
    pub fn is_ref(&self) -> bool {
        self.reference.is_some()
    }
    pub fn ref_str(&self) -> &str {
        self.reference.as_deref().unwrap_or("")
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Charset {
    Digits,
    Hex,
    Base64url,
    Base64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Shape {
    pub charset: Charset,
    pub length: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Volatile {
    pub at: Vec<String>,
    pub shape: Shape,
    /// stable string found near the token in the site's JS (operationName or neighboring path segment)
    pub anchor: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Trigger {
    /// URL template, `{param}` filled from args
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<TriggerStep>>,
    /// neutral page to load first, then soft-navigate to `url`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_from: Option<String>,
}

/// Stable request identity only. Never a queryId/doc_id/hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// pathname with `*` for any one segment
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
}

impl Match {
    pub fn is_empty(&self) -> bool {
        self.method.is_none() && self.host.is_none() && self.path.is_none() && self.operation_name.is_none()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct HtmlRecipe {
    pub items: String,
    #[serde(default)]
    pub fields: IndexMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Embedded {
    pub regex: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    #[default]
    Json,
    Html,
    Embedded,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResponseSpec {
    #[serde(default)]
    pub format: Format,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xssi_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extract: Option<String>,
    /// paths kept per item; `name=path~regex` keeps what the regex's group 1 finds in a string
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pick: Option<Vec<String>>,
    /// key path -> type, for drift detection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<IndexMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<HtmlRecipe>,
    /// capture group 1 is where the JSON starts
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded: Option<Embedded>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    #[default]
    String,
    Number,
    Boolean,
    Object,
    Array,
}

impl ParamType {
    pub fn name(self) -> &'static str {
        match self {
            ParamType::String => "string",
            ParamType::Number => "number",
            ParamType::Boolean => "boolean",
            ParamType::Object => "object",
            ParamType::Array => "array",
        }
    }
}

fn t() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Param {
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: ParamType,
    #[serde(default = "t")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    /// a regex the whole value must match; a call with an arg that doesn't is `input`, and nothing is sent
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// what a valid value looks like, said to the agent when an arg fails `pattern` ("YYYY-MM-DD")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl Param {
    pub fn new(name: &str) -> Param {
        Param {
            name: name.to_string(),
            kind: ParamType::String,
            required: true,
            description: None,
            example: None,
            default: None,
            pattern: None,
            hint: None,
        }
    }
}

fn one() -> u8 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub request: Request,
    #[serde(default)]
    pub slots: Vec<Slot>,
    #[serde(default)]
    pub volatile: Vec<Volatile>,
    pub trigger: Trigger,
    #[serde(default, rename = "match")]
    pub matcher: Match,
    #[serde(default)]
    pub response: ResponseSpec,
    #[serde(default)]
    pub params: Vec<Param>,
    pub read_only: bool,
    /// header or field names whose captured value is a public constant, kept literal
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<Vec<String>>,
    #[serde(default = "one")]
    pub min_tier: u8,
    #[serde(default)]
    pub learned_logged_in: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Site {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// cookie names whose presence means logged in (overrides the heuristic)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_cookies: Option<Vec<String>>,
    #[serde(default)]
    pub operations: Vec<Operation>,
}

pub fn site_name_ok(name: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^(?i)[a-z0-9][a-z0-9._-]*$").unwrap()).is_match(name)
}

/// The issues a value has against the schema, each as "✖ <what>\n  → at <path>" like zod reports them.
fn issue(path: &str, what: &str) -> String {
    format!("✖ {what}\n  → at {path}")
}

fn ref_ok(r: &str) -> bool {
    (r.starts_with("cookie:") && r.len() > 7) || (r.starts_with("session:") && r.len() > 8)
}

/// Checks the typed value for what serde cannot: the step grammar, the ref form, one of param/ref,
/// regex validity, the tier range and the site name. Returns every issue found.
pub fn validate_site(site: &Site) -> Vec<String> {
    let mut issues = Vec::new();
    if !site_name_ok(&site.name) {
        issues.push(issue("name", "Invalid string: must match pattern /^[a-z0-9][a-z0-9._-]*$/i"));
    }
    for (i, op) in site.operations.iter().enumerate() {
        let p = format!("operations[{i}]");
        if op.name.is_empty() {
            issues.push(issue(&format!("{p}.name"), "Too small: expected string to have >=1 characters"));
        }
        if !(1..=3).contains(&op.min_tier) {
            issues.push(issue(&format!("{p}.minTier"), "Invalid input: expected 1 | 2 | 3"));
        }
        for (j, s) in op.slots.iter().enumerate() {
            let sp = format!("{p}.slots[{j}]");
            if s.at.is_empty() {
                issues.push(issue(&format!("{sp}.at"), "Too small: expected array to have >=1 items"));
            }
            for (k, step) in s.at.iter().enumerate() {
                if !valid_step(step) {
                    issues.push(issue(
                        &format!("{sp}.at[{k}]"),
                        "step must be path:<i>, query:<k>, header:<n>, form:<k>, json:<pointer>, or body",
                    ));
                }
            }
            if let Some(r) = &s.reference {
                if !ref_ok(r) {
                    issues.push(issue(&format!("{sp}.ref"), "ref must be cookie:<name> or session:<name>"));
                }
            }
            if s.param.is_some() == s.reference.is_some() {
                issues.push(issue(&sp, "a slot needs exactly one of param or ref"));
            }
        }
        for (j, v) in op.volatile.iter().enumerate() {
            let vp = format!("{p}.volatile[{j}]");
            if v.at.is_empty() {
                issues.push(issue(&format!("{vp}.at"), "Too small: expected array to have >=1 items"));
            }
            for (k, step) in v.at.iter().enumerate() {
                if !valid_step(step) {
                    issues.push(issue(
                        &format!("{vp}.at[{k}]"),
                        "step must be path:<i>, query:<k>, header:<n>, form:<k>, json:<pointer>, or body",
                    ));
                }
            }
            if v.shape.length == 0 {
                issues.push(issue(&format!("{vp}.shape.length"), "Too small: expected number to be >0"));
            }
        }
        if let Some(pick) = &op.response.pick {
            for (j, item) in pick.iter().enumerate() {
                if let Some(cut) = item.find('~') {
                    if !valid_regex(&item[cut + 1..]) {
                        issues.push(issue(&format!("{p}.response.pick[{j}]"), "the regex after ~ in pick must be valid"));
                    }
                }
            }
        }
        for (j, param) in op.params.iter().enumerate() {
            let pp = format!("{p}.params[{j}]");
            if param.name.is_empty() {
                issues.push(issue(&format!("{pp}.name"), "Too small: expected string to have >=1 characters"));
            }
            if let Some(pat) = &param.pattern {
                if !valid_regex(pat) {
                    issues.push(issue(&format!("{pp}.pattern"), "pattern must be a valid regular expression"));
                }
            }
        }
    }
    issues
}

/// Lower-case every header name, as the codec writes them.
pub fn normalize_site(site: &mut Site) {
    for op in &mut site.operations {
        lower_headers(&mut op.request);
    }
}

pub fn lower_headers(req: &mut Request) {
    let mut out = Headers::new();
    for (k, v) in req.headers.iter() {
        out.insert(k.to_lowercase(), v.clone());
    }
    req.headers = out;
}

/// A serde error in zod's words: the path and what was expected.
fn serde_issue(e: &serde_json::Error) -> String {
    format!("✖ {e}")
}

pub fn parse_site(input: &Value) -> Result<Site> {
    let mut site: Site = serde_json::from_value(input.clone())
        .map_err(|e| anyhow!("invalid site spec:\n{}", serde_issue(&e)))?;
    let issues = validate_site(&site);
    if !issues.is_empty() {
        return Err(anyhow!("invalid site spec:\n{}", issues.join("\n")));
    }
    normalize_site(&mut site);
    Ok(site)
}

/// `OperationSchema.parse`: the same checks for one operation (learning finishes with it).
pub fn parse_operation(input: &Value) -> Result<Operation> {
    let site = serde_json::json!({ "name": "x", "baseUrl": "https://x", "operations": [input] });
    let mut s = parse_site(&site)?;
    Ok(s.operations.remove(0))
}

/// Validate an operation value that is already typed.
pub fn check_operation(op: &Operation) -> Result<Operation> {
    let v = serde_json::to_value(op)?;
    parse_operation(&v)
}

/// A JSON step list given on the command line, checked like the schema would.
pub fn parse_match(v: &Value) -> Result<Match> {
    let m: Match = serde_json::from_value(v.clone()).map_err(|e| anyhow!("{}", serde_issue(&e)))?;
    Ok(m)
}

pub fn parse_html_recipe(v: &Value) -> Result<HtmlRecipe> {
    serde_json::from_value(v.clone()).map_err(|e| anyhow!("{}", serde_issue(&e)))
}

pub fn parse_steps(v: &Value) -> Result<Vec<TriggerStep>> {
    serde_json::from_value(v.clone()).map_err(|e| anyhow!("{}", serde_issue(&e)))
}
