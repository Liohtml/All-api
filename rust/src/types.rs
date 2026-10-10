//! Shared contract between the browser layer (which produces exchanges) and the core (which
//! learns and executes operations from them). Both sides use only this module.
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

pub type Headers = IndexMap<String, String>;

/// One request/response pair observed in a real browser. Bodies are raw UTF-8 text.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Exchange {
    pub id: u64,
    /// CDP resource type, lower-cased: "document" | "xhr" | "fetch" | "script" | ...
    pub resource_type: String,
    pub request: ExchangeRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ExchangeResponse>,
    /// true when the request was intercepted and aborted before leaving the browser (write learning)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub aborted: bool,
}

/// The request as the browser sent it: the same shape a stored template has.
pub type ExchangeRequest = crate::spec::Request;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: Headers,
    /// raw body text, read inside the response handler; absent for redirects/beacons
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default)]
    pub content_type: String,
}

impl Exchange {
    pub fn body(&self) -> &str {
        self.response.as_ref().and_then(|r| r.body.as_deref()).unwrap_or("")
    }
    pub fn status(&self) -> Option<u16> {
        self.response.as_ref().map(|r| r.status)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

/// A browser-shaped cookie, stored in the per-site jar.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoredCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    /// unix seconds; -1 for a session cookie
    #[serde(default = "minus_one")]
    pub expires: f64,
    #[serde(default)]
    pub http_only: bool,
    #[serde(default)]
    pub secure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_site: Option<SameSite>,
}

fn minus_one() -> f64 {
    -1.0
}

impl StoredCookie {
    pub fn new(name: &str, value: &str, domain: &str) -> Self {
        StoredCookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: domain.to_string(),
            path: "/".to_string(),
            expires: -1.0,
            http_only: false,
            secure: false,
            same_site: None,
        }
    }
}

/// Everything the browser layer hands back from one trigger run.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaptureResult {
    pub exchanges: Vec<Exchange>,
    pub cookies: Vec<StoredCookie>,
    /// final page URL after the trigger ran
    pub final_url: String,
    /// the final page origin's localStorage and sessionStorage, so learning can ref a token kept there
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<IndexMap<String, String>>,
    /// every URL the page had, history API changes (an SPA's pushState) included: echoes of them are not evidence
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StepAction {
    Click,
    Fill,
    Press,
    Wait,
    Goto,
}

impl StepAction {
    pub const ALL: [&'static str; 5] = ["click", "fill", "press", "wait", "goto"];
    pub fn name(self) -> &'static str {
        match self {
            StepAction::Click => "click",
            StepAction::Fill => "fill",
            StepAction::Press => "press",
            StepAction::Wait => "wait",
            StepAction::Goto => "goto",
        }
    }
}

/// How to make the site's own frontend fire a request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TriggerStep {
    pub action: StepAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// milliseconds for "wait"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ms: Option<f64>,
}
