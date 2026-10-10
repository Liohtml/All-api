//! Shared helpers for the integration tests: fixtures built from JSON literals, like the TypeScript tests do.
#![allow(dead_code)]
pub mod cookie_db;
pub mod fixture;
use api_anything::learn::Args;
use api_anything::session::Session;
use api_anything::spec::{Operation, Site, parse_operation, parse_site};
use api_anything::types::{Exchange, StoredCookie};
use serde_json::Value;

pub fn ex(v: Value) -> Exchange {
    serde_json::from_value(v).expect("an exchange literal")
}

pub fn exs(v: Value) -> Vec<Exchange> {
    serde_json::from_value(v).expect("exchange literals")
}

pub fn op(v: Value) -> Operation {
    parse_operation(&v).expect("a valid operation")
}

pub fn site(v: Value) -> Site {
    parse_site(&v).expect("a valid site")
}

pub fn args(v: Value) -> Args {
    match v {
        Value::Object(o) => o,
        _ => panic!("args must be an object"),
    }
}

pub fn cookie(name: &str, value: &str, domain: &str) -> StoredCookie {
    let mut c = StoredCookie::new(name, value, domain);
    c.secure = false;
    c
}

pub fn session(cookies: Vec<StoredCookie>, values: &[(&str, &str)]) -> Session {
    Session::with(
        cookies,
        values
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

pub fn no_session() -> Session {
    Session::empty()
}

/// Serialize for `deepEqual`-style comparisons against JSON literals.
pub fn j<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap()
}

/// A temporary home for the store, set for the whole test process.
pub struct Home {
    pub dir: tempfile::TempDir,
}

impl Home {
    pub fn new() -> Home {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: the tests in one binary run under one home; the variable is set before any thread reads it
        unsafe { std::env::set_var("API_ANYTHING_HOME", dir.path()) };
        Home { dir }
    }
    pub fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

pub fn enc(s: &str) -> String {
    api_anything::util::encode_uri_component(s)
}
