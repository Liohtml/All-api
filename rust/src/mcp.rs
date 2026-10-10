//! stdio MCP server with four fixed meta-tools, so the tool list costs the same at 2 sites or 200.
//! Writes are hidden from list_operations and refused by call_operation unless started with allow_writes.
//! It cannot create operations (that is the CLI's capture/add), and its login cannot import cookies
//! a human did not already choose to import: page content may be steering the agent.
use crate::browser::{close_browser, login as login_window};
use crate::execute::{CallOptions, call};
use crate::extract::returned_fields;
use crate::heal::profile_dir;
use crate::login::{ImportOptions, browser_source, cookie_names, import_session, is_logged_in, resolve_login_target};
use crate::session::{load_session, save_session, session_file, with_lock};
use crate::store::{list_sites, load_site, site_notes};
use crate::util::{first_line, re};
use serde_json::{Map, Value, json};
use std::sync::LazyLock;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A `next` hint in MCP terms: the CLI's `ops`, `sites` and `login` are tools here; commands only the
/// CLI has (heal, add, capture) the agent runs in its own shell, or hands to the user when it has none.
pub fn mcp_next(next: &str) -> String {
    static ALLOW: LazyLock<regex::Regex> = LazyLock::new(|| re(r"rerun with --allow-writes \(MCP: [^)]*\)"));
    static OPS: LazyLock<regex::Regex> = LazyLock::new(|| re(r"api-anything ops ([\w.-]+)"));
    static SITES: LazyLock<regex::Regex> = LazyLock::new(|| re(r"api-anything sites"));
    static LOGIN: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?:ask the user to run:? )?api-anything login ([\w.-]+)"));
    static ADD: LazyLock<regex::Regex> = LazyLock::new(|| re(r"api-anything add creates one"));
    static CLI_ONLY: LazyLock<regex::Regex> = LazyLock::new(|| re(r"\bapi-anything (heal|add|capture|verify|export)\b"));
    let out = ALLOW.replacen(next, 1, "ask the user to restart this MCP server with --allow-writes");
    let out = OPS.replace_all(&out, "list_operations {\"site\":\"$1\"}");
    let out = SITES.replace_all(&out, "list_sites");
    let out = LOGIN.replace_all(&out, "the login tool {\"site\":\"$1\"} (mode \"window\" when the user must sign in or clear a challenge by hand)");
    let out = ADD.replacen(&out, 1, "a new site is added with the CLI");
    if CLI_ONLY.is_match(&out) {
        format!("{out} (api-anything is a CLI: run it in your shell, as npx -y github:goodnight000/api-anything when the command is not installed; with no shell, ask the user)")
    } else {
        out.into_owned()
    }
}

/// A list of records repeats every key in every item. Over MCP such a list is sent once-per-key as
/// `{columns, rows}`; a missing field is null. Anything else, including a one-item list, is sent as is.
pub fn as_table(data: &Value) -> Value {
    let Value::Array(items) = data else { return data.clone() };
    if items.len() < 2 || !items.iter().all(|x| x.is_object()) {
        return data.clone();
    }
    let mut columns: Vec<String> = Vec::new();
    for x in items {
        for k in x.as_object().unwrap().keys() {
            if !columns.contains(k) {
                columns.push(k.clone());
            }
        }
    }
    let rows: Vec<Value> = items.iter().map(|x| Value::Array(columns.iter().map(|c| x.get(c).cloned().unwrap_or(Value::Null)).collect())).collect();
    json!({ "columns": columns, "rows": rows })
}

pub struct Server {
    pub allow_writes: bool,
}

pub struct Reply {
    pub value: Value,
    pub is_error: bool,
}

fn reply(v: Value, is_error: bool) -> Reply {
    Reply { value: v, is_error }
}

impl Server {
    pub fn new(allow_writes: bool) -> Server {
        Server { allow_writes }
    }

    pub fn instructions(&self) -> String {
        // without naming the sites up front, an agent asked "what does Goodreads rate X?" reaches for web search
        format!(
            "Calls these websites' own data requests directly, usually over plain HTTP: {}. When the user wants data from one of them, prefer list_operations then call_operation over web search or a browser.",
            list_sites().join(", ")
        )
    }

    pub fn tools(&self) -> Vec<Value> {
        let allow = self.allow_writes;
        vec![
            json!({
                "name": "list_sites",
                "description": "List the websites api-anything can call, with how many operations each has.",
                "inputSchema": { "type": "object", "properties": {} },
                "annotations": { "readOnlyHint": true, "openWorldHint": false }
            }),
            json!({
                "name": "list_operations",
                "description": "List a site's operations with their params and the keys a result item can carry (returns; one the site leaves out is absent), and the site's notes (caveats, arg formats). Call this before call_operation.",
                "inputSchema": { "type": "object", "properties": { "site": { "type": "string", "description": "site name from list_sites" } }, "required": ["site"] },
                "annotations": { "readOnlyHint": true, "openWorldHint": false }
            }),
            json!({
                "name": "call_operation",
                "description": format!("Call a site operation. Returns {{ok, class, data, tier, healed?, ms, reason?, next?}}; a list of two or more records comes back as data {{columns, rows}} (one row per item, null for a missing field); a one-item list stays a list. `reason` also explains a slow success. On failure follow `next` at most once, then stop and report.{}",
                    if allow { " Write operations change the user's account: only call them when the user asked for that exact action." } else { " Writes are disabled on this server." }),
                "inputSchema": { "type": "object", "properties": {
                    "site": { "type": "string" },
                    "op": { "type": "string", "description": "operation name from list_operations" },
                    "args": { "type": "object", "description": "param name -> value", "additionalProperties": true }
                }, "required": ["site", "op"] },
                "annotations": { "readOnlyHint": !allow, "destructiveHint": allow, "openWorldHint": true }
            }),
            json!({
                "name": "login",
                "description": "Sign in to a site so its operations work; use after a call returns class 'auth'. mode 'import' (default) refreshes the session from the browser profile the user already chose with `api-anything login` (no password); 'window' opens a visible browser for the user to sign in and clear 2FA/captcha by hand: tell the user to close that window when they are signed in, because the call only returns once it is closed.",
                "inputSchema": { "type": "object", "properties": {
                    "site": { "type": "string", "description": "site name from list_sites" },
                    "url": { "type": "string", "description": "a full URL, if the site is not yet known (window mode only)" },
                    "mode": { "type": "string", "enum": ["import", "window"] }
                } },
                "annotations": { "openWorldHint": true }
            }),
        ]
    }

    /// Every failure comes back as {error, next} JSON, like call_operation's, never as a bare exception text.
    pub async fn call_tool(&self, name: &str, args: &Map<String, Value>) -> Reply {
        match self.call_tool_inner(name, args).await {
            Ok(r) => r,
            Err(e) => {
                let msg = first_line(&e.to_string());
                let next = if msg.contains("invalid site name") || msg.contains("no site") { "list_sites" } else { "fix or delete the file named in error, then retry once" };
                reply(json!({ "ok": false, "error": msg, "next": next }), true)
            }
        }
    }

    async fn call_tool_inner(&self, name: &str, args: &Map<String, Value>) -> anyhow::Result<Reply> {
        let s = |k: &str| args.get(k).and_then(|v| v.as_str()).map(|v| v.to_string());
        match name {
            "list_sites" => {
                let sites: Vec<Value> = list_sites()
                    .into_iter()
                    .map(|name| match load_site(&name) {
                        Ok(Some(r)) => {
                            let ops = r.site.operations.iter().filter(|o| self.allow_writes || o.read_only).count();
                            let mut v = json!({ "name": name });
                            if let Some(d) = &r.site.description {
                                v["description"] = json!(d);
                            }
                            v["operations"] = json!(ops);
                            v
                        }
                        Ok(None) => json!({ "name": name, "error": format!("no site \"{name}\"") }),
                        Err(e) => json!({ "name": name, "error": e.to_string() }),
                    })
                    .collect();
                Ok(reply(Value::Array(sites), false))
            }
            "list_operations" => {
                let site = s("site").unwrap_or_default();
                let Some(r) = load_site(&site)? else { return Ok(reply(json!({ "error": format!("no site \"{site}\""), "next": "list_sites" }), true)) };
                let notes = site_notes(&r.site.name);
                let operations: Vec<Value> = r
                    .site
                    .operations
                    .iter()
                    .filter(|o| self.allow_writes || o.read_only)
                    .map(|o| {
                        let mut v = Map::new();
                        v.insert("name".into(), json!(o.name));
                        if let Some(d) = &o.description {
                            v.insert("description".into(), json!(d));
                        }
                        if !o.read_only {
                            v.insert("write".into(), json!(true));
                        }
                        if let Some(r) = returned_fields(&o.response) {
                            v.insert("returns".into(), json!(r));
                        }
                        let params: Vec<Value> = o
                            .params
                            .iter()
                            .map(|p| {
                                let mut pv = Map::new();
                                pv.insert("name".into(), json!(p.name));
                                pv.insert("type".into(), json!(p.kind.name()));
                                pv.insert("required".into(), json!(p.required));
                                if let Some(d) = &p.description {
                                    pv.insert("description".into(), json!(d));
                                }
                                if let Some(e) = &p.example {
                                    pv.insert("example".into(), e.clone());
                                }
                                if let Some(h) = &p.hint {
                                    pv.insert("hint".into(), json!(h));
                                }
                                if let Some(pat) = &p.pattern {
                                    pv.insert("pattern".into(), json!(pat));
                                }
                                Value::Object(pv)
                            })
                            .collect();
                        v.insert("params".into(), Value::Array(params));
                        Value::Object(v)
                    })
                    .collect();
                let mut out = json!({ "site": site, "operations": operations });
                if let Some(n) = notes {
                    out["notes"] = json!(n);
                }
                Ok(reply(out, false))
            }
            "call_operation" => {
                let site = s("site").unwrap_or_default();
                let op = s("op").unwrap_or_default();
                let call_args = args.get("args").and_then(|a| a.as_object()).cloned().unwrap_or_default();
                let r = call(&site, &op, call_args, CallOptions { allow_writes: self.allow_writes, ..Default::default() }).await;
                let mut v = serde_json::to_value(&r)?;
                if let Some(d) = &r.data {
                    v["data"] = as_table(d);
                }
                if let Some(n) = &r.next {
                    v["next"] = json!(mcp_next(n));
                }
                Ok(reply(v, !r.ok))
            }
            "login" => {
                let Some(target) = s("site").or_else(|| s("url")) else { return Ok(reply(json!({ "error": "give a site or a url" }), true)) };
                let t = match resolve_login_target(&target) {
                    Ok(t) => t,
                    Err(e) => return Ok(reply(json!({ "error": e.to_string(), "next": "list_sites" }), true)),
                };
                if s("mode").as_deref() == Some("window") {
                    // a human signs in by hand: they see which site and which account
                    let cookies = login_window(&t.url, &profile_dir(), false).await?;
                    let file = session_file(&t.site)?;
                    let c2 = cookies.clone();
                    with_lock(&file, || {
                        let mut sess = load_session(&t.site)?;
                        sess.cookies = c2;
                        sess.source = Some("window".into());
                        save_session(&t.site, &sess)
                    })?;
                    return Ok(reply(json!({ "ok": true, "site": t.site, "source": "window", "cookies": cookie_names(&cookies), "loggedIn": is_logged_in(&cookies, t.login_cookies.as_deref()) }), false));
                }
                // An agent may be acting on injected page text: it may only refresh a known site's session from
                // the profile a human already picked, never pull another domain's or another account's cookies.
                let source = if load_site(&t.site)?.is_some() { browser_source(&t.site)? } else { None };
                let Some(source) = source else {
                    return Ok(reply(
                        json!({ "ok": false, "site": t.site, "error": "MCP can only refresh a session the user imported with the CLI", "next": format!("ask the user to run in a terminal: api-anything login {} (or use mode \"window\")", t.site) }),
                        true,
                    ));
                };
                let imported = match import_session(&t.site, &t.url, ImportOptions { login_cookies: t.login_cookies.clone(), profile: Some(source.clone()), file: None, push_profile: true }).await {
                    Ok(i) => i,
                    Err(e) => return Ok(reply(json!({ "ok": false, "site": t.site, "error": e.to_string(), "next": format!("ask the user to run: api-anything login {}", t.site) }), true)),
                };
                let Some(imported) = imported else {
                    return Ok(reply(json!({ "ok": false, "site": t.site, "error": format!("no signed-in session in {source}"), "next": format!("ask the user to run: api-anything login {}", t.site) }), true));
                };
                let mut v = json!({ "ok": true, "site": t.site, "source": imported.source, "profile": format!("{}/{}", imported.browser, imported.profile) });
                if let Some(n) = &imported.name {
                    v["profileName"] = json!(n);
                }
                v["cookies"] = json!(cookie_names(&imported.cookies));
                v["loggedIn"] = json!(is_logged_in(&imported.cookies, t.login_cookies.as_deref()));
                Ok(reply(v, false))
            }
            other => Ok(reply(json!({ "error": format!("unknown tool {other}") }), true)),
        }
    }
}

const PROTOCOL: &str = "2025-06-18";

/// Serve the four tools over stdio JSON-RPC until the client goes away.
pub async fn serve_stdio(allow_writes: bool) -> anyhow::Result<()> {
    let server = Server::new(allow_writes);
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            let err = json!({ "jsonrpc": "2.0", "id": Value::Null, "error": { "code": -32700, "message": "parse error" } });
            out.write_all(format!("{err}\n").as_bytes()).await?;
            continue;
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let Some(id) = id else { continue }; // a notification
        let result: Result<Value, (i64, String)> = match method.as_str() {
            "initialize" => {
                let asked = params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or(PROTOCOL);
                let version = if ["2024-11-05", "2025-03-26", "2025-06-18"].contains(&asked) { asked } else { PROTOCOL };
                Ok(json!({ "protocolVersion": version, "capabilities": { "tools": {} }, "serverInfo": { "name": "api-anything", "version": VERSION }, "instructions": server.instructions() }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": server.tools() })),
            "tools/call" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").and_then(|a| a.as_object()).cloned().unwrap_or_default();
                let r = server.call_tool(name, &args).await;
                Ok(json!({ "content": [{ "type": "text", "text": r.value.to_string() }], "isError": r.is_error }))
            }
            "resources/list" => Ok(json!({ "resources": [] })),
            "prompts/list" => Ok(json!({ "prompts": [] })),
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        let response = match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err((code, message)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
        };
        out.write_all(format!("{response}\n").as_bytes()).await?;
        out.flush().await?;
    }
    // An open Chrome would keep the process alive after the client goes away.
    close_browser().await;
    Ok(())
}
