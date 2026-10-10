//! Port of test/e2e.test.ts: end to end against the offline fixture site, in a temp
//! API_ANYTHING_HOME, through the public entry points: add_operation (what `api-anything add`
//! runs), call, the CLI, and the MCP server.
mod common;
use api_anything::browser::{TriggerOptions, clear_profile_cookies, close_browser, run_trigger};
use api_anything::execute::{CallOptions, CallResult, call};
use api_anything::heal::{AddInput, CapturePageOptions, FromCapture, Recipe, add_operation, capture_page, profile_dir};
use api_anything::login::{ImportOptions, import_session};
use api_anything::session::{Session, load_session, save_session};
use api_anything::spec::{Match, Trigger, parse_html_recipe};
use api_anything::store::{remembered_tier, stale_mark};
use api_anything::util::now_ms;
use common::fixture::{Fixture, PUBLIC_BEARER};
use common::{Home, args, j};
use regex::Regex;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// One runtime for the whole binary, like node's one event loop: the shared Chrome belongs to the
/// runtime that launched it, so every test runs on this one.
static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

static HOME: LazyLock<Home> = LazyLock::new(Home::new);
const SITE: &str = "fixture";

fn chrome() -> bool {
    LazyLock::force(&HOME);
    if std::env::var("API_ANYTHING_CHROME").is_err() {
        let p = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
        if std::path::Path::new(p).exists() {
            unsafe { std::env::set_var("API_ANYTHING_CHROME", p) };
        }
    }
    api_anything::browser::chrome_available()
}

/// One fixture for the whole file, as the `describe` has, on its own runtime so it outlives each test's.
static FX: LazyLock<Fixture> = LazyLock::new(|| {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let f = Fixture::start().await;
            tx.send(f).unwrap();
            std::future::pending::<()>().await;
        });
    });
    rx.recv().unwrap()
});

/// The tests build on one another in file order (node runs them so): one at a time, in turn.
static STAGE: AtomicUsize = AtomicUsize::new(0);
struct Turn(usize);
impl Drop for Turn {
    fn drop(&mut self) {
        STAGE.store(self.0, Ordering::SeqCst);
    }
}
async fn turn(n: usize) -> Turn {
    while STAGE.load(Ordering::SeqCst) != n - 1 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Turn(n)
}

fn fast() -> CallOptions {
    CallOptions { min_interval_ms: Some(0), ..Default::default() }
}

fn re(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

fn heals() -> Vec<Value> {
    std::fs::read_to_string(HOME.path().join("heals.jsonl"))
        .unwrap_or_default()
        .trim()
        .split('\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn spec_file() -> PathBuf {
    HOME.path().join("sites").join(format!("{SITE}.json"))
}

fn spec_text() -> String {
    std::fs::read_to_string(spec_file()).unwrap()
}

struct CliOut {
    code: i32,
    stdout: String,
    stderr: String,
}

/// The CLI, as a child process (the fixture lives in this process and must keep answering).
async fn cli(args: &[&str]) -> CliOut {
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-anything"))
        .args(args)
        .env("API_ANYTHING_HOME", HOME.path())
        .output()
        .await
        .unwrap();
    CliOut { code: out.status.code().unwrap_or(1), stdout: String::from_utf8_lossy(&out.stdout).into_owned(), stderr: String::from_utf8_lossy(&out.stderr).into_owned() }
}

fn add(op: &str, trigger: Option<Trigger>, examples: Vec<Value>) -> AddInput {
    AddInput {
        site: SITE.into(),
        op: op.into(),
        trigger,
        examples: examples.into_iter().map(args).collect(),
        matcher: None,
        write: false,
        description: None,
        response: None,
        public: None,
        from: None,
        from2: None,
        fetcher: None,
    }
}

fn trigger(url: &str) -> Option<Trigger> {
    Some(Trigger { url: url.to_string(), steps: None, soft_from: None })
}

fn steps(v: Value) -> Option<Vec<api_anything::types::TriggerStep>> {
    Some(serde_json::from_value(v).unwrap())
}

fn path_match(path: &str) -> Option<Match> {
    Some(Match { path: Some(path.to_string()), ..Default::default() })
}

fn js(r: &CallResult) -> String {
    serde_json::to_string(r).unwrap()
}

fn skip() {
    eprintln!("Google Chrome not installed: skipped");
}

/// What test/fixture/cookie-db.ts `makeChromiumDb` writes: <profileDir>/Network/Cookies as modern
/// Chrome does, with v10-encrypted values.
fn make_chromium_db(profile_dir: &Path, rows: &[(&str, &str, &str)], password: &str) {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    use sha2::Digest;
    let meta_version = 24;
    // the platform default src/import.rs derives with, so each OS tests its own path
    let iterations = if cfg!(target_os = "linux") { 1 } else { 1003 };
    let key = api_anything::import::derive_key(password, iterations);
    std::fs::create_dir_all(profile_dir.join("Network")).unwrap();
    let db = rusqlite::Connection::open(profile_dir.join("Network").join("Cookies")).unwrap();
    db.execute_batch("DROP TABLE IF EXISTS meta; DROP TABLE IF EXISTS cookies; CREATE TABLE meta(key TEXT, value TEXT)").unwrap();
    db.execute("INSERT INTO meta VALUES('version', ?1)", [meta_version.to_string()]).unwrap();
    db.execute_batch("CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER)").unwrap();
    for (host_key, name, value) in rows {
        let prefix: Vec<u8> = sha2::Sha256::digest(host_key.as_bytes()).to_vec();
        let mut plain = prefix;
        plain.extend_from_slice(value.as_bytes());
        let enc = cbc::Encryptor::<aes::Aes128>::new(&key.into(), &[0x20u8; 16].into());
        let mut encrypted = b"v10".to_vec();
        encrypted.extend(enc.encrypt_padded_vec_mut::<aes::cipher::block_padding::Pkcs7>(&plain));
        db.execute(
            "INSERT INTO cookies VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            rusqlite::params![host_key, name, "", encrypted, "/", 0i64, 0i64, 0i64, -1i64],
        )
        .unwrap();
    }
}

#[test]
fn t01_add_get_user_from_u_name_with_two_examples_call_it_for_a_new_name_at_tier_1() {
    RT.block_on(async {
        let _t = turn(1).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let mut input = add("getUser", trigger(&format!("{}/u/{{name}}", fx.url)), vec![json!({ "name": "alice" }), json!({ "name": "bob" })]);
        input.response = Some(Recipe { extract: Some("data.user".into()), pick: Some(vec!["name".into(), "followers".into(), "posts[0].text".into()]), ..Default::default() });
        let r = add_operation(input).await.unwrap();
        assert_eq!(r.operation.min_tier, 1, "{}", r.warnings.join("\n"));
        assert_eq!(j(&r.operation.matcher), json!({ "method": "GET", "host": "127.0.0.1", "path": "/api/graphql/*/UserByName" }));
        assert_eq!(r.operation.volatile.iter().map(|v| v.anchor.as_str()).collect::<Vec<_>>(), ["UserByName"]);

        let res = call(SITE, "getUser", args(json!({ "name": "carol" })), fast()).await;
        assert!(res.ok, "{}", js(&res));
        assert_eq!(res.tier, Some(1));
        assert_eq!(res.data, Some(json!({ "name": "carol", "followers": 500, "posts[0].text": "hello from carol" })));

        let session = load_session(SITE).unwrap();
        let ct0 = session.cookies.iter().find(|c| c.name == "ct0").expect("the jar holds the CSRF cookie");
        assert!(!spec_text().contains(&ct0.value), "the spec never holds a credential");
    })
}

#[test]
fn t02_after_rotate_the_call_heals_by_rescan_no_browser_and_logs_it() {
    RT.block_on(async {
        let _t = turn(2).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        fx.rotate();
        let res = call(SITE, "getUser", args(json!({ "name": "dave" })), fast()).await;
        assert!(res.ok, "{}", js(&res));
        assert_eq!(res.healed, Some(true));
        assert_eq!(res.tier, Some(1));
        assert_eq!(heals().iter().map(|h| (h["op"].clone(), h["strategy"].clone())).collect::<Vec<_>>(), [(json!("getUser"), json!("rescan"))]);
        assert!(spec_text().contains(&fx.state().user_query_id));
    })
}

#[test]
fn t02b_a_handle_that_doesnt_exist_is_input_the_example_still_answers_no_heal_no_browser() {
    RT.block_on(async {
        let _t = turn(3).await;
        if !chrome() {
            return skip();
        }
        let before = heals().len();
        let res = call(SITE, "getUser", args(json!({ "name": "nobody_zz" })), fast()).await;
        assert_eq!(j(&res.class), json!("input"), "{}", js(&res));
        assert!(re("do not heal").is_match(res.next.as_deref().unwrap_or("")));
        assert_eq!(heals().len(), before);
    })
}

#[test]
fn t03_heal_loop_guard_then_a_heal_by_recapture_when_rescan_cannot_work() {
    RT.block_on(async {
        let _t = turn(4).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        add_operation(add("getUser2", trigger(&format!("{}/u/{{name}}", fx.url)), vec![json!({ "name": "alice" }), json!({ "name": "bob" })])).await.unwrap();
        let mut spec: Value = serde_json::from_str(&spec_text()).unwrap();
        let op = spec["operations"].as_array_mut().unwrap().iter_mut().find(|o| o["name"] == "getUser2").unwrap();
        for v in op["volatile"].as_array_mut().unwrap() {
            v["anchor"] = json!("NoSuchAnchor");
        }
        std::fs::write(spec_file(), spec.to_string()).unwrap();
        fx.rotate();

        // getUser healed minutes ago: drifting again marks it stale instead of re-healing; the read still answers via the trigger.
        let guarded = call(SITE, "getUser", args(json!({ "name": "erin" })), fast()).await;
        assert!(guarded.ok, "{}", js(&guarded));
        assert_eq!(guarded.tier, Some(3));
        assert_eq!(guarded.healed, None);
        assert!(stale_mark(SITE, "getUser", now_ms()).is_some());
        assert_eq!(heals().len(), 1);

        let res = call(SITE, "getUser2", args(json!({ "name": "frank" })), fast()).await;
        assert!(res.ok, "{}", js(&res));
        assert_eq!(res.healed, Some(true));
        let last = heals().last().cloned().unwrap();
        assert_eq!(last["op"], json!("getUser2"));
        assert_eq!(last["strategy"], json!("recapture"));
        let again = call(SITE, "getUser2", args(json!({ "name": "grace" })), fast()).await;
        assert_eq!(again.tier, Some(1), "the healed template replays at tier 1");
    })
}

#[test]
fn t04_a_write_is_learned_without_being_performed_and_runs_only_with_allow_writes_exactly_once() {
    RT.block_on(async {
        let _t = turn(5).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let writes = || fx.calls().iter().filter(|c| c.path.contains("/CreatePost")).count();
        let mut input = add("createPost", None, vec![json!({ "text": "first draft here" }), json!({ "text": "second draft here" })]);
        input.trigger = Some(Trigger {
            url: format!("{}/compose", fx.url),
            steps: steps(json!([
                { "action": "fill", "selector": "#text", "value": "{text}" },
                { "action": "click", "selector": "#post" }
            ])),
            soft_from: None,
        });
        input.write = true;
        let r = add_operation(input).await.unwrap();
        assert!(!r.operation.read_only);
        assert_eq!(writes(), 0, "learning sent no write");

        let refused = call(SITE, "createPost", args(json!({ "text": "not allowed" })), fast()).await;
        assert_eq!(j(&refused.class), json!("refused"));
        assert_eq!(writes(), 0);

        let res = call(SITE, "createPost", args(json!({ "text": "hello from api-anything" })), CallOptions { allow_writes: true, ..fast() }).await;
        assert!(res.ok, "{}", js(&res));
        assert_eq!(writes(), 1);
        assert!(re("hello from api-anything").is_match(&serde_json::to_string(&res.data).unwrap()));
    })
}

#[test]
fn t05_a_per_request_signature_pins_the_op_to_tier_3_which_answers_through_the_trigger() {
    RT.block_on(async {
        let _t = turn(6).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        fx.set_require_signature(true);
        let mut input = add("feed", trigger(&format!("{}/feed", fx.url)), vec![json!({})]);
        input.matcher = path_match("/api/signed/feed");
        let r = add_operation(input).await.unwrap();
        assert_eq!(r.operation.min_tier, 3, "{}", r.warnings.join("\n"));
        let res = call(SITE, "feed", args(json!({})), fast()).await;
        assert!(res.ok, "{}", js(&res));
        assert_eq!(res.tier, Some(3));
        assert_eq!(remembered_tier(SITE, "feed"), None, "the spec's own minTier is not remembered, so editing it takes effect");
        assert_eq!(res.data, Some(json!([{ "id": "f1", "text": "first" }, { "id": "f2", "text": "second" }])));
    })
}

#[test]
fn t06_a_login_wall_served_as_200_html_is_auth_with_a_login_hint() {
    RT.block_on(async {
        let _t = turn(7).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        run_trigger(TriggerOptions::new(&format!("{}/login", fx.url), &profile_dir())).await.unwrap(); // stands in for `api-anything login`
        let mut input = add("secret", trigger(&format!("{}/private", fx.url)), vec![json!({})]);
        input.matcher = path_match("/private");
        add_operation(input).await.unwrap();
        assert_eq!(call(SITE, "secret", args(json!({})), fast()).await.data, Some(json!({ "data": { "secret": "only for you" } })));

        // log out everywhere: the profile and the jar
        clear_profile_cookies("127.0.0.1", &profile_dir()).await.unwrap();
        save_session(SITE, &Session::empty()).unwrap();
        let res = call(SITE, "secret", args(json!({})), fast()).await;
        assert!(!res.ok);
        assert_eq!(j(&res.class), json!("auth"), "{}", js(&res));
        assert!(re("api-anything login fixture").is_match(res.next.as_deref().unwrap_or("")));
    })
}

#[test]
fn t07_a_rate_limit_is_reported_as_rate_with_no_heal_and_no_retry_via_the_cli() {
    RT.block_on(async {
        let _t = turn(8).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let mut input = add("limited", trigger(&format!("{}/api/limited", fx.url)), vec![json!({})]);
        input.matcher = path_match("/api/limited");
        add_operation(input).await.unwrap();
        let hits = || fx.calls().iter().filter(|c| c.path == "/api/limited").count();
        let before = hits();
        let heal_count = heals().len();
        let r = cli(&["call", SITE, "limited"]).await;
        assert_eq!(r.code, 1, "{}\n{}", r.stdout, r.stderr);
        let res: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(res["class"], json!("rate"));
        assert!(re("(?m)^next: rate limited").is_match(&r.stderr), "{}", r.stderr);
        assert_eq!(hits(), before + 1);
        assert_eq!(heals().len(), heal_count);
    })
}

#[test]
fn t08_layered_f_req_form_encoding_with_the_xssi_prefix_works_for_a_new_query() {
    RT.block_on(async {
        let _t = turn(9).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let r = add_operation(add("search", trigger(&format!("{}/search?q={{q}}", fx.url)), vec![json!({ "q": "kittens" }), json!({ "q": "puppies" })])).await.unwrap();
        assert!(
            r.operation.slots.iter().any(|s| s.param.as_deref() == Some("q") && s.at.first().map(|a| a.as_str()) == Some("form:f.req") && s.at.len() == 3),
            "{}",
            serde_json::to_string(&r.operation.slots).unwrap()
        );
        assert_eq!(r.operation.response.xssi_prefix.as_deref(), Some(")]}'"));
        let res = call(SITE, "search", args(json!({ "q": "red \"pandas\" & co" })), fast()).await;
        assert!(res.ok, "{}", js(&res));
        assert_eq!(r.operation.response.extract.as_deref(), Some("[0][2][0]"), "the suggestion steps into the JSON-encoded payload");
        assert_eq!(res.data.as_ref().unwrap()[0], json!(["red \"pandas\" & co result 1", "https://example.test/red%20%22pandas%22%20%26%20co/1"]));
    })
}

#[test]
fn t09_the_html_recipe_on_a_server_rendered_list_returns_picked_items() {
    RT.block_on(async {
        let _t = turn(10).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let mut input = add("listUsers", trigger(&format!("{}/list", fx.url)), vec![json!({})]);
        input.matcher = path_match("/list");
        input.response = Some(Recipe {
            html: Some(parse_html_recipe(&json!({ "items": "li.user", "fields": { "name": "a.name", "followers": "span.followers", "href": "a.name@href" } })).unwrap()),
            pick: Some(vec!["name".into(), "href".into()]),
            ..Default::default()
        });
        let added = add_operation(input).await.unwrap();
        assert!(!added.warnings.iter().any(|w| re("response is HTML").is_match(w)), "no 'set response.html' warning when --html was given");
        assert_eq!(j(&added.preview), json!({ "count": 3, "first": { "name": "alice", "href": "/u/alice" } }));
        assert_eq!(added.captures.len(), 2, "both trigger runs are saved as captures");
        let res = call(SITE, "listUsers", args(json!({})), fast()).await;
        assert!(res.ok, "{}", js(&res));
        assert_eq!(res.data, Some(json!([{ "name": "alice", "href": "/u/alice" }, { "name": "bob", "href": "/u/bob" }, { "name": "carol", "href": "/u/carol" }])));
    })
}

/// A line-delimited JSON-RPC client over the CLI's `mcp` stdio, what the TS test's StdioClientTransport is.
struct McpClient {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    next_id: u64,
    instructions: String,
}

impl McpClient {
    async fn connect() -> McpClient {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-anything"))
            .arg("mcp")
            .env("API_ANYTHING_HOME", HOME.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut c = McpClient { child, stdin, lines, next_id: 0, instructions: String::new() };
        let init = c.request("initialize", json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "e2e", "version": "0" } })).await;
        c.instructions = init["instructions"].as_str().unwrap_or("").to_string();
        c.stdin.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
        c
    }
    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let msg = json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params });
        self.stdin.write_all(format!("{msg}\n").as_bytes()).await.unwrap();
        loop {
            let line = self.lines.next_line().await.unwrap().expect("the server answers");
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == json!(self.next_id) {
                assert!(v.get("error").is_none(), "{line}");
                return v["result"].clone();
            }
        }
    }
    async fn list_tools(&mut self) -> Vec<Value> {
        self.request("tools/list", json!({})).await["tools"].as_array().cloned().unwrap()
    }
    async fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({ "name": name, "arguments": arguments })).await
    }
    async fn close(mut self) {
        drop(self.stdin);
        let _ = tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await;
        let _ = self.child.start_kill();
    }
}

fn text(r: &Value) -> Value {
    serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[test]
fn t10_the_mcp_server_lists_3_meta_tools_calls_reads_and_hides_and_refuses_writes() {
    RT.block_on(async {
        let _t = turn(11).await;
        if !chrome() {
            return skip();
        }
        let mut client = McpClient::connect().await;
        let tools = client.list_tools().await;
        let mut names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        names.sort();
        assert_eq!(names, ["call_operation", "list_operations", "list_sites", "login"]);
        assert_eq!(tools.iter().find(|t| t["name"] == "call_operation").map(|t| t["annotations"]["readOnlyHint"].clone()), Some(json!(true)));
        // the agent is told which sites it can call before it picks web search
        assert!(re(&format!(r"\b{SITE}\b")).is_match(&client.instructions), "{}", client.instructions);

        let ops = text(&client.call_tool("list_operations", json!({ "site": SITE })).await);
        assert!(ops["operations"].as_array().unwrap().iter().any(|o| o["name"] == "search"));
        assert!(!ops["operations"].as_array().unwrap().iter().any(|o| o["name"] == "createPost"), "writes are hidden");

        let ok = client.call_tool("call_operation", json!({ "site": SITE, "op": "search", "args": { "q": "otters" } })).await;
        assert!(ok["isError"] != json!(true), "{ok}");
        assert!(serde_json::to_string(&text(&ok)["data"]).unwrap().contains("otters result 1"));

        let refused = client.call_tool("call_operation", json!({ "site": SITE, "op": "createPost", "args": { "text": "nope" } })).await;
        assert_eq!(refused["isError"], json!(true));
        assert_eq!(text(&refused)["class"], json!("refused"));
        client.close().await;
    })
}

#[test]
fn t11_a_missing_session_value_clean_home_is_auth_one_trigger_run_refreshes_it_then_tier_1_works() {
    RT.block_on(async {
        let _t = turn(12).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let mut input = add("getUser3", trigger(&format!("{}/u/{{name}}", fx.url)), vec![json!({ "name": "alice" }), json!({ "name": "bob" })]);
        input.response = Some(Recipe { extract: Some("data.user.name".into()), ..Default::default() });
        add_operation(input).await.unwrap();
        let mut s = load_session(SITE).unwrap();
        s.values.clear(); // as from a bundled spec on a fresh machine
        save_session(SITE, &s).unwrap();
        let r = call(SITE, "getUser3", args(json!({ "name": "heidi" })), fast()).await;
        assert!(r.ok, "{}", js(&r));
        assert_eq!(r.tier, Some(3));
        assert!(re("refreshed the session").is_match(r.reason.as_deref().unwrap_or("")));
        assert_eq!(load_session(SITE).unwrap().values.get("getUser3/authorization").map(|s| s.as_str()), Some(PUBLIC_BEARER));
        let again = call(SITE, "getUser3", args(json!({ "name": "ivan" })), fast()).await;
        assert_eq!(again.tier, Some(1), "{}", js(&again));
    })
}

#[test]
fn t12_public_keeps_a_public_bearer_literal_works_with_no_session_values_and_export_allows_it() {
    RT.block_on(async {
        let _t = turn(13).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let mut input = add("getUserPublic", trigger(&format!("{}/u/{{name}}", fx.url)), vec![json!({ "name": "alice" }), json!({ "name": "bob" })]);
        input.public = Some(vec!["authorization".into()]);
        input.response = Some(Recipe { extract: Some("data.user.name".into()), ..Default::default() });
        add_operation(input).await.unwrap();
        let mut s = load_session(SITE).unwrap();
        s.values.clear();
        save_session(SITE, &s).unwrap();
        let r = call(SITE, "getUserPublic", args(json!({ "name": "judy" })), CallOptions { max_tier: Some(1), ..fast() }).await;
        assert!(r.ok, "{}", js(&r));
        assert_eq!(r.data, Some(json!("judy")));
        let mut s = load_session(SITE).unwrap();
        s.values = [("authorization".to_string(), PUBLIC_BEARER.to_string())].into_iter().collect(); // the export scan sees it live
        save_session(SITE, &s).unwrap();
        let out = cli(&["export", SITE, "--keep-examples"]).await;
        let spec: Value = serde_json::from_str(&out.stdout).unwrap_or_else(|_| panic!("{}\n{}", out.stdout, out.stderr));
        let op = spec["operations"].as_array().unwrap().iter().find(|o| o["name"] == "getUserPublic").unwrap();
        assert_eq!(op["request"]["headers"]["authorization"], json!(PUBLIC_BEARER));
        assert_eq!(op["params"][0]["example"], json!("alice"));
    })
}

#[test]
fn t13_a_write_sent_as_a_get_by_a_button_is_learned_without_being_sent_from_a_non_write_capture_is_refused() {
    RT.block_on(async {
        let _t = turn(14).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let follows = || fx.calls().iter().filter(|c| c.path.starts_with("/api/follow")).count();
        let mut input = add("follow", None, vec![json!({ "user": "alice" }), json!({ "user": "carol" })]);
        input.trigger = Some(Trigger { url: format!("{}/follow/{{user}}", fx.url), steps: steps(json!([{ "action": "click", "selector": "#follow" }])), soft_from: None });
        input.write = true;
        let r = add_operation(input).await.unwrap();
        assert_eq!(r.operation.request.method, "GET");
        assert_eq!(follows(), 0, "learning sent no write");
        let cap = capture_page(CapturePageOptions { url: format!("{}/list", fx.url), steps: None, soft_from: None, write: false, args: None }).await.unwrap();
        let mut input = add("w2", None, vec![json!({})]);
        input.write = true;
        input.from = Some(FromCapture { capture: cap, id: None });
        let err = add_operation(input).await.err().expect("refused").to_string();
        assert!(re("ran without --write").is_match(&err), "{err}");
    })
}

#[test]
fn t14_ids_that_differ_per_page_load_but_replay_fine_are_session_scoped_min_tier_stays_1() {
    RT.block_on(async {
        let _t = turn(15).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let mut input = add("scoped", trigger(&format!("{}/scoped?q={{q}}", fx.url)), vec![json!({ "q": "kittens" }), json!({ "q": "puppies" })]);
        input.response = Some(Recipe { extract: Some("data.results".into()), ..Default::default() });
        let r = add_operation(input).await.unwrap();
        assert_eq!(r.operation.min_tier, 1, "{}", r.warnings.join("\n"));
        assert!(r.warnings.iter().any(|w| re("session-scoped").is_match(w)));
        let res = call(SITE, "scoped", args(json!({ "q": "otters" })), fast()).await;
        assert_eq!(res.data, Some(json!(["otters one", "otters two"])));
        assert_eq!(res.tier, Some(1));
    })
}

#[test]
fn t15_add_from_a_saved_run_re_learns_without_a_browser_templating_step_selectors() {
    RT.block_on(async {
        let _t = turn(16).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let cap = capture_page(CapturePageOptions {
            url: format!("{}/follow/alice", fx.url),
            steps: steps(json!([
                { "action": "click", "selector": "#follow" },
                { "action": "wait", "selector": "a[href=\"/u/alice\"], #follow" }
            ])),
            soft_from: None,
            write: true,
            args: None,
        })
        .await
        .unwrap();
        let mut input = add("follow2", None, vec![json!({ "user": "alice" })]);
        input.write = true;
        input.from = Some(FromCapture { capture: cap, id: None });
        let r = add_operation(input).await.unwrap();
        assert_eq!(r.operation.trigger.url, format!("{}/follow/{{user}}", fx.url));
        assert_eq!(r.operation.trigger.steps.as_ref().and_then(|s| s.get(1)).and_then(|s| s.selector.as_deref()), Some("a[href=\"/u/{user}\"], #follow"));
        assert_eq!(r.captures, Vec::<String>::new());
    })
}

#[test]
fn t16_a_site_that_walls_plain_http_answers_at_tier_2_and_the_result_says_why() {
    RT.block_on(async {
        let _t = turn(17).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let mut input = add("walled", trigger(&format!("{}/walled", fx.url)), vec![json!({})]);
        input.matcher = path_match("/api/walled");
        add_operation(input).await.unwrap();
        let r = call(SITE, "walled", args(json!({})), fast()).await;
        assert_eq!(r.tier, Some(2), "{}", js(&r));
        assert!(re(r"tier 1 was blocked \(Cloudflare").is_match(r.reason.as_deref().unwrap_or("")), "{:?}", r.reason);
        let again = call(SITE, "walled", args(json!({})), fast()).await;
        assert_eq!(again.tier, Some(2));
        assert!(re("started at tier 2").is_match(again.reason.as_deref().unwrap_or("")), "{:?}", again.reason);
        assert_eq!(remembered_tier(SITE, "walled"), Some(2));
    })
}

// The TS file runs 18 before 17; neither depends on the other, and this file's turns follow its test names.
#[test]
fn t17_captures_next_hint_points_at_inspect_and_html_when_the_best_candidate_is_the_page_itself() {
    RT.block_on(async {
        let _t = turn(18).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        close_browser().await; // the CLI launches its own Chrome on the same profile
        let r = cli(&["capture", &format!("{}/list", fx.url), "--example", "q=alice"]).await;
        let out: Value = serde_json::from_str(&r.stdout).unwrap_or_else(|_| panic!("{}\n{}", r.stdout, r.stderr));
        assert_eq!(out["candidates"][0]["kind"], json!("document"));
        assert!(re("inspect .* --html").is_match(out["next"].as_str().unwrap_or("")), "{}", out["next"]);
    })
}

#[test]
fn t18_login_imports_the_session_from_the_browser_a_revoke_fresh_cookie_self_heals_by_re_import() {
    RT.block_on(async {
        let _t = turn(19).await;
        if !chrome() {
            return skip();
        }
        let fx = &*FX;
        let host = "127.0.0.1";
        let browser_root = tempfile::tempdir().unwrap();
        let write_session = |token: &str| make_chromium_db(&browser_root.path().join("Default"), &[(host, "session", token)], "pw");
        let first = fx.mint_session();
        write_session(&first);
        unsafe {
            std::env::set_var(
                "API_ANYTHING_BROWSER_ROOTS",
                json!([{ "name": "Chrome", "family": "chromium", "root": browser_root.path().to_str().unwrap(), "password": "pw" }]).to_string(),
            )
        };
        let run = async {
            // Learn the op while the profile is signed in, so its response format is JSON not the login wall.
            run_trigger(TriggerOptions::new(&format!("{}/login", fx.url), &profile_dir())).await.unwrap();
            let mut input = add("secret2", trigger(&format!("{}/private", fx.url)), vec![json!({})]);
            input.matcher = path_match("/private");
            input.response = Some(Recipe { extract: Some("data".into()), ..Default::default() });
            add_operation(input).await.unwrap();

            // login by import: browserless, no Keychain (password injected), no profile push
            let imported = import_session(SITE, &format!("{}/", fx.url), ImportOptions { push_profile: false, ..Default::default() }).await.unwrap();
            assert_eq!(imported.as_ref().map(|i| i.source.as_str()), Some("chrome:Default"));
            assert_eq!(load_session(SITE).unwrap().source.as_deref(), Some("chrome:Default"));

            let res = call(SITE, "secret2", args(json!({})), CallOptions { max_tier: Some(1), ..fast() }).await;
            assert!(res.ok, "{}", js(&res));
            assert_eq!(res.data, Some(json!({ "secret": "only for you" })));

            // the server logs the session out; the human re-signs in, so the browser DB now holds a fresh cookie
            fx.revoke(&first);
            write_session(&fx.mint_session());
            let res = call(SITE, "secret2", args(json!({})), CallOptions { max_tier: Some(1), ..fast() }).await;
            assert!(res.ok, "{} self-healed by re-importing from the same profile", js(&res));
        };
        let outcome = std::panic::AssertUnwindSafe(run);
        let result = futures_util::FutureExt::catch_unwind(outcome).await;
        unsafe { std::env::remove_var("API_ANYTHING_BROWSER_ROOTS") };
        close_browser().await;
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
    })
}
