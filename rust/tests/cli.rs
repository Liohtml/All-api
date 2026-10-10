//! The CLI as an agent meets it, against the offline fixture site: which flags and names a command
//! takes, and what it says when the page, the recipe or the examples are not ones it can work with.
//! Port of `../test/cli.test.ts`: each test spawns the `api-anything` binary with its own home.
mod common;
use api_anything::heal::{AddInput, add_operation};
use api_anything::spec::Trigger;
use api_anything::util::{encode_uri_component, iso_now};
use common::fixture::{Fixture, PUBLIC_BEARER};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Once;

const CHROMIUM: &str = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";

/// The Chrome the CLI subprocess is told about, when there is one.
fn chrome_path() -> Option<String> {
    if let Ok(p) = std::env::var("API_ANYTHING_CHROME") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    Path::new(CHROMIUM).exists().then(|| CHROMIUM.to_string())
}

/// `chromeAvailable()`, after pointing API_ANYTHING_CHROME at the Playwright Chromium when it is there.
fn chrome() -> bool {
    static SET: Once = Once::new();
    SET.call_once(|| {
        if std::env::var("API_ANYTHING_CHROME").is_err() && Path::new(CHROMIUM).exists() {
            // SAFETY: set once, before any test of this binary spawns a thread that reads it
            unsafe { std::env::set_var("API_ANYTHING_CHROME", CHROMIUM) };
        }
    });
    api_anything::browser::chrome_available()
}

fn re(pat: &str) -> Regex {
    Regex::new(pat).unwrap_or_else(|e| panic!("bad regex {pat}: {e}"))
}

macro_rules! assert_match {
    ($hay:expr, $pat:expr) => {{
        let hay: &str = &$hay;
        assert!(re($pat).is_match(hay), "expected /{}/ to match: {hay}", $pat);
    }};
    ($hay:expr, $pat:expr, $($why:tt)+) => {{
        let hay: &str = &$hay;
        assert!(re($pat).is_match(hay), "{}: expected /{}/ to match: {hay}", format!($($why)+), $pat);
    }};
}

macro_rules! assert_no_match {
    ($hay:expr, $pat:expr) => {{
        let hay: &str = &$hay;
        assert!(!re($pat).is_match(hay), "expected /{}/ not to match: {hay}", $pat);
    }};
    ($hay:expr, $pat:expr, $($why:tt)+) => {{
        let hay: &str = &$hay;
        assert!(!re($pat).is_match(hay), "{}: expected /{}/ not to match: {hay}", format!($($why)+), $pat);
    }};
}

/// A JSON string field, as the TS tests read `out.error` and the like.
fn s(v: &Value) -> String {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}")).to_string()
}

/// `warnings.join("\n")`.
fn joined(v: &Value) -> String {
    v.as_array().unwrap_or_else(|| panic!("not an array: {v}")).iter().map(s).collect::<Vec<_>>().join("\n")
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}\nstderr: {}", self.stdout, self.stderr))
    }
}

/* A capture file as `capture` saves one, made without a browser: what is done with a saved capture needs none. */

const CSRF: &str = "seeded-csrf-token-0123456789";

fn jar() -> Vec<Value> {
    vec![json!({ "name": "ct0", "value": CSRF, "domain": "127.0.0.1", "path": "/", "expires": -1, "httpOnly": false, "secure": false })]
}

/// `{ ...JAR[0], ...over }`.
fn cookie_like(over: Value) -> Value {
    let mut c = jar().remove(0);
    for (k, v) in over.as_object().unwrap() {
        c[k] = v.clone();
    }
    c
}

/// One CLI home: `API_ANYTHING_HOME` for every command this test runs.
struct Cli {
    home: tempfile::TempDir,
}

impl Cli {
    fn new() -> Cli {
        Cli { home: tempfile::tempdir().unwrap() }
    }

    fn home(&self) -> &Path {
        self.home.path()
    }

    /// Runs `api-anything <args>`; async on purpose: the fixture server lives in this process and must keep answering.
    async fn run(&self, args: &[&str]) -> Out {
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-anything"));
        cmd.args(args).env("API_ANYTHING_HOME", self.home()).current_dir(env!("CARGO_MANIFEST_DIR"));
        if let Some(c) = chrome_path() {
            cmd.env("API_ANYTHING_CHROME", c);
        }
        let o = cmd.output().await.expect("the api-anything binary runs");
        Out { code: o.status.code().unwrap_or(1), stdout: String::from_utf8_lossy(&o.stdout).into_owned(), stderr: String::from_utf8_lossy(&o.stderr).into_owned() }
    }

    /// `seed(id, capture)`: `{ id, at, finalUrl, cookies: JAR, ...capture }` under captures/.
    fn seed(&self, id: &str, capture: Value) {
        fs::create_dir_all(self.home().join("captures")).unwrap();
        let mut file = Map::new();
        file.insert("id".into(), json!(id));
        file.insert("at".into(), json!(iso_now()));
        file.insert("finalUrl".into(), capture["url"].clone());
        file.insert("cookies".into(), json!(jar()));
        for (k, v) in capture.as_object().expect("a capture object") {
            file.insert(k.clone(), v.clone());
        }
        fs::write(self.home().join("captures").join(format!("{id}.json")), serde_json::to_string(&Value::Object(file)).unwrap()).unwrap();
    }

    fn sites_file(&self, site: &str) -> PathBuf {
        self.home().join("sites").join(format!("{site}.json"))
    }

    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.home().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    /// The "flags and command names" suite's site: a read that needs no session, GET /api/spa/user?name=<name>.
    fn plain_site(&self, f: &Fixture) {
        fs::create_dir_all(self.home().join("sites")).unwrap();
        let site = json!({
            "name": "plain",
            "baseUrl": f.url,
            "operations": [
                {
                    "name": "getUser",
                    "readOnly": true,
                    "trigger": { "url": format!("{}/spa/{{name}}", f.url) },
                    "match": { "method": "GET", "path": "/api/spa/user" },
                    "request": { "method": "GET", "url": format!("{}/api/spa/user?name=alice", f.url), "headers": {} },
                    "slots": [{ "param": "name", "at": ["query:name"] }],
                    "params": [{ "name": "name", "example": "alice" }],
                },
            ],
        });
        fs::write(self.sites_file("plain"), serde_json::to_string(&site).unwrap()).unwrap();
    }
}

/// One request as the fixture's pages send it, and the fixture's answer to it. `form`: a POST's body.
async fn answered(f: &Fixture, id: u64, resource_type: &str, path: &str, cookie: Option<&str>, form: Option<&str>) -> Value {
    let mut headers = Map::new();
    if resource_type != "document" {
        headers.insert("x-csrf-token".into(), json!(CSRF));
        headers.insert("authorization".into(), json!(PUBLIC_BEARER));
        let mut cookies = vec![format!("ct0={CSRF}")];
        cookies.extend(cookie.map(|c| c.to_string()));
        headers.insert("cookie".into(), json!(cookies.join("; ")));
        headers.insert("referer".into(), json!(format!("{}/", f.url)));
        if form.is_some() {
            headers.insert("content-type".into(), json!("application/x-www-form-urlencoded;charset=UTF-8"));
        }
    }
    let method = if form.is_some() { "POST" } else { "GET" };
    let url = format!("{}{path}", f.url);
    let client = reqwest::Client::new();
    let mut req = client.request(method.parse().unwrap(), &url);
    for (k, v) in &headers {
        req = req.header(k.as_str(), s(v));
    }
    if let Some(body) = form {
        req = req.body(body.to_string());
    }
    let res = req.send().await.expect("the fixture answers");
    let status = res.status().as_u16();
    let content_type = res.headers().get("content-type").map(|v| v.to_str().unwrap_or("").to_string()).unwrap_or_default();
    let body = res.text().await.unwrap();
    let mut request = json!({ "method": method, "url": url, "headers": headers });
    if let Some(form) = form {
        request["body"] = json!(form);
    }
    json!({
        "id": id,
        "resourceType": resource_type,
        "request": request,
        "response": { "status": status, "headers": {}, "contentType": content_type, "body": body },
    })
}

/// `{ ...e, request: { ...e.request, headers: { ...e.request.headers, [name]: value } } }`.
fn with_header(e: &Value, name: &str, value: &str) -> Value {
    let mut e = e.clone();
    e["request"]["headers"][name] = json!(value);
    e
}

/// The argv a shell hands the `api-anything ...` command a hint spells out.
fn shell_argv(hint: &str) -> Vec<String> {
    let command = re(r"api-anything (\S.*); then ").captures(hint).map(|c| c[1].to_string());
    let command = command.unwrap_or_else(|| panic!("no command in: {hint}"));
    let out = std::process::Command::new("sh").arg("-c").arg(format!("set -- {command}; printf '%s\\0' \"$@\"")).output().unwrap();
    assert!(out.status.success(), "sh: {}", String::from_utf8_lossy(&out.stderr));
    let words: Vec<String> = out.stdout.split(|b| *b == 0).filter(|w| !w.is_empty()).map(|w| String::from_utf8(w.to_vec()).unwrap()).collect();
    assert_eq!(words.first().map(|w| w.as_str()), Some("api-anything"), "{hint}");
    words[1..].to_vec()
}

/* ------------------------------------------------------ flags and command names */

fn step(action: &str) -> String {
    serde_json::to_string(&json!([{ "action": action, "selector": "#file", "value": "file.pdf" }])).unwrap()
}

#[tokio::test]
async fn a_flag_the_command_does_not_take_is_refused_naming_the_command_and_its_help() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    cli.plain_site(&f);
    let r = cli.run(&["call", "plain", "getUser", "name=carol", "--pick", "name", "--limit", "1"]).await;
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert_match!(s(&r.json()["error"]), r"^call .*--pick.*--limit");
    assert_match!(r.stderr, r"(?m)^next: api-anything call --help");

    // --steps belongs to capture and add: elsewhere it is not even parsed
    let steps = cli.run(&["call", "plain", "getUser", "name=carol", "--steps", "not json"]).await;
    assert_match!(s(&steps.json()["error"]), r"^call .*--steps");

    let own = cli.run(&["call", "plain", "getUser", "name=carol", "--max-tier", "1"]).await;
    assert_eq!(own.json()["data"], json!({ "name": "carol" }), "{}", own.stdout);
    assert_eq!(cli.run(&["call", "--limit", "1", "--help"]).await.code, 0, "--help still answers");
}

#[tokio::test]
async fn a_name_every_object_inherits_is_an_unknown_command_like_any_other() {
    let cli = Cli::new();
    let usage = cli.run(&["--help"]).await.stdout;
    for name in ["toString", "constructor"] {
        let r = cli.run(&[name]).await;
        assert_eq!(r.code, 1, "{name}");
        assert_eq!(r.stdout, usage, "{name}");
        assert_match!(r.stderr, &format!("^next: unknown command \"{name}\""), "{name}");
        assert_eq!(cli.run(&[name, "--help"]).await.stdout, usage, "{name} --help");
    }
}

#[tokio::test]
async fn a_step_steps_cannot_run_is_one_short_line_the_action_and_the_actions_there_are() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    cli.plain_site(&f);
    let list = format!("{}/list", f.url);
    let upload = cli.run(&["capture", &list, "--steps", &step("upload")]).await;
    assert_eq!(upload.code, 1);
    let said = s(&upload.json()["error"]);
    assert_match!(said, r#"^--steps: .*"upload""#);
    assert_match!(said, r"upload.*not supported");
    for action in ["click", "fill", "press", "wait", "goto"] {
        assert_match!(said, &format!(r"\b{action}\b"));
    }
    assert_no_match!(said, "\"code\"|\n", "one line, not the validator's report");

    let hover = s(&cli.run(&["add", "plain", "x", "--trigger", &list, "--steps", &step("hover")]).await.json()["error"]);
    assert_match!(hover, r#""hover".*\bclick\b"#);
    assert_no_match!(hover, "upload");

    // any other malformed step: what is wrong and where, on one line, not the validator's JSON report
    let typed = cli.run(&["capture", &list, "--steps", r#"[{"action":"click","selector":5}]"#]).await;
    assert_match!(s(&typed.json()["error"]), r"^--steps: [^{\[\n]* \[0\]\.selector$");
}

#[tokio::test]
async fn a_commands_help_names_the_output_fields_an_agent_has_to_act_on() {
    let cli = Cli::new();
    let named: [(&str, &[&str]); 3] = [("capture", &["blocked", "pageStatus"]), ("add", &["replaced"]), ("inspect", &["note"])];
    for (command, fields) in named {
        let help = cli.run(&[command, "--help"]).await.stdout;
        for field in fields {
            assert_match!(help, &format!(r"\b{field}\b"), "{command} --help: {field}");
        }
    }
}

#[tokio::test]
async fn a_malformed_json_flag_points_at_the_help_of_the_command_it_was_given_to() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    cli.plain_site(&f);
    let list = format!("{}/list", f.url);
    cli.seed("cflags", json!({ "url": list, "exchanges": [answered(&f, 1, "document", "/list", None, None).await] }));
    let hover = step("hover");
    let bad: [(&str, Vec<&str>); 4] = [
        ("capture", vec![&list, "--steps", r#"[{"action":"click","selector":5}]"#]),
        ("add", vec!["plain", "x", "--trigger", &list, "--steps", &hover]),
        ("call", vec!["plain", "getUser", "--json", r#"{"name":"#]),
        ("inspect", vec!["cflags", "1", "--html", r#"{"items":1}"#]),
    ];
    for (command, args) in bad {
        let mut argv = vec![command];
        argv.extend(args);
        let r = cli.run(&argv).await;
        assert_eq!(r.code, 1, "{command}");
        assert_match!(r.stderr, &format!("^next: api-anything {command} --help"), "{command}");
    }
    assert_match!(cli.run(&["add", "plain", "x", "--from", "c", "--match", "{"]).await.stderr, r"^next: api-anything add --help");
}

/* ------------------------------------------------------------------ inspect */

/// 1: the list page; 2: a user's JSON; 3: a user with no posts; 4: the list searched for nobody.
async fn seed_csaved(cli: &Cli, f: &Fixture) {
    let user = |id: u64, name: &str, posts: &[&str]| {
        let body = json!({ "data": { "user": { "name": name, "followers": 500, "posts": posts.iter().map(|text| json!({ "text": text })).collect::<Vec<_>>() } } });
        json!({
            "id": id,
            "resourceType": "fetch",
            "request": { "method": "GET", "url": format!("{}/", f.url), "headers": {} },
            "response": { "status": 200, "headers": {}, "contentType": "application/json", "body": serde_json::to_string(&body).unwrap() },
        })
    };
    cli.seed(
        "csaved",
        json!({
            "url": format!("{}/list", f.url),
            "exchanges": [
                answered(f, 1, "document", "/list", None, None).await,
                user(2, "alice", &["hello from alice"]),
                user(3, "dora", &[]),
                answered(f, 4, "document", "/list?q=nobody", None, None).await,
            ],
        }),
    );
}

async fn inspect(cli: &Cli, request: u64, flags: &[&str]) -> (Out, Value) {
    let id = request.to_string();
    let mut argv = vec!["inspect", "csaved", &id];
    argv.extend(flags);
    let r = cli.run(&argv).await;
    let out = r.json();
    (r, out)
}

#[tokio::test]
async fn it_takes_adds_recipe_flags_extract_or_path_and_pick_after_html_too() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_csaved(&cli, &f).await;
    assert_eq!(inspect(&cli, 2, &["--extract", "data.user", "--pick", "name"]).await.1["data"], json!({ "name": "alice" }));
    assert_eq!(inspect(&cli, 2, &["--path", "data.user.posts[0].text"]).await.1["data"], json!("hello from alice"));
    let recipe = r#"{"items":"li.user","fields":{"name":"a.name","followers":"span.followers"}}"#;
    assert_eq!(
        inspect(&cli, 1, &["--html", recipe, "--pick", "name"]).await.1["data"],
        json!([{ "name": "alice" }, { "name": "bob" }, { "name": "carol" }])
    );
}

#[tokio::test]
async fn a_path_or_selector_that_finds_nothing_fails_and_says_so_an_empty_list_at_a_path_is_a_result() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_csaved(&cli, &f).await;
    let next = r"(?m)^next: api-anything inspect csaved \d";
    let (path, out) = inspect(&cli, 2, &["--path", "data.wrong"]).await;
    assert_eq!(path.code, 1);
    assert_eq!(out["ok"], json!(false));
    assert_match!(s(&out["error"]), r"data\.wrong");
    assert_match!(path.stderr, next);

    let (selector, out) = inspect(&cli, 1, &["--html", r#"{"items":"li.nope","fields":{"name":"a"}}"#]).await;
    assert_eq!(selector.code, 1);
    assert_match!(s(&out["error"]), r"--html.*li\.nope");
    assert_match!(selector.stderr, next);

    let (regex, out) = inspect(&cli, 1, &["--embedded", r"window\.state = (\{)"]).await;
    assert_eq!(regex.code, 1);
    assert_match!(s(&out["error"]), "--embedded");

    // the page is not JSON: a path into it finds nothing, rather than printing the page
    assert_eq!(inspect(&cli, 1, &["--extract", "data.user"]).await.0.code, 1);

    let (empty, out) = inspect(&cli, 3, &["--extract", "data.user.posts"]).await;
    assert_eq!(empty.code, 0, "{}", empty.stdout);
    assert_eq!(out["data"], json!([]));
}

#[tokio::test]
async fn an_html_recipe_on_a_page_with_no_results_answers_empty_when_the_items_container_is_there_empty() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_csaved(&cli, &f).await;
    let (zero, out) = inspect(&cli, 4, &["--html", r#"{"items":"ul.users li.user","fields":{"name":"a.name"}}"#]).await;
    assert_eq!(zero.code, 0, "{}", zero.stdout);
    assert_eq!(out["data"], json!([]));
    assert_match!(s(&out["note"]), r"ul\.users.*empty");
    // the same page, a selector with no container to find: nothing tells no results from a wrong selector
    assert_eq!(inspect(&cli, 4, &["--html", r#"{"items":"li.user","fields":{"name":"a.name"}}"#]).await.0.code, 1);
}

/* -------------------------------------------------- add from a saved capture */

/// The steps that post a text on /compose.
fn steps(text: &str) -> Value {
    json!([
        { "action": "fill", "selector": "#text", "value": text },
        { "action": "click", "selector": "#post" },
    ])
}

fn post(f: &Fixture) -> String {
    format!("/api/graphql/{}/CreatePost", f.state().create_query_id)
}

fn posts(f: &Fixture) -> usize {
    let p = post(f);
    f.calls().iter().filter(|c| c.path == p).count()
}

/// calice, cbob: /u/<name>. Request 1 is the page, 2 the user's JSON. cpost: /compose captured with
/// --write. Request 2 is the POST the guard aborted, so it has no answer; 3 is a search the page also
/// POSTed, which went through and was answered.
async fn seed_add_captures(cli: &Cli, f: &Fixture) {
    for name in ["alice", "bob"] {
        let variables = encode_uri_component(&serde_json::to_string(&json!({ "name": name, "withExtras": true })).unwrap());
        cli.seed(
            &format!("c{name}"),
            json!({
                "url": format!("{}/u/{name}", f.url),
                "exchanges": [
                    answered(f, 1, "document", &format!("/u/{name}"), None, None).await,
                    answered(f, 2, "fetch", &format!("/api/graphql/{}/UserByName?variables={variables}", f.state().user_query_id), None, None).await,
                ],
            }),
        );
    }
    let search = serde_json::to_string(&json!([[["search", serde_json::to_string(&json!(["kittens", 10])).unwrap(), null, "generic"]]])).unwrap();
    cli.seed(
        "cpost",
        json!({
            "url": format!("{}/compose", f.url),
            "write": true,
            "steps": steps("hello alice"),
            "exchanges": [
                answered(f, 1, "document", "/compose", None, None).await,
                {
                    "id": 2,
                    "resourceType": "fetch",
                    "request": {
                        "method": "POST",
                        "url": format!("{}{}", f.url, post(f)),
                        "headers": { "x-csrf-token": CSRF, "authorization": PUBLIC_BEARER, "content-type": "application/json" },
                        "body": serde_json::to_string(&json!({ "variables": { "text": "hello alice" }, "queryId": f.state().create_query_id })).unwrap(),
                    },
                    "aborted": true,
                },
                answered(f, 3, "xhr", "/api/rpc?rpcids=search", None, Some(&format!("f.req={}", encode_uri_component(&search)))).await,
            ],
        }),
    );
}

/// add fixture <op> from the capture of that user's page; `flags` are split on spaces.
async fn add(cli: &Cli, op: &str, from: &str, flags: &str) -> (Out, Value) {
    let capture = format!("c{from}");
    let mut argv = vec!["add", "fixture", op, "--from", &capture, "--pick-request", "2"];
    argv.extend(flags.split(' '));
    let r = cli.run(&argv).await;
    let out = r.json();
    (r, out)
}

async fn carol(cli: &Cli, op: &str) -> Value {
    cli.run(&["call", "fixture", op, "name=carol"]).await.json()["data"].clone()
}

#[tokio::test]
async fn example2_with_from_and_no_from2_is_refused_and_the_way_it_says_to_go_works() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    let (r, out) = add(&cli, "twice", "alice", "--example name=alice --example2 name=bob").await;
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert_match!(s(&out["error"]), r"--example2 .*--from2");
    assert_eq!(shell_argv(&r.stderr), vec!["capture", &format!("{}/u/bob", f.url), "--example", "name=bob"]);
    assert_match!(r.stderr, "--from2");
    assert_eq!(cli.run(&["ops", "fixture"]).await.code, 1, "nothing was saved");

    let (both, out) = add(&cli, "twice", "alice", "--example name=alice --from2 cbob --example2 name=bob").await;
    assert_eq!(both.code, 0, "{}", both.stdout);
    assert_no_match!(joined(&out["warnings"]), "one example", "the two captures were diffed");
}

#[tokio::test]
async fn the_capture_that_refusal_asks_for_repeats_how_the_first_was_made_write_steps_quoting() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    let refused = |capture: &'static str, flags: Vec<String>| {
        let cli = &cli;
        async move {
            let mut argv = vec!["add", "demo", "send", "--from", capture];
            argv.extend(flags.iter().map(|s| s.as_str()));
            let r = cli.run(&argv).await;
            assert_eq!(r.code, 1, "{}", r.stdout);
            r.stderr
        }
    };
    let flags = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    // a write captured with --write: type the text, click Post
    cli.seed("cwrite", json!({ "url": format!("{}/compose", f.url), "write": true, "steps": steps("hello alice"), "exchanges": [] }));
    assert_eq!(
        shell_argv(&refused("cwrite", flags(&["--write", "--example", "text=hello alice", "--example2", "text=hello bob"])).await),
        vec![
            "capture".to_string(),
            format!("{}/compose", f.url),
            "--steps".to_string(),
            serde_json::to_string(&steps("hello bob")).unwrap(),
            "--write".to_string(),
            "--example".to_string(),
            "text=hello bob".to_string(),
        ]
    );

    // the value in the URL, a soft navigation, and a quote for the shell to trip on
    cli.seed("csoft", json!({ "url": format!("{}/spa/alice?tab=posts", f.url), "softFrom": format!("{}/spa/home", f.url), "exchanges": [] }));
    assert_eq!(
        shell_argv(&refused("csoft", flags(&["--example", "name=alice", "--example2", "name=bob o'neil"])).await),
        vec![
            "capture".to_string(),
            format!("{}/spa/bob%20o'neil?tab=posts", f.url),
            "--soft-from".to_string(),
            format!("{}/spa/home", f.url),
            "--example".to_string(),
            "name=bob o'neil".to_string(),
        ]
    );

    // the first example is nowhere in the capture's url or steps: no command, rather than a wrong one
    cli.seed("cfeed", json!({ "url": format!("{}/feed", f.url), "write": true, "exchanges": [] }));
    let words = refused("cfeed", flags(&["--example", "name=alice", "--example2", "name=bob"])).await;
    assert_no_match!(words, "api-anything capture");
    assert_match!(words, "--write");
    assert_match!(words, "--from2");
}

#[tokio::test]
async fn a_recipe_is_fixed_by_adding_the_op_again_from_its_capture_the_stored_examples_stand_in_for_example() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    let (_, wrong) = add(&cli, "getUser", "alice", "--example name=alice --extract data.wrong").await;
    assert_eq!(wrong["params"], json!(["name:string"]));
    assert_match!(joined(&wrong["warnings"]), "add --from calice");

    // that advice, followed: no example and no --pick-request, and the stored example finds the request
    let r = cli.run(&["add", "fixture", "getUser", "--from", "calice", "--extract", "data.user", "--pick", "name"]).await;
    let fixed = r.json();
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(fixed["replaced"], json!(true));
    assert_eq!(fixed["params"], json!(["name:string"]), "the param is not dropped");
    assert_eq!(fixed["preview"], json!({ "first": { "name": "alice" } }));
    assert_eq!(carol(&cli, "getUser").await, json!({ "name": "carol" }));

    // the new recipe is judged on the captured answer, as add judges one
    let (_, still) = add(&cli, "getUser", "alice", "--extract data.nope").await;
    assert!(still.get("preview").is_none(), "{still}");
    assert_match!(joined(&still["warnings"]), r"data\.nope.*add --from calice");

    // a flag that shapes the request needs no example either
    let (pinned, out) = add(&cli, "getUser", "alice", "--match path=/api/graphql/*/UserByName --extract data.user --pick name").await;
    assert_eq!(pinned.code, 0, "{}", pinned.stdout);
    assert_eq!(out["params"], json!(["name:string"]));
    assert_eq!(carol(&cli, "getUser").await, json!({ "name": "carol" }));

    // another request of the capture carries the example somewhere else (the page's own URL): the op is
    // not quietly re-bound to it
    let page = cli.run(&["add", "fixture", "getUser", "--from", "calice", "--pick-request", "1"]).await;
    assert_eq!(page.code, 1, "{}", page.stdout);
    assert_match!(s(&page.json()["error"]), r"other places.*stored ones were used \(name=alice\).*--example");
    assert_eq!(carol(&cli, "getUser").await, json!({ "name": "carol" }), "the op is as it was");
}

#[tokio::test]
async fn a_capture_made_with_other_values_is_not_learned_with_the_stored_ones_a_value_that_sits_elsewhere_binds_nothing() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    add(&cli, "viewed", "alice", "--example name=alice --extract data.user --pick name").await;
    // bob's page, where the stored example (alice) is the viewer in the same request
    let variables = encode_uri_component(&serde_json::to_string(&json!({ "name": "bob", "withExtras": true })).unwrap());
    cli.seed(
        "cviewer",
        json!({
            "url": format!("{}/u/bob", f.url),
            "exchanges": [
                answered(&f, 1, "document", "/u/bob", None, None).await,
                answered(&f, 2, "fetch", &format!("/api/graphql/{}/UserByName?variables={variables}&viewer=alice", f.state().user_query_id), None, None).await,
            ],
        }),
    );
    let (refused, out) = add(&cli, "viewed", "viewer", "--extract data.user --pick name,followers").await;
    assert_eq!(refused.code, 1, "{}", refused.stdout);
    assert_match!(s(&out["error"]), r"other places.*stored ones were used \(name=alice\).*--example");
    assert_eq!(carol(&cli, "viewed").await, json!({ "name": "carol" }), "the op is as it was");
    // with the values the capture was made with, it is learned from it
    let (_, learned) = add(&cli, "viewed", "viewer", "--example name=bob --extract data.user --pick name,followers").await;
    assert_eq!(learned["preview"], json!({ "first": { "name": "bob", "followers": 300 } }));
    assert_eq!(carol(&cli, "viewed").await, json!({ "name": "carol", "followers": 500 }), "name fills the user asked for");
}

#[tokio::test]
async fn description_alone_changes_the_description_with_no_recipe_flag_the_stored_recipe_stands() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    add(&cli, "described", "alice", "--example name=alice --extract data.user --pick name").await;
    let r = cli.run(&["add", "fixture", "described", "--from", "calice", "--description", "A user's name"]).await;
    let out = r.json();
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(out["replaced"], json!(true));
    assert_eq!(carol(&cli, "described").await, json!({ "name": "carol" }), "extract and pick are still there");
    let ops = cli.run(&["ops", "fixture"]).await.json()["operations"].clone();
    let described = ops.as_array().unwrap().iter().find(|o| o["name"] == json!("described")).unwrap().clone();
    assert_eq!(described["description"], json!("A user's name"));

    // an empty one clears it, and still leaves the recipe alone
    let cleared = cli.run(&["add", "fixture", "described", "--from", "calice", "--description", ""]).await;
    assert_eq!(cleared.code, 0, "{}", cleared.stdout);
    assert_eq!(carol(&cli, "described").await, json!({ "name": "carol" }), "extract and pick are still there");
    let after = cli.run(&["ops", "fixture"]).await.json()["operations"].clone();
    let described = after.as_array().unwrap().iter().find(|o| o["name"] == json!("described")).unwrap().clone();
    assert!(described.get("description").is_none(), "{described}");
}

#[tokio::test]
async fn an_op_with_no_stored_example_is_not_learned_again_without_one_its_params_are_not_dropped() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    add(&cli, "bare", "alice", "--example name=alice --extract data.wrong").await;
    // a shared spec is exported without its example values
    let file = cli.sites_file("fixture");
    let mut spec: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    for op in spec["operations"].as_array_mut().unwrap() {
        for p in op["params"].as_array_mut().unwrap() {
            p.as_object_mut().unwrap().remove("example");
        }
    }
    fs::write(&file, serde_json::to_string(&spec).unwrap()).unwrap();

    let (refused, out) = add(&cli, "bare", "alice", "--extract data.user --pick name").await;
    assert_eq!(refused.code, 1, "{}", refused.stdout);
    assert_match!(s(&out["error"]), r"no stored example for name.*--example.*calice");
    let (_, fixed) = add(&cli, "bare", "alice", "--example name=alice --extract data.user --pick name").await;
    assert_eq!(fixed["params"], json!(["name:string"]));
    assert_eq!(carol(&cli, "bare").await, json!({ "name": "carol" }));
}

/// `add fixture <op> <flags...>`, flags verbatim.
async fn add_fixture(cli: &Cli, op: &str, flags: &[&str]) -> (Out, Value) {
    let mut argv = vec!["add", "fixture", op];
    argv.extend(flags);
    let r = cli.run(&argv).await;
    let out = r.json();
    (r, out)
}

#[tokio::test]
async fn an_op_added_again_is_scanned_for_credentials_as_any_add_is_the_captures_cookies_and_tokens_count() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    // /api/mine keys its answer by the session cookie's value, "guest" without one
    const SESSION: &str = "cookie-value-new-session";
    let mine = |id: &'static str, session: Option<&'static str>| {
        let (cli, f) = (&cli, &f);
        async move {
            let cookies = match session {
                Some(s) => {
                    let mut c = jar();
                    c.push(cookie_like(json!({ "name": "session", "value": s })));
                    c
                }
                None => jar(),
            };
            let cookie = session.map(|s| format!("session={s}"));
            cli.seed(
                id,
                json!({
                    "url": format!("{}/mine?name=alice", f.url),
                    "cookies": cookies,
                    "exchanges": [answered(f, 1, "fetch", "/api/mine?name=alice", cookie.as_deref(), None).await],
                }),
            );
        }
    };
    mine("cguest", None).await;
    let (learned, out) = add_fixture(&cli, "mine", &["--from", "cguest", "--pick-request", "1", "--example", "name=alice"]).await;
    assert_match!(s(&out["extract"]), "^guest", "{}", learned.stdout);

    // the same request captured signed in: an extract through the cookie's value is refused, typed or suggested
    mine("csigned", Some(SESSION)).await;
    let (typed, out) = add_fixture(&cli, "mine", &["--from", "csigned", "--extract", &format!("{SESSION}[0]")]).await;
    assert_eq!(typed.code, 1, "{}", typed.stdout);
    assert_match!(s(&out["error"]), "credential");
    let (suggested, out) = add_fixture(&cli, "mine2", &["--from", "csigned", "--pick-request", "1", "--example", "name=alice"]).await;
    assert_eq!(suggested.code, 1, "{}", suggested.stdout);
    assert_match!(s(&out["error"]), "credential");
    assert_no_match!(cli.read("sites/fixture.json"), SESSION);

    // a credential the captured request carries in a header the op has no slot for counts too
    const TOKEN: &str = "NewPrivateSession9876543210";
    let guest = answered(&f, 1, "fetch", "/api/mine?name=alice", None, None).await;
    cli.seed("cheader", json!({ "url": format!("{}/mine?name=alice", f.url), "exchanges": [with_header(&guest, "x-auth-token", TOKEN)] }));
    let (header, out) = add_fixture(&cli, "mine", &["--from", "cheader", "--extract", TOKEN]).await;
    assert_eq!(header.code, 1, "{}", header.stdout);
    assert_match!(s(&out["error"]), "credential");
    // so does a description that names it, though nothing else changes
    let (named, out) = add_fixture(&cli, "mine", &["--from", "cheader", "--description", &format!("the session {TOKEN}")]).await;
    assert_eq!(named.code, 1, "{}", named.stdout);
    assert_match!(s(&out["error"]), "credential");
    // and a random-looking value under an ordinary header name that the page also keeps in storage
    const OPAQUE: &str = "Zq7RandomOpaque0192837465abc";
    cli.seed(
        "copaque",
        json!({ "url": format!("{}/mine?name=alice", f.url), "storage": { "opaque": OPAQUE }, "exchanges": [with_header(&guest, "x-opaque", OPAQUE)] }),
    );
    let (opaque, out) = add_fixture(&cli, "mine", &["--from", "copaque", "--extract", OPAQUE]).await;
    assert_eq!(opaque.code, 1, "{}", opaque.stdout);
    assert_match!(s(&out["error"]), "credential");
    // and a short token the page keeps inside a JSON entry of its storage
    const SHORT: &str = "abcd1234";
    cli.seed(
        "cnested",
        json!({
            "url": format!("{}/mine?name=alice", f.url),
            "storage": { "auth": serde_json::to_string(&json!({ "access_token": SHORT })).unwrap() },
            "exchanges": [with_header(&guest, "x-opaque", SHORT)],
        }),
    );
    let session_short = format!("session {SHORT}");
    for flags in [vec!["--extract", SHORT], vec!["--description", &session_short]] {
        let mut argv = vec!["--from", "cnested"];
        argv.extend(flags);
        let (nested, out) = add_fixture(&cli, "mine", &argv).await;
        assert_eq!(nested.code, 1, "{}", nested.stdout);
        assert_match!(s(&out["error"]), "credential");
    }
    for secret in [TOKEN, OPAQUE, SHORT] {
        assert_no_match!(cli.read("sites/fixture.json"), secret);
    }
}

#[tokio::test]
async fn a_recipe_may_name_a_random_looking_value_that_is_not_a_credential_a_build_id_the_response_is_keyed_by() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    const BUILD: &str = "R7q8Ab9Cd0Ef1Gh2Ij3Kl4Mn";
    let guest = answered(&f, 1, "fetch", "/api/mine?name=alice", None, None).await;
    let mut keyed = with_header(&guest, "x-build", BUILD);
    keyed["response"]["body"] = json!(serde_json::to_string(&json!({ BUILD: [{ "name": "alice" }] })).unwrap());
    cli.seed("cbuild", json!({ "url": format!("{}/mine?name=alice", f.url), "exchanges": [keyed] }));
    let add = |flags: Vec<&'static str>| {
        let cli = &cli;
        async move {
            let mut argv = vec!["--from", "cbuild"];
            argv.extend(flags);
            add_fixture(cli, "built", &argv).await
        }
    };
    assert_eq!(add(vec!["--pick-request", "1", "--example", "name=alice"]).await.0.code, 0);
    let (repaired, out) = add(vec!["--extract", BUILD]).await;
    assert_eq!(repaired.code, 0, "{}", repaired.stdout);
    assert_eq!(out["replaced"], json!(true));
}

#[tokio::test]
async fn an_op_added_again_is_not_refused_for_its_own_example_however_much_it_looks_like_a_key() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    // a public object id passed as the param: random-looking, and under a name that reads like a credential's
    const KEY: &str = "PublicObjectAbc12345";
    cli.seed(
        "cobject",
        json!({ "url": format!("{}/mine?name={KEY}", f.url), "exchanges": [answered(&f, 1, "fetch", &format!("/api/mine?name={KEY}"), None, None).await] }),
    );
    let example = format!("name={KEY}");
    let (learned, _) = add_fixture(&cli, "object", &["--from", "cobject", "--pick-request", "1", "--example", &example]).await;
    assert_eq!(learned.code, 0, "{}", learned.stdout);
    let (repaired, out) = add_fixture(&cli, "object", &["--from", "cobject", "--extract", "guest", "--pick", "name"]).await;
    assert_eq!(repaired.code, 0, "{}", repaired.stdout);
    assert_eq!(out["replaced"], json!(true));
}

/* ------------------- an op added again from a capture is checked as any add is */

/// A request no page of the fixture sends, and an answer for it: only what add does with the capture is under test.
fn lookup(f: &Fixture, path: &str, body: Option<&str>) -> Value {
    let mut request = json!({
        "method": if body.is_some() { "POST" } else { "GET" },
        "url": format!("{}{path}", f.url),
        "headers": if body.is_some() { json!({ "content-type": "application/json" }) } else { json!({}) },
    });
    if let Some(b) = body {
        request["body"] = json!(b);
    }
    json!({
        "id": 1,
        "resourceType": "fetch",
        "request": request,
        "response": { "status": 200, "headers": {}, "contentType": "application/json", "body": r#"{"data":[{"name":"alice"}]}"# },
    })
}

/// `add fixture <op> --from <from> --pick-request 1 <flags...>`.
async fn add_from(cli: &Cli, op: &str, from: &str, flags: &[&str]) -> (Out, Value) {
    let mut argv = vec!["--from", from, "--pick-request", "1"];
    argv.extend(flags);
    add_fixture(cli, op, &argv).await
}

fn saved(cli: &Cli) -> String {
    cli.read("sites/fixture.json")
}

#[tokio::test]
async fn every_credential_in_the_request_counts_two_that_would_take_one_refs_name_included() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    let (old, query, body) = ("OldPrivateTokenAbc12345", "QueryPrivateTokenBcd23456", "BodyPrivateTokenCde34567");
    cli.seed(
        "ctoken",
        json!({ "url": format!("{}/page", f.url), "exchanges": [lookup(&f, "/api/lookup?name=alice", Some(&serde_json::to_string(&json!({ "token": old })).unwrap()))] }),
    );
    assert_eq!(add_from(&cli, "lookup", "ctoken", &["--example", "name=alice", "--extract", "data"]).await.0.code, 0);
    // the same op's request, now with a second token in the query: the body's is the ref the op already has
    let path = format!("/api/lookup?name=alice&token={query}");
    cli.seed(
        "ctokens",
        json!({ "url": format!("{}/page", f.url), "exchanges": [lookup(&f, &path, Some(&serde_json::to_string(&json!({ "token": body })).unwrap()))] }),
    );
    for token in [query, body] {
        let (named, out) = add_from(&cli, "lookup", "ctokens", &["--description", &format!("session {token}")]).await;
        assert_eq!(named.code, 1, "{}", named.stdout);
        assert_match!(s(&out["error"]), "credential");
    }
    for token in [old, query, body] {
        assert_no_match!(saved(&cli), token);
    }
}

#[tokio::test]
async fn a_request_the_learner_cannot_place_the_examples_in_is_refused_and_what_it_holds_is_not_saved() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    const SHORT: &str = "abcd1234";
    cli.seed("cnamed", json!({ "url": format!("{}/page", f.url), "exchanges": [lookup(&f, "/api/named?name=alice", None)] }));
    assert_eq!(add_from(&cli, "named", "cnamed", &["--example", "name=alice", "--extract", "data"]).await.0.code, 0);
    // an empty query key is a position no slot can name, and its value is a token the page stores
    cli.seed(
        "cnokey",
        json!({
            "url": format!("{}/page", f.url),
            "storage": { "auth": serde_json::to_string(&json!({ "access_token": SHORT })).unwrap() },
            "exchanges": [lookup(&f, &format!("/api/named?={SHORT}"), None)],
        }),
    );
    let (named, _) = add_from(&cli, "named", "cnokey", &["--description", &format!("session {SHORT}")]).await;
    assert_eq!(named.code, 1, "{}", named.stdout);
    assert_no_match!(saved(&cli), SHORT);
}

#[tokio::test]
async fn what_the_op_holds_public_was_said_of_the_value_it_was_learned_with_not_of_another_sent_in_its_place() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    let (shipped, private) = ("PublicStaticApiKeyAbc12345", "PrivateRuntimeApiKeyZyx98765");
    let keyed = |key: &str| {
        let mut e = lookup(&f, "/api/shipped?name=alice", None);
        e["id"] = json!(2);
        e["request"]["headers"] = json!({ "x-api-key": key });
        e
    };
    // the site's own script ships the first key to every visitor, so the learner leaves it in the request
    let script = json!({
        "id": 1,
        "resourceType": "script",
        "request": { "method": "GET", "url": format!("{}/app.js", f.url), "headers": {} },
        "response": {
            "status": 200,
            "headers": { "cache-control": "public" },
            "contentType": "application/javascript",
            "body": format!("const key=\"{shipped}\";"),
        },
    });
    cli.seed("cshipped", json!({ "url": format!("{}/page", f.url), "cookies": [], "exchanges": [script, keyed(shipped)] }));
    let first = cli.run(&["add", "fixture", "shipped", "--from", "cshipped", "--pick-request", "2", "--example", "name=alice", "--extract", "data"]).await;
    assert_eq!(first.code, 0, "{}", first.stdout);
    let op = || {
        let spec: Value = serde_json::from_str(&saved(&cli)).unwrap();
        spec["operations"].as_array().unwrap().iter().find(|o| o["name"] == json!("shipped")).unwrap().clone()
    };
    assert_eq!(op()["public"], json!(["x-api-key"]));
    // a later capture sends another key there, and no script ships it
    cli.seed("cprivate", json!({ "url": format!("{}/page", f.url), "cookies": [], "exchanges": [keyed(private)] }));
    for flags in [vec!["--description", private], vec!["--extract", "data", "--pick", private]] {
        let mut argv = vec!["add", "fixture", "shipped", "--from", "cprivate", "--pick-request", "2"];
        argv.extend(flags);
        let r = cli.run(&argv).await;
        assert_eq!(r.code, 1, "{}", r.stdout);
        assert_match!(s(&r.json()["error"]), "credential");
    }
    assert_no_match!(saved(&cli), private);
}

#[tokio::test]
async fn a_value_the_session_store_still_holds_is_a_credential_though_the_ops_ref_has_moved_on_to_another() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    let (first, rotated) = ("OriginalStoredSecretAbc12345", "RotatedStoredSecretZyx98765");
    let opaque = |value: &str| with_header(&lookup(&f, "/api/rotated?name=alice", None), "x-opaque", value);
    cli.seed("cfirst", json!({ "url": format!("{}/page", f.url), "cookies": [], "storage": { "oldStorage": first }, "exchanges": [opaque(first)] }));
    assert_eq!(add_from(&cli, "rotated", "cfirst", &["--example", "name=alice", "--extract", "data"]).await.0.code, 0);
    // the page now keeps another value under another key, and sends that one
    cli.seed("csecond", json!({ "url": format!("{}/page", f.url), "cookies": [], "storage": { "newStorage": rotated }, "exchanges": [opaque(rotated)] }));
    for secret in [first, rotated] {
        for flags in [vec!["--description", secret], vec!["--extract", "data", "--pick", secret]] {
            let (r, out) = add_from(&cli, "rotated", "csecond", &flags).await;
            assert_eq!(r.code, 1, "{}", r.stdout);
            assert_match!(s(&out["error"]), "credential");
        }
    }
    for secret in [first, rotated] {
        assert_no_match!(saved(&cli), secret);
    }
}

#[tokio::test]
async fn adding_an_op_again_keeps_the_session_its_capture_shows_the_next_call_sends_the_new_login() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    let jar_with = |session: &str| {
        let mut c = jar();
        c.push(cookie_like(json!({ "name": "session", "value": session, "httpOnly": true })));
        c
    };
    let signed_in = |session: String| {
        let f = &f;
        let jar_with = &jar_with;
        async move {
            json!({
                "url": format!("{}/private", f.url),
                "cookies": jar_with(&session),
                "exchanges": [answered(f, 1, "fetch", "/private", Some(&format!("session={session}")), None).await],
            })
        }
    };
    let first = f.mint_session();
    cli.seed("clogin", signed_in(first).await);
    assert_eq!(add_from(&cli, "private", "clogin", &["--extract", "data"]).await.0.code, 0);
    let call = || async { cli.run(&["call", "fixture", "private", "--max-tier", "1"]).await.json() };
    assert_eq!(call().await["ok"], json!(true));
    // the site signs the stored session out, the user signs in again, and the next capture is made with the new one
    let stored_login = || -> String {
        let session: Value = serde_json::from_str(&cli.read("sessions/fixture.json")).unwrap();
        s(&session["cookies"].as_array().unwrap().iter().find(|c| c["name"] == json!("session")).unwrap()["value"])
    };
    for flags in [vec!["--description", "the signed-in page"], vec!["--extract", "data", "--pick", "secret"]] {
        f.revoke(&stored_login());
        assert_eq!(call().await["class"], json!("auth"), "the stored login is signed out");
        cli.seed("crelogin", signed_in(f.mint_session()).await);
        assert_eq!(add_from(&cli, "private", "crelogin", &flags).await.0.code, 0);
        let after = call().await;
        assert_eq!(after["ok"], json!(true), "{after}");
    }
}

#[tokio::test]
async fn adding_an_op_again_from_its_own_request_refreshes_the_session_value_its_ref_reads() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    let (first, next) = ("FirstOpaqueValueAbc12345", "NextOpaqueValueBcd23456");
    let opaque = |value: &str| with_header(&lookup(&f, "/api/reffed?name=alice", None), "x-opaque", value);
    let stored = || -> Vec<String> {
        let session: Value = serde_json::from_str(&cli.read("sessions/fixture.json")).unwrap();
        session["values"].as_object().unwrap().values().map(s).collect()
    };
    cli.seed("cref", json!({ "url": format!("{}/page", f.url), "cookies": [], "storage": { "opaque": first }, "exchanges": [opaque(first)] }));
    assert_eq!(add_from(&cli, "reffed", "cref", &["--example", "name=alice", "--extract", "data"]).await.0.code, 0);
    assert!(stored().iter().any(|v| v == first));
    // the same request, sending the value the page holds now
    cli.seed("cref2", json!({ "url": format!("{}/page", f.url), "cookies": [], "storage": { "opaque": next }, "exchanges": [opaque(next)] }));
    assert_eq!(add_from(&cli, "reffed", "cref2", &["--extract", "data", "--pick", "name"]).await.0.code, 0);
    assert!(stored().iter().any(|v| v == next) && !stored().iter().any(|v| v == first), "the ref now holds what the request sent");
    for value in [first, next] {
        assert_no_match!(saved(&cli), value);
    }
}

#[tokio::test]
async fn a_description_is_not_saved_from_a_capture_that_holds_no_request_of_the_op_nothing_says_what_is_secret_in_it() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    const TOKEN: &str = "OtherEndpointTokenAbc12345";
    cli.seed("cbase", json!({ "url": format!("{}/page", f.url), "exchanges": [lookup(&f, "/api/base?name=alice", None)] }));
    assert_eq!(add_from(&cli, "base", "cbase", &["--example", "name=alice", "--extract", "data"]).await.0.code, 0);
    cli.seed("celse", json!({ "url": format!("{}/page", f.url), "exchanges": [lookup(&f, &format!("/api/other?token={TOKEN}"), None)] }));
    let r = cli.run(&["add", "fixture", "base", "--from", "celse", "--description", TOKEN]).await;
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert_match!(s(&r.json()["error"]), r"no captured request carries the example values.*stored ones were used \(name=alice\)");
    assert_no_match!(saved(&cli), TOKEN);
}

#[tokio::test]
async fn a_param_under_a_credentials_name_stays_a_param_the_stored_example_says_so() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    const KEY: &str = "PublicObjectAbc12345";
    cli.seed("ckeyed", json!({ "url": format!("{}/page", f.url), "exchanges": [lookup(&f, &format!("/api/keyed?api_key={KEY}"), None)] }));
    let (learned, _) = add_from(&cli, "keyed", "ckeyed", &["--example", &format!("key={KEY}"), "--extract", "data"]).await;
    assert_eq!(learned.code, 0, "{}", learned.stdout);
    // learned with no example that value would be called a credential; the stored example says it is the param
    let (repaired, out) = add_from(&cli, "keyed", "ckeyed", &["--extract", "data", "--pick", "name"]).await;
    assert_eq!(repaired.code, 0, "{}", repaired.stdout);
    assert_eq!(out["replaced"], json!(true));
    let spec: Value = serde_json::from_str(&saved(&cli)).unwrap();
    let keyed = spec["operations"].as_array().unwrap().iter().find(|o| o["name"] == json!("keyed")).unwrap();
    assert_eq!(keyed["params"].as_array().unwrap().iter().map(|p| p["name"].clone()).collect::<Vec<_>>(), vec![json!("key")]);
}

#[tokio::test]
async fn a_request_a_write_capture_aborted_is_learned_as_a_write_or_not_at_all_whatever_its_name() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    let add = |op: &'static str, request: &'static str, example: &'static str| {
        let cli = &cli;
        async move {
            let r = cli.run(&["add", "demo", op, "--from", "cpost", "--pick-request", request, "--example", example]).await;
            let out = r.json();
            (r, out)
        }
    };
    // no op of that name yet, so nothing but the capture says it is a write
    let (fresh, out) = add("post", "2", "text=hello alice").await;
    assert_eq!(fresh.code, 1, "{}", fresh.stdout);
    assert_match!(s(&out["error"]), r"intercepted.*--write");
    assert_eq!(cli.run(&["ops", "demo"]).await.code, 1, "nothing was saved");

    // the method alone says nothing: a POST the same capture let through, and answered, is a read
    let (search, out) = add("search", "3", "q=kittens").await;
    assert_eq!(search.code, 0, "{}", search.stdout);
    assert_eq!(out["readOnly"], json!(true));
    assert_eq!(posts(&f), 0, "no POST reached the site");

    // as the second capture of a pair, the request the diff reads from it decides, not how it was captured:
    // the answered search is a read there too
    let pair = cli
        .run(&["add", "demo", "search2", "--from", "cpost", "--pick-request", "3", "--example", "q=kittens", "--from2", "cpost", "--example2", "q=kittens"])
        .await;
    assert_eq!(pair.code, 0, "{}", pair.stdout);
    assert_eq!(pair.json()["readOnly"], json!(true));
    // but a request it intercepted is a write there, whatever the first capture shows
    let first: Value = serde_json::from_str(&cli.read("captures/cpost.json")).unwrap();
    let sent: Vec<Value> = first["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            if e["id"] == json!(2) {
                let mut e = e.clone();
                e.as_object_mut().unwrap().remove("aborted");
                e["response"] = json!({ "status": 200, "headers": {}, "contentType": "application/json", "body": r#"{"data":{"ok":true}}"# });
                e
            } else {
                e.clone()
            }
        })
        .collect();
    cli.seed("csent", json!({ "url": first["url"], "steps": first["steps"], "exchanges": sent }));
    let held = cli
        .run(&["add", "demo", "post2", "--from", "csent", "--pick-request", "2", "--example", "text=hello alice", "--from2", "cpost", "--example2", "text=hello alice"])
        .await;
    assert_eq!(held.code, 1, "{}", held.stdout);
    assert_match!(s(&held.json()["error"]), r"cpost .*intercepted request 2 as a write.*--write");
    // and one it intercepted that the diff does not read decides nothing: the answered search is read,
    // a search with other args that was held back is beside the point
    let form = |q: &str| format!("f.req={}", encode_uri_component(&serde_json::to_string(&json!([[["search", serde_json::to_string(&json!([q, 10])).unwrap(), null, "generic"]]])).unwrap()));
    let mut other = answered(&f, 2, "xhr", "/api/rpc?rpcids=search", None, Some(&form("unrelated"))).await;
    other.as_object_mut().unwrap().remove("response");
    other["aborted"] = json!(true);
    cli.seed(
        "cpups",
        json!({
            "url": format!("{}/compose", f.url),
            "write": true,
            "exchanges": [answered(&f, 1, "xhr", "/api/rpc?rpcids=search", None, Some(&form("puppies"))).await, other],
        }),
    );
    let beside = cli
        .run(&["add", "demo", "search3", "--from", "cpost", "--pick-request", "3", "--example", "q=kittens", "--from2", "cpups", "--example2", "q=puppies"])
        .await;
    assert_eq!(beside.code, 0, "{}", beside.stdout);
    assert_eq!(beside.json()["readOnly"], json!(true));
    assert_eq!(posts(&f), 0, "no POST reached the site");
}

#[tokio::test]
async fn a_write_stays_a_write_learning_it_again_to_fix_its_recipe_too_is_refused_without_write() {
    let f = Fixture::start().await;
    let cli = Cli::new();
    seed_add_captures(&cli, &f).await;
    let send = |flags: Vec<&'static str>| {
        let cli = &cli;
        async move {
            let mut argv = vec!["add", "demo", "send", "--from", "cpost"];
            argv.extend(flags);
            let r = cli.run(&argv).await;
            let out = r.json();
            (r, out)
        }
    };
    let (learned, out) = send(vec!["--write", "--example", "text=hello alice"]).await;
    assert_eq!(out["readOnly"], json!(false), "{}", learned.stdout);

    // fixing its recipe is learning it again: without --write that is refused, with it the op stays a write
    let (bare, out) = send(vec!["--extract", "data.create_post"]).await;
    assert_eq!(bare.code, 1, "{}", bare.stdout);
    assert_match!(s(&out["error"]), r"is a write.*--write");
    let (fixed, out) = send(vec!["--write", "--extract", "data.create_post"]).await;
    assert_eq!(fixed.code, 0, "{}", fixed.stdout);
    assert_eq!(out["readOnly"], json!(false));
    assert_eq!(out["params"], json!(["text:string"]), "the stored example stood in");
    let refused = cli.run(&["call", "demo", "send", "text=never asked for"]).await.json();
    assert_eq!(refused["class"], json!("refused"), "{refused}");

    // with --example it is learned again, and without --write that would save it as a read
    let (relearn, out) = send(vec!["--pick-request", "2", "--example", "text=hello alice"]).await;
    assert_eq!(relearn.code, 1, "{}", relearn.stdout);
    assert_match!(s(&out["error"]), "--write");
    assert_match!(cli.run(&["ops", "demo"]).await.stdout, r#""readOnly":false"#);
    // nor under a name that differs only in case, which is no existing op's
    let cased = cli.run(&["add", "demo", "SEND", "--from", "cpost", "--pick-request", "2", "--example", "text=hello alice"]).await;
    assert_eq!(cased.code, 1, "{}", cased.stdout);
    assert_no_match!(cli.run(&["ops", "demo"]).await.stdout, r#""SEND""#);
    // by its trigger too: refused before any browser runs it unintercepted
    // SAFETY: the only in-process read of API_ANYTHING_HOME in this test binary is the add_operation below
    unsafe { std::env::set_var("API_ANYTHING_HOME", cli.home()) };
    let again = AddInput {
        site: "demo".into(),
        op: "send".into(),
        trigger: Some(Trigger { url: format!("{}/compose", f.url), steps: Some(serde_json::from_value(steps("{text}")).unwrap()), soft_from: None }),
        examples: vec![common::args(json!({ "text": "hello alice" }))],
        matcher: None,
        write: false,
        description: None,
        response: None,
        public: None,
        from: None,
        from2: None,
        fetcher: None,
    };
    let err = add_operation(again).await.err().expect("refused");
    assert_match!(err.to_string(), "--write");
    assert_eq!(posts(&f), 0, "no POST reached the site");
}

/* -------------------------------------------------------- capture's next hint */

async fn capture(cli: &Cli, f: &Fixture, path: &str, flags: &[&str]) -> Value {
    let url = format!("{}{path}", f.url);
    let mut argv = vec!["capture", &url];
    argv.extend(flags);
    let r = cli.run(&argv).await;
    r.json()
}

const SIGN_IN_PAGE: &str = r"sign-in page.*api-anything login";
const LEARN: &str = r"\badd <site> <op> --from c";
const ALSO_FORM: &str = r"sign-in form.*api-anything login";

#[tokio::test]
async fn sign_in_page_takes_a_login_path_and_a_sign_in_form_on_it_asked_for_or_redirected_to() {
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let f = Fixture::start().await;
    let cli = Cli::new();
    for path in ["/account", "/signin"] {
        let next = s(&capture(&cli, &f, path, &[]).await["next"]);
        assert_match!(next, SIGN_IN_PAGE, "{path}");
        assert_no_match!(next, LEARN, "{path}");
        assert_match!(next, r"api-anything inspect c\w+ \d+", "the stop still says how to look at the page");
    }
    // a public page that merely lives under a login-like path is learned from like any other
    let docs = s(&capture(&cli, &f, "/docs/login", &["--example", "name=alice"]).await["next"]);
    assert_match!(docs, LEARN);
    assert_no_match!(docs, "sign-in");
}

#[tokio::test]
async fn example_values_that_no_candidate_returned_on_a_page_with_a_sign_in_form_are_a_stronger_caveat_not_a_stop() {
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let f = Fixture::start().await;
    let cli = Cli::new();
    let next = s(&capture(&cli, &f, "/private", &["--example", "name=alice"]).await["next"]);
    assert_match!(next, LEARN);
    assert_match!(next, r"none of the example values.*sign-in form.*check the example values.*api-anything login");
    assert_no_match!(next, SIGN_IN_PAGE);
}

#[tokio::test]
async fn login_wording_with_no_sign_in_form_on_the_page_adds_nothing_to_the_recommendation() {
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let f = Fixture::start().await;
    let cli = Cli::new();
    let next = s(&capture(&cli, &f, "/notice", &["--example", "name=zelda"]).await["next"]);
    assert_match!(next, LEARN);
    assert_no_match!(next, "sign-in");
}

#[tokio::test]
async fn a_sign_in_form_with_nothing_to_say_the_data_is_missing_is_said_beside_the_recommendation() {
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let f = Fixture::start().await;
    let cli = Cli::new();
    let pages: [(&str, &[&str]); 5] = [
        ("/private", &[]),                                 // a login page served in place, but no example to miss
        ("/card/alice", &[]),                              // public data in the page's state JSON, under a login box
        ("/catalog", &[]),                                 // a public listing that sits inside the search form
        ("/community", &[]),                               // a redirect, to a public page with a login box
        ("/forum/alice", &["--example", "name=alice"]),    // the example is in a JSON request's answer, not in the page
    ];
    for (path, flags) in pages {
        let next = s(&capture(&cli, &f, path, flags).await["next"]);
        assert_no_match!(next, SIGN_IN_PAGE, "{path}");
        assert_match!(next, LEARN, "{path}");
        assert_match!(next, ALSO_FORM, "{path}");
    }
}

#[tokio::test]
async fn an_http_error_is_a_dead_end_only_when_the_erroring_page_is_itself_the_best_candidate() {
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    let f = Fixture::start().await;
    let cli = Cli::new();
    let gone = s(&capture(&cli, &f, "/no/such/page", &[]).await["next"]);
    assert_match!(gone, "404.*URL");
    assert_no_match!(gone, LEARN);
    // a static host's 404 fallback serving the app, which fetches the user's JSON
    let out = capture(&cli, &f, "/app/alice", &["--example", "name=alice"]).await;
    assert_eq!(out["candidates"][0]["kind"], json!("fetch"));
    assert_match!(s(&out["next"]), LEARN);
    assert_no_match!(s(&out["next"]), "check the URL");
    assert_eq!(out["pageStatus"], json!(404), "the document's status is reported on its own");
}
