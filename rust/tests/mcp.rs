mod common;
use api_anything::mcp::{Server, as_table, mcp_next};
use api_anything::store::save_site;
use common::{Home, site};
use serde_json::{Value, json};
use std::sync::LazyLock;

static HOME: LazyLock<Home> = LazyLock::new(Home::new);

#[test]
fn mcp_sends_a_list_of_records_as_columns_rows_keys_once_null_for_a_missing_field() {
    let data = json!([
        { "airline": ["JetBlue"], "price": 209, "via": ["BOS"] },
        { "airline": ["Delta"], "price": 219 },
    ]);
    assert_eq!(
        as_table(&data),
        json!({
            "columns": ["airline", "price", "via"],
            "rows": [
                [["JetBlue"], 209, ["BOS"]],
                [["Delta"], 219, null],
            ],
        })
    );
}

#[test]
fn mcp_sends_anything_that_is_not_a_list_of_two_or_more_records_unchanged() {
    for data in [
        json!([{ "a": 1 }]),
        json!([]),
        json!([1, 2]),
        json!([[1], [2]]),
        json!([{ "a": 1 }, null]),
        json!({ "a": 1 }),
        json!("text"),
        Value::Null,
    ] {
        assert_eq!(as_table(&data), data);
    }
}

/* ------------------------------------------------------------ mcp_next: the CLI's hints in MCP terms */

#[test]
fn mcp_next_turns_the_allow_writes_rerun_into_a_server_restart() {
    assert_eq!(
        mcp_next("only if the user asked for this write: rerun with --allow-writes (MCP: start the server with --allow-writes)"),
        "only if the user asked for this write: ask the user to restart this MCP server with --allow-writes"
    );
}

#[test]
fn mcp_next_turns_ops_and_sites_into_the_list_tools() {
    assert_eq!(
        mcp_next("check the args against: api-anything ops google-flights; do not heal or re-add"),
        "check the args against: list_operations {\"site\":\"google-flights\"}; do not heal or re-add"
    );
    assert_eq!(
        mcp_next("api-anything sites lists what exists; api-anything add creates one"),
        "list_sites lists what exists; a new site is added with the CLI"
    );
}

#[test]
fn mcp_next_turns_a_login_command_into_the_login_tool_with_the_window_mode_note() {
    assert_eq!(
        mcp_next("ask the user to run: api-anything login linkedin; then retry once"),
        "the login tool {\"site\":\"linkedin\"} (mode \"window\" when the user must sign in or clear a challenge by hand); then retry once"
    );
    assert_eq!(
        mcp_next(
            "the site is challenging automated requests: ask the user to run api-anything login x.com and clear the challenge, then retry once"
        ),
        "the site is challenging automated requests: the login tool {\"site\":\"x.com\"} (mode \"window\" when the user must sign in or clear a challenge by hand) and clear the challenge, then retry once"
    );
    assert_eq!(
        mcp_next(
            "check the args against api-anything ops linkedin; if the site needs an account, ask the user to run api-anything login linkedin"
        ),
        "check the args against list_operations {\"site\":\"linkedin\"}; if the site needs an account, the login tool {\"site\":\"linkedin\"} (mode \"window\" when the user must sign in or clear a challenge by hand)"
    );
}

#[test]
fn mcp_next_keeps_cli_only_commands_and_says_where_to_run_them() {
    const SHELL: &str = " (api-anything is a CLI: run it in your shell, as npx -y github:goodnight000/api-anything when the command is not installed; with no shell, ask the user)";
    for hint in [
        "api-anything heal linkedin searchPeople; if that fails, re-learn it with api-anything add linkedin searchPeople ...",
        "if the site works in a browser, re-learn the response recipe: api-anything add demo get ... --extract <path> (api-anything capture <trigger url> shows the response); otherwise report it",
        "wait for the stale mark to expire, or force it: api-anything heal demo get",
    ] {
        assert_eq!(mcp_next(hint), format!("{hint}{SHELL}"));
    }
    assert_eq!(mcp_next("fix or delete that spec file, then retry once"), "fix or delete that spec file, then retry once");
}

/* ------------------------------------------------------------ the list tools against a saved spec */

fn demo() -> Value {
    json!({
        "name": "demo",
        "baseUrl": "https://demo.test",
        "description": "a demo site",
        "operations": [
            {
                "name": "get",
                "description": "one item",
                "request": {"method": "GET", "url": "https://demo.test/a?id=1", "headers": {}},
                "slots": [{"param": "id", "at": ["query:id"]}],
                "trigger": {"url": "https://demo.test/"},
                "response": {"format": "json", "extract": "items", "pick": ["name", "n=count"]},
                "params": [{"name": "id", "type": "number", "required": true, "example": 1, "hint": "a number", "pattern": "^\\d+$"}],
                "readOnly": true,
            },
            {
                "name": "remove",
                "request": {"method": "POST", "url": "https://demo.test/rm", "headers": {}},
                "slots": [],
                "trigger": {"url": "https://demo.test/"},
                "response": {"format": "json"},
                "params": [],
                "readOnly": false,
            },
        ],
    })
}

async fn tool(server: &Server, name: &str, args: Value) -> (Value, bool) {
    let a = match args {
        Value::Object(o) => o,
        _ => Default::default(),
    };
    let r = server.call_tool(name, &a).await;
    (r.value, r.is_error)
}

#[tokio::test]
async fn list_sites_and_list_operations_read_a_saved_spec_and_hide_writes_unless_allowed() {
    LazyLock::force(&HOME);
    save_site(&site(demo())).unwrap();
    let server = Server::new(false);

    let (sites, is_error) = tool(&server, "list_sites", json!({})).await;
    assert!(!is_error);
    let demo_row = sites.as_array().unwrap().iter().find(|s| s["name"] == json!("demo")).expect("demo listed");
    assert_eq!(demo_row, &json!({ "name": "demo", "description": "a demo site", "operations": 1 }));

    let (ops, is_error) = tool(&server, "list_operations", json!({ "site": "demo" })).await;
    assert!(!is_error);
    assert_eq!(
        ops,
        json!({
            "site": "demo",
            "operations": [{
                "name": "get",
                "description": "one item",
                "returns": ["name", "n"],
                "params": [{ "name": "id", "type": "number", "required": true, "example": 1, "hint": "a number", "pattern": "^\\d+$" }],
            }],
        })
    );

    // with --allow-writes the write is listed, marked, and counted
    let allowed = Server::new(true);
    let (sites, _) = tool(&allowed, "list_sites", json!({})).await;
    let demo_row = sites.as_array().unwrap().iter().find(|s| s["name"] == json!("demo")).unwrap();
    assert_eq!(demo_row["operations"], json!(2));
    let (ops, _) = tool(&allowed, "list_operations", json!({ "site": "demo" })).await;
    let names: Vec<(&str, bool)> =
        ops["operations"].as_array().unwrap().iter().map(|o| (o["name"].as_str().unwrap(), o["write"] == json!(true))).collect();
    assert_eq!(names, vec![("get", false), ("remove", true)]);

    // an unknown site is an error with a next, never a bare exception
    let (r, is_error) = tool(&server, "list_operations", json!({ "site": "nope" })).await;
    assert!(is_error);
    assert_eq!(r, json!({ "error": "no site \"nope\"", "next": "list_sites" }));
    let (r, is_error) = tool(&server, "list_operations", json!({ "site": "../etc" })).await;
    assert!(is_error, "{r}");
    assert_eq!(r["next"], json!("list_sites"));
    assert!(r["error"].as_str().unwrap().contains("invalid site name"), "{r}");
}
