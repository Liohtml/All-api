# How the Rust crate maps to the TypeScript source

Every module in `src/*.rs` is a one-to-one port of `../src/*.ts`, with the same function names
in snake_case. `docs/DESIGN.md` is the spec for both. This file lists the API differences a
reader of the TypeScript (or its tests) needs.

## Conventions

| TypeScript | Rust |
|---|---|
| `unknown` / JSON data | `serde_json::Value` (numbers keep their exact text: `arbitrary_precision`) |
| `undefined` | `None` of an `Option` |
| `Record<string, unknown>` args | `learn::Args` = `serde_json::Map<String, Value>` (insertion order kept) |
| `Record<string, string>` headers | `types::Headers` = `IndexMap<String, String>` |
| `throw new Error(msg)` | `anyhow::Error`; match on `e.to_string()`; typed errors downcast: `http::BadHeader`, `http::RedirectRefused`, `cdp::ProfileInUse`, `import::AmbiguousProfile`, `cli::Fail` |
| `Slot.ref` | `Slot.reference` (serialized as `"ref"`) |
| `Operation.match` | `Operation.matcher` (serialized as `"match"`) |
| `Param.type` | `Param.kind` (serialized as `"type"`) |
| `OperationSchema.parse(x)` | `spec::parse_operation(&json)` / `spec::check_operation(&op)` |
| `parseSite(x)` | `spec::parse_site(&json)` |
| `Date.now()` ms | `util::now_ms()` (f64); `new Date().toISOString()` is `util::iso_now()` |
| `fetchImpl` injection | `http::Fetcher` trait object (`SharedFetcher = Arc<dyn Fetcher>`), passed in `SendOptions.fetcher` / `CallOptions.fetcher` / `AddInput.fetcher` |
| `process.env.API_ANYTHING_HOME` | the same variable; `API_ANYTHING_CHROME` points at a Chrome/Chromium binary; `API_ANYTHING_BUNDLED_DIR` replaces the bundled `sites/` (default: embedded in the binary) |

## Module notes

- `codec`: `get_at(&Request, &[Step]) -> Result<Option<Value>>`, `set_at(&Request, &[Step], &Value)`,
  `set_text` (a string value), `walk` -> `Vec<Leaf { at, value, kind: LeafType, container, repeated }>`.
- `learn`: `LearnInput::new(exchanges, examples, name, trigger, read_only)` then set the optional
  fields; `learn_operation(&input) -> Result<Learned>`; `rank_candidates(&[Exchange], &Args, RankOptions)`.
- `http`: `build_request`, `with_defaults`, `next_hop(op, session, from, status, location, taken, limit)`,
  `send(op, args, session, &SendOptions)` (async) -> `Sent`.
- `classify`: `classify(&Operation, &Observed) -> Classified { class, reason, missing }`; `judge` adds `data: Option<Value>`.
- `extract`: `extract(&ResponseSpec, body) -> Result<Option<Value>>`, `cap_output(&Value, max) -> Capped`.
- `session` / `store`: as in TS; `store::Bundled::Dir(path)` stands in for the `bundledDir` test parameter.
- `heal`: `fill_trigger`, `templatize_url`, `capture_trigger`, `unplaced`, `write_guard`, `run_op_trigger(site, op, args, intercept: bool)`,
  `capture_page(CapturePageOptions)`, `load_capture`, `add_operation(AddInput)`, `rescan(site, op, args, fetcher)`,
  `heal_operation(site, op, args, HealOptions { validate: Arc<dyn Fn(Operation) -> BoxFuture<Attempt>>, fetcher, login_cookies, browser })`
  -> `HealResult::{Healed, Identical, Failed}`. `Attempt` is a struct with `tier`, `class`, `reason`, `status`, `data`, `missing`, `redirected`, `hint`, `note`.
- `execute`: `call(site, op, args, CallOptions) -> CallResult` and `heal(...)` (both async). `CallResult`
  serializes to the TS shape (`ok`, `class`, `data`, `truncated`, `tier`, `healed`, `ms`, `reason`, `next`, `strategy`).
- `browser`: `run_trigger(TriggerOptions)`, `page_fetch(PageFetchOptions)`, `login(url, profile_dir, wait_for_enter)`,
  `profile_cookies`, `add_cookies_to_profile`, `clear_profile_cookies`, `close_browser()`, `chrome_available()`.
  Chrome is driven over the DevTools protocol (`cdp.rs`), not Playwright: there is no separate
  "route" and "tap"; one `Fetch.requestPaused` handler per page judges every request, redirect hops
  and unload-time requests included, and popups are attached before their first navigation.
- `import` / `login`: `import_from_browsers(url, login_cookies, pin)`, `cookies_from_file`, `parse_pin`,
  `browser_roots()` (reads `API_ANYTHING_BROWSER_ROOTS` for tests), `import_session`, `reimport_if_browser`, `logout`.
- `mcp`: `mcp_next`, `as_table`, `Server::new(allow_writes).call_tool(name, &args)`, `serve_stdio(allow_writes)`.
- `cli`: `cli::main_with(argv) -> exit code`; the binary is `api-anything`.

## Tests

`tests/*.rs` port `../test/*.test.ts` one to one. `tests/common/fixture.rs` is the offline site
(`Fixture::start().await`), `tests/common/mod.rs` the fixture helpers. Browser tests use the
Chrome named by `API_ANYTHING_CHROME` (falling back to the Playwright Chromium under `/opt/pw-browsers` when present) and skip without one.

Each browser test file runs on one shared tokio runtime (the shared Chrome belongs to the runtime
that launched it) and its tests take turns on one home directory, so `cargo test --test <file>`
passes with the default parallel dispatch as well as with `--test-threads=1`. Tests whose TS
version depends on file order carry a `t<n>_` prefix.

Where a TS test checks something that only exists in Node or Playwright, the Rust test checks the
behavior behind it instead; each such test says so in a comment:

| TS test | Rust |
|---|---|
| `browser`: the headless user agent is asked of Chrome once, then read from `chrome-ua.json` | no probe and no cache over CDP (the override comes from the running Chrome's version); asserts the user agent is a Chrome one without `Headless`, as the server receives it |
| `browser-surface`: a run leaves no timer behind | not ported: it counts Node's active `Timeout` handles |
| `browser-surface`: Ctrl-C mid-capture exits 130 | the binary dies by SIGINT (no handler, as in Node); exit 130 or the signal, Chrome gone within 3 s |
| `browser-surface`: Playwright fault injection (`tabs.sync`, a `goto`/`close` that never settles) | the observable outcome (a new tab's navigation stopped and recorded aborted; another run's page can still send once a run is over) |
| `round3`: "Execution context was destroyed" | CDP's wording, "Inspected target navigated or closed", accepted too |
| `live`: the WAF test relies on the tier-3 test running first | the precondition (the WAF cookie in the profile) is set in the test |
| `execute-classify`, `e2e`: `test/fixture/cookie-db.ts` | `make_chromium_db` in the test file (rusqlite, AES-CBC v10) |
