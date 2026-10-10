# The Rust implementation

`rust/` is a second implementation of API Anything, in Rust, following `DESIGN.md` line for
line. It exists for three reasons: a single binary that needs no Node runtime and no `node_modules`
(the bundled site specs are compiled in); a browser layer that talks to Chrome over the DevTools
protocol directly, with no Playwright in between; and a second, independent check on the design,
since every test in `test/` has a counterpart in `rust/tests/`.

## What is the same

- The commands, their flags, their JSON output and their `next` hints.
- The data: `~/.api-anything` (or `API_ANYTHING_HOME`) holds the same files in the same formats,
  so a spec learned by one implementation is called by the other, and a session imported by one
  signs in the other.
- The MCP server: the same four tools, over stdio.
- The library: `api_anything::execute::call`, `heal::add_operation`, `learn::learn_operation`
  and the other modules named in `rust/PORTING.md`.

## What differs

- Chrome is started with `--remote-debugging-pipe`: it exits when the process does, and no port
  is opened. Popups are attached before their first navigation, so a guarded run covers them from
  the start, where the Playwright version had to reason about tabs it had not been told about yet.
- `API_ANYTHING_CHROME` points the browser layer at any Chromium build (Chromium, Brave, a
  Playwright download). The TypeScript version only looks where Google Chrome installs.
- The headless user agent is fixed per page over the protocol, so there is no `chrome-ua.json`.
- User-supplied regular expressions (`pick ... ~regex`, `--embedded`, a param's `pattern`) are
  JavaScript-style and compiled with lookaround support; `[` inside a character class is literal
  as in JavaScript.
- HTML is parsed by html5ever (through `scraper`), a spec-compliant parser: a fragment is wrapped
  in `html`/`head`/`body`, and a `tr` outside a table is dropped, as a browser would.

## Building and testing

```sh
cd rust
cargo build --release          # target/release/api-anything
cargo test                     # browser tests skip when no Chrome is found
cargo clippy --all-targets -- -D warnings
cargo fmt
```

CI runs the same three on every pull request, with Google Chrome on the runner.
