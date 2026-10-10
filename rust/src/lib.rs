//! api-anything: learn reusable operations from a website's browser traffic and call them from a
//! CLI, a library or an MCP server. `docs/DESIGN.md` is the spec every module follows.
pub mod browser;
pub mod cdp;
pub mod classify;
pub mod cli;
pub mod codec;
pub mod execute;
pub mod extract;
pub mod heal;
pub mod html;
pub mod http;
pub mod import;
pub mod learn;
pub mod login;
pub mod mcp;
pub mod outline;
pub mod secrets;
pub mod session;
pub mod spec;
pub mod store;
pub mod types;
pub mod util;
