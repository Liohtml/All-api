//! test/edge/browser-surface.test.ts: edge cases for the browser layer, CLI, MCP server and store.
//! Each test is a regression for a bug that was fixed. The browser tests run serially under one
//! runtime and one home, as node:test runs them in order on one event loop.
mod common;
use api_anything::browser::{PageFetchOptions, TriggerOptions, add_cookies_to_profile, close_browser, hold, open_browser, page_fetch, run_trigger};
use api_anything::execute::{CallOptions, call};
use api_anything::heal::{AddInput, CapturePageOptions, Recipe, add_operation, capture_page, load_capture, profile_dir};
use api_anything::mcp::Server;
use api_anything::secrets::scan_secrets;
use api_anything::session::Session;
use api_anything::spec::{Trigger, parse_match, parse_steps};
use api_anything::store::{STALE_TTL_MS, clear_stale, export_site, load_site, mark_stale, stale_mark};
use api_anything::types::{CaptureResult, Exchange, StoredCookie};
use api_anything::util::{encode_uri_component, now_ms};
use common::{Home, args, j};
use edge::{EdgeFixture, TOKEN};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/* ------------------------------------------------------------ the edge fixture */

/// Port of test/edge/browser-surface.fixture.ts: pages that never go network-quiet, never fire
/// `load`, open popups, embed iframes, download files, redirect to a login page, debounce search
/// input, and serve very large bodies.
mod edge {
    #![allow(dead_code)]
    use axum::body::{Body, Bytes};
    use axum::extract::{Request, State};
    use axum::http::{HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Response};
    use base64::Engine;
    use futures_util::StreamExt;
    use sha1::{Digest, Sha1};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncReadExt;
    use tokio::sync::oneshot;

    /// A session cookie in base64 with "/", "+" and "=" (percent-encoded whenever a page puts it in a URL).
    pub const TOKEN: &str = "q2Fz/9kLmT0vX+Yb7NcW1pRe/Hs3JuQa8Df+Lg6ZoVy4=";

    struct Inner {
        calls: Mutex<Vec<String>>,
        hanging: Mutex<Vec<oneshot::Sender<()>>>,
        held: Mutex<Vec<oneshot::Sender<()>>>,
        ws_messages: AtomicUsize,
        root_redirect: bool,
        port: u16,
    }

    pub struct EdgeFixture {
        pub url: String,
        inner: Arc<Inner>,
        task: tokio::task::JoinHandle<()>,
    }

    fn html(body: &str, status: u16) -> Response {
        Response::builder()
            .status(status)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::from(format!("<!doctype html><html><head><meta charset=\"utf-8\"></head><body>{body}</body></html>")))
            .unwrap()
    }
    fn json(v: serde_json::Value, status: u16) -> Response {
        Response::builder().status(status).header("content-type", "application/json").body(Body::from(v.to_string())).unwrap()
    }
    fn data_fetch(name: &str) -> String {
        format!(
            "<div id=\"out\"></div><script>fetch(\"/api/data?name=\"+encodeURIComponent({})).then(r=>r.json()).then(v=>{{document.getElementById(\"out\").textContent=JSON.stringify(v)}})</script>",
            serde_json::Value::String(name.to_string())
        )
    }
    fn enc(s: &str) -> String {
        api_anything::util::encode_uri_component(s)
    }

    async fn ws(inner: Arc<Inner>, mut req: Request) -> Response {
        let key = req.headers().get("sec-websocket-key").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let digest = Sha1::digest(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes());
        let accept = base64::engine::general_purpose::STANDARD.encode(digest);
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let Ok(up) = on_upgrade.await else { return };
            let mut io = hyper_util::rt::TokioIo::new(up);
            // one frame at a time: opcode 1 is a text message, 8 is the close frame
            loop {
                let mut head = [0u8; 2];
                if io.read_exact(&mut head).await.is_err() {
                    break;
                }
                let opcode = head[0] & 0x0f;
                let masked = head[1] & 0x80 != 0;
                let mut len = (head[1] & 0x7f) as u64;
                if len == 126 {
                    let mut b = [0u8; 2];
                    if io.read_exact(&mut b).await.is_err() {
                        break;
                    }
                    len = u16::from_be_bytes(b) as u64;
                } else if len == 127 {
                    let mut b = [0u8; 8];
                    if io.read_exact(&mut b).await.is_err() {
                        break;
                    }
                    len = u64::from_be_bytes(b);
                }
                if masked {
                    let mut m = [0u8; 4];
                    if io.read_exact(&mut m).await.is_err() {
                        break;
                    }
                }
                let mut payload = vec![0u8; len as usize];
                if io.read_exact(&mut payload).await.is_err() {
                    break;
                }
                if opcode == 1 {
                    inner.ws_messages.fetch_add(1, Ordering::SeqCst);
                }
                if opcode == 8 {
                    break;
                }
            }
        });
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-accept", accept)
            .body(Body::empty())
            .unwrap()
    }

    async fn handle(State(inner): State<Arc<Inner>>, req: Request) -> Response {
        let path = req.uri().path().to_string();
        let search = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
        let query: HashMap<String, String> = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        let name = query.get("name").cloned().unwrap_or_else(|| "alice".to_string());
        let cookie = req.headers().get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        inner.calls.lock().unwrap().push(format!("{path}{search}"));
        match path.as_str() {
            "/ws" => ws(inner.clone(), req).await,
            "/api/data" => json(serde_json::json!({ "data": { "name": name, "followers": name.len() * 100 } }), 200),
            "/api/search" => {
                let q = query.get("q").cloned().unwrap_or_else(|| "null".to_string());
                json(serde_json::json!({ "results": [format!("{q} one"), format!("{q} two")] }), 200)
            }
            "/api/big" => {
                let pad = "x".repeat(300);
                let mut body = String::with_capacity(7_000_000);
                body.push_str("{\"data\":{\"items\":[");
                for i in 0..20_000 {
                    if i > 0 {
                        body.push(',');
                    }
                    body.push_str(&format!("{{\"id\":{i},\"name\":{},\"pad\":\"{pad}\"}}", serde_json::Value::String(name.clone())));
                }
                body.push_str("]}}");
                Response::builder().status(200).header("content-type", "application/json").body(Body::from(body)).unwrap()
            }
            "/api/huge-items" => {
                // five items, each far bigger than the 20k-char output cap
                let items: Vec<serde_json::Value> = (0..5).map(|i| serde_json::json!({ "id": i, "name": name, "blob": "y".repeat(30_000) })).collect();
                json(serde_json::json!({ "data": items }), 200)
            }
            "/api/beacon" => Response::builder().status(204).body(Body::empty()).unwrap(),
            "/api/sse" => {
                let pings = futures_util::stream::unfold((), |()| async {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    Some((Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b": ping\n\n")), ()))
                });
                let stream = futures_util::stream::once(async { Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b": open\n\n")) }).chain(pings);
                Response::builder()
                    .status(200)
                    .header("content-type", "text/event-stream")
                    .header("cache-control", "no-cache")
                    .body(Body::from_stream(stream))
                    .unwrap()
            }
            "/hang" => {
                // never answers
                let (tx, rx) = oneshot::channel::<()>();
                inner.hanging.lock().unwrap().push(tx);
                let _ = rx.await;
                Response::builder().status(404).body(Body::empty()).unwrap()
            }
            "/data-page" => html(&data_fetch(&name), 200),
            "/hang-img" => html(&format!("{}<img src=\"/hang\">", data_fetch(&name)), 200),
            "/sse-page" => html(&format!("{}<script>new EventSource(\"/api/sse\")</script>", data_fetch(&name)), 200),
            "/beacon-page" => html(&format!("{}<script>setInterval(()=>fetch(\"/api/beacon\",{{method:\"POST\",body:\"t=\"+Date.now()}}),150)</script>", data_fetch(&name)), 200),
            // hydration that waits a little before loading its data
            "/late" => html(&format!("<div id=\"out\"></div><script>setTimeout(()=>fetch(\"/api/data?name=\"+encodeURIComponent({})),1200)</script>", serde_json::Value::String(name.clone())), 200),
            // search-as-you-type with a 600 ms debounce, the common typeahead pattern
            "/debounce" => html(
                "<input id=\"q\"><ul id=\"out\"></ul><script>let t;document.getElementById(\"q\").addEventListener(\"input\",e=>{clearTimeout(t);t=setTimeout(()=>fetch(\"/api/search?q=\"+encodeURIComponent(e.target.value)).then(r=>r.json()).then(v=>{document.getElementById(\"out\").textContent=JSON.stringify(v)}),600)})</script>",
                200,
            ),
            "/popup" => html(&format!("<a id=\"open\" target=\"_blank\" href=\"/data-page?name={}\">open</a>", enc(&name)), 200),
            "/iframe" => html(&format!("<iframe src=\"/data-page?name={}\"></iframe>", enc(&name)), 200),
            "/file.csv" => Response::builder()
                .status(200)
                .header("content-type", "text/csv")
                .header("content-disposition", "attachment; filename=\"export.csv\"")
                .body(Body::from(format!("name,followers\n{name},100\n")))
                .unwrap(),
            "/dl-page" => html(&format!("<a id=\"dl\" href=\"/file.csv?name={}\">download</a>{}", enc(&name), data_fetch(&name)), 200),
            "/members" => {
                // behind a login wall: signed-in visitors carry the sid cookie
                if cookie.starts_with("sid=") || cookie.contains("; sid=") {
                    html(&data_fetch(&name), 200)
                } else {
                    Response::builder().status(302).header("location", format!("/login-page?next={}", enc(&format!("{path}{search}")))).body(Body::empty()).unwrap()
                }
            }
            "/login-page" => html(
                "<h1>Sign in</h1><form action=\"/session\" method=\"post\"><input name=\"username\"><input type=\"password\" name=\"password\"><button>Log in</button></form>",
                200,
            ),
            "/big-page" => html(&format!("{}<script>fetch(\"/api/big?name={}\")</script>", format!("<p>{}</p>", "lorem ipsum ".repeat(50)).repeat(4000), enc(&name)), 200),
            "/huge-page" => html(&format!("<script>fetch(\"/api/huge-items?name={}\")</script>", enc(&name)), 200),
            // old-school writes that are GETs but not xhr/fetch: an image ping (Hacker News style), a link, a GET form
            "/vote-page" => html(
                &format!(
                    concat!(
                        "<button id=\"img\" onclick=\"new Image().src='/api/vote?how=img'\">up</button>",
                        "<a id=\"link\" href=\"/api/vote?how=link\">vote</a>",
                        "<form id=\"f\" action=\"/api/vote\" method=\"get\"><input name=\"how\" value=\"form\"><button id=\"submit\">go</button></form>",
                        "<button id=\"script\" onclick=\"const s=document.createElement('script');s.src='/api/vote?how=script';document.body.appendChild(s)\">jsonp</button>",
                        "<button id=\"iframe\" onclick=\"const f=document.createElement('iframe');f.src='/api/vote?how=iframe';document.body.appendChild(f)\">frame</button>",
                        "<button id=\"post\" onclick=\"fetch('/api/vote?how=post',{{method:'POST',body:'up'}})\">post</button>",
                        // the write is a new tab's first navigation
                        "<a id=\"newtab\" target=\"_blank\" href=\"/api/vote?how=newtab\">vote in a tab</a>",
                        "<button id=\"open\" onclick=\"window.open('/api/vote?how=open')\">open</button>",
                        // an asset the write guard allows, answered with a redirect to the write
                        "<button id=\"hop\" onclick=\"const l=document.createElement('link');l.rel='stylesheet';l.href='/safe.css';document.head.appendChild(l)\">hop</button>",
                        // an asset load the write guard allows during the steps: the server seeing it shows they have started
                        "<button id=\"css\" onclick=\"const l=document.createElement('link');l.rel='stylesheet';l.href='/acting.css';document.head.appendChild(l)\">css</button>",
                        // a client that sends a failed request again (axios-retry, Apollo's RetryLink), here with no backoff
                        "<button id=\"retry\" onclick=\"const go=()=>fetch('/api/vote?how=retry').catch(go);go()\">retry</button>",
                        "{}"
                    ),
                    data_fetch(&name)
                ),
                200,
            ),
            "/leave-page" => {
                // writes a page sends as it goes away, the way analytics and autosave do
                let how = query.get("how").cloned().unwrap_or_default();
                let vote = serde_json::Value::String(format!("/api/vote?how={how}")).to_string();
                let send = match how.as_str() {
                    "beacon" => format!("addEventListener(\"pagehide\",()=>navigator.sendBeacon({vote},\"up\"))"),
                    "keepalive" => format!("addEventListener(\"pagehide\",()=>fetch({vote},{{method:\"POST\",body:\"up\",keepalive:true}}))"),
                    "hidden" => format!("document.addEventListener(\"visibilitychange\",()=>navigator.sendBeacon({vote},\"up\"))"),
                    "img" => format!("addEventListener(\"pagehide\",()=>{{new Image().src={vote}}})"),
                    // a handler that is slow to get to it
                    "slow" => format!("addEventListener(\"pagehide\",()=>{{const t=Date.now();while(Date.now()-t<400);navigator.sendBeacon({vote},\"up\")}})"),
                    // no handler at all: the browser itself sends it when the document goes; the fetch after it says it registered
                    "later" => format!("fetchLater({vote},{{method:\"POST\",body:\"up\"}});fetch(\"/api/data?name=registered\")"),
                    _ => String::new(),
                };
                html(&format!("<script>{send}</script>{}", data_fetch(&name)), 200)
            }
            // opens a tab whose document is slow: the tab has no page yet when the run that opened it ends
            "/late-tab-page" => html(&format!("<script>window.open(\"/held-vote\")</script>{}", data_fetch(&name)), 200),
            // an app that starts only once its shared worker has answered (a session kept across tabs)
            "/worker-app" => {
                let inner_js = data_fetch(&name);
                let inner_js = inner_js.trim_start_matches("<div id=\"out\"></div><script>").trim_end_matches("</script>");
                html(&format!("<script>const w=new SharedWorker(\"/app-worker.js?\"+Math.random());w.port.onmessage=e=>{{{inner_js}}};w.port.start()</script><div id=\"out\"></div>"), 200)
            }
            "/app-worker.js" => Response::builder()
                .status(200)
                .header("content-type", "application/javascript")
                .body(Body::from("onconnect=e=>fetch(\"/api/data?name=from-worker\").then(()=>e.ports[0].postMessage(\"ready\"))"))
                .unwrap(),
            "/safe.css" => Response::builder().status(302).header("location", "/api/vote?how=hop").body(Body::empty()).unwrap(),
            // the renderer hangs for good shortly after load: nothing run in the page ever answers again
            "/stuck-page" => html(&format!("{}<script>setTimeout(()=>{{for(;;){{}}}},300)</script>", data_fetch(&name)), 200),
            // opens a tab that opens the slow tab and closes itself: the slow tab's opener is gone when its page comes
            "/chain-page" => html(&format!("<script>window.open(\"/chain-tab\")</script>{}", data_fetch(&name)), 200),
            "/chain-tab" => html("<script>window.open(\"/held-vote\");setTimeout(()=>window.close(),200)</script>", 200),
            "/held-vote" => {
                // answered by release(), with a page that writes
                let (tx, rx) = oneshot::channel::<()>();
                inner.held.lock().unwrap().push(tx);
                let _ = rx.await;
                html("<script>fetch(\"/api/vote?how=latetab\",{method:\"POST\",body:\"up\"})</script>", 200)
            }
            "/api/vote" => Response::builder().status(200).header("content-type", "text/plain").body(Body::from("voted")).unwrap(),
            // a chat app: the socket opens at load, the message (the write) goes over it on click
            "/chat" => html(
                "<input id=\"msg\" value=\"hello\"><button id=\"send\">send</button><script>const ws=new WebSocket(\"ws://\"+location.host+\"/ws\");document.getElementById(\"send\").onclick=()=>ws.send(document.getElementById(\"msg\").value)</script>",
                200,
            ),
            "/" => {
                // like an API host whose root redirects to the main site on another origin
                if inner.root_redirect {
                    Response::builder().status(302).header("location", format!("http://localhost:{}/landing", inner.port)).body(Body::empty()).unwrap()
                } else {
                    html("<p>home</p>", 200)
                }
            }
            "/landing" => html("<p>main site</p>", 200),
            // the page echoes a base64 session cookie, prefixed, inside a query value
            "/tok-page" => Response::builder()
                .status(200)
                .header("content-type", "text/html; charset=utf-8")
                .header("set-cookie", HeaderValue::from_str(&format!("tok={TOKEN}; Path=/; SameSite=Lax")).unwrap())
                .body(Body::from(format!(
                    "<!doctype html><div id=\"out\"></div><script>const t=(document.cookie.match(/(?:^|; )tok=([^;]*)/)||[])[1];fetch(\"/api/data?name=\"+encodeURIComponent({})+\"&auth=\"+encodeURIComponent(\"v1:\"+t))</script>",
                    serde_json::Value::String(name.clone())
                )))
                .unwrap(),
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }

    impl EdgeFixture {
        pub async fn start() -> EdgeFixture {
            Self::start_with(false).await
        }
        pub async fn start_with(root_redirect: bool) -> EdgeFixture {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let inner = Arc::new(Inner { calls: Mutex::new(vec![]), hanging: Mutex::new(vec![]), held: Mutex::new(vec![]), ws_messages: AtomicUsize::new(0), root_redirect, port });
            let app = axum::Router::new().fallback(handle).with_state(inner.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            EdgeFixture { url: format!("http://127.0.0.1:{port}"), inner, task }
        }
        /// path + query of every request, in order
        pub fn calls(&self) -> Vec<String> {
            self.inner.calls.lock().unwrap().clone()
        }
        /// text frames received over /ws (each one a message the page sent: a write over a WebSocket)
        pub fn ws_messages(&self) -> usize {
            self.inner.ws_messages.load(Ordering::SeqCst)
        }
        /// answer the /held-vote requests that have been waiting
        pub fn release(&self) {
            for tx in self.inner.held.lock().unwrap().drain(..) {
                let _ = tx.send(());
            }
        }
        pub fn close(&self) {
            self.inner.hanging.lock().unwrap().clear();
            self.inner.held.lock().unwrap().clear();
            self.task.abort();
        }
    }
}

/* ------------------------------------------------------------ harness */

static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
/// One home and one shared browser for the binary: the tests take turns, as node's do in one file.
static LOCK: Mutex<()> = Mutex::new(());
static HOME: LazyLock<Home> = LazyLock::new(Home::new);
/// The first describe's own profile (`prof`); the others use the home's.
static PROF: LazyLock<tempfile::TempDir> = LazyLock::new(|| tempfile::tempdir().unwrap());
static FX: tokio::sync::OnceCell<EdgeFixture> = tokio::sync::OnceCell::const_new();

fn run<F: Future>(f: F) -> F::Output {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    LazyLock::force(&HOME);
    RT.block_on(f)
}

fn chrome() -> bool {
    if std::env::var("API_ANYTHING_CHROME").is_err() {
        let p = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
        if std::path::Path::new(p).exists() {
            unsafe { std::env::set_var("API_ANYTHING_CHROME", p) };
        }
    }
    let ok = api_anything::browser::chrome_available();
    if !ok {
        eprintln!("Google Chrome not installed: skipped");
    }
    ok
}

async fn fx() -> &'static EdgeFixture {
    FX.get_or_init(EdgeFixture::start).await
}

fn home() -> PathBuf {
    HOME.path().to_path_buf()
}

fn fast() -> CallOptions {
    CallOptions { min_interval_ms: Some(0), ..Default::default() }
}

/// A read op whose request is GET <path>?name=alice, triggered by a page on the fixture.
fn op(fx: &EdgeFixture, name: &str, trigger: &str, path: &str, extra: Value) -> Value {
    let mut v = json!({
        "name": name,
        "readOnly": true,
        "trigger": { "url": format!("{}{trigger}", fx.url) },
        "match": { "method": "GET", "path": "/api/data" },
        "request": { "method": "GET", "url": format!("{}{path}?name=alice", fx.url), "headers": {} },
        "slots": [{ "param": "name", "at": ["query:name"] }],
        "params": [{ "name": "name", "example": "alice" }],
        "response": { "format": "json", "extract": "data" },
    });
    if let (Value::Object(o), Value::Object(e)) = (&mut v, extra) {
        for (k, x) in e {
            o.insert(k, x);
        }
    }
    v
}

fn write_spec(fx: &EdgeFixture, ops: Vec<Value>, site: &str) {
    let dir = home().join("sites");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{site}.json")), json!({ "name": site, "baseUrl": fx.url, "operations": ops }).to_string()).unwrap();
}

fn data<'a>(r: &'a CaptureResult, name: &str) -> Option<&'a Exchange> {
    r.exchanges.iter().find(|e| e.request.url.contains(&format!("/api/data?name={name}")))
}

fn urls(r: &CaptureResult) -> String {
    r.exchanges.iter().map(|e| e.request.url.clone()).collect::<Vec<_>>().join(", ")
}

fn steps(v: Value) -> Vec<api_anything::types::TriggerStep> {
    parse_steps(&v).unwrap()
}

async fn sleep(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

async fn until(f: impl Fn() -> bool, ms: u64) -> bool {
    let end = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < end {
        if f() {
            return true;
        }
        sleep(100).await;
    }
    f()
}

fn votes(fx: &EdgeFixture) -> Vec<String> {
    fx.calls().into_iter().filter(|c| c.starts_with("/api/vote")).collect()
}

/// `ctx.clearCookies()`: every cookie in the profile.
async fn clear_cookies() {
    let _h = hold();
    let b = open_browser(&profile_dir(), true).await.unwrap();
    let p = b.new_page(None).await.unwrap();
    p.send("Network.clearBrowserCookies", json!({})).await.unwrap();
    let _ = p.close().await;
}

fn add(site: &str, op: &str, trigger: Option<Trigger>, examples: Vec<Value>) -> AddInput {
    AddInput { site: site.into(), op: op.into(), trigger, examples: examples.into_iter().map(args).collect(), matcher: None, write: false, description: None, response: None, public: None, from: None, from2: None, fetcher: None }
}

fn re(p: &str) -> regex::Regex {
    regex::Regex::new(p).unwrap()
}

/* ------------------------------------------------------------ runTrigger */

async fn trigger(url: &str, steps_v: Option<Value>, timeout_ms: Option<u64>) -> anyhow::Result<CaptureResult> {
    let mut o = TriggerOptions::new(url, PROF.path());
    o.steps = steps_v.map(steps);
    o.timeout_ms = timeout_ms;
    run_trigger(o).await
}

#[test]
fn iframe_requests_made_inside_a_frame_are_captured_with_bodies() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = trigger(&format!("{}/iframe?name=frida", fx.url), None, None).await.unwrap();
        let body: Value = serde_json::from_str(data(&r, "frida").map(|e| e.body()).filter(|b| !b.is_empty()).unwrap_or("{}")).unwrap();
        assert_eq!(body["data"]["name"], json!("frida"));
    });
}

#[test]
fn very_large_page_a_2_4_mb_document_and_a_6_7_mb_json_body_come_through_intact() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = trigger(&format!("{}/big-page?name=bigs", fx.url), None, None).await.unwrap();
        let big = r.exchanges.iter().find(|e| e.request.url.contains("/api/big"));
        let body: Value = serde_json::from_str(big.map(|e| e.body()).filter(|b| !b.is_empty()).unwrap_or("{}")).unwrap();
        assert_eq!(body["data"]["items"].as_array().map(|a| a.len()), Some(20_000));
        assert!(r.exchanges.iter().find(|e| e.resource_type == "document").map(|e| e.body().len()).unwrap_or(0) > 2_000_000);
    });
}

#[test]
fn debounced_typeahead_600_ms_after_fill_is_captured() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = trigger(&format!("{}/debounce", fx.url), Some(json!([{ "action": "fill", "selector": "#q", "value": "kittens" }])), None).await.unwrap();
        assert!(r.exchanges.iter().any(|e| e.request.url.ends_with("/api/search?q=kittens")), "{}", urls(&r));
    });
}

#[test]
fn clicking_a_download_link_does_not_break_the_capture() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = trigger(&format!("{}/dl-page?name=dolly", fx.url), Some(json!([{ "action": "click", "selector": "#dl" }])), None).await.unwrap();
        assert!(data(&r, "dolly").is_some(), "{}", urls(&r));
        assert!(r.exchanges.iter().any(|e| e.request.url.contains("/file.csv")), "{}", urls(&r));
    });
}

#[test]
fn a_step_whose_selector_is_gone_fails_within_the_budget_and_names_the_selector() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let t0 = Instant::now();
        let r = trigger(&format!("{}/data-page?name=x", fx.url), Some(json!([{ "action": "click", "selector": "#gone-button" }])), Some(3000)).await;
        let e = r.err().expect("the step fails");
        assert!(e.to_string().contains("#gone-button"), "{e}");
        assert!(t0.elapsed() < Duration::from_millis(8000), "{:?}", t0.elapsed());
    });
}

#[test]
fn popup_the_data_request_made_in_a_tab_the_trigger_opens_is_captured() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = trigger(&format!("{}/popup?name=pop", fx.url), Some(json!([{ "action": "click", "selector": "#open" }])), None).await.unwrap();
        assert!(data(&r, "pop").is_some(), "captured: {}", urls(&r));
    });
}

#[test]
fn popup_a_tab_the_trigger_opened_is_closed_afterwards_no_tab_leak_in_a_long_lived_mcp_server() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let _h = hold();
        let ctx = open_browser(PROF.path(), true).await.unwrap();
        let before = ctx.pages().len();
        for i in 0..3 {
            trigger(&format!("{}/popup?name=pop{i}", fx.url), Some(json!([{ "action": "click", "selector": "#open" }])), None).await.unwrap();
        }
        // the browser reports a closed tab a moment after the run closed it
        until(|| ctx.pages().len() == before, 2000).await;
        assert_eq!(ctx.pages().len(), before, "open tabs grew by one per run");
    });
}

#[test]
fn a_subresource_that_never_answers_no_load_event_still_yields_the_data_the_page_fetched() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = trigger(&format!("{}/hang-img?name=hank", fx.url), None, Some(6000)).await.unwrap();
        assert!(data(&r, "hank").is_some(), "{}", urls(&r));
    });
}

#[test]
fn a_page_with_an_open_event_source_finishes_long_before_the_timeout() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let t0 = Instant::now();
        let r = trigger(&format!("{}/sse-page?name=sse", fx.url), None, Some(15_000)).await.unwrap();
        assert!(data(&r, "sse").is_some(), "{}", urls(&r));
        assert!(t0.elapsed() < Duration::from_millis(6000), "took {} ms (the whole timeout)", t0.elapsed().as_millis());
    });
}

#[test]
fn a_page_with_a_150_ms_analytics_beacon_finishes_long_before_the_timeout() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let t0 = Instant::now();
        let r = trigger(&format!("{}/beacon-page?name=bea", fx.url), None, Some(15_000)).await.unwrap();
        assert!(data(&r, "bea").is_some(), "{}", urls(&r));
        assert!(t0.elapsed() < Duration::from_millis(6000), "took {} ms (the whole timeout)", t0.elapsed().as_millis());
    });
}

#[test]
fn a_data_request_fired_1_2_s_after_load_deferred_hydration_is_captured() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = trigger(&format!("{}/late?name=lately", fx.url), None, None).await.unwrap();
        assert!(data(&r, "lately").is_some(), "captured: {}", urls(&r));
    });
}

#[test]
fn a_trigger_url_that_answers_with_a_download_is_captured_not_a_thrown_download_is_starting() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = trigger(&format!("{}/file.csv?name=carla", fx.url), None, None).await.unwrap();
        assert!(r.exchanges.iter().any(|e| e.request.url.contains("/file.csv")), "{}", urls(&r));
    });
}

// "a run leaves no timer behind that would keep the process alive" counts Node's active Timeout
// handles (process.getActiveResourcesInfo); a tokio runtime exposes no such count, so it is not ported.

#[test]
fn a_page_whose_renderer_hangs_the_run_still_ends_and_the_browser_is_free_for_the_next_one() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let t0 = Instant::now();
        let mut o = TriggerOptions::new(&format!("{}/stuck-page?name=stuck", fx.url), PROF.path());
        o.timeout_ms = Some(3000);
        o.intercept = Some(Arc::new(|e, acting, _| acting && e.request.method != "GET"));
        // the run goes on past the race, as a promise does: a run that does not end is the failure
        let ended = match tokio::time::timeout(Duration::from_millis(45_000), tokio::spawn(run_trigger(o))).await {
            Ok(Ok(Ok(r))) => data(&r, "stuck").is_some(),
            Ok(_) => true,
            Err(_) => false,
        };
        assert!(ended, "hung: after {} ms with timeoutMs 3000", t0.elapsed().as_millis());
        let next = trigger(&format!("{}/data-page?name=after", fx.url), None, None).await.unwrap();
        assert!(data(&next, "after").map(|e| !e.body().is_empty()).unwrap_or(false), "{}", urls(&next));
    });
}

#[test]
fn tier_2_works_when_the_api_origins_root_redirects_to_another_origin() {
    if !chrome() {
        return;
    }
    run(async {
        let fx2 = EdgeFixture::start_with(true).await;
        let r = page_fetch(PageFetchOptions {
            origin: fx2.url.clone(),
            url: format!("{}/api/data?name=zed", fx2.url),
            method: "GET".into(),
            headers: Default::default(),
            body: None,
            profile_dir: PROF.path().to_path_buf(),
            headless: true,
            timeout_ms: None,
            retry_on_navigation: false,
            redirect: None,
        })
        .await
        .unwrap();
        assert_eq!(r.status, 200);
        let body: Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(body["data"]["name"], json!("zed"));
        fx2.close();
    });
}

/* ------------------------------------------------------------ call() through the browser */

fn tier3_ops(fx: &EdgeFixture) -> Vec<Value> {
    vec![op(fx, "members", "/members?name={name}", "/api/data", json!({ "minTier": 3 })), op(fx, "page", "/data-page?name={name}", "/api/data", json!({ "minTier": 3 }))]
}

#[test]
fn concurrent_tier_3_calls_share_one_chrome_and_each_gets_its_own_answer() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        write_spec(fx, tier3_ops(fx), "edge");
        let names = ["ann", "ben", "cat", "dan"];
        let rs = futures_util::future::join_all(names.iter().map(|name| call("edge", "page", args(json!({ "name": name })), fast()))).await;
        let got: Vec<Value> = rs.iter().map(|r| r.data.as_ref().map(|d| d["name"].clone()).unwrap_or(Value::Null)).collect();
        assert_eq!(got, names.iter().map(|n| json!(n)).collect::<Vec<_>>(), "{}", rs.iter().map(|r| j(r).to_string()).collect::<Vec<_>>().join("\n"));
    });
}

#[test]
fn tier_3_soft_from_read_the_answer_is_the_request_for_this_calls_args_not_the_neutral_pages_own() {
    if !chrome() {
        return;
    }
    run(async {
        let main = common::fixture::Fixture::start().await;
        let dir = home().join("sites");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("spa.json"),
            json!({
                "name": "spa",
                "baseUrl": main.url,
                "operations": [{
                    "name": "user",
                    "readOnly": true,
                    "minTier": 3,
                    "trigger": { "url": format!("{}/spa/{{name}}", main.url), "softFrom": format!("{}/spa/alice", main.url) },
                    "match": { "method": "GET", "path": "/api/spa/user" },
                    "request": { "method": "GET", "url": format!("{}/api/spa/user?name=alice", main.url), "headers": {} },
                    "slots": [{ "param": "name", "at": ["query:name"] }],
                    "params": [{ "name": "name", "example": "alice" }],
                    "response": { "format": "json" },
                }],
            })
            .to_string(),
        )
        .unwrap();
        let r = call("spa", "user", args(json!({ "name": "bob" })), fast()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.data, Some(json!({ "name": "bob" })), "returned the neutral page's data as this call's answer");
        main.close();
    });
}

#[test]
fn a_read_only_ops_tier_3_trigger_cannot_perform_a_write_mcp_without_allow_writes() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let mut ops = tier3_ops(fx);
        // a shared spec says "read", but its trigger clicks a button that POSTs
        ops.push(op(
            fx,
            "sneaky",
            "/vote-page?name={name}",
            "/api/data",
            json!({ "minTier": 3, "trigger": { "url": format!("{}/vote-page?name={{name}}", fx.url), "steps": [{ "action": "click", "selector": "#post" }] } }),
        ));
        write_spec(fx, ops, "edge");
        let server = Server::new(false); // writes not allowed
        let before = votes(fx).len();
        server.call_tool("call_operation", &args(json!({ "site": "edge", "op": "sneaky", "args": { "name": "zed" } }))).await;
        assert_eq!(votes(fx)[before..], Vec::<String>::new()[..], "a POST left the browser during a read");
    });
}

#[test]
fn add_on_a_trigger_that_redirects_to_a_login_page_does_not_silently_learn_the_login_page() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        write_spec(fx, tier3_ops(fx), "edge");
        clear_cookies().await;
        let login = re("(?i)log ?in|sign ?in");
        match add_operation(add("edge", "walled", Some(Trigger { url: format!("{}/members?name={{name}}", fx.url), steps: None, soft_from: None }), vec![json!({ "name": "alice" }), json!({ "name": "bobby" })])).await {
            Err(e) => assert!(login.is_match(&e.to_string()), "{e}"),
            Ok(r) => assert!(
                r.warnings.iter().any(|w| login.is_match(w)),
                "learned {} with no login warning; preview: {}",
                r.operation.request.url,
                r.preview.as_ref().map(|p| j(p).to_string()).unwrap_or_default().chars().take(120).collect::<String>()
            ),
        }
    });
}

#[test]
fn a_tier_3_read_whose_trigger_lands_on_a_login_page_is_auth_with_a_login_hint() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        write_spec(fx, tier3_ops(fx), "edge");
        clear_cookies().await;
        let r = call("edge", "members", args(json!({ "name": "zed" })), fast()).await;
        assert!(!r.ok);
        assert_eq!(r.class, api_anything::classify::Class::Auth, "{}", j(&r));
        assert!(re("api-anything login edge").is_match(r.next.as_deref().unwrap_or("")), "{:?}", r.next);
    });
}

#[test]
fn once_the_user_has_signed_in_that_tier_3_read_answers_the_logged_out_run_must_not_mark_it_stale() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        write_spec(fx, tier3_ops(fx), "edge");
        clear_cookies().await;
        let logged_out = call("edge", "members", args(json!({ "name": "zed" })), fast()).await;
        assert_eq!(logged_out.class, api_anything::classify::Class::Auth, "{}", j(&logged_out));
        // what `api-anything login` leaves behind
        add_cookies_to_profile(&[StoredCookie::new("sid", "signed-in-session-1234", "127.0.0.1")], &profile_dir()).await.unwrap();
        let r = call("edge", "members", args(json!({ "name": "zed" })), fast()).await;
        assert!(r.ok, "{}; stale={:?}", j(&r), stale_mark("edge", "members", now_ms()));
        assert_eq!(r.data, Some(json!({ "name": "zed", "followers": 300 })));
    });
}

/* ------------------------------------------------------------ writes and tier 2 */

fn hang_ops(fx: &EdgeFixture) -> Vec<Value> {
    vec![json!({
        "name": "hang",
        "readOnly": true,
        "minTier": 2,
        "trigger": { "url": format!("{}/data-page", fx.url) },
        "match": { "path": "/hang" },
        "request": { "method": "GET", "url": format!("{}/hang", fx.url), "headers": {} },
        "response": { "format": "json" },
    })]
}

async fn capture_write(url: &str, steps_v: Option<Value>, soft_from: Option<String>) -> api_anything::heal::CaptureFile {
    capture_page(CapturePageOptions { url: url.to_string(), steps: steps_v.map(steps), soft_from, write: true, args: None }).await.unwrap()
}

#[test]
fn a_known_writes_match_aborts_it_whatever_its_resource_type_image_ping() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        write_spec(fx, hang_ops(fx), "edge");
        let before = votes(fx).len();
        // learning itself may refuse (an image request is ranked as noise even with --match); the write must not go out either way
        let mut input = add("edge", "vote", Some(Trigger { url: format!("{}/vote-page", fx.url), steps: Some(steps(json!([{ "action": "click", "selector": "#img" }]))), soft_from: None }), vec![json!({})]);
        input.write = true;
        input.matcher = Some(parse_match(&json!({ "path": "/api/vote" })).unwrap());
        let _ = add_operation(input).await;
        assert_eq!(votes(fx).len(), before, "learning sent the vote");
    });
}

async fn get_write_never_reaches_the_server(sel: &str) {
    let fx = fx().await;
    let before = votes(fx).len();
    capture_write(&format!("{}/vote-page", fx.url), Some(json!([{ "action": "click", "selector": sel }])), None).await;
    assert_eq!(votes(fx)[before..], Vec::<String>::new()[..], "the write was performed while learning it");
}

#[test]
fn capture_write_a_get_write_sent_by_an_image_ping_during_the_steps_never_reaches_the_server() {
    if !chrome() {
        return;
    }
    run(get_write_never_reaches_the_server("#img"));
}

#[test]
fn capture_write_a_get_write_sent_by_a_link_navigation_during_the_steps_never_reaches_the_server() {
    if !chrome() {
        return;
    }
    run(get_write_never_reaches_the_server("#link"));
}

#[test]
fn capture_write_a_get_write_sent_by_a_get_form_submission_during_the_steps_never_reaches_the_server() {
    if !chrome() {
        return;
    }
    run(get_write_never_reaches_the_server("#submit"));
}

#[test]
fn capture_write_a_get_write_sent_by_an_injected_script_jsonp_during_the_steps_never_reaches_the_server() {
    if !chrome() {
        return;
    }
    run(get_write_never_reaches_the_server("#script"));
}

#[test]
fn capture_write_a_get_write_sent_by_an_injected_iframe_during_the_steps_never_reaches_the_server() {
    if !chrome() {
        return;
    }
    run(get_write_never_reaches_the_server("#iframe"));
}

#[test]
fn capture_write_a_get_write_sent_by_a_link_that_opens_in_a_new_tab_during_the_steps_never_reaches_the_server() {
    if !chrome() {
        return;
    }
    run(get_write_never_reaches_the_server("#newtab"));
}

#[test]
fn capture_write_a_get_write_sent_by_window_open_during_the_steps_never_reaches_the_server() {
    if !chrome() {
        return;
    }
    run(get_write_never_reaches_the_server("#open"));
}

#[test]
fn capture_write_a_get_write_sent_by_a_fetch_the_page_sends_again_after_every_failure_never_reaches_the_server() {
    if !chrome() {
        return;
    }
    run(get_write_never_reaches_the_server("#retry"));
}

#[test]
fn capture_write_a_stylesheet_the_guard_allows_that_is_redirected_to_the_write_is_stopped_at_the_redirect() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let before = votes(fx).len();
        let seen = fx.calls().len();
        let r = capture_write(&format!("{}/vote-page", fx.url), Some(json!([{ "action": "click", "selector": "#hop" }])), None).await;
        assert!(fx.calls()[seen..].contains(&"/safe.css".to_string()), "the stylesheet itself was allowed, so the redirect happened");
        assert_eq!(votes(fx)[before..], Vec::<String>::new()[..], "the redirect carried the request to the write");
        let hops: Vec<(bool, String)> = r.result.exchanges.iter().filter(|e| e.request.url.ends_with("/api/vote?how=hop")).map(|e| (e.aborted, e.resource_type.clone())).collect();
        assert_eq!(hops, vec![(true, "stylesheet".to_string())], "recorded once, as aborted");
    });
}

#[test]
fn capture_write_a_write_that_is_a_new_tabs_first_navigation_is_recorded_as_aborted_so_it_can_be_learned() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let r = capture_write(&format!("{}/vote-page", fx.url), Some(json!([{ "action": "click", "selector": "#newtab" }])), None).await;
        let vote = r.result.exchanges.iter().find(|e| e.request.url.ends_with("/api/vote?how=newtab"));
        assert_eq!(vote.map(|v| (v.aborted, v.resource_type.clone())), Some((true, "document".to_string())), "{}", urls(&r.result));
    });
}

/// `ctx.pages().find(p => p.url() === url)`
fn page_at(ctx: &api_anything::browser::Browser, url: &str) -> Option<api_anything::browser::Attached> {
    ctx.pages().into_iter().find(|p| p.url == url)
}

#[test]
fn capture_write_a_new_tab_that_another_runs_page_opens_meanwhile_is_not_stopped_by_this_runs_guard() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let before = votes(fx).len();
        let seen = fx.calls().len();
        // The first step loads a stylesheet, which the write guard lets through: once the server has
        // seen it the run is in its steps, where every other GET of its own pages is aborted.
        let url = format!("{}/vote-page", fx.url);
        let run_task = tokio::spawn(async move { capture_write(&url, Some(json!([{ "action": "click", "selector": "#css" }, { "action": "wait", "ms": 4000 }])), None).await });
        // after the run has started: it holds the browser, which is otherwise closed when idle
        let _h = hold();
        let ctx = open_browser(&profile_dir(), true).await.unwrap();
        let other = ctx.new_page(None).await.unwrap();
        other.navigate(&format!("{}/vote-page?name=other", fx.url), None, Duration::from_secs(30)).await.unwrap();
        assert!(until(|| fx.calls()[seen..].contains(&"/acting.css".to_string()), 20_000).await, "the run reached its steps");
        let known: HashSet<String> = ctx.pages().into_iter().map(|p| p.target_id).collect();
        other.evaluate("document.querySelector('#newtab').click()").await.unwrap();
        let landed = format!("{}/api/vote?how=newtab", fx.url);
        assert!(until(|| ctx.pages().iter().any(|p| !known.contains(&p.target_id) && p.url == landed), 10_000).await, "the other page's tab opened and loaded");
        for p in ctx.pages().into_iter().filter(|p| !known.contains(&p.target_id)) {
            let _ = ctx.close_target(&p.target_id).await;
        }
        assert!(!run_task.is_finished(), "the run had ended before the other tab opened: nothing was tested");
        assert_eq!(votes(fx)[before..], vec!["/api/vote?how=newtab".to_string()][..], "this run's guard stopped another run's tab");
        let _ = other.close().await;
        run_task.await.unwrap();
    });
}

#[test]
fn another_runs_new_tab_still_loads_after_this_runs_first_page_has_closed_while_a_tab_it_opened_lives_on() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let before = votes(fx).len();
        // Guarded like a write from its step on. Its match never answers, so after the step it waits
        // a few seconds without touching its page, which can be closed under it meanwhile.
        let mine_url = format!("{}/popup?name=mine", fx.url);
        let mut o = TriggerOptions::new(&mine_url, &profile_dir());
        o.steps = Some(steps(json!([{ "action": "click", "selector": "#open" }])));
        o.matcher = Some(Arc::new(|_| false));
        o.intercept = Some(Arc::new(|_, acting, _| acting));
        let run_task = tokio::spawn(async move {
            let _ = run_trigger(o).await;
        });
        // after the run has started: it holds the browser, which is otherwise closed when idle
        let _h = hold();
        let ctx = open_browser(&profile_dir(), true).await.unwrap();
        let other = ctx.new_page(None).await.unwrap();
        other.navigate(&format!("{}/vote-page?name=other", fx.url), None, Duration::from_secs(30)).await.unwrap();
        let mine = || page_at(&ctx, &mine_url);
        let tabbed = until(|| mine().map(|m| ctx.pages().iter().any(|p| p.opener_id.as_deref() == Some(m.target_id.as_str()))).unwrap_or(false), 20_000).await;
        assert!(tabbed, "the run's page opened its tab");
        let mine_id = mine().unwrap().target_id;
        ctx.close_target(&mine_id).await.unwrap();
        // A tab is reported at its address once its first navigation is over; when a guard aborted it,
        // it sits on Chrome's error page instead. The run's own tab may be a moment from being held,
        // and a tab opened in that moment is rightly taken for a possible tab of the run: one opened
        // after it must load.
        let landed = format!("{}/api/vote?how=newtab", fx.url);
        let mut loaded = false;
        let mut opened: Vec<String> = Vec::new();
        for _ in 0..5 {
            if loaded || run_task.is_finished() {
                break;
            }
            let known: HashSet<String> = ctx.pages().into_iter().map(|p| p.target_id).collect();
            other.evaluate("document.querySelector('#newtab').click()").await.unwrap();
            until(|| ctx.pages().iter().any(|p| !known.contains(&p.target_id)), 5000).await;
            sleep(300).await;
            let fresh: Vec<_> = ctx.pages().into_iter().filter(|p| !known.contains(&p.target_id)).collect();
            loaded = fresh.iter().any(|p| p.url == landed);
            opened.extend(fresh.into_iter().map(|p| p.target_id));
            if !loaded {
                sleep(200).await;
            }
        }
        assert!(!run_task.is_finished(), "the run had ended before the other tab loaded: nothing was tested");
        assert!(loaded, "this run's guard stopped every tab another run opened once its own first page was gone");
        assert!(votes(fx).len() > before);
        run_task.await.unwrap();
        for id in opened {
            let _ = ctx.close_target(&id).await;
        }
        let _ = other.close().await;
    });
}

#[test]
fn the_runs_only_page_closes_while_a_tab_it_opened_still_has_no_page_the_tab_goes_with_the_run_and_other_runs_tabs_load() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let before = votes(fx).len();
        let seen = fx.calls().len();
        // Guarded like a write, except that the slow tab's own document may be asked for (and then
        // waits at the server). The match never answers, so the run waits a few seconds without
        // touching its page.
        let only_url = format!("{}/late-tab-page?name=only", fx.url);
        let mut o = TriggerOptions::new(&only_url, &profile_dir());
        o.matcher = Some(Arc::new(|_| false));
        o.intercept = Some(Arc::new(|e, acting, _| acting && !e.request.url.ends_with("/held-vote")));
        let run_task = tokio::spawn(async move {
            let _ = run_trigger(o).await;
        });
        // after the run has started: it holds the browser, so that it (and anything the run left behind) is still there once the run is over
        let _h = hold();
        let ctx = open_browser(&profile_dir(), true).await.unwrap();
        let other = ctx.new_page(None).await.unwrap();
        other.navigate(&format!("{}/vote-page?name=other", fx.url), None, Duration::from_secs(30)).await.unwrap();
        assert!(until(|| fx.calls()[seen..].contains(&"/held-vote".to_string()), 20_000).await, "the slow tab was opened");
        let only = page_at(&ctx, &only_url).expect("the run's page");
        ctx.close_target(&only.target_id).await.unwrap();
        run_task.await.unwrap();
        // A tab is reported at its address once its first navigation is over, or on Chrome's error
        // page when a guard aborted it.
        let known: HashSet<String> = ctx.pages().into_iter().map(|p| p.target_id).collect();
        other.evaluate("document.querySelector('#newtab').click()").await.unwrap();
        until(|| ctx.pages().iter().any(|p| !known.contains(&p.target_id)), 5000).await;
        sleep(300).await;
        let tab = ctx.pages().into_iter().find(|p| !known.contains(&p.target_id)).expect("the other page's tab");
        let landed = tab.url.clone();
        let _ = ctx.close_target(&tab.target_id).await;
        assert_eq!(landed, format!("{}/api/vote?how=newtab", fx.url), "what the run left behind aborted another run's tab");
        fx.release(); // the slow tab's document, with a script that POSTs: nobody is left to run it
        sleep(500).await;
        assert_eq!(votes(fx)[before..], vec!["/api/vote?how=newtab".to_string()][..]);
        let open: Vec<String> = ctx.pages().into_iter().map(|p| p.url).collect();
        assert!(!open.iter().any(|u| u.contains("/held-vote")), "the run's tab was left open: {open:?}");
        let _ = other.close().await;
    });
}

// In the TypeScript, "when the browser does not say whose a new tab is, its first navigation is
// still judged, as the run's own" injects a fault into Playwright's tab bookkeeping. Over DevTools a
// popup is attached, and covered, before its first navigation: the test keeps the behavior wanted.
#[test]
fn when_the_browser_does_not_say_whose_a_new_tab_is_its_first_navigation_is_still_judged_as_the_runs_own() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let before = votes(fx).len();
        let seen = fx.calls().len();
        let r = capture_write(
            &format!("{}/vote-page", fx.url),
            Some(json!([{ "action": "click", "selector": "#css" }, { "action": "wait", "ms": 1500 }, { "action": "click", "selector": "#newtab" }])),
            None,
        )
        .await;
        assert!(fx.calls()[seen..].contains(&"/acting.css".to_string()), "the run reached its steps");
        assert_eq!(votes(fx)[before..], Vec::<String>::new()[..], "the write was performed while learning it");
        // decided, not left waiting for an answer that never comes: stopped, and in the capture
        let tab: Vec<&Exchange> = r.result.exchanges.iter().filter(|e| e.request.url.ends_with("/api/vote?how=newtab")).collect();
        assert_eq!(tab.first().map(|e| e.aborted), Some(true), "the new tab's navigation was never judged: {}", j(&tab));
    });
}

#[test]
fn the_record_of_who_opened_which_tab_keeps_nothing_of_tabs_that_have_closed() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let _h = hold();
        let ctx = open_browser(&profile_dir(), true).await.unwrap();
        for _ in 0..3 {
            capture_write(&format!("{}/vote-page", fx.url), Some(json!([{ "action": "click", "selector": "#newtab" }])), None).await;
        }
        // the record lives as long as the browser does: a long-lived server would grow it with every tab
        assert!(until(|| ctx.opener_records() == 0, 2000).await, "{} closed tabs still on record", ctx.opener_records());
    });
}

#[test]
fn an_app_that_waits_for_its_shared_worker_starts_guarded_or_not() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let guards: [Option<api_anything::browser::Intercept>; 2] = [None, Some(Arc::new(|e, _, _| e.request.method != "GET"))];
        for intercept in guards {
            let guarded = intercept.is_some();
            let mut o = TriggerOptions::new(&format!("{}/worker-app?name=app", fx.url), &profile_dir());
            o.intercept = intercept;
            let r = run_trigger(o).await.unwrap();
            let urls: Vec<String> = r.exchanges.iter().filter_map(|e| url::Url::parse(&e.request.url).ok()).map(|u| format!("{}{}", u.path(), u.query().map(|q| format!("?{q}")).unwrap_or_default())).collect();
            assert!(urls.contains(&"/api/data?name=app".to_string()), "{}: {urls:?}", if guarded { "guarded" } else { "unguarded" });
        }
    });
}

#[test]
fn a_tab_the_runs_page_opened_that_has_no_page_yet_when_the_run_ends_is_closed_with_it_and_never_writes() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let before = votes(fx).len();
        let seen = fx.calls().len();
        let _h = hold();
        // guarded like a tier-3 read: the tab's own document (a GET) may load, what it POSTs may not leave
        let mut o = TriggerOptions::new(&format!("{}/late-tab-page", fx.url), &profile_dir());
        o.intercept = Some(Arc::new(|e, acting, _| acting && e.request.method != "GET"));
        run_trigger(o).await.unwrap();
        assert!(fx.calls()[seen..].contains(&"/held-vote".to_string()), "the slow tab was opened");
        fx.release(); // the tab's document arrives only now, with a script that POSTs
        sleep(1000).await;
        assert_eq!(votes(fx)[before..], Vec::<String>::new()[..], "the tab wrote once the run's guard was lifted");
        let open: Vec<String> = open_browser(&profile_dir(), true).await.unwrap().pages().into_iter().map(|p| p.url).filter(|u| u.contains("/held-vote")).collect();
        assert_eq!(open, Vec::<String>::new(), "the tab was left open");
    });
}

#[test]
fn a_tab_whose_opener_has_closed_by_the_time_its_page_comes_is_still_the_runs_what_it_posts_mid_run_never_leaves() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let before = votes(fx).len();
        let seen = fx.calls().len();
        // mid-run: once the slow tab has asked for its document and the tab between has closed itself
        let answered = tokio::spawn(async move {
            let asked = until(|| fx.calls()[seen..].contains(&"/held-vote".to_string()), 20_000).await;
            sleep(600).await;
            fx.release();
            asked
        });
        let mut o = TriggerOptions::new(&format!("{}/chain-page", fx.url), &profile_dir());
        o.steps = Some(steps(json!([{ "action": "wait", "ms": 3000 }])));
        o.intercept = Some(Arc::new(|e, acting, _| acting && e.request.method != "GET"));
        run_trigger(o).await.unwrap();
        assert!(answered.await.unwrap(), "the slow tab was opened");
        sleep(300).await;
        assert_eq!(votes(fx)[before..], Vec::<String>::new()[..], "a tab of the run wrote: its opener was closed, so nobody claimed it");
    });
}

async fn leaving_write_never_reaches_the_server(how: &str) {
    let fx = fx().await;
    let before = votes(fx).len();
    let r = capture_write(&format!("{}/leave-page?how={how}", fx.url), None, None).await;
    // nothing arriving proves nothing if the page never registered its deferred request
    if how == "later" && !r.result.exchanges.iter().any(|e| e.request.url.ends_with("/api/data?name=registered")) {
        eprintln!("this Chrome has no fetchLater(): skipped");
        return;
    }
    sleep(300).await; // what a closing page got out arrives after the run has returned
    assert_eq!(votes(fx)[before..], Vec::<String>::new()[..], "the write was performed while learning it");
    // stopped as the run ended, and still learnable: a write that is only ever sent on leaving
    let stopped: Vec<bool> = load_capture(&r.id).unwrap().result.exchanges.iter().filter(|e| e.request.url.ends_with(&format!("/api/vote?how={how}"))).map(|e| e.aborted).collect();
    assert_eq!(stopped, vec![true], "{}", urls(&r.result));
}

#[test]
fn capture_write_a_pagehide_beacon_never_reaches_the_server_when_the_run_ends_and_is_in_the_capture() {
    if !chrome() {
        return;
    }
    run(leaving_write_never_reaches_the_server("beacon"));
}

#[test]
fn capture_write_a_keepalive_fetch_on_pagehide_never_reaches_the_server_when_the_run_ends_and_is_in_the_capture() {
    if !chrome() {
        return;
    }
    run(leaving_write_never_reaches_the_server("keepalive"));
}

#[test]
fn capture_write_a_beacon_when_the_page_is_hidden_never_reaches_the_server_when_the_run_ends_and_is_in_the_capture() {
    if !chrome() {
        return;
    }
    run(leaving_write_never_reaches_the_server("hidden"));
}

#[test]
fn capture_write_an_image_ping_on_pagehide_never_reaches_the_server_when_the_run_ends_and_is_in_the_capture() {
    if !chrome() {
        return;
    }
    run(leaving_write_never_reaches_the_server("img"));
}

#[test]
fn capture_write_a_pagehide_handler_that_takes_400_ms_to_send_never_reaches_the_server_when_the_run_ends_and_is_in_the_capture() {
    if !chrome() {
        return;
    }
    run(leaving_write_never_reaches_the_server("slow"));
}

#[test]
fn capture_write_a_deferred_fetch_later_never_reaches_the_server_when_the_run_ends_and_is_in_the_capture() {
    if !chrome() {
        return;
    }
    run(leaving_write_never_reaches_the_server("later"));
}

#[test]
fn capture_write_a_beacon_a_page_sends_as_the_run_leaves_it_for_the_next_is_aborted_and_recorded() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let before = votes(fx).len();
        // the neutral page is left by a plain load (it has no router): its pagehide fires mid-run
        let r = capture_write(&format!("{}/data-page", fx.url), None, Some(format!("{}/leave-page?how=beacon", fx.url))).await;
        sleep(300).await;
        assert_eq!(votes(fx)[before..], Vec::<String>::new()[..], "the write was performed while learning it");
        let beacon = r.result.exchanges.iter().find(|e| e.request.url.ends_with("/api/vote?how=beacon"));
        assert_eq!(
            beacon.map(|b| (b.aborted, b.request.method.clone(), b.request.body.clone())),
            Some((true, "POST".to_string(), Some("up".to_string()))),
            "{}",
            urls(&r.result)
        );
    });
}

#[test]
fn capture_write_a_message_sent_over_an_already_open_web_socket_never_reaches_the_server() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let before = fx.ws_messages();
        capture_write(
            &format!("{}/chat", fx.url),
            Some(json!([{ "action": "fill", "selector": "#msg", "value": "a private message" }, { "action": "click", "selector": "#send" }])),
            None,
        )
        .await;
        sleep(300).await;
        assert_eq!(fx.ws_messages(), before, "the message was sent while learning it");
    });
}

// In the TypeScript, "a page that will neither empty nor close keeps the socket guard until it is
// really gone, however long that takes" injects a fault into Playwright's page.goto/close so the
// run's page outlives the run, and checks that a context-wide socket guard is neither dropped on a
// timer nor kept once the page is gone. Over DevTools the guard is a script in the guarded page
// itself, which lives and dies with it: what remains observable is that a page of another run can
// send over its socket once this run is over.
#[test]
fn a_page_that_will_neither_empty_nor_close_keeps_the_socket_guard_until_it_is_really_gone_however_long_that_takes() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        let before = fx.ws_messages();
        let _h = hold();
        capture_write(&format!("{}/chat", fx.url), Some(json!([{ "action": "wait", "ms": 1500 }])), None).await;
        assert_eq!(fx.ws_messages(), before, "a page of the run sent over its socket");
        // once the run's page is really gone the guard goes too: it must not drop another page's sends
        let ctx = open_browser(&profile_dir(), true).await.unwrap();
        let other = ctx.new_page(None).await.unwrap();
        other.navigate(&format!("{}/chat", fx.url), None, Duration::from_secs(30)).await.unwrap();
        let mut sent = false;
        let end = Instant::now() + Duration::from_millis(5000);
        while !sent && Instant::now() < end {
            let _ = other.evaluate("document.querySelector('#send').click()").await;
            sleep(200).await;
            sent = fx.ws_messages() > before;
        }
        let _ = other.close().await;
        assert!(sent, "the socket guard outlived the run's last page");
    });
}

#[test]
fn a_tier_2_request_that_never_answers_times_out_instead_of_hanging_the_call() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        write_spec(fx, hang_ops(fx), "edge");
        let t0 = Instant::now();
        let r = tokio::time::timeout(Duration::from_millis(20_000), call("edge", "hang", args(json!({})), CallOptions { min_interval_ms: Some(0), timeout_ms: Some(3000), ..Default::default() })).await;
        assert!(r.is_ok(), "call() still pending after 20 s (timeoutMs 3000)");
        assert!(t0.elapsed() < Duration::from_millis(15_000), "{:?}", t0.elapsed());
    });
}

/* ------------------------------------------------------------ two processes, one profile */

struct CliRun {
    code: Option<i32>,
    signal: Option<i32>,
    stdout: String,
    stderr: String,
    ms: u64,
}

struct Spawned {
    child: tokio::process::Child,
    t0: Instant,
}

fn cli_spawn(cmd_args: &[&str]) -> Spawned {
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-anything"));
    c.args(cmd_args).env("API_ANYTHING_HOME", home()).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    Spawned { child: c.spawn().expect("the api-anything binary"), t0: Instant::now() }
}

impl Spawned {
    fn pid(&self) -> i32 {
        self.child.id().unwrap() as i32
    }
    async fn wait(mut self, kill_after_ms: Option<u64>) -> CliRun {
        use std::os::unix::process::ExitStatusExt;
        let t0 = self.t0;
        let stdout = self.child.stdout.take().unwrap();
        let stderr = self.child.stderr.take().unwrap();
        let out = tokio::spawn(async move {
            let mut s = String::new();
            let _ = tokio::io::AsyncReadExt::read_to_string(&mut tokio::io::BufReader::new(stdout), &mut s).await;
            s
        });
        let err = tokio::spawn(async move {
            let mut s = String::new();
            let _ = tokio::io::AsyncReadExt::read_to_string(&mut tokio::io::BufReader::new(stderr), &mut s).await;
            s
        });
        let status = match kill_after_ms {
            Some(ms) => match tokio::time::timeout(Duration::from_millis(ms), self.child.wait()).await {
                Ok(s) => s.unwrap(),
                Err(_) => {
                    let _ = self.child.start_kill();
                    self.child.wait().await.unwrap()
                }
            },
            None => self.child.wait().await.unwrap(),
        };
        CliRun { code: status.code(), signal: status.signal(), stdout: out.await.unwrap(), stderr: err.await.unwrap(), ms: t0.elapsed().as_millis() as u64 }
    }
}

async fn cli(cmd_args: &[&str]) -> CliRun {
    cli_spawn(cmd_args).wait(None).await
}

/// A step that keeps a capture running, so a signal lands mid-capture.
const BUSY: &str = r#"[{"action":"wait","ms":20000}]"#;

/// Chrome processes launched on this home's profile.
fn chromes() -> usize {
    let needle = format!("{}/profile", home().display());
    let out = std::process::Command::new("ps").args(["-axo", "command"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    out.lines().filter(|l| l.contains(&needle) && !l.contains("ps -axo")).count()
}

fn kill(pid: i32, sig: i32) {
    unsafe {
        libc::kill(pid, sig);
    }
}

fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// An `api-anything mcp` server that has run a tier-3 call, so it holds the profile.
struct McpClient {
    child: tokio::process::Child,
    stdin: Option<tokio::process::ChildStdin>,
    lines: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    next_id: u64,
}

impl McpClient {
    async fn request(&mut self, method: &str, params: Value) -> Value {
        use tokio::io::AsyncWriteExt;
        self.next_id += 1;
        let msg = json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params });
        self.stdin.as_mut().unwrap().write_all(format!("{msg}\n").as_bytes()).await.unwrap();
        loop {
            let line = tokio::time::timeout(Duration::from_secs(120), self.lines.next_line()).await.expect("an answer within 2 min").unwrap().expect("the server answers");
            let v: Value = serde_json::from_str(&line).unwrap();
            if v.get("id") == Some(&json!(self.next_id)) {
                return v;
            }
        }
    }
    fn pid(&self) -> i32 {
        self.child.id().unwrap() as i32
    }
    /// `!alive(pid)` for a child this test holds: a child nobody has waited for stays a zombie that still answers `kill(pid, 0)`.
    fn exited(&mut self) -> bool {
        self.child.try_wait().map(|s| s.is_some()).unwrap_or(true)
    }
    /// `client.close()`: the transport goes away (stdin closed, then the process waited for).
    async fn close(mut self) {
        drop(self.stdin.take());
        let _ = tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await;
        let _ = self.child.start_kill();
    }
}

async fn mcp_holding_chrome() -> McpClient {
    use tokio::io::AsyncBufReadExt;
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-anything"));
    c.arg("mcp").env("API_ANYTHING_HOME", home()).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    let mut child = c.spawn().expect("the api-anything binary");
    let stdin = child.stdin.take();
    let stdout = child.stdout.take().unwrap();
    let mut client = McpClient { child, stdin, lines: tokio::io::BufReader::new(stdout).lines(), next_id: 0 };
    client.request("initialize", json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "edge", "version": "0" } })).await;
    let r = client.request("tools/call", json!({ "name": "call_operation", "arguments": { "site": "edge", "op": "page", "args": { "name": "mcp" } } })).await;
    assert_eq!(r["result"]["isError"], json!(false), "{r}");
    client
}

fn two_process_ops(fx: &EdgeFixture) -> Vec<Value> {
    vec![
        op(fx, "page", "/data-page?name={name}", "/api/data", json!({ "minTier": 3 })),
        // stored template points at a path that now 404s: drift, healable by recapture from /data-page
        op(fx, "gone", "/data-page?name={name}", "/api/gone", json!({})),
    ]
}

#[test]
fn a_cli_capture_exits_cleanly_and_leaves_no_chrome_behind() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        close_browser().await;
        write_spec(fx, two_process_ops(fx), "edge");
        let r = cli(&["capture", &format!("{}/data-page?name=cli", fx.url)]).await;
        assert_eq!(r.code, Some(0), "{}{}", r.stdout, r.stderr);
        assert!(until(|| chromes() == 0, 3000).await, "Chrome processes left on the profile");
    });
}

#[test]
fn ctrl_c_mid_capture_exits_130_and_kills_chrome() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        close_browser().await;
        write_spec(fx, two_process_ops(fx), "edge");
        // a wait step keeps the capture busy (the SSE page alone no longer holds a capture open)
        let running = cli_spawn(&["capture", &format!("{}/sse-page", fx.url), "--steps", BUSY]);
        let pid = running.pid();
        assert!(until(|| chromes() > 0, 15_000).await, "Chrome never started");
        kill(pid, libc::SIGINT);
        let r = running.wait(Some(30_000)).await;
        // Node's default SIGINT handler exits 130; a Rust binary with no handler ends by the signal itself
        assert!(r.code == Some(130) || r.signal == Some(libc::SIGINT), "code {:?} signal {:?}", r.code, r.signal);
        assert!(until(|| chromes() == 0, 3000).await, "Chrome processes left on the profile");
    });
}

#[test]
fn sigkill_mid_capture_leaves_no_chrome_behind_and_the_next_run_can_launch_on_the_profile() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        close_browser().await;
        write_spec(fx, two_process_ops(fx), "edge");
        // a wait step keeps the capture busy (the SSE page alone no longer holds a capture open)
        let running = cli_spawn(&["capture", &format!("{}/sse-page", fx.url), "--steps", BUSY]);
        let pid = running.pid();
        assert!(until(|| chromes() > 0, 15_000).await, "Chrome never started");
        sleep(1000).await;
        kill(pid, libc::SIGKILL);
        running.wait(Some(30_000)).await;
        assert!(until(|| chromes() == 0, 5000).await, "orphaned Chrome processes on the profile");
        let next = cli(&["capture", &format!("{}/data-page?name=after", fx.url)]).await;
        assert_eq!(next.code, Some(0), "{}{}", next.stdout.chars().take(300).collect::<String>(), next.stderr);
    });
}

#[test]
fn closing_the_mcp_servers_stdin_exits_it_and_its_chrome() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        close_browser().await;
        write_spec(fx, two_process_ops(fx), "edge");
        let client = mcp_holding_chrome().await;
        let pid = client.pid();
        client.close().await;
        assert!(until(|| !alive(pid), 5000).await, "server still running");
        assert!(until(|| chromes() == 0, 5000).await, "Chrome left running");
    });
}

#[test]
fn sigterm_mid_capture_exits_promptly() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        close_browser().await;
        write_spec(fx, two_process_ops(fx), "edge");
        // a wait step keeps the capture busy (the SSE page alone no longer holds a capture open)
        let running = cli_spawn(&["capture", &format!("{}/sse-page", fx.url), "--steps", BUSY]);
        let pid = running.pid();
        assert!(until(|| chromes() > 0, 15_000).await, "Chrome never started");
        sleep(2000).await; // the page is loaded and the capture is waiting for the network to go quiet
        let t0 = Instant::now();
        kill(pid, libc::SIGTERM);
        let r = running.wait(Some(40_000)).await;
        assert!(t0.elapsed() < Duration::from_millis(5000), "exited {} ms after SIGTERM: {}", t0.elapsed().as_millis(), r.stdout.chars().take(160).collect::<String>());
    });
}

#[test]
fn while_an_mcp_server_holds_the_profile_a_cli_capture_fails_fast_with_a_hint_naming_the_lock() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        close_browser().await;
        write_spec(fx, two_process_ops(fx), "edge");
        let client = mcp_holding_chrome().await;
        let r = cli_spawn(&["capture", &format!("{}/data-page?name=second", fx.url)]).wait(Some(60_000)).await;
        client.close().await;
        if r.code == Some(0) {
            return; // sharing the browser would be a fine fix too
        }
        assert!(r.ms < 15_000, "took {} ms", r.ms);
        assert!(
            re("(?im)^next: .*(in use|another|already running|mcp)").is_match(&r.stderr),
            "stderr: {}; stdout starts: {}",
            r.stderr,
            r.stdout.chars().take(200).collect::<String>()
        );
    });
}

#[test]
fn a_heal_that_could_not_launch_chrome_profile_locked_does_not_mark_the_op_stale_for_30_min() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        close_browser().await;
        write_spec(fx, two_process_ops(fx), "edge");
        clear_stale("edge", "gone");
        let client = mcp_holding_chrome().await;
        let first = call("edge", "gone", args(json!({ "name": "zed" })), fast()).await; // same profile, other process: launch fails
        client.close().await;
        close_browser().await;
        assert!(until(|| chromes() == 0, 5000).await);
        let again = call("edge", "gone", args(json!({ "name": "zed" })), fast()).await;
        assert!(again.ok, "first: {}\nthen: {}", first.reason.as_deref().unwrap_or("").chars().take(160).collect::<String>(), j(&again).to_string().chars().take(400).collect::<String>());
    });
}

#[test]
fn the_mcp_server_exits_on_sigterm_once_it_has_launched_chrome() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        close_browser().await;
        write_spec(fx, two_process_ops(fx), "edge");
        let mut client = mcp_holding_chrome().await;
        kill(client.pid(), libc::SIGTERM);
        let end = Instant::now() + Duration::from_millis(5000);
        let mut gone = client.exited();
        while !gone && Instant::now() < end {
            sleep(100).await;
            gone = client.exited();
        }
        client.close().await;
        assert!(gone, "server still running 5 s after SIGTERM");
    });
}

/* ------------------------------------------------------------ MCP */

fn mcp_ops(fx: &EdgeFixture) -> Vec<Value> {
    vec![op(fx, "get", "/data-page?name={name}", "/api/data", json!({})), op(fx, "huge", "/huge-page?name={name}", "/api/huge-items", json!({}))]
}

async fn mcp_setup() -> (&'static EdgeFixture, Server) {
    let fx = fx().await;
    write_spec(fx, mcp_ops(fx), "edge");
    std::fs::write(home().join("sites").join("broken.json"), "{ not json").unwrap();
    (fx, Server::new(false))
}

#[test]
fn unknown_site_unknown_op_missing_param_is_error_with_a_next_hint() {
    run(async {
        let (_fx, client) = mcp_setup().await;
        for a in [json!({ "site": "nope", "op": "x" }), json!({ "site": "edge", "op": "nope" }), json!({ "site": "edge", "op": "get" })] {
            let r = client.call_tool("call_operation", &args(a.clone())).await;
            assert!(r.is_error, "{a}");
            assert!(r.value.get("next").map(|n| !n.is_null() && n != "").unwrap_or(false), "{}", r.value);
        }
        let ops = client.call_tool("list_operations", &args(json!({ "site": "nope" }))).await;
        assert!(ops.is_error);
    });
}

#[test]
fn wrongly_typed_tool_args_are_rejected_as_is_error() {
    run(async {
        let (_fx, client) = mcp_setup().await;
        let r = client.call_tool("call_operation", &args(json!({ "site": "edge", "op": "get", "args": "name=bob" }))).await;
        assert!(r.is_error, "{}", r.value);
    });
}

#[test]
fn list_sites_reports_a_corrupt_spec_per_site_and_still_lists_the_rest() {
    run(async {
        let (_fx, client) = mcp_setup().await;
        let r = client.call_tool("list_sites", &args(json!({}))).await.value;
        let sites = r.as_array().expect("a list");
        assert!(sites.iter().find(|s| s["name"] == "broken").and_then(|s| s.get("error")).is_some(), "{r}");
        assert!(sites.iter().any(|s| s["name"] == "edge"), "{r}");
    });
}

#[test]
fn concurrent_tier_1_calls_all_answer_with_their_own_data() {
    run(async {
        let (_fx, client) = mcp_setup().await;
        let names = ["ann", "ben", "cat"];
        let calls: Vec<_> = names.iter().map(|name| args(json!({ "site": "edge", "op": "get", "args": { "name": name } }))).collect();
        let rs = futures_util::future::join_all(calls.iter().map(|a| client.call_tool("call_operation", a))).await;
        let got: Vec<Value> = rs.iter().map(|r| r.value["data"]["name"].clone()).collect();
        assert_eq!(got, names.iter().map(|n| json!(n)).collect::<Vec<_>>(), "{}", rs.iter().map(|r| r.value.to_string()).collect::<Vec<_>>().join("\n"));
    });
}

#[test]
fn a_corrupt_spec_or_an_invalid_site_name_comes_back_as_json_with_a_next_hint_like_every_other_failure() {
    run(async {
        let (_fx, client) = mcp_setup().await;
        for site in ["broken", "../../etc/passwd"] {
            let r = client.call_tool("call_operation", &args(json!({ "site": site, "op": "x" }))).await;
            assert!(r.is_error, "{}", r.value);
            assert!(r.value.is_object(), "not JSON: {}", r.value);
            assert!(r.value.get("next").map(|n| !n.is_null() && n != "").unwrap_or(false), "{}", r.value);
        }
    });
}

#[test]
fn huge_results_items_bigger_than_the_output_cap_are_cut_not_dropped_to_an_empty_list() {
    run(async {
        let (_fx, client) = mcp_setup().await;
        let r = client.call_tool("call_operation", &args(json!({ "site": "edge", "op": "huge", "args": { "name": "bob" } }))).await.value;
        assert_eq!(r["ok"], json!(true), "{r}");
        let items = if r["data"].is_array() { r["data"].clone() } else { r["data"]["rows"].clone() };
        assert!(items.as_array().map(|a| !a.is_empty()).unwrap_or(false), "data={} truncated={}", r["data"], r["truncated"]);
    });
}

/* ------------------------------------------------------------ CLI args and store files */

fn cli_ops(fx: &EdgeFixture) -> Vec<Value> {
    vec![op(
        fx,
        "get",
        "/data-page?name={name}",
        "/api/data",
        json!({
            "request": { "method": "GET", "url": format!("{}/api/data?name=alice&n=5", fx.url), "headers": {} },
            "slots": [{ "param": "name", "at": ["query:name"] }, { "param": "n", "at": ["query:n"] }],
            "params": [{ "name": "name", "example": "alice" }, { "name": "n", "type": "number", "required": false }],
        }),
    )]
}

async fn dry(extra: &[&str]) -> (CliRun, Value) {
    let mut a = vec!["call", "edge", "get"];
    a.extend_from_slice(extra);
    a.push("--dry");
    let r = cli(&a).await;
    let out: Value = serde_json::from_str(&r.stdout).unwrap_or_else(|_| panic!("not JSON: {} / {}", r.stdout, r.stderr));
    (r, out)
}

#[test]
fn k_v_splits_on_the_first_equals_json_merges_under_k_v_empty_values_are_kept() {
    run(async {
        let fx = fx().await;
        write_spec(fx, cli_ops(fx), "edge");
        let url = |o: &Value| o["request"]["url"].as_str().unwrap_or("").to_string();
        assert!(re(r"name=a%3Db%3Dc&n=5$").is_match(&url(&dry(&["name=a=b=c"]).await.1)));
        assert!(re(r"name=y&n=3$").is_match(&url(&dry(&["--json", r#"{"name":"x","n":3}"#, "name=y"]).await.1)));
        assert!(re(r"name=&n=5$").is_match(&url(&dry(&["name="]).await.1)));
        assert!(re(r"n=12345678901234567890$").is_match(&url(&dry(&["name=x", "n=12345678901234567890"]).await.1)), "no rounding past 2^53");
    });
}

#[test]
fn malformed_input_fails_with_exit_1_a_json_error_and_a_next_line() {
    run(async {
        let fx = fx().await;
        write_spec(fx, cli_ops(fx), "edge");
        for a in [vec!["name=x", "--nope"], vec!["name=x", "--json"], vec!["=x"], vec!["--json", r#"{"name":"#], vec!["name=x", "n=abc"]] {
            let mut full = vec!["call", "edge", "get"];
            full.extend_from_slice(&a);
            full.push("--dry");
            let r = cli(&full).await;
            assert_eq!(r.code, Some(1), "{}", a.join(" "));
            let out: Value = serde_json::from_str(&r.stdout).unwrap_or_else(|_| panic!("not JSON: {}", r.stdout));
            assert_eq!(out["ok"], json!(false));
            assert!(re("(?m)^next: ").is_match(&r.stderr), "{}", r.stderr);
        }
        let bad = cli(&["inspect", "../../etc/passwd"]).await;
        assert_eq!(bad.code, Some(1));
    });
}

#[test]
fn a_read_only_home_still_serves_tier_1_reads() {
    run(async {
        use std::os::unix::fs::PermissionsExt;
        let fx = fx().await;
        write_spec(fx, cli_ops(fx), "edge");
        let h = home();
        std::fs::set_permissions(h.join("sites"), std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::set_permissions(&h, std::fs::Permissions::from_mode(0o500)).unwrap();
        let r = call("edge", "get", args(json!({ "name": "rosa" })), fast()).await;
        std::fs::set_permissions(&h, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(h.join("sites"), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(r.ok, "{}", j(&r));
    });
}

#[test]
fn max_tier_with_a_non_number_is_rejected_instead_of_silently_meaning_no_cap_no_browser() {
    run(async {
        let fx = fx().await;
        write_spec(fx, cli_ops(fx), "edge");
        let r = cli(&["call", "edge", "get", "name=x", "--max-tier", "abc"]).await;
        assert_eq!(r.code, Some(1));
        let out: Value = serde_json::from_str(&r.stdout).unwrap_or_else(|_| panic!("not JSON: {}", r.stdout));
        let text = out["error"].as_str().or(out["reason"].as_str()).unwrap_or("");
        assert!(re("max-tier").is_match(text), "{out}");
    });
}

#[test]
fn a_corrupt_session_file_is_reported_as_such_file_named_not_as_bad_args() {
    run(async {
        let fx = fx().await;
        write_spec(fx, cli_ops(fx), "edge");
        let sessions = home().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(sessions.join("edge.json"), r#"{"cookies": ["#).unwrap();
        let r = cli(&["call", "edge", "get", "name=x"]).await;
        std::fs::remove_file(sessions.join("edge.json")).unwrap();
        let out: Value = serde_json::from_str(&r.stdout).unwrap_or_else(|_| panic!("not JSON: {}", r.stdout));
        assert_ne!(out["class"], json!("input"), "class input with next \"{}\"", out["next"]);
        let text = out["reason"].as_str().or(out["error"].as_str()).unwrap_or("");
        assert!(re(r"sessions[/\\]edge\.json").is_match(text), "{out}");
    });
}

#[test]
fn site_names_differ_only_by_case_one_spec_file_must_not_get_two_sets_of_state() {
    run(async {
        let fx = fx().await;
        write_spec(fx, cli_ops(fx), "edge");
        let Some(upper) = load_site("EDGE").unwrap() else { return }; // case-sensitive file system: EDGE is simply unknown
        mark_stale("edge", "get", "probe", STALE_TTL_MS, now_ms(), None);
        let mark = stale_mark(&upper.site.name, "get", now_ms());
        clear_stale("edge", "get");
        assert!(mark.is_some(), "loadSite(\"EDGE\") resolves edge.json as site \"{}\", whose state is separate", upper.site.name);
    });
}

/* ------------------------------------------------------------ export secret scan */

fn sid_session() -> Session {
    let mut c = StoredCookie::new("sid", TOKEN, "example.com");
    c.http_only = true;
    c.secure = true;
    Session::with(vec![c], Default::default())
}

#[test]
fn exact_live_values_are_refused_raw_jwt_and_bearer_shapes_warn() {
    let session = sid_session();
    let hit = scan_secrets(&json!({ "url": format!("https://example.com/?s={TOKEN}") }), &session, &HashSet::new());
    assert_eq!(hit.secrets, vec!["$.url holds the live cookie sid".to_string()]);
    let w = scan_secrets(&json!({ "h": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlXzEyMw" }), &Session::empty(), &HashSet::new());
    assert!(re("JWT").is_match(&w.warnings.join(",")), "{:?}", w.warnings);
}

#[test]
fn a_live_cookie_that_sits_percent_encoded_or_json_escaped_in_the_spec_is_still_refused() {
    let session = sid_session();
    for spec in [
        json!({ "url": format!("https://example.com/api?s={}", encode_uri_component(TOKEN)) }),
        json!({ "body": format!("f.req={}", encode_uri_component(&json!({ "t": TOKEN }).to_string())) }),
        json!({ "body": json!({ "t": TOKEN }).to_string().replace('/', "\\/") }),
    ] {
        assert!(!scan_secrets(&spec, &session, &HashSet::new()).secrets.is_empty(), "missed in {spec}");
    }
}

#[test]
fn add_plus_export_a_page_that_echoes_its_base64_session_cookie_inside_a_query_value_export_must_refuse() {
    if !chrome() {
        return;
    }
    run(async {
        let fx = fx().await;
        close_browser().await;
        let mut input = add("tok", "user", Some(Trigger { url: format!("{}/tok-page?name={{name}}", fx.url), steps: None, soft_from: None }), vec![json!({ "name": "alice" }), json!({ "name": "bobby" })]);
        input.response = Some(Recipe { extract: Some("data".into()), ..Default::default() });
        let r = add_operation(input).await.unwrap();
        let ex = export_site("tok", false).unwrap();
        let text = j(&ex.spec).to_string();
        assert!(!text.contains("alice") && !text.contains("bobby"), "examples stripped");
        assert!(
            !text.contains(&encode_uri_component(TOKEN)) || !ex.secrets.is_empty(),
            "exported the live cookie ({}) with secrets={:?} warnings={:?}; add warnings={:?}",
            ex.spec.operations[0].request.url,
            ex.secrets,
            ex.warnings,
            r.warnings
        );
    });
}
