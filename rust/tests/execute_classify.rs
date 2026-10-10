//! test/edge/execute-classify.test.ts (with execute-classify.fixture.ts) and the `call` block of
//! test/edge/round2-classify.test.ts. Each test is a regression for a bug that was fixed.
//! Chrome-only tests skip without Chrome.
mod common;
use api_anything::browser::{add_cookies_to_profile, close_browser, open_browser};
use api_anything::classify::{Class, Observed, classify, judge};
use api_anything::execute::{CallOptions, call, heal};
use api_anything::extract::cap_output;
use api_anything::heal::profile_dir;
use api_anything::http::{Fetcher, HttpRequest, HttpResponse};
use api_anything::login::{ImportOptions, import_session};
use api_anything::mcp::Server;
use api_anything::session::{Session, cookie_header_for, cookie_value, load_session, merge_capture, save_session};
use api_anything::spec::Operation;
use api_anything::store::{remember_tier, save_site};
use api_anything::types::{Headers, StoredCookie};
use api_anything::util::{b64_encode, now_ms};
use bytes::Bytes;
use common::{Home, args, cookie, enc, j, session, site};
use futures_util::future::{BoxFuture, LocalBoxFuture};
use futures_util::{FutureExt, StreamExt};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::io::Write as _;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::Notify;

static HOME: LazyLock<Home> = LazyLock::new(Home::new);
/// One home and one Chrome profile for the binary: the tests take turns, like node's sequential tests in one file.
static LOCK: Mutex<()> = Mutex::new(());
/// One runtime for every test, so the shared browser outlives the test that opened it, as in the TS file.
static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());

fn chrome() -> bool {
    if std::env::var("API_ANYTHING_CHROME").is_err() {
        let p = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
        if Path::new(p).exists() {
            unsafe { std::env::set_var("API_ANYTHING_CHROME", p) };
        }
    }
    api_anything::browser::chrome_available()
}

/* ----------------------------------------------------------------- a small HTTP server */

#[derive(Clone, Debug)]
struct Hit {
    method: String,
    url: String,
    headers: HashMap<String, String>,
    body: String,
}

impl Hit {
    fn h(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
    fn chrome_ua(&self) -> bool {
        self.h("user-agent").unwrap_or("").contains("Chrome/")
    }
}

/// How a route answers: a response, silence, or a dropped socket.
enum Resp {
    Http(hyper::Response<BoxBody<Bytes, Infallible>>),
    Never,
    Reset,
}

type Handler = Arc<dyn Fn(Hit) -> BoxFuture<'static, Resp> + Send + Sync>;

fn res(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> Resp {
    let mut b = hyper::Response::builder().status(status);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    Resp::Http(b.body(Full::new(Bytes::from(body)).boxed()).unwrap())
}

fn json_r(v: Value, status: u16, headers: &[(&str, &str)]) -> Resp {
    let mut all: Vec<(&str, &str)> = vec![("content-type", "application/json")];
    all.extend_from_slice(headers);
    res(status, &all, v.to_string().into_bytes())
}

fn head(status: u16, headers: &[(&str, &str)]) -> Resp {
    res(status, headers, vec![])
}

fn html_r(status: u16, body: &str) -> Resp {
    res(status, &[("content-type", "text/html")], body.as_bytes().to_vec())
}

/// Headers sent, then a body that never ends.
fn stall() -> Resp {
    let first = futures_util::stream::once(async { Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"{\"items\":["))) });
    let body = StreamBody::new(first.chain(futures_util::stream::pending()));
    Resp::Http(hyper::Response::builder().status(200).header("content-type", "application/json").body(BoxBody::new(body)).unwrap())
}

#[cfg(unix)]
fn linger_zero(fd: std::os::unix::io::RawFd) {
    let l = libc::linger { l_onoff: 1, l_linger: 0 };
    // SAFETY: a plain setsockopt on a socket this task still owns
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &l as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
}

/// Serve `handler` on a fresh port of `host`; `shown` is the host name in the returned base URL.
async fn serve(host: &str, shown: &str, handler: Handler) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((host, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let handler = handler.clone();
            tokio::spawn(async move {
                #[cfg(unix)]
                let fd = {
                    use std::os::unix::io::AsRawFd;
                    stream.as_raw_fd()
                };
                let reset = Arc::new(Notify::new());
                let reset2 = reset.clone();
                let service = service_fn(move |req: hyper::Request<Incoming>| {
                    let handler = handler.clone();
                    let reset = reset2.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                        let mut headers: HashMap<String, String> = HashMap::new();
                        for (k, v) in parts.headers.iter() {
                            let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
                            headers.entry(k.as_str().to_string()).and_modify(|e| *e = format!("{e}, {v}")).or_insert(v);
                        }
                        let url = parts.uri.path_and_query().map(|p| p.to_string()).unwrap_or_else(|| "/".to_string());
                        let hit =
                            Hit { method: parts.method.to_string(), url, headers, body: String::from_utf8_lossy(&bytes).into_owned() };
                        match handler(hit).await {
                            Resp::Http(r) => Ok::<_, Infallible>(r),
                            Resp::Never => std::future::pending().await,
                            Resp::Reset => {
                                reset.notify_one();
                                std::future::pending().await
                            }
                        }
                    }
                });
                let conn = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service);
                tokio::select! {
                    _ = conn => {}
                    _ = reset.notified() => {
                        #[cfg(unix)]
                        linger_zero(fd);
                    }
                }
            });
        }
    });
    (format!("http://{shown}:{port}"), task)
}

/* ----------------------------------------------------------------- the edge-case site */

#[derive(Clone, Debug)]
struct FxState {
    /// a counter the /rotate route bumps
    rotate: u32,
    /// the session cookie value /api/me honours
    sid: String,
}

struct Fx {
    /// http://127.0.0.1:<port>
    base: String,
    /// a second origin (another server), for cross-origin redirects
    #[allow(dead_code)]
    other: String,
    hits: Arc<Mutex<Vec<Hit>>>,
    other_hits: Arc<Mutex<Vec<Hit>>>,
    state: Arc<Mutex<FxState>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Fx {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn query_of(url: &str) -> (String, HashMap<String, String>) {
    let u = url::Url::parse(&format!("http://x{url}")).unwrap();
    (u.path().to_string(), u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect())
}

fn compress(e: &str, raw: &[u8]) -> Vec<u8> {
    match e {
        "gzip" => {
            let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(raw).unwrap();
            z.finish().unwrap()
        }
        "deflate" => {
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(raw).unwrap();
            z.finish().unwrap()
        }
        "br" => {
            let mut out = Vec::new();
            {
                let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
                w.write_all(raw).unwrap();
            }
            out
        }
        _ => zstd::encode_all(raw, 3).unwrap(),
    }
}

const LOGIN_PAGE: &str =
    "<!doctype html><title>Log in</title><form action=\"/login\"><input name=\"user\"><input type=\"password\" name=\"pw\"></form>";

fn fixture_route(hit: Hit, state: Arc<Mutex<FxState>>, other_base: String) -> Resp {
    let (path, q) = query_of(&hit.url);
    let cookie = hit.h("cookie").unwrap_or("").to_string();
    let qs = |k: &str| q.get(k).cloned();
    let status_q = |k: &str| qs(k).and_then(|s| s.parse::<u16>().ok());
    let body = hit.body.clone();
    // a GET write that counts a vote at each address and sends the browser on to the next one
    if let Some(n) = path.strip_prefix("/vote/").and_then(|n| n.parse::<u32>().ok()) {
        return head(302, &[("location", &format!("/vote/{}", n + 1))]);
    }
    match path.as_str() {
        // a consent/session bootstrap: the cookie set on the redirect is required on the next hop
        "/bootstrap" => head(302, &[("location", "/needs-step"), ("set-cookie", "step=1; Path=/")]),
        "/needs-step" => {
            if Regex::new(r"(^|; )step=1").unwrap().is_match(&cookie) {
                json_r(json!({"items": [{"id": 1}]}), 200, &[])
            } else {
                json_r(json!({"error": "session not initialised"}), 400, &[])
            }
        }
        // rotates a cookie on every answer; the next call must present the latest value
        "/rotate" => {
            let mut s = state.lock().unwrap();
            let want = format!("tok={}", s.rotate);
            let had = s.rotate == 0 || cookie.contains(&want);
            s.rotate += 1;
            let set = format!("tok={}; Path=/", s.rotate);
            if had {
                json_r(json!({"items": [{"n": s.rotate}]}), 200, &[("set-cookie", &set)])
            } else {
                json_r(json!({"error": "stale token"}), 401, &[("set-cookie", &set)])
            }
        }
        "/away" => head(status_q("s").unwrap_or(302), &[("location", &format!("{other_base}/landing"))]),
        // A read the page asks for twice: first signed, which the server sends on to a check that
        // keeps the method (307), and then, once that answered, for the data.
        "/signed-page" => {
            let search = url::Url::parse(&format!("http://x{}", hit.url)).unwrap().query().map(|s| format!("?{s}")).unwrap_or_default();
            html_r(
                200,
                &format!(
                    "<!doctype html><title>signed</title><script>const r=\"/read{search}\";fetch(r,{{method:\"POST\",body:\"initial\"}}).then(r=>r.json()).then(()=>fetch(r,{{method:\"POST\",body:\"final\"}}))</script>"
                ),
            )
        }
        // ?far: the check is on another origin
        "/read" => {
            if body == "initial" {
                head(307, &[("location", &if q.contains_key("far") { format!("{other_base}/answer") } else { "/answer".to_string() })])
            } else {
                json_r(json!({"items": [{"name": "alice"}]}), 200, &[])
            }
        }
        "/answer" => json_r(json!({"checked": hit.method == "POST" && body == "initial"}), 200, &[]),
        // a same-origin redirect with the status the test asks for
        "/hop" => head(status_q("s").unwrap_or(0), &[("location", &qs("to").unwrap_or_else(|| "/landed".to_string()))]),
        // a redirect to the other origin whose Location copies the token a JSON header carried
        "/away-copy" => {
            let token = serde_json::from_str::<Value>(hit.h("x-session").unwrap_or("{}"))
                .ok()
                .and_then(|v| v.get("token").map(api_anything::util::as_text))
                .unwrap_or_else(|| "undefined".to_string());
            head(302, &[("location", &format!("{other_base}/landing?token={token}"))])
        }
        // a POST redirected to an endpoint that turns away a bodiless request still carrying body headers
        "/hop-strict" => head(status_q("s").unwrap_or(0), &[("location", "/strict")]),
        "/strict" => {
            let kept: Vec<&str> = ["content-type", "content-language", "content-encoding", "content-location"]
                .into_iter()
                .filter(|h| hit.headers.contains_key(*h))
                .collect();
            if kept.is_empty() {
                json_r(json!({"items": [{"ok": 1}]}), 200, &[])
            } else {
                json_r(json!({"error": format!("body headers: {}", kept.join(","))}), 415, &[])
            }
        }
        // answers with the body headers the request arrived with
        "/told" => json_r(
            json!({"items": [{"language": hit.h("content-language").unwrap_or("en"), "type": hit.h("content-type").unwrap_or("")}]}),
            200,
            &[],
        ),
        // a write that is passed on, with its method and body, for as long as it is followed
        "/again" => head(status_q("s").unwrap_or(0), &[("location", &hit.url)]),
        // six redirects, then the data
        "/chain" => {
            let n: u32 = qs("n").and_then(|s| s.parse().ok()).unwrap_or(0);
            if n < 6 {
                head(302, &[("location", &format!("/chain?n={}", n + 1))])
            } else {
                json_r(json!({"items": [{"end": n}]}), 200, &[])
            }
        }
        "/loop" => head(302, &[("location", "/loop")]),
        "/to-login" => head(302, &[("location", "/accounts/login/?next=/api")]),
        "/accounts/login/" => html_r(200, "<!doctype html><title>Welcome</title><div id=app></div>"),
        "/enc" => {
            let raw = json!({"items": [{"name": "café ☕"}]}).to_string();
            let e = qs("e").unwrap_or_default();
            res(200, &[("content-type", "application/json"), ("content-encoding", &e)], compress(&e, raw.as_bytes()))
        }
        // "café" in ISO-8859-1
        "/latin1" => {
            res(200, &[("content-type", "application/json; charset=iso-8859-1")], b"{\"items\":[{\"name\":\"caf\xe9\"}]}".to_vec())
        }
        // "日本" in Shift_JIS
        "/sjis" => {
            let mut b = b"<html><body><ul><li class=i>".to_vec();
            b.extend_from_slice(&[0x93, 0xfa, 0x96, 0x7b]);
            b.extend_from_slice(b"</li></ul></body></html>");
            res(200, &[("content-type", "text/html; charset=shift_jis")], b)
        }
        "/bom" => {
            let mut b = vec![0xef, 0xbb, 0xbf];
            b.extend_from_slice(b"{\"items\":[1]}");
            res(200, &[("content-type", "application/json")], b)
        }
        "/huge" => {
            let items: Vec<Value> = (0..50_000).map(|i| json!({"id": i, "title": format!("item {i}"), "blurb": "x".repeat(60)})).collect();
            json_r(json!({"items": items}), 200, &[])
        }
        "/fat-item" => json_r(json!({"items": [{"id": 1, "text": "y".repeat(40_000)}, {"id": 2, "text": "short"}]}), 200, &[]),
        "/stall" => stall(),
        "/never" => Resp::Never,
        "/reset" => Resp::Reset,
        "/empty" => head(204, &[]),
        // "no results" answered as 204; the example query has results
        "/maybe" => {
            if qs("q").as_deref() == Some("alice") {
                json_r(json!({"items": [{"q": "alice"}]}), 200, &[])
            } else {
                head(204, &[])
            }
        }
        "/r429" => json_r(json!({"error": "Too Many Requests"}), 429, &[("retry-after", &qs("ra").unwrap_or_else(|| "120".to_string()))]),
        "/gql" => json_r(serde_json::from_str(&qs("body").unwrap_or_default()).unwrap_or(Value::Null), 200, &[]),
        // Post/Redirect/Get: the POST ran, then the landing page is forbidden to scripts
        "/api/follow" => {
            if hit.method == "POST" {
                head(303, &[("location", "/done")])
            } else {
                json_r(json!({"error": "method"}), 405, &[])
            }
        }
        "/done" => res(403, &[("content-type", "text/plain")], b"Forbidden".to_vec()),
        // the write succeeded; the page it lands on has a change-password form
        "/api/settings" => {
            html_r(200, "<!doctype html><h1>Settings saved</h1><form action=\"/pw\"><input type=\"password\" name=\"new\"></form>")
        }
        "/api/user" => {
            let name = qs("name");
            if name.as_deref() == Some("alice") {
                json_r(json!({"user": {"name": name}}), 200, &[])
            } else {
                json_r(json!({"error": "Not Found"}), 404, &[])
            }
        }
        "/api/items" => json_r(json!({"items": [{"page": qs("page")}]}), 200, &[]),
        // signed-in data: answers the one session the server honours, else its login page as 200 HTML
        "/api/me" => {
            let sid = state.lock().unwrap().sid.clone();
            if cookie.contains(&format!("sid={sid}")) { json_r(json!({"items": [{"me": sid}]}), 200, &[]) } else { html_r(200, LOGIN_PAGE) }
        }
        // a write that runs, then bounces the POST to a login check that refuses it
        "/api/save" => {
            if q.contains_key("login") {
                res(403, &[("content-type", "text/html")], LOGIN_PAGE.as_bytes().to_vec())
            } else {
                head(307, &[("location", "/api/save?login=1")])
            }
        }
        // a button whose handler fires twice (a double-bound listener), next to a request that belongs with the write
        "/double-page" => html_r(
            200,
            "<!doctype html><title>double</title><button id=\"go\">go</button><script>document.getElementById(\"go\").onclick=()=>{fetch(\"/api/companion\",{method:\"POST\",body:\"c=1\"});for(let i=0;i<2;i++)fetch(\"/api/double\",{method:\"POST\",body:\"x=1\"})}</script>",
        ),
        "/save-page" => {
            html_r(200, "<!doctype html><title>save</title><script>fetch(\"/api/save\",{method:\"POST\",body:\"x=1\"})</script>")
        }
        // a page whose script asks for the signed-in data
        "/me-page" => html_r(200, "<!doctype html><title>me</title><script>fetch(\"/api/me\")</script>"),
        // a wall that answers a non-browser client the way a framework answers a stale CSRF token (or with ?status=)
        "/api/picky" => {
            if hit.chrome_ua() {
                json_r(json!({"items": [{"picky": "ok"}]}), 200, &[])
            } else {
                json_r(json!({"message": "CSRF token mismatch."}), status_q("status").filter(|s| *s != 0).unwrap_or(419), &[])
            }
        }
        // double-submit CSRF: the header must repeat the ct cookie
        "/api/csrf" => {
            let ct = Regex::new(r"(?:^|; )ct=([^;]+)").unwrap().captures(&cookie).map(|m| m[1].to_string());
            match ct {
                Some(ct) if hit.h("x-csrf") == Some(ct.as_str()) => json_r(json!({"items": [{"ct": ct}]}), 200, &[]),
                _ => json_r(json!({"error": "CSRF token mismatch"}), 403, &[]),
            }
        }
        // an API behind a header only the page's own script knows (a guest token)
        "/api/token" => {
            if hit.h("x-token") == Some("guest-token-1") {
                json_r(json!({"items": [{"token": "ok"}]}), 200, &[])
            } else {
                json_r(json!({"error": "Bad guest token"}), 401, &[])
            }
        }
        "/tokened" => html_r(
            200,
            "<!doctype html><title>tokened</title><script>fetch(\"/api/token\",{headers:{\"x-token\":\"guest-token-1\"}})</script>",
        ),
        // a page whose script asks the API for its own ?page=
        "/paged" => html_r(
            200,
            "<!doctype html><title>paged</title><script>fetch(\"/api/items?page=\"+encodeURIComponent(new URLSearchParams(location.search).get(\"page\")))</script>",
        ),
        "/" => html_r(200, "<!doctype html><title>home</title>"),
        _ => json_r(json!({"items": [{"path": path}]}), 200, &[]),
    }
}

impl Fx {
    async fn start() -> Fx {
        let hits: Arc<Mutex<Vec<Hit>>> = Arc::new(Mutex::new(vec![]));
        let other_hits: Arc<Mutex<Vec<Hit>>> = Arc::new(Mutex::new(vec![]));
        let state = Arc::new(Mutex::new(FxState { rotate: 0, sid: "none".to_string() }));

        // The other origin takes anything from anywhere, credentials included: what a hostile redirect target does.
        let oh = other_hits.clone();
        let other_handler: Handler = Arc::new(move |hit: Hit| {
            oh.lock().unwrap().push(hit.clone());
            async move {
                // /answer is a check a page on the first origin reads after a redirect sent it here, which the
                // browser then checks against origin "null"
                let origin = if hit.url == "/answer" { "*".to_string() } else { hit.h("origin").unwrap_or("*").to_string() };
                let allow_headers = hit.h("access-control-request-headers").unwrap_or("").to_string();
                let allow_methods = hit.h("access-control-request-method").unwrap_or("").to_string();
                let cors: Vec<(&str, &str)> = vec![
                    ("access-control-allow-origin", origin.as_str()),
                    ("access-control-allow-credentials", "true"),
                    ("access-control-allow-headers", allow_headers.as_str()),
                    ("access-control-allow-methods", allow_methods.as_str()),
                ];
                if hit.method == "OPTIONS" {
                    return head(204, &cors);
                }
                json_r(json!({"landed": true}), 200, &cors)
            }
            .boxed()
        });
        let (other, other_task) = serve("127.0.0.1", "localhost", other_handler).await;

        let h = hits.clone();
        let st = state.clone();
        let other_base = other.clone();
        let handler: Handler = Arc::new(move |hit: Hit| {
            h.lock().unwrap().push(hit.clone());
            let st = st.clone();
            let other_base = other_base.clone();
            async move { fixture_route(hit, st, other_base) }.boxed()
        });
        let (base, task) = serve("127.0.0.1", "127.0.0.1", handler).await;
        Fx { base, other, hits, other_hits, state, tasks: vec![task, other_task] }
    }
    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }
    fn other_hits(&self) -> Vec<Hit> {
        self.other_hits.lock().unwrap().clone()
    }
    fn clear_hits(&self) {
        self.hits.lock().unwrap().clear();
    }
    fn clear_other_hits(&self) {
        self.other_hits.lock().unwrap().clear();
    }
    fn set_sid(&self, sid: &str) {
        self.state.lock().unwrap().sid = sid.to_string();
    }
    fn set_rotate(&self, n: u32) {
        self.state.lock().unwrap().rotate = n;
    }
}

/* ----------------------------------------------------------------- test scaffolding */

/// The TS `beforeEach`, under the lock.
fn fresh() -> MutexGuard<'static, ()> {
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _ = std::fs::remove_file(HOME.path().join("state.json"));
    let _ = std::fs::remove_dir_all(HOME.path().join("sessions"));
    g
}

/// A test on the fixture. The browser is closed afterwards, whatever happened.
fn edge<F, Fut>(f: F)
where
    F: FnOnce(Fx) -> Fut,
    Fut: Future<Output = ()>,
{
    let _g = fresh();
    chrome();
    RT.block_on(async move {
        let fx = Fx::start().await;
        let r = AssertUnwindSafe(f(fx)).catch_unwind().await;
        close_browser().await;
        if let Err(e) = r {
            std::panic::resume_unwind(e);
        }
    });
}

/// A Chrome-only test: skipped with a note when there is no Chrome.
fn chrome_test<F, Fut>(f: F)
where
    F: FnOnce(Fx) -> Fut,
    Fut: Future<Output = ()>,
{
    if !chrome() {
        eprintln!("Google Chrome not installed: skipped");
        return;
    }
    edge(f);
}

fn merge(base: &mut Value, over: Value) {
    if let (Value::Object(b), Value::Object(o)) = (base, over) {
        for (k, v) in o {
            b.insert(k, v);
        }
    }
}

/// A read op on the fixture: GET <path>, extract "items".
fn rd(fx: &Fx, name: &str, path: &str, over: Value) -> Value {
    let mut v = json!({
        "name": name,
        "readOnly": true,
        "request": {"method": "GET", "url": format!("{}{path}", fx.base), "headers": {}},
        "trigger": {"url": format!("{}/", fx.base)},
        "response": {"format": "json", "extract": "items"},
    });
    merge(&mut v, over);
    v
}

fn save(fx: &Fx, name: &str, operations: Vec<Value>) {
    save_site(&site(json!({"name": name, "baseUrl": fx.base, "operations": operations}))).unwrap();
}

fn opts(max_tier: Option<u8>, timeout_ms: Option<u64>) -> CallOptions {
    CallOptions { allow_writes: false, fetcher: None, max_tier, min_interval_ms: Some(0), timeout_ms }
}

fn t1() -> CallOptions {
    opts(Some(1), Some(3000))
}

fn writes(mut o: CallOptions) -> CallOptions {
    o.allow_writes = true;
    o
}

/// A write whose body holds a session value two layers down: base64 of JSON, inside a JSON string.
fn wrapped(fx: &Fx, path: &str, over: Value) -> Value {
    let mut v = json!({
        "name": "post",
        "readOnly": false,
        "request": {
            "method": "POST",
            "url": format!("{}{path}", fx.base),
            "headers": {"content-type": "application/json"},
            "body": json!({"state": b64_encode(b"{\"token\":\"PLACEHOLDER-TOKEN\"}")}).to_string(),
        },
        "slots": [{"ref": "session:token", "at": ["body", "json:/state", "b64", "json:/token"]}],
        "trigger": {"url": format!("{}/", fx.base)},
        "response": {"format": "json"},
    });
    merge(&mut v, over);
    v
}

/// What a `wrapped` body carried, as the server decodes it.
fn unwrapped(body: &str) -> String {
    let v: Value = serde_json::from_str(body).unwrap();
    api_anything::util::b64_decode_lenient_str(v["state"].as_str().unwrap())
}

fn reason(r: &api_anything::execute::CallResult) -> &str {
    r.reason.as_deref().unwrap_or("")
}

fn next(r: &api_anything::execute::CallResult) -> &str {
    r.next.as_deref().unwrap_or("")
}

fn matches(re: &str, s: &str) -> bool {
    Regex::new(re).unwrap().is_match(s)
}

fn with_source(mut s: Session, source: &str) -> Session {
    s.source = Some(source.to_string());
    s
}

/// The TS `fetchImpl` injection: answers from `f` and keeps `${method} ${url} ${body}` of every request.
type Answer = Box<dyn Fn(&HttpRequest) -> anyhow::Result<HttpResponse> + Send + Sync>;

struct FnFetcher {
    hits: Mutex<Vec<String>>,
    f: Answer,
}

impl Fetcher for FnFetcher {
    fn fetch(&self, req: HttpRequest, _timeout: Duration) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        self.hits.lock().unwrap().push(format!("{} {} {}", req.method, req.url, req.body.as_deref().unwrap_or("")));
        let r = (self.f)(&req);
        Box::pin(async move { r })
    }
}

fn fetcher(f: impl Fn(&HttpRequest) -> anyhow::Result<HttpResponse> + Send + Sync + 'static) -> Arc<FnFetcher> {
    Arc::new(FnFetcher { hits: Mutex::new(vec![]), f: Box::new(f) })
}

fn mem_response(status: u16, headers: &[(&str, &str)], body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Headers>(),
        set_cookie: vec![],
        body: body.as_bytes().to_vec(),
        url: String::new(),
    }
}

fn mem_json(v: Value, status: u16) -> HttpResponse {
    mem_response(status, &[("content-type", "application/json")], &v.to_string())
}

/// Write <profileDir>/Network/Cookies as modern Chrome does, with v10-encrypted values (test/fixture/cookie-db.ts).
fn make_chromium_db(profile_dir: &Path, rows: &[(&str, &str, &str)], password: &str) {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    use sha2::Digest;
    let meta_version = 24;
    // the platform default src/import.rs derives with, so each OS tests its own path
    let iterations = if cfg!(target_os = "linux") { 1 } else { 1003 };
    let key = api_anything::import::derive_key(password, iterations);
    std::fs::create_dir_all(profile_dir.join("Network")).unwrap();
    let db = rusqlite::Connection::open(profile_dir.join("Network").join("Cookies")).unwrap();
    db.execute_batch(
        "DROP TABLE IF EXISTS meta; DROP TABLE IF EXISTS cookies; CREATE TABLE meta(key TEXT, value TEXT); CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER)",
    )
    .unwrap();
    db.execute("INSERT INTO meta VALUES('version', ?1)", [meta_version.to_string()]).unwrap();
    for (host_key, name, value) in rows {
        let mut plain = sha2::Sha256::digest(host_key.as_bytes()).to_vec();
        plain.extend_from_slice(value.as_bytes());
        let iv = [0x20u8; 16];
        let enc = cbc::Encryptor::<aes::Aes128>::new((&key).into(), (&iv).into())
            .encrypt_padded_vec_mut::<aes::cipher::block_padding::Pkcs7>(&plain);
        let mut blob = b"v10".to_vec();
        blob.extend(enc);
        db.execute(
            "INSERT INTO cookies VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            rusqlite::params![host_key, name, "", blob, "/", 0i64, 0i64, 0i64, -1i64],
        )
        .unwrap();
    }
}

fn set_browser_roots(root: &Path) {
    let roots = json!([{"name": "Chrome", "family": "chromium", "root": root.display().to_string(), "password": "pw"}]).to_string();
    unsafe { std::env::set_var("API_ANYTHING_BROWSER_ROOTS", roots) };
}

fn clear_browser_roots() {
    unsafe { std::env::remove_var("API_ANYTHING_BROWSER_ROOTS") };
}

/// The CLI binary with the test home: (code, stdout, stderr).
async fn cli(args: &[&str]) -> (i32, String, String) {
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-anything"))
        .args(args)
        .env("API_ANYTHING_HOME", HOME.path())
        .output()
        .await
        .unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/* ----------------------------------------------------------------- cookies and redirects */

#[test]
fn a_cookie_set_on_a_redirect_hop_is_sent_on_the_next_hop_consent_session_bootstrap() {
    edge(|fx| async move {
        save(&fx, "boot", vec![rd(&fx, "list", "/bootstrap", json!({}))]);
        let r = call("boot", "list", args(json!({})), t1()).await;
        let second = fx.hits().into_iter().find(|h| h.url == "/needs-step");
        assert_eq!(
            second.as_ref().and_then(|h| h.h("cookie")),
            Some("step=1"),
            "the Set-Cookie of the 302 must ride on the follow-up request"
        );
        assert!(r.ok, "{}", j(&r));
    });
}

#[test]
fn a_set_cookie_from_a_tier_1_answer_is_persisted_so_the_next_call_presents_the_rotated_value() {
    edge(|fx| async move {
        save(&fx, "rot", vec![rd(&fx, "list", "/rotate", json!({}))]);
        fx.set_rotate(0);
        let a = call("rot", "list", args(json!({})), t1()).await;
        assert!(a.ok, "{}", j(&a));
        assert!(
            load_session("rot").unwrap().cookies.iter().any(|c| c.name == "tok" && c.value == "1"),
            "tok=1 from the answer is in the jar"
        );
        let b = call("rot", "list", args(json!({})), t1()).await;
        assert!(b.ok, "{}", j(&b));
    });
}

#[test]
fn cross_origin_redirects_drop_authorization_refd_headers_and_cookies_303_turns_post_into_get() {
    edge(|fx| async move {
        save(
            &fx,
            "xo",
            vec![
                rd(
                    &fx,
                    "me",
                    "/away?s=302",
                    json!({
                        "request": {
                            "method": "GET",
                            "url": format!("{}/away?s=302", fx.base),
                            "headers": {"authorization": "", "x-csrf-token": "", "x-keep": "1"},
                        },
                        "slots": [
                            {"ref": "session:authorization", "at": ["header:authorization"]},
                            {"ref": "cookie:ct0", "at": ["header:x-csrf-token"]},
                        ],
                        "response": {"format": "json"},
                    }),
                ),
                json!({
                    "name": "post307",
                    "readOnly": false,
                    "request": {
                        "method": "POST",
                        "url": format!("{}/away?s=307", fx.base),
                        "headers": {"authorization": "Bearer PUBLIC-LITERAL", "content-type": "application/json"},
                        "body": "{}",
                    },
                    "trigger": {"url": format!("{}/", fx.base)},
                    "response": {"format": "json"},
                }),
            ],
        );
        save_session(
            "xo",
            &session(vec![cookie("ct0", "SECRET-CSRF-VALUE-123", "127.0.0.1")], &[("authorization", "Bearer SECRET-BEARER")]),
        )
        .unwrap();
        let r = call("xo", "me", args(json!({})), t1()).await;
        assert!(r.ok, "{}", j(&r));
        let h = fx.other_hits()[0].clone();
        assert_eq!(h.h("authorization"), None);
        assert_eq!(h.h("x-csrf-token"), None);
        assert_eq!(h.h("cookie"), None);
        assert_eq!(h.h("x-keep"), Some("1"));

        fx.clear_other_hits();
        let w = call("xo", "post307", args(json!({})), writes(t1())).await;
        assert!(!w.ok, "{}", j(&w));
        assert!(reason(&w).contains("it would send this write again"), "{w:?}");
        assert_eq!(fx.other_hits().len(), 0, "a 307 would send the write a second time");

        // the same request as a read (a query sent as a POST) is taken on, without its authorization
        save(
            &fx,
            "xoread",
            vec![rd(
                &fx,
                "query",
                "/away?s=307",
                json!({
                    "request": {
                        "method": "POST",
                        "url": format!("{}/away?s=307", fx.base),
                        "headers": {"authorization": "Bearer PUBLIC-LITERAL", "content-type": "application/json"},
                        "body": "{}",
                    },
                    "response": {"format": "json"},
                }),
            )],
        );
        let q = call("xoread", "query", args(json!({})), t1()).await;
        assert!(q.ok, "{}", j(&q));
        let seen: Vec<(String, String, Option<String>)> =
            fx.other_hits().iter().map(|h| (h.method.clone(), h.body.clone(), h.h("authorization").map(String::from))).collect();
        assert_eq!(
            seen,
            vec![("POST".to_string(), "{}".to_string(), None)],
            "307 keeps the method and body; even a literal authorization is dropped cross-origin"
        );
    });
}

#[test]
fn a_write_sent_on_by_303_to_a_page_that_answers_401_ran_it_is_not_sent_again() {
    edge(|fx| async move {
        save(
            &fx,
            "prg401",
            vec![rd(
                &fx,
                "save",
                "/hop?s=303&to=/api/token",
                json!({
                    "readOnly": false,
                    "request": {"method": "POST", "url": format!("{}/hop?s=303&to=/api/token", fx.base), "headers": {}, "body": "x=1"},
                }),
            )],
        );
        fx.clear_hits();
        let r = call("prg401", "save", args(json!({})), writes(t1())).await;
        assert_eq!(
            fx.hits().iter().map(|h| format!("{} {}", h.method, h.url)).collect::<Vec<_>>(),
            vec!["POST /hop?s=303&to=/api/token", "GET /api/token"],
            "{}",
            j(&r)
        );
        assert!(!r.ok);
        assert!(next(&r).contains("check the site"), "{r:?}");
        assert!(!next(&r).contains("retry once"), "{r:?}");
    });
}

#[test]
fn a_cross_origin_307_is_not_followed_when_a_body_slot_holds_a_session_value_whatever_encodes_it_base64() {
    edge(|fx| async move {
        // a read with a body (a query sent as a POST): a write stops at any 307
        save(&fx, "xob64", vec![wrapped(&fx, "/away?s=307", json!({"readOnly": true}))]);
        save_session("xob64", &session(vec![], &[("token", "SECRET-BODY-TOKEN-123")])).unwrap();
        let r = call("xob64", "post", args(json!({})), t1()).await;
        assert!(unwrapped(&fx.hits()[0].body).contains("SECRET-BODY-TOKEN-123"), "the site itself gets its token");
        assert_eq!(fx.other_hits().len(), 0, "the other origin got {:?}", fx.other_hits().first().map(|h| h.body.clone()));
        assert!(!r.ok, "{}", j(&r));
        assert!(matches(r"not following the HTTP 307 redirect to http://localhost", reason(&r)), "{r:?}");
        assert!(matches(r"^do not retry: .* re-learn it with api-anything add xob64 post", next(&r)), "{r:?}");
        assert!(!next(&r).contains("retry once"));
        assert_eq!(fx.hits().len(), 1, "sent once");
    });
}

#[test]
fn a_cross_origin_redirect_drops_a_header_whose_ref_sits_under_a_json_layer() {
    edge(|fx| async move {
        save(
            &fx,
            "xowrap",
            vec![rd(
                &fx,
                "me",
                "/away?s=302",
                json!({
                    "request": {
                        "method": "GET",
                        "url": format!("{}/away?s=302", fx.base),
                        "headers": {"x-wrap": "{\"token\":\"\"}", "x-keep": "1"},
                    },
                    "slots": [{"ref": "cookie:ct0", "at": ["header:x-wrap", "json:/token"]}],
                    "response": {"format": "json"},
                }),
            )],
        );
        save_session("xowrap", &session(vec![cookie("ct0", "SECRET-CSRF-VALUE-123", "127.0.0.1")], &[])).unwrap();
        let r = call("xowrap", "me", args(json!({})), t1()).await;
        assert!(r.ok, "{}", j(&r));
        assert!(fx.hits()[0].h("x-wrap").unwrap_or("").contains("SECRET-CSRF-VALUE-123"), "the site itself gets it");
        assert_eq!(fx.other_hits()[0].h("x-wrap"), None);
        assert_eq!(fx.other_hits()[0].h("x-keep"), Some("1"));
    });
}

#[test]
fn a_redirect_loop_ends_with_a_non_ok_answer_instead_of_hanging() {
    edge(|fx| async move {
        save(&fx, "loop", vec![rd(&fx, "l", "/loop", json!({}))]);
        let r = call("loop", "l", args(json!({})), t1()).await;
        assert!(!r.ok);
        assert_eq!(r.class, Class::Error);
        assert!(fx.hits().len() <= 6);
    });
}

#[test]
fn a_redirect_to_a_login_page_where_json_was_expected_is_auth() {
    edge(|fx| async move {
        save(&fx, "tl", vec![rd(&fx, "l", "/to-login", json!({}))]);
        let r = call("tl", "l", args(json!({})), t1()).await;
        assert_eq!(r.class, Class::Auth, "{}", j(&r));
    });
}

#[test]
fn jar_scoping_longest_path_first_for_duplicate_names_expired_never_sent_secure_only_over_https_localhost() {
    let now = 1_800_000_000_000.0;
    let mut api = cookie("sid", "api", ".shop.test");
    api.path = "/api".to_string();
    let mut old = cookie("old", "x", ".shop.test");
    old.expires = now / 1000.0 - 1.0;
    let mut sec = cookie("sec", "s", ".shop.test");
    sec.secure = true;
    let jar = vec![cookie("sid", "root", ".shop.test"), api, old, sec];
    assert_eq!(cookie_header_for(&jar, "http://shop.test/api/v1", now), "sid=api; sid=root");
    assert_eq!(cookie_header_for(&jar, "https://shop.test/apix", now), "sid=root; sec=s");
    assert_eq!(cookie_value(&jar, "sid", Some("https://shop.test/api/v1"), now).as_deref(), Some("api"));
    assert_eq!(cookie_value(&jar, "sid", Some("https://evil-shop.test/api"), now), None, "no suffix match across sites");
}

#[test]
fn a_cookie_ref_never_takes_another_sites_cookie_under_a_multi_label_public_suffix_co_uk_github_io() {
    // browser.ts siteCookies keeps every cookie whose domain ends in siteOf(host); for bbc.co.uk that is ".co.uk",
    // so the shared profile's argos.co.uk cookies land in bbc's jar
    let mut a = cookie("csrftoken", "ARGOS-SECRET", ".argos.co.uk");
    a.secure = true;
    let mut b = cookie("csrftoken", "ALICE-SECRET", "alice.github.io");
    b.secure = true;
    let jar = vec![a, b];
    assert_eq!(cookie_value(&jar, "csrftoken", Some("https://api.bbc.co.uk/x"), now_ms()), None);
    assert_eq!(cookie_value(&jar, "csrftoken", Some("https://mallory.github.io/api"), now_ms()), None);
}

/* ----------------------------------------------------------------- bodies */

#[test]
fn gzip_br_deflate_and_zstd_bodies_are_decoded() {
    edge(|fx| async move {
        let encs = ["gzip", "br", "deflate", "zstd"];
        save(&fx, "enc", encs.iter().map(|e| rd(&fx, e, &format!("/enc?e={e}"), json!({}))).collect());
        for e in encs {
            let r = call("enc", e, args(json!({})), t1()).await;
            assert_eq!(r.data, Some(json!([{"name": "café ☕"}])), "{e}: {}", j(&r));
        }
    });
}

#[test]
fn a_utf_8_bom_before_json_parses() {
    edge(|fx| async move {
        save(&fx, "bom", vec![rd(&fx, "b", "/bom", json!({}))]);
        let r = call("bom", "b", args(json!({})), t1()).await;
        assert_eq!(r.data, Some(json!([1])), "{}", j(&r));
    });
}

#[test]
fn the_declared_charset_is_honoured_iso_8859_1_json_shift_jis_html() {
    edge(|fx| async move {
        save(
            &fx,
            "cs",
            vec![
                rd(&fx, "latin", "/latin1", json!({})),
                rd(&fx, "sjis", "/sjis", json!({"response": {"format": "html", "html": {"items": "li.i", "fields": {"t": ""}}}})),
            ],
        );
        let l = call("cs", "latin", args(json!({})), t1()).await;
        let s = call("cs", "sjis", args(json!({})), t1()).await;
        assert_eq!(json!({"latin": l.data, "sjis": s.data}), json!({"latin": [{"name": "café"}], "sjis": [{"t": "日本"}]}));
    });
}

#[test]
fn an_mb_scale_json_array_comes_back_capped_at_an_item_boundary_with_a_truncation_note() {
    edge(|fx| async move {
        save(&fx, "big", vec![rd(&fx, "b", "/huge", json!({}))]);
        let r = call("big", "b", args(json!({})), t1()).await;
        assert!(r.ok);
        let n = r.data.as_ref().and_then(|d| d.as_array()).map(|a| a.len()).unwrap_or(0);
        assert!(n > 10 && n < 50_000, "{n} items");
        let len = j(&r).to_string().len();
        assert!(len < 22_000, "output {len} chars");
        assert!(matches(r"showing \d+ of 50000 items", r.truncated.as_deref().unwrap_or("")), "{:?}", r.truncated);
    });
}

#[test]
fn an_array_whose_first_item_alone_exceeds_the_cap_still_returns_some_data() {
    edge(|fx| async move {
        save(&fx, "fat", vec![rd(&fx, "f", "/fat-item", json!({}))]);
        let r = call("fat", "f", args(json!({})), t1()).await;
        assert!(r.ok);
        assert!(r.truncated.is_some());
        let n = r.data.as_ref().and_then(|d| d.as_array()).map(|a| a.len());
        assert!(
            n.map(|n| n >= 1).unwrap_or(false),
            "data: {} / {:?}",
            j(&r.data).to_string().chars().take(80).collect::<String>(),
            r.truncated
        );
    });
}

#[test]
fn capping_a_long_string_keeps_a_prefix_of_the_string_itself_not_of_its_json_encoding() {
    let html = "<div class=\"a\">\n".repeat(3000);
    let c = cap_output(&Value::String(html.clone()), 20_000);
    let data = c.data.as_str().expect("a string");
    assert!(html.starts_with(data), "starts with {:?}", data.chars().take(30).collect::<String>());
}

#[test]
fn capping_an_object_with_a_big_nested_array_returns_a_json_value_not_cut_json_text() {
    let timeline: Vec<Value> = (0..2000).map(|i| json!({"id": i, "text": "tweet text here"})).collect();
    let value = json!({"user": {"id": 1}, "timeline": timeline});
    let c = cap_output(&value, 20_000);
    assert!(
        c.data.is_object(),
        "got a {}: {}",
        api_anything::extract::type_name(&c.data),
        c.data.to_string().chars().take(60).collect::<String>()
    );
}

#[test]
fn a_read_answered_204_with_no_body_is_not_ok_and_is_sent_once() {
    edge(|fx| async move {
        save(&fx, "e204", vec![rd(&fx, "e", "/empty", json!({}))]);
        let r = call("e204", "e", args(json!({})), t1()).await;
        assert_ne!(r.class, Class::Ok);
        assert_eq!(fx.hits().len(), 1, "exactly one request");
    });
}

#[test]
fn an_empty_204_read_while_the_example_args_still_answer_is_input_the_missing_data_check_not_a_heal() {
    edge(|fx| async move {
        save(
            &fx,
            "m204",
            vec![rd(
                &fx,
                "s",
                "/maybe?q=alice",
                json!({
                    "slots": [{"param": "q", "at": ["query:q"]}],
                    "params": [{"name": "q", "example": "alice"}],
                }),
            )],
        );
        let r = call("m204", "s", args(json!({"q": "zz_no_results"})), t1()).await;
        assert_eq!(r.class, Class::Input, "{}", j(&r));
    });
}

/* ----------------------------------------------------------------- transport failures */

#[test]
fn a_body_that_stalls_after_the_headers_times_out_with_a_clear_reason() {
    edge(|fx| async move {
        save(&fx, "stall", vec![rd(&fx, "s", "/stall", json!({}))]);
        let t0 = Instant::now();
        let r = call("stall", "s", args(json!({})), opts(Some(1), Some(300))).await;
        assert_eq!(r.class, Class::Error);
        assert!(reason(&r).contains("no response within 300 ms"), "{r:?}");
        assert!(t0.elapsed() < Duration::from_millis(2500));
    });
}

#[test]
fn a_server_that_never_answers_times_out_a_reset_is_an_error_a_write_reset_is_sent_once_and_flagged_ambiguous() {
    edge(|fx| async move {
        save(
            &fx,
            "net",
            vec![
                rd(&fx, "n", "/never", json!({})),
                rd(&fx, "r", "/reset", json!({})),
                json!({
                    "name": "w",
                    "readOnly": false,
                    "request": {"method": "POST", "url": format!("{}/reset", fx.base), "headers": {}, "body": "x=1"},
                    "trigger": {"url": format!("{}/", fx.base)},
                }),
            ],
        );
        let n = call("net", "n", args(json!({})), opts(Some(1), Some(200))).await;
        assert!(reason(&n).contains("no response within 200 ms"), "{n:?}");
        assert_eq!(call("net", "r", args(json!({})), t1()).await.class, Class::Error);
        fx.clear_hits();
        let w = call("net", "w", args(json!({})), writes(t1())).await;
        assert_eq!(w.class, Class::Error);
        assert_eq!(fx.hits().len(), 1);
        assert!(next(&w).contains("may have gone through"), "{w:?}");
    });
}

#[test]
fn a_network_error_names_its_cause_refused_dns_not_just_fetch_failed() {
    edge(|fx| async move {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        save_site(&site(json!({
            "name": "down",
            "baseUrl": format!("http://127.0.0.1:{port}"),
            "operations": [
                {
                    "name": "d",
                    "readOnly": true,
                    "request": {"method": "GET", "url": format!("http://127.0.0.1:{port}/x"), "headers": {}},
                    "trigger": {"url": format!("{}/", fx.base)},
                    "response": {"format": "json", "extract": "items"},
                },
            ],
        })))
        .unwrap();
        let r = call("down", "d", args(json!({})), t1()).await;
        assert_eq!(r.class, Class::Error);
        assert!(matches(r"(?i)ECONNREFUSED|refused", reason(&r)), "reason: {}", reason(&r));

        let dns = fetcher(|_| Err(anyhow::anyhow!("fetch failed: ENOTFOUND (getaddrinfo ENOTFOUND api.nowhere.test)")));
        let mut o = t1();
        o.fetcher = Some(dns);
        let d = call("down", "d", args(json!({})), o).await;
        assert!(reason(&d).contains("ENOTFOUND"), "reason: {}", reason(&d));
    });
}

#[test]
fn http_429_reports_the_servers_retry_after_seconds_and_http_date() {
    edge(|fx| async move {
        save(
            &fx,
            "rl",
            vec![
                rd(&fx, "s", "/r429?ra=120", json!({})),
                rd(&fx, "d", &format!("/r429?ra={}", enc("Wed, 21 Oct 2026 07:28:00 GMT")), json!({})),
            ],
        );
        let s = call("rl", "s", args(json!({})), t1()).await;
        assert_eq!(s.class, Class::Rate);
        assert!(format!("{} {}", reason(&s), next(&s)).contains("120"), "{}", j(&s));
        let d = call("rl", "d", args(json!({})), t1()).await;
        assert!(matches(r"2026-10-21|Oct 2026", &format!("{} {}", reason(&d), next(&d))), "{}", j(&d));
    });
}

/* ----------------------------------------------------------------- classification */

fn gql_op(over: Value) -> Operation {
    let mut v = json!({
        "name": "user",
        "request": {"method": "GET", "url": "https://g.test/graphql?q=1", "headers": {}},
        "slots": [{"param": "login", "at": ["query:q"]}],
        "params": [{"name": "login"}],
        "trigger": {"url": "https://g.test/{login}"},
        "response": {"format": "json", "extract": "data.user"},
        "readOnly": true,
    });
    merge(&mut v, over);
    common::op(v)
}

fn obs(status: u16, body: &str, ct: &str, headers: &[(&str, &str)]) -> Observed {
    let mut h: Headers = Headers::new();
    h.insert("content-type".to_string(), ct.to_string());
    for (k, v) in headers {
        h.insert(k.to_string(), v.to_string());
    }
    Observed { status, headers: h, body: body.to_string(), url: None }
}

const JSON_CT: &str = "application/json";

#[test]
fn challenge_pages_from_every_listed_vendor_are_blocked_whatever_the_status() {
    let o = gql_op(json!({}));
    let cases: Vec<(&str, Observed)> = vec![
        (
            "Cloudflare 403",
            obs(
                403,
                "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={}</script></body></html>",
                "text/html",
                &[],
            ),
        ),
        ("Cloudflare cf-mitigated", obs(403, "", "text/html", &[("cf-mitigated", "challenge")])),
        ("Cloudflare 503", obs(503, "<title>Just a moment...</title>", "text/html", &[])),
        ("Cloudflare WAF", obs(403, "<title>Attention Required! | Cloudflare</title>", "text/html", &[])),
        (
            "Akamai",
            obs(
                403,
                "<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>Reference #18.1 <a href=\"https://errors.edgesuite.net/18.1\">",
                "text/html",
                &[],
            ),
        ),
        ("DataDome JSON", obs(403, "{\"url\":\"https://geo.captcha-delivery.com/captcha/?initialCid=AHrlqAAA\"}", JSON_CT, &[])),
        (
            "PerimeterX JSON",
            obs(403, "{\"appId\":\"PXu6b0qd2S\",\"blockScript\":\"/u6b0qd2S/captcha/captcha.js\",\"vid\":\"x\"}", JSON_CT, &[]),
        ),
        ("PerimeterX 200 page", obs(200, "<html><body><div id=px-captcha></div>Press & Hold</body></html>", "text/html", &[])),
        ("reCAPTCHA 200 interstitial", obs(200, "<html><div class=\"g-recaptcha\" data-sitekey=\"x\"></div></html>", "text/html", &[])),
    ];
    for (name, r) in &cases {
        assert_eq!(classify(&o, r).class, Class::Blocked, "{name}");
    }
    assert_eq!(
        classify(&o, &obs(429, "<title>Access denied | Error 1015</title> You are being rate limited", "text/html", &[])).class,
        Class::Rate
    );
}

#[test]
fn imperva_incapsula_and_kasada_interstitials_are_blocked_tier_escalation_not_drift_or_rate() {
    let o = gql_op(json!({}));
    let incapsula = obs(
        200,
        "<html><head><META NAME=\"robots\" CONTENT=\"noindex,nofollow\"><script src=\"/_Incapsula_Resource?SWJIYLWA=5074a744\"></script></head><body><iframe src=\"/_Incapsula_Resource?CWUDNSAI=9\">Request unsuccessful. Incapsula incident ID: 1</iframe></body></html>",
        "text/html",
        &[],
    );
    assert_eq!(classify(&o, &incapsula).class, Class::Blocked, "Imperva");
    let kasada = obs(
        429,
        "<html><script src=\"/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/ips.js\"></script></html>",
        "text/html",
        &[("x-kpsdk-ct", "abc")],
    );
    assert_eq!(classify(&o, &kasada).class, Class::Blocked, "Kasada");
}

#[test]
fn http_400_with_a_csrf_marker_is_auth_design_400_403_with_login_or_csrf_markers() {
    let w = gql_op(json!({"readOnly": false, "response": {"format": "json"}}));
    assert_eq!(classify(&w, &obs(403, "{\"error\":\"CSRF token mismatch\"}", JSON_CT, &[])).class, Class::Auth);
    assert_eq!(classify(&w, &obs(400, "{\"error\":\"CSRF token mismatch\"}", JSON_CT, &[])).class, Class::Auth);
}

#[test]
fn http_5xx_is_error_retry_hint_4xx_without_markers_is_not_auth() {
    assert_eq!(classify(&gql_op(json!({})), &obs(503, "Service Unavailable", "text/plain", &[("retry-after", "30")])).class, Class::Error);
    assert_eq!(classify(&gql_op(json!({})), &obs(500, "{\"error\":\"internal\"}", JSON_CT, &[])).class, Class::Error);
    assert_eq!(
        classify(&gql_op(json!({})), &obs(403, "{\"message\":\"CSRF token missing or incorrect.\"}", JSON_CT, &[])).class,
        Class::Auth
    );
    assert_eq!(classify(&gql_op(json!({})), &obs(401, "", JSON_CT, &[])).class, Class::Auth);
}

#[test]
fn json_served_as_text_html_is_still_json_an_html_login_page_where_json_was_expected_is_auth() {
    assert_eq!(
        classify(&gql_op(json!({})), &obs(200, "{\"data\":{\"user\":{\"id\":1}}}", "text/html; charset=utf-8", &[])).class,
        Class::Ok
    );
    assert_eq!(
        classify(&gql_op(json!({})), &obs(200, "<!doctype html><form><input name=u><input type=\"password\"></form>", "text/html", &[]))
            .class,
        Class::Auth
    );
}

#[test]
fn graphql_errors_with_null_data_map_to_rate_auth_drift_error() {
    let o = gql_op(json!({}));
    assert_eq!(
        classify(&o, &obs(200, "{\"errors\":[{\"message\":\"Rate limit exceeded\"}],\"data\":null}", JSON_CT, &[])).class,
        Class::Rate
    );
    assert_eq!(classify(&o, &obs(200, "{\"errors\":[{\"message\":\"Bad guest token\"}]}", JSON_CT, &[])).class, Class::Auth);
    assert_eq!(classify(&o, &obs(200, "{\"errors\":[{\"message\":\"PersistedQueryNotFound\"}]}", JSON_CT, &[])).class, Class::Drift);
}

#[test]
fn graphql_partial_data_errors_next_to_a_null_extract_target_are_not_a_successful_null() {
    let o = gql_op(json!({}));
    let rate = judge(
        &o,
        &obs(200, "{\"data\":{\"user\":null},\"errors\":[{\"message\":\"Rate limit exceeded\",\"path\":[\"user\"]}]}", JSON_CT, &[]),
    );
    assert_eq!(rate.class, Class::Rate, "{rate:?}");
    let nf = judge(
        &o,
        &obs(
            200,
            "{\"data\":{\"user\":null},\"errors\":[{\"type\":\"NOT_FOUND\",\"path\":[\"user\"],\"message\":\"Could not resolve to a User with the login of 'zz'.\"}]}",
            JSON_CT,
            &[],
        ),
    );
    assert_ne!(nf.class, Class::Ok, "{nf:?}");
    // errors on an unrelated field with the target present: still ok
    assert_eq!(
        judge(
            &o,
            &obs(200, "{\"data\":{\"user\":{\"id\":1},\"ads\":null},\"errors\":[{\"message\":\"x\",\"path\":[\"ads\"]}]}", JSON_CT, &[])
        )
        .class,
        Class::Ok
    );
}

#[test]
fn a_write_answered_2xx_is_ok_even_when_the_landing_page_has_a_password_field_it_ran() {
    let w = gql_op(json!({"readOnly": false, "response": {"format": "json"}}));
    assert_eq!(classify(&w, &obs(204, "", "", &[])).class, Class::Ok);
    let saved =
        judge(&w, &obs(200, "<!doctype html><h1>Settings saved</h1><form><input type=\"password\" name=\"new\"></form>", "text/html", &[]));
    assert_eq!(saved.class, Class::Ok, "{saved:?}");
}

/* ----------------------------------------------------------------- the ladder */

#[test]
fn http_404_for_an_unknown_entity_on_a_query_param_api_is_input_after_the_example_check_not_a_heal() {
    edge(|fx| async move {
        save(
            &fx,
            "nf404",
            vec![rd(
                &fx,
                "user",
                "/api/user?name=alice",
                json!({
                    "slots": [{"param": "name", "at": ["query:name"]}],
                    "params": [{"name": "name", "example": "alice"}],
                    "response": {"format": "json", "extract": "user"},
                }),
            )],
        );
        let ok = call("nf404", "user", args(json!({"name": "alice"})), t1()).await;
        assert!(ok.ok, "{}", j(&ok));
        let r = call("nf404", "user", args(json!({"name": "zz_nobody"})), t1()).await;
        assert_eq!(r.class, Class::Input, "{}", j(&r));
    });
}

#[test]
fn a_remembered_escalation_does_not_stop_max_tier_1_from_trying_tier_1() {
    edge(|fx| async move {
        save(&fx, "mem", vec![rd(&fx, "l", "/plain", json!({}))]);
        remember_tier("mem", "l", Some(2));
        let r = call("mem", "l", args(json!({})), t1()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.tier, Some(1));
    });
}

#[test]
fn an_unknown_arg_name_a_typo_is_refused_instead_of_silently_using_the_default() {
    edge(|fx| async move {
        save(
            &fx,
            "typo",
            vec![rd(
                &fx,
                "items",
                "/api/items?page=1",
                json!({
                    "slots": [{"param": "page", "at": ["query:page"]}],
                    "params": [{"name": "page", "default": "1", "required": false}],
                }),
            )],
        );
        let r = call("typo", "items", args(json!({"pgae": "7"})), t1()).await;
        assert_eq!(r.class, Class::Input, "{}", j(&r));
        assert_eq!(fx.hits().len(), 0, "nothing sent");
    });
}

#[test]
fn a_numeric_arg_in_a_form_that_would_be_rounded_past_2_53_is_input_and_nothing_is_sent() {
    edge(|fx| async move {
        save(
            &fx,
            "big",
            vec![rd(
                &fx,
                "items",
                "/api/items?page=1",
                json!({
                    "slots": [{"param": "page", "at": ["query:page"]}],
                    "params": [{"name": "page", "type": "number"}],
                }),
            )],
        );
        let r = call("big", "items", args(json!({"page": "9007199254740993e0"})), t1()).await;
        assert_eq!(r.class, Class::Input, "{}", j(&r));
        assert!(reason(&r).contains("would lose precision"), "{r:?}");
        assert_eq!(fx.hits().len(), 0, "nothing sent");
        assert_eq!(
            call("big", "items", args(json!({"page": "9007199254740993"})), t1()).await.data,
            Some(json!([{"page": "9007199254740993"}]))
        );
    });
}

#[test]
fn a_corrupt_session_or_state_file_is_reported_as_such_not_check_the_args_and_call_does_not_throw() {
    edge(|fx| async move {
        save(&fx, "corrupt", vec![rd(&fx, "l", "/plain", json!({}))]);
        std::fs::create_dir_all(HOME.path().join("sessions")).unwrap();
        std::fs::write(HOME.path().join("sessions").join("corrupt.json"), "{\"cookies\":[{\"name\":\"a\"").unwrap();
        let s = call("corrupt", "l", args(json!({})), t1()).await;
        assert_ne!(s.class, Class::Input, "{}", j(&s));
        std::fs::remove_file(HOME.path().join("sessions").join("corrupt.json")).unwrap();
        std::fs::write(HOME.path().join("state.json"), "{\"tier\":").unwrap();
        let _ = call("corrupt", "l", args(json!({})), t1()).await;
    });
}

#[test]
fn in_process_concurrent_calls_to_one_site_are_paced_and_all_answer() {
    edge(|fx| async move {
        save(&fx, "conc", vec![rd(&fx, "l", "/plain", json!({}))]);
        let t0 = Instant::now();
        let paced = || {
            let mut o = t1();
            o.min_interval_ms = Some(100);
            o
        };
        let rs = futures_util::future::join_all((0..3).map(|_| call("conc", "l", args(json!({})), paced()))).await;
        assert!(rs.iter().all(|r| r.ok), "{:?}", rs.iter().map(j).collect::<Vec<_>>());
        assert!(t0.elapsed() >= Duration::from_millis(190), "3 requests at 100 ms spacing");
    });
}

/* ----------------------------------------------------------------- writes gating */

fn write_site(fx: &Fx) {
    save(
        fx,
        "wr",
        vec![
            rd(fx, "read", "/plain", json!({})),
            json!({
                "name": "follow",
                "readOnly": false,
                "request": {
                    "method": "POST",
                    "url": format!("{}/api/follow", fx.base),
                    "headers": {"content-type": "application/json"},
                    "body": "{\"id\":\"1\"}",
                },
                "trigger": {"url": format!("{}/", fx.base)},
                "response": {"format": "json"},
            }),
        ],
    );
}

#[test]
fn library_call_refused_without_allow_writes_heal_always_refuses_a_write_nothing_sent() {
    edge(|fx| async move {
        write_site(&fx);
        let r = call("wr", "follow", args(json!({})), t1()).await;
        assert_eq!(r.class, Class::Refused);
        assert_eq!(heal("wr", "follow", args(json!({})), writes(t1())).await.class, Class::Refused);
        assert_eq!(fx.hits().len(), 0);
    });
}

#[test]
fn mcp_writes_hidden_and_refused_unless_the_server_allows_them() {
    edge(|fx| async move {
        write_site(&fx);
        let server = Server::new(false);
        let list = server.call_tool("list_operations", &args(json!({"site": "wr"}))).await;
        assert!(!list.value.to_string().contains("follow"), "{}", list.value);
        let r = server.call_tool("call_operation", &args(json!({"site": "wr", "op": "follow", "args": {}}))).await;
        assert!(r.value.to_string().contains("refused"), "{}", r.value);
        assert_eq!(fx.hits().len(), 0);
    });
}

#[test]
fn cli_a_write_without_allow_writes_is_refused_dry_redacts_every_credential_and_sends_nothing() {
    edge(|fx| async move {
        write_site(&fx);
        save(
            &fx,
            "dry",
            vec![rd(
                &fx,
                "me",
                "/plain",
                json!({
                    "request": {"method": "GET", "url": format!("{}/plain", fx.base), "headers": {"authorization": "", "x-csrf-token": ""}},
                    "slots": [
                        {"ref": "session:authorization", "at": ["header:authorization"]},
                        {"ref": "cookie:ct0", "at": ["header:x-csrf-token"]},
                    ],
                }),
            )],
        );
        save_session(
            "dry",
            &session(vec![cookie("ct0", "LIVE-CSRF-SECRET-1", "127.0.0.1")], &[("authorization", "Bearer LIVE-BEARER-SECRET")]),
        )
        .unwrap();
        let (code, out, _) = cli(&["call", "wr", "follow"]).await;
        assert_eq!(code, 1);
        assert!(out.contains("refused"), "{out}");
        let (code, out, err) = cli(&["call", "dry", "me", "--dry"]).await;
        assert_eq!(code, 0, "{err}");
        assert!(!out.contains("LIVE-"), "{out}");
        assert!(out.contains("<ct0>"), "{out}");
        assert_eq!(fx.hits().len(), 0);
        // verify runs reads only
        let (_, vout, _) = cli(&["verify", "wr"]).await;
        assert_eq!(fx.hits().iter().filter(|h| h.method == "POST").count(), 0, "{vout}");
    });
}

#[test]
fn cli_an_invalid_max_tier_is_rejected() {
    edge(|fx| async move {
        save(&fx, "mt", vec![rd(&fx, "l", "/plain", json!({}))]);
        let (code, out, err) = cli(&["call", "mt", "l", "--max-tier", "abc"]).await;
        assert_ne!(code, 0, "{out}");
        assert!(err.contains("max-tier"), "{err}");
    });
}

#[test]
fn auth_stays_at_tier_1_when_no_browser_tier_may_run_and_when_a_login_is_on_record() {
    edge(|fx| async move {
        save(&fx, "pickyoff", vec![rd(&fx, "items", "/api/picky", json!({}))]);
        // capped at tier 1: the answer is the site's, with the login hint, not "needs tier 2"
        let capped = call("pickyoff", "items", args(json!({})), t1()).await;
        assert_eq!(capped.class, Class::Auth, "{}", j(&capped));
        assert_eq!(capped.tier, Some(1));
        assert!(next(&capped).contains("api-anything login pickyoff"), "{capped:?}");
        // a login was run for this site (its source is recorded, though its cookies are gone): recovery, not a probe
        save_session("pickyoff", &with_source(session(vec![], &[]), "window")).unwrap();
        fx.clear_hits();
        let known = call("pickyoff", "items", args(json!({})), opts(Some(2), Some(3000))).await;
        assert_eq!(known.class, Class::Auth, "{}", j(&known));
        assert_eq!(known.tier, Some(1));
        assert_eq!(fx.hits().iter().filter(|h| h.url == "/api/picky").count(), 1, "one request, no page fetch");
    });
}

/* ----------------------------------------------------------------- Chrome-only */

fn o2() -> CallOptions {
    opts(Some(2), Some(5000))
}

#[test]
fn a_write_whose_post_was_redirected_303_to_a_403_page_ran_it_is_not_re_sent_at_tier_2() {
    chrome_test(|fx| async move {
        save(
            &fx,
            "prg",
            vec![json!({
                "name": "follow",
                "readOnly": false,
                "request": {
                    "method": "POST",
                    "url": format!("{}/api/follow", fx.base),
                    "headers": {"content-type": "application/json"},
                    "body": "{\"id\":\"1\"}",
                },
                "trigger": {"url": format!("{}/", fx.base)},
                "response": {"format": "json"},
            })],
        );
        let r = call("prg", "follow", args(json!({})), writes(o2())).await;
        let posts = fx.hits().iter().filter(|h| h.method == "POST" && h.url == "/api/follow").count();
        assert_eq!(posts, 1, "POST sent {posts} times; result {}", j(&r));
    });
}

#[test]
fn tier_2_follows_tier_1s_redirect_policy_a_cross_origin_307_gets_no_refd_header_and_no_body_holding_a_session_value() {
    chrome_test(|fx| async move {
        save(
            &fx,
            "t2xo",
            vec![
                rd(
                    &fx,
                    "me",
                    "/away?s=307",
                    json!({
                        "minTier": 2,
                        "request": {"method": "GET", "url": format!("{}/away?s=307", fx.base), "headers": {"x-csrf": "", "x-keep": "1"}},
                        "slots": [{"ref": "cookie:ct", "at": ["header:x-csrf"]}],
                        "response": {"format": "json"},
                    }),
                ),
                wrapped(&fx, "/away?s=307", json!({"minTier": 2, "readOnly": true})),
            ],
        );
        save_session("t2xo", &session(vec![cookie("ct", "SECRET-CSRF-VALUE-123", "127.0.0.1")], &[("token", "SECRET-BODY-TOKEN-123")]))
            .unwrap();
        // the other origin approves every CORS preflight, so only the policy stands between it and the request
        let landed = |fx: &Fx| fx.other_hits().into_iter().filter(|h| h.method != "OPTIONS").collect::<Vec<_>>();
        let r = call("t2xo", "me", args(json!({})), o2()).await;
        assert_eq!(fx.hits().iter().find(|h| h.url == "/away?s=307").and_then(|h| h.h("x-csrf")), Some("SECRET-CSRF-VALUE-123"));
        assert_eq!(landed(&fx).len(), 1, "{}", j(&r));
        assert_eq!(landed(&fx)[0].h("x-csrf"), None, "the CSRF header went to another origin");
        assert_eq!(landed(&fx)[0].h("x-keep"), Some("1"));
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.tier, Some(2));

        fx.clear_hits();
        fx.clear_other_hits();
        let w = call("t2xo", "post", args(json!({})), o2()).await;
        assert!(unwrapped(&fx.hits().iter().find(|h| h.method == "POST").unwrap().body).contains("SECRET-BODY-TOKEN-123"));
        assert_eq!(landed(&fx).len(), 0, "the other origin got {:?}", landed(&fx).first().map(|h| h.body.clone()));
        assert!(!w.ok, "{}", j(&w));
        assert_eq!(w.tier, Some(2));
        assert!(matches(r"not following the HTTP 307 redirect to http://localhost", reason(&w)), "{w:?}");
        assert!(matches(r"^do not retry: .* re-learn it with api-anything add t2xo post", next(&w)), "{w:?}");
        assert_eq!(fx.hits().iter().filter(|h| h.method == "POST").count(), 1, "the request was sent once");
    });
}

/// Playwright's `clearCookies({ name })` on the shared profile.
async fn clear_profile_cookie_named(name: &str) {
    let b = open_browser(&profile_dir(), true).await.unwrap();
    let mine: Vec<StoredCookie> = b.all_cookies().await.unwrap().into_iter().filter(|c| c.name == name).collect();
    if mine.is_empty() {
        return;
    }
    let page = b.new_page(None).await.unwrap();
    for c in mine {
        let _ = page.send("Network.deleteCookies", json!({"name": c.name, "domain": c.domain, "path": c.path})).await;
    }
    let _ = page.close().await;
}

#[test]
fn tier_2_same_origin_redirects_a_hops_cookie_rides_on_the_next_307_keeps_post_and_body_303_makes_a_bodiless_get_a_loop_ends() {
    chrome_test(|fx| async move {
        let post = |s: u16| {
            let mut v = rd(&fx, &format!("post{s}"), &format!("/hop?s={s}"), json!({"minTier": 2}));
            // the 307 is a read with a body: a write stops there
            merge(
                &mut v,
                json!({
                    "readOnly": s == 307,
                    "request": {
                        "method": "POST",
                        "url": format!("{}/hop?s={s}", fx.base),
                        "headers": {"content-type": "application/json"},
                        "body": "{\"id\":\"1\"}",
                    },
                }),
            );
            v
        };
        save(
            &fx,
            "t2hop",
            vec![
                rd(&fx, "boot", "/bootstrap", json!({"minTier": 2})),
                post(307),
                post(303),
                rd(&fx, "loop", "/loop", json!({"minTier": 2})),
            ],
        );
        clear_profile_cookie_named("step").await;
        let r = call("t2hop", "boot", args(json!({})), o2()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.tier, Some(2));
        assert!(matches(r"(^|; )step=1", fx.hits().iter().find(|h| h.url == "/needs-step").and_then(|h| h.h("cookie")).unwrap_or("")));

        for (s, method, body, ct) in [(307u16, "POST", "{\"id\":\"1\"}", Some("application/json")), (303, "GET", "", None)] {
            fx.clear_hits();
            let w = call("t2hop", &format!("post{s}"), args(json!({})), writes(o2())).await;
            assert!(w.ok, "{}", j(&w));
            let landed = fx.hits().into_iter().find(|h| h.url == "/landed");
            assert_eq!(
                (
                    landed.as_ref().map(|h| h.method.clone()),
                    landed.as_ref().map(|h| h.body.clone()),
                    landed.as_ref().and_then(|h| h.h("content-type").map(String::from))
                ),
                (Some(method.to_string()), Some(body.to_string()), ct.map(String::from)),
                "{s}"
            );
            assert_eq!(fx.hits().iter().filter(|h| h.url.starts_with("/hop")).count(), 1, "the write was sent once");
        }

        fx.clear_hits();
        let lp = call("t2hop", "loop", args(json!({})), o2()).await;
        assert!(!lp.ok);
        assert_eq!(lp.class, Class::Error, "{}", j(&lp));
        assert!(fx.hits().len() <= 21, "{} requests", fx.hits().len());

        // Post/Redirect/Get to a page that refuses scripts: the 403 answers the redirect's follow-up, so the write ran
        let mut follow = post(303);
        merge(
            &mut follow,
            json!({"name": "follow", "request": {"method": "POST", "url": format!("{}/api/follow", fx.base), "headers": {}, "body": "x=1"}}),
        );
        save(&fx, "t2prg", vec![follow]);
        fx.clear_hits();
        let ran = call("t2prg", "follow", args(json!({})), writes(o2())).await;
        assert_eq!(ran.tier, Some(2), "{}", j(&ran));
        assert_eq!(fx.hits().iter().filter(|h| h.method == "POST").count(), 1, "the write was sent once");
        assert!(next(&ran).contains("may have gone through"), "a redirected write is one that ran: {ran:?}");
    });
}

/// The per-tier tests of the "browser tiers" block; `tier` 1 needs no Chrome, but the block skips without one.
fn per_tier(tier: u8, f: impl FnOnce(Fx, u8, CallOptions) -> LocalBoxFuture<'static, ()>) {
    chrome_test(move |fx| f(fx, tier, opts(Some(tier), Some(5000))));
}

fn a_location_that_copies_a_token_from_inside_a_header_is_not_followed_to_another_origin(tier: u8) {
    per_tier(tier, |fx, tier, o| {
        async move {
            let name = format!("copy{tier}");
            save(
                &fx,
                &name,
                vec![rd(
                    &fx,
                    "me",
                    "/away-copy",
                    json!({
                        "minTier": tier,
                        "request": {"method": "GET", "url": format!("{}/away-copy", fx.base), "headers": {"x-session": "{\"token\":\"\"}"}},
                        "slots": [{"ref": "session:token", "at": ["header:x-session", "json:/token"]}],
                        "response": {"format": "json"},
                    }),
                )],
            );
            save_session(&name, &session(vec![], &[("token", "SECRET-token-1234")])).unwrap();
            let r = call(&name, "me", args(json!({})), o).await;
            assert_eq!(
                fx.other_hits().iter().filter(|h| h.method != "OPTIONS").map(|h| h.url.clone()).collect::<Vec<_>>(),
                Vec::<String>::new(),
                "the token reached the other origin in the address"
            );
            assert!(!r.ok, "{}", j(&r));
            assert!(reason(&r).contains("not following the HTTP 302 redirect"), "{r:?}");
        }
        .boxed_local()
    });
}

#[test]
fn tier_1_a_location_that_copies_a_token_from_inside_a_header_is_not_followed_to_another_origin() {
    a_location_that_copies_a_token_from_inside_a_header_is_not_followed_to_another_origin(1);
}

#[test]
fn tier_2_a_location_that_copies_a_token_from_inside_a_header_is_not_followed_to_another_origin() {
    a_location_that_copies_a_token_from_inside_a_header_is_not_followed_to_another_origin(2);
}

fn a_post_redirected_to_a_get_loses_every_body_header_with_its_body(tier: u8) {
    per_tier(tier, |fx, tier, o| {
        async move {
            for s in [301, 302, 303] {
                let name = format!("strict{tier}s{s}");
                save(
                    &fx,
                    &name,
                    vec![rd(
                        &fx,
                        "q",
                        &format!("/hop-strict?s={s}"),
                        json!({
                            "minTier": tier,
                            "request": {
                                "method": "POST",
                                "url": format!("{}/hop-strict?s={s}", fx.base),
                                "headers": {"content-type": "text/plain", "content-language": "en", "content-location": "/x"},
                                "body": "q",
                            },
                        }),
                    )],
                );
                let r = call(&name, "q", args(json!({})), o.clone()).await;
                assert!(r.ok, "HTTP {s}: {}", j(&r));
            }
        }
        .boxed_local()
    });
}

#[test]
fn tier_1_a_post_redirected_to_a_get_loses_every_body_header_with_its_body() {
    a_post_redirected_to_a_get_loses_every_body_header_with_its_body(1);
}

#[test]
fn tier_2_a_post_redirected_to_a_get_loses_every_body_header_with_its_body() {
    a_post_redirected_to_a_get_loses_every_body_header_with_its_body(2);
}

fn a_get_answered_303_goes_on_as_it_was_headers_and_all(tier: u8) {
    per_tier(tier, |fx, tier, o| {
        async move {
            let name = format!("told{tier}");
            save(
                &fx,
                &name,
                vec![rd(
                    &fx,
                    "q",
                    "/hop?s=303&to=/told",
                    json!({
                        "minTier": tier,
                        "request": {
                            "method": "GET",
                            "url": format!("{}/hop?s=303&to=/told", fx.base),
                            "headers": {"content-language": "fr", "content-type": "application/json"},
                        },
                    }),
                )],
            );
            let r = call(&name, "q", args(json!({})), o).await;
            assert_eq!(r.data, Some(json!([{"language": "fr", "type": "application/json"}])), "{}", j(&r));
        }
        .boxed_local()
    });
}

#[test]
fn tier_1_a_get_answered_303_goes_on_as_it_was_headers_and_all() {
    a_get_answered_303_goes_on_as_it_was_headers_and_all(1);
}

#[test]
fn tier_2_a_get_answered_303_goes_on_as_it_was_headers_and_all() {
    a_get_answered_303_goes_on_as_it_was_headers_and_all(2);
}

fn a_session_value_no_header_can_carry_fails_naming_the_header_never_the_value(tier: u8) {
    per_tier(tier, |fx, tier, o| {
        async move {
            let name = format!("brk{tier}");
            save(
                &fx,
                &name,
                vec![rd(
                    &fx,
                    "me",
                    "/api/brk",
                    json!({
                        "minTier": tier,
                        "request": {"method": "GET", "url": format!("{}/api/brk", fx.base), "headers": {"x-token": ""}},
                        "slots": [{"ref": "session:tok", "at": ["header:x-token"]}],
                    }),
                )],
            );
            save_session(&name, &session(vec![], &[("tok", "SECRET-source-token-1234\r\nextra")])).unwrap();
            fx.clear_hits();
            let r = call(&name, "me", args(json!({})), o).await;
            assert!(!r.ok);
            assert!(!matches(r"SECRET|extra", &j(&r).to_string()), "{}", j(&r));
            assert!(reason(&r).contains("the x-token header"), "{r:?}");
            assert!(matches(r"api-anything login brk\d", next(&r)), "{r:?}");
            assert_eq!(fx.hits().iter().filter(|h| h.url == "/api/brk").count(), 0);
        }
        .boxed_local()
    });
}

#[test]
fn tier_1_a_session_value_no_header_can_carry_fails_naming_the_header_never_the_value() {
    a_session_value_no_header_can_carry_fails_naming_the_header_never_the_value(1);
}

#[test]
fn tier_2_a_session_value_no_header_can_carry_fails_naming_the_header_never_the_value() {
    a_session_value_no_header_can_carry_fails_naming_the_header_never_the_value(2);
}

fn a_write_is_not_sent_a_second_time_by_a_redirect_and_the_result_says_where_it_stopped(tier: u8) {
    per_tier(tier, |fx, tier, o| {
        async move {
            let write = |name: &str, method: &str, path: &str| {
                let mut v = rd(&fx, name, path, json!({"minTier": tier}));
                let mut request = json!({"method": method, "url": format!("{}{path}", fx.base), "headers": {}});
                if method != "GET" {
                    request["body"] = json!("x=1");
                }
                merge(&mut v, json!({"readOnly": false, "request": request}));
                v
            };
            let sends =
                |fx: &Fx| fx.hits().iter().map(|h| h.url.clone()).filter(|u| matches(r"^/(again|hop|landed)", u)).collect::<Vec<_>>();
            let name = format!("once{tier}");
            save(
                &fx,
                &name,
                vec![
                    write("loop307", "POST", "/again?s=307"),
                    write("loop308", "POST", "/again?s=308"),
                    write("moved", "POST", "/hop?s=307"),
                    write("put", "PUT", "/hop?s=302"),
                    write("vote", "GET", "/again?s=302"),
                    write("prg", "GET", "/hop?s=302"),
                ],
            );
            for (op, status) in [("loop307", 307), ("loop308", 308), ("moved", 307), ("put", 302), ("vote", 302)] {
                fx.clear_hits();
                let r = call(&name, op, args(json!({})), writes(o.clone())).await;
                assert_eq!(sends(&fx).len(), 1, "{op} was sent to {:?}: {}", sends(&fx), j(&r));
                assert!(!r.ok, "{op}: {}", j(&r));
                assert_eq!(
                    r.reason.as_deref(),
                    Some(format!("not following the HTTP {status} redirect to {}: it would send this write again", fx.base).as_str()),
                    "{op}"
                );
                assert!(
                    matches(
                        r"^the write was sent once.*check the site first.*Do not retry.*api-anything add once\d \w+ \.\.\. --write",
                        next(&r)
                    ),
                    "{r:?}"
                );
            }
            // a GET write's landing page is another request: followed
            fx.clear_hits();
            let prg = call(&name, "prg", args(json!({})), writes(o)).await;
            assert!(prg.ok, "{}", j(&prg));
            assert_eq!(sends(&fx), vec!["/hop?s=302", "/landed"]);
        }
        .boxed_local()
    });
}

#[test]
fn tier_1_a_write_is_not_sent_a_second_time_by_a_redirect_and_the_result_says_where_it_stopped() {
    a_write_is_not_sent_a_second_time_by_a_redirect_and_the_result_says_where_it_stopped(1);
}

#[test]
fn tier_2_a_write_is_not_sent_a_second_time_by_a_redirect_and_the_result_says_where_it_stopped() {
    a_write_is_not_sent_a_second_time_by_a_redirect_and_the_result_says_where_it_stopped(2);
}

// each tier's cap is the one it had before redirects were followed by hand: 5 at tier 1, 20 at tier 2
fn cap_of(tier: u8) -> usize {
    if tier == 1 { 5 } else { 20 }
}

fn a_chain_is_followed_up_to_cap_redirects_one_more_ends_saying_so_and_how_to_go_on(tier: u8) {
    per_tier(tier, |fx, tier, o| {
        async move {
            let cap = cap_of(tier);
            let name = format!("chain{tier}");
            save(&fx, &name, vec![rd(&fx, "far", "/chain", json!({"minTier": tier})), rd(&fx, "round", "/loop", json!({"minTier": tier}))]);
            let far = call(&name, "far", args(json!({})), o.clone()).await;
            if tier == 2 {
                assert_eq!(far.data, Some(json!([{"end": 6}])), "{}", j(&far));
            } else {
                assert!(matches(r"^stopped after 5 redirects", reason(&far)), "{}", j(&far));
            }

            fx.clear_hits();
            let r = call(&name, "round", args(json!({})), o).await;
            assert!(!r.ok, "{}", j(&r));
            assert!(matches(&format!(r"^stopped after {cap} redirects, the last one to http://127\.0\.0\.1:\d+$"), reason(&r)), "{r:?}");
            assert!(matches(r"do not retry.*api-anything add chain\d round", next(&r)), "{r:?}");
            assert_eq!(fx.hits().iter().filter(|h| h.url == "/loop").count(), cap + 1);
        }
        .boxed_local()
    });
}

#[test]
fn tier_1_a_chain_is_followed_up_to_5_redirects_one_more_ends_saying_so_and_how_to_go_on() {
    a_chain_is_followed_up_to_cap_redirects_one_more_ends_saying_so_and_how_to_go_on(1);
}

#[test]
fn tier_2_a_chain_is_followed_up_to_20_redirects_one_more_ends_saying_so_and_how_to_go_on() {
    a_chain_is_followed_up_to_cap_redirects_one_more_ends_saying_so_and_how_to_go_on(2);
}

fn a_get_write_sent_on_to_a_new_address_at_each_hop_reaches_the_server_no_more_than_cap_1_times(tier: u8) {
    per_tier(tier, |fx, tier, o| {
        async move {
            let cap = cap_of(tier);
            let name = format!("votes{tier}");
            save(&fx, &name, vec![rd(&fx, "vote", "/vote/0", json!({"minTier": tier, "readOnly": false}))]);
            fx.clear_hits();
            let r = call(&name, "vote", args(json!({})), writes(o)).await;
            assert!(!r.ok, "{}", j(&r));
            assert_eq!(fx.hits().iter().filter(|h| h.url.starts_with("/vote")).count(), cap + 1);
            assert!(next(&r).contains("check the site first"), "{r:?}");
        }
        .boxed_local()
    });
}

#[test]
fn tier_1_a_get_write_sent_on_to_a_new_address_at_each_hop_reaches_the_server_no_more_than_6_times() {
    a_get_write_sent_on_to_a_new_address_at_each_hop_reaches_the_server_no_more_than_cap_1_times(1);
}

#[test]
fn tier_2_a_get_write_sent_on_to_a_new_address_at_each_hop_reaches_the_server_no_more_than_21_times() {
    a_get_write_sent_on_to_a_new_address_at_each_hop_reaches_the_server_no_more_than_cap_1_times(2);
}

#[test]
fn tier_2_refuses_a_redirect_it_cannot_tell_from_anothers_the_origin_page_sent_the_same_request_at_the_same_time() {
    chrome_test(|fx| async move {
        let waiting: Arc<Mutex<Vec<tokio::sync::oneshot::Sender<usize>>>> = Arc::new(Mutex::new(vec![]));
        let landed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
        let (w2, l2) = (waiting.clone(), landed.clone());
        let twin: Handler = Arc::new(move |hit: Hit| {
            let (waiting, landed) = (w2.clone(), l2.clone());
            async move {
                if hit.url == "/" {
                    return html_r(200, "<!doctype html><title>twin</title><script>fetch(\"/twin?token=SECRET-query-token-123\",{method:\"POST\",body:\"q\"})</script>");
                }
                // a POST: Chrome's cache makes a second GET of one URL wait for the first
                if hit.url.starts_with("/twin") {
                    // held until the page's own request and the call's are both in; then each is sent somewhere else
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    {
                        let mut w = waiting.lock().unwrap();
                        w.push(tx);
                        if w.len() == 2 {
                            for (i, s) in w.drain(..).enumerate() {
                                let _ = s.send(i);
                            }
                        }
                    }
                    let i = rx.await.unwrap();
                    return head(302, &[("location", &format!("/to-{i}"))]);
                }
                landed.lock().unwrap().push(hit.url.clone());
                json_r(json!({}), 200, &[])
            }
            .boxed()
        });
        let (base, task) = serve("127.0.0.1", "127.0.0.1", twin).await;
        let request = json!({"method": "POST", "url": format!("{base}/twin?token=x"), "headers": {}, "body": "q"});
        let slots = json!([{"ref": "session:token", "at": ["query:token"]}]);
        let query = rd(&fx, "query", "/twin", json!({"minTier": 2, "request": request, "slots": slots}));
        save_site(&site(json!({"name": "twin", "baseUrl": base, "operations": [query]}))).unwrap();
        save_session("twin", &session(vec![], &[("token", "SECRET-query-token-123")])).unwrap();
        let r = call("twin", "query", args(json!({})), o2()).await;
        assert!(!r.ok, "{}", j(&r));
        assert!(matches(r"not following a redirect from http://127\.0\.0\.1:\d+: .* cannot be told apart", reason(&r)), "{r:?}");
        assert!(!j(&r).to_string().contains("SECRET-query-token-123"), "the result carries the session's token");
        let landed = landed.lock().unwrap().clone();
        assert!(!landed.iter().any(|l| l == "/to-1"), "followed anyway: {landed:?}");
        task.abort();
    });
}

#[test]
fn a_params_default_reaches_the_tier_3_trigger_the_page_opens_with_it_not_with_a_literal_page() {
    chrome_test(|fx| async move {
        save(
            &fx,
            "deftrig",
            vec![rd(
                &fx,
                "items",
                "/api/items?page=1",
                json!({
                    "minTier": 3,
                    "slots": [{"param": "page", "at": ["query:page"]}],
                    "params": [{"name": "page", "default": "7", "required": false}],
                    "trigger": {"url": format!("{}/paged?page={{page}}", fx.base)},
                    "match": {"path": "/api/items"},
                }),
            )],
        );
        let r = call("deftrig", "items", args(json!({})), opts(None, Some(5000))).await;
        let pages: Vec<String> = fx.hits().iter().filter(|h| h.url.starts_with("/paged")).map(|h| h.url.clone()).collect();
        assert_eq!(pages, vec!["/paged?page=7"], "{}", j(&r));
        assert_eq!(r.tier, Some(3), "{}", j(&r));
        assert_eq!(r.data, Some(json!([{"page": "7"}])));
    });
}

fn me_count(fx: &Fx) -> usize {
    fx.hits().iter().filter(|h| h.url == "/api/me").count()
}

#[test]
fn auth_at_tier_2_re_imports_the_browser_session_into_the_profile_and_retries_once_a_write_is_not_resent() {
    chrome_test(|fx| async move {
        save(
            &fx,
            "t2auth",
            vec![
                rd(&fx, "me", "/api/me", json!({"minTier": 2})),
                rd(
                    &fx,
                    "save",
                    "/api/me",
                    json!({
                        "minTier": 2,
                        "readOnly": false,
                        "request": {"method": "POST", "url": format!("{}/api/me", fx.base), "headers": {}, "body": "x=1"},
                    }),
                ),
            ],
        );
        let root = tempfile::Builder::new().prefix("everyday-browser-").tempdir_in(HOME.path()).unwrap();
        // the human signs in in their everyday browser; the server honours only that session
        let sign_in = |sid: &str| {
            fx.set_sid(sid);
            make_chromium_db(&root.path().join("Default"), &[("127.0.0.1", "sid", sid)], "pw");
        };
        set_browser_roots(root.path());
        sign_in("first");
        assert_eq!(
            import_session("t2auth", &format!("{}/", fx.base), ImportOptions::new()).await.unwrap().map(|i| i.source),
            Some("chrome:Default".to_string())
        );
        assert_eq!(call("t2auth", "me", args(json!({})), o2()).await.data, Some(json!([{"me": "first"}])));

        sign_in("second");
        fx.clear_hits();
        let r = call("t2auth", "me", args(json!({})), o2()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.tier, Some(2));
        assert_eq!(r.data, Some(json!([{"me": "second"}])));
        assert_eq!(me_count(&fx), 2, "one retry");

        // logged out with nothing new to import: one retry, then the login hint
        fx.set_sid("third");
        fx.clear_hits();
        let out = call("t2auth", "me", args(json!({})), o2()).await;
        assert_eq!(out.class, Class::Auth, "{}", j(&out));
        assert!(next(&out).contains("api-anything login t2auth"), "{out:?}");
        assert_eq!(me_count(&fx), 2, "at most once per call");

        // a write answered 200 with the login page may have run: never resent
        fx.clear_hits();
        let w = call("t2auth", "save", args(json!({})), writes(o2())).await;
        assert_eq!(w.class, Class::Auth, "{}", j(&w));
        assert_eq!(me_count(&fx), 1, "the write was sent once");
        clear_browser_roots();
    });
}

#[test]
fn a_tier_3_reads_own_request_may_be_sent_on_by_a_307_to_its_own_origin_or_another() {
    chrome_test(|fx| async move {
        for far in [false, true] {
            let q = if far { "?far=1" } else { "" };
            let name = if far { "signedfar" } else { "signed" };
            save(
                &fx,
                name,
                vec![rd(
                    &fx,
                    "q",
                    &format!("/read{q}"),
                    json!({
                        "minTier": 3,
                        "trigger": {"url": format!("{}/signed-page{q}", fx.base)},
                        "request": {"method": "POST", "url": format!("{}/read{q}", fx.base), "headers": {}, "body": "final"},
                        "match": {"method": "POST", "path": "/read"},
                    }),
                )],
            );
            fx.clear_hits();
            fx.clear_other_hits();
            let r = call(name, "q", args(json!({})), opts(Some(3), Some(5000))).await;
            let posts =
                |hits: Vec<Hit>| hits.iter().filter(|h| h.method == "POST").map(|h| format!("{} {}", h.url, h.body)).collect::<Vec<_>>();
            // the check is reached, wherever it is, and then the page asks for the data
            let mut all = posts(fx.hits());
            all.extend(posts(fx.other_hits()));
            all.sort();
            assert_eq!(all, vec!["/answer initial".to_string(), format!("/read{q} final"), format!("/read{q} initial")], "{}", j(&r));
            assert_eq!(posts(fx.other_hits()).len(), if far { 1 } else { 0 });
            assert_eq!(r.tier, Some(3), "{}", j(&r));
            assert_eq!(r.data, Some(json!([{"name": "alice"}])));
        }
    });
}

#[test]
fn auth_at_tier_3_re_imports_the_browser_session_into_the_profile_and_retries_once() {
    chrome_test(|fx| async move {
        save(
            &fx,
            "t3auth",
            vec![rd(
                &fx,
                "me",
                "/api/me",
                json!({"minTier": 3, "trigger": {"url": format!("{}/me-page", fx.base)}, "match": {"path": "/api/me"}}),
            )],
        );
        let root = tempfile::Builder::new().prefix("everyday-browser-").tempdir_in(HOME.path()).unwrap();
        let sign_in = |sid: &str| {
            fx.set_sid(sid);
            make_chromium_db(&root.path().join("Default"), &[("127.0.0.1", "sid", sid)], "pw");
        };
        let o = opts(None, Some(5000));
        set_browser_roots(root.path());
        sign_in("first");
        assert_eq!(
            import_session("t3auth", &format!("{}/", fx.base), ImportOptions::new()).await.unwrap().map(|i| i.source),
            Some("chrome:Default".to_string())
        );
        assert_eq!(call("t3auth", "me", args(json!({})), o.clone()).await.data, Some(json!([{"me": "first"}])));

        sign_in("second");
        fx.clear_hits();
        let r = call("t3auth", "me", args(json!({})), o.clone()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.tier, Some(3));
        assert_eq!(r.data, Some(json!([{"me": "second"}])));
        assert_eq!(me_count(&fx), 2, "one retry");

        // logged out with nothing new to import: one retry, then the login hint
        fx.set_sid("third");
        fx.clear_hits();
        let out = call("t3auth", "me", args(json!({})), o).await;
        assert_eq!(out.class, Class::Auth, "{}", j(&out));
        assert!(next(&out).contains("api-anything login t3auth"), "{out:?}");
        assert_eq!(me_count(&fx), 2, "at most once per call");
        clear_browser_roots();
    });
}

#[test]
fn a_tier_3_write_that_ran_and_was_then_redirected_to_a_refusal_is_not_sent_again_by_auth_recovery() {
    chrome_test(|fx| async move {
        save(
            &fx,
            "t3write",
            vec![rd(
                &fx,
                "save",
                "/api/save",
                json!({
                    "minTier": 3,
                    "trigger": {"url": format!("{}/save-page", fx.base)},
                    "match": {"method": "POST", "path": "/api/save"},
                    "readOnly": false,
                    "request": {"method": "POST", "url": format!("{}/api/save", fx.base), "headers": {}, "body": "x=1"},
                }),
            )],
        );
        // a session to re-import, so recovery would have something to retry with
        let root = tempfile::Builder::new().prefix("everyday-browser-").tempdir_in(HOME.path()).unwrap();
        make_chromium_db(&root.path().join("Default"), &[("127.0.0.1", "sid", "any")], "pw");
        set_browser_roots(root.path());
        assert_eq!(
            import_session("t3write", &format!("{}/", fx.base), ImportOptions::new()).await.unwrap().map(|i| i.source),
            Some("chrome:Default".to_string())
        );
        fx.clear_hits();
        let r = call("t3write", "save", args(json!({})), writes(opts(None, Some(5000)))).await;
        let saves = fx.hits().iter().filter(|h| h.method == "POST" && h.url == "/api/save").count();
        assert_eq!(saves, 1, "the write was sent {saves} times; result {}", j(&r));
        assert!(!r.ok);
        assert!(next(&r).contains("check the site"), "{r:?}");
        assert!(!next(&r).contains("retry once"), "{r:?}");
        // the server's 307 would have the page send the write a second time: stopped, and said
        assert_eq!(
            fx.hits().iter().filter(|h| h.url == "/api/save?login=1").map(|h| h.method.clone()).collect::<Vec<_>>(),
            Vec::<String>::new(),
            "the redirect sent the write on"
        );
        assert_eq!(r.class, Class::Error, "{}", j(&r));
        assert!(matches(r"^the site answered this write with a redirect that would send it again: stopped", reason(&r)), "{r:?}");
        assert!(matches(r"api-anything add t3write save \.\.\. --write", next(&r)), "{r:?}");
        clear_browser_roots();
    });
}

#[test]
fn a_tier_3_write_whose_page_sends_it_twice_is_performed_once_and_the_result_says_a_repeat_was_stopped() {
    chrome_test(|fx| async move {
        save(
            &fx,
            "t3twice",
            vec![rd(
                &fx,
                "save",
                "/api/double",
                json!({
                    "minTier": 3,
                    "trigger": {"url": format!("{}/double-page", fx.base), "steps": [{"action": "click", "selector": "#go"}]},
                    "match": {"method": "POST", "path": "/api/double"},
                    "readOnly": false,
                    "request": {"method": "POST", "url": format!("{}/api/double", fx.base), "headers": {}, "body": "x=1"},
                    "response": {"format": "json"},
                }),
            )],
        );
        let r = call("t3twice", "save", args(json!({})), writes(opts(None, Some(5000)))).await;
        let posts = |path: &str| fx.hits().iter().filter(|h| h.method == "POST" && h.url == path).count();
        assert_eq!(posts("/api/double"), 1, "the write reached the server {} times", posts("/api/double"));
        assert_eq!(posts("/api/companion"), 1, "what else the trigger sends is left alone");
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.tier, Some(3));
        assert!(matches(r"sent this write 2 times.* stopped", reason(&r)), "{r:?}");
    });
}

#[test]
fn auth_at_tier_2_from_a_stale_cookie_behind_a_header_ref_the_jar_is_refreshed_from_the_profile_one_retry() {
    chrome_test(|fx| async move {
        save(
            &fx,
            "t2csrf",
            vec![rd(
                &fx,
                "items",
                "/api/csrf",
                json!({
                    "minTier": 2,
                    "request": {"method": "GET", "url": format!("{}/api/csrf", fx.base), "headers": {"x-csrf": ""}},
                    "slots": [{"ref": "cookie:ct", "at": ["header:x-csrf"]}],
                }),
            )],
        );
        // the site rotated its token in the profile; the jar still holds the old one
        add_cookies_to_profile(&[cookie("ct", "fresh", "127.0.0.1")], &profile_dir()).await.unwrap();
        save_session("t2csrf", &session(vec![cookie("ct", "stale", "127.0.0.1")], &[])).unwrap();
        let r = call("t2csrf", "items", args(json!({})), o2()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.tier, Some(2));
        assert_eq!(r.data, Some(json!([{"ct": "fresh"}])));
        assert_eq!(fx.hits().iter().filter(|h| h.url == "/api/csrf").count(), 2, "one retry");
    });
}

#[test]
fn auth_at_tier_2_a_cookie_ref_the_refreshed_jar_cannot_place_is_a_failed_call_not_a_thrown_one() {
    chrome_test(|fx| async move {
        save(
            &fx,
            "t2wrap",
            vec![rd(
                &fx,
                "items",
                "/api/csrf",
                json!({
                    "minTier": 2,
                    "request": {"method": "GET", "url": format!("{}/api/csrf", fx.base), "headers": {"x-wrap": "{}"}},
                    "slots": [{"ref": "cookie:ct", "at": ["header:x-wrap", "json:/token"]}],
                }),
            )],
        );
        // with no ct in the jar the slot is skipped; the profile has one, and it has nowhere to go in "{}"
        add_cookies_to_profile(&[cookie("ct", "fresh", "127.0.0.1")], &profile_dir()).await.unwrap();
        save_session("t2wrap", &session(vec![], &[])).unwrap();
        let r = call("t2wrap", "items", args(json!({})), o2()).await;
        assert!(!r.ok, "{}", j(&r));
        assert!(reason(&r).contains("JSON pointer"), "{r:?}");
    });
}

#[test]
fn auth_at_tier_2_for_a_read_with_a_session_ref_one_trigger_run_refreshes_the_value_and_answers() {
    chrome_test(|fx| async move {
        save(
            &fx,
            "t2token",
            vec![rd(
                &fx,
                "items",
                "/api/token",
                json!({
                    "minTier": 2,
                    "request": {"method": "GET", "url": format!("{}/api/token", fx.base), "headers": {"x-token": ""}},
                    "slots": [{"ref": "session:x-token", "at": ["header:x-token"]}],
                    "trigger": {"url": format!("{}/tokened", fx.base)},
                    "match": {"path": "/api/token"},
                }),
            )],
        );
        let o = opts(None, Some(5000));
        let r = call("t2token", "items", args(json!({})), o.clone()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.tier, Some(3));
        assert!(matches(r"^tier 2 said auth .*refreshed the session", reason(&r)), "{r:?}");
        assert_eq!(call("t2token", "items", args(json!({})), o).await.tier, Some(2), "the refreshed value serves tier 2");
    });
}

#[test]
fn auth_with_no_login_on_record_gets_one_attempt_from_a_real_page_before_giving_up_and_the_tier_that_answers_is_remembered() {
    chrome_test(|fx| async move {
        save(&fx, "picky", vec![rd(&fx, "items", "/api/picky", json!({}))]);
        let o = opts(None, Some(5000));
        fx.clear_hits();
        let r = call("picky", "items", args(json!({})), o.clone()).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.tier, Some(2));
        assert_eq!(r.data, Some(json!([{"picky": "ok"}])));
        assert!(reason(&r).contains("tier 1 said auth with no login on record"), "{r:?}");
        // the next call starts where this one got through
        fx.clear_hits();
        assert_eq!(call("picky", "items", args(json!({})), o).await.tier, Some(2));
        assert_eq!(fx.hits().iter().filter(|h| h.url == "/api/picky").count(), 1, "tier 1 was not tried again");
    });
}

#[test]
fn when_the_page_says_auth_too_the_call_ends_exactly_as_it_would_have_tier_1s_auth_and_the_login_hint() {
    chrome_test(|fx| async move {
        // /api/me answers its login page to everyone but the one session it honours
        save(&fx, "walled", vec![rd(&fx, "me", "/api/me", json!({}))]);
        fx.set_sid("nobody-has-this");
        fx.clear_hits();
        let r = call("walled", "me", args(json!({})), opts(None, Some(5000))).await;
        assert_eq!(r.class, Class::Auth, "{}", j(&r));
        assert_eq!(r.tier, Some(1));
        assert!(next(&r).contains("api-anything login walled"), "{r:?}");
        let from_page = fx.hits().iter().filter(|h| h.url == "/api/me" && h.chrome_ua()).count();
        assert_eq!(from_page, 1, "one attempt from a page, and no trigger run");
    });
}

#[test]
fn a_write_is_never_given_the_page_attempt_it_ends_as_tier_1s_auth_and_no_page_sent_it() {
    chrome_test(|fx| async move {
        // 401 is an answer a write may be retried after, so only the read-only rule keeps this one from the page
        let url = format!("{}/api/picky?status=401", fx.base);
        save(
            &fx,
            "pickywrite",
            vec![rd(
                &fx,
                "save",
                "/api/picky",
                json!({"readOnly": false, "request": {"method": "POST", "url": url, "headers": {}, "body": "x=1"}}),
            )],
        );
        fx.clear_hits();
        let r = call("pickywrite", "save", args(json!({})), writes(opts(None, Some(5000)))).await;
        assert_eq!(r.class, Class::Auth, "{}", j(&r));
        assert_eq!(r.tier, Some(1));
        // recovery may send it once more after a 401, with the profile's cookies: that is plain HTTP too
        assert!(fx.hits().iter().filter(|h| h.method == "POST").count() <= 2);
        assert_eq!(fx.hits().iter().filter(|h| h.chrome_ua()).count(), 0, "no page was opened");
    });
}

#[test]
fn a_login_that_recovery_finds_counts_with_one_in_the_jar_by_then_auth_is_the_answer_and_no_page_is_opened() {
    chrome_test(|fx| async move {
        // nothing on record at the start; the Chrome profile holds a login cookie the wall does not care about
        save(
            &fx,
            "pickyin",
            vec![rd(
                &fx,
                "items",
                "/api/picky",
                json!({"request": {"method": "GET", "url": format!("{}/api/picky", fx.base), "headers": {}}}),
            )],
        );
        add_cookies_to_profile(&[cookie("sessionid", "signed-in-elsewhere", "127.0.0.1")], &profile_dir()).await.unwrap();
        fx.clear_hits();
        let r = call("pickyin", "items", args(json!({})), opts(None, Some(5000))).await;
        assert_eq!(r.class, Class::Auth, "{}", j(&r));
        assert_eq!(r.tier, Some(1));
        assert_eq!(fx.hits().iter().filter(|h| h.chrome_ua()).count(), 0, "no page was opened");
    });
}

#[test]
fn recovery_comes_before_the_page_attempt_a_fresher_cookie_in_the_chrome_profile_answers_at_tier_1() {
    chrome_test(|fx| async move {
        // a session with no source (one saved by an older version), an empty jar, and the cookie only in the profile
        save(&fx, "legacy", vec![rd(&fx, "me", "/api/me", json!({}))]);
        fx.set_sid("profile-only");
        add_cookies_to_profile(&[cookie("sid", "profile-only", "127.0.0.1")], &profile_dir()).await.unwrap();
        save_session("legacy", &session(vec![], &[])).unwrap();
        fx.clear_hits();
        let r = call("legacy", "me", args(json!({})), opts(None, Some(5000))).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.tier, Some(1));
        assert_eq!(r.data, Some(json!([{"me": "profile-only"}])));
        let from_page = fx.hits().iter().filter(|h| h.url == "/api/me" && h.chrome_ua()).count();
        assert_eq!(from_page, 0, "the jar was refreshed from the profile and plain HTTP answered");
    });
}

#[test]
fn tier_2_honours_timeout_ms() {
    chrome_test(|fx| async move {
        save(&fx, "t2slow", vec![rd(&fx, "n", "/never", json!({"minTier": 2})), rd(&fx, "up", "/plain", json!({"minTier": 2}))]);
        // timeoutMs bounds the wait for the site's answer, not Chrome's first start in this process
        // (many seconds on a busy machine): have the browser up on the origin before the clock starts.
        assert!(call("t2slow", "up", args(json!({})), opts(Some(2), None)).await.ok);
        let t0 = Instant::now();
        let r = tokio::time::timeout(Duration::from_millis(15_000), call("t2slow", "n", args(json!({})), opts(Some(2), Some(1000)))).await;
        assert!(r.is_ok(), "no answer after {} ms with timeoutMs 1000", t0.elapsed().as_millis());
    });
}

#[test]
fn tier_2s_timeout_ms_is_one_deadline_once_chrome_is_up_opening_the_sites_page_and_the_fetch_share_it() {
    chrome_test(|fx| async move {
        // a site whose root page takes 2.5 s to come, and whose API never answers
        let slow: Handler = Arc::new(|hit: Hit| {
            async move {
                if hit.url != "/" {
                    return Resp::Never;
                }
                tokio::time::sleep(Duration::from_millis(2500)).await;
                html_r(200, "<!doctype html><title>slow</title>")
            }
            .boxed()
        });
        let (base, task) = serve("127.0.0.1", "127.0.0.1", slow).await;
        save(&fx, "t2up", vec![rd(&fx, "up", "/plain", json!({"minTier": 2}))]);
        assert!(call("t2up", "up", args(json!({})), opts(Some(2), None)).await.ok, "Chrome is up");
        let request = json!({"method": "GET", "url": format!("{base}/api"), "headers": {}});
        save_site(&site(
            json!({"name": "t2late", "baseUrl": base, "operations": [rd(&fx, "n", "/api", json!({"minTier": 2, "request": request}))]}),
        ))
        .unwrap();
        let t0 = Instant::now();
        let r = call("t2late", "n", args(json!({})), opts(Some(2), Some(3000))).await;
        let ms = t0.elapsed().as_millis();
        assert!(!r.ok, "{}", j(&r));
        assert!(reason(&r).contains("no response within 3000 ms"), "{r:?}");
        assert!(ms < 4500, "{ms} ms with timeoutMs 3000: the page's 2.5 s were not counted");
        task.abort();
    });
}

#[test]
fn a_second_process_cli_next_to_a_running_mcp_server_can_still_use_tier_2() {
    chrome_test(|fx| async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        close_browser().await;
        save(&fx, "two", vec![rd(&fx, "l", "/plain", json!({"minTier": 2}))]);
        // an MCP server stays up with Chrome open
        let mut holder = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-anything"))
            .arg("mcp")
            .env("API_ANYTHING_HOME", HOME.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
        let mut stdin = holder.stdin.take().unwrap();
        let mut lines = tokio::io::BufReader::new(holder.stdout.take().unwrap()).lines();
        let ask =
            |id: u64, method: &str, params: Value| format!("{}\n", json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        stdin
            .write_all(
                ask(
                    1,
                    "initialize",
                    json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}}),
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stdin
            .write_all(
                ask(2, "tools/call", json!({"name": "call_operation", "arguments": {"site": "two", "op": "l", "args": {}}})).as_bytes(),
            )
            .await
            .unwrap();
        stdin.flush().await.unwrap();
        let answered = loop {
            let Ok(Some(line)) = lines.next_line().await else { panic!("holder exited") };
            let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            if v["id"] == json!(2) {
                break v["result"]["content"][0]["text"].as_str().unwrap_or("").to_string();
            }
        };
        assert!(answered.contains("\"ok\":true"), "HOLDER {answered}");
        let r = call("two", "l", args(json!({})), opts(None, None)).await;
        assert!(r.ok, "{}: {} (reason {} chars)", r.class, reason(&r).chars().take(200).collect::<String>(), reason(&r).len());
        let _ = holder.kill().await;
    });
}

/* ----------------------------------------------------------------- two processes */

/// The child's half of the two-process tests: this binary, run again with the role in the environment.
fn race_child(test: &str, tag: &str) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--test-threads=1"])
        .env("AA_RACE_TAG", tag)
        .env("API_ANYTHING_HOME", HOME.path())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
fn race_child_cookies() {
    let Ok(tag) = std::env::var("AA_RACE_TAG") else { return };
    for i in 0..150 {
        merge_capture("race", &[cookie(&format!("{tag}{i}"), "v", "race.test")], &IndexMap::new(), now_ms()).unwrap();
    }
}

#[test]
fn race_child_tiers() {
    let Ok(tag) = std::env::var("AA_RACE_TAG") else { return };
    for i in 0..150 {
        remember_tier("race", &format!("{tag}{i}"), Some(2));
    }
}

#[test]
fn two_processes_merging_browser_cookies_into_one_jar_lose_nothing() {
    let _g = fresh();
    let mut a = race_child("race_child_cookies", "a");
    let mut b = race_child("race_child_cookies", "b");
    let codes = [a.wait().unwrap().code().unwrap_or(-1), b.wait().unwrap().code().unwrap_or(-1)];
    assert_eq!(codes, [0, 0]);
    let n = load_session("race").unwrap().cookies.len();
    assert_eq!(n, 300, "jar kept {n} of 300 cookies");
}

#[test]
fn two_processes_writing_state_json_tier_memory_stale_marks_lose_nothing() {
    let _g = fresh();
    let mut a = race_child("race_child_tiers", "a");
    let mut b = race_child("race_child_tiers", "b");
    assert_eq!([a.wait().unwrap().code().unwrap_or(-1), b.wait().unwrap().code().unwrap_or(-1)], [0, 0]);
    let state: Value = serde_json::from_str(&std::fs::read_to_string(HOME.path().join("state.json")).unwrap()).unwrap();
    let n = state["tier"].as_object().map(|o| o.len()).unwrap_or(0);
    assert_eq!(n, 300, "state kept {n} of 300 tier entries");
}

/* ----------------------------------------------------------------- round2-classify: call */

/// round2's `op(over)`: the c.test search read, through the schema.
fn r2_site(name: &str, over: Value) {
    let mut o = json!({
        "name": "o",
        "readOnly": true,
        "request": {"method": "GET", "url": "https://c.test/api/search?q=alice", "headers": {}},
        "slots": [{"param": "q", "at": ["query:q"]}],
        "params": [{"name": "q", "example": "alice"}],
        "trigger": {"url": "https://c.test/s?q={q}"},
        "response": {"format": "json", "extract": "results"},
    });
    merge(&mut o, over);
    o["name"] = json!("o");
    save_site(&site(json!({"name": name, "baseUrl": "https://c.test", "operations": [o]}))).unwrap();
}

fn r2_t1(f: &Arc<FnFetcher>) -> CallOptions {
    CallOptions { allow_writes: false, fetcher: Some(f.clone()), max_tier: Some(1), min_interval_ms: Some(0), timeout_ms: None }
}

fn r2_hits(f: &FnFetcher) -> Vec<String> {
    f.hits.lock().unwrap().clone()
}

#[test]
fn a_search_with_no_results_returns_ok_with_empty_list_and_replays_nothing() {
    let _g = fresh();
    RT.block_on(async {
        r2_site("empty", json!({}));
        let f = fetcher(|_| Ok(mem_json(json!({"results": []}), 200)));
        let r = call("empty", "o", args(json!({"q": "zzqxnonexistent"})), r2_t1(&f)).await;
        assert!(r.ok, "{}", j(&r));
        assert_eq!(r.data, Some(json!([])));
        assert_eq!(r2_hits(&f).len(), 1, "no example replay");
    });
}

#[test]
fn a_reads_bare_403_for_these_args_while_the_examples_answer_is_input_no_climb_no_heal() {
    let _g = fresh();
    RT.block_on(async {
        r2_site("private", json!({}));
        let refused = || mem_json(json!({"message": "This profile can't be accessed", "status": 403}), 403);
        let f = fetcher(move |req| Ok(if req.url.contains("alice") { mem_json(json!({"results": [{"id": 1}]}), 200) } else { refused() }));
        let mut o = r2_t1(&f);
        o.max_tier = Some(3);
        let r = call("private", "o", args(json!({"q": "bob"})), o).await;
        assert_eq!(r.class, Class::Input, "{}", j(&r));
        assert_eq!(r.tier, Some(1));
        assert!(matches(r"refused for these args .*; the example args still return data", reason(&r)), "{r:?}");
        assert_eq!(r2_hits(&f).len(), 2, "the call and one example replay");
        // the examples refused too: still a wall, still climbs (capped here)
        let f = fetcher(move |_| Ok(refused()));
        let w = call("private", "o", args(json!({"q": "bob"})), r2_t1(&f)).await;
        assert_eq!(w.class, Class::Blocked);
        assert_eq!(r2_hits(&f).len(), 2);
    });
}

#[test]
fn no_data_for_these_args_while_the_examples_answer_says_the_operation_works() {
    let _g = fresh();
    RT.block_on(async {
        r2_site("nodata", json!({}));
        let f = fetcher(|req| Ok(mem_json(if req.url.contains("alice") { json!({"results": [{"id": 1}]}) } else { json!({}) }, 200)));
        let r = call("nodata", "o", args(json!({"q": "bob"})), r2_t1(&f)).await;
        assert_eq!(r.class, Class::Input);
        assert!(matches(r"no results for these args .*; the example args still return data, so the operation works", reason(&r)), "{r:?}");
    });
}

#[test]
fn a_cross_origin_307_is_not_followed_when_the_body_carries_a_session_value() {
    let _g = fresh();
    RT.block_on(async {
        r2_site(
            "redir",
            json!({
                "readOnly": false,
                "request": {
                    "method": "POST",
                    "url": "https://c.test/api/post",
                    "headers": {"content-type": "application/x-www-form-urlencoded"},
                    "body": "q=alice&fb_dtsg=PLACEHOLDER",
                },
                "slots": [
                    {"param": "q", "at": ["form:q"]},
                    {"ref": "session:fb_dtsg", "at": ["form:fb_dtsg"]},
                ],
            }),
        );
        save_session("redir", &session(vec![], &[("fb_dtsg", "SECRET_DTSG_VALUE")])).unwrap();
        let f = fetcher(|req| {
            Ok(if req.url.starts_with("https://c.test/") {
                mem_response(307, &[("location", "https://other.test/collect")], "")
            } else {
                mem_json(json!({"ok": 1}), 200)
            })
        });
        let r = call("redir", "o", args(json!({"q": "x"})), writes(r2_t1(&f))).await;
        assert!(!r.ok, "{}", j(&r));
        assert!(matches(r"not following the HTTP 307 redirect to https://other\.test", reason(&r)), "{r:?}");
        assert_eq!(
            r2_hits(&f).into_iter().filter(|h| h.contains("other.test")).collect::<Vec<_>>(),
            Vec::<String>::new(),
            "the other origin got nothing"
        );
        // same origin, or no session value aboard: followed as before
        r2_site("redir2", json!({"request": {"method": "GET", "url": "https://c.test/api/search?q=alice", "headers": {}}}));
        let f = fetcher(|req| {
            Ok(if req.url.starts_with("https://c.test/") {
                mem_response(307, &[("location", "https://other.test/api")], "")
            } else {
                mem_json(json!({"results": [{"id": 1}]}), 200)
            })
        });
        let ok = call("redir2", "o", args(json!({"q": "x"})), r2_t1(&f)).await;
        assert!(ok.ok, "{}", j(&ok));
    });
}
