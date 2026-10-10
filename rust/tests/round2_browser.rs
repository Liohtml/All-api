//! Port of test/edge/round2-browser.test.ts. Round-2 regressions for the browser layer: a popup's
//! WebSocket sends are dropped while learning a write, and a run waits out a JS challenge that
//! reloads the page.
mod common;
use api_anything::browser::{TriggerOptions, close_browser, run_trigger};
use api_anything::heal::{CapturePageOptions, capture_page, profile_dir};
use base64::Engine;
use common::Home;
use regex::Regex;
use serde_json::json;
use sha1::Digest;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One runtime for the whole binary, like node's one event loop: the shared Chrome belongs to the
/// runtime that launched it, so every test runs on this one.
static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
/// API_ANYTHING_HOME is one variable for the process: the tests take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn chrome() -> bool {
    if std::env::var("API_ANYTHING_CHROME").is_err() {
        let p = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
        if std::path::Path::new(p).exists() {
            unsafe { std::env::set_var("API_ANYTHING_CHROME", p) };
        }
    }
    api_anything::browser::chrome_available()
}

fn skip() {
    eprintln!("Google Chrome not installed: skipped");
}

/// `newHome()`: a fresh home with its `sites` dir, set for the process.
fn new_home() -> Home {
    let h = Home::new();
    std::fs::create_dir_all(h.path().join("sites")).unwrap();
    h
}

fn re(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

/* ---------------------------------------------------------- the test site */

/// The TS file's `httpServer` plus its `upgrade` handler, on a raw socket: pages, the JSON endpoint,
/// and a WebSocket that counts the text frames it receives.
struct Site {
    url: String,
    ws_messages: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Site {
    async fn start() -> Site {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ws_messages = Arc::new(AtomicUsize::new(0));
        let counter = ws_messages.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { break };
                tokio::spawn(serve(sock, counter.clone()));
            }
        });
        Site { url: format!("http://127.0.0.1:{port}"), ws_messages, task }
    }
    fn ws_messages(&self) -> usize {
        self.ws_messages.load(Ordering::SeqCst)
    }
    fn close(&self) {
        self.task.abort();
    }
}

fn page(body: &str, status: u16) -> (u16, Vec<(String, String)>, String) {
    (
        status,
        vec![("content-type".into(), "text/html; charset=utf-8".into())],
        format!("<!doctype html><html><head><meta charset=\"utf-8\"><title>t</title></head><body>{body}</body></html>"),
    )
}

fn route(path: &str, query: &HashMap<String, String>, cookie: &str) -> (u16, Vec<(String, String)>, String) {
    match path {
        "/pop" => page(r#"<button id="popupws" onclick="window.open('/chat2')">chat</button>"#, 200),
        "/chat2" => {
            page(r#"<script>const ws=new WebSocket("ws://"+location.host+"/ws");ws.onopen=()=>ws.send("a private message")</script>"#, 200)
        }
        "/hotels" => {
            // AWS WAF-style interstitial that takes a while to solve, then reloads with its token cookie
            let delay = query.get("delay").map(|s| s.as_str()).unwrap_or("2500");
            if !re("aws-waf-token=ok").is_match(cookie) {
                return (
                    202,
                    vec![("content-type".into(), "text/html".into())],
                    format!(
                        r#"<!doctype html><html><head><title></title><script>window.awsWafCookieDomainList=['127.0.0.1'];window.gokuProps={{"key":"k"}};</script><script>setTimeout(()=>{{document.cookie="aws-waf-token=ok; path=/";location.reload()}},{delay})</script></head><body></body></html>"#
                    ),
                );
            }
            page(
                &format!(
                    r#"<div class="card">{} hotel</div><script>fetch("/api/list")</script>"#,
                    query.get("q").map(|s| s.as_str()).unwrap_or("null")
                ),
                200,
            )
        }
        "/api/list" => (200, vec![("content-type".into(), "application/json".into())], r#"{"items":[1,2]}"#.into()),
        _ => (404, vec![], String::new()),
    }
}

async fn serve(mut sock: tokio::net::TcpStream, ws_messages: Arc<AtomicUsize>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // one request per connection: the response says Connection: close
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let Ok(n) = sock.read(&mut chunk).await else { return };
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split(' ');
        let _method = parts.next().unwrap_or("GET");
        let target = parts.next().unwrap_or("/");
        let headers: HashMap<String, String> =
            lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())).collect();
        let (path, query_text) = target.split_once('?').unwrap_or((target, ""));
        let query: HashMap<String, String> =
            url::form_urlencoded::parse(query_text.as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        if headers.get("upgrade").map(|u| u.eq_ignore_ascii_case("websocket")).unwrap_or(false) {
            let key = headers.get("sec-websocket-key").cloned().unwrap_or_default();
            let accept = base64::engine::general_purpose::STANDARD
                .encode(sha1::Sha1::digest(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()));
            if sock.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await.is_err() {
                return;
            }
            // what the TS handler counts: each chunk whose first byte is a text frame's
            loop {
                let Ok(n) = sock.read(&mut chunk).await else { return };
                if n == 0 {
                    return;
                }
                if chunk[0] & 0x0f == 1 {
                    ws_messages.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        let length: usize = headers.get("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
        while buf.len() < head_end + length {
            let Ok(n) = sock.read(&mut chunk).await else { return };
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let (status, extra, body) = route(path, &query, headers.get("cookie").map(|s| s.as_str()).unwrap_or(""));
        let mut out = format!(
            "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            if status == 200 { "OK" } else { "Status" },
            body.len()
        );
        for (k, v) in extra {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        out.push_str(&body);
        let _ = sock.write_all(out.as_bytes()).await;
        let _ = sock.shutdown().await;
        return;
    }
}

/* ------------------------------------------------------------ 5, 6: browser */

#[test]
fn capture_write_a_web_socket_message_sent_from_a_popup_the_steps_open_never_reaches_the_server() {
    RT.block_on(async {
        let _s = SERIAL.lock().await;
        if !chrome() {
            return skip();
        }
        let server = Site::start().await;
        let url = server.url.clone();
        let _home = new_home();
        let steps: Vec<api_anything::types::TriggerStep> =
            serde_json::from_value(json!([{ "action": "click", "selector": "#popupws" }, { "action": "wait", "ms": 1500 }])).unwrap();
        capture_page(CapturePageOptions {
            url: format!("{url}/pop"),
            steps: Some(steps.clone()),
            soft_from: None,
            write: true,
            args: None,
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(server.ws_messages(), 0, "the popup's message was sent while learning a write");
        // control: without --write the same page does send it (the fixture works)
        capture_page(CapturePageOptions { url: format!("{url}/pop"), steps: Some(steps), soft_from: None, write: false, args: None })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(server.ws_messages(), 1);
        close_browser().await;
        server.close();
    })
}

#[test]
fn every_saved_capture_prunes_the_directory_so_a_library_caller_no_cli_never_piles_them_up() {
    RT.block_on(async {
        let _s = SERIAL.lock().await;
        if !chrome() {
            return skip();
        }
        let server = Site::start().await;
        let url = server.url.clone();
        let home = new_home();
        let dir = home.path().join("captures");
        std::fs::create_dir_all(&dir).unwrap();
        let stale = std::time::SystemTime::now() - Duration::from_secs(25 * 3600);
        for i in 0..3 {
            let f = dir.join(format!("cold{i}.json"));
            std::fs::write(&f, "{}").unwrap();
            std::fs::File::options().write(true).open(&f).unwrap().set_modified(stale).unwrap();
        }
        let c = capture_page(CapturePageOptions { url: format!("{url}/pop"), steps: None, soft_from: None, write: false, args: None })
            .await
            .unwrap();
        let mut names: Vec<String> =
            std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, [format!("{}.json", c.id)]);
        close_browser().await;
        server.close();
    })
}

#[test]
fn a_run_waits_out_a_js_challenge_that_reloads_after_a_couple_of_seconds_instead_of_ending_on_the_interstitial() {
    RT.block_on(async {
        let _s = SERIAL.lock().await;
        if !chrome() {
            return skip();
        }
        let server = Site::start().await;
        let url = server.url.clone();
        let _home = new_home();
        let mut o = TriggerOptions::new(&format!("{url}/hotels?q=Madrid&delay=2500"), &profile_dir());
        o.matcher = Some(Arc::new(|e| e.request.url.contains("/hotels")));
        let with_match = run_trigger(o).await.unwrap();
        let docs: Vec<_> = with_match.exchanges.iter().filter(|e| e.request.url.contains("/hotels") && e.response.is_some()).collect();
        assert_eq!(
            docs.last().and_then(|d| d.status()),
            Some(200),
            "documents: {}",
            docs.iter().map(|d| d.status().map(|s| s.to_string()).unwrap_or_default()).collect::<Vec<_>>().join(",")
        );
        assert!(re("Madrid hotel").is_match(docs.last().map(|d| d.body()).unwrap_or("")));
        let _home = new_home(); // a fresh profile: challenged again
        let plain = run_trigger(TriggerOptions::new(&format!("{url}/hotels?q=Porto&delay=3000"), &profile_dir())).await.unwrap();
        assert!(
            plain.exchanges.iter().any(|e| e.request.url.ends_with("/api/list") && e.status() == Some(200)),
            "the real page's data request was captured"
        );
        close_browser().await;
        server.close();
    })
}
