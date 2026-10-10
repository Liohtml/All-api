//! A small Chrome DevTools Protocol client: launch Chrome, speak JSON with it over a pipe (or a
//! WebSocket), match replies to requests, and hand events to whoever subscribed.
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Debug)]
pub struct Event {
    pub session_id: Option<String>,
    pub method: String,
    pub params: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Filter {
    All,
    /// events of the browser itself (no session)
    Browser,
    Session(String),
}

struct Subscriber {
    filter: Filter,
    tx: mpsc::UnboundedSender<Event>,
}

struct Shared {
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>,
    subscribers: Mutex<Vec<Subscriber>>,
    closed: AtomicBool,
}

/// One connection to a browser. Clone it freely: every clone speaks over the same transport.
#[derive(Clone)]
pub struct Cdp {
    tx: mpsc::UnboundedSender<String>,
    shared: Arc<Shared>,
    next_id: Arc<AtomicU64>,
}

impl Cdp {
    /// A client over any transport: `tx` carries outgoing messages, `rx` yields incoming ones.
    fn from_channels(tx: mpsc::UnboundedSender<String>, mut rx: mpsc::UnboundedReceiver<String>) -> Cdp {
        let shared = Arc::new(Shared { pending: Mutex::new(HashMap::new()), subscribers: Mutex::new(Vec::new()), closed: AtomicBool::new(false) });
        let s2 = shared.clone();
        tokio::spawn(async move {
            while let Some(text) = rx.recv().await {
                let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
                if let Some(id) = v.get("id").and_then(|i| i.as_u64()) {
                    let waiter = s2.pending.lock().unwrap().remove(&id);
                    if let Some(w) = waiter {
                        let out = match v.get("error") {
                            Some(e) => Err(anyhow!("{}", e.get("message").and_then(|m| m.as_str()).unwrap_or("CDP error"))),
                            None => Ok(v.get("result").cloned().unwrap_or(Value::Null)),
                        };
                        let _ = w.send(out);
                    }
                } else if let Some(method) = v.get("method").and_then(|m| m.as_str()) {
                    let ev = Event {
                        session_id: v.get("sessionId").and_then(|s| s.as_str()).map(|s| s.to_string()),
                        method: method.to_string(),
                        params: v.get("params").cloned().unwrap_or(Value::Null),
                    };
                    let mut subs = s2.subscribers.lock().unwrap();
                    subs.retain(|s| {
                        let wants = match &s.filter {
                            Filter::All => true,
                            Filter::Browser => ev.session_id.is_none(),
                            Filter::Session(id) => ev.session_id.as_deref() == Some(id.as_str()),
                        };
                        if wants { s.tx.send(ev.clone()).is_ok() } else { !s.tx.is_closed() }
                    });
                }
            }
            s2.closed.store(true, Ordering::SeqCst);
            let waiters: Vec<_> = s2.pending.lock().unwrap().drain().collect();
            for (_, w) in waiters {
                let _ = w.send(Err(anyhow!("the browser connection closed")));
            }
            s2.subscribers.lock().unwrap().clear();
        });
        Cdp { tx, shared, next_id: Arc::new(AtomicU64::new(1)) }
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// Send a command on a session (None: the browser itself) and wait for its result.
    pub async fn send(&self, session: Option<&str>, method: &str, params: Value) -> Result<Value> {
        if self.is_closed() {
            bail!("the browser connection closed");
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().unwrap().insert(id, tx);
        let mut msg = json!({ "id": id, "method": method, "params": params });
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        if self.tx.send(msg.to_string()).is_err() {
            self.shared.pending.lock().unwrap().remove(&id);
            bail!("the browser connection closed");
        }
        match tokio::time::timeout(Duration::from_secs(60), rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => bail!("the browser connection closed"),
            Err(_) => {
                self.shared.pending.lock().unwrap().remove(&id);
                bail!("{method} got no answer from the browser in 60 s")
            }
        }
    }

    pub fn subscribe(&self, filter: Filter) -> mpsc::UnboundedReceiver<Event> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.shared.subscribers.lock().unwrap().push(Subscriber { filter, tx });
        rx
    }
}

/* ----------------------------------------------------------------- launch */

const LOCKED: &str = "ProcessSingleton|already in use|SingletonLock|profile appears to be in use";

/// Another process holds api-anything's Chrome profile.
#[derive(Debug)]
pub struct ProfileInUse(pub PathBuf);

impl std::fmt::Display for ProfileInUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the api-anything Chrome profile is in use by another process (an MCP server or another api-anything command): {}",
            self.0.display()
        )
    }
}
impl std::error::Error for ProfileInUse {}

/// The installed Chrome: `API_ANYTHING_CHROME`, else the paths the Chrome installer uses.
pub fn chrome_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("API_ANYTHING_CHROME") {
        if !p.is_empty() {
            let path = PathBuf::from(p);
            return if path.exists() { Some(path) } else { None };
        }
    }
    let candidates: Vec<PathBuf> = if cfg!(target_os = "macos") {
        vec![PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")]
    } else if cfg!(target_os = "windows") {
        ["LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"]
            .iter()
            .filter_map(|k| std::env::var(k).ok())
            .map(|d| Path::new(&d).join("Google").join("Chrome").join("Application").join("chrome.exe"))
            .collect()
    } else {
        vec![PathBuf::from("/opt/google/chrome/chrome")]
    };
    candidates.into_iter().find(|p| p.exists())
}

pub struct Launched {
    pub cdp: Cdp,
    pub child: Child,
}

fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Start Chrome on a persistent profile and connect to it. Waits up to `lock_wait` for a profile
/// another process holds, then fails with `ProfileInUse`.
pub async fn launch(profile_dir: &Path, headless: bool, lock_wait: Duration) -> Result<Launched> {
    let bin = chrome_path().ok_or_else(|| anyhow!("Google Chrome is not installed"))?;
    std::fs::create_dir_all(profile_dir)?;
    let deadline = tokio::time::Instant::now() + lock_wait;
    let locked = regex::Regex::new(LOCKED).unwrap();
    loop {
        match launch_once(&bin, profile_dir, headless).await {
            Ok(l) => return Ok(l),
            Err(e) => {
                if !locked.is_match(&e.to_string()) {
                    return Err(e);
                }
                if tokio::time::Instant::now() > deadline {
                    return Err(ProfileInUse(profile_dir.to_path_buf()).into());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

fn chrome_command(bin: &Path, profile_dir: &Path, headless: bool) -> Command {
    let mut cmd = Command::new(bin);
    cmd.arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-background-networking")
        .arg("--disable-background-timer-throttling")
        .arg("--disable-backgrounding-occluded-windows")
        .arg("--disable-renderer-backgrounding")
        .arg("--disable-breakpad")
        .arg("--disable-client-side-phishing-detection")
        .arg("--disable-component-update")
        .arg("--disable-default-apps")
        .arg("--disable-dev-shm-usage")
        .arg("--disable-extensions")
        .arg("--disable-hang-monitor")
        .arg("--disable-ipc-flooding-protection")
        .arg("--disable-popup-blocking")
        .arg("--disable-prompt-on-repost")
        .arg("--disable-sync")
        .arg("--disable-search-engine-choice-screen")
        .arg("--disable-features=Translate,HttpsUpgrades,PaintHolding,DestroyProfileOnBrowserClose,MediaRouter,DialMediaRouteProvider,GlobalMediaControls,AcceptCHFrame,AvoidUnnecessaryBeforeUnloadCheckSync")
        .arg("--disable-blink-features=AutomationControlled")
        .arg("--metrics-recording-only")
        .arg("--password-store=basic")
        .arg("--use-mock-keychain")
        .arg("--no-service-autorun")
        .arg("--force-color-profile=srgb")
        .arg("--allow-pre-commit-input")
        .arg("--unsafely-disable-devtools-self-xss-warnings");
    if headless {
        cmd.arg("--headless=new").arg("--hide-scrollbars").arg("--mute-audio");
    }
    if running_as_root() {
        cmd.arg("--no-sandbox");
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    cmd
}

/// Read Chrome's stderr until it reports a DevTools address (the WebSocket transport) or exits.
async fn stderr_until<F: Fn(&str) -> bool>(child: &mut Child, until: F) -> Result<Option<String>> {
    let stderr = child.stderr.take().expect("piped stderr");
    let mut lines = BufReader::new(stderr).lines();
    let mut log = String::new();
    let found = tokio::time::timeout(Duration::from_secs(30), async {
        while let Ok(Some(line)) = lines.next_line().await {
            if until(&line) {
                return Ok::<Option<String>, anyhow::Error>(Some(line));
            }
            log.push_str(&line);
            log.push('\n');
            if log.len() > 64_000 {
                log.drain(..32_000);
            }
        }
        Ok(None)
    })
    .await;
    // keep draining stderr so Chrome never blocks on a full pipe
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    match found {
        Ok(Ok(Some(l))) => Ok(Some(l)),
        Ok(Ok(None)) => bail!("Chrome exited before it listened for DevTools: {}", log.trim()),
        Ok(Err(e)) => Err(e),
        Err(_) => bail!("Chrome did not start within 30 s: {}", log.trim()),
    }
}

#[cfg(unix)]
async fn launch_once(bin: &Path, profile_dir: &Path, headless: bool) -> Result<Launched> {
    use std::os::fd::FromRawFd;
    // Chrome speaks CDP over fds 3 (it reads) and 4 (it writes), and exits when the pipe closes:
    // no port to race for, and no Chrome left behind when this process dies.
    let mut to_chrome = [0i32; 2];
    let mut from_chrome = [0i32; 2];
    unsafe {
        if libc::pipe2(to_chrome.as_mut_ptr(), libc::O_CLOEXEC) != 0 || libc::pipe2(from_chrome.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            bail!("could not create the DevTools pipes");
        }
    }
    let (child_read, parent_write) = (to_chrome[0], to_chrome[1]);
    let (parent_read, child_write) = (from_chrome[0], from_chrome[1]);
    let mut cmd = chrome_command(bin, profile_dir, headless);
    cmd.arg("--remote-debugging-pipe").arg("about:blank");
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(child_read, 3) < 0 || libc::dup2(child_write, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let spawned = cmd.spawn();
    unsafe {
        libc::close(child_read);
        libc::close(child_write);
    }
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            unsafe {
                libc::close(parent_read);
                libc::close(parent_write);
            }
            bail!("could not start Chrome ({}): {e}", bin.display());
        }
    };
    let writer = unsafe { std::fs::File::from_raw_fd(parent_write) };
    let reader = unsafe { std::fs::File::from_raw_fd(parent_read) };
    let mut writer = tokio::fs::File::from_std(writer);
    let reader = tokio::fs::File::from_std(reader);
    let (tx, mut out_rx) = mpsc::unbounded_channel::<String>();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            let mut bytes = m.into_bytes();
            bytes.push(0);
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let mut r = BufReader::new(reader);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match r.read_until(0, &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if buf.last() == Some(&0) {
                        buf.pop();
                    }
                    if in_tx.send(String::from_utf8_lossy(&buf).into_owned()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let cdp = Cdp::from_channels(tx, in_rx);
    // A profile another Chrome holds: this one exits with its complaint on stderr instead of answering.
    let version = tokio::time::timeout(Duration::from_secs(30), cdp.send(None, "Browser.getVersion", json!({}))).await;
    match version {
        Ok(Ok(_)) => {
            let stderr = child.stderr.take();
            if let Some(stderr) = stderr {
                let mut lines = BufReader::new(stderr).lines();
                tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
            }
            Ok(Launched { cdp, child })
        }
        _ => {
            let why = stderr_until(&mut child, |_| false).await.err().map(|e| e.to_string()).unwrap_or_default();
            let _ = child.kill().await;
            bail!("{}", if why.is_empty() { "Chrome did not answer over its DevTools pipe".to_string() } else { why })
        }
    }
}

#[cfg(not(unix))]
async fn launch_once(bin: &Path, profile_dir: &Path, headless: bool) -> Result<Launched> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let mut cmd = chrome_command(bin, profile_dir, headless);
    cmd.arg("--remote-debugging-port=0").arg("about:blank");
    let mut child = cmd.spawn().map_err(|e| anyhow!("could not start Chrome ({}): {e}", bin.display()))?;
    let line = stderr_until(&mut child, |l| l.contains("ws://")).await?.unwrap_or_default();
    let ws_url = line[line.find("ws://").unwrap_or(0)..].trim().to_string();
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.map_err(|e| anyhow!("could not connect to Chrome at {ws_url}: {e}"))?;
    let (mut sink, mut stream) = ws.split();
    let (tx, mut out_rx) = mpsc::unbounded_channel::<String>();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if sink.send(Message::Text(m.into())).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(Ok(m)) = stream.next().await {
            let text = match m {
                Message::Text(t) => t.to_string(),
                Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                _ => continue,
            };
            if in_tx.send(text).is_err() {
                break;
            }
        }
    });
    Ok(Launched { cdp: Cdp::from_channels(tx, in_rx), child })
}
