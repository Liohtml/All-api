//! The browser layer: the installed Chrome over the DevTools protocol, one persistent profile per
//! process. Produces raw Exchanges for the learner (tier 3 / create / heal) and runs tier-2 page fetches.
pub use crate::cdp::ProfileInUse;
use crate::cdp::{Cdp, Event, Filter, chrome_path, launch};
use crate::classify::{Observed, bot_wall};
use crate::session::site_of;
use crate::spec::Request as Hop;
use crate::types::{CaptureResult, Exchange, ExchangeResponse, Headers, SameSite, StepAction, StoredCookie, TriggerStep};
use crate::util::{now_ms, parse_url};
use anyhow::{Result, anyhow, bail};
use indexmap::IndexMap;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

// Chrome locks a profile to one process. A long-lived process (the MCP server) releases it after
// this much idle time, and a second process waits up to LOCK_WAIT_MS for it.
const IDLE_CLOSE_MS: u64 = 3_000;
const LOCK_WAIT_MS: u64 = 15_000;

/// Checked up front so callers can skip cleanly.
pub fn chrome_available() -> bool {
    chrome_path().is_some()
}

#[derive(Clone, Debug)]
pub struct Attached {
    pub target_id: String,
    pub session_id: String,
    pub opener_id: Option<String>,
    pub url: String,
}

#[derive(Default)]
struct BrowserInner {
    /// each open tab that another tab opened, with that tab (or, once it closed, the one that opened it)
    opener_of: HashMap<String, String>,
    /// page targets with a session, by target
    attached: HashMap<String, Attached>,
    /// targets no run and no caller has taken
    unclaimed: Vec<String>,
    /// target -> the run that owns it
    owners: HashMap<String, u64>,
    /// run -> where its popups are announced
    runs: HashMap<u64, mpsc::UnboundedSender<Attached>>,
    /// callers waiting for the target they just created
    waiters: HashMap<String, oneshot::Sender<Attached>>,
    /// told the id of every destroyed target
    destroyed: Vec<mpsc::UnboundedSender<String>>,
    origin_pages: HashMap<String, Arc<Page>>,
    /// a blank tab kept for the browser's life: Chrome ends its session (and drops session cookies)
    /// once the last tab closes, and Playwright's persistent context keeps its first page open
    keep_alive: Option<String>,
}

pub struct Browser {
    cdp: Cdp,
    child: Mutex<Option<tokio::process::Child>>,
    pub profile_dir: PathBuf,
    pub headless: bool,
    /// the headless build's user agent with HeadlessChrome replaced
    user_agent: Option<String>,
    inner: Mutex<BrowserInner>,
    /// one caller at a time between asking for a page and taking it, so two never take the same target
    creating: tokio::sync::Mutex<()>,
}

impl Browser {
    /// Runs the browser's own events: who attaches, who opened whom, who closed.
    fn watch(self: &Arc<Self>) {
        let me = Arc::downgrade(self);
        let mut rx = self.cdp.subscribe(Filter::Browser);
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                let Some(b) = me.upgrade() else { break };
                b.on_browser_event(ev).await;
            }
        });
    }

    async fn on_browser_event(self: &Arc<Self>, ev: Event) {
        let info = ev.params.get("targetInfo").cloned().unwrap_or(Value::Null);
        let target_id = info.get("targetId").and_then(|t| t.as_str()).map(|s| s.to_string());
        let opener = info.get("openerId").and_then(|t| t.as_str()).map(|s| s.to_string());
        match ev.method.as_str() {
            "Target.targetCreated" | "Target.targetInfoChanged" => {
                let mut inner = self.inner.lock().unwrap();
                if let (Some(t), Some(o)) = (&target_id, &opener) {
                    inner.opener_of.insert(t.clone(), o.clone());
                }
                // where the tab is now, not where it was when it attached (about:blank for one this process opened)
                if let (Some(t), Some(u)) = (&target_id, info.get("url").and_then(|u| u.as_str())) {
                    if let Some(a) = inner.attached.get_mut(t) {
                        a.url = u.to_string();
                    }
                }
            }
            "Target.attachedToTarget" => {
                let Some(t) = target_id else { return };
                let session = ev.params.get("sessionId").and_then(|s| s.as_str()).unwrap_or("").to_string();
                let kind = info.get("type").and_then(|s| s.as_str()).unwrap_or("");
                if kind != "page" {
                    let _ = self.cdp.send(Some(&session), "Runtime.runIfWaitingForDebugger", json!({})).await;
                    return;
                }
                let at = Attached {
                    target_id: t.clone(),
                    session_id: session.clone(),
                    opener_id: opener.clone(),
                    url: info.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string(),
                };
                let (waiter, run_tx) = {
                    let mut inner = self.inner.lock().unwrap();
                    if let Some(o) = &opener {
                        inner.opener_of.insert(t.clone(), o.clone());
                    }
                    inner.attached.insert(t.clone(), at.clone());
                    let waiter = inner.waiters.remove(&t);
                    let run_tx = if waiter.is_none() {
                        opener
                            .as_ref()
                            .and_then(|_| self_owner(&inner, &t))
                            .and_then(|run| inner.runs.get(&run).cloned().map(|tx| (run, tx)))
                    } else {
                        None
                    };
                    if waiter.is_none() && run_tx.is_none() && inner.keep_alive.as_deref() != Some(t.as_str()) {
                        inner.unclaimed.push(t.clone());
                    }
                    (waiter, run_tx)
                };
                if let Some(w) = waiter {
                    let _ = w.send(at);
                } else if let Some((run, tx)) = run_tx {
                    self.inner.lock().unwrap().owners.insert(t.clone(), run);
                    if tx.send(at).is_err() {
                        // the run is over: the popup runs free
                        let _ = self.cdp.send(Some(&session), "Runtime.runIfWaitingForDebugger", json!({})).await;
                    }
                } else {
                    let _ = self.cdp.send(Some(&session), "Runtime.runIfWaitingForDebugger", json!({})).await;
                }
            }
            "Target.targetDestroyed" => {
                let Some(t) = ev.params.get("targetId").and_then(|t| t.as_str()).map(|s| s.to_string()) else { return };
                let watchers: Vec<mpsc::UnboundedSender<String>> = {
                    let mut inner = self.inner.lock().unwrap();
                    let opener = inner.opener_of.remove(&t);
                    if let Some(o) = opener {
                        let kids: Vec<String> = inner.opener_of.iter().filter(|(_, by)| **by == t).map(|(id, _)| id.clone()).collect();
                        for k in kids {
                            inner.opener_of.insert(k, o.clone());
                        }
                    }
                    inner.attached.remove(&t);
                    inner.unclaimed.retain(|x| x != &t);
                    inner.owners.remove(&t);
                    inner.origin_pages.retain(|_, p| p.target_id != t);
                    inner.destroyed.retain(|w| !w.is_closed());
                    inner.destroyed.clone()
                };
                for w in watchers {
                    let _ = w.send(t.clone());
                }
            }
            _ => {}
        }
    }

    fn destroyed_events(&self) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.lock().unwrap().destroyed.push(tx);
        rx
    }

    /// A fresh page (about:blank), set up for capture. `run`: the run that owns it, so its popups go there too.
    pub async fn new_page(self: &Arc<Self>, run: Option<u64>) -> Result<Arc<Page>> {
        let _one = self.creating.lock().await;
        let reuse = {
            let mut inner = self.inner.lock().unwrap();
            let idx = inner
                .unclaimed
                .iter()
                .position(|t| inner.attached.get(t).map(|a| a.url == "about:blank" || a.url.is_empty()).unwrap_or(false));
            idx.map(|i| inner.unclaimed.remove(i)).and_then(|t| inner.attached.get(&t).cloned())
        };
        let at = match reuse {
            Some(a) => a,
            None => {
                let (tx, rx) = oneshot::channel();
                // its own window: a second tab in a window is a background tab, hidden to its page (headless too),
                // and a hidden page never goes hidden on unload, so what it sends then would be missed
                let created = self.cdp.send(None, "Target.createTarget", json!({ "url": "about:blank", "newWindow": true })).await?;
                let target_id = created.get("targetId").and_then(|t| t.as_str()).ok_or_else(|| anyhow!("no target id"))?.to_string();
                let already = {
                    let mut inner = self.inner.lock().unwrap();
                    inner.unclaimed.retain(|t| t != &target_id);
                    match inner.attached.get(&target_id).cloned() {
                        Some(a) => Some(a),
                        None => {
                            inner.waiters.insert(target_id.clone(), tx);
                            None
                        }
                    }
                };
                match already {
                    Some(a) => a,
                    None => tokio::time::timeout(Duration::from_secs(15), rx)
                        .await
                        .map_err(|_| anyhow!("the new page did not attach"))?
                        .map_err(|_| anyhow!("the new page did not attach"))?,
                }
            }
        };
        if let Some(r) = run {
            self.inner.lock().unwrap().owners.insert(at.target_id.clone(), r);
        }
        let page = new_page_on(self, &at);
        page.setup().await?;
        // A target this process created attaches paused (waitForDebuggerOnStart) and a navigation on it
        // never starts its request; a reused tab was let go on attach, and letting it go again is a no-op.
        page.resume().await;
        Ok(page)
    }

    /// Where a run's popups are announced; the run covers each before it runs.
    pub fn register_run(&self, run: u64) -> mpsc::UnboundedReceiver<Attached> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.lock().unwrap().runs.insert(run, tx);
        rx
    }

    pub fn unregister_run(&self, run: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.runs.remove(&run);
        inner.owners.retain(|_, r| *r != run);
    }

    /// A page for a popup the browser announced, set up like any other.
    pub fn adopt(self: &Arc<Self>, at: &Attached) -> Arc<Page> {
        // still held before its first navigation: the run covers it (`cover_popup`) and then resumes it
        new_page_on(self, at)
    }

    /// Open tabs a run's pages opened (through closed ones too) that are not among `held`.
    pub fn strays(&self, run: u64, held: &HashSet<String>) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        let mut kin: HashSet<String> = inner.owners.iter().filter(|(_, r)| **r == run).map(|(t, _)| t.clone()).collect();
        kin.extend(held.iter().cloned());
        loop {
            let n = kin.len();
            let more: Vec<String> = inner.opener_of.iter().filter(|(_, o)| kin.contains(*o)).map(|(id, _)| id.clone()).collect();
            kin.extend(more);
            if kin.len() == n {
                break;
            }
        }
        kin.into_iter().filter(|id| !held.contains(id) && inner.attached.contains_key(id)).collect()
    }

    /// The open pages (tabs) as the browser reported them, with their current URL.
    pub fn pages(&self) -> Vec<Attached> {
        self.inner.lock().unwrap().attached.values().cloned().collect()
    }

    /// How many tabs are on record as opened by another one; a closed tab leaves no record.
    pub fn opener_records(&self) -> usize {
        self.inner.lock().unwrap().opener_of.len()
    }

    pub async fn close_target(&self, target_id: &str) -> Result<()> {
        self.cdp.send(None, "Target.closeTarget", json!({ "targetId": target_id })).await?;
        Ok(())
    }

    pub async fn all_cookies(&self) -> Result<Vec<StoredCookie>> {
        let r = self.cdp.send(None, "Storage.getCookies", json!({})).await?;
        Ok(r.get("cookies").and_then(|c| c.as_array()).map(|a| a.iter().map(to_stored).collect()).unwrap_or_default())
    }

    async fn shutdown(&self) {
        let _ = tokio::time::timeout(Duration::from_secs(3), self.cdp.send(None, "Browser.close", json!({}))).await;
        let child = self.child.lock().unwrap().take();
        if let Some(mut c) = child {
            let _ = tokio::time::timeout(Duration::from_secs(5), c.wait()).await;
            let _ = c.start_kill();
        }
    }
}

fn self_owner(inner: &BrowserInner, target: &str) -> Option<u64> {
    let mut t = target.to_string();
    for _ in 0..32 {
        if let Some(run) = inner.owners.get(&t) {
            return Some(*run);
        }
        {
            let o = inner.opener_of.get(&t)?;
            t = o.clone()
        }
    }
    None
}

fn to_stored(c: &Value) -> StoredCookie {
    let s = |k: &str| c.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    StoredCookie {
        name: s("name"),
        value: s("value"),
        domain: s("domain"),
        path: s("path"),
        expires: c.get("expires").and_then(|v| v.as_f64()).unwrap_or(-1.0),
        http_only: c.get("httpOnly").and_then(|v| v.as_bool()).unwrap_or(false),
        secure: c.get("secure").and_then(|v| v.as_bool()).unwrap_or(false),
        same_site: match c.get("sameSite").and_then(|v| v.as_str()) {
            Some("Strict") => Some(SameSite::Strict),
            Some("Lax") => Some(SameSite::Lax),
            Some("None") => Some(SameSite::None),
            _ => None,
        },
    }
}

/* ------------------------------------------------------------------- page */

pub struct Page {
    browser: Arc<Browser>,
    pub target_id: String,
    pub session_id: String,
    main_frame: Mutex<String>,
    closed: AtomicBool,
    /// every request the page sent since it was opened, by request id, hop by hop, so a fetch can
    /// tell the redirect of a request the page itself sent earlier from its own
    requests: Mutex<HashMap<String, Vec<SentRequest>>>,
}

/// A request as the page sent it: (method, url, body).
type SentRequest = (String, String, Option<String>);

/// A page on an attached target, recording its requests from the start.
fn new_page_on(browser: &Arc<Browser>, at: &Attached) -> Arc<Page> {
    let page = Arc::new(Page {
        browser: browser.clone(),
        target_id: at.target_id.clone(),
        session_id: at.session_id.clone(),
        main_frame: Mutex::new(String::new()),
        closed: AtomicBool::new(false),
        requests: Mutex::new(HashMap::new()),
    });
    let mut rx = page.events();
    let weak = Arc::downgrade(&page);
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let Some(page) = weak.upgrade() else { break };
            if ev.method == "Network.requestWillBeSent" {
                let rid = ev.params.get("requestId").and_then(|r| r.as_str()).unwrap_or("").to_string();
                let req = ev.params.get("request").cloned().unwrap_or(Value::Null);
                page.requests.lock().unwrap().entry(rid).or_default().push((
                    req.get("method").and_then(|m| m.as_str()).unwrap_or("GET").to_string(),
                    req.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string(),
                    req.get("postData").and_then(|b| b.as_str()).map(|s| s.to_string()),
                ));
            }
        }
    });
    page
}

impl Page {
    pub async fn send(&self, method: &str, params: Value) -> Result<Value> {
        self.browser.cdp.send(Some(&self.session_id), method, params).await
    }

    pub fn events(&self) -> mpsc::UnboundedReceiver<Event> {
        self.browser.cdp.subscribe(Filter::Session(self.session_id.clone()))
    }

    pub fn main_frame(&self) -> String {
        self.main_frame.lock().unwrap().clone()
    }

    /// What a page of a run has enabled: (method, params, required).
    fn enables(&self) -> Vec<(&'static str, Value, bool)> {
        let mut v = vec![
            ("Page.enable", json!({}), true),
            ("Page.setLifecycleEventsEnabled", json!({ "enabled": true }), true),
            ("Network.enable", json!({ "maxPostDataSize": 16 * 1024 * 1024 }), true),
            // A service worker's fetches bypass interception and hide requests from capture.
            ("Network.setBypassServiceWorker", json!({ "bypass": true }), false),
            ("Runtime.enable", json!({}), true),
        ];
        if let Some(ua) = &self.browser.user_agent {
            v.push(("Emulation.setUserAgentOverride", json!({ "userAgent": ua }), false));
        }
        v
    }

    async fn setup(&self) -> Result<()> {
        for (method, params, required) in self.enables() {
            let r = self.send(method, params).await;
            if required {
                r?;
            }
        }
        self.read_frame_tree().await
    }

    async fn read_frame_tree(&self) -> Result<()> {
        let tree = self.send("Page.getFrameTree", json!({})).await?;
        if let Some(id) = tree.pointer("/frameTree/frame/id").and_then(|v| v.as_str()) {
            *self.main_frame.lock().unwrap() = id.to_string();
        }
        Ok(())
    }

    /// A popup is held before its first navigation, and its renderer answers nothing until it is
    /// resumed; the browser's half of each enable applies as soon as it is sent. So the enables are
    /// sent now and answered later (`finish_setup`, once the page runs).
    fn setup_in_background(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<Result<Value>>> {
        self.enables()
            .into_iter()
            .map(|(method, params, _)| {
                let me = self.clone();
                tokio::spawn(async move { me.send(method, params).await })
            })
            .collect()
    }

    async fn finish_setup(&self, pending: Vec<tokio::task::JoinHandle<Result<Value>>>) -> Result<()> {
        for p in pending {
            let _ = tokio::time::timeout(Duration::from_millis(10_000), p).await;
        }
        self.read_frame_tree().await
    }

    /// Let a page that was paused at its first navigation go.
    pub async fn resume(&self) {
        let _ = self.send("Runtime.runIfWaitingForDebugger", json!({})).await;
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || !self.browser.inner.lock().unwrap().attached.contains_key(&self.target_id)
    }

    /// Load `url` and wait for DOMContentLoaded (a download, or an aborted navigation, counts as loaded).
    pub async fn navigate(&self, url: &str, referer: Option<&str>, timeout: Duration) -> Result<()> {
        let mut rx = self.events();
        let mut params = json!({ "url": url });
        if let Some(r) = referer {
            params["referrer"] = json!(r);
        }
        let r = self.send("Page.navigate", params).await?;
        if let Some(err) = r.get("errorText").and_then(|e| e.as_str()) {
            if err.contains("ERR_ABORTED") {
                return Ok(());
            }
            bail!("page.goto: {err} at {url}");
        }
        let mut loader = r.get("loaderId").and_then(|l| l.as_str()).unwrap_or("").to_string();
        let frame = self.main_frame();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                bail!("page.goto: Timeout {} ms exceeded loading {url}", timeout.as_millis());
            }
            let Ok(Some(ev)) = tokio::time::timeout(left, rx.recv()).await else {
                bail!("page.goto: Timeout {} ms exceeded loading {url}", timeout.as_millis())
            };
            if ev.method == "Page.lifecycleEvent" {
                let name = ev.params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let f = ev.params.get("frameId").and_then(|n| n.as_str()).unwrap_or("");
                let l = ev.params.get("loaderId").and_then(|n| n.as_str()).unwrap_or("");
                // A document a script replaces before it has loaded (a challenge's location.replace) never
                // fires its own DOMContentLoaded: the one that replaces it is the page that loaded.
                if name == "init" && f == frame && !loader.is_empty() && !l.is_empty() && l != loader {
                    loader = l.to_string();
                }
                if (name == "DOMContentLoaded" || name == "load") && f == frame && (loader.is_empty() || l == loader) {
                    return Ok(());
                }
            }
            if ev.method == "Page.domContentEventFired" && loader.is_empty() {
                return Ok(());
            }
            if ev.method == "Inspector.targetCrashed" {
                bail!("page.goto: the page crashed");
            }
        }
    }

    /// Run JavaScript in the page and return its value (a promise is awaited).
    pub async fn evaluate(&self, expression: &str) -> Result<Value> {
        let r = self.send("Runtime.evaluate", json!({ "expression": expression, "awaitPromise": true, "returnByValue": true })).await?;
        if let Some(ex) = r.get("exceptionDetails") {
            let text = ex
                .pointer("/exception/description")
                .and_then(|d| d.as_str())
                .or_else(|| ex.get("text").and_then(|t| t.as_str()))
                .unwrap_or("evaluation failed");
            bail!("{text}");
        }
        Ok(r.pointer("/result/value").cloned().unwrap_or(Value::Null))
    }

    /// Where the page is; a renderer that does not answer (hung) is given a few seconds, then the browser's word is taken.
    pub async fn url(&self) -> String {
        match tokio::time::timeout(Duration::from_millis(5000), self.evaluate("location.href")).await {
            Ok(Ok(Value::String(s))) => s,
            _ => self.browser.inner.lock().unwrap().attached.get(&self.target_id).map(|a| a.url.clone()).unwrap_or_default(),
        }
    }

    pub async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        self.browser.close_target(&self.target_id).await
    }

    /// Poll for a selector, up to `timeout`.
    async fn wait_for_selector(&self, selector: &str, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let found = self.evaluate(&format!("!!document.querySelector({})", json!(selector))).await.unwrap_or(Value::Bool(false));
            if found == Value::Bool(true) {
                return Ok(());
            }
            if tokio::time::Instant::now() > deadline {
                bail!("waiting for selector \"{selector}\" timed out after {} ms", timeout.as_millis());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn click(&self, selector: &str, timeout: Duration) -> Result<()> {
        self.wait_for_selector(selector, timeout).await?;
        let rect = self
            .evaluate(&format!(
                "(() => {{ const el = document.querySelector({}); el.scrollIntoView({{block: 'center', inline: 'center'}}); const r = el.getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2, r.width, r.height]; }})()",
                json!(selector)
            ))
            .await?;
        let x = rect.get(0).and_then(|v| v.as_f64()).unwrap_or(0.0);
        let y = rect.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0);
        let w = rect.get(2).and_then(|v| v.as_f64()).unwrap_or(0.0);
        if w <= 0.0 {
            // not rendered (display:none): the DOM's own click still runs the handlers
            self.evaluate(&format!("document.querySelector({}).click()", json!(selector))).await?;
            return Ok(());
        }
        self.send("Input.dispatchMouseEvent", json!({ "type": "mouseMoved", "x": x, "y": y })).await?;
        self.send("Input.dispatchMouseEvent", json!({ "type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1 })).await?;
        self.send("Input.dispatchMouseEvent", json!({ "type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1 }))
            .await?;
        Ok(())
    }

    async fn fill(&self, selector: &str, value: &str, timeout: Duration) -> Result<()> {
        self.wait_for_selector(selector, timeout).await?;
        self.evaluate(&format!(
            "(() => {{ const el = document.querySelector({}); el.focus(); if ('value' in el) {{ el.value = ''; }} else {{ el.textContent = ''; }} }})()",
            json!(selector)
        ))
        .await?;
        self.send("Input.insertText", json!({ "text": value })).await?;
        Ok(())
    }

    async fn press(&self, selector: Option<&str>, key: &str, timeout: Duration) -> Result<()> {
        if let Some(sel) = selector {
            self.wait_for_selector(sel, timeout).await?;
            self.evaluate(&format!("document.querySelector({}).focus()", json!(sel))).await?;
        }
        let (code, vk, text): (&str, u32, Option<String>) = match key {
            "Enter" => ("Enter", 13, Some("\r".to_string())),
            "Tab" => ("Tab", 9, None),
            "Escape" => ("Escape", 27, None),
            "Backspace" => ("Backspace", 8, None),
            "Delete" => ("Delete", 46, None),
            "ArrowDown" => ("ArrowDown", 40, None),
            "ArrowUp" => ("ArrowUp", 38, None),
            "ArrowLeft" => ("ArrowLeft", 37, None),
            "ArrowRight" => ("ArrowRight", 39, None),
            "Space" | " " => ("Space", 32, Some(" ".to_string())),
            k if k.chars().count() == 1 => ("", k.to_uppercase().chars().next().unwrap() as u32, Some(k.to_string())),
            k => (k, 0, None),
        };
        let mut down =
            json!({ "type": if text.is_some() { "keyDown" } else { "rawKeyDown" }, "key": key, "code": code, "windowsVirtualKeyCode": vk });
        if let Some(t) = &text {
            down["text"] = json!(t);
            down["unmodifiedText"] = json!(t);
        }
        self.send("Input.dispatchKeyEvent", down).await?;
        self.send("Input.dispatchKeyEvent", json!({ "type": "keyUp", "key": key, "code": code, "windowsVirtualKeyCode": vk })).await?;
        Ok(())
    }
}

/* -------------------------------------------------------- shared instance */

struct Global {
    current: Option<Arc<Browser>>,
    users: usize,
    idle_gen: u64,
}

static GLOBAL: LazyLock<Mutex<Global>> = LazyLock::new(|| Mutex::new(Global { current: None, users: 0, idle_gen: 0 }));
static LAUNCHING: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

/// Marks the browser busy; dropping it releases it (and starts the idle clock).
pub struct Hold(());

pub fn hold() -> Hold {
    let mut g = GLOBAL.lock().unwrap();
    g.users += 1;
    g.idle_gen += 1;
    Hold(())
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut g = GLOBAL.lock().unwrap();
        g.users = g.users.saturating_sub(1);
        if g.users == 0 {
            g.idle_gen += 1;
            let generation = g.idle_gen;
            drop(g);
            if let Ok(h) = tokio::runtime::Handle::try_current() {
                h.spawn(async move {
                    tokio::time::sleep(Duration::from_millis(IDLE_CLOSE_MS)).await;
                    let still = {
                        let g = GLOBAL.lock().unwrap();
                        g.users == 0 && g.idle_gen == generation
                    };
                    if still {
                        close_browser().await;
                    }
                });
            }
        }
    }
}

/// The process-wide browser on `profile_dir`. A different profile or headless mode closes the old one first.
pub async fn open_browser(profile_dir: &Path, headless: bool) -> Result<Arc<Browser>> {
    let _guard = LAUNCHING.lock().await;
    let current = GLOBAL.lock().unwrap().current.clone();
    if let Some(b) = current {
        if b.profile_dir == profile_dir && b.headless == headless && !b.cdp.is_closed() {
            return Ok(b);
        }
        GLOBAL.lock().unwrap().current = None;
        b.shutdown().await;
    }
    let launched = launch(profile_dir, headless, Duration::from_millis(LOCK_WAIT_MS)).await?;
    let cdp = launched.cdp.clone();
    let version = cdp.send(None, "Browser.getVersion", json!({})).await?;
    let ua = version.get("userAgent").and_then(|u| u.as_str()).unwrap_or("");
    // Default headless UA says "HeadlessChrome/<v>" and some sites answer 403 to it.
    let user_agent = if headless && ua.contains("HeadlessChrome") { Some(ua.replace("HeadlessChrome", "Chrome")) } else { None };
    let browser = Arc::new(Browser {
        cdp: cdp.clone(),
        child: Mutex::new(Some(launched.child)),
        profile_dir: profile_dir.to_path_buf(),
        headless,
        user_agent,
        inner: Mutex::new(BrowserInner::default()),
        creating: tokio::sync::Mutex::new(()),
    });
    browser.watch();
    cdp.send(None, "Target.setDiscoverTargets", json!({ "discover": true })).await?;
    cdp.send(
        None,
        "Target.setAutoAttach",
        json!({ "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true, "filter": [{ "type": "page", "exclude": false }, { "exclude": true }] }),
    )
    .await?;
    if headless {
        let kept = cdp.send(None, "Target.createTarget", json!({ "url": "about:blank" })).await?;
        if let Some(id) = kept.get("targetId").and_then(|t| t.as_str()) {
            let mut inner = browser.inner.lock().unwrap();
            inner.keep_alive = Some(id.to_string());
            inner.unclaimed.retain(|t| t != id);
        }
    }
    GLOBAL.lock().unwrap().current = Some(browser.clone());
    Ok(browser)
}

/// Close the shared browser. Call it before a normal exit.
pub async fn close_browser() {
    let b = GLOBAL.lock().unwrap().current.take();
    if let Some(b) = b {
        b.inner.lock().unwrap().origin_pages.clear();
        b.shutdown().await;
    }
}

pub fn site_cookies(cookies: &[StoredCookie], url: &str) -> Vec<StoredCookie> {
    let Some(u) = parse_url(url) else { return vec![] };
    let site = site_of(u.host_str().unwrap_or(""));
    cookies
        .iter()
        .filter(|c| {
            let d = c.domain.trim_start_matches('.');
            d == site || d.ends_with(&format!(".{site}"))
        })
        .cloned()
        .collect()
}

/// The profile's current cookies for url's site: the cheap auth refresh, no page load.
pub async fn profile_cookies(url: &str, profile_dir: &Path) -> Result<Vec<StoredCookie>> {
    let _h = hold();
    let b = open_browser(profile_dir, true).await?;
    Ok(site_cookies(&b.all_cookies().await?, url))
}

/// Put imported cookies into api-anything's own Chrome profile, so tier 2/3 and heals are logged in too.
pub async fn add_cookies_to_profile(cookies: &[StoredCookie], profile_dir: &Path) -> Result<()> {
    if cookies.is_empty() {
        return Ok(());
    }
    let _h = hold();
    let b = open_browser(profile_dir, true).await?;
    let list: Vec<Value> = cookies
        .iter()
        .map(|c| {
            let mut v = json!({ "name": c.name, "value": c.value, "domain": c.domain, "path": if c.path.is_empty() { "/" } else { &c.path }, "httpOnly": c.http_only, "secure": c.secure });
            if c.expires > 0.0 {
                v["expires"] = json!(c.expires);
            }
            if let Some(s) = c.same_site {
                v["sameSite"] = json!(match s { SameSite::Strict => "Strict", SameSite::Lax => "Lax", SameSite::None => "None" });
            }
            v
        })
        .collect();
    // through a page: at the browser level, with no browser context named, Chrome stores nothing
    let page = b.new_page(None).await?;
    let r = page.send("Storage.setCookies", json!({ "cookies": list })).await;
    let _ = page.close().await;
    r?;
    Ok(())
}

/// Clear one site's cookies from the profile: any host under the registrable domain.
pub async fn clear_profile_cookies(site: &str, profile_dir: &Path) -> Result<()> {
    let _h = hold();
    let b = open_browser(profile_dir, true).await?;
    let all = b.all_cookies().await?;
    let mine: Vec<&StoredCookie> = all
        .iter()
        .filter(|c| {
            let d = c.domain.trim_start_matches('.');
            d == site || d.ends_with(&format!(".{site}"))
        })
        .collect();
    if mine.is_empty() {
        return Ok(());
    }
    let page = b.new_page(None).await?;
    for c in mine {
        let _ = page.send("Network.deleteCookies", json!({ "name": c.name, "domain": c.domain, "path": c.path })).await;
    }
    let _ = page.close().await;
    Ok(())
}

/* ---------------------------------------------------------------- capture */

/// Decides what a guarded run's pages may send: `acting` is true once the page has loaded and the
/// steps run (false again while a bot challenge's interstitial is up); `via` is the request a
/// redirect hop's chain started from. A WebSocket message is asked as resourceType "websocket".
pub type Intercept = Arc<dyn Fn(&Exchange, bool, Option<&Exchange>) -> bool + Send + Sync>;
pub type Matcher = Arc<dyn Fn(&Exchange) -> bool + Send + Sync>;

pub struct TriggerOptions {
    pub url: String,
    pub steps: Option<Vec<TriggerStep>>,
    /// open this page first, then reach `url` by an in-app navigation so SPAs fire their XHRs
    pub soft_from: Option<String>,
    pub headless: bool,
    pub profile_dir: PathBuf,
    /// requests it matches are aborted before leaving the browser and recorded with aborted:true
    pub intercept: Option<Intercept>,
    /// the op's own request: the run ends soon after one answers
    pub matcher: Option<Matcher>,
    /// extra wait after the network first goes quiet (default 300)
    pub settle_ms: Option<u64>,
    /// overall budget; also the per-action timeout (default 30000)
    pub timeout_ms: Option<u64>,
}

impl TriggerOptions {
    pub fn new(url: &str, profile_dir: &Path) -> TriggerOptions {
        TriggerOptions {
            url: url.to_string(),
            steps: None,
            soft_from: None,
            headless: true,
            profile_dir: profile_dir.to_path_buf(),
            intercept: None,
            matcher: None,
            settle_ms: None,
            timeout_ms: None,
        }
    }
}

// Binary resources: their bodies are never useful to the learner and are not valid UTF-8. A stream's never ends.
const NO_BODY: [&str; 6] = ["image", "media", "font", "stylesheet", "eventsource", "websocket"];
const QUIET_MS: f64 = 500.0;
// Streams never finish; a request open this long is a long poll or a hung tracker, not the data.
const LONG_LIVED: [&str; 2] = ["eventsource", "websocket"];
const LONG_MS: f64 = 3000.0;
// An endpoint hit more often than this is polling or a beacon: its repeats are not "still loading".
const REPEATS: u32 = 2;
// Pages that fetch their data a moment after load (deferred hydration): how long to wait for a first XHR.
const FIRST_XHR_MS: u64 = 2000;
// With an op's match: how long a quiet page may go without firing it before the run gives up on it.
const MATCH_GRACE_MS: f64 = 3000.0;
// How long a bot challenge's interstitial may take to solve itself and load the real page.
const CHALLENGE_WAIT_MS: u64 = 15_000;
// How long a page gets to be emptied, and then to close, before the run ends without waiting for it.
const SEAL_MS: u64 = 5000;
// The path of the beacon a page being emptied sends last from pagehide: the old document is through.
const SEAL_MARK: &str = "/__api_anything_sealed__";

fn lower_headers(v: Option<&Value>) -> Headers {
    let mut out = Headers::new();
    if let Some(Value::Object(o)) = v {
        for (k, x) in o {
            if let Some(s) = x.as_str() {
                out.insert(k.to_lowercase(), s.to_string());
            }
        }
    }
    out
}

fn resource_type(v: Option<&Value>) -> String {
    v.and_then(|t| t.as_str()).unwrap_or("other").to_lowercase()
}

#[derive(Default)]
struct Cap {
    exchanges: Vec<Exchange>,
    /// requestId -> the exchange of its current hop
    by_req: HashMap<String, usize>,
    /// requestId -> every hop's exchange, in order
    hops: HashMap<String, Vec<usize>>,
    extra_req_applied: HashMap<String, usize>,
    extra_req_stash: HashMap<String, Vec<Headers>>,
    extra_res_stash: HashMap<String, Headers>,
    /// requests the guard stopped before the network reported them, by network id: recorded from the
    /// pause itself (a popup's first navigation, a beacon a leaving page sends), filled in if the report comes
    aborted_ids: HashMap<String, usize>,
    /// chains whose redirect hop the guard stopped, by network id: the page is told nothing of that
    /// redirect, its status included, so the chain's first request keeps no response
    stopped_hops: HashSet<String>,
    /// the request each chain of redirects started from, by network id, as it was paused
    chains: HashMap<String, Exchange>,
    pending: HashMap<String, f64>,
    hits: HashMap<String, u32>,
    last_activity: f64,
    /// top-level documents of the run's first page, in order
    docs: Vec<usize>,
    /// exchanges whose body is still being read
    body_pending: HashSet<usize>,
    /// every URL the first page's main frame had, history API changes included
    locations: Vec<String>,
    acting: bool,
    sealed: bool,
    /// pages whose last document has unloaded under the seal (their SEAL_MARK beacon came)
    sealed_marks: HashSet<String>,
    /// requests the guard has been asked about and not answered yet
    deciding: usize,
}

struct Run {
    id: u64,
    browser: Arc<Browser>,
    cap: Mutex<Cap>,
    intercept: Option<Intercept>,
    deadline: tokio::time::Instant,
    pages: Mutex<Vec<Arc<Page>>>,
    held: Mutex<HashSet<String>>,
}

impl Run {
    fn walled(cap: &Cap) -> bool {
        let Some(&d) = cap.docs.last() else { return false };
        let ex = &cap.exchanges[d];
        let Some(r) = &ex.response else { return false };
        bot_wall(
            &Observed { status: r.status, headers: r.headers.clone(), body: r.body.clone().unwrap_or_default(), url: None },
            false,
            None,
        )
        .is_some()
    }

    /// `walled`, once the latest document's body is in (bounded: a stuck read is not a wall)
    async fn walled_now(&self) -> bool {
        let end = tokio::time::Instant::now() + Duration::from_millis(3000);
        loop {
            let (ready, w) = {
                let cap = self.cap.lock().unwrap();
                match cap.docs.last() {
                    Some(&d) => {
                        let ex = &cap.exchanges[d];
                        (ex.response.is_some() && !cap.body_pending.contains(&d), Self::walled(&cap))
                    }
                    None => (true, false),
                }
            };
            if ready || tokio::time::Instant::now() > end {
                return w;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    // A JS challenge solves itself by POSTing a proof, then reloads: while it is on screen, the steps are not acting yet.
    async fn acting_now(&self) -> bool {
        let acting = self.cap.lock().unwrap().acting;
        acting && !self.walled_now().await
    }

    fn quiet(cap: &Cap) -> bool {
        let now = now_ms();
        !cap.pending.values().any(|t| now - t < LONG_MS) && now - cap.last_activity >= QUIET_MS
    }

    async fn idle(&self, cap_ms: u64) {
        let end = self.deadline.min(tokio::time::Instant::now() + Duration::from_millis(cap_ms));
        while tokio::time::Instant::now() < end && !Self::quiet(&self.cap.lock().unwrap()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn answered(&self, m: &Matcher) -> bool {
        self.cap.lock().unwrap().exchanges.iter().any(|e| m(e) && (e.response.is_some() || e.aborted))
    }

    fn has_xhr(&self) -> bool {
        self.cap.lock().unwrap().exchanges.iter().any(|e| e.resource_type == "xhr" || e.resource_type == "fetch")
    }

    async fn wait_for_data(&self, matcher: Option<&Matcher>, settle_ms: u64, timeout_ms: u64) {
        if let Some(m) = matcher {
            // The op's own request answering is the signal; then a short settle.
            // A page quiet for a few seconds without it is not going to send it (a login wall, a 404 page).
            while tokio::time::Instant::now() < self.deadline
                && !self.answered(m)
                && !{
                    let cap = self.cap.lock().unwrap();
                    Self::quiet(&cap) && now_ms() - cap.last_activity > MATCH_GRACE_MS
                }
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            tokio::time::sleep(Duration::from_millis(settle_ms)).await;
            self.idle(3000).await;
            return;
        }
        self.idle(timeout_ms).await;
        tokio::time::sleep(Duration::from_millis(settle_ms)).await;
        self.idle(timeout_ms).await;
        if !self.has_xhr() {
            let end = self.deadline.min(tokio::time::Instant::now() + Duration::from_millis(FIRST_XHR_MS));
            while tokio::time::Instant::now() < end && !self.has_xhr() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            self.idle(timeout_ms).await;
        }
    }

    /// Wait (bounded) for a challenge interstitial to solve itself; true when a real document replaced it.
    async fn outwait(&self) -> bool {
        if !self.walled_now().await {
            return false;
        }
        let end = self.deadline.min(tokio::time::Instant::now() + Duration::from_millis(CHALLENGE_WAIT_MS));
        let seen = self.cap.lock().unwrap().docs.len();
        loop {
            let (more, walled) = {
                let cap = self.cap.lock().unwrap();
                let latest_ready = cap.docs.last().map(|d| cap.exchanges[*d].response.is_some()).unwrap_or(false);
                (cap.docs.len() > seen && latest_ready, Self::walled(&cap))
            };
            if tokio::time::Instant::now() >= end || (more && !walled) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let cap = self.cap.lock().unwrap();
        cap.docs.len() > seen && !Self::walled(&cap)
    }

    /// The guard's verdict on one paused request; what it stops is recorded as aborted.
    async fn decide(self: &Arc<Self>, ex: Exchange, network_id: Option<String>, via: Option<Exchange>) -> bool {
        let Some(intercept) = &self.intercept else { return false };
        let sealed = self.cap.lock().unwrap().sealed;
        let acting = if sealed { self.cap.lock().unwrap().acting } else { self.acting_now().await };
        let stop = intercept(&ex, acting, via.as_ref());
        // Once sealed everything is stopped, but only what the guard itself stops joins the capture:
        // a write a page sends as it leaves can be learned, the rest of a closing page's traffic is noise.
        if stop {
            let mut cap = self.cap.lock().unwrap();
            if let (true, Some(n)) = (via.is_some(), network_id.as_ref()) {
                cap.stopped_hops.insert(n.clone());
                if let Some(&first) = cap.hops.get(n).and_then(|h| h.first()) {
                    cap.exchanges[first].response = None;
                }
            }
            // A pause that names no network id (a deferred fetchLater) may still be a request the
            // network reported: the latest unanswered one of its method and URL.
            let reported = network_id.as_ref().map(|n| cap.by_req.get(n).copied()).unwrap_or_else(|| {
                cap.exchanges.iter().rposition(|e| {
                    !e.aborted && e.response.is_none() && e.request.method == ex.request.method && e.request.url == ex.request.url
                })
            });
            match reported {
                Some(idx) => cap.exchanges[idx].aborted = true,
                None => {
                    let id = cap.exchanges.len() as u64 + 1;
                    cap.exchanges.push(Exchange { id, aborted: true, ..ex });
                    if let Some(n) = &network_id {
                        let idx = cap.exchanges.len() - 1;
                        cap.aborted_ids.insert(n.clone(), idx);
                    }
                }
            }
        }
        stop || sealed
    }
}

/// Attach the guard to a page: the WebSocket drop script and request interception.
const WS_DROP: &str = "(()=>{try{WebSocket.prototype.send=function(){};}catch(e){}})()";

/// Whether the guard drops WebSocket messages: a chat "send" goes over an open socket, where no HTTP interception sees it.
fn drops_sockets(run: &Run) -> bool {
    let Some(intercept) = &run.intercept else { return false };
    let probe = Exchange {
        id: 0,
        resource_type: "websocket".into(),
        request: Hop { method: "SEND".into(), url: String::new(), headers: Headers::new(), body: None },
        response: None,
        aborted: false,
    };
    intercept(&probe, false, None) && intercept(&probe, true, None)
}

async fn cover(run: &Arc<Run>, page: &Arc<Page>) -> Result<()> {
    if run.intercept.is_some() {
        if drops_sockets(run) {
            let _ = page.send("Page.addScriptToEvaluateOnNewDocument", json!({ "source": WS_DROP })).await;
            let _ = page.evaluate(WS_DROP).await;
        }
        page.send("Fetch.enable", json!({ "patterns": [{ "urlPattern": "*" }] })).await?;
    }
    Ok(())
}

/// A popup is covered while the browser still holds its first navigation: request interception is
/// the browser's and answers at once, the socket script is queued for its first document, and the
/// enables are left pending until the page runs. Then it is resumed, and watched from before that.
async fn cover_popup(run: &Arc<Run>, page: &Arc<Page>) -> Result<()> {
    let pending = page.setup_in_background();
    if run.intercept.is_some() {
        page.send("Fetch.enable", json!({ "patterns": [{ "urlPattern": "*" }] })).await?;
        if drops_sockets(run) {
            let p = page.clone();
            tokio::spawn(async move { p.send("Page.addScriptToEvaluateOnNewDocument", json!({ "source": WS_DROP })).await });
        }
    }
    watch_page(run.clone(), page.clone(), false);
    page.resume().await;
    page.finish_setup(pending).await?;
    if drops_sockets(run) {
        let _ = page.evaluate(WS_DROP).await;
    }
    Ok(())
}

async fn read_body(run: Arc<Run>, page: Arc<Page>, rid: String, idx: usize) {
    let r = tokio::time::timeout(Duration::from_secs(20), page.send("Network.getResponseBody", json!({ "requestId": rid }))).await;
    let body = match r {
        Ok(Ok(v)) => {
            let text = v.get("body").and_then(|b| b.as_str()).unwrap_or("").to_string();
            if v.get("base64Encoded").and_then(|b| b.as_bool()).unwrap_or(false) {
                Some(String::from_utf8_lossy(&crate::util::b64_decode_lenient(text.as_bytes())).into_owned())
            } else {
                Some(text)
            }
        }
        _ => None,
    };
    let mut cap = run.cap.lock().unwrap();
    if let Some(r) = cap.exchanges[idx].response.as_mut() {
        r.body = body;
    }
    cap.body_pending.remove(&idx);
}

/// The request body as the server gets it: a gzip/deflate/br-encoded body decoded.
fn decode_post(entries: Option<&Value>, encoding: &str, fallback: Option<String>) -> Option<String> {
    let bytes: Option<Vec<u8>> = entries.and_then(|e| e.as_array()).map(|a| {
        a.iter().flat_map(|x| crate::util::b64_decode_lenient(x.get("bytes").and_then(|b| b.as_str()).unwrap_or("").as_bytes())).collect()
    });
    let enc = encoding.to_lowercase();
    if let (Some(b), false) = (&bytes, enc.is_empty()) {
        use std::io::Read;
        let mut out = Vec::new();
        let ok = if enc.contains("gzip") {
            flate2::read::GzDecoder::new(&b[..]).read_to_end(&mut out).is_ok()
        } else if enc.contains("br") {
            brotli::Decompressor::new(&b[..], 4096).read_to_end(&mut out).is_ok()
        } else {
            flate2::read::ZlibDecoder::new(&b[..]).read_to_end(&mut out).is_ok()
                || flate2::read::DeflateDecoder::new(&b[..]).read_to_end(&mut out).is_ok()
        };
        if ok && !out.is_empty() {
            return Some(String::from_utf8_lossy(&out).into_owned());
        }
    }
    fallback.or_else(|| bytes.map(|b| String::from_utf8_lossy(&b).into_owned()))
}

/// One page's events into the run's capture: requests, responses, bodies, navigations and the guard.
fn watch_page(run: Arc<Run>, page: Arc<Page>, first: bool) {
    let mut rx = page.events();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let p = &ev.params;
            let rid = p.get("requestId").and_then(|r| r.as_str()).unwrap_or("").to_string();
            match ev.method.as_str() {
                "Network.requestWillBeSent" => {
                    let req = p.get("request").cloned().unwrap_or(Value::Null);
                    let now = now_ms();
                    let mut cap = run.cap.lock().unwrap();
                    if let Some(redirect) = p.get("redirectResponse") {
                        if let Some(&idx) = cap.by_req.get(&rid) {
                            if cap.exchanges[idx].response.is_none() && !cap.stopped_hops.contains(&rid) {
                                let headers = lower_headers(redirect.get("headers"));
                                let ct = headers.get("content-type").cloned().unwrap_or_default();
                                cap.exchanges[idx].response = Some(ExchangeResponse {
                                    status: redirect.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16,
                                    headers,
                                    body: None,
                                    content_type: ct,
                                });
                            }
                        }
                    }
                    let url = format!(
                        "{}{}",
                        req.get("url").and_then(|u| u.as_str()).unwrap_or(""),
                        req.get("urlFragment").and_then(|u| u.as_str()).unwrap_or("")
                    );
                    let headers = lower_headers(req.get("headers"));
                    let encoding = headers.get("content-encoding").cloned().unwrap_or_default();
                    let body = decode_post(
                        req.get("postDataEntries"),
                        &encoding,
                        req.get("postData").and_then(|b| b.as_str()).map(|s| s.to_string()),
                    );
                    let kind = resource_type(p.get("type"));
                    let request = Hop {
                        method: req.get("method").and_then(|m| m.as_str()).unwrap_or("GET").to_string(),
                        url: url.clone(),
                        headers,
                        body,
                    };
                    let idx = match cap.aborted_ids.remove(&rid) {
                        // the guard recorded it from the pause: this is the same request, fully reported
                        Some(idx) => {
                            let e = &mut cap.exchanges[idx];
                            e.resource_type = kind.clone();
                            e.request = request;
                            idx
                        }
                        None => {
                            let id = cap.exchanges.len() as u64 + 1;
                            cap.exchanges.push(Exchange { id, resource_type: kind.clone(), request, response: None, aborted: false });
                            cap.exchanges.len() - 1
                        }
                    };
                    cap.by_req.insert(rid.clone(), idx);
                    cap.hops.entry(rid.clone()).or_default().push(idx);
                    // headers as sent on the wire (cookie included) may have been reported already
                    let applied = *cap.extra_req_applied.get(&rid).unwrap_or(&0);
                    let hops = cap.hops.get(&rid).cloned().unwrap_or_default();
                    let mut stash = cap.extra_req_stash.remove(&rid).unwrap_or_default();
                    let mut applied_now = applied;
                    while !stash.is_empty() && hops.len() > applied_now {
                        let h = stash.remove(0);
                        let target = hops[applied_now];
                        for (k, v) in h {
                            cap.exchanges[target].request.headers.insert(k, v);
                        }
                        applied_now += 1;
                    }
                    if !stash.is_empty() {
                        cap.extra_req_stash.insert(rid.clone(), stash);
                    }
                    cap.extra_req_applied.insert(rid.clone(), applied_now);
                    let is_doc = kind == "document" && p.get("frameId").and_then(|f| f.as_str()) == Some(page.main_frame().as_str());
                    if first && is_doc {
                        cap.docs.push(idx);
                        // A challenge's verify POST, cut off by the reload it triggered, would hold "quiet" and the body reads.
                        cap.pending.retain(|r, _| r == &rid);
                    }
                    let endpoint = match parse_url(&url) {
                        Some(u) => format!("{} {}{}", cap.exchanges[idx].request.method, crate::util::origin_of(&u), u.path()),
                        None => format!("{} {url}", cap.exchanges[idx].request.method),
                    };
                    let n = cap.hits.get(&endpoint).copied().unwrap_or(0) + 1;
                    cap.hits.insert(endpoint, n);
                    if !LONG_LIVED.contains(&kind.as_str()) && n <= REPEATS {
                        cap.pending.insert(rid.clone(), now);
                        cap.last_activity = now;
                    }
                    let fetch_post =
                        req.get("hasPostData").and_then(|b| b.as_bool()).unwrap_or(false) && cap.exchanges[idx].request.body.is_none();
                    drop(cap);
                    if fetch_post {
                        let run2 = run.clone();
                        let page2 = page.clone();
                        let rid2 = rid.clone();
                        tokio::spawn(async move {
                            if let Ok(v) = page2.send("Network.getRequestPostData", json!({ "requestId": rid2 })).await {
                                if let Some(b) = v.get("postData").and_then(|b| b.as_str()) {
                                    let mut cap = run2.cap.lock().unwrap();
                                    cap.exchanges[idx].request.body = Some(b.to_string());
                                }
                            }
                        });
                    }
                }
                "Network.requestWillBeSentExtraInfo" => {
                    let headers = lower_headers(p.get("headers"));
                    let mut cap = run.cap.lock().unwrap();
                    let applied = *cap.extra_req_applied.get(&rid).unwrap_or(&0);
                    let hops = cap.hops.get(&rid).cloned().unwrap_or_default();
                    if hops.len() > applied {
                        let target = hops[applied];
                        for (k, v) in headers {
                            cap.exchanges[target].request.headers.insert(k, v);
                        }
                        cap.extra_req_applied.insert(rid.clone(), applied + 1);
                    } else {
                        cap.extra_req_stash.entry(rid.clone()).or_default().push(headers);
                    }
                }
                "Network.responseReceived" => {
                    let res = p.get("response").cloned().unwrap_or(Value::Null);
                    let mut cap = run.cap.lock().unwrap();
                    let Some(&idx) = cap.by_req.get(&rid) else { continue };
                    let mut headers = lower_headers(res.get("headers"));
                    if let Some(extra) = cap.extra_res_stash.remove(&rid) {
                        for (k, v) in extra {
                            headers.insert(k, v);
                        }
                    }
                    let ct = headers
                        .get("content-type")
                        .cloned()
                        .unwrap_or_else(|| res.get("mimeType").and_then(|m| m.as_str()).unwrap_or("").to_string());
                    let status = res.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
                    cap.exchanges[idx].response = Some(ExchangeResponse { status, headers, body: None, content_type: ct });
                    let kind = cap.exchanges[idx].resource_type.clone();
                    if !NO_BODY.contains(&kind.as_str()) {
                        cap.body_pending.insert(idx);
                    }
                }
                "Network.responseReceivedExtraInfo" => {
                    let headers = lower_headers(p.get("headers"));
                    let mut cap = run.cap.lock().unwrap();
                    match cap.by_req.get(&rid).copied().filter(|i| cap.exchanges[*i].response.is_some()) {
                        Some(idx) => {
                            if let Some(r) = cap.exchanges[idx].response.as_mut() {
                                for (k, v) in headers {
                                    r.headers.insert(k, v);
                                }
                            }
                        }
                        None => {
                            cap.extra_res_stash.insert(rid.clone(), headers);
                        }
                    }
                }
                "Network.loadingFinished" => {
                    let (idx, pending) = {
                        let mut cap = run.cap.lock().unwrap();
                        if cap.pending.remove(&rid).is_some() {
                            cap.last_activity = now_ms();
                        }
                        let idx = cap.by_req.get(&rid).copied();
                        (idx, idx.map(|i| cap.body_pending.contains(&i)).unwrap_or(false))
                    };
                    if let (Some(idx), true) = (idx, pending) {
                        tokio::spawn(read_body(run.clone(), page.clone(), rid.clone(), idx));
                    }
                }
                "Network.loadingFailed" => {
                    let mut cap = run.cap.lock().unwrap();
                    if cap.pending.remove(&rid).is_some() {
                        cap.last_activity = now_ms();
                    }
                    if let Some(&idx) = cap.by_req.get(&rid) {
                        cap.body_pending.remove(&idx);
                    }
                }
                "Page.frameNavigated" => {
                    if first {
                        let frame = p.get("frame").cloned().unwrap_or(Value::Null);
                        if frame.get("id").and_then(|i| i.as_str()) == Some(page.main_frame().as_str()) {
                            if let Some(u) = frame.get("url").and_then(|u| u.as_str()) {
                                let mut cap = run.cap.lock().unwrap();
                                if cap.locations.last().map(|l| l != u).unwrap_or(true) {
                                    cap.locations.push(u.to_string());
                                }
                            }
                        }
                    }
                }
                "Page.navigatedWithinDocument" => {
                    if first && p.get("frameId").and_then(|i| i.as_str()) == Some(page.main_frame().as_str()) {
                        if let Some(u) = p.get("url").and_then(|u| u.as_str()) {
                            let mut cap = run.cap.lock().unwrap();
                            if cap.locations.last().map(|l| l != u).unwrap_or(true) {
                                cap.locations.push(u.to_string());
                            }
                        }
                    }
                }
                "Fetch.requestPaused" => {
                    let req = p.get("request").cloned().unwrap_or(Value::Null);
                    if req.get("url").and_then(|u| u.as_str()).map(|u| u.contains(SEAL_MARK)).unwrap_or(false) {
                        run.cap.lock().unwrap().sealed_marks.insert(page.target_id.clone());
                        let page2 = page.clone();
                        let fetch_id = rid.clone();
                        tokio::spawn(async move {
                            let _ = page2.send("Fetch.failRequest", json!({ "requestId": fetch_id, "errorReason": "Aborted" })).await;
                        });
                        continue;
                    }
                    let ex = Exchange {
                        id: 0,
                        resource_type: resource_type(p.get("resourceType")),
                        request: Hop {
                            method: req.get("method").and_then(|m| m.as_str()).unwrap_or("GET").to_string(),
                            url: format!(
                                "{}{}",
                                req.get("url").and_then(|u| u.as_str()).unwrap_or(""),
                                req.get("urlFragment").and_then(|u| u.as_str()).unwrap_or("")
                            ),
                            headers: lower_headers(req.get("headers")),
                            body: req.get("postData").and_then(|b| b.as_str()).map(|s| s.to_string()),
                        },
                        response: None,
                        aborted: false,
                    };
                    let fetch_id = rid.clone();
                    let network_id = p.get("networkId").and_then(|n| n.as_str()).map(|s| s.to_string());
                    // A hop goes on under its request's network id. Chrome marks it with redirectedRequestId, but
                    // not a cross-origin fetch's: the id seen paused before is what tells it.
                    let via = {
                        let mut cap = run.cap.lock().unwrap();
                        match &network_id {
                            Some(n) => match cap.chains.get(n) {
                                Some(first) => Some(first.clone()),
                                None => {
                                    cap.chains.insert(n.clone(), ex.clone());
                                    None
                                }
                            },
                            None => None,
                        }
                    };
                    run.cap.lock().unwrap().deciding += 1;
                    let run2 = run.clone();
                    let page2 = page.clone();
                    tokio::spawn(async move {
                        let stop = run2.decide(ex, network_id, via).await;
                        let _ = if stop {
                            page2.send("Fetch.failRequest", json!({ "requestId": fetch_id, "errorReason": "Aborted" })).await
                        } else {
                            page2.send("Fetch.continueRequest", json!({ "requestId": fetch_id })).await
                        };
                        run2.cap.lock().unwrap().deciding -= 1;
                    });
                }
                _ => {}
            }
        }
    });
}

async fn within<T>(fut: impl std::future::Future<Output = Result<T>>, ms: u64) -> Option<T> {
    match tokio::time::timeout(Duration::from_millis(ms), fut).await {
        Ok(Ok(v)) => Some(v),
        _ => None,
    }
}

async fn run_step(page: &Page, s: &TriggerStep, timeout: Duration) -> Result<()> {
    let need = |v: &Option<String>, what: &str| -> Result<String> {
        v.clone().filter(|x| !x.is_empty()).ok_or_else(|| anyhow!("trigger step \"{}\" needs {what}", s.action.name()))
    };
    match s.action {
        StepAction::Click => page.click(&need(&s.selector, "a selector")?, timeout).await,
        StepAction::Fill => page.fill(&need(&s.selector, "a selector")?, s.value.as_deref().unwrap_or(""), timeout).await,
        StepAction::Press => page.press(s.selector.as_deref().filter(|x| !x.is_empty()), &need(&s.value, "a key")?, timeout).await,
        StepAction::Wait => {
            if let Some(sel) = s.selector.as_deref().filter(|x| !x.is_empty()) {
                page.wait_for_selector(sel, timeout).await
            } else {
                tokio::time::sleep(Duration::from_millis(s.ms.unwrap_or(1000.0).max(0.0) as u64)).await;
                Ok(())
            }
        }
        StepAction::Goto => {
            let url = s
                .value
                .clone()
                .or_else(|| s.selector.clone())
                .filter(|x| !x.is_empty())
                .ok_or_else(|| anyhow!("trigger step \"goto\" needs a url in value"))?;
            page.navigate(&url, None, timeout).await
        }
    }
}

/// Load the trigger in the browser and return every exchange it caused, with bodies and cookies.
pub async fn run_trigger(o: TriggerOptions) -> Result<CaptureResult> {
    let timeout_ms = o.timeout_ms.unwrap_or(30_000);
    let timeout = Duration::from_millis(timeout_ms);
    let _h = hold();
    let browser = open_browser(&o.profile_dir, o.headless).await?;
    let run_id = NEXT_RUN.fetch_add(1, Ordering::SeqCst);
    let mut popups = browser.register_run(run_id);
    let page = match browser.new_page(Some(run_id)).await {
        Ok(p) => p,
        Err(e) => {
            browser.unregister_run(run_id);
            return Err(e);
        }
    };
    let run = Arc::new(Run {
        id: run_id,
        browser: browser.clone(),
        cap: Mutex::new(Cap { last_activity: now_ms(), ..Cap::default() }),
        intercept: o.intercept.clone(),
        deadline: tokio::time::Instant::now() + timeout,
        pages: Mutex::new(vec![page.clone()]),
        held: Mutex::new(HashSet::from([page.target_id.clone()])),
    });
    // This run's pages: its own and any popup they open, covered before their first navigation.
    let popup_run = run.clone();
    let popup_task = tokio::spawn(async move {
        while let Some(at) = popups.recv().await {
            let p = popup_run.browser.adopt(&at);
            popup_run.pages.lock().unwrap().push(p.clone());
            popup_run.held.lock().unwrap().insert(p.target_id.clone());
            if cover_popup(&popup_run, &p).await.is_err() {
                p.resume().await;
            }
        }
    });
    let mut result = run_inner(&run, &page, &o, timeout).await;
    // The pages are closed before the guards are lifted: an open page still sends.
    let _gone = close_pages(&run).await;
    // what a page sent as it was emptied (a pagehide beacon, stopped and recorded) belongs to the capture too
    if let Ok(r) = &mut result {
        r.exchanges = run.cap.lock().unwrap().exchanges.clone();
    }
    popup_task.abort();
    browser.unregister_run(run_id);
    result
}

async fn run_inner(run: &Arc<Run>, page: &Arc<Page>, o: &TriggerOptions, timeout: Duration) -> Result<CaptureResult> {
    // in place before the first document, so that what it defers (fetchLater) passes through it
    cover(run, page).await.map_err(|e| anyhow!("could not attach the request guard to the page: {e}"))?;
    watch_page(run.clone(), page.clone(), true);
    let settle = o.settle_ms.unwrap_or(300);
    if let Some(from) = &o.soft_from {
        page.navigate(from, None, timeout).await?;
        run.idle(5000).await;
        let from_url = page.url().await;
        let before = run.cap.lock().unwrap().exchanges.len();
        // A link the app rendered goes through its router; otherwise the history API plus popstate,
        // which client routers listen to. An injected <a> would not be routed.
        let routing = format!(
            "(() => {{ const u = {}; const link = [...document.querySelectorAll('a[href]')].find(a => a.href === u && (!a.target || a.target === '_self')); if (link) return link.click(); try {{ history.pushState({{}}, '', u); dispatchEvent(new PopStateEvent('popstate', {{ state: {{}} }})); }} catch (e) {{}} }})()",
            json!(o.url)
        );
        let _ = within(page.evaluate(&routing), SEAL_MS).await;
        run.idle(5000).await;
        let routed =
            run.cap.lock().unwrap().exchanges[before..].iter().any(|e| ["xhr", "fetch", "document"].contains(&e.resource_type.as_str()));
        if !routed {
            page.navigate(&o.url, Some(&from_url), timeout).await?;
        }
    } else {
        page.navigate(&o.url, None, timeout).await?;
    }
    run.cap.lock().unwrap().acting = true;
    // steps typed into a challenge interstitial would time out on selectors the real page has
    if o.steps.as_ref().map(|s| !s.is_empty()).unwrap_or(false) {
        run.outwait().await;
    }
    for s in o.steps.iter().flatten() {
        run_step(page, s, timeout).await?;
    }
    run.wait_for_data(o.matcher.as_ref(), settle, timeout.as_millis() as u64).await;
    // A JS challenge solves itself and reloads, often after a second or more: wait (bounded) for a real document.
    if run.outwait().await {
        run.wait_for_data(o.matcher.as_ref(), settle, timeout.as_millis() as u64).await;
    }
    // Bodies still arriving get a short grace, not the whole budget: a hung long poll is not the data.
    let grace = run.deadline.min(tokio::time::Instant::now() + Duration::from_millis(5000));
    while tokio::time::Instant::now() < grace && !run.cap.lock().unwrap().body_pending.is_empty() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Tokens an SPA keeps in web storage (not the jar); learning turns a request repeating one into a session: ref.
    let storage_v = within(
        page.evaluate("Object.fromEntries([localStorage, sessionStorage].flatMap(s => Object.keys(s).map(k => [k, s.getItem(k) ?? ''])).filter(([, v]) => v.length <= 16384))"),
        SEAL_MS,
    )
    .await
    .unwrap_or(Value::Null);
    let mut storage: IndexMap<String, String> = IndexMap::new();
    if let Value::Object(o) = storage_v {
        for (k, v) in o {
            if let Some(s) = v.as_str() {
                storage.insert(k, s.to_string());
            }
        }
    }
    let cookies = site_cookies(&run.browser.all_cookies().await.unwrap_or_default(), &o.url);
    let final_url = page.url().await;
    let cap = run.cap.lock().unwrap();
    Ok(CaptureResult {
        exchanges: cap.exchanges.clone(),
        cookies,
        final_url,
        storage: Some(storage),
        locations: Some(cap.locations.clone()),
    })
}

/// The end of a run: a guarded run's pages are emptied before they are closed, with the guards
/// still live, so what a page sends as it leaves fails; a tab the run opened but holds no page for
/// is closed through the browser. True when every page of the run is known to be closed.
async fn close_pages(run: &Arc<Run>) -> bool {
    if run.intercept.is_some() {
        run.cap.lock().unwrap().sealed = true;
        let mut emptied: HashSet<String> = HashSet::new();
        let end = tokio::time::Instant::now() + Duration::from_millis(3 * SEAL_MS);
        while tokio::time::Instant::now() < end {
            let fresh: Vec<Arc<Page>> =
                run.pages.lock().unwrap().iter().filter(|p| !emptied.contains(&p.target_id) && !p.is_closed()).cloned().collect();
            for p in &fresh {
                emptied.insert(p.target_id.clone());
                // A round trip through the new document, then through the browser: whatever the old
                // one sent as it unloaded has been paused and failed before either returns.
                // The new document commits before the old one has unloaded (its pagehide and
                // visibilitychange handlers run after, and may be slow): a beacon of our own, sent last as
                // the old document goes hidden (after pagehide), says when it is through. It never leaves the browser.
                let marked = within(
                    p.evaluate(&format!(
                        "(() => {{ const mark = () => {{ if (document.visibilityState !== 'hidden') return; try {{ navigator.sendBeacon(new URL({}, location.href).href, '') }} catch (e) {{}} }}; addEventListener('pagehide', mark); addEventListener('visibilitychange', mark); return 1 }})()",
                        json!(SEAL_MARK)
                    )),
                    SEAL_MS,
                )
                .await
                .is_some();
                if within(p.navigate("about:blank", None, Duration::from_millis(SEAL_MS)), SEAL_MS).await.is_some() {
                    let _ = within(p.evaluate("0"), SEAL_MS).await;
                }
                let wait = tokio::time::Instant::now() + Duration::from_millis(SEAL_MS);
                while marked && !run.cap.lock().unwrap().sealed_marks.contains(&p.target_id) && tokio::time::Instant::now() < wait {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let wait = tokio::time::Instant::now() + Duration::from_millis(SEAL_MS);
                while run.cap.lock().unwrap().deciding > 0 && tokio::time::Instant::now() < wait {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            let held = run.held.lock().unwrap().clone();
            let lost = run.browser.strays(run.id, &held);
            for id in &lost {
                let _ = within(run.browser.close_target(id), SEAL_MS).await;
            }
            if fresh.is_empty() && lost.is_empty() {
                break;
            }
            if !lost.is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    let pages: Vec<Arc<Page>> = run.pages.lock().unwrap().clone();
    for p in &pages {
        let _ = within(p.close(), SEAL_MS).await;
    }
    let held = run.held.lock().unwrap().clone();
    pages.iter().all(|p| p.is_closed()) && run.browser.strays(run.id, &held).is_empty()
}

/* ------------------------------------------------------------- page fetch */

#[derive(Clone, Debug)]
pub struct PageFetchResult {
    pub status: u16,
    pub headers: Headers,
    pub body: String,
    pub url: String,
    pub ms: u64,
    /// the first answer was a redirect
    pub redirected: bool,
}

pub type RedirectFn = Arc<dyn Fn(&Hop, u16, &str, usize) -> Result<Hop> + Send + Sync>;

pub struct PageFetchOptions {
    pub origin: String,
    pub url: String,
    pub method: String,
    pub headers: Headers,
    pub body: Option<String>,
    pub profile_dir: PathBuf,
    pub headless: bool,
    pub timeout_ms: Option<u64>,
    /// a read: when the origin page navigates mid-fetch, wait for it to load and fetch once more
    pub retry_on_navigation: bool,
    /// the request a redirect asks for next, or a refusal; without it the redirect itself is the answer
    pub redirect: Option<RedirectFn>,
}

struct HopAnswer {
    status: u16,
    headers: Headers,
    body: String,
    url: String,
    location: Option<String>,
}

/// A page on `origin` to fetch from: its root, or a blank stand-in when the root redirects elsewhere.
async fn origin_page(browser: &Arc<Browser>, origin: &str, left: Duration) -> Result<Arc<Page>> {
    // the guard is released before is_closed() takes the same lock
    let kept = browser.inner.lock().unwrap().origin_pages.get(origin).cloned();
    if let Some(p) = kept {
        if !p.is_closed() {
            return Ok(p);
        }
    }
    let page = browser.new_page(None).await?;
    let _ = page.navigate(origin, None, left).await;
    let here = crate::util::origin_str(&page.url().await).unwrap_or_default();
    if here != origin {
        // Same-origin is what matters for fetch(): serve a blank document at an unused path, never sent to the site.
        let blank = format!("{origin}/__api_anything_blank__");
        page.send("Fetch.enable", json!({ "patterns": [{ "urlPattern": blank.clone() }] })).await?;
        let p2 = page.clone();
        let mut rx = page.events();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                if ev.method == "Fetch.requestPaused" {
                    let rid = ev.params.get("requestId").and_then(|r| r.as_str()).unwrap_or("").to_string();
                    let _ = p2
                        .send(
                            "Fetch.fulfillRequest",
                            json!({ "requestId": rid, "responseCode": 200, "responseHeaders": [{ "name": "content-type", "value": "text/html" }], "body": crate::util::b64_encode(b"<!doctype html><title></title>") }),
                        )
                        .await;
                }
            }
        });
        page.navigate(&blank, None, left).await?;
    }
    browser.inner.lock().unwrap().origin_pages.insert(origin.to_string(), page.clone());
    Ok(page)
}

/// The redirect a page's manual fetch() got, read from what the browser saw of it: the page itself
/// is told nothing, not even the status.
/// a response the page's own fetch got: request id, URL, the id it was redirected from, status, headers
type Seen = Arc<Mutex<Vec<(String, String, Option<String>, u16, Headers)>>>;

async fn redirect_of(seen: &Seen, hop: &Hop, url: &str) -> Result<HopAnswer> {
    let bare = |u: &str| u.split('#').next().unwrap_or("").to_string();
    let mine = || -> Vec<(u16, Headers)> {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|(m, u, b, _, _)| m == &hop.method && bare(u) == bare(url) && b.clone().or_else(|| hop.body.clone()) == hop.body)
            .map(|(_, _, _, s, h)| (*s, h.clone()))
            .collect()
    };
    let end = tokio::time::Instant::now() + Duration::from_millis(1000);
    while mine().is_empty() && tokio::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The page's own copy of the request is answered at the same moment: its redirect may be reported
    // a few ms after the fetch resolved, so the answers are taken once no more arrive.
    let mut answers = mine();
    loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = mine();
        if now.len() == answers.len() || tokio::time::Instant::now() >= end {
            break;
        }
        answers = now;
    }
    let distinct: HashSet<String> =
        answers.iter().map(|(s, h)| format!("{s} {}", h.get("location").cloned().unwrap_or_default())).collect();
    if distinct.len() != 1 {
        let why = if answers.is_empty() {
            "its answer was not seen, so where it leads is unknown"
        } else {
            "the page sent the same request at the same time and their redirects differ, so this one's cannot be told apart"
        };
        bail!("not following a redirect from {}: {why}", crate::util::origin_str(url).unwrap_or_default());
    }
    let (status, headers) = answers[0].clone();
    let location = headers.get("location").cloned();
    Ok(HopAnswer { status, headers, body: String::new(), url: url.to_string(), location })
}

async fn fetch_once(page: &Arc<Page>, hop: &Hop, left: Duration, timeout_ms: u64) -> Result<HopAnswer> {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let mut rx = page.events();
    let seen2 = seen.clone();
    let page2 = page.clone();
    let watcher = tokio::spawn(async move {
        let mut requests: HashMap<String, SentRequest> = HashMap::new();
        // A request the page sent before this fetch (its own copy of the same one) is in the page's
        // record; the page records the hop after a redirect too, so the answered hop is found by its URL.
        let known = |requests: &HashMap<String, SentRequest>, rid: &str, url: &str| {
            requests.get(rid).cloned().or_else(|| {
                page2
                    .requests
                    .lock()
                    .unwrap()
                    .get(rid)
                    .and_then(|hops| hops.iter().rev().find(|(_, u, _)| u == url).or(hops.first()).cloned())
            })
        };
        while let Some(ev) = rx.recv().await {
            let rid = ev.params.get("requestId").and_then(|r| r.as_str()).unwrap_or("").to_string();
            match ev.method.as_str() {
                "Network.requestWillBeSent" => {
                    let req = ev.params.get("request").cloned().unwrap_or(Value::Null);
                    if let Some(redirect) = ev.params.get("redirectResponse") {
                        if let Some((m, u, b)) = known(&requests, &rid, redirect.get("url").and_then(|u| u.as_str()).unwrap_or("")) {
                            let status = redirect.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
                            if (300..400).contains(&status) {
                                seen2.lock().unwrap().push((m, u, b, status, lower_headers(redirect.get("headers"))));
                            }
                        }
                    }
                    requests.insert(
                        rid,
                        (
                            req.get("method").and_then(|m| m.as_str()).unwrap_or("GET").to_string(),
                            req.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string(),
                            req.get("postData").and_then(|b| b.as_str()).map(|s| s.to_string()),
                        ),
                    );
                }
                "Network.responseReceived" => {
                    let res = ev.params.get("response").cloned().unwrap_or(Value::Null);
                    let status = res.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
                    if (300..400).contains(&status) {
                        if let Some((m, u, b)) = known(&requests, &rid, res.get("url").and_then(|u| u.as_str()).unwrap_or("")) {
                            seen2.lock().unwrap().push((m, u, b, status, lower_headers(res.get("headers"))));
                        }
                    }
                }
                "Network.responseReceivedExtraInfo" => {
                    let headers = lower_headers(ev.params.get("headers"));
                    let mut s = seen2.lock().unwrap();
                    if let Some(last) = s.last_mut() {
                        if headers.contains_key("location") && !last.4.contains_key("location") {
                            for (k, v) in headers {
                                last.4.insert(k, v);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });
    let headers: serde_json::Map<String, Value> =
        hop.headers.iter().filter(|(k, _)| !k.starts_with(':')).map(|(k, v)| (k.clone(), json!(v))).collect();
    let script = format!(
        "(async () => {{ const r = await fetch({url}, {{ method: {method}, headers: {headers}, body: {body}, credentials: 'include', redirect: 'manual', signal: AbortSignal.timeout({left}) }}); if (r.type === 'opaqueredirect') return {{ opaque: true, url: r.url }}; const h = {{}}; r.headers.forEach((v, k) => {{ h[k] = v; }}); return {{ opaque: false, status: r.status, headers: h, body: await r.text(), url: r.url }}; }})()",
        url = json!(hop.url),
        method = json!(hop.method),
        headers = Value::Object(headers),
        body = match &hop.body {
            Some(b) => json!(b),
            None => Value::Null,
        },
        left = left.as_millis()
    );
    let r = tokio::time::timeout(left + Duration::from_millis(1000), page.evaluate(&script)).await;
    let out = match r {
        Err(_) => Err(anyhow!("no response within {timeout_ms} ms")),
        Ok(Err(e)) => {
            let m = e.to_string();
            if m.contains("TimeoutError") || m.to_lowercase().contains("timed out") {
                Err(anyhow!("no response within {timeout_ms} ms"))
            } else {
                Err(e)
            }
        }
        Ok(Ok(v)) => {
            if v.get("opaque") == Some(&Value::Bool(true)) {
                redirect_of(&seen, hop, v.get("url").and_then(|u| u.as_str()).unwrap_or(&hop.url)).await
            } else {
                Ok(HopAnswer {
                    status: v.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16,
                    headers: lower_headers(v.get("headers")),
                    body: v.get("body").and_then(|b| b.as_str()).unwrap_or("").to_string(),
                    url: v.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string(),
                    location: None,
                })
            }
        }
    };
    watcher.abort();
    out
}

/// Tier 2: fetch() from inside a page on the site origin, so TLS, cookies and sec-fetch are the browser's own.
pub async fn page_fetch(o: PageFetchOptions) -> Result<PageFetchResult> {
    let timeout_ms = o.timeout_ms.unwrap_or(30_000);
    let _h = hold();
    let browser = open_browser(&o.profile_dir, o.headless).await?;
    // One deadline for the whole call from here, with Chrome up.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let left = || deadline.saturating_duration_since(tokio::time::Instant::now()).max(Duration::from_millis(1));
    let mut page = origin_page(&browser, &o.origin, left()).await?;
    let body = if o.method == "GET" || o.method == "HEAD" { None } else { o.body.clone() };
    let mut hop = Hop { url: o.url.clone(), method: o.method.clone(), headers: o.headers.clone(), body };
    let t0 = now_ms();
    let mut redirected = false;
    let mut hops = 0usize;
    loop {
        let answer = match fetch_once(&page, &hop, left(), timeout_ms).await {
            Ok(a) => a,
            Err(e) => {
                let m = e.to_string();
                if !o.retry_on_navigation
                    || !(m.contains("Execution context was destroyed")
                        || m.to_lowercase().contains("navigat")
                        || m.contains("Cannot find context"))
                {
                    return Err(e);
                }
                // it may have landed on another origin (a challenge's redirect): start from a fresh page on ours
                let wait_end = deadline;
                while tokio::time::Instant::now() < wait_end {
                    if page.evaluate("document.readyState !== 'loading'").await.ok() == Some(Value::Bool(true)) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let here = crate::util::origin_str(&page.url().await).unwrap_or_default();
                if here != o.origin {
                    browser.inner.lock().unwrap().origin_pages.remove(&o.origin);
                    let _ = page.close().await;
                    page = origin_page(&browser, &o.origin, left()).await?;
                }
                fetch_once(&page, &hop, left(), timeout_ms).await?
            }
        };
        let ms = (now_ms() - t0).round() as u64;
        let Some(location) = answer.location.clone() else {
            return Ok(PageFetchResult {
                status: answer.status,
                headers: answer.headers,
                body: answer.body,
                url: answer.url,
                ms,
                redirected,
            });
        };
        redirected = true;
        let Some(redirect) = &o.redirect else {
            return Ok(PageFetchResult {
                status: answer.status,
                headers: answer.headers,
                body: answer.body,
                url: answer.url,
                ms,
                redirected,
            });
        };
        hop = redirect(&hop, answer.status, &location, hops)?;
        hops += 1;
    }
}

/* ------------------------------------------------------------------ login */

/// Open `url` headed so the user can sign in. Resolves when they close the window or press Enter
/// in the terminal; what counts as logged in is the caller's call. Returns the site's cookies.
pub async fn login(url: &str, profile_dir: &Path, wait_for_enter: bool) -> Result<Vec<StoredCookie>> {
    let _h = hold();
    let browser = open_browser(profile_dir, false).await?;
    let mut destroyed = browser.destroyed_events();
    let page = browser.new_page(None).await?;
    page.navigate(url, None, Duration::from_secs(30)).await?;
    // Closing the last window closes the browser, after which cookies can't be read, so keep a snapshot.
    let mut snapshot = browser.all_cookies().await.unwrap_or_default();
    let (enter_tx, mut enter_rx) = oneshot::channel::<()>();
    if wait_for_enter {
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut line = String::new();
            let _ = tokio::io::BufReader::new(tokio::io::stdin()).read_line(&mut line).await;
            let _ = enter_tx.send(());
        });
    }
    loop {
        tokio::select! {
            d = destroyed.recv() => {
                match d {
                    Some(t) if t == page.target_id => break,
                    None => break,
                    _ => {}
                }
            }
            _ = &mut enter_rx, if wait_for_enter => break,
            _ = tokio::time::sleep(Duration::from_millis(1000)) => {
                if browser.cdp.is_closed() || page.is_closed() { break; }
                if let Ok(c) = browser.all_cookies().await { snapshot = c; }
            }
        }
    }
    if let Ok(c) = browser.all_cookies().await {
        snapshot = c;
    }
    drop(_h);
    close_browser().await;
    Ok(site_cookies(&snapshot, url))
}
