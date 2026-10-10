#![allow(dead_code)]
//! Offline stand-in for a real GUI-only site. Each route mimics one real-world pattern
//! api-anything must handle: persisted GraphQL ids in a hashed bundle (X), layered form/JSON
//! encoding with an XSSI prefix (Google), UI-triggered writes, per-request signatures,
//! login walls served as 200 HTML or by redirect, a login box on a public page, rate limits, and
//! server-rendered HTML lists.
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use rand::RngCore;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct FixtureCall {
    pub method: String,
    /// path plus query string
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Clone, Debug)]
pub struct FixtureState {
    pub user_query_id: String,
    pub create_query_id: String,
    pub build: String,
}

struct Inner {
    state: FixtureState,
    calls: Vec<FixtureCall>,
    seen_sigs: HashSet<String>,
    revoked: HashSet<String>,
    require_signature: bool,
    limited_hits: u32,
}

pub struct Fixture {
    pub url: String,
    inner: Arc<Mutex<Inner>>,
    task: tokio::task::JoinHandle<()>,
}

pub const APP_VERSION: &str = "2026.09.27-a1b2c3";
/// A public web-app bearer, the same for every visitor (X's pattern); the API refuses requests without it.
pub const PUBLIC_BEARER: &str = "Bearer AAAAAAAAAAAAAAAAAAAAAFixturePublicBearer0000";

fn id22() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    api_anything::util::b64url_encode(&b)
}
fn hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const LIST_USERS: [&str; 3] = ["alice", "bob", "carol"];

// The page JS. One bundle for every page, dispatching on location.pathname, like a real SPA entry.
fn app_js(s: &FixtureState) -> String {
    format!(
        r#"(()=>{{
const registry=[{{queryId:"{uq}",operationName:"UserByName",operationType:"query"}},{{queryId:"{cq}",operationName:"CreatePost",operationType:"mutation"}}];
const qid=op=>registry.find(r=>r.operationName===op).queryId;
const ct0=()=>(document.cookie.match(/(?:^|; )ct0=([^;]*)/)||[])[1]||"";
const H=()=>({{"x-csrf-token":ct0(),"x-app-version":"{ver}",authorization:"{bearer}"}});
const out=v=>{{document.getElementById("app").textContent=JSON.stringify(v)}};
const p=location.pathname;
let m;
if((m=p.match(/^\/u\/([^/]+)$/))){{
  const variables=encodeURIComponent(JSON.stringify({{name:decodeURIComponent(m[1]),withExtras:true}}));
  fetch("/api/graphql/"+qid("UserByName")+"/UserByName?variables="+variables,{{headers:H()}}).then(r=>r.json()).then(out);
}}else if(p==="/search"){{
  const q=new URLSearchParams(location.search).get("q")||"";
  const x=new XMLHttpRequest();
  x.open("POST","/api/rpc?rpcids=search");
  x.setRequestHeader("content-type","application/x-www-form-urlencoded;charset=UTF-8");
  x.onload=()=>out(JSON.parse(JSON.parse(x.responseText.slice(5))[0][2]));
  x.send("f.req="+encodeURIComponent(JSON.stringify([[["search",JSON.stringify([q,10]),null,"generic"]]])));
}}else if(p==="/compose"){{
  document.getElementById("post").addEventListener("click",()=>{{
    const text=document.getElementById("text").value;
    fetch("/api/graphql/"+qid("CreatePost")+"/CreatePost",{{method:"POST",headers:{{...H(),"content-type":"application/json"}},body:JSON.stringify({{variables:{{text}},queryId:qid("CreatePost")}})}}).then(r=>r.json()).then(out,()=>{{}});
  }});
}}else if(p==="/feed"){{
  const sig=Date.now()+"."+Math.random().toString(36).slice(2);
  fetch("/api/signed/feed",{{headers:{{...H(),"x-sig":sig}}}}).then(r=>r.json()).then(out);
}}else if(p==="/scoped"){{
  const ei=Math.random().toString(36).slice(2)+Math.random().toString(36).slice(2);
  fetch("/api/scoped?q="+encodeURIComponent(new URLSearchParams(location.search).get("q")||"")+"&ei="+ei).then(r=>r.json()).then(out);
}}else if((m=p.match(/^\/follow\/([^/]+)$/))){{
  document.getElementById("follow").addEventListener("click",()=>fetch("/api/follow?user="+m[1]).then(r=>r.json()).then(out,()=>{{}}));
}}else if(p==="/walled"){{
  fetch("/api/walled").then(r=>r.json()).then(out);
}}else if(p.startsWith("/spa/")){{
  const route=()=>{{
    const name=decodeURIComponent(location.pathname.slice(5));
    document.getElementById("app").innerHTML="<nav>"+["alice","bob"].map(n=>'<a data-link href="/spa/'+n+'">'+n+'</a>').join(" ")+"</nav>";
    fetch("/api/spa/user?name="+encodeURIComponent(name)).then(r=>r.json()).then(v=>{{document.title=v.name}});
  }};
  document.addEventListener("click",e=>{{const a=e.target.closest("a[data-link]");if(!a)return;e.preventDefault();history.pushState({{}},"",a.href);route();}});
  addEventListener("popstate",route);
  route();
}}
}})();"#,
        uq = s.user_query_id,
        cq = s.create_query_id,
        ver = APP_VERSION,
        bearer = PUBLIC_BEARER
    )
}

fn page(build: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Fixture</title></head><body>{body}<div id=\"app\"></div><script src=\"/static/app.{build}.js\"></script></body></html>"
    )
}

const LOGIN_FORM: &str = "<form action=\"/login\" method=\"get\"><input name=\"user\"><input type=\"password\" name=\"password\"><button>Sign in</button></form>";
fn login_page() -> String {
    format!(
        "<!doctype html><html><head><title>Log in</title></head><body>{LOGIN_FORM}</body></html>"
    )
}

fn user(name: &str, extras: bool) -> Value {
    let mut u = json!({
        "name": name,
        "followers": name.len() * 100,
    });
    if extras {
        u["bio"] = json!(format!("I am {name}"));
    }
    // snowflake-sized ids stay strings, as real sites send them
    u["posts"] = json!([
        {"id": "1850000000000000001", "text": format!("hello from {name}")},
        {"id": "1850000000000000002", "text": format!("{name} again")}
    ]);
    json!({"data": {"user": u}})
}

fn cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let raw = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            if eq > 0 {
                out.insert(part[..eq].to_string(), part[eq + 1..].to_string());
            }
        }
    }
    out
}

fn send(status: u16, content_type: &str, body: String, extra: &[(&str, String)]) -> Response {
    let mut r = Response::builder()
        .status(status)
        .header("content-type", content_type);
    for (k, v) in extra {
        r = r.header(*k, v.as_str());
    }
    r.body(Body::from(body)).unwrap()
}

fn json_res(status: u16, v: Value) -> Response {
    send(
        status,
        "application/json; charset=utf-8",
        v.to_string(),
        &[],
    )
}

fn redirect(location: &str, extra: &[(&str, String)]) -> Response {
    let mut all: Vec<(&str, String)> = vec![("location", location.to_string())];
    all.extend(extra.iter().cloned());
    send(302, "text/plain", String::new(), &all)
}

async fn handle(State(inner): State<Arc<Mutex<Inner>>>, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let body_bytes = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024)
        .await
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&body_bytes).into_owned();
    let p = uri.path().to_string();
    let query: HashMap<String, String> =
        url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    let jar = cookies(&headers);
    let header_map: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let h = |name: &str| header_map.get(name).cloned().unwrap_or_default();

    let state = {
        let mut g = inner.lock().unwrap();
        if p.starts_with("/api/") {
            g.calls.push(FixtureCall {
                method: method.to_string(),
                path: format!(
                    "{}{}",
                    uri.path(),
                    uri.query().map(|q| format!("?{q}")).unwrap_or_default()
                ),
                headers: header_map.clone(),
                body: body.clone(),
            });
        }
        g.state.clone()
    };

    // HTML pages hand out the CSRF cookie that page JS echoes in x-csrf-token (X's ct0 pattern).
    let html = |status: u16, markup: String| -> Response {
        let extra: Vec<(&str, String)> = if jar.contains_key("ct0") {
            vec![]
        } else {
            vec![(
                "set-cookie",
                format!("ct0={}; Path=/; SameSite=Lax", hex(16)),
            )]
        };
        send(status, "text/html; charset=utf-8", markup, &extra)
    };
    let csrf_ok = || {
        jar.get("ct0")
            .map(|c| !c.is_empty() && h("x-csrf-token") == *c)
            .unwrap_or(false)
    };
    let users_list = || {
        LIST_USERS
            .iter()
            .map(|n| format!("<li>{n}</li>"))
            .collect::<String>()
    };

    if p == "/" {
        return html(
            200,
            page(
                &state.build,
                &LIST_USERS
                    .iter()
                    .map(|n| format!("<a href=\"/u/{n}\">{n}</a>"))
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
        );
    }
    let one_seg = |prefix: &str| {
        p.starts_with(prefix) && p.len() > prefix.len() && !p[prefix.len()..].contains('/')
    };
    if one_seg("/u/")
        || p == "/search"
        || p == "/feed"
        || p == "/scoped"
        || p == "/walled"
        || p.starts_with("/spa/")
    {
        return html(200, page(&state.build, ""));
    }
    if p == "/compose" {
        return html(
            200,
            page(
                &state.build,
                "<textarea id=\"text\"></textarea><button id=\"post\">Post</button>",
            ),
        );
    }
    if one_seg("/follow/") {
        return html(
            200,
            page(&state.build, "<button id=\"follow\">Follow</button>"),
        );
    }
    if p == "/sw" {
        return html(200, "<!doctype html><html><body><script>(async()=>{try{navigator.serviceWorker.register(\"/sw.js\").catch(()=>{});await Promise.race([navigator.serviceWorker.ready,new Promise(r=>setTimeout(r,500))])}catch{}fetch(\"/api/sw-write\",{method:\"POST\",body:\"do-it\"})})()</script></body></html>".to_string());
    }
    if p == "/sw.js" {
        return send(200, "text/javascript", "self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(clients.claim()));self.addEventListener('fetch',e=>e.respondWith(fetch(e.request)));".to_string(), &[]);
    }
    if p == "/list" {
        let q = query.get("q").cloned().unwrap_or_default();
        let items: String = LIST_USERS
            .iter()
            .filter(|n| n.contains(q.as_str()))
            .map(|n| format!("<li class=\"user\"><a class=\"name\" href=\"/u/{n}\">{n}</a> <span class=\"followers\">{}</span></li>", n.len() * 100))
            .collect();
        return html(
            200,
            format!("<!doctype html><html><body><ul class=\"users\">{items}</ul></body></html>"),
        );
    }
    if p == format!("/static/app.{}.js", state.build) {
        return send(200, "application/javascript", app_js(&state), &[]);
    }
    if p == "/login" {
        let token = hex(12);
        return redirect(
            "/private",
            &[(
                "set-cookie",
                format!("session={token}; Path=/; HttpOnly; SameSite=Lax"),
            )],
        );
    }
    if p == "/private" {
        let valid = jar
            .get("session")
            .map(|s| !s.is_empty() && !inner.lock().unwrap().revoked.contains(s))
            .unwrap_or(false);
        return if valid {
            json_res(200, json!({"data": {"secret": "only for you"}}))
        } else {
            html(200, login_page())
        };
    }
    if p == "/account" {
        return redirect("/signin?next=%2Faccount", &[]);
    }
    if p == "/signin" {
        return html(200, login_page());
    }
    if p.starts_with("/app/") {
        return html(404, "<!doctype html><html><body><div id=\"app\"></div><script>fetch(\"/api/scoped?q=\"+location.pathname.slice(5))</script></body></html>".to_string());
    }
    if p == "/community" {
        return redirect("/forum", &[]);
    }
    if p == "/docs/login" {
        return html(
            200,
            format!(
                "<!doctype html><html><body><ul>{}</ul></body></html>",
                users_list()
            ),
        );
    }
    if p == "/notice" {
        return html(
            200,
            format!(
                "<!doctype html><html><body><p>Please log in to comment.</p><ul>{}</ul></body></html>",
                users_list()
            ),
        );
    }
    if p == "/catalog" {
        return html(
            200,
            format!(
                "<!doctype html><html><body>{LOGIN_FORM}<form action=\"/catalog\"><input name=\"q\"><ul>{}</ul></form></body></html>",
                users_list()
            ),
        );
    }
    if p.starts_with("/card/") {
        return html(
            200,
            format!(
                "<!doctype html><html><body>{LOGIN_FORM}<script>window.state = {}</script></body></html>",
                json!({"member": {"name": &p[6..]}})
            ),
        );
    }
    if p == "/forum" {
        return html(
            200,
            format!(
                "<!doctype html><html><body>{LOGIN_FORM}<ul>{}</ul></body></html>",
                users_list()
            ),
        );
    }
    if p.starts_with("/forum/") {
        return html(
            200,
            format!(
                "<!doctype html><html><body>{LOGIN_FORM}<script>fetch(\"/api/scoped?q=\"+location.pathname.slice(7))</script></body></html>"
            ),
        );
    }

    if let Some(rest) = p.strip_prefix("/api/graphql/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() == 2 && (parts[1] == "UserByName" || parts[1] == "CreatePost") {
            let (qid, op) = (parts[0], parts[1]);
            let want = if op == "UserByName" {
                &state.user_query_id
            } else {
                &state.create_query_id
            };
            if qid != want {
                return send(404, "text/plain", String::new(), &[]);
            }
            if !csrf_ok() {
                return json_res(403, json!({"errors": [{"message": "csrf token mismatch"}]}));
            }
            if h("authorization") != PUBLIC_BEARER {
                return json_res(
                    400,
                    json!({"errors": [{"message": "Bad Authentication data", "code": 215}]}),
                );
            }
            if op == "UserByName" && method == Method::GET {
                let v: Value = match serde_json::from_str(
                    query.get("variables").map(|s| s.as_str()).unwrap_or(""),
                ) {
                    Ok(v) => v,
                    Err(_) => {
                        return json_res(
                            400,
                            json!({"errors": [{"message": "variables must be JSON"}]}),
                        );
                    }
                };
                let Some(name) = v.get("name").and_then(|n| n.as_str()) else {
                    return json_res(
                        400,
                        json!({"errors": [{"message": "Variable $name must be defined"}]}),
                    );
                };
                // a handle that doesn't exist: 200 with empty data, as X answers
                if name.starts_with("nobody") {
                    return json_res(200, json!({"data": {}}));
                }
                return json_res(
                    200,
                    user(name, v.get("withExtras") == Some(&Value::Bool(true))),
                );
            }
            if op == "CreatePost" && method == Method::POST {
                let parsed: Value =
                    serde_json::from_str(if body.is_empty() { "{}" } else { &body })
                        .unwrap_or(json!({}));
                let text = parsed
                    .get("variables")
                    .and_then(|v| v.get("text"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis();
                return json_res(
                    200,
                    json!({"data": {"create_post": {"id": format!("19{now}"), "text": text}}}),
                );
            }
            return json_res(405, json!({"errors": [{"message": "method not allowed"}]}));
        }
    }

    if p == "/api/rpc" && method == Method::POST {
        let freq = url::form_urlencoded::parse(body.as_bytes())
            .find(|(k, _)| k == "f.req")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        let parsed = serde_json::from_str::<Value>(&freq).ok().and_then(|outer| {
            let inner_text = outer.get(0)?.get(0)?.get(1)?.as_str()?.to_string();
            let arr: Value = serde_json::from_str(&inner_text).ok()?;
            Some(arr.get(0)?.as_str()?.to_string())
        });
        return match parsed {
            Some(q) => {
                let results: Vec<Value> = (1..=3)
                    .map(|i| {
                        json!([
                            format!("{q} result {i}"),
                            format!(
                                "https://example.test/{}/{i}",
                                api_anything::util::encode_uri_component(&q)
                            )
                        ])
                    })
                    .collect();
                send(
                    200,
                    "application/json; charset=utf-8",
                    format!(
                        ")]}}'\n{}",
                        json!([["wrb.fr", "search", json!([results]).to_string()]])
                    ),
                    &[],
                )
            }
            None => send(400, "text/plain", "bad f.req".to_string(), &[]),
        };
    }

    if p == "/api/signed/feed" {
        let sig = h("x-sig");
        let mut g = inner.lock().unwrap();
        if g.require_signature {
            if sig.is_empty() || g.seen_sigs.contains(&sig) {
                return json_res(403, json!({"errors": [{"message": "invalid signature"}]}));
            }
            g.seen_sigs.insert(sig);
        }
        return json_res(
            200,
            json!({"data": {"feed": [{"id": "f1", "text": "first"}, {"id": "f2", "text": "second"}]}}),
        );
    }

    // A bot wall that only lets real browsers through; Chrome's brotli support stands in for its TLS fingerprint.
    if p == "/api/walled" {
        let ae = h("accept-encoding");
        if !ae.split(|c: char| !c.is_alphanumeric()).any(|t| t == "br") {
            return send(403, "text/html", "<html><head><title>Just a moment...</title></head><body>cf-chl-bypass</body></html>".to_string(), &[]);
        }
        return json_res(200, json!({"data": {"items": ["behind the wall"]}}));
    }
    if p == "/api/scoped" {
        let q = query
            .get("q")
            .cloned()
            .unwrap_or_else(|| "null".to_string());
        return json_res(
            200,
            json!({"data": {"results": [format!("{q} one"), format!("{q} two")]}}),
        );
    }
    if p == "/api/mine" {
        let key = jar
            .get("session")
            .cloned()
            .unwrap_or_else(|| "guest".to_string());
        return json_res(
            200,
            json!({key: [{"name": query.get("name").cloned().map(Value::String).unwrap_or(Value::Null)}]}),
        );
    }
    if p == "/api/follow" || p == "/api/sw-write" {
        return json_res(200, json!({"ok": true}));
    }
    if p == "/api/spa/user" {
        return json_res(
            200,
            json!({"name": query.get("name").cloned().map(Value::String).unwrap_or(Value::Null)}),
        );
    }
    if p == "/api/limited" {
        let mut g = inner.lock().unwrap();
        g.limited_hits += 1;
        return if g.limited_hits > 2 {
            json_res(429, json!({"message": "Rate limit exceeded. Please wait."}))
        } else {
            json_res(200, json!({"data": {"n": g.limited_hits}}))
        };
    }
    (
        StatusCode::NOT_FOUND,
        [("content-type", "text/plain")],
        "not found",
    )
        .into_response()
}

impl Fixture {
    pub async fn start() -> Fixture {
        let inner = Arc::new(Mutex::new(Inner {
            state: FixtureState {
                user_query_id: id22(),
                create_query_id: id22(),
                build: hex(4),
            },
            calls: vec![],
            seen_sigs: HashSet::new(),
            revoked: HashSet::new(),
            require_signature: false,
            limited_hits: 0,
        }));
        let app = axum::Router::new()
            .fallback(handle)
            .with_state(inner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Fixture {
            url: format!("http://127.0.0.1:{port}"),
            inner,
            task,
        }
    }
    /// every /api/* hit, in order
    pub fn calls(&self) -> Vec<FixtureCall> {
        self.inner.lock().unwrap().calls.clone()
    }
    pub fn state(&self) -> FixtureState {
        self.inner.lock().unwrap().state.clone()
    }
    /// new UserByName/CreatePost queryIds and a new bundle hash; old ids 404 with an empty body
    pub fn rotate(&self) {
        let mut g = self.inner.lock().unwrap();
        g.state.user_query_id = id22();
        g.state.create_query_id = id22();
        g.state.build = hex(4);
    }
    pub fn set_require_signature(&self, on: bool) {
        self.inner.lock().unwrap().require_signature = on;
    }
    /// invalidate one /private session token (server-side logout)
    pub fn revoke(&self, token: &str) {
        self.inner.lock().unwrap().revoked.insert(token.to_string());
    }
    /// mint a fresh valid session token, as /login would (stands in for a re-login in the browser)
    pub fn mint_session(&self) -> String {
        hex(12)
    }
    pub fn close(&self) {
        self.task.abort();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
