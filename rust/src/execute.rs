//! `call()`: the execution ladder (DESIGN.md "Execution ladder"), the classifier-driven actions,
//! the heal-loop guards, and the write rules. Always sends the stored template first; healing is
//! reactive only.
use crate::browser::{PageFetchOptions, ProfileInUse, chrome_available, page_fetch, profile_cookies};
use crate::classify::{Class, Observed, judge};
use crate::extract::cap_output;
use crate::heal::{Attempt, HealOptions, HealResult, PROFILE_HINT, heal_operation, judge_exchange, profile_dir, run_op_trigger};
use crate::http::{Args, BadHeader, RedirectRefused, RefusalKind, SendOptions, SharedFetcher, build_request, holds_ref, next_hop, send, with_defaults};
use crate::login::reimport_if_browser;
use crate::session::{Session, load_session, logged_in, merge_capture, save_session, session_file, with_lock};
use crate::spec::{Operation, Site};
use crate::store::{STALE_TTL_MS, Strategy, last_heal_at, load_site, mark_stale, remember_tier, remembered_tier, stale_mark};
use crate::util::{as_text, iso_at, json, now_ms};
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

pub type Tier = u8;

#[derive(Clone, Default)]
pub struct CallOptions {
    /// required for any readOnly:false op, at every entry point
    pub allow_writes: bool,
    pub fetcher: Option<SharedFetcher>,
    /// highest transport tier to use (default 3); 1 also means no browser at all
    pub max_tier: Option<Tier>,
    /// per-site gap between tier-1 requests (default 1000)
    pub min_interval_ms: Option<u64>,
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct CallResult {
    pub ok: bool,
    pub class: Class,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// extracted, picked, capped
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// what to do about a failure; follow it at most once
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Strategy>,
    pub ms: u64,
}

impl CallResult {
    fn failed(class: Class, reason: String, next: Option<String>) -> CallResult {
        CallResult { ok: false, class, data: None, truncated: None, tier: None, healed: None, ms: 0, reason: Some(reason), next, strategy: None }
    }
}

const HEAL_GUARD_MS: f64 = 10.0 * 60_000.0;
// A write is retried only when the server certainly did not run it; timeouts and 5xx are ambiguous.
const NOT_EXECUTED: [u16; 4] = [400, 401, 403, 404];

/// Certainly not run: a 400/401/403/404 answered to the request itself. After a redirect it ran. At
/// tier 3 the page sent it and the answer judged may be a redirect's follow-up: never proof.
fn not_run(a: Option<&Attempt>) -> bool {
    a.map(|a| a.status.map(|s| NOT_EXECUTED.contains(&s)).unwrap_or(false) && !a.redirected && a.tier != 3).unwrap_or(false)
}

#[derive(Clone)]
struct Ctx {
    site: String,
    args: Args,
    opts: CallOptions,
    max_tier: Tier,
}

fn next_for(c: Class, site: &str, op: &Operation, a: Option<&Attempt>) -> Option<String> {
    if c == Class::Ok {
        return None;
    }
    if c == Class::Refused {
        return Some("only if the user asked for this write: rerun with --allow-writes (MCP: start the server with --allow-writes)".to_string());
    }
    if let Some(h) = a.and_then(|a| a.hint.clone()) {
        return Some(h);
    }
    // A write the server may have run: never invite a second send.
    let ran = !op.read_only && a.is_some() && !not_run(a);
    if ran && c != Class::Drift && c != Class::Auth {
        return Some("the write may have gone through: check the site before any retry".to_string());
    }
    Some(match c {
        Class::Auth => format!(
            "ask the user to run: api-anything login {site}; then {}",
            if ran { "check the site, and retry only if the write is not there" } else { "retry once" }
        ),
        Class::Rate => {
            if a.map(|a| a.reason.contains("retry after")).unwrap_or(false) {
                "rate limited: do not retry before the time in reason".to_string()
            } else {
                "rate limited: do not retry now; wait a few minutes".to_string()
            }
        }
        Class::Blocked => format!("the site is challenging automated requests: ask the user to run api-anything login {site} and clear the challenge, then retry once"),
        Class::Drift => {
            if !op.read_only {
                format!("{}re-learn it with api-anything add {site} {} ... --write", if ran { "the write may have run: check the site first, then " } else { "" }, op.name)
            } else {
                format!("api-anything heal {site} {}; if that fails, re-learn it with api-anything add {site} {} ...", op.name, op.name)
            }
        }
        Class::Input => format!("check the args against: api-anything ops {site}"),
        _ => "retry once; if it fails the same way, stop and report the reason".to_string(),
    })
}

fn success(a: &Attempt, reason: Option<String>, healed: Option<bool>) -> CallResult {
    let capped = cap_output(a.data.as_ref().unwrap_or(&Value::Null), 20_000);
    CallResult { ok: true, class: Class::Ok, data: Some(if a.data.is_none() { Value::Null } else { capped.data }), truncated: capped.truncated, tier: Some(a.tier), healed, ms: 0, reason, next: None, strategy: None }
}

/// The op's stored example args, with defaults; None when a required param has none.
fn example_args(op: &Operation) -> Option<Args> {
    let mut out = Args::new();
    for p in &op.params {
        match p.example.clone().or_else(|| p.default.clone()) {
            Some(v) => {
                out.insert(p.name.clone(), v);
            }
            None if p.required => return None,
            None => {}
        }
    }
    Some(out)
}

fn same_args(a: &Args, b: &Args, op: &Operation) -> bool {
    let text = |args: &Args, p: &crate::spec::Param| args.get(&p.name).or(p.default.as_ref()).map(as_text).unwrap_or_default();
    op.params.iter().all(|p| text(a, p) == text(b, p))
}

/// What to do about a write whose redirect was not followed, since that would have sent it again.
fn sent_once(site: &str, op: &Operation) -> String {
    format!(
        "the write was sent once and may have run: check the site first. Do not retry: the site answered it with a redirect that would send it a second time, which was not followed; if the operation moved, learn it at its new address: api-anything add {site} {} ... --write",
        op.name
    )
}

async fn attempt(ctx: &Ctx, op: &Operation, tier: Tier) -> Attempt {
    match attempt_inner(ctx, op, tier).await {
        Ok(a) => a,
        Err(e) => {
            // nothing was sent when the browser could not start
            if e.downcast_ref::<ProfileInUse>().is_some() {
                let mut a = Attempt::new(tier, Class::Error, &e.to_string());
                a.hint = Some(PROFILE_HINT.to_string());
                return a;
            }
            if let Some(r) = e.downcast_ref::<RedirectRefused>() {
                // The redirect is the site's answer, so a retry meets it again; the request it answered was sent.
                let add = format!("api-anything add {} {} ...{}", ctx.site, op.name, if op.read_only { "" } else { " --write" });
                let mut a = Attempt::new(tier, Class::Error, &r.message);
                a.ambiguous = true;
                if r.kind == Some(RefusalKind::Again) {
                    a.hint = Some(sent_once(&ctx.site, op));
                    return a;
                }
                let why = if r.kind.is_some() {
                    format!("the site's redirects for this request do not end (a loop, or a chain past the limit); learn the operation again from the page that uses it, at the address the site now answers from: {add}")
                } else if op.read_only {
                    format!("the site sends this request on to another origin, which was not followed; re-learn it with {add} if the site moved there")
                } else {
                    format!("re-learn it with {add} if the site moved there")
                };
                a.hint = Some(if op.read_only { format!("do not retry: {why}") } else { format!("the write may have run: check the site first. Do not retry: {why}") });
                return a;
            }
            let mut a = Attempt::new(tier, Class::Error, &crate::util::first_line(&e.to_string()));
            a.ambiguous = true;
            a
        }
    }
}

async fn attempt_inner(ctx: &Ctx, op: &Operation, tier: Tier) -> anyhow::Result<Attempt> {
    if tier == 3 {
        // For a write this is the UI sending it: the one attempt.
        let run = run_op_trigger(&ctx.site, op, &ctx.args, false).await?;
        let judged = run.matched.as_ref().and_then(|m| judge_exchange(op, m));
        // The page is told nothing of a redirect that was stopped, its status included: this is the answer.
        let resent = if run.resends > 0 {
            let mut a = Attempt::new(tier, Class::Error, "the site answered this write with a redirect that would send it again: stopped in the browser");
            a.ambiguous = true;
            a.hint = Some(sent_once(&ctx.site, op));
            Some(a)
        } else {
            None
        };
        let mut a = judged.or(resent).unwrap_or_else(|| match &run.login_wall {
            Some(w) => Attempt::new(tier, Class::Auth, &format!("the trigger landed on a sign-in page ({w})")),
            None => Attempt::new(tier, Class::Drift, &format!("the trigger fired no request matching {}", json(&serde_json::to_value(&op.matcher).unwrap_or(Value::Null)))),
        });
        if run.repeats > 0 {
            let stopped = if run.repeats == 1 { "the repeat was".to_string() } else { format!("{} repeats were", run.repeats) };
            a.note = Some(format!("the page sent this write {} times: {stopped} stopped in the browser", run.repeats + 1));
        }
        return Ok(a);
    }
    let session = load_session(&ctx.site)?;
    let (status, headers, body, url, redirected) = if tier == 1 {
        let sent = send(op, &ctx.args, &session, &SendOptions { site: ctx.site.clone(), fetcher: ctx.opts.fetcher.clone(), timeout_ms: ctx.opts.timeout_ms, min_interval_ms: ctx.opts.min_interval_ms }).await?;
        // A rotating cookie (a rolling session, __cf_bm) must ride on the next call.
        if !sent.set_cookies.is_empty() {
            let _ = merge_capture(&ctx.site, &sent.set_cookies, &indexmap::IndexMap::new(), now_ms());
        }
        (sent.status, sent.headers, sent.body, sent.url, sent.redirected)
    } else {
        let req = build_request(op, &ctx.args, &session)?;
        let mut headers = req.headers.clone();
        headers.shift_remove("cookie"); // the page sends the profile's own cookies
        let origin = crate::util::origin_str(&req.url).unwrap_or_default();
        let op2 = op.clone();
        let session2 = session.clone();
        let r = page_fetch(PageFetchOptions {
            origin,
            url: req.url.clone(),
            method: req.method.clone(),
            headers,
            body: req.body.clone(),
            profile_dir: profile_dir(),
            headless: true,
            timeout_ms: ctx.opts.timeout_ms,
            retry_on_navigation: op.read_only,
            // tier 1's policy, one hop at a time: a page's own fetch() would follow with everything aboard
            redirect: Some(Arc::new(move |from, status, location, taken| next_hop(&op2, &session2, from, status, location, taken, crate::http::MAX_REDIRECTS))),
        })
        .await?;
        (r.status, r.headers, r.body, r.url, r.redirected)
    };
    let j = judge(op, &Observed { status, headers, body, url: Some(url) });
    Ok(Attempt { tier, status: Some(status), redirected, class: j.class, reason: j.reason, missing: j.missing, data: j.data, ..Default::default() })
}

/// Replace the jar with the profile's cookies. True when that changes the request this tier sends.
async fn refresh_cookies(ctx: &Ctx, op: &Operation, tier: Tier) -> bool {
    if !chrome_available() {
        return false;
    }
    let Ok(fresh) = profile_cookies(&op.request.url, &profile_dir()).await else { return false };
    let Ok(file) = session_file(&ctx.site) else { return false };
    let swap = || -> anyhow::Result<bool> {
        let s = load_session(&ctx.site)?;
        let sent = |cookies: Vec<crate::types::StoredCookie>| -> Option<String> {
            let mut req = build_request(op, &ctx.args, &Session { cookies, ..s.clone() }).ok()?;
            if tier > 1 {
                req.headers.shift_remove("cookie");
            }
            Some(json(&serde_json::to_value(&req).ok()?))
        };
        let before = sent(s.cookies.clone());
        save_session(&ctx.site, &Session { cookies: fresh.clone(), ..s.clone() })?;
        Ok(sent(fresh.clone()) != before)
    };
    with_lock(&file, swap).unwrap_or(false)
}

async fn on_drift(ctx: &Ctx, site: &Site, op: &Operation, a: Attempt) -> CallResult {
    let fail = |b: &Attempt, reason: Option<String>, next: Option<String>| CallResult {
        ok: false,
        class: b.class,
        data: None,
        truncated: None,
        tier: Some(b.tier),
        healed: None,
        ms: 0,
        reason: Some(reason.unwrap_or_else(|| b.reason.clone())),
        next: next.or_else(|| next_for(b.class, &ctx.site, op, Some(b))),
        strategy: None,
    };

    // An op learned signed in, called with no login cookie: the site hides the data from guests; it did not move.
    if a.missing && op.learned_logged_in {
        let jar = load_session(&ctx.site).map(|s| s.cookies).unwrap_or_default();
        if !logged_in(&jar, site.login_cookies.as_deref(), now_ms()) {
            let mut b = a.clone();
            b.class = Class::Auth;
            return fail(&b, Some(format!("{}; the op was learned signed in and the session has no login cookie", a.reason)), None);
        }
    }

    // "No such user" and "no results" look exactly like a moved extract path. If the example args
    // still return data through the same template, nothing drifted: the args are the problem.
    let examples = example_args(op);
    let mut examples_fail = false;
    if a.missing && op.read_only {
        if let Some(ex) = &examples {
            if same_args(ex, &ctx.args, op) {
                examples_fail = true;
            } else {
                let b = attempt(&Ctx { args: ex.clone(), ..ctx.clone() }, op, a.tier).await;
                if b.class == Class::Ok {
                    let mut c = a.clone();
                    c.class = Class::Input;
                    return fail(
                        &c,
                        Some(format!("no results for these args ({}); the example args still return data, so the operation works", a.reason)),
                        Some(format!("check the args against: api-anything ops {}; do not heal or re-add", ctx.site)),
                    );
                }
                // throttled or challenged while checking: stop, don't spend a heal (a browser run) against it
                if matches!(b.class, Class::Rate | Class::Blocked | Class::Auth) {
                    return fail(&b, None, None);
                }
                examples_fail = true;
            }
        }
    }

    let mut guard: Option<String> = None;
    let stale = stale_mark(&ctx.site, &op.name, now_ms());
    let healed_at = last_heal_at(&ctx.site, &op.name);
    if let Some(s) = &stale {
        guard = Some(format!("stale until {}: {}", iso_at(s.until), s.reason));
    } else if let Some(h) = healed_at {
        if now_ms() - h < HEAL_GUARD_MS {
            let reason = format!("drifted again within 10 min of a heal ({})", a.reason);
            mark_stale(&ctx.site, &op.name, &reason, STALE_TTL_MS, now_ms(), None);
            guard = Some(format!("marked stale: {reason}"));
        }
    }
    if let Some(guard) = guard {
        // Not re-healed. A read can still get its answer from the site's own frontend.
        if op.read_only && a.tier < 3 && ctx.max_tier >= 3 && stale.as_ref().and_then(|s| s.tier3) != Some(false) && chrome_available() {
            let b = attempt(ctx, op, 3).await;
            if b.class == Class::Ok {
                return success(&b, Some(guard), None);
            }
            // the site's own request doesn't answer either: stop paying a browser run per call
            if b.hint.is_none() && b.class != Class::Auth {
                mark_stale(&ctx.site, &op.name, &stale.as_ref().map(|s| s.reason.clone()).unwrap_or_else(|| guard.clone()), STALE_TTL_MS, now_ms(), Some(false));
            }
        }
        // `heal` refuses writes: a stale write is re-learned
        let next = if op.read_only {
            format!("wait for the stale mark to expire, or force it: api-anything heal {} {}", ctx.site, op.name)
        } else {
            format!("wait for the stale mark to expire, or re-learn it: api-anything add {} {} ... --write", ctx.site, op.name)
        };
        return fail(&a, Some(format!("{}; {guard}", a.reason)), Some(next));
    }

    // A candidate is validated by replaying it; at tier 3 the site's own request would answer instead, validating nothing.
    let vctx = ctx.clone();
    let vtier = a.tier.min(2);
    let validate: crate::heal::Validate = Arc::new(move |candidate: Operation| {
        let c = vctx.clone();
        Box::pin(async move { attempt(&c, &candidate, vtier).await })
    });
    let h = heal_operation(&ctx.site, op, &ctx.args, HealOptions { validate, fetcher: ctx.opts.fetcher.clone(), login_cookies: site.login_cookies.clone(), browser: ctx.max_tier > 1 }).await;
    match h {
        HealResult::Healed { attempt: ha, .. } => success(&ha, None, Some(true)),
        // Throttled, challenged, logged out, or no browser: nothing was learned about the op, so it is not stale.
        HealResult::Failed { transient: true, reason, attempt: ha, .. } => {
            let b = ha.unwrap_or_else(|| a.clone());
            fail(&b, Some(format!("{}; heal stopped: {reason}", a.reason)), None)
        }
        HealResult::Failed { reason, attempt: ha, fallback, .. } => {
            // A heal that tried everything and failed would fail the same way on the next call: don't rerun the browser each time.
            if ctx.max_tier > 1 {
                mark_stale(&ctx.site, &op.name, &format!("heal failed: {reason}"), STALE_TTL_MS, now_ms(), Some(fallback.as_ref().map(|f| f.class == Class::Ok).unwrap_or(false)));
            }
            // The template can't be replayed, but the site's own request answered: that is the tier-3 read.
            if let Some(f) = fallback.as_ref().filter(|f| f.class == Class::Ok && ctx.max_tier >= 3) {
                return success(f, Some(format!("heal failed ({reason}); answered by the site's own request")), None);
            }
            let b = ha.or(fallback).unwrap_or_else(|| a.clone());
            fail(&b, Some(format!("{}; heal failed: {reason}", b.reason)), None)
        }
        HealResult::Identical { fallback, .. } => {
            if let Some(f) = fallback.as_ref().filter(|f| f.class == Class::Ok && ctx.max_tier >= 3) {
                let _ = f;
            }
            if examples_fail {
                // Same request, and even the examples get no data: the response recipe drifted (a renamed field), or the site is down.
                let mut b = a.clone();
                b.class = Class::Drift;
                return fail(
                    &b,
                    Some(format!("the site takes the same request but its response lacks the data ({}), for the op's example args too", a.reason)),
                    Some(format!(
                        "if the site works in a browser, re-learn the response recipe: api-anything add {} {} ... --extract <path> (api-anything capture <trigger url> shows the response); otherwise report it",
                        ctx.site, op.name
                    )),
                );
            }
            let mut b = a.clone();
            b.class = Class::Input;
            fail(
                &b,
                Some(format!("not drift: re-learning gave a byte-identical template ({})", a.reason)),
                Some(format!("check the args against api-anything ops {}; if the site needs an account, ask the user to run api-anything login {}", ctx.site, ctx.site)),
            )
        }
    }
}

enum Resolved {
    Found(Site, Operation),
    Failed(CallResult),
}

fn resolve(site_name: &str, op_name: &str) -> Resolved {
    let r = match load_site(site_name) {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            let bad = msg.contains("invalid site name");
            return Resolved::Failed(CallResult::failed(
                if bad { Class::Input } else { Class::Error },
                crate::util::first_line(&msg),
                Some(if bad { "api-anything sites lists what exists".to_string() } else { "fix or delete that spec file, then retry once".to_string() }),
            ));
        }
    };
    let Some(r) = r else {
        return Resolved::Failed(CallResult::failed(Class::Input, format!("no site \"{site_name}\""), Some("api-anything sites lists what exists; api-anything add creates one".to_string())));
    };
    let Some(op) = r.site.operations.iter().find(|o| o.name == op_name).cloned() else {
        return Resolved::Failed(CallResult::failed(Class::Input, format!("no operation \"{op_name}\" on {}", r.site.name), Some(format!("api-anything ops {}", r.site.name))));
    };
    Resolved::Found(r.site, op)
}

/// Call one operation. Never fails for site-side failures; the result carries class, reason and next.
pub async fn call(site_name: &str, op_name: &str, args: Args, opts: CallOptions) -> CallResult {
    let t0 = now_ms();
    let mut r = call_inner(site_name, op_name, args, opts).await;
    r.ms = (now_ms() - t0).round() as u64;
    r
}

async fn call_inner(site_name: &str, op_name: &str, args: Args, opts: CallOptions) -> CallResult {
    let (site, op) = match resolve(site_name, op_name) {
        Resolved::Found(s, o) => (s, o),
        Resolved::Failed(r) => return r,
    };
    let site_name = site.name.clone();
    let write = !op.read_only;
    if write && !opts.allow_writes {
        return CallResult::failed(Class::Refused, format!("{} is a write and writes are not allowed", op.name), next_for(Class::Refused, &site_name, &op, None));
    }
    // A misspelled optional arg would silently fall back to its default: refuse it.
    let unknown: Vec<&String> = args.keys().filter(|k| !op.params.iter().any(|p| &p.name == *k)).collect();
    if !unknown.is_empty() {
        let takes = op.params.iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ");
        return CallResult::failed(
            Class::Input,
            format!("unknown arg {}; {} takes {}", unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "), op.name, if takes.is_empty() { "no args".to_string() } else { takes }),
            next_for(Class::Input, &site_name, &op, None),
        );
    }
    // Resolved once: the tier-3 trigger and its answer's match take a default just as the request does.
    let args = with_defaults(&op, &args);
    let session = match load_session(&site_name) {
        Ok(s) => s,
        Err(e) => {
            return CallResult::failed(
                Class::Error,
                e.to_string(),
                Some(format!("delete {}, then ask the user to run api-anything login {site_name} if the site needs an account", session_file(&site_name).map(|p| p.display().to_string()).unwrap_or_default())),
            );
        }
    };
    if let Err(e) = build_request(&op, &args, &session) {
        let next = if e.downcast_ref::<BadHeader>().is_some() {
            Some(format!("nothing was sent. Check the args; if the value is the session's, ask the user to run: api-anything login {site_name}"))
        } else {
            next_for(Class::Input, &site_name, &op, None)
        };
        return CallResult::failed(Class::Input, e.to_string(), next);
    }

    // No login on record for this site: the session has no source, the jar has no live login cookie,
    // and the op neither takes a credential nor was learned signed in.
    let no_login = || {
        if op.slots.iter().any(holds_ref) || op.learned_logged_in {
            return false;
        }
        match load_session(&site_name) {
            Ok(s) => s.source.is_none() && !logged_in(&s.cookies, site.login_cookies.as_deref(), now_ms()),
            Err(_) => false,
        }
    };
    let ctx = Ctx { site: site_name.clone(), args, opts: opts.clone(), max_tier: opts.max_tier.unwrap_or(3) };
    let remembered = remembered_tier(&site_name, &op.name);
    // A remembered escalation is a speed hint, not a requirement: under a lower cap, start at the op's own tier.
    let mut tier: Tier = op.min_tier.max(remembered.filter(|r| *r <= ctx.max_tier).unwrap_or(1));
    // Why a call ran above tier 1, so a slow call explains itself.
    let mut notes: Vec<String> = if tier > op.min_tier { vec![format!("started at tier {tier}: an earlier call escalated there")] } else { vec![] };
    let mut auth_tried = false;
    let mut examples_checked = false;
    loop {
        if tier > ctx.max_tier {
            let mut r = CallResult::failed(Class::Blocked, format!("needs tier {tier}, capped at {}", ctx.max_tier), Some(format!("allow a higher tier (--max-tier {tier})")));
            r.tier = Some(tier);
            return r;
        }
        if tier > 1 && !chrome_available() {
            let mut r = CallResult::failed(Class::Blocked, format!("tier {tier} needs Google Chrome"), Some("install Google Chrome, then retry once".to_string()));
            r.tier = Some(tier);
            return r;
        }
        let a = attempt(&ctx, &op, tier).await;
        if let Some(n) = &a.note {
            notes.push(n.clone());
        }
        if a.class == Class::Ok {
            // Only an escalation is remembered; a tier the spec itself asks for is not, so editing minTier takes effect.
            let keep = if tier > op.min_tier { Some(tier) } else { None };
            if remembered != keep {
                remember_tier(&site_name, &op.name, keep);
            }
            return success(&a, if notes.is_empty() { None } else { Some(notes.join("; ")) }, None);
        }
        let reason = match &a.note {
            Some(n) => format!("{}; {n}", a.reason),
            None => a.reason.clone(),
        };
        let fail = |a: &Attempt| {
            let mut r = CallResult::failed(a.class, reason.clone(), next_for(a.class, &site_name, &op, Some(a)));
            r.tier = Some(tier);
            r
        };
        if write && !not_run(Some(&a)) {
            return fail(&a);
        }
        // A bare 403 is a wall or a refusal of this one entity (a private profile): if the example args
        // answer through the same tier, the args are the problem, and a browser run would not help.
        if a.class == Class::Blocked && a.missing && !write && !examples_checked {
            examples_checked = true;
            if let Some(ex) = example_args(&op) {
                if !same_args(&ex, &ctx.args, &op) && attempt(&Ctx { args: ex.clone(), ..ctx.clone() }, &op, tier).await.class == Class::Ok {
                    let mut r = CallResult::failed(
                        Class::Input,
                        format!("refused for these args ({}); the example args still return data, so the operation works", a.reason),
                        Some(format!("check the args (a private, restricted or missing entity is refused this way) against: api-anything ops {site_name}; do not heal or re-add")),
                    );
                    r.tier = Some(tier);
                    return r;
                }
            }
        }
        if a.class == Class::Blocked && tier < (if write { 2 } else { 3 }) {
            notes.push(format!("tier {tier} was blocked ({})", a.reason));
            tier += 1;
            continue;
        }
        // Once per call, at any tier. A write gets here only when it certainly did not run.
        if a.class == Class::Auth && !auth_tried {
            auth_tried = true;
            // An imported session is a mirror of the everyday browser: silently re-import from the same
            // profile once (browserless), in case the human re-signed in there. Then retry.
            if reimport_if_browser(&site_name, &op.request.url, site.login_cookies.as_deref()).await {
                continue;
            }
            // tier 3 ran the site's own page: the profile's cookies and session values are what it just used
            if tier == 3 || ctx.max_tier <= 1 {
                return fail(&a);
            }
            if refresh_cookies(&ctx, &op, tier).await {
                continue;
            }
            // Session values (a bearer, a guest token) come from the site's own requests: a trigger run
            // refreshes them, and for a read its answer is this call's answer.
            if op.read_only && ctx.max_tier >= 3 && chrome_available() && op.slots.iter().any(|s| s.ref_str().starts_with("session:")) {
                let b = attempt(&ctx, &op, 3).await;
                if b.class == Class::Ok {
                    let mut why = notes.clone();
                    why.push(format!("tier {tier} said {} ({})", a.class, a.reason));
                    return success(&b, Some(format!("{}; refreshed the session through the site's own request", why.join("; "))), None);
                }
                // The run answered other args (a trigger fixed to one page), but it refreshed the session values: retry once.
                continue;
            }
        }
        if a.class == Class::Drift {
            return on_drift(&ctx, &site, &op, a).await;
        }
        // Recovery is spent, plain HTTP still says auth, and the site has no login on record that could
        // have run out: a wall that answers 419 or 401 to what is not a browser looks the same. One tier-2
        // attempt tells them apart, for a read only.
        if a.class == Class::Auth && tier == 1 && !write && ctx.max_tier >= 2 && chrome_available() && no_login() {
            let b = attempt(&ctx, &op, 2).await;
            if b.class == Class::Ok {
                remember_tier(&site_name, &op.name, Some(2));
                return success(&b, Some(format!("tier 1 said auth with no login on record for this site ({}); a real page got the answer", a.reason)), None);
            }
        }
        return fail(&a);
    }
}

/// Forced heal for `api-anything heal`: ignores the stale guard. Reads only; a write's check would perform it.
pub async fn heal(site_name: &str, op_name: &str, args: Args, opts: CallOptions) -> CallResult {
    let t0 = now_ms();
    let mut r = heal_inner(site_name, op_name, args, opts).await;
    r.ms = (now_ms() - t0).round() as u64;
    r
}

async fn heal_inner(site_name: &str, op_name: &str, args: Args, opts: CallOptions) -> CallResult {
    let (site, op) = match resolve(site_name, op_name) {
        Resolved::Found(s, o) => (s, o),
        Resolved::Failed(r) => return r,
    };
    let site_name = site.name.clone();
    if !op.read_only {
        return CallResult::failed(
            Class::Refused,
            "healing a write is validated by performing it".to_string(),
            Some(format!("writes heal during a real call: api-anything call {site_name} {op_name} ... --allow-writes")),
        );
    }
    let ctx = Ctx { site: site_name.clone(), args, opts: opts.clone(), max_tier: opts.max_tier.unwrap_or(3) };
    let tier: Tier = op.min_tier.max(remembered_tier(&site_name, &op.name).unwrap_or(1)).min(2);
    let vctx = ctx.clone();
    let validate: crate::heal::Validate = Arc::new(move |c: Operation| {
        let v = vctx.clone();
        Box::pin(async move { attempt(&v, &c, tier).await })
    });
    let h = heal_operation(&site_name, &op, &ctx.args, HealOptions { validate, fetcher: opts.fetcher.clone(), login_cookies: site.login_cookies.clone(), browser: ctx.max_tier > 1 }).await;
    match h {
        HealResult::Healed { attempt: a, strategy, .. } => {
            let mut r = success(&a, None, Some(true));
            r.strategy = Some(strategy);
            r
        }
        HealResult::Identical { .. } => CallResult { ok: true, class: Class::Ok, data: None, truncated: None, tier: None, healed: Some(false), ms: 0, reason: Some("the stored template is already current".to_string()), next: None, strategy: None },
        HealResult::Failed { reason, attempt: a, fallback, .. } => {
            let b = a.or(fallback);
            let class = b.as_ref().map(|b| b.class).unwrap_or(Class::Drift);
            let mut r = CallResult::failed(class, reason, next_for(class, &site_name, &op, b.as_ref()));
            r.tier = b.as_ref().map(|b| b.tier);
            r
        }
    }
}
