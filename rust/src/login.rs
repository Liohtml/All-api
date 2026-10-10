//! login = get a signed-in session for a site. By default it IMPORTS cookies from the user's
//! everyday browser; `--window` and `--cookies` are the other two sources. This module wires the
//! pure import (import.rs) to the session store and the persistent Chrome profile.
use crate::browser::{add_cookies_to_profile, chrome_available, clear_profile_cookies};
use crate::heal::profile_dir;
use crate::import::{ImportPin, ImportedSession, belongs, cookies_from_file, import_from_browsers, parse_pin};
use crate::session::{load_session, logged_in, safe_name, save_session, session_file, site_of, with_lock};
use crate::store::{list_sites, load_site};
use crate::types::StoredCookie;
use crate::util::{now_ms, parse_url, re};
use anyhow::{Result, bail};

/// The known site whose baseUrl is on this host (www. or not).
fn site_on_host(host: &str) -> Option<String> {
    let bare = |h: &str| h.to_lowercase().trim_start_matches("www.").to_string();
    list_sites().into_iter().find(|n| match load_site(n) {
        Ok(Some(r)) => parse_url(&r.site.base_url).map(|u| bare(u.host_str().unwrap_or("")) == bare(host)).unwrap_or(false),
        _ => false, // a corrupt spec is reported by the commands that use it
    })
}

pub struct LoginTarget {
    pub site: String,
    pub url: String,
    pub login_cookies: Option<Vec<String>>,
}

/// Turn a login target into { site, url, login_cookies }: a site name, a domain or a URL.
pub fn resolve_login_target(target: &str) -> Result<LoginTarget> {
    let mut url = target.to_string();
    if !re(r"(?i)^https?://").is_match(target) {
        let known = if crate::spec::site_name_ok(target) { load_site(target)? } else { None };
        if let Some(k) = known {
            return Ok(LoginTarget {
                site: k.site.name.clone(),
                url: k.site.base_url.clone(),
                login_cookies: k.site.login_cookies.clone(),
            });
        }
        if !re(r"(?i)^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(/.*)?$").is_match(target) {
            bail!("no site \"{target}\": give a site name from api-anything sites, a domain (example.com) or a URL");
        }
        url = format!("https://{target}");
    }
    let host = parse_url(&url).map(|u| u.host_str().unwrap_or("").to_lowercase()).unwrap_or_default();
    if let Some(name) = site_on_host(&host) {
        let s = load_site(&name)?.map(|r| r.site).expect("the site was listed");
        // a bare domain means the site itself; a full URL may name its sign-in page
        let u = if url == target { url } else { s.base_url.clone() };
        return Ok(LoginTarget { site: s.name.clone(), url: u, login_cookies: s.login_cookies.clone() });
    }
    Ok(LoginTarget { site: host.trim_start_matches("www.").to_string(), url, login_cookies: None })
}

#[derive(Default)]
pub struct ImportOptions {
    pub login_cookies: Option<Vec<String>>,
    /// "Chrome/Profile 1" or a session source "chrome:Profile 1"
    pub profile: Option<String>,
    /// a cookies.txt / JSON export, for servers/CI with no browser
    pub file: Option<String>,
    /// also inject into api-anything's Chrome profile (default true when Chrome is present)
    pub push_profile: bool,
}

impl ImportOptions {
    pub fn new() -> ImportOptions {
        ImportOptions { push_profile: true, ..Default::default() }
    }
}

fn for_site(c: &StoredCookie, url: &str) -> bool {
    parse_url(url).map(|u| belongs(&c.domain, &site_of(u.host_str().unwrap_or("")))).unwrap_or(false)
}

/// Import a session for `site` and save it. None when nothing was importable (the caller falls back to the window).
pub async fn import_session(site: &str, url: &str, o: ImportOptions) -> Result<Option<ImportedSession>> {
    let imported: Option<ImportedSession> = if let Some(file) = &o.file {
        let text = std::fs::read_to_string(file)?;
        let cookies: Vec<StoredCookie> = cookies_from_file(&text, url)?.into_iter().filter(|c| for_site(c, url)).collect();
        if cookies.is_empty() {
            None
        } else {
            Some(ImportedSession { cookies, source: "file".into(), browser: "file".into(), profile: file.clone(), name: None, email: None })
        }
    } else {
        let pin: Option<ImportPin> = o.profile.as_ref().map(|p| parse_pin(p));
        import_from_browsers(url, o.login_cookies.as_deref(), pin.as_ref())?
    };
    let Some(imported) = imported.filter(|i| !i.cookies.is_empty()) else { return Ok(None) };
    let file = session_file(site)?;
    let cookies = imported.cookies.clone();
    let source = imported.source.clone();
    with_lock(&file, || {
        let mut s = load_session(site)?;
        s.cookies = cookies;
        s.source = Some(source);
        save_session(site, &s)
    })?;
    if o.push_profile && chrome_available() {
        // an open Chrome, a locked profile: the jar still works for tier 1
        let _ = add_cookies_to_profile(&imported.cookies, &profile_dir()).await;
    }
    Ok(Some(imported))
}

/// The browser profile a human chose for this site ("chrome:Profile 1"), if its session came from one.
pub fn browser_source(site: &str) -> Result<Option<String>> {
    Ok(load_session(site)?.source.filter(|s| s != "window" && s != "file"))
}

/// Self-heal an imported session: re-import from the same browser profile once. No-op for "window" and "file" sources.
pub async fn reimport_if_browser(site: &str, url: &str, login_cookies: Option<&[String]>) -> bool {
    let Ok(Some(source)) = browser_source(site) else { return false };
    let pin = parse_pin(&source);
    let opts = ImportOptions {
        login_cookies: login_cookies.map(|l| l.to_vec()),
        profile: Some(format!("{}/{}", pin.browser.clone().unwrap_or_default(), pin.profile)),
        file: None,
        push_profile: true,
    };
    matches!(import_session(site, url, opts).await, Ok(Some(_)))
}

/// logout: clear the jar and this site's cookies in the profile.
pub async fn logout(site: &str) -> Result<()> {
    safe_name(site)?;
    let file = session_file(site)?;
    with_lock(&file, || save_session(site, &crate::session::Session::empty()))?;
    if chrome_available() {
        let _ = clear_profile_cookies(site, &profile_dir()).await;
    }
    Ok(())
}

/// Cookie NAMES only, for printing: values are never logged.
pub fn cookie_names(cookies: &[StoredCookie]) -> Vec<String> {
    let mut names: Vec<String> = cookies.iter().map(|c| c.name.clone()).collect();
    names.sort();
    names.dedup();
    names
}

pub fn is_logged_in(cookies: &[StoredCookie], login_cookies: Option<&[String]>) -> bool {
    logged_in(cookies, login_cookies, now_ms())
}
