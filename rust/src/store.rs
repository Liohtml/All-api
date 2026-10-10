//! Site specs (user dir wins over bundled), heal log, stale marks, and remembered tiers.
use crate::codec::{leaf_name, set_at, walk};
use crate::secrets::{ip_in, is_credential, scan_secrets};
use crate::session::{ensure_dir, home, load_session, read_json, safe_name, with_lock, write_private};
use crate::spec::{Site, parse_site};
use crate::util::{iso_at, json_pretty, now_ms};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

mod bundled {
    include!(concat!(env!("OUT_DIR"), "/bundled.rs"));
}

/// Where the community specs come from: the copies built into the binary, or a directory (tests,
/// and `API_ANYTHING_BUNDLED_DIR` for a checkout's `sites/`).
#[derive(Clone, Debug, PartialEq)]
pub enum Bundled {
    Embedded,
    Dir(PathBuf),
}

impl Bundled {
    pub fn default_source() -> Bundled {
        match std::env::var("API_ANYTHING_BUNDLED_DIR") {
            Ok(d) if !d.is_empty() => Bundled::Dir(PathBuf::from(d)),
            _ => Bundled::Embedded,
        }
    }
    fn names(&self) -> Vec<String> {
        match self {
            Bundled::Embedded => bundled::BUNDLED.iter().map(|(n, _, _)| n.to_string()).collect(),
            Bundled::Dir(d) => json_names(d),
        }
    }
    fn spec(&self, name: &str) -> Option<(String, String)> {
        match self {
            Bundled::Embedded => bundled::BUNDLED
                .iter()
                .find(|(n, _, _)| *n == name)
                .map(|(n, j, _)| (format!("<bundled>/{n}.json"), j.to_string())),
            Bundled::Dir(d) => {
                let p = d.join(format!("{name}.json"));
                fs::read_to_string(&p).ok().map(|t| (p.display().to_string(), t))
            }
        }
    }
    fn notes(&self, name: &str) -> Option<String> {
        match self {
            Bundled::Embedded => bundled::BUNDLED.iter().find(|(n, _, _)| *n == name).and_then(|(_, _, m)| m.map(|s| s.to_string())),
            Bundled::Dir(d) => fs::read_to_string(d.join(format!("{name}.md"))).ok(),
        }
    }
}

fn json_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else { return vec![] };
    entries
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.strip_suffix(".json").map(|s| s.to_string())
        })
        .collect()
}

pub fn user_sites_dir() -> PathBuf {
    home().join("sites")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    User,
    Bundled,
}

#[derive(Clone, Debug)]
pub struct Resolved {
    pub site: Site,
    pub source: Source,
    pub path: String,
}

pub fn load_site(name: &str) -> Result<Option<Resolved>> {
    load_site_from(name, &Bundled::default_source())
}

pub fn load_site_from(name: &str, bundled: &Bundled) -> Result<Option<Resolved>> {
    let name = safe_name(name)?;
    let user = user_sites_dir().join(format!("{name}.json"));
    let parse = |path: &str, text: &str| -> Result<Site> {
        let v: Value = serde_json::from_str(text).map_err(|e| anyhow!("{path}: {e}"))?;
        let mut site = parse_site(&v).map_err(|e| anyhow!("{path}: {e}"))?;
        // The file name is the site's address; saving under a different inner name would overwrite another site.
        site.name = name.clone();
        Ok(site)
    };
    if user.exists() {
        let text = fs::read_to_string(&user).map_err(|e| anyhow!("{}: {e}", user.display()))?;
        let path = user.display().to_string();
        return Ok(Some(Resolved { site: parse(&path, &text)?, source: Source::User, path }));
    }
    if let Some((path, text)) = bundled.spec(&name) {
        return Ok(Some(Resolved { site: parse(&path, &text)?, source: Source::Bundled, path }));
    }
    Ok(None)
}

/// A site's notes for whoever calls it: `<site>.md` beside its spec, the user's copy first, up to
/// its `## Maintainer notes` heading.
pub fn site_notes(name: &str) -> Option<String> {
    site_notes_from(name, &Bundled::default_source())
}

pub fn site_notes_from(name: &str, bundled: &Bundled) -> Option<String> {
    let name = safe_name(name).ok()?;
    let user = user_sites_dir().join(format!("{name}.md"));
    let text = fs::read_to_string(&user).ok().or_else(|| bundled.notes(&name))?;
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"(?im)^## Maintainer notes\s*$").unwrap());
    let for_callers = match re.find(&text) {
        Some(m) => &text[..m.start()],
        None => &text,
    };
    Some(for_callers.trim().to_string())
}

pub fn list_sites() -> Vec<String> {
    list_sites_from(&Bundled::default_source())
}

pub fn list_sites_from(bundled: &Bundled) -> Vec<String> {
    let mut names: HashSet<String> = json_names(&user_sites_dir()).into_iter().collect();
    names.extend(bundled.names());
    let mut out: Vec<String> = names.into_iter().collect();
    out.sort();
    out
}

/// Writes the user copy; a healed bundled spec becomes a user spec this way.
pub fn save_site(site: &Site) -> Result<String> {
    let path = user_sites_dir().join(format!("{}.json", safe_name(&site.name)?));
    let checked = parse_site(&serde_json::to_value(site)?)?;
    write_private(&path, &format!("{}\n", json_pretty(&serde_json::to_value(&checked)?, 2)))?;
    Ok(path.display().to_string())
}

/// Read-modify-write one site's user spec under its lock, so concurrent adds and heals never drop
/// each other's operations. f gets the current spec (user copy, else bundled), None for a new site.
pub fn update_site(name: &str, f: impl FnOnce(Option<Site>) -> Result<Site>) -> Result<String> {
    let file = user_sites_dir().join(format!("{}.json", safe_name(name)?));
    with_lock(&file, || {
        let current = load_site(name)?.map(|r| r.site);
        save_site(&f(current)?)
    })
}

/* ------------------------------------------------------------------ state */

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StaleMark {
    pub until: f64,
    pub reason: String,
    /// false when the site's own frontend did not answer either, so a tier-3 read is pointless
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier3: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct State {
    #[serde(default)]
    stale: indexmap::IndexMap<String, StaleMark>,
    #[serde(default)]
    tier: indexmap::IndexMap<String, u8>,
    #[serde(default)]
    healed_at: indexmap::IndexMap<String, f64>,
}

fn state_file() -> PathBuf {
    home().join("state.json")
}

fn key(site: &str, op: &str) -> String {
    format!("{site}/{op}")
}

fn load_state() -> State {
    // tier memory and stale marks are hints: a corrupt file is started over, never a failed call
    match read_json(&state_file()) {
        Ok(Some(v)) => serde_json::from_value(v).unwrap_or_default(),
        _ => State::default(),
    }
}

fn update_state(f: impl FnOnce(&mut State)) {
    // a read-only home loses tier memory and stale marks (hints), never the call's answer
    let _ = with_lock(&state_file(), || {
        let mut s = load_state();
        f(&mut s);
        write_private(&state_file(), &json_pretty(&serde_json::to_value(&s)?, 1))
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Strategy {
    Rescan,
    Recapture,
}

impl Strategy {
    pub fn name(self) -> &'static str {
        match self {
            Strategy::Rescan => "rescan",
            Strategy::Recapture => "recapture",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealEntry {
    pub site: String,
    pub op: String,
    pub strategy: Strategy,
    /// short human summary of what changed
    pub diff: String,
}

/// Append to heals.jsonl and remember when the op was last healed (for the heal-loop guard).
pub fn append_heal(entry: &HealEntry, now: f64) -> Result<()> {
    ensure_dir(&home())?;
    let file = home().join("heals.jsonl");
    let mut line = serde_json::Map::new();
    line.insert("at".into(), Value::String(iso_at(now)));
    if let Value::Object(o) = serde_json::to_value(entry)? {
        line.extend(o);
    }
    use std::io::Write;
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&file)?;
    writeln!(f, "{}", Value::Object(line))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&file, fs::Permissions::from_mode(0o600));
    }
    let k = key(&entry.site, &entry.op);
    update_state(|s| {
        s.healed_at.insert(k, now);
    });
    Ok(())
}

pub fn last_heal_at(site: &str, op: &str) -> Option<f64> {
    load_state().healed_at.get(&key(site, op)).copied()
}

pub fn mark_stale(site: &str, op: &str, reason: &str, ttl_ms: f64, now: f64, tier3: Option<bool>) {
    let k = key(site, op);
    let mark = StaleMark { until: now + ttl_ms, reason: reason.to_string(), tier3 };
    update_state(|s| {
        s.stale.insert(k, mark);
    });
}

pub const STALE_TTL_MS: f64 = 30.0 * 60_000.0;

pub fn clear_stale(site: &str, op: &str) {
    let k = key(site, op);
    update_state(|s| {
        s.stale.shift_remove(&k);
    });
}

/// Current stale mark for an op, if it has not expired.
pub fn stale_mark(site: &str, op: &str, now: f64) -> Option<StaleMark> {
    load_state().stale.get(&key(site, op)).filter(|m| m.until > now).cloned()
}

#[derive(Clone, Debug, Serialize)]
pub struct StaleEntry {
    pub site: String,
    pub op: String,
    pub until: f64,
    pub reason: String,
}

pub fn stale_list(now: f64) -> Vec<StaleEntry> {
    load_state()
        .stale
        .iter()
        .filter(|(_, m)| m.until > now)
        .map(|(k, m)| {
            let i = k.find('/').unwrap_or(k.len());
            StaleEntry { site: k[..i].to_string(), op: k.get(i + 1..).unwrap_or("").to_string(), until: m.until, reason: m.reason.clone() }
        })
        .collect()
}

/// The tier an op escalated to; None forgets it (the op's own minTier applies again).
pub fn remember_tier(site: &str, op: &str, tier: Option<u8>) {
    let k = key(site, op);
    update_state(|s| match tier {
        None => {
            s.tier.shift_remove(&k);
        }
        Some(t) => {
            s.tier.insert(k, t);
        }
    });
}

pub fn remembered_tier(site: &str, op: &str) -> Option<u8> {
    load_state().tier.get(&key(site, op)).copied()
}

/* ----------------------------------------------------------------- export */

pub struct Exported {
    pub spec: Site,
    pub secrets: Vec<String>,
    pub warnings: Vec<String>,
}

/// A shareable copy: example values stripped from the stored request (param slots become `{name}`,
/// or null in a typed JSON leaf) and from params (unless `keep_examples`), response shapes dropped,
/// then scanned against this machine's live session.
pub fn export_site(name: &str, keep_examples: bool) -> Result<Exported> {
    let Some(r) = load_site(name)? else { bail!("no site \"{name}\"") };
    let mut spec = r.site.clone();
    let mut allowed: HashSet<String> = HashSet::new();
    let mut named: Vec<(String, String)> = Vec::new();
    let mut ips: Vec<String> = Vec::new();
    for (i, op) in spec.operations.iter_mut().enumerate() {
        for slot in &op.slots {
            let Some(pname) = &slot.param else { continue };
            let Some(p) = op.params.iter().find(|x| &x.name == pname) else { continue };
            let typed = p.kind != crate::spec::ParamType::String
                && slot.template.is_none()
                && slot.at.last().map(|s| s.starts_with("json:")).unwrap_or(false);
            let value = if typed {
                Value::Null
            } else {
                Value::String(slot.template.clone().unwrap_or_else(|| format!("{{{}}}", p.name)))
            };
            if let Ok(req) = set_at(&op.request, &slot.at, &value) {
                op.request = req;
            }
        }
        if !keep_examples {
            for p in &mut op.params {
                p.example = None;
            }
        }
        op.response.shape = None;
        let public: HashSet<String> = op.public.clone().unwrap_or_default().iter().map(|h| h.to_lowercase()).collect();
        for h in &public {
            allowed.insert(format!("$.operations[{i}].request.headers.{h}"));
        }
        // Learning makes these refs; a literal one is a hand-written or older spec's credential.
        for leaf in walk(&op.request) {
            if !leaf.is_string() || leaf.container {
                continue;
            }
            let root = &leaf.at[0];
            let field = if let Some(h) = root.strip_prefix("header:") {
                format!("headers.{h}")
            } else if root.starts_with("path") || root.starts_with("query") {
                "url".to_string()
            } else {
                "body".to_string()
            };
            let path = format!("$.operations[{i}].request.{field}");
            let where_ = format!("$.operations[{i}].request {}", leaf.at.join(" > "));
            let n = leaf_name(&leaf.at);
            if !public.contains(&n.to_lowercase()) && is_credential(&n, &leaf.value) {
                named.push((
                    path,
                    format!("{where_} holds a literal credential ({n}); make it a session: ref, or list {n} in the op's public names if the site ships it to everyone"),
                ));
            }
            if let Some(ip) = ip_in(&leaf.value) {
                ips.push(format!("{where_} holds the IP address {ip} (likely yours, as the page reported it); blank it if the site does not need it"));
            }
        }
    }
    let scan = scan_secrets(&serde_json::to_value(&spec)?, &load_session(name)?, &allowed);
    // one finding per place: the exact live hit already names it
    let more: Vec<String> = named
        .into_iter()
        .filter(|(p, _)| !scan.secrets.iter().any(|s| s.starts_with(&format!("{p} "))))
        .map(|(_, why)| why)
        .collect();
    let mut secrets = scan.secrets;
    secrets.extend(more);
    let mut warnings = scan.warnings;
    warnings.extend(ips);
    Ok(Exported { spec, secrets, warnings })
}

pub fn now() -> f64 {
    now_ms()
}
