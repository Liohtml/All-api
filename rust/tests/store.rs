mod common;
use api_anything::secrets::scan_secrets;
use api_anything::session::save_session;
use api_anything::spec::Site;
use api_anything::store::{
    Bundled, HealEntry, Source, Strategy, append_heal, clear_stale, export_site, last_heal_at,
    list_sites_from, load_site, load_site_from, mark_stale, remember_tier, remembered_tier,
    save_site, site_notes_from, stale_list, stale_mark,
};
use common::{Home, j, site};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// Every test here sets API_ANYTHING_HOME (one process-wide variable), so they take turns like node's
/// sequential tests in one file do.
static HOME: Mutex<()> = Mutex::new(());

struct Fresh {
    _guard: MutexGuard<'static, ()>,
    home: Home,
    bundled_dir: tempfile::TempDir,
}

impl Fresh {
    fn home(&self) -> &Path {
        self.home.path()
    }
    fn bundled(&self) -> Bundled {
        Bundled::Dir(self.bundled_dir.path().to_path_buf())
    }
    fn write_bundled(&self, name: &str, text: &str) {
        fs::write(self.bundled_dir.path().join(name), text).unwrap();
    }
    fn write_user(&self, name: &str, text: &str) {
        fs::create_dir_all(self.home().join("sites")).unwrap();
        fs::write(self.home().join("sites").join(name), text).unwrap();
    }
}

fn fresh() -> Fresh {
    let guard = HOME.lock().unwrap_or_else(|e| e.into_inner());
    Fresh {
        _guard: guard,
        home: Home::new(),
        bundled_dir: tempfile::tempdir().unwrap(),
    }
}

/// The TS `site(description)` literal, as JSON so a test can add or rename fields before parsing.
fn site_json(description: &str) -> Value {
    json!({
        "name": "demo",
        "baseUrl": "https://demo.test",
        "description": description,
        "operations": [
            {
                "name": "get",
                "request": {"method": "GET", "url": "https://demo.test/a", "headers": {}},
                "slots": [],
                "volatile": [],
                "trigger": {"url": "https://demo.test/"},
                "match": {},
                "response": {"format": "json"},
                "params": [],
                "readOnly": true,
                "minTier": 1,
                "learnedLoggedIn": false,
            },
        ],
    })
}

fn demo(description: &str) -> Site {
    site(site_json(description))
}

fn with(mut v: Value, over: Value) -> Value {
    if let (Value::Object(b), Value::Object(o)) = (&mut v, over) {
        for (k, x) in o {
            b.insert(k, x);
        }
    }
    v
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn resolution_user_copy_wins_over_bundled_save_writes_a_user_copy() {
    use std::os::unix::fs::PermissionsExt;
    let f = fresh();
    f.write_bundled(
        "demo.json",
        &with(site_json("bundled"), json!({"unknownField": 1})).to_string(),
    );
    f.write_bundled(
        "other.json",
        &with(site_json("other"), json!({"name": "other"})).to_string(),
    );
    let b = load_site_from("demo", &f.bundled()).unwrap().unwrap();
    assert_eq!(b.source, Source::Bundled);
    assert_eq!(b.site.description.as_deref(), Some("bundled"));
    assert_eq!(
        j(&b.site).get("unknownField"),
        None,
        "unknown fields stripped"
    );

    let path = save_site(&demo("healed")).unwrap();
    assert_eq!(Path::new(&path), f.home().join("sites").join("demo.json"));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let u = load_site_from("demo", &f.bundled()).unwrap().unwrap();
    assert_eq!(u.source, Source::User);
    assert_eq!(u.site.description.as_deref(), Some("healed"));
    assert_eq!(list_sites_from(&f.bundled()), vec!["demo", "other"]);
    assert!(load_site_from("missing", &f.bundled()).unwrap().is_none());
    let err = load_site_from("../x", &f.bundled())
        .unwrap_err()
        .to_string();
    assert!(err.contains("invalid site name"), "{err}");

    f.write_user("bad.json", &json!({"name": "bad"}).to_string());
    let err = load_site_from("bad", &f.bundled()).unwrap_err().to_string();
    assert!(err.contains("bad.json: invalid site spec"), "{err}");
}

#[test]
fn site_notes_stop_at_the_maintainer_notes_heading_the_users_copy_wins() {
    let f = fresh();
    f.write_bundled(
        "demo.md",
        "Airport codes only.\n\n- First page only.\n\n## Maintainer notes\n\nVerified 2026-09-27.\n\n## How it works\n\nA POST.\n",
    );
    assert_eq!(
        site_notes_from("demo", &f.bundled()).as_deref(),
        Some("Airport codes only.\n\n- First page only.")
    );
    // only that heading on a line of its own ends the notes
    let whole = "See ## Maintainer notes below.\n\n## Maintainer notes for callers\n\n## Known limits\n\nFirst page only.";
    f.write_bundled("whole.md", &format!("{whole}\n"));
    assert_eq!(
        site_notes_from("whole", &f.bundled()).as_deref(),
        Some(whole)
    );
    f.write_bundled(
        "internal.md",
        "## Maintainer notes\n\nNothing for callers.\n",
    );
    assert_eq!(
        site_notes_from("internal", &f.bundled()).as_deref(),
        Some("")
    );
    assert_eq!(site_notes_from("missing", &f.bundled()), None);

    // a user's own file, with the heading capitalized another way
    f.write_user(
        "demo.md",
        "Mine.\n\n## Maintainer Notes\n\nMy own history.\n",
    );
    assert_eq!(
        site_notes_from("demo", &f.bundled()).as_deref(),
        Some("Mine.")
    );
}

#[test]
fn heal_log_appends_jsonl_and_records_the_heal_time() {
    let f = fresh();
    let entry = |strategy: Strategy, diff: &str| HealEntry {
        site: "x".into(),
        op: "getUser".into(),
        strategy,
        diff: diff.into(),
    };
    append_heal(&entry(Strategy::Rescan, "queryId A -> B"), 1000.0).unwrap();
    append_heal(&entry(Strategy::Recapture, "header added"), 2000.0).unwrap();
    let text = fs::read_to_string(f.home().join("heals.jsonl")).unwrap();
    let lines: Vec<Value> = text
        .trim()
        .split('\n')
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["strategy"], json!("recapture"));
    assert_eq!(last_heal_at("x", "getUser"), Some(2000.0));
    assert_eq!(last_heal_at("x", "other"), None);
}

#[test]
fn stale_marks_expire_after_their_ttl_and_carry_a_reason_tiers_are_remembered() {
    let _f = fresh();
    mark_stale(
        "x",
        "getUser",
        "healed twice in 10 min",
        30.0 * 60_000.0,
        0.0,
        None,
    );
    let m = stale_mark("x", "getUser", 1000.0).unwrap();
    assert_eq!(
        (m.until, m.reason.as_str(), m.tier3),
        (30.0 * 60_000.0, "healed twice in 10 min", None)
    );
    assert!(stale_mark("x", "getUser", 30.0 * 60_000.0).is_none());
    let list = stale_list(1000.0);
    assert_eq!(list.len(), 1);
    let e = &list[0];
    assert_eq!(
        (e.site.as_str(), e.op.as_str(), e.until, e.reason.as_str()),
        ("x", "getUser", 30.0 * 60_000.0, "healed twice in 10 min")
    );
    clear_stale("x", "getUser");
    assert!(stale_mark("x", "getUser", 1000.0).is_none());

    assert_eq!(remembered_tier("x", "getUser"), None);
    remember_tier("x", "getUser", Some(2));
    assert_eq!(remembered_tier("x", "getUser"), Some(2));
}

#[test]
fn secret_scan_exact_live_values_are_secrets_heuristics_only_warn_and_url_paths_do_not_trip_them() {
    let mut sid = common::cookie("sid", "\"abc123secret\"", "x.test");
    sid.http_only = true;
    sid.secure = true;
    let session = common::session(vec![sid], &[("authorization", "Bearer zzzzzzzz")]);
    let spec = json!({
        "url": "https://x.test/api/graphql/SfvBzVjFV1WLibrBOSdD6w/UserByScreenNameAndMore/extra/segments",
        "h": {"a": "abc123secret", "b": "eyJhbGciOi.eyJzdWIiOiIx.c2lnbmF0dXJl"},
    });
    let r = scan_secrets(&spec, &session, &HashSet::new());
    assert_eq!(r.secrets, vec!["$.h.a holds the live cookie sid"]);
    assert_eq!(
        r.warnings,
        vec!["$.h.b looks like a JWT (eyJhbGciOi.eyJzdWIiOiIx....); check it is public"]
    );
}

#[test]
fn a_specs_file_name_is_its_name_so_saving_never_overwrites_another_sites_file() {
    let f = fresh();
    f.write_user(
        "work.json",
        &with(site_json("copy"), json!({"name": "prod"})).to_string(),
    );
    f.write_user("prod.json", &site_json("prod").to_string());
    let r = load_site("work").unwrap().unwrap();
    assert_eq!(r.site.name, "work");
    save_site(&r.site).unwrap();
    assert_eq!(
        read_json(&f.home().join("sites").join("prod.json"))["description"],
        json!("prod")
    );
}

#[test]
fn export_shapes_and_typed_example_values_stripped_examples_kept_on_request_public_headers_allowed()
{
    let _f = fresh();
    let op = json!({
        "name": "get",
        "request": {
            "method": "POST",
            "url": "https://demo.test/a",
            "headers": {"authorization": "Bearer PUBLICBEARERPUBLICBEARER"},
            "body": "{\"id\":1234567,\"q\":\"alpha\"}",
        },
        "slots": [
            {"param": "id", "at": ["body", "json:/id"]},
            {"param": "q", "at": ["body", "json:/q"]},
        ],
        "params": [
            {"name": "id", "type": "number", "required": true, "example": 1234567},
            {"name": "q", "type": "string", "required": true, "example": "alpha"},
        ],
        "volatile": [],
        "trigger": {"url": "https://demo.test/"},
        "match": {},
        "response": {"format": "json", "shape": {"viewer.accounts.jane.doe@corp.example": "object"}},
        "readOnly": true,
        "minTier": 1,
        "learnedLoggedIn": false,
        "public": ["authorization"],
    });
    let spec = with(site_json("x"), json!({"operations": [op.clone()]}));
    save_site(&site(spec.clone())).unwrap();
    save_session(
        "demo",
        &common::session(
            vec![],
            &[("authorization", "Bearer PUBLICBEARERPUBLICBEARER")],
        ),
    )
    .unwrap();
    let r = export_site("demo", false).unwrap();
    let o = &r.spec.operations[0];
    assert_eq!(
        o.request.body.as_deref(),
        Some("{\"id\":null,\"q\":\"{q}\"}")
    );
    assert_eq!(o.response.shape, None);
    assert_eq!(o.params[0].example, None);
    assert_eq!(
        r.secrets,
        Vec::<String>::new(),
        "the public header is allowed"
    );
    assert_eq!(
        export_site("demo", true).unwrap().spec.operations[0].params[1].example,
        Some(json!("alpha"))
    );
    let mut no_public = op;
    no_public.as_object_mut().unwrap().remove("public");
    save_site(&site(with(spec, json!({"operations": [no_public]})))).unwrap();
    assert_eq!(
        export_site("demo", false).unwrap().secrets,
        vec![
            "$.operations[0].request.headers.authorization holds the live session value authorization"
        ]
    );
}
