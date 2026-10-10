//! Embed the bundled site specs (`../sites/*.json` and their `.md` notes) into the binary, so an
//! installed `api-anything` needs no files beside it.
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let sites = manifest.join("..").join("sites");
    println!("cargo:rerun-if-changed={}", sites.display());
    let mut entries: Vec<(String, PathBuf, Option<PathBuf>)> = Vec::new();
    if let Ok(dir) = fs::read_dir(&sites) {
        for e in dir.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "json").unwrap_or(false) {
                let name = p.file_stem().unwrap().to_string_lossy().to_string();
                let md = p.with_extension("md");
                println!("cargo:rerun-if-changed={}", p.display());
                println!("cargo:rerun-if-changed={}", md.display());
                entries.push((name, p.clone(), if md.exists() { Some(md) } else { None }));
            }
        }
    }
    entries.sort();
    let mut out = String::from("/// (site name, spec JSON, notes) for every bundled site.\npub static BUNDLED: &[(&str, &str, Option<&str>)] = &[\n");
    for (name, json, md) in entries {
        let md = match md {
            Some(m) => format!("Some(include_str!({:?}))", m.canonicalize().unwrap().display().to_string()),
            None => "None".to_string(),
        };
        out.push_str(&format!("    ({:?}, include_str!({:?}), {}),\n", name, json.canonicalize().unwrap().display().to_string(), md));
    }
    out.push_str("];\n");
    let dest = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bundled.rs");
    fs::write(dest, out).unwrap();
}
