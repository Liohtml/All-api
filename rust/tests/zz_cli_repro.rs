//! TEMPORARY: measures how often `capture` stalls on Page.navigate against the fixture. Deleted after use.
mod common;
use common::fixture::Fixture;

#[tokio::test]
async fn repro_capture_stall() {
    let chrome = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
    if !std::path::Path::new(chrome).exists() {
        return;
    }
    let f = Fixture::start().await;
    let home = tempfile::tempdir().unwrap();
    let mut fails = 0;
    for i in 0..12 {
        let path = ["/catalog", "/notice", "/account", "/no/such/page"][i % 4];
        let url = format!("{}{path}", f.url);
        let t = std::time::Instant::now();
        let o = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-anything"))
            .args(["capture", &url])
            .env("API_ANYTHING_HOME", home.path())
            .env("API_ANYTHING_CHROME", chrome)
            .env("API_ANYTHING_DEBUG", "1")
            .output()
            .await
            .unwrap();
        let out = String::from_utf8_lossy(&o.stdout);
        let ok = out.contains("\"next\"");
        if !ok {
            fails += 1;
        }
        eprintln!("run {i} {path}: {} in {:.1}s; stderr: {}", if ok { "ok" } else { "STALL" }, t.elapsed().as_secs_f64(), String::from_utf8_lossy(&o.stderr).trim());
        if !ok {
            eprintln!("  stdout: {}", out.trim());
        }
    }
    eprintln!("fails: {fails}/12");
}
