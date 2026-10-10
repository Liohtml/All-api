//! The `api-anything` command.
fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("a tokio runtime");
    let code = rt.block_on(api_anything::cli::main_with(argv));
    // a Chrome left running, or a pending timer, must not hold the process
    rt.shutdown_timeout(std::time::Duration::from_millis(500));
    std::process::exit(code);
}
