#[tokio::main]
async fn main() {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
    mollysocket::run_cli().await;
}
