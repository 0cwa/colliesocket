mod cli;
mod config;
mod db;
mod enrollment;
mod push;
mod push_store;
mod qrcode;
mod server;
mod utils;
mod vapid;
mod ws;

#[tokio::main]
async fn main() {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
    cli::cli().await;
}
