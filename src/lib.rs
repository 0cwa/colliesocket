//! CollieSocket's existing service modules behind a library boundary.
//!
//! The current public entry point is only for the command-line executable.
//! Configuration, logging, and service state still have process-wide lifetimes;
//! this is not yet an embeddable, restartable GUI service API. Keep credential
//! and configuration modules private while a separate host API is developed.

mod cli;
mod config;
mod control;
mod db;
mod enrollment;
mod push;
mod push_store;
mod qrcode;
mod server;
mod utils;
mod vapid;
mod ws;

#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzz_api;

/// Run the existing command-line interface once inside its Tokio runtime.
///
/// This parses process arguments, initializes the process logger and global
/// configuration, and may terminate the process on command or configuration
/// errors. The executable owns the runtime and its restrictive Unix umask.
/// Do not call this entry point from a Tauri command or other embedded host.
pub async fn run_cli() {
    cli::cli().await;
}
