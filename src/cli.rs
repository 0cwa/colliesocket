use clap::{ArgAction, Parser, Subcommand};
use qrcode::QrcodeCommand;
use std::{env, path::PathBuf};
use vapid::VapidCommand;

use crate::cli::{connection::ConnectionCommand, test::TestCommand};
use crate::config;

mod connection;
mod enrollment;
mod push;
mod qrcode;
mod server;
mod test;
mod vapid;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(infer_subcommands = true)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Verbosity level
    #[arg(short, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Protected encrypted enrollment and key updates.
    Enrollment {
        #[command(subcommand)]
        command: enrollment::EnrollmentCommand,
    },
    /// Queue and dispatch encrypted events.
    Push {
        #[command(subcommand)]
        command: push::PushCommand,
    },
    /// Apply transactional schema migrations.
    Migrate {},
    /// Probe private loopback readiness.
    Ready {},
    /// Run webserver and websockets
    Server {},

    /// Generate and test VAPID keys
    Vapid {
        #[command(subcommand)]
        command: VapidCommand,
    },

    /// Print mollysocket link URL and show the associated QR code
    QRCode {
        #[command(subcommand)]
        command: QrcodeCommand,
    },

    /// Add, remove and list connections
    Connection {
        #[command(subcommand)]
        command: ConnectionCommand,
    },

    /// Test account and endpoint validity
    Test {
        #[command(subcommand)]
        command: TestCommand,
    },
}

pub async fn cli() {
    let cli = Cli::parse();

    match cli.verbose {
        0 => (),
        1 => match env::var("RUST_LOG") {
            Ok(v) if (v.as_str() == "trace" || v.as_str() == "debug") => (),
            _ => env::set_var("RUST_LOG", "info"),
        },
        2 => match env::var("RUST_LOG") {
            Ok(v) if (v.as_str() == "trace") => (),
            _ => env::set_var("RUST_LOG", "debug"),
        },
        _ => env::set_var("RUST_LOG", "trace"),
    }

    match &cli.command {
        Command::Server {} => (),
        Command::Vapid { .. } => (),
        _ => {
            if env::var("RUST_LOG").is_err() {
                env::set_var("RUST_LOG", "info");
            }
        }
    }
    let mut logger = env_logger::Builder::from_env(env_logger::Env::default());
    // Dependency trace output can contain endpoints, headers and wire frames.
    for module in [
        "reqwest",
        "hyper",
        "hyper_util",
        "h2",
        "rustls",
        "tungstenite",
        "tokio_tungstenite",
        "trust_dns_resolver",
        "trust_dns_proto",
    ] {
        logger.filter_module(module, log::LevelFilter::Off);
    }
    logger
        .filter_module("rocket", log::LevelFilter::Warn)
        .init();

    log::debug!("env_logger initialized");

    config::load_config(cli.config);

    match &cli.command {
        Command::Server {} => server::server().await,
        Command::QRCode { command } => qrcode::qrcode(command),
        Command::Connection { command } => connection::connection(command).await,
        Command::Test { command } => test::test(command).await,
        Command::Vapid { command } => vapid::vapid(command),
        Command::Enrollment { command } => {
            print_result(enrollment::run(command).await.map_err(|e| e.0))
        }
        Command::Push { command } => print_result(push::run(command).await),
        Command::Migrate {} => print_result(
            crate::push_store::PushStore::open(config::get_db())
                .map(|_| serde_json::json!({"schema_version":2}))
                .map_err(|e| e.code()),
        ),
        Command::Ready {} => print_result(
            crate::server::ready::probe()
                .await
                .map(|_| serde_json::json!({"ready":true})),
        ),
    }
}

pub fn print_result(result: Result<serde_json::Value, &'static str>) {
    match result {
        Ok(value) => println!("{value}"),
        Err(code) => {
            eprintln!("{}", serde_json::json!({"error":code}));
            std::process::exit(1);
        }
    }
}
