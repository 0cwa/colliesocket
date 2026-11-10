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

/// Dependency diagnostics can contain endpoints, headers, and Signal frames.
/// Enforce the namespace here as well as in the filter: env_filter matches
/// prefixes, so a directive for `mollysocket` also matches `mollysocket_extra`.
struct ApplicationLogger {
    inner: env_logger::Logger,
}

impl log::Log for ApplicationLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        application_log_target(metadata.target()) && self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            self.inner.log(record);
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

fn application_log_target(target: &str) -> bool {
    if target == "mollysocket" {
        return true;
    }
    let Some(path) = target.strip_prefix("mollysocket::") else {
        return false;
    };
    path.split("::").all(|component| {
        let mut bytes = component.bytes();
        bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

/// Accept plain levels and this application's module selectors only. Never
/// pass RUST_LOG to env_logger's parser: a longer dependency selector overrides
/// a later `dependency=off` directive. Ignore invalid/foreign directives without
/// printing their contents. Regex filters and foreign namespaces are unsupported.
fn application_log_builder(
    specification: Option<&str>,
    verbosity: u8,
    default_level: log::LevelFilter,
) -> env_logger::Builder {
    use log::LevelFilter;

    let mut application_level = default_level;
    let mut modules = Vec::new();
    for directive in specification.unwrap_or_default().split(',').map(str::trim) {
        if let Some((module, level)) = directive.split_once('=') {
            let module = module.trim();
            if !application_log_target(module) {
                continue;
            }
            let level = level.trim();
            let level = if level.is_empty() {
                LevelFilter::Trace
            } else if let Ok(level) = level.parse::<LevelFilter>() {
                level
            } else {
                continue;
            };
            modules.push((module, level));
        } else if let Ok(level) = directive.parse::<LevelFilter>() {
            application_level = level;
        } else if application_log_target(directive) {
            modules.push((directive, LevelFilter::Trace));
        }
    }
    let verbosity_level = match verbosity {
        0 => LevelFilter::Off,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    let mut builder = env_logger::Builder::new();
    builder
        .filter_level(LevelFilter::Off)
        .filter_module("mollysocket", application_level.max(verbosity_level));
    for (module, level) in modules {
        builder.filter_module(module, level);
    }
    builder
}

pub async fn cli() {
    let cli = Cli::parse();
    let default_level = match &cli.command {
        Command::Server {} | Command::Vapid { .. } => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };
    let specification = env::var("RUST_LOG").ok();
    let mut builder = application_log_builder(specification.as_deref(), cli.verbose, default_level);
    let style = match env::var("RUST_LOG_STYLE").as_deref() {
        Ok("always") => env_logger::WriteStyle::Always,
        Ok("never") => env_logger::WriteStyle::Never,
        _ => env_logger::WriteStyle::Auto,
    };
    builder.write_style(style);
    let logger = ApplicationLogger {
        inner: builder.build(),
    };
    let maximum_level = logger.inner.filter();
    log::set_boxed_logger(Box::new(logger)).expect("logger initialization failed");
    log::set_max_level(maximum_level);

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

#[cfg(test)]
mod tests {
    use super::*;
    use log::{Level, LevelFilter, Log, Metadata, Record};
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    fn logger(specification: Option<&str>, verbosity: u8) -> ApplicationLogger {
        ApplicationLogger {
            inner: application_log_builder(specification, verbosity, LevelFilter::Error).build(),
        }
    }

    fn enabled(logger: &ApplicationLogger, target: &str, level: Level) -> bool {
        logger.enabled(&Metadata::builder().target(target).level(level).build())
    }

    #[test]
    fn specific_dependency_selectors_cannot_enable_any_dependency_level() {
        let specifications = [
            "trace",
            "trace,mollysocket=trace,reqwest::async_impl::client=trace,tungstenite::handshake::client=trace",
            "mollysocket::ws=trace,hyper::proto::h1::io=trace,rustls::client::hs=trace",
            "mollysocket=debug,rocket::server=trace,trust_dns_resolver::name_server=trace",
            "mollysocket_extra=trace,mollysocketx::client=trace,=trace,malformed/SECRET",
        ];
        for specification in specifications {
            let logger = logger(Some(specification), 3);
            for target in [
                "reqwest::async_impl::client",
                "tungstenite::handshake::client",
                "tungstenite::protocol",
                "hyper::proto::h1::io",
                "hyper_util::client::legacy::connect::http",
                "h2::proto::streams",
                "rustls::client::hs",
                "tokio_tungstenite::compat",
                "trust_dns_resolver::name_server",
                "trust_dns_proto::rr",
                "rocket::server",
                "colliesocket_push",
                "mollysocket_extra::client",
                "mollysocketx::client",
                "mollysocket::",
                "mollysocket::bad\nmodule",
            ] {
                for level in [
                    Level::Error,
                    Level::Warn,
                    Level::Info,
                    Level::Debug,
                    Level::Trace,
                ] {
                    assert!(
                        !enabled(&logger, target, level),
                        "dependency target enabled: {target}"
                    );
                }
            }
        }
    }

    #[test]
    fn plain_levels_and_application_module_filters_remain_usable() {
        let trace = logger(Some("trace"), 0);
        assert!(enabled(&trace, "mollysocket", Level::Trace));
        assert!(enabled(&trace, "mollysocket::cli", Level::Trace));
        let scoped = logger(
            Some("off,mollysocket=info,mollysocket::ws=trace,mollysocket::ws::tls=off"),
            0,
        );
        assert!(enabled(&scoped, "mollysocket::cli", Level::Info));
        assert!(!enabled(&scoped, "mollysocket::cli", Level::Debug));
        assert!(enabled(
            &scoped,
            "mollysocket::ws::signalwebsocket",
            Level::Trace
        ));
        assert!(!enabled(&scoped, "mollysocket::ws::tls", Level::Error));
        let shorthand = logger(Some("mollysocket::push"), 0);
        assert!(enabled(&shorthand, "mollysocket::push", Level::Trace));
        assert!(!enabled(&shorthand, "mollysocket::cli", Level::Info));
        assert!(!enabled(
            &logger(Some("OFF"), 0),
            "mollysocket::cli",
            Level::Error
        ));
    }

    #[test]
    fn verbosity_controls_application_default_without_losing_explicit_module_filters() {
        let default = logger(None, 0);
        assert!(enabled(&default, "mollysocket::server", Level::Error));
        assert!(!enabled(&default, "mollysocket::server", Level::Info));
        for (verbosity, expected) in [(1, Level::Info), (2, Level::Debug), (3, Level::Trace)] {
            let logger = logger(Some("warn,reqwest::connect=trace"), verbosity);
            assert!(enabled(&logger, "mollysocket::server", expected));
        }
        assert!(enabled(
            &logger(Some("trace"), 1),
            "mollysocket::server",
            Level::Trace
        ));
        assert!(!enabled(
            &logger(Some("mollysocket::ws=off"), 3),
            "mollysocket::ws",
            Level::Error
        ));
    }

    #[test]
    fn direct_dependency_records_do_not_reach_the_output_writer() {
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut builder = application_log_builder(
            Some("trace,tungstenite::handshake::client=trace,mollysocket_extra=trace"),
            0,
            LevelFilter::Info,
        );
        builder.target(env_logger::Target::Pipe(Box::new(Capture(output.clone()))));
        builder.format(|writer, record| writeln!(writer, "{}", record.args()));
        let logger = ApplicationLogger {
            inner: builder.build(),
        };
        for target in [
            "tungstenite::handshake::client",
            "mollysocket_extra::client",
        ] {
            logger.log(
                &Record::builder()
                    .target(target)
                    .level(Level::Trace)
                    .args(format_args!("SYNTHETIC-CREDENTIAL-REDACTION-CANARY"))
                    .build(),
            );
        }
        logger.log(
            &Record::builder()
                .target("mollysocket::cli")
                .level(Level::Info)
                .args(format_args!("application_log_available"))
                .build(),
        );
        logger.flush();
        assert_eq!(&*output.lock().unwrap(), b"application_log_available\n");
    }
}
