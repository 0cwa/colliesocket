use crate::{enrollment, pairing};
use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
pub(crate) enum PairingIntent {
    PairBridge,
    AddReceiver,
}

#[derive(Subcommand)]
pub(crate) enum PairingCommand {
    /// Start a local pairing session and print the QR offer as JSON.
    Create {
        #[arg(long)]
        host_label: String,
        #[arg(long)]
        provider_origin: Option<String>,
        #[arg(long, default_value_t = pairing::DEFAULT_TTL)]
        ttl_seconds: i64,
        #[arg(long, value_enum, default_value = "pair_bridge")]
        intent: PairingIntent,
        /// Also render the public offer as a terminal QR on stderr.
        #[arg(long)]
        qr: bool,
    },
    /// Show the state and expiry of a local pairing session.
    Status { session_id: String },
    /// Cancel an active local pairing session.
    Cancel { session_id: String },
    /// Accept a sealed request through the protected service account.
    Submit {
        #[arg(long, required_unless_present = "stdin", conflicts_with = "stdin")]
        file: Option<PathBuf>,
        #[arg(long, required_unless_present = "file")]
        stdin: bool,
    },
}

pub(super) async fn run(command: &PairingCommand) -> Result<serde_json::Value, enrollment::Error> {
    match command {
        PairingCommand::Create {
            host_label,
            provider_origin,
            ttl_seconds,
            intent,
            qr,
        } => {
            let intent = match intent {
                PairingIntent::PairBridge => pairing::Intent::PairBridge,
                PairingIntent::AddReceiver => pairing::Intent::AddReceiver,
            };
            let offer =
                pairing::create(intent, host_label, provider_origin.as_deref(), *ttl_seconds)?;
            let offer =
                serde_json::to_value(offer).map_err(|_| enrollment::Error("state_unavailable"))?;
            if *qr {
                eprint!(
                    "{}",
                    crate::qrcode::text_to_printable_qr(&offer.to_string())
                );
            }
            Ok(offer)
        }
        PairingCommand::Status { session_id } => pairing::status(session_id, false),
        PairingCommand::Cancel { session_id } => pairing::status(session_id, true),
        PairingCommand::Submit { file, stdin: _ } => {
            let data = match file {
                Some(path) => enrollment::read_protected_file(path, pairing::MAX_REQUEST_BYTES)?,
                None => enrollment::read_bounded_stdin(pairing::MAX_REQUEST_BYTES)?,
            };
            pairing::submit(&data).await
        }
    }
}
