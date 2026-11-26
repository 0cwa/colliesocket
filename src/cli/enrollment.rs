use clap::Subcommand;
use std::path::PathBuf;
#[derive(Subcommand)]
pub enum EnrollmentCommand {
    /// Import through the authenticated service account, never a public edge.
    Import {
        #[arg(long, required_unless_present = "stdin", conflicts_with = "stdin")]
        file: Option<PathBuf>,
        #[arg(long, required_unless_present = "file")]
        stdin: bool,
    },
    /// List local registrations, or show encrypted status for one account.
    Status { account_id: Option<String> },
    /// Revoke one encrypted receiver without unlinking the bridge.
    Revoke {
        #[arg(long)]
        account_id: String,
        #[arg(long)]
        receiver_id: String,
    },
}
pub async fn run(
    command: &EnrollmentCommand,
) -> Result<serde_json::Value, crate::enrollment::Error> {
    match command {
        EnrollmentCommand::Import { file, stdin: _ } => {
            let bytes = match file {
                Some(path) => crate::enrollment::read_protected_file(
                    path,
                    crate::enrollment::MAX_IMPORT_BYTES,
                )?,
                None => crate::enrollment::read_stdin()?,
            };
            crate::enrollment::import(&bytes).await
        }
        EnrollmentCommand::Revoke {
            account_id,
            receiver_id,
        } => crate::enrollment::revoke(account_id, receiver_id),
        EnrollmentCommand::Status { account_id } => {
            crate::enrollment::status(account_id.as_deref())
        }
    }
}
