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
    /// Show local registration state without endpoint or keys.
    Status { account_id: String },
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
        EnrollmentCommand::Status { account_id } => crate::enrollment::status(account_id),
    }
}
