use clap::Subcommand;
use serde_json::{json, Value};
#[derive(Subcommand)]
pub enum PushCommand {
    Test {
        account_id: String,
    },
    Wake {
        account_id: String,
    },
    Drain {
        #[arg(long, required = true)]
        once: bool,
    },
}
pub async fn run(command: &PushCommand) -> Result<Value, &'static str> {
    match command {
        PushCommand::Test { account_id } => crate::push::enqueue(account_id, "test", None),
        PushCommand::Wake { account_id } => crate::push::enqueue(account_id, "wake", None),
        PushCommand::Drain { once: _ } => Ok(json!({"processed":crate::push::drain_once().await?})),
    }
}
