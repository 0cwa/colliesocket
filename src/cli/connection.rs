use crate::{config, db, push, push_store::PushStore, utils::post_allowed};
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand)]
pub enum ConnectionCommand {
    /// Add a legacy wake-only connection when explicitly enabled.
    Add {
        account_id: String,
        #[arg(value_parser=clap::value_parser!(u32).range(1..))]
        device_id: u32,
        password: String,
        endpoint: String,
    },
    /// List registration state without passwords, keys or endpoints.
    List {
        #[arg(short, long)]
        anonymized: bool,
    },
    /// Remove local state without unlinking the Signal device.
    Remove { account_id: String },
    /// Queue an encrypted test; explicit legacy mode sends only a generic wake.
    Ping { account_id: String },
}

pub async fn connection(command: &ConnectionCommand) {
    let result = match command {
        ConnectionCommand::Add {
            account_id,
            device_id,
            password,
            endpoint,
        } => add(account_id, *device_id, password, endpoint).await,
        ConnectionCommand::List { anonymized: _ } => PushStore::open(config::get_db())
            .and_then(|s| s.list_redacted())
            .map(|rows| json!({"encrypted_accounts":rows}))
            .map_err(|e| e.code()),
        ConnectionCommand::Remove { account_id } => PushStore::open(config::get_db())
            .and_then(|mut s| s.remove(account_id))
            .map(|removed| json!({"removed":removed,"signal_unlinked":false}))
            .map_err(|e| e.code()),
        ConnectionCommand::Ping { account_id } => ping(account_id).await,
    };
    crate::cli::print_result(result);
}
async fn add(
    account: &str,
    device: u32,
    password: &str,
    endpoint: &str,
) -> Result<serde_json::Value, &'static str> {
    if !config::legacy_wake_enabled() {
        return Err("legacy_disabled");
    }
    if push::enrolled(account)? {
        return Err("encryption_required");
    }
    if !config::is_uuid_valid(account) {
        return Err("invalid_enrollment");
    }
    if !config::is_endpoint_valid(endpoint).await {
        return Err("invalid_endpoint");
    }
    let co = db::Connection::new(account.into(), device, password.into(), endpoint.into());
    db::MollySocketDb::new()
        .map_err(|_| "state_unavailable")?
        .add(&co)
        .map_err(|_| "state_unavailable")?;
    if push::legacy_connection_is_current(&co)? {
        let url = url::Url::parse(endpoint).map_err(|_| "invalid_endpoint")?;
        // A provider failure is not an enrollment rollback or device unlink.
        if post_allowed::post_legacy_wake(url).await.is_err() {
            log::warn!("legacy_wake_failed");
        }
    }
    Ok(json!({"registered":true,"mode":"legacy_wake"}))
}
async fn ping(account: &str) -> Result<serde_json::Value, &'static str> {
    if push::enrolled(account)? {
        return push::enqueue(account, "test", None);
    }
    if !config::legacy_wake_enabled() {
        return Err("legacy_disabled");
    }
    let co = db::MollySocketDb::new()
        .map_err(|_| "state_unavailable")?
        .get(account)
        .map_err(|_| "not_found")?;
    if !push::legacy_connection_is_current(&co)? {
        return Err("encryption_required");
    }
    let url = url::Url::parse(&co.endpoint).map_err(|_| "invalid_endpoint")?;
    let response = post_allowed::post_legacy_wake(url)
        .await
        .map_err(|_| "state_unavailable")?;
    if !response.status().is_success() {
        return Err("state_unavailable");
    }
    Ok(json!({"provider_accepted":true}))
}
