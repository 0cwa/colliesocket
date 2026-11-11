//! Enrollment-v2 control blobs carried in the CollieSocket device's Signal copy.
//! Outer Signal sender/type metadata is not an authentication boundary.
use crate::{
    config,
    db::Connection,
    push,
    push_store::{ControlSnapshot, PushStore, Subscription, MAX_JSON_INTEGER},
};
use openssl::symm::{decrypt_aead, Cipher};
use serde::{Deserialize, Serialize};

pub(crate) const MAGIC: &[u8; 21] = b"CollieSocket-Control\0";
const VERSION: u8 = 2;
const HEADER_BYTES: usize = MAGIC.len() + 1 + 8;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MIN_BLOB_BYTES: usize = HEADER_BYTES + NONCE_BYTES + TAG_BYTES;
pub(crate) const MAX_BLOB_BYTES: usize = 4096;
const MAX_PLAINTEXT_BYTES: usize = 3072;
pub(crate) const CONFIRMATION_INTERVAL: i64 = 30;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlUpdate {
    pub(crate) endpoint: String,
    pub(crate) p256dh: String,
    pub(crate) auth: String,
}

pub(crate) struct AuthenticatedUpdate {
    pub(crate) epoch: u64,
    pub(crate) digest: String,
    pub(crate) update: ControlUpdate,
}

pub(crate) enum ControlResult {
    Applied { endpoint: String },
    Replayed { endpoint: String },
    Rejected,
}

impl std::fmt::Debug for ControlUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ControlUpdate([REDACTED])")
    }
}
impl std::fmt::Debug for AuthenticatedUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticatedUpdate([REDACTED])")
    }
}
impl std::fmt::Debug for ControlResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Applied { .. } => "Applied([REDACTED])",
            Self::Replayed { .. } => "Replayed([REDACTED])",
            Self::Rejected => "Rejected",
        })
    }
}

pub(crate) fn is_control(content: &[u8]) -> bool {
    content.starts_with(MAGIC)
}

fn aad(header: &[u8], account: &str, device_id: u32) -> Option<Vec<u8>> {
    if account.len() != 36 || !(2..=2_147_483_647).contains(&device_id) {
        return None;
    }
    let mut hex = String::with_capacity(32);
    for (offset, byte) in account.bytes().enumerate() {
        if matches!(offset, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
        } else if byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) {
            hex.push(char::from(byte));
        } else {
            return None;
        }
    }
    let mut result = Vec::with_capacity(50);
    result.extend_from_slice(header);
    for i in (0..32).step_by(2) {
        result.push(u8::from_str_radix(&hex[i..i + 2], 16).ok()?);
    }
    result.extend_from_slice(&device_id.to_be_bytes());
    Some(result)
}

pub(crate) fn authenticate(
    content: &[u8],
    snapshot: &ControlSnapshot,
) -> Option<AuthenticatedUpdate> {
    if !is_control(content)
        || !(MIN_BLOB_BYTES..=MAX_BLOB_BYTES).contains(&content.len())
        || content[MAGIC.len()] != VERSION
        || content.len() - MIN_BLOB_BYTES > MAX_PLAINTEXT_BYTES
    {
        return None;
    }
    let epoch = u64::from_be_bytes(content[MAGIC.len() + 1..HEADER_BYTES].try_into().ok()?);
    if !(1..=MAX_JSON_INTEGER).contains(&epoch) {
        return None;
    }
    let associated = aad(
        &content[..HEADER_BYTES],
        &snapshot.account_id,
        snapshot.device_id,
    )?;
    let ciphertext_end = content.len() - TAG_BYTES;
    // decrypt_aead returns plaintext only after GCM tag verification succeeds.
    // Never parse or use plaintext from a failed authentication attempt.
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &snapshot.key,
        Some(&content[HEADER_BYTES..HEADER_BYTES + NONCE_BYTES]),
        &associated,
        &content[HEADER_BYTES + NONCE_BYTES..ciphertext_end],
        &content[ciphertext_end..],
    )
    .ok()?;
    let update: ControlUpdate = serde_json::from_slice(&plaintext).ok()?;
    let message = AuthenticatedUpdate {
        epoch,
        digest: openssl::sha::sha256(content)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        update,
    };
    replacement(&snapshot.subscription, &message)
        .validate()
        .ok()?;
    Some(message)
}

pub(crate) fn replacement(old: &Subscription, message: &AuthenticatedUpdate) -> Subscription {
    Subscription {
        endpoint: message.update.endpoint.clone(),
        p256dh: message.update.p256dh.clone(),
        auth: message.update.auth.clone(),
        subscription_epoch: message.epoch,
        ..old.clone()
    }
}

pub(crate) fn generation_for_connection(
    connection: &Connection,
) -> Result<Option<String>, &'static str> {
    PushStore::open(config::get_db())
        .and_then(|store| store.control_generation_for_connection(connection))
        .map_err(|error| error.code())
}

/// Called only for reserved control content on a key-enabled socket. Fixed
/// errors represent temporary local failures: callers must not ACK them.
pub(crate) async fn handle(
    connection: &Connection,
    expected_generation: Option<&str>,
    content: &[u8],
) -> Result<ControlResult, &'static str> {
    let Some(generation) = expected_generation else {
        return Ok(ControlResult::Rejected);
    };
    if !config::is_uuid_valid(&connection.uuid) || content.len() > MAX_BLOB_BYTES {
        return Ok(ControlResult::Rejected);
    }
    let snapshot = PushStore::open(config::get_db())
        .and_then(|store| store.control_snapshot_for_connection(connection, generation))
        .map_err(|error| error.code())?;
    let Some(snapshot) = snapshot else {
        return Ok(ControlResult::Rejected);
    };
    let Some(message) = authenticate(content, &snapshot) else {
        return Ok(ControlResult::Rejected);
    };
    let current_epoch = snapshot.subscription.subscription_epoch;
    let identical_retry = message.epoch == current_epoch
        && snapshot.last_blob_digest.as_deref() == Some(message.digest.as_str());
    let next_epoch = current_epoch < MAX_JSON_INTEGER && message.epoch == current_epoch + 1;
    if !identical_retry && !next_epoch {
        return Ok(ControlResult::Rejected);
    }
    // Retry receipts need no DNS and cannot reactivate inactive subscriptions.
    // New destinations receive exactly the importer's account/origin/address
    // checks; the push worker independently rechecks policy on every send.
    if next_epoch && !config::is_endpoint_valid(&message.update.endpoint).await {
        return Ok(ControlResult::Rejected);
    }
    PushStore::open(config::get_db())
        .and_then(|mut store| store.apply_control(&snapshot, &message, push::now()))
        .map_err(|error| error.code())
}

#[cfg(test)]
pub(crate) fn seal_for_test(
    enrollment: &crate::push_store::Enrollment,
    epoch: u64,
    plaintext: &[u8],
    nonce: [u8; NONCE_BYTES],
) -> Vec<u8> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let key = URL_SAFE_NO_PAD
        .decode(enrollment.control_key.as_ref().unwrap())
        .unwrap();
    let mut blob = MAGIC.to_vec();
    blob.push(VERSION);
    blob.extend_from_slice(&epoch.to_be_bytes());
    let associated = aad(&blob, &enrollment.account_id, enrollment.device_id).unwrap();
    let mut tag = [0; TAG_BYTES];
    let ciphertext = openssl::symm::encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        &associated,
        plaintext,
        &mut tag,
    )
    .unwrap();
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob.extend_from_slice(&tag);
    blob
}
