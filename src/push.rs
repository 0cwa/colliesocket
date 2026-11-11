//! Durable encrypted delivery attempts. Provider acceptance is not device delivery.
use crate::{
    config,
    push_store::{DeliveryOutcome, Event, PushStore, StoreError, Subscription},
    utils::post_allowed,
};
use colliesocket_push::SubscriptionKeys;
use serde_json::{json, Value};
use std::{
    sync::atomic::{AtomicI64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub static HEARTBEAT: AtomicI64 = AtomicI64::new(0);
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
pub fn uuid_v4() -> Result<String, &'static str> {
    let mut bytes = [0u8; 16];
    openssl::rand::rand_bytes(&mut bytes).map_err(|_| "state_unavailable")?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
pub(crate) fn new_event(
    sub: &Subscription,
    kind: &str,
    code: Option<&str>,
) -> Result<Event, &'static str> {
    let issued = now();
    Ok(Event {
        version: sub.event_version(),
        event_id: uuid_v4()?,
        instance: sub.instance.clone(),
        subscription_epoch: sub.subscription_epoch,
        kind: kind.into(),
        issued_at: issued,
        expires_at: issued.saturating_add(300),
        code: code.map(str::to_owned),
    })
}
pub fn enqueue(account: &str, kind: &str, code: Option<&str>) -> Result<Value, &'static str> {
    if !config::is_uuid_valid(account) {
        return Err("invalid_enrollment");
    }
    let mut store = PushStore::open(config::get_db()).map_err(|e| e.code())?;
    let sub = store
        .get_subscription(account)
        .map_err(|e| e.code())?
        .ok_or("not_found")?;
    let event = new_event(&sub, kind, code)?;
    store
        .enqueue(account, &event, event.issued_at)
        .map_err(|e| e.code())?;
    Ok(json!({"event_id":event.event_id,"queued":true}))
}
pub fn enrolled(account: &str) -> Result<bool, &'static str> {
    PushStore::open(config::get_db())
        .and_then(|s| s.get_subscription(account))
        .map(|s| s.is_some())
        .map_err(|e| e.code())
}
pub fn enqueue_for_connection(
    co: &crate::db::Connection,
    kind: &str,
    code: Option<&str>,
) -> Result<bool, &'static str> {
    if !config::is_uuid_valid(&co.uuid) {
        return Ok(false);
    }
    let mut store = PushStore::open(config::get_db()).map_err(|e| e.code())?;
    let Some(sub) = store
        .subscription_for_connection(&co.uuid, co.device_id, &co.password, &co.endpoint)
        .map_err(|e| e.code())?
    else {
        return Ok(false);
    };
    // Preserve this exact snapshot through enqueue's transactional epoch check.
    let event = new_event(&sub, kind, code)?;
    match store.enqueue(&co.uuid, &event, event.issued_at) {
        Ok(queued) => Ok(queued),
        Err(
            StoreError::EpochConflict
            | StoreError::SubscriptionMissing
            | StoreError::SubscriptionInactive,
        ) => Ok(false),
        Err(e) => Err(e.code()),
    }
}
pub fn legacy_connection_is_current(co: &crate::db::Connection) -> Result<bool, &'static str> {
    if !config::legacy_wake_enabled() || !config::is_uuid_valid(&co.uuid) {
        return Ok(false);
    }
    PushStore::open(config::get_db())
        .and_then(|s| {
            s.legacy_connection_is_current(&co.uuid, co.device_id, &co.password, &co.endpoint)
        })
        .map_err(|e| e.code())
}
pub fn response_outcome(status: u16, retry_after: Option<&str>) -> DeliveryOutcome {
    match status {
        200..=299 => DeliveryOutcome::Accepted,
        404 | 410 => DeliveryOutcome::Gone,
        401 | 403 => DeliveryOutcome::ProviderRejected,
        408 | 429 | 500..=599 => DeliveryOutcome::Retry {
            retry_after: retry_after.and_then(|s| {
                let digits = s.trim();
                (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then(|| {
                    digits
                        .bytes()
                        .fold(0u32, |n, b| {
                            n.saturating_mul(10).saturating_add(u32::from(b - b'0'))
                        })
                        .min(120)
                })
            }),
        },
        _ => DeliveryOutcome::PermanentFailure,
    }
}
fn encrypt_event(event: &Event, sub: &Subscription) -> Result<Vec<u8>, &'static str> {
    crate::push_store::validate_event(event, now()).map_err(|e| e.code())?;
    let bytes = serde_json::to_vec(event).map_err(|_| "invalid_event")?;
    SubscriptionKeys::from_base64url(&sub.p256dh, &sub.auth)
        .map_err(|_| "invalid_key")?
        .encrypt_padded(&bytes)
        .map_err(|_| "invalid_event")
}
pub async fn drain_once() -> Result<bool, &'static str> {
    let mut store = PushStore::open(config::get_db()).map_err(|e| e.code())?;
    let Some(claim) = store.claim_due(now()).map_err(|e| e.code())? else {
        return Ok(false);
    };
    if !config::is_uuid_valid(&claim.account_id) {
        store
            .complete(&claim, DeliveryOutcome::PermanentFailure, now())
            .map_err(|e| e.code())?;
        return Ok(true);
    }
    drop(store);
    let body = match encrypt_event(&claim.event, &claim.subscription) {
        Ok(b) => b,
        Err(code) => {
            PushStore::open(config::get_db())
                .and_then(|mut s| s.complete(&claim, DeliveryOutcome::PermanentFailure, now()))
                .map_err(|e| e.code())?;
            return Err(code);
        }
    };
    let ttl = claim.event.expires_at.saturating_sub(now());
    let outcome = if ttl <= 0 {
        DeliveryOutcome::PermanentFailure
    } else {
        let url = url::Url::parse(&claim.subscription.endpoint).map_err(|_| "invalid_endpoint")?;
        match post_allowed::post_encrypted(url, body, ttl.clamp(1, 300) as u32).await {
            Ok(response) => response_outcome(
                response.status().as_u16(),
                response
                    .headers()
                    .get("Retry-After")
                    .and_then(|h| h.to_str().ok()),
            ),
            Err(_) => DeliveryOutcome::Retry { retry_after: None },
        }
    };
    PushStore::open(config::get_db())
        .and_then(|mut s| s.complete(&claim, outcome, now()))
        .map_err(|e| e.code())?;
    Ok(true)
}
pub async fn run() {
    loop {
        HEARTBEAT.store(now(), Ordering::Relaxed);
        if drain_once().await.is_err() {
            HEARTBEAT.store(0, Ordering::Relaxed);
            log::warn!("push_worker_failed");
        } else {
            HEARTBEAT.store(now(), Ordering::Relaxed);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_acceptance_retry_and_stale_classification() {
        assert!(matches!(
            response_outcome(202, None),
            DeliveryOutcome::Accepted
        ));
        assert!(matches!(response_outcome(410, None), DeliveryOutcome::Gone));
        assert!(matches!(
            response_outcome(403, None),
            DeliveryOutcome::ProviderRejected
        ));
        assert!(matches!(
            response_outcome(302, None),
            DeliveryOutcome::PermanentFailure
        ));
        assert!(matches!(
            response_outcome(429, Some("999999999999999999999999999")),
            DeliveryOutcome::Retry {
                retry_after: Some(120)
            }
        ));
        assert!(matches!(
            response_outcome(503, Some("  20  ")),
            DeliveryOutcome::Retry {
                retry_after: Some(20)
            }
        ));
        for value in ["-1", "1.5", "Tue, future date", ""] {
            assert!(matches!(
                response_outcome(429, Some(value)),
                DeliveryOutcome::Retry { retry_after: None }
            ));
        }
    }
    #[test]
    fn all_event_kinds_use_the_same_real_encrypted_profile() {
        let enrollment: crate::push_store::Enrollment = serde_json::from_slice(include_bytes!(
            "../contracts/encrypted-push/v1/fixtures/enrollment-valid.json"
        ))
        .unwrap();
        for (kind, code) in [
            ("wake", None),
            ("test", None),
            ("status", Some("connection_conflict")),
            ("status", Some("connection_unavailable")),
        ] {
            let event = new_event(&enrollment.subscription, kind, code).unwrap();
            let body = encrypt_event(&event, &enrollment.subscription).unwrap();
            assert_eq!(body.len(), 4096);
            assert_eq!(&body[16..20], &4096u32.to_be_bytes());
            assert_eq!(body[20], 65);
        }
    }
}
