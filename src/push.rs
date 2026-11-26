//! Durable encrypted delivery attempts. Provider acceptance is not device delivery.
use crate::{
    config,
    push_store::{DeliveryOutcome, Event, PushStore, QueuedEvent, StoreError, Subscription},
    utils::post_allowed,
};
use colliesocket_push::SubscriptionKeys;
use serde_json::{json, Value};
use std::{
    future::Future,
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
    new_event_at(sub, kind, code, now()).map_err(|error| error.code())
}

pub(crate) fn new_event_at(
    sub: &Subscription,
    kind: &str,
    code: Option<&str>,
    issued: i64,
) -> Result<Event, StoreError> {
    let (key_id, import_id) = sub
        .event_identity
        .as_ref()
        .map(|identity| {
            (
                Some(identity.key_id.clone()),
                Some(identity.import_id.clone()),
            )
        })
        .unwrap_or((None, None));
    Ok(Event {
        version: sub.event_version(),
        event_id: uuid_v4().map_err(|_| StoreError::StateUnavailable)?,
        instance: sub.instance.clone(),
        subscription_epoch: sub.subscription_epoch,
        kind: kind.into(),
        issued_at: issued,
        expires_at: issued.saturating_add(300),
        code: code.map(str::to_owned),
        key_id,
        import_id,
        receiver_id: None,
    })
}
pub fn enqueue(account: &str, kind: &str, code: Option<&str>) -> Result<Value, &'static str> {
    if !config::is_uuid_valid(account) {
        return Err("invalid_enrollment");
    }
    let mut store = PushStore::open(config::get_db()).map_err(|e| e.code())?;
    let ids = store
        .enqueue_routes(account, None, kind, code, now())
        .map_err(|e| e.code())?;
    if ids.len() == 1 {
        Ok(json!({"event_id":ids[0],"queued":true}))
    } else {
        Ok(json!({"event_ids":ids,"queued":true}))
    }
}
pub fn enrolled(account: &str) -> Result<bool, &'static str> {
    PushStore::open(config::get_db())
        .and_then(|s| s.is_enrolled(account))
        .map_err(|e| e.code())
}
pub fn enqueue_for_connection(
    co: &crate::db::Connection,
    expected_generation: &str,
    kind: &str,
    code: Option<&str>,
) -> Result<bool, &'static str> {
    if !config::is_uuid_valid(&co.uuid) {
        return Ok(false);
    }
    Ok(!PushStore::open(config::get_db())
        .and_then(|mut store| {
            store.enqueue_routes(&co.uuid, Some((co, expected_generation)), kind, code, now())
        })
        .map_err(|e| e.code())?
        .is_empty())
}
/// Run legacy websocket/CLI wakes under the same cross-process import fence.
/// The configured 10-second Tokio timeout bounds the callback; SQLite uses a
/// separate 15-second busy wait for contending writers.
pub(crate) async fn with_legacy_dispatch<F, Fut, T>(
    co: &crate::db::Connection,
    dispatch: F,
) -> Result<Option<T>, &'static str>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    if !config::legacy_wake_enabled() || !config::is_uuid_valid(&co.uuid) {
        return Ok(None);
    }
    let mut store = PushStore::open(config::get_db()).map_err(|e| e.code())?;
    let guarded = tokio::time::timeout(
        crate::push_store::LEGACY_DISPATCH_TIMEOUT,
        store.with_legacy_dispatch(co, dispatch),
    )
    .await
    .map_err(|_| "state_unavailable")?;
    guarded.map_err(|e| e.code())
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

fn provider_http_failure_status(status: u16) -> Option<u16> {
    (!(200..=299).contains(&status)).then_some(status)
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
    drop(store);
    deliver(claim).await?;
    Ok(true)
}

async fn deliver(claim: QueuedEvent) -> Result<(), &'static str> {
    if !config::is_uuid_valid(&claim.account_id) {
        return finish(&claim, DeliveryOutcome::PermanentFailure);
    }
    if claim.event.receiver_id.is_some() && !claim_is_current(&claim)? {
        return Ok(());
    }
    let body = match encrypt_event(&claim.event, &claim.subscription) {
        Ok(b) => b,
        Err(code) => {
            finish(&claim, DeliveryOutcome::PermanentFailure)?;
            return Err(code);
        }
    };
    let ttl = claim.event.expires_at.saturating_sub(now());
    let outcome = if ttl <= 0 {
        DeliveryOutcome::PermanentFailure
    } else {
        let url = url::Url::parse(&claim.subscription.endpoint).map_err(|_| "invalid_endpoint")?;
        match post_allowed::post_encrypted_if(url, body, ttl.clamp(1, 300) as u32, || {
            claim_is_current(&claim)
        })
        .await
        {
            Ok(Some(response)) => {
                let status = response.status().as_u16();
                if let Some(status) = provider_http_failure_status(status) {
                    // Status is useful for provider diagnosis; endpoint and response data may
                    // contain credentials, topic tokens, or other subscription secrets.
                    log::warn!("push_provider_http_failure status={status}");
                }
                response_outcome(
                    status,
                    response
                        .headers()
                        .get("Retry-After")
                        .and_then(|h| h.to_str().ok()),
                )
            }
            Ok(None) => return Ok(()),
            Err(_) => DeliveryOutcome::Retry { retry_after: None },
        }
    };
    finish(&claim, outcome)
}

fn claim_is_current(claim: &QueuedEvent) -> Result<bool, &'static str> {
    PushStore::open(config::get_db())
        .and_then(|store| store.claim_is_current(claim, now()))
        .map_err(|e| e.code())
}

fn finish(claim: &QueuedEvent, outcome: DeliveryOutcome) -> Result<(), &'static str> {
    PushStore::open(config::get_db())
        .and_then(|mut store| store.complete(claim, outcome, now))
        .map_err(|e| e.code())
}

pub async fn run() {
    use futures_util::{stream::FuturesUnordered, StreamExt};
    const MAX_IN_FLIGHT: usize = 32;
    let mut deliveries = FuturesUnordered::new();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let result = (|| {
                    let mut store = PushStore::open(config::get_db())?;
                    while deliveries.len() < MAX_IN_FLIGHT {
                        let Some(claim) = store.claim_due(now())? else { break };
                        deliveries.push(deliver(claim));
                    }
                    Ok::<_, StoreError>(())
                })();
                if result.is_err() {
                    HEARTBEAT.store(0, Ordering::Relaxed);
                    log::warn!("push_worker_failed");
                } else {
                    HEARTBEAT.store(now(), Ordering::Relaxed);
                }
            }
            Some(result) = deliveries.next(), if !deliveries.is_empty() => {
                if result.is_err() {
                    log::warn!("push_worker_failed");
                }
            }
        }
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
        assert_eq!(provider_http_failure_status(400), Some(400));
        assert_eq!(provider_http_failure_status(202), None);
        assert!(matches!(
            response_outcome(400, None),
            DeliveryOutcome::PermanentFailure
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
