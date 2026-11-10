//! Protected local enrollment and durable encrypted-push state.
//!
//! This module never establishes enrollment trust or authorizes a network
//! destination. The private importer must authenticate its input and apply the
//! configured account and exact-origin rules before calling `enroll`. Transport
//! must independently recheck its destination policy at every attempt.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcPoint},
    nid::Nid,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::HashSet, fmt, fs, path::Path, time::Duration};

pub const SCHEMA_VERSION: u32 = 2;
pub const MAX_JSON_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_EVENT_BYTES: usize = 3072;
pub const MAX_ACCOUNTS: usize = 4096;
pub const MAX_REQUESTS_PER_ACCOUNT: usize = 1024;
pub const MAX_QUEUE_PER_ACCOUNT: usize = 16;
pub const MAX_QUEUE_GLOBAL: usize = 4096;
pub const MAX_EVENT_IDS: usize = 8192;
pub const MAX_EVENT_LIFETIME: i64 = 300;
pub const CLOCK_TOLERANCE: i64 = 60;
pub const LEASE_SECONDS: i64 = 30;
pub const MAX_ATTEMPTS: u32 = 4;

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    InvalidEnrollment,
    InvalidEvent,
    InvalidEndpoint,
    UnsupportedVersion,
    CapabilityRequired,
    EncryptionRequired,
    InvalidKeys,
    IdempotencyConflict,
    EpochConflict,
    SubscriptionMissing,
    SubscriptionInactive,
    CapacityExceeded,
    QueueFull,
    UnsafeStatePath,
    FutureSchema,
    StateUnavailable,
}

impl StoreError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidEnrollment => "invalid_enrollment",
            Self::InvalidEvent => "invalid_event",
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::UnsupportedVersion => "unsupported_version",
            Self::CapabilityRequired => "capability_required",
            Self::EncryptionRequired => "encryption_required",
            Self::InvalidKeys => "invalid_key",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::EpochConflict => "epoch_conflict",
            Self::SubscriptionMissing => "not_found",
            Self::SubscriptionInactive => "subscription_inactive",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::QueueFull => "queue_full",
            Self::UnsafeStatePath => "unsafe_file",
            Self::FutureSchema => "state_unavailable",
            Self::StateUnavailable => "state_unavailable",
        }
    }
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for StoreError {}
impl From<rusqlite::Error> for StoreError {
    fn from(_: rusqlite::Error) -> Self {
        Self::StateUnavailable
    }
}
impl From<serde_json::Error> for StoreError {
    fn from(_: serde_json::Error) -> Self {
        Self::StateUnavailable
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub enrollment_version: u32,
    pub request_id: String,
    pub account_id: String,
    pub device_id: u32,
    pub password: String,
    pub subscription: Subscription,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subscription {
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub instance: String,
    pub subscription_epoch: u64,
    pub encryption_required: bool,
    pub supported_event_versions: Vec<u32>,
    pub capabilities: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub version: u32,
    pub event_id: String,
    pub instance: String,
    pub subscription_epoch: u64,
    pub kind: String,
    pub issued_at: i64,
    pub expires_at: i64,
    #[serde(
        default,
        deserialize_with = "present_code",
        skip_serializing_if = "Option::is_none"
    )]
    pub code: Option<String>,
}

fn present_code<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Option<String>, D::Error> {
    // An omitted field is permitted, but an explicit JSON null is not a code.
    String::deserialize(d).map(Some)
}

macro_rules! redacted_debug {
    ($($t:ty),+) => { $(impl fmt::Debug for $t {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($t), "([REDACTED])"))
        }
    })+ };
}
redacted_debug!(Enrollment, Subscription, Event);

fn canonical_uuid(value: &str, v4: bool) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(c)
            }
        })
        && (!v4 || (b[14] == b'4' && matches!(b[19], b'8' | b'9' | b'a' | b'b')))
}

fn valid_instance(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn valid_epoch(epoch: u64) -> bool {
    (1..=MAX_JSON_INTEGER).contains(&epoch)
}

fn key_bytes(value: &str, len: usize) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| StoreError::InvalidKeys)?;
    if bytes.len() != len || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(StoreError::InvalidKeys);
    }
    Ok(bytes)
}

impl Subscription {
    pub fn validate(&self) -> Result<()> {
        if !self.encryption_required {
            return Err(StoreError::EncryptionRequired);
        }
        if self.supported_event_versions != [1] {
            return Err(StoreError::UnsupportedVersion);
        }
        if self.capabilities != ["wake", "test", "status"] {
            return Err(StoreError::CapabilityRequired);
        }
        if !valid_instance(&self.instance) || !valid_epoch(self.subscription_epoch) {
            return Err(StoreError::InvalidEnrollment);
        }
        if self.endpoint.is_empty()
            || self.endpoint.len() > 2048
            || self
                .endpoint
                .bytes()
                .any(|b| !b.is_ascii() || b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(StoreError::InvalidEndpoint);
        }
        let endpoint = url::Url::parse(&self.endpoint).map_err(|_| StoreError::InvalidEndpoint)?;
        let authority = self
            .endpoint
            .split_once("://")
            .map(|(_, tail)| tail.split(['/', '?', '#']).next().unwrap_or(""));
        if !matches!(endpoint.scheme(), "https" | "http")
            || endpoint.host().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
            || endpoint.port_or_known_default().is_none_or(|p| p == 0)
            || authority.is_none_or(|a| a.is_empty() || a.contains('@'))
            || self.endpoint.contains('\\')
        {
            return Err(StoreError::InvalidEndpoint);
        }
        let key = key_bytes(&self.p256dh, 65)?;
        key_bytes(&self.auth, 16)?;
        if key[0] != 4 {
            return Err(StoreError::InvalidKeys);
        }
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|_| StoreError::StateUnavailable)?;
        let mut ctx = BigNumContext::new().map_err(|_| StoreError::StateUnavailable)?;
        let point =
            EcPoint::from_bytes(&group, &key, &mut ctx).map_err(|_| StoreError::InvalidKeys)?;
        if point.is_infinity(&group)
            || !point
                .is_on_curve(&group, &mut ctx)
                .map_err(|_| StoreError::InvalidKeys)?
        {
            return Err(StoreError::InvalidKeys);
        }
        Ok(())
    }
}

impl Enrollment {
    pub fn validate(&self) -> Result<()> {
        if self.enrollment_version != 1 {
            return Err(StoreError::UnsupportedVersion);
        }
        if !canonical_uuid(&self.request_id, true)
            || !canonical_uuid(&self.account_id, false)
            || !(2..=2_147_483_647).contains(&self.device_id)
            || !(16..=256).contains(&self.password.len())
            || !self.password.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(StoreError::InvalidEnrollment);
        }
        self.subscription.validate()
    }
}

impl Event {
    pub fn validate(&self, now: i64) -> Result<()> {
        let time_ok = |v: i64| v >= 0 && (v as u64) <= MAX_JSON_INTEGER;
        if self.version != 1
            || !canonical_uuid(&self.event_id, true)
            || !valid_instance(&self.instance)
            || !valid_epoch(self.subscription_epoch)
            || !time_ok(now)
            || !time_ok(self.issued_at)
            || !time_ok(self.expires_at)
            || self.issued_at > now + CLOCK_TOLERANCE
            || self.expires_at <= now
            || !(1..=MAX_EVENT_LIFETIME).contains(&(self.expires_at - self.issued_at))
        {
            return Err(StoreError::InvalidEvent);
        }
        match (self.kind.as_str(), self.code.as_deref()) {
            ("wake" | "test", None)
            | ("status", Some("connection_conflict" | "connection_unavailable")) => (),
            _ => return Err(StoreError::InvalidEvent),
        }
        if serde_json::to_vec(self)?.len() > MAX_EVENT_BYTES {
            return Err(StoreError::InvalidEvent);
        }
        Ok(())
    }
}

pub fn validate_enrollment(enrollment: &Enrollment) -> Result<()> {
    enrollment.validate()
}
pub fn validate_subscription(subscription: &Subscription) -> Result<()> {
    subscription.validate()
}
pub fn validate_event(event: &Event, now: i64) -> Result<()> {
    event.validate(now)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    Active,
    Stale,
    ProviderRejected,
}
impl AccountState {
    fn from_db(value: &str) -> Result<Self> {
        match value {
            "active" => Ok(Self::Active),
            "stale" => Ok(Self::Stale),
            "provider_rejected" => Ok(Self::ProviderRejected),
            _ => Err(StoreError::StateUnavailable),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentDisposition {
    Created,
    Rotated,
    Unchanged,
}
impl EnrollmentDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Rotated => "rotated",
            Self::Unchanged => "unchanged",
        }
    }
    fn from_db(value: &str) -> Result<Self> {
        match value {
            "created" => Ok(Self::Created),
            "rotated" => Ok(Self::Rotated),
            "unchanged" => Ok(Self::Unchanged),
            _ => Err(StoreError::StateUnavailable),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct EnrollmentResult {
    pub replayed: bool,
    pub disposition: EnrollmentDisposition,
    pub subscription_epoch: u64,
}

#[derive(Debug, Serialize)]
pub struct RedactedAccount {
    pub account_id: String,
    pub subscription_epoch: u64,
    pub state: AccountState,
    pub queued: usize,
}

pub struct QueuedEvent {
    pub account_id: String,
    pub subscription: Subscription,
    pub event: Event,
    pub attempt: u32,
    lease_token: String,
}
redacted_debug!(QueuedEvent);

#[derive(Clone, Copy, Debug)]
pub enum DeliveryOutcome {
    Accepted,
    Retry { retry_after: Option<u32> },
    Gone,
    ProviderRejected,
    PermanentFailure,
}

pub struct PushStore {
    db: Connection,
}

fn digest<T: Serialize>(value: &T) -> Result<String> {
    fn sort_objects(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for child in map.values_mut() {
                    sort_objects(child);
                }
                map.sort_keys();
            }
            serde_json::Value::Array(array) => {
                for child in array {
                    sort_objects(child);
                }
            }
            _ => (),
        }
    }
    let mut json = serde_json::to_value(value)?;
    sort_objects(&mut json);
    Ok(openssl::sha::sha256(&serde_json::to_vec(&json)?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn token() -> Result<String> {
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes).map_err(|_| StoreError::StateUnavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

impl PushStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        protect_path(path)?;
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        let version: u32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::FutureSchema);
        }
        db.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;",
        )?;
        let mode: String = db.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        if mode != "delete" {
            db.pragma_update(None, "journal_mode", "DELETE")?;
        }
        if version < SCHEMA_VERSION {
            migrate(&mut db)?;
        }
        verify_schema(&db)?;
        Ok(Self { db })
    }

    /// Read the original receipt without DNS, activation, or other mutation.
    pub fn receipt_for(&self, enrollment: &Enrollment) -> Result<Option<EnrollmentResult>> {
        enrollment.validate()?;
        receipt(&self.db, enrollment, &digest(enrollment)?)
    }

    pub fn enroll(&mut self, enrollment: &Enrollment, now: i64) -> Result<EnrollmentResult> {
        enrollment.validate()?;
        if now < 0 || now as u64 > MAX_JSON_INTEGER {
            return Err(StoreError::InvalidEnrollment);
        }
        let hash = digest(enrollment)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(original) = receipt(&tx, enrollment, &hash)? {
            return Ok(original);
        }
        let count: usize = tx.query_row(
            "SELECT count(*) FROM encrypted_enrollment_requests WHERE account_id=?1",
            [&enrollment.account_id],
            |r| row_count(r, 0),
        )?;
        if count >= MAX_REQUESTS_PER_ACCOUNT {
            return Err(StoreError::CapacityExceeded);
        }
        let existing: Option<(String, String, u32, String)> = tx.query_row(
            "SELECT subscription_json,state,connection_device_id,connection_password FROM encrypted_subscriptions WHERE account_id=?1",
            [&enrollment.account_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let disposition;
        let mut changed_credentials = false;
        if let Some((json, state, device, password)) = existing {
            let old: Subscription = serde_json::from_str(&json)?;
            changed_credentials = device != enrollment.device_id || password != enrollment.password;
            if enrollment.subscription.subscription_epoch == old.subscription_epoch
                && old == enrollment.subscription
                && !changed_credentials
                && state == "active"
            {
                disposition = EnrollmentDisposition::Unchanged;
            } else if old.subscription_epoch < MAX_JSON_INTEGER
                && enrollment.subscription.subscription_epoch == old.subscription_epoch + 1
            {
                disposition = EnrollmentDisposition::Rotated;
            } else {
                return Err(StoreError::EpochConflict);
            }
        } else {
            if enrollment.subscription.subscription_epoch != 1 {
                return Err(StoreError::EpochConflict);
            }
            let count: usize =
                tx.query_row("SELECT count(*) FROM encrypted_subscriptions", [], |r| {
                    row_count(r, 0)
                })?;
            if count >= MAX_ACCOUNTS {
                return Err(StoreError::CapacityExceeded);
            }
            disposition = EnrollmentDisposition::Created;
        }

        if disposition != EnrollmentDisposition::Unchanged {
            let json = serde_json::to_string(&enrollment.subscription)?;
            if disposition == EnrollmentDisposition::Created {
                // Preserve an existing legacy connection's forbidden flag. A
                // later authenticated credential change can recover it.
                let changed = tx.execute("UPDATE connections SET device_id=?2,password=?3,endpoint=?4,last_registration=?5 WHERE uuid=?1",
                    params![enrollment.account_id,enrollment.device_id,enrollment.password,enrollment.subscription.endpoint,now])?;
                if changed == 0 {
                    tx.execute("INSERT INTO connections(uuid,device_id,password,endpoint,forbidden,last_registration) VALUES(?1,?2,?3,?4,0,?5)",
                        params![enrollment.account_id,enrollment.device_id,enrollment.password,enrollment.subscription.endpoint,now])?;
                }
                tx.execute("INSERT INTO encrypted_subscriptions(account_id,subscription_epoch,subscription_json,state,connection_device_id,connection_password,connection_endpoint,updated_at) VALUES(?1,?2,?3,'active',?4,?5,?6,?7)",
                    params![enrollment.account_id,enrollment.subscription.subscription_epoch as i64,json,enrollment.device_id,enrollment.password,enrollment.subscription.endpoint,now])?;
            } else {
                // Update the shadow tuple first, so the legacy-overwrite guard
                // permits exactly this connection update inside the transaction.
                tx.execute("UPDATE encrypted_subscriptions SET subscription_epoch=?2,subscription_json=?3,state='active',connection_device_id=?4,connection_password=?5,connection_endpoint=?6,updated_at=?7 WHERE account_id=?1",
                    params![enrollment.account_id,enrollment.subscription.subscription_epoch as i64,json,enrollment.device_id,enrollment.password,enrollment.subscription.endpoint,now])?;
                let changed = tx.execute("UPDATE connections SET device_id=?2,password=?3,endpoint=?4,last_registration=?5,forbidden=CASE WHEN ?6 THEN 0 ELSE forbidden END WHERE uuid=?1",
                    params![enrollment.account_id,enrollment.device_id,enrollment.password,enrollment.subscription.endpoint,now,changed_credentials])?;
                if changed != 1 {
                    return Err(StoreError::StateUnavailable);
                }
                tx.execute(
                    "DELETE FROM encrypted_push_queue WHERE account_id=?1",
                    [&enrollment.account_id],
                )?;
            }
        }
        tx.execute("INSERT INTO encrypted_enrollment_requests(account_id,request_id,request_digest,subscription_epoch,disposition,created_at) VALUES(?1,?2,?3,?4,?5,?6)",
            params![enrollment.account_id,enrollment.request_id,hash,enrollment.subscription.subscription_epoch as i64,disposition.as_str(),now])?;
        tx.commit()?;
        Ok(EnrollmentResult {
            replayed: false,
            disposition,
            subscription_epoch: enrollment.subscription.subscription_epoch,
        })
    }

    pub fn get_subscription(&self, account_id: &str) -> Result<Option<Subscription>> {
        let value: Option<String> = self
            .db
            .query_row(
                "SELECT subscription_json FROM encrypted_subscriptions WHERE account_id=?1",
                [account_id],
                |r| r.get(0),
            )
            .optional()?;
        value
            .map(|s| serde_json::from_str(&s).map_err(StoreError::from))
            .transpose()
    }

    /// Build an event from this exact snapshot, then pass it directly to
    /// `enqueue`, which rejects intervening epoch/instance changes atomically.
    /// Endpoint must be the original string, not a URL-normalized rendering.
    pub fn subscription_for_connection(
        &self,
        account_id: &str,
        device_id: u32,
        password: &str,
        endpoint: &str,
    ) -> Result<Option<Subscription>> {
        let value: Option<String> = self.db.query_row(
            "SELECT s.subscription_json FROM encrypted_subscriptions s JOIN connections c ON c.uuid=s.account_id WHERE s.account_id=?1 AND c.device_id=?2 AND c.password=?3 AND c.endpoint=?4",
            params![account_id,device_id,password,endpoint], |r| r.get(0)).optional()?;
        value
            .map(|s| serde_json::from_str(&s).map_err(StoreError::from))
            .transpose()
    }

    /// Only an explicitly legacy-mode worker may call this. Encrypted workers
    /// must never use a missing enrollment as a reason to fall back to plaintext.
    pub fn legacy_connection_is_current(
        &self,
        account_id: &str,
        device_id: u32,
        password: &str,
        endpoint: &str,
    ) -> Result<bool> {
        Ok(self.db.query_row("SELECT EXISTS(SELECT 1 FROM connections c WHERE c.uuid=?1 AND c.device_id=?2 AND c.password=?3 AND c.endpoint=?4 AND c.forbidden=0 AND NOT EXISTS(SELECT 1 FROM encrypted_subscriptions s WHERE s.account_id=c.uuid))",
            params![account_id,device_id,password,endpoint], |r| r.get(0))?)
    }

    pub fn account_state(&self, account_id: &str) -> Result<Option<AccountState>> {
        let state: Option<String> = self
            .db
            .query_row(
                "SELECT state FROM encrypted_subscriptions WHERE account_id=?1",
                [account_id],
                |r| r.get(0),
            )
            .optional()?;
        state.map(|s| AccountState::from_db(&s)).transpose()
    }

    pub fn list_enrolled_account_ids(&self) -> Result<HashSet<String>> {
        let mut stmt = self
            .db
            .prepare("SELECT account_id FROM encrypted_subscriptions")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|r| r.map_err(StoreError::from)).collect()
    }

    pub fn list_redacted(&self) -> Result<Vec<RedactedAccount>> {
        let mut stmt = self.db.prepare("SELECT s.account_id,s.subscription_epoch,s.state,(SELECT count(*) FROM encrypted_push_queue q WHERE q.account_id=s.account_id) FROM encrypted_subscriptions s ORDER BY s.account_id")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                row_epoch(r, 1)?,
                r.get::<_, String>(2)?,
                row_count(r, 3)?,
            ))
        })?;
        rows.map(|r| {
            let (account_id, subscription_epoch, state, queued) = r?;
            Ok(RedactedAccount {
                account_id,
                subscription_epoch,
                state: AccountState::from_db(&state)?,
                queued,
            })
        })
        .collect()
    }

    /// Returns false for an identical previously accepted event ID. The ledger
    /// survives provider acceptance and key rotation until the event expires.
    pub fn enqueue(&mut self, account_id: &str, event: &Event, now: i64) -> Result<bool> {
        event.validate(now)?;
        let json = serde_json::to_string(event)?;
        let hash = digest(&(account_id, event))?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        prune(&tx, now)?;
        let seen: Option<String> = tx
            .query_row(
                "SELECT event_digest FROM encrypted_push_event_ids WHERE event_id=?1",
                [&event.event_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(seen) = seen {
            if seen != hash {
                return Err(StoreError::InvalidEvent);
            }
            tx.commit()?;
            return Ok(false);
        }
        let current: Option<(String, String)> = tx
            .query_row(
                "SELECT subscription_json,state FROM encrypted_subscriptions WHERE account_id=?1",
                [account_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (sub, state) = current.ok_or(StoreError::SubscriptionMissing)?;
        let sub: Subscription = serde_json::from_str(&sub)?;
        if sub.subscription_epoch != event.subscription_epoch || sub.instance != event.instance {
            return Err(StoreError::EpochConflict);
        }
        if state != "active" {
            return Err(StoreError::SubscriptionInactive);
        }
        let account_count: usize = tx.query_row(
            "SELECT count(*) FROM encrypted_push_queue WHERE account_id=?1",
            [account_id],
            |r| row_count(r, 0),
        )?;
        let global_count: usize =
            tx.query_row("SELECT count(*) FROM encrypted_push_queue", [], |r| {
                row_count(r, 0)
            })?;
        let id_count: usize =
            tx.query_row("SELECT count(*) FROM encrypted_push_event_ids", [], |r| {
                row_count(r, 0)
            })?;
        if account_count >= MAX_QUEUE_PER_ACCOUNT
            || global_count >= MAX_QUEUE_GLOBAL
            || id_count >= MAX_EVENT_IDS
        {
            return Err(StoreError::QueueFull);
        }
        tx.execute("INSERT INTO encrypted_push_event_ids(event_id,account_id,event_digest,expires_at) VALUES(?1,?2,?3,?4)", params![event.event_id,account_id,hash,event.expires_at])?;
        tx.execute("INSERT INTO encrypted_push_queue(event_id,account_id,subscription_epoch,event_json,expires_at,attempts,next_attempt_at) VALUES(?1,?2,?3,?4,?5,0,?6)", params![event.event_id,account_id,event.subscription_epoch as i64,json,event.expires_at,now])?;
        tx.commit()?;
        Ok(true)
    }

    /// Persist an attempt before returning work. An abandoned claim remains
    /// leased for 30 seconds; a late completion cannot affect its replacement.
    pub fn claim_due(&mut self, now: i64) -> Result<Option<QueuedEvent>> {
        if now < 0 || now as u64 > MAX_JSON_INTEGER {
            return Err(StoreError::StateUnavailable);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        prune(&tx, now)?;
        let row: Option<(String,String,String,u32)> = tx.query_row(
            "SELECT q.account_id,s.subscription_json,q.event_json,q.attempts FROM encrypted_push_queue q JOIN encrypted_subscriptions s ON s.account_id=q.account_id WHERE s.state='active' AND s.subscription_epoch=q.subscription_epoch AND q.next_attempt_at<=?1 AND (q.lease_until IS NULL OR q.lease_until<=?1) AND q.attempts<4 ORDER BY q.next_attempt_at,q.rowid LIMIT 1",
            [now], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let Some((account_id, sub, event, attempts)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        let subscription: Subscription = serde_json::from_str(&sub)?;
        let event: Event = serde_json::from_str(&event)?;
        let lease_token = token()?;
        tx.execute("UPDATE encrypted_push_queue SET attempts=attempts+1,lease_until=?2,lease_token=?3 WHERE event_id=?1", params![event.event_id,now+LEASE_SECONDS,lease_token])?;
        tx.commit()?;
        Ok(Some(QueuedEvent {
            account_id,
            subscription,
            event,
            attempt: attempts + 1,
            lease_token,
        }))
    }

    pub fn complete(
        &mut self,
        claim: &QueuedEvent,
        outcome: DeliveryOutcome,
        now: i64,
    ) -> Result<()> {
        if now < 0 || now as u64 > MAX_JSON_INTEGER {
            return Err(StoreError::StateUnavailable);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(u32,i64)> = tx.query_row(
            "SELECT q.attempts,q.expires_at FROM encrypted_push_queue q JOIN encrypted_subscriptions s ON s.account_id=q.account_id WHERE q.event_id=?1 AND q.account_id=?2 AND q.lease_token=?3 AND q.subscription_epoch=?4 AND s.subscription_epoch=q.subscription_epoch AND s.state='active'",
            params![claim.event.event_id,claim.account_id,claim.lease_token,claim.event.subscription_epoch as i64], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((attempt, expires)) = current else {
            return Ok(());
        };
        match outcome {
            DeliveryOutcome::Gone | DeliveryOutcome::ProviderRejected => {
                let state = if matches!(outcome, DeliveryOutcome::Gone) {
                    "stale"
                } else {
                    "provider_rejected"
                };
                tx.execute(
                    "UPDATE encrypted_subscriptions SET state=?2,updated_at=?3 WHERE account_id=?1",
                    params![claim.account_id, state, now],
                )?;
                tx.execute(
                    "DELETE FROM encrypted_push_queue WHERE account_id=?1",
                    [&claim.account_id],
                )?;
            }
            DeliveryOutcome::Retry { retry_after } if attempt < MAX_ATTEMPTS && expires > now => {
                let delay = [5i64, 30, 120][(attempt - 1) as usize]
                    .max(retry_after.unwrap_or(0).min(120) as i64);
                if now.saturating_add(delay) < expires {
                    tx.execute("UPDATE encrypted_push_queue SET next_attempt_at=?2,lease_until=NULL,lease_token=NULL WHERE event_id=?1", params![claim.event.event_id,now+delay])?;
                } else {
                    tx.execute(
                        "DELETE FROM encrypted_push_queue WHERE event_id=?1",
                        [&claim.event.event_id],
                    )?;
                }
            }
            _ => {
                tx.execute(
                    "DELETE FROM encrypted_push_queue WHERE event_id=?1",
                    [&claim.event.event_id],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn pending_count(&self, account_id: Option<&str>) -> Result<usize> {
        match account_id {
            Some(account) => Ok(self.db.query_row(
                "SELECT count(*) FROM encrypted_push_queue WHERE account_id=?1",
                [account],
                |r| row_count(r, 0),
            )?),
            None => {
                Ok(self
                    .db
                    .query_row("SELECT count(*) FROM encrypted_push_queue", [], |r| {
                        row_count(r, 0)
                    })?)
            }
        }
    }

    /// Explicit local removal only. This never contacts Signal or unlinks a device.
    pub fn remove(&mut self, account_id: &str) -> Result<bool> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM encrypted_push_queue WHERE account_id=?1",
            [account_id],
        )?;
        tx.execute(
            "DELETE FROM encrypted_push_event_ids WHERE account_id=?1",
            [account_id],
        )?;
        tx.execute(
            "DELETE FROM encrypted_enrollment_requests WHERE account_id=?1",
            [account_id],
        )?;
        tx.execute(
            "DELETE FROM encrypted_subscriptions WHERE account_id=?1",
            [account_id],
        )?;
        let removed = tx.execute("DELETE FROM connections WHERE uuid=?1", [account_id])? > 0;
        tx.commit()?;
        Ok(removed)
    }
}

fn row_count(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<usize> {
    let value: i64 = row.get(index)?;
    usize::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn row_epoch(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    if value < 1 || value as u64 > MAX_JSON_INTEGER {
        return Err(rusqlite::Error::IntegralValueOutOfRange(index, value));
    }
    Ok(value as u64)
}

fn receipt(
    db: &Connection,
    enrollment: &Enrollment,
    digest: &str,
) -> Result<Option<EnrollmentResult>> {
    let row: Option<(String,u64,String)> = db.query_row("SELECT request_digest,subscription_epoch,disposition FROM encrypted_enrollment_requests WHERE account_id=?1 AND request_id=?2", params![enrollment.account_id,enrollment.request_id], |r| Ok((r.get(0)?,row_epoch(r,1)?,r.get(2)?))).optional()?;
    row.map(|(stored, subscription_epoch, disposition)| {
        if stored != digest {
            return Err(StoreError::IdempotencyConflict);
        }
        Ok(EnrollmentResult {
            replayed: true,
            subscription_epoch,
            disposition: EnrollmentDisposition::from_db(&disposition)?,
        })
    })
    .transpose()
}

fn prune(tx: &Transaction<'_>, now: i64) -> Result<()> {
    tx.execute("DELETE FROM encrypted_push_queue WHERE expires_at<=?1 OR (attempts>=4 AND (lease_until IS NULL OR lease_until<=?1))", [now])?;
    tx.execute(
        "DELETE FROM encrypted_push_event_ids WHERE expires_at<=?1",
        [now],
    )?;
    Ok(())
}

#[cfg(unix)]
fn protect_path(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let bad = |_| StoreError::UnsafeStatePath;
    if path.file_name().is_none() || path.to_str() == Some(":memory:") {
        return Err(StoreError::UnsafeStatePath);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(bad)?;
    }
    let uid = unsafe { libc::geteuid() };
    let parent_meta = fs::symlink_metadata(parent).map_err(bad)?;
    if !parent_meta.is_dir() || parent_meta.uid() != uid || parent_meta.mode() & 0o7777 != 0o700 {
        return Err(StoreError::UnsafeStatePath);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(bad)?;
    let meta = file.metadata().map_err(bad)?;
    if !meta.is_file() || meta.uid() != uid || meta.nlink() != 1 || meta.mode() & 0o7777 != 0o600 {
        return Err(StoreError::UnsafeStatePath);
    }
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(Path::new(&sidecar)) {
            Ok(m)
                if !m.is_file()
                    || m.uid() != uid
                    || m.nlink() != 1
                    || m.mode() & 0o7777 != 0o600 =>
            {
                return Err(StoreError::UnsafeStatePath)
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(StoreError::UnsafeStatePath),
        }
    }
    Ok(())
}
#[cfg(not(unix))]
fn protect_path(_: &Path) -> Result<()> {
    Err(StoreError::UnsafeStatePath)
}

fn verify_connection_schema(db: &Connection) -> Result<()> {
    let mut statement = db.prepare("PRAGMA table_info(connections)")?;
    let fields: Vec<String> = statement
        .query_map([], |r| r.get(1))?
        .collect::<std::result::Result<_, _>>()?;
    if fields
        != [
            "uuid",
            "device_id",
            "password",
            "endpoint",
            "forbidden",
            "last_registration",
        ]
    {
        return Err(StoreError::StateUnavailable);
    }
    let mut statement =
        db.prepare("SELECT name FROM pragma_index_list('connections') WHERE \"unique\"=1")?;
    let indexes: Vec<String> = statement
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    let mut valid_key = false;
    for index in indexes {
        let mut fields = db.prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")?;
        let fields: Vec<String> = fields
            .query_map([index], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        valid_key |= fields == ["uuid"];
    }
    if !valid_key {
        return Err(StoreError::StateUnavailable);
    }
    Ok(())
}

fn verify_schema(db: &Connection) -> Result<()> {
    verify_connection_schema(db)?;
    for (kind, name) in [
        ("table", "encrypted_subscriptions"),
        ("table", "encrypted_enrollment_requests"),
        ("table", "encrypted_push_event_ids"),
        ("table", "encrypted_push_queue"),
        ("trigger", "encrypted_connection_insert_guard"),
        ("trigger", "encrypted_connection_update_guard"),
        ("trigger", "encrypted_connection_delete_guard"),
    ] {
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2)",
            params![kind, name],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(StoreError::StateUnavailable);
        }
    }
    Ok(())
}

fn migrate(db: &mut Connection) -> Result<()> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Another process may have completed migration while this opener waited.
    let version: u32 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::FutureSchema);
    }
    if version == SCHEMA_VERSION {
        tx.commit()?;
        return Ok(());
    }
    tx.execute_batch("CREATE TABLE IF NOT EXISTS connections(uuid TEXT UNIQUE ON CONFLICT REPLACE,device_id INTEGER,password TEXT,endpoint TEXT,forbidden BOOLEAN NOT NULL CHECK(forbidden IN(0,1)),last_registration INTEGER);")?;
    verify_connection_schema(&tx)?;
    tx.execute_batch(r#"
CREATE TABLE encrypted_subscriptions(
 account_id TEXT PRIMARY KEY REFERENCES connections(uuid),
 subscription_epoch INTEGER NOT NULL CHECK(subscription_epoch BETWEEN 1 AND 9007199254740991),
 subscription_json TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN('active','stale','provider_rejected')),
 connection_device_id INTEGER NOT NULL, connection_password TEXT NOT NULL,
 connection_endpoint TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE encrypted_enrollment_requests(
 account_id TEXT NOT NULL REFERENCES encrypted_subscriptions(account_id) ON DELETE CASCADE,
 request_id TEXT NOT NULL, request_digest TEXT NOT NULL,
 subscription_epoch INTEGER NOT NULL,
 disposition TEXT NOT NULL CHECK(disposition IN('created','rotated','unchanged')),
 created_at INTEGER NOT NULL, PRIMARY KEY(account_id,request_id)
);
CREATE TABLE encrypted_push_event_ids(
 event_id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES encrypted_subscriptions(account_id) ON DELETE CASCADE,
 event_digest TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX encrypted_event_expiry ON encrypted_push_event_ids(expires_at);
CREATE TABLE encrypted_push_queue(
 event_id TEXT PRIMARY KEY REFERENCES encrypted_push_event_ids(event_id) ON DELETE CASCADE,
 account_id TEXT NOT NULL REFERENCES encrypted_subscriptions(account_id) ON DELETE CASCADE,
 subscription_epoch INTEGER NOT NULL, event_json TEXT NOT NULL, expires_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 4), next_attempt_at INTEGER NOT NULL,
 lease_until INTEGER, lease_token TEXT
);
CREATE INDEX encrypted_queue_due ON encrypted_push_queue(next_attempt_at,lease_until);
CREATE INDEX encrypted_queue_account ON encrypted_push_queue(account_id);
CREATE TRIGGER encrypted_connection_insert_guard BEFORE INSERT ON connections
 WHEN EXISTS(SELECT 1 FROM encrypted_subscriptions WHERE account_id=NEW.uuid)
 BEGIN SELECT RAISE(ABORT,'encrypted_enrollment_required'); END;
CREATE TRIGGER encrypted_connection_update_guard BEFORE UPDATE OF uuid,device_id,password,endpoint ON connections
 WHEN EXISTS(SELECT 1 FROM encrypted_subscriptions WHERE account_id=OLD.uuid OR account_id=NEW.uuid)
 AND (NEW.uuid IS NOT OLD.uuid OR NOT EXISTS(SELECT 1 FROM encrypted_subscriptions WHERE account_id=NEW.uuid AND connection_device_id=NEW.device_id AND connection_password=NEW.password AND connection_endpoint=NEW.endpoint))
 BEGIN SELECT RAISE(ABORT,'encrypted_enrollment_required'); END;
CREATE TRIGGER encrypted_connection_delete_guard BEFORE DELETE ON connections
 WHEN EXISTS(SELECT 1 FROM encrypted_subscriptions WHERE account_id=OLD.uuid)
 BEGIN SELECT RAISE(ABORT,'encrypted_enrollment_required'); END;
PRAGMA user_version=2;
"#)?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcKey, PointConversionForm};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::{path::PathBuf, sync::OnceLock};

    const NOW: i64 = 1_800_000_000;
    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let base = std::env::var_os("TMPDIR")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let path = base.join(format!("colliesocket-store-{}", token().unwrap()));
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("state.sqlite")
        }
        fn store(&self) -> PushStore {
            PushStore::open(self.path()).unwrap()
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn id(n: u64) -> String {
        format!("00000000-0000-4000-8000-{n:012x}")
    }
    fn enrollment() -> Enrollment {
        static PUBLIC: OnceLock<String> = OnceLock::new();
        let public = PUBLIC.get_or_init(|| {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let key = EcKey::generate(&group).unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            URL_SAFE_NO_PAD.encode(
                key.public_key()
                    .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
                    .unwrap(),
            )
        });
        Enrollment {
            enrollment_version: 1,
            request_id: id(1),
            account_id: ACCOUNT.into(),
            device_id: 2,
            password: "synthetic-password-only".into(),
            subscription: Subscription {
                endpoint: "https://push.example.test/synthetic-token".into(),
                p256dh: public.clone(),
                auth: URL_SAFE_NO_PAD.encode([7u8; 16]),
                instance: "collie:test-1".into(),
                subscription_epoch: 1,
                encryption_required: true,
                supported_event_versions: vec![1],
                capabilities: vec!["wake".into(), "test".into(), "status".into()],
            },
        }
    }
    fn event(enrollment: &Enrollment, n: u64) -> Event {
        Event {
            version: 1,
            event_id: id(n),
            instance: enrollment.subscription.instance.clone(),
            subscription_epoch: enrollment.subscription.subscription_epoch,
            kind: "wake".into(),
            issued_at: NOW,
            expires_at: NOW + 300,
            code: None,
        }
    }
    fn rotate(enrollment: &Enrollment, n: u64) -> Enrollment {
        let mut new = enrollment.clone();
        new.request_id = id(n);
        new.subscription.subscription_epoch += 1;
        new
    }
    fn legacy_database(dir: &TestDir, version: u32) {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(dir.path())
            .unwrap();
        let db = Connection::open(dir.path()).unwrap();
        db.execute_batch("CREATE TABLE connections(uuid TEXT UNIQUE ON CONFLICT REPLACE,device_id INTEGER,password TEXT,endpoint TEXT,forbidden BOOLEAN NOT NULL CHECK(forbidden IN(0,1)),last_registration INTEGER);").unwrap();
        let e = enrollment();
        db.execute(
            "INSERT INTO connections VALUES(?1,?2,?3,?4,1,123)",
            params![
                e.account_id,
                e.device_id,
                e.password,
                e.subscription.endpoint
            ],
        )
        .unwrap();
        db.pragma_update(None, "user_version", version).unwrap();
    }

    #[test]
    fn migrates_legacy_zero_and_one_without_changing_connections() {
        for version in [0, 1] {
            let dir = TestDir::new();
            legacy_database(&dir, version);
            let store = dir.store();
            assert_eq!(
                store
                    .db
                    .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                    .unwrap(),
                2
            );
            let row: (String, u32, String, String, bool, i64) = store
                .db
                .query_row("SELECT * FROM connections", [], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                })
                .unwrap();
            let e = enrollment();
            assert_eq!(
                row,
                (
                    e.account_id,
                    e.device_id,
                    e.password,
                    e.subscription.endpoint,
                    true,
                    123
                )
            );
            assert!(store.list_enrolled_account_ids().unwrap().is_empty());
            drop(store);
            assert!(PushStore::open(dir.path()).is_ok());
        }
    }

    #[test]
    fn future_and_partial_schemas_are_rejected_without_version_downgrade() {
        let dir = TestDir::new();
        let store = dir.store();
        store.db.pragma_update(None, "user_version", 3).unwrap();
        drop(store);
        assert!(matches!(
            PushStore::open(dir.path()),
            Err(StoreError::FutureSchema)
        ));
        let db = Connection::open(dir.path()).unwrap();
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            3
        );
        drop(db);
        let partial = TestDir::new();
        legacy_database(&partial, 1);
        let db = Connection::open(partial.path()).unwrap();
        db.execute_batch("CREATE TABLE encrypted_subscriptions(broken TEXT);")
            .unwrap();
        drop(db);
        assert!(PushStore::open(partial.path()).is_err());
        let db = Connection::open(partial.path()).unwrap();
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM connections", [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='encrypted_push_queue'",
                [],
                |r| r.get::<_, u32>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn protects_database_paths_and_redacts_secrets() {
        use std::os::unix::fs::{symlink, MetadataExt};
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        assert_eq!(fs::metadata(dir.path()).unwrap().mode() & 0o7777, 0o600);
        let report = serde_json::to_string(&store.list_redacted().unwrap()).unwrap();
        let debug = format!("{e:?} {:?} {:?}", e.subscription, event(&e, 11));
        for secret in [
            &e.password,
            &e.subscription.endpoint,
            &e.subscription.auth,
            &e.subscription.p256dh,
        ] {
            assert!(!report.contains(secret));
            assert!(!debug.contains(secret));
        }
        drop(store);
        let linked = dir.0.join("symlink.sqlite");
        symlink(dir.path(), &linked).unwrap();
        assert!(matches!(
            PushStore::open(&linked),
            Err(StoreError::UnsafeStatePath)
        ));
        let hard = dir.0.join("hard.sqlite");
        fs::hard_link(dir.path(), &hard).unwrap();
        assert!(matches!(
            PushStore::open(&hard),
            Err(StoreError::UnsafeStatePath)
        ));
        fs::remove_file(hard).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            PushStore::open(dir.path()),
            Err(StoreError::UnsafeStatePath)
        ));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            PushStore::open(dir.path()),
            Err(StoreError::UnsafeStatePath)
        ));
    }

    #[test]
    fn rejects_malformed_keys_urls_versions_and_json_shapes() {
        let good = enrollment();
        good.validate().unwrap();
        for auth in [
            "AA".to_owned(),
            URL_SAFE_NO_PAD.encode([7u8; 15]),
            format!("{}=", good.subscription.auth),
        ] {
            let mut e = good.clone();
            e.subscription.auth = auth;
            assert_eq!(e.validate(), Err(StoreError::InvalidKeys));
        }
        for key in [
            URL_SAFE_NO_PAD.encode([0u8; 65]),
            URL_SAFE_NO_PAD.encode([4u8; 64]),
        ] {
            let mut e = good.clone();
            e.subscription.p256dh = key;
            assert_eq!(e.validate(), Err(StoreError::InvalidKeys));
        }
        for endpoint in [
            "https://push.example.test/#",
            "https://push.example.test/x\n",
            "https://push.example.test/x y",
            "https://u:p@push.example.test/",
            "https://@push.example.test/",
            "https://push.example.test\\x",
            "https:push.example.test",
            "file:///private",
        ] {
            let mut e = good.clone();
            e.subscription.endpoint = endpoint.into();
            assert!(e.validate().is_err(), "{endpoint}");
        }
        let mut e = good.clone();
        e.subscription.encryption_required = false;
        assert_eq!(e.validate(), Err(StoreError::EncryptionRequired));
        let mut e = good.clone();
        e.subscription.supported_event_versions = vec![1, 2];
        assert_eq!(e.validate(), Err(StoreError::UnsupportedVersion));
        let mut e = good.clone();
        e.subscription.capabilities.swap(0, 1);
        assert!(e.validate().is_err());
        for field in [0, 1, 2] {
            let mut e = good.clone();
            match field {
                0 => e.request_id.push('\n'),
                1 => e.subscription.instance.push('\n'),
                _ => e.password.push('\n'),
            };
            assert!(e.validate().is_err());
        }
        let json = serde_json::to_string(&good).unwrap();
        assert!(serde_json::from_str::<Enrollment>(
            &json.replace("\"enrollment_version\":1", "\"enrollment_version\":1.0")
        )
        .is_err());
        assert!(
            serde_json::from_str::<Enrollment>(&json.replacen('{', "{\"unknown\":true,", 1))
                .is_err()
        );
        let utf16: Vec<u8> = json.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(serde_json::from_slice::<Enrollment>(&utf16).is_err());
        let mut local = good;
        local.subscription.endpoint = "http://127.0.0.1:8080/test".into();
        local.validate().unwrap(); // Importer must authorize the exact origin.
    }

    #[test]
    fn event_validation_rejects_replay_metadata_and_explicit_null_code() {
        let e = enrollment();
        let good = event(&e, 3);
        good.validate(NOW).unwrap();
        let mut bad = good.clone();
        bad.issued_at = NOW + 61;
        bad.expires_at = NOW + 300;
        assert!(bad.validate(NOW).is_err());
        let mut bad = good.clone();
        bad.expires_at = NOW + 301;
        assert!(bad.validate(NOW).is_err());
        let mut bad = good.clone();
        bad.expires_at = NOW;
        assert!(bad.validate(NOW).is_err());
        let mut bad = good.clone();
        bad.issued_at = -1;
        assert!(bad.validate(NOW).is_err());
        let mut bad = good.clone();
        bad.expires_at = MAX_JSON_INTEGER as i64 + 1;
        assert!(bad.validate(NOW).is_err());
        let mut bad = good.clone();
        bad.event_id.push('\n');
        assert!(bad.validate(NOW).is_err());
        let mut bad = good.clone();
        bad.code = Some("connection_conflict".into());
        assert!(bad.validate(NOW).is_err());
        let mut status = good.clone();
        status.kind = "status".into();
        assert!(status.validate(NOW).is_err());
        status.code = Some("connection_conflict".into());
        status.validate(NOW).unwrap();
        status.code = Some("connection_unavailable".into());
        status.validate(NOW).unwrap();
        let json = serde_json::to_string(&good).unwrap();
        assert!(serde_json::from_str::<Event>(&json.replacen('{', "{\"code\":null,", 1)).is_err());
        assert!(
            serde_json::from_str::<Event>(&json.replace("\"version\":1", "\"version\":1.0"))
                .is_err()
        );
    }

    #[test]
    fn receipts_are_durable_and_reuse_conflicts_never_mutate() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        let original = store.enroll(&e, NOW).unwrap();
        assert_eq!(original.disposition, EnrollmentDisposition::Created);
        assert!(store.enroll(&e, NOW + 1).unwrap().replayed);
        let mut changed = e.clone();
        changed.password.push('x');
        assert_eq!(
            store.enroll(&changed, NOW + 2),
            Err(StoreError::IdempotencyConflict)
        );
        let mut unchanged = e.clone();
        unchanged.request_id = id(2);
        assert_eq!(
            store.enroll(&unchanged, NOW + 3).unwrap().disposition,
            EnrollmentDisposition::Unchanged
        );
        drop(store);
        let store = dir.store();
        let replay = store.receipt_for(&e).unwrap().unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.disposition, original.disposition);
        assert_eq!(
            store.receipt_for(&changed),
            Err(StoreError::IdempotencyConflict)
        );
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap().unwrap(),
            e.subscription
        );
    }

    #[test]
    fn same_url_rotation_is_atomic_and_old_receipts_do_not_reactivate_stale() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        store.enqueue(ACCOUNT, &event(&e, 11), NOW).unwrap();
        let old = store.claim_due(NOW).unwrap().unwrap();
        let mut rotated = rotate(&e, 2);
        rotated.subscription.auth = URL_SAFE_NO_PAD.encode([9u8; 16]);
        assert_eq!(
            store.enroll(&rotated, NOW + 1).unwrap().disposition,
            EnrollmentDisposition::Rotated
        );
        assert_eq!(store.pending_count(None).unwrap(), 0);
        store
            .complete(&old, DeliveryOutcome::Gone, NOW + 2)
            .unwrap();
        assert_eq!(
            store.account_state(ACCOUNT).unwrap(),
            Some(AccountState::Active)
        );
        let active = event(&rotated, 12);
        store.enqueue(ACCOUNT, &active, NOW + 2).unwrap();
        let claim = store.claim_due(NOW + 2).unwrap().unwrap();
        store
            .complete(&claim, DeliveryOutcome::Gone, NOW + 3)
            .unwrap();
        assert_eq!(
            store.account_state(ACCOUNT).unwrap(),
            Some(AccountState::Stale)
        );
        assert!(store.receipt_for(&e).unwrap().unwrap().replayed);
        assert!(store.enroll(&rotated, NOW + 4).unwrap().replayed);
        assert_eq!(
            store.account_state(ACCOUNT).unwrap(),
            Some(AccountState::Stale)
        );
        let mut same = rotated.clone();
        same.request_id = id(3);
        assert_eq!(store.enroll(&same, NOW + 4), Err(StoreError::EpochConflict));
        let recovered = rotate(&rotated, 4);
        store.enroll(&recovered, NOW + 5).unwrap();
        assert_eq!(
            store.account_state(ACCOUNT).unwrap(),
            Some(AccountState::Active)
        );
        let mut skipped = rotate(&recovered, 5);
        skipped.subscription.subscription_epoch += 1;
        assert_eq!(
            store.enroll(&skipped, NOW + 6),
            Err(StoreError::EpochConflict)
        );
        let mut old_epoch = e.clone();
        old_epoch.request_id = id(6);
        assert_eq!(
            store.enroll(&old_epoch, NOW + 6),
            Err(StoreError::EpochConflict)
        );
    }

    #[test]
    fn registration_rollback_restores_connection_subscription_queue_and_receipt() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        let queued = event(&e, 11);
        store.enqueue(ACCOUNT, &queued, NOW).unwrap();
        store.db.execute_batch("CREATE TRIGGER fail_registration BEFORE INSERT ON encrypted_enrollment_requests BEGIN SELECT RAISE(ABORT,'injected_interruption'); END;").unwrap();
        let mut new = rotate(&e, 2);
        new.password.push('x');
        new.subscription.auth = URL_SAFE_NO_PAD.encode([8u8; 16]);
        assert_eq!(
            store.enroll(&new, NOW + 1),
            Err(StoreError::StateUnavailable)
        );
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap().unwrap(),
            e.subscription
        );
        assert_eq!(
            store
                .db
                .query_row(
                    "SELECT password FROM connections WHERE uuid=?1",
                    [ACCOUNT],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            e.password
        );
        assert_eq!(store.pending_count(None).unwrap(), 1);
        assert!(store.receipt_for(&new).unwrap().is_none());
        store
            .db
            .execute_batch("DROP TRIGGER fail_registration;")
            .unwrap();
        drop(store);
        let mut store = dir.store();
        store.enroll(&new, NOW + 2).unwrap();
        assert_eq!(store.pending_count(None).unwrap(), 0);
    }

    #[test]
    fn legacy_writes_cannot_overwrite_or_delete_encrypted_connections() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        assert!(store
            .db
            .execute(
                "INSERT OR REPLACE INTO connections VALUES(?1,2,'wrong','https://wrong.test/',0,0)",
                [ACCOUNT]
            )
            .is_err());
        assert!(store
            .db
            .execute(
                "UPDATE connections SET password='wrong' WHERE uuid=?1",
                [ACCOUNT]
            )
            .is_err());
        assert!(store
            .db
            .execute(
                "UPDATE connections SET endpoint=NULL WHERE uuid=?1",
                [ACCOUNT]
            )
            .is_err());
        assert!(store
            .db
            .execute("DELETE FROM connections WHERE uuid=?1", [ACCOUNT])
            .is_err());
        store
            .db
            .execute(
                "INSERT INTO connections VALUES('other',2,'legacy','https://legacy.test/',0,0)",
                [],
            )
            .unwrap();
        assert!(store
            .db
            .execute(
                "UPDATE OR REPLACE connections SET uuid=?1 WHERE uuid='other'",
                [ACCOUNT]
            )
            .is_err());
        store
            .db
            .execute(
                "UPDATE connections SET forbidden=1 WHERE uuid=?1",
                [ACCOUNT],
            )
            .unwrap();
        assert!(store.remove(ACCOUNT).unwrap());
        assert!(!store.remove(ACCOUNT).unwrap());
        assert!(store.receipt_for(&e).unwrap().is_none());
        assert!(store.get_subscription(ACCOUNT).unwrap().is_none());
    }

    #[test]
    fn only_authenticated_new_credentials_reset_signal_forbidden() {
        let dir = TestDir::new();
        legacy_database(&dir, 1);
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        let forbidden = |s: &PushStore| {
            s.db.query_row(
                "SELECT forbidden FROM connections WHERE uuid=?1",
                [ACCOUNT],
                |r| r.get::<_, bool>(0),
            )
            .unwrap()
        };
        assert!(forbidden(&store));
        let mut keys = rotate(&e, 2);
        keys.subscription.auth = URL_SAFE_NO_PAD.encode([8u8; 16]);
        store.enroll(&keys, NOW + 1).unwrap();
        assert!(forbidden(&store));
        let mut creds = rotate(&keys, 3);
        creds.password.push('x');
        store.enroll(&creds, NOW + 2).unwrap();
        assert!(!forbidden(&store));
        store
            .db
            .execute(
                "UPDATE connections SET forbidden=1 WHERE uuid=?1",
                [ACCOUNT],
            )
            .unwrap();
        store.enroll(&creds, NOW + 3).unwrap();
        assert!(forbidden(&store));
    }

    #[test]
    fn event_ledger_retains_idempotency_after_provider_acceptance() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        let ev = event(&e, 11);
        assert!(store.enqueue(ACCOUNT, &ev, NOW).unwrap());
        assert!(!store.enqueue(ACCOUNT, &ev, NOW).unwrap());
        let claim = store.claim_due(NOW).unwrap().unwrap();
        store
            .complete(&claim, DeliveryOutcome::Accepted, NOW + 1)
            .unwrap();
        assert_eq!(store.pending_count(None).unwrap(), 0);
        assert!(!store.enqueue(ACCOUNT, &ev, NOW + 2).unwrap());
        let mut changed = ev.clone();
        changed.kind = "test".into();
        assert_eq!(
            store.enqueue(ACCOUNT, &changed, NOW + 2),
            Err(StoreError::InvalidEvent)
        );
        assert!(store.claim_due(NOW + 300).unwrap().is_none());
        assert_eq!(
            store
                .db
                .query_row("SELECT count(*) FROM encrypted_push_event_ids", [], |r| r
                    .get::<_, u32>(
                    0
                ))
                .unwrap(),
            0
        );
    }

    #[test]
    fn retry_schedule_and_provider_retry_after_are_bounded_by_attempts_and_expiry() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        store.enqueue(ACCOUNT, &event(&e, 11), NOW).unwrap();
        for (attempt, at, next) in [
            (1, NOW, NOW + 5),
            (2, NOW + 5, NOW + 35),
            (3, NOW + 35, NOW + 155),
            (4, NOW + 155, NOW + 156),
        ] {
            let claim = store.claim_due(at).unwrap().unwrap();
            assert_eq!(claim.attempt, attempt);
            store
                .complete(&claim, DeliveryOutcome::Retry { retry_after: None }, at)
                .unwrap();
            assert!(store.claim_due(next - 1).unwrap().is_none());
        }
        assert_eq!(store.pending_count(None).unwrap(), 0);
        store.enqueue(ACCOUNT, &event(&e, 12), NOW).unwrap();
        let claim = store.claim_due(NOW).unwrap().unwrap();
        store
            .complete(
                &claim,
                DeliveryOutcome::Retry {
                    retry_after: Some(u32::MAX),
                },
                NOW,
            )
            .unwrap();
        assert!(store.claim_due(NOW + 119).unwrap().is_none());
        let claim = store.claim_due(NOW + 120).unwrap().unwrap();
        store
            .complete(
                &claim,
                DeliveryOutcome::Retry {
                    retry_after: Some(120),
                },
                NOW + 299,
            )
            .unwrap();
        assert_eq!(store.pending_count(None).unwrap(), 0);
    }

    #[test]
    fn crashed_claims_resume_after_lease_and_late_completion_cannot_remove_replacement() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        store.enqueue(ACCOUNT, &event(&e, 11), NOW).unwrap();
        let abandoned = store.claim_due(NOW).unwrap().unwrap();
        drop(store);
        let mut store = dir.store();
        assert!(store.claim_due(NOW + 29).unwrap().is_none());
        let resumed = store.claim_due(NOW + 30).unwrap().unwrap();
        assert_eq!(resumed.attempt, 2);
        store
            .complete(&abandoned, DeliveryOutcome::Gone, NOW + 31)
            .unwrap();
        assert_eq!(
            store.account_state(ACCOUNT).unwrap(),
            Some(AccountState::Active)
        );
        assert_eq!(store.pending_count(None).unwrap(), 1);
        drop(resumed);
        assert_eq!(store.claim_due(NOW + 60).unwrap().unwrap().attempt, 3);
        assert_eq!(store.claim_due(NOW + 90).unwrap().unwrap().attempt, 4);
        assert!(store.claim_due(NOW + 120).unwrap().is_none());
        assert_eq!(store.pending_count(None).unwrap(), 0);
    }

    #[test]
    fn provider_rejections_never_delete_or_forbid_signal_connections() {
        for (outcome, state) in [
            (DeliveryOutcome::Gone, AccountState::Stale),
            (
                DeliveryOutcome::ProviderRejected,
                AccountState::ProviderRejected,
            ),
        ] {
            let dir = TestDir::new();
            let mut store = dir.store();
            let e = enrollment();
            store.enroll(&e, NOW).unwrap();
            store.enqueue(ACCOUNT, &event(&e, 11), NOW).unwrap();
            store.enqueue(ACCOUNT, &event(&e, 12), NOW).unwrap();
            let claim = store.claim_due(NOW).unwrap().unwrap();
            store.complete(&claim, outcome, NOW + 300).unwrap();
            assert_eq!(store.account_state(ACCOUNT).unwrap(), Some(state));
            assert_eq!(store.pending_count(None).unwrap(), 0);
            assert!(!store
                .db
                .query_row(
                    "SELECT forbidden FROM connections WHERE uuid=?1",
                    [ACCOUNT],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap());
        }
    }

    #[test]
    fn connection_snapshot_rejects_stale_credentials_and_intervening_epoch_changes() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let mut e = enrollment();
        e.subscription.endpoint = "https://PUSH.example.test:443/synthetic".into();
        store.enroll(&e, NOW).unwrap();
        assert!(store
            .subscription_for_connection(
                ACCOUNT,
                e.device_id,
                &e.password,
                &e.subscription.endpoint
            )
            .unwrap()
            .is_some());
        let normalized = url::Url::parse(&e.subscription.endpoint)
            .unwrap()
            .to_string();
        assert!(store
            .subscription_for_connection(ACCOUNT, e.device_id, &e.password, &normalized)
            .unwrap()
            .is_none());
        let mut second = rotate(&e, 2);
        second.password.push('x');
        store.enroll(&second, NOW + 1).unwrap();
        assert!(store
            .subscription_for_connection(
                ACCOUNT,
                e.device_id,
                &e.password,
                &e.subscription.endpoint
            )
            .unwrap()
            .is_none());
        let captured = store
            .subscription_for_connection(
                ACCOUNT,
                second.device_id,
                &second.password,
                &second.subscription.endpoint,
            )
            .unwrap()
            .unwrap();
        let mut third = rotate(&second, 3);
        third.password.push('y');
        store.enroll(&third, NOW + 2).unwrap();
        let mut status = event(&second, 11);
        status.subscription_epoch = captured.subscription_epoch;
        status.kind = "status".into();
        status.code = Some("connection_conflict".into());
        assert_eq!(
            store.enqueue(ACCOUNT, &status, NOW + 2),
            Err(StoreError::EpochConflict)
        );
        assert_eq!(store.pending_count(None).unwrap(), 0);
        let mut fourth = rotate(&third, 4);
        fourth.subscription.auth = URL_SAFE_NO_PAD.encode([9u8; 16]);
        store.enroll(&fourth, NOW + 3).unwrap();
        assert_eq!(
            store
                .subscription_for_connection(
                    ACCOUNT,
                    third.device_id,
                    &third.password,
                    &third.subscription.endpoint
                )
                .unwrap()
                .unwrap(),
            fourth.subscription
        );
    }

    #[test]
    fn legacy_snapshot_fails_closed_after_upgrade_removal_or_credential_changes() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        let current = |s: &PushStore| {
            s.legacy_connection_is_current(
                ACCOUNT,
                e.device_id,
                &e.password,
                &e.subscription.endpoint,
            )
            .unwrap()
        };
        assert!(!current(&store));
        store
            .db
            .execute(
                "INSERT INTO connections VALUES(?1,?2,?3,?4,0,0)",
                params![
                    e.account_id,
                    e.device_id,
                    e.password,
                    e.subscription.endpoint
                ],
            )
            .unwrap();
        assert!(current(&store));
        assert!(!store
            .legacy_connection_is_current(ACCOUNT, 3, &e.password, &e.subscription.endpoint)
            .unwrap());
        assert!(!store
            .legacy_connection_is_current(
                ACCOUNT,
                2,
                "different-password",
                &e.subscription.endpoint
            )
            .unwrap());
        assert!(!store
            .legacy_connection_is_current(ACCOUNT, 2, &e.password, "https://different.test/")
            .unwrap());
        store
            .db
            .execute("UPDATE connections SET forbidden=1", [])
            .unwrap();
        assert!(!current(&store));
        store
            .db
            .execute("UPDATE connections SET forbidden=0", [])
            .unwrap();
        store.enroll(&e, NOW).unwrap();
        assert!(!current(&store));
        store.remove(ACCOUNT).unwrap();
        assert!(!current(&store));
    }

    #[test]
    fn queue_and_ledger_capacity_fail_closed_without_partial_inserts() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        for n in 0..MAX_QUEUE_PER_ACCOUNT {
            store
                .enqueue(ACCOUNT, &event(&e, 100 + n as u64), NOW)
                .unwrap();
        }
        assert_eq!(
            store.enqueue(ACCOUNT, &event(&e, 999), NOW),
            Err(StoreError::QueueFull)
        );
        assert_eq!(store.pending_count(None).unwrap(), MAX_QUEUE_PER_ACCOUNT);
        store
            .db
            .execute("DELETE FROM encrypted_push_queue", [])
            .unwrap();
        store
            .db
            .execute("DELETE FROM encrypted_push_event_ids", [])
            .unwrap();
        // Construct a boundary-sized retained ledger without thousands of fsyncs.
        store.db.execute("WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<8192) INSERT INTO encrypted_push_event_ids SELECT printf('fixture-%d',x),?1,'fixture-digest',?2 FROM n",params![ACCOUNT,NOW+300]).unwrap();
        assert_eq!(
            store.enqueue(ACCOUNT, &event(&e, 999), NOW),
            Err(StoreError::QueueFull)
        );
        assert_eq!(store.pending_count(None).unwrap(), 0);
        store
            .db
            .execute("DELETE FROM encrypted_push_event_ids", [])
            .unwrap();
        let mut second = enrollment();
        second.account_id = id(9);
        second.request_id = id(10);
        store.enroll(&second, NOW).unwrap();
        store.db.execute("WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO encrypted_push_event_ids SELECT printf('fixture-%d',x),?1,'fixture-digest',?2 FROM n",params![ACCOUNT,NOW+300]).unwrap();
        store.db.execute("INSERT INTO encrypted_push_queue(event_id,account_id,subscription_epoch,event_json,expires_at,attempts,next_attempt_at) SELECT event_id,account_id,1,'{}',expires_at,0,?1 FROM encrypted_push_event_ids",[NOW]).unwrap();
        assert_eq!(
            store.enqueue(&second.account_id, &event(&second, 999), NOW),
            Err(StoreError::QueueFull)
        );
        assert_eq!(store.pending_count(None).unwrap(), MAX_QUEUE_GLOBAL);
    }

    #[test]
    fn canonical_digest_sorts_nested_objects_and_preserves_array_order() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"z":1,"a":[{"d":2,"b":1}]}"#).unwrap();
        let expected = openssl::sha::sha256(br#"{"a":[{"b":1,"d":2}],"z":1}"#)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(digest(&value).unwrap(), expected);
        assert_ne!(
            digest(&serde_json::json!([1, 2])).unwrap(),
            digest(&serde_json::json!([2, 1])).unwrap()
        );
    }

    #[test]
    fn global_account_capacity_rejects_new_registration_but_preserves_receipt_replay() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        store.db.execute("WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4095) INSERT INTO connections SELECT printf('fixture-account-%d',x),2,?1,?2,0,?3 FROM n",params![e.password,e.subscription.endpoint,NOW]).unwrap();
        let sub = serde_json::to_string(&e.subscription).unwrap();
        store.db.execute("INSERT INTO encrypted_subscriptions SELECT uuid,1,?1,'active',device_id,password,endpoint,?2 FROM connections WHERE uuid<>?3",params![sub,NOW,ACCOUNT]).unwrap();
        let mut next = e.clone();
        next.account_id = id(987);
        next.request_id = id(988);
        assert_eq!(
            store.enroll(&next, NOW + 1),
            Err(StoreError::CapacityExceeded)
        );
        assert!(store.receipt_for(&next).unwrap().is_none());
        assert!(store.enroll(&e, NOW + 1).unwrap().replayed);
        assert_eq!(
            store.list_enrolled_account_ids().unwrap().len(),
            MAX_ACCOUNTS
        );
        store.remove("fixture-account-1").unwrap();
        assert_eq!(
            store.enroll(&next, NOW + 2).unwrap().disposition,
            EnrollmentDisposition::Created
        );
        assert!(matches!(
            store.claim_due(i64::MAX),
            Err(StoreError::StateUnavailable)
        ));
    }

    #[test]
    fn request_capacity_preserves_original_receipt_and_does_not_prune_history() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        store.enroll(&e, NOW).unwrap();
        store.db.execute("WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1023) INSERT INTO encrypted_enrollment_requests SELECT ?1,printf('fixture-%d',x),'fixture-digest',1,'unchanged',?2 FROM n",params![ACCOUNT,NOW]).unwrap();
        let next = rotate(&e, 2);
        assert_eq!(
            store.enroll(&next, NOW + 10),
            Err(StoreError::CapacityExceeded)
        );
        assert!(store.enroll(&e, NOW + 1_000_000).unwrap().replayed);
        assert_eq!(
            store
                .get_subscription(ACCOUNT)
                .unwrap()
                .unwrap()
                .subscription_epoch,
            1
        );
    }
}
