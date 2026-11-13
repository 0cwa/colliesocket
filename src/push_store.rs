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
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::Signer,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::HashSet, fmt, fs, future::Future, path::Path, time::Duration};

pub const SCHEMA_VERSION: u32 = 5;
pub const MAX_JSON_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_IMPORT_SEQUENCE: u64 = i64::MAX as u64;
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
pub const CONTROL_STATUS_RETRY_SECONDS: i64 = 30;
pub const LEGACY_DISPATCH_TIMEOUT: Duration = Duration::from_secs(10);
const SQLITE_WRITE_WAIT: Duration = Duration::from_secs(15);

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
    #[serde(
        default,
        deserialize_with = "present_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub import_seq: Option<u64>,
    pub account_id: String,
    pub device_id: u32,
    pub password: String,
    #[serde(
        default,
        deserialize_with = "present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub control_key: Option<String>,
    pub subscription: Subscription,
}

#[derive(Clone, Serialize, Deserialize)]
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
    #[serde(skip)]
    pub(crate) event_identity: Option<EventIdentity>,
}

impl PartialEq for Subscription {
    fn eq(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint
            && self.p256dh == other.p256dh
            && self.auth == other.auth
            && self.instance == other.instance
            && self.subscription_epoch == other.subscription_epoch
            && self.encryption_required == other.encryption_required
            && self.supported_event_versions == other.supported_event_versions
            && self.capabilities == other.capabilities
    }
}
impl Eq for Subscription {}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EventIdentity {
    pub key_id: String,
    pub import_id: String,
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
        deserialize_with = "present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub code: Option<String>,
    #[serde(
        default,
        deserialize_with = "present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub key_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub import_id: Option<String>,
}

fn present_string<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    // An omitted optional string is permitted, but explicit JSON null is not.
    String::deserialize(d).map(Some)
}

fn present_u64<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Option<u64>, D::Error> {
    u64::deserialize(d).map(Some)
}

macro_rules! redacted_debug {
    ($($t:ty),+) => { $(impl fmt::Debug for $t {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($t), "([REDACTED])"))
        }
    })+ };
}
redacted_debug!(Enrollment, Subscription, Event);

#[derive(Clone, PartialEq, Eq)]
pub struct ControlContext {
    pub subscription: Subscription,
    pub control_key: String,
}
redacted_debug!(ControlContext);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlDisposition {
    Applied,
    Unchanged,
}

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

fn event_key_id_vector(
    account_id: &str,
    device_id: u32,
    instance: &str,
    control_key: &str,
) -> Result<(Vec<u8>, Vec<u8>, String)> {
    if !canonical_uuid(account_id, false) || !valid_instance(instance) {
        return Err(StoreError::InvalidEnrollment);
    }
    let key = key_bytes(control_key, 32)?;
    let mut message = b"COLLIESOCKET-EVENT-KEY-ID\0\x03".to_vec();
    let uuid_hex: Vec<u8> = account_id.bytes().filter(|byte| *byte != b'-').collect();
    for pair in uuid_hex.chunks_exact(2) {
        let pair = std::str::from_utf8(pair).map_err(|_| StoreError::InvalidEnrollment)?;
        message.push(u8::from_str_radix(pair, 16).map_err(|_| StoreError::InvalidEnrollment)?);
    }
    message.extend_from_slice(&device_id.to_be_bytes());
    let instance_len = u16::try_from(instance.len()).map_err(|_| StoreError::InvalidEnrollment)?;
    message.extend_from_slice(&instance_len.to_be_bytes());
    message.extend_from_slice(instance.as_bytes());

    let pkey = PKey::hmac(&key).map_err(|_| StoreError::StateUnavailable)?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), &pkey).map_err(|_| StoreError::StateUnavailable)?;
    signer
        .update(&message)
        .map_err(|_| StoreError::StateUnavailable)?;
    let digest = signer
        .sign_to_vec()
        .map_err(|_| StoreError::StateUnavailable)?;
    if digest.len() != 32 {
        return Err(StoreError::StateUnavailable);
    }
    let key_id = URL_SAFE_NO_PAD.encode(&digest);
    Ok((message, digest, key_id))
}

fn event_key_id(
    account_id: &str,
    device_id: u32,
    instance: &str,
    control_key: &str,
) -> Result<String> {
    event_key_id_vector(account_id, device_id, instance, control_key).map(|(_, _, key_id)| key_id)
}

fn event_identity(
    account_id: &str,
    device_id: u32,
    instance: &str,
    control_key: Option<&str>,
    import_id: Option<&str>,
) -> Result<Option<EventIdentity>> {
    match (control_key, import_id) {
        (Some(control_key), Some(import_id)) => Ok(Some(EventIdentity {
            key_id: event_key_id(account_id, device_id, instance, control_key)?,
            import_id: import_id.to_owned(),
        })),
        (None, None) => Ok(None),
        _ => Err(StoreError::StateUnavailable),
    }
}

fn restore_subscription(
    json: &str,
    account_id: &str,
    device_id: u32,
    control_key: Option<&str>,
    import_id: Option<&str>,
) -> Result<Subscription> {
    let mut subscription: Subscription = serde_json::from_str(json)?;
    if subscription.event_version() == 3 {
        subscription.event_identity = Some(
            event_identity(
                account_id,
                device_id,
                &subscription.instance,
                control_key,
                import_id,
            )?
            .ok_or(StoreError::StateUnavailable)?,
        );
    }
    Ok(subscription)
}

impl Subscription {
    pub fn event_version(&self) -> u32 {
        match self.supported_event_versions.as_slice() {
            [1, 2] => 2,
            [1, 2, 3] => 3,
            _ => 1,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.encryption_required {
            return Err(StoreError::EncryptionRequired);
        }
        if self.supported_event_versions != [1]
            && self.supported_event_versions != [1, 2]
            && self.supported_event_versions != [1, 2, 3]
        {
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
        if !matches!(self.enrollment_version, 1 | 2 | 3) {
            return Err(StoreError::UnsupportedVersion);
        }
        match self.control_key.as_deref() {
            Some(key) => {
                if !matches!(self.enrollment_version, 2 | 3) {
                    return Err(StoreError::InvalidEnrollment);
                }
                key_bytes(key, 32)?;
                let expected: &[u32] = if self.enrollment_version == 3 {
                    &[1, 2, 3]
                } else {
                    &[1, 2]
                };
                if self.subscription.supported_event_versions != expected {
                    return Err(StoreError::UnsupportedVersion);
                }
            }
            None if self.subscription.supported_event_versions != [1] => {
                return Err(StoreError::UnsupportedVersion);
            }
            None => (),
        }
        if self.enrollment_version == 3 {
            let sequence = self.import_seq.ok_or(StoreError::InvalidEnrollment)?;
            if !(1..=MAX_IMPORT_SEQUENCE).contains(&sequence) || self.control_key.is_none() {
                return Err(StoreError::InvalidEnrollment);
            }
        } else if self.import_seq.is_some() {
            return Err(StoreError::InvalidEnrollment);
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
        if !matches!(self.version, 1 | 2 | 3)
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
        match self.version {
            1 | 2 if self.key_id.is_some() || self.import_id.is_some() => {
                return Err(StoreError::InvalidEvent)
            }
            3 => {
                let key_id = self.key_id.as_deref().ok_or(StoreError::InvalidEvent)?;
                let import_id = self.import_id.as_deref().ok_or(StoreError::InvalidEvent)?;
                if key_bytes(key_id, 32).is_err() || !canonical_uuid(import_id, true) {
                    return Err(StoreError::InvalidEvent);
                }
            }
            _ => (),
        }
        match (self.version, self.kind.as_str(), self.code.as_deref()) {
            (_, "wake" | "test", None)
            | (_, "status", Some("connection_conflict" | "connection_unavailable"))
            | (2 | 3, "status", Some("subscription_updated"))
            | (3, "status", Some("enrollment_imported")) => (),
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
        // Legacy dispatch uses a configured 10-second Tokio timeout while it
        // holds SQLite's database-wide writer reservation. Contending writers
        // have a separate 15-second SQLite busy wait.
        db.busy_timeout(SQLITE_WRITE_WAIT)?;
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

    /// Retry only the current v3 import status for an exact cached receipt.
    /// Historical receipts remain read-only and never imply current state.
    pub fn retry_current_import_status(
        &mut self,
        enrollment: &Enrollment,
        now: i64,
    ) -> Result<bool> {
        enrollment.validate()?;
        if enrollment.enrollment_version != 3 {
            return Ok(false);
        }
        if now < 0 || now as u64 > MAX_JSON_INTEGER {
            return Err(StoreError::InvalidEnrollment);
        }
        let hash = digest(enrollment)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if receipt(&tx, enrollment, &hash)?.is_none() {
            tx.commit()?;
            return Ok(false);
        }
        let row: Option<(
            String,
            String,
            u32,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<i64>,
        )> = tx
            .query_row(
                "SELECT subscription_json,state,connection_device_id,connection_password,connection_endpoint,control_key,import_id,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                [&enrollment.account_id],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
            )
            .optional()?;
        let mut current_replay = false;
        if let Some((json, state, device, password, endpoint, control_key, import_id, seq)) = row {
            let expected_json = serde_json::to_string(&enrollment.subscription)?;
            if json == expected_json
                && device == enrollment.device_id
                && password == enrollment.password
                && endpoint == enrollment.subscription.endpoint
                && control_key == enrollment.control_key
                && import_id.as_deref() == Some(enrollment.request_id.as_str())
                && seq == enrollment.import_seq.map(|value| value as i64)
            {
                current_replay = true;
                if state == "active" {
                    let event = make_enrollment_imported_event(enrollment, now)?;
                    ensure_enrollment_confirmation(&tx, &enrollment.account_id, &event, now)?;
                }
            }
        }
        tx.commit()?;
        Ok(current_replay)
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
        let existing: Option<(
            String,
            String,
            u32,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<i64>,
        )> = tx
            .query_row(
                "SELECT subscription_json,state,connection_device_id,connection_password,connection_endpoint,control_key,import_id,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                [&enrollment.account_id],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
            )
            .optional()?;
        let disposition;
        let mut changed_credentials = false;
        let mut intent_only_update = false;
        if let Some((
            json,
            state,
            device,
            password,
            connection_endpoint,
            control_key,
            import_id,
            import_seq,
        )) = existing
        {
            let old: Subscription = serde_json::from_str(&json)?;
            changed_credentials = device != enrollment.device_id || password != enrollment.password;
            if enrollment.enrollment_version == 3 {
                let incoming_seq = enrollment.import_seq.ok_or(StoreError::InvalidEnrollment)?;
                let same_credentials =
                    !changed_credentials && connection_endpoint == enrollment.subscription.endpoint;
                let same_control_key = control_key == enrollment.control_key;
                let exact_subscription = old == enrollment.subscription;
                let next_epoch = old.subscription_epoch < MAX_JSON_INTEGER
                    && enrollment.subscription.subscription_epoch == old.subscription_epoch + 1;
                let fresh_key = !same_control_key;

                if let Some(floor) = import_seq {
                    if import_id.is_none()
                        || import_id.as_deref() == Some(enrollment.request_id.as_str())
                        || floor < 1
                        || incoming_seq <= floor as u64
                    {
                        return Err(StoreError::EpochConflict);
                    }
                    let reaffirmation = state == "active"
                        && enrollment.subscription.subscription_epoch == old.subscription_epoch
                        && exact_subscription
                        && same_credentials
                        && same_control_key;
                    if reaffirmation {
                        intent_only_update = true;
                        disposition = EnrollmentDisposition::Rotated;
                    } else if next_epoch && fresh_key {
                        disposition = EnrollmentDisposition::Rotated;
                    } else {
                        return Err(StoreError::EpochConflict);
                    }
                } else {
                    if import_id.is_some() {
                        return Err(StoreError::StateUnavailable);
                    }
                    let mut old_with_v3_versions = old.clone();
                    old_with_v3_versions.supported_event_versions =
                        enrollment.subscription.supported_event_versions.clone();
                    let adoption = state == "active"
                        && old.supported_event_versions == [1, 2]
                        && enrollment.subscription.supported_event_versions == [1, 2, 3]
                        && enrollment.subscription.subscription_epoch == old.subscription_epoch
                        && old_with_v3_versions == enrollment.subscription
                        && same_credentials
                        && same_control_key;
                    if adoption {
                        intent_only_update = true;
                        disposition = EnrollmentDisposition::Rotated;
                    } else if next_epoch && fresh_key {
                        disposition = EnrollmentDisposition::Rotated;
                    } else {
                        return Err(StoreError::EpochConflict);
                    }
                }
            } else if import_seq.is_some() || import_id.is_some() {
                // A cached exact v1/v2 receipt was handled above. A fresh
                // legacy request cannot express or lower the retained floor.
                return Err(StoreError::EpochConflict);
            } else {
                // A control blob authenticates account/device/version/epoch,
                // not the private password or instance. Every state-changing
                // keyed legacy import therefore needs a fresh key.
                let unchanged = enrollment.subscription.subscription_epoch
                    == old.subscription_epoch
                    && old == enrollment.subscription
                    && !changed_credentials
                    && connection_endpoint == enrollment.subscription.endpoint
                    && control_key == enrollment.control_key
                    && state == "active";
                if enrollment.control_key.is_some()
                    && control_key == enrollment.control_key
                    && !unchanged
                {
                    return Err(StoreError::InvalidEnrollment);
                }
                if unchanged {
                    disposition = EnrollmentDisposition::Unchanged;
                } else if old.subscription_epoch < MAX_JSON_INTEGER
                    && enrollment.subscription.subscription_epoch == old.subscription_epoch + 1
                {
                    disposition = EnrollmentDisposition::Rotated;
                } else {
                    return Err(StoreError::EpochConflict);
                }
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
                tx.execute("INSERT INTO encrypted_subscriptions(account_id,subscription_epoch,subscription_json,state,connection_device_id,connection_password,connection_endpoint,updated_at,control_key,import_id,import_seq) VALUES(?1,?2,?3,'active',?4,?5,?6,?7,?8,?9,?10)",
                    params![enrollment.account_id,enrollment.subscription.subscription_epoch as i64,json,enrollment.device_id,enrollment.password,enrollment.subscription.endpoint,now,enrollment.control_key,if enrollment.enrollment_version == 3 {Some(enrollment.request_id.as_str())} else {None},enrollment.import_seq.map(|sequence| sequence as i64)])?;
            } else if intent_only_update {
                // Same-key same-epoch adoption/reaffirmation changes only
                // negotiated protocol or import intent metadata. Preserve the
                // active state and Signal replay window.
                tx.execute("UPDATE encrypted_subscriptions SET subscription_json=?2,updated_at=?3,import_id=?4,import_seq=?5 WHERE account_id=?1",
                    params![enrollment.account_id,json,now,enrollment.request_id,enrollment.import_seq.map(|sequence| sequence as i64)])?;
                tx.execute(
                    "DELETE FROM encrypted_push_queue WHERE account_id=?1",
                    [&enrollment.account_id],
                )?;
            } else {
                // Update the shadow tuple first, so the legacy-overwrite guard
                // permits exactly this connection update inside the transaction.
                tx.execute("UPDATE encrypted_subscriptions SET subscription_epoch=?2,subscription_json=?3,state='active',connection_device_id=?4,connection_password=?5,connection_endpoint=?6,updated_at=?7,control_key=?8,last_control_digest=NULL,control_status_at=NULL,import_id=?9,import_seq=?10 WHERE account_id=?1",
                    params![enrollment.account_id,enrollment.subscription.subscription_epoch as i64,json,enrollment.device_id,enrollment.password,enrollment.subscription.endpoint,now,enrollment.control_key,if enrollment.enrollment_version == 3 {Some(enrollment.request_id.as_str())} else {None},enrollment.import_seq.map(|sequence| sequence as i64)])?;
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
            // Private replacement revokes every earlier socket, even when its
            // credential tuple and control key later return to old values.
            // Controls and idempotent imports deliberately retain this token.
            tx.execute(
                "INSERT INTO encrypted_subscription_generations(account_id,generation) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET generation=excluded.generation",
                params![enrollment.account_id, token()?],
            )?;
            if enrollment.enrollment_version == 3 {
                let event = make_enrollment_imported_event(enrollment, now)?;
                ensure_enrollment_confirmation(&tx, &enrollment.account_id, &event, now)?;
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
        let row: Option<(String, u32, Option<String>, Option<String>)> = self
            .db
            .query_row(
                "SELECT subscription_json,connection_device_id,control_key,import_id FROM encrypted_subscriptions WHERE account_id=?1",
                [account_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        row.map(|(json, device_id, control_key, import_id)| {
            restore_subscription(
                &json,
                account_id,
                device_id,
                control_key.as_deref(),
                import_id.as_deref(),
            )
        })
        .transpose()
    }

    /// Capture once before connecting, never refresh it from a socket callback.
    /// A new private import revokes the generation while controls retain it.
    pub fn private_generation_for_connection(
        &self,
        co: &crate::db::Connection,
    ) -> Result<Option<String>> {
        let generation: Option<String> = self.db.query_row(
            "SELECT g.generation FROM encrypted_subscription_generations g JOIN connections c ON c.uuid=g.account_id WHERE c.uuid=?1 AND c.device_id=?2 AND c.password=?3 AND c.endpoint=?4 AND c.forbidden=0",
            params![co.uuid,co.device_id,co.password,co.endpoint], |r| r.get(0)).optional()?;
        if let Some(generation) = &generation {
            key_bytes(generation, 32).map_err(|_| StoreError::StateUnavailable)?;
        }
        Ok(generation)
    }

    /// A key is available only to the current, non-forbidden socket generation.
    /// Endpoint changes made by control must be reflected in that tuple before
    /// processing the next message; a replaced private import stays obsolete.
    pub fn control_context_for_connection(
        &self,
        co: &crate::db::Connection,
        expected_generation: &str,
    ) -> Result<Option<ControlContext>> {
        let row: Option<(String, String, Option<String>, u32)> = self.db.query_row(
            "SELECT s.subscription_json,s.control_key,s.import_id,s.connection_device_id FROM encrypted_subscriptions s JOIN connections c ON c.uuid=s.account_id JOIN encrypted_subscription_generations g ON g.account_id=s.account_id WHERE s.account_id=?1 AND c.device_id=?2 AND c.password=?3 AND c.endpoint=?4 AND c.forbidden=0 AND s.control_key IS NOT NULL AND g.generation=?5",
            params![co.uuid,co.device_id,co.password,co.endpoint,expected_generation],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        row.map(|(json, control_key, import_id, device_id)| {
            let subscription = restore_subscription(
                &json,
                &co.uuid,
                device_id,
                Some(&control_key),
                import_id.as_deref(),
            )?;
            subscription.validate()?;
            key_bytes(&control_key, 32)?;
            if !matches!(subscription.event_version(), 2 | 3) {
                return Err(StoreError::StateUnavailable);
            }
            Ok(ControlContext {
                subscription,
                control_key,
            })
        })
        .transpose()
    }

    /// Apply an already authenticated control frame after the caller has
    /// authorized its endpoint. This transaction rechecks the exact private
    /// credential/key snapshot, advances only the permitted fields, and queues
    /// confirmation before the transport may acknowledge the Signal frame.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_endpoint_update(
        &mut self,
        co: &crate::db::Connection,
        expected_generation: &str,
        expected_key: &str,
        new_subscription: &Subscription,
        wire_digest: &[u8; 32],
        confirmation: &Event,
        now: i64,
    ) -> Result<ControlDisposition> {
        new_subscription.validate()?;
        key_bytes(expected_key, 32)?;
        confirmation.validate(now)?;
        if !matches!(new_subscription.event_version(), 2 | 3)
            || confirmation.version != new_subscription.event_version()
            || confirmation.kind != "status"
            || confirmation.code.as_deref() != Some("subscription_updated")
            || confirmation.instance != new_subscription.instance
            || confirmation.subscription_epoch != new_subscription.subscription_epoch
        {
            return Err(StoreError::InvalidEvent);
        }
        let hash: String = wire_digest.iter().map(|b| format!("{b:02x}")).collect();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(String, String, Option<String>, Option<i64>, String)> = tx.query_row(
            "SELECT s.subscription_json,s.control_key,s.last_control_digest,s.control_status_at,s.state FROM encrypted_subscriptions s JOIN connections c ON c.uuid=s.account_id JOIN encrypted_subscription_generations g ON g.account_id=s.account_id WHERE s.account_id=?1 AND c.device_id=?2 AND c.password=?3 AND c.endpoint=?4 AND c.forbidden=0 AND s.control_key IS NOT NULL AND g.generation=?5",
            params![co.uuid,co.device_id,co.password,co.endpoint,expected_generation],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let (json, control_key, previous_digest, last_status, state) =
            current.ok_or(StoreError::SubscriptionMissing)?;
        if control_key != expected_key {
            return Err(StoreError::EpochConflict);
        }
        let old: Subscription = serde_json::from_str(&json)?;
        if old.instance != new_subscription.instance
            || old.encryption_required != new_subscription.encryption_required
            || old.supported_event_versions != new_subscription.supported_event_versions
            || old.capabilities != new_subscription.capabilities
        {
            return Err(StoreError::InvalidEnrollment);
        }
        if new_subscription.subscription_epoch <= old.subscription_epoch {
            if new_subscription.subscription_epoch != old.subscription_epoch
                || previous_digest.as_deref() != Some(hash.as_str())
                || old != *new_subscription
            {
                return Err(StoreError::EpochConflict);
            }
            // Replay never changes the subscription or revives inactive state.
            // A lost push receipt may only recover its bounded confirmation.
            if state == "active" {
                ensure_control_confirmation(&tx, &co.uuid, confirmation, last_status, now)?;
            }
            tx.commit()?;
            return Ok(ControlDisposition::Unchanged);
        }

        let json = serde_json::to_string(new_subscription)?;
        // The shadow tuple must change first to satisfy the legacy write guard.
        tx.execute("UPDATE encrypted_subscriptions SET subscription_epoch=?2,subscription_json=?3,state='active',connection_endpoint=?4,updated_at=?5,last_control_digest=?6,control_status_at=NULL WHERE account_id=?1",
            params![co.uuid,new_subscription.subscription_epoch as i64,json,new_subscription.endpoint,now,hash])?;
        if tx.execute(
            "UPDATE connections SET endpoint=?2 WHERE uuid=?1",
            params![co.uuid, new_subscription.endpoint],
        )? != 1
        {
            return Err(StoreError::StateUnavailable);
        }
        tx.execute(
            "DELETE FROM encrypted_push_queue WHERE account_id=?1",
            [&co.uuid],
        )?;
        ensure_control_confirmation(&tx, &co.uuid, confirmation, None, now)?;
        tx.commit()?;
        Ok(ControlDisposition::Applied)
    }

    /// Build an event from this exact snapshot, then pass it directly to
    /// `enqueue_for_connection`, which rechecks the generation and forbidden
    /// flag together with the event's epoch/instance inside its transaction.
    /// Endpoint must be the original string, not a URL-normalized rendering.
    pub fn subscription_for_connection(
        &self,
        account_id: &str,
        device_id: u32,
        password: &str,
        endpoint: &str,
        expected_generation: &str,
    ) -> Result<Option<Subscription>> {
        let row: Option<(String, Option<String>, Option<String>)> = self.db.query_row(
            "SELECT s.subscription_json,s.control_key,s.import_id FROM encrypted_subscriptions s JOIN connections c ON c.uuid=s.account_id JOIN encrypted_subscription_generations g ON g.account_id=s.account_id WHERE s.account_id=?1 AND c.device_id=?2 AND c.password=?3 AND c.endpoint=?4 AND c.forbidden=0 AND g.generation=?5",
            params![account_id,device_id,password,endpoint,expected_generation], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        row.map(|(json, control_key, import_id)| {
            restore_subscription(
                &json,
                account_id,
                device_id,
                control_key.as_deref(),
                import_id.as_deref(),
            )
        })
        .transpose()
    }

    /// Serialize a legacy authorization and its bounded dispatch against every
    /// encrypted import. SQLite's IMMEDIATE transaction is shared across
    /// processes; its writer lock is database-wide, so other accounts' writes
    /// also wait for this request. The transport must bound `dispatch`.
    pub(crate) async fn with_legacy_dispatch<F, Fut, T>(
        &mut self,
        co: &crate::db::Connection,
        dispatch: F,
    ) -> Result<Option<T>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM connections c WHERE c.uuid=?1 AND c.device_id=?2 AND c.password=?3 AND c.endpoint=?4 AND c.forbidden=0 AND NOT EXISTS(SELECT 1 FROM encrypted_subscriptions s WHERE s.account_id=c.uuid))",
            params![co.uuid, co.device_id, co.password, co.endpoint],
            |r| r.get(0),
        )?;
        if !current {
            return Ok(None);
        }

        // The authorization remains protected until the request future ends.
        // The caller applies the configured 10-second Tokio timeout across
        // DNS, policy checks, and HTTP.
        let outcome = dispatch().await;
        tx.commit()?;
        Ok(Some(outcome))
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
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let queued = enqueue_event(&tx, account_id, event, now)?;
        tx.commit()?;
        Ok(queued)
    }

    /// Recheck the socket's private generation and credentials in the same
    /// transaction as enqueue. Rejected callbacks must not even prune the queue.
    pub fn enqueue_for_connection(
        &mut self,
        co: &crate::db::Connection,
        expected_generation: &str,
        event: &Event,
        now: i64,
    ) -> Result<bool> {
        event.validate(now)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM connections c JOIN encrypted_subscription_generations g ON g.account_id=c.uuid WHERE c.uuid=?1 AND c.device_id=?2 AND c.password=?3 AND c.endpoint=?4 AND c.forbidden=0 AND g.generation=?5)",
            params![co.uuid,co.device_id,co.password,co.endpoint,expected_generation], |r| r.get(0))?;
        if !current {
            return Ok(false);
        }
        let queued = enqueue_event(&tx, &co.uuid, event, now)?;
        tx.commit()?;
        Ok(queued)
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

fn ensure_control_confirmation(
    tx: &Transaction<'_>,
    account_id: &str,
    event: &Event,
    last_status: Option<i64>,
    now: i64,
) -> Result<()> {
    if last_status.is_some_and(|last| now < last.saturating_add(CONTROL_STATUS_RETRY_SECONDS)) {
        return Ok(());
    }
    let pending: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM encrypted_push_queue WHERE account_id=?1 AND subscription_epoch=?2 AND expires_at>?3 AND (attempts<4 OR lease_until>?3) AND json_extract(event_json,'$.version')=?4 AND json_extract(event_json,'$.kind')='status' AND json_extract(event_json,'$.code')='subscription_updated' AND (?5 IS NULL OR json_extract(event_json,'$.import_id')=?5) AND (?6 IS NULL OR json_extract(event_json,'$.key_id')=?6))",
        params![account_id,event.subscription_epoch as i64,now,event.version,event.import_id,event.key_id], |r| r.get(0))?;
    if !pending {
        if !enqueue_event(tx, account_id, event, now)? {
            return Err(StoreError::InvalidEvent);
        }
        tx.execute(
            "UPDATE encrypted_subscriptions SET control_status_at=?2 WHERE account_id=?1",
            params![account_id, now],
        )?;
    }
    Ok(())
}

fn make_enrollment_imported_event(enrollment: &Enrollment, now: i64) -> Result<Event> {
    if enrollment.enrollment_version != 3 || enrollment.subscription.event_version() != 3 {
        return Err(StoreError::InvalidEnrollment);
    }
    let control_key = enrollment
        .control_key
        .as_deref()
        .ok_or(StoreError::InvalidEnrollment)?;
    let event = Event {
        version: 3,
        event_id: random_uuid_v4()?,
        instance: enrollment.subscription.instance.clone(),
        subscription_epoch: enrollment.subscription.subscription_epoch,
        kind: "status".into(),
        issued_at: now,
        expires_at: now.saturating_add(MAX_EVENT_LIFETIME),
        code: Some("enrollment_imported".into()),
        key_id: Some(event_key_id(
            &enrollment.account_id,
            enrollment.device_id,
            &enrollment.subscription.instance,
            control_key,
        )?),
        import_id: Some(enrollment.request_id.clone()),
    };
    event.validate(now)?;
    Ok(event)
}

fn ensure_enrollment_confirmation(
    tx: &Transaction<'_>,
    account_id: &str,
    event: &Event,
    now: i64,
) -> Result<()> {
    let pending: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM encrypted_push_queue WHERE account_id=?1 AND subscription_epoch=?2 AND expires_at>?3 AND (attempts<?4 OR lease_until>?3) AND json_extract(event_json,'$.version')=3 AND json_extract(event_json,'$.kind')='status' AND json_extract(event_json,'$.code')='enrollment_imported' AND json_extract(event_json,'$.import_id')=?5 AND json_extract(event_json,'$.key_id')=?6)",
        params![account_id,event.subscription_epoch as i64,now,MAX_ATTEMPTS,event.import_id,event.key_id],
        |r| r.get(0),
    )?;
    if pending {
        return Ok(());
    }
    let last_status: Option<i64> = tx.query_row(
        "SELECT max(created_at) FROM encrypted_push_event_ids WHERE account_id=?1 AND status_retry_key=?2",
        params![account_id,event.import_id],
        |r| r.get(0),
    )?;
    if last_status.is_some_and(|last| now < last.saturating_add(CONTROL_STATUS_RETRY_SECONDS)) {
        return Ok(());
    }
    if !enqueue_event(tx, account_id, event, now)? {
        return Err(StoreError::InvalidEvent);
    }
    Ok(())
}

fn random_uuid_v4() -> Result<String> {
    let mut bytes = [0u8; 16];
    openssl::rand::rand_bytes(&mut bytes).map_err(|_| StoreError::StateUnavailable)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

// All enrollment checks and outbox changes share the caller's transaction.
fn enqueue_event(tx: &Transaction<'_>, account_id: &str, event: &Event, now: i64) -> Result<bool> {
    event.validate(now)?;
    let json = serde_json::to_string(event)?;
    let hash = digest(&(account_id, event))?;
    prune(tx, now)?;
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
        return Ok(false);
    }
    let current: Option<(String, String, u32, Option<String>, Option<String>)> = tx
        .query_row(
            "SELECT subscription_json,state,connection_device_id,control_key,import_id FROM encrypted_subscriptions WHERE account_id=?1",
            [account_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let (sub_json, state, device_id, control_key, import_id) =
        current.ok_or(StoreError::SubscriptionMissing)?;
    let sub = restore_subscription(
        &sub_json,
        account_id,
        device_id,
        control_key.as_deref(),
        import_id.as_deref(),
    )?;
    if sub.subscription_epoch != event.subscription_epoch || sub.instance != event.instance {
        return Err(StoreError::EpochConflict);
    }
    if event.version != sub.event_version() {
        return Err(StoreError::UnsupportedVersion);
    }
    if event.version == 3
        && sub.event_identity.as_ref().is_none_or(|identity| {
            event.key_id.as_deref() != Some(identity.key_id.as_str())
                || event.import_id.as_deref() != Some(identity.import_id.as_str())
        })
    {
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
    let status_retry_key =
        if event.version == 3 && event.code.as_deref() == Some("enrollment_imported") {
            event.import_id.as_deref()
        } else {
            None
        };
    tx.execute("INSERT INTO encrypted_push_event_ids(event_id,account_id,event_digest,expires_at,status_retry_key,created_at) VALUES(?1,?2,?3,?4,?5,?6)", params![event.event_id,account_id,hash,event.expires_at,status_retry_key,now])?;
    tx.execute("INSERT INTO encrypted_push_queue(event_id,account_id,subscription_epoch,event_json,expires_at,attempts,next_attempt_at) VALUES(?1,?2,?3,?4,?5,0,?6)", params![event.event_id,account_id,event.subscription_epoch as i64,json,event.expires_at,now])?;
    Ok(true)
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
        ("table", "encrypted_subscription_generations"),
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
    // A schema marker alone must not make a partially migrated store usable.
    db.prepare("SELECT control_key,last_control_digest,control_status_at,import_id,import_seq FROM encrypted_subscriptions LIMIT 0")?;
    db.prepare("SELECT event_id,event_digest,expires_at,status_retry_key,created_at FROM encrypted_push_event_ids LIMIT 0")?;
    db.prepare("SELECT account_id,generation FROM encrypted_subscription_generations LIMIT 0")?;
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
    if version < 2 {
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
    }
    if version < 3 {
        tx.execute_batch(
            "ALTER TABLE encrypted_subscriptions ADD COLUMN control_key TEXT;
         ALTER TABLE encrypted_subscriptions ADD COLUMN last_control_digest TEXT;
         ALTER TABLE encrypted_subscriptions ADD COLUMN control_status_at INTEGER;",
        )?;
    }
    if version < 4 {
        tx.execute_batch(
            "CREATE TABLE encrypted_subscription_generations(
             account_id TEXT PRIMARY KEY REFERENCES encrypted_subscriptions(account_id) ON DELETE CASCADE,
             generation TEXT NOT NULL);",
        )?;
        let accounts: Vec<String> = tx
            .prepare("SELECT account_id FROM encrypted_subscriptions")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for account in accounts {
            tx.execute(
                "INSERT INTO encrypted_subscription_generations(account_id,generation) VALUES(?1,?2)",
                params![account, token()?],
            )?;
        }
    }
    if version < 5 {
        tx.execute_batch(
            "ALTER TABLE encrypted_subscriptions ADD COLUMN import_id TEXT;
             ALTER TABLE encrypted_subscriptions ADD COLUMN import_seq INTEGER
             CHECK(import_seq IS NULL OR import_seq BETWEEN 1 AND 9223372036854775807);
             ALTER TABLE encrypted_push_event_ids ADD COLUMN status_retry_key TEXT;
             ALTER TABLE encrypted_push_event_ids ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    // Invalid historical schemas must roll back the whole migration, including
    // the generation table and schema marker, instead of partially advancing.
    verify_schema(&tx)?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcKey, PointConversionForm};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, Ordering},
            OnceLock,
        },
    };

    const NOW: i64 = 1_800_000_000;
    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    static SQLITE_BUSY_OBSERVED: AtomicBool = AtomicBool::new(false);
    static SQLITE_BUSY_STOP: AtomicBool = AtomicBool::new(false);

    fn observe_sqlite_busy(_: i32) -> bool {
        SQLITE_BUSY_OBSERVED.store(true, Ordering::Release);
        std::thread::sleep(Duration::from_millis(1));
        !SQLITE_BUSY_STOP.load(Ordering::Acquire)
    }

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
            control_key: None,
            subscription: Subscription {
                endpoint: "https://push.example.test/synthetic-token".into(),
                p256dh: public.clone(),
                auth: URL_SAFE_NO_PAD.encode([7u8; 16]),
                instance: "collie:test-1".into(),
                subscription_epoch: 1,
                encryption_required: true,
                supported_event_versions: vec![1],
                capabilities: vec!["wake".into(), "test".into(), "status".into()],
                event_identity: None,
            },
            import_seq: None,
        }
    }
    fn event(enrollment: &Enrollment, n: u64) -> Event {
        let identity = if enrollment.enrollment_version == 3 {
            Some(EventIdentity {
                key_id: event_key_id(
                    &enrollment.account_id,
                    enrollment.device_id,
                    &enrollment.subscription.instance,
                    enrollment.control_key.as_deref().unwrap(),
                )
                .unwrap(),
                import_id: enrollment.request_id.clone(),
            })
        } else {
            None
        };
        Event {
            version: enrollment.subscription.event_version(),
            event_id: id(n),
            instance: enrollment.subscription.instance.clone(),
            subscription_epoch: enrollment.subscription.subscription_epoch,
            kind: "wake".into(),
            issued_at: NOW,
            expires_at: NOW + 300,
            code: None,
            key_id: identity.as_ref().map(|value| value.key_id.clone()),
            import_id: identity.map(|value| value.import_id),
        }
    }
    fn rotate(enrollment: &Enrollment, n: u64) -> Enrollment {
        let mut new = enrollment.clone();
        new.request_id = id(n);
        new.subscription.subscription_epoch += 1;
        new
    }
    fn keyed_enrollment() -> Enrollment {
        let mut e = enrollment();
        e.enrollment_version = 2;
        e.control_key = Some(URL_SAFE_NO_PAD.encode([23u8; 32]));
        e.subscription.supported_event_versions = vec![1, 2];
        e
    }

    fn v3_enrollment() -> Enrollment {
        let mut e = keyed_enrollment();
        e.enrollment_version = 3;
        e.import_seq = Some(1);
        e.subscription.supported_event_versions = vec![1, 2, 3];
        e
    }

    fn v3_import_from(e: &Enrollment, request: u64, sequence: u64) -> Enrollment {
        let mut next = e.clone();
        next.enrollment_version = 3;
        next.request_id = id(request);
        next.import_seq = Some(sequence);
        next.subscription.supported_event_versions = vec![1, 2, 3];
        next
    }

    fn server_seed_v3_from_template(
        store: &mut PushStore,
        template: &Enrollment,
        epoch: u64,
        sequence: u64,
        final_request_id: Option<&str>,
    ) -> Enrollment {
        assert!(epoch >= 1 && sequence >= epoch);
        let base_request = if epoch == 1 {
            final_request_id
                .map(str::to_owned)
                .unwrap_or_else(|| id(20_000))
        } else {
            id(20_000)
        };
        let mut current = v3_import_from(template, 20_000, sequence - epoch + 1);
        current.request_id = base_request;
        current.subscription.subscription_epoch = 1;
        if epoch > 1 {
            current.control_key = Some(URL_SAFE_NO_PAD.encode([21; 32]));
        }
        store.enroll(&current, NOW).unwrap();
        for next_epoch in 2..=epoch {
            current = v3_import_from(&current, 20_000 + next_epoch, sequence - epoch + next_epoch);
            if next_epoch == epoch {
                if let Some(request_id) = final_request_id {
                    current.request_id = request_id.to_owned();
                }
            }
            current.subscription.subscription_epoch = next_epoch;
            current.control_key = Some(URL_SAFE_NO_PAD.encode([next_epoch as u8 + 30; 32]));
            if next_epoch == epoch {
                current.control_key = template.control_key.clone();
                current.subscription = template.subscription.clone();
                current.subscription.subscription_epoch = next_epoch;
            }
            store
                .enroll(&current, NOW + next_epoch as i64)
                .unwrap_or_else(|error| panic!("fixture seed epoch {next_epoch}: {error:?}"));
        }
        current
    }

    fn server_seed_v3(
        store: &mut PushStore,
        epoch: u64,
        sequence: u64,
        final_request_id: Option<&str>,
    ) -> Enrollment {
        server_seed_v3_from_template(store, &v3_enrollment(), epoch, sequence, final_request_id)
    }

    fn private_generation(store: &PushStore) -> String {
        private_generation_for(store, ACCOUNT)
    }
    fn private_generation_for(store: &PushStore, account_id: &str) -> String {
        store
            .db
            .query_row(
                "SELECT generation FROM encrypted_subscription_generations WHERE account_id=?1",
                [account_id],
                |r| r.get(0),
            )
            .unwrap()
    }
    fn connection(e: &Enrollment) -> crate::db::Connection {
        crate::db::Connection::new(
            e.account_id.clone(),
            e.device_id,
            e.password.clone(),
            e.subscription.endpoint.clone(),
        )
    }
    fn confirmation(sub: &Subscription, n: u64, now: i64) -> Event {
        Event {
            version: 2,
            event_id: id(n),
            instance: sub.instance.clone(),
            subscription_epoch: sub.subscription_epoch,
            kind: "status".into(),
            issued_at: now,
            expires_at: now + 300,
            code: Some("subscription_updated".into()),
            key_id: None,
            import_id: None,
        }
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
                SCHEMA_VERSION
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
    fn migration_from_two_preserves_v1_receipts_and_queued_pushes() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        let original = store.enroll(&e, NOW).unwrap();
        store.enqueue(ACCOUNT, &event(&e, 11), NOW).unwrap();
        // Reconstruct the previous schema without touching its existing rows.
        store
            .db
            .execute_batch(
                "DROP TABLE encrypted_subscription_generations;
             ALTER TABLE encrypted_subscriptions DROP COLUMN control_key;
             ALTER TABLE encrypted_subscriptions DROP COLUMN last_control_digest;
             ALTER TABLE encrypted_subscriptions DROP COLUMN control_status_at;
             ALTER TABLE encrypted_subscriptions DROP COLUMN import_id;
             ALTER TABLE encrypted_subscriptions DROP COLUMN import_seq;
             ALTER TABLE encrypted_push_event_ids DROP COLUMN status_retry_key;
             ALTER TABLE encrypted_push_event_ids DROP COLUMN created_at;
             PRAGMA user_version=2;",
            )
            .unwrap();
        drop(store);
        let mut store = dir.store();
        let receipt = store.receipt_for(&e).unwrap().unwrap();
        assert!(receipt.replayed);
        assert_eq!(receipt.disposition, original.disposition);
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap(),
            Some(e.subscription.clone())
        );
        assert!(store
            .control_context_for_connection(&connection(&e), &private_generation(&store))
            .unwrap()
            .is_none());
        assert_eq!(store.pending_count(None).unwrap(), 1);
        assert_eq!(store.claim_due(NOW).unwrap().unwrap().event.version, 1);
        assert!(!serde_json::to_string(&e).unwrap().contains("control_key"));
    }

    #[test]
    fn migration_from_four_preserves_receipts_generations_and_leased_events() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = keyed_enrollment();
        let original = store.enroll(&e, NOW).unwrap();
        store.enqueue(ACCOUNT, &event(&e, 111), NOW).unwrap();
        store.claim_due(NOW).unwrap().unwrap();
        let generation = private_generation(&store);
        let leased: (u32, i64, Option<i64>, Option<String>) = store
            .db
            .query_row(
                "SELECT attempts,next_attempt_at,lease_until,lease_token FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        store
            .db
            .execute_batch(
                "ALTER TABLE encrypted_subscriptions DROP COLUMN import_id;
                 ALTER TABLE encrypted_subscriptions DROP COLUMN import_seq;
                 ALTER TABLE encrypted_push_event_ids DROP COLUMN status_retry_key;
                 ALTER TABLE encrypted_push_event_ids DROP COLUMN created_at;
                 PRAGMA user_version=4;",
            )
            .unwrap();
        drop(store);

        let store = dir.store();
        assert_eq!(private_generation(&store), generation);
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap(),
            Some(e.subscription.clone())
        );
        assert_eq!(store.pending_count(None).unwrap(), 1);
        let after_lease: (u32, i64, Option<i64>, Option<String>) = store
            .db
            .query_row(
                "SELECT attempts,next_attempt_at,lease_until,lease_token FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(after_lease, leased);
        assert!(
            store.receipt_for(&e).unwrap().is_some_and(
                |receipt| receipt.replayed && receipt.disposition == original.disposition
            )
        );
        let null_intent: (Option<String>, Option<i64>) = store
            .db
            .query_row(
                "SELECT import_id,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                [ACCOUNT],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(null_intent, (None, None));
    }

    #[test]
    fn enrollment_v2_requires_exact_optional_key_and_negotiation() {
        let good = keyed_enrollment();
        good.validate().unwrap();
        assert_eq!(good.subscription.event_version(), 2);
        let mut no_key = enrollment();
        no_key.enrollment_version = 2;
        no_key.validate().unwrap();
        assert_eq!(no_key.subscription.event_version(), 1);
        let mut bad = good.clone();
        bad.enrollment_version = 1;
        assert_eq!(bad.validate(), Err(StoreError::InvalidEnrollment));
        for key in [
            String::new(),
            URL_SAFE_NO_PAD.encode([23u8; 31]),
            format!("{}=", good.control_key.as_ref().unwrap()),
        ] {
            let mut bad = good.clone();
            bad.control_key = Some(key);
            assert_eq!(bad.validate(), Err(StoreError::InvalidKeys));
        }
        let mut bad = good.clone();
        bad.control_key = None;
        assert_eq!(bad.validate(), Err(StoreError::UnsupportedVersion));
        let mut bad = good.clone();
        bad.subscription.supported_event_versions = vec![1];
        assert_eq!(bad.validate(), Err(StoreError::UnsupportedVersion));
        let json = serde_json::to_string(&no_key).unwrap();
        assert!(serde_json::from_str::<Enrollment>(&json.replacen(
            '{',
            "{\"control_key\":null,",
            1
        ))
        .is_err());
        let json = serde_json::to_string(&good).unwrap();
        assert!(serde_json::from_str::<Enrollment>(&json.replacen(
            '{',
            "{\"control_key\":\"duplicate\",",
            1
        ))
        .is_err());
        assert!(!format!("{good:?}").contains(good.control_key.as_ref().unwrap()));
        let mut status = confirmation(&good.subscription, 12, NOW);
        status.validate(NOW).unwrap();
        status.version = 1;
        assert_eq!(status.validate(NOW), Err(StoreError::InvalidEvent));
    }

    #[test]
    fn enrollment_v3_requires_signed_sequence_and_exact_negotiation() {
        let good = v3_enrollment();
        good.validate().unwrap();
        assert_eq!(good.subscription.event_version(), 3);
        assert!(!serde_json::to_string(&keyed_enrollment())
            .unwrap()
            .contains("import_seq"));
        for sequence in [None, Some(0), Some(MAX_IMPORT_SEQUENCE + 1)] {
            let mut bad = good.clone();
            bad.import_seq = sequence;
            assert_eq!(bad.validate(), Err(StoreError::InvalidEnrollment));
        }
        let mut bad = good.clone();
        bad.subscription.supported_event_versions = vec![1, 2];
        assert_eq!(bad.validate(), Err(StoreError::UnsupportedVersion));
        let mut bad = good.clone();
        bad.subscription.capabilities = vec!["wake".into()];
        assert_eq!(bad.validate(), Err(StoreError::CapabilityRequired));
        bad.subscription.supported_event_versions = vec![1, 2];
        assert_eq!(bad.validate(), Err(StoreError::UnsupportedVersion));
        let mut bad = keyed_enrollment();
        bad.import_seq = Some(1);
        assert_eq!(bad.validate(), Err(StoreError::InvalidEnrollment));

        let json = serde_json::to_string(&good).unwrap();
        assert!(serde_json::from_str::<Enrollment>(
            &json.replace("\"import_seq\":1", "\"import_seq\":null")
        )
        .is_err());
    }

    #[test]
    fn rust_key_id_matches_the_canonical_v3_message_and_digest_vector() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/contracts/encrypted-push/v3/fixtures/key-id-v3.json"
        )))
        .unwrap();
        let (message, digest, key_id) = event_key_id_vector(
            fixture["account_id"].as_str().unwrap(),
            fixture["device_id"].as_u64().unwrap() as u32,
            fixture["instance"].as_str().unwrap(),
            fixture["control_key"].as_str().unwrap(),
        )
        .unwrap();
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(hex(&message), fixture["message_hex"]);
        assert_eq!(hex(&digest), fixture["digest_hex"]);
        assert_eq!(key_id, fixture["key_id"]);
    }

    #[test]
    fn v3_events_require_canonical_identity_and_v1_v2_stay_identity_free() {
        let v2 = keyed_enrollment();
        let mut v2_event = event(&v2, 901);
        v2_event.validate(NOW).unwrap();
        v2_event.key_id = Some(URL_SAFE_NO_PAD.encode([9u8; 32]));
        assert_eq!(v2_event.validate(NOW), Err(StoreError::InvalidEvent));

        let v3 = v3_enrollment();
        let good = event(&v3, 902);
        good.validate(NOW).unwrap();
        let mut missing = good.clone();
        missing.import_id = None;
        assert_eq!(missing.validate(NOW), Err(StoreError::InvalidEvent));
        let mut bad_key = good;
        bad_key.key_id = Some(format!("{}=", URL_SAFE_NO_PAD.encode([9u8; 32])));
        assert_eq!(bad_key.validate(NOW), Err(StoreError::InvalidEvent));
    }

    #[test]
    fn keyed_legacy_row_adopts_v3_at_the_same_epoch_and_queues_bound_status() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let legacy = crate::enrollment::parse(include_bytes!(
            "../contracts/encrypted-push/v2/fixtures/enrollment-keyed.json"
        ))
        .unwrap();
        store.enroll(&legacy, NOW).unwrap();
        store
            .enqueue(&legacy.account_id, &event(&legacy, 903), NOW)
            .unwrap();
        let old_generation = private_generation_for(&store, &legacy.account_id);

        let adoption = crate::enrollment::parse(include_bytes!(
            "../contracts/encrypted-push/v3/fixtures/enrollment-first-v3-adoption-v3.json"
        ))
        .unwrap();
        assert_eq!(
            adoption.subscription.subscription_epoch,
            legacy.subscription.subscription_epoch
        );
        assert_eq!(adoption.control_key, legacy.control_key);
        let result = store.enroll(&adoption, NOW + 1).unwrap();
        assert_eq!(result.disposition, EnrollmentDisposition::Rotated);
        assert_ne!(
            private_generation_for(&store, &legacy.account_id),
            old_generation
        );
        assert_eq!(store.pending_count(None).unwrap(), 1);
        let row: (Option<String>, Option<i64>) = store
            .db
            .query_row(
                "SELECT import_id,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                [&legacy.account_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                Some(adoption.request_id.clone()),
                adoption.import_seq.map(|sequence| sequence as i64)
            )
        );

        let after_adoption = durable_snapshot(&store);
        let replay = store.enroll(&legacy, NOW + 2).unwrap();
        assert!(replay.replayed);
        assert_eq!(durable_snapshot(&store), after_adoption);
        let mut stale_legacy = legacy.clone();
        stale_legacy.request_id = id(908);
        assert_eq!(
            store.enroll(&stale_legacy, NOW + 2),
            Err(StoreError::EpochConflict)
        );
        assert_eq!(durable_snapshot(&store), after_adoption);

        let imported = store.claim_due(NOW + 1).unwrap().unwrap().event;
        assert_eq!(imported.version, 3);
        assert_eq!(imported.kind, "status");
        assert_eq!(imported.code.as_deref(), Some("enrollment_imported"));
        assert_eq!(
            imported.import_id.as_deref(),
            Some(adoption.request_id.as_str())
        );
        assert_eq!(
            imported.key_id.as_deref(),
            Some(
                event_key_id(
                    &adoption.account_id,
                    adoption.device_id,
                    &adoption.subscription.instance,
                    adoption.control_key.as_deref().unwrap(),
                )
                .unwrap()
                .as_str()
            )
        );

        let subscription = store.get_subscription(&legacy.account_id).unwrap().unwrap();
        let serialized = serde_json::to_string(&subscription).unwrap();
        assert!(!serialized.contains("event_identity"));
        assert!(!serialized.contains(&adoption.request_id));
    }

    #[test]
    fn rejected_first_v3_adoption_mismatches_leave_every_table_unchanged() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../contracts/encrypted-push/v3/fixtures/first-v3-adoption-cases-v3.json"
        ))
        .unwrap();
        for mismatch in fixture["rejected_adoption_mutations"]
            .as_array()
            .unwrap()
            .iter()
        {
            let id = mismatch["id"].as_str().unwrap();
            let dir = TestDir::new();
            let mut store = dir.store();
            let legacy = crate::enrollment::parse(include_bytes!(
                "../contracts/encrypted-push/v2/fixtures/enrollment-keyed.json"
            ))
            .unwrap();
            store.enroll(&legacy, NOW).unwrap();
            store
                .enqueue(&legacy.account_id, &event(&legacy, 909), NOW)
                .unwrap();
            let before = durable_snapshot(&store);
            let before_generation = private_generation_for(&store, &legacy.account_id);
            let mut candidate = crate::enrollment::parse(include_bytes!(
                "../contracts/encrypted-push/v3/fixtures/enrollment-first-v3-adoption-v3.json"
            ))
            .unwrap();
            let value = &mismatch["value"];
            if mismatch["expected_error"] == "invalid_enrollment" {
                let mut candidate_json = serde_json::to_value(&candidate).unwrap();
                *candidate_json
                    .pointer_mut("/subscription/supported_event_versions")
                    .unwrap() = value.clone();
                assert!(
                    serde_json::from_value::<Enrollment>(candidate_json).is_err(),
                    "{} must fail strict deserialization",
                    id
                );
                assert_eq!(durable_snapshot(&store), before);
                assert_eq!(
                    private_generation_for(&store, &legacy.account_id),
                    before_generation
                );
                continue;
            }
            match mismatch["path"].as_str().unwrap() {
                "subscription.endpoint" => {
                    candidate.subscription.endpoint = value.as_str().unwrap().into()
                }
                "control_key" => candidate.control_key = Some(value.as_str().unwrap().into()),
                "subscription.p256dh" => {
                    candidate.subscription.p256dh = value.as_str().unwrap().into()
                }
                "subscription.auth" => candidate.subscription.auth = value.as_str().unwrap().into(),
                "password" => candidate.password = value.as_str().unwrap().into(),
                "device_id" => candidate.device_id = value.as_u64().unwrap() as u32,
                "subscription.instance" => {
                    candidate.subscription.instance = value.as_str().unwrap().into()
                }
                "subscription.capabilities" => {
                    candidate.subscription.capabilities =
                        serde_json::from_value(value.clone()).unwrap()
                }
                "subscription.supported_event_versions" => {
                    candidate.subscription.supported_event_versions =
                        serde_json::from_value(value.clone()).unwrap()
                }
                path => panic!("unexpected adoption mutation path: {path}"),
            }
            let expected = match mismatch["expected_error"].as_str().unwrap() {
                "epoch_conflict" => StoreError::EpochConflict,
                "capability_required" => StoreError::CapabilityRequired,
                "unsupported_version" => StoreError::UnsupportedVersion,
                error => panic!("unexpected adoption error: {error}"),
            };
            assert_eq!(store.enroll(&candidate, NOW + 1), Err(expected), "{}", id);
            if expected == StoreError::EpochConflict {
                assert!(store.receipt_for(&candidate).unwrap().is_none());
            }
            assert_eq!(durable_snapshot(&store), before);
            assert_eq!(
                private_generation_for(&store, &legacy.account_id),
                before_generation
            );
        }
    }

    #[test]
    fn account_selection_creates_independent_registration_and_requires_epoch_one() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../contracts/encrypted-push/v3/fixtures/first-v3-adoption-cases-v3.json"
        ))
        .unwrap();
        let cases = fixture["account_selection_cases"].as_array().unwrap();
        assert_eq!(cases.len(), 2);

        for case in cases {
            let dir = TestDir::new();
            let mut store = dir.store();
            let existing_a: Enrollment = serde_json::from_str(include_str!(
                "../contracts/encrypted-push/v2/fixtures/enrollment-keyed.json"
            ))
            .unwrap();
            assert_eq!(
                existing_a.account_id,
                case["existing_account_a"]["account_id"].as_str().unwrap()
            );
            store.enroll(&existing_a, NOW).unwrap();
            store
                .enqueue(&existing_a.account_id, &event(&existing_a, 919), NOW)
                .unwrap();
            let before_a = durable_account_snapshot(&store, &existing_a.account_id);
            let before = durable_snapshot(&store);

            let enrollment_fixture = match case["id"].as_str().unwrap() {
                "independent-account-b-epoch1-create" => "enrollment-independent-account-b-v3.json",
                "absent-account-b-epoch-above-one-rejected" => {
                    "enrollment-absent-account-b-epoch2-v3.json"
                }
                id => panic!("unexpected account-selection vector: {id}"),
            };
            let raw = match enrollment_fixture {
                "enrollment-independent-account-b-v3.json" => include_str!(
                    "../contracts/encrypted-push/v3/fixtures/enrollment-independent-account-b-v3.json"
                ),
                "enrollment-absent-account-b-epoch2-v3.json" => include_str!(
                    "../contracts/encrypted-push/v3/fixtures/enrollment-absent-account-b-epoch2-v3.json"
                ),
                _ => unreachable!(),
            };
            let enrollment: Enrollment = serde_json::from_str(raw).unwrap();
            assert_eq!(
                enrollment.account_id,
                case["selected_account_id"].as_str().unwrap()
            );
            assert_eq!(enrollment.request_id, case["request_id"].as_str().unwrap());
            assert_eq!(enrollment.control_key, existing_a.control_key);

            if case["expected"] == "create_b" {
                let response: serde_json::Value = serde_json::from_str(include_str!(
                    "../contracts/encrypted-push/v3/fixtures/response-independent-account-b-v3.json"
                ))
                .unwrap();
                let expected_event: Event = serde_json::from_str(include_str!(
                    "../contracts/encrypted-push/v3/fixtures/event-independent-account-b-v3.json"
                ))
                .unwrap();
                let result = store.enroll(&enrollment, NOW + 1).unwrap();
                assert!(!result.replayed);
                assert_eq!(result.disposition, EnrollmentDisposition::Created);
                assert_eq!(result.subscription_epoch, 1);
                assert_eq!(response["status"], "accepted");
                assert_eq!(response["replayed"], false);
                assert_eq!(response["subscription_epoch"], 1);
                assert_eq!(
                    store.get_subscription(&enrollment.account_id).unwrap(),
                    Some(enrollment.subscription.clone())
                );
                let queued_json: String = store
                    .db
                    .query_row(
                        "SELECT event_json FROM encrypted_push_queue WHERE account_id=?1",
                        [&enrollment.account_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                let queued: Event = serde_json::from_str(&queued_json).unwrap();
                assert_eq!(queued.version, expected_event.version);
                assert_eq!(queued.instance, expected_event.instance);
                assert_eq!(queued.subscription_epoch, expected_event.subscription_epoch);
                assert_eq!(queued.key_id, expected_event.key_id);
                assert_eq!(queued.import_id, expected_event.import_id);
                assert_eq!(queued.kind, expected_event.kind);
                assert_eq!(queued.code, expected_event.code);
                assert_eq!(
                    durable_account_snapshot(&store, &existing_a.account_id),
                    before_a
                );
                assert_ne!(durable_snapshot(&store), before);
            } else {
                assert_eq!(case["expected_error"], "epoch_conflict");
                assert_eq!(
                    store.enroll(&enrollment, NOW + 1),
                    Err(StoreError::EpochConflict)
                );
                assert_eq!(durable_snapshot(&store), before);
                assert_eq!(
                    durable_account_snapshot(&store, &existing_a.account_id),
                    before_a
                );
                assert!(store.receipt_for(&enrollment).unwrap().is_none());
            }
        }
    }

    #[test]
    fn inactive_first_adoption_and_reaffirmation_vectors_are_no_mutation_rejections() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../contracts/encrypted-push/v3/fixtures/first-v3-adoption-cases-v3.json"
        ))
        .unwrap();
        for (index, case) in fixture["inactive_same_epoch_cases"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let dir = TestDir::new();
            let mut store = dir.store();
            let candidate = match case["operation"].as_str().unwrap() {
                "first_v3_adoption" => {
                    let legacy = keyed_enrollment();
                    store.enroll(&legacy, NOW).unwrap();
                    v3_import_from(&legacy, 940 + index as u64, 20)
                }
                "same_epoch_reaffirmation" => {
                    let first = v3_enrollment();
                    store.enroll(&first, NOW).unwrap();
                    v3_import_from(&first, 940 + index as u64, 2)
                }
                operation => panic!("unexpected inactive operation: {operation}"),
            };
            store
                .db
                .execute(
                    "UPDATE encrypted_subscriptions SET state=?2 WHERE account_id=?1",
                    params![ACCOUNT, case["row_state"].as_str().unwrap()],
                )
                .unwrap();
            let before = durable_snapshot(&store);
            let generation = private_generation(&store);
            assert_eq!(
                store.enroll(&candidate, NOW + 1),
                Err(StoreError::EpochConflict),
                "{}",
                case["id"].as_str().unwrap()
            );
            assert!(store.receipt_for(&candidate).unwrap().is_none());
            assert_eq!(durable_snapshot(&store), before);
            assert_eq!(private_generation(&store), generation);
        }
    }

    #[test]
    fn same_epoch_reaffirmation_replaces_intent_and_inactive_reaffirmation_is_read_only() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let first = v3_enrollment();
        store.enroll(&first, NOW).unwrap();
        let first_event = event(&first, 905);
        let first_generation = private_generation(&store);

        let second = v3_import_from(&first, 906, 2);
        store.enroll(&second, NOW + 1).unwrap();
        let second_generation = private_generation(&store);
        assert_ne!(second_generation, first_generation);
        assert_eq!(store.pending_count(None).unwrap(), 1);
        assert_eq!(
            store.enqueue(ACCOUNT, &first_event, NOW + 2),
            Err(StoreError::EpochConflict)
        );
        let current = store.claim_due(NOW + 2).unwrap().unwrap().event;
        assert_eq!(
            current.import_id.as_deref(),
            Some(second.request_id.as_str())
        );

        store
            .db
            .execute(
                "UPDATE encrypted_subscriptions SET state='stale' WHERE account_id=?1",
                [ACCOUNT],
            )
            .unwrap();
        let before_count: usize = store
            .db
            .query_row(
                "SELECT count(*) FROM encrypted_enrollment_requests WHERE account_id=?1",
                [ACCOUNT],
                |r| row_count(r, 0),
            )
            .unwrap();
        let before_queue: usize = store
            .db
            .query_row(
                "SELECT count(*) FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
                |r| row_count(r, 0),
            )
            .unwrap();
        let third = v3_import_from(&second, 907, 3);
        assert_eq!(
            store.enroll(&third, NOW + 3),
            Err(StoreError::EpochConflict)
        );
        assert_eq!(private_generation(&store), second_generation);
        assert_eq!(
            store
                .db
                .query_row(
                    "SELECT count(*) FROM encrypted_enrollment_requests WHERE account_id=?1",
                    [ACCOUNT],
                    |r| row_count(r, 0),
                )
                .unwrap(),
            before_count
        );
        assert_eq!(
            store
                .db
                .query_row(
                    "SELECT count(*) FROM encrypted_push_queue WHERE account_id=?1",
                    [ACCOUNT],
                    |r| row_count(r, 0),
                )
                .unwrap(),
            before_queue
        );
    }

    #[test]
    fn current_v3_receipt_status_retry_is_bounded_and_never_rotates_generation() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let current = v3_enrollment();
        store.enroll(&current, NOW).unwrap();
        let generation = private_generation(&store);
        let initial_event: String = store
            .db
            .query_row(
                "SELECT event_json FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
                |r| r.get(0),
            )
            .unwrap();
        let initial_event: Event = serde_json::from_str(&initial_event).unwrap();

        assert!(store
            .retry_current_import_status(&current, NOW + CONTROL_STATUS_RETRY_SECONDS)
            .unwrap());
        assert_eq!(store.pending_count(None).unwrap(), 1);
        assert_eq!(private_generation(&store), generation);
        let status_id_count: usize = store
            .db
            .query_row(
                "SELECT count(*) FROM encrypted_push_event_ids WHERE status_retry_key=?1",
                [&current.request_id],
                |r| row_count(r, 0),
            )
            .unwrap();
        assert_eq!(status_id_count, 1);

        store
            .db
            .execute(
                "DELETE FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
            )
            .unwrap();
        assert!(store
            .retry_current_import_status(&current, NOW + CONTROL_STATUS_RETRY_SECONDS + 1)
            .unwrap());
        assert_eq!(store.pending_count(None).unwrap(), 1);
        assert_eq!(private_generation(&store), generation);
        let retried: String = store
            .db
            .query_row(
                "SELECT event_json FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
                |r| r.get(0),
            )
            .unwrap();
        let retried: Event = serde_json::from_str(&retried).unwrap();
        assert_ne!(retried.event_id, initial_event.event_id);
        assert_eq!(retried.import_id, initial_event.import_id);
        assert_eq!(retried.key_id, initial_event.key_id);
        let latest_status_at: i64 = store
            .db
            .query_row(
                "SELECT max(created_at) FROM encrypted_push_event_ids WHERE status_retry_key=?1",
                [&current.request_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(latest_status_at, NOW + CONTROL_STATUS_RETRY_SECONDS + 1);

        assert!(store
            .retry_current_import_status(&current, NOW + CONTROL_STATUS_RETRY_SECONDS + 2)
            .unwrap());
        assert_eq!(store.pending_count(None).unwrap(), 1);
        assert_eq!(private_generation(&store), generation);
        let status_id_count_after_coalesce: usize = store
            .db
            .query_row(
                "SELECT count(*) FROM encrypted_push_event_ids WHERE status_retry_key=?1",
                [&current.request_id],
                |r| row_count(r, 0),
            )
            .unwrap();
        assert_eq!(status_id_count_after_coalesce, 2);

        store
            .db
            .execute(
                "UPDATE encrypted_subscriptions SET state='stale' WHERE account_id=?1",
                [ACCOUNT],
            )
            .unwrap();
        store
            .db
            .execute(
                "DELETE FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
            )
            .unwrap();
        assert!(store
            .retry_current_import_status(&current, NOW + 100)
            .unwrap());
        assert_eq!(store.pending_count(None).unwrap(), 0);
        assert_eq!(private_generation(&store), generation);
        assert_eq!(
            store
                .db
                .query_row(
                    "SELECT count(*) FROM encrypted_push_event_ids WHERE status_retry_key=?1",
                    [&current.request_id],
                    |r| row_count(r, 0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn enrollment_replay_coalesces_a_live_fourth_lease_and_retries_after_expiry() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let current = v3_enrollment();
        store.enroll(&current, NOW).unwrap();
        let generation = private_generation(&store);
        let mut fourth_claim = None;

        for (index, when) in [NOW, NOW + 5, NOW + 35, NOW + 155].into_iter().enumerate() {
            let claim = store.claim_due(when).unwrap().unwrap();
            assert_eq!(claim.attempt, index as u32 + 1);
            if claim.attempt < MAX_ATTEMPTS {
                store
                    .complete(&claim, DeliveryOutcome::Retry { retry_after: None }, when)
                    .unwrap();
            } else {
                fourth_claim = Some(claim);
            }
        }

        let fourth_claim = fourth_claim.unwrap();
        let original_event_id = fourth_claim.event.event_id.clone();
        let live_lease_until = NOW + 155 + LEASE_SECONDS;
        let before_live_replay = durable_snapshot(&store);
        let replay = store.enroll(&current, NOW + 156).unwrap();
        assert!(replay.replayed);
        assert!(crate::enrollment::current_v3_replay_status(
            &mut store,
            &current,
            &replay,
            NOW + 156,
        )
        .unwrap());
        assert_eq!(durable_snapshot(&store), before_live_replay);
        assert_eq!(private_generation(&store), generation);
        let leased: (u32, Option<i64>, Option<String>) = store
            .db
            .query_row(
                "SELECT attempts,lease_until,lease_token FROM encrypted_push_queue WHERE event_id=?1",
                [&original_event_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(leased.0, MAX_ATTEMPTS);
        assert_eq!(leased.1, Some(live_lease_until));
        assert!(leased.2.is_some());
        assert_eq!(store.pending_count(Some(ACCOUNT)).unwrap(), 1);

        let retry_after_expiry = store.enroll(&current, live_lease_until).unwrap();
        assert!(retry_after_expiry.replayed);
        assert!(crate::enrollment::current_v3_replay_status(
            &mut store,
            &current,
            &retry_after_expiry,
            live_lease_until,
        )
        .unwrap());
        assert_eq!(private_generation(&store), generation);
        assert_eq!(store.pending_count(Some(ACCOUNT)).unwrap(), 1);
        let replacement: (String, u32) = store
            .db
            .query_row(
                "SELECT event_id,attempts FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_ne!(replacement.0, original_event_id);
        assert_eq!(replacement.1, 0);
        let retry_rows: usize = store
            .db
            .query_row(
                "SELECT count(*) FROM encrypted_push_event_ids WHERE status_retry_key=?1",
                [&current.request_id],
                |row| row_count(row, 0),
            )
            .unwrap();
        assert_eq!(retry_rows, 2);
        let latest_status_at: i64 = store
            .db
            .query_row(
                "SELECT max(created_at) FROM encrypted_push_event_ids WHERE status_retry_key=?1",
                [&current.request_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(latest_status_at, live_lease_until);
    }

    #[test]
    fn a_later_v3_wake_repeats_identity_after_import_status_is_lost() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let current = v3_enrollment();
        store.enroll(&current, NOW).unwrap();
        store
            .db
            .execute(
                "DELETE FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
            )
            .unwrap();

        let subscription = store.get_subscription(ACCOUNT).unwrap().unwrap();
        let wake = crate::push::new_event(&subscription, "wake", None).unwrap();
        assert_eq!(wake.version, 3);
        assert_eq!(wake.import_id.as_deref(), Some(current.request_id.as_str()));
        store.enqueue(ACCOUNT, &wake, wake.issued_at).unwrap();
        let stored: String = store
            .db
            .query_row(
                "SELECT event_json FROM encrypted_push_queue WHERE event_id=?1",
                [&wake.event_id],
                |r| r.get(0),
            )
            .unwrap();
        let stored: Event = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored.key_id, wake.key_id);
        assert_eq!(stored.import_id, wake.import_id);
        assert_eq!(stored.code, None);
    }

    #[test]
    fn v3_control_update_keeps_import_identity_and_uses_v3_confirmation() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let enrollment = v3_enrollment();
        store.enroll(&enrollment, NOW).unwrap();
        let connection = connection(&enrollment);
        let generation = private_generation(&store);
        let context = store
            .control_context_for_connection(&connection, &generation)
            .unwrap()
            .unwrap();
        let mut updated = context.subscription.clone();
        updated.endpoint = "https://push.example.test/updated-v3".into();
        updated.subscription_epoch += 1;
        let mut confirmation = confirmation(&updated, 921, NOW);
        confirmation.version = 3;
        confirmation.key_id = Some(
            event_key_id(
                &enrollment.account_id,
                enrollment.device_id,
                &updated.instance,
                enrollment.control_key.as_deref().unwrap(),
            )
            .unwrap(),
        );
        confirmation.import_id = Some(enrollment.request_id.clone());
        assert_eq!(confirmation.version, 3);
        assert_eq!(
            confirmation.import_id.as_deref(),
            Some(enrollment.request_id.as_str())
        );
        store
            .apply_endpoint_update(
                &connection,
                &generation,
                enrollment.control_key.as_deref().unwrap(),
                &updated,
                &[28; 32],
                &confirmation,
                NOW,
            )
            .unwrap();
        assert_eq!(private_generation(&store), generation);
        let retained: (Option<String>, Option<i64>) = store
            .db
            .query_row(
                "SELECT import_id,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                [ACCOUNT],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(retained, (Some(enrollment.request_id.clone()), Some(1)));
        let queued = store.claim_due(NOW).unwrap().unwrap().event;
        assert_eq!(queued.code.as_deref(), Some("subscription_updated"));
        assert_eq!(queued.version, 3);
        assert_eq!(
            queued.import_id.as_deref(),
            Some(enrollment.request_id.as_str())
        );
    }

    #[test]
    fn historical_v3_receipt_does_not_requeue_or_confirm_a_replaced_intent() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let first = v3_enrollment();
        store.enroll(&first, NOW).unwrap();
        let second = v3_import_from(&first, 912, 2);
        store.enroll(&second, NOW + 1).unwrap();
        let generation = private_generation(&store);
        let before = durable_snapshot(&store);

        assert!(!store
            .retry_current_import_status(&first, NOW + 100)
            .unwrap());
        assert_eq!(durable_snapshot(&store), before);
        assert_eq!(private_generation(&store), generation);
        assert_eq!(store.pending_count(None).unwrap(), 1);
        let current: String = store
            .db
            .query_row(
                "SELECT event_json FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
                |r| r.get(0),
            )
            .unwrap();
        let current: Event = serde_json::from_str(&current).unwrap();
        assert_eq!(
            current.import_id.as_deref(),
            Some(second.request_id.as_str())
        );
    }

    #[test]
    fn receipt_created_after_cache_miss_is_classified_as_current_v3_replay() {
        let dir = TestDir::new();
        let mut delayed = dir.store();
        let mut concurrent = dir.store();
        let enrollment = v3_enrollment();

        // This models the import request's receipt lookup before endpoint DNS.
        assert!(delayed.receipt_for(&enrollment).unwrap().is_none());
        assert!(!concurrent.enroll(&enrollment, NOW).unwrap().replayed);
        let committed = durable_snapshot(&delayed);
        let generation = private_generation(&delayed);

        // The delayed request resumes after the competing process committed.
        let receipt = delayed.enroll(&enrollment, NOW + 1).unwrap();
        assert!(receipt.replayed);
        assert!(crate::enrollment::current_v3_replay_status(
            &mut delayed,
            &enrollment,
            &receipt,
            NOW + 1,
        )
        .unwrap());
        assert_eq!(durable_snapshot(&delayed), committed);
        assert_eq!(private_generation(&delayed), generation);
        assert_eq!(delayed.pending_count(Some(ACCOUNT)).unwrap(), 1);
    }

    #[test]
    fn receipt_created_after_cache_miss_but_superseded_is_historical_and_read_only() {
        let dir = TestDir::new();
        let mut delayed = dir.store();
        let mut concurrent = dir.store();
        let first = v3_enrollment();

        assert!(delayed.receipt_for(&first).unwrap().is_none());
        concurrent.enroll(&first, NOW).unwrap();
        let second = v3_import_from(&first, 928, 2);
        concurrent.enroll(&second, NOW + 1).unwrap();

        let receipt = delayed.enroll(&first, NOW + 2).unwrap();
        assert!(receipt.replayed);
        let before_retry = durable_snapshot(&delayed);
        let generation = private_generation(&delayed);
        assert!(!crate::enrollment::current_v3_replay_status(
            &mut delayed,
            &first,
            &receipt,
            NOW + 2,
        )
        .unwrap());
        assert_eq!(durable_snapshot(&delayed), before_retry);
        assert_eq!(private_generation(&delayed), generation);
        assert_eq!(delayed.pending_count(Some(ACCOUNT)).unwrap(), 1);

        let queued: String = delayed
            .db
            .query_row(
                "SELECT event_json FROM encrypted_push_queue WHERE account_id=?1",
                [ACCOUNT],
                |r| r.get(0),
            )
            .unwrap();
        let queued: Event = serde_json::from_str(&queued).unwrap();
        assert_eq!(
            queued.import_id.as_deref(),
            Some(second.request_id.as_str())
        );
    }

    #[test]
    fn v3_floor_rejects_stale_reused_and_legacy_requests_without_mutation() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let current = v3_import_from(&v3_enrollment(), 913, 8);
        store.enroll(&current, NOW).unwrap();
        let before = durable_snapshot(&store);
        let generation = private_generation(&store);
        let floor_before: (Option<String>, Option<i64>) = store
            .db
            .query_row(
                "SELECT import_id,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                [ACCOUNT],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();

        let mut stale = v3_import_from(&current, 914, 7);
        stale.subscription.subscription_epoch += 1;
        stale.control_key = Some(URL_SAFE_NO_PAD.encode([25u8; 32]));
        assert_eq!(
            store.enroll(&stale, NOW + 1),
            Err(StoreError::EpochConflict)
        );

        let equal = v3_import_from(&current, 915, 8);
        assert_eq!(
            store.enroll(&equal, NOW + 1),
            Err(StoreError::EpochConflict)
        );

        let mut different_key = v3_import_from(&current, 916, 9);
        different_key.control_key = Some(URL_SAFE_NO_PAD.encode([26u8; 32]));
        assert_eq!(
            store.enroll(&different_key, NOW + 1),
            Err(StoreError::EpochConflict)
        );

        let mut conflicting_id = current.clone();
        conflicting_id.import_seq = Some(9);
        assert_eq!(
            store.enroll(&conflicting_id, NOW + 1),
            Err(StoreError::IdempotencyConflict)
        );

        let mut legacy = keyed_enrollment();
        legacy.request_id = id(917);
        assert_eq!(
            store.enroll(&legacy, NOW + 1),
            Err(StoreError::EpochConflict)
        );

        assert_eq!(durable_snapshot(&store), before);
        assert_eq!(private_generation(&store), generation);
        assert_eq!(
            store
                .db
                .query_row(
                    "SELECT import_id,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                    [ACCOUNT],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap(),
            floor_before
        );
    }

    #[test]
    fn server_v3_never_accepts_a_lower_epoch_with_a_newer_sequence() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let current = server_seed_v3(&mut store, 3, 8, None);
        let before = durable_snapshot(&store);
        let generation = private_generation(&store);
        let mut lower = v3_import_from(&current, 918, 9);
        lower.subscription.subscription_epoch = current.subscription.subscription_epoch - 1;

        assert_eq!(
            store.enroll(&lower, NOW + 10),
            Err(StoreError::EpochConflict)
        );
        assert_eq!(durable_snapshot(&store), before);
        assert_eq!(private_generation(&store), generation);
        let retained: (i64, i64) = store
            .db
            .query_row(
                "SELECT subscription_epoch,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                [ACCOUNT],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(retained, (3, 8));
    }

    #[test]
    fn runtime_cases_v3_are_exercised_or_explicitly_phone_only() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../contracts/encrypted-push/v3/fixtures/runtime-cases-v3.json"
        ))
        .unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert!(!cases.is_empty(), "runtime case fixture must not be empty");
        let mut seen = std::collections::HashSet::new();
        for case in cases {
            let id = case["id"].as_str().unwrap();
            assert!(seen.insert(id), "duplicate runtime case {id}");
            match id {
                "stale-sequence-unseen-request-id" => {
                    assert_eq!(case["expected"], "reject");
                    assert_eq!(case["expected_error"], "epoch_conflict");
                    let dir = TestDir::new();
                    let mut store = dir.store();
                    let retained = &case["retained"];
                    let incoming = &case["incoming"];
                    let current = server_seed_v3(
                        &mut store,
                        retained["epoch"].as_u64().unwrap(),
                        retained["import_seq"].as_u64().unwrap(),
                        None,
                    );
                    let before = durable_snapshot(&store);
                    let mut stale =
                        v3_import_from(&current, 1002, incoming["import_seq"].as_u64().unwrap());
                    stale.subscription.subscription_epoch = incoming["epoch"].as_u64().unwrap();
                    stale.control_key = Some(URL_SAFE_NO_PAD.encode([25; 32]));
                    assert_eq!(
                        store.enroll(&stale, NOW + 1),
                        Err(StoreError::EpochConflict)
                    );
                    assert_eq!(durable_snapshot(&store), before);
                }
                "equal-sequence-nonidentical" => {
                    assert_eq!(case["expected"], "reject");
                    assert_eq!(case["expected_error"], "epoch_conflict");
                    let dir = TestDir::new();
                    let mut store = dir.store();
                    let retained = &case["retained"];
                    let incoming = &case["incoming"];
                    let current = server_seed_v3(
                        &mut store,
                        retained["epoch"].as_u64().unwrap(),
                        retained["import_seq"].as_u64().unwrap(),
                        None,
                    );
                    let before = durable_snapshot(&store);
                    let mut equal =
                        v3_import_from(&current, 1004, incoming["import_seq"].as_u64().unwrap());
                    equal.subscription.subscription_epoch = incoming["epoch"].as_u64().unwrap();
                    assert_eq!(
                        store.enroll(&equal, NOW + 1),
                        Err(StoreError::EpochConflict)
                    );
                    assert_eq!(durable_snapshot(&store), before);
                }
                "same-epoch-different-key" => {
                    assert_eq!(case["expected"], "reject");
                    assert_eq!(case["expected_error"], "epoch_conflict");
                    let dir = TestDir::new();
                    let mut store = dir.store();
                    let retained = &case["retained"];
                    let incoming = &case["incoming"];
                    let current = server_seed_v3(
                        &mut store,
                        retained["epoch"].as_u64().unwrap(),
                        retained["import_seq"].as_u64().unwrap(),
                        None,
                    );
                    let before = durable_snapshot(&store);
                    let mut next =
                        v3_import_from(&current, 1006, incoming["import_seq"].as_u64().unwrap());
                    next.subscription.subscription_epoch = incoming["epoch"].as_u64().unwrap();
                    next.control_key = Some(URL_SAFE_NO_PAD.encode([26; 32]));
                    assert_eq!(store.enroll(&next, NOW + 1), Err(StoreError::EpochConflict));
                    assert_eq!(durable_snapshot(&store), before);
                }
                "conflicting-repeated-request-id" => {
                    assert_eq!(case["expected"], "reject");
                    assert_eq!(case["expected_error"], "idempotency_conflict");
                    let dir = TestDir::new();
                    let mut store = dir.store();
                    let retained = &case["retained"];
                    let current = server_seed_v3(
                        &mut store,
                        retained["epoch"].as_u64().unwrap(),
                        retained["import_seq"].as_u64().unwrap(),
                        None,
                    );
                    let before = durable_snapshot(&store);
                    let mut conflict = current.clone();
                    conflict.password.push_str("-different");
                    assert_eq!(
                        store.enroll(&conflict, NOW + 1),
                        Err(StoreError::IdempotencyConflict)
                    );
                    assert_eq!(durable_snapshot(&store), before);
                }
                "reaffirm-same-epoch-fresh-id" => {
                    assert_eq!(case["expected"], "accept");
                    let dir = TestDir::new();
                    let mut store = dir.store();
                    let retained = &case["retained"];
                    let incoming = &case["incoming"];
                    let first = server_seed_v3(
                        &mut store,
                        retained["epoch"].as_u64().unwrap(),
                        retained["import_seq"].as_u64().unwrap(),
                        None,
                    );
                    let generation = private_generation(&store);
                    let mut second =
                        v3_import_from(&first, 1009, incoming["import_seq"].as_u64().unwrap());
                    second.subscription.subscription_epoch = incoming["epoch"].as_u64().unwrap();
                    store
                        .enroll(
                            &second,
                            NOW + retained["epoch"].as_u64().unwrap() as i64 + 1,
                        )
                        .unwrap();
                    assert_ne!(private_generation(&store), generation);
                    let row: (Option<String>, Option<i64>) = store.db.query_row("SELECT import_id,import_seq FROM encrypted_subscriptions WHERE account_id=?1", [ACCOUNT], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert_eq!(
                        row,
                        (
                            Some(second.request_id.clone()),
                            Some(incoming["import_seq"].as_i64().unwrap())
                        )
                    );
                    assert_eq!(case["row_state"], "active");
                    assert_eq!(case["row_claimable"], true);
                    assert_eq!(case["old_queued_work_invalidated"], true);
                    assert_eq!(case["confirmation_queued_atomically"], true);
                    let confirmation = store
                        .claim_due(NOW + retained["epoch"].as_u64().unwrap() as i64 + 2)
                        .unwrap()
                        .unwrap()
                        .event;
                    assert_eq!(confirmation.kind, "status");
                    assert_eq!(confirmation.code.as_deref(), Some("enrollment_imported"));
                    assert_eq!(
                        confirmation.import_id.as_deref(),
                        Some(second.request_id.as_str())
                    );
                    assert_eq!(case["confirmation_claimable"], true);
                }
                "old-file-recorded-reimport-after-newer-same-epoch" => {
                    assert_eq!(case["expected"], "saved_historical_receipt");
                    let dir = TestDir::new();
                    let mut store = dir.store();
                    let input = case["incoming"].clone();
                    let request = input["request_id"].as_str().unwrap();
                    let stale_seq = input["import_seq"].as_u64().unwrap();
                    let epoch = input["epoch"].as_u64().unwrap();
                    let template = crate::enrollment::parse(include_bytes!(
                        "../contracts/encrypted-push/v3/fixtures/enrollment-historical-request-v3.json"
                    ))
                    .unwrap();
                    let first = server_seed_v3_from_template(
                        &mut store,
                        &template,
                        epoch,
                        stale_seq,
                        Some(request),
                    );
                    assert_eq!(first.request_id, request);
                    assert_eq!(first.account_id, input["account_id"].as_str().unwrap());
                    assert_eq!(first.device_id, input["device_id"].as_u64().unwrap() as u32);
                    assert_eq!(
                        first.subscription.instance,
                        input["instance"].as_str().unwrap()
                    );
                    assert_eq!(
                        event_key_id(
                            &first.account_id,
                            first.device_id,
                            &first.subscription.instance,
                            first.control_key.as_deref().unwrap(),
                        )
                        .unwrap(),
                        input["key_id"].as_str().unwrap()
                    );
                    let mut current = v3_import_from(
                        &first,
                        1011,
                        case["retained"]["import_seq"].as_u64().unwrap(),
                    );
                    current.subscription.subscription_epoch = epoch;
                    store.enroll(&current, NOW + 1).unwrap();
                    let before = durable_snapshot(&store);
                    let generation = private_generation_for(&store, &first.account_id);
                    let pending = store.pending_count(Some(&first.account_id)).unwrap();
                    let historical = store.enroll(&first, NOW + 2).unwrap();
                    assert!(historical.replayed);
                    assert_eq!(historical.subscription_epoch, epoch);
                    assert_eq!(case["replayed"], historical.replayed);
                    assert_eq!(durable_snapshot(&store), before);
                    assert_eq!(
                        private_generation_for(&store, &first.account_id),
                        generation
                    );
                    assert!(!crate::enrollment::current_v3_replay_status(
                        &mut store,
                        &first,
                        &historical,
                        NOW + 2
                    )
                    .unwrap());
                    assert_eq!(durable_snapshot(&store), before);
                    assert_eq!(
                        private_generation_for(&store, &first.account_id),
                        generation
                    );
                    assert_eq!(
                        store.pending_count(Some(&first.account_id)).unwrap(),
                        pending
                    );
                }
                "old-file-unseen-reimport-after-newer-same-epoch" => {
                    assert_eq!(case["expected"], "reject");
                    assert_eq!(case["expected_error"], "epoch_conflict");
                    let dir = TestDir::new();
                    let mut store = dir.store();
                    let retained = case["retained"].clone();
                    let current = server_seed_v3(
                        &mut store,
                        retained["epoch"].as_u64().unwrap(),
                        retained["import_seq"].as_u64().unwrap(),
                        None,
                    );
                    let input = case["incoming"].clone();
                    let mut stale =
                        v3_import_from(&current, 1013, input["import_seq"].as_u64().unwrap());
                    stale.request_id = input["request_id"].as_str().unwrap().to_owned();
                    stale.subscription.subscription_epoch = input["epoch"].as_u64().unwrap();
                    let before = durable_snapshot(&store);
                    assert_eq!(
                        store.enroll(&stale, NOW + 1),
                        Err(StoreError::EpochConflict)
                    );
                    assert_eq!(durable_snapshot(&store), before);
                }
                "delayed-old-same-epoch-event"
                | "legacy-unknown-intent"
                | "explicit-lower-epoch-recovery"
                | "lost-status-later-wake"
                | "ordinary-lower-epoch-before-later-candidate"
                | "cap-refusal-rerender-restart"
                | "rerender-existing-no-slot"
                | "restart-retains-pending-intents"
                | "unknown-legacy-migration" => {
                    /* Phone-only runtime behavior; exercised by Android lane. */
                    let expected = match id {
                        "delayed-old-same-epoch-event"
                        | "legacy-unknown-intent"
                        | "unknown-legacy-migration" => "no_promotion",
                        "explicit-lower-epoch-recovery" => "recover",
                        "lost-status-later-wake"
                        | "ordinary-lower-epoch-before-later-candidate"
                        | "rerender-existing-no-slot"
                        | "restart-retains-pending-intents" => "accept",
                        "cap-refusal-rerender-restart" => "reject",
                        _ => unreachable!(),
                    };
                    assert_eq!(case["expected"], expected);
                }
                unknown => panic!("unclassified runtime case: {unknown}"),
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(48))]
        #[test]
        fn v3_sequence_attempts_preserve_floor_and_rejected_state(ops in proptest::collection::vec((0u8..3, 0u8..3, 0u8..2, 0u8..5), 1..12)) {
            let dir = TestDir::new();
            let mut store = dir.store();
            let mut current = v3_enrollment();
            store.enroll(&current, NOW).unwrap();
            let mut floor = 1u64;
            let mut epoch = 1u64;
            let initial: (i64, i64) = store.db.query_row(
                "SELECT subscription_epoch,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                [ACCOUNT],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            proptest::prop_assert_eq!(initial, (1, 1));

            for (index, (sequence_mode, epoch_mode, key_mode, context_mode)) in ops.into_iter().enumerate() {
                let before = durable_snapshot(&store);
                let mut candidate = current.clone();
                candidate.request_id = id(30_000 + index as u64);
                let incoming_seq = match sequence_mode {
                    0 => floor,
                    1 => floor.saturating_sub(1).max(1),
                    _ => floor + 1,
                };
                candidate.import_seq = Some(incoming_seq);
                let incoming_epoch = match epoch_mode {
                    0 => epoch,
                    1 => epoch + 1,
                    _ => epoch + 2,
                };
                candidate.subscription.subscription_epoch = incoming_epoch;
                if key_mode == 1 {
                    candidate.control_key = Some(URL_SAFE_NO_PAD.encode([index as u8 + 40; 32]));
                }
                match context_mode {
                    0 => {}
                    1 => candidate.password.push_str(&format!("-{index}")),
                    2 => candidate.device_id += index as u32 + 1,
                    3 => {
                        candidate.subscription.auth =
                            URL_SAFE_NO_PAD.encode([index as u8 + 40; 16])
                    }
                    _ => candidate.subscription.instance.push_str(&format!("-{index}")),
                }
                let fresh_key = candidate.control_key != current.control_key;
                let unchanged_context = context_mode == 0;
                let accepted = incoming_seq > floor
                    && ((incoming_epoch == epoch && !fresh_key && unchanged_context)
                        || (incoming_epoch == epoch + 1 && fresh_key));
                let result = store.enroll(&candidate, NOW + index as i64 + 1);
                proptest::prop_assert_eq!(result.is_ok(), accepted);
                if accepted {
                    floor = incoming_seq;
                    epoch = incoming_epoch;
                    current = candidate;
                } else {
                    proptest::prop_assert_eq!(result, Err(StoreError::EpochConflict));
                    proptest::prop_assert_eq!(durable_snapshot(&store), before);
                }
                let retained: (i64, i64) = store.db.query_row(
                    "SELECT subscription_epoch,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                    [ACCOUNT],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ).unwrap();
                proptest::prop_assert_eq!(retained, (epoch as i64, floor as i64));
            }
        }
    }

    #[test]
    fn same_epoch_reaffirmation_rejects_changed_credentials_and_subscription() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let current = v3_enrollment();
        store.enroll(&current, NOW).unwrap();

        // The contract permits same-epoch reaffirmation only for unchanged
        // credentials, key, and subscription context.
        for (index, mutation) in [
            "password",
            "device_id",
            "subscription.auth",
            "subscription.instance",
        ]
        .into_iter()
        .enumerate()
        {
            let mut candidate = current.clone();
            candidate.request_id = id(31_000 + index as u64);
            candidate.import_seq = Some(2);
            match mutation {
                "password" => candidate.password.push_str("-changed"),
                "device_id" => candidate.device_id += 1,
                "subscription.auth" => {
                    candidate.subscription.auth = URL_SAFE_NO_PAD.encode([8u8; 16])
                }
                "subscription.instance" => candidate.subscription.instance.push_str("-changed"),
                _ => unreachable!(),
            }
            assert_eq!(
                candidate.subscription.subscription_epoch, current.subscription.subscription_epoch,
                "{mutation} candidate keeps the epoch"
            );
            assert_eq!(candidate.control_key, current.control_key);
            assert_eq!(candidate.import_seq, Some(2));

            let before = durable_snapshot(&store);
            let generation = private_generation(&store);
            assert_eq!(
                store.enroll(&candidate, NOW + 1),
                Err(StoreError::EpochConflict),
                "{mutation} must not qualify as reaffirmation"
            );
            assert_eq!(durable_snapshot(&store), before, "{mutation}");
            assert_eq!(private_generation(&store), generation, "{mutation}");
            assert!(
                store.receipt_for(&candidate).unwrap().is_none(),
                "{mutation}"
            );
        }
    }

    #[test]
    fn imported_status_insert_failure_rolls_back_new_and_reaffirmed_intents() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let first = v3_enrollment();
        store
            .db
            .execute_batch(
                "CREATE TRIGGER fail_enrollment_status BEFORE INSERT ON encrypted_push_queue
                 WHEN json_extract(NEW.event_json,'$.code')='enrollment_imported'
                 BEGIN SELECT RAISE(ABORT,'injected_status_failure'); END;",
            )
            .unwrap();
        assert_eq!(store.enroll(&first, NOW), Err(StoreError::StateUnavailable));
        assert!(store.get_subscription(ACCOUNT).unwrap().is_none());
        assert!(store.receipt_for(&first).unwrap().is_none());
        assert_eq!(store.pending_count(None).unwrap(), 0);
        let connection_count: usize = store
            .db
            .query_row("SELECT count(*) FROM connections", [], |r| row_count(r, 0))
            .unwrap();
        assert_eq!(connection_count, 0);
        store
            .db
            .execute_batch("DROP TRIGGER fail_enrollment_status;")
            .unwrap();
        store.enroll(&first, NOW).unwrap();

        let before = durable_snapshot(&store);
        let generation = private_generation(&store);
        let reaffirmed = v3_import_from(&first, 920, 2);
        store
            .db
            .execute_batch(
                "CREATE TRIGGER fail_enrollment_status BEFORE INSERT ON encrypted_push_queue
                 WHEN json_extract(NEW.event_json,'$.code')='enrollment_imported'
                 BEGIN SELECT RAISE(ABORT,'injected_status_failure'); END;",
            )
            .unwrap();
        assert_eq!(
            store.enroll(&reaffirmed, NOW + 1),
            Err(StoreError::StateUnavailable)
        );
        assert_eq!(durable_snapshot(&store), before);
        assert_eq!(private_generation(&store), generation);
        assert!(store.receipt_for(&reaffirmed).unwrap().is_none());
        let row: (Option<String>, Option<i64>) = store
            .db
            .query_row(
                "SELECT import_id,import_seq FROM encrypted_subscriptions WHERE account_id=?1",
                [ACCOUNT],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, (Some(first.request_id), Some(1)));
    }

    #[test]
    fn unkeyed_legacy_row_requires_exact_next_epoch_and_a_fresh_key_for_v3() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let legacy = enrollment();
        store.enroll(&legacy, NOW).unwrap();

        let mut invalid_same_epoch = v3_import_from(&legacy, 918, 5);
        invalid_same_epoch.control_key = Some(URL_SAFE_NO_PAD.encode([27u8; 32]));
        assert_eq!(
            store.enroll(&invalid_same_epoch, NOW + 1),
            Err(StoreError::EpochConflict)
        );
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap(),
            Some(legacy.subscription.clone())
        );

        let mut next_epoch = invalid_same_epoch;
        next_epoch.request_id = id(919);
        next_epoch.subscription.subscription_epoch = 2;
        let result = store.enroll(&next_epoch, NOW + 2).unwrap();
        assert_eq!(result.disposition, EnrollmentDisposition::Rotated);
        assert_eq!(store.pending_count(None).unwrap(), 1);
        assert_eq!(
            store
                .get_subscription(ACCOUNT)
                .unwrap()
                .unwrap()
                .event_version(),
            3
        );
    }

    #[test]
    fn control_rotation_revives_stale_atomically_and_replay_only_recovers_status() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = keyed_enrollment();
        store.enroll(&e, NOW).unwrap();
        let generation = private_generation(&store);
        let original = connection(&e);
        let key = e.control_key.as_ref().unwrap();
        store.enqueue(ACCOUNT, &event(&e, 11), NOW).unwrap();
        let obsolete_claim = store.claim_due(NOW).unwrap().unwrap();
        store
            .complete(&obsolete_claim, DeliveryOutcome::Gone, NOW)
            .unwrap();
        assert_eq!(
            store.account_state(ACCOUNT).unwrap(),
            Some(AccountState::Stale)
        );

        let mut updated = e.subscription.clone();
        updated.endpoint.push_str("-new");
        updated.auth = URL_SAFE_NO_PAD.encode([45u8; 16]);
        updated.subscription_epoch = 4; // Lost phone updates may skip epochs.
        let first = confirmation(&updated, 12, NOW + 1);
        assert_eq!(
            store
                .apply_endpoint_update(
                    &original,
                    &generation,
                    key,
                    &updated,
                    &[3; 32],
                    &first,
                    NOW + 1
                )
                .unwrap(),
            ControlDisposition::Applied
        );
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap(),
            Some(updated.clone())
        );
        assert_eq!(
            store.account_state(ACCOUNT).unwrap(),
            Some(AccountState::Active)
        );
        assert!(store
            .control_context_for_connection(&original, &generation)
            .unwrap()
            .is_none());
        let mut current = connection(&e);
        current.endpoint = updated.endpoint.clone();
        let context = store
            .control_context_for_connection(&current, &generation)
            .unwrap()
            .unwrap();
        assert_eq!(context.control_key, *key);
        assert_eq!(context.subscription, updated);
        let row: (u32, String, bool, i64) = store.db.query_row(
            "SELECT device_id,password,forbidden,last_registration FROM connections WHERE uuid=?1",
            [ACCOUNT], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(row, (e.device_id, e.password.clone(), false, NOW));

        // Replays coalesce with pending status without touching subscription time.
        let retry = confirmation(&updated, 13, NOW + 40);
        assert_eq!(
            store
                .apply_endpoint_update(
                    &current,
                    &generation,
                    key,
                    &updated,
                    &[3; 32],
                    &retry,
                    NOW + 40
                )
                .unwrap(),
            ControlDisposition::Unchanged
        );
        assert_eq!(store.pending_count(None).unwrap(), 1);
        assert_eq!(
            store
                .db
                .query_row(
                    "SELECT updated_at FROM encrypted_subscriptions WHERE account_id=?1",
                    [ACCOUNT],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            NOW + 1
        );
        let status = store.claim_due(NOW + 40).unwrap().unwrap();
        assert_eq!(status.event, first);
        assert_eq!(status.subscription, updated);
        store
            .complete(&status, DeliveryOutcome::Accepted, NOW + 40)
            .unwrap();
        // Provider acceptance isn't phone receipt: an identical replay can
        // recover a lost confirmation, bounded to one every thirty seconds.
        store
            .apply_endpoint_update(
                &current,
                &generation,
                key,
                &updated,
                &[3; 32],
                &retry,
                NOW + 40,
            )
            .unwrap();
        assert_eq!(store.pending_count(None).unwrap(), 1);
        let status = store.claim_due(NOW + 40).unwrap().unwrap();
        assert_eq!(status.event, retry);
        store
            .complete(&status, DeliveryOutcome::Accepted, NOW + 41)
            .unwrap();
        let throttled = confirmation(&updated, 14, NOW + 42);
        store
            .apply_endpoint_update(
                &current,
                &generation,
                key,
                &updated,
                &[3; 32],
                &throttled,
                NOW + 42,
            )
            .unwrap();
        assert_eq!(store.pending_count(None).unwrap(), 0);
        let later = confirmation(&updated, 15, NOW + 71);
        store
            .apply_endpoint_update(
                &current,
                &generation,
                key,
                &updated,
                &[3; 32],
                &later,
                NOW + 71,
            )
            .unwrap();
        assert_eq!(store.pending_count(None).unwrap(), 1);
        // A late provider callback from before rotation cannot stale the new epoch.
        store
            .complete(&obsolete_claim, DeliveryOutcome::Gone, NOW + 72)
            .unwrap();
        assert_eq!(
            store.account_state(ACCOUNT).unwrap(),
            Some(AccountState::Active)
        );
        let status = store.claim_due(NOW + 72).unwrap().unwrap();
        store
            .complete(&status, DeliveryOutcome::Gone, NOW + 72)
            .unwrap();
        let inactive_retry = confirmation(&updated, 16, NOW + 110);
        assert_eq!(
            store
                .apply_endpoint_update(
                    &current,
                    &generation,
                    key,
                    &updated,
                    &[3; 32],
                    &inactive_retry,
                    NOW + 110
                )
                .unwrap(),
            ControlDisposition::Unchanged
        );
        assert_eq!(
            store.account_state(ACCOUNT).unwrap(),
            Some(AccountState::Stale)
        );
        assert_eq!(store.pending_count(None).unwrap(), 0);
        drop(store);
        let store = dir.store();
        assert_eq!(store.get_subscription(ACCOUNT).unwrap(), Some(updated));
        assert_eq!(
            store.account_state(ACCOUNT).unwrap(),
            Some(AccountState::Stale)
        );
    }

    #[test]
    fn control_rejects_changed_replays_private_fields_and_obsolete_credentials() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = keyed_enrollment();
        store.enroll(&e, NOW).unwrap();
        let generation = private_generation(&store);
        let co = connection(&e);
        let key = e.control_key.as_ref().unwrap();
        let mut next = e.subscription.clone();
        next.subscription_epoch = 2;
        let status = confirmation(&next, 20, NOW);
        assert_eq!(
            store.apply_endpoint_update(
                &co,
                &generation,
                &URL_SAFE_NO_PAD.encode([0u8; 32]),
                &next,
                &[4; 32],
                &status,
                NOW
            ),
            Err(StoreError::EpochConflict)
        );
        let mut private = next.clone();
        private.instance.push_str("-private-change");
        let invalid_status = confirmation(&private, 21, NOW);
        assert_eq!(
            store.apply_endpoint_update(
                &co,
                &generation,
                key,
                &private,
                &[4; 32],
                &invalid_status,
                NOW
            ),
            Err(StoreError::InvalidEnrollment)
        );
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap(),
            Some(e.subscription.clone())
        );
        assert_eq!(store.pending_count(None).unwrap(), 0);
        store
            .apply_endpoint_update(&co, &generation, key, &next, &[4; 32], &status, NOW)
            .unwrap();
        assert_eq!(
            store.apply_endpoint_update(&co, &generation, key, &next, &[5; 32], &status, NOW),
            Err(StoreError::EpochConflict)
        );
        let old_status = confirmation(&e.subscription, 22, NOW);
        assert_eq!(
            store.apply_endpoint_update(
                &co,
                &generation,
                key,
                &e.subscription,
                &[4; 32],
                &old_status,
                NOW
            ),
            Err(StoreError::EpochConflict)
        );
        assert_eq!(store.pending_count(None).unwrap(), 1);

        // A private key rotation invalidates a previously captured control key,
        // and even identical credentials cannot restore an old control receipt.
        let mut imported = e.clone();
        imported.request_id = id(2);
        imported.subscription.subscription_epoch = 3;
        imported.control_key = Some(URL_SAFE_NO_PAD.encode([24u8; 32]));
        store.enroll(&imported, NOW + 1).unwrap();
        let generation = private_generation(&store);
        let mut fourth = imported.subscription.clone();
        fourth.subscription_epoch = 4;
        let status = confirmation(&fourth, 23, NOW + 1);
        assert_eq!(
            store.apply_endpoint_update(&co, &generation, key, &fourth, &[6; 32], &status, NOW + 1),
            Err(StoreError::EpochConflict)
        );
        let imported_status = confirmation(&imported.subscription, 24, NOW + 1);
        assert_eq!(
            store.apply_endpoint_update(
                &co,
                &generation,
                imported.control_key.as_ref().unwrap(),
                &imported.subscription,
                &[4; 32],
                &imported_status,
                NOW + 1
            ),
            Err(StoreError::EpochConflict)
        );
        let mut wrong = connection(&imported);
        wrong.password.push('x');
        assert!(store
            .control_context_for_connection(&wrong, &generation)
            .unwrap()
            .is_none());
        assert_eq!(
            store.apply_endpoint_update(
                &wrong,
                &generation,
                imported.control_key.as_ref().unwrap(),
                &fourth,
                &[6; 32],
                &status,
                NOW + 1
            ),
            Err(StoreError::SubscriptionMissing)
        );
        store
            .db
            .execute(
                "UPDATE connections SET forbidden=1 WHERE uuid=?1",
                [ACCOUNT],
            )
            .unwrap();
        assert!(store
            .control_context_for_connection(&co, &generation)
            .unwrap()
            .is_none());
        assert_eq!(
            store.apply_endpoint_update(
                &co,
                &generation,
                imported.control_key.as_ref().unwrap(),
                &fourth,
                &[6; 32],
                &status,
                NOW + 1
            ),
            Err(StoreError::SubscriptionMissing)
        );
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap(),
            Some(imported.subscription)
        );
        assert_eq!(store.pending_count(None).unwrap(), 0);
    }

    #[test]
    fn control_persistence_failure_rolls_back_endpoint_epoch_and_confirmation() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = keyed_enrollment();
        store.enroll(&e, NOW).unwrap();
        let generation = private_generation(&store);
        store.enqueue(ACCOUNT, &event(&e, 30), NOW).unwrap();
        let co = connection(&e);
        let mut next = e.subscription.clone();
        next.endpoint.push_str("-new");
        next.subscription_epoch = 2;
        let status = confirmation(&next, 31, NOW);
        store.db.execute_batch("CREATE TRIGGER fail_control_status BEFORE INSERT ON encrypted_push_queue BEGIN SELECT RAISE(ABORT,'injected_interruption'); END;").unwrap();
        assert_eq!(
            store.apply_endpoint_update(
                &co,
                &generation,
                e.control_key.as_ref().unwrap(),
                &next,
                &[7; 32],
                &status,
                NOW
            ),
            Err(StoreError::StateUnavailable)
        );
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap(),
            Some(e.subscription.clone())
        );
        assert_eq!(
            store
                .control_context_for_connection(&co, &generation)
                .unwrap()
                .unwrap()
                .subscription,
            e.subscription
        );
        assert_eq!(store.pending_count(None).unwrap(), 1);
        let replay: (Option<String>, Option<i64>) = store.db.query_row("SELECT last_control_digest,control_status_at FROM encrypted_subscriptions WHERE account_id=?1", [ACCOUNT], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(replay, (None, None));
        store
            .db
            .execute_batch("DROP TRIGGER fail_control_status;")
            .unwrap();
        drop(store);
        let mut store = dir.store();
        assert_eq!(
            store
                .apply_endpoint_update(
                    &co,
                    &generation,
                    e.control_key.as_ref().unwrap(),
                    &next,
                    &[7; 32],
                    &status,
                    NOW
                )
                .unwrap(),
            ControlDisposition::Applied
        );
        assert_eq!(store.pending_count(None).unwrap(), 1);
        assert_eq!(store.claim_due(NOW).unwrap().unwrap().event, status);
    }

    #[test]
    fn private_lifecycle_replacement_requires_fresh_control_key() {
        for change in ["password", "device", "instance"] {
            let dir = TestDir::new();
            let mut store = dir.store();
            let e = keyed_enrollment();
            store.enroll(&e, NOW).unwrap();
            let mut replacement = rotate(&e, 2);
            match change {
                "password" => replacement.password.push('x'),
                "device" => replacement.device_id += 1,
                _ => replacement.subscription.instance.push_str("-new"),
            }
            assert_eq!(
                store.enroll(&replacement, NOW + 1),
                Err(StoreError::InvalidEnrollment)
            );
            assert_eq!(
                store.get_subscription(ACCOUNT).unwrap(),
                Some(e.subscription.clone())
            );
            assert!(store.receipt_for(&replacement).unwrap().is_none());
            replacement.control_key = Some(URL_SAFE_NO_PAD.encode([99u8; 32]));
            store.enroll(&replacement, NOW + 1).unwrap();
            let generation = private_generation(&store);
            let mut prebuilt = replacement.subscription.clone();
            prebuilt.subscription_epoch = 100;
            prebuilt.endpoint.push_str("-old-lifecycle");
            let status = confirmation(&prebuilt, 50, NOW + 2);
            assert_eq!(
                store.apply_endpoint_update(
                    &connection(&replacement),
                    &generation,
                    e.control_key.as_ref().unwrap(),
                    &prebuilt,
                    &[8; 32],
                    &status,
                    NOW + 2,
                ),
                Err(StoreError::EpochConflict)
            );
            assert_eq!(
                store.get_subscription(ACCOUNT).unwrap(),
                Some(replacement.subscription)
            );
            assert_eq!(store.pending_count(None).unwrap(), 0);
        }
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = keyed_enrollment();
        store.enroll(&e, NOW).unwrap();
        let mut endpoint_rotation = rotate(&e, 2);
        endpoint_rotation.subscription.endpoint.push_str("-new");
        // Even an endpoint-only private change needs a fresh key.
        assert_eq!(
            store.enroll(&endpoint_rotation, NOW + 1),
            Err(StoreError::InvalidEnrollment)
        );
        // The idempotent import may repeat the current key.
        let mut repeat = e.clone();
        repeat.request_id = id(77);
        assert_eq!(
            store.enroll(&repeat, NOW + 1).unwrap().disposition,
            EnrollmentDisposition::Unchanged
        );
        endpoint_rotation.control_key = Some(URL_SAFE_NO_PAD.encode([98u8; 32]));
        store.enroll(&endpoint_rotation, NOW + 1).unwrap();
        let generation = private_generation(&store);
        assert_eq!(
            store
                .control_context_for_connection(&connection(&endpoint_rotation), &generation)
                .unwrap()
                .unwrap()
                .control_key,
            endpoint_rotation.control_key.unwrap()
        );
    }

    #[test]
    fn same_key_private_import_cannot_be_rolled_back_by_prebuilt_control_frames() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let a = keyed_enrollment();
        store.enroll(&a, NOW).unwrap();
        let key = a.control_key.clone().unwrap();
        // The phone built frames for epochs 2 (endpoint B) and 3 (B2) while the
        // server was offline. Meanwhile the user privately imports endpoint C at
        // epoch 2 with the same key.
        let mut c = rotate(&a, 2);
        c.subscription.endpoint.push_str("-c");
        assert_eq!(
            store.enroll(&c, NOW + 1),
            Err(StoreError::InvalidEnrollment)
        );
        assert!(store.receipt_for(&c).unwrap().is_none());
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap(),
            Some(a.subscription.clone())
        );
        // With a fresh key the import succeeds and the old frames are dead.
        c.control_key = Some(URL_SAFE_NO_PAD.encode([42u8; 32]));
        store.enroll(&c, NOW + 1).unwrap();
        let generation = private_generation(&store);
        let co = connection(&c);
        for epoch in [2u64, 3] {
            let mut frame = c.subscription.clone();
            frame.subscription_epoch = epoch;
            frame.endpoint = format!("https://push.example.test/frame-{epoch}");
            let status = confirmation(&frame, 60 + epoch, NOW + 2);
            assert!(store
                .apply_endpoint_update(
                    &co,
                    &generation,
                    &key,
                    &frame,
                    &[epoch as u8; 32],
                    &status,
                    NOW + 2
                )
                .is_err());
        }
        assert_eq!(
            store.get_subscription(ACCOUNT).unwrap(),
            Some(c.subscription)
        );
        assert_eq!(store.pending_count(None).unwrap(), 0);
    }

    fn durable_snapshot(store: &PushStore) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        [
            ("connections", "SELECT * FROM connections ORDER BY rowid"),
            (
                "encrypted_subscriptions",
                "SELECT * FROM encrypted_subscriptions ORDER BY rowid",
            ),
            (
                "encrypted_enrollment_requests",
                "SELECT * FROM encrypted_enrollment_requests ORDER BY rowid",
            ),
            (
                "encrypted_push_queue",
                "SELECT * FROM encrypted_push_queue ORDER BY rowid",
            ),
            (
                "encrypted_push_event_ids",
                "SELECT * FROM encrypted_push_event_ids ORDER BY rowid",
            ),
            (
                "encrypted_subscription_generations",
                "SELECT * FROM encrypted_subscription_generations ORDER BY rowid",
            ),
        ]
        .iter()
        .map(|(_table, query)| {
            let mut statement = store.db.prepare(query).unwrap();
            let rows = statement
                .query_map([], |row| {
                    (0..row.as_ref().column_count())
                        .map(|index| row.get(index))
                        .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                })
                .unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        })
        .collect()
    }

    fn durable_account_snapshot(
        store: &PushStore,
        account_id: &str,
    ) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        [
            ("connections", "SELECT * FROM connections WHERE uuid=?1"),
            (
                "encrypted_subscriptions",
                "SELECT * FROM encrypted_subscriptions WHERE account_id=?1",
            ),
            (
                "encrypted_enrollment_requests",
                "SELECT * FROM encrypted_enrollment_requests WHERE account_id=?1",
            ),
            (
                "encrypted_push_queue",
                "SELECT * FROM encrypted_push_queue WHERE account_id=?1",
            ),
            (
                "encrypted_push_event_ids",
                "SELECT * FROM encrypted_push_event_ids WHERE account_id=?1",
            ),
            (
                "encrypted_subscription_generations",
                "SELECT * FROM encrypted_subscription_generations WHERE account_id=?1",
            ),
        ]
        .iter()
        .map(|(_table, query)| {
            let mut statement = store.db.prepare(query).unwrap();
            let rows = statement
                .query_map([account_id], |row| {
                    (0..row.as_ref().column_count())
                        .map(|index| row.get(index))
                        .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                })
                .unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        })
        .collect()
    }

    // This projection intentionally ignores fields introduced in schema v5 so
    // the schema-3 migration test can compare data that existed on both sides.
    fn durable_snapshot_pre_v5(store: &PushStore) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        [
            ("connections", "SELECT * FROM connections ORDER BY rowid"),
            (
                "encrypted_subscriptions",
                "SELECT account_id,subscription_epoch,subscription_json,state,connection_device_id,connection_password,connection_endpoint,updated_at,control_key,last_control_digest,control_status_at FROM encrypted_subscriptions ORDER BY rowid",
            ),
            (
                "encrypted_enrollment_requests",
                "SELECT * FROM encrypted_enrollment_requests ORDER BY rowid",
            ),
            (
                "encrypted_push_queue",
                "SELECT * FROM encrypted_push_queue ORDER BY rowid",
            ),
            (
                "encrypted_push_event_ids",
                "SELECT event_id,account_id,event_digest,expires_at FROM encrypted_push_event_ids ORDER BY rowid",
            ),
            (
                "encrypted_subscription_generations",
                "SELECT * FROM encrypted_subscription_generations ORDER BY rowid",
            ),
        ]
        .iter()
        .map(|(_table, query)| {
            let mut statement = store.db.prepare(query).unwrap();
            let rows = statement
                .query_map([], |row| {
                    (0..row.as_ref().column_count())
                        .map(|index| row.get(index))
                        .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                })
                .unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        })
        .collect()
    }

    #[test]
    fn schema_three_migration_preserves_control_receipts_queue_leases_and_v1_state() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = keyed_enrollment();
        store.enroll(&e, NOW).unwrap();
        let co = connection(&e);
        let old_generation = private_generation(&store);
        let mut updated = e.subscription.clone();
        updated.subscription_epoch = 7;
        let status = confirmation(&updated, 90, NOW);
        store
            .apply_endpoint_update(
                &co,
                &old_generation,
                e.control_key.as_ref().unwrap(),
                &updated,
                &[9; 32],
                &status,
                NOW,
            )
            .unwrap();
        let leased = store.claim_due(NOW).unwrap().unwrap();
        assert_eq!(leased.attempt, 1);

        let mut v1 = enrollment();
        v1.account_id = id(900);
        store.enroll(&v1, NOW).unwrap();
        store.enqueue(&v1.account_id, &event(&v1, 91), NOW).unwrap();
        let mut before = durable_snapshot_pre_v5(&store);
        before.pop(); // Schema 3 has no generation table.
        store
            .db
            .execute_batch(
                "DROP TABLE encrypted_subscription_generations;
                 ALTER TABLE encrypted_subscriptions DROP COLUMN import_id;
                 ALTER TABLE encrypted_subscriptions DROP COLUMN import_seq;
                 ALTER TABLE encrypted_push_event_ids DROP COLUMN status_retry_key;
                 ALTER TABLE encrypted_push_event_ids DROP COLUMN created_at;
                 PRAGMA user_version=3;",
            )
            .unwrap();
        drop(store);

        let store = dir.store();
        let mut after = durable_snapshot_pre_v5(&store);
        after.pop();
        assert_eq!(after, before);
        assert!(store.receipt_for(&e).unwrap().unwrap().replayed);
        assert!(store.receipt_for(&v1).unwrap().unwrap().replayed);
        let generation = private_generation(&store);
        assert_ne!(generation, old_generation);
        assert_ne!(
            generation,
            store
                .private_generation_for_connection(&connection(&v1))
                .unwrap()
                .unwrap()
        );
        drop(store);
        let store = dir.store();
        assert_eq!(private_generation(&store), generation);
    }

    #[test]
    fn incomplete_schema_three_migration_does_not_commit_a_generation_or_new_marker() {
        let dir = TestDir::new();
        let mut store = dir.store();
        store.enroll(&keyed_enrollment(), NOW).unwrap();
        store.db.execute_batch("DROP TABLE encrypted_subscription_generations; ALTER TABLE encrypted_subscriptions DROP COLUMN import_id; ALTER TABLE encrypted_subscriptions DROP COLUMN import_seq; ALTER TABLE encrypted_push_event_ids DROP COLUMN status_retry_key; ALTER TABLE encrypted_push_event_ids DROP COLUMN created_at; DROP TRIGGER encrypted_connection_update_guard; PRAGMA user_version=3;").unwrap();
        drop(store);
        assert!(matches!(
            PushStore::open(dir.path()),
            Err(StoreError::StateUnavailable)
        ));
        let db = Connection::open(dir.path()).unwrap();
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            3
        );
        assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE name='encrypted_subscription_generations'", [], |r| r.get::<_, u32>(0)).unwrap(), 0);
        assert_eq!(
            db.query_row("SELECT count(*) FROM encrypted_subscriptions", [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn private_generations_revoke_same_tuple_callbacks_across_key_aba_and_recreation() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let original = keyed_enrollment();
        store.enroll(&original, NOW).unwrap();
        let co = connection(&original);
        let mut revoked = vec![private_generation(&store)];
        let mut current = original.clone();
        let db = crate::db::MollySocketDb::open(dir.path()).unwrap();

        // Include A -> B -> A, keyed -> keyless, and keyless -> keyed plus an
        // instance change. None changes account/device/password/endpoint.
        for (index, key) in [Some([24; 32]), Some([23; 32]), None, Some([25; 32])]
            .into_iter()
            .enumerate()
        {
            current = rotate(&current, index as u64 + 2);
            current.control_key = key.map(|key| URL_SAFE_NO_PAD.encode(key));
            current.subscription.supported_event_versions = if current.control_key.is_some() {
                vec![1, 2]
            } else {
                vec![1]
            };
            if index == 3 {
                current.subscription.instance.push_str("-replacement");
            }
            store.enroll(&current, NOW + 1).unwrap();
            let generation = private_generation(&store);
            assert!(!revoked.contains(&generation));
            let wake = event(&current, 100 + index as u64);
            let mut status = event(&current, 110 + index as u64);
            status.kind = "status".into();
            status.code = Some("connection_conflict".into());
            let before = durable_snapshot(&store);
            for old in &revoked {
                assert!(store
                    .control_context_for_connection(&co, old)
                    .unwrap()
                    .is_none());
                assert!(store
                    .subscription_for_connection(
                        ACCOUNT,
                        co.device_id,
                        &co.password,
                        &co.endpoint,
                        old
                    )
                    .unwrap()
                    .is_none());
                assert!(!store
                    .enqueue_for_connection(&co, old, &wake, NOW + 1)
                    .unwrap());
                assert!(!store
                    .enqueue_for_connection(&co, old, &status, NOW + 1)
                    .unwrap());
                assert!(!db.forbid_if_current(&co, Some(old)).unwrap());
                if let Some(key) = &current.control_key {
                    let mut newer = current.subscription.clone();
                    newer.subscription_epoch += 10;
                    let confirmation = confirmation(&newer, 120 + index as u64, NOW + 1);
                    assert_eq!(
                        store.apply_endpoint_update(
                            &co,
                            old,
                            key,
                            &newer,
                            &[10; 32],
                            &confirmation,
                            NOW + 1
                        ),
                        Err(StoreError::SubscriptionMissing)
                    );
                }
            }
            // A legacy-mode callback cannot forbid an encrypted replacement.
            assert!(!db.forbid_if_current(&co, None).unwrap());
            assert_eq!(durable_snapshot(&store), before);
            assert!(store
                .enqueue_for_connection(&co, &generation, &wake, NOW + 1)
                .unwrap());
            assert!(store.enroll(&current, NOW + 2).unwrap().replayed);
            let mut unchanged = current.clone();
            unchanged.request_id = id(1000 + index as u64);
            assert_eq!(
                store.enroll(&unchanged, NOW + 2).unwrap().disposition,
                EnrollmentDisposition::Unchanged
            );
            assert_eq!(private_generation(&store), generation);
            revoked.push(generation);
        }

        // Deleted state can be recreated with epoch 1 and identical credentials;
        // its old callbacks still must not become current again.
        assert!(store.remove(ACCOUNT).unwrap());
        store.enroll(&original, NOW + 3).unwrap();
        let recreated = private_generation(&store);
        assert!(!revoked.contains(&recreated));
        let before = durable_snapshot(&store);
        for old in &revoked {
            assert!(!store
                .enqueue_for_connection(&co, old, &event(&original, 150), NOW + 3)
                .unwrap());
            assert!(!db.forbid_if_current(&co, Some(old)).unwrap());
        }
        assert_eq!(durable_snapshot(&store), before);
        assert!(store
            .enqueue_for_connection(&co, &recreated, &event(&original, 151), NOW + 3)
            .unwrap());
    }

    #[test]
    fn forbidden_transition_between_snapshot_and_enqueue_cannot_change_the_outbox() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = keyed_enrollment();
        store.enroll(&e, NOW).unwrap();
        let co = connection(&e);
        let generation = private_generation(&store);
        assert!(store
            .subscription_for_connection(
                ACCOUNT,
                co.device_id,
                &co.password,
                &co.endpoint,
                &generation
            )
            .unwrap()
            .is_some());
        let captured = event(&e, 160);
        let db = crate::db::MollySocketDb::open(dir.path()).unwrap();
        assert!(db.forbid_if_current(&co, Some(&generation)).unwrap());
        let before = durable_snapshot(&store);
        assert!(!store
            .enqueue_for_connection(&co, &generation, &captured, NOW + 1)
            .unwrap());
        assert!(store
            .subscription_for_connection(
                ACCOUNT,
                co.device_id,
                &co.password,
                &co.endpoint,
                &generation
            )
            .unwrap()
            .is_none());
        assert!(store
            .control_context_for_connection(&co, &generation)
            .unwrap()
            .is_none());
        assert_eq!(durable_snapshot(&store), before);
    }

    #[test]
    fn control_replay_preserves_a_leased_fourth_attempt_and_refreshes_only_after_its_end() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = keyed_enrollment();
        store.enroll(&e, NOW).unwrap();
        let co = connection(&e);
        let generation = private_generation(&store);
        let mut updated = e.subscription.clone();
        updated.subscription_epoch = 8;
        let first = confirmation(&updated, 170, NOW);
        let key = e.control_key.as_ref().unwrap();
        store
            .apply_endpoint_update(&co, &generation, key, &updated, &[11; 32], &first, NOW)
            .unwrap();
        for (index, when) in [NOW, NOW + 5, NOW + 35, NOW + 155].into_iter().enumerate() {
            let claim = store.claim_due(when).unwrap().unwrap();
            assert_eq!(claim.attempt, index as u32 + 1);
            if index != 3 {
                store
                    .complete(&claim, DeliveryOutcome::Retry { retry_after: None }, when)
                    .unwrap();
            }
        }
        let before = durable_snapshot(&store);
        let replay = confirmation(&updated, 171, NOW + 156);
        assert_eq!(
            store
                .apply_endpoint_update(
                    &co,
                    &generation,
                    key,
                    &updated,
                    &[11; 32],
                    &replay,
                    NOW + 156
                )
                .unwrap(),
            ControlDisposition::Unchanged
        );
        assert_eq!(durable_snapshot(&store), before);
        drop(store);
        let mut store = dir.store();
        store
            .apply_endpoint_update(
                &co,
                &generation,
                key,
                &updated,
                &[11; 32],
                &replay,
                NOW + 170,
            )
            .unwrap();
        assert_eq!(durable_snapshot(&store), before);

        // The expired attempt is pruned without reusing its event or lease.
        let fresh = confirmation(&updated, 172, NOW + 186);
        store
            .apply_endpoint_update(
                &co,
                &generation,
                key,
                &updated,
                &[11; 32],
                &fresh,
                NOW + 186,
            )
            .unwrap();
        let claim = store.claim_due(NOW + 186).unwrap().unwrap();
        assert_eq!(claim.event, fresh);
        assert_eq!(claim.attempt, 1);
        assert_eq!(private_generation(&store), generation);
        assert_eq!(store.get_subscription(ACCOUNT).unwrap(), Some(updated));
    }

    #[test]
    fn full_confirmation_ledger_rolls_back_control_and_preserves_private_generation() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = keyed_enrollment();
        store.enroll(&e, NOW).unwrap();
        let co = connection(&e);
        let generation = private_generation(&store);
        store.enqueue(ACCOUNT, &event(&e, 180), NOW).unwrap();
        store.db.execute("WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO encrypted_push_event_ids(event_id,account_id,event_digest,expires_at) SELECT printf('capacity-%d',x),?2,'synthetic-digest',?3 FROM n", params![(MAX_EVENT_IDS - 1) as i64, ACCOUNT, NOW + 300]).unwrap();
        let mut updated = e.subscription.clone();
        updated.endpoint.push_str("-new");
        updated.subscription_epoch = 12;
        let status = confirmation(&updated, 181, NOW);
        let before = durable_snapshot(&store);
        assert_eq!(
            store.apply_endpoint_update(
                &co,
                &generation,
                e.control_key.as_ref().unwrap(),
                &updated,
                &[12; 32],
                &status,
                NOW
            ),
            Err(StoreError::QueueFull)
        );
        assert_eq!(durable_snapshot(&store), before);
        store
            .db
            .execute(
                "DELETE FROM encrypted_push_event_ids WHERE event_id='capacity-1'",
                [],
            )
            .unwrap();
        assert_eq!(
            store
                .apply_endpoint_update(
                    &co,
                    &generation,
                    e.control_key.as_ref().unwrap(),
                    &updated,
                    &[12; 32],
                    &status,
                    NOW
                )
                .unwrap(),
            ControlDisposition::Applied
        );
        assert_eq!(private_generation(&store), generation);
        assert_eq!(store.pending_count(None).unwrap(), 1);
        assert_eq!(store.claim_due(NOW).unwrap().unwrap().event, status);
    }

    #[test]
    fn future_and_partial_schemas_are_rejected_without_version_downgrade() {
        let dir = TestDir::new();
        let store = dir.store();
        store
            .db
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        drop(store);
        assert!(matches!(
            PushStore::open(dir.path()),
            Err(StoreError::FutureSchema)
        ));
        let db = Connection::open(dir.path()).unwrap();
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            SCHEMA_VERSION + 1
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
    fn enrollment_receipts_are_scoped_by_account_and_request_id() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let first = enrollment();
        assert_eq!(
            store.enroll(&first, NOW).unwrap().disposition,
            EnrollmentDisposition::Created
        );

        let mut second_account = first.clone();
        second_account.account_id = id(2);
        assert_eq!(second_account.request_id, first.request_id);
        let second_receipt = store.enroll(&second_account, NOW + 1).unwrap();
        assert_eq!(second_receipt.disposition, EnrollmentDisposition::Created);
        assert!(!second_receipt.replayed);
        assert!(store.enroll(&first, NOW + 2).unwrap().replayed);
        assert!(store.enroll(&second_account, NOW + 2).unwrap().replayed);
        assert_eq!(
            store.get_subscription(&first.account_id).unwrap().unwrap(),
            first.subscription
        );
        assert_eq!(
            store
                .get_subscription(&second_account.account_id)
                .unwrap()
                .unwrap(),
            second_account.subscription
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
        let generation = private_generation(&store);
        assert!(store
            .subscription_for_connection(
                ACCOUNT,
                e.device_id,
                &e.password,
                &e.subscription.endpoint,
                &generation,
            )
            .unwrap()
            .is_some());
        let normalized = url::Url::parse(&e.subscription.endpoint)
            .unwrap()
            .to_string();
        assert!(store
            .subscription_for_connection(
                ACCOUNT,
                e.device_id,
                &e.password,
                &normalized,
                &generation
            )
            .unwrap()
            .is_none());
        let mut second = rotate(&e, 2);
        second.password.push('x');
        store.enroll(&second, NOW + 1).unwrap();
        let second_generation = private_generation(&store);
        assert!(store
            .subscription_for_connection(
                ACCOUNT,
                e.device_id,
                &e.password,
                &e.subscription.endpoint,
                &generation,
            )
            .unwrap()
            .is_none());
        let captured = store
            .subscription_for_connection(
                ACCOUNT,
                second.device_id,
                &second.password,
                &second.subscription.endpoint,
                &second_generation,
            )
            .unwrap()
            .unwrap();
        let mut third = rotate(&second, 3);
        third.password.push('y');
        store.enroll(&third, NOW + 2).unwrap();
        let third_generation = private_generation(&store);
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
        // Even with unchanged Signal credentials and endpoint, the private
        // replacement revokes the old socket's subscription snapshot.
        assert!(store
            .subscription_for_connection(
                ACCOUNT,
                third.device_id,
                &third.password,
                &third.subscription.endpoint,
                &third_generation,
            )
            .unwrap()
            .is_none());
        let fourth_generation = private_generation(&store);
        assert_eq!(
            store
                .subscription_for_connection(
                    ACCOUNT,
                    third.device_id,
                    &third.password,
                    &third.subscription.endpoint,
                    &fourth_generation,
                )
                .unwrap()
                .unwrap(),
            fourth.subscription
        );
    }

    async fn try_legacy_dispatch(store: &mut PushStore, co: &crate::db::Connection) -> Option<()> {
        store
            .with_legacy_dispatch(co, || std::future::ready(()))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn legacy_dispatch_fails_closed_after_upgrade_removal_or_credential_changes() {
        let dir = TestDir::new();
        let mut store = dir.store();
        let e = enrollment();
        let legacy = crate::db::Connection::new(
            e.account_id.clone(),
            e.device_id,
            e.password.clone(),
            e.subscription.endpoint.clone(),
        );
        assert_eq!(try_legacy_dispatch(&mut store, &legacy).await, None);
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
        assert_eq!(try_legacy_dispatch(&mut store, &legacy).await, Some(()));
        let wrong_device = crate::db::Connection::new(
            e.account_id.clone(),
            3,
            e.password.clone(),
            e.subscription.endpoint.clone(),
        );
        let wrong_password = crate::db::Connection::new(
            e.account_id.clone(),
            e.device_id,
            "different-password".into(),
            e.subscription.endpoint.clone(),
        );
        let wrong_endpoint = crate::db::Connection::new(
            e.account_id.clone(),
            e.device_id,
            e.password.clone(),
            "https://different.test/".into(),
        );
        assert_eq!(try_legacy_dispatch(&mut store, &wrong_device).await, None);
        assert_eq!(try_legacy_dispatch(&mut store, &wrong_password).await, None);
        assert_eq!(try_legacy_dispatch(&mut store, &wrong_endpoint).await, None);
        store
            .db
            .execute("UPDATE connections SET forbidden=1", [])
            .unwrap();
        assert_eq!(try_legacy_dispatch(&mut store, &legacy).await, None);
        store
            .db
            .execute("UPDATE connections SET forbidden=0", [])
            .unwrap();
        store.enroll(&e, NOW).unwrap();
        assert_eq!(try_legacy_dispatch(&mut store, &legacy).await, None);
        store.remove(ACCOUNT).unwrap();
        assert_eq!(try_legacy_dispatch(&mut store, &legacy).await, None);
    }

    #[tokio::test]
    async fn legacy_dispatch_and_encrypted_import_share_a_barrier_in_both_orders() {
        let dir = TestDir::new();
        let enrollment = enrollment();
        let legacy = crate::db::Connection::new(
            enrollment.account_id.clone(),
            enrollment.device_id,
            enrollment.password.clone(),
            enrollment.subscription.endpoint.clone(),
        );
        let initial = dir.store();
        initial
            .db
            .execute(
                "INSERT INTO connections VALUES(?1,?2,?3,?4,0,0)",
                params![
                    enrollment.account_id,
                    enrollment.device_id,
                    enrollment.password,
                    enrollment.subscription.endpoint
                ],
            )
            .unwrap();
        drop(initial);

        SQLITE_BUSY_OBSERVED.store(false, Ordering::Release);
        SQLITE_BUSY_STOP.store(false, Ordering::Release);
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let mut legacy_store = dir.store();
                let (authorized_tx, authorized_rx) = futures_channel::oneshot::channel();
                let (release_tx, release_rx) = futures_channel::oneshot::channel();
                let dispatch = tokio::task::spawn_local(async move {
                    legacy_store
                        .with_legacy_dispatch(&legacy, || async move {
                            let _ = authorized_tx.send(());
                            release_rx.await.expect("dispatch release barrier");
                            "legacy request began"
                        })
                        .await
                        .unwrap()
                });
                authorized_rx.await.expect("legacy authorization barrier");

                let path = dir.path();
                let next = enrollment.clone();
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                let import_thread = std::thread::spawn(move || {
                    let mut importer = PushStore::open(path).unwrap();
                    importer.db.busy_handler(Some(observe_sqlite_busy)).unwrap();
                    let result = importer.enroll(&next, NOW);
                    done_tx.send(result).unwrap();
                });

                let saw_import_wait = tokio::time::timeout(Duration::from_secs(5), async {
                    while !SQLITE_BUSY_OBSERVED.load(Ordering::Acquire) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .is_ok();
                if !saw_import_wait {
                    SQLITE_BUSY_STOP.store(true, Ordering::Release);
                    let _ = release_tx.send(());
                    let _ = tokio::task::spawn_blocking(move || import_thread.join()).await;
                    panic!("encrypted import did not wait on the active legacy dispatch");
                }
                assert!(done_rx.try_recv().is_err());

                release_tx.send(()).expect("release legacy dispatch");
                assert_eq!(dispatch.await.unwrap(), Some("legacy request began"));
                let import_result = tokio::task::spawn_blocking(move || done_rx.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                import_thread.join().unwrap();
                assert_eq!(import_result.disposition, EnrollmentDisposition::Created);
            })
            .await;

        // Reverse ordering: after import commits, the common guard refuses
        // every later legacy entry point before the dispatch closure runs.
        let mut after_import = dir.store();
        let mut dispatched = false;
        let result = after_import
            .with_legacy_dispatch(
                &crate::db::Connection::new(
                    enrollment.account_id.clone(),
                    enrollment.device_id,
                    enrollment.password.clone(),
                    enrollment.subscription.endpoint.clone(),
                ),
                || async {
                    dispatched = true;
                },
            )
            .await
            .unwrap();
        assert_eq!(result, None);
        assert!(!dispatched);
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
        store.db.execute("WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<8192) INSERT INTO encrypted_push_event_ids(event_id,account_id,event_digest,expires_at) SELECT printf('fixture-%d',x),?1,'fixture-digest',?2 FROM n",params![ACCOUNT,NOW+300]).unwrap();
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
        store.db.execute("WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO encrypted_push_event_ids(event_id,account_id,event_digest,expires_at) SELECT printf('fixture-%d',x),?1,'fixture-digest',?2 FROM n",params![ACCOUNT,NOW+300]).unwrap();
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
        store.db.execute("INSERT INTO encrypted_subscriptions(account_id,subscription_epoch,subscription_json,state,connection_device_id,connection_password,connection_endpoint,updated_at) SELECT uuid,1,?1,'active',device_id,password,endpoint,?2 FROM connections WHERE uuid<>?3",params![sub,NOW,ACCOUNT]).unwrap();
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
