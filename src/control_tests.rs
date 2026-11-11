//! Transaction and adversarial tests for the enrollment-v2 control boundary.
use super::*;
use crate::control::{authenticate, seal_for_test, ControlResult};
use std::path::PathBuf;

const NOW: i64 = 1_800_000_000;
const BLOB: &[u8] = include_bytes!("../contracts/encrypted-push/v2/fixtures/control-update.bin");

struct State(PathBuf);
impl State {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("colliesocket-control-{}", token().unwrap())))
    }
    fn path(&self) -> PathBuf {
        self.0.join("state.db")
    }
    fn open(&self) -> PushStore {
        PushStore::open(self.path()).unwrap()
    }
}
impl Drop for State {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn enrollment() -> Enrollment {
    serde_json::from_slice(include_bytes!(
        "../contracts/encrypted-push/v2/fixtures/enrollment-keyed.json"
    ))
    .unwrap()
}
fn connection(enrollment: &Enrollment) -> crate::db::Connection {
    crate::db::Connection::new(
        enrollment.account_id.clone(),
        enrollment.device_id,
        enrollment.password.clone(),
        enrollment.subscription.endpoint.clone(),
    )
}
fn snapshot(store: &PushStore, connection: &crate::db::Connection) -> ControlSnapshot {
    let generation = store
        .control_generation_for_connection(connection)
        .unwrap()
        .unwrap();
    store
        .control_snapshot_for_connection(connection, &generation)
        .unwrap()
        .unwrap()
}
fn wake(enrollment: &Enrollment, id: u8) -> Event {
    Event {
        version: enrollment.subscription.event_version().unwrap(),
        event_id: format!("00000000-0000-4000-8000-{id:012x}"),
        instance: enrollment.subscription.instance.clone(),
        subscription_epoch: enrollment.subscription.subscription_epoch,
        kind: "wake".into(),
        issued_at: NOW,
        expires_at: NOW + 300,
        code: None,
    }
}

#[test]
fn control_enrollment_is_additive_strict_and_redacts_private_key() {
    let keyed = enrollment();
    keyed.validate().unwrap();
    assert_eq!(keyed.subscription.event_version().unwrap(), 2);
    let mut keyless = keyed.clone();
    keyless.control_key = None;
    keyless.subscription.supported_event_versions = vec![1];
    keyless.validate().unwrap();
    keyless.enrollment_version = 1;
    keyless.validate().unwrap();
    let original: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../contracts/encrypted-push/v1/fixtures/enrollment-valid.json"
    ))
    .unwrap();
    let parsed: Enrollment = serde_json::from_value(original.clone()).unwrap();
    assert_eq!(digest(&parsed).unwrap(), digest(&original).unwrap());
    assert!(!serde_json::to_string(&parsed)
        .unwrap()
        .contains("control_key"));
    assert!(!format!("{keyed:?}").contains(keyed.control_key.as_ref().unwrap()));

    let mut invalid = keyed.clone();
    invalid.enrollment_version = 1;
    assert_eq!(invalid.validate(), Err(StoreError::InvalidEnrollment));
    for key in [
        "".to_owned(),
        URL_SAFE_NO_PAD.encode([7; 31]),
        format!("{}=", keyed.control_key.as_ref().unwrap()),
    ] {
        invalid = keyed.clone();
        invalid.control_key = Some(key);
        assert_eq!(invalid.validate(), Err(StoreError::InvalidKeys));
    }
    invalid = keyed.clone();
    invalid.control_key = None;
    assert_eq!(invalid.validate(), Err(StoreError::UnsupportedVersion));
    invalid = keyed.clone();
    invalid.subscription.supported_event_versions = vec![1];
    assert_eq!(invalid.validate(), Err(StoreError::UnsupportedVersion));
    let mut null = serde_json::to_value(&keyed).unwrap();
    null["control_key"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<Enrollment>(null).is_err());
    let mut status = wake(&keyed, 1);
    status.kind = "status".into();
    status.code = Some("subscription_updated".into());
    status.validate(NOW).unwrap();
    status.version = 1;
    assert_eq!(status.validate(NOW), Err(StoreError::InvalidEvent));
}

#[test]
fn control_schema_migration_preserves_v1_state_and_receipt_digests() {
    let state = State::new();
    let mut store = state.open();
    let e: Enrollment = serde_json::from_slice(include_bytes!(
        "../contracts/encrypted-push/v1/fixtures/enrollment-valid.json"
    ))
    .unwrap();
    store.enroll(&e, NOW).unwrap();
    store.enqueue(&e.account_id, &wake(&e, 1), NOW).unwrap();
    // Remove only the additive v3 table to recreate the prior released schema.
    store
        .db
        .execute_batch("DROP TABLE encrypted_control_state; PRAGMA user_version=2;")
        .unwrap();
    drop(store);
    let mut store = state.open();
    assert_eq!(
        store
            .db
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    assert_eq!(
        store.get_subscription(&e.account_id).unwrap().unwrap(),
        e.subscription
    );
    assert!(store.receipt_for(&e).unwrap().unwrap().replayed);
    assert!(store
        .control_generation_for_connection(&connection(&e))
        .unwrap()
        .is_none());
    assert_eq!(store.claim_due(NOW).unwrap().unwrap().event.version, 1);
}

#[test]
fn control_independent_vector_binds_account_device_epoch_version_nonce_and_ciphertext() {
    let state = State::new();
    let mut store = state.open();
    let e = enrollment();
    store.enroll(&e, NOW).unwrap();
    let mut captured = snapshot(&store, &connection(&e));
    let update = authenticate(BLOB, &captured).unwrap();
    assert_eq!(update.epoch, 2);
    assert_eq!(update.update.endpoint, "https://push.example.test/new");
    // These mutations cover each authenticated portion of the binary frame.
    for offset in [21, 29, 30, 42, BLOB.len() - 1] {
        let mut corrupt = BLOB.to_vec();
        corrupt[offset] ^= 1;
        assert!(
            authenticate(&corrupt, &captured).is_none(),
            "offset {offset}"
        );
    }
    captured.account_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into();
    assert!(authenticate(BLOB, &captured).is_none());
    captured.account_id = e.account_id.clone();
    captured.device_id += 1;
    assert!(authenticate(BLOB, &captured).is_none());
    captured.device_id = e.device_id;
    captured.key[0] ^= 1;
    assert!(authenticate(BLOB, &captured).is_none());
    captured.key[0] ^= 1;
    for length in [0, 20, 21, 29, 41, 57, BLOB.len() - 1] {
        assert!(authenticate(&BLOB[..length], &captured).is_none());
    }
    let mut oversized = BLOB.to_vec();
    oversized.resize(crate::control::MAX_BLOB_BYTES + 1, 0);
    assert!(authenticate(&oversized, &captured).is_none());
}

#[test]
fn control_authenticated_plaintext_still_rejects_duplicate_and_private_fields() {
    let state = State::new();
    let mut store = state.open();
    let e = enrollment();
    store.enroll(&e, NOW).unwrap();
    let captured = snapshot(&store, &connection(&e));
    let value: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../contracts/encrypted-push/v2/fixtures/control-update.json"
    ))
    .unwrap();
    let valid = serde_json::to_vec(&value).unwrap();
    let mut invalid = Vec::new();
    for field in [
        "password",
        "control_key",
        "instance",
        "account_id",
        "device_id",
        "subscription_epoch",
    ] {
        let mut changed = value.clone();
        changed[field] = serde_json::Value::String("must-stay-private".into());
        invalid.push(serde_json::to_vec(&changed).unwrap());
    }
    invalid.extend([
        [
            b"{\"endpoint\":\"https://evil.example/\",".as_slice(),
            &valid[1..],
        ]
        .concat(),
        [b"\xef\xbb\xbf".as_slice(), &valid].concat(),
        [valid.as_slice(), b"{}"].concat(),
        vec![b' '; 3073],
        vec![0xff],
        b"null".to_vec(),
        b"{}".to_vec(),
    ]);
    for field in ["endpoint", "auth", "p256dh"] {
        let mut changed = value.clone();
        changed[field] = serde_json::Value::Null;
        invalid.push(serde_json::to_vec(&changed).unwrap());
    }
    for (i, plain) in invalid.iter().enumerate() {
        let blob = seal_for_test(&e, 2, plain, [i as u8; 12]);
        assert!(authenticate(&blob, &captured).is_none(), "case {i}");
    }
    assert_eq!(
        store.get_subscription(&e.account_id).unwrap().unwrap(),
        e.subscription
    );
    assert_eq!(store.pending_count(None).unwrap(), 0);
}

#[test]
fn control_rotation_revives_stale_but_replays_only_refresh_bounded_confirmations() {
    let state = State::new();
    let mut store = state.open();
    let e = enrollment();
    store.enroll(&e, NOW).unwrap();
    store.enqueue(&e.account_id, &wake(&e, 1), NOW).unwrap();
    let old_attempt = store.claim_due(NOW).unwrap().unwrap();
    store
        .complete(&old_attempt, DeliveryOutcome::Gone, NOW + 1)
        .unwrap();
    assert_eq!(
        store.account_state(&e.account_id).unwrap(),
        Some(AccountState::Stale)
    );
    let mut co = connection(&e);
    let captured = snapshot(&store, &co);
    let update = authenticate(BLOB, &captured).unwrap();
    assert!(matches!(
        store.apply_control(&captured, &update, NOW + 2).unwrap(),
        ControlResult::Applied { .. }
    ));
    let next = store.get_subscription(&e.account_id).unwrap().unwrap();
    assert_eq!(next.subscription_epoch, 2);
    assert_eq!(next.instance, e.subscription.instance);
    assert_eq!(next.endpoint, update.update.endpoint);
    assert_eq!(next.p256dh, update.update.p256dh);
    assert_eq!(next.auth, update.update.auth);
    assert_eq!(
        store.account_state(&e.account_id).unwrap(),
        Some(AccountState::Active)
    );
    let credentials: (u32, String, bool) = store
        .db
        .query_row(
            "SELECT device_id,password,forbidden FROM connections WHERE uuid=?1",
            [&e.account_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(credentials, (e.device_id, e.password.clone(), false));
    assert_eq!(store.pending_count(None).unwrap(), 1);
    // A late old-provider result cannot mark the new epoch stale.
    store
        .complete(&old_attempt, DeliveryOutcome::Gone, NOW + 3)
        .unwrap();
    assert_eq!(
        store.account_state(&e.account_id).unwrap(),
        Some(AccountState::Active)
    );
    co.endpoint = next.endpoint.clone();
    let replay = snapshot(&store, &co);
    let confirmation = store.claim_due(NOW + 3).unwrap().unwrap();
    assert_eq!(confirmation.event.version, 2);
    assert_eq!(
        confirmation.event.code.as_deref(),
        Some("subscription_updated")
    );
    assert_eq!(confirmation.subscription, next);
    assert!(matches!(
        store.apply_control(&replay, &update, NOW + 4).unwrap(),
        ControlResult::Replayed { .. }
    ));
    let lease: (u32, String) = store
        .db
        .query_row(
            "SELECT attempts,lease_token FROM encrypted_push_queue",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(lease, (1, confirmation.lease_token.clone()));
    store
        .complete(&confirmation, DeliveryOutcome::Accepted, NOW + 5)
        .unwrap();
    store.apply_control(&replay, &update, NOW + 6).unwrap();
    assert_eq!(store.pending_count(None).unwrap(), 0);
    store.apply_control(&replay, &update, NOW + 32).unwrap();
    assert_eq!(store.pending_count(None).unwrap(), 1);
    let refreshed = store.claim_due(NOW + 32).unwrap().unwrap();
    assert_ne!(refreshed.event.event_id, confirmation.event.event_id);
    assert_eq!(refreshed.event.subscription_epoch, 2);
    assert_eq!(
        store.get_subscription(&e.account_id).unwrap().unwrap(),
        next
    );
    store
        .complete(&refreshed, DeliveryOutcome::Gone, NOW + 33)
        .unwrap();
    store.apply_control(&replay, &update, NOW + 64).unwrap();
    assert_eq!(store.pending_count(None).unwrap(), 0);
    assert_eq!(
        store.account_state(&e.account_id).unwrap(),
        Some(AccountState::Stale)
    );
    drop(store);
    let mut store = state.open();
    let replay = snapshot(&store, &co);
    assert!(matches!(
        store.apply_control(&replay, &update, NOW + 65).unwrap(),
        ControlResult::Replayed { .. }
    ));
    assert_eq!(
        store.account_state(&e.account_id).unwrap(),
        Some(AccountState::Stale)
    );
}

#[test]
fn control_queue_capacity_rolls_back_every_part_of_acceptance() {
    let state = State::new();
    let mut store = state.open();
    let e = enrollment();
    store.enroll(&e, NOW).unwrap();
    store.enqueue(&e.account_id, &wake(&e, 1), NOW).unwrap();
    store.db.execute("WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<8191) INSERT INTO encrypted_push_event_ids SELECT printf('capacity-%d',x),?1,'fixture-digest',?2 FROM n", params![e.account_id,NOW+300]).unwrap();
    let co = connection(&e);
    let captured = snapshot(&store, &co);
    let update = authenticate(BLOB, &captured).unwrap();
    assert!(matches!(
        store.apply_control(&captured, &update, NOW + 1),
        Err(StoreError::QueueFull)
    ));
    assert_eq!(
        store.get_subscription(&e.account_id).unwrap().unwrap(),
        e.subscription
    );
    assert_eq!(store.pending_count(None).unwrap(), 1);
    assert!(snapshot(&store, &co).last_blob_digest.is_none());
    let endpoint: String = store
        .db
        .query_row(
            "SELECT endpoint FROM connections WHERE uuid=?1",
            [&e.account_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(endpoint, e.subscription.endpoint);
    store
        .db
        .execute(
            "DELETE FROM encrypted_push_event_ids WHERE event_id LIKE 'capacity-%'",
            [],
        )
        .unwrap();
    assert!(matches!(
        store.apply_control(&captured, &update, NOW + 2).unwrap(),
        ControlResult::Applied { .. }
    ));
    assert_eq!(store.pending_count(None).unwrap(), 1);
}

#[test]
fn control_conflicting_reencrypt_skipped_epochs_and_private_import_races_are_noops() {
    let state = State::new();
    let mut store = state.open();
    let e = enrollment();
    store.enroll(&e, NOW).unwrap();
    let mut co = connection(&e);
    let captured = snapshot(&store, &co);
    let update = authenticate(BLOB, &captured).unwrap();
    let plain = include_bytes!("../contracts/encrypted-push/v2/fixtures/control-update.json");
    for epoch in [1, 3, MAX_JSON_INTEGER] {
        let blob = seal_for_test(&e, epoch, plain, [epoch as u8; 12]);
        let bad = authenticate(&blob, &captured).unwrap();
        assert!(matches!(
            store.apply_control(&captured, &bad, NOW + 1).unwrap(),
            ControlResult::Rejected
        ));
    }
    assert!(matches!(
        store.apply_control(&captured, &update, NOW + 2).unwrap(),
        ControlResult::Applied { .. }
    ));
    // A snapshot captured before rotation cannot apply a concurrently arriving next update.
    let third = authenticate(&seal_for_test(&e, 3, plain, [3; 12]), &captured).unwrap();
    assert!(matches!(
        store.apply_control(&captured, &third, NOW + 3).unwrap(),
        ControlResult::Rejected
    ));
    co.endpoint = update.update.endpoint.clone();
    let replay = snapshot(&store, &co);
    let reencrypted = authenticate(&seal_for_test(&e, 2, plain, [42; 12]), &replay).unwrap();
    assert!(matches!(
        store.apply_control(&replay, &reencrypted, NOW + 4).unwrap(),
        ControlResult::Rejected
    ));
    let mut imported = e.clone();
    imported.request_id = "00000000-0000-4000-8000-000000000099".into();
    imported.subscription = store.get_subscription(&e.account_id).unwrap().unwrap();
    imported.subscription.subscription_epoch = 3;
    // Even reuse of the same private key must invalidate a captured generation.
    store.enroll(&imported, NOW + 5).unwrap();
    assert!(matches!(
        store.apply_control(&replay, &third, NOW + 6).unwrap(),
        ControlResult::Rejected
    ));
    assert!(store
        .control_snapshot_for_connection(&co, &captured.generation)
        .unwrap()
        .is_none());
    assert_eq!(
        store.get_subscription(&e.account_id).unwrap().unwrap(),
        imported.subscription
    );
    assert_eq!(store.pending_count(None).unwrap(), 0);
}

#[test]
fn control_generation_guards_wake_callbacks_during_same_tuple_private_rotation() {
    let state = State::new();
    let mut store = state.open();
    let mut e = enrollment();
    let co = connection(&e);
    let mut keyless = e.clone();
    keyless.enrollment_version = 1;
    keyless.control_key = None;
    keyless.subscription.supported_event_versions = vec![1];
    store.enroll(&keyless, NOW).unwrap();
    assert!(store
        .enqueue_for_connection(&co, None, &wake(&keyless, 1), NOW)
        .unwrap());
    e.subscription.subscription_epoch = 2;
    e.request_id = "00000000-0000-4000-8000-000000000002".into();
    store.enroll(&e, NOW + 1).unwrap();
    let generation = store
        .control_generation_for_connection(&co)
        .unwrap()
        .unwrap();
    assert!(!store
        .enqueue_for_connection(&co, None, &wake(&e, 2), NOW + 2)
        .unwrap());
    assert!(store
        .enqueue_for_connection(&co, Some(&generation), &wake(&e, 3), NOW + 2)
        .unwrap());
    e.subscription.subscription_epoch = 3;
    e.control_key = Some(URL_SAFE_NO_PAD.encode([9; 32]));
    e.request_id = "00000000-0000-4000-8000-000000000003".into();
    store.enroll(&e, NOW + 3).unwrap();
    assert!(!store
        .enqueue_for_connection(&co, Some(&generation), &wake(&e, 4), NOW + 4)
        .unwrap());
    let replacement = store
        .control_generation_for_connection(&co)
        .unwrap()
        .unwrap();
    assert_ne!(replacement, generation);
    assert!(store
        .enqueue_for_connection(&co, Some(&replacement), &wake(&e, 5), NOW + 4)
        .unwrap());
}
