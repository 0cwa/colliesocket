//! SQLite state for v4 receivers. The bridge owns Signal credentials and
//! each receiver owns its subscription, control key, receipt history and queue.
use super::*;
use crate::receiver_enrollment::ReceiverEnrollment;

const MAX_RECEIVERS_PER_ACCOUNT: usize = 16;
const MAX_RECEIVER_IDS_PER_ACCOUNT: usize = 64;
const BRIDGE_ENDPOINT: &str = "https://bridge.invalid/";

pub(super) const SCHEMA: &str = "
CREATE TABLE receiver_bridges(
 account_id TEXT PRIMARY KEY NOT NULL REFERENCES connections(uuid),
 primary_receiver_id TEXT NOT NULL,
 device_id INTEGER NOT NULL, password TEXT NOT NULL,
 generation TEXT NOT NULL,
 FOREIGN KEY(account_id,primary_receiver_id) REFERENCES push_receivers(account_id,receiver_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE push_receivers(
 account_id TEXT NOT NULL REFERENCES connections(uuid),
 receiver_id TEXT NOT NULL, label TEXT, instance TEXT NOT NULL,
 subscription_epoch INTEGER NOT NULL CHECK(subscription_epoch BETWEEN 1 AND 9007199254740991),
 subscription_json TEXT, control_key TEXT,
 state TEXT NOT NULL CHECK(state IN('active','stale','provider_rejected','revoked')),
 import_id TEXT NOT NULL,
 import_seq INTEGER NOT NULL CHECK(import_seq BETWEEN 1 AND 9223372036854775807),
 generation TEXT NOT NULL, last_control_digest BLOB, control_status_at INTEGER,
 PRIMARY KEY(account_id,receiver_id),
 CHECK((state='revoked' AND control_key IS NULL AND subscription_json IS NULL)
    OR (state!='revoked' AND control_key IS NOT NULL AND subscription_json IS NOT NULL))
);
CREATE TABLE receiver_enrollment_requests(
 account_id TEXT NOT NULL, receiver_id TEXT NOT NULL,
 request_id TEXT NOT NULL, request_digest TEXT NOT NULL, key_digest BLOB NOT NULL,
 subscription_epoch INTEGER NOT NULL, disposition TEXT NOT NULL CHECK(disposition IN('created','rotated')),
 PRIMARY KEY(account_id,receiver_id,request_id),
 UNIQUE(account_id,key_digest),
 FOREIGN KEY(account_id,receiver_id) REFERENCES push_receivers(account_id,receiver_id) ON DELETE CASCADE
);
CREATE TABLE receiver_push_queue(
 event_id TEXT PRIMARY KEY NOT NULL, account_id TEXT NOT NULL, receiver_id TEXT NOT NULL,
 receiver_generation TEXT NOT NULL,
 subscription_epoch INTEGER NOT NULL, event_json TEXT NOT NULL, expires_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 4), next_attempt_at INTEGER NOT NULL,
 lease_until INTEGER, lease_token TEXT,
 FOREIGN KEY(account_id,receiver_id) REFERENCES push_receivers(account_id,receiver_id) ON DELETE CASCADE
);
CREATE INDEX receiver_queue_due ON receiver_push_queue(next_attempt_at,lease_until);
CREATE INDEX receiver_queue_route ON receiver_push_queue(account_id,receiver_id);
CREATE TABLE receiver_pairing_targets(
 session_id TEXT PRIMARY KEY NOT NULL REFERENCES pairing_sessions(session_id) ON DELETE CASCADE,
 account_id TEXT NOT NULL, generation TEXT NOT NULL
);
CREATE TRIGGER receiver_bridge_insert_guard BEFORE INSERT ON connections
 WHEN EXISTS(SELECT 1 FROM receiver_bridges WHERE account_id=NEW.uuid)
 BEGIN SELECT RAISE(ABORT,'encrypted_enrollment_required'); END;
CREATE TRIGGER receiver_bridge_update_guard BEFORE UPDATE OF uuid,device_id,password,endpoint ON connections
 WHEN EXISTS(SELECT 1 FROM receiver_bridges WHERE account_id=OLD.uuid OR account_id=NEW.uuid)
 AND (NEW.uuid IS NOT OLD.uuid OR NOT EXISTS(
     SELECT 1 FROM receiver_bridges WHERE account_id=NEW.uuid AND device_id=NEW.device_id
     AND password=NEW.password AND NEW.endpoint='https://bridge.invalid/'))
 BEGIN SELECT RAISE(ABORT,'encrypted_enrollment_required'); END;
CREATE TRIGGER receiver_bridge_delete_guard BEFORE DELETE ON connections
 WHEN EXISTS(SELECT 1 FROM receiver_bridges WHERE account_id=OLD.uuid)
 BEGIN SELECT RAISE(ABORT,'encrypted_enrollment_required'); END;
";

pub(super) fn verify_schema(db: &Connection) -> Result<()> {
    db.prepare("SELECT b.primary_receiver_id,b.device_id,b.password,b.generation,r.label,r.subscription_json,r.control_key,r.import_id,r.import_seq,r.generation,r.last_control_digest,r.control_status_at,k.request_digest,k.key_digest,k.disposition,q.receiver_generation,q.event_json,q.next_attempt_at,q.lease_token,t.generation
                FROM receiver_bridges b,push_receivers r,receiver_enrollment_requests k,receiver_push_queue q,receiver_pairing_targets t LIMIT 0")?;
    let guards: u32 = db.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='trigger'
         AND name IN ('receiver_bridge_insert_guard','receiver_bridge_update_guard','receiver_bridge_delete_guard')",
        [],
        |r| r.get(0),
    )?;
    if guards != 3 {
        return Err(StoreError::StateUnavailable);
    }
    Ok(())
}

pub(super) fn bridge_generation(db: &Connection, account: &str) -> Result<Option<(u32, String)>> {
    Ok(db.query_row(
        "SELECT c.device_id,COALESCE(b.generation,g.generation)
         FROM connections c LEFT JOIN receiver_bridges b ON b.account_id=c.uuid
         LEFT JOIN encrypted_subscription_generations g ON g.account_id=c.uuid
         WHERE c.uuid=?1 AND c.forbidden=0 AND (b.account_id IS NOT NULL OR g.account_id IS NOT NULL)",
        [account], |r| Ok((r.get(0)?,r.get(1)?)),
    ).optional()?)
}

fn device_change_allowed(
    db: &Connection,
    account: &str,
    device_id: u32,
    except: Option<&str>,
) -> Result<bool> {
    Ok(db.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM connections c JOIN push_receivers r ON r.account_id=c.uuid
         WHERE c.uuid=?1 AND c.device_id!=?2 AND r.state!='revoked' AND r.receiver_id IS NOT ?3)",
        params![account, device_id, except],
        |r| r.get(0),
    )?)
}

fn key_used(db: &Connection, account: &str, key: &str) -> Result<bool> {
    let fingerprint = openssl::sha::sha256(&key_bytes(key, 32)?);
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM receiver_enrollment_requests WHERE account_id=?1 AND key_digest=?2)",
        params![account,fingerprint.as_slice()], |r| r.get(0),
    )?)
}

pub(super) fn check_legacy_import(db: &Connection, enrollment: &Enrollment) -> Result<()> {
    let account = &enrollment.account_id;
    let upgraded: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM receiver_bridges WHERE account_id=?1)",
        [account],
        |r| r.get(0),
    )?;
    if upgraded || !device_change_allowed(db, account, enrollment.device_id, None)? {
        return Err(StoreError::EpochConflict);
    }
    if let Some(key) = &enrollment.control_key {
        if key_used(db, account, key)? {
            return Err(StoreError::InvalidEnrollment);
        }
    }
    Ok(())
}

fn receipt(
    db: &Connection,
    enrollment: &ReceiverEnrollment,
    hash: &str,
) -> Result<Option<EnrollmentResult>> {
    let recorded: Option<(String, u64, String)> = db
        .query_row(
            "SELECT request_digest,subscription_epoch,disposition FROM receiver_enrollment_requests
         WHERE account_id=?1 AND receiver_id=?2 AND request_id=?3",
            params![
                enrollment.account_id,
                enrollment.receiver_id,
                enrollment.request_id
            ],
            |r| Ok((r.get(0)?, row_epoch(r, 1)?, r.get(2)?)),
        )
        .optional()?;
    recorded
        .map(|(previous, subscription_epoch, disposition)| {
            if previous != hash {
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

pub(super) fn install(
    tx: &Transaction<'_>,
    enrollment: &ReceiverEnrollment,
    now: i64,
) -> Result<EnrollmentResult> {
    enrollment.validate()?;
    if !(1..=MAX_JSON_INTEGER as i64).contains(&now) {
        return Err(StoreError::StateUnavailable);
    }
    let account = &enrollment.account_id;
    let receiver = &enrollment.receiver_id;
    let epoch = enrollment.subscription.subscription_epoch;
    let hash = digest(enrollment)?;
    if let Some(original) = receipt(tx, enrollment, &hash)? {
        return Ok(original);
    }

    let current: Option<(String,u64,i64)> = tx.query_row(
        "SELECT state,subscription_epoch,import_seq FROM push_receivers WHERE account_id=?1 AND receiver_id=?2",
        params![account,receiver], |r| Ok((r.get(0)?,row_epoch(r,1)?,r.get(2)?)),
    ).optional()?;
    let primary: Option<(String, String)> = tx
        .query_row(
            "SELECT b.primary_receiver_id,r.state FROM receiver_bridges b
         JOIN push_receivers r ON r.account_id=b.account_id AND r.receiver_id=b.primary_receiver_id
         WHERE b.account_id=?1",
            [account],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let disposition = if enrollment.password.is_some() {
        if primary
            .as_ref()
            .is_some_and(|(id, state)| id != receiver && state != "revoked")
            || (current.is_some() && primary.as_ref().is_none_or(|(id, _)| id != receiver))
            || !device_change_allowed(tx, account, enrollment.device_id, Some(receiver))?
        {
            return Err(StoreError::EpochConflict);
        }
        let legacy_epoch = if primary.is_none() {
            tx.query_row(
                "SELECT subscription_epoch FROM encrypted_subscriptions WHERE account_id=?1",
                [account],
                |r| row_epoch(r, 0),
            )
            .optional()?
        } else {
            None
        };
        match &current {
            Some((state, old_epoch, sequence))
                if state != "revoked"
                    && epoch == old_epoch + 1
                    && (enrollment.import_seq as i64) > *sequence =>
            {
                EnrollmentDisposition::Rotated
            }
            Some(_) => return Err(StoreError::EpochConflict),
            None if epoch == legacy_epoch.unwrap_or(0) + 1 => {
                if primary.is_none() && legacy_epoch.is_none() {
                    let count = tx.query_row(
                        "SELECT count(*) FROM (SELECT account_id FROM encrypted_subscriptions UNION SELECT account_id FROM receiver_bridges)",
                        [], |r| row_count(r, 0),
                    )?;
                    if count >= MAX_ACCOUNTS {
                        return Err(StoreError::CapacityExceeded);
                    }
                }
                EnrollmentDisposition::Created
            }
            None => return Err(StoreError::EpochConflict),
        }
    } else {
        if bridge_generation(tx, account)?.is_none_or(|(device, _)| device != enrollment.device_id)
        {
            return Err(StoreError::SubscriptionMissing);
        }
        if current.is_some() || epoch != 1 {
            return Err(StoreError::EpochConflict);
        }
        EnrollmentDisposition::Created
    };

    let other_key: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM encrypted_subscriptions WHERE account_id=?1 AND control_key=?2)",
        params![account,enrollment.control_key], |r| r.get(0),
    )?;
    if other_key || key_used(tx, account, &enrollment.control_key)? {
        return Err(StoreError::InvalidEnrollment);
    }
    if current.is_none() {
        let (total, live) = tx.query_row(
            "SELECT count(*),count(CASE WHEN state!='revoked' THEN 1 END) FROM push_receivers WHERE account_id=?1",
            [account], |r| Ok((row_count(r,0)?, row_count(r,1)?)),
        )?;
        let reserve_primary_slot = enrollment.password.is_none()
            && primary.as_ref().is_none_or(|(_, state)| state == "revoked");
        let limit = MAX_RECEIVERS_PER_ACCOUNT - usize::from(reserve_primary_slot);
        if total >= MAX_RECEIVER_IDS_PER_ACCOUNT || live >= limit {
            return Err(StoreError::CapacityExceeded);
        }
    }
    let requests = tx.query_row(
        "SELECT count(*) FROM receiver_enrollment_requests WHERE account_id=?1 AND receiver_id=?2",
        params![account, receiver],
        |r| row_count(r, 0),
    )?;
    if requests >= MAX_REQUESTS_PER_ACCOUNT {
        return Err(StoreError::CapacityExceeded);
    }

    if let Some(password) = enrollment.password.as_deref() {
        update_bridge(tx, enrollment, password, now)?;
    }
    let generation = token()?;
    let json = serde_json::to_string(&enrollment.subscription)?;
    tx.execute(
        "INSERT INTO push_receivers(account_id,receiver_id,label,instance,subscription_epoch,subscription_json,control_key,state,import_id,import_seq,generation)
         VALUES(?1,?2,?3,?4,?5,?6,?7,'active',?8,?9,?10)
         ON CONFLICT(account_id,receiver_id) DO UPDATE SET label=excluded.label, instance=excluded.instance, subscription_epoch=excluded.subscription_epoch,
         subscription_json=excluded.subscription_json, control_key=excluded.control_key, state='active', import_id=excluded.import_id,
         import_seq=excluded.import_seq, generation=excluded.generation,last_control_digest=NULL,control_status_at=NULL",
        params![account,receiver,enrollment.label,enrollment.subscription.instance,epoch as i64,json,enrollment.control_key,enrollment.request_id,enrollment.import_seq as i64,generation],
    )?;
    let fingerprint = openssl::sha::sha256(&key_bytes(&enrollment.control_key, 32)?);
    tx.execute(
        "INSERT INTO receiver_enrollment_requests VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            account,
            receiver,
            enrollment.request_id,
            hash,
            fingerprint.as_slice(),
            epoch as i64,
            disposition.as_str()
        ],
    )?;
    delete_route_queue(tx, account, receiver)?;
    prune(tx, now)?;
    let event = new_event(
        &enrollment.subscription,
        receiver,
        &enrollment.request_id,
        "status",
        Some("enrollment_imported"),
        now,
    )?;
    enqueue_receiver(tx, account, &generation, &event, now)?;
    Ok(EnrollmentResult {
        replayed: false,
        disposition,
        subscription_epoch: epoch,
    })
}

fn update_bridge(
    tx: &Transaction<'_>,
    enrollment: &ReceiverEnrollment,
    password: &str,
    now: i64,
) -> Result<()> {
    let account = &enrollment.account_id;
    let device = enrollment.device_id;
    // A v4 bridge's connection tuple contains no subscription endpoint.
    // Preserve the archived legacy row for historical receipts and its guard.
    tx.execute(
        "UPDATE encrypted_subscriptions SET state='stale',connection_device_id=?2,connection_password=?3,connection_endpoint=?4
         WHERE account_id=?1",
        params![account,device,password,BRIDGE_ENDPOINT],
    )?;
    tx.execute(
        "DELETE FROM encrypted_push_queue WHERE account_id=?1",
        [account],
    )?;
    tx.execute(
        "DELETE FROM encrypted_subscription_generations WHERE account_id=?1",
        [account],
    )?;
    let inserted = tx.execute(
        "INSERT INTO connections(uuid,device_id,password,endpoint,forbidden,last_registration)
         SELECT ?1,?2,?3,?4,0,?5 WHERE NOT EXISTS(SELECT 1 FROM connections WHERE uuid=?1)",
        params![account, device, password, BRIDGE_ENDPOINT, now],
    )?;
    tx.execute(
        "INSERT INTO receiver_bridges(account_id,primary_receiver_id,device_id,password,generation)
         VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(account_id) DO UPDATE SET primary_receiver_id=excluded.primary_receiver_id,
         device_id=excluded.device_id,password=excluded.password,generation=excluded.generation",
        params![account, enrollment.receiver_id, device, password, token()?],
    )?;
    if inserted == 0 {
        tx.execute(
            "UPDATE connections SET forbidden=CASE WHEN device_id IS NOT ?2 OR password IS NOT ?3 THEN 0 ELSE forbidden END,
             device_id=?2,password=?3,endpoint=?4,last_registration=?5 WHERE uuid=?1",
            params![account,device,password,BRIDGE_ENDPOINT,now],
        )?;
    }
    Ok(())
}

pub(super) fn delete_route_queue(db: &Connection, account: &str, receiver: &str) -> Result<()> {
    db.execute(
        "DELETE FROM receiver_push_queue WHERE account_id=?1 AND receiver_id=?2",
        params![account, receiver],
    )?;
    Ok(())
}

pub(super) fn new_event(
    sub: &Subscription,
    receiver: &str,
    import_id: &str,
    kind: &str,
    code: Option<&str>,
    now: i64,
) -> Result<Event> {
    let mut event = crate::push::new_event_at(sub, kind, code, now)?;
    event.receiver_id = Some(receiver.into());
    event.import_id = Some(import_id.into());
    Ok(event)
}

pub(super) fn enqueue_receiver(
    tx: &Transaction<'_>,
    account: &str,
    generation: &str,
    event: &Event,
    now: i64,
) -> Result<()> {
    event.validate(now)?;
    let receiver = event
        .receiver_id
        .as_deref()
        .ok_or(StoreError::InvalidEvent)?;
    let count = tx.query_row(
        "SELECT count(*) FROM receiver_push_queue WHERE account_id=?1 AND receiver_id=?2",
        params![account, receiver],
        |r| row_count(r, 0),
    )?;
    if count >= MAX_QUEUE_PER_ACCOUNT || super::global_queue_count(tx)? >= MAX_QUEUE_GLOBAL {
        return Err(StoreError::QueueFull);
    }
    tx.execute(
        "INSERT INTO receiver_push_queue(event_id,account_id,receiver_id,receiver_generation,subscription_epoch,event_json,expires_at,attempts,next_attempt_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,0,?8)",
        params![event.event_id,account,receiver,generation,event.subscription_epoch as i64,serde_json::to_string(event)?,event.expires_at,now],
    )?;
    Ok(())
}

impl PushStore {
    pub(crate) fn receiver_receipt(
        &self,
        enrollment: &ReceiverEnrollment,
    ) -> Result<Option<EnrollmentResult>> {
        receipt(&self.db, enrollment, &digest(enrollment)?)
    }

    pub(crate) fn enroll_receiver(
        &mut self,
        enrollment: &ReceiverEnrollment,
        now: i64,
    ) -> Result<EnrollmentResult> {
        if enrollment.password.is_none() {
            return Err(StoreError::InvalidEnrollment);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = install(&tx, enrollment, now)?;
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn revoke_receiver(&mut self, account: &str, receiver: &str) -> Result<bool> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE push_receivers SET state='revoked',control_key=NULL,subscription_json=NULL,generation=?3,
             last_control_digest=NULL,control_status_at=NULL WHERE account_id=?1 AND receiver_id=?2 AND state!='revoked'",
            params![account,receiver,token()?],
        )? > 0;
        if changed {
            delete_route_queue(&tx, account, receiver)?;
        }
        tx.commit()?;
        Ok(changed)
    }

    pub(crate) fn is_enrolled(&self, account: &str) -> Result<bool> {
        is_enrolled(&self.db, account)
    }
}

fn current_socket(db: &Connection, co: &crate::db::Connection, expected: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM connections c LEFT JOIN receiver_bridges b ON b.account_id=c.uuid
         LEFT JOIN encrypted_subscription_generations g ON g.account_id=c.uuid
         WHERE c.uuid=?1 AND c.device_id=?2 AND c.password=?3 AND c.endpoint=?4 AND c.forbidden=0
           AND COALESCE(b.generation,g.generation)=?5)",
        params![co.uuid,co.device_id,co.password,co.endpoint,expected],
        |r| r.get(0),
    )?)
}

impl PushStore {
    /// All routes are selected under the same socket and subscription snapshot.
    /// A full or inactive route cannot block another route on the same bridge.
    pub(crate) fn enqueue_routes(
        &mut self,
        account: &str,
        socket: Option<(&crate::db::Connection, &str)>,
        kind: &str,
        code: Option<&str>,
        now: i64,
    ) -> Result<Vec<String>> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((co, generation)) = socket {
            if co.uuid != account || !current_socket(&tx, co, generation)? {
                return Ok(Vec::new());
            }
        }
        prune(&tx, now)?;
        let mut ids = Vec::new();
        let mut skipped = None;
        if let Some(legacy) = get_subscription(&tx, account)? {
            let event = crate::push::new_event_at(&legacy, kind, code, now)?;
            match enqueue_event(&tx, account, &event, now) {
                Ok(true) => ids.push(event.event_id),
                Ok(false) => (),
                Err(error @ (StoreError::QueueFull | StoreError::SubscriptionInactive)) => {
                    skipped = Some(error)
                }
                Err(error) => return Err(error),
            }
        }
        let receivers = tx.prepare(
            "SELECT receiver_id,subscription_json,import_id,generation FROM push_receivers
             WHERE account_id=?1 AND state='active' AND EXISTS(SELECT 1 FROM connections WHERE uuid=?1 AND forbidden=0)
             ORDER BY receiver_id",
        )?.query_map([account], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
        for (receiver, json, import_id, generation) in receivers {
            let subscription = serde_json::from_str(&json)?;
            let event = new_event(&subscription, &receiver, &import_id, kind, code, now)?;
            match enqueue_receiver(&tx, account, &generation, &event, now) {
                Ok(()) => ids.push(event.event_id),
                Err(error @ StoreError::QueueFull) => skipped = Some(error),
                Err(error) => return Err(error),
            }
        }
        if ids.is_empty() && (socket.is_none() || skipped == Some(StoreError::QueueFull)) {
            return Err(skipped.unwrap_or(if is_enrolled(&tx, account)? {
                StoreError::SubscriptionInactive
            } else {
                StoreError::SubscriptionMissing
            }));
        }
        if skipped == Some(StoreError::QueueFull) {
            log::warn!("push_queue_full");
        }
        tx.commit()?;
        Ok(ids)
    }
}

fn is_enrolled(db: &Connection, account: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM encrypted_subscriptions WHERE account_id=?1 UNION ALL
         SELECT 1 FROM receiver_bridges WHERE account_id=?1)",
        [account],
        |r| r.get(0),
    )?)
}

pub(crate) struct ReceiverControl {
    pub subscription: Subscription,
    pub key: String,
    generation: String,
}

impl PushStore {
    pub(crate) fn receiver_control(
        &self,
        co: &crate::db::Connection,
        bridge: &str,
        receiver: &str,
    ) -> Result<Option<ReceiverControl>> {
        let snapshot = self.db.unchecked_transaction()?;
        if !current_socket(&snapshot, co, bridge)? {
            return Ok(None);
        }
        let row: Option<(String, String, String)> = snapshot
            .query_row(
                "SELECT subscription_json,control_key,generation FROM push_receivers
             WHERE account_id=?1 AND receiver_id=?2 AND state!='revoked'",
                params![co.uuid, receiver],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(json, key, generation)| {
            Ok(ReceiverControl {
                subscription: serde_json::from_str(&json)?,
                key,
                generation,
            })
        })
        .transpose()
    }

    pub(crate) fn apply_receiver_control(
        &mut self,
        co: &crate::db::Connection,
        bridge: &str,
        receiver: &str,
        context: ReceiverControl,
        update: &crate::control::AuthenticatedUpdate,
        now: i64,
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !current_socket(&tx, co, bridge)? {
            return Ok(());
        }
        let row: Option<(String,String,String,Option<Vec<u8>>,Option<i64>)> = tx.query_row(
            "SELECT subscription_json,import_id,state,last_control_digest,control_status_at FROM push_receivers
             WHERE account_id=?1 AND receiver_id=?2 AND generation=?3 AND state!='revoked' AND control_key=?4",
            params![co.uuid,receiver,context.generation,context.key],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).optional()?;
        let Some((json, import_id, state, last_digest, last_status)) = row else {
            return Ok(());
        };
        let mut subscription: Subscription = serde_json::from_str(&json)?;
        let generation;
        if update.subscription_epoch > subscription.subscription_epoch {
            subscription
                .endpoint
                .clone_from(&update.subscription.endpoint);
            subscription.p256dh.clone_from(&update.subscription.p256dh);
            subscription.auth.clone_from(&update.subscription.auth);
            subscription.subscription_epoch = update.subscription_epoch;
            subscription.validate()?;
            generation = token()?;
            tx.execute(
                "UPDATE push_receivers SET subscription_json=?3,subscription_epoch=?4,state='active',
                 generation=?5,last_control_digest=?6,control_status_at=NULL WHERE account_id=?1 AND receiver_id=?2",
                params![co.uuid,receiver,serde_json::to_string(&subscription)?,subscription.subscription_epoch as i64,generation,update.digest.as_slice()],
            )?;
            delete_route_queue(&tx, &co.uuid, receiver)?;
        } else if update.subscription_epoch == subscription.subscription_epoch
            && last_digest.as_deref() == Some(update.digest.as_slice())
            && state == "active"
        {
            if last_status
                .is_some_and(|last| now < last.saturating_add(CONTROL_STATUS_RETRY_SECONDS))
            {
                return Ok(());
            }
            let pending: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM receiver_push_queue WHERE account_id=?1 AND receiver_id=?2
                 AND receiver_generation=?3 AND expires_at>?4 AND (attempts<4 OR lease_until>?4)
                 AND json_extract(event_json,'$.code')='subscription_updated')",
                params![co.uuid,receiver,context.generation,now], |r| r.get(0),
            )?;
            if pending {
                return Ok(());
            }
            generation = context.generation;
        } else {
            return Ok(());
        }
        prune(&tx, now)?;
        let confirmation = new_event(
            &subscription,
            receiver,
            &import_id,
            "status",
            Some("subscription_updated"),
            now,
        )?;
        enqueue_receiver(&tx, &co.uuid, &generation, &confirmation, now)?;
        tx.execute(
            "UPDATE push_receivers SET control_status_at=?3 WHERE account_id=?1 AND receiver_id=?2",
            params![co.uuid, receiver, now],
        )?;
        tx.commit()?;
        Ok(())
    }
}
