//! Pairing and its enrollment share one SQLite writer transaction.
use super::*;

pub(super) const SCHEMA: &str = "
CREATE TABLE pairing_sessions (
 session_id TEXT PRIMARY KEY NOT NULL,
 created_at INTEGER NOT NULL CHECK(created_at > 0),
 expires_at INTEGER NOT NULL CHECK(expires_at - created_at BETWEEN 1 AND 600),
 state TEXT NOT NULL CHECK(state IN ('active','consumed','expired','cancelled')),
 offer_json TEXT,
 private_key BLOB,
 CHECK ((state='active' AND offer_json IS NOT NULL AND private_key IS NOT NULL AND length(private_key)=32)
    OR (state!='active' AND offer_json IS NULL AND private_key IS NULL))
);";
const MAX_ACTIVE: usize = 8;
const MAX_RETAINED: usize = 1024;
const REPLAY_RETENTION: i64 = 86_400;

pub(crate) struct SessionStatus {
    pub state: String,
    pub expires_at: i64,
}

fn session_status(db: &Connection, id: &str, now: i64) -> Result<SessionStatus> {
    db.query_row(
        "SELECT CASE WHEN state='active' AND expires_at<=?2 THEN 'expired' ELSE state END,expires_at
         FROM pairing_sessions WHERE session_id=?1 AND created_at<=?2 AND expires_at>?3",
        params![id, now, now - REPLAY_RETENTION],
        |r| Ok(SessionStatus { state: r.get(0)?, expires_at: r.get(1)? }),
    )
    .optional()?
    .ok_or(StoreError::InvalidSession)
}

fn active(status: SessionStatus) -> Result<SessionStatus> {
    match status.state.as_str() {
        "active" => Ok(status),
        "consumed" => Err(StoreError::SessionConsumed),
        "expired" => Err(StoreError::SessionExpired),
        _ => Err(StoreError::InvalidSession),
    }
}

fn close(db: &Connection, id: &str, state: &str) -> Result<()> {
    let changed = db.execute(
        "UPDATE pairing_sessions SET state=?2,offer_json=NULL,private_key=NULL
         WHERE session_id=?1 AND state='active'",
        params![id, state],
    )?;
    if changed != 1 {
        return Err(StoreError::StateUnavailable);
    }
    Ok(())
}

fn prune(db: &Connection, now: i64) -> Result<()> {
    db.execute(
        "DELETE FROM pairing_sessions WHERE expires_at<=?1",
        [now - REPLAY_RETENTION],
    )?;
    db.execute(
        "UPDATE pairing_sessions SET state='expired',offer_json=NULL,private_key=NULL
         WHERE state='active' AND expires_at<=?1",
        [now],
    )?;
    Ok(())
}

impl PushStore {
    pub(crate) fn reap_pairings(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        prune(&tx, crate::push::now())?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn create_pairing(
        &mut self,
        id: &str,
        created_at: i64,
        expires_at: i64,
        offer_json: &str,
        private_key: &[u8],
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        prune(&tx, created_at)?;
        let (total, active): (usize, usize) = tx.query_row(
            "SELECT count(*),count(CASE WHEN state='active' THEN 1 END) FROM pairing_sessions",
            [],
            |r| Ok((row_count(r, 0)?, row_count(r, 1)?)),
        )?;
        if total >= MAX_RETAINED || active >= MAX_ACTIVE {
            tx.commit()?;
            return Err(StoreError::CapacityExceeded);
        }
        tx.execute(
            "INSERT INTO pairing_sessions VALUES(?1,?2,?3,'active',?4,?5)",
            params![id, created_at, expires_at, offer_json, private_key],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn pairing_status(&mut self, id: &str) -> Result<SessionStatus> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = crate::push::now();
        prune(&tx, now)?;
        let result = session_status(&tx, id, now);
        tx.commit()?;
        result
    }

    pub(crate) fn cancel_pairing(&mut self, id: &str) -> Result<SessionStatus> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = crate::push::now();
        prune(&tx, now)?;
        let result = session_status(&tx, id, now).and_then(active);
        let result = match result {
            Ok(mut status) => {
                close(&tx, id, "cancelled")?;
                status.state = "cancelled".to_owned();
                Ok(status)
            }
            Err(error) => Err(error),
        };
        tx.commit()?;
        result
    }

    pub(crate) fn load_pairing(&mut self, id: &str) -> Result<(String, Vec<u8>)> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = crate::push::now();
        prune(&tx, now)?;
        let result = session_status(&tx, id, now).and_then(active);
        let result = result.and_then(|_| {
            Ok(tx.query_row(
                "SELECT offer_json,private_key FROM pairing_sessions WHERE session_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        });
        tx.commit()?;
        result
    }

    pub(crate) fn enroll_pairing<T>(
        &mut self,
        id: &str,
        enrollment: &Enrollment,
        make_receipt: impl FnOnce(EnrollmentResult, bool) -> Result<T>,
    ) -> Result<T> {
        enrollment.validate()?;
        if enrollment.enrollment_version != 3 {
            return Err(StoreError::UnsupportedVersion);
        }
        let hash = digest(enrollment)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = crate::push::now();
        if !(1..=MAX_JSON_INTEGER as i64).contains(&now) {
            return Err(StoreError::StateUnavailable);
        }
        if let Err(error) = session_status(&tx, id, now).and_then(active) {
            if error == StoreError::SessionExpired {
                // Record the observed expiry even if the deadline crossed
                // while checking the enrollment policy.
                prune(&tx, now)?;
                tx.commit()?;
            }
            return Err(error);
        }
        let receipt = Self::enroll_in(&tx, enrollment, now, &hash)?;
        let current =
            receipt.replayed && Self::retry_current_import_status_in(&tx, enrollment, now, &hash)?;
        let response = make_receipt(receipt, current)?;
        close(&tx, id, "consumed")?;
        tx.commit()?;
        Ok(response)
    }
}
