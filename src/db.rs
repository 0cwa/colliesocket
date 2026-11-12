use eyre::Result;
use rusqlite::{self, Row};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::config;

pub struct MollySocketDb {
    db: Arc<Mutex<rusqlite::Connection>>,
}

pub struct Connection {
    pub uuid: String,
    pub device_id: u32,
    pub password: String,
    pub endpoint: String,
    pub forbidden: bool,
    pub last_registration: OptTime,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("forbidden", &self.forbidden)
            .field("credentials", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Connection {
    pub fn new(uuid: String, device_id: u32, password: String, endpoint: String) -> Self {
        Connection {
            uuid,
            device_id,
            password,
            endpoint,
            forbidden: false,
            last_registration: OptTime::from(SystemTime::now()),
        }
    }
}

#[derive(Debug)]
pub struct OptTime(pub Option<SystemTime>);

impl From<&OptTime> for i64 {
    fn from(i: &OptTime) -> i64 {
        let instant = match i.0 {
            Some(instant) => instant,
            None => return 0,
        };
        match instant.duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs() as i64,
            Err(_) => 0,
        }
    }
}

impl From<i64> for OptTime {
    fn from(i: i64) -> OptTime {
        if i == 0 {
            return OptTime(None);
        }
        let duration = Duration::from_secs(i as u64);
        OptTime(UNIX_EPOCH.checked_add(duration))
    }
}

impl From<SystemTime> for OptTime {
    fn from(t: SystemTime) -> Self {
        OptTime(Some(t))
    }
}

impl Connection {
    fn map(row: &Row) -> Result<Connection> {
        Ok(Connection {
            uuid: row.get(0)?,
            device_id: row.get(1)?,
            password: row.get(2)?,
            endpoint: row.get(3)?,
            forbidden: row.get(4)?,
            last_registration: OptTime::from(row.get::<usize, i64>(5)?),
        })
    }
}

impl MollySocketDb {
    pub fn new() -> Result<MollySocketDb> {
        Self::open(config::get_db())
    }
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<MollySocketDb> {
        let path = path.as_ref();
        drop(crate::push_store::PushStore::open(path)?);
        let db = rusqlite::Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;",
        )?;
        Ok(MollySocketDb {
            db: Arc::new(Mutex::new(db)),
        })
    }

    pub fn add(&self, co: &Connection) -> Result<()> {
        self.db.lock().unwrap().execute(
            "INSERT INTO connections(uuid, device_id, password, endpoint, forbidden, last_registration)
            VALUES (?, ?, ?, ?, ?, ?);",
            [&co.uuid, &co.device_id.to_string(), &co.password, &co.endpoint, &String::from(if co.forbidden { "1" } else { "0" }), &i64::from(&co.last_registration).to_string()]
        )?;
        Ok(())
    }

    pub fn update_last_registration(&self, uuid: &str) -> Result<()> {
        let now = OptTime::from(SystemTime::now());
        self.db.lock().unwrap().execute(
            "UPDATE connections
            SET last_registration = ?
            WHERE uuid = ?;",
            [&i64::from(&now).to_string(), uuid],
        )?;
        Ok(())
    }

    pub fn forbid_if_current(
        &self,
        co: &Connection,
        expected_generation: Option<&str>,
    ) -> Result<bool> {
        Ok(self.db.lock().unwrap().execute(
            "UPDATE connections SET forbidden=1 WHERE uuid=?1 AND device_id=?2 AND password=?3 AND endpoint=?4 AND forbidden=0 AND (SELECT generation FROM encrypted_subscription_generations WHERE account_id=?1) IS ?5",
            rusqlite::params![co.uuid,co.device_id,co.password,co.endpoint,expected_generation])?>0)
    }

    pub fn list(&self) -> Result<Vec<Connection>> {
        self.db
            .lock()
            .unwrap()
            .prepare("SELECT * FROM connections;")?
            .query_and_then([], Connection::map)?
            .collect::<Result<Vec<Connection>>>()
    }

    pub fn get(&self, uuid: &str) -> Result<Connection> {
        self.db
            .lock()
            .unwrap()
            .prepare("SELECT * FROM connections WHERE uuid=?1 LIMIT 1")?
            .query_and_then([uuid], Connection::map)?
            .next()
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?
    }

    pub fn rm(&self, uuid: &str) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .execute("DELETE FROM connections WHERE uuid=?1;", [&uuid])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db() {
        let directory = std::env::temp_dir().join(format!(
            "colliesocket-db-{}",
            crate::push::uuid_v4().unwrap()
        ));
        let db = MollySocketDb::open(directory.join("state.db")).unwrap();
        let uuid = "0d2ff653-3d88-43de-bcdb-f6657d3484e4";
        db.add(&Connection::new(
            String::from(uuid),
            1,
            String::from("pass"),
            String::from("http://0.0.0.0/"),
        ))
        .unwrap();
        assert!(db
            .list()
            .unwrap()
            .iter()
            .map(|co| &co.uuid)
            .any(|row_uuid| row_uuid == uuid));
        db.rm(uuid).unwrap();
        drop(db);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn late_signal_rejection_does_not_forbid_replacement_credentials() {
        let directory = std::env::temp_dir().join(format!(
            "colliesocket-db-{}",
            crate::push::uuid_v4().unwrap()
        ));
        let db = MollySocketDb::open(directory.join("state.db")).unwrap();
        let old = Connection::new(
            "11111111-1111-4111-8111-111111111111".into(),
            2,
            "synthetic-old-password".into(),
            "https://push.example.test/a".into(),
        );
        db.add(&old).unwrap();
        let new = Connection::new(
            old.uuid.clone(),
            2,
            "synthetic-new-password".into(),
            old.endpoint.clone(),
        );
        db.add(&new).unwrap();
        assert!(!db.forbid_if_current(&old, None).unwrap());
        assert!(!db.get(&old.uuid).unwrap().forbidden);
        assert!(db.forbid_if_current(&new, None).unwrap());
        assert!(db.get(&new.uuid).unwrap().forbidden);
        drop(db);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
