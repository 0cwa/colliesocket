//! Read-only projection of local registration metadata for the CLI.
use super::{
    protected_state_file, row_epoch, valid_instance, verify_connection_schema, AccountState,
    Result, StoreError, SCHEMA_VERSION,
};
use rusqlite::{Connection, OpenFlags, Row};
use serde::Serialize;
use std::{
    io::{ErrorKind, Read},
    path::Path,
};

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    EncryptedV1,
    EncryptedV2,
    EncryptedV3,
    LegacyUnkeyed,
}

#[derive(Serialize)]
pub(crate) struct RegistrationStatus {
    account_id: String,
    device_id: u32,
    mode: Mode,
    enrollment_version: Option<u32>,
    pub(crate) selected_event_version: Option<u32>,
    has_control_key: bool,
    pub(crate) subscription_epoch: Option<u64>,
    pub(crate) instance: Option<String>,
    endpoint_origin: Option<String>,
    active: bool,
    #[serde(skip)]
    pub(crate) state: Option<AccountState>,
}

pub(crate) fn read(path: &Path, account: Option<&str>) -> Result<Vec<RegistrationStatus>> {
    let Some(mut file) = protected_state_file(path, false)? else {
        return Ok(Vec::new());
    };
    // CollieSocket uses rollback journals. A read-only SQLite connection can
    // still create or update WAL sidecars, so reject WAL before opening SQLite.
    let mut header = [0; 20];
    match file.read_exact(&mut header) {
        Ok(()) if header[18..] != [1, 1] => return Err(StoreError::StateUnavailable),
        Ok(()) => (),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => (),
        Err(_) => return Err(StoreError::StateUnavailable),
    }
    // Close the preflight descriptor before SQLite takes its POSIX locks.
    drop(file);

    let mut db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let snapshot = db.transaction()?;
    let version: u32 = snapshot.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::FutureSchema);
    }
    if version == 0
        && snapshot.query_row("SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema)", [], |r| {
            r.get::<_, bool>(0)
        })?
    {
        return Ok(Vec::new());
    }
    verify_connection_schema(&snapshot)?;

    let sql = if version < 2 {
        if account.is_some() {
            return Ok(Vec::new());
        }
        "SELECT uuid, device_id, endpoint, forbidden, NULL FROM connections ORDER BY uuid"
            .to_owned()
    } else {
        let has_control_key = if version < 3 {
            "0"
        } else {
            "s.control_key IS NOT NULL"
        };
        format!(
            "SELECT c.uuid, c.device_id, c.endpoint, c.forbidden, s.state, s.subscription_epoch,
                    json_extract(s.subscription_json, '$.instance'),
                    json_extract(s.subscription_json, '$.supported_event_versions'),
                    {has_control_key}
             FROM connections c LEFT JOIN encrypted_subscriptions s ON s.account_id = c.uuid
             WHERE ?1 IS NULL OR (s.state IS NOT NULL AND c.uuid = ?1)
             ORDER BY c.uuid"
        )
    };
    let mut statement = snapshot.prepare(&sql)?;
    let mut rows = if version < 2 {
        statement.query([])?
    } else {
        statement.query([account])?
    };
    let mut statuses = Vec::new();
    while let Some(row) = rows.next()? {
        statuses.push(registration(row, version)?);
    }
    Ok(statuses)
}

fn registration(row: &Row<'_>, schema_version: u32) -> Result<RegistrationStatus> {
    let endpoint: Option<String> = row.get(2)?;
    let mut status = RegistrationStatus {
        account_id: row.get(0)?,
        device_id: row.get(1)?,
        endpoint_origin: endpoint.as_deref().and_then(endpoint_origin),
        mode: Mode::LegacyUnkeyed,
        enrollment_version: None,
        selected_event_version: None,
        has_control_key: false,
        subscription_epoch: None,
        instance: None,
        active: !row.get::<_, bool>(3)?,
        state: None,
    };
    if let Some(state) = row.get::<_, Option<String>>(4)? {
        let state = AccountState::from_db(&state)?;
        let instance: String = row.get(6)?;
        if !valid_instance(&instance) {
            return Err(StoreError::StateUnavailable);
        }
        let versions: Vec<u32> = serde_json::from_str(&row.get::<_, String>(7)?)?;
        status.has_control_key = row.get(8)?;
        let (mode, enrollment_version, event_version) =
            encrypted_versions(&versions, status.has_control_key, schema_version)?;
        status.mode = mode;
        status.enrollment_version = enrollment_version;
        status.selected_event_version = Some(event_version);
        status.subscription_epoch = Some(row_epoch(row, 5)?);
        status.instance = Some(instance);
        status.active = state == AccountState::Active;
        status.state = Some(state);
    }
    Ok(status)
}

fn encrypted_versions(
    versions: &[u32],
    has_control_key: bool,
    schema_version: u32,
) -> Result<(Mode, Option<u32>, u32)> {
    match (versions, has_control_key) {
        // Schema 2 only supported v1 imports. Starting at schema 3, v1 and
        // unkeyed v2 imports leave identical current subscription metadata.
        ([1], false) => Ok((Mode::EncryptedV1, (schema_version == 2).then_some(1), 1)),
        ([1, 2], true) => Ok((Mode::EncryptedV2, Some(2), 2)),
        ([1, 2, 3], true) => Ok((Mode::EncryptedV3, Some(3), 3)),
        _ => Err(StoreError::StateUnavailable),
    }
}

fn endpoint_origin(endpoint: &str) -> Option<String> {
    let (_, tail) = endpoint.split_once("://")?;
    // The URL parser can repair a missing authority or treat a backslash as
    // a separator. Never turn text from a malformed endpoint into a host.
    if tail.starts_with(['/', '?', '#'])
        || endpoint.contains('\\')
        || endpoint
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return None;
    }
    let url = url::Url::parse(endpoint).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.port_or_known_default().is_none_or(|p| p == 0)
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_origin_strips_url_components_and_canonicalizes_ports() {
        for (endpoint, expected) in [
            (
                "https://user:pass@PUSH.example:443/path?secret=x#fragment",
                "https://push.example",
            ),
            ("http://push.example:80/path", "http://push.example"),
            (
                "https://[2001:db8::1]:8443/path",
                "https://[2001:db8::1]:8443",
            ),
        ] {
            assert_eq!(endpoint_origin(endpoint).as_deref(), Some(expected));
        }
        for invalid in [
            "not-a-url",
            "ftp://example.test/path",
            "https:///path-secret",
            "https://?query-secret",
            "https://example.test:0/path",
            "https://example.test\\path",
            "https://example.test\t/path",
        ] {
            assert_eq!(endpoint_origin(invalid), None);
        }
    }

    #[test]
    fn stored_versions_distinguish_protocol_from_ambiguous_import_version() {
        use Mode::*;
        assert_eq!(
            encrypted_versions(&[1], false, 2),
            Ok((EncryptedV1, Some(1), 1))
        );
        assert_eq!(
            encrypted_versions(&[1], false, 5),
            Ok((EncryptedV1, None, 1))
        );
        assert_eq!(
            encrypted_versions(&[1, 2], true, 5),
            Ok((EncryptedV2, Some(2), 2))
        );
        assert_eq!(
            encrypted_versions(&[1, 2, 3], true, 5),
            Ok((EncryptedV3, Some(3), 3))
        );
        assert_eq!(
            encrypted_versions(&[1, 2, 3], false, 5),
            Err(StoreError::StateUnavailable)
        );
    }
}
