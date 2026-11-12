//! Protected local enrollment. The service account is the initial authority.
use crate::{
    config, push,
    push_store::{self, Enrollment, EnrollmentDisposition, PushStore},
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, IsTerminal, Read},
    path::Path,
};

pub const MAX_IMPORT_BYTES: u64 = 8192;
#[derive(Debug, Clone, Copy)]
pub struct Error(pub &'static str);

fn receipt_response(
    enrollment: &Enrollment,
    receipt: push_store::EnrollmentResult,
    current_v3_replay: bool,
) -> Value {
    let status = if enrollment.enrollment_version == 3 && receipt.replayed {
        if current_v3_replay {
            "unchanged"
        } else {
            "accepted"
        }
    } else if matches!(receipt.disposition, EnrollmentDisposition::Unchanged) {
        "unchanged"
    } else {
        "accepted"
    };
    let mut response = json!({"enrollment_version":enrollment.enrollment_version,"request_id":enrollment.request_id,
        "instance":enrollment.subscription.instance,"subscription_epoch":receipt.subscription_epoch,
        "selected_event_version":enrollment.subscription.event_version(),"capabilities":["wake","test","status"],
        "status":status});
    if enrollment.enrollment_version == 3 {
        response["replayed"] = json!(receipt.replayed);
    }
    response
}

pub(crate) fn current_v3_replay_status(
    store: &mut PushStore,
    enrollment: &Enrollment,
    receipt: &push_store::EnrollmentResult,
    now: i64,
) -> Result<bool, Error> {
    if enrollment.enrollment_version == 3 && receipt.replayed {
        store
            .retry_current_import_status(enrollment, now)
            .map_err(|error| Error(error.code()))
    } else {
        Ok(false)
    }
}

pub fn bounded_read(reader: impl Read, limit: u64) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("unsafe_file"))?;
    if bytes.len() as u64 > limit {
        return Err(Error("input_too_large"));
    }
    Ok(bytes)
}

#[cfg(unix)]
pub fn read_protected_file(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    };
    if path.as_os_str().as_bytes().contains(&0) {
        return Err(Error("unsafe_file"));
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error("unsafe_file"))?;
    let meta = file.metadata().map_err(|_| Error("unsafe_file"))?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
    {
        return Err(Error("unsafe_file"));
    }
    bounded_read(file, limit)
}
#[cfg(not(unix))]
pub fn read_protected_file(_: &Path, _: u64) -> Result<Vec<u8>, Error> {
    Err(Error("unsafe_file"))
}

pub fn read_stdin() -> Result<Vec<u8>, Error> {
    if io::stdin().is_terminal() {
        return Err(Error("unsafe_file"));
    }
    bounded_read(io::stdin().lock(), MAX_IMPORT_BYTES)
}

pub fn parse(bytes: &[u8]) -> Result<Enrollment, Error> {
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        return Err(Error("input_too_large"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error("invalid_json"))?;
    let value: Enrollment = serde_json::from_str(text).map_err(|error| {
        // Typed decoding preserves duplicate-field rejection while keeping
        // valid JSON with schema errors distinct from malformed JSON.
        let code = if error.is_syntax()
            || error.is_eof()
            || error.to_string().starts_with("duplicate field")
        {
            "invalid_json"
        } else {
            "invalid_enrollment"
        };
        Error(code)
    })?;
    push_store::validate_enrollment(&value).map_err(|e| Error(e.code()))?;
    Ok(value)
}

pub async fn import(bytes: &[u8]) -> Result<Value, Error> {
    let enrollment = parse(bytes)?;
    if !config::is_uuid_valid(&enrollment.account_id) {
        return Err(Error("invalid_enrollment"));
    }
    let mut store = PushStore::open(config::get_db()).map_err(|e| Error(e.code()))?;
    // A receipt found before DNS avoids network work. A competing import can
    // still create the same receipt while this request checks DNS, so classify
    // the final receipt against current state in either path below.
    let receipt = match store
        .receipt_for(&enrollment)
        .map_err(|e| Error(e.code()))?
    {
        Some(receipt) => receipt,
        None => {
            if !config::is_endpoint_valid(&enrollment.subscription.endpoint).await {
                return Err(Error("invalid_endpoint"));
            }
            store
                .enroll(&enrollment, push::now())
                .map_err(|e| Error(e.code()))?
        }
    };
    let current_v3_replay =
        current_v3_replay_status(&mut store, &enrollment, &receipt, push::now())?;
    Ok(receipt_response(&enrollment, receipt, current_v3_replay))
}

pub fn status(account: &str) -> Result<Value, Error> {
    let store = PushStore::open(config::get_db()).map_err(|e| Error(e.code()))?;
    let sub = store
        .get_subscription(account)
        .map_err(|e| Error(e.code()))?
        .ok_or(Error("not_found"))?;
    let state = store
        .account_state(account)
        .map_err(|e| Error(e.code()))?
        .ok_or(Error("not_found"))?;
    Ok(
        json!({"instance":sub.instance,"subscription_epoch":sub.subscription_epoch,"state":state,"event_version":sub.event_version()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push_store::Subscription;

    fn response_enrollment(version: u32) -> Enrollment {
        let keyed = version >= 2;
        Enrollment {
            enrollment_version: version,
            request_id: "22222222-2222-4222-8222-222222222222".into(),
            import_seq: (version == 3).then_some(9),
            account_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            device_id: 2,
            password: "synthetic-password-only".into(),
            control_key: keyed.then(|| "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".into()),
            subscription: Subscription {
                endpoint: "https://push.example.test/token".into(),
                p256dh: String::new(),
                auth: String::new(),
                instance: "fixture-instance".into(),
                subscription_epoch: 5,
                encryption_required: true,
                supported_event_versions: match version {
                    1 => vec![1],
                    2 => vec![1, 2],
                    _ => vec![1, 2, 3],
                },
                capabilities: vec!["wake".into(), "test".into(), "status".into()],
                event_identity: None,
            },
        }
    }
    #[test]
    fn bounded_utf8_and_invalid_json_fail_closed() {
        assert_eq!(
            bounded_read(&[0u8; 8193][..], 8192).unwrap_err().0,
            "input_too_large"
        );
        assert_eq!(parse(&[0xff, 0xfe, b'{', 0]).unwrap_err().0, "invalid_json");
        assert_eq!(
            parse(b"{\"enrollment_version\":1,\"enrollment_version\":1}")
                .unwrap_err()
                .0,
            "invalid_json"
        );
        assert_eq!(parse(b"null").unwrap_err().0, "invalid_enrollment");
        assert_eq!(parse(b"{}").unwrap_err().0, "invalid_enrollment");
    }

    #[test]
    fn v3_receipts_distinguish_current_and_historical_replays_without_identity_leaks() {
        let enrollment = response_enrollment(3);
        let cached = push_store::EnrollmentResult {
            replayed: true,
            disposition: EnrollmentDisposition::Rotated,
            subscription_epoch: 5,
        };
        let current = receipt_response(&enrollment, cached, true);
        assert_eq!(current["status"], "unchanged");
        assert_eq!(current["replayed"], true);

        let historical = receipt_response(&enrollment, cached, false);
        assert_eq!(historical["status"], "accepted");
        assert_eq!(historical["replayed"], true);
        assert!(historical.get("import_seq").is_none());
        assert!(historical.get("key_id").is_none());

        let fresh = receipt_response(
            &enrollment,
            push_store::EnrollmentResult {
                replayed: false,
                disposition: EnrollmentDisposition::Rotated,
                subscription_epoch: 5,
            },
            false,
        );
        assert_eq!(fresh["status"], "accepted");
        assert_eq!(fresh["replayed"], false);
    }

    #[test]
    fn v2_receipt_response_bytes_do_not_gain_a_replay_marker() {
        let enrollment = response_enrollment(2);
        let response = receipt_response(
            &enrollment,
            push_store::EnrollmentResult {
                replayed: true,
                disposition: EnrollmentDisposition::Created,
                subscription_epoch: 5,
            },
            false,
        );
        assert_eq!(
            response,
            json!({
                "enrollment_version": 2,
                "request_id": "22222222-2222-4222-8222-222222222222",
                "instance": "fixture-instance",
                "subscription_epoch": 5,
                "selected_event_version": 2,
                "capabilities": ["wake", "test", "status"],
                "status": "accepted"
            })
        );
    }
    #[cfg(unix)]
    #[test]
    fn protected_files_reject_links_public_modes_and_fifos() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root =
            std::env::temp_dir().join(format!("colliesocket-import-{}", push::uuid_v4().unwrap()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("input.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_protected_file(&path, 8192).unwrap(), b"{}");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_protected_file(&path, 8192).unwrap_err().0,
            "unsafe_file"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&path, root.join("symlink")).unwrap();
        assert!(read_protected_file(&root.join("symlink"), 8192).is_err());
        fs::hard_link(&path, root.join("hardlink")).unwrap();
        assert!(read_protected_file(&path, 8192).is_err());
        let fifo = std::ffi::CString::new(root.join("fifo").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(read_protected_file(&root.join("fifo"), 8192).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
