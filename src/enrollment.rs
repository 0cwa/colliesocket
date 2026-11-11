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
    // A lost receipt can be recovered without DNS and cannot reactivate stale state.
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
    Ok(
        json!({"enrollment_version":enrollment.enrollment_version,"request_id":enrollment.request_id,
        "instance":enrollment.subscription.instance,"subscription_epoch":receipt.subscription_epoch,
        "selected_event_version":enrollment.subscription.event_version().map_err(|e| Error(e.code()))?,"capabilities":["wake","test","status"],
        "status":if matches!(receipt.disposition,EnrollmentDisposition::Unchanged){"unchanged"}else{"accepted"}}),
    )
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
        json!({"instance":sub.instance,"subscription_epoch":sub.subscription_epoch,"state":state,"event_version":sub.event_version().map_err(|e| Error(e.code()))?}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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
