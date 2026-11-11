//! Enrollment-v2 control frames. Signal envelope metadata is not authority.
//!
//! Keep this decoder independent of I/O: only authenticated plaintext is ever
//! passed to subscription validation or destination-policy checks.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openssl::symm::{decrypt_aead, Cipher};
use serde::Deserialize;

pub const MAGIC: &[u8; 17] = b"COLLIESOCKET-CTRL";
const HEADER_BYTES: usize = 46;
const NONCE_END: usize = HEADER_BYTES + 12;
const TAG_BYTES: usize = 16;
pub const MAX_PLAINTEXT_BYTES: usize = 3072;
pub const MAX_FRAME_BYTES: usize = NONCE_END + MAX_PLAINTEXT_BYTES + TAG_BYTES;

// Deliberately no Debug: these fields include private endpoint and key material.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointUpdate {
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
}

pub struct AuthenticatedUpdate {
    pub subscription_epoch: u64,
    pub subscription: EndpointUpdate,
    pub digest: [u8; 32],
}

pub fn is_candidate(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

fn account_bytes(account: &str) -> Option<[u8; 16]> {
    let hex: String = account.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.is_ascii() {
        return None;
    }
    let mut output = [0; 16];
    for (i, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(output)
}

/// Reject malformed, unauthenticated or wrongly addressed frames identically.
/// The caller must still validate the subscription and atomically check epoch.
pub fn decrypt(
    bytes: &[u8],
    account: &str,
    device: u32,
    control_key: &str,
) -> Option<AuthenticatedUpdate> {
    if !(NONCE_END + TAG_BYTES + 1..=MAX_FRAME_BYTES).contains(&bytes.len())
        || !is_candidate(bytes)
        || bytes[17] != 2
        || bytes[18..34] != account_bytes(account)?
        || bytes[34..38] != device.to_be_bytes()
    {
        return None;
    }
    let epoch = u64::from_be_bytes(bytes[38..46].try_into().ok()?);
    if !(1..=crate::push_store::MAX_JSON_INTEGER).contains(&epoch) {
        return None;
    }
    let key = URL_SAFE_NO_PAD.decode(control_key).ok()?;
    if key.len() != 32 || URL_SAFE_NO_PAD.encode(&key) != control_key {
        return None;
    }
    let tag_start = bytes.len() - TAG_BYTES;
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&bytes[HEADER_BYTES..NONCE_END]),
        &bytes[..HEADER_BYTES],
        &bytes[NONCE_END..tag_start],
        &bytes[tag_start..],
    )
    .ok()?;
    // Typed serde decoding rejects duplicate/unknown fields, explicit null,
    // malformed UTF-8, BOM and extra JSON values without exposing plaintext.
    let subscription = serde_json::from_slice::<EndpointUpdate>(&plaintext).ok()?;
    Some(AuthenticatedUpdate {
        subscription_epoch: epoch,
        subscription,
        digest: openssl::sha::sha256(bytes),
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use openssl::symm::encrypt_aead;

    pub const ACCOUNT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    pub const KEY: [u8; 32] = [0x36; 32];

    pub fn frame_for(account: &str, device: u32, epoch: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut header = MAGIC.to_vec();
        header.push(2);
        header.extend_from_slice(&account_bytes(account).unwrap());
        header.extend_from_slice(&device.to_be_bytes());
        header.extend_from_slice(&epoch.to_be_bytes());
        let mut nonce = [0; 12];
        openssl::rand::rand_bytes(&mut nonce).unwrap();
        let mut tag = [0; TAG_BYTES];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &KEY,
            Some(&nonce),
            &header,
            plaintext,
            &mut tag,
        )
        .unwrap();
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&ciphertext);
        header.extend_from_slice(&tag);
        header
    }

    #[test]
    fn decodes_the_independent_python_contract_vector() {
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../contracts/encrypted-push/v2/fixtures/control-v2.json"
        ))
        .unwrap();
        let frame = URL_SAFE_NO_PAD
            .decode(fixture["frame_base64url"].as_str().unwrap())
            .unwrap();
        let update = decrypt(
            &frame,
            fixture["account_id"].as_str().unwrap(),
            fixture["device_id"].as_u64().unwrap() as u32,
            fixture["control_key"].as_str().unwrap(),
        )
        .unwrap();
        let plaintext: EndpointUpdate =
            serde_json::from_str(fixture["plaintext_utf8"].as_str().unwrap()).unwrap();
        assert_eq!(
            update.subscription_epoch,
            fixture["subscription_epoch"].as_u64().unwrap()
        );
        assert_eq!(update.subscription.endpoint, plaintext.endpoint);
        assert_eq!(update.subscription.p256dh, plaintext.p256dh);
        assert_eq!(update.subscription.auth, plaintext.auth);
    }

    #[test]
    fn authenticates_context_and_every_encrypted_byte() {
        let body = br#"{"endpoint":"https://push.example.test/new","p256dh":"synthetic","auth":"synthetic"}"#;
        let frame = frame_for(ACCOUNT, 2, 3, body);
        let key = URL_SAFE_NO_PAD.encode(KEY);
        let decoded = decrypt(&frame, ACCOUNT, 2, &key).unwrap();
        assert_eq!(decoded.subscription_epoch, 3);
        assert_eq!(
            decoded.subscription.endpoint,
            "https://push.example.test/new"
        );
        assert_eq!(decoded.digest, openssl::sha::sha256(&frame));
        for offset in 0..frame.len() {
            let mut changed = frame.clone();
            changed[offset] ^= 1;
            assert!(
                decrypt(&changed, ACCOUNT, 2, &key).is_none(),
                "offset {offset}"
            );
        }
        assert!(decrypt(&frame, ACCOUNT, 3, &key).is_none());
        assert!(decrypt(&frame, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 2, &key).is_none());
        assert!(decrypt(&frame, ACCOUNT, 2, &URL_SAFE_NO_PAD.encode([0; 32])).is_none());
        assert!(decrypt(&frame, ACCOUNT, 2, &(key.clone() + "=")).is_none());
    }

    #[test]
    fn rejects_oversize_truncation_and_authenticated_schema_changes() {
        let key = URL_SAFE_NO_PAD.encode(KEY);
        for body in [
            br#"{"endpoint":"x","endpoint":"y","p256dh":"p","auth":"a"}"#.as_slice(),
            br#"{"endpoint":"x","p256dh":"p","auth":"a","password":"private"}"#,
            br#"{"endpoint":"x","p256dh":"p","auth":null}"#,
            br#"{"endpoint":"x","p256dh":"p"}"#,
            br#"{"endpoint":"x","p256dh":"p","auth":"a"} {}"#,
            b"\xef\xbb\xbf{}",
            b"\xff",
        ] {
            assert!(decrypt(&frame_for(ACCOUNT, 2, 2, body), ACCOUNT, 2, &key).is_none());
        }
        let frame = frame_for(
            ACCOUNT,
            2,
            2,
            br#"{"endpoint":"x","p256dh":"p","auth":"a"}"#,
        );
        for size in 0..frame.len() {
            assert!(decrypt(&frame[..size], ACCOUNT, 2, &key).is_none());
        }
        assert!(decrypt(&vec![0; MAX_FRAME_BYTES + 1], ACCOUNT, 2, &key).is_none());
        for epoch in [0, crate::push_store::MAX_JSON_INTEGER + 1, u64::MAX] {
            assert!(decrypt(&frame_for(ACCOUNT, 2, epoch, b"{}"), ACCOUNT, 2, &key).is_none());
        }
        assert!(is_candidate(MAGIC));
        assert!(!is_candidate(b"normal Signal ciphertext"));
    }
}
