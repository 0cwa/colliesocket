//! Authenticated Signal subscription controls. Signal envelope metadata is not authority.
//!
//! Keep this decoder independent of I/O: only authenticated plaintext is ever
//! passed to subscription validation or destination-policy checks.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openssl::symm::{decrypt_aead, Cipher};
use serde::Deserialize;

pub const MAGIC: &[u8; 17] = b"COLLIESOCKET-CTRL";
const HEADER_BYTES: usize = 46;
#[cfg(test)]
const NONCE_END: usize = HEADER_BYTES + 12;
const TAG_BYTES: usize = 16;
pub const MAX_PLAINTEXT_BYTES: usize = 3072;
#[cfg(test)]
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
    decrypt_for_receiver(bytes, account, device, None, control_key)
}

/// The clear receiver ID is only a lookup hint. It is also authenticated AAD.
pub fn receiver_id(bytes: &[u8]) -> Option<String> {
    if !is_candidate(bytes) || bytes.get(17) != Some(&4) {
        return None;
    }
    let raw = bytes.get(38..54)?;
    let hex: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
    let id = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    crate::push_store::canonical_uuid(&id, true).then_some(id)
}

pub fn decrypt_for_receiver(
    bytes: &[u8],
    account: &str,
    device: u32,
    receiver: Option<&str>,
    control_key: &str,
) -> Option<AuthenticatedUpdate> {
    let (version, header) = if receiver.is_some() {
        (4, HEADER_BYTES + 16)
    } else {
        (2, HEADER_BYTES)
    };
    let nonce_end = header + 12;
    if !(nonce_end + TAG_BYTES + 1..=nonce_end + MAX_PLAINTEXT_BYTES + TAG_BYTES)
        .contains(&bytes.len())
        || !is_candidate(bytes)
        || bytes[17] != version
        || bytes[18..34] != account_bytes(account)?
        || bytes[34..38] != device.to_be_bytes()
        || receiver.is_some_and(|id| receiver_id(bytes).as_deref() != Some(id))
    {
        return None;
    }
    let epoch = u64::from_be_bytes(bytes[header - 8..header].try_into().ok()?);
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
        Some(&bytes[header..nonce_end]),
        &bytes[..header],
        &bytes[nonce_end..tag_start],
        &bytes[tag_start..],
    )
    .ok()?;
    // Typed serde decoding rejects duplicate/unknown fields, explicit null,
    // malformed UTF-8, BOM and extra JSON values without exposing plaintext.
    if receiver.is_some()
        && plaintext.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
    {
        return None;
    }
    let subscription = serde_json::from_slice::<EndpointUpdate>(&plaintext).ok()?;
    Some(AuthenticatedUpdate {
        subscription_epoch: epoch,
        subscription,
        digest: openssl::sha::sha256(bytes),
    })
}

#[cfg(any(test, feature = "fuzzing"))]
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
        // This helper is compiled only for tests and the fuzzing feature; the
        // fixed synthetic key makes a content-derived nonce reproducible.
        let digest = openssl::sha::sha256(&[header.as_slice(), plaintext].concat());
        let nonce: [u8; 12] = digest[..12].try_into().unwrap();
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
        let empty_seed = include_bytes!("../fuzz/corpus/control_raw/empty.bin");
        assert!(decrypt(
            empty_seed,
            fixture["account_id"].as_str().unwrap(),
            fixture["device_id"].as_u64().unwrap() as u32,
            fixture["control_key"].as_str().unwrap(),
        )
        .is_none());
        assert_eq!(
            frame.as_slice(),
            include_bytes!("../fuzz/corpus/control_raw/v2-frame.bin")
        );
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
    fn fuzz_corpora_replay_through_production_control_decoder() {
        crate::fuzz_api::replay_committed_corpus("control_raw", |bytes| {
            crate::fuzz_api::decrypt_raw_control_frame(bytes);
        });
        crate::fuzz_api::replay_committed_corpus("control_authenticated", |bytes| {
            crate::fuzz_api::exercise_authenticated_control_input(bytes);
        });
    }

    #[test]
    fn authenticates_context_and_every_encrypted_byte() {
        let seed = include_bytes!(
            "../fuzz/corpus/control_authenticated/valid-prefixed-endpoint-update.bin"
        );
        assert_eq!(seed[0], 0);
        let body = &seed[1..];
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
        let oversized_json = format!(
            r#"{{"endpoint":"{}","p256dh":"p","auth":"a"}}"#,
            "x".repeat(MAX_PLAINTEXT_BYTES)
        );
        assert!(oversized_json.len() > MAX_PLAINTEXT_BYTES);
        assert!(decrypt(
            &frame_for(ACCOUNT, 2, 2, oversized_json.as_bytes()),
            ACCOUNT,
            2,
            &key
        )
        .is_none());
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

    #[test]
    fn v4_authenticates_the_independent_receiver_control_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../contracts/encrypted-push/v4/fixtures/control-vector.json"
        ))
        .unwrap();
        let frame: Vec<u8> = vector["frame_hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let account = vector["account_id"].as_str().unwrap();
        let receiver = vector["receiver_id"].as_str().unwrap();
        let device = vector["device_id"].as_u64().unwrap() as u32;
        let key = vector["control_key"].as_str().unwrap();
        assert_eq!(receiver_id(&frame).as_deref(), Some(receiver));
        let update = decrypt_for_receiver(&frame, account, device, Some(receiver), key).unwrap();
        assert_eq!(update.subscription_epoch, 2);
        let plain: EndpointUpdate = serde_json::from_str(include_str!(
            "../contracts/encrypted-push/v4/fixtures/control-plaintext.json"
        ))
        .unwrap();
        assert_eq!(update.subscription.endpoint, plain.endpoint);
        assert_eq!(update.subscription.auth, plain.auth);
        assert_eq!(update.subscription.p256dh, plain.p256dh);
        assert!(decrypt(&frame, account, device, key).is_none());
        assert!(decrypt_for_receiver(&frame, account, device + 1, Some(receiver), key).is_none());
        assert!(decrypt_for_receiver(&frame, account, device, Some(ACCOUNT), key).is_none());
        let wrong_account = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        assert!(decrypt_for_receiver(&frame, wrong_account, device, Some(receiver), key).is_none());
        assert!(decrypt_for_receiver(
            &frame,
            account,
            device,
            Some(receiver),
            &URL_SAFE_NO_PAD.encode(KEY)
        )
        .is_none());
        for i in 0..frame.len() {
            let mut changed = frame.clone();
            changed[i] ^= 1;
            assert!(decrypt_for_receiver(&changed, account, device, Some(receiver), key).is_none());
        }
    }
}
