mod support;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use colliesocket_push::{
    Error, SubscriptionKeys, MAX_BODY_BYTES, MAX_JSON_BYTES, MAX_PLAINTEXT_BYTES,
};
use support::*;

#[test]
fn published_rfc8291_vector_matches_every_byte() {
    let body = deterministic_encrypt(RFC_PLAINTEXT.to_vec());
    assert_eq!(body, decode(RFC_CIPHERTEXT));
    // The RFC sample HTTP header says 145, but the actual published bytes are 144.
    assert_eq!(body.len(), 144);
}

#[test]
fn malformed_keys_rejected_without_panics_or_secret_errors() {
    for auth in [
        "",
        "a",
        "AAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAA",
        "BTBZMqHH6r4Tts7J_aSIgg==",
        "!TBZMqHH6r4Tts7J_aSIgg",
        "BTBZMqHH6r4Tts7J_aSIgh",
    ] {
        let result = SubscriptionKeys::from_base64url(RECEIVER_PUBLIC, auth);
        assert!(result.is_err(), "malformed auth accepted");
        assert!(!format!("{}", result.unwrap_err()).contains(AUTH));
    }
    for public in [vec![], vec![0], vec![4; 64], vec![4; 66], vec![0; 65], {
        let mut bytes = vec![0; 65];
        bytes[0] = 4;
        bytes
    }] {
        assert!(SubscriptionKeys::from_base64url(&URL_SAFE_NO_PAD.encode(public), AUTH).is_err());
    }
    let mut wrong_prefix = decode(RECEIVER_PUBLIC);
    wrong_prefix[0] = 2;
    assert!(SubscriptionKeys::from_base64url(&URL_SAFE_NO_PAD.encode(wrong_prefix), AUTH).is_err());
    assert!(SubscriptionKeys::from_base64url(&format!("{RECEIVER_PUBLIC}="), AUTH).is_err());
    assert!(SubscriptionKeys::from_base64url(&RECEIVER_PUBLIC.replace('_', "/"), AUTH).is_err());
    let keys = SubscriptionKeys::from_base64url(RECEIVER_PUBLIC, AUTH).unwrap();
    assert_eq!(format!("{keys:?}"), "SubscriptionKeys([REDACTED])");
}

#[test]
fn exact_size_limits_include_framing_and_json_padding() {
    let keys = SubscriptionKeys::from_base64url(RECEIVER_PUBLIC, AUTH).unwrap();
    for size in [0, 1, 42, MAX_PLAINTEXT_BYTES] {
        let body = keys.encrypt(&vec![b'x'; size]).unwrap();
        assert_eq!(body.len(), size + 103);
        assert_eq!(&body[16..20], &4096_u32.to_be_bytes());
        assert_eq!(body[20], 65);
        assert_eq!(body[21], 4);
        assert!(body.len() <= MAX_BODY_BYTES && body.len() - 86 < 4096);
    }
    assert_eq!(
        keys.encrypt(&vec![0; MAX_PLAINTEXT_BYTES + 1]),
        Err(Error::PayloadTooLarge)
    );
    assert_eq!(
        keys.encrypt_padded(&vec![b' '; MAX_JSON_BYTES])
            .unwrap()
            .len(),
        MAX_BODY_BYTES
    );
    assert_eq!(
        keys.encrypt_padded(&vec![b' '; MAX_JSON_BYTES + 1]),
        Err(Error::PayloadTooLarge)
    );
}

#[test]
fn random_production_sender_uses_fresh_salt_and_ephemeral_key() {
    let keys = SubscriptionKeys::from_base64url(RECEIVER_PUBLIC, AUTH).unwrap();
    let first = keys.encrypt_padded(SYNTHETIC_JSON).unwrap();
    let second = keys.encrypt_padded(SYNTHETIC_JSON).unwrap();
    assert_eq!(first.len(), MAX_BODY_BYTES);
    assert_eq!(second.len(), MAX_BODY_BYTES);
    assert_ne!(&first[..16], &second[..16]);
    assert_ne!(&first[21..86], &second[21..86]);
    assert_ne!(first, second);
}

#[test]
fn committed_deterministic_fixtures_match_fresh_rust_output() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    assert_eq!(
        std::fs::read(path.join("rfc8291.bin")).unwrap(),
        deterministic_encrypt(RFC_PLAINTEXT.to_vec())
    );
    let mut padded = SYNTHETIC_JSON.to_vec();
    padded.resize(MAX_PLAINTEXT_BYTES, b' ');
    assert_eq!(
        std::fs::read(path.join("wake-v1.bin")).unwrap(),
        deterministic_encrypt(padded)
    );
}
