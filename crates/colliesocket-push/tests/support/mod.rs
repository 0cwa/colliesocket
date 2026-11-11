//! Test-only deterministic RFC 8291 glue. Never compiled into the library.
//!
//! Adapted from Leo Gaskin's web-push-native encrypt_predictably/compute_ikm,
//! commit 6b0a3f10377af3c9401a7c1a60b1e34d41155c5d (release 0.5.0), MIT OR Apache-2.0.
//! Retained license: LICENSE-web-push-native-MIT. All primitives are RustCrypto;
//! framing uses ece-native. These public RFC test keys must never be deployed.
#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;
use web_push_native::{p256, p256::elliptic_curve::sec1::ToEncodedPoint};

pub const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
pub const RECEIVER_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
pub const RECEIVER_PUBLIC: &str =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
pub const SENDER_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
pub const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
pub const RFC_PLAINTEXT: &[u8] = b"When I grow up, I want to be a watermelon";
pub const RFC_CIPHERTEXT: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";
pub const SYNTHETIC_JSON: &[u8] = br#"{"version":1,"event_id":"11111111-1111-4111-8111-111111111111","instance":"fixture-instance","subscription_epoch":1,"kind":"wake","issued_at":1735689600,"expires_at":1735689900}"#;

pub fn decode(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value)
        .expect("fixed public RFC test data")
}

pub fn deterministic_encrypt(plaintext: Vec<u8>) -> Vec<u8> {
    let sender = p256::SecretKey::from_slice(&decode(SENDER_PRIVATE)).unwrap();
    let receiver = p256::PublicKey::from_sec1_bytes(&decode(RECEIVER_PUBLIC)).unwrap();
    let shared = p256::ecdh::diffie_hellman(sender.to_nonzero_scalar(), receiver.as_affine());
    let sender_public = sender.public_key().to_encoded_point(false);
    let mut info = b"WebPush: info\0".to_vec();
    info.extend_from_slice(receiver.to_encoded_point(false).as_bytes());
    info.extend_from_slice(sender_public.as_bytes());
    let mut ikm = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(&decode(AUTH)), shared.raw_secret_bytes().as_ref())
        .expand(&info, &mut ikm)
        .unwrap();
    assert_eq!(
        shared.raw_secret_bytes().as_slice(),
        decode("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs")
    );
    assert_eq!(
        ikm.as_slice(),
        decode("S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg")
    );
    ece_native::encrypt(
        ikm,
        decode(SALT).try_into().unwrap(),
        sender_public,
        std::iter::once(plaintext),
        4096,
    )
    .unwrap()
}
