//! Public synthetic fixtures only. No configurable production keys/endpoints.
#[path = "../tests/support/mod.rs"]
mod support;
use colliesocket_push::{SubscriptionKeys, MAX_PLAINTEXT_BYTES};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;
use support::*;

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures"));
    std::fs::create_dir_all(&output)?;
    let rfc = deterministic_encrypt(RFC_PLAINTEXT.to_vec());
    assert_eq!(rfc, decode(RFC_CIPHERTEXT));
    let mut padded = SYNTHETIC_JSON.to_vec();
    padded.resize(MAX_PLAINTEXT_BYTES, b' ');
    let wake = deterministic_encrypt(padded);
    let random =
        SubscriptionKeys::from_base64url(RECEIVER_PUBLIC, AUTH)?.encrypt_padded(SYNTHETIC_JSON)?;
    for (name, bytes) in [
        ("rfc8291.bin", &rfc),
        ("wake-v1.bin", &wake),
        ("sender-random.bin", &random),
    ] {
        std::fs::write(output.join(name), bytes)?;
        println!("{name} bytes={} sha256={}", bytes.len(), sha256_hex(bytes));
    }
    std::fs::write(output.join("wake-v1.json"), SYNTHETIC_JSON)?;
    let metadata = serde_json::json!({
        "synthetic":true,
        "warning":"Public RFC test keys only; never use for a real subscription",
        "source":"https://www.rfc-editor.org/rfc/rfc8291#section-5",
        "receiver_private":RECEIVER_PRIVATE,"p256dh":RECEIVER_PUBLIC,"auth":AUTH,
        "sender_private":SENDER_PRIVATE,"salt":SALT,"record_size":4096,
        "files":[
            {"path":"rfc8291.bin","sha256":sha256_hex(&rfc),"deterministic":true},
            {"path":"wake-v1.bin","sha256":sha256_hex(&wake),"deterministic":true},
            {"path":"sender-random.bin","sha256":sha256_hex(&random),"deterministic":false}
        ]
    });
    std::fs::write(
        output.join("metadata.json"),
        format!("{}\n", serde_json::to_string_pretty(&metadata)?),
    )?;
    Ok(())
}
