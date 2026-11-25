//! Protected host-side handling for the pairing/v1 protocol.
use crate::{
    config,
    enrollment::{self, Error},
    push,
    push_store::{canonical_uuid, PushStore, StoreError, MAX_JSON_INTEGER},
    vapid,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use openssl::{
    derive::Deriver,
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    sha::sha256,
    sign::Signer,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

pub(crate) const DEFAULT_TTL: i64 = 300;
pub(crate) const MAX_REQUEST_BYTES: u64 = 11_264;
const MAX_SEALED_BYTES: usize = enrollment::MAX_IMPORT_BYTES as usize + 16;
const KEY_ERROR: Error = Error("state_unavailable");
const INVALID_REQUEST: Error = Error("invalid_request");
const INVALID_ENVELOPE: Error = Error("invalid_envelope");

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", try_from = "String")]
pub(crate) enum Intent {
    PairBridge,
    AddReceiver,
}

impl TryFrom<String> for Intent {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "pair_bridge" => Ok(Self::PairBridge),
            "add_receiver" => Ok(Self::AddReceiver),
            _ => Err("invalid intent"),
        }
    }
}

impl Intent {
    fn supported(self) -> Result<(), Error> {
        match self {
            Self::PairBridge => Ok(()),
            Self::AddReceiver => Err(Error("unsupported_intent")),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Offer {
    pairing_version: u8,
    session_id: String,
    intent: Intent,
    expires_at: i64,
    host_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_origin: Option<String>,
    vapid_public_key: String,
    server_public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    pairing_version: u64,
    session_id: String,
    intent: Intent,
    client_public_key: String,
    nonce: String,
    ciphertext: String,
}

fn open_store() -> Result<PushStore, Error> {
    PushStore::open(config::get_db()).map_err(|e| Error(e.code()))
}

fn canonical_origin(value: &str) -> bool {
    value.len() <= 256
        && value.bytes().all(|b| (33..=126).contains(&b))
        && Url::parse(value).is_ok_and(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.port_or_known_default().is_some_and(|port| port != 0)
                && url.origin().ascii_serialization() == value
        })
}

pub(crate) fn create(
    intent: Intent,
    host_label: &str,
    provider_origin: Option<&str>,
    ttl: i64,
) -> Result<Offer, Error> {
    intent.supported()?;
    if !(1..=600).contains(&ttl)
        || !(1..=64).contains(&host_label.len())
        || !host_label.as_bytes()[0].is_ascii_alphanumeric()
        || !host_label.as_bytes()[host_label.len() - 1].is_ascii_alphanumeric()
        || !host_label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" ._:-".contains(&b))
    {
        return Err(Error("invalid_offer"));
    }
    let provider_origin = provider_origin
        .map(str::to_owned)
        .or_else(config::single_provider_origin);
    if provider_origin
        .as_deref()
        .is_some_and(|value| !canonical_origin(value))
    {
        return Err(Error("invalid_offer"));
    }

    let key = PKey::generate_x25519().map_err(|_| KEY_ERROR)?;
    let created_at = push::now();
    if !(1..=MAX_JSON_INTEGER as i64 - ttl).contains(&created_at) {
        return Err(KEY_ERROR);
    }
    let offer = Offer {
        pairing_version: 1,
        session_id: push::uuid_v4().map_err(Error)?,
        intent,
        expires_at: created_at + ttl,
        host_label: host_label.to_owned(),
        provider_origin,
        vapid_public_key: vapid::get_vapid_pubkey().map_err(|_| KEY_ERROR)?.to_owned(),
        server_public_key: B64.encode(key.raw_public_key().map_err(|_| KEY_ERROR)?),
    };
    open_store()?
        .create_pairing(
            &offer.session_id,
            created_at,
            offer.expires_at,
            &serde_json::to_string(&offer).map_err(|_| KEY_ERROR)?,
            &key.raw_private_key().map_err(|_| KEY_ERROR)?,
        )
        .map_err(|e| Error(e.code()))?;
    Ok(offer)
}

pub(crate) fn status(id: &str, cancel: bool) -> Result<Value, Error> {
    if !canonical_uuid(id, true) {
        return Err(Error("invalid_session"));
    }
    let mut store = open_store()?;
    let status = if cancel {
        store.cancel_pairing(id)
    } else {
        store.pairing_status(id)
    }
    .map_err(|e| Error(e.code()))?;
    Ok(json!({
        "pairing_version": 1, "session_id": id, "expires_at": status.expires_at,
        "state": status.state
    }))
}

fn fixed_bytes<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    B64.decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(INVALID_REQUEST)
}

fn transcript(offer: &Offer, client: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let mut bytes = b"COLLIESOCKET-PAIRING\0".to_vec();
    bytes.push(offer.pairing_version);
    bytes.extend_from_slice(offer.session_id.as_bytes());
    bytes.push(match offer.intent {
        Intent::PairBridge => 1,
        Intent::AddReceiver => 2,
    });
    bytes.extend_from_slice(&offer.expires_at.to_be_bytes());
    for value in [
        offer.host_label.as_str(),
        offer.provider_origin.as_deref().unwrap_or(""),
    ] {
        let length = u16::try_from(value.len()).map_err(|_| KEY_ERROR)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&fixed_bytes::<65>(&offer.vapid_public_key)?);
    bytes.extend_from_slice(&fixed_bytes::<32>(&offer.server_public_key)?);
    bytes.extend_from_slice(client);
    Ok(bytes)
}

fn hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let key = PKey::hmac(key).map_err(|_| KEY_ERROR)?;
    Signer::new(MessageDigest::sha256(), &key)
        .and_then(|mut signer| signer.sign_oneshot_to_vec(data))
        .map_err(|_| KEY_ERROR)
}

fn shared_secret(private: &PKey<Private>, peer: &[u8; 32]) -> Result<Vec<u8>, Error> {
    // RFC 7748 decoders allow alternate encodings. The pairing format allows
    // one representation so the wire key and transcript identify one point.
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    if peer.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less {
        return Err(INVALID_ENVELOPE);
    }
    let peer = PKey::public_key_from_raw_bytes(peer, Id::X25519).map_err(|_| INVALID_ENVELOPE)?;
    let mut deriver = Deriver::new(private).map_err(|_| KEY_ERROR)?;
    deriver.set_peer(&peer).map_err(|_| INVALID_ENVELOPE)?;
    let result = deriver.derive_to_vec().map_err(|_| INVALID_ENVELOPE)?;
    if result.iter().all(|byte| *byte == 0) {
        return Err(INVALID_ENVELOPE);
    }
    Ok(result)
}

fn keys(shared: &[u8], transcript: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // RFC 5869 extract, then one SHA-256 block of expand for each direction.
    let prk = hmac(&sha256(transcript), shared)?;
    Ok((
        hmac(&prk, b"COLLIESOCKET-PAIRING-V1 request\x01")?,
        hmac(&prk, b"COLLIESOCKET-PAIRING-V1 receipt\x01")?,
    ))
}

fn seal_receipt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    request_nonce: &[u8; 12],
    request_sealed: &[u8],
    receipt: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if receipt.len() > 1024 {
        return Err(StoreError::StateUnavailable);
    }
    let mut receipt_aad = aad.to_vec();
    receipt_aad.extend_from_slice(&sha256(
        &[request_nonce.as_slice(), request_sealed].concat(),
    ));
    let mut tag = [0; 16];
    let mut sealed = encrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(nonce),
        &receipt_aad,
        receipt,
        &mut tag,
    )
    .map_err(|_| StoreError::StateUnavailable)?;
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

pub(crate) async fn submit(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(Error("input_too_large"));
    }
    // Serde's generated struct visitor also accepts a positional array.
    if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err(INVALID_REQUEST);
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|_| INVALID_REQUEST)?;
    if request.pairing_version != 1 {
        return Err(Error("unsupported_version"));
    }
    if !canonical_uuid(&request.session_id, true) {
        return Err(Error("invalid_session"));
    }
    let client = fixed_bytes::<32>(&request.client_public_key)?;
    let nonce = fixed_bytes::<12>(&request.nonce)?;
    let sealed = B64
        .decode(&request.ciphertext)
        .map_err(|_| INVALID_REQUEST)?;
    if !(17..=MAX_SEALED_BYTES).contains(&sealed.len()) {
        return Err(INVALID_REQUEST);
    }
    request.intent.supported()?;

    let (offer_json, private) = open_store()?
        .load_pairing(&request.session_id)
        .map_err(|e| Error(e.code()))?;
    let offer: Offer = serde_json::from_str(&offer_json).map_err(|_| KEY_ERROR)?;
    if offer.session_id != request.session_id || offer.intent != request.intent {
        return Err(INVALID_ENVELOPE);
    }
    if vapid::get_vapid_pubkey().map_err(|_| KEY_ERROR)? != offer.vapid_public_key {
        return Err(Error("invalid_session"));
    }
    let private = PKey::private_key_from_raw_bytes(&private, Id::X25519).map_err(|_| KEY_ERROR)?;
    let aad = transcript(&offer, &client).map_err(|_| KEY_ERROR)?;
    let shared = shared_secret(&private, &client)?;
    let (request_key, receipt_key) = keys(&shared, &aad)?;
    let cipher = Cipher::aes_256_gcm();
    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    let plaintext = decrypt_aead(cipher, &request_key, Some(&nonce), &aad, ciphertext, tag)
        .map_err(|_| INVALID_ENVELOPE)?;
    let shape: Value = serde_json::from_slice(&plaintext).map_err(|_| Error("invalid_json"))?;
    if !shape.get("subscription").is_some_and(Value::is_object) {
        return Err(Error("invalid_enrollment"));
    }
    // The shared typed parser still checks for duplicate and unknown members.
    let enrollment = enrollment::parse(&plaintext)?;
    if enrollment.enrollment_version != 3 {
        return Err(Error("unsupported_version"));
    }
    enrollment::authorize_account(&enrollment)?;
    if let Some(expected) = offer.provider_origin {
        let endpoint =
            Url::parse(&enrollment.subscription.endpoint).map_err(|_| Error("invalid_endpoint"))?;
        if endpoint.origin().ascii_serialization() != expected {
            return Err(Error("invalid_endpoint"));
        }
    }
    enrollment::authorize_destination(&enrollment).await?;

    let mut receipt_nonce = [0; 12];
    openssl::rand::rand_bytes(&mut receipt_nonce).map_err(|_| KEY_ERROR)?;
    let sealed_receipt = open_store()?
        .enroll_pairing(&request.session_id, &enrollment, |receipt, current| {
            let receipt =
                serde_json::to_vec(&enrollment::receipt_response(&enrollment, receipt, current))?;
            seal_receipt(
                &receipt_key,
                &receipt_nonce,
                &aad,
                &nonce,
                &sealed,
                &receipt,
            )
        })
        .map_err(|e| Error(e.code()))?;
    Ok(json!({
        "pairing_version": 1, "session_id": request.session_id, "intent": request.intent,
        "nonce": B64.encode(receipt_nonce), "ciphertext": B64.encode(sealed_receipt)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn opens_independent_request_and_seals_matching_receipt() {
        let vectors: Vec<Value> = serde_json::from_str(include_str!(
            "../contracts/pairing/v1/fixtures/sealed-vectors.json"
        ))
        .unwrap();
        assert_eq!(vectors.len(), 2);
        for vector in vectors {
            let offer: Offer = serde_json::from_value(vector["offer"].clone()).unwrap();
            let request: Request = serde_json::from_value(vector["request"].clone()).unwrap();
            let server = PKey::private_key_from_raw_bytes(
                &fixed_bytes::<32>(vector["server_private_key"].as_str().unwrap()).unwrap(),
                Id::X25519,
            )
            .unwrap();
            assert_eq!(
                B64.encode(server.raw_public_key().unwrap()),
                offer.server_public_key
            );
            let client_pub = fixed_bytes::<32>(&request.client_public_key).unwrap();
            let shared = shared_secret(&server, &client_pub).unwrap();
            assert_eq!(hex(&shared), vector["shared_secret_hex"]);
            let aad = transcript(&offer, &client_pub).unwrap();
            assert_eq!(hex(&aad), vector["transcript_hex"]);
            let (request_key, receipt_key) = keys(&shared, &aad).unwrap();
            assert_eq!(hex(&request_key), vector["request_key_hex"]);
            assert_eq!(hex(&receipt_key), vector["receipt_key_hex"]);

            let nonce = fixed_bytes::<12>(&request.nonce).unwrap();
            let sealed = B64.decode(request.ciphertext).unwrap();
            let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
            let decrypt = |key: &[u8], aad: &[u8]| {
                decrypt_aead(
                    Cipher::aes_256_gcm(),
                    key,
                    Some(&nonce),
                    aad,
                    ciphertext,
                    tag,
                )
            };
            let plaintext = decrypt(&request_key, &aad).unwrap();
            assert_eq!(
                plaintext,
                vector["enrollment_json"].as_str().unwrap().as_bytes()
            );
            assert_eq!(enrollment::parse(&plaintext).unwrap().enrollment_version, 3);
            let mut tampered = offer;
            tampered.host_label.push('X');
            let wrong_aad = transcript(&tampered, &client_pub).unwrap();
            let (wrong_key, _) = keys(&shared, &wrong_aad).unwrap();
            assert!(decrypt(&wrong_key, &wrong_aad).is_err());

            // These bytes come from the independent Python fixture verbatim.
            let response = &vector["response"];
            let receipt_nonce = fixed_bytes::<12>(response["nonce"].as_str().unwrap()).unwrap();
            let receipt = vector["receipt_json"].as_str().unwrap();
            let response_bytes = seal_receipt(
                &receipt_key,
                &receipt_nonce,
                &aad,
                &nonce,
                &sealed,
                receipt.as_bytes(),
            )
            .unwrap();
            assert_eq!(B64.encode(response_bytes), response["ciphertext"]);
        }
    }

    #[test]
    fn provider_origin_uses_one_ascii_spelling() {
        let cases: Vec<Value> = serde_json::from_str(include_str!(
            "../contracts/pairing/v1/fixtures/origin-cases.json"
        ))
        .unwrap();
        for case in cases {
            assert_eq!(
                canonical_origin(case["origin"].as_str().unwrap()),
                case["valid"].as_bool().unwrap(),
                "{}",
                case["name"].as_str().unwrap(),
            );
        }
    }

    #[test]
    fn rejects_noncanonical_coordinates_and_low_order_keys() {
        let server = PKey::generate_x25519().unwrap();
        let mut noncanonical = [0xff; 32];
        noncanonical[0] = 0xed;
        noncanonical[31] = 0x7f;
        for invalid in [[0; 32], noncanonical, [0xff; 32]] {
            assert_eq!(
                shared_secret(&server, &invalid).unwrap_err().0,
                "invalid_envelope"
            );
        }
        assert_eq!(
            Intent::AddReceiver.supported().unwrap_err().0,
            "unsupported_intent"
        );
    }
}
