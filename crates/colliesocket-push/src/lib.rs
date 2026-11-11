//! Sender-only RFC 8291 encryption. HTTP policy and VAPID are separate.
//!
//! Untrusted keys are validated before entering the dependency. No receiver or
//! deterministic production encryption API is provided.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::fmt;
use web_push_native::{p256::PublicKey, Auth};

pub const MAX_BODY_BYTES: usize = 4096;
/// Body budget minus 86-byte header, one delimiter, and 16-byte GCM tag.
pub const MAX_PLAINTEXT_BYTES: usize = 3993;
/// Application JSON limit before adding trailing ASCII spaces.
pub const MAX_JSON_BYTES: usize = 3072;
pub const RECORD_SIZE: u32 = 4096;

/// Fixed error categories never include supplied keys or payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPublicKeyEncoding,
    InvalidPublicKeyLength,
    InvalidPublicKey,
    InvalidAuthEncoding,
    InvalidAuthLength,
    PayloadTooLarge,
    EncryptionFailed,
}

impl Error {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidPublicKeyEncoding => "invalid_p256dh_encoding",
            Self::InvalidPublicKeyLength => "invalid_p256dh_length",
            Self::InvalidPublicKey => "invalid_p256dh",
            Self::InvalidAuthEncoding => "invalid_auth_encoding",
            Self::InvalidAuthLength => "invalid_auth_length",
            Self::PayloadTooLarge => "payload_too_large",
            Self::EncryptionFailed => "encryption_failed",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for Error {}

/// Validated public receiver point and confidential authentication secret.
/// No Serialize or raw-key accessor is provided. Debug is always redacted.
#[derive(Clone)]
pub struct SubscriptionKeys {
    public_key: PublicKey,
    auth: Auth,
}

impl fmt::Debug for SubscriptionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SubscriptionKeys([REDACTED])")
    }
}

fn decode_canonical(
    value: &str,
    encoded_len: usize,
    length_error: Error,
    encoding_error: Error,
) -> Result<Vec<u8>, Error> {
    if value.len() != encoded_len {
        return Err(length_error);
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| encoding_error)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(encoding_error);
    }
    Ok(bytes)
}

impl SubscriptionKeys {
    /// Accept only canonical unpadded base64url, a 65-byte uncompressed on-curve
    /// P-256 public point, and a 16-byte confidential auth secret.
    pub fn from_base64url(p256dh: &str, auth: &str) -> Result<Self, Error> {
        let public_bytes = decode_canonical(
            p256dh,
            87,
            Error::InvalidPublicKeyLength,
            Error::InvalidPublicKeyEncoding,
        )?;
        if public_bytes.len() != 65 {
            return Err(Error::InvalidPublicKeyLength);
        }
        if public_bytes[0] != 4 {
            return Err(Error::InvalidPublicKey);
        }
        let public_key =
            PublicKey::from_sec1_bytes(&public_bytes).map_err(|_| Error::InvalidPublicKey)?;
        let auth_bytes = decode_canonical(
            auth,
            22,
            Error::InvalidAuthLength,
            Error::InvalidAuthEncoding,
        )?;
        let auth_array: [u8; 16] = auth_bytes
            .try_into()
            .map_err(|_| Error::InvalidAuthLength)?;
        Ok(Self {
            public_key,
            auth: Auth::from(auth_array),
        })
    }

    /// Low-level one-record encryption with fresh OS salt and ephemeral key.
    /// Application events must call encrypt_padded instead. The return value is
    /// the actual HTTP binary body, not a JSON/base64 envelope.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(Error::PayloadTooLarge);
        }
        let mut body = web_push_native::encrypt(plaintext.to_vec(), &self.public_key, &self.auth)
            .map_err(|_| Error::EncryptionFailed)?;
        if body.len() != plaintext.len() + 103
            || body.len() > MAX_BODY_BYTES
            || body[20] != 65
            || body[21] != 4
        {
            return Err(Error::EncryptionFailed);
        }
        // Native 0.5.0 emits rs equal to the record length. RFC 8291 section 4
        // requires a strictly larger rs. This standard header is not AEAD AAD;
        // normalizing rs changes no ciphertext and preserves standard framing.
        body[16..20].copy_from_slice(&RECORD_SIZE.to_be_bytes());
        Ok(body)
    }

    /// Pad application JSON to 3993 plaintext bytes, yielding a 4096-byte body.
    /// The caller validates/serializes JSON; trailing ASCII spaces are legal JSON
    /// whitespace inside authenticated ciphertext. They are not custom framing.
    pub fn encrypt_padded(&self, json: &[u8]) -> Result<Vec<u8>, Error> {
        if json.len() > MAX_JSON_BYTES {
            return Err(Error::PayloadTooLarge);
        }
        let mut padded = Vec::with_capacity(MAX_PLAINTEXT_BYTES);
        padded.extend_from_slice(json);
        padded.resize(MAX_PLAINTEXT_BYTES, b' ');
        self.encrypt(&padded)
    }
}
