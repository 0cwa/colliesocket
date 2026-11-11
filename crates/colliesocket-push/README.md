# CollieSocket RFC 8291 sender slice

This standalone crate produces real encrypted binary Web Push bodies. It does
not send HTTP requests, implement a UnifiedPush connector, or establish VAPID
authentication. Integrating callers retain their allowed-destination transport,
SSRF checks, explicit private-origin allowances, disabled redirects, and
separate VAPID handling.

## Application interface

```rust
let keys = colliesocket_push::SubscriptionKeys::from_base64url(&p256dh, &auth)?;
let binary_body = keys.encrypt_padded(&serialized_event_json)?;
```

`encrypt_padded` accepts at most 3072 JSON bytes, adds trailing ASCII spaces to
3993 bytes, and encrypts to exactly 4096 bytes. The caller is responsible for
validating/serializing the application event. JSON whitespace is inside the
ciphertext; RFC 8291 framing remains standard. Test/status events use the same
path. The lower-level `encrypt` method permits up to 3993 bytes and is intended
for unpadded protocol checks, not production application events.

`p256dh` must be canonical unpadded base64url decoding to an on-curve,
uncompressed 65-byte P-256 point. `auth` must decode to exactly 16 bytes and is
confidential. Error categories contain no input values; key Debug output is
redacted. Production encryption uses the pinned sender's OS-generated random
salt and ephemeral key on every invocation. Fixed salt/keys exist only in the
test/example helper and are public RFC material, never a production option.

## Reviewed dependency boundary

The exact sender dependency is `web-push-native = 0.5.0`, default features off.
Its release source is [6b0a3f10377af3c9401a7c1a60b1e34d41155c5d][sender]. Its
default serialization and VAPID features are deliberately unused. `Cargo.lock`
freezes the full resolved graph. The crate's declared minimum Rust version is
1.87; reproduction uses the toolchain recorded in the fresh execution evidence.

The pinned sender emits `rs = plaintext_length + 17`. RFC 8291 section 4 requires
a strictly greater record-size field. The wrapper normalizes bytes 16–19 to
big-endian 4096. `rs` is not AEAD associated data, so this changes no ciphertext.
The largest record is 4010 bytes within the complete 4096-byte body budget.

Upstream's `Auth::clone_from_slice` convenience JSON path can panic on an invalid
length. This wrapper validates lengths before constructing Auth and does not
deserialize upstream WebPushBuilder. The pinned ECE decryptor also lacks strict
validation for every final delimiter and zero record size. It is not used here
as an untrusted receiver or the independent verification oracle. This focused
review is not a security audit or shipping approval.

The deterministic test helper adapts upstream's private helper, retaining
attribution and `LICENSE-web-push-native-MIT`. It uses RustCrypto P-256/HKDF and
`ece-native`; it implements no cryptographic primitives.

## Reproduction

From the repository root with Rust and Python installed:

```sh
python3 -m pip install -r crates/colliesocket-push/tools/requirements.txt
sh crates/colliesocket-push/tools/conformance.sh
```

The script checks Rust tests and committed fixtures, regenerates into a private
temporary directory, compares deterministic bytes, and independently decrypts
fresh random production-sender output. It preserves committed fixtures. With
dependencies cached, set `CARGO_NET_OFFLINE=true` for offline Cargo execution.

To generate fresh evidence separately:

```sh
cargo run --locked --manifest-path crates/colliesocket-push/Cargo.toml \
  --example generate_fixtures -- /tmp/colliesocket-fixture-check
python3 crates/colliesocket-push/tools/check_fixtures.py /tmp/colliesocket-fixture-check
```

`fixtures/metadata.json` identifies public test keys and hashes. The published
RFC 8291 vector is reproduced byte for byte. Its decoded body is **144 bytes**
(41 plaintext + 86 header + 1 delimiter + 16 tag), despite the example's HTTP
Content-Length saying 145. Tests compare the actual published ciphertext.
`wake-v1.bin` is deterministic. `sender-random.bin` uses the actual production
API and intentionally varies on regeneration. Event timestamps are historical
synthetic values: event validation requires the fixture clock, not current time.

The independent checker uses Python HMAC and cryptography/OpenSSL P-256 and
AES-GCM, distinct from the sender's RustCrypto primitives. It reproduces
deterministic ciphertext, decrypts actual random Rust output, checks RFC
intermediate values, and rejects malformed/tampered/wrong-key inputs. This is
independent primitive-stack and framing evidence; it is not a same-library
roundtrip or Android interoperability. Android, lock behavior, real distributor,
production enrollment, and security acceptance remain separate gates.

Fresh executed results and dependency provenance are in `evidence/`. They are
from this reconstructed workspace; unavailable historical commits or prior
execution records are not claimed as recovered evidence.

[sender]: https://github.com/leotaku/web-push-native/blob/6b0a3f10377af3c9401a7c1a60b1e34d41155c5d/web_push/src/lib.rs

Standards: [RFC 8291](https://www.rfc-editor.org/rfc/rfc8291),
[RFC 8188](https://www.rfc-editor.org/rfc/rfc8188).
