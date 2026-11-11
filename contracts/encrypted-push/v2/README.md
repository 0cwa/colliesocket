# CollieSocket enrollment v2

V2 lets a phone rotate its encrypted push subscription through the existing
Signal connection, including when CollieSocket runs behind NAT. Initial
enrollment and changes to private identity/control credentials still use the
protected import. [The normative protocol](protocol.md) defines the exact
AES-GCM control format, the additive migration from frozen v1, and receipt-based
confirmation.

| File | Purpose |
| --- | --- |
| `protocol.md` | Wire bytes, authentication, epochs, retries, confirmation and migration |
| `enrollment.schema.json` | Protected v2 import, with optional control key |
| `control.schema.json` | Exact decrypted control plaintext |
| `event.schema.json` | Version-2 push event and bounded status codes |
| `response.schema.json` | V2 private-import receipt |
| `fixtures/` | Public synthetic import/event examples and deterministic crypto vector |
| `tools/conformance.py` | Independent offline schema, crypto and rejection checks |

Run from the repository root:

```sh
python3 contracts/encrypted-push/v2/tools/conformance.py
```

The checker uses the dependencies already listed in
`../v1/tools/requirements.txt`. Its synthetic fixture proves byte-level
interoperability independently of Rust; it does not establish Android device
delivery, keystore behavior or live Signal acceptance. Server websocket and
durability integration tests are separate. All fixture keys are public test
data and MUST NOT be used for a real enrollment.

V1 remains frozen and continues to work without a control key. Consumers must
adopt the new contract deliberately; pin the reviewed repository commit for
cross-repository use.
