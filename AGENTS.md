# CollieSocket agent notes

- Downstream of MollySocket. Keep the `mollysocket` executable name, `MOLLY_` configuration and upstream attribution.
- `contracts/encrypted-push/v1` is frozen, and other repos pin it by commit. A behaviour change goes in a new contract version with a migration note.
- Keep these protections when changing send or enrollment code: address and redirect checks in `src/utils/post_allowed.rs`, no plaintext fallback for encrypted enrollments, no secrets in logs.
- A provider 2xx means the provider accepted the message, not that a device received it.
- Keep PRs to one concern. Test logs and result records go in the PR description, not the diff. `handoff/`, `evidence/` and `provenance/` are historical records, so don't add to them.
- Checks: `cargo test --locked`; `python3 tests/server_cli.py` after `cargo build --locked`; `python3 contracts/encrypted-push/v1/tools/conformance.py`; `python3 crates/colliesocket-push/tools/check_fixtures.py contracts/encrypted-push/v1/fixtures/crypto`. A test run that collected 0 tests failed.
- This repo is public. Name only projects with a public repo, or Collie Pack, and describe anything else generically ("the push provider", "the distributor"). The suite plan is `docs/SPEC.md` in the private `0cwa/collie-pack`.
