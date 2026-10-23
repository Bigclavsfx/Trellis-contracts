# External evidence verification

The additive `shared::external_evidence` API authenticates imported audit bundles.
Existing bundle layouts and unsigned export/verification APIs are unchanged.
Contracts opt in by exposing admin-authorized wrappers for source registration and
import; legacy `verify_bundle` checks integrity only and must not authorize imports.

Register an Ed25519 public key per source with `configure_source`. Sign exactly
the 32 bytes returned by `signing_message`: SHA-256 of canonical XDR containing
the v1 domain, destination contract address, network ID, source, expiry ledger and complete
bundle. Metadata, record ordering and redaction settings are authenticated.
The signature itself is excluded. Import requires admin authorization and checks
bundle integrity, the 50-record limit, expiry (inclusive), and the registered key.
Invalid signatures abort the host transaction before any writes. An empty bundle
is valid, matching the existing export contract.

An exact authenticated retry returns false without a second import event.
Reusing a source/bundle ID with different signed content returns Conflict. Expired
or revoked signatures cannot be retried, even for a previously accepted bundle.
Use a fresh bundle ID and signature after expiry; do not overwrite audit history.
Register a new source key to rotate it, or pass None to revoke. Revocation blocks
future imports, not historical evidence; investigate accepted receipts separately.

Receipts are persistent and receive the standard shared TTL extension. Restore
archived receipts before retrying old IDs; operational tooling must preserve the
source/ID namespace and must not treat expiry/eviction as permission to replay
downstream effects. This API records authenticated ingestion only: consumers must
tie any downstream mutations to the same atomic invocation and receipt result.
Rollback by disabling the integrating entry point or revoking the source; preserve
receipts and exported events. No existing storage migration is required.

Verification: `cargo test -p shared --lib external_evidence`.

The repository's shared crate currently has an unrelated malformed export block
in its root module. Until that is repaired separately, run the production-module
verification harness instead:

```
cargo test --manifest-path scripts/issue-verification/Cargo.toml external_evidence
```

The harness imports the real production sources by path; it does not substitute
mock implementations of authorization, storage, hashing, or signature checking.
