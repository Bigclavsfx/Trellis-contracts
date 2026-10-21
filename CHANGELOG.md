# Changelog

All notable changes to the Trellis Contracts repository are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `shared::client_validation`: Request validation for cross-repo Trellis clients — schema-version compatibility gate, field/semantic checks reusing `shared::semantic`, caller-identity authorization (donor/depositor/seller must match the authenticated caller), and a generic `fingerprint_request` plus `begin_idempotent_request`/`complete_idempotent_request` retry wrapper around `shared::idempotency` (#336); see `docs/CLIENT_REQUEST_VALIDATION.md`
- `shared::event_dead_letter`: Dead-letter recovery for failed domain-event handlers — `dispatch_event` captures a handler failure instead of propagating it, `retry_dead_letter` is a permissionless backoff-gated retry of a due letter, and `requeue_dead_letter`/`discard_dead_letter` are the admin-gated recovery/rollback path for an exhausted letter; reuses `shared::jobs::RetryPolicy` and `is_retryable_error` directly (#335); see `docs/EVENT_DEAD_LETTER.md`
- `shared::health_guard`: Authorized dependency health-check reporting and a retry/circuit-breaker budget around degraded-mode fallback execution — admin-managed reporter registry gating `shared::degradation::record_dependency_check`, and `execute_guarded` (wrapping `execute_with_fallback`) that trips `DegradationError::CircuitBreakerOpen` after a configurable number of fallback attempts inside a rolling window, with admin reset and half-open cooldown recovery (#334); see `docs/DEPENDENCY_HEALTH_GUARD.md`
- `shared::snapshot`: Signed, hash-chained state snapshot export for audit and debugging — admin-managed Ed25519 signer registry, per-module chained `capture_snapshot`, full on-chain `verify_chain` re-derivation, and a bounded, storage-free-verifiable `export_snapshots`/`verify_export` bundle (#301); see `docs/STATE_SNAPSHOT_EXPORT.md`
- `shared::workflow_correlation`: shared correlation-ID policy for multi-contract workflows (1–64 bytes of ASCII letters, digits, `-`, `_`) with a chain check that requires every step of a workflow to carry the same ID; retries reuse the ID (#330); see `docs/WORKFLOW_CORRELATION.md`
- `shared::migration::dry_run_cross_contract`: preview a migration across several contracts in one batch, reporting batch validity, totals across valid plans, approval requirements, and duplicate contracts, before any write (#332); see `docs/MIGRATION_SAFETY.md`
- `shared::release_readiness::verify_initialized_addresses`: smoke-test gate check that fails when any initialized address is unset or the list is empty (#331); see `docs/RELEASE_READINESS.md`
- Permission matrix tests for `contracts/access-control` covering every privileged entrypoint with an unauthorized caller, asserting `NotAdmin`, `RoleEscalation`, or `Unauthorized` and that refused calls leave state unchanged (#333)
- `shared::policy_preview`: Policy simulation preview framework for previewing affected records and users, expected operational side effects, and rollback constraints before committing irreversible or high-impact changes across Treasury, Aid, Referral, Governance, Oracle, and Marketplace modules (#250); see `docs/POLICY_SIMULATION_PREVIEW.md`
- `shared::degradation`: External dependency degradation matrix with failure mode classification, tiered degradation levels (`Nominal`, `DegradedMinor`, `DegradedMajor`, `CriticalFailure`), user-safe fallback behavior (`FallbackStrategy`, `FallbackDecision`), automated checks, and recovery receipts across Treasury, Aid, Referral, Governance, Oracle, and Marketplace modules (#231); see `docs/EXTERNAL_DEPENDENCY_DEGRADATION_MATRIX.md`
- `shared::export`: Permission-aware export pipeline with bounded memory chunking, in-flight cancellation, multi-module role authorization (Treasury, Aid, Referral, Governance, Oracle, Marketplace), forbidden field purging, and cumulative SHA-256 stream digests; see `docs/EXPORT_PIPELINE.md`
- `shared::audit_ledger`: an append-only, hash-chained ledger for privileged and financial events (roles, config, upgrades, pause/unpause, treasury/aid/escrow/referral/governance/oracle/marketplace value movement) with on-chain `verify_chain`, permissioned bounded `export_ledger`, storage-free `verify_export`, a publishable head-checkpoint event, and tamper-detection tests (#233); see `docs/AUDIT_LEDGER.md`
- `shared::operational_metadata`: Data minimization review and retention enforcement for operational metadata across Treasury, Aid, Referral, Governance, Oracle, and Marketplace modules with classification, redundant field pruning, two-phase testable deletion, hold management, and migration adapters (#229); see `docs/OPERATIONAL_METADATA_RETENTION.md`
- Two-step ownership transfer with pending acceptance and expiry in `shared::auth` and `contracts/access-control`, requiring explicit cryptographic acceptance by the target owner, supporting automatic expiry rejection, and allowing cancellation before acceptance (#150); see `docs/ACCESS_CONTROL.md`
- `shared::lifecycle_events`: a canonical, versioned event envelope (`("lifecycle", resource, transition)` with schema version, resource ID, from/to state, actor, and timestamp) for every lifecycle transition, plus an ordered-sequence assertion harness (`testing::lifecycle_events`) that fails tests when an expected event is missing or reordered (#144); see `docs/LIFECYCLE_EVENTS.md`
- `shared::disclosure`: progressive disclosure of transaction detail fields, where a `Critical`-severity field can never end up reachable only through the advanced/expanded view (#125)
- Machine-readable changelog (`changelog/entries.json` + `changelog/schema.json`) for protocol-facing changes, validated in CI (#126); see `docs/CHANGELOG_SCHEMA.md`
- Fault-injection test suite (`testing/src/fault_injection.rs`) exercising the sandbox's fake oracle/token/RPC adapters for hard failures, staleness, insufficient balance, and submission timeouts, proving each fails actionably with no partial state (#127)
- PR checklist enforcement (`scripts/check-pr-checklist.cjs`, new `release-readiness.yml` workflow) so an incomplete `.github/PULL_REQUEST_TEMPLATE.md` checklist fails CI instead of only reviewer attention; documented in `docs/RELEASE_READINESS.md` (#128)
- Cross-contract integration test suite covering full aid lifecycle, expiry flows, authorization boundaries, partial failure recovery, and referral commission distribution
- WASM size budget check in CI with per-contract limits and PR comments showing size deltas
- Automated API documentation publishing to GitHub Pages on every merge to main
- Improved crate-level rustdoc for all core contracts (aid, treasury, referral, oracle, registry)
- Landing page for API documentation explaining contract relationships and navigation

### Changed
- Enhanced rustdoc crate-level documentation with usage examples and cross-references
- Updated CI workflow to include WASM size measurement step

### Fixed
- Restored `shared/src/lib.rs`, which was truncated mid-file with a malformed `no_std` attribute, invalid module declarations, and duplicate re-exports, so the `shared` crate (and everything depending on it) could not compile. The module list and re-exports were reconstructed from the last intact revision plus the newer `release_readiness` module, and several latent compile errors in `shared` (over-long `symbol_short!` values, unencodable `Option<user-defined type>` contract fields, missing imports, duplicate `ensure_supported_version`/`is_supported_version` re-exports) were corrected without changing public behavior.
- `shared`'s `health`, `reconciliation`, and `telemetry` modules were re-exported (`pub use health::{...}` etc.) without a matching `mod` declaration in `shared/src/lib.rs` — an unresolved-module compile error for the whole workspace. Added the three missing `pub mod` declarations.

---

## [0.1.0] - 2024-09-24

### Added
- **Initial Release**: Complete Soroban smart contract suite for humanitarian aid distribution
- **Core Contracts**:
  - `aid-contract`: Direct aid settlement, escrow, and claim management
  - `treasury-contract`: Protocol treasury management with per-category balances and withdrawal limits
  - `referral-contract`: Multi-tier referral network with commission accrual and distribution
  - `governance-contract`: Multi-signature governance for role management and protocol upgrades
  - `oracle-contract`: Off-chain data integration and verification bridge
  - `registry-contract`: Central contract discovery and version tracking
  - `payments-contract`: Token transfer and payment settlement layer
  - `rebalancer-contract`: Liquidity rebalancing and reserve management
  - `nft-marketplace`: NFT minting, trading, and marketplace functionality
  - `access-control`: Role-based access control primitives
  - `upgradeability`: Centralized upgrade registry and coordinator

- **Shared Library**:
  - Error codes and event schemas
  - Storage helpers and authorization patterns
  - Batch transfer primitives for atomic multi-recipient payments
  - Persistent storage optimization (`persistent_read` for TTL-free reads)

- **Testing Infrastructure**:
  - Comprehensive test harness with mocks and helpers
  - Gas optimization benchmarking suite
  - Fuzzing harnesses for critical modules
  - Simulation tools for multi-user protocol activity

- **CI/CD**:
  - GitHub Actions workflows for build, clippy, test, and format checks
  - Automated test execution on push and pull requests

- **Documentation**:
  - GAS_OPTIMIZATION.md: Complete gas optimization guide with identified hotspots and benchmarks
  - UPGRADEABILITY.md: System-wide upgrade registry and coordinator documentation
  - Per-contract README files explaining module responsibilities and interfaces
  - CODE_OF_CONDUCT.md and contribution guidelines

- **Deployment Scripts**:
  - `scripts/deploy.sh`: Multi-contract deployment to testnet/mainnet
  - `scripts/initialize.sh`: Contract initialization utilities
  - `scripts/upgrade.sh`: Upgrade execution and management
  - `scripts/verify.sh`: Deployment verification tools
  - `scripts/register_upgradeable.sh`: Contract registration for upgrade system

### Key Features
- **Security**: Reentrancy protection, signature verification, overflow-safe arithmetic, access control, replay protection
- **Efficiency**: Gas optimizations for storage reads, validation ordering, event batching
- **Auditability**: Transparent transaction records, immutable event logs, comprehensive state tracking
- **Upgradeability**: Centralized upgrade registry with version tracking and history
- **Modularity**: Independent contracts with clear interfaces and cross-contract integration
- **Production Ready**: Comprehensive error handling, edge case coverage, extensive testing

### Architecture
- Modular contract design with separation of concerns
- Shared library for common patterns and utilities
- Central registry for contract discovery and upgrade management
- Multi-signature governance for protocol changes
- Role-based access control across all contracts

### Testing Coverage
- Unit tests for all contract functions
- Integration tests for cross-contract flows
- Gas benchmarking tests for optimization verification
- Fuzzing tests for critical security-sensitive operations
- Simulation harnesses for multi-user scenarios

---

## Versioning Strategy

The Trellis Contracts project uses a hybrid versioning approach:

### Repository Version
- Follows Semantic Versioning (MAJOR.MINOR.PATCH)
- Incremented when contract suite interfaces or behaviors change significantly
- Used for releases and documentation

### Individual Contract Versions
- Each contract tracks its own version in the upgradeability registry
- Allows independent contract updates without forcing suite-wide version bumps
- Critical for the on-chain upgrade system where contract identity is preserved across versions

See [UPGRADEABILITY.md](./UPGRADEABILITY.md) for details on the on-chain upgrade registry and version tracking.

---

## How to Contribute

When adding changes, update this CHANGELOG by:
1. Adding entries to the `[Unreleased]` section
2. Following the existing format (Added, Changed, Deprecated, Removed, Fixed, Security)
3. Keeping entries concise and user-focused
4. When preparing a release, rename `[Unreleased]` to a dated version section

See [CONTRIBUTING.md](./CONTRIBUTING.md) for full contribution guidelines.
