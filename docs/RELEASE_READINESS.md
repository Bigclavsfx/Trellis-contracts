# Release Readiness Gate Framework (Issues #128 & #253)

Critical Trellis changes — anything touching an on-chain interface, storage layout, emitted event,
or multi-contract integration across **Treasury, Aid, Referral, Governance, Oracle, and Marketplace** —
must pass a strict release readiness gate before merge or deployment promotion.

The readiness gate combines:
1. **Repository & CI Gates**: Automated checks in `.github/workflows/ci.yml` and `.github/workflows/release-readiness.yml`.
2. **Executable Gate Tool**: [`scripts/release-readiness-gate.cjs`](../scripts/release-readiness-gate.cjs) verifying repository integrity, changelog schemas, audit allowlists, and deployment readiness.
3. **On-Chain & SDK Verification**: [`shared::release_readiness`](../shared/src/release_readiness.rs) providing Soroban-level manifest evaluation and automated rollback rehearsal simulation.
4. **Pull Request Checklist**: PR body gate in [`.github/PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md) enforced mechanically by [`scripts/check-pr-checklist.cjs`](../scripts/check-pr-checklist.cjs).

---

## 1. The Four Mandatory Release Gates

Every production release or protocol upgrade must satisfy all four gate pillars across all impacted modules:

| Gate Pillar | Purpose & Verification Scope | Enforcing Tool / Script |
|---|---|---|
| **1. Migrations Gate** | Verifies storage schema compatibility, non-destructive migration steps, dry-run simulation, and changelog migration notes. | `scripts/release-readiness-gate.cjs`, `scripts/validate-changelog.cjs`, `shared::migration` |
| **2. Security Gate** | Verifies `cargo audit` cleanly passes, no allowlist entries are expired, invariant tests hold, and role separation (Admin vs Upgrader) is respected. | `./scripts/security/run-audit.sh`, `security/audit-allowlist.toml`, `shared::invariants` |
| **3. Smoke Tests Gate** | Verifies post-deploy cross-contract wiring (Aid ↔ Treasury, Treasury ↔ Referral, Registry) and getter liveness via zero-value read-only simulation. | `scripts/verify-deployment.sh`, `scripts/verify-deployment.cjs` |
| **4. Rollback Rehearsal Gate** | Verifies rollback plan documentation, pre-upgrade snapshot capture, and dry-run rehearsal proving state integrity upon revert. | `shared::release_readiness::rehearse_rollback`, `UPGRADEABILITY.md`, `docs/RUNBOOK.md` |

---

## 2. Module Scoping

The readiness gate enforces checks across all six core Trellis protocol modules:

| Module | Core Responsibility | Critical Invariants & Smoke Getters |
|---|---|---|
| **Treasury** (`contracts/treasury-contract`) | Multi-asset reserves, category balances, emergency controls. | `TreasuryContract::referral_contract`, category reserve invariants. |
| **Aid** (`contracts/aid-contract`) | Donor allocations, milestone tranches, pull-based claims. | `AidContract::get_treasury`, total allocated $\le$ balance. |
| **Referral** (`contracts/referral-contract`) | Affiliate tracking, multi-tier commission accrual. | `ReferralContract::get_treasury`, commission basis-point bounds. |
| **Governance** (`contracts/governance-contract`) | Proposal lifecycle, multi-sig approvals, timelocks. | `GovernanceContract::get_admin`, `get_proposal`. |
| **Oracle** (`contracts/oracle-contract`) | Price feed aggregation, submitter staking, quorum. | `OracleContract::get_latest_price`, median quorum rules. |
| **Marketplace** (`contracts/nft-marketplace`) | NFT listings, auctions, pull-based refund escrow. | `MarketplaceContract::get_admin`, pull refund reserves. |

---

## 3. The PR Checklist

Defined in [`.github/PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md) and checked on every open, edit, or synchronize event:

### 3.1 Checklist Sections Enforced by CI
1. `## Type of Change`: At least one change type selected.
2. `## Checklist`: All base CI requirements checked:
   - `cargo build --release` succeeds
   - Tests added or updated, and `cargo test --workspace` passes
   - `cargo fmt --all -- --check` is clean
   - `cargo clippy --workspace -- -D warnings` is clean
   - `./scripts/security/run-audit.sh --skip-wasm` passes
   - Docs updated where behaviour changed
3. `## On-chain Interface`:
   - No emitted event topic or payload changed (or migration note added)
   - No storage layout change (or migration plan described)
4. `## Release Readiness Gate` (Issue #253):
   - **Migrations**: Storage schema dry-run and compatibility verified (`docs/MIGRATION_SAFETY.md`)
   - **Security**: Security audit and invariant checks passed (`scripts/security/run-audit.sh`, `docs/SECURITY_INVARIANTS.md`)
   - **Smoke tests**: Cross-contract wiring and getter liveness verified (`scripts/verify-deployment.sh` / `scripts/verify-deployment.cjs`)
   - **Rollback rehearsal**: Rollback rehearsal passed and recovery steps documented (`docs/RUNBOOK.md`, `docs/RELEASE_READINESS.md`)

---

## 4. Executable Rollback Rehearsal Framework

Soroban upgrades replace WASM bytecode while retaining instance and persistent storage. To ensure an upgrade does not corrupt existing data or leave contracts irrecoverable, maintainers must execute a **Rollback Rehearsal** before mainnet execution.

### 4.1 Rehearsal Flow
```text
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ Current State   │ ──1──►│ Upgrade & State │ ──2──►│ Simulated Error │
│ (Version N)     │       │ Migration (N+1) │       │ / Invariant Reg │
└─────────────────┘       └─────────────────┘       └─────────────────┘
                                                             │ 3
                                                             ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ Auditable       │◄──5───│ State & Schema  │◄──4───│ Execute Rollback│
│ Rehearsal Receipt│      │ Integrity Check │       │ to Version N    │
└─────────────────┘       └─────────────────┘       └─────────────────┘
```

1. **Snapshot**: Capture baseline record keys and state roots.
2. **Simulate Upgrade**: Execute schema migration via [`shared::migration::dry_run`].
3. **Inject Fault**: Trigger simulated post-upgrade invariant validation failure.
4. **Execute Rollback**: Revert WASM reference and version to previous known-good baseline.
5. **Verify State**: Confirm all sample records, indexes, and balances remain readable and valid.
6. **Receipt**: Emit structured event and store [`RollbackRehearsalReceipt`].

### 4.2 Programmatic Usage (`shared::release_readiness`)
```rust
use shared::release_readiness::{rehearse_rollback, ReleaseModule, RollbackRehearsalParams};
use shared::migration::RollbackStrategy;

let params = RollbackRehearsalParams {
    module: ReleaseModule::Aid,
    current_version: 1,
    target_version: 2,
    previous_wasm_hash: known_good_wasm_hash,
    strategy: RollbackStrategy::Revert,
    simulate_regression: true,
};

let receipt = rehearse_rollback(&env, &params)?;
assert!(receipt.passed);
assert!(receipt.state_intact);
assert_eq!(receipt.restored_version, 1);
```

---

## 5. Operational Edge Cases & Failure Modes

### 5.1 Edge Cases
- **Mid-Migration Interruption**: Network dropped or gas exceeded during multi-step migration.
  - *Mitigation*: The `MigrationJournal` records `resume_index`. Recovery continues deterministically from the last completed step without re-executing completed side-effects.
- **Expired Security Allowlist Entry**: An advisory allowlist entry in `security/audit-allowlist.toml` expired while a PR was pending review.
  - *Mitigation*: `release-readiness-gate.cjs` fails fast. Renew the allowlist with updated upstream review, or patch the dependency.
- **Backward-Incompatible Schema Deserialization**: New bytecode expects additional fields that do not exist in pre-existing persistent storage keys.
  - *Mitigation*: Pre-flight dry-run in `UpgradeabilityContract::propose_upgrade` triggers `validate_storage` on the migration hook, rejecting the proposal with `StorageIncompatible (909)` before execution.
- **Unintended Deployment Pause**: Contract deployed with pause bit set, blocking user interactions.
  - *Mitigation*: Smoke test gate verifies zero-value read-only simulation; fails if `ContractPaused (5)` is returned unintentionally.

### 5.2 Failure Modes & Triage Matrix

| Failure Mode | Root Cause | Operator Response |
|---|---|---|
| `MissingMigrationVerification (971)` | PR or release manifest lacks dry-run migration verification. | Run `shared::migration::dry_run` and document migration notes. |
| `MissingSecurityCheck (972)` | Security audit unperformed or allowlist entry expired. | Run `./scripts/security/run-audit.sh` and update `security/audit-allowlist.toml`. |
| `MissingSmokeTest (973)` | Deployment wiring unverified on target network. | Execute `node scripts/verify-deployment.cjs <network>`. |
| `MissingRollbackRehearsal (974)` | No rollback rehearsal conducted for target module. | Run `rehearse_rollback` in testing environment and record receipt. |
| `GateCheckFailed (970)` | One or more gate checks explicitly failed. | Inspect failing check output, fix underlying issue, and re-run gate. |

---

## 6. Rollback and Recovery Steps

If a production upgrade encounters post-deployment anomalies:

1. **Pause Contract State** (§3.6 in [`RUNBOOK.md`](./RUNBOOK.md)):
   ```bash
   soroban contract invoke --id "$CONTRACT_ID" --network "$NETWORK" \
     --source-account "$ADMIN_IDENTITY" -- set_paused --paused true
   ```
2. **Retrieve Known-Good WASM Hash**:
   Look up the previous version WASM hash from `DEPLOYMENTS.md` or upgrade history:
   ```bash
   soroban contract invoke --id "$UPGRADEABILITY_REGISTRY_ID" --network "$NETWORK" \
     -- get_rollback_info --contract_id "$CONTRACT_ID"
   ```
3. **Execute Rollback Upgrade**:
   Propose and execute the rollback upgrade through the coordinator:
   ```bash
   ./scripts/upgrade.sh "$UPGRADEABILITY_REGISTRY_ID" "$CONTRACT_ID" \
     "$KNOWN_GOOD_WASM_PATH" "$PREVIOUS_VERSION" "emergency rollback"
   ```
4. **Execute Post-Rollback Restore Validation**:
   ```bash
   ./scripts/validate-restore.sh
   node scripts/verify-deployment.cjs "$NETWORK"
   ```
5. **Unpause and Resume Operations**:
   Unpause only after all smoke tests pass and verify state consistency.

---

## 7. Emergency Fixes and Bypass Procedures

In an active high-severity incident (e.g. fund-freeze transaction or critical vulnerability remediation), an emergency fix may need to merge before all checklist items can be completed.

Add the documented exception marker to the PR body:

```markdown
<!-- release-readiness-exception: <Incident ID, emergency rationale, and approving tech lead> -->
```

- `check-pr-checklist.cjs` and `release-readiness-gate.cjs` acknowledge the exception and report it in CI logs instead of blocking the build.
- The bypass is recorded permanently in the git and CI history.
- Post-incident, a follow-up PR must be opened to complete deferred tests, audits, and rollback rehearsals.

---

## 8. CLI Tooling & Local Verification

Run the release readiness gate locally:

```bash
# Run all repository readiness gates
node scripts/release-readiness-gate.cjs --check-all

# Verify PR body markdown file
node scripts/release-readiness-gate.cjs --body-file my-pr-body.md

# Verify single module readiness
node scripts/release-readiness-gate.cjs --module treasury

# Validate changelog and schema
node scripts/validate-changelog.cjs
```

---

## 9. Initialized Address Coverage (Issue #331)

The smoke-test gate must cover **every** address a deployment initializes (for
example Aid → Treasury, Treasury → Referral). `shared::release_readiness::verify_initialized_addresses`
takes one `InitializedAddress` per expected wiring, where `address` is the
value read back from the deployed contract.

- Any entry whose `address` is `None` fails the gate with `MissingSmokeTest`.
- An empty list also fails. A gate that verified nothing has not passed.
- The check is offline and pure. The live read-back is still performed by
  `scripts/verify-deployment.cjs`, which needs network access.
