# Developer Diagnostics: Local Setup, Dependencies, Network & Seed Data Validation

## 1. Overview & Purpose

Developing and integrating Soroban smart contracts across Trellis requires validating host dependencies, cryptographic crate pins, environment configurations, network connectivity to Stellar RPC services, and seed data integrity across six interdependent protocol modules:
- **Treasury** (`contracts/treasury-contract`): Financial reserves, SAC token transfers, and category vaults.
- **Aid** (`contracts/aid-contract`): Humanitarian aid disbursements, donor escrows, milestones, and claims.
- **Referral** (`contracts/referral-contract`): Multi-tier commission accounting and affiliate tracking.
- **Governance** (`contracts/governance-contract`): Multi-sig proposal voting, thresholds, and administrative actions.
- **Oracle** (`contracts/oracle-contract`): External price feeds, staleness windows, and median aggregation.
- **Marketplace** (`contracts/nft-marketplace`): NFT listings, escrow auctions, and royalty payments.

The **Developer Diagnostics Command** (`node scripts/developer-diagnostics.cjs`) allows a contributor to run a single command that validates the local development setup, verifies external service assumptions, audits seed fixtures, and provides actionable, copy-pasteable failure fixes.

---

## 2. Core Diagnostic Pillars

The diagnostics command validates five core pillars:

| Pillar | Focus Area | Checks Performed | Minimum Acceptance Standard |
| :--- | :--- | :--- | :--- |
| **1. Dependencies** | Host Tools & Workspace Invariants | Node.js runtime, Git CLI, Rust/cargo, wasm32 target, Soroban SDK 21.x workspace pin, Dalek crypto pins (`=4.1.3`, `=2.1.1`), and file structure across all 6 contract modules. | Node >= 18, Git in PATH, Rust 1.85 / Soroban SDK 21.x pinned, modules present with valid `Cargo.toml` and `src/lib.rs`. |
| **2. Environment Config** | Configuration & Secret Safety | `STELLAR_NETWORK`, `STELLAR_RPC_URL`, `TRELLIS_ENV`, and strict secret key redaction (`TRELLIS_SECRET_KEY`). | Valid network identifier, valid HTTP(S) RPC URL, valid environment tag. Secrets are NEVER printed in plain text. |
| **3. Network Access** | Service Assumptions & Connectivity | Stellar RPC reachability probe (HTTP `/health` and JSON-RPC `getHealth` with 3-second timeout), external Oracle service assumptions, and SAC token interface availability. | RPC reachable or degraded offline mode recognized; test mocks and external interface adapters verified. |
| **4. Seed Data** | Fixture Schema & Integrity | Backfill seed data across all 6 modules (`fixtures/backfill/*.json`), detecting schema mismatches and isolating invalid test fixtures. | All 6 seed fixtures contain valid JSON records, valid Stellar strkeys (`G...`, `C...`), valid statuses, and non-negative amounts. |
| **5. Failure Fixes** | Actionable Remediation | Exact remediation command for every failing or warning check; optional `--fix` flag to scaffold missing configuration. | Every failure outputs a copy-pasteable fix command. |

---

## 3. CLI Runner & Execution Modes

Contributors can run developer diagnostics directly from the repository root:

```bash
# Standard interactive check (warnings allowed, exits 1 only on critical failures)
node scripts/developer-diagnostics.cjs

# Offline mode (skips live RPC probes, ideal for air-gapped or travel development)
node scripts/developer-diagnostics.cjs --offline

# Strict mode for CI pipelines (exits 1 if ANY warning or failure is found)
node scripts/developer-diagnostics.cjs --strict

# Automated remediation mode (scaffolds default local .env if missing)
node scripts/developer-diagnostics.cjs --fix

# Target a specific module
node scripts/developer-diagnostics.cjs --module aid
node scripts/developer-diagnostics.cjs --module treasury

# Machine-readable JSON output for CI pipelines and tooling
node scripts/developer-diagnostics.cjs --json

# Harness self-test mode (validates runner integrity)
node scripts/developer-diagnostics.cjs --self-test
```

Alternatively, Unix contributors can invoke:
```bash
./scripts/diagnostics.sh
```

---

## 4. Automated Verification Test Suite

The repository includes an executable verification suite that exercises all diagnostic checks, secret redaction, and CLI modes:

```bash
node scripts/verify-developer-diagnostics.cjs
```

The verification suite runs 45 automated test assertions across 6 test suites:
1. CLI execution & JSON output schema validation (`isHealthy`, `counts`, `results`, `remediations`).
2. Dependencies and all 6 contract modules (Treasury, Aid, Referral, Governance, Oracle, Marketplace).
3. Environment configuration and secret redaction invariants (verifies `TRELLIS_SECRET_KEY` is never leaked).
4. Network access and external service assumptions (online probe, timeout, and `--offline` flag).
5. Seed data validation across all 6 module fixtures (verifies valid records and classifies invalid test fixtures).
6. Actionable remediation generation and CLI flags (`--self-test`, `--module`, `--fix`).

---

## 5. Operational Edge Cases & Failure Modes

### 5.1 Air-Gapped / Offline Environments
- **Symptom**: `network:rpc_connectivity [Warning]: Unable to establish RPC connection`.
- **Handling**: In offline development environments, live network probes may time out. Pass the `--offline` flag (`node scripts/developer-diagnostics.cjs --offline`) to skip external network calls and validate local contract compilation and seed data offline.

### 5.2 Stellar RPC Rate Limits & Transient Timeouts
- **Symptom**: `network:rpc_connectivity` warns on public testnet RPC.
- **Handling**: Public endpoints like `https://soroban-testnet.stellar.org` may intermittently throttle or experience latency. Diagnostics enforces a strict 3-second timeout to prevent blocking. To run against a local standalone node, set `STELLAR_RPC_URL=http://localhost:8000/soroban/rpc` and run `soroban network start standalone`.

### 5.3 Secret Credential Leakage Prevention
- **Invariant**: The developer diagnostics runner **NEVER** prints secret keys in full to standard output, standard error, or JSON reports.
- **Behavior**: If `TRELLIS_SECRET_KEY` is set in the environment or `.env`, diagnostics validates its format (`^S[A-Z0-9]{55}$`) and displays only a truncated preview (`S...XX`) or `***`.

### 5.4 Corrupted Seed Data Fixtures
- **Symptom**: `seed:<module> [Failed]: Malformed JSON in seed fixture`.
- **Handling**: If a developer accidentally corrupts a JSON seed fixture, diagnostics pinpoints the exact file and line error. Run `git checkout fixtures/backfill/` to restore clean seed data.

---

## 6. Rollback & Recovery Steps

### 6.1 Read-Only Execution Guarantee
The developer diagnostics command is **strictly read-only** by default. It executes non-mutating checks:
- No smart contract state is modified.
- No Stellar transactions are submitted or funded.
- No repository files are altered unless explicitly invoked with `--fix`.

### 6.2 Remediation Rollback (`--fix`)
If the `--fix` flag was used to generate `.env`, reverting the change requires only removing the generated `.env` file:
```bash
# Revert scaffolded configuration
git checkout -- .env 2>/dev/null || rm -f .env
```

### 6.3 Retry Procedure
After resolving a reported failure (e.g. installing a toolchain target or updating an environment variable):
1. Run `node scripts/developer-diagnostics.cjs`.
2. Confirm the failing check transitions to `[Passed]`.
3. Proceed with contract building and testing: `cargo test --workspace`.

---

## 7. Backwards Compatibility Statement

All diagnostics tooling is purely additive:
- Public smart contract entrypoints, signatures, and WASM binaries remain untouched.
- On-chain storage layouts, contract schemas, and event definitions remain 100% backward-compatible.
- Existing CI scripts (`scripts/diagnostics.sh` and `scripts/contributor-diagnostics.cjs`) remain operational.
