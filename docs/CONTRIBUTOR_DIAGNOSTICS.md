# Contributor Diagnostics: Environment, Toolchain, and Dependency Invariant Validation (Issue #297)

## 1. Overview & Purpose

Developing and testing multi-contract Soroban workspaces requires strict synchronization of host tools, target architectures, and cryptographic crate pins. Even minor version mismatches in cryptographic dependencies (such as unpinned `curve25519-dalek` or `ed25519-dalek` sub-dependencies) can result in subtle runtime signature verification failures, non-deterministic WASM compilation artifacts, or build-time compilation panics.

The **Contributor Diagnostics Suite** provides end-to-end automated verification across two layers:
1. **On-Chain / Contract Level (`shared::diagnostics`)**: Deterministic Soroban data models and verification functions to evaluate system health, record diagnostic checks, and protect against schema incompatibilities.
2. **CLI Runner (`scripts/contributor-diagnostics.cjs`)**: An automated developer tool and CI gate that validates developer environments before contract compilation.

---

## 1.1 Failure, retry, and authorization semantics

The diagnostics runner is read-only and should be safe to rerun after any local setup change. A failed probe records the check name and remediation text, then continues collecting the remaining checks so one missing tool does not hide unrelated failures. Retry a failed check only after applying its printed remediation; transient RPC failures can be rerun without changing contract state.

Diagnostics must never print secret values. Presence checks may report that a credential is missing, but authentication failures should be summarized as an authorization failure rather than exposing tokens, private keys, request headers, or raw provider responses. Release and deployment commands remain separate from this contributor-only diagnostic path.

For release evidence, preserve the machine-readable `--json` output together with the migration and rollback records. A failed release gate is retried by rerunning the corresponding read-only check after remediation; it is not bypassed by lowering a threshold or mutating a deployment.
## 2. Diagnostic Categories

The diagnostics harness checks five core categories:

| Category | Checks Performed | Minimum Acceptance Standard |
| :--- | :--- | :--- |
| **Environment** | Node.js runtime, Git CLI | Node.js >= 18.0.0, Git installed in PATH. |
| **Toolchain** | `rustc`, `cargo`, WASM target | Rust 1.80+, Cargo in PATH, `wasm32-unknown-unknown` installed. |
| **Dependency Invariants** | Soroban SDK, Dalek crypto pins | `soroban-sdk = "21.x"` workspace pin, `curve25519-dalek = "=4.1.3"`, `ed25519-dalek = "=2.1.1"`. |
| **Storage Schema** | Schema consistency, Changelog | Valid JSON schema in `changelog/entries.json` matching `schema.json`. |
| **Workspace Fixtures** | Unit test fixtures, shared suites | All core modules contain corresponding unit test suites. |

---

## 3. CLI Runner & Execution Modes

Run the diagnostics tool directly from the repository root:

```bash
# Standard mode (warnings allowed, exits 1 only on failures)
node scripts/contributor-diagnostics.cjs

# Strict mode (exits 1 if ANY warning or failure is found)
node scripts/contributor-diagnostics.cjs --strict

# Machine-readable JSON output for CI pipelines
node scripts/contributor-diagnostics.cjs --json

# Self-test mode (validates internal runner integrity)
node scripts/contributor-diagnostics.cjs --self-test
```

### JSON Output Schema

```json
{
  "isHealthy": true,
  "isStrict": false,
  "counts": {
    "passed": 9,
    "warnings": 0,
    "failed": 0
  },
  "results": [
    {
      "component": "soroban-sdk-workspace-invariant",
      "category": "DependencyInvariants",
      "status": "Passed",
      "message": "Soroban SDK 21.x pinned in workspace.dependencies"
    }
  ]
}
```

---

## 4. On-Chain Diagnostics Model (`shared::diagnostics`)

Soroban contracts can record and verify diagnostic status using the shared diagnostics library:

```rust
use soroban_sdk::{symbol_short, Env, Vec};
use shared::diagnostics::{
    create_diagnostic_check, evaluate_diagnostics, record_system_diagnostic,
    DiagnosticCategory, DiagnosticCheck, DiagnosticStatus,
};

// 1. Create diagnostic check
let check = create_diagnostic_check(
    symbol_short!("soroban"),
    DiagnosticCategory::DependencyInvariants,
    DiagnosticStatus::Passed,
    symbol_short!("dep_ok"),
    env.ledger().timestamp(),
);

// 2. Evaluate checks list
let mut checks = Vec::new(&env);
checks.push_back(check);
let report = evaluate_diagnostics(&env, &checks, false, env.ledger().timestamp())?;

// 3. Persist diagnostic report under admin authorization
record_system_diagnostic(&env, &admin_address, &report)?;
```

---

## 5. Troubleshooting & Remediation Runbook

### Issue: `wasm32-unknown-unknown target not installed`
- **Cause**: The Rust toolchain does not have the WASM compiler target installed.
- **Fix**: Run `rustup target add wasm32-unknown-unknown`.

### Issue: `Soroban SDK must be pinned to 21.x`
- **Cause**: Workspace `Cargo.toml` or child crates are using conflicting or unpinned Soroban versions.
- **Fix**: Ensure `Cargo.toml` specifies `soroban-sdk = { version = "21.0.0", default-features = true }`.

### Issue: `Changelog integrity failure`
- **Cause**: `changelog/entries.json` is missing required fields (`summary`, `issue`, `impact`, `version`).
- **Fix**: Run `node scripts/validate-changelog.cjs` to locate offending JSON lines and format accordingly.

---

## 6. Backwards Compatibility & Rollback

- All diagnostic checks in `shared::diagnostics` are purely additive.
- Persistent storage for diagnostic records uses dedicated isolated key `KEY_LAST_DIAGNOSTIC` (`symbol_short!("last_diag")`), ensuring zero impact on user balances, vaults, or core contract states.
- Reverting the diagnostics changes requires only removing the module declaration without requiring storage data migrations.
