# Migration Safety Framework (Issue #51)

Guardrails for schema and data migrations across the Trellis Soroban
contract suite. The framework lives in [`shared::migration`](../shared/src/migration.rs)
and is intentionally storage-light: one instance-storage journal per contract.

## Why

In Soroban the WASM upgrade and the state migration are separate transactions.
A migration that fails midway can leave the contract on new code with
half-migrated state. The framework makes that failure **visible**, **resumable**,
and **reversible**:

| Risk | Guardrail |
|---|---|
| "How many records will this touch?" | `dry_run()` reports impact before any write |
| "Did it finish correctly?" | `evaluate_post_checks()` + `finish_migration()` |
| "It died at step 2 of 5." | `MigrationJournal` records the exact resume point |
| "How do we get back?" | `RollbackStrategy` + `rollback_notes` on the plan |

## Types

```rust
MigrationPlan {
    from_version, to_version,        // to_version must be > from_version
    steps: Vec<MigrationStep>,       // strictly increasing step ids
    rollback: RollbackStrategy,      // Revert | ForwardFix | Manual
    rollback_notes: String,
}

MigrationStep { id, name, kind, affected_records, destructive }
MigrationStepKind = Storage | Schema | DataBackfill | Config | Custom
```

## Dry run (report before writes)

`dry_run(&plan)` is a **pure function** — it never reads or writes contract
storage, so it is safe on a read-only path and in simulations.

```rust
let report = shared::migration::dry_run(&plan);
assert!(report.plan_valid);
let affected  = report.affected_records;   // sum across steps
let destructive = report.destructive_steps; // needs approval when > 0
```

An invalid plan (bad version range, empty steps, unordered ids) returns
`plan_valid: false` and the failing `MigrationError` code instead of panicking.

## Data Simulation (Dry Run)

To estimate data impact, use the testing utility `testing::migration::MigrationSimulator`. It helps determine which specific storage records will successfully migrate, which will fail (e.g. data corruption or un-parseable formats), and which require manual handling by administrators.

```rust
let simulator = MigrationSimulator::new(&env, old_records, migration_fn);
let report = simulator.run();
// report.successful, report.failed, report.manual_handling
```

The simulator enforces read-only verification because it runs entirely in memory or off-chain, performing no irreversible writes to the ledger.

## Storage Layout Validation & Invariant Pre-flight (Issue #97)

To prevent breaking schema changes from deploying incompatible WASM code and corrupting persistent storage:

1. **`MigrationHook` Interface**: Migration hooks must implement:
   - `validate_storage(env: Env, target: Address) -> Result<(), Error>`
   - `pre_upgrade(env: Env, old_version: u32, new_version: u32) -> bool`
   - `post_upgrade(env: Env, old_version: u32, new_version: u32)`

2. **Pre-flight Dry-Run in `propose_upgrade`**:
   Before an upgrade proposal is accepted into the registry, the coordinator invokes `validate_storage(&env, target)` on the registered migration hook.
   - Samples existing storage records to ensure contracttype deserialization succeeds.
   - Verifies critical protocol invariants (e.g. total balances equal token reserves).
   - If validation fails or panics upon deserialization, proposal creation is aborted with `UpgradeError::StorageIncompatible`.

3. **Execution Guard in `execute_upgrade`**:
   Before bytecode is swapped, `validate_storage` runs again to ensure state consistency has not drifted since proposal time.

## Storage Schema Version Guards (Issue #140)

To prevent incompatible bytecode interpretations across contract upgrades, every contract stamps its active storage schema version in instance storage (`stor_ver`). Read operations are protected with deterministic guards:
- Active schema version reads succeed.
- Old-compatible versions (e.g. V1) remain decodable and can be upgraded monotonically.
- Incompatible or missing schema versions fail fast with `Error::UnsupportedSchemaVersion`.
See [`docs/STORAGE_SCHEMA_GUARDS.md`](./STORAGE_SCHEMA_GUARDS.md) for full architecture and runbook details.

## Running a migration

```rust
// 1. Preview (no writes).
let report = dry_run(&plan);

// 2. Stage the journal.
let mut journal = begin_migration(&env, &plan, env.ledger().timestamp())?;

// 3. Complete steps strictly in order.
journal = mark_step_complete(&env, &plan, 1, now)?;
journal = mark_step_complete(&env, &plan, 2, now)?;

// 4. Post-checks decide whether the migration is complete.
let mut checks = Vec::new(&env);
checks.push_back(PostCheck { id: symbol_short!("rows"), passed: true });
checks.push_back(PostCheck { id: symbol_short!("sums"), passed: true });
finish_migration(&env, &checks, now)?;
```

`mark_step_complete` rejects out-of-order ids with
`MigrationError::StepOutOfOrder`, which is what makes recovery deterministic:
`resume_index(&journal)` always points at the next step to run.

## Failure, resume, and rollback

If a step fails, record it:

```rust
fail_migration(&env, &symbol_short!("remap"), error_code, now)?;
```

The journal keeps `status = Failed`, `failed_step`, and `last_error`, and
`is_resumable(&journal)` stays `true`, so a retry can continue from
`resume_index(&journal)` without re-running completed steps.

If a **post-check** fails, `finish_migration` returns
`MigrationError::PostCheckFailed` and records the first failing check id in
`journal.failed_step`. Follow the plan's rollback strategy:

- `RollbackStrategy::Revert` — re-deploy the previous WASM / restore the
  pre-migration snapshot.
- `RollbackStrategy::ForwardFix` — ship the corrective forward migration; do
  not roll state back.
- `RollbackStrategy::Manual` — escalate using the operator runbook.

`clear_journal(&env)` removes the journal once the outcome is recorded
elsewhere; only then can a new migration start.

## Post-checks that operators should run

1. `rows` — every expected record exists after the migration.
2. `sums` — aggregate invariants (totals, balances) are unchanged.
3. `keys` — no legacy keys remain in active read paths.
4. `version` — the stored schema version equals `plan.to_version`.

## Validation

```bash
cargo test -p shared migration
```

## Rollback notes template

```text
Plan:      v<from> -> v<to>
Strategy:  Revert | ForwardFix | Manual
Previous WASM hash:  <hash>
Pre-migration snapshot: <ledger / backup reference>
Forward-fix PR:     <link>
Escalation:         <who / where>
```

## Cross-contract dry run (Issue #332)

A migration that spans several contracts (for example Aid and Treasury) should
be previewed as one batch with `shared::migration::dry_run_cross_contract`.
It takes one `ContractMigrationPlan` per contract and returns a
`CrossContractDryRunReport`:

| Field | Meaning |
|---|---|
| `batch_valid` | `true` only when the batch is non-empty and every plan is valid and unique |
| `affected_records` / `destructive_steps` | Totals across the valid plans only (saturating) |
| `requires_approval` | `true` when any contract in the batch has a destructive step |
| `first_invalid` | First contract whose plan is invalid or duplicated |
| `per_contract` | Each contract's own `DryRunReport`, in the order supplied |

Operational edge cases:

- **Duplicate contract in a batch.** The second entry is reported as
  `InvalidPlan`, and the batch is invalid. This stops one contract's migration
  from being staged twice.
- **Empty batch.** Never valid, so a release cannot pass by migrating nothing.
- **One invalid plan.** The batch is invalid. Totals still count the valid
  plans so operators can see the blast radius, but `batch_valid` is `false`, so
  nothing should be staged until the invalid plan is fixed.

The function is pure and reads or writes no storage, so it is safe on a read
path and in simulations.
