# Restore Validation Framework

After a database restore or schema migration, maintainers must run validation checks to ensure core records, relationships, and settlement references remain consistent across the ledger state. This document defines the restore invariants, assumptions, and failure escalation steps.

## Restore Invariants

The repository domain enforces the following invariants which must hold true after any restore or migration:

1. **No Missing Records:** All critical core state elements (e.g., global configuration, initialized protocol accounts) must exist.
2. **No Orphaned Records:** Relational integrity must be maintained. For instance, payment receipts or sub-accounts must link to a valid, existing parent account.
3. **No Duplicated Records:** Unique constraints must hold, particularly for settlement references or idempotency keys, which must never be duplicated.
4. **No Inconsistent Records:** Derived state or aggregate values (e.g., total supply vs. sum of individual balances) must strictly match the underlying authoritative records.

## Running the Validation

We provide a read-only validation script to verify these invariants:

```bash
./scripts/validate-restore.sh
```

By default, the script executes read-only queries against the ledger/database without mutating any state.

## Recovery Assumptions

- **Read-Only Access:** The validation process assumes the environment is temporarily paused for writes, allowing a clean, static snapshot to be validated.
- **Data Availability:** We assume access to the necessary RPC endpoints or database replicas to perform comprehensive state checks.
- **Deterministic Checkpoints:** In case of migration failures, recovery relies on the deterministic checkpoints defined in `RECOVERY.md`.

## Interpreting Failures and Escalation Steps

If `./scripts/validate-restore.sh` reports failures, maintainers should interpret and escalate them as follows:

| Failure Type | Interpretation | Escalation Step |
| --- | --- | --- |
| **Missing Records** | Core state is incomplete. The restore may have failed midway, or the snapshot was truncated. | Escalate to **Tier 2 Support**. Do not resume operations. Restore from a known-good backup or run the [Backfill Tool](BACKFILL_TOOL.md): `./scripts/backfill.sh --module <mod> --input <file>`. |
| **Orphaned Records** | The relationship links are broken, often due to out-of-order data insertion during migration. | Run relational backfill via the [Backfill Tool](BACKFILL_TOOL.md): `./scripts/backfill.sh --module referral --input <file>`. If unresolved, escalate to the **Database Administration Team**. |
| **Duplicated Records** | Idempotency or uniqueness constraints have been violated, typically due to duplicated side-effects. | **Halt all trading.** Identify the duplicated side effects. Manual deduplication is required by the **Protocol Engineering Team**. |
| **Inconsistent Records**| Aggregate values have drifted from the underlying records, possibly due to a logic bug during migration. | Escalate immediately to the **Security and Protocol Engineering Teams**. Do not resume operations until consistency is manually verified and corrected. |


## Missing and archived persistent records (Issue #336)

A persistent entry whose TTL lapses is archived. The contract reads it as
absent, the same as a key that was never written. The contract cannot tell
these cases apart, so the rule is simple: **never turn absence into a default
unless the contract's invariants prove the record can be absent.**

`shared::storage::persistent_get_required` enforces this rule. On a miss it
returns `Error::NotFound` and does not bump the TTL, so a refused read cannot
extend an entry that is about to be restored. Use `persistent_get` and handle
`None` explicitly wherever absence is a legitimate state.

| Situation | Caller behaviour | Recovery |
| --- | --- | --- |
| Record required by invariant returns `NotFound` | Fail the operation. Do not substitute a default. | Restore the archived entry with the network's restore operation (`RestoreFootprint`), then retry. |
| Record was never written and absence is legitimate | Handle `None` as the "no record" state. | None needed. |
| Record is restored and written back with a fresh TTL | The retried `persistent_get_required` returns the value. | None needed. |

Covered by `shared/src/test_storage.rs`: a present value is returned, a
never-written key and an archived record both return `NotFound`, and a restored
record reads again.

### Call sites that default absence to zero (review list)

These reads currently return `0` or an empty collection on a miss. If the
entry was archived, the operation proceeds on the wrong state, with no error.
Each one needs an explicit review: either absence is legitimate for it, or it
should move to `persistent_get_required`. This PR does not change them, because
absence is a legitimate state for some of them and changing them would alter
contract behaviour.

- `contracts/nft-marketplace/src/storage.rs`: `PendingRefunds::get` returns `0`
  for a missing `PendingRefund`. A bidder with no refund is legitimate, so
  absence is ambiguous here.
- `contracts/oracle-contract/src/storage.rs`: `SubmitterStake` returns `0`.
- `contracts/aid-contract/src/storage.rs`: `DonorAidCount` returns `0`.

**Operational edge cases.** An archived record that is restored after its
settlement window has passed may change a result that operators have already
reported. Compare the restored value with the audit ledger before re-running
any operation.

**Rollback.** `persistent_get_required` is additive. No existing call site
changes, so reverting the commit removes the helper and its tests and leaves
on-chain behaviour unchanged.
