# Resumable treasury whitelist repair

This additive library slice repairs the treasury strategy whitelist (`strat_lst`)
against canonical approval records (`strat_ok`, strategy). It removes orphans and
duplicates and adds approved missing candidates. It never changes approvals,
positions, balances or financial totals. Existing contract interfaces and storage
layouts are unchanged; integrating contracts expose admin-authorized wrappers.

Call start_repair with a fresh job ID and known missing strategy candidates. The
job automatically includes every existing whitelist entry. Plans hold at most 100
unique strategies, including the original index; larger scopes fail before writes.
Call advance_repair with the stored cursor and a batch limit of 1–10. Each batch
re-reads current canonical approvals, updates the index and persists its cursor
atomically. Older cursors return the current job without repeating work, future
cursors fail, and completion retries return the completed checkpoint. Only one
job may run per contract. All mutations require the configured admin's signature.

Discovery is explicit: storage is not enumerable. Supply missing candidates from
a trusted complete registry or finalized indexer inventory. The job always checks
approval on-chain, so a supplied candidate cannot grant itself approval. Restore
archived canonical records before execution. An absent approval means unapproved;
archive/type failures abort the transaction rather than skipping a record.

If an index writer races a batch, the next batch returns Conflict and preserves
the cursor and concurrent state. Pause strategy configuration while repairing
when a stable snapshot is needed. Approvals can change after a processed batch;
quiesce writers and run a fresh audit/job to reconcile the complete final view.
This slice does not attempt a global financial repair or automatic discovery.

On interruption, retrieve get_repair_job and resume at its cursor; local worker
memory is irrelevant. Job records are persistent and use the shared TTL policy;
restore the job if archived before resuming. The active instance marker prevents
a replacement run from silently discarding an interrupted job. A failed batch
does not advance the checkpoint, and canonical records remain untouched.

rollback_repair restores the original derived index only if the live index equals
the job's last written snapshot and no different repair is active. It preserves
the audit record and is idempotent. If a concurrent writer makes rollback unsafe,
abandon_repair releases the active job without changing the index; start a fresh
job from current truth. Rollback may restore known old drift, so audit afterward.
Do not reuse job IDs or delete checkpoints during an incident. Retain audit events
and snapshots through code rollback; no old record migration is required.

Run `cargo test --manifest-path scripts/issue-verification/Cargo.toml test_resumable_repair`.
Tests cover multi-invocation resume, stale/future cursors, canonical changes,
duplicate/orphan removal, rollback, conflicts, abandonment, limits and auth.
