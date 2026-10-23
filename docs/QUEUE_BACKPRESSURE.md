# Bounded background work

The existing worker accepts at most 64 pending plus indexed dead-letter jobs by
default. Admins can call `configure_queue_capacity` with 1–256. This uses a new
instance key and preserves WorkerConfig, Job, receipt and existing key layouts.
JobError adds QueueFull (8) and InvalidCapacity (9); existing values are unchanged.

New work at capacity returns QueueFull before assigning an ID, recording an
event or altering counters. Dedupe checks run first, so pending/completed retries
still return their original outcomes at capacity. Retry attempts retain their
reserved slot; moving a job to dead letters or requeueing it does not increase
occupancy. A discarded dead letter no longer reserves a slot and must pass
admission again when requeued. Pause blocks requeue as well as admission/execution.
Worker management and capacity changes require the configured admin's signature;
enqueue and cranking retain their existing permissionless behavior.

On saturation, stop producers, run due work, inspect terminal failures and discard
resolved dead letters, then retry rejected work with the same dedupe key. Avoid
busy-loop retries: respect next_due_ledger and the stored backoff policy. Completion
and administrative discard release slots; no accepted work is silently dropped.
Handler failures must remain idempotent as described in WORKERS.md.

For pre-existing queues above capacity, admission stops while cranks and reserved
requeues continue. Drain before rollout if bounded scan costs are required from
the first transaction; existing large vectors are not truncated or migrated.
Lowering capacity below occupancy similarly blocks only new work. Roll back a
capacity change by restoring its previous value, or pause the worker during
incident response. Persistent jobs/indexes require normal TTL maintenance and
archive restoration together; missing archived entries are not completed jobs.
Retained completed receipts and forensic records are audit history, outside the
active-work bound, and follow the existing retention policy.

Run `cargo test --manifest-path scripts/issue-verification/Cargo.toml test_queue_backpressure` for normal, saturated, retry, terminal,
discard/requeue, pause, and unauthorized configuration coverage.

The existing payment convenience wrapper maps framework failures other than
Disabled/InvalidPolicy to InvalidArgument; direct worker integrations receive
QueueFull. Wrappers must propagate admission failure as a contract error to roll
back any preceding application writes, or reserve admission before expensive work.
