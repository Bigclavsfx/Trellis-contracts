# Concurrent writes and retry replay

Soroban serializes committed invocations. These regression tests model competing
producers as explicit ordered calls, with ledger sequence and timestamp set by
the existing LedgerSequenceHarness. They do not use threads, sleeps or wall time.

The schedule enqueues two logical writes, duplicates both submissions with changed
due times, then runs competing cranks at ledgers 10, 10, 10, 11, 11 and 12. The
first attempt of each job fails before the application write. Early cranks must
respect backoff; successful retries increment persistent application state exactly
once. Late reprocessing and duplicate enqueue must resolve through receipts.
The test checks every queue/counter checkpoint against a fixed expected trace,
repeats the schedule from a fresh environment, and reverses producer order to
verify the same final state and retry trace. Unauthorized capacity changes are
interleaved and must leave admission unchanged.

The handler deliberately returns errors before mutation: returning Err from a
plain Rust helper does not roll back earlier handler writes. Production handlers
must be idempotent or abort the entire contract transaction when atomic rollback
is required. The tests assert both transient failure and successful recovery;
they do not claim to simulate parallel host execution or network consensus.

Run `cargo test --manifest-path scripts/issue-verification/Cargo.toml test_concurrent_replay`.
This harness imports the actual worker, authorization, storage and ledger sources
and bypasses the existing unrelated syntax error in the shared crate root.
No production schema, interface, dependency, or migration changes are made for
this test-only issue. To reproduce a failure, rerun the same test and inspect the
first differing checkpoint; never advance receipts manually to force a pass.
