# Focused production-module verification

This standalone crate imports production sources by path. It does not copy or
replace authorization, storage, crypto, worker, repair, or ledger implementations.
Its own workspace and lockfile allow verification while the main shared crate has
an unrelated malformed export block. The extra event/batch imports support the
existing error-catalog coverage tests.

Use a compatible installed Rust toolchain (validation used `cargo +stable` under
WSL), from the repository root:

```
cargo +stable test --locked --manifest-path scripts/issue-verification/Cargo.toml external_evidence
cargo +stable test --locked --manifest-path scripts/issue-verification/Cargo.toml test_queue_backpressure
cargo +stable test --locked --manifest-path scripts/issue-verification/Cargo.toml test_concurrent_replay
cargo +stable test --locked --manifest-path scripts/issue-verification/Cargo.toml test_resumable_repair
```

Run all imported tests with:

```
cargo +stable test --locked --manifest-path scripts/issue-verification/Cargo.toml
```

Two pre-existing error-catalog tests fail with the original source as well:

- `error_taxonomy::tests::settlement_metadata_preserves_correlation_id` expects
  SETTLEMENT_NOT_READY but receives INSUFFICIENT_BALANCE.
- `error_taxonomy::tests::newly_explained_rejections_keep_category_and_retry_policy`
  expects INVALID_DUTCH_PRICES but receives VALIDATION_FAILED.

These failures are outside the four issues. To verify the remaining imported
suite while keeping the exclusions explicit:

```
cargo +stable test --locked --manifest-path scripts/issue-verification/Cargo.toml -- --skip error_taxonomy::tests::settlement_metadata_preserves_correlation_id --skip error_taxonomy::tests::newly_explained_rejections_keep_category_and_retry_policy
```

The main workspace still fails parsing its existing shared export block, so this
harness is not a claim that the complete workspace builds. Once that defect is
fixed separately, the new modules and tests are also registered in the shared
crate for normal workspace verification. Contract integration remains opt-in;
existing public entrypoints and stored layouts are preserved.
