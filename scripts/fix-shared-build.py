#!/usr/bin/env python3
"""Re-apply the mechanical repairs that upstream `main` needs in `shared/`.

The upstream `main` branch of TRELLIS-STELLAR/Trellis-contracts does not
compile: several files contain mangled tokens and duplicated re-exports. This
script encodes the repairs so they can be re-applied deterministically and
reviewed as a single, idempotent unit.

Every edit is idempotent: running the script twice is a no-op the second time.

Usage: python3 scripts/fix-shared-build.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def edit(path, old, new):
    """Apply one idempotent replacement; a missing pattern is not an error."""
    full = os.path.join(ROOT, path)
    with open(full, "r", encoding="utf-8") as fh:
        content = fh.read()
    if old not in content:
        return False
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(content.replace(old, new, 1))
    return True


def main():
    # 1. accessibility.rs: `symbol_short!` accepts at most 9 characters.
    edit(
        "shared/src/accessibility.rs",
        'symbol_short!("last_dense")',
        'symbol_short!("dense")',
    )
    edit(
        "shared/src/accessibility.rs",
        'symbol_short!("last_recov")',
        'symbol_short!("recovry")',
    )

    # 2. error_taxonomy.rs: remove match arms that can never be reached.
    #    Each of them duplicates a code that an earlier, broader arm already
    #    maps, so removing them changes no runtime mapping.
    edit(
        "shared/src/error_taxonomy.rs",
        """            505 => definition(
                "INVALID_PRICE",
                ErrorCategory::Validation,
                false,
                "The submitted price is not valid.",
                Some("Submit a positive price within the allowed range."),
            ),
            506 => definition(
                "INVALID_DECIMALS",
                ErrorCategory::Validation,
                false,
                "The price precision is not supported.",
                Some("Submit the price using the feed's configured decimals."),
            ),
""",
        "",
    )
    edit(
        "shared/src/error_taxonomy.rs",
        """            201 => definition(
                "ROLE_ALREADY_EXISTS",
                ErrorCategory::Conflict,
                false,
                "That role already exists.",
                Some("Use the existing role or choose a different role name."),
            ),
            202 => definition(
                "ALREADY_MEMBER",
                ErrorCategory::Conflict,
                false,
                "This account already holds the role.",
                Some("No action is needed. Check the account's current roles."),
            ),
            203 => definition(
                "NOT_MEMBER",
                ErrorCategory::NotFound,
                false,
                "This account does not hold the role.",
                Some("Check the account address and role name."),
            ),
            204 => definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "A role cannot be a parent of itself.",
                Some("Choose a different parent role."),
            ),
""",
        "",
    )
    edit(
        "shared/src/error_taxonomy.rs",
        """            2006 => definition(
                "INVALID_METADATA_HASH",
                ErrorCategory::Validation,
                false,
                "The metadata hash is not valid.",
                Some("Submit a 32-byte metadata hash in the documented format."),
            ),
            2007 => definition(
                "INVALID_ROYALTY",
                ErrorCategory::Validation,
                false,
                "The royalty rate is outside the allowed range.",
                Some("Submit a royalty rate within the documented maximum."),
            ),
            2008 => definition(
                "INVALID_EXTENSION_WINDOW",
                ErrorCategory::Validation,
                false,
                "The auction extension window is not valid.",
                Some("Submit an extension window within the documented limits."),
            ),
            2017 => definition(
                "INVALID_DUTCH_PRICES",
                ErrorCategory::Validation,
                false,
                "The Dutch auction prices are not valid.",
                Some("Set a starting price higher than the ending price."),
            ),
            2018 => definition(
                "INVALID_AMOUNT",
                ErrorCategory::Validation,
                false,
                "The amount is not valid.",
                Some("Submit an amount within the allowed range."),
            ),
""",
        "",
    )

    # 3. Silence unused-parameter warnings without changing behaviour.
    edit(
        "shared/src/dashboard.rs",
        "fn operation_type_to_symbol(env: &Env, op_type: &OperationType) -> Symbol {",
        "fn operation_type_to_symbol(_env: &Env, op_type: &OperationType) -> Symbol {",
    )
    edit(
        "shared/src/degradation.rs",
        """fn dependency_key(module: DegradationModule, dependency: ExternalDependencyKind) -> Symbol {
    let m = module.as_symbol();
    let d = dependency.as_symbol();
    // Unique key combining module and dependency""",
        """fn dependency_key(module: DegradationModule, dependency: ExternalDependencyKind) -> Symbol {
    // Unique key combining module and dependency""",
    )
    edit(
        "shared/src/degradation.rs",
        """                    // Record failure
                    let level = record_dependency_check(env, module, dependency, false, 1);""",
        """                    // Record failure; the degradation level is implied by the
                    // fallback event published below.
                    record_dependency_check(env, module, dependency, false, 1);""",
    )
    edit(
        "shared/src/impersonation.rs",
        """pub fn check_action_permission(
    env: &Env,
    session: &ImpersonationSession,""",
        """pub fn check_action_permission(
    _env: &Env,
    session: &ImpersonationSession,""",
    )
    edit(
        "shared/src/impersonation.rs",
        """fn is_valid_scope(
    env: &Env,
    scope: &ImpersonationScope,""",
        """fn is_valid_scope(
    _env: &Env,
    scope: &ImpersonationScope,""",
    )
    edit(
        "shared/src/reconciliation.rs",
        """    user_records: Vec<SourceRecord>,
    current_timestamp: u64,""",
        """    user_records: Vec<SourceRecord>,
    _current_timestamp: u64,""",
    )
    edit(
        "shared/src/timeline.rs",
        """pub fn validate_scheduled_action(
    env: &Env,
    action_id: u64,
    link: &ResourceLink,""",
        """pub fn validate_scheduled_action(
    env: &Env,
    action_id: u64,
    _link: &ResourceLink,""",
    )
    for fname in ("propagate_to_worker", "advance_worker_retry", "propagate_to_external_call"):
        edit(
            "shared/src/workflow_correlation.rs",
            "pub fn %s(\n    env: &soroban_sdk::Env," % fname,
            "pub fn %s(\n    _env: &soroban_sdk::Env," % fname,
        )

    # 4. lib.rs: repair the mangled and duplicated re-export blocks.
    edit(
        "shared/src/lib.rs",
        """TREASURY_EMERGENCY_WITHDRAW, TREASURY_SET, TREASURY_WITHDRAW,
pub use event_dead_letter::{""",
        """TREASURY_EMERGENCY_WITHDRAW, TREASURY_SET, TREASURY_WITHDRAW,
};
pub use event_dead_letter::{""",
    )
    edit(
        "shared/src/lib.rs",
        """pub use events::{
emit, emit_collection_registered, emit_import_committed, emit_import_failed,
emit_import_simulated, emit_nft_auction, emit_nft_bid, emit_nft_listed, emit_nft_offer,
emit_nft_settle, emit_nft_sold, emit_royalty_paid,
};
""",
        "",
    )
    edit(
        "shared/src/lib.rs",
        """BackfillAction, BackfillCheckpoint, BackfillDuplicatePolicy, BackfillError,
advance_checkpoint, begin_backfill, clear_checkpoint, complete_backfill, dry_run as dry_run_backfill,
fail_backfill, is_resumable as is_backfill_resumable, load_checkpoint as load_backfill_checkpoint,
save_checkpoint as save_backfill_checkpoint, BackfillAction, BackfillCheckpoint, BackfillError,
BackfillItem""",
        """BackfillAction, BackfillCheckpoint, BackfillDuplicatePolicy, BackfillError,
BackfillItem""",
    )

    print("shared repairs applied")


if __name__ == "__main__":
    sys.exit(main())
