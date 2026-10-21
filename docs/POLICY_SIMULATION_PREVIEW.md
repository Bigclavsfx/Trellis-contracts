# Policy Simulation Preview Framework

## Overview

The **Policy Simulation Preview Framework** (`shared::policy_preview`, Issue #250) provides deterministic pre-execution preview, side effect analysis, and rollback constraint evaluation before committing irreversible or high-impact configuration changes across the six core Soroban modules in Trellis:

- **Treasury** (`PolicyModule::Treasury`): Reserve floors, withdrawal limits, daily withdrawal velocity.
- **Aid** (`PolicyModule::Aid`): Disbursement caps, recipient eligibility thresholds, claim timeouts.
- **Referral** (`PolicyModule::Referral`): Tier commission basis points, qualification thresholds.
- **Governance** (`PolicyModule::Governance`): Quorum requirements, voting delays, execution windows.
- **Oracle** (`PolicyModule::Oracle`): Maximum price variance bounds, staleness tolerances, minimum quorum.
- **Marketplace** (`PolicyModule::Marketplace`): Fee schedules, royalty caps, listing extension windows.

## Core Capabilities

1. **Affected Records & Users Preview**:
   - Calculates the percentage delta between current active policy and proposed changes.
   - Computes expected affected records count (e.g. active disbursements, pending escrows, unexecuted proposals) and affected users count.
2. **Expected Side Effects Breakdown**:
   - Categorizes operational impact: `ClaimsInvalidated`, `ProposalsDisrupted`, `CommissionsReduced`, `OracleFallbackElevated`, `MarketplaceSettlementAdjusted`, `WithdrawalsThrottled`.
   - Assigns severity: `Low`, `Medium`, `High`, or `Critical`.
3. **Rollback Constraints & Feasibility**:
   - Classifies reversibility (`is_reversible`). Irreversible policy changes (e.g. invariant rewrites, state deletions) are explicitly marked.
   - Computes valid rollback window in ledgers (`rollback_window_ledgers`).
   - Assesses invariant preservation requirements and dual-maintainer signoff mandates (`requires_dual_signoff`).
4. **Time-Bounded Previews & Dual-Maintainer Authorization**:
   - Generated previews have an explicit validity window (`valid_until_ledger`, defaulting to 500 ledgers).
   - High-impact and critical policy changes require independent co-signer authorization (`commit_policy_change(&env, &maintainer, preview_id, Some(&co_signer))`).
5. **Auditable Rollback**:
   - Previous parameters are archived to `CommittedHistory`.
   - Maintainers can trigger `rollback_policy_change(&env, &maintainer, module)` to cleanly revert to prior known-good configuration.

## Operational Workflow

```rust
use shared::policy_preview::{
    simulate_policy_preview, commit_policy_change, rollback_policy_change,
    ProposedPolicyChange, PolicyModule, PolicyType, PolicyParameters
};

// 1. Simulate preview
let change = ProposedPolicyChange {
    module: PolicyModule::Treasury,
    policy_type: PolicyType::TreasuryLimits,
    new_params: PolicyParameters {
        primary_limit: 400_000_000,
        secondary_limit: 1,
        window_or_rate: 50,
        max_tier: 3,
        region_restriction: false,
        irreversible_flag: false,
    },
    rationale: String::from_str(&env, "Tightening withdrawal limit during market volatility"),
};

let preview = simulate_policy_preview(&env, &admin, &change, 200, 100)?;
println!("Affected records: {}", preview.affected_records_count);
println!("Severity: {:?}", preview.severity);
println!("Requires dual signoff: {}", preview.rollback_constraints.requires_dual_signoff);

// 2. Commit preview with co-signer
let active_params = commit_policy_change(&env, &admin, preview.preview_id, Some(&co_admin))?;

// 3. Rollback if post-deployment anomalies detected
let restored_params = rollback_policy_change(&env, &admin, PolicyModule::Treasury)?;
```

## Failure Modes & Edge Cases

| Failure Mode | Root Cause | System Behavior | Remediation / Recovery |
|---|---|---|---|
| `InvalidPolicyConfig` | Negative limits or zero window rate | `simulate_policy_preview` rejects with `Error::ConfigInvalid` | Verify configuration bounds before generating preview |
| `SimulationPreviewExpired` | Attempted commit after `valid_until_ledger` | Commit blocked | Generate fresh simulation preview with latest state snapshot |
| `DualSignoffRequired` | Co-signer missing or identical to initiator on high-impact change | Commit blocked with `Error::Unauthorized` | Require separate administrator co-signature |
| `IrreversibleChangeBlocked` | Attempted rollback on change marked `irreversible_flag: true` | Rollback blocked with `Error::ConfigInvalid` | Execute manual forward compensation migration |
| `Unauthorized` | Caller lacks maintainer role | Operation rejected with `Error::Unauthorized` | Call from designated admin address |

## Rollback & Recovery Procedures

1. **Immediate Rollback**:
   - If an applied policy change results in unexpected rejection rates or user friction, maintainers call `rollback_policy_change`.
   - The framework restores the stored `CommittedHistory` snapshot and emits `("pol_rb", module)`.
2. **Compensatory Forward Migration for Irreversible Changes**:
   - For changes where `irreversible_flag` was set to true, automatic rollback is disallowed to prevent invariant corruption.
   - Maintainers inspect `rollback_constraints.recovery_steps` and execute a compensatory policy change.
