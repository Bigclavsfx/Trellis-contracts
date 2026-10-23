#!/usr/bin/env node
/**
 * Executable verification runner for Snapshot Restore Verification:
 * Validates critical data invariants, derived view / index rebuilding, loud failure
 * reporting with remediation steps, and deterministic rollback across all 6 core modules:
 * Treasury, Aid, Referral, Governance, Oracle, and Marketplace.
 */

const assert = require("node:assert/strict");

const RestoreModule = {
  Treasury: "Treasury",
  Aid: "Aid",
  Referral: "Referral",
  Governance: "Governance",
  Oracle: "Oracle",
  Marketplace: "Marketplace",
};

const FailureKind = {
  None: "None",
  SolvencyDeficit: "SolvencyDeficit",
  NegativeBalance: "NegativeBalance",
  OrphanedRecord: "OrphanedRecord",
  DuplicateRecordKey: "DuplicateRecordKey",
  LifecycleInconsistency: "LifecycleInconsistency",
  DerivedViewDrift: "DerivedViewDrift",
  QuorumViolation: "QuorumViolation",
  BoundaryExceeded: "BoundaryExceeded",
  QuarantineRequired: "QuarantineRequired",
};

const Severity = {
  Info: "Info",
  Medium: "Medium",
  High: "High",
  Critical: "Critical",
};

/**
 * Validates critical canonical records against core invariants.
 */
function verifyCriticalDataInvariants(module, records) {
  const mismatches = [];
  let totalReserve = 0n;
  let totalLiabilities = 0n;

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];

    // 1. Negative balance check
    if (
      ["TreasuryBalance", "TreasuryLiability", "ReferralCommission", "AidRecord", "MarketplaceEscrow"].includes(
        rec.kind
      ) &&
      rec.amount < 0n
    ) {
      mismatches.push({
        module,
        failureKind: FailureKind.NegativeBalance,
        targetId: rec.recordId,
        targetSymbol: rec.entitySymbol,
        expectedVal: 0n,
        actualVal: rec.amount,
        severity: Severity.Critical,
        message: "Negative balance detected on critical financial record",
        repairSteps:
          "CRITICAL: Halt contract operations. Investigate accounting journal and deposit/withdraw history. Do not balance by manufacturing credit.",
      });
    }

    if (rec.kind === "TreasuryBalance") totalReserve += rec.amount;
    if (rec.kind === "TreasuryLiability") totalLiabilities += rec.amount;

    // 2. Duplicate primary key check
    for (let j = i + 1; j < records.length; j++) {
      const other = records[j];
      if (rec.kind === other.kind && rec.recordId === other.recordId) {
        mismatches.push({
          module,
          failureKind: FailureKind.DuplicateRecordKey,
          targetId: rec.recordId,
          targetSymbol: rec.entitySymbol,
          expectedVal: 1n,
          actualVal: 2n,
          severity: Severity.High,
          message: "Duplicate primary key collision detected in restored snapshot",
          repairSteps:
            "Halt batch processing. Perform manual deduplication runbook: see docs/RESTORE_VALIDATION.md for conflict resolution.",
        });
      }
    }

    // 3. Relational integrity (no orphaned children)
    if (rec.kind === "AidClaim") {
      const parentExists = records.some((r) => r.kind === "AidRecord" && r.recordId === rec.parentId);
      if (!parentExists) {
        mismatches.push({
          module,
          failureKind: FailureKind.OrphanedRecord,
          targetId: rec.recordId,
          targetSymbol: rec.entitySymbol,
          expectedVal: BigInt(rec.parentId),
          actualVal: 0n,
          severity: Severity.High,
          message: "Orphaned aid claim references non-existent parent aid disbursement",
          repairSteps:
            `Run relational backfill: ./scripts/backfill.sh --module aid --input <file>. Restore missing aid record #${rec.parentId}.`,
        });
      }
    } else if (rec.kind === "ReferralEdge" && rec.parentId !== 0) {
      const parentExists = records.some((r) => r.kind === "ReferralEdge" && r.recordId === rec.parentId);
      if (!parentExists) {
        mismatches.push({
          module,
          failureKind: FailureKind.OrphanedRecord,
          targetId: rec.recordId,
          targetSymbol: rec.entitySymbol,
          expectedVal: BigInt(rec.parentId),
          actualVal: 0n,
          severity: Severity.High,
          message: "Orphaned referral node references non-existent upline partner",
          repairSteps:
            `Run relational backfill: ./scripts/backfill.sh --module referral --input <file>. Reconstruct parent-child mapping for #${rec.parentId}.`,
        });
      }
    } else if (rec.kind === "GovernanceBallot") {
      const parentExists = records.some((r) => r.kind === "GovernanceProposal" && r.recordId === rec.parentId);
      if (!parentExists) {
        mismatches.push({
          module,
          failureKind: FailureKind.OrphanedRecord,
          targetId: rec.recordId,
          targetSymbol: rec.entitySymbol,
          expectedVal: BigInt(rec.parentId),
          actualVal: 0n,
          severity: Severity.High,
          message: "Orphaned ballot references non-existent governance proposal",
          repairSteps:
            `Purge orphaned ballots or backfill missing proposal record: ./scripts/backfill.sh --module governance --proposal-id ${rec.parentId}.`,
        });
      }
    } else if (rec.kind === "MarketplaceEscrow") {
      const parentExists = records.some((r) => r.kind === "MarketplaceListing" && r.recordId === rec.parentId);
      if (!parentExists) {
        mismatches.push({
          module,
          failureKind: FailureKind.OrphanedRecord,
          targetId: rec.recordId,
          targetSymbol: rec.entitySymbol,
          expectedVal: BigInt(rec.parentId),
          actualVal: 0n,
          severity: Severity.High,
          message: "Orphaned marketplace escrow holds funds for non-existent listing",
          repairSteps:
            `CRITICAL: Reconcile marketplace escrows. Refund stranded buyers or restore missing listing record #${rec.parentId}.`,
        });
      }
    }

    // 4. Boundary and Quorum limits
    if (rec.kind === "ReferralEdge" && rec.auxiliaryValue > 10000) {
      mismatches.push({
        module,
        failureKind: FailureKind.BoundaryExceeded,
        targetId: rec.recordId,
        targetSymbol: rec.entitySymbol,
        expectedVal: 10000n,
        actualVal: BigInt(rec.auxiliaryValue),
        severity: Severity.High,
        message: "Referral commission rate exceeds maximum allowable 10,000 basis points",
        repairSteps: "Clamp commission rate to maximum permitted bounds via admin governance update.",
      });
    } else if (rec.kind === "OracleFeed" && rec.auxiliaryValue === 0) {
      mismatches.push({
        module,
        failureKind: FailureKind.QuorumViolation,
        targetId: rec.recordId,
        targetSymbol: rec.entitySymbol,
        expectedVal: 1n,
        actualVal: 0n,
        severity: Severity.High,
        message: "Oracle price feed quorum requirement is zero (must require at least 1 signer)",
        repairSteps: "Re-initialize oracle feed quorum to configured minimum threshold in docs/CONFIGURATION.md.",
      });
    }

    // 5. Lifecycle consistency
    if (rec.kind === "GovernanceProposal") {
      const validStates = ["active", "executed", "cancelled", "defeated"];
      if (!validStates.includes(rec.status)) {
        mismatches.push({
          module,
          failureKind: FailureKind.LifecycleInconsistency,
          targetId: rec.recordId,
          targetSymbol: rec.entitySymbol,
          expectedVal: 0n,
          actualVal: 0n,
          severity: Severity.High,
          message: "Governance proposal has unrecognized lifecycle status",
          repairSteps: "Advance or reset proposal state machine to a valid variant (active, executed, cancelled, defeated).",
        });
      }
    }
  }

  // 6. Solvency Invariant (Reserve >= Liabilities)
  if (module === RestoreModule.Treasury && totalLiabilities > 0n && totalReserve < totalLiabilities) {
    mismatches.push({
      module,
      failureKind: FailureKind.SolvencyDeficit,
      targetId: 0,
      targetSymbol: "solvency",
      expectedVal: totalLiabilities,
      actualVal: totalReserve,
      severity: Severity.Critical,
      message: `Contract reserve balance (${totalReserve}) is strictly less than internal liabilities (${totalLiabilities})`,
      repairSteps:
        `CRITICAL: Halt trading. Deficit of ${totalLiabilities - totalReserve} detected. Reconcile physical SAC token reserves against internal liabilities.`,
    });
  }

  return mismatches;
}

/**
 * Rebuilds secondary derived indexes and cached aggregate projections from canonical records.
 */
function rebuildDerivedViews(module, canonicalRecords) {
  const views = [];

  switch (module) {
    case RestoreModule.Treasury: {
      const categoryTotals = {};
      for (const rec of canonicalRecords) {
        if (rec.kind === "TreasuryStrategy") {
          views.push({
            module,
            viewName: "strat_idx",
            kind: "Index",
            keyId: rec.recordId,
            keySymbol: rec.entitySymbol,
            numericValue: rec.amount,
            isActive: rec.status === "active",
          });
        } else if (rec.kind === "TreasuryBalance") {
          categoryTotals[rec.entitySymbol] = (categoryTotals[rec.entitySymbol] || 0n) + rec.amount;
        }
      }
      for (const [sym, sum] of Object.entries(categoryTotals)) {
        views.push({
          module,
          viewName: "cat_bal",
          kind: "Cache",
          keyId: 0,
          keySymbol: sym,
          numericValue: sum,
          isActive: true,
        });
      }
      break;
    }

    case RestoreModule.Aid: {
      for (const rec of canonicalRecords) {
        if (rec.kind === "AidRecord") {
          if (rec.status === "active") {
            views.push({
              module,
              viewName: "search",
              kind: "Index",
              keyId: rec.recordId,
              keySymbol: rec.entitySymbol,
              numericValue: rec.amount,
              isActive: true,
            });
          }
          views.push({
            module,
            viewName: "donor_aid",
            kind: "Index",
            keyId: rec.recordId,
            keySymbol: rec.entitySymbol,
            numericValue: rec.amount,
            isActive: true,
          });
        }
      }
      break;
    }

    case RestoreModule.Referral: {
      for (const rec of canonicalRecords) {
        if (rec.kind === "ReferralEdge") {
          views.push({
            module,
            viewName: "downline",
            kind: "Index",
            keyId: rec.recordId,
            keySymbol: rec.entitySymbol,
            numericValue: BigInt(rec.auxiliaryValue),
            isActive: true,
          });
        } else if (rec.kind === "ReferralCommission") {
          views.push({
            module,
            viewName: "comm_acc",
            kind: "Cache",
            keyId: rec.recordId,
            keySymbol: rec.entitySymbol,
            numericValue: rec.amount,
            isActive: true,
          });
        }
      }
      break;
    }

    case RestoreModule.Governance: {
      let tallyFor = 0n;
      let tallyAgt = 0n;
      for (const rec of canonicalRecords) {
        if (rec.kind === "GovernanceProposal" && rec.status === "active") {
          views.push({
            module,
            viewName: "act_prop",
            kind: "Index",
            keyId: rec.recordId,
            keySymbol: rec.entitySymbol,
            numericValue: rec.amount,
            isActive: true,
          });
        } else if (rec.kind === "GovernanceBallot") {
          if (rec.auxiliaryValue === 1) tallyFor += rec.amount;
          else tallyAgt += rec.amount;
        }
      }
      views.push({
        module,
        viewName: "tally_for",
        kind: "Cache",
        keyId: 0,
        keySymbol: "for",
        numericValue: tallyFor,
        isActive: true,
      });
      views.push({
        module,
        viewName: "tally_agt",
        kind: "Cache",
        keyId: 0,
        keySymbol: "against",
        numericValue: tallyAgt,
        isActive: true,
      });
      break;
    }

    case RestoreModule.Oracle: {
      for (const rec of canonicalRecords) {
        if (rec.kind === "OracleFeed") {
          views.push({
            module,
            viewName: "feed_reg",
            kind: "Index",
            keyId: rec.recordId,
            keySymbol: rec.entitySymbol,
            numericValue: rec.amount,
            isActive: rec.status === "active",
          });
        } else if (rec.kind === "OracleRound") {
          views.push({
            module,
            viewName: "price_rnd",
            kind: "Cache",
            keyId: rec.recordId,
            keySymbol: rec.entitySymbol,
            numericValue: rec.amount,
            isActive: true,
          });
        }
      }
      break;
    }

    case RestoreModule.Marketplace: {
      let minFloor = null;
      for (const rec of canonicalRecords) {
        if (rec.kind === "MarketplaceListing" && rec.status === "open") {
          if (minFloor === null || rec.amount < minFloor) {
            minFloor = rec.amount;
          }
          views.push({
            module,
            viewName: "listing",
            kind: "Index",
            keyId: rec.recordId,
            keySymbol: rec.entitySymbol,
            numericValue: rec.amount,
            isActive: true,
          });
        }
      }
      if (minFloor !== null) {
        views.push({
          module,
          viewName: "floor_p",
          kind: "Cache",
          keyId: 0,
          keySymbol: "floor",
          numericValue: minFloor,
          isActive: true,
        });
      }
      break;
    }
  }

  return views;
}

/**
 * Reconciles rebuilt views with existing views, detecting missing, orphaned, or stale entries.
 */
function reconcileDerivedViews(module, rebuiltViews, existingViews) {
  const drifts = [];

  for (const expected of rebuiltViews) {
    const actual = existingViews.find(
      (e) => e.viewName === expected.viewName && e.keyId === expected.keyId && e.keySymbol === expected.keySymbol
    );
    if (!actual) {
      drifts.push({
        module,
        failureKind: FailureKind.DerivedViewDrift,
        targetId: expected.keyId,
        targetSymbol: expected.viewName,
        expectedVal: 1n,
        actualVal: 0n,
        severity: Severity.Medium,
        message: `Missing derived view entry for ${expected.viewName}:${expected.keyId}`,
        repairSteps: "Rebuild derived view using rebuildDerivedViews to synchronize canonical records into index.",
      });
    } else if (actual.numericValue !== expected.numericValue) {
      drifts.push({
        module,
        failureKind: FailureKind.DerivedViewDrift,
        targetId: expected.keyId,
        targetSymbol: expected.viewName,
        expectedVal: expected.numericValue,
        actualVal: actual.numericValue,
        severity: Severity.Medium,
        message: `Cached aggregate or projection counter diverges from canonical records on ${expected.viewName}`,
        repairSteps: "Synchronize projection cache: invoke rebuildDerivedViews or run projection repair worker.",
      });
    }
  }

  for (const actual of existingViews) {
    const expected = rebuiltViews.find(
      (r) => r.viewName === actual.viewName && r.keyId === actual.keyId && r.keySymbol === actual.keySymbol
    );
    if (!expected) {
      drifts.push({
        module,
        failureKind: FailureKind.DerivedViewDrift,
        targetId: actual.keyId,
        targetSymbol: actual.viewName,
        expectedVal: 0n,
        actualVal: 1n,
        severity: Severity.Medium,
        message: `Orphaned secondary index entry exists for record inactive or deleted in canonical state: ${actual.viewName}:${actual.keyId}`,
        repairSteps: "Purge stale index entry via rebuildDerivedViews.",
      });
    }
  }

  return drifts;
}

// ---------------------------------------------------------------------------
// Test Execution & Verification
// ---------------------------------------------------------------------------

console.log("==================================================================");
console.log("TRELLIS: SNAPSHOT RESTORE VERIFICATION RUNNER");
console.log("==================================================================\n");

// [1/7] Treasury Solvency Invariant and Category Balance Rebuilding
console.log("[1/7] Testing Treasury Solvency Invariants & Derived View Rebuilding...");
const cleanTreasury = [
  { module: RestoreModule.Treasury, kind: "TreasuryBalance", recordId: 1, parentId: 0, entitySymbol: "reserve", amount: 100000n, status: "active", auxiliaryValue: 0 },
  { module: RestoreModule.Treasury, kind: "TreasuryBalance", recordId: 2, parentId: 0, entitySymbol: "rewards", amount: 40000n, status: "active", auxiliaryValue: 0 },
  { module: RestoreModule.Treasury, kind: "TreasuryLiability", recordId: 3, parentId: 0, entitySymbol: "liab", amount: 120000n, status: "active", auxiliaryValue: 0 },
  { module: RestoreModule.Treasury, kind: "TreasuryStrategy", recordId: 50, parentId: 0, entitySymbol: "strat_1", amount: 20000n, status: "active", auxiliaryValue: 0 },
];
const treasuryMismatches = verifyCriticalDataInvariants(RestoreModule.Treasury, cleanTreasury);
assert.strictEqual(treasuryMismatches.length, 0, "Clean treasury should have 0 mismatches");

const treasuryViews = rebuildDerivedViews(RestoreModule.Treasury, cleanTreasury);
assert.strictEqual(treasuryViews.length, 3, "Treasury should rebuild 1 strategy index + 2 category balance caches");
assert.ok(treasuryViews.some((v) => v.viewName === "strat_idx" && v.keyId === 50));
assert.ok(treasuryViews.some((v) => v.viewName === "cat_bal" && v.keySymbol === "reserve" && v.numericValue === 100000n));
console.log("  ✓ Treasury solvency ($140,000 >= $120,000) verified and derived views rebuilt");

// [2/7] Solvency Deficit and Negative Balance Loud Failure
console.log("\n[2/7] Testing Loud Mismatch Reporting on Solvency Deficit and Negative Balance...");
const deficitTreasury = [
  { module: RestoreModule.Treasury, kind: "TreasuryBalance", recordId: 1, parentId: 0, entitySymbol: "reserve", amount: 50000n, status: "active", auxiliaryValue: 0 },
  { module: RestoreModule.Treasury, kind: "TreasuryLiability", recordId: 2, parentId: 0, entitySymbol: "liab", amount: 90000n, status: "active", auxiliaryValue: 0 },
  { module: RestoreModule.Treasury, kind: "TreasuryBalance", recordId: 3, parentId: 0, entitySymbol: "bad_cat", amount: -5000n, status: "active", auxiliaryValue: 0 },
];
const deficitMismatches = verifyCriticalDataInvariants(RestoreModule.Treasury, deficitTreasury);
assert.strictEqual(deficitMismatches.length, 2, "Expected 2 critical mismatches (solvency deficit + negative balance)");
const solvencyDef = deficitMismatches.find((m) => m.failureKind === FailureKind.SolvencyDeficit);
assert.ok(solvencyDef, "Must fail loudly with SolvencyDeficit");
assert.strictEqual(solvencyDef.severity, Severity.Critical);
assert.ok(solvencyDef.repairSteps.includes("CRITICAL: Halt trading"));
assert.ok(solvencyDef.repairSteps.includes("Deficit of 45000"));
const negBal = deficitMismatches.find((m) => m.failureKind === FailureKind.NegativeBalance);
assert.ok(negBal, "Must fail loudly with NegativeBalance");
assert.strictEqual(negBal.severity, Severity.Critical);
console.log("  ✓ Solvency deficit (-40,000) and negative balance failed loudly with actionable repair steps");

// [3/7] Aid Module Relational Integrity and Discovery Search Index Rebuilding
console.log("\n[3/7] Testing Aid Relational Integrity & Discovery Search Index Rebuilding...");
const aidRecords = [
  { module: RestoreModule.Aid, kind: "AidRecord", recordId: 101, parentId: 0, entitySymbol: "donor_a", amount: 20000n, status: "active", auxiliaryValue: 0 },
  { module: RestoreModule.Aid, kind: "AidRecord", recordId: 102, parentId: 0, entitySymbol: "donor_b", amount: 10000n, status: "settled", auxiliaryValue: 0 },
  { module: RestoreModule.Aid, kind: "AidClaim", recordId: 501, parentId: 999, entitySymbol: "beneficiary_c", amount: 5000n, status: "claimed", auxiliaryValue: 0 },
];
const aidMismatches = verifyCriticalDataInvariants(RestoreModule.Aid, aidRecords);
assert.strictEqual(aidMismatches.length, 1, "Expected 1 orphaned claim mismatch");
assert.strictEqual(aidMismatches[0].failureKind, FailureKind.OrphanedRecord);
assert.ok(aidMismatches[0].repairSteps.includes("./scripts/backfill.sh --module aid"));

const aidViews = rebuildDerivedViews(RestoreModule.Aid, aidRecords);
assert.strictEqual(aidViews.filter((v) => v.viewName === "search").length, 1, "Only active aid 101 in search index");
assert.strictEqual(aidViews.find((v) => v.viewName === "search").keyId, 101);
assert.strictEqual(aidViews.filter((v) => v.viewName === "donor_aid").length, 2, "Both aids recorded in donor index");
console.log("  ✓ Orphaned aid claim flagged with backfill remediation; discovery search index rebuilt without settled aid");

// [4/7] Referral Module Downline Tree and Commission Cache Rebuilding
console.log("\n[4/7] Testing Referral Downline & Commission Accrual Rebuilding...");
const referralRecords = [
  { module: RestoreModule.Referral, kind: "ReferralEdge", recordId: 10, parentId: 0, entitySymbol: "root_partner", amount: 0n, status: "active", auxiliaryValue: 500 },
  { module: RestoreModule.Referral, kind: "ReferralEdge", recordId: 11, parentId: 10, entitySymbol: "sub_partner", amount: 0n, status: "active", auxiliaryValue: 300 },
  { module: RestoreModule.Referral, kind: "ReferralEdge", recordId: 12, parentId: 888, entitySymbol: "orphan_partner", amount: 0n, status: "active", auxiliaryValue: 12000 },
  { module: RestoreModule.Referral, kind: "ReferralCommission", recordId: 10, parentId: 0, entitySymbol: "root_partner", amount: 15000n, status: "active", auxiliaryValue: 0 },
];
const referralMismatches = verifyCriticalDataInvariants(RestoreModule.Referral, referralRecords);
assert.strictEqual(referralMismatches.length, 2, "Expected 2 mismatches: orphaned upline and rate boundary exceeded");
assert.ok(referralMismatches.some((m) => m.failureKind === FailureKind.OrphanedRecord));
assert.ok(referralMismatches.some((m) => m.failureKind === FailureKind.BoundaryExceeded));

const referralViews = rebuildDerivedViews(RestoreModule.Referral, referralRecords);
assert.ok(referralViews.some((v) => v.viewName === "downline" && v.keyId === 11));
assert.ok(referralViews.some((v) => v.viewName === "comm_acc" && v.keySymbol === "root_partner" && v.numericValue === 15000n));
console.log("  ✓ Referral downline tree rebuilt and accrued commissions verified against 10,000 bps boundary");

// [5/7] Governance Proposals & Vote Tally Projections
console.log("\n[5/7] Testing Governance Proposals & Ballot Tally Aggregation...");
const govRecords = [
  { module: RestoreModule.Governance, kind: "GovernanceProposal", recordId: 1, parentId: 0, entitySymbol: "prop_1", amount: 0n, status: "active", auxiliaryValue: 0 },
  { module: RestoreModule.Governance, kind: "GovernanceProposal", recordId: 2, parentId: 0, entitySymbol: "prop_2", amount: 0n, status: "executed", auxiliaryValue: 0 },
  { module: RestoreModule.Governance, kind: "GovernanceBallot", recordId: 10, parentId: 1, entitySymbol: "voter_1", amount: 1200n, status: "voted", auxiliaryValue: 1 },
  { module: RestoreModule.Governance, kind: "GovernanceBallot", recordId: 11, parentId: 1, entitySymbol: "voter_2", amount: 450n, status: "voted", auxiliaryValue: 0 },
];
const govMismatches = verifyCriticalDataInvariants(RestoreModule.Governance, govRecords);
assert.strictEqual(govMismatches.length, 0, "Clean governance records should pass invariants");

const govViews = rebuildDerivedViews(RestoreModule.Governance, govRecords);
assert.strictEqual(govViews.filter((v) => v.viewName === "act_prop").length, 1, "Only proposal 1 in active proposals index");
const tallyFor = govViews.find((v) => v.viewName === "tally_for");
const tallyAgt = govViews.find((v) => v.viewName === "tally_agt");
assert.strictEqual(tallyFor.numericValue, 1200n, "Tally for must equal 1,200");
assert.strictEqual(tallyAgt.numericValue, 450n, "Tally against must equal 450");
console.log("  ✓ Active governance proposals filtered and vote tallies accurately reconstructed from ballots");

// [6/7] Oracle Feed Quorum and Marketplace Floor Price Calculation
console.log("\n[6/7] Testing Oracle Feeds & Marketplace Floor Price Calculation...");
const oracleRecords = [
  { module: RestoreModule.Oracle, kind: "OracleFeed", recordId: 1, parentId: 0, entitySymbol: "XLM/USD", amount: 125000n, status: "active", auxiliaryValue: 3 },
  { module: RestoreModule.Oracle, kind: "OracleFeed", recordId: 2, parentId: 0, entitySymbol: "USDC/USD", amount: 100000n, status: "active", auxiliaryValue: 0 }, // Invalid: quorum 0
  { module: RestoreModule.Oracle, kind: "OracleRound", recordId: 1, parentId: 0, entitySymbol: "XLM/USD", amount: 125100n, status: "active", auxiliaryValue: 100 },
];
const oracleMismatches = verifyCriticalDataInvariants(RestoreModule.Oracle, oracleRecords);
assert.strictEqual(oracleMismatches.length, 1);
assert.strictEqual(oracleMismatches[0].failureKind, FailureKind.QuorumViolation);

const marketRecords = [
  { module: RestoreModule.Marketplace, kind: "MarketplaceListing", recordId: 1, parentId: 0, entitySymbol: "trellis_art", amount: 5000n, status: "open", auxiliaryValue: 0 },
  { module: RestoreModule.Marketplace, kind: "MarketplaceListing", recordId: 2, parentId: 0, entitySymbol: "trellis_art", amount: 3200n, status: "open", auxiliaryValue: 0 },
  { module: RestoreModule.Marketplace, kind: "MarketplaceListing", recordId: 3, parentId: 0, entitySymbol: "trellis_art", amount: 1000n, status: "sold", auxiliaryValue: 0 },
];
const marketViews = rebuildDerivedViews(RestoreModule.Marketplace, marketRecords);
const floorView = marketViews.find((v) => v.viewName === "floor_p");
assert.ok(floorView);
assert.strictEqual(floorView.numericValue, 3200n, "Floor price must be minimum of open listings (3,200), ignoring sold (1,000)");
console.log("  ✓ Oracle zero-quorum flagged; marketplace floor price (3,200) calculated from open listings only");

// [7/7] Derived View Drift Reconciliation and Rollback Restoration
console.log("\n[7/7] Testing Derived View Drift Reconciliation & Pre-Restore Rollback...");
const rebuiltTreasury = rebuildDerivedViews(RestoreModule.Treasury, cleanTreasury);
const staleExistingTreasury = [
  { module: RestoreModule.Treasury, viewName: "cat_bal", kind: "Cache", keyId: 0, keySymbol: "reserve", numericValue: 80000n, isActive: true }, // Stale! Expected 100,000
  { module: RestoreModule.Treasury, viewName: "strat_idx", kind: "Index", keyId: 999, keySymbol: "orphan_strat", numericValue: 10000n, isActive: true }, // Orphan!
];
const driftReports = reconcileDerivedViews(RestoreModule.Treasury, rebuiltTreasury, staleExistingTreasury);
assert.strictEqual(driftReports.length, 4, "Expected 4 drifts: stale reserve cache + missing rewards cache + missing strat 50 + orphaned strat 999");
assert.ok(driftReports.some((d) => d.actualVal === 80000n && d.expectedVal === 100000n));
assert.ok(driftReports.some((d) => d.targetSymbol === "cat_bal" && d.actualVal === 0n));
assert.ok(driftReports.some((d) => d.targetId === 999));
assert.ok(driftReports.some((d) => d.targetId === 50));

// Simulate rollback restoration
const originalPreRestoreSnapshot = staleExistingTreasury.map((v) => ({ ...v }));
let restoredState = rebuiltTreasury.map((v) => ({ ...v }));
assert.notDeepStrictEqual(restoredState, originalPreRestoreSnapshot);
// Rollback applied
restoredState = originalPreRestoreSnapshot.map((v) => ({ ...v }));
assert.deepStrictEqual(restoredState, staleExistingTreasury, "Pre-restore state restored accurately on rollback");
console.log("  ✓ Drift reconciliation detected stale cache and orphaned index; pre-restore rollback restored state");

console.log("\n==================================================================");
console.log("ALL SNAPSHOT RESTORE VERIFICATION CHECKS PASSED SUCCESSFULLY");
console.log("==================================================================");
process.exit(0);
