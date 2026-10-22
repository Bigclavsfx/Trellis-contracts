#!/usr/bin/env node
/**
 * Automated Verification Suite for Developer Diagnostics Command
 *
 * Verifies that the developer diagnostics command comprehensively checks:
 * 1. Dependencies and Soroban contract modules (Treasury, Aid, Referral, Governance, Oracle, Marketplace).
 * 2. Environment configuration and strict secret redaction invariants.
 * 3. Network access, RPC probing, external service assumptions, and offline fallback.
 * 4. Seed data fixture validation across all 6 modules.
 * 5. Actionable common failure fixes and remediation generation for all warnings/failures.
 * 6. CLI execution modes (--json, --offline, --strict, --self-test, --module).
 *
 * Usage:
 *   node scripts/verify-developer-diagnostics.cjs
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const DIAGNOSTICS_CLI = path.join(ROOT, "scripts", "developer-diagnostics.cjs");

let passedTests = 0;
let failedTests = 0;

function assert(condition, testName, details = "") {
  if (condition) {
    passedTests++;
    console.log(`  ✓ ${testName}`);
  } else {
    failedTests++;
    console.error(`  ✗ FAIL: ${testName} ${details ? `(${details})` : ""}`);
  }
}

function runDiagnostics(args, extraEnv = {}) {
  const env = { ...process.env, ...extraEnv };
  const res = spawnSync(process.execPath, [DIAGNOSTICS_CLI, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    env,
  });
  return {
    status: res.status,
    stdout: res.stdout || "",
    stderr: res.stderr || "",
  };
}

console.log("==================================================================");
console.log("TRELLIS CONTRACTS: VERIFY DEVELOPER DIAGNOSTICS SUITE");
console.log("==================================================================\n");

// ---------------------------------------------------------------------------
// Suite 1: CLI Execution & JSON Schema Validation
// ---------------------------------------------------------------------------
console.log("[1/6] Verifying CLI Execution & JSON Output Schema...");
{
  const res = runDiagnostics(["--json", "--offline"]);
  assert(res.status === 0, "CLI exits with 0 in standard offline mode");

  let parsed = null;
  try {
    parsed = JSON.parse(res.stdout);
  } catch (err) {
    assert(false, "Output is valid JSON", err.message);
  }

  if (parsed) {
    assert(parsed.isHealthy === true, "Report reports isHealthy = true");
    assert(parsed.isStrict === false, "Report reports isStrict = false");
    assert(typeof parsed.counts === "object", "Report contains counts object");
    assert(parsed.counts.total >= 20, `Report checked ${parsed.counts.total} components (>= 20)`);
    assert(Array.isArray(parsed.results), "Report contains results array");
    assert(Array.isArray(parsed.remediations), "Report contains remediations array");
  }
}

// ---------------------------------------------------------------------------
// Suite 2: Dependencies & All 6 Soroban Contract Modules
// ---------------------------------------------------------------------------
console.log("\n[2/6] Verifying Dependencies & Multi-Module Coverage...");
{
  const res = runDiagnostics(["--json", "--offline"]);
  const report = JSON.parse(res.stdout);
  const results = report.results;

  const requiredModules = ["treasury", "aid", "referral", "governance", "oracle", "marketplace"];
  for (const mod of requiredModules) {
    const modCheck = results.find((r) => r.component === `module:${mod}`);
    assert(modCheck !== undefined, `Module check present for module:${mod}`);
    if (modCheck) {
      assert(modCheck.status === "Passed", `Module ${mod} passes dependency & file structure validation`);
    }
  }

  const sdkCheck = results.find((r) => r.component === "soroban-sdk-workspace-invariant");
  assert(sdkCheck && sdkCheck.status === "Passed", "Soroban SDK 21.x workspace invariant verified");

  const dalekCheck = results.find((r) => r.component === "dalek-crypto-invariant");
  assert(dalekCheck && dalekCheck.status === "Passed", "Cryptographic Dalek pins verified");
}

// ---------------------------------------------------------------------------
// Suite 3: Environment Configuration & Strict Secret Redaction
// ---------------------------------------------------------------------------
console.log("\n[3/6] Verifying Environment Configuration & Secret Redaction Invariant...");
{
  const fakeSecret = "SAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP";
  const res = runDiagnostics(["--json", "--offline"], {
    TRELLIS_SECRET_KEY: fakeSecret,
    STELLAR_NETWORK: "testnet",
    STELLAR_RPC_URL: "https://soroban-testnet.stellar.org",
  });

  assert(!res.stdout.includes(fakeSecret), "CRITICAL: Full secret key is NEVER printed in plain text");
  assert(res.stdout.includes("SAAA...PP"), "Redacted secret preview appears (first4...last2 format)");

  const report = JSON.parse(res.stdout);
  const netCheck = report.results.find((r) => r.component === "env:STELLAR_NETWORK");
  assert(netCheck && netCheck.status === "Passed", "STELLAR_NETWORK=testnet passes validation");

  const rpcCheck = report.results.find((r) => r.component === "env:STELLAR_RPC_URL");
  assert(rpcCheck && rpcCheck.status === "Passed", "STELLAR_RPC_URL format validation passes");
}

// ---------------------------------------------------------------------------
// Suite 4: Network Access & External Service Assumptions
// ---------------------------------------------------------------------------
console.log("\n[4/6] Verifying Network Access & External Service Assumptions...");
{
  // Test offline mode flag
  const resOffline = runDiagnostics(["--json", "--offline"]);
  const reportOffline = JSON.parse(resOffline.stdout);
  const rpcOffline = reportOffline.results.find((r) => r.component === "network:rpc_connectivity");
  assert(rpcOffline && rpcOffline.status === "Passed", "Offline flag (--offline) safely skips live RPC probe");

  // Verify external service assumptions (Oracle feed & Token contracts)
  const oracleAssumption = reportOffline.results.find((r) => r.component === "service:external_oracle_assumptions");
  assert(oracleAssumption && oracleAssumption.status === "Passed", "External oracle service assumption verified");

  const tokenAssumption = reportOffline.results.find((r) => r.component === "service:external_token_assumptions");
  assert(tokenAssumption && tokenAssumption.status === "Passed", "Stellar Asset Contract / token interface assumption verified");
}

// ---------------------------------------------------------------------------
// Suite 5: Seed Data Validation Across All 6 Modules
// ---------------------------------------------------------------------------
console.log("\n[5/6] Verifying Seed Data Validation Across All 6 Modules...");
{
  const res = runDiagnostics(["--json", "--offline"]);
  const report = JSON.parse(res.stdout);
  const results = report.results;

  const seedModules = ["treasury", "aid", "referral", "governance", "oracle", "marketplace"];
  for (const sm of seedModules) {
    const sCheck = results.find((r) => r.component === `seed:${sm}`);
    assert(sCheck !== undefined, `Seed data validation performed for seed:${sm}`);
  }

  // Aid seed data fixture validation
  const aidSeed = results.find((r) => r.component === "seed:aid");
  assert(aidSeed && aidSeed.status === "Passed", "fixtures/backfill/aid.json valid records and schema verified");

  // Treasury seed data detects intentional negative test fixture record
  const treasurySeed = results.find((r) => r.component === "seed:treasury");
  assert(treasurySeed && treasurySeed.status === "Warning", "fixtures/backfill/treasury.json intentional test invalid record safely classified");
}

// ---------------------------------------------------------------------------
// Suite 6: Actionable Failure Fixes & CLI Execution Modes
// ---------------------------------------------------------------------------
console.log("\n[6/6] Verifying Actionable Remediation & CLI Modes...");
{
  const res = runDiagnostics(["--json", "--offline"]);
  const report = JSON.parse(res.stdout);

  assert(report.remediations.length > 0, "Remediations array populated for all warnings/failures");
  for (const rem of report.remediations) {
    assert(
      typeof rem.remediation === "string" && rem.remediation.length > 10,
      `Actionable remediation provided for ${rem.component}`
    );
  }

  // Self-test mode
  const selfTestRes = runDiagnostics(["--self-test"]);
  assert(selfTestRes.status === 0, "Self-test mode (--self-test) runs cleanly");
  assert(selfTestRes.stdout.includes("Self-test completed"), "Self-test emits completion summary");

  // Module filter mode
  const modFilterRes = runDiagnostics(["--json", "--offline", "--module", "aid"]);
  const modReport = JSON.parse(modFilterRes.stdout);
  const aidOnly = modReport.results.filter((r) => r.component.startsWith("module:") || r.component.startsWith("seed:"));
  assert(
    aidOnly.every((r) => r.component.includes("aid")),
    "--module aid correctly filters validation scope"
  );
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log("\n==================================================================");
console.log(`RESULTS: ${passedTests} passed, ${failedTests} failed`);
console.log("==================================================================");

if (failedTests > 0) {
  console.error("\nOne or more developer diagnostics verification checks failed.");
  process.exit(1);
} else {
  console.log("\nAll developer diagnostics verification tests passed successfully!");
  process.exit(0);
}
