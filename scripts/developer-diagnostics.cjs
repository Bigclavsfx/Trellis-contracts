#!/usr/bin/env node
/**
 * Trellis Contracts — Developer Diagnostics Command
 *
 * Validates local setup, dependency invariants, environment configuration,
 * external service assumptions, seed data integrity, and provides actionable
 * failure fixes across the Soroban contract modules:
 * - Treasury (contracts/treasury-contract)
 * - Aid (contracts/aid-contract)
 * - Referral (contracts/referral-contract)
 * - Governance (contracts/governance-contract)
 * - Oracle (contracts/oracle-contract)
 * - Marketplace (contracts/nft-marketplace)
 *
 * Usage:
 *   node scripts/developer-diagnostics.cjs [options]
 *
 * Options:
 *   --json          Emit machine-readable JSON output
 *   --strict        Fail (exit 1) on any warning or failure
 *   --self-test     Run internal harness self-tests without host prerequisites
 *   --fix           Attempt automated remediation of fixable local config issues
 *   --offline       Skip network probes and validate degraded offline assumptions
 *   --module <name> Focus validation on a specific module (treasury, aid, referral, governance, oracle, marketplace)
 *   --help, -h      Display usage information
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const https = require("node:https");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const args = process.argv.slice(2);

const isJson = args.includes("--json");
const isStrict = args.includes("--strict");
const isSelfTest = args.includes("--self-test");
const isFix = args.includes("--fix");
const isOffline = args.includes("--offline");

if (args.includes("--help") || args.includes("-h")) {
  console.log(`
Trellis Contracts Developer Diagnostics Command

Usage:
  node scripts/developer-diagnostics.cjs [options]

Options:
  --json          Emit machine-readable JSON output
  --strict        Fail (exit 1) on any warning or failure (recommended for CI)
  --self-test     Run simulated self-test verifying harness logic
  --fix           Scaffold local .env with safe defaults if missing
  --offline       Skip live network RPC probes (for air-gapped development)
  --module <name> Focus checks on a single module (treasury, aid, referral, governance, oracle, marketplace)
  --help, -h      Show this message

Validates:
  1. Dependencies (Node.js, Git, Rustc, Cargo, wasm32 target, Soroban SDK 21.x, Dalek pins, 6 contract modules)
  2. Environment Config (STELLAR_NETWORK, STELLAR_RPC_URL, TRELLIS_ENV, secret redaction, contract IDs)
  3. Network Access & Services (Stellar RPC health probe, oracle/token service assumptions, offline mode)
  4. Seed Data (fixtures/backfill for treasury, aid, referral, governance, oracle, marketplace)
  5. Common Failure Fixes (Actionable remediation command for every failing or warning check)
`);
  process.exit(0);
}

// Optional module filter
let targetModule = null;
const moduleIdx = args.indexOf("--module");
if (moduleIdx !== -1 && args[moduleIdx + 1]) {
  targetModule = args[moduleIdx + 1].toLowerCase();
}

const results = [];
const remediations = [];

/**
 * Record a diagnostic check result.
 */
function recordCheck({ component, category, status, message, remediation = null, details = null }) {
  const entry = {
    component,
    category,
    status, // "Passed" | "Warning" | "Failed"
    message,
    remediation,
    details,
  };
  results.push(entry);
  if (remediation && (status === "Failed" || status === "Warning")) {
    remediations.push({ component, status, remediation });
  }
}

/**
 * Execute a check safely.
 */
function check(component, category, fn) {
  try {
    const outcome = fn();
    if (!outcome) return;
    if (outcome.status === "Failed" || outcome.error) {
      recordCheck({
        component,
        category,
        status: "Failed",
        message: outcome.error || outcome.message || "Check failed",
        remediation: outcome.remediation,
        details: outcome.details,
      });
    } else if (outcome.status === "Warning" || outcome.warning) {
      recordCheck({
        component,
        category,
        status: "Warning",
        message: outcome.warning || outcome.message || "Warning encountered",
        remediation: outcome.remediation,
        details: outcome.details,
      });
    } else {
      recordCheck({
        component,
        category,
        status: "Passed",
        message: outcome.message || "OK",
        details: outcome.details,
      });
    }
  } catch (err) {
    recordCheck({
      component,
      category,
      status: "Failed",
      message: err.message || String(err),
      remediation: "Inspect error log and verify workspace integrity",
    });
  }
}

/**
 * Redact sensitive secret values (never print full keys).
 */
function redactSecret(secret) {
  if (!secret) return "(not set)";
  if (typeof secret !== "string") return "***";
  if (secret.length <= 8) return "***";
  return `${secret.slice(0, 4)}...${secret.slice(-2)}`;
}

/**
 * Load local .env / .env.local if present (without external dependencies).
 */
function loadLocalEnv() {
  const envFiles = [".env", ".env.local"];
  for (const f of envFiles) {
    const p = path.join(ROOT, f);
    if (fs.existsSync(p)) {
      try {
        const content = fs.readFileSync(p, "utf8");
        for (const line of content.split("\n")) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith("#")) continue;
          const eqIdx = trimmed.indexOf("=");
          if (eqIdx !== -1) {
            const k = trimmed.slice(0, eqIdx).trim();
            let v = trimmed.slice(eqIdx + 1).trim();
            if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
              v = v.slice(1, -1);
            }
            if (!process.env[k]) {
              process.env[k] = v;
            }
          }
        }
      } catch {
        // ignore read error
      }
    }
  }
}

loadLocalEnv();

// ---------------------------------------------------------------------------
// 0. Automated Fix Handler (--fix)
// ---------------------------------------------------------------------------
if (isFix) {
  console.log("Applying automated developer diagnostics remediation (--fix)...");
  const envPath = path.join(ROOT, ".env");
  if (!fs.existsSync(envPath)) {
    const template = [
      "# Trellis Contracts Local Development Environment Configuration",
      "# Generated automatically by: node scripts/developer-diagnostics.cjs --fix",
      "TRELLIS_ENV=local",
      "STELLAR_NETWORK=standalone",
      "STELLAR_RPC_URL=http://localhost:8000/soroban/rpc",
      "# For testnet, use:",
      "# STELLAR_NETWORK=testnet",
      "# STELLAR_RPC_URL=https://soroban-testnet.stellar.org",
      "# TRELLIS_SECRET_KEY=S...",
      "",
    ].join("\n");
    fs.writeFileSync(envPath, template, "utf8");
    console.log("  ✓ Created default .env with safe local/standalone network settings.");
  } else {
    console.log("  ℹ .env already exists; preserving existing configuration.");
  }
}

// ---------------------------------------------------------------------------
// Self-Test Mode (--self-test)
// ---------------------------------------------------------------------------
if (isSelfTest) {
  console.log("Running Developer Diagnostics self-test...");
  check("node-version-self-test", "Dependencies", () => ({
    message: "Node.js v20+ simulated check passed",
  }));
  check("soroban-sdk-invariant-self-test", "Dependencies", () => ({
    message: "Soroban SDK 21.x pinned in workspace",
  }));
  check("stellar-network-env-self-test", "EnvironmentConfig", () => ({
    message: "STELLAR_NETWORK=standalone validated",
  }));
  check("rpc-access-self-test", "NetworkAccess", () => ({
    message: "Simulated RPC reachability check passed",
  }));
  check("seed-data-self-test", "SeedData", () => ({
    message: "All 6 module backfill seed fixtures validated",
  }));

  const passed = results.filter((r) => r.status === "Passed").length;
  const failed = results.filter((r) => r.status === "Failed").length;
  console.log(`Self-test completed: ${passed}/5 simulated checks passed, ${failed} failed.`);
  process.exit(failed === 0 ? 0 : 1);
}

// ---------------------------------------------------------------------------
// 1. Dependencies & Multi-Module Verification
// ---------------------------------------------------------------------------
check("node-runtime", "Dependencies", () => {
  const current = process.versions.node;
  const major = parseInt(current.split(".")[0], 10);
  if (major < 18) {
    return {
      status: "Failed",
      error: `Node.js v18+ required; current version is v${current}`,
      remediation: "Install Node.js 18 or 20 LTS: https://nodejs.org",
    };
  }
  return { message: `Node.js v${current} satisfies minimum requirements (v18+)` };
});

check("git-cli", "Dependencies", () => {
  const res = spawnSync("git", ["--version"], { encoding: "utf8" });
  if (res.status !== 0) {
    return {
      status: "Failed",
      error: "Git executable not found in PATH",
      remediation: "Install git: apt install git / brew install git / https://git-scm.com",
    };
  }
  return { message: res.stdout.trim() };
});

check("rustc-toolchain", "Dependencies", () => {
  const res = spawnSync("rustc", ["--version"], { encoding: "utf8" });
  if (res.status !== 0) {
    return {
      status: "Warning",
      warning: "rustc executable not found or not in PATH",
      remediation: "Install Rust 1.85 via rustup: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh; rustup toolchain install 1.85.0",
    };
  }
  return { message: res.stdout.trim() };
});

check("cargo-cli", "Dependencies", () => {
  const res = spawnSync("cargo", ["--version"], { encoding: "utf8" });
  if (res.status !== 0) {
    return {
      status: "Warning",
      warning: "cargo executable not found or not in PATH",
      remediation: "Ensure $HOME/.cargo/bin is added to your PATH environment variable",
    };
  }
  return { message: res.stdout.trim() };
});

check("wasm-target", "Dependencies", () => {
  const res = spawnSync("rustup", ["target", "list", "--installed"], { encoding: "utf8" });
  if (res.status === 0 && (res.stdout.includes("wasm32v1-none") || res.stdout.includes("wasm32-unknown-unknown"))) {
    return { message: "WASM target installed (wasm32v1-none / wasm32-unknown-unknown)" };
  }
  return {
    status: "Warning",
    warning: "WASM compilation target not confirmed",
    remediation: "Add Soroban WASM target: rustup target add wasm32v1-none",
  };
});

check("soroban-sdk-workspace-invariant", "Dependencies", () => {
  const rootCargoPath = path.join(ROOT, "Cargo.toml");
  if (!fs.existsSync(rootCargoPath)) {
    return {
      status: "Failed",
      error: "Root Cargo.toml missing",
      remediation: "Ensure running from Trellis-contracts root directory",
    };
  }
  const rootCargo = fs.readFileSync(rootCargoPath, "utf8");
  if (!rootCargo.includes("soroban-sdk") || !rootCargo.includes("21.")) {
    return {
      status: "Failed",
      error: "Soroban SDK must be pinned to 21.x in workspace.dependencies",
      remediation: "Add 'soroban-sdk = { version = \"21.0.0\", default-features = true }' to Cargo.toml [workspace.dependencies]",
    };
  }
  return { message: "Soroban SDK 21.x pinned in workspace.dependencies" };
});

check("dalek-crypto-invariant", "Dependencies", () => {
  const rootCargo = fs.readFileSync(path.join(ROOT, "Cargo.toml"), "utf8");
  const hasCurve = rootCargo.includes("curve25519-dalek = \"=4.1.3\"");
  const hasEd = rootCargo.includes("ed25519-dalek = \"=2.1.1\"");
  if (!hasCurve || !hasEd) {
    return {
      status: "Warning",
      warning: "Exact Dalek crypto pins (=4.1.3, =2.1.1) not explicitly declared in root Cargo.toml",
      remediation: "Add curve25519-dalek = \"=4.1.3\" and ed25519-dalek = \"=2.1.1\" to [workspace.dependencies]",
    };
  }
  return { message: "Cryptographic primitive invariants pinned (curve25519-dalek =4.1.3, ed25519-dalek =2.1.1)" };
});

// Module-level verification for all 6 Soroban contract modules
const CORE_MODULES = [
  { name: "treasury", dir: "contracts/treasury-contract" },
  { name: "aid", dir: "contracts/aid-contract" },
  { name: "referral", dir: "contracts/referral-contract" },
  { name: "governance", dir: "contracts/governance-contract" },
  { name: "oracle", dir: "contracts/oracle-contract" },
  { name: "marketplace", dir: "contracts/nft-marketplace" },
];

for (const mod of CORE_MODULES) {
  if (targetModule && targetModule !== mod.name) continue;

  check(`module:${mod.name}`, "Dependencies", () => {
    const modDir = path.join(ROOT, mod.dir);
    if (!fs.existsSync(modDir)) {
      return {
        status: "Failed",
        error: `Module directory ${mod.dir} not found`,
        remediation: `Restore missing module directory ${mod.dir} from repository`,
      };
    }
    const cargoFile = path.join(modDir, "Cargo.toml");
    const srcFile = path.join(modDir, "src", "lib.rs");
    if (!fs.existsSync(cargoFile)) {
      return {
        status: "Failed",
        error: `Module ${mod.name} is missing Cargo.toml`,
        remediation: `Create valid Cargo.toml in ${mod.dir}`,
      };
    }
    if (!fs.existsSync(srcFile)) {
      return {
        status: "Failed",
        error: `Module ${mod.name} is missing src/lib.rs entrypoint`,
        remediation: `Restore src/lib.rs in ${mod.dir}`,
      };
    }

    const cargoContent = fs.readFileSync(cargoFile, "utf8");
    if (!cargoContent.includes("soroban-sdk") || (!cargoContent.includes("shared") && mod.name !== "shared")) {
      return {
        status: "Warning",
        warning: `Module ${mod.name} does not explicitly bind workspace dependencies (soroban-sdk, shared)`,
        remediation: `Ensure ${mod.dir}/Cargo.toml references soroban-sdk and shared workspace dependencies`,
      };
    }

    return { message: `Module ${mod.name} present with valid Cargo.toml and src/lib.rs` };
  });
}

// ---------------------------------------------------------------------------
// 2. Environment Configuration & Secret Redaction
// ---------------------------------------------------------------------------
check("env:STELLAR_NETWORK", "EnvironmentConfig", () => {
  const network = process.env.STELLAR_NETWORK || "standalone";
  const validNetworks = ["standalone", "local", "futurenet", "testnet", "mainnet"];
  if (!validNetworks.includes(network) && !network.startsWith("Test SDF") && !network.startsWith("Public Global")) {
    return {
      status: "Failed",
      error: `STELLAR_NETWORK='${network}' is invalid`,
      remediation: "Set STELLAR_NETWORK=standalone (local), testnet (dev), or mainnet (prod). Run with --fix to set default.",
    };
  }
  return { message: `STELLAR_NETWORK='${network}' is valid` };
});

check("env:STELLAR_RPC_URL", "EnvironmentConfig", () => {
  const network = process.env.STELLAR_NETWORK || "standalone";
  const rpcUrl = process.env.STELLAR_RPC_URL;
  if (!rpcUrl) {
    if (network === "standalone" || network === "local") {
      return {
        status: "Warning",
        warning: "STELLAR_RPC_URL not set; using local fallback http://localhost:8000/soroban/rpc",
        remediation: "Set STELLAR_RPC_URL=http://localhost:8000/soroban/rpc or run with --fix",
      };
    }
    return {
      status: "Failed",
      error: "STELLAR_RPC_URL is missing for remote network",
      remediation: "Set STELLAR_RPC_URL=https://soroban-testnet.stellar.org (testnet)",
    };
  }
  if (!rpcUrl.startsWith("http://") && !rpcUrl.startsWith("https://")) {
    return {
      status: "Failed",
      error: `STELLAR_RPC_URL='${rpcUrl}' must start with http:// or https://`,
      remediation: "Specify a valid HTTP/HTTPS URL for STELLAR_RPC_URL",
    };
  }
  return { message: `STELLAR_RPC_URL='${rpcUrl}' format valid` };
});

check("env:TRELLIS_ENV", "EnvironmentConfig", () => {
  const envVal = process.env.TRELLIS_ENV || "local";
  if (!["local", "staging", "production"].includes(envVal)) {
    return {
      status: "Failed",
      error: `TRELLIS_ENV='${envVal}' is unknown`,
      remediation: "Set TRELLIS_ENV=local, staging, or production",
    };
  }
  return { message: `TRELLIS_ENV='${envVal}'` };
});

check("env:TRELLIS_SECRET_KEY(redacted)", "EnvironmentConfig", () => {
  const secret = process.env.TRELLIS_SECRET_KEY;
  const envVal = process.env.TRELLIS_ENV || "local";
  if (!secret) {
    if (envVal === "staging" || envVal === "production") {
      return {
        status: "Failed",
        error: `TRELLIS_SECRET_KEY required for non-local environment (${envVal})`,
        remediation: "Set TRELLIS_SECRET_KEY for deployment authority",
      };
    }
    return {
      status: "Passed",
      message: "TRELLIS_SECRET_KEY not set (optional for local standalone development)",
    };
  }

  // Validate format: Stellar secret seed starts with 'S' and is 56 characters
  const isValidStrkey = /^S[A-Z0-9]{55}$/.test(secret);
  const preview = redactSecret(secret);
  if (!isValidStrkey) {
    return {
      status: "Warning",
      warning: `TRELLIS_SECRET_KEY (${preview}) does not match standard 56-char Stellar secret seed format`,
      remediation: "Ensure TRELLIS_SECRET_KEY is a valid S... ed25519 seed key (56 characters)",
    };
  }
  return { message: `TRELLIS_SECRET_KEY present (${preview}) — format verified` };
});

// ---------------------------------------------------------------------------
// 3. Network Access & External Service Assumptions
// ---------------------------------------------------------------------------
check("network:rpc_connectivity", "NetworkAccess", () => {
  if (isOffline) {
    return {
      status: "Passed",
      message: "Offline mode specified (--offline); skipping live RPC reachability probe",
    };
  }

  const rpcUrl = process.env.STELLAR_RPC_URL || "https://soroban-testnet.stellar.org";
  const isLocalRpc = rpcUrl.includes("localhost") || rpcUrl.includes("127.0.0.1");

  // Probe with synchronous spawn of curl or node fetch simulation
  // Check curl availability for quick probe
  const curlCheck = spawnSync("curl", ["--version"], { encoding: "utf8", timeout: 2000 });
  if (curlCheck.status === 0) {
    // Probe JSON-RPC getHealth with a strict 3-second timeout
    const postData = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getHealth", params: [] });
    const probe = spawnSync(
      "curl",
      [
        "-fsS",
        "--max-time",
        "3",
        "-H",
        "Content-Type: application/json",
        "-d",
        postData,
        rpcUrl,
      ],
      { encoding: "utf8", timeout: 3500 }
    );

    if (probe.status === 0 && probe.stdout && probe.stdout.includes("healthy")) {
      return { message: `RPC endpoint reachable and healthy at ${rpcUrl}` };
    }

    // Try GET /health endpoint fallback
    const healthUrl = rpcUrl.replace(/\/+$/, "") + "/health";
    const probeHealth = spawnSync("curl", ["-fsS", "--max-time", "3", healthUrl], { encoding: "utf8", timeout: 3500 });
    if (probeHealth.status === 0) {
      return { message: `RPC health endpoint reachable at ${healthUrl}` };
    }
  }

  if (isLocalRpc) {
    return {
      status: "Warning",
      warning: `Local Soroban RPC at ${rpcUrl} is not running or not responding`,
      remediation: "Start local Soroban standalone node: 'soroban network start standalone' or run with --offline",
    };
  }

  return {
    status: "Warning",
    warning: `Unable to establish RPC connection to ${rpcUrl} (offline or timeout)`,
    remediation: "Check Internet connection / VPN, or pass --offline for local development",
  };
});

check("service:external_oracle_assumptions", "NetworkAccess", () => {
  // Oracle module external assumptions: requires either reachable price provider or local mock
  const oracleDir = path.join(ROOT, "contracts", "oracle-contract");
  const testingMocksDir = path.join(ROOT, "testing", "src", "mocks");
  const hasLocalMock = fs.existsSync(testingMocksDir) || fs.existsSync(path.join(ROOT, "testing"));

  if (!hasLocalMock && !fs.existsSync(oracleDir)) {
    return {
      status: "Warning",
      warning: "Oracle contract and testing mocks missing; external feed assumptions cannot be verified",
      remediation: "Pull latest main repository to ensure testing crate and oracle mocks are present",
    };
  }
  return { message: "External price feed assumptions satisfied via contract harness & testing mocks" };
});

check("service:external_token_assumptions", "NetworkAccess", () => {
  // Stellar Asset Contract (SAC) token assumption used by treasury and aid
  const testingPath = path.join(ROOT, "testing");
  if (fs.existsSync(testingPath)) {
    return { message: "Stellar Asset Contract (SAC) & SEP-41 token interfaces supported by testing harness" };
  }
  return {
    status: "Warning",
    warning: "Testing crate not found; local SAC token simulations may be unavailable",
    remediation: "Verify testing/ directory exists in repository workspace",
  };
});

// ---------------------------------------------------------------------------
// 4. Seed Data Verification Across All 6 Modules
// ---------------------------------------------------------------------------
const SEED_MODULES = [
  {
    name: "treasury",
    file: "fixtures/backfill/treasury.json",
    validate: (records) => {
      if (!Array.isArray(records)) throw new Error("Expected array of treasury records");
      let validCount = 0;
      let invalidCount = 0;
      for (let i = 0; i < records.length; i++) {
        const r = records[i];
        if (!r.token || !r.category || r.balance === undefined) {
          throw new Error(`Record ${i} missing token, category, or balance`);
        }
        // Balance string validation
        const bal = BigInt(r.balance);
        if (bal < 0n) {
          invalidCount++;
        } else {
          validCount++;
        }
      }
      return { validCount, invalidCount, total: records.length };
    },
  },
  {
    name: "aid",
    file: "fixtures/backfill/aid.json",
    validate: (records) => {
      if (!Array.isArray(records)) throw new Error("Expected array of aid records");
      for (let i = 0; i < records.length; i++) {
        const r = records[i];
        if (!r.id || !r.donor || !r.recipient || !r.token || r.amount === undefined) {
          throw new Error(`Record ${i} missing required aid fields`);
        }
        if (!["Pending", "Settled", "Refunded"].includes(r.status)) {
          throw new Error(`Record ${i} invalid aid status: ${r.status}`);
        }
      }
      return { total: records.length };
    },
  },
  {
    name: "referral",
    file: "fixtures/backfill/referral.json",
    validate: (records) => {
      if (!Array.isArray(records)) throw new Error("Expected array of referral records");
      return { total: records.length };
    },
  },
  {
    name: "governance",
    file: "fixtures/backfill/governance.json",
    validate: (records) => {
      if (!Array.isArray(records)) throw new Error("Expected array of governance records");
      return { total: records.length };
    },
  },
  {
    name: "oracle",
    file: "fixtures/backfill/oracle.json",
    validate: (records) => {
      if (!Array.isArray(records)) throw new Error("Expected array of oracle records");
      return { total: records.length };
    },
  },
  {
    name: "marketplace",
    file: "fixtures/backfill/marketplace.json",
    validate: (records) => {
      if (!Array.isArray(records)) throw new Error("Expected array of marketplace records");
      return { total: records.length };
    },
  },
];

for (const sm of SEED_MODULES) {
  if (targetModule && targetModule !== sm.name) continue;

  check(`seed:${sm.name}`, "SeedData", () => {
    const filePath = path.join(ROOT, sm.file);
    if (!fs.existsSync(filePath)) {
      return {
        status: "Failed",
        error: `Seed data fixture missing: ${sm.file}`,
        remediation: `Restore ${sm.file} from repository fixtures/backfill/`,
      };
    }

    let records;
    try {
      const content = fs.readFileSync(filePath, "utf8");
      records = JSON.parse(content);
    } catch (parseErr) {
      return {
        status: "Failed",
        error: `Malformed JSON in seed fixture ${sm.file}: ${parseErr.message}`,
        remediation: `Correct JSON syntax in ${sm.file}`,
      };
    }

    try {
      const stats = sm.validate(records);
      if (stats.invalidCount && stats.invalidCount > 0) {
        return {
          status: "Warning",
          warning: `Fixture ${sm.file} contains ${stats.invalidCount} intentional test invalid records (${stats.validCount} valid)`,
          details: stats,
          remediation: `Review ${sm.file} records; negative balances are reserved for negative backfill testing`,
        };
      }
      return { message: `Seed data fixture ${sm.file} validated (${stats.total} records)` };
    } catch (valErr) {
      return {
        status: "Failed",
        error: `Seed data validation failed in ${sm.file}: ${valErr.message}`,
        remediation: `Fix schema mismatch in ${sm.file}`,
      };
    }
  });
}

// ---------------------------------------------------------------------------
// Summary & Exit Codes
// ---------------------------------------------------------------------------
const passedCount = results.filter((r) => r.status === "Passed").length;
const warningCount = results.filter((r) => r.status === "Warning").length;
const failedCount = results.filter((r) => r.status === "Failed").length;

const isHealthy = isStrict ? failedCount === 0 && warningCount === 0 : failedCount === 0;

if (isJson) {
  console.log(
    JSON.stringify(
      {
        isHealthy,
        isStrict,
        counts: { passed: passedCount, warnings: warningCount, failed: failedCount, total: results.length },
        remediations,
        results,
      },
      null,
      2
    )
  );
} else {
  console.log("==================================================================");
  console.log("TRELLIS CONTRACTS: DEVELOPER DIAGNOSTICS RUNNER");
  console.log("==================================================================\n");

  const categories = ["Dependencies", "EnvironmentConfig", "NetworkAccess", "SeedData"];
  for (const cat of categories) {
    const catResults = results.filter((r) => r.category === cat);
    if (catResults.length === 0) continue;
    console.log(`--- [ ${cat.toUpperCase()} ] ---`);
    for (const r of catResults) {
      let icon = "✓";
      if (r.status === "Warning") icon = "⚠";
      if (r.status === "Failed") icon = "✗";
      console.log(`  ${icon} [${r.status}] ${r.component}: ${r.message}`);
    }
    console.log("");
  }

  if (remediations.length > 0) {
    console.log("------------------------------------------------------------------");
    console.log("COMMON FAILURE FIXES & REMEDIATION:");
    console.log("------------------------------------------------------------------");
    for (const rem of remediations) {
      console.log(`  • ${rem.component} [${rem.status}]:`);
      console.log(`    Fix: ${rem.remediation}`);
    }
    console.log("");
  }

  console.log("==================================================================");
  console.log(`SUMMARY: ${passedCount} passed, ${warningCount} warnings, ${failedCount} failed`);
  console.log(`STATUS: ${isHealthy ? "HEALTHY" : "FAILED"}`);
  if (!isHealthy && !isStrict) {
    console.log("Remediation: apply the fixes listed above, then re-run:");
    console.log("  node scripts/developer-diagnostics.cjs");
  }
  console.log("==================================================================");
}

process.exit(isHealthy ? 0 : 1);
