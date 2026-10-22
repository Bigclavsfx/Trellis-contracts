#!/usr/bin/env bash
# Trellis contributor diagnostics — local health checks (Issue #67).
#
# One command that checks setup, dependencies, configuration, database state
# (ledger snapshot), and common integration mocks before contributors start.
#
# Usage:
#   ./scripts/diagnostics.sh            # full check, human output
#   ./scripts/diagnostics.sh --json     # machine-readable output
#   ./scripts/diagnostics.sh --self-test# validate fixture wiring (CI)
#
# Guarantees:
# - Never mutates production data (read-only; no deploy/invoke with funding).
# - Every failure prints an actionable remediation line.
# - Exit 0 when all checks pass, 1 otherwise.
set -u

JSON=0
SELF_TEST=0
for arg in "$@"; do
  case "$arg" in
    --json) JSON=1 ;;
    --self-test) SELF_TEST=1 ;;
  esac
done

PASS=0
FAIL=0
RESULTS=""

record() { # record <name> <ok:0|1> <remediation>
  local name="$1" ok="$2" remediation="$3"
  if [ "$ok" -eq 0 ]; then
    PASS=$((PASS+1))
    RESULTS="${RESULTS}PASS ${name}\n"
  else
    FAIL=$((FAIL+1))
    RESULTS="${RESULTS}FAIL ${name} :: ${remediation}\n"
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

check_tool() { # check_tool <cmd> <remediation>
  if have_cmd "$1"; then record "tool:$1" 0 ""; else record "tool:$1" 1 "$2"; fi
}

check_tool rustc "Install Rust 1.85 via rustup: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh; rustup toolchain install 1.85.0"
check_tool cargo "Install cargo via rustup (see above); ensure \$HOME/.cargo/bin is on PATH."
check_tool soroban "Install Soroban CLI: cargo install --locked soroban-cli"
check_tool git "Install git: apt install git / brew install git"

# Rust target (read-only probe, no install)
if rustup target list --installed 2>/dev/null | grep -q "wasm32"; then
  record "target:wasm" 0 ""
else
  record "target:wasm" 1 "Add WASM target: rustup target add wasm32v1-none (repo pins Rust 1.85 in rust-toolchain.toml)"
fi

# Required env vars (presence only; values validated by validate-config.sh)
if [ -n "${STELLAR_NETWORK:-}" ]; then record "env:STELLAR_NETWORK" 0 ""; else record "env:STELLAR_NETWORK" 1 "Set STELLAR_NETWORK=testnet|mainnet|standalone (see docs/CONFIGURATION.md)"; fi
if [ -n "${STELLAR_RPC_URL:-}" ]; then record "env:STELLAR_RPC_URL" 0 ""; else record "env:STELLAR_RPC_URL" 1 "Set STELLAR_RPC_URL=https://... (see docs/CONFIGURATION.md)"; fi
# Secret presence is informational here; never print its value.
if [ -n "${TRELLIS_SECRET_KEY:-}" ]; then record "env:TRELLIS_SECRET_KEY(present)" 0 ""; else record "env:TRELLIS_SECRET_KEY(present)" 1 "Set TRELLIS_SECRET_KEY for deploys only; diagnostics never prints it (see docs/CONFIGURATION.md)"; fi

# Config validator (fail-fast schema check, no secrets printed)
if [ -x "./scripts/validate-config.sh" ]; then
  if ./scripts/validate-config.sh --quiet >/dev/null 2>&1; then
    record "config:validate-config.sh" 0 ""
  else
    record "config:validate-config.sh" 1 "Run ./scripts/validate-config.sh for actionable config errors"
  fi
else
  record "config:validate-config.sh" 1 "Missing scripts/validate-config.sh; pull latest main"
fi

# Service connectivity (read-only RPC probe, short timeout, skipped when offline)
if [ -n "${STELLAR_RPC_URL:-}" ] && have_cmd curl; then
  if curl -fsS --max-time 5 "${STELLAR_RPC_URL}/health" >/dev/null 2>&1 || curl -fsS --max-time 5 "${STELLAR_RPC_URL}" -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth","params":[]}' >/dev/null 2>&1; then
    record "rpc:connectivity" 0 ""
  else
    record "rpc:connectivity" 1 "RPC unreachable at \$STELLAR_RPC_URL; check network/VPN or use standalone: soroban network use standalone"
  fi
else
  record "rpc:connectivity" 1 "Cannot probe RPC: set STELLAR_RPC_URL and install curl"
fi

# Test fixtures / workspace layout (no build, just presence)
for f in Cargo.toml shared/src/lib.rs shared/src/compat.rs shared/src/quota.rs shared/src/config.rs testing/README.md; do
  if [ -e "$f" ]; then record "fixture:$f" 0 ""; else record "fixture:$f" 1 "Missing $f; pull latest main / run git status"; fi
done

# Contract modules (Treasury, Aid, Referral, Governance, Oracle, Marketplace)
for m in treasury-contract aid-contract referral-contract governance-contract oracle-contract nft-marketplace; do
  if [ -e "contracts/$m/Cargo.toml" ] && [ -e "contracts/$m/src/lib.rs" ]; then
    record "module:$m" 0 ""
  else
    record "module:$m" 1 "Missing contract module contracts/$m; pull latest main"
  fi
done

# Seed data fixtures
for s in treasury aid referral governance oracle marketplace; do
  if [ -e "fixtures/backfill/${s}.json" ]; then
    record "seed:${s}" 0 ""
  else
    record "seed:${s}" 1 "Missing seed fixture fixtures/backfill/${s}.json"
  fi
done

if [ "$SELF_TEST" -eq 1 ]; then
  if [ ! -x "$0" ]; then echo "SELF-TEST FAIL: diagnostics.sh not executable"; exit 1; fi
  if [ ! -x "./scripts/validate-config.sh" ]; then echo "SELF-TEST FAIL: validate-config.sh not executable"; exit 1; fi
  echo "SELF-TEST PASS: diagnostics wiring ok (pass=$PASS fail=$FAIL)"
fi

if [ "$JSON" -eq 1 ]; then
  printf '{"pass":%d,"fail":%d}\n' "$PASS" "$FAIL"
else
  printf -- "----------------------------------------\n"
  printf "%b" "$RESULTS"
  printf -- "----------------------------------------\n"
  printf "Diagnostics: %d passed, %d failed\n" "$PASS" "$FAIL"
  if [ "$FAIL" -gt 0 ]; then
    printf "Remediation: fix each FAIL line above, then re-run ./scripts/diagnostics.sh\n"
  else
    printf "All checks passed. Run: cargo test --workspace\n"
  fi
fi

[ "$FAIL" -eq 0 ]
