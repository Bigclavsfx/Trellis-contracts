# Dependency Health Check Authorization & Retry Budget

`shared::health_guard` (Issue #334) closes two gaps left open by the existing
dependency health/degradation system
(`shared::health`, `shared::degradation`; see
[`docs/EXTERNAL_DEPENDENCY_DEGRADATION_MATRIX.md`](./EXTERNAL_DEPENDENCY_DEGRADATION_MATRIX.md)):

1. **No authorization on health reporting.** `set_dependency_health` and
   `record_dependency_check` take no caller at all. Anything that can reach
   them can report a dependency healthy (silently disabling its fallback
   protection) or down (forcing every caller into fallback or rejection).
2. **No bound on retries.** `DegradationError::CircuitBreakerOpen` (code
   `986`) is declared but nothing ever returns it — there is no limit on how
   many times a caller may fall back to a degraded path before that is
   treated as its own incident.

`shared::health_guard` adds both without changing `shared::health`,
`shared::degradation`, or any contract interface.

## Design in one paragraph

An admin registers the addresses allowed to report health checks
(`register_reporter`). `report_health_check` checks that the caller is
registered and authenticates before forwarding to
`shared::degradation::record_dependency_check` — nothing is recorded on an
unauthorized or unauthenticated call. Separately, `execute_guarded` wraps
`shared::degradation::execute_with_fallback`, intercepting the fallback
closure to call `check_and_record_attempt` first: it tracks attempts in a
rolling `window_ledgers` window per `(module, dependency)` pair, and once
`max_attempts` is exceeded inside that window the breaker trips, rejecting
every further attempt with `Error::OperationPaused`
(`DegradationError::CircuitBreakerOpen`) until `cooldown_ledgers` pass. The
first attempt after the cooldown elapses opens a fresh window rather than
being rejected again — a half-open retry, not a second trip.

## Public surface

| Item | Purpose |
|---|---|
| `register_reporter` / `revoke_reporter` | Admin-gated authorization of health-check reporters. |
| `is_registered_reporter` | Read-only authorization check. |
| `report_health_check` | Authorized, authenticated entry point into `shared::degradation::record_dependency_check`. |
| `get_retry_budget` / `set_retry_budget` | Read/admin-write the per-`(module, dependency)` retry budget (defaults apply when unset). |
| `breaker_state` / `reset_breaker` | Read the current circuit-breaker window, or have an admin clear it immediately. |
| `check_and_record_attempt` | The breaker gate itself; also callable directly by code that doesn't go through `execute_guarded`. |
| `execute_guarded` | Drop-in replacement for `execute_with_fallback` that adds the breaker gate around every fallback invocation. |

## Who can do what

| Action | Required role / condition |
|---|---|
| Register / revoke a reporter | `Role::Admin` |
| Report a health check | Registered reporter, authenticated |
| Read retry budget, breaker state | Anyone (read-only, no auth required) |
| Set retry budget, reset breaker | `Role::Admin` |
| Run guarded primary/fallback logic (`execute_guarded`) | Whatever the caller's own entry point already requires; this module adds no new gate on the primary path |

## Operational edge cases

| Situation | Behavior |
|---|---|
| Unregistered caller reports a health check | `Error::Unauthorized`; `shared::degradation` state is untouched. |
| Registered reporter does not authenticate | `Address::require_auth` traps the transaction before anything is recorded. |
| Fallback invoked `<= max_attempts` times within `window_ledgers` | Each attempt proceeds; the window slides forward once it elapses. |
| Fallback invoked `> max_attempts` times within `window_ledgers` | The breaker trips: this and every subsequent attempt returns `Error::OperationPaused` until the cooldown elapses. |
| First attempt after `cooldown_ledgers` have passed since trip | Treated as a fresh window (half-open): allowed and counted as attempt 1, not rejected again. |
| Admin needs to unblock a dependency immediately | `reset_breaker` clears the window and trip state without waiting for the cooldown. |
| No `RetryBudget` configured for a pair | `get_retry_budget` returns the documented defaults (3 attempts / 120-ledger window / 360-ledger cooldown); behavior is never silently unbounded. |
| `set_retry_budget` with a zero field | `Error::InvalidArgument` — a zero budget/window can never be satisfied, a zero cooldown would never let the breaker recover. |
| Admin revokes a reporter | Idempotent; past reports it already made are unaffected. |
| Primary path is healthy | `execute_guarded` never calls `check_and_record_attempt`; a healthy dependency pays no circuit-breaker cost. |

## Rollback and recovery

This module keeps no history, only current reporter/budget/breaker state, so
recovery means correcting that state rather than undoing a write:

1. **Reporter compromised or misbehaving** (e.g. reporting false failures to
   force a dependency into fallback/rejection, or false successes to mask a
   real outage): call `revoke_reporter` immediately. Its past reports already
   fed into `shared::degradation`'s own counters; use
   `shared::degradation::recover_dependency` (admin-gated) to restore that
   dependency to `Nominal` once its real health is confirmed.
2. **Breaker tripped on a dependency that has actually recovered**: call
   `reset_breaker` rather than waiting out the cooldown.
3. **Retry budget misconfigured** (too tight, causing spurious trips, or too
   loose, letting a failing dependency be hammered repeatedly): call
   `set_retry_budget` with corrected values. It takes effect on the very next
   attempt — the budget is read fresh every call, so there is nothing to
   migrate.

## Compatibility

Purely additive: new storage keys (`HealthGuardKey::Reporter`, `::Budget`,
`::Breaker`), no changes to `shared::health`, `shared::degradation`, or any
contract interface. Existing callers of `record_dependency_check` /
`execute_with_fallback` are unaffected until a contract opts into
`report_health_check` / `execute_guarded` instead.
