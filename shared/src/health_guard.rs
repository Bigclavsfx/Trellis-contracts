//! Authorized health-check reporting and a retry/circuit-breaker budget for
//! degraded-mode fallback execution (Issue #334).
//!
//! `shared::health` already records raw dependency status and
//! `shared::degradation` already derives a [`DegradationLevel`] and a safe
//! [`FallbackStrategy`] from it (see `docs/EXTERNAL_DEPENDENCY_DEGRADATION_MATRIX.md`).
//! This module closes two gaps that system leaves open:
//!
//! - **Authorization.** Every write path in `shared::health` /
//!   `shared::degradation` (`set_dependency_health`, `record_dependency_check`)
//!   takes no caller at all — any code that can reach them can report a
//!   dependency healthy (silently disabling its fallback protection) or down
//!   (forcing every caller into fallback/rejection). [`report_health_check`]
//!   requires the caller to be an admin-registered reporter and to
//!   authenticate before a report is accepted.
//! - **Retry / circuit breaker.** `DegradationError::CircuitBreakerOpen` is
//!   declared in `shared::degradation` but nothing ever returns it — there is
//!   no bound on how many times a caller may fall back to a degraded path.
//!   [`execute_guarded`] wraps `shared::degradation::execute_with_fallback`
//!   and enforces a bounded [`RetryBudget`]: once a dependency's fallback is
//!   invoked more than `max_attempts` times inside `window_ledgers`, the
//!   breaker trips and every further attempt is rejected with
//!   `DegradationError::CircuitBreakerOpen` (mapped to [`Error::OperationPaused`])
//!   until `cooldown_ledgers` pass, at which point the next attempt resets the
//!   window instead of being rejected.
//!
//! Neither change touches `shared::health` or `shared::degradation`: this
//! module composes with their existing public functions and adds nothing to
//! their storage or control flow. A contract adopts it by calling
//! [`report_health_check`] instead of `record_dependency_check` directly, and
//! [`execute_guarded`] instead of `execute_with_fallback` directly; both
//! existing functions remain available and unchanged for callers that don't
//! need the extra gating.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | Unregistered caller reports a health check | `Error::Unauthorized`; `shared::degradation` state is untouched. |
//! | Registered reporter does not authenticate | `Address::require_auth` traps the transaction before anything is recorded. |
//! | Fallback invoked `<= max_attempts` times within `window_ledgers` | Each attempt proceeds; the window slides forward on the next report after it elapses. |
//! | Fallback invoked `> max_attempts` times within `window_ledgers` | The breaker trips: this and every subsequent attempt returns `Error::OperationPaused` until the cooldown elapses. |
//! | First attempt after `cooldown_ledgers` have passed since trip | Treated as a fresh window (half-open): the attempt is allowed and counted as attempt 1 of a new window rather than rejected again. |
//! | Admin needs to unblock a dependency immediately | [`reset_breaker`] clears the window and trip state without waiting for the cooldown. |
//! | No `RetryBudget` configured for a `(module, dependency)` pair | [`get_retry_budget`] returns the documented defaults; behavior is never silently "unbounded". |
//! | `set_retry_budget` with a zero field | `Error::InvalidArgument` — a zero budget, window, or cooldown can never be satisfied or would never recover. |
//! | Admin revokes a reporter | Idempotent; past reports already recorded in `shared::degradation` are unaffected. |
//!
//! ## Recovery / rollback
//!
//! This module keeps no history, only current breaker/reporter/budget state,
//! so "rollback" means resetting that state rather than undoing a write:
//!
//! 1. **Reporter compromised or misbehaving** (e.g. reporting false
//!    failures to force a dependency into fallback/rejection): call
//!    [`revoke_reporter`] immediately. Past reports it made already fed into
//!    `shared::degradation`'s own counters; use `shared::degradation::recover_dependency`
//!    (admin-gated) to restore that dependency to `Nominal` once its real
//!    health is confirmed.
//! 2. **Breaker tripped on a dependency that has actually recovered**: call
//!    [`reset_breaker`] rather than waiting out the cooldown.
//! 3. **Retry budget misconfigured** (too tight, causing spurious trips, or
//!    too loose, letting a failing dependency be hammered): call
//!    [`set_retry_budget`] with corrected values; it takes effect on the next
//!    attempt, no migration needed since the stored budget is read fresh
//!    every time.
//!
//! ## Compatibility
//!
//! Purely additive: new storage keys, no changes to `shared::health`,
//! `shared::degradation`, or any contract interface. Existing callers of
//! `record_dependency_check` / `execute_with_fallback` are unaffected until a
//! contract opts into the gated entry points this module adds.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol};

use crate::auth::{has_role, Role};
use crate::degradation::{
    execute_with_fallback, record_dependency_check, DegradationError, DegradationLevel,
    DegradationModule, ExternalDependencyKind, FallbackStrategy,
};
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_has, persistent_remove, persistent_set};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default number of fallback attempts allowed inside one window before the
/// breaker trips.
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;

/// Default retry window, in ledgers (~10 minutes at 5s/ledger).
pub const DEFAULT_RETRY_WINDOW_LEDGERS: u32 = 120;

/// Default cooldown after a trip before the window resets, in ledgers
/// (~30 minutes at 5s/ledger).
pub const DEFAULT_RETRY_COOLDOWN_LEDGERS: u32 = 360;

/// Event topic for reporter-registry and circuit-breaker events.
pub const TOPIC_HEALTH_GUARD: Symbol = symbol_short!("hguard");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How many fallback attempts a `(module, dependency)` pair tolerates inside
/// `window_ledgers` before the breaker trips, and how long it stays tripped.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryBudget {
    pub max_attempts: u32,
    pub window_ledgers: u32,
    pub cooldown_ledgers: u32,
}

fn default_retry_budget() -> RetryBudget {
    RetryBudget {
        max_attempts: DEFAULT_RETRY_ATTEMPTS,
        window_ledgers: DEFAULT_RETRY_WINDOW_LEDGERS,
        cooldown_ledgers: DEFAULT_RETRY_COOLDOWN_LEDGERS,
    }
}

/// Current retry/circuit-breaker window for one `(module, dependency)` pair.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitBreakerState {
    pub module: DegradationModule,
    pub dependency: ExternalDependencyKind,
    pub window_start_ledger: u32,
    pub attempts_in_window: u32,
    pub tripped: bool,
    pub trip_ledger: u32,
}

fn default_breaker_state(
    module: DegradationModule,
    dependency: ExternalDependencyKind,
    ledger: u32,
) -> CircuitBreakerState {
    CircuitBreakerState {
        module,
        dependency,
        window_start_ledger: ledger,
        attempts_in_window: 0,
        tripped: false,
        trip_ledger: 0,
    }
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum HealthGuardKey {
    /// Presence of this key means `Address` may call [`report_health_check`].
    Reporter(Address),
    /// Admin-configured [`RetryBudget`] override for `(module, dependency)`.
    Budget(Symbol, Symbol),
    /// Current [`CircuitBreakerState`] for `(module, dependency)`.
    Breaker(Symbol, Symbol),
}

fn pair_key(module: DegradationModule, dependency: ExternalDependencyKind) -> (Symbol, Symbol) {
    (module.as_symbol(), dependency.as_symbol())
}

// ---------------------------------------------------------------------------
// Reporter registry (authorization path)
// ---------------------------------------------------------------------------

/// Authorizes `reporter` to call [`report_health_check`]. Admin-gated and idempotent.
pub fn register_reporter(env: &Env, admin: &Address, reporter: &Address) -> Result<(), Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();
    persistent_set(env, &HealthGuardKey::Reporter(reporter.clone()), &true);
    Ok(())
}

/// Revokes `reporter`. Admin-gated. No-op (returns `Ok`) if not registered.
///
/// Reports already recorded in `shared::degradation` before revocation are
/// unaffected; use `shared::degradation::recover_dependency` to clear a
/// dependency's degraded state once its real health is confirmed.
pub fn revoke_reporter(env: &Env, admin: &Address, reporter: &Address) -> Result<(), Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();
    persistent_remove(env, &HealthGuardKey::Reporter(reporter.clone()));
    Ok(())
}

/// Returns `true` when `reporter` is currently authorized.
pub fn is_registered_reporter(env: &Env, reporter: &Address) -> bool {
    persistent_has(env, &HealthGuardKey::Reporter(reporter.clone()))
}

/// Authorized entry point for recording a dependency health check.
///
/// `reporter` must be registered via [`register_reporter`] and authenticate;
/// otherwise [`Error::Unauthorized`] is returned before
/// `shared::degradation::record_dependency_check` is touched.
pub fn report_health_check(
    env: &Env,
    reporter: &Address,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
    success: bool,
    error_code: u32,
) -> Result<DegradationLevel, Error> {
    if !is_registered_reporter(env, reporter) {
        return Err(Error::Unauthorized);
    }
    reporter.require_auth();
    Ok(record_dependency_check(
        env, module, dependency, success, error_code,
    ))
}

// ---------------------------------------------------------------------------
// Retry budget configuration
// ---------------------------------------------------------------------------

/// Returns the configured [`RetryBudget`] for `(module, dependency)`, or the
/// documented defaults when none has been set.
pub fn get_retry_budget(
    env: &Env,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
) -> RetryBudget {
    let (m, d) = pair_key(module, dependency);
    persistent_get::<HealthGuardKey, RetryBudget>(env, &HealthGuardKey::Budget(m, d))
        .unwrap_or_else(default_retry_budget)
}

/// Sets the [`RetryBudget`] for `(module, dependency)`. Admin-gated.
///
/// Returns [`Error::InvalidArgument`] if any field is zero: a zero budget or
/// window can never be satisfied, and a zero cooldown would never let the
/// breaker recover.
pub fn set_retry_budget(
    env: &Env,
    admin: &Address,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
    budget: RetryBudget,
) -> Result<(), Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();
    if budget.max_attempts == 0 || budget.window_ledgers == 0 || budget.cooldown_ledgers == 0 {
        return Err(Error::InvalidArgument);
    }
    let (m, d) = pair_key(module, dependency);
    persistent_set(env, &HealthGuardKey::Budget(m, d), &budget);
    Ok(())
}

// ---------------------------------------------------------------------------
// Circuit breaker (retry path)
// ---------------------------------------------------------------------------

/// Returns the current [`CircuitBreakerState`] for `(module, dependency)`, or
/// a fresh, untripped state when none is stored yet. Reading never writes.
pub fn breaker_state(
    env: &Env,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
) -> CircuitBreakerState {
    let (m, d) = pair_key(module, dependency);
    persistent_get::<HealthGuardKey, CircuitBreakerState>(env, &HealthGuardKey::Breaker(m, d))
        .unwrap_or_else(|| default_breaker_state(module, dependency, env.ledger().sequence()))
}

/// Admin override: immediately clears a tripped breaker without waiting for
/// its cooldown.
pub fn reset_breaker(
    env: &Env,
    admin: &Address,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
) -> Result<(), Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();
    let ledger = env.ledger().sequence();
    let (m, d) = pair_key(module, dependency);
    persistent_set(
        env,
        &HealthGuardKey::Breaker(m, d),
        &default_breaker_state(module, dependency, ledger),
    );
    env.events().publish(
        (TOPIC_HEALTH_GUARD, symbol_short!("reset")),
        (module.as_symbol(), dependency.as_symbol(), ledger),
    );
    Ok(())
}

/// Records one fallback attempt against `(module, dependency)`'s retry
/// budget, tripping the breaker if it is exceeded.
///
/// Returns [`Error::OperationPaused`] (via `DegradationError::CircuitBreakerOpen`)
/// when the breaker is tripped and the cooldown has not yet elapsed. The
/// first attempt after the cooldown elapses is treated as a fresh window
/// rather than rejected again.
pub fn check_and_record_attempt(
    env: &Env,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
) -> Result<(), Error> {
    let current_ledger = env.ledger().sequence();
    let budget = get_retry_budget(env, module, dependency);
    let mut state = breaker_state(env, module, dependency);
    let (m, d) = pair_key(module, dependency);

    if state.tripped {
        if current_ledger.saturating_sub(state.trip_ledger) >= budget.cooldown_ledgers {
            state.tripped = false;
            state.attempts_in_window = 0;
            state.window_start_ledger = current_ledger;
        } else {
            return Err(DegradationError::CircuitBreakerOpen.into());
        }
    } else if current_ledger.saturating_sub(state.window_start_ledger) > budget.window_ledgers {
        state.window_start_ledger = current_ledger;
        state.attempts_in_window = 0;
    }

    state.attempts_in_window = state.attempts_in_window.saturating_add(1);

    if state.attempts_in_window > budget.max_attempts {
        state.tripped = true;
        state.trip_ledger = current_ledger;
        persistent_set(env, &HealthGuardKey::Breaker(m, d), &state);
        env.events().publish(
            (TOPIC_HEALTH_GUARD, symbol_short!("tripped")),
            (module.as_symbol(), dependency.as_symbol(), current_ledger),
        );
        return Err(DegradationError::CircuitBreakerOpen.into());
    }

    persistent_set(env, &HealthGuardKey::Breaker(m, d), &state);
    Ok(())
}

// ---------------------------------------------------------------------------
// Guarded execution
// ---------------------------------------------------------------------------

/// Drop-in replacement for `shared::degradation::execute_with_fallback` that
/// additionally enforces the `(module, dependency)` retry budget around
/// every fallback invocation, whether the fallback runs because the primary
/// path failed or because the dependency was already degraded.
///
/// No extra check runs on the primary path: a healthy dependency pays no
/// circuit-breaker cost.
pub fn execute_guarded<T, F, G>(
    env: &Env,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
    primary_op: F,
    fallback_op: G,
) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error>,
    G: FnOnce(FallbackStrategy) -> Result<T, Error>,
{
    execute_with_fallback(env, module, dependency, primary_op, |strategy| {
        check_and_record_attempt(env, module, dependency)?;
        fallback_op(strategy)
    })
}
