//! Bounded, resumable repair of the treasury strategy whitelist from approval records.
use crate::{
    auth::require_admin,
    storage::{persistent_get, persistent_set},
};
use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol, Vec};

const LIST: Symbol = symbol_short!("strat_lst");
const APPROVED: Symbol = symbol_short!("strat_ok");
const ACTIVE: Symbol = symbol_short!("rpr_act");
pub const MAX_REPAIR_STRATEGIES: u32 = 100;
pub const MAX_REPAIR_BATCH: u32 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairError {
    Unauthorized,
    InvalidPlan,
    Busy,
    NotFound,
    Conflict,
    InvalidCursor,
    Terminal,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairStatus {
    Running,
    Completed,
    RolledBack,
    Abandoned,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairJob {
    pub id: u64,
    /// Stable union of the original index and supplied missing candidates.
    pub candidates: Vec<Address>,
    pub before: Vec<Address>,
    pub last_written: Vec<Address>,
    pub cursor: u32,
    pub status: RepairStatus,
}

fn job_key(id: u64) -> (Symbol, u64) {
    (symbol_short!("rpr_job"), id)
}
fn list(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&LIST)
        .unwrap_or_else(|| Vec::new(env))
}
fn authorize(env: &Env, caller: &Address) -> Result<(), RepairError> {
    require_admin(env, caller).map_err(|_| RepairError::Unauthorized)
}

pub fn get_repair_job(env: &Env, id: u64) -> Option<RepairJob> {
    persistent_get(env, &job_key(id))
}

/// Existing index entries are included automatically; supplied candidates discover missing entries.
/// A reused job ID is rejected so a completed repair can never be silently replaced.
pub fn start_repair(
    env: &Env,
    caller: &Address,
    id: u64,
    missing_candidates: &Vec<Address>,
) -> Result<RepairJob, RepairError> {
    authorize(env, caller)?;
    if get_repair_job(env, id).is_some() {
        return Err(RepairError::Conflict);
    }
    if env.storage().instance().has(&ACTIVE) {
        return Err(RepairError::Busy);
    }
    let before = list(env);
    if before.len() > MAX_REPAIR_STRATEGIES || missing_candidates.len() > MAX_REPAIR_STRATEGIES {
        return Err(RepairError::InvalidPlan);
    }
    let mut candidates = Vec::new(env);
    for address in before.iter().chain(missing_candidates.iter()) {
        if !candidates.contains(&address) {
            candidates.push_back(address);
        }
    }
    if candidates.is_empty() || candidates.len() > MAX_REPAIR_STRATEGIES {
        return Err(RepairError::InvalidPlan);
    }
    let job = RepairJob {
        id,
        candidates,
        before: before.clone(),
        last_written: before,
        cursor: 0,
        status: RepairStatus::Running,
    };
    persistent_set(env, &job_key(id), &job);
    env.storage().instance().set(&ACTIVE, &id);
    Ok(job)
}

/// A stale cursor is an idempotent retry; a future cursor is rejected.
/// Read current canonical approvals at execution, never trust a caller-supplied repair value.
pub fn advance_repair(
    env: &Env,
    caller: &Address,
    id: u64,
    expected_cursor: u32,
    limit: u32,
) -> Result<RepairJob, RepairError> {
    authorize(env, caller)?;
    if limit == 0 || limit > MAX_REPAIR_BATCH {
        return Err(RepairError::InvalidPlan);
    }
    let mut job = get_repair_job(env, id).ok_or(RepairError::NotFound)?;
    if expected_cursor > job.cursor {
        return Err(RepairError::InvalidCursor);
    }
    if job.status == RepairStatus::RolledBack || job.status == RepairStatus::Abandoned {
        return Err(RepairError::Terminal);
    }
    if expected_cursor < job.cursor || job.status == RepairStatus::Completed {
        return Ok(job);
    }
    if env.storage().instance().get::<_, u64>(&ACTIVE) != Some(id) || list(env) != job.last_written
    {
        return Err(RepairError::Conflict);
    }
    let end = job.cursor.saturating_add(limit).min(job.candidates.len());
    let mut repaired = job.last_written.clone();
    for index in job.cursor..end {
        let address = job.candidates.get(index).unwrap();
        let approved: bool = persistent_get(env, &(APPROVED, address.clone())).unwrap_or(false);
        // Remove all occurrences, including duplicates, before adding one approved entry.
        let mut next = Vec::new(env);
        for entry in repaired.iter() {
            if entry != address {
                next.push_back(entry);
            }
        }
        if approved {
            next.push_back(address);
        }
        repaired = next;
    }
    // No fallible validation follows the first write. Checkpoint and projection commit together.
    env.storage().instance().set(&LIST, &repaired);
    job.last_written = repaired;
    job.cursor = end;
    if end == job.candidates.len() {
        job.status = RepairStatus::Completed;
        env.storage().instance().remove(&ACTIVE);
    }
    persistent_set(env, &job_key(id), &job);
    env.events()
        .publish((symbol_short!("repair"), id), (job.cursor, job.status));
    Ok(job)
}

/// Restore the original derived index only if no later writer has changed it.
pub fn rollback_repair(env: &Env, caller: &Address, id: u64) -> Result<RepairJob, RepairError> {
    authorize(env, caller)?;
    let mut job = get_repair_job(env, id).ok_or(RepairError::NotFound)?;
    if job.status == RepairStatus::RolledBack {
        return Ok(job);
    }
    if job.status == RepairStatus::Abandoned {
        return Err(RepairError::Terminal);
    }
    let active: Option<u64> = env.storage().instance().get(&ACTIVE);
    if active.is_some() && active != Some(id) || list(env) != job.last_written {
        return Err(RepairError::Conflict);
    }
    env.storage().instance().set(&LIST, &job.before);
    job.status = RepairStatus::RolledBack;
    if active == Some(id) {
        env.storage().instance().remove(&ACTIVE);
    }
    persistent_set(env, &job_key(id), &job);
    env.events()
        .publish((symbol_short!("repair"), id), (job.cursor, job.status));
    Ok(job)
}

/// Release a conflicted run without overwriting a concurrent writer. Preserve its audit record.
pub fn abandon_repair(env: &Env, caller: &Address, id: u64) -> Result<RepairJob, RepairError> {
    authorize(env, caller)?;
    let mut job = get_repair_job(env, id).ok_or(RepairError::NotFound)?;
    if job.status != RepairStatus::Running {
        return Err(RepairError::Terminal);
    }
    if env.storage().instance().get::<_, u64>(&ACTIVE) != Some(id) {
        return Err(RepairError::Conflict);
    }
    job.status = RepairStatus::Abandoned;
    persistent_set(env, &job_key(id), &job);
    env.storage().instance().remove(&ACTIVE);
    env.events()
        .publish((symbol_short!("repair"), id), (job.cursor, job.status));
    Ok(job)
}
