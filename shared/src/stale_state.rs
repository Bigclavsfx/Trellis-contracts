//! Cross-source stale-state detection for irreversible workflows (issue #111).

use crate::storage::persistent_set;
use soroban_sdk::{contracterror, contracttype, Bytes, BytesN, Env};

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateSnapshot {
    pub wallet_revision: u64,
    pub api_revision: u64,
    pub ledger_sequence: u32,
}

#[contracttype]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleStateReason {
    /// No drift was detected; the prepared snapshot is still current.
    None = 0,
    WalletChanged = 1,
    ApiChanged = 2,
    LedgerAdvanced = 3,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    RefreshWallet,
    RefreshApi,
    ReSimulate,
    RestartFlow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleStateReport {
    pub stale: bool,
    pub reason: StaleStateReason,
    pub recovery: RecoveryAction,
}

/// A replayable operation envelope. Clients can persist this value while
/// offline and submit it after reconnecting; the stable id makes retries from
/// another tab idempotent once the envelope reaches contract storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedOperation {
    pub id: BytesN<32>,
    pub payload: Bytes,
    pub expected: StateSnapshot,
    pub status: QueuedOperationStatus,
    pub attempts: u32,
    /// Set to `None` when no conflict is parked; non-optional because Soroban
    /// cannot encode an `Option` containing a user-defined struct.
    pub conflict_reason: StaleStateReason,
    pub recovery: RecoveryAction,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuedOperationStatus {
    Pending,
    InProgress,
    Conflict,
    Completed,
    Discarded,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictResolution {
    RetryWithLatest,
    Discard,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum QueueError {
    OperationIdConflict = 1,
    OperationNotFound = 2,
    OperationNotInConflict = 3,
    OperationNotInProgress = 4,
}

#[contracttype]
#[derive(Clone)]
enum QueueKey {
    Operation(BytesN<32>),
}

/// Persist an operation envelope. Repeating the same id and payload is safe;
/// reusing an id for different work is rejected instead of overwriting it.
pub fn enqueue(
    env: &Env,
    id: &BytesN<32>,
    payload: &Bytes,
    expected: StateSnapshot,
) -> Result<QueuedOperation, QueueError> {
    let key = QueueKey::Operation(id.clone());
    if let Some(existing) = env.storage().persistent().get::<_, QueuedOperation>(&key) {
        if existing.payload != *payload || existing.expected != expected {
            return Err(QueueError::OperationIdConflict);
        }
        return Ok(existing);
    }
    let operation = QueuedOperation {
        id: id.clone(),
        payload: payload.clone(),
        expected,
        status: QueuedOperationStatus::Pending,
        attempts: 0,
        conflict_reason: StaleStateReason::None,
        recovery: RecoveryAction::RestartFlow,
    };
    persistent_set(env, &key, &operation);
    Ok(operation)
}

/// Recheck the snapshot before replay. A stale operation is parked with a
/// reason that the caller can present to the user instead of being retried
/// against changed state.
pub fn check_before_replay(
    env: &Env,
    id: &BytesN<32>,
    current: StateSnapshot,
) -> Result<QueuedOperation, QueueError> {
    let key = QueueKey::Operation(id.clone());
    let mut operation = env
        .storage()
        .persistent()
        .get::<_, QueuedOperation>(&key)
        .ok_or(QueueError::OperationNotFound)?;
    if operation.status == QueuedOperationStatus::InProgress {
        let report = detect(operation.expected, current);
        if report.stale {
            operation.status = QueuedOperationStatus::Conflict;
            operation.conflict_reason = report.reason;
            operation.recovery = report.recovery;
            persistent_set(env, &key, &operation);
        }
        return Ok(operation);
    }
    if operation.status != QueuedOperationStatus::Pending {
        return Ok(operation);
    }
    let report = detect(operation.expected, current);
    if report.stale {
        operation.status = QueuedOperationStatus::Conflict;
        operation.conflict_reason = report.reason;
        operation.recovery = report.recovery;
    } else {
        operation.attempts = operation.attempts.saturating_add(1);
        operation.status = QueuedOperationStatus::InProgress;
    }
    persistent_set(env, &key, &operation);
    Ok(operation)
}

/// Mark a successfully submitted operation complete so duplicate tabs cannot
/// submit it again.
pub fn complete_operation(env: &Env, id: &BytesN<32>) -> Result<QueuedOperation, QueueError> {
    let key = QueueKey::Operation(id.clone());
    let mut operation = env
        .storage()
        .persistent()
        .get::<_, QueuedOperation>(&key)
        .ok_or(QueueError::OperationNotFound)?;
    if operation.status != QueuedOperationStatus::InProgress {
        return Err(QueueError::OperationNotInProgress);
    }
    operation.status = QueuedOperationStatus::Completed;
    operation.conflict_reason = StaleStateReason::None;
    operation.recovery = RecoveryAction::RestartFlow;
    persistent_set(env, &key, &operation);
    Ok(operation)
}

/// Resolve a parked conflict explicitly. Retrying refreshes the expected
/// snapshot; discarding leaves a durable tombstone so another tab cannot
/// replay the operation accidentally.
pub fn resolve_conflict(
    env: &Env,
    id: &BytesN<32>,
    choice: ConflictResolution,
    current: StateSnapshot,
) -> Result<QueuedOperation, QueueError> {
    let key = QueueKey::Operation(id.clone());
    let mut operation = env
        .storage()
        .persistent()
        .get::<_, QueuedOperation>(&key)
        .ok_or(QueueError::OperationNotFound)?;
    if operation.status != QueuedOperationStatus::Conflict {
        return Err(QueueError::OperationNotInConflict);
    }
    match choice {
        ConflictResolution::RetryWithLatest => {
            operation.expected = current;
            operation.status = QueuedOperationStatus::Pending;
            operation.conflict_reason = StaleStateReason::None;
            operation.recovery = RecoveryAction::RestartFlow;
        }
        ConflictResolution::Discard => operation.status = QueuedOperationStatus::Discarded,
    }
    persistent_set(env, &key, &operation);
    Ok(operation)
}

/// Compare the snapshot used to prepare a transaction with current state.
/// Ledger movement is checked first because a re-simulation is required even
/// when wallet and API revisions are unchanged.
pub fn detect(prepared: StateSnapshot, current: StateSnapshot) -> StaleStateReport {
    if current.ledger_sequence != prepared.ledger_sequence {
        return StaleStateReport {
            stale: true,
            reason: StaleStateReason::LedgerAdvanced,
            recovery: RecoveryAction::ReSimulate,
        };
    }
    if current.wallet_revision != prepared.wallet_revision {
        return StaleStateReport {
            stale: true,
            reason: StaleStateReason::WalletChanged,
            recovery: RecoveryAction::RefreshWallet,
        };
    }
    if current.api_revision != prepared.api_revision {
        return StaleStateReport {
            stale: true,
            reason: StaleStateReason::ApiChanged,
            recovery: RecoveryAction::RefreshApi,
        };
    }
    StaleStateReport {
        stale: false,
        reason: StaleStateReason::None,
        recovery: RecoveryAction::RestartFlow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;
    fn snapshot() -> StateSnapshot {
        StateSnapshot {
            wallet_revision: 4,
            api_revision: 9,
            ledger_sequence: 100,
        }
    }

    #[test]
    fn unchanged_snapshot_is_safe_to_continue() {
        let report = detect(snapshot(), snapshot());
        assert!(!report.stale);
        assert_eq!(report.reason, StaleStateReason::None);
    }

    #[test]
    fn each_source_drift_has_a_deterministic_recovery() {
        let prepared = snapshot();
        let mut current = prepared;
        current.wallet_revision += 1;
        assert_eq!(
            detect(prepared, current).recovery,
            RecoveryAction::RefreshWallet
        );
        current = prepared;
        current.api_revision += 1;
        assert_eq!(
            detect(prepared, current).recovery,
            RecoveryAction::RefreshApi
        );
        current = prepared;
        current.ledger_sequence += 1;
        assert_eq!(
            detect(prepared, current).recovery,
            RecoveryAction::ReSimulate
        );
    }

    #[test]
    fn ledger_drift_takes_precedence_over_cache_drift() {
        let prepared = snapshot();
        let current = StateSnapshot {
            wallet_revision: 5,
            api_revision: 10,
            ledger_sequence: 101,
        };
        let report = detect(prepared, current);
        assert_eq!(report.reason, StaleStateReason::LedgerAdvanced);
        assert_eq!(report.recovery, RecoveryAction::ReSimulate);
    }

    #[test]
    fn queued_operation_survives_reopen_and_requires_explicit_conflict_choice() {
        let env = Env::default();
        let id = BytesN::from_array(&env, &[7; 32]);
        let payload = Bytes::from_slice(&env, b"transfer");
        let initial = snapshot();
        enqueue(&env, &id, &payload, initial).unwrap();
        assert_eq!(enqueue(&env, &id, &payload, initial).unwrap().attempts, 0);

        let mut current = initial;
        current.ledger_sequence += 1;
        let parked = check_before_replay(&env, &id, current).unwrap();
        assert_eq!(parked.status, QueuedOperationStatus::Conflict);
        assert_eq!(parked.recovery, RecoveryAction::ReSimulate);

        let resumed =
            resolve_conflict(&env, &id, ConflictResolution::RetryWithLatest, current).unwrap();
        assert_eq!(resumed.status, QueuedOperationStatus::Pending);
        assert_eq!(resumed.expected, current);
        let claimed = check_before_replay(&env, &id, current).unwrap();
        assert_eq!(claimed.status, QueuedOperationStatus::InProgress);
        assert_eq!(claimed.attempts, 1);
        let completed = complete_operation(&env, &id).unwrap();
        assert_eq!(completed.status, QueuedOperationStatus::Completed);
    }

    #[test]
    fn queue_rejects_reusing_an_id_for_different_payload() {
        let env = Env::default();
        let id = BytesN::from_array(&env, &[9; 32]);
        enqueue(&env, &id, &Bytes::from_slice(&env, b"first"), snapshot()).unwrap();
        assert_eq!(
            enqueue(&env, &id, &Bytes::from_slice(&env, b"second"), snapshot()),
            Err(QueueError::OperationIdConflict)
        );
    }

    #[test]
    fn interrupted_claim_is_parked_as_a_conflict_after_state_advances() {
        let env = Env::default();
        let id = BytesN::from_array(&env, &[11; 32]);
        let prepared = snapshot();
        enqueue(&env, &id, &Bytes::from_slice(&env, b"transfer"), prepared).unwrap();
        assert_eq!(
            check_before_replay(&env, &id, prepared).unwrap().status,
            QueuedOperationStatus::InProgress
        );
        let mut current = prepared;
        current.ledger_sequence += 1;
        let recovered = check_before_replay(&env, &id, current).unwrap();
        assert_eq!(recovered.status, QueuedOperationStatus::Conflict);
        assert_eq!(
            recovered.conflict_reason,
            StaleStateReason::LedgerAdvanced
        );
    }
}
