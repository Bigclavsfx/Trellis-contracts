use soroban_sdk::{contracttype, Address, BytesN, Env, Symbol};
use crate::errors::Error;
use crate::storage::{persistent_has, persistent_set};
use crate::utils::now;

/// Replay protection fields for signed operations.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPayload {
    /// A unique identifier for the payload to prevent replays.
    pub nonce: BytesN<32>,
    /// The ledger sequence or timestamp after which the payload is invalid.
    pub expiry: u64,
    /// The scope or target of the operation (e.g., contract name or function).
    pub scope: Symbol,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayKey {
    /// Tracks consumed payloads.
    Consumed(Address, BytesN<32>),
}

/// Validates a signed payload and marks it as consumed to prevent replays.
/// 
/// Rejects expired payloads, mismatched scopes, and replays.
/// Assumes signer.require_auth() has already been called or will be called by the caller
/// (but calls it here for safety as well if it's the right place, wait no).
/// Actually, signer.require_auth() verifies that the contract invocation itself is authorized by the signer.
pub fn consume_payload(
    env: &Env,
    signer: &Address,
    payload: &SignedPayload,
    expected_scope: &Symbol,
) -> Result<(), Error> {
    // 1. Check expiry (using timestamp)
    let current_time = now(env);
    if payload.expiry < current_time {
        return Err(Error::Expired);
    }

    // 2. Check scope
    if payload.scope != *expected_scope {
        return Err(Error::InvalidArgument);
    }

    // 3. Check replay
    let key = ReplayKey::Consumed(signer.clone(), payload.nonce.clone());
    if persistent_has(env, &key) {
        return Err(Error::AlreadyClaimed);
    }

    // 4. Persist nonce
    persistent_set(env, &key, &true);

    // 5. Require auth (this verifies the user signed the host invocation)
    signer.require_auth();

    Ok(())
}
