#![cfg(test)]

//! Tests for [`crate::maintainer_approval`] (Issue #228).
//!
//! The approval flow is exercised with real Ed25519 signatures: every
//! maintainer owns a deterministic signing key, and the intent digest that
//! the contract recomputes is signed off-chain exactly the way an operator
//! tool would sign it.

extern crate std;

use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::{Address as _, Events as _, Ledger as _},
    Address, Bytes, BytesN, Env, IntoVal, Symbol, Vec,
};

use crate::audit_ledger;
use crate::auth;
use crate::canonical::CanonicalPart;
use crate::maintainer_approval::{
    approve_intent, begin_execution, cancel_intent, export_receipts, get_approvals, get_intent,
    get_policy, get_receipt, intent_hash, is_high_impact, is_maintainer, list_intents,
    list_receipts, maintainer_key, pending_intents, propose_intent, receipt_count, receipt_head,
    record_failure, record_success, register_maintainer, reject_intent, revoke_maintainer,
    set_action_impact, set_policy, sweep_expired, verify_export, verify_receipts, ActionIntent,
    ApprovalError, ApprovalKey, ApprovalPolicy, IntentStatus, ReceiptExportBundle, ReceiptOutcome,
    ReceiptVerificationFailure, DEFAULT_APPROVAL_THRESHOLD, MAX_INTENT_TTL_LEDGERS,
};

/// Minimal contract used only to give the shared modules a storage namespace.
#[contract]
pub struct ApprovalHarness;

#[contractimpl]
impl ApprovalHarness {
    pub fn noop(_env: Env) {}
}

const MODULE: Symbol = symbol_short!("treasury");
const ACTION: Symbol = symbol_short!("withdraw");

/// A maintainer: an on-chain address plus the Ed25519 key it signs with.
struct Maintainer {
    addr: Address,
    key: SigningKey,
}

impl Maintainer {
    /// Builds a maintainer with a deterministic signing key.
    fn new(env: &Env, seed: u8) -> Self {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        secret[1] = 0x5a;
        let key = SigningKey::from_bytes(&secret);
        Maintainer {
            addr: Address::generate(env),
            key,
        }
    }

    fn public_key(&self, env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &self.key.verifying_key().to_bytes())
    }

    /// Signs a 32-byte digest the way an operator tool would.
    fn sign(&self, env: &Env, digest: &BytesN<32>) -> BytesN<64> {
        let signature = self.key.sign(&digest.to_array());
        BytesN::from_array(env, &signature.to_bytes())
    }
}

/// Builds the parameter vector used by the tests.
fn params(env: &Env, amount: i128) -> Vec<CanonicalPart> {
    let mut parts: Vec<CanonicalPart> = Vec::new(env);
    parts.push_back(CanonicalPart::Text(Bytes::from_slice(env, b"reserve")));
    parts.push_back(CanonicalPart::Int(amount));
    parts
}

/// Registers `maintainer` under the admin's authority.
fn enroll(env: &Env, admin: &Address, maintainer: &Maintainer) {
    register_maintainer(env, admin, &maintainer.addr, &maintainer.public_key(env))
        .expect("maintainer registration must succeed");
}

/// Computes the digest an operator tool would sign for an intent.
fn digest(
    env: &Env,
    proposer: &Address,
    target: &Address,
    params: &Vec<CanonicalPart>,
    expires_ledger: u32,
) -> BytesN<32> {
    let params_digest = crate::maintainer_approval::params_digest(env, params)
        .expect("params digest must succeed");
    intent_hash(
        env,
        &MODULE,
        &ACTION,
        proposer,
        target,
        &params_digest,
        expires_ledger,
    )
}

/// Proposes an intent signed by `proposer`.
fn propose(
    env: &Env,
    proposer: &Maintainer,
    target: &Address,
    params: &Vec<CanonicalPart>,
    expires_ledger: u32,
) -> Result<ActionIntent, ApprovalError> {
    let hash = digest(env, &proposer.addr, target, params, expires_ledger);
    let signature = proposer.sign(env, &hash);
    propose_intent(
        env,
        &proposer.addr,
        MODULE,
        ACTION,
        target.clone(),
        params.clone(),
        expires_ledger,
        signature,
    )
}

/// Approves an intent signed by `approver`.
fn approve(
    env: &Env,
    approver: &Maintainer,
    intent: &ActionIntent,
) -> Result<IntentStatus, ApprovalError> {
    let signature = approver.sign(env, &intent.intent_hash);
    approve_intent(env, &approver.addr, MODULE, intent.intent_id, signature)
}

/// Sets up an environment with an admin and three maintainers.
///
/// Returns the environment, the contract id, the admin, and the maintainers.
fn setup(seed: u8) -> (Env, Address, Address, Maintainer, Maintainer, Maintainer) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, ApprovalHarness);
    let admin = Address::generate(&env);
    let alice = Maintainer::new(&env, seed);
    let bob = Maintainer::new(&env, seed + 1);
    let carol = Maintainer::new(&env, seed + 2);

    env.as_contract(&id, || {
        auth::initialize_admin(&env, &admin).expect("admin init must succeed");
        enroll(&env, &admin, &alice);
        enroll(&env, &admin, &bob);
        enroll(&env, &admin, &carol);
    });

    (env, id, admin, alice, bob, carol)
}

// ---------------------------------------------------------------------------
// Maintainer registry
// ---------------------------------------------------------------------------

#[test]
fn registering_a_maintainer_requires_the_admin_role() {
    let (env, id, _admin, alice, _bob, _carol) = setup(1);
    let outsider = Maintainer::new(&env, 9);

    env.as_contract(&id, || {
        assert_eq!(
            register_maintainer(&env, &outsider.addr, &alice.addr, &outsider.public_key(&env)),
            Err(ApprovalError::Unauthorized)
        );
    });
}

#[test]
fn maintainer_registration_is_unique_per_address_and_key() {
    let (env, id, admin, alice, bob, _carol) = setup(2);

    env.as_contract(&id, || {
        // Same address, different key.
        assert_eq!(
            register_maintainer(&env, &admin, &alice.addr, &bob.public_key(&env)),
            Err(ApprovalError::AlreadyExists)
        );
        // Different address, key already taken.
        assert_eq!(
            register_maintainer(&env, &admin, &bob.addr, &alice.public_key(&env)),
            Err(ApprovalError::AlreadyExists)
        );
        assert!(is_maintainer(&env, &alice.addr));
        assert_eq!(
            maintainer_key(&env, &alice.addr),
            Some(alice.public_key(&env)),
            "the registered key must be readable"
        );
    });
}

#[test]
fn revoked_maintainers_can_no_longer_propose() {
    let (env, id, admin, alice, bob, _carol) = setup(3);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        revoke_maintainer(&env, &admin, &alice.addr).expect("revoke must succeed");
        assert!(!is_maintainer(&env, &alice.addr));

        let hash = digest(&env, &alice.addr, &target, &params(&env, 100), expiry);
        let signature = alice.sign(&env, &hash);
        assert_eq!(
            propose_intent(
                &env,
                &alice.addr,
                MODULE,
                ACTION,
                target.clone(),
                params(&env, 100),
                expiry,
                signature
            ),
            Err(ApprovalError::UnknownMaintainer)
        );

        // The other maintainers are unaffected.
        assert!(propose(&env, &bob, &target, &params(&env, 100), expiry).is_ok());
    });
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[test]
fn the_default_policy_requires_two_approvals_and_treats_actions_as_high_impact() {
    let (env, id, _admin, _alice, _bob, _carol) = setup(4);

    env.as_contract(&id, || {
        let policy = get_policy(&env, MODULE);
        assert_eq!(policy.threshold, DEFAULT_APPROVAL_THRESHOLD);
        assert_eq!(policy.threshold, 2);
        assert!(!policy.allow_self_approval);
        assert!(
            is_high_impact(&env, MODULE, ACTION),
            "actions are high-impact until an administrator says otherwise"
        );
    });
}

#[test]
fn policy_bounds_are_enforced() {
    let (env, id, admin, _alice, _bob, _carol) = setup(5);

    env.as_contract(&id, || {
        assert_eq!(
            set_policy(&env, &admin, MODULE, 0, 100, false),
            Err(ApprovalError::InvalidArgument)
        );
        assert_eq!(
            set_policy(&env, &admin, MODULE, 17, 100, false),
            Err(ApprovalError::InvalidArgument)
        );
        assert_eq!(
            set_policy(&env, &admin, MODULE, 2, 0, false),
            Err(ApprovalError::InvalidArgument)
        );
        assert_eq!(
            set_policy(&env, &admin, MODULE, 2, MAX_INTENT_TTL_LEDGERS + 1, false),
            Err(ApprovalError::InvalidArgument)
        );

        let policy = set_policy(&env, &admin, MODULE, 3, 500, true).expect("policy must be set");
        assert_eq!(policy.threshold, 3);
        assert_eq!(policy.ttl_ledgers, 500);
        assert!(policy.allow_self_approval);
        assert_eq!(get_policy(&env, MODULE), policy);

        // A policy change applies to the next intent.
        set_action_impact(&env, &admin, MODULE, ACTION, false).expect("impact must be set");
        assert!(!is_high_impact(&env, MODULE, ACTION));
    });
}

// ---------------------------------------------------------------------------
// Proposing
// ---------------------------------------------------------------------------

#[test]
fn proposing_requires_a_registered_maintainer() {
    let (env, id, _admin, _alice, _bob, _carol) = setup(6);
    let outsider = Maintainer::new(&env, 9);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        assert_eq!(
            propose(&env, &outsider, &target, &params(&env, 10), expiry),
            Err(ApprovalError::UnknownMaintainer)
        );
    });
}

#[test]
fn an_intent_is_bound_to_its_parameters_target_and_expiry() {
    let (env, id, _admin, alice, _bob, _carol) = setup(7);
    let target = Address::generate(&env);
    let other = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 500), expiry)
            .expect("proposal must succeed");

        assert_eq!(intent.intent_id, 1);
        assert_eq!(intent.module, MODULE);
        assert_eq!(intent.action, ACTION);
        assert_eq!(intent.proposer, alice.addr);
        assert_eq!(intent.target, target);
        assert_eq!(intent.status, IntentStatus::Pending);
        assert_eq!(intent.approval_count, 0);
        assert_eq!(intent.expires_ledger, expiry);
        assert_eq!(intent.attempts, 0);

        // The digest changes with every bound field.
        let base = intent.intent_hash.clone();
        let other_params = digest(&env, &alice.addr, &target, &params(&env, 501), expiry);
        let other_target = digest(&env, &alice.addr, &other, &params(&env, 500), expiry);
        let other_expiry = digest(&env, &alice.addr, &target, &params(&env, 500), expiry + 1);
        assert_ne!(base, other_params);
        assert_ne!(base, other_target);
        assert_ne!(base, other_expiry);

        assert_eq!(get_intent(&env, MODULE, 1), Some(intent));
        assert_eq!(get_intent(&env, MODULE, 2), None);
    });
}

#[test]
fn an_intent_cannot_outlive_the_policy_ttl() {
    let (env, id, admin, alice, _bob, _carol) = setup(8);
    let target = Address::generate(&env);
    let now = env.ledger().sequence();

    env.as_contract(&id, || {
        set_policy(&env, &admin, MODULE, 2, 10, false).expect("policy must be set");

        // Already expired.
        assert_eq!(
            propose(&env, &alice, &target, &params(&env, 1), now),
            Err(ApprovalError::Expired)
        );
        // Beyond the TTL.
        assert_eq!(
            propose(&env, &alice, &target, &params(&env, 1), now + 11),
            Err(ApprovalError::InvalidArgument)
        );
        // Inside the TTL.
        assert!(propose(&env, &alice, &target, &params(&env, 1), now + 10).is_ok());
    });
}

// ---------------------------------------------------------------------------
// Approving
// ---------------------------------------------------------------------------

#[test]
fn execution_requires_the_threshold() {
    let (env, id, _admin, alice, bob, carol) = setup(9);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 250), expiry)
            .expect("proposal must succeed");

        assert_eq!(approve(&env, &bob, &intent), Ok(IntentStatus::Pending));
        assert_eq!(intent.approval_count, 0);
        assert_eq!(
            get_intent(&env, MODULE, intent.intent_id)
                .expect("intent must exist")
                .approval_count,
            1
        );

        // One approval is not enough to execute.
        assert_eq!(
            begin_execution(&env, &bob.addr, MODULE, intent.intent_id),
            Err(ApprovalError::InvalidState)
        );

        assert_eq!(approve(&env, &carol, &intent), Ok(IntentStatus::Approved));
        assert!(begin_execution(&env, &bob.addr, MODULE, intent.intent_id).is_ok());
    });
}

#[test]
fn a_proposer_cannot_approve_their_own_intent() {
    let (env, id, admin, alice, bob, _carol) = setup(10);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 42), expiry)
            .expect("proposal must succeed");
        assert_eq!(
            approve(&env, &alice, &intent),
            Err(ApprovalError::SelfApproval)
        );

        // Unless the policy explicitly allows it.
        set_policy(&env, &admin, MODULE, 1, 1_000, true).expect("policy must be set");
        assert_eq!(approve(&env, &alice, &intent), Ok(IntentStatus::Approved));
        let _ = bob;
    });
}

#[test]
fn a_maintainer_cannot_approve_twice() {
    let (env, id, _admin, alice, bob, _carol) = setup(11);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 7), expiry)
            .expect("proposal must succeed");
        assert_eq!(approve(&env, &bob, &intent), Ok(IntentStatus::Pending));
        assert_eq!(
            approve(&env, &bob, &intent),
            Err(ApprovalError::DuplicateApproval)
        );
        assert_eq!(get_approvals(&env, MODULE, intent.intent_id).len(), 1);
    });
}

#[test]
fn approving_an_unknown_or_closed_intent_fails() {
    let (env, id, _admin, alice, bob, carol) = setup(12);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 7), expiry)
            .expect("proposal must succeed");

        // Unknown intent id.
        let signature = bob.sign(&env, &intent.intent_hash);
        assert_eq!(
            approve_intent(&env, &bob.addr, MODULE, 999, signature),
            Err(ApprovalError::NotFound)
        );

        // Cancel it, then try to approve.
        cancel_intent(&env, &alice.addr, MODULE, intent.intent_id, symbol_short!("changed"))
            .expect("cancel must succeed");
        let signature = carol.sign(&env, &intent.intent_hash);
        assert_eq!(
            approve_intent(&env, &carol.addr, MODULE, intent.intent_id, signature),
            Err(ApprovalError::InvalidState)
        );
    });
}

#[test]
fn expired_intents_cannot_be_approved_or_executed() {
    let (env, id, admin, alice, bob, carol) = setup(13);
    let target = Address::generate(&env);
    let now = env.ledger().sequence();

    env.as_contract(&id, || {
        set_policy(&env, &admin, MODULE, 1, 10, false).expect("policy must be set");
        let intent = propose(&env, &alice, &target, &params(&env, 7), now + 5)
            .expect("proposal must succeed");

        // Move past the expiry.
        env.ledger().set_sequence_number(now + 6);

        assert_eq!(approve(&env, &bob, &intent), Err(ApprovalError::Expired));
        assert_eq!(
            begin_execution(&env, &bob.addr, MODULE, intent.intent_id),
            Err(ApprovalError::Expired)
        );
        let _ = carol;
    });
}

// ---------------------------------------------------------------------------
// Executing and closing
// ---------------------------------------------------------------------------

#[test]
fn a_successful_execution_produces_a_verifiable_receipt() {
    let (env, id, _admin, alice, bob, carol) = setup(14);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 750), expiry)
            .expect("proposal must succeed");
        approve(&env, &bob, &intent).expect("approval must succeed");
        approve(&env, &carol, &intent).expect("approval must succeed");

        let started = begin_execution(&env, &bob.addr, MODULE, intent.intent_id)
            .expect("execution must start");
        assert_eq!(started.status, IntentStatus::Executing);
        assert_eq!(started.attempts, 1);
        assert_eq!(started.executor, Some(bob.addr.clone()));

        let receipt = record_success(&env, &bob.addr, MODULE, intent.intent_id)
            .expect("receipt must be recorded");
        assert_eq!(receipt.outcome, ReceiptOutcome::Succeeded);
        assert_eq!(receipt.receipt_id, 1);
        assert_eq!(receipt.intent_id, intent.intent_id);
        assert_eq!(receipt.approval_count, 2);
        assert_eq!(receipt.approvals.len(), 2);
        assert_eq!(receipt.intent_hash, intent.intent_hash);
        assert_eq!(receipt.executor, Some(bob.addr.clone()));
        assert_eq!(receipt.proposer, alice.addr);

        // The intent is closed.
        assert_eq!(
            get_intent(&env, MODULE, intent.intent_id)
                .expect("intent must exist")
                .status,
            IntentStatus::Executed
        );
        assert_eq!(
            begin_execution(&env, &bob.addr, MODULE, intent.intent_id),
            Err(ApprovalError::InvalidState)
        );

        // The chain verifies and the head matches.
        let report = verify_receipts(&env, MODULE);
        assert_eq!(report.failure, ReceiptVerificationFailure::None);
        assert_eq!(report.checked, 1);
        assert_eq!(receipt_count(&env, MODULE), 1);
        assert_eq!(receipt_head(&env, MODULE).length, 1);
        assert_eq!(receipt_head(&env, MODULE).head_hash, receipt.receipt_hash);
        assert_eq!(get_receipt(&env, MODULE, 1), Some(receipt));
    });
}

#[test]
fn a_failed_execution_is_reviewable_and_can_be_retried() {
    let (env, id, _admin, alice, bob, carol) = setup(15);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 750), expiry)
            .expect("proposal must succeed");
        approve(&env, &bob, &intent).expect("approval must succeed");
        approve(&env, &carol, &intent).expect("approval must succeed");
        begin_execution(&env, &bob.addr, MODULE, intent.intent_id)
            .expect("execution must start");

        let failure = record_failure(
            &env,
            &bob.addr,
            MODULE,
            intent.intent_id,
            symbol_short!("no_funds"),
        )
        .expect("failure receipt must be recorded");
        assert_eq!(failure.outcome, ReceiptOutcome::Failed);
        assert_eq!(failure.reason, symbol_short!("no_funds"));
        assert_eq!(failure.approval_count, 2);

        assert_eq!(
            get_intent(&env, MODULE, intent.intent_id)
                .expect("intent must exist")
                .status,
            IntentStatus::Failed
        );

        // The failure is reviewable.
        let report = verify_receipts(&env, MODULE);
        assert_eq!(report.failure, ReceiptVerificationFailure::None);
        let receipts = list_receipts(&env, MODULE, 1, 10);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts.get(0).expect("receipt must exist").outcome, ReceiptOutcome::Failed);

        // A failed intent can be retried while it is still valid.
        let retried = begin_execution(&env, &carol.addr, MODULE, intent.intent_id)
            .expect("retry must start");
        assert_eq!(retried.attempts, 2);
        let success = record_success(&env, &carol.addr, MODULE, intent.intent_id)
            .expect("receipt must be recorded");
        assert_eq!(success.outcome, ReceiptOutcome::Succeeded);
        assert_eq!(success.receipt_id, 2);
        assert_eq!(receipt_count(&env, MODULE), 2);
    });
}

#[test]
fn a_rejected_intent_is_closed_and_recorded() {
    let (env, id, _admin, alice, bob, _carol) = setup(16);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 750), expiry)
            .expect("proposal must succeed");
        approve(&env, &bob, &intent).expect("approval must succeed");

        let receipt = reject_intent(
            &env,
            &bob.addr,
            MODULE,
            intent.intent_id,
            symbol_short!("risk"),
        )
        .expect("rejection must be recorded");
        assert_eq!(receipt.outcome, ReceiptOutcome::Rejected);
        assert_eq!(
            get_intent(&env, MODULE, intent.intent_id)
                .expect("intent must exist")
                .status,
            IntentStatus::Rejected
        );
        assert_eq!(
            begin_execution(&env, &bob.addr, MODULE, intent.intent_id),
            Err(ApprovalError::InvalidState)
        );
    });
}

#[test]
fn only_the_proposer_can_cancel_an_intent() {
    let (env, id, _admin, alice, bob, _carol) = setup(17);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 750), expiry)
            .expect("proposal must succeed");

        assert_eq!(
            cancel_intent(&env, &bob.addr, MODULE, intent.intent_id, symbol_short!("nope")),
            Err(ApprovalError::Unauthorized)
        );

        let receipt = cancel_intent(
            &env,
            &alice.addr,
            MODULE,
            intent.intent_id,
            symbol_short!("changed"),
        )
        .expect("cancellation must be recorded");
        assert_eq!(receipt.outcome, ReceiptOutcome::Cancelled);
        assert_eq!(
            get_intent(&env, MODULE, intent.intent_id)
                .expect("intent must exist")
                .status,
            IntentStatus::Cancelled
        );
    });
}

#[test]
fn expired_intents_are_swept() {
    let (env, id, admin, alice, bob, _carol) = setup(18);
    let target = Address::generate(&env);
    let now = env.ledger().sequence();

    env.as_contract(&id, || {
        set_policy(&env, &admin, MODULE, 2, 10, false).expect("policy must be set");
        let intent = propose(&env, &alice, &target, &params(&env, 7), now + 5)
            .expect("proposal must succeed");

        env.ledger().set_sequence_number(now + 6);
        let swept = sweep_expired(&env, MODULE, 10).expect("sweep must succeed");
        assert_eq!(swept, 1);
        assert_eq!(
            get_intent(&env, MODULE, intent.intent_id)
                .expect("intent must exist")
                .status,
            IntentStatus::Expired
        );

        // A second sweep finds nothing left to do.
        assert_eq!(sweep_expired(&env, MODULE, 10).expect("sweep must succeed"), 0);
        let _ = bob;
    });
}

// ---------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------

#[test]
fn receipts_are_listed_in_order_and_intents_can_be_filtered() {
    let (env, id, _admin, alice, bob, carol) = setup(19);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let first = propose(&env, &alice, &target, &params(&env, 1), expiry)
            .expect("proposal must succeed");
        let second = propose(&env, &alice, &target, &params(&env, 2), expiry)
            .expect("proposal must succeed");

        let pending = pending_intents(&env, MODULE, 10);
        assert_eq!(pending.len(), 2);

        approve(&env, &bob, &first).expect("approval must succeed");
        approve(&env, &carol, &first).expect("approval must succeed");
        begin_execution(&env, &bob.addr, MODULE, first.intent_id).expect("execution must start");
        record_success(&env, &bob.addr, MODULE, first.intent_id).expect("receipt must exist");

        let receipts = list_receipts(&env, MODULE, 1, 10);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts.get(0).expect("receipt must exist").receipt_id, 1);

        let intents = list_intents(&env, MODULE, 1, 10);
        assert_eq!(intents.len(), 2);
        assert_eq!(intents.get(1).expect("intent must exist").intent_id, second.intent_id);

        // Only the second intent is still open.
        let pending = pending_intents(&env, MODULE, 10);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.get(0).expect("intent must exist").intent_id, second.intent_id);
    });
}

#[test]
fn a_tampered_receipt_breaks_the_chain() {
    let (env, id, _admin, alice, bob, carol) = setup(20);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 1), expiry)
            .expect("proposal must succeed");
        approve(&env, &bob, &intent).expect("approval must succeed");
        approve(&env, &carol, &intent).expect("approval must succeed");
        begin_execution(&env, &bob.addr, MODULE, intent.intent_id).expect("execution must start");
        let receipt = record_success(&env, &bob.addr, MODULE, intent.intent_id)
            .expect("receipt must exist");

        // Edit a stored receipt: the hash no longer matches its fields.
        let mut tampered = receipt.clone();
        tampered.reason = symbol_short!("edited");
        crate::storage::persistent_set(
            &env,
            &ApprovalKey::Receipt(MODULE, 1),
            &tampered,
        );
        let report = verify_receipts(&env, MODULE);
        assert_eq!(report.failure, ReceiptVerificationFailure::HashMismatch);
        assert_eq!(report.first_invalid_id, 1);
    });
}

#[test]
fn a_missing_receipt_is_detected() {
    let (env, id, _admin, alice, bob, carol) = setup(21);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 1), expiry)
            .expect("proposal must succeed");
        approve(&env, &bob, &intent).expect("approval must succeed");
        approve(&env, &carol, &intent).expect("approval must succeed");
        begin_execution(&env, &bob.addr, MODULE, intent.intent_id).expect("execution must start");
        record_success(&env, &bob.addr, MODULE, intent.intent_id).expect("receipt must exist");

        crate::storage::persistent_remove(
            &env,
            &ApprovalKey::Receipt(MODULE, 1),
        );
        let report = verify_receipts(&env, MODULE);
        assert_eq!(report.failure, ReceiptVerificationFailure::MissingEntry);
        assert_eq!(report.first_invalid_id, 1);
    });
}

#[test]
fn receipts_export_and_verify_off_chain() {
    let (env, id, admin, alice, bob, carol) = setup(22);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 1), expiry)
            .expect("proposal must succeed");
        approve(&env, &bob, &intent).expect("approval must succeed");
        approve(&env, &carol, &intent).expect("approval must succeed");
        begin_execution(&env, &bob.addr, MODULE, intent.intent_id).expect("execution must start");
        record_success(&env, &bob.addr, MODULE, intent.intent_id).expect("receipt must exist");

        let bundle = export_receipts(&env, &admin, MODULE, 1, 10).expect("export must succeed");
        assert_eq!(bundle.receipts.len(), 1);
        assert!(!bundle.has_more);
        let report = verify_export(&env, &bundle);
        assert_eq!(report.failure, ReceiptVerificationFailure::None);
        assert_eq!(report.checked, 1);

        // A tampered bundle is rejected.
        let mut tampered: ReceiptExportBundle = bundle.clone();
        tampered.digest = BytesN::from_array(&env, &[7u8; 32]);
        let report = verify_export(&env, &tampered);
        assert_eq!(report.failure, ReceiptVerificationFailure::HashMismatch);
    });
}

#[test]
fn the_flow_is_mirrored_into_the_audit_ledger() {
    let (env, id, _admin, alice, bob, carol) = setup(23);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let before = audit_ledger::length(&env);
        let intent = propose(&env, &alice, &target, &params(&env, 1), expiry)
            .expect("proposal must succeed");
        approve(&env, &bob, &intent).expect("approval must succeed");
        approve(&env, &carol, &intent).expect("approval must succeed");
        begin_execution(&env, &bob.addr, MODULE, intent.intent_id).expect("execution must start");
        record_success(&env, &bob.addr, MODULE, intent.intent_id).expect("receipt must exist");

        assert!(
            audit_ledger::length(&env) > before,
            "the approval flow must leave privileged audit entries"
        );
        assert_eq!(audit_ledger::verify_chain(&env).verified, true);
    });
}

#[test]
fn events_are_emitted_for_every_state_change() {
    let (env, id, _admin, alice, bob, carol) = setup(24);
    let target = Address::generate(&env);
    let expiry = env.ledger().sequence() + 100;

    env.as_contract(&id, || {
        let intent = propose(&env, &alice, &target, &params(&env, 1), expiry)
            .expect("proposal must succeed");
        approve(&env, &bob, &intent).expect("approval must succeed");
        approve(&env, &carol, &intent).expect("approval must succeed");
        begin_execution(&env, &bob.addr, MODULE, intent.intent_id).expect("execution must start");
        record_success(&env, &bob.addr, MODULE, intent.intent_id).expect("receipt must exist");

        let events = env.events().all();
        assert!(events.len() >= 5, "expected state-change events");
        let mut saw_proposal = false;
        for (_emitter, topics, _data) in events.iter() {
            if topics == (symbol_short!("approval"), MODULE, symbol_short!("proposed")).into_val(&env)
            {
                saw_proposal = true;
            }
        }
        assert!(saw_proposal, "expected an approval-flow event");
    });
}

#[test]
fn a_default_policy_is_returned_for_unknown_modules() {
    let (env, id, _admin, _alice, _bob, _carol) = setup(25);

    env.as_contract(&id, || {
        let policy: ApprovalPolicy = get_policy(&env, symbol_short!("unknown"));
        assert_eq!(policy.module, symbol_short!("unknown"));
        assert_eq!(policy.threshold, DEFAULT_APPROVAL_THRESHOLD);
    });
}
