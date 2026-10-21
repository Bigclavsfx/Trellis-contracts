use soroban_sdk::{Bytes, Env, Vec};

use crate::errors::Error;
use crate::workflow_correlation::{
    check_workflow_chain, validate_workflow_id, MAX_WORKFLOW_ID_LEN,
};

fn id(env: &Env, raw: &[u8]) -> Bytes {
    Bytes::from_slice(env, raw)
}

fn chain(env: &Env, ids: &[Bytes]) -> Vec<Bytes> {
    let mut v = Vec::new(env);
    for item in ids {
        v.push_back(item.clone());
    }
    v
}

#[test]
fn valid_id_with_allowed_characters_is_accepted() {
    let env = Env::default();
    assert_eq!(validate_workflow_id(&id(&env, b"aid-claim_42")), Ok(()));
}

#[test]
fn empty_id_is_rejected() {
    let env = Env::default();
    assert_eq!(
        validate_workflow_id(&id(&env, b"")),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn id_at_the_length_limit_is_accepted_and_one_byte_more_is_rejected() {
    let env = Env::default();
    let at_limit = [b'a'; MAX_WORKFLOW_ID_LEN as usize];
    let over_limit = [b'a'; MAX_WORKFLOW_ID_LEN as usize + 1];

    assert_eq!(validate_workflow_id(&id(&env, &at_limit)), Ok(()));
    assert_eq!(
        validate_workflow_id(&id(&env, &over_limit)),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn ids_with_separators_or_spaces_are_rejected() {
    let env = Env::default();
    let cases: [&[u8]; 4] = [b"aid claim", b"aid.claim", b"aid:claim", b"aid/claim"];
    for raw in cases {
        assert_eq!(
            validate_workflow_id(&id(&env, raw)),
            Err(Error::InvalidArgument),
            "{raw:?} should be rejected"
        );
    }
}

#[test]
fn chain_sharing_one_id_across_contracts_returns_that_id() {
    let env = Env::default();
    let wf = id(&env, b"wf-fund-claim");
    let steps = chain(&env, &[wf.clone(), wf.clone(), wf.clone()]);

    assert_eq!(check_workflow_chain(&steps), Ok(wf));
}

#[test]
fn retried_step_reusing_the_same_id_is_accepted() {
    let env = Env::default();
    let wf = id(&env, b"wf-retry");
    // Aid emits, the call fails, the client retries the same step, then Treasury emits.
    let steps = chain(&env, &[wf.clone(), wf.clone(), wf.clone()]);

    assert_eq!(check_workflow_chain(&steps), Ok(wf));
}

#[test]
fn chain_mixing_two_workflows_is_rejected() {
    let env = Env::default();
    let steps = chain(&env, &[id(&env, b"wf-one"), id(&env, b"wf-two")]);

    assert_eq!(check_workflow_chain(&steps), Err(Error::InvalidArgument));
}

#[test]
fn chain_with_one_invalid_id_is_rejected_even_if_others_match() {
    let env = Env::default();
    let bad = id(&env, b"wf bad");
    let steps = chain(&env, &[bad.clone(), bad.clone()]);

    assert_eq!(check_workflow_chain(&steps), Err(Error::InvalidArgument));
}

#[test]
fn empty_chain_is_rejected() {
    let env = Env::default();
    let steps: Vec<Bytes> = Vec::new(&env);

    assert_eq!(check_workflow_chain(&steps), Err(Error::InvalidArgument));
}
