//! Permission matrix tests (Issue #333).
//!
//! Every privileged entrypoint is called with an unauthorized caller and must
//! reject it with the error its matrix row implies:
//!
//! - deployment-wide actions fail with [`AccessControlError::NotAdmin`];
//! - role- and owner-scoped actions fail with [`AccessControlError::RoleEscalation`];
//! - the audit trail fails with [`shared::Error::Unauthorized`].
//!
//! Each rejection is also checked for side effects: a refused call must leave
//! the role, admin, and invitation state exactly as it was.

use soroban_sdk::{symbol_short, testutils::Address as _, Address, Env, Symbol};

use crate::{AccessControlContract, AccessControlContractClient, AccessControlError};

fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let super_admin = Address::generate(&env);
    let contract_id = env.register_contract(None, AccessControlContract);
    let client = AccessControlContractClient::new(&env, &contract_id);
    client.initialize(&super_admin);
    (env, super_admin, contract_id)
}

fn client_for<'a>(env: &'a Env, contract_id: &Address) -> AccessControlContractClient<'a> {
    AccessControlContractClient::new(env, contract_id)
}

#[test]
fn deployment_wide_entrypoints_reject_outsider_with_not_admin() {
    let (env, super_admin, contract_id) = setup();
    let client = client_for(&env, &contract_id);
    let outsider = Address::generate(&env);
    let target = Address::generate(&env);
    let role = Symbol::new(&env, "manager");
    client.create_role(&super_admin, &role);

    assert!(matches!(
        client.try_add_admin(&outsider, &target),
        Err(Ok(AccessControlError::NotAdmin))
    ));
    assert!(matches!(
        client.try_remove_admin(&outsider, &super_admin),
        Err(Ok(AccessControlError::NotAdmin))
    ));
    assert!(matches!(
        client.try_create_role(&outsider, &Symbol::new(&env, "auditor")),
        Err(Ok(AccessControlError::NotAdmin))
    ));
    assert!(matches!(
        client.try_set_role_parent(&outsider, &role, &symbol_short!("super")),
        Err(Ok(AccessControlError::NotAdmin))
    ));
    assert!(matches!(
        client.try_grant_role(&outsider, &role, &target),
        Err(Ok(AccessControlError::NotAdmin))
    ));
    assert!(matches!(
        client.try_grant_role_timed(&outsider, &role, &target, &3600),
        Err(Ok(AccessControlError::NotAdmin))
    ));
    assert!(matches!(
        client.try_revoke_role(&outsider, &role, &target),
        Err(Ok(AccessControlError::NotAdmin))
    ));
    assert!(matches!(
        client.try_pause(&outsider, &symbol_short!("roles")),
        Err(Ok(AccessControlError::NotAdmin))
    ));
    assert!(matches!(
        client.try_resume(&outsider, &symbol_short!("roles")),
        Err(Ok(AccessControlError::NotAdmin))
    ));

    // The refused calls changed nothing: the super-admin is still the only admin,
    // the role was not granted, and the scope was not paused.
    assert!(client.is_admin(&super_admin));
    assert!(!client.is_admin(&outsider));
    assert!(!client.has_role(&role, &target));
    assert!(!client.is_paused(&symbol_short!("roles")));
}

#[test]
fn audit_trail_rejects_non_maintainer_with_unauthorized() {
    let (env, _super_admin, contract_id) = setup();
    let client = client_for(&env, &contract_id);
    let outsider = Address::generate(&env);

    assert!(matches!(
        client.try_audit_trail(&outsider, &10),
        Err(Ok(shared::Error::Unauthorized))
    ));
}

#[test]
fn role_scoped_invitation_rejects_outsider_with_role_escalation() {
    let (env, super_admin, contract_id) = setup();
    let client = client_for(&env, &contract_id);
    let outsider = Address::generate(&env);
    let invitee = Address::generate(&env);
    let role = Symbol::new(&env, "manager");
    client.create_role(&super_admin, &role);

    assert!(matches!(
        client.try_create_invitation(&outsider, &role, &invitee, &600),
        Err(Ok(AccessControlError::RoleEscalation))
    ));
}

#[test]
fn role_holder_may_invite_but_another_holder_may_not_cancel_the_invitation() {
    let (env, super_admin, contract_id) = setup();
    let client = client_for(&env, &contract_id);
    let inviter = Address::generate(&env);
    let other_holder = Address::generate(&env);
    let invitee = Address::generate(&env);
    let role = Symbol::new(&env, "manager");
    client.create_role(&super_admin, &role);
    client.grant_role(&super_admin, &role, &inviter);
    client.grant_role(&super_admin, &role, &other_holder);

    // Role-scoped: any holder of `role` may invite.
    client.create_invitation(&inviter, &role, &invitee, &600);

    // Owner-scoped: only the original inviter or a maintainer may cancel it.
    assert!(matches!(
        client.try_revoke_invitation(&other_holder, &role, &invitee),
        Err(Ok(AccessControlError::RoleEscalation))
    ));

    // The refused cancel left the invitation in place, so the maintainer can still revoke it.
    client.revoke_invitation(&super_admin, &role, &invitee);
}

#[test]
fn owner_scoped_cancel_rejects_outsider_with_role_escalation_and_keeps_invitation() {
    let (env, super_admin, contract_id) = setup();
    let client = client_for(&env, &contract_id);
    let outsider = Address::generate(&env);
    let invitee = Address::generate(&env);
    let role = Symbol::new(&env, "manager");
    client.create_role(&super_admin, &role);
    client.create_invitation(&super_admin, &role, &invitee, &600);

    assert!(matches!(
        client.try_revoke_invitation(&outsider, &role, &invitee),
        Err(Ok(AccessControlError::RoleEscalation))
    ));

    client.revoke_invitation(&super_admin, &role, &invitee);
}
