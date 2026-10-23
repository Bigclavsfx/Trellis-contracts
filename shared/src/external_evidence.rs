//! Authenticated external evidence ingestion; existing unsigned exports stay unchanged.
use soroban_sdk::{contracttype, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env, Symbol};

use crate::{
    auth::require_admin,
    evidence::{verify_bundle, AuditEvidenceBundle},
};

pub const MAX_EXTERNAL_RECORDS: u32 = 50;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedExternalEvidence {
    pub source: Symbol,
    pub expires_ledger: u32,
    pub bundle: AuditEvidenceBundle,
    pub signature: BytesN<64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceImportError {
    Unauthorized,
    UnknownSource,
    InvalidBundle,
    Expired,
    Conflict,
}

/// Admin-authenticated source key rotation/revocation. None revokes a source.
pub fn configure_source(
    env: &Env,
    caller: &Address,
    source: Symbol,
    key: Option<BytesN<32>>,
) -> Result<(), EvidenceImportError> {
    require_admin(env, caller).map_err(|_| EvidenceImportError::Unauthorized)?;
    let storage_key = (symbol_short!("ext_src"), source);
    match key {
        Some(key) => env.storage().instance().set(&storage_key, &key),
        None => env.storage().instance().remove(&storage_key),
    }
    Ok(())
}

/// Sign these exact bytes: SHA-256 of canonical XDR, including all bundle metadata,
/// the destination contract, source and validity window (domain/schema v1).
pub fn signing_message(env: &Env, evidence: &SignedExternalEvidence) -> Bytes {
    let payload = (
        Bytes::from_slice(env, b"trellis_external_evidence_v1"),
        env.current_contract_address(),
        env.ledger().network_id(),
        evidence.source.clone(),
        evidence.expires_ledger,
        evidence.bundle.clone(),
    )
        .to_xdr(env);
    let digest: BytesN<32> = env.crypto().sha256(&payload).into();
    digest.into()
}

/// Returns false for an exact authenticated retry, true for a new import.
/// Invalid signatures abort in the Soroban host before any storage mutation.
pub fn import_external_evidence(
    env: &Env,
    caller: &Address,
    evidence: &SignedExternalEvidence,
) -> Result<bool, EvidenceImportError> {
    require_admin(env, caller).map_err(|_| EvidenceImportError::Unauthorized)?;
    let key: BytesN<32> = env
        .storage()
        .instance()
        .get(&(symbol_short!("ext_src"), evidence.source.clone()))
        .ok_or(EvidenceImportError::UnknownSource)?;
    if evidence.bundle.record_count > MAX_EXTERNAL_RECORDS
        || evidence.bundle.records.len() > MAX_EXTERNAL_RECORDS
        || !verify_bundle(env, &evidence.bundle)
    {
        return Err(EvidenceImportError::InvalidBundle);
    }
    if env.ledger().sequence() > evidence.expires_ledger {
        return Err(EvidenceImportError::Expired);
    }
    let message = signing_message(env, evidence);
    env.crypto()
        .ed25519_verify(&key, &message, &evidence.signature);
    let receipt_key = (
        symbol_short!("ext_rcpt"),
        evidence.source.clone(),
        evidence.bundle.bundle_id,
    );
    if let Some(previous) = env.storage().persistent().get::<_, Bytes>(&receipt_key) {
        if previous != message {
            return Err(EvidenceImportError::Conflict);
        }
        env.storage().persistent().extend_ttl(
            &receipt_key,
            crate::storage::PERSISTENT_TTL_THRESHOLD,
            crate::storage::PERSISTENT_BUMP_AMOUNT,
        );
        return Ok(false);
    }
    env.storage().persistent().set(&receipt_key, &message);
    env.storage().persistent().extend_ttl(
        &receipt_key,
        crate::storage::PERSISTENT_TTL_THRESHOLD,
        crate::storage::PERSISTENT_BUMP_AMOUNT,
    );
    env.events().publish(
        (symbol_short!("ext_ev"), evidence.source.clone()),
        (evidence.bundle.bundle_id, message),
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{create_evidence_bundle, RawEvidenceInput, REDACTION_SUPPORT};
    use ed25519_dalek::{Signer, SigningKey};
    use soroban_sdk::{
        contract, contractimpl,
        testutils::{Address as _, Ledger},
        Vec,
    };

    #[contract]
    struct Fixture;

    #[contractimpl]
    impl Fixture {
        pub fn ingest(env: Env, caller: Address, evidence: SignedExternalEvidence) -> bool {
            import_external_evidence(&env, &caller, &evidence).unwrap()
        }
    }

    fn setup() -> (Env, Address, Address, SigningKey) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, Fixture);
        let admin = Address::generate(&env);
        let signing = SigningKey::from_bytes(&[42; 32]);
        env.as_contract(&id, || {
            crate::auth::set_admin(&env, &admin);
            configure_source(
                &env,
                &admin,
                symbol_short!("ngo"),
                Some(BytesN::from_array(
                    &env,
                    &signing.verifying_key().to_bytes(),
                )),
            )
            .unwrap();
        });
        (env, id, admin, signing)
    }

    fn message_array(env: &Env, evidence: &SignedExternalEvidence) -> [u8; 32] {
        let mut bytes = [0; 32];
        signing_message(env, evidence).copy_into_slice(&mut bytes);
        bytes
    }

    fn signed(env: &Env, key: &SigningKey) -> SignedExternalEvidence {
        let mut evidence = SignedExternalEvidence {
            source: symbol_short!("ngo"),
            expires_ledger: 100,
            bundle: create_evidence_bundle(
                env,
                1,
                symbol_short!("ticket"),
                REDACTION_SUPPORT,
                &BytesN::from_array(env, &[1; 32]),
                &[RawEvidenceInput {
                    record_id: 1,
                    timestamp: 5,
                    actor: Address::generate(env),
                    module: symbol_short!("aid"),
                    action: symbol_short!("claim"),
                    correlation_id: BytesN::from_array(env, &[2; 32]),
                    sensitive_payload: Bytes::from_slice(env, b"external receipt"),
                    status_code: 0,
                }],
            ),
            signature: BytesN::from_array(env, &[0; 64]),
        };
        evidence.signature =
            BytesN::from_array(env, &key.sign(&message_array(env, &evidence)).to_bytes());
        evidence
    }

    #[test]
    fn authenticated_retry_conflict_expiry_and_revocation() {
        let (env, id, admin, key) = setup();
        let evidence = env.as_contract(&id, || signed(&env, &key));
        let ingest = |caller: &Address, value: &SignedExternalEvidence| {
            env.as_contract(&id, || import_external_evidence(&env, caller, value))
        };
        assert_eq!(ingest(&admin, &evidence), Ok(true));
        assert_eq!(ingest(&admin, &evidence), Ok(false));
        let mut changed = evidence.clone();
        changed.bundle.ticket_id = symbol_short!("other");
        changed.signature = env.as_contract(&id, || {
            BytesN::from_array(&env, &key.sign(&message_array(&env, &changed)).to_bytes())
        });
        assert_eq!(ingest(&admin, &changed), Err(EvidenceImportError::Conflict));
        let stranger = Address::generate(&env);
        assert_eq!(
            ingest(&stranger, &evidence),
            Err(EvidenceImportError::Unauthorized)
        );
        assert_eq!(
            env.as_contract(&id, || configure_source(
                &env,
                &stranger,
                symbol_short!("ngo"),
                None
            )),
            Err(EvidenceImportError::Unauthorized)
        );
        let mut invalid = evidence.clone();
        invalid.bundle.record_count = 2;
        assert_eq!(
            ingest(&admin, &invalid),
            Err(EvidenceImportError::InvalidBundle)
        );
        invalid.bundle.records = Vec::new(&env);
        invalid.bundle.record_count = MAX_EXTERNAL_RECORDS + 1;
        assert_eq!(
            ingest(&admin, &invalid),
            Err(EvidenceImportError::InvalidBundle)
        );
        env.ledger().with_mut(|l| l.sequence_number = 101);
        assert_eq!(ingest(&admin, &evidence), Err(EvidenceImportError::Expired));
        env.as_contract(&id, || {
            configure_source(&env, &admin, symbol_short!("ngo"), None)
        })
        .unwrap();
        assert_eq!(
            ingest(&admin, &evidence),
            Err(EvidenceImportError::UnknownSource)
        );
    }

    #[test]
    fn bad_signature_writes_nothing_and_valid_retry_recovers() {
        let (env, id, admin, key) = setup();
        let valid = env.as_contract(&id, || signed(&env, &key));
        let mut invalid = valid.clone();
        invalid.signature = BytesN::from_array(&env, &[0; 64]);
        let client = FixtureClient::new(&env, &id);
        assert!(client.try_ingest(&admin, &invalid).is_err());
        assert!(client.ingest(&admin, &valid));
        assert!(!client.ingest(&admin, &valid));
    }

    #[test]
    fn admin_identity_without_signature_is_rejected() {
        let env = Env::default();
        let id = env.register_contract(None, Fixture);
        let admin = Address::generate(&env);
        let key = SigningKey::from_bytes(&[42; 32]);
        let valid = env.as_contract(&id, || {
            crate::auth::set_admin(&env, &admin);
            signed(&env, &key)
        });
        assert!(FixtureClient::new(&env, &id)
            .try_ingest(&admin, &valid)
            .is_err());
    }

    #[test]
    fn tampered_metadata_aborts_signature_verification() {
        let (env, id, admin, key) = setup();
        let valid = env.as_contract(&id, || signed(&env, &key));
        let mut evidence = valid.clone();
        evidence.bundle.created_at += 1;
        let client = FixtureClient::new(&env, &id);
        assert!(client.try_ingest(&admin, &evidence).is_err());
        assert!(client.ingest(&admin, &valid));
    }

    #[test]
    fn signature_cannot_cross_contracts() {
        let (env, id, admin, key) = setup();
        let evidence = env.as_contract(&id, || signed(&env, &key));
        let other = env.register_contract(None, Fixture);
        env.as_contract(&other, || {
            crate::auth::set_admin(&env, &admin);
            configure_source(
                &env,
                &admin,
                symbol_short!("ngo"),
                Some(BytesN::from_array(&env, &key.verifying_key().to_bytes())),
            )
            .unwrap();
        });
        assert!(FixtureClient::new(&env, &other)
            .try_ingest(&admin, &evidence)
            .is_err());
        assert!(FixtureClient::new(&env, &id).ingest(&admin, &evidence));
    }
}
