#![no_std]
//! # Registry Contract
//!
//! Central contract discovery and version tracking for Trellis.
//!
//! ## Overview
//!
//! The Registry Contract maintains a global directory of Trellis contracts, enabling:
//! - **Contract discovery**: Look up live contract addresses by name
//! - **Version history**: Track all versions of each contract
//! - **Upgrade tracking**: See when a contract was replaced
//! - **Cross-contract communication**: Contracts query the registry to find peers
//!
//! ## Example Flow
//!
//! 1. Admin calls [`RegistryContract::set_contract`] with contract name and address
//! 2. Applications query [`RegistryContract::get_contract`] to discover endpoints
//! 3. When a contract is upgraded, admin calls `set_contract` again
//! 4. Registry stores both versions; `get_version_history` shows the timeline
//!
//! ## Queries
//!
//! - [`RegistryContract::get_contract`]: Get the current address for a named contract
//! - [`RegistryContract::get_version_history`]: View all historical versions
//! - [`RegistryContract::get_all_contracts`]: List all registered contracts
//!
//! For full API details, see the module items below.

use shared::events::{emit_action_executed, emit_module_initialized};
use shared::storage::{persistent_get, persistent_read, persistent_set};
use shared::{auth, errors::Error};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env, Map, Symbol,
    Vec,
};

// Storage keys
const KEY_CONTRACTS: Symbol = symbol_short!("contracts");
const KEY_METADATA: Symbol = symbol_short!("metadata");
const KEY_HISTORY: Symbol = symbol_short!("history");
const KEY_NAMES: Symbol = symbol_short!("names");
const KEY_META_NAMES: Symbol = symbol_short!("meta_nms");
const KEY_DEACTIVATED: Symbol = symbol_short!("deact");
const KEY_DEACT_HIST: Symbol = symbol_short!("deacth");

/// Bound global registry scans so getters and writes stay within Soroban
/// execution budgets. Version history is independently bounded per name.
pub const MAX_REGISTRY_ENTRIES: u32 = 64;
pub const MAX_VERSION_HISTORY: u32 = 64;

/// Represents a registered contract with its address and version.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractRegistration {
    pub address: Address,
    pub version: u32,
}

/// Represents metadata for a contract, module, or entity.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataEntry {
    /// URI pointing to the metadata (e.g., IPFS, HTTPS)
    pub uri: Bytes,
    /// SHA-256 hash of the metadata content for verification
    pub hash: Bytes,
    /// Whether this entry can be updated after creation
    pub immutable: bool,
    /// Timestamp when this entry was created or last updated
    pub updated_at: u64,
    /// Version of the metadata schema
    pub schema_version: u32,
}

/// Combined registry entry containing both contract and metadata information.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryEntry {
    pub contract: ContractRegistration,
    pub metadata: MetadataEntry,
}

/// Records the deactivation state of a registered contract name.
///
/// A deactivated record remains discoverable via `get_contract` so that
/// callers can observe the state, but restricted operations must check
/// [`RegistryContract::is_active`] before executing.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeactivationState {
    pub deactivated: bool,
    pub deactivated_at: u64,
}
// ===========================================================================
// Contract Implementation
#[contract]
pub struct RegistryContract;

/// The registry contract does not accept a caller-supplied correlation ID
/// (registration is not tied to a request-scoped workflow), so every
/// correlated event uses the canonical zero correlation ID.
fn zero_correlation_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

#[contractimpl]
impl RegistryContract {
    // ─── Initialization ──────────────────────────────────────────────────────

    /// Initialise the contract, setting the admin address.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        auth::initialize_admin(&env, &admin)?;
        emit_module_initialized(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("registry"),
            1,
            &admin,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    // ─── Contract Registration ─────────────────────────────────────────────

    /// Register or update a contract address for `name` and record the version.
    ///
    /// **Gas optimization**: The history Vec is only deserialized and
    /// re-serialized when a genuinely new version is registered.  When the
    /// version already exists (common on repeated deploys), the expensive
    /// Vec read + linear scan is skipped entirely.
    pub fn set_contract(
        env: Env,
        caller: Address,
        name: Symbol,
        address: Address,
        version: u32,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;

        // A deactivated name must be reactivated before it can be re-registered.
        if let Some(state) = persistent_read::<_, DeactivationState>(&env, &(KEY_DEACTIVATED, name.clone())) {
            if state.deactivated {
                return Err(Error::InvalidArgument);
            }
        }

        ensure_name_capacity(&env, &KEY_NAMES, &name)?;
        let mut versions: Vec<u32> =
            persistent_get(&env, &(KEY_HISTORY, name.clone())).unwrap_or_else(|| Vec::new(&env));
        let already_present =
            !versions.is_empty() && versions.get(versions.len() - 1).unwrap_or(0) == version;
        if !already_present && !versions.iter().any(|existing| existing == version) {
            if versions.len() >= MAX_VERSION_HISTORY {
                return Err(Error::InvalidArgument);
            }
            versions.push_back(version);
        }

        persistent_set(
            &env,
            &(KEY_CONTRACTS, name.clone()),
            &ContractRegistration {
                address: address.clone(),
                version,
            },
        );
        push_unique_symbol(&env, &KEY_NAMES, &name);

        // Check the latest version first to avoid deserializing the full
        // history Vec when the version already exists.
        // Record version history
        if !already_present {
            persistent_set(&env, &(KEY_HISTORY, name.clone()), &versions);
        }

        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("registry"),
            symbol_short!("set_ctr"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Resolve the latest registered address and version for `name`.
    pub fn get_contract(env: Env, name: Symbol) -> Result<(Address, u32), Error> {
        let registration: ContractRegistration =
            persistent_read(&env, &(KEY_CONTRACTS, name)).ok_or(Error::NotFound)?;
        Ok((registration.address, registration.version))
    }

    /// Return the version history for `name`.
    pub fn get_version_history(env: Env, name: Symbol) -> Result<Vec<u32>, Error> {
        persistent_read(&env, &(KEY_HISTORY, name)).ok_or(Error::NotFound)
    }

    // ─── Deactivation ───────────────────────────────────────────────────────

    /// Deactivate a registered contract record.
    ///
    /// Only the admin may deactivate, and only records that currently exist
    /// and are not already deactivated are eligible. Deactivation is a soft
    /// state change: the record remains discoverable but restricted
    /// operations must reject it until it is reactivated.
    pub fn deactivate_contract(
        env: Env,
        caller: Address,
        name: Symbol,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;

        // Eligibility: the record must exist.
        if persistent_read::<_, ContractRegistration>(&env, &(KEY_CONTRACTS, name.clone())).is_none() {
            return Err(Error::NotFound);
        }

        // Eligibility: must not already be deactivated.
        if let Some(state) = persistent_read::<_, DeactivationState>(&env, &(KEY_DEACTIVATED, name.clone())) {
            if state.deactivated {
                return Err(Error::InvalidArgument);
            }
        }

        let timestamp = env.ledger().timestamp();
        let state = DeactivationState {
            deactivated: true,
            deactivated_at: timestamp,
        };
        persistent_set(&env, &(KEY_DEACTIVATED, name.clone()), &state);

        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("registry"),
            symbol_short!("deact"),
            &caller,
            true,
            timestamp,
        );
        Ok(())
    }

    /// Reactivate a previously deactivated contract record.
    ///
    /// Only the admin may reactivate, and only records currently marked as
    /// deactivated are eligible.
    pub fn reactivate_contract(
        env: Env,
        caller: Address,
        name: Symbol,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;

        let state: DeactivationState = persistent_read(&env, &(KEY_DEACTIVATED, name.clone()))
            .ok_or(Error::NotFound)?;
        if !state.deactivated {
            return Err(Error::InvalidArgument);
        }

        let timestamp = env.ledger().timestamp();
        let new_state = DeactivationState {
            deactivated: false,
            deactivated_at: timestamp,
        };
        persistent_set(&env, &(KEY_DEACTIVATED, name.clone()), &new_state);

        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("registry"),
            symbol_short!("react"),
            &caller,
            true,
            timestamp,
        );
        Ok(())
    }

    /// Return whether a registered name is currently active.
    ///
    /// Names that have never been deactivated are considered active.
    pub fn is_active(env: Env, name: Symbol) -> Result<bool, Error> {
        persistent_read::<_, ContractRegistration>(&env, &(KEY_CONTRACTS, name.clone()))
            .ok_or(Error::NotFound)?;
        match persistent_read::<_, DeactivationState>(&env, &(KEY_DEACTIVATED, name)) {
            Some(state) => Ok(!state.deactivated),
            None => Ok(true),
        }
    }

    /// Return the deactivation state for a name, if it has ever been toggled.
    pub fn get_deactivation_state(env: Env, name: Symbol) -> Result<DeactivationState, Error> {
        persistent_read(&env, &(KEY_DEACTIVATED, name)).ok_or(Error::NotFound)
    }

    // ─── Metadata Registry ──────────────────────────────────────────────────

    /// Register or update metadata for an identifier.
    ///
    /// # Arguments
    /// * `caller` - Must be the admin
    /// * `name` - The identifier (e.g., "treasury", "oracle")
    /// * `uri` - URI pointing to the metadata (IPFS, HTTPS, etc.)
    /// * `hash` - SHA-256 hash of the metadata content for verification
    /// * `immutable` - If true, this entry cannot be updated after creation
    /// * `schema_version` - Version of the metadata schema
    pub fn set_metadata(
        env: Env,
        caller: Address,
        name: Symbol,
        uri: Bytes,
        hash: Bytes,
        immutable: bool,
        schema_version: u32,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;

        ensure_name_capacity(&env, &KEY_META_NAMES, &name)?;

        // Check if entry exists and is immutable
        if let Some(existing) =
            persistent_read::<_, MetadataEntry>(&env, &(KEY_METADATA, name.clone()))
        {
            if existing.immutable {
                return Err(Error::ImmutableEntry);
            }
        }

        // Validate hash (ensure it's 32 bytes for SHA-256)
        if hash.len() != 32 {
            return Err(Error::InvalidHash);
        }

        // Validate URI (ensure safe schemes like HTTPS, IPFS, Arweave; reject javascript:, data:, CRLF)
        shared::sanitize::validate_external_url(&uri, shared::sanitize::MAX_URL_LEN, false)?;

        let entry = MetadataEntry {
            uri,
            hash,
            immutable,
            updated_at: env.ledger().timestamp(),
            schema_version,
        };

        persistent_set(&env, &(KEY_METADATA, name.clone()), &entry);
        push_unique_symbol(&env, &KEY_META_NAMES, &name);

        Ok(())
    }

    /// Retrieve metadata for an identifier.
    pub fn get_metadata(env: Env, name: Symbol) -> Result<MetadataEntry, Error> {
        persistent_read(&env, &(KEY_METADATA, name)).ok_or(Error::MetadataNotFound)
    }

    /// Get the metadata hash for an identifier (for verification).
    pub fn get_metadata_hash(env: Env, name: Symbol) -> Result<Bytes, Error> {
        let entry = Self::get_metadata(env, name)?;
        Ok(entry.hash)
    }

    /// Check if an entry is immutable.
    pub fn is_immutable(env: Env, name: Symbol) -> Result<bool, Error> {
        let entry = Self::get_metadata(env, name)?;
        Ok(entry.immutable)
    }

    /// Get the full registry entry (contract + metadata) for an identifier.
    pub fn get_registry_entry(env: Env, name: Symbol) -> Result<RegistryEntry, Error> {
        let contract: ContractRegistration =
            persistent_read(&env, &(KEY_CONTRACTS, name.clone())).ok_or(Error::NotFound)?;
        let metadata: MetadataEntry =
            persistent_read(&env, &(KEY_METADATA, name)).ok_or(Error::MetadataNotFound)?;

        Ok(RegistryEntry { contract, metadata })
    }

    /// List all registered names.
    pub fn list_names(env: Env) -> Result<Vec<Symbol>, Error> {
        Ok(persistent_read(&env, &KEY_NAMES).unwrap_or_else(|| Vec::new(&env)))
    }

    /// List all metadata entries.
    pub fn list_metadata_entries(env: Env) -> Result<Map<Symbol, MetadataEntry>, Error> {
        let mut metadata_map: Map<Symbol, MetadataEntry> = Map::new(&env);
        let names: Vec<Symbol> =
            persistent_read(&env, &KEY_META_NAMES).unwrap_or_else(|| Vec::new(&env));
        for name in names.iter() {
            if let Some(entry) =
                persistent_read::<_, MetadataEntry>(&env, &(KEY_METADATA, name.clone()))
            {
                metadata_map.set(name, entry);
            }
        }
        Ok(metadata_map)
    }
}

fn push_unique_symbol(env: &Env, key: &Symbol, value: &Symbol) {
    let mut values: Vec<Symbol> = persistent_read(env, key).unwrap_or_else(|| Vec::new(env));
    if !values.iter().any(|existing| existing == *value) {
        values.push_back(value.clone());
        persistent_set(env, key, &values);
    }
}

/// Reject a new registry name before any storage mutation once its directory
/// would exceed the maximum size. Existing names remain freely updatable.
fn ensure_name_capacity(env: &Env, key: &Symbol, name: &Symbol) -> Result<(), Error> {
    let names: Vec<Symbol> = persistent_get(env, key).unwrap_or_else(|| Vec::new(env));
    if names.iter().any(|existing| existing == *name) || names.len() < MAX_REGISTRY_ENTRIES {
        Ok(())
    } else {
        Err(Error::InvalidArgument)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use shared::errors::Error;
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Bytes, Symbol,
    };

    fn create_test_hash(env: &Env) -> Bytes {
        // Create a 32-byte hash for testing
        let mut hash = Bytes::new(env);
        for i in 0..32 {
            hash.push_back(i as u8);
        }
        hash
    }

    #[test]
    fn registers_and_resolves_contracts_with_version_history() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name = Symbol::new(&env, "treasury");
        assert!(registry
            .try_set_contract(&admin, &name, &treasury, &1_u32)
            .is_ok());
        let upgraded_treasury = Address::generate(&env);
        assert!(registry
            .try_set_contract(&admin, &name, &upgraded_treasury, &2_u32)
            .is_ok());

        let (resolved_address, version) = registry.get_contract(&name);
        assert_eq!(resolved_address, upgraded_treasury);
        assert_eq!(version, 2_u32);

        let history = registry.get_version_history(&name);
        assert_eq!(history.len(), 2);
        assert_eq!(history.get(0).unwrap(), 1_u32);
        assert_eq!(history.get(1).unwrap(), 2_u32);
    }

    #[test]
    fn registry_rejects_the_first_name_over_the_scan_limit_without_writing_it() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);
        registry.initialize(&admin);

        for index in 0..MAX_REGISTRY_ENTRIES {
            let name = Symbol::new(&env, &std::format!("c{index}"));
            let address = Address::generate(&env);
            registry.set_contract(&admin, &name, &address, &1);
        }

        let overflow_name = Symbol::new(&env, "overflow_name");
        let overflow_address = Address::generate(&env);
        assert_eq!(
            registry.try_set_contract(&admin, &overflow_name, &overflow_address, &1),
            Err(Ok(Error::InvalidArgument))
        );
        assert_eq!(registry.list_names().len(), MAX_REGISTRY_ENTRIES);
        assert_eq!(
            registry.try_get_contract(&overflow_name),
            Err(Ok(Error::NotFound))
        );
    }

    #[test]
    fn version_history_rejects_overflow_without_replacing_the_current_version() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);
        registry.initialize(&admin);
        let name = Symbol::new(&env, "history_bound");

        for version in 1..=MAX_VERSION_HISTORY {
            let address = Address::generate(&env);
            registry.set_contract(&admin, &name, &address, &version);
        }

        let last_address = Address::generate(&env);
        assert_eq!(
            registry.try_set_contract(&admin, &name, &last_address, &(MAX_VERSION_HISTORY + 1)),
            Err(Ok(Error::InvalidArgument))
        );
        assert_eq!(
            registry.get_version_history(&name).len(),
            MAX_VERSION_HISTORY
        );
        assert_eq!(registry.get_contract(&name).1, MAX_VERSION_HISTORY);
    }

    #[test]
    fn rejects_non_admin_registration() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        let treasury = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name = Symbol::new(&env, "treasury");
        assert!(matches!(
            registry.try_set_contract(&attacker, &name, &treasury, &1_u32),
            Err(Ok(Error::Unauthorized))
        ));
        assert!(registry.list_names().is_empty());
        assert_eq!(registry.try_get_contract(&name), Err(Ok(Error::NotFound)));
    }

    // ===========================================================================
    // Gas benchmark tests
    // ===========================================================================

    /// Benchmark: set_contract fast-path for existing version.
    ///
    /// Before: every call deserialized the full history Vec and ran a linear
    /// scan to check for duplicates.
    /// After: the last version is checked first (O(1)) — if it matches, the
    /// expensive Vec deserialization + linear scan is skipped entirely.
    #[test]
    fn gas_bench_set_contract_same_version_skips_history() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name = Symbol::new(&env, "treasury");
        let addr1 = Address::generate(&env);

        // First registration — full history write
        assert!(registry
            .try_set_contract(&admin, &name, &addr1, &1_u32)
            .is_ok());

        // Second call with same version — fast path, no history update
        let result = registry.try_set_contract(&admin, &name, &addr1, &1_u32);
        assert!(result.is_ok());

        // Verify history still has only 1 entry
        let history = registry.get_version_history(&name);
        assert_eq!(history.len(), 1);

        // New version — normal path, history updated
        let addr2 = Address::generate(&env);
        assert!(registry
            .try_set_contract(&admin, &name, &addr2, &2_u32)
            .is_ok());
        let history = registry.get_version_history(&name);
        assert_eq!(history.len(), 2);
    }

    // ─── Metadata Tests ─────────────────────────────────────────────────────

    #[test]
    fn registers_and_retrieves_metadata() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(1000);
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name = Symbol::new(&env, "test_contract");
        let uri = Bytes::from_slice(&env, b"ipfs://QmTest123");
        let hash = create_test_hash(&env);
        let immutable = false;
        let schema_version = 1;

        assert!(registry
            .try_set_metadata(&admin, &name, &uri, &hash, &immutable, &schema_version)
            .is_ok());

        let metadata = registry.get_metadata(&name);
        assert_eq!(metadata.uri, uri);
        assert_eq!(metadata.hash, hash);
        assert_eq!(metadata.immutable, false);
        assert_eq!(metadata.schema_version, 1);
        assert!(metadata.updated_at > 0);
    }

    #[test]
    fn prevents_updating_immutable_entry() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name = Symbol::new(&env, "immutable_contract");
        let uri = Bytes::from_slice(&env, b"ipfs://QmImmutable");
        let hash = create_test_hash(&env);
        let immutable = true;
        let schema_version = 1;

        // Create immutable entry
        assert!(registry
            .try_set_metadata(&admin, &name, &uri, &hash, &immutable, &schema_version)
            .is_ok());

        // Try to update it - should fail
        let new_uri = Bytes::from_slice(&env, b"ipfs://QmNew");
        assert!(matches!(
            registry.try_set_metadata(&admin, &name, &new_uri, &hash, &immutable, &schema_version),
            Err(Ok(Error::ImmutableEntry))
        ));
    }

    #[test]
    fn updates_mutable_entry() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name = Symbol::new(&env, "mutable_contract");
        let uri1 = Bytes::from_slice(&env, b"ipfs://QmFirst");
        let hash = create_test_hash(&env);
        let immutable = false;
        let schema_version = 1;

        // Create mutable entry
        assert!(registry
            .try_set_metadata(&admin, &name, &uri1, &hash, &immutable, &schema_version)
            .is_ok());

        // Update it - should succeed
        let uri2 = Bytes::from_slice(&env, b"ipfs://QmSecond");
        assert!(registry
            .try_set_metadata(&admin, &name, &uri2, &hash, &immutable, &schema_version)
            .is_ok());

        let metadata = registry.get_metadata(&name);
        assert_eq!(metadata.uri, uri2);
    }

    #[test]
    fn rejects_invalid_hash_length() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name = Symbol::new(&env, "bad_hash_contract");
        let uri = Bytes::from_slice(&env, b"ipfs://QmTest");
        let invalid_hash = Bytes::from_slice(&env, b"short"); // Not 32 bytes
        let immutable = false;
        let schema_version = 1;

        assert!(matches!(
            registry.try_set_metadata(
                &admin,
                &name,
                &uri,
                &invalid_hash,
                &immutable,
                &schema_version
            ),
            Err(Ok(Error::InvalidHash))
        ));
    }

    #[test]
    fn malformed_metadata_payloads_do_not_partially_mutate_storage() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);
        registry.initialize(&admin);

        let name = Symbol::new(&env, "payload_test");
        let original_uri = Bytes::from_slice(&env, b"ipfs://QmOriginal");
        let original_hash = create_test_hash(&env);
        registry.set_metadata(&admin, &name, &original_uri, &original_hash, &false, &1);

        let mut oversized_uri = Bytes::new(&env);
        for _ in 0..=shared::sanitize::MAX_URL_LEN {
            oversized_uri.push_back(b'a');
        }
        assert_eq!(
            registry.try_set_metadata(&admin, &name, &oversized_uri, &original_hash, &false, &1),
            Err(Ok(Error::InvalidArgument))
        );
        let unchanged = registry.get_metadata(&name);
        assert_eq!(unchanged.uri, original_uri);
        assert_eq!(unchanged.hash, original_hash);

        let unsafe_uri = Bytes::from_slice(&env, b"javascript:alert(1)");
        assert_eq!(
            registry.try_set_metadata(&admin, &name, &unsafe_uri, &original_hash, &false, &1),
            Err(Ok(Error::InvalidArgument))
        );
        assert_eq!(registry.get_metadata(&name), unchanged);

        let malformed_name = Symbol::new(&env, "bad_hash");
        let malformed_hash = Bytes::from_slice(&env, b"short");
        assert_eq!(
            registry.try_set_metadata(
                &admin,
                &malformed_name,
                &original_uri,
                &malformed_hash,
                &false,
                &1
            ),
            Err(Ok(Error::InvalidHash))
        );
        assert_eq!(
            registry.try_get_metadata(&malformed_name),
            Err(Ok(Error::MetadataNotFound))
        );
        assert_eq!(registry.list_metadata_entries().len(), 1);
    }

    #[test]
    fn gets_metadata_hash() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name = Symbol::new(&env, "hash_test");
        let uri = Bytes::from_slice(&env, b"ipfs://QmHashTest");
        let hash = create_test_hash(&env);
        let immutable = false;
        let schema_version = 1;

        assert!(registry
            .try_set_metadata(&admin, &name, &uri, &hash, &immutable, &schema_version)
            .is_ok());

        let retrieved_hash = registry.get_metadata_hash(&name);
        assert_eq!(retrieved_hash, hash);
    }

    #[test]
    fn checks_immutability() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name = Symbol::new(&env, "immutability_test");
        let uri = Bytes::from_slice(&env, b"ipfs://QmImmutableTest");
        let hash = create_test_hash(&env);
        let immutable = true;
        let schema_version = 1;

        assert!(registry
            .try_set_metadata(&admin, &name, &uri, &hash, &immutable, &schema_version)
            .is_ok());

        let is_immutable = registry.is_immutable(&name);
        assert_eq!(is_immutable, true);
    }

    #[test]
    fn gets_full_registry_entry() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let contract_addr = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name = Symbol::new(&env, "full_entry");
        let uri = Bytes::from_slice(&env, b"ipfs://QmFullEntry");
        let hash = create_test_hash(&env);
        let immutable = false;
        let schema_version = 1;
        let version = 5_u32;

        // Register contract
        assert!(registry
            .try_set_contract(&admin, &name, &contract_addr, &version)
            .is_ok());

        // Register metadata
        assert!(registry
            .try_set_metadata(&admin, &name, &uri, &hash, &immutable, &schema_version)
            .is_ok());

        // Get full entry
        let entry = registry.get_registry_entry(&name);
        assert_eq!(entry.contract.address, contract_addr);
        assert_eq!(entry.contract.version, version);
        assert_eq!(entry.metadata.uri, uri);
        assert_eq!(entry.metadata.hash, hash);
        assert_eq!(entry.metadata.immutable, false);
        assert_eq!(entry.metadata.schema_version, schema_version);
    }

    #[test]
    fn lists_registered_names() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let contract1 = Address::generate(&env);
        let contract2 = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);

        registry.initialize(&admin);

        let name1 = Symbol::new(&env, "contract_a");
        let name2 = Symbol::new(&env, "contract_b");

        assert!(registry
            .try_set_contract(&admin, &name1, &contract1, &1_u32)
            .is_ok());
        assert!(registry
            .try_set_contract(&admin, &name2, &contract2, &1_u32)
            .is_ok());

        let names = registry.list_names();
        assert_eq!(names.len(), 2);
        assert!(names.iter().any(|n| n == name1));
        assert!(names.iter().any(|n| n == name2));
    }

    #[test]
    fn worst_case_registry_reads_stay_within_budget() {
        const CPU_LIMIT: u64 = 10_000_000;
        const MEMORY_LIMIT: u64 = 2_000_000;

        let env = Env::default();
        env.mock_all_auths();
        let registry_id = env.register_contract(None, RegistryContract);
        let admin = Address::generate(&env);
        let registry = RegistryContractClient::new(&env, &registry_id);
        registry.initialize(&admin);

        // Fill the directory to its supported high-cardinality limit before
        // measuring the full list/search read.
        for index in 0..MAX_REGISTRY_ENTRIES {
            let name = Symbol::new(&env, &std::format!("c{index}"));
            let address = Address::generate(&env);
            registry.set_contract(&admin, &name, &address, &1);
        }

        env.budget().reset_unlimited();
        let cpu_before = env.budget().cpu_instruction_cost();
        let memory_before = env.budget().memory_bytes_cost();
        let names = registry.list_names();
        let cpu = env.budget().cpu_instruction_cost().saturating_sub(cpu_before);
        let memory = env.budget().memory_bytes_cost().saturating_sub(memory_before);
        assert_eq!(names.len(), MAX_REGISTRY_ENTRIES);
        assert!(
            cpu <= CPU_LIMIT,
            "full registry scan used {cpu} CPU instructions (limit {CPU_LIMIT})"
        );
        assert!(
            memory <= MEMORY_LIMIT,
            "full registry scan used {memory} memory bytes (limit {MEMORY_LIMIT})"
        );

        // A single key can also accumulate a full supported ledger history.
        let history_name = Symbol::new(&env, "history");
        for version in 1..=MAX_VERSION_HISTORY {
            let address = Address::generate(&env);
            registry.set_contract(&admin, &history_name, &address, &version);
        }

        env.budget().reset_unlimited();
        let cpu_before = env.budget().cpu_instruction_cost();
        let memory_before = env.budget().memory_bytes_cost();
        let history = registry.get_version_history(&history_name);
        let cpu = env.budget().cpu_instruction_cost().saturating_sub(cpu_before);
        let memory = env.budget().memory_bytes_cost().saturating_sub(memory_before);
        assert_eq!(history.len(), MAX_VERSION_HISTORY);
        assert!(
            cpu <= CPU_LIMIT,
            "full version-history read used {cpu} CPU instructions (limit {CPU_LIMIT})"
        );
        assert!(
            memory <= MEMORY_LIMIT,
            "full version-history read used {memory} memory bytes (limit {MEMORY_LIMIT})"
        );
    }
}
