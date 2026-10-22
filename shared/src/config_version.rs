//! Configuration version checks across environments.
//!
//! Ensures configuration consistency between testnet, mainnet, and development
//! environments by tracking version hashes and validating compatibility.
//!
//! All parsing operates on canonical byte forms (a `soroban_sdk::String` is
//! copied into a bounded buffer first), so the module stays `no_std`-clean and
//! deterministic: the same logical version string always produces the same
//! compatibility report.

use soroban_sdk::{contracterror, contracttype, BytesN, Env, String, Vec};

/// Longest semantic-version string accepted by the validators. Bounds the
/// stack buffer used to copy a `String` before parsing.
const MAX_VERSION_LEN: usize = 32;

/// Configuration version for tracking changes across environments.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigVersion {
    /// Semantic version (e.g., "1.2.3")
    pub version: String,
    /// Hash of the configuration content
    pub content_hash: BytesN<32>,
    /// Environment this config is for
    pub environment: Environment,
    /// Timestamp when this version was created
    pub created_at: u64,
    /// Whether this version is approved for deployment
    pub is_approved: bool,
}

/// Supported deployment environments.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Environment {
    Development,
    Testnet,
    Mainnet,
}

/// Configuration compatibility check result.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityCheck {
    pub is_compatible: bool,
    pub version_a: String,
    pub version_b: String,
    pub breaking_changes: Vec<String>,
    pub warnings: Vec<String>,
}

/// Errors for configuration version operations.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ConfigVersionError {
    /// Version format is invalid
    InvalidVersionFormat = 1,
    /// Environment mismatch
    EnvironmentMismatch = 2,
    /// Version is not approved for deployment
    NotApproved = 3,
    /// Breaking changes detected
    BreakingChangesDetected = 4,
    /// Config version not found
    NotFound = 5,
}

/// Parses a `major.minor.patch` string into numeric components.
///
/// Returns `None` when the input does not have exactly three non-empty,
/// digit-only components (no leading/trailing/double dots, no overflow).
fn parse_semver(raw: &[u8]) -> Option<(u32, u32, u32)> {
    let mut comps = [0u32; 3];
    let mut idx: usize = 0;
    let mut cur: u32 = 0;
    let mut have_digit = false;
    for &b in raw {
        match b {
            b'.' => {
                if !have_digit || idx >= 2 {
                    return None;
                }
                comps[idx] = cur;
                idx += 1;
                cur = 0;
                have_digit = false;
            }
            b'0'..=b'9' => {
                cur = cur.checked_mul(10)?.checked_add((b - b'0') as u32)?;
                have_digit = true;
            }
            _ => return None,
        }
    }
    if !have_digit || idx != 2 {
        return None;
    }
    comps[2] = cur;
    Some((comps[0], comps[1], comps[2]))
}

/// Copies a bounded `String` into a reusable buffer; `None` when too long.
fn string_bytes<'a>(string: &String, buffer: &'a mut [u8; MAX_VERSION_LEN]) -> Option<&'a [u8]> {
    let len = string.len() as usize;
    if len == 0 || len > MAX_VERSION_LEN {
        return None;
    }
    string.copy_into_slice(&mut buffer[..len]);
    Some(&buffer[..len])
}

/// Validate semantic version format (major.minor.patch).
pub fn validate_version_format(version: &String) -> Result<(), ConfigVersionError> {
    let mut buffer = [0u8; MAX_VERSION_LEN];
    match string_bytes(version, &mut buffer) {
        Some(bytes) => {
            if parse_semver(bytes).is_some() {
                Ok(())
            } else {
                Err(ConfigVersionError::InvalidVersionFormat)
            }
        }
        // Empty or over-long version strings are format failures, not
        // copy failures: callers receive a stable typed error.
        None => Err(ConfigVersionError::InvalidVersionFormat),
    }
}

/// Check if version B is compatible with version A.
/// Compatible means: same major version, minor version >= A's minor.
pub fn check_compatibility(env: &Env, version_a: &str, version_b: &str) -> CompatibilityCheck {
    let mut breaking_changes = Vec::new(env);
    let mut warnings = Vec::new(env);

    let parsed_a = parse_semver(version_a.as_bytes());
    let parsed_b = parse_semver(version_b.as_bytes());

    if let (Some((major_a, minor_a, patch_a)), Some((major_b, minor_b, patch_b))) =
        (parsed_a, parsed_b)
    {
        // A different major version invalidates every stored assumption.
        if major_a != major_b {
            breaking_changes.push_back(String::from_str(
                env,
                "Major version mismatch - breaking changes expected",
            ));
        }

        // A downgrade in the minor version removes previously-added entries.
        if minor_b < minor_a {
            breaking_changes.push_back(String::from_str(
                env,
                "Minor version downgrade detected",
            ));
        }

        // Patch revisions are additive-only downgrades, so just warn.
        if patch_b < patch_a {
            warnings.push_back(String::from_str(env, "Patch version downgrade"));
        }
    } else {
        breaking_changes.push_back(String::from_str(env, "Invalid version format"));
    }

    CompatibilityCheck {
        is_compatible: breaking_changes.is_empty(),
        version_a: String::from_str(env, version_a),
        version_b: String::from_str(env, version_b),
        breaking_changes,
        warnings,
    }
}

/// Validate that a config version is approved for deployment.
pub fn validate_deployment_approval(
    config: &ConfigVersion,
    target_env: Environment,
) -> Result<(), ConfigVersionError> {
    if config.environment != target_env {
        return Err(ConfigVersionError::EnvironmentMismatch);
    }

    if !config.is_approved {
        return Err(ConfigVersionError::NotApproved);
    }

    Ok(())
}

/// Compare two configuration versions and return compatibility report.
pub fn compare_versions(
    env: &Env,
    old_version: &ConfigVersion,
    new_version: &ConfigVersion,
) -> CompatibilityCheck {
    // Registry version strings are bounded, so the copies always fit; over-long
    // or empty strings degrade to "" and surface as `Invalid version format`.
    let mut buf_a = [0u8; MAX_VERSION_LEN];
    let mut buf_b = [0u8; MAX_VERSION_LEN];
    let old_raw = string_bytes(&old_version.version, &mut buf_a)
        .and_then(|b| core::str::from_utf8(b).ok())
        .unwrap_or("");
    let new_raw = string_bytes(&new_version.version, &mut buf_b)
        .and_then(|b| core::str::from_utf8(b).ok())
        .unwrap_or("");
    check_compatibility(env, old_raw, new_raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Env, String};

    #[test]
    fn test_validate_version_format() {
        let env = Env::default();
        let valid = String::from_str(&env, "1.2.3");
        assert!(validate_version_format(&valid).is_ok());

        let invalid = String::from_str(&env, "1.2");
        assert!(validate_version_format(&invalid).is_err());

        let empty = String::from_str(&env, "");
        assert!(validate_version_format(&empty).is_err());

        let double_dot = String::from_str(&env, "1..2");
        assert!(validate_version_format(&double_dot).is_err());

        let trailing = String::from_str(&env, "1.2.");
        assert!(validate_version_format(&trailing).is_err());
    }

    #[test]
    fn test_check_compatibility() {
        let env = Env::default();

        // Compatible versions
        let result = check_compatibility(&env, "1.2.3", "1.3.0");
        assert!(result.is_compatible);

        // Breaking change (major version)
        let result = check_compatibility(&env, "1.2.3", "2.0.0");
        assert!(!result.is_compatible);

        // Minor downgrade
        let result = check_compatibility(&env, "1.3.0", "1.2.0");
        assert!(!result.is_compatible);

        // Patch downgrade only warns
        let result = check_compatibility(&env, "1.2.5", "1.2.4");
        assert!(result.is_compatible);
        assert_eq!(result.warnings.len(), 1);

        // Malformed input reports one breaking change
        let result = check_compatibility(&env, "1.2.3", "not-a-version");
        assert!(!result.is_compatible);
    }

    #[test]
    fn test_compare_versions_from_registry() {
        let env = Env::default();
        let old_version = ConfigVersion {
            version: String::from_str(&env, "1.4.0"),
            content_hash: BytesN::from_array(&env, &[0u8; 32]),
            environment: Environment::Testnet,
            created_at: 100,
            is_approved: true,
        };
        let new_version = ConfigVersion {
            version: String::from_str(&env, "1.5.0"),
            content_hash: BytesN::from_array(&env, &[1u8; 32]),
            environment: Environment::Testnet,
            created_at: 200,
            is_approved: false,
        };

        let report = compare_versions(&env, &old_version, &new_version);
        assert!(report.is_compatible);
        assert_eq!(report.version_a, String::from_str(&env, "1.4.0"));
    }

    #[test]
    fn test_validate_deployment_approval() {
        let env = Env::default();
        let config = ConfigVersion {
            version: String::from_str(&env, "1.0.0"),
            content_hash: BytesN::from_array(&env, &[0u8; 32]),
            environment: Environment::Testnet,
            created_at: 0,
            is_approved: true,
        };

        assert!(validate_deployment_approval(&config, Environment::Testnet).is_ok());
        assert!(validate_deployment_approval(&config, Environment::Mainnet).is_err());

        let unapproved = ConfigVersion {
            is_approved: false,
            ..config
        };
        assert!(validate_deployment_approval(&unapproved, Environment::Testnet).is_err());
    }
}
