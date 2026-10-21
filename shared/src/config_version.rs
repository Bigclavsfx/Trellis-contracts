//! Configuration version checks across environments.
//!
//! Ensures configuration consistency between testnet, mainnet, and development
//! environments by tracking version hashes and validating compatibility.

use soroban_sdk::{contracterror, contracttype, BytesN, Env, String, Vec};

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

/// Validate semantic version format (major.minor.patch).
pub fn validate_version_format(version: &String) -> Result<(), ConfigVersionError> {
    // Basic validation: must contain at least one dot
    let version_str = version.to_string();
    if version_str.is_empty() {
        return Err(ConfigVersionError::InvalidVersionFormat);
    }

    // Count dots - should have exactly 2 for semver
    let mut dot_count = 0;
    let bytes = version_str.as_bytes();
    for &b in bytes {
        if b == b'.' {
            dot_count += 1;
        }
    }

    if dot_count != 2 {
        return Err(ConfigVersionError::InvalidVersionFormat);
    }

    Ok(())
}

/// Check if version B is compatible with version A.
/// Compatible means: same major version, minor version >= A's minor.
pub fn check_compatibility(
    env: &Env,
    version_a: &str,
    version_b: &str,
) -> CompatibilityCheck {
    let mut breaking_changes = Vec::new(env);
    let mut warnings = Vec::new(env);

    // Parse versions
    let parts_a: Vec<&str> = version_a.split('.').collect();
    let parts_b: Vec<&str> = version_b.split('.').collect();

    if parts_a.len() != 3 || parts_b.len() != 3 {
        breaking_changes.push_back(String::from_str(env, "Invalid version format"));
        return CompatibilityCheck {
            is_compatible: false,
            version_a: String::from_str(env, version_a),
            version_b: String::from_str(env, version_b),
            breaking_changes,
            warnings,
        };
    }

    let major_a: u32 = parts_a[0].parse().unwrap_or(0);
    let major_b: u32 = parts_b[0].parse().unwrap_or(0);
    let minor_a: u32 = parts_a[1].parse().unwrap_or(0);
    let minor_b: u32 = parts_b[1].parse().unwrap_or(0);

    // Check major version compatibility
    if major_a != major_b {
        breaking_changes.push_back(String::from_str(
            env,
            "Major version mismatch - breaking changes expected",
        ));
    }

    // Check minor version
    if minor_b < minor_a {
        breaking_changes.push_back(String::from_str(
            env,
            "Minor version downgrade detected",
        ));
    }

    // Check patch version
    let patch_a: u32 = parts_a[2].parse().unwrap_or(0);
    let patch_b: u32 = parts_b[2].parse().unwrap_or(0);
    if patch_b < patch_a {
        warnings.push_back(String::from_str(env, "Patch version downgrade"));
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
    check_compatibility(
        env,
        &old_version.version.to_string(),
        &new_version.version.to_string(),
    )
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
    }
}
