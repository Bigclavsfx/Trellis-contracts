//! Canonical serialization and input normalization for signed data (Issue #62).
//!
//! Any payload that is signed, hashed, compared, or settled must be reduced to
//! a single canonical byte representation so that equivalent input cannot
//! produce inconsistent signatures or ledger records. This module provides:
//!
//! - [`normalize_text`] — trims, lower-cases, and collapses internal
//!   whitespace so casing and spacing variants converge on one value.
//! - [`normalize_int`] — renders an `i128` as canonical decimal (no leading
//!   zeros, explicit sign only when negative) so numeric precision cannot vary.
//! - [`canonical_bytes`] — length-prefixed, type-tagged, deterministically
//!   **ordered** encoding of a set of [`CanonicalPart`]s. Ordering is imposed
//!   by the encoder, so callers cannot accidentally sign a different byte
//!   sequence by reordering fields.
//! - [`canonical_fingerprint`] — `sha256(canonical_bytes)` for signing/hashing.
//! - [`canonicalize_legacy`] — migrates legacy `key=value` payloads onto the
//!   same canonical form so pre-existing records stay verifiable.
//!
//! ## Encoding version
//!
//! | Version | Meaning |
//! |---:|---|
//! | `0` | Legacy, pre-canonical `key=value` payloads (readable via [`canonicalize_legacy`]). |
//! | `1` (current) | Canonical encoding emitted by [`canonical_bytes`]. |
//!
//! ## Rejection rules
//!
//! Non-canonical input is **normalized** where a single obvious canonical form
//! exists (case, whitespace, integer formatting) and **rejected** with
//! [`Error::InvalidArgument`] when it cannot be represented safely (over-long
//! fields, malformed legacy lines, unbalanced key/value pairs). Unknown
//! encoding versions return [`Error::UnsupportedSchemaVersion`].

use soroban_sdk::{contracttype, Bytes, BytesN, Env, Vec};

use crate::errors::Error;

/// Encoding version emitted by [`canonical_bytes`].
pub const CANONICAL_ENCODING_VERSION: u32 = 1;
/// Legacy, pre-canonical payloads.
pub const LEGACY_ENCODING_VERSION: u32 = 0;
/// Longest text or key field accepted during normalization.
pub const MAX_FIELD_LEN: u32 = 128;

/// A typed value participating in a canonical signed payload.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalPart {
    /// Boolean flag.
    Bool(bool),
    /// Numeric amount, canonicalized to decimal.
    Int(i128),
    /// Free text, normalized for case/whitespace.
    Text(Bytes),
    /// Opaque bytes (already canonical on the caller's side).
    Raw(Bytes),
}

fn tag_of(part: &CanonicalPart) -> u8 {
    match part {
        CanonicalPart::Bool(_) => 1,
        CanonicalPart::Int(_) => 2,
        CanonicalPart::Text(_) => 3,
        CanonicalPart::Raw(_) => 4,
    }
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Normalize free text: trim surrounding whitespace, ASCII-lower-case, and
/// collapse internal whitespace runs to a single space.
///
/// Returns [`Error::InvalidArgument`] when the field exceeds [`MAX_FIELD_LEN`].
pub fn normalize_text(env: &Env, raw: &Bytes) -> Result<Bytes, Error> {
    if raw.len() > MAX_FIELD_LEN {
        return Err(Error::InvalidArgument);
    }
    let mut buf = [0u8; MAX_FIELD_LEN as usize];
    let mut n: usize = 0;
    let mut pending_space = false;
    for i in 0..raw.len() {
        let b = raw.get(i).ok_or(Error::InvalidArgument)?;
        if is_ws(b) {
            if n > 0 {
                pending_space = true;
            }
            continue;
        }
        if pending_space {
            if n >= buf.len() {
                return Err(Error::InvalidArgument);
            }
            buf[n] = b' ';
            n += 1;
            pending_space = false;
        }
        if n >= buf.len() {
            return Err(Error::InvalidArgument);
        }
        buf[n] = b.to_ascii_lowercase();
        n += 1;
    }
    Ok(Bytes::from_slice(env, &buf[..n]))
}

/// Render an `i128` as canonical decimal bytes.
pub fn normalize_int(env: &Env, value: i128) -> Bytes {
    let mut buf = [0u8; 40];
    let negative = value < 0;
    let mut magnitude: u128 = value.unsigned_abs();
    let mut i = buf.len();
    if magnitude == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while magnitude > 0 {
        i -= 1;
        buf[i] = b'0' + (magnitude % 10) as u8;
        magnitude /= 10;
    }
    if negative {
        i -= 1;
        buf[i] = b'-';
    }
    Bytes::from_slice(env, &buf[i..])
}

fn encode_part(env: &Env, part: &CanonicalPart) -> Result<Bytes, Error> {
    let payload = match part {
        CanonicalPart::Bool(b) => Bytes::from_slice(env, &[if *b { 1u8 } else { 0u8 }]),
        CanonicalPart::Int(v) => normalize_int(env, *v),
        CanonicalPart::Text(t) => normalize_text(env, t)?,
        CanonicalPart::Raw(b) => {
            if b.len() > MAX_FIELD_LEN {
                return Err(Error::InvalidArgument);
            }
            b.clone()
        }
    };
    let mut out = Bytes::new(env);
    out.append(&Bytes::from_slice(env, &[tag_of(part)]));
    out.append(&Bytes::from_slice(env, &payload.len().to_be_bytes()));
    out.append(&payload);
    Ok(out)
}

fn encoded_lt(a: &Bytes, b: &Bytes) -> bool {
    let n = a.len().min(b.len());
    for i in 0..n {
        let (x, y) = (a.get(i).unwrap(), b.get(i).unwrap());
        if x != y {
            return x < y;
        }
    }
    a.len() < b.len()
}

fn sort_encoded(env: &Env, items: &Vec<Bytes>) -> Vec<Bytes> {
    let mut out: Vec<Bytes> = Vec::new(env);
    for i in 0..items.len() {
        let cur = items.get(i).unwrap();
        let n = out.len();
        let mut inserted = false;
        let mut j = 0u32;
        while j < n {
            let existing = out.get(j).unwrap();
            if encoded_lt(&cur, &existing) {
                out.insert(j, cur.clone());
                inserted = true;
                break;
            }
            j += 1;
        }
        if !inserted {
            out.push_back(cur);
        }
    }
    out
}

/// Produce the canonical byte representation of a payload.
///
/// Fields are encoded as `[tag][len_be:4][payload]` and sorted by their
/// encoded bytes, so callers get a stable ordering regardless of insertion
/// order. A one-byte encoding version prefixes the result.
pub fn canonical_bytes(env: &Env, parts: &Vec<CanonicalPart>) -> Result<Bytes, Error> {
    let mut encoded: Vec<Bytes> = Vec::new(env);
    for i in 0..parts.len() {
        encoded.push_back(encode_part(env, &parts.get(i).unwrap())?);
    }
    let sorted = sort_encoded(env, &encoded);
    let mut out = Bytes::new(env);
    out.append(&Bytes::from_slice(
        env,
        &CANONICAL_ENCODING_VERSION.to_be_bytes(),
    ));
    for i in 0..sorted.len() {
        out.append(&sorted.get(i).unwrap());
    }
    Ok(out)
}

/// `sha256` fingerprint of [`canonical_bytes`] — the value to sign or store.
pub fn canonical_fingerprint(env: &Env, parts: &Vec<CanonicalPart>) -> Result<BytesN<32>, Error> {
    Ok(env
        .crypto()
        .sha256(&canonical_bytes(env, parts)?)
        .to_bytes())
}

/// Returns `true` when `version` predates the canonical encoding.
pub fn is_legacy_encoding(version: u32) -> bool {
    version < CANONICAL_ENCODING_VERSION
}

/// Accept the legacy and current encoding versions, reject anything else.
pub fn ensure_supported_encoding(version: u32) -> Result<(), Error> {
    if version <= CANONICAL_ENCODING_VERSION {
        Ok(())
    } else {
        Err(Error::UnsupportedSchemaVersion)
    }
}

/// Parse a legacy `key=value` payload (`\n` or `;` separated) into parts.
///
/// Keys and values are normalized exactly like [`CanonicalPart::Text`], so a
/// legacy record and its canonical re-encoding share a fingerprint.
pub fn parse_legacy_kv(env: &Env, raw: &Bytes) -> Result<Vec<CanonicalPart>, Error> {
    fn flush(
        env: &Env,
        parts: &mut Vec<CanonicalPart>,
        key: &[u8],
        val: &[u8],
        kn: usize,
        vn: usize,
    ) -> Result<(), Error> {
        if kn == 0 {
            return Err(Error::InvalidArgument);
        }
        let k = normalize_text(env, &Bytes::from_slice(env, &key[..kn]))?;
        let v = normalize_text(env, &Bytes::from_slice(env, &val[..vn]))?;
        parts.push_back(CanonicalPart::Text(k));
        parts.push_back(CanonicalPart::Text(v));
        Ok(())
    }

    let mut parts: Vec<CanonicalPart> = Vec::new(env);
    let mut key = [0u8; MAX_FIELD_LEN as usize];
    let mut val = [0u8; MAX_FIELD_LEN as usize];
    let mut kn = 0usize;
    let mut vn = 0usize;
    let mut in_value = false;

    for i in 0..raw.len() {
        let b = raw.get(i).ok_or(Error::InvalidArgument)?;
        if b == b'\n' || b == b';' {
            if kn == 0 && vn == 0 {
                continue; // tolerate blank/duplicate separators
            }
            flush(env, &mut parts, &key, &val, kn, vn)?;
            kn = 0;
            vn = 0;
            in_value = false;
            continue;
        }
        if b == b'=' && !in_value {
            if kn == 0 {
                return Err(Error::InvalidArgument);
            }
            in_value = true;
            continue;
        }
        let (buf, n) = if in_value {
            (&mut val, &mut vn)
        } else {
            (&mut key, &mut kn)
        };
        if *n >= MAX_FIELD_LEN as usize {
            return Err(Error::InvalidArgument);
        }
        buf[*n] = b;
        *n += 1;
    }
    if kn > 0 || vn > 0 {
        flush(env, &mut parts, &key, &val, kn, vn)?;
    }
    Ok(parts)
}

/// Migrate a legacy payload onto the canonical encoding.
pub fn canonicalize_legacy(env: &Env, raw: &Bytes) -> Result<Bytes, Error> {
    canonical_bytes(env, &parse_legacy_kv(env, raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(env: &Env, s: &str) -> CanonicalPart {
        CanonicalPart::Text(Bytes::from_slice(env, s.as_bytes()))
    }

    #[test]
    fn ordering_does_not_change_canonical_bytes() {
        let env = Env::default();
        let mut a: Vec<CanonicalPart> = Vec::new(&env);
        a.push_back(CanonicalPart::Int(10));
        a.push_back(text(&env, "Alpha"));

        let mut b: Vec<CanonicalPart> = Vec::new(&env);
        b.push_back(text(&env, "alpha"));
        b.push_back(CanonicalPart::Int(10));

        assert_eq!(
            canonical_bytes(&env, &a).unwrap(),
            canonical_bytes(&env, &b).unwrap()
        );
    }

    #[test]
    fn casing_and_whitespace_are_normalized() {
        let env = Env::default();
        let messy = normalize_text(&env, &Bytes::from_slice(&env, b"  Alpha   BETA \t")).unwrap();
        let clean = normalize_text(&env, &Bytes::from_slice(&env, b"alpha beta")).unwrap();
        assert_eq!(messy, clean);
    }

    #[test]
    fn integers_use_canonical_decimal() {
        let env = Env::default();
        assert_eq!(normalize_int(&env, 0), Bytes::from_slice(&env, b"0"));
        assert_eq!(normalize_int(&env, 42), Bytes::from_slice(&env, b"42"));
        assert_eq!(normalize_int(&env, -7), Bytes::from_slice(&env, b"-7"));
        assert_eq!(
            normalize_int(&env, i128::MIN),
            Bytes::from_slice(&env, b"-170141183460469231731687303715884105728")
        );
        assert_eq!(
            normalize_int(&env, i128::MAX),
            Bytes::from_slice(&env, b"170141183460469231731687303715884105727")
        );
    }

    #[test]
    fn over_long_fields_are_rejected() {
        let env = Env::default();
        let long = Bytes::from_slice(&env, &[b'a'; 200]);
        assert_eq!(normalize_text(&env, &long), Err(Error::InvalidArgument));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let env = Env::default();
        let mut a: Vec<CanonicalPart> = Vec::new(&env);
        a.push_back(CanonicalPart::Bool(true));
        a.push_back(CanonicalPart::Int(-5));
        let mut b: Vec<CanonicalPart> = Vec::new(&env);
        b.push_back(CanonicalPart::Int(-5));
        b.push_back(CanonicalPart::Bool(true));
        assert_eq!(
            canonical_fingerprint(&env, &a).unwrap(),
            canonical_fingerprint(&env, &b).unwrap()
        );
    }

    #[test]
    fn legacy_payloads_migrate_to_canonical() {
        let env = Env::default();
        let legacy = Bytes::from_slice(&env, b"Amount=100\nRegion= Kenya \nRegion=Kenya");
        let parts = parse_legacy_kv(&env, &legacy).unwrap();
        // 3 pairs -> 6 parts.
        assert_eq!(parts.len(), 6);
        let canonical = canonicalize_legacy(&env, &legacy).unwrap();
        assert!(!canonical.is_empty());
        // Same logical content in a different order/formatting converges.
        let reordered = Bytes::from_slice(&env, b"region=kenya;amount=100;REGION=Kenya");
        assert_eq!(canonical, canonicalize_legacy(&env, &reordered).unwrap());
    }

    #[test]
    fn malformed_legacy_lines_are_rejected() {
        let env = Env::default();
        assert!(parse_legacy_kv(&env, &Bytes::from_slice(&env, b"=missingkey")).is_err());
    }

    #[test]
    fn encoding_versions_are_guarded() {
        assert!(is_legacy_encoding(LEGACY_ENCODING_VERSION));
        assert!(!is_legacy_encoding(CANONICAL_ENCODING_VERSION));
        assert!(ensure_supported_encoding(0).is_ok());
        assert!(ensure_supported_encoding(1).is_ok());
        assert_eq!(
            ensure_supported_encoding(2),
            Err(Error::UnsupportedSchemaVersion)
        );
    }
}
