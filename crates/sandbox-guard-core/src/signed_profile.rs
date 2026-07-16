use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ProfileError, VendorProfile};

pub const SIGNED_PROFILE_ENVELOPE_SCHEMA_VERSION: u32 = 1;
pub const MAX_SIGNED_PROFILE_BYTES: usize = 64 * 1024;

/// A versioned distribution envelope whose exact serialized bytes are signed.
///
/// Verification never canonicalizes or reserializes TOML. The detached Ed25519 signature covers
/// the original byte string containing both `profile_version` and the complete vendor profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProfileEnvelope {
    pub schema_version: u32,
    pub profile_version: String,
    pub profile: VendorProfile,
}

impl SignedProfileEnvelope {
    pub fn validate(&self) -> Result<(), SignedProfileError> {
        if self.schema_version != SIGNED_PROFILE_ENVELOPE_SCHEMA_VERSION {
            return Err(SignedProfileError::UnsupportedSchema(self.schema_version));
        }
        validate_distribution_component("profile version", &self.profile_version)?;
        self.profile.validate()?;
        Ok(())
    }
}

/// Verify the signer pin and detached signature before parsing the exact signed TOML bytes.
///
/// The public key, signature, and expected signer fingerprint use the same lowercase-or-uppercase
/// hexadecimal representation accepted by the verified tool store. Whitespace around those three
/// values is ignored; the signed package bytes themselves are never trimmed or transformed.
pub fn verify_signed_profile_bytes(
    package_bytes: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
    expected_signer_fingerprint_sha256: &str,
) -> Result<SignedProfileEnvelope, SignedProfileError> {
    if package_bytes.len() > MAX_SIGNED_PROFILE_BYTES {
        return Err(SignedProfileError::PackageTooLarge {
            actual: package_bytes.len(),
            maximum: MAX_SIGNED_PROFILE_BYTES,
        });
    }

    let public_key_bytes = decode_hex(public_key_hex, 32, "public key")?;
    let expected_fingerprint =
        decode_hex(expected_signer_fingerprint_sha256, 32, "signer fingerprint")?;
    let observed_fingerprint = Sha256::digest(&public_key_bytes);
    if observed_fingerprint.as_slice() != expected_fingerprint.as_slice() {
        return Err(SignedProfileError::SignerMismatch {
            expected: hex::encode(expected_fingerprint),
            observed: hex::encode(observed_fingerprint),
        });
    }

    let signature_bytes = decode_hex(signature_hex, 64, "signature")?;
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignedProfileError::InvalidEncoding("public key"))?,
    )
    .map_err(|_| SignedProfileError::InvalidEncoding("public key"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| SignedProfileError::InvalidEncoding("signature"))?;
    verifying_key
        .verify_strict(package_bytes, &signature)
        .map_err(|_| SignedProfileError::SignatureVerification)?;

    let document =
        std::str::from_utf8(package_bytes).map_err(|_| SignedProfileError::InvalidUtf8)?;
    let envelope: SignedProfileEnvelope = toml::from_str(document)?;
    envelope.validate()?;
    Ok(envelope)
}

fn decode_hex(
    value: &str,
    expected_bytes: usize,
    label: &'static str,
) -> Result<Vec<u8>, SignedProfileError> {
    let decoded =
        hex::decode(value.trim()).map_err(|_| SignedProfileError::InvalidEncoding(label))?;
    if decoded.len() != expected_bytes {
        return Err(SignedProfileError::InvalidEncoding(label));
    }
    Ok(decoded)
}

fn validate_distribution_component(
    label: &'static str,
    value: &str,
) -> Result<(), SignedProfileError> {
    if value.is_empty()
        || value.len() > 128
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SignedProfileError::InvalidComponent {
            label,
            value: value.to_owned(),
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum SignedProfileError {
    #[error("signed profile package is {actual} bytes, exceeding the {maximum}-byte limit")]
    PackageTooLarge { actual: usize, maximum: usize },
    #[error("invalid {0} encoding")]
    InvalidEncoding(&'static str),
    #[error("signer fingerprint mismatch: expected {expected}, observed {observed}")]
    SignerMismatch { expected: String, observed: String },
    #[error("profile signature verification failed")]
    SignatureVerification,
    #[error("signed profile package is not UTF-8")]
    InvalidUtf8,
    #[error("parse signed profile envelope: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("unsupported signed profile envelope schema {0}")]
    UnsupportedSchema(u32),
    #[error("invalid {label} {value:?}")]
    InvalidComponent { label: &'static str, value: String },
    #[error("invalid vendor profile: {0}")]
    Profile(#[from] ProfileError),
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::builtin_grok_profile;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn envelope() -> SignedProfileEnvelope {
        SignedProfileEnvelope {
            schema_version: SIGNED_PROFILE_ENVELOPE_SCHEMA_VERSION,
            profile_version: "1.0.0-alpha.1".to_owned(),
            profile: builtin_grok_profile(),
        }
    }

    fn package_bytes(envelope: &SignedProfileEnvelope) -> Vec<u8> {
        toml::to_string_pretty(envelope).unwrap().into_bytes()
    }

    fn signed_material(bytes: &[u8], key: &SigningKey) -> (String, String, String) {
        let public_key = key.verifying_key().to_bytes();
        (
            hex::encode(key.sign(bytes).to_bytes()),
            hex::encode(public_key),
            hex::encode(Sha256::digest(public_key)),
        )
    }

    #[test]
    fn verifies_exact_raw_bytes_before_parsing_and_validation() {
        let expected = envelope();
        let bytes = package_bytes(&expected);
        let key = signing_key();
        let (signature, public_key, fingerprint) = signed_material(&bytes, &key);

        let verified =
            verify_signed_profile_bytes(&bytes, &signature, &public_key, &fingerprint).unwrap();
        assert_eq!(verified, expected);

        let mut changed = bytes.clone();
        let index = changed.iter().position(|byte| *byte == b'g').unwrap();
        changed[index] = b'G';
        assert!(matches!(
            verify_signed_profile_bytes(&changed, &signature, &public_key, &fingerprint),
            Err(SignedProfileError::SignatureVerification)
        ));
    }

    #[test]
    fn equivalent_reserialization_is_not_the_signed_message() {
        let expected = envelope();
        let original = package_bytes(&expected);
        let mut equivalent = b"\n".to_vec();
        equivalent.extend_from_slice(&original);
        assert_eq!(
            toml::from_str::<SignedProfileEnvelope>(std::str::from_utf8(&equivalent).unwrap())
                .unwrap(),
            expected
        );
        let key = signing_key();
        let (signature, public_key, fingerprint) = signed_material(&original, &key);

        assert!(matches!(
            verify_signed_profile_bytes(&equivalent, &signature, &public_key, &fingerprint),
            Err(SignedProfileError::SignatureVerification)
        ));
    }

    #[test]
    fn signer_pin_key_and_signature_must_all_agree() {
        let bytes = package_bytes(&envelope());
        let key = signing_key();
        let other = SigningKey::from_bytes(&[0x24; 32]);
        let (signature, public_key, fingerprint) = signed_material(&bytes, &key);
        let (_, other_public_key, other_fingerprint) = signed_material(&bytes, &other);

        assert!(matches!(
            verify_signed_profile_bytes(&bytes, &signature, &public_key, &other_fingerprint),
            Err(SignedProfileError::SignerMismatch { .. })
        ));
        assert!(matches!(
            verify_signed_profile_bytes(&bytes, &signature, &other_public_key, &other_fingerprint),
            Err(SignedProfileError::SignatureVerification)
        ));
        assert!(matches!(
            verify_signed_profile_bytes(&bytes, &"00".repeat(64), &public_key, &fingerprint),
            Err(SignedProfileError::SignatureVerification)
        ));
    }

    #[test]
    fn parsing_happens_only_after_a_valid_signature() {
        let invalid_toml = b"not = [valid";
        let key = signing_key();
        let (valid_signature, public_key, fingerprint) = signed_material(invalid_toml, &key);

        assert!(matches!(
            verify_signed_profile_bytes(invalid_toml, &"00".repeat(64), &public_key, &fingerprint),
            Err(SignedProfileError::SignatureVerification)
        ));
        assert!(matches!(
            verify_signed_profile_bytes(invalid_toml, &valid_signature, &public_key, &fingerprint),
            Err(SignedProfileError::Parse(_))
        ));
    }

    #[test]
    fn envelope_and_profile_validation_fail_closed_after_verification() {
        let key = signing_key();
        for invalid in [
            {
                let mut value = envelope();
                value.schema_version = 2;
                value
            },
            {
                let mut value = envelope();
                value.profile_version = "../1.0.0".to_owned();
                value
            },
            {
                let mut value = envelope();
                value.profile.name = "../grok".to_owned();
                value
            },
        ] {
            let bytes = package_bytes(&invalid);
            let (signature, public_key, fingerprint) = signed_material(&bytes, &key);
            assert!(
                verify_signed_profile_bytes(&bytes, &signature, &public_key, &fingerprint).is_err()
            );
        }
    }

    #[test]
    fn unknown_envelope_fields_and_oversized_packages_are_rejected() {
        let valid = package_bytes(&envelope());
        let mut unknown = b"unknown = true\n".to_vec();
        unknown.extend_from_slice(&valid);
        let key = signing_key();
        let (signature, public_key, fingerprint) = signed_material(&unknown, &key);
        assert!(matches!(
            verify_signed_profile_bytes(&unknown, &signature, &public_key, &fingerprint),
            Err(SignedProfileError::Parse(_))
        ));

        let nested = std::str::from_utf8(&valid)
            .unwrap()
            .replacen("[profile]\n", "[profile]\nunknown = true\n", 1)
            .into_bytes();
        let (signature, public_key, fingerprint) = signed_material(&nested, &key);
        assert!(matches!(
            verify_signed_profile_bytes(&nested, &signature, &public_key, &fingerprint),
            Err(SignedProfileError::Parse(_))
        ));

        let non_utf8 = [0xff, 0xfe, 0xfd];
        let (signature, public_key, fingerprint) = signed_material(&non_utf8, &key);
        assert!(matches!(
            verify_signed_profile_bytes(&non_utf8, &signature, &public_key, &fingerprint),
            Err(SignedProfileError::InvalidUtf8)
        ));

        let oversized = vec![b' '; MAX_SIGNED_PROFILE_BYTES + 1];
        assert!(matches!(
            verify_signed_profile_bytes(&oversized, "", "", ""),
            Err(SignedProfileError::PackageTooLarge { .. })
        ));
    }
}
