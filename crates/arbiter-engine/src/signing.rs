//! Ed25519 manifest signing and verification.
//!
//! Provides utilities to:
//! 1. Generate a signing key pair (CI/CD pipeline, offline)
//! 2. Sign a manifest file (CI/CD pipeline)
//! 3. Verify a manifest signature at boot (runtime)
//!
//! The public key is compiled into the binary. The private key
//! never leaves the signing environment.

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// 32-byte public key for Ed25519 verification.
pub type VerifyingKeyBytes = [u8; 32];

/// Generate a new Ed25519 signing key pair.
///
/// Returns `(signing_key_bytes, verifying_key_bytes)`.
/// The signing key (64 bytes) is secret; the verifying key (32 bytes)
/// is compiled into the binary.
pub fn generate_keypair() -> ([u8; 32], VerifyingKeyBytes) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key.to_bytes(), verifying_key.to_bytes())
}

/// Sign manifest content with an Ed25519 signing key.
///
/// Returns the 64-byte signature as a hex string.
pub fn sign_manifest(manifest_content: &str, signing_key_bytes: &[u8; 32]) -> String {
    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let signature = signing_key.sign(manifest_content.as_bytes());
    hex::encode(&signature.to_bytes())
}

/// Verify an Ed25519 signature against manifest content.
///
/// `signature_hex` is the hex-encoded 64-byte signature.
/// `verifying_key_bytes` is the 32-byte public key.
pub fn verify_manifest(
    manifest_content: &str,
    signature_hex: &str,
    verifying_key_bytes: &VerifyingKeyBytes,
) -> Result<bool> {
    let sig_bytes = hex::decode(signature_hex).context("decoding signature hex")?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;

    let signature = Signature::from_bytes(&sig_array);
    let verifying_key =
        VerifyingKey::from_bytes(verifying_key_bytes).context("invalid verifying key")?;

    Ok(verifying_key
        .verify(manifest_content.as_bytes(), &signature)
        .is_ok())
}

/// Hex encoding/decoding helpers (avoids adding `hex` crate dependency).
mod hex {
    use anyhow::{Context, Result};

    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>> {
        if s.len() % 2 != 0 {
            anyhow::bail!("hex string must have even length");
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex digit")
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let content = r#"{"version":"1","boundaries":[]}"#;
        let signature = sign_manifest(content, &sk);
        assert!(verify_manifest(content, &signature, &vk).unwrap());
    }

    #[test]
    fn tampered_content_fails_verification() {
        let (sk, vk) = generate_keypair();
        let content = r#"{"version":"1","boundaries":[]}"#;
        let signature = sign_manifest(content, &sk);

        let tampered = r#"{"version":"2","boundaries":[]}"#;
        assert!(!verify_manifest(tampered, &signature, &vk).unwrap());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (sk, _vk) = generate_keypair();
        let (_sk2, vk2) = generate_keypair();
        let content = r#"{"version":"1","boundaries":[]}"#;
        let signature = sign_manifest(content, &sk);
        assert!(!verify_manifest(content, &signature, &vk2).unwrap());
    }
}
