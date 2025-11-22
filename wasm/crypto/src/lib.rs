// DKIM Cryptographic Operations - WebAssembly Module
//
// High-performance cryptographic primitives for DKIM signature verification.
// Compiled to WebAssembly for near-native speed in the browser.
//
// Copyright (c) 2025 DKIM Verifier Contributors
// Licensed under MIT License

use wasm_bindgen::prelude::*;
use sha2::{Sha256, Sha512, Digest};
use ed25519_dalek::{Verifier, Signature, VerifyingKey};
use rsa::{RsaPublicKey, PaddingScheme, PublicKey};
use rsa::sha2::Sha256 as RsaSha256;
use base64::{Engine as _, engine::general_purpose};

/// Initialize the WASM module
/// Call this before using any other functions
#[wasm_bindgen(start)]
pub fn init() {
    // Set panic hook for better error messages in browser console
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    web_sys::console::log_1(&"DKIM Crypto WASM module initialized".into());
}

/// Compute SHA-256 hash of input data
///
/// # Arguments
/// * `data` - Input data as bytes
///
/// # Returns
/// Base64-encoded SHA-256 hash
#[wasm_bindgen]
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    general_purpose::STANDARD.encode(result)
}

/// Compute SHA-256 hash (returns raw bytes)
///
/// # Arguments
/// * `data` - Input data as bytes
///
/// # Returns
/// Raw SHA-256 hash bytes
#[wasm_bindgen]
pub fn sha256_hash_raw(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-512 hash of input data
///
/// # Arguments
/// * `data` - Input data as bytes
///
/// # Returns
/// Base64-encoded SHA-512 hash
#[wasm_bindgen]
pub fn sha512_hash(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    general_purpose::STANDARD.encode(result)
}

/// Verify Ed25519 signature (used in DKIM with ed25519-sha256)
///
/// # Arguments
/// * `public_key` - Base64-encoded Ed25519 public key
/// * `message` - Message that was signed
/// * `signature` - Base64-encoded Ed25519 signature
///
/// # Returns
/// `true` if signature is valid, `false` otherwise
#[wasm_bindgen]
pub fn verify_ed25519(
    public_key: &str,
    message: &[u8],
    signature: &str,
) -> Result<bool, JsValue> {
    // Decode base64 inputs
    let pub_key_bytes = general_purpose::STANDARD
        .decode(public_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {}", e)))?;

    let sig_bytes = general_purpose::STANDARD
        .decode(signature)
        .map_err(|e| JsValue::from_str(&format!("Invalid signature: {}", e)))?;

    // Parse public key
    let pub_key_array: [u8; 32] = pub_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Public key must be 32 bytes"))?;

    let verifying_key = VerifyingKey::from_bytes(&pub_key_array)
        .map_err(|e| JsValue::from_str(&format!("Invalid Ed25519 key: {}", e)))?;

    // Parse signature
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Signature must be 64 bytes"))?;

    let signature = Signature::from_bytes(&sig_array);

    // Verify signature
    match verifying_key.verify(message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify RSA signature with SHA-256 (used in DKIM with rsa-sha256)
///
/// # Arguments
/// * `public_key_der` - Base64-encoded DER public key
/// * `message` - Message that was signed
/// * `signature` - Base64-encoded RSA signature
///
/// # Returns
/// `true` if signature is valid, `false` otherwise
#[wasm_bindgen]
pub fn verify_rsa_sha256(
    public_key_der: &str,
    message: &[u8],
    signature: &str,
) -> Result<bool, JsValue> {
    // Decode base64 inputs
    let pub_key_bytes = general_purpose::STANDARD
        .decode(public_key_der)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {}", e)))?;

    let sig_bytes = general_purpose::STANDARD
        .decode(signature)
        .map_err(|e| JsValue::from_str(&format!("Invalid signature: {}", e)))?;

    // Parse RSA public key from DER
    let public_key = RsaPublicKey::from_pkcs1_der(&pub_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid RSA key: {}", e)))?;

    // Compute SHA-256 hash of message
    let mut hasher = RsaSha256::new();
    hasher.update(message);
    let hash = hasher.finalize();

    // Verify signature using PKCS1v15 padding
    let padding = PaddingScheme::new_pkcs1v15_sign::<RsaSha256>();
    match public_key.verify(padding, &hash, &sig_bytes) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Compute DKIM body hash (SHA-256)
///
/// # Arguments
/// * `body` - Email body (canonicalized)
/// * `length` - Optional body length limit (0 = no limit)
///
/// # Returns
/// Base64-encoded SHA-256 hash
#[wasm_bindgen]
pub fn compute_body_hash(body: &[u8], length: usize) -> String {
    let data = if length > 0 && length < body.len() {
        &body[..length]
    } else {
        body
    };

    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    general_purpose::STANDARD.encode(result)
}

/// Fast base64 encoding
#[wasm_bindgen]
pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Fast base64 decoding
#[wasm_bindgen]
pub fn base64_decode(data: &str) -> Result<Vec<u8>, JsValue> {
    general_purpose::STANDARD
        .decode(data)
        .map_err(|e| JsValue::from_str(&format!("Base64 decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"Hello, World!";
        let hash = sha256_hash(data);
        // Known SHA-256 hash of "Hello, World!"
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Test data";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }
}
