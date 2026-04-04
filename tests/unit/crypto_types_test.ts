// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2025 Jonathan D.A. Jewell <6759885+hyperpolymath@users.noreply.github.com>

/// <reference lib="deno.ns" />

/**
 * Unit tests for cryptographic type contracts in rrecord-verity.
 *
 * Tests verify that signature algorithms, key IDs, hash values, and
 * DKIM signature fields conform to their expected formats and contracts.
 */

import { assertEquals, assertMatch, assertThrows } from "@std/assert";

// Crypto type contract validators
interface SignatureAlgorithm {
	name: string;
	hashAlgorithm: string;
}

interface DKIMKeyRecord {
	version: string;
	keyType: string;
	publicKey: string;
	hashAlgorithms: string[];
	serviceTypes: string[];
}

interface DKIMSignature {
	version: "1.0" | "1.1";
	algorithm: string;
	bodyCanonicalization: string;
	headerCanonicalization: string;
	signedHeaders: string[];
	signature: string;
	bodyHash: string;
	domain: string;
	selector: string;
	signatureTimestamp: number;
	expireTime?: number;
	agentOrUserIdentity?: string;
	copiedHeaderFields?: string[];
}

/**
 * Validate signature algorithm name is recognized.
 * Valid: "rsa-sha1", "rsa-sha256", "ed25519-sha256", etc.
 */
function validateAlgorithmName(name: string): boolean {
	const validAlgorithms = /^(rsa|ed25519|ecdsa)-(sha1|sha256|sha512)$/i;
	return validAlgorithms.test(name);
}

/**
 * Validate key ID format: non-empty, ASCII printable.
 */
function validateKeyId(keyId: string): boolean {
	if (keyId.length === 0) return false;
	// Allow alphanumeric, hyphen, underscore
	return /^[a-z0-9\-_]+$/i.test(keyId);
}

/**
 * Validate hash value: hex string, minimum length for SHA256 (64 chars).
 */
function validateHashValue(hash: string, algorithmName: string = "sha256"): boolean {
	const hexPattern = /^[a-f0-9]+$/i;
	if (!hexPattern.test(hash)) return false;

	// SHA1: 40 chars, SHA256: 64 chars, SHA512: 128 chars
	const expectedLengths: Record<string, number> = {
		"sha1": 40,
		"sha256": 64,
		"sha512": 128,
	};

	const expectedLength = expectedLengths[algorithmName.toLowerCase()] || 64;
	return hash.length === expectedLength;
}

/**
 * Validate DKIM signature has all required fields.
 */
function validateDKIMSignature(sig: DKIMSignature): boolean {
	const requiredFields = ["version", "algorithm", "bodyCanonicalization",
		"headerCanonicalization", "signedHeaders", "signature", "bodyHash", "domain"];

	for (const field of requiredFields) {
		if (!sig[field as keyof DKIMSignature]) return false;
	}

	return sig.signedHeaders.length > 0;
}

/**
 * Validate DMARC policy value: "none", "quarantine", "reject" only.
 */
function validateDMARCPolicy(policy: string): boolean {
	return ["none", "quarantine", "reject"].includes(policy.toLowerCase());
}

Deno.test("Crypto Types - Algorithm Names", () => {
	assertEquals(validateAlgorithmName("rsa-sha256"), true);
	assertEquals(validateAlgorithmName("rsa-sha1"), true);
	assertEquals(validateAlgorithmName("ed25519-sha256"), true);
	assertEquals(validateAlgorithmName("ecdsa-sha256"), true);
	assertEquals(validateAlgorithmName("invalid-algo"), false);
	assertEquals(validateAlgorithmName(""), false);
});

Deno.test("Crypto Types - Key ID Format", () => {
	assertEquals(validateKeyId("default"), true);
	assertEquals(validateKeyId("key-1"), true);
	assertEquals(validateKeyId("key_2"), true);
	assertEquals(validateKeyId("selector123"), true);
	assertEquals(validateKeyId(""), false);
	assertEquals(validateKeyId("key@invalid"), false);
	assertEquals(validateKeyId("key with spaces"), false);
});

Deno.test("Crypto Types - Hash Values", () => {
	// Valid SHA256 hash (64 hex chars)
	assertEquals(
		validateHashValue("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
		true
	);

	// Valid SHA1 hash (40 hex chars)
	assertEquals(
		validateHashValue("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
		true
	);

	// Invalid: wrong length
	assertEquals(validateHashValue("abc123", "sha256"), false);

	// Invalid: non-hex characters
	assertEquals(
		validateHashValue("zzzza3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
		false
	);
});

Deno.test("Crypto Types - DKIM Signature Fields", () => {
	const validSig: DKIMSignature = {
		version: "1.0",
		algorithm: "rsa-sha256",
		bodyCanonicalization: "simple",
		headerCanonicalization: "relaxed",
		signedHeaders: ["from", "to", "subject"],
		signature: "validbase64signature...",
		bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		domain: "example.com",
		selector: "default",
		signatureTimestamp: 1234567890,
	};

	assertEquals(validateDKIMSignature(validSig), true);

	// Missing required field
	const incompleteSig = { ...validSig };
	delete (incompleteSig as any).domain;
	assertEquals(validateDKIMSignature(incompleteSig), false);

	// Empty signed headers
	const noHeadersSig = { ...validSig, signedHeaders: [] };
	assertEquals(validateDKIMSignature(noHeadersSig), false);
});

Deno.test("Crypto Types - DMARC Policy Values", () => {
	assertEquals(validateDMARCPolicy("none"), true);
	assertEquals(validateDMARCPolicy("quarantine"), true);
	assertEquals(validateDMARCPolicy("reject"), true);
	assertEquals(validateDMARCPolicy("None"), true); // case-insensitive
	assertEquals(validateDMARCPolicy("REJECT"), true);
	assertEquals(validateDMARCPolicy("invalid"), false);
	assertEquals(validateDMARCPolicy(""), false);
	assertEquals(validateDMARCPolicy("allow"), false);
});

Deno.test("Crypto Types - Signature Algorithm Enum", () => {
	const algorithms = [
		{ name: "rsa-sha256", hashAlgorithm: "sha256" },
		{ name: "rsa-sha1", hashAlgorithm: "sha1" },
		{ name: "ed25519-sha256", hashAlgorithm: "sha256" },
	];

	for (const algo of algorithms) {
		assertEquals(validateAlgorithmName(algo.name), true);
	}
});
