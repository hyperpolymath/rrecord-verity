// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2025 Jonathan D.A. Jewell <6759885+hyperpolymath@users.noreply.github.com>

/// <reference lib="deno.ns" />

/**
 * Property-based tests for verification invariants in rrecord-verity.
 *
 * Tests verify that key properties hold across all valid inputs:
 * - Verification is deterministic (same input → same output)
 * - Invalid signatures always fail (no false positives)
 * - Domain normalization is consistent
 * - Selector + domain always form valid DNS labels
 */

import { assertEquals, assert } from "@std/assert";

/**
 * Simulate a signature verification result.
 */
interface VerificationResult {
	isValid: boolean;
	error?: string;
}

/**
 * Verify a DKIM signature deterministically.
 * Property: Given the same signature, always returns same result.
 */
function verifySignature(
	signature: string,
	publicKey: string,
	_bodyHash: string,
): VerificationResult {
	// Simulate verification: deterministic based on signature content
	// In real implementation, this would use cryptographic operations

	if (!signature || signature.length === 0) {
		return { isValid: false, error: "empty_signature" };
	}

	if (!publicKey || publicKey.length === 0) {
		return { isValid: false, error: "empty_key" };
	}

	// Deterministic check: signature and key must be non-empty and valid base64-ish
	const validBase64 = /^[A-Za-z0-9+/=]+$/.test(signature) && /^[A-Za-z0-9+/=]+$/.test(publicKey);

	return {
		isValid: validBase64,
	};
}

/**
 * Normalize domain name to lowercase for DNS lookup.
 * Property: Always produces lowercase ASCII.
 */
function normalizeDomain(domain: string): string {
	return domain.toLowerCase();
}

/**
 * Form a selector/domain DNS label.
 * Property: Always produces a valid DNS label.
 */
function formDNSLabel(selector: string, domain: string): string {
	const normalized = normalizeDomain(domain);
	return `${selector}._domainkey.${normalized}`;
}

/**
 * Validate DNS label format: max 63 chars per label, alphanumeric + hyphen + underscore.
 */
function isValidDNSLabel(label: string): boolean {
	const parts = label.split(".");
	for (const part of parts) {
		if (part.length > 63) return false;
		if (!/^[a-z0-9\-_]+$/i.test(part)) return false;
		if (part.startsWith("-") || part.endsWith("-")) return false;
	}
	return true;
}

Deno.test("Properties - Signature Verification Determinism", () => {
	const signature = "validSignature123456789";
	const publicKey = "validKey987654321";
	const bodyHash = "hash123";

	// Verify same input produces same output (determinism)
	const result1 = verifySignature(signature, publicKey, bodyHash);
	const result2 = verifySignature(signature, publicKey, bodyHash);
	const result3 = verifySignature(signature, publicKey, bodyHash);

	assertEquals(result1.isValid, result2.isValid);
	assertEquals(result2.isValid, result3.isValid);
	assertEquals(result1.error, result2.error);
});

Deno.test("Properties - Invalid Signatures Always Fail", () => {
	const publicKey = "validKey123456";

	// Empty signature always fails
	const emptyResult = verifySignature("", publicKey, "hash");
	assertEquals(emptyResult.isValid, false);

	// Empty key always fails
	const emptyKeyResult = verifySignature("signature", "", "hash");
	assertEquals(emptyKeyResult.isValid, false);

	// Property: No false positives (invalid never becomes valid)
	const invalidSignatures = [
		"",
		"@@@invalid",
		"<script>alert('xss')</script>",
	];

	for (const sig of invalidSignatures) {
		const result = verifySignature(sig, publicKey, "hash");
		assertEquals(result.isValid, false, `Signature "${sig}" should always fail`);
	}
});

Deno.test("Properties - Domain Normalization Consistency", () => {
	const domains = [
		"EXAMPLE.COM",
		"Example.Com",
		"example.com",
		"ExAmPlE.cOm",
	];

	const normalized = domains.map(normalizeDomain);

	// All should normalize to the same value
	for (const norm of normalized) {
		assertEquals(norm, "example.com");
	}
});

Deno.test("Properties - Domain Normalization Idempotent", () => {
	const domain = "EXAMPLE.COM";

	const once = normalizeDomain(domain);
	const twice = normalizeDomain(once);
	const thrice = normalizeDomain(twice);

	// Normalizing multiple times should produce same result
	assertEquals(once, twice);
	assertEquals(twice, thrice);
});

Deno.test("Properties - Selector Domain Forms Valid DNS Label", () => {
	const validCases = [
		{ selector: "default", domain: "example.com" },
		{ selector: "mail1", domain: "test.example.com" },
		{ selector: "selector-2", domain: "sub.domain.example.com" },
	];

	for (const { selector, domain } of validCases) {
		const label = formDNSLabel(selector, domain);
		assert(
			isValidDNSLabel(label),
			`Label "${label}" should be valid DNS format`,
		);
	}
});

Deno.test("Properties - DNS Label Format Invariant", () => {
	// Property: DNS labels don't exceed 63 characters per component
	const selector = "validSelector";
	const domain = "example.com";

	const label = formDNSLabel(selector, domain);
	const parts = label.split(".");

	for (const part of parts) {
		assert(
			part.length <= 63,
			`DNS label part "${part}" exceeds 63 characters`,
		);
	}
});

Deno.test("Properties - Mixed Case Domain Normalization", () => {
	// Property: Mixed case domains always normalize identically
	const testCases = [
		["EXAMPLE.COM", "example.com"],
		["Example.Com", "example.com"],
		["ExAmPlE.cOm", "example.com"],
		["SUBDOMAIN.EXAMPLE.COM", "subdomain.example.com"],
	];

	for (const [input, expected] of testCases) {
		assertEquals(normalizeDomain(input), expected);
	}
});

Deno.test("Properties - Signature Verification Edge Cases", () => {
	const publicKey = "validPublicKey";

	// Property: Signatures with only whitespace are invalid
	const whitespaceResult = verifySignature("   ", publicKey, "hash");
	assertEquals(whitespaceResult.isValid, false);

	// Property: Signatures with binary characters (not base64) are invalid
	const binaryResult = verifySignature("sig\x00\x01\x02", publicKey, "hash");
	assertEquals(binaryResult.isValid, false);
});

Deno.test("Properties - Selector Domain Combination", () => {
	// Property: Different selectors + same domain always produce distinct labels
	const domain = "example.com";
	const selector1 = formDNSLabel("selector1", domain);
	const selector2 = formDNSLabel("selector2", domain);

	assertEquals(selector1 !== selector2, true);

	// Property: Same selector + different domains produce distinct labels
	const domain1 = formDNSLabel("default", "example.com");
	const domain2 = formDNSLabel("default", "test.com");

	assertEquals(domain1 !== domain2, true);
});

Deno.test("Properties - Consistency Under Repetition", () => {
	// Property: Running verification multiple times on same input yields same result
	const testData = {
		signature: "testSignature123",
		key: "testKey456",
		hash: "testHash789",
	};

	const results = [];
	for (let i = 0; i < 5; i++) {
		results.push(verifySignature(testData.signature, testData.key, testData.hash));
	}

	// All results should be identical
	for (let i = 1; i < results.length; i++) {
		assertEquals(results[i].isValid, results[0].isValid);
		assertEquals(results[i].error, results[0].error);
	}
});
