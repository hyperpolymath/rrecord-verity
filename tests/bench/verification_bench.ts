// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2025 Jonathan D.A. Jewell <6759885+hyperpolymath@users.noreply.github.com>

/// <reference lib="deno.ns" />

/**
 * Performance benchmarks for rrecord-verity verification operations.
 *
 * Measures throughput and latency of key operations:
 * - DKIM record parsing
 * - Signature format validation
 * - Policy evaluation
 * - Domain canonicalization
 */

/**
 * Parse DKIM TXT record.
 */
function parseDKIMRecord(record: string): Record<string, string> | null {
	if (!record.startsWith("v=DKIM1")) {
		return null;
	}

	const tags: Record<string, string> = {};
	const tagMatches = record.matchAll(/([a-z])=([^;]*)/g);

	for (const match of tagMatches) {
		tags[match[1]] = match[2].trim();
	}

	return tags;
}

/**
 * Validate signature format (base64-ish).
 */
function validateSignatureFormat(sig: string): boolean {
	return /^[A-Za-z0-9+/=]+$/.test(sig);
}

/**
 * Evaluate DMARC policy.
 */
function evaluateDMARCPolicy(
	policy: string,
	alignmentResult: "pass" | "fail",
): string {
	if (alignmentResult === "fail") {
		if (policy === "reject") return "REJECT";
		if (policy === "quarantine") return "QUARANTINE";
	}
	return "PASS";
}

/**
 * Canonicalize domain name.
 */
function canonicalizeDomain(domain: string): string {
	return domain.toLowerCase();
}

Deno.bench(
	{
		name: "DKIM Record Parsing - Single Tag",
		baseline: true,
		group: "parsing",
	},
	() => {
		const record = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP";
		parseDKIMRecord(record);
	},
);

Deno.bench(
	{
		name: "DKIM Record Parsing - Multiple Tags",
		group: "parsing",
	},
	() => {
		const record =
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAADCBiQKBgQDwIRPUC3SBsEmGqZ9; h=sha256; c=relaxed/relaxed; t=1234567890; x=1234567900";
		parseDKIMRecord(record);
	},
);

Deno.bench(
	{
		name: "DKIM Record Parsing - Large Record",
		group: "parsing",
	},
	() => {
		const record =
			"v=DKIM1; k=rsa; p=" +
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRPUC3SBsEmGqZ9ZJW3Dkd/Tq4" +
			"oQcKKOUULSqS9YzKFwqS9YzKFwqS9YzKFwqS9YzKFwqS9YzKFwqS9YzKFwqS9Y5TmJ" +
			"nL9QIDAQAB";
		parseDKIMRecord(record);
	},
);

Deno.bench(
	{
		name: "Signature Format Validation - Valid",
		baseline: true,
		group: "validation",
	},
	() => {
		const sig = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
		validateSignatureFormat(sig);
	},
);

Deno.bench(
	{
		name: "Signature Format Validation - Invalid",
		group: "validation",
	},
	() => {
		const sig = "not@valid#signature!";
		validateSignatureFormat(sig);
	},
);

Deno.bench(
	{
		name: "Signature Format Validation - Base64 with Padding",
		group: "validation",
	},
	() => {
		const sig =
			"TIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRPUC3SBsEmGqZ9ZJW3Dkd/TQ==";
		validateSignatureFormat(sig);
	},
);

Deno.bench(
	{
		name: "DMARC Policy Evaluation - Pass",
		baseline: true,
		group: "evaluation",
	},
	() => {
		evaluateDMARCPolicy("reject", "pass");
	},
);

Deno.bench(
	{
		name: "DMARC Policy Evaluation - Fail/Reject",
		group: "evaluation",
	},
	() => {
		evaluateDMARCPolicy("reject", "fail");
	},
);

Deno.bench(
	{
		name: "DMARC Policy Evaluation - Fail/Quarantine",
		group: "evaluation",
	},
	() => {
		evaluateDMARCPolicy("quarantine", "fail");
	},
);

Deno.bench(
	{
		name: "Domain Canonicalization - Simple",
		baseline: true,
		group: "canonicalization",
	},
	() => {
		canonicalizeDomain("EXAMPLE.COM");
	},
);

Deno.bench(
	{
		name: "Domain Canonicalization - Subdomain",
		group: "canonicalization",
	},
	() => {
		canonicalizeDomain("mail.subdomain.EXAMPLE.COM");
	},
);

Deno.bench(
	{
		name: "Domain Canonicalization - Mixed Case",
		group: "canonicalization",
	},
	() => {
		canonicalizeDomain("ExAmPlE.cOm");
	},
);

Deno.bench(
	{
		name: "Combined Pipeline - Record + Validation + Evaluation",
		group: "pipeline",
	},
	() => {
		const record = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP";
		parseDKIMRecord(record);

		const sig = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
		validateSignatureFormat(sig);

		evaluateDMARCPolicy("reject", "pass");
	},
);

Deno.bench(
	{
		name: "Batch DKIM Record Parsing (10 records)",
		group: "batch",
	},
	() => {
		const records = [
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP1",
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP2",
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP3",
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP4",
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP5",
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP6",
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP7",
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP8",
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP9",
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP0",
		];

		for (const record of records) {
			parseDKIMRecord(record);
		}
	},
);

Deno.bench(
	{
		name: "Batch Domain Canonicalization (20 domains)",
		group: "batch",
	},
	() => {
		const domains = [
			"EXAMPLE.COM",
			"Example.Com",
			"MAIL.EXAMPLE.COM",
			"Mail.Example.Com",
			"SUB.DOMAIN.EXAMPLE.COM",
			"Sub.Domain.Example.Com",
			"SUBDOMAIN.EXAMPLE.COM",
			"Subdomain.Example.Com",
			"TEST.COM",
			"Test.Com",
			"MAIL.TEST.COM",
			"Mail.Test.Com",
			"STAGING.TEST.COM",
			"Staging.Test.Com",
			"PROD.COM",
			"Prod.Com",
			"API.PROD.COM",
			"Api.Prod.Com",
			"SECURE.PROD.COM",
			"Secure.Prod.Com",
		];

		for (const domain of domains) {
			canonicalizeDomain(domain);
		}
	},
);
