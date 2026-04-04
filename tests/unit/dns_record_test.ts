// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2025 Jonathan D.A. Jewell <6759885+hyperpolymath@users.noreply.github.com>

/// <reference lib="deno.ns" />

/**
 * Unit tests for DNS record parsing contracts in rrecord-verity.
 *
 * Tests verify that DKIM, SPF, and DMARC DNS record parsing
 * correctly validates record format and handles unknown tags gracefully.
 */

import { assertEquals, assertMatch } from "@std/assert";

interface DNSRecord {
	type: "DKIM" | "SPF" | "DMARC";
	value: string;
	tags?: Record<string, string>;
}

/**
 * Parse DKIM TXT record. Must start with "v=DKIM1".
 */
function parseDKIMRecord(record: string): DNSRecord | null {
	if (!record.startsWith("v=DKIM1")) {
		return null;
	}

	const tags: Record<string, string> = {};
	const tagMatches = record.matchAll(/([a-z])=([^;]*)/g);

	for (const match of tagMatches) {
		tags[match[1]] = match[2].trim();
	}

	return {
		type: "DKIM",
		value: record,
		tags,
	};
}

/**
 * Parse SPF record. Must start with "v=spf1".
 */
function parseSPFRecord(record: string): DNSRecord | null {
	if (!record.startsWith("v=spf1")) {
		return null;
	}

	return {
		type: "SPF",
		value: record,
	};
}

/**
 * Parse DMARC record. Must start with "v=DMARC1".
 */
function parseDMARCRecord(record: string): DNSRecord | null {
	if (!record.startsWith("v=DMARC1")) {
		return null;
	}

	const tags: Record<string, string> = {};
	const tagMatches = record.matchAll(/([a-z]+)=([^;]*)/g);

	for (const match of tagMatches) {
		tags[match[1]] = match[2].trim();
	}

	return {
		type: "DMARC",
		value: record,
		tags,
	};
}

/**
 * Check if record format is valid for forward compatibility.
 * Unknown tags should be ignored, not cause parsing to fail.
 */
function isForwardCompatible(record: string, type: "DKIM" | "DMARC"): boolean {
	// Both DKIM and DMARC allow unknown tags (forward compatibility)
	// Only the version tag is mandatory
	if (type === "DKIM") {
		return record.includes("v=DKIM1");
	}
	if (type === "DMARC") {
		return record.includes("v=DMARC1");
	}
	return false;
}

Deno.test("DNS Records - DKIM Record Parsing", () => {
	const validDKIM = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/";
	const parsed = parseDKIMRecord(validDKIM);

	assertEquals(parsed !== null, true);
	assertEquals(parsed?.type, "DKIM");
	assertEquals(parsed?.tags?.v, "DKIM1");
	assertEquals(parsed?.tags?.k, "rsa");
});

Deno.test("DNS Records - DKIM Invalid Prefix", () => {
	const invalidDKIM = "v=DKIM2; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/";
	const parsed = parseDKIMRecord(invalidDKIM);

	assertEquals(parsed, null);
});

Deno.test("DNS Records - SPF Record Parsing", () => {
	const validSPF = "v=spf1 ip4:192.0.2.0/24 -all";
	const parsed = parseSPFRecord(validSPF);

	assertEquals(parsed !== null, true);
	assertEquals(parsed?.type, "SPF");
	assertEquals(parsed?.value, validSPF);
});

Deno.test("DNS Records - SPF Invalid Prefix", () => {
	const invalidSPF = "v=spf2 ip4:192.0.2.0/24 -all";
	const parsed = parseSPFRecord(invalidSPF);

	assertEquals(parsed, null);
});

Deno.test("DNS Records - DMARC Record Parsing", () => {
	const validDMARC = "v=DMARC1; p=reject; rua=mailto:admin@example.com";
	const parsed = parseDMARCRecord(validDMARC);

	assertEquals(parsed !== null, true);
	assertEquals(parsed?.type, "DMARC");
	assertEquals(parsed?.tags?.v, "DMARC1");
	assertEquals(parsed?.tags?.p, "reject");
});

Deno.test("DNS Records - DMARC Tag Parsing", () => {
	const dmarc = "v=DMARC1; p=quarantine; rua=mailto:admin@example.com; ruf=mailto:forensics@example.com; fo=1";
	const parsed = parseDMARCRecord(dmarc);

	assertEquals(parsed?.tags?.p, "quarantine");
	assertEquals(parsed?.tags?.rua, "mailto:admin@example.com");
	assertEquals(parsed?.tags?.fo, "1");
});

Deno.test("DNS Records - Forward Compatibility DKIM", () => {
	// Record with unknown future tag should still parse
	const futureDKIM = "v=DKIM1; k=rsa; x-future-tag=value; p=MIGfMA0GCS...";

	assertEquals(isForwardCompatible(futureDKIM, "DKIM"), true);
	const parsed = parseDKIMRecord(futureDKIM);
	assertEquals(parsed !== null, true);
	// Unknown tag is ignored but doesn't break parsing
});

Deno.test("DNS Records - Forward Compatibility DMARC", () => {
	// Record with unknown future tag should still parse
	const futureDMARC = "v=DMARC1; p=none; x-future-tag=value; rua=mailto:admin@example.com";

	assertEquals(isForwardCompatible(futureDMARC, "DMARC"), true);
	const parsed = parseDMARCRecord(futureDMARC);
	assertEquals(parsed !== null, true);
});

Deno.test("DNS Records - DKIM Missing Version", () => {
	const noVersion = "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/";
	const parsed = parseDKIMRecord(noVersion);

	assertEquals(parsed, null);
});

Deno.test("DNS Records - DMARC Missing Version", () => {
	const noVersion = "p=reject; rua=mailto:admin@example.com";
	const parsed = parseDMARCRecord(noVersion);

	assertEquals(parsed, null);
});

Deno.test("DNS Records - Empty Record", () => {
	assertEquals(parseDKIMRecord(""), null);
	assertEquals(parseSPFRecord(""), null);
	assertEquals(parseDMARCRecord(""), null);
});

Deno.test("DNS Records - Whitespace Handling", () => {
	const dkimWithWhitespace = "v=DKIM1 ; k=rsa ; p=test";
	const parsed = parseDKIMRecord(dkimWithWhitespace);
	// Should handle gracefully (our regex allows whitespace)
	assertEquals(parsed !== null, true);
});
