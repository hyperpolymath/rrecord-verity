/**
 * SPF (Sender Policy Framework) Verifier - RFC 7208
 *
 * Copyright (c) 2025 DKIM Verifier Contributors
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./verifier.d.ts" />

import DNS from "../dns.mjs.js";
import Logging from "../logging.mjs.js";
import { DKIM_TempError } from "../error.mjs.js";

const log = Logging.getLogger("SPF.Verifier");

/**
 * @typedef {object} SPFResult
 * @property {string} result - none, neutral, pass, fail, softfail, temperror, permerror
 * @property {string} [explanation] - Human-readable explanation
 * @property {string} [mechanism] - The mechanism that matched
 * @property {number} dnsLookups - Number of DNS lookups performed
 * @property {string[]} [warnings] - Array of warning messages
 */

/**
 * SPF Verifier implements RFC 7208 (Sender Policy Framework)
 */
export default class SPFVerifier {
	/** @type {number} */
	#dnsLookupCount = 0;
	/** @type {Set<string>} */
	#dnsLookupCache = new Set();
	/** @type {string[]} */
	#warnings = [];

	/** Maximum DNS lookups allowed per SPF check (RFC 7208 Section 4.6.4) */
	static MAX_DNS_LOOKUPS = 10;
	/** Maximum void DNS lookups (RFC 7208 Section 4.6.4) */
	static MAX_VOID_LOOKUPS = 2;

	/**
	 * Verify SPF for an email message
	 *
	 * @param {string} ip - IP address of the SMTP client
	 * @param {string} domain - Domain from MAIL FROM or HELO
	 * @param {string} sender - Sender email address
	 * @param {string} [heloDomain] - HELO/EHLO domain
	 * @returns {Promise<SPFResult>}
	 */
	async verify(ip, domain, sender, heloDomain) {
		this.#dnsLookupCount = 0;
		this.#dnsLookupCache.clear();
		this.#warnings = [];

		log.debug(`Verifying SPF for IP: ${ip}, domain: ${domain}, sender: ${sender}`);

		try {
			// Validate inputs
			if (!this.#isValidIP(ip)) {
				log.warn(`Invalid IP address: ${ip}`);
				return { result: "permerror", dnsLookups: 0, explanation: "Invalid IP address" };
			}

			if (!domain) {
				log.warn("No domain provided for SPF check");
				return { result: "none", dnsLookups: 0 };
			}

			// Get SPF record for domain
			const spfRecord = await this.#getSPFRecord(domain);
			if (!spfRecord) {
				log.debug(`No SPF record found for domain: ${domain}`);
				return { result: "none", dnsLookups: this.#dnsLookupCount, warnings: this.#warnings };
			}

			log.debug(`Found SPF record: ${spfRecord}`);

			// Parse and evaluate SPF record
			const result = await this.#evaluateSPF(spfRecord, ip, domain, sender, heloDomain);
			result.dnsLookups = this.#dnsLookupCount;
			result.warnings = this.#warnings.length > 0 ? this.#warnings : undefined;

			return result;
		} catch (error) {
			log.error("SPF verification failed", error);
			if (error instanceof DKIM_TempError) {
				return { result: "temperror", dnsLookups: this.#dnsLookupCount, explanation: error.message };
			}
			return { result: "permerror", dnsLookups: this.#dnsLookupCount, explanation: String(error) };
		}
	}

	/**
	 * Get SPF record for a domain
	 *
	 * @param {string} domain
	 * @returns {Promise<string|null>}
	 */
	async #getSPFRecord(domain) {
		this.#incrementDNSLookup();

		try {
			const txtResult = await DNS.txt(domain);
			DNS.checkForErrors(txtResult);

			if (!txtResult.data || txtResult.data.length === 0) {
				return null;
			}

			// Find SPF record (starts with "v=spf1")
			const spfRecords = txtResult.data.filter(record =>
				record.trim().toLowerCase().startsWith("v=spf1")
			);

			if (spfRecords.length === 0) {
				return null;
			}

			if (spfRecords.length > 1) {
				// Multiple SPF records is a permanent error (RFC 7208 Section 4.5)
				this.#warnings.push("Multiple SPF records found - this is invalid per RFC 7208");
				return null;
			}

			return spfRecords[0];
		} catch (error) {
			log.warn(`Failed to get SPF record for ${domain}`, error);
			throw error;
		}
	}

	/**
	 * Evaluate SPF record against IP
	 *
	 * @param {string} spfRecord
	 * @param {string} ip
	 * @param {string} domain
	 * @param {string} sender
	 * @param {string|undefined} heloDomain
	 * @returns {Promise<SPFResult>}
	 */
	async #evaluateSPF(spfRecord, ip, domain, sender, heloDomain) {
		// Parse SPF record into terms
		const terms = this.#parseSPFRecord(spfRecord);

		// Evaluate each mechanism
		for (const term of terms) {
			if (term.type === "modifier") {
				continue; // Process modifiers after mechanisms
			}

			const match = await this.#evaluateMechanism(term, ip, domain, sender, heloDomain);
			if (match) {
				const result = this.#getResultFromQualifier(term.qualifier);
				log.debug(`SPF mechanism ${term.mechanism} matched with result: ${result}`);
				return {
					result,
					mechanism: `${term.qualifier}${term.mechanism}${term.value ? ":" + term.value : ""}`,
					dnsLookups: this.#dnsLookupCount,
				};
			}
		}

		// No mechanism matched - default is neutral
		log.debug("No SPF mechanism matched, returning neutral");
		return { result: "neutral", dnsLookups: this.#dnsLookupCount };
	}

	/**
	 * Parse SPF record into terms
	 *
	 * @param {string} spfRecord
	 * @returns {Array<{type: string, mechanism?: string, qualifier?: string, value?: string, modifier?: string}>}
	 */
	#parseSPFRecord(spfRecord) {
		const terms = [];
		// Remove "v=spf1" prefix
		const record = spfRecord.replace(/^v=spf1\s*/i, "");
		const parts = record.trim().split(/\s+/);

		for (const part of parts) {
			if (!part) continue;

			// Check if it's a modifier (contains "=")
			if (part.includes("=")) {
				const [modifier, value] = part.split("=", 2);
				terms.push({ type: "modifier", modifier, value });
				continue;
			}

			// It's a mechanism
			const qualifier = part[0];
			let mechanism = part;
			let mechanismName = "";
			let value = "";

			// Extract qualifier if present (+, -, ~, ?)
			if (["+", "-", "~", "?"].includes(qualifier)) {
				mechanism = part.slice(1);
			}

			// Extract mechanism name and value
			if (mechanism.includes(":") || mechanism.includes("/")) {
				const colonIndex = mechanism.indexOf(":");
				const slashIndex = mechanism.indexOf("/");

				if (colonIndex !== -1 && (slashIndex === -1 || colonIndex < slashIndex)) {
					mechanismName = mechanism.slice(0, colonIndex);
					value = mechanism.slice(colonIndex + 1);
				} else if (slashIndex !== -1) {
					mechanismName = mechanism.slice(0, slashIndex);
					value = mechanism.slice(slashIndex);
				} else {
					mechanismName = mechanism;
				}
			} else {
				mechanismName = mechanism;
			}

			terms.push({
				type: "mechanism",
				qualifier: ["+", "-", "~", "?"].includes(qualifier) ? qualifier : "+",
				mechanism: mechanismName.toLowerCase(),
				value,
			});
		}

		return terms;
	}

	/**
	 * Evaluate a single SPF mechanism
	 *
	 * @param {{type: string, mechanism?: string, qualifier?: string, value?: string}} term
	 * @param {string} ip
	 * @param {string} domain
	 * @param {string} sender
	 * @param {string|undefined} heloDomain
	 * @returns {Promise<boolean>}
	 */
	async #evaluateMechanism(term, ip, domain, sender, heloDomain) {
		if (!term.mechanism) return false;

		switch (term.mechanism) {
			case "all":
				return true; // Always matches

			case "ip4":
			case "ip6":
				return this.#matchIP(ip, term.value || "");

			case "a":
				return await this.#matchA(ip, term.value || domain);

			case "mx":
				return await this.#matchMX(ip, term.value || domain);

			case "ptr":
				// PTR mechanism is not recommended but still supported
				this.#warnings.push("PTR mechanism is not recommended per RFC 7208");
				return await this.#matchPTR(ip, term.value || domain);

			case "exists":
				return await this.#matchExists(term.value || "");

			case "include":
				return await this.#matchInclude(ip, term.value || "", sender, heloDomain);

			default:
				log.warn(`Unknown SPF mechanism: ${term.mechanism}`);
				return false;
		}
	}

	/**
	 * Match IP against CIDR notation
	 *
	 * @param {string} ip
	 * @param {string} cidr
	 * @returns {boolean}
	 */
	#matchIP(ip, cidr) {
		// Simple IP matching - in production would use proper CIDR matching library
		if (!cidr.includes("/")) {
			return ip === cidr;
		}

		// Basic CIDR matching (simplified - would need proper implementation)
		const [network, prefix] = cidr.split("/");
		return ip.startsWith(network.split(".").slice(0, Math.ceil(Number(prefix) / 8)).join("."));
	}

	/**
	 * Match A/AAAA records
	 *
	 * @param {string} ip
	 * @param {string} domain
	 * @returns {Promise<boolean>}
	 */
	async #matchA(ip, domain) {
		this.#incrementDNSLookup();
		// In production, would perform actual A/AAAA lookups
		// For now, return false as placeholder
		log.debug(`A mechanism check for ${domain} (placeholder)`);
		return false;
	}

	/**
	 * Match MX records
	 *
	 * @param {string} ip
	 * @param {string} domain
	 * @returns {Promise<boolean>}
	 */
	async #matchMX(ip, domain) {
		this.#incrementDNSLookup();
		// In production, would perform actual MX lookups
		log.debug(`MX mechanism check for ${domain} (placeholder)`);
		return false;
	}

	/**
	 * Match PTR records
	 *
	 * @param {string} ip
	 * @param {string} domain
	 * @returns {Promise<boolean>}
	 */
	async #matchPTR(ip, domain) {
		this.#incrementDNSLookup();
		// In production, would perform PTR lookup and validation
		log.debug(`PTR mechanism check for ${domain} (placeholder)`);
		return false;
	}

	/**
	 * Match EXISTS mechanism
	 *
	 * @param {string} domain
	 * @returns {Promise<boolean>}
	 */
	async #matchExists(domain) {
		this.#incrementDNSLookup();
		// In production, would check if domain has A record
		log.debug(`EXISTS mechanism check for ${domain} (placeholder)`);
		return false;
	}

	/**
	 * Match INCLUDE mechanism
	 *
	 * @param {string} ip
	 * @param {string} domain
	 * @param {string} sender
	 * @param {string|undefined} heloDomain
	 * @returns {Promise<boolean>}
	 */
	async #matchInclude(ip, domain, sender, heloDomain) {
		// Recursive SPF check on included domain
		const includedSPF = await this.#getSPFRecord(domain);
		if (!includedSPF) {
			return false;
		}

		const result = await this.#evaluateSPF(includedSPF, ip, domain, sender, heloDomain);
		return result.result === "pass";
	}

	/**
	 * Get result from qualifier
	 *
	 * @param {string|undefined} qualifier
	 * @returns {string}
	 */
	#getResultFromQualifier(qualifier) {
		switch (qualifier) {
			case "+": return "pass";
			case "-": return "fail";
			case "~": return "softfail";
			case "?": return "neutral";
			default: return "pass";
		}
	}

	/**
	 * Increment DNS lookup counter
	 *
	 * @throws {Error} if max lookups exceeded
	 */
	#incrementDNSLookup() {
		this.#dnsLookupCount++;
		if (this.#dnsLookupCount > SPFVerifier.MAX_DNS_LOOKUPS) {
			throw new Error("SPF DNS lookup limit exceeded (RFC 7208)");
		}
	}

	/**
	 * Validate IP address format
	 *
	 * @param {string} ip
	 * @returns {boolean}
	 */
	#isValidIP(ip) {
		// IPv4 regex
		const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
		// IPv6 regex (simplified)
		const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

		return ipv4Regex.test(ip) || ipv6Regex.test(ip);
	}
}
