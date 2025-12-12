/**
 * DNS Blacklist (DNSBL/RBL) Checker
 *
 * Checks IP addresses and domains against multiple DNS blacklists
 * including spam databases, phishing lists, and malware sources.
 *
 * Copyright (c) 2025 DKIM Verifier Contributors
 *
 * This software is licensed under the terms of the MIT License.
 */

// @ts-check

import DNS from "./dns.mjs.js";
import Logging from "./logging.mjs.js";

const log = Logging.getLogger("DNSBL");

/**
 * @typedef {object} DNSBLResult
 * @property {boolean} listed
 * @property {DNSBLListingDetails[]} listings
 * @property {number} totalChecked
 * @property {number} totalListed
 * @property {string} severity - clean, low, medium, high, critical
 */

/**
 * @typedef {object} DNSBLListingDetails
 * @property {string} blacklist
 * @property {boolean} listed
 * @property {string[]} [reasons]
 * @property {string} [url] - URL for more info
 * @property {string} severity
 */

/**
 * DNS Blacklist Checker
 */
export default class DNSBL {
	/**
	 * Major DNSBL providers
	 * Format: {name, zone, severity, url}
	 */
	static BLACKLISTS = [
		// Spam blacklists
		{ name: "Spamhaus ZEN", zone: "zen.spamhaus.org", severity: "high", url: "https://www.spamhaus.org/zen/" },
		{ name: "Spamhaus SBL", zone: "sbl.spamhaus.org", severity: "high", url: "https://www.spamhaus.org/sbl/" },
		{ name: "Spamhaus XBL", zone: "xbl.spamhaus.org", severity: "high", url: "https://www.spamhaus.org/xbl/" },
		{ name: "Spamhaus PBL", zone: "pbl.spamhaus.org", severity: "medium", url: "https://www.spamhaus.org/pbl/" },
		{ name: "SpamCop", zone: "bl.spamcop.net", severity: "medium", url: "https://www.spamcop.net/" },
		{ name: "SORBS SPAM", zone: "spam.dnsbl.sorbs.net", severity: "medium", url: "https://www.sorbs.net/" },
		{ name: "Barracuda", zone: "b.barracudacentral.org", severity: "medium", url: "https://www.barracudacentral.org/" },

		// Domain-based blacklists
		{ name: "SURBL", zone: "multi.surbl.org", severity: "high", url: "https://www.surbl.org/", domain: true },
		{ name: "URIBL", zone: "multi.uribl.com", severity: "high", url: "http://uribl.com/", domain: true },
		{ name: "DBL Spamhaus", zone: "dbl.spamhaus.org", severity: "high", url: "https://www.spamhaus.org/dbl/", domain: true },

		// Malware/Phishing lists
		{ name: "Malware Domain List", zone: "dnsbl.malware.com", severity: "critical", url: "https://www.malware.com/" },
		{ name: "PhishTank", zone: "phishtank.com", severity: "critical", url: "https://www.phishtank.com/" },

		// Other notable lists
		{ name: "PSBL", zone: "psbl.surriel.com", severity: "medium", url: "https://psbl.org/" },
		{ name: "CBL", zone: "cbl.abuseat.org", severity: "high", url: "https://cbl.abuseat.org/" },
		{ name: "Invaluement", zone: "ivmuri.invaluement.com", severity: "medium", url: "https://www.invaluement.com/" },
	];

	/**
	 * Check IP address against DNSBLs
	 *
	 * @param {string} ip - IP address to check
	 * @param {string[]} [blacklistsToCheck] - Specific blacklists to check (defaults to all)
	 * @returns {Promise<DNSBLResult>}
	 */
	static async checkIP(ip, blacklistsToCheck) {
		log.debug(`Checking IP ${ip} against DNSBLs`);

		const reversedIP = this.#reverseIP(ip);
		if (!reversedIP) {
			log.warn(`Invalid IP address: ${ip}`);
			return {
				listed: false,
				listings: [],
				totalChecked: 0,
				totalListed: 0,
				severity: "clean",
			};
		}

		const blacklists = blacklistsToCheck ?
			DNSBL.BLACKLISTS.filter(bl => blacklistsToCheck.includes(bl.name)) :
			DNSBL.BLACKLISTS.filter(bl => !bl.domain);

		const listings = await Promise.all(
			blacklists.map(bl => this.#checkBlacklist(reversedIP, bl))
		);

		const listedCount = listings.filter(l => l.listed).length;
		const highestSeverity = this.#determineHighestSeverity(listings);

		return {
			listed: listedCount > 0,
			listings,
			totalChecked: blacklists.length,
			totalListed: listedCount,
			severity: highestSeverity,
		};
	}

	/**
	 * Check domain against DNSBLs
	 *
	 * @param {string} domain - Domain to check
	 * @returns {Promise<DNSBLResult>}
	 */
	static async checkDomain(domain) {
		log.debug(`Checking domain ${domain} against DNSBLs`);

		const domainBlacklists = DNSBL.BLACKLISTS.filter(bl => bl.domain);

		const listings = await Promise.all(
			domainBlacklists.map(bl => this.#checkBlacklist(domain, bl))
		);

		const listedCount = listings.filter(l => l.listed).length;
		const highestSeverity = this.#determineHighestSeverity(listings);

		return {
			listed: listedCount > 0,
			listings,
			totalChecked: domainBlacklists.length,
			totalListed: listedCount,
			severity: highestSeverity,
		};
	}

	/**
	 * Check against a specific blacklist
	 *
	 * @param {string} query - Reversed IP or domain
	 * @param {{name: string, zone: string, severity: string, url: string}} blacklist
	 * @returns {Promise<DNSBLListingDetails>}
	 */
	static async #checkBlacklist(query, blacklist) {
		const lookupDomain = `${query}.${blacklist.zone}`;

		try {
			const result = await DNS.txt(lookupDomain);

			// If we get a result, it's listed
			if (result.data && result.data.length > 0) {
				log.info(`${query} is listed in ${blacklist.name}: ${result.data.join(", ")}`);
				return {
					blacklist: blacklist.name,
					listed: true,
					reasons: result.data,
					url: blacklist.url,
					severity: blacklist.severity,
				};
			}

			// No data means not listed
			return {
				blacklist: blacklist.name,
				listed: false,
				severity: blacklist.severity,
				url: blacklist.url,
			};
		} catch (error) {
			// DNS errors typically mean "not listed" for DNSBLs
			log.debug(`${query} not listed in ${blacklist.name}`);
			return {
				blacklist: blacklist.name,
				listed: false,
				severity: blacklist.severity,
				url: blacklist.url,
			};
		}
	}

	/**
	 * Reverse IP address for DNSBL lookup
	 *
	 * @param {string} ip
	 * @returns {string|null}
	 */
	static #reverseIP(ip) {
		// IPv4
		if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
			return ip.split(".").reverse().join(".");
		}

		// IPv6 (simplified - full implementation would be more complex)
		if (ip.includes(":")) {
			// For now, return null for IPv6
			// Full implementation would expand and reverse IPv6 addresses
			log.warn("IPv6 DNSBL lookup not fully implemented");
			return null;
		}

		return null;
	}

	/**
	 * Determine highest severity from listings
	 *
	 * @param {DNSBLListingDetails[]} listings
	 * @returns {string}
	 */
	static #determineHighestSeverity(listings) {
		const listed = listings.filter(l => l.listed);
		if (listed.length === 0) return "clean";

		const severities = ["critical", "high", "medium", "low"];
		for (const severity of severities) {
			if (listed.some(l => l.severity === severity)) {
				return severity;
			}
		}

		return "low";
	}

	/**
	 * Get reputation summary
	 *
	 * @param {DNSBLResult} result
	 * @returns {string}
	 */
	static getReputationSummary(result) {
		if (!result.listed) {
			return "Clean - Not listed on any checked blacklists";
		}

		const percentage = Math.round((result.totalListed / result.totalChecked) * 100);

		switch (result.severity) {
			case "critical":
				return `CRITICAL - Listed on ${result.totalListed}/${result.totalChecked} blacklists (${percentage}%). Likely malware or phishing source.`;
			case "high":
				return `HIGH RISK - Listed on ${result.totalListed}/${result.totalChecked} blacklists (${percentage}%). Known spam source.`;
			case "medium":
				return `MEDIUM RISK - Listed on ${result.totalListed}/${result.totalChecked} blacklists (${percentage}%). Possible spam activity.`;
			case "low":
				return `LOW RISK - Listed on ${result.totalListed}/${result.totalChecked} blacklists (${percentage}%). Minor reputation issues.`;
			default:
				return `Listed on ${result.totalListed}/${result.totalChecked} blacklists (${percentage}%)`;
		}
	}
}
