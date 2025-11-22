/**
 * VirusTotal Integration
 *
 * Integrates with VirusTotal API to check URLs, domains, and file hashes
 * against VirusTotal's database of known malware and malicious sites.
 *
 * Supports both API-based and manual submission workflows.
 *
 * Copyright (c) 2025 DKIM Verifier Contributors
 *
 * This software is licensed under the terms of the MIT License.
 */

// @ts-check

import Logging from "./logging.mjs.js";

const log = Logging.getLogger("VirusTotal");

/**
 * @typedef {object} VirusTotalResult
 * @property {boolean} malicious
 * @property {number} positives - Number of engines detecting threat
 * @property {number} total - Total number of engines checked
 * @property {string} permalink - Link to full report
 * @property {VTEngineResult[]} engines
 * @property {string} scanDate
 * @property {string} [category] - phishing, malware, clean
 */

/**
 * @typedef {object} VTEngineResult
 * @property {string} engine
 * @property {boolean} detected
 * @property {string} [result]
 */

/**
 * VirusTotal Integration
 */
export default class VirusTotalIntegration {
	/** @type {string|null} */
	static #apiKey = null;

	/** VirusTotal API v3 base URL */
	static API_BASE = "https://www.virustotal.com/api/v3";

	/** VirusTotal Web UI base URL */
	static WEB_BASE = "https://www.virustotal.com/gui";

	/**
	 * Set API key for VirusTotal
	 *
	 * @param {string} apiKey
	 */
	static setAPIKey(apiKey) {
		this.#apiKey = apiKey;
		log.info("VirusTotal API key configured");
	}

	/**
	 * Check if API key is configured
	 *
	 * @returns {boolean}
	 */
	static hasAPIKey() {
		return this.#apiKey !== null && this.#apiKey.length > 0;
	}

	/**
	 * Scan a URL using VirusTotal API
	 *
	 * @param {string} url
	 * @returns {Promise<VirusTotalResult>}
	 */
	static async scanURL(url) {
		if (!this.hasAPIKey()) {
			log.warn("VirusTotal API key not configured");
			throw new Error("VirusTotal API key not configured");
		}

		log.debug(`Scanning URL: ${url}`);

		try {
			// First, get the URL ID
			const urlId = this.#getURLId(url);

			// Check if URL has been scanned before
			const response = await fetch(`${this.API_BASE}/urls/${urlId}`, {
				headers: {
					"x-apikey": this.#apiKey,
				},
			});

			if (response.status === 200) {
				const data = await response.json();
				return this.#parseURLReport(data);
			} else if (response.status === 404) {
				// URL not in database, submit for scanning
				log.debug("URL not in database, submitting for scan");
				return await this.#submitURL(url);
			} else {
				throw new Error(`VirusTotal API error: ${response.status}`);
			}
		} catch (error) {
			log.error("VirusTotal scan failed", error);
			throw error;
		}
	}

	/**
	 * Scan a domain using VirusTotal API
	 *
	 * @param {string} domain
	 * @returns {Promise<VirusTotalResult>}
	 */
	static async scanDomain(domain) {
		if (!this.hasAPIKey()) {
			throw new Error("VirusTotal API key not configured");
		}

		log.debug(`Scanning domain: ${domain}`);

		try {
			const response = await fetch(`${this.API_BASE}/domains/${domain}`, {
				headers: {
					"x-apikey": this.#apiKey,
				},
			});

			if (response.status === 200) {
				const data = await response.json();
				return this.#parseDomainReport(data);
			} else {
				throw new Error(`VirusTotal API error: ${response.status}`);
			}
		} catch (error) {
			log.error("VirusTotal domain scan failed", error);
			throw error;
		}
	}

	/**
	 * Check file hash against VirusTotal
	 *
	 * @param {string} hash - SHA256, SHA1, or MD5 hash
	 * @returns {Promise<VirusTotalResult>}
	 */
	static async checkFileHash(hash) {
		if (!this.hasAPIKey()) {
			throw new Error("VirusTotal API key not configured");
		}

		log.debug(`Checking file hash: ${hash}`);

		try {
			const response = await fetch(`${this.API_BASE}/files/${hash}`, {
				headers: {
					"x-apikey": this.#apiKey,
				},
			});

			if (response.status === 200) {
				const data = await response.json();
				return this.#parseFileReport(data);
			} else if (response.status === 404) {
				return {
					malicious: false,
					positives: 0,
					total: 0,
					permalink: `${this.WEB_BASE}/file/${hash}`,
					engines: [],
					scanDate: new Date().toISOString(),
					category: "unknown",
				};
			} else {
				throw new Error(`VirusTotal API error: ${response.status}`);
			}
		} catch (error) {
			log.error("VirusTotal file hash check failed", error);
			throw error;
		}
	}

	/**
	 * Submit URL for scanning (without API key)
	 * Returns a permalink for manual checking
	 *
	 * @param {string} url
	 * @returns {string} Permalink to check results manually
	 */
	static getManualSubmissionLink(url) {
		const encoded = encodeURIComponent(url);
		return `${this.WEB_BASE}/url/${this.#getURLId(url)}`;
	}

	/**
	 * Submit URL for scanning
	 *
	 * @param {string} url
	 * @returns {Promise<VirusTotalResult>}
	 */
	static async #submitURL(url) {
		const formData = new FormData();
		formData.append("url", url);

		const response = await fetch(`${this.API_BASE}/urls`, {
			method: "POST",
			headers: {
				"x-apikey": this.#apiKey,
			},
			body: formData,
		});

		if (response.status !== 200) {
			throw new Error(`Failed to submit URL: ${response.status}`);
		}

		const data = await response.json();

		// Return a pending result
		return {
			malicious: false,
			positives: 0,
			total: 0,
			permalink: data.data?.links?.self || `${this.WEB_BASE}/url/${this.#getURLId(url)}`,
			engines: [],
			scanDate: new Date().toISOString(),
			category: "pending",
		};
	}

	/**
	 * Parse URL report from VirusTotal API
	 *
	 * @param {any} data
	 * @returns {VirusTotalResult}
	 */
	static #parseURLReport(data) {
		const attributes = data.data?.attributes || {};
		const stats = attributes.last_analysis_stats || {};
		const results = attributes.last_analysis_results || {};

		const positives = stats.malicious || 0;
		const total = Object.keys(results).length;

		const engines = Object.entries(results).map(([name, result]) => ({
			engine: name,
			detected: result.category === "malicious" || result.category === "suspicious",
			result: result.result || result.category,
		}));

		let category = "clean";
		if (stats.malicious > 0) category = "malware";
		if (stats.phishing > 0) category = "phishing";

		return {
			malicious: positives > 0,
			positives,
			total,
			permalink: `${this.WEB_BASE}/url/${data.data?.id || ""}`,
			engines,
			scanDate: attributes.last_analysis_date ?
				new Date(attributes.last_analysis_date * 1000).toISOString() :
				new Date().toISOString(),
			category,
		};
	}

	/**
	 * Parse domain report from VirusTotal API
	 *
	 * @param {any} data
	 * @returns {VirusTotalResult}
	 */
	static #parseDomainReport(data) {
		const attributes = data.data?.attributes || {};
		const stats = attributes.last_analysis_stats || {};
		const results = attributes.last_analysis_results || {};

		const positives = stats.malicious || 0;
		const total = Object.keys(results).length;

		const engines = Object.entries(results).map(([name, result]) => ({
			engine: name,
			detected: result.category === "malicious",
			result: result.result || result.category,
		}));

		let category = "clean";
		if (stats.malicious > 0) category = "malware";
		if (stats.phishing > 0) category = "phishing";

		return {
			malicious: positives > 0,
			positives,
			total,
			permalink: `${this.WEB_BASE}/domain/${data.data?.id || ""}`,
			engines,
			scanDate: attributes.last_analysis_date ?
				new Date(attributes.last_analysis_date * 1000).toISOString() :
				new Date().toISOString(),
			category,
		};
	}

	/**
	 * Parse file report from VirusTotal API
	 *
	 * @param {any} data
	 * @returns {VirusTotalResult}
	 */
	static #parseFileReport(data) {
		const attributes = data.data?.attributes || {};
		const stats = attributes.last_analysis_stats || {};
		const results = attributes.last_analysis_results || {};

		const positives = stats.malicious || 0;
		const total = Object.keys(results).length;

		const engines = Object.entries(results).map(([name, result]) => ({
			engine: name,
			detected: result.category === "malicious",
			result: result.result || result.category,
		}));

		return {
			malicious: positives > 0,
			positives,
			total,
			permalink: `${this.WEB_BASE}/file/${data.data?.id || ""}`,
			engines,
			scanDate: attributes.last_analysis_date ?
				new Date(attributes.last_analysis_date * 1000).toISOString() :
				new Date().toISOString(),
			category: positives > 0 ? "malware" : "clean",
		};
	}

	/**
	 * Get URL ID for VirusTotal API (base64 encoded without padding)
	 *
	 * @param {string} url
	 * @returns {string}
	 */
	static #getURLId(url) {
		// VirusTotal uses base64 URL encoding without padding
		const encoded = btoa(url);
		return encoded.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
	}

	/**
	 * Get severity assessment from VirusTotal result
	 *
	 * @param {VirusTotalResult} result
	 * @returns {string} - clean, suspicious, malicious, critical
	 */
	static getSeverityAssessment(result) {
		if (result.positives === 0) {
			return "clean";
		}

		const detectionRate = result.total > 0 ? result.positives / result.total : 0;

		if (detectionRate >= 0.5) {
			return "critical";
		} else if (detectionRate >= 0.25) {
			return "malicious";
		} else if (detectionRate >= 0.1) {
			return "suspicious";
		} else {
			return "low_risk";
		}
	}

	/**
	 * Generate human-readable summary
	 *
	 * @param {VirusTotalResult} result
	 * @returns {string}
	 */
	static getSummary(result) {
		if (result.positives === 0) {
			return `✓ Clean - No threats detected by ${result.total} security engines`;
		}

		const severity = this.getSeverityAssessment(result);
		const percentage = result.total > 0 ? Math.round((result.positives / result.total) * 100) : 0;

		switch (severity) {
			case "critical":
				return `⚠️ CRITICAL THREAT - ${result.positives}/${result.total} engines (${percentage}%) detected this as ${result.category}`;
			case "malicious":
				return `⚠️ MALICIOUS - ${result.positives}/${result.total} engines (${percentage}%) flagged this as suspicious`;
			case "suspicious":
				return `⚠️ SUSPICIOUS - ${result.positives}/${result.total} engines (${percentage}%) detected potential threats`;
			default:
				return `⚠️ LOW RISK - ${result.positives}/${result.total} engines flagged this`;
		}
	}

	/**
	 * Batch scan multiple URLs (respects API rate limits)
	 *
	 * @param {string[]} urls
	 * @param {number} delayMs - Delay between requests in milliseconds
	 * @returns {Promise<Map<string, VirusTotalResult>>}
	 */
	static async batchScanURLs(urls, delayMs = 15000) {
		const results = new Map();

		for (const url of urls) {
			try {
				const result = await this.scanURL(url);
				results.set(url, result);

				// Wait to respect rate limits (4 requests per minute with free API)
				if (urls.indexOf(url) < urls.length - 1) {
					await this.#sleep(delayMs);
				}
			} catch (error) {
				log.error(`Failed to scan URL: ${url}`, error);
				// Continue with next URL
			}
		}

		return results;
	}

	/**
	 * Sleep helper
	 *
	 * @param {number} ms
	 * @returns {Promise<void>}
	 */
	static #sleep(ms) {
		return new Promise(resolve => setTimeout(resolve, ms));
	}
}
