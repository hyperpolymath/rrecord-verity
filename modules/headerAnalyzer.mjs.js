/**
 * Comprehensive Email Header Analyzer
 *
 * Analyzes all email headers for security, privacy, and compliance issues.
 *
 * Copyright (c) 2025 DKIM Verifier Contributors
 *
 * This software is licensed under the terms of the MIT License.
 */

// @ts-check
///<reference path="./headerAnalyzer.d.ts" />

import Logging from "./logging.mjs.js";
import MsgParser from "./msgParser.mjs.js";

const log = Logging.getLogger("HeaderAnalyzer");

/**
 * @typedef {object} HeaderAnalysisResult
 * @property {ReceivedHeaderAnalysis[]} receivedPath
 * @property {SecurityIssue[]} securityIssues
 * @property {PrivacyIssue[]} privacyIssues
 * @property {TransportAnalysis} transport
 * @property {HeaderLinting[]} lintingIssues
 * @property {object} summary
 * @property {number} summary.totalHops
 * @property {number} summary.encryptedHops
 * @property {number} summary.securityScore - 0-100
 * @property {string} summary.overallAssessment
 */

/**
 * @typedef {object} ReceivedHeaderAnalysis
 * @property {number} hop
 * @property {string} from
 * @property {string} by
 * @property {string|null} with
 * @property {Date|null} timestamp
 * @property {boolean} encrypted - TLS used
 * @property {string|null} tlsVersion
 * @property {string|null} cipher
 * @property {string[]} warnings
 * @property {string} raw
 */

/**
 * @typedef {object} SecurityIssue
 * @property {string} severity - critical, high, medium, low
 * @property {string} category - authentication, transport, content, configuration
 * @property {string} description
 * @property {string} recommendation
 * @property {string[]} affectedHeaders
 */

/**
 * @typedef {object} PrivacyIssue
 * @property {string} severity - high, medium, low
 * @property {string} type
 * @property {string} description
 * @property {string} leakedInfo
 * @property {string[]} affectedHeaders
 */

/**
 * @typedef {object} TransportAnalysis
 * @property {boolean} allHopsEncrypted
 * @property {string[]} unencryptedHops
 * @property {string} weakestTLS
 * @property {boolean} hasDowngrade
 * @property {string[]} suspiciousHops
 */

/**
 * @typedef {object} HeaderLinting
 * @property {string} header
 * @property {string} issue
 * @property {string} rfc
 * @property {string} severity - error, warning, info
 */

/**
 * Comprehensive Header Analyzer
 */
export default class HeaderAnalyzer {
	/**
	 * Analyze all headers in an email message
	 *
	 * @param {Map<string, string[]>} headers
	 * @returns {HeaderAnalysisResult}
	 */
	static analyzeHeaders(headers) {
		log.debug("Starting comprehensive header analysis");

		const receivedPath = this.#analyzeReceivedPath(headers);
		const transport = this.#analyzeTransport(receivedPath);
		const securityIssues = this.#findSecurityIssues(headers, receivedPath, transport);
		const privacyIssues = this.#findPrivacyIssues(headers);
		const lintingIssues = this.#lintHeaders(headers);

		const summary = this.#generateSummary(receivedPath, transport, securityIssues, privacyIssues);

		return {
			receivedPath,
			securityIssues,
			privacyIssues,
			transport,
			lintingIssues,
			summary,
		};
	}

	/**
	 * Analyze Received headers to trace message path
	 *
	 * @param {Map<string, string[]>} headers
	 * @returns {ReceivedHeaderAnalysis[]}
	 */
	static #analyzeReceivedPath(headers) {
		const received = headers.get("received") || [];
		const path = [];

		// Received headers are in reverse order (most recent first)
		for (let i = 0; i < received.length; i++) {
			const header = received[i];
			const analysis = this.#parseReceivedHeader(header, received.length - i);
			path.push(analysis);
		}

		return path.reverse(); // Return in chronological order
	}

	/**
	 * Parse a single Received header
	 *
	 * @param {string} header
	 * @param {number} hop
	 * @returns {ReceivedHeaderAnalysis}
	 */
	static #parseReceivedHeader(header, hop) {
		const warnings = [];
		const headerLower = header.toLowerCase();

		// Extract 'from' field
		const fromMatch = header.match(/from\s+([^\s]+)/i);
		const from = fromMatch ? fromMatch[1] : "unknown";

		// Extract 'by' field
		const byMatch = header.match(/by\s+([^\s]+)/i);
		const by = byMatch ? byMatch[1] : "unknown";

		// Extract 'with' field (protocol)
		const withMatch = header.match(/with\s+([^\s]+)/i);
		const withProtocol = withMatch ? withMatch[1] : null;

		// Check for TLS/encryption
		const encrypted = headerLower.includes("tls") ||
			headerLower.includes("esmtps") ||
			headerLower.includes("esmtpsa");

		// Extract TLS version
		let tlsVersion = null;
		const tlsMatch = header.match(/tls\s*v?(1\.[0-3]|1\.0|ssl\s*v?3)/i);
		if (tlsMatch) {
			tlsVersion = tlsMatch[1];
			if (tlsVersion.toLowerCase().includes("ssl") || tlsVersion === "1.0" || tlsVersion === "1.1") {
				warnings.push(`Outdated TLS version: ${tlsVersion}`);
			}
		}

		// Extract cipher
		let cipher = null;
		const cipherMatch = header.match(/cipher[=:\s]+([^\s,;)]+)/i);
		if (cipherMatch) {
			cipher = cipherMatch[1];
			if (this.#isWeakCipher(cipher)) {
				warnings.push(`Weak cipher detected: ${cipher}`);
			}
		}

		// Extract timestamp
		const timestamp = MsgParser.tryExtractReceivedTime(header);

		// Check for suspicious patterns
		if (from === "unknown" || from.includes("[")) {
			warnings.push("Suspicious or missing from field");
		}

		if (!encrypted) {
			warnings.push("Unencrypted hop");
		}

		return {
			hop,
			from,
			by,
			with: withProtocol,
			timestamp,
			encrypted,
			tlsVersion,
			cipher,
			warnings,
			raw: header,
		};
	}

	/**
	 * Analyze transport security across all hops
	 *
	 * @param {ReceivedHeaderAnalysis[]} path
	 * @returns {TransportAnalysis}
	 */
	static #analyzeTransport(path) {
		const unencryptedHops = [];
		const suspiciousHops = [];
		let weakestTLS = "TLS1.3";
		let hasDowngrade = false;

		for (const hop of path) {
			if (!hop.encrypted) {
				unencryptedHops.push(`Hop ${hop.hop}: ${hop.from} -> ${hop.by}`);
			}

			if (hop.tlsVersion) {
				if (this.#compareTLSVersions(hop.tlsVersion, weakestTLS) < 0) {
					weakestTLS = hop.tlsVersion;
				}
			}

			if (hop.warnings.some(w => w.includes("Suspicious"))) {
				suspiciousHops.push(`Hop ${hop.hop}: ${hop.from}`);
			}
		}

		// Check for TLS downgrade attacks
		let prevVersion = null;
		for (const hop of path) {
			if (hop.tlsVersion) {
				if (prevVersion && this.#compareTLSVersions(hop.tlsVersion, prevVersion) < 0) {
					hasDowngrade = true;
					break;
				}
				prevVersion = hop.tlsVersion;
			}
		}

		return {
			allHopsEncrypted: unencryptedHops.length === 0,
			unencryptedHops,
			weakestTLS,
			hasDowngrade,
			suspiciousHops,
		};
	}

	/**
	 * Find security issues in headers
	 *
	 * @param {Map<string, string[]>} headers
	 * @param {ReceivedHeaderAnalysis[]} path
	 * @param {TransportAnalysis} transport
	 * @returns {SecurityIssue[]}
	 */
	static #findSecurityIssues(headers, path, transport) {
		const issues = [];

		// Check for missing security headers
		if (!headers.has("authentication-results")) {
			issues.push({
				severity: "medium",
				category: "authentication",
				description: "Missing Authentication-Results header",
				recommendation: "Email has no authentication results header. This may indicate the receiving server did not perform SPF/DKIM/DMARC checks.",
				affectedHeaders: [],
			});
		}

		// Check for unencrypted transport
		if (!transport.allHopsEncrypted) {
			issues.push({
				severity: "high",
				category: "transport",
				description: "Email transmitted over unencrypted connections",
				recommendation: `${transport.unencryptedHops.length} hop(s) did not use TLS encryption. Email content may have been visible to network observers.`,
				affectedHeaders: ["received"],
			});
		}

		// Check for TLS downgrade
		if (transport.hasDowngrade) {
			issues.push({
				severity: "critical",
				category: "transport",
				description: "Possible TLS downgrade attack detected",
				recommendation: "The TLS version decreased during transit, which may indicate an active attack.",
				affectedHeaders: ["received"],
			});
		}

		// Check for weak TLS
		if (transport.weakestTLS && this.#compareTLSVersions(transport.weakestTLS, "TLS1.2") < 0) {
			issues.push({
				severity: "high",
				category: "transport",
				description: `Weak TLS version used: ${transport.weakestTLS}`,
				recommendation: "Upgrade mail servers to use TLS 1.2 or higher.",
				affectedHeaders: ["received"],
			});
		}

		// Check for missing security headers on outgoing
		const returnPath = headers.get("return-path");
		if (!returnPath || returnPath.length === 0) {
			issues.push({
				severity: "low",
				category: "configuration",
				description: "Missing Return-Path header",
				recommendation: "Return-Path header helps with bounce handling.",
				affectedHeaders: [],
			});
		}

		// Check for suspicious Reply-To
		const replyTo = headers.get("reply-to");
		const from = headers.get("from");
		if (replyTo && from && replyTo[0] !== from[0]) {
			issues.push({
				severity: "medium",
				category: "content",
				description: "Reply-To address differs from From address",
				recommendation: "This is common in phishing emails. Verify the reply-to address is legitimate.",
				affectedHeaders: ["reply-to", "from"],
			});
		}

		// Check for suspicious received hops
		if (transport.suspiciousHops.length > 0) {
			issues.push({
				severity: "high",
				category: "transport",
				description: "Suspicious mail hops detected",
				recommendation: `${transport.suspiciousHops.length} suspicious hop(s) found in the email path.`,
				affectedHeaders: ["received"],
			});
		}

		// Check for missing Message-ID
		if (!headers.has("message-id")) {
			issues.push({
				severity: "low",
				category: "configuration",
				description: "Missing Message-ID header",
				recommendation: "Message-ID helps with email threading and deduplication.",
				affectedHeaders: [],
			});
		}

		// Check for suspicious User-Agent or X-Mailer
		const userAgent = headers.get("user-agent") || headers.get("x-mailer");
		if (userAgent && userAgent.some(ua => this.#isSuspiciousMailer(ua))) {
			issues.push({
				severity: "medium",
				category: "content",
				description: "Suspicious mail client detected",
				recommendation: "The User-Agent or X-Mailer header indicates a potentially suspicious email client.",
				affectedHeaders: ["user-agent", "x-mailer"],
			});
		}

		return issues;
	}

	/**
	 * Find privacy issues in headers
	 *
	 * @param {Map<string, string[]>} headers
	 * @returns {PrivacyIssue[]}
	 */
	static #findPrivacyIssues(headers) {
		const issues = [];

		// Check for IP address leakage
		const xOrigIP = headers.get("x-originating-ip");
		if (xOrigIP && xOrigIP.length > 0) {
			issues.push({
				severity: "high",
				type: "IP Address Leakage",
				description: "X-Originating-IP header reveals sender's IP address",
				leakedInfo: xOrigIP[0],
				affectedHeaders: ["x-originating-ip"],
			});
		}

		// Check for client info leakage
		const xMailer = headers.get("x-mailer");
		if (xMailer && xMailer.length > 0) {
			issues.push({
				severity: "low",
				type: "Client Information",
				description: "X-Mailer header reveals email client details",
				leakedInfo: xMailer[0],
				affectedHeaders: ["x-mailer"],
			});
		}

		// Check for internal network info
		const received = headers.get("received") || [];
		for (const rcv of received) {
			if (this.#containsPrivateIP(rcv)) {
				issues.push({
					severity: "medium",
					type: "Internal Network Exposure",
					description: "Received header contains private IP addresses",
					leakedInfo: "Internal network topology information",
					affectedHeaders: ["received"],
				});
				break; // Only report once
			}
		}

		// Check for timezone leakage
		const date = headers.get("date");
		if (date && date.length > 0 && this.#containsTimezone(date[0])) {
			issues.push({
				severity: "low",
				type: "Timezone Information",
				description: "Date header reveals sender's timezone",
				leakedInfo: this.#extractTimezone(date[0]) || "unknown",
				affectedHeaders: ["date"],
			});
		}

		return issues;
	}

	/**
	 * Lint headers for RFC compliance
	 *
	 * @param {Map<string, string[]>} headers
	 * @returns {HeaderLinting[]}
	 */
	static #lintHeaders(headers) {
		const issues = [];

		// Check required headers (RFC 5322)
		const requiredHeaders = ["from", "date"];
		for (const required of requiredHeaders) {
			if (!headers.has(required)) {
				issues.push({
					header: required,
					issue: `Missing required header: ${required}`,
					rfc: "RFC 5322",
					severity: "error",
				});
			}
		}

		// Check for duplicate headers that should be unique
		const uniqueHeaders = ["from", "sender", "reply-to", "to", "subject", "message-id", "date"];
		for (const unique of uniqueHeaders) {
			const values = headers.get(unique);
			if (values && values.length > 1) {
				issues.push({
					header: unique,
					issue: `Duplicate header: ${unique} appears ${values.length} times`,
					rfc: "RFC 5322",
					severity: "warning",
				});
			}
		}

		// Check From header format
		const from = headers.get("from");
		if (from && from.length > 0) {
			try {
				MsgParser.parseFromHeader(from[0]);
			} catch (error) {
				issues.push({
					header: "from",
					issue: "Invalid From header format",
					rfc: "RFC 5322",
					severity: "error",
				});
			}
		}

		// Check Date header
		const date = headers.get("date");
		if (date && date.length > 0) {
			const dateValue = new Date(date[0]);
			if (dateValue.toString() === "Invalid Date") {
				issues.push({
					header: "date",
					issue: "Invalid date format",
					rfc: "RFC 5322",
					severity: "error",
				});
			}
			// Check for dates too far in future
			const now = new Date();
			const daysDiff = (dateValue.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
			if (daysDiff > 1) {
				issues.push({
					header: "date",
					issue: `Date is ${Math.floor(daysDiff)} days in the future`,
					rfc: "RFC 5322",
					severity: "warning",
				});
			}
		}

		return issues;
	}

	/**
	 * Generate summary assessment
	 *
	 * @param {ReceivedHeaderAnalysis[]} path
	 * @param {TransportAnalysis} transport
	 * @param {SecurityIssue[]} securityIssues
	 * @param {PrivacyIssue[]} privacyIssues
	 * @returns {{totalHops: number, encryptedHops: number, securityScore: number, overallAssessment: string}}
	 */
	static #generateSummary(path, transport, securityIssues, privacyIssues) {
		const totalHops = path.length;
		const encryptedHops = path.filter(h => h.encrypted).length;

		// Calculate security score (0-100)
		let score = 100;

		// Deduct for security issues
		for (const issue of securityIssues) {
			switch (issue.severity) {
				case "critical": score -= 30; break;
				case "high": score -= 15; break;
				case "medium": score -= 8; break;
				case "low": score -= 3; break;
			}
		}

		// Deduct for unencrypted hops
		const encryptionRatio = totalHops > 0 ? encryptedHops / totalHops : 1;
		score -= (1 - encryptionRatio) * 20;

		score = Math.max(0, Math.min(100, score));

		let assessment;
		if (score >= 90) assessment = "Excellent - Strong security posture";
		else if (score >= 75) assessment = "Good - Minor security concerns";
		else if (score >= 50) assessment = "Fair - Moderate security issues detected";
		else if (score >= 25) assessment = "Poor - Significant security problems";
		else assessment = "Critical - Severe security vulnerabilities";

		return {
			totalHops,
			encryptedHops,
			securityScore: Math.round(score),
			overallAssessment: assessment,
		};
	}

	// Helper methods

	/**
	 * Check if cipher is weak
	 *
	 * @param {string} cipher
	 * @returns {boolean}
	 */
	static #isWeakCipher(cipher) {
		const weakPatterns = ["rc4", "des", "md5", "null", "export", "anon"];
		const cipherLower = cipher.toLowerCase();
		return weakPatterns.some(pattern => cipherLower.includes(pattern));
	}

	/**
	 * Compare TLS versions
	 *
	 * @param {string} v1
	 * @param {string} v2
	 * @returns {number} -1 if v1 < v2, 0 if equal, 1 if v1 > v2
	 */
	static #compareTLSVersions(v1, v2) {
		const parseVersion = (v) => {
			const match = v.match(/(\d+)\.(\d+)/);
			if (!match) return [0, 0];
			return [parseInt(match[1], 10), parseInt(match[2], 10)];
		};

		const [major1, minor1] = parseVersion(v1);
		const [major2, minor2] = parseVersion(v2);

		if (major1 !== major2) return major1 - major2;
		return minor1 - minor2;
	}

	/**
	 * Check if mailer is suspicious
	 *
	 * @param {string} mailer
	 * @returns {boolean}
	 */
	static #isSuspiciousMailer(mailer) {
		const suspicious = ["bulk", "mass", "spam", "bot"];
		const mailerLower = mailer.toLowerCase();
		return suspicious.some(pattern => mailerLower.includes(pattern));
	}

	/**
	 * Check if string contains private IP
	 *
	 * @param {string} str
	 * @returns {boolean}
	 */
	static #containsPrivateIP(str) {
		const privateIPPatterns = [
			/\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
			/\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/,
			/\b192\.168\.\d{1,3}\.\d{1,3}\b/,
		];
		return privateIPPatterns.some(pattern => pattern.test(str));
	}

	/**
	 * Check if string contains timezone
	 *
	 * @param {string} str
	 * @returns {boolean}
	 */
	static #containsTimezone(str) {
		return /[+-]\d{4}/.test(str);
	}

	/**
	 * Extract timezone from string
	 *
	 * @param {string} str
	 * @returns {string|null}
	 */
	static #extractTimezone(str) {
		const match = str.match(/([+-]\d{4})/);
		return match ? match[1] : null;
	}
}
