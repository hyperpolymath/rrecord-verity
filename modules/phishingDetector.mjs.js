/**
 * Phishing / Vishing / Smishing Detection System
 *
 * Advanced heuristic-based detection of phishing attacks using multiple
 * detection techniques including URL analysis, content analysis,
 * sender verification, and behavioral patterns.
 *
 * Copyright (c) 2025 DKIM Verifier Contributors
 *
 * This software is licensed under the terms of the MIT License.
 */

// @ts-check

import Logging from "./logging.mjs.js";

const log = Logging.getLogger("PhishingDetector");

/**
 * @typedef {object} PhishingAnalysisResult
 * @property {number} riskScore - 0-100, higher is more suspicious
 * @property {string} riskLevel - safe, low, medium, high, critical
 * @property {PhishingIndicator[]} indicators
 * @property {string[]} recommendations
 * @property {boolean} isLikelyPhishing
 */

/**
 * @typedef {object} PhishingIndicator
 * @property {string} type
 * @property {string} severity - low, medium, high, critical
 * @property {string} description
 * @property {number} scoreImpact
 * @property {string} evidence
 */

/**
 * Phishing Detector - Uses heuristics to detect phishing attempts
 */
export default class PhishingDetector {
	/** Common phishing keywords */
	static PHISHING_KEYWORDS = [
		"verify your account",
		"confirm your identity",
		"suspended account",
		"unusual activity",
		"click here immediately",
		"urgent action required",
		"verify your password",
		"update your information",
		"confirm your details",
		"security alert",
		"account will be closed",
		"limited time offer",
		"claim your prize",
		"you've won",
		"congratulations",
		"act now",
		"reset your password",
		"billing problem",
		"payment failed",
		"refund",
	];

	/** Suspicious TLDs often used in phishing */
	static SUSPICIOUS_TLDS = [
		".tk",
		".ml",
		".ga",
		".cf",
		".gq",
		".xyz",
		".top",
		".work",
		".click",
		".link",
		".download",
		".stream",
	];

	/** Commonly impersonated brands */
	static IMPERSONATED_BRANDS = [
		"paypal",
		"amazon",
		"microsoft",
		"apple",
		"google",
		"facebook",
		"netflix",
		"ebay",
		"bank",
		"irs",
		"fedex",
		"ups",
		"dhl",
	];

	/**
	 * Analyze email for phishing indicators
	 *
	 * @param {object} email
	 * @param {string} email.subject
	 * @param {string} email.body
	 * @param {string} email.from
	 * @param {string[]} email.links
	 * @param {Map<string, string[]>} email.headers
	 * @returns {PhishingAnalysisResult}
	 */
	static analyzeEmail(email) {
		log.debug("Analyzing email for phishing indicators");

		const indicators = [];
		let riskScore = 0;

		// Analyze subject line
		const subjectIndicators = this.#analyzeSubject(email.subject);
		indicators.push(...subjectIndicators);
		riskScore += subjectIndicators.reduce((sum, ind) => sum + ind.scoreImpact, 0);

		// Analyze sender
		const senderIndicators = this.#analyzeSender(email.from, email.headers);
		indicators.push(...senderIndicators);
		riskScore += senderIndicators.reduce((sum, ind) => sum + ind.scoreImpact, 0);

		// Analyze content
		const contentIndicators = this.#analyzeContent(email.body);
		indicators.push(...contentIndicators);
		riskScore += contentIndicators.reduce((sum, ind) => sum + ind.scoreImpact, 0);

		// Analyze links
		const linkIndicators = this.#analyzeLinks(email.links, email.from);
		indicators.push(...linkIndicators);
		riskScore += linkIndicators.reduce((sum, ind) => sum + ind.scoreImpact, 0);

		// Analyze headers
		const headerIndicators = this.#analyzeHeaders(email.headers);
		indicators.push(...headerIndicators);
		riskScore += headerIndicators.reduce((sum, ind) => sum + ind.scoreImpact, 0);

		// Cap risk score at 100
		riskScore = Math.min(100, riskScore);

		const riskLevel = this.#getRiskLevel(riskScore);
		const isLikelyPhishing = riskScore >= 60;
		const recommendations = this.#generateRecommendations(indicators, riskScore);

		log.info(`Phishing analysis complete: Risk score ${riskScore}, Level: ${riskLevel}`);

		return {
			riskScore,
			riskLevel,
			indicators,
			recommendations,
			isLikelyPhishing,
		};
	}

	/**
	 * Analyze subject line for phishing indicators
	 *
	 * @param {string} subject
	 * @returns {PhishingIndicator[]}
	 */
	static #analyzeSubject(subject) {
		const indicators = [];
		const subjectLower = subject.toLowerCase();

		// Check for urgency/pressure keywords
		for (const keyword of PhishingDetector.PHISHING_KEYWORDS) {
			if (subjectLower.includes(keyword)) {
				indicators.push({
					type: "urgency_keyword",
					severity: "medium",
					description: `Subject contains urgency keyword: "${keyword}"`,
					scoreImpact: 8,
					evidence: subject,
				});
				break; // Only count once
			}
		}

		// Check for excessive punctuation (!!!, ???)
		if (/[!?]{3,}/.test(subject)) {
			indicators.push({
				type: "excessive_punctuation",
				severity: "low",
				description: "Subject contains excessive punctuation (urgency tactic)",
				scoreImpact: 3,
				evidence: subject,
			});
		}

		// Check for ALL CAPS
		if (subject === subject.toUpperCase() && subject.length > 10) {
			indicators.push({
				type: "all_caps",
				severity: "low",
				description: "Subject is in ALL CAPS (aggressive marketing tactic)",
				scoreImpact: 5,
				evidence: subject,
			});
		}

		// Check for "Re:" or "Fwd:" when it's likely fake
		if (/^(re|fwd):/i.test(subject) && subjectLower.includes("account")) {
			indicators.push({
				type: "fake_reply",
				severity: "medium",
				description: "Subject looks like a reply but may be fake (social engineering)",
				scoreImpact: 7,
				evidence: subject,
			});
		}

		return indicators;
	}

	/**
	 * Analyze sender for phishing indicators
	 *
	 * @param {string} from
	 * @param {Map<string, string[]>} headers
	 * @returns {PhishingIndicator[]}
	 */
	static #analyzeSender(from, headers) {
		const indicators = [];
		const fromLower = from.toLowerCase();

		// Check for brand impersonation
		for (const brand of PhishingDetector.IMPERSONATED_BRANDS) {
			if (fromLower.includes(brand)) {
				// Check if domain actually matches the brand
				const domain = this.#extractDomain(from);
				if (domain && !domain.includes(brand)) {
					indicators.push({
						type: "brand_impersonation",
						severity: "critical",
						description: `Sender appears to impersonate ${brand} but uses different domain: ${domain}`,
						scoreImpact: 25,
						evidence: from,
					});
				} else if (domain && !this.#isLegitBrandDomain(brand, domain)) {
					indicators.push({
						type: "suspicious_brand_domain",
						severity: "high",
						description: `Sender claims to be from ${brand} but uses suspicious domain: ${domain}`,
						scoreImpact: 20,
						evidence: from,
					});
				}
			}
		}

		// Check for suspicious domain
		const domain = this.#extractDomain(from);
		if (domain) {
			for (const tld of PhishingDetector.SUSPICIOUS_TLDS) {
				if (domain.endsWith(tld)) {
					indicators.push({
						type: "suspicious_tld",
						severity: "medium",
						description: `Sender uses suspicious TLD: ${tld}`,
						scoreImpact: 10,
						evidence: domain,
					});
					break;
				}
			}

			// Check for excessive subdomains (e.g., paypal.secure.login.phishing.com)
			const parts = domain.split(".");
			if (parts.length > 4) {
				indicators.push({
					type: "excessive_subdomains",
					severity: "medium",
					description: "Sender domain has excessive subdomains (obfuscation tactic)",
					scoreImpact: 8,
					evidence: domain,
				});
			}

			// Check for number-heavy domains
			const numberCount = (domain.match(/\d/g) || []).length;
			if (numberCount > 5) {
				indicators.push({
					type: "number_heavy_domain",
					severity: "low",
					description: "Sender domain contains many numbers (suspicious pattern)",
					scoreImpact: 5,
					evidence: domain,
				});
			}
		}

		// Check for display name mismatch
		const displayName = this.#extractDisplayName(from);
		if (displayName && domain) {
			const displayLower = displayName.toLowerCase();
			for (const brand of PhishingDetector.IMPERSONATED_BRANDS) {
				if (displayLower.includes(brand) && !domain.includes(brand)) {
					indicators.push({
						type: "display_name_mismatch",
						severity: "high",
						description: `Display name mentions ${brand} but domain doesn't match`,
						scoreImpact: 18,
						evidence: `${displayName} <${domain}>`,
					});
					break;
				}
			}
		}

		// Check Reply-To mismatch
		const replyTo = headers.get("reply-to");
		if (replyTo && replyTo[0] && replyTo[0] !== from) {
			indicators.push({
				type: "reply_to_mismatch",
				severity: "medium",
				description: "Reply-To address differs from From address (potential phishing)",
				scoreImpact: 12,
				evidence: `From: ${from}, Reply-To: ${replyTo[0]}`,
			});
		}

		return indicators;
	}

	/**
	 * Analyze email content for phishing indicators
	 *
	 * @param {string} body
	 * @returns {PhishingIndicator[]}
	 */
	static #analyzeContent(body) {
		const indicators = [];
		const bodyLower = body.toLowerCase();

		// Check for common phishing phrases
		let phishingPhraseCount = 0;
		for (const keyword of PhishingDetector.PHISHING_KEYWORDS) {
			if (bodyLower.includes(keyword)) {
				phishingPhraseCount++;
			}
		}

		if (phishingPhraseCount >= 3) {
			indicators.push({
				type: "multiple_phishing_keywords",
				severity: "high",
				description: `Email contains ${phishingPhraseCount} common phishing phrases`,
				scoreImpact: 15,
				evidence: `${phishingPhraseCount} suspicious phrases detected`,
			});
		} else if (phishingPhraseCount >= 1) {
			indicators.push({
				type: "phishing_keywords",
				severity: "medium",
				description: "Email contains common phishing phrases",
				scoreImpact: 8,
				evidence: `${phishingPhraseCount} suspicious phrase(s) detected`,
			});
		}

		// Check for requests for sensitive information
		const sensitiveKeywords = ["password", "ssn", "social security", "credit card", "bank account", "pin"];
		for (const keyword of sensitiveKeywords) {
			if (bodyLower.includes(keyword) && bodyLower.includes("provide")) {
				indicators.push({
					type: "sensitive_info_request",
					severity: "critical",
					description: `Email requests sensitive information: ${keyword}`,
					scoreImpact: 30,
					evidence: keyword,
				});
				break;
			}
		}

		// Check for grammatical errors (simplified check)
		const errorPatterns = [
			/\b(your|you\'re)\s+(account|password|information)\s+has?\s+been\s+/i,
			/\bplease\s+to\s+/i,
			/\bkindly\s+revert\s+back\b/i,
		];

		for (const pattern of errorPatterns) {
			if (pattern.test(body)) {
				indicators.push({
					type: "grammatical_errors",
					severity: "low",
					description: "Email contains grammatical errors common in phishing",
					scoreImpact: 5,
					evidence: "Grammatical patterns detected",
				});
				break;
			}
		}

		// Check for generic greetings
		if (/^(dear|hello)\s+(customer|user|member|sir|madam)/i.test(body)) {
			indicators.push({
				type: "generic_greeting",
				severity: "low",
				description: "Email uses generic greeting instead of personal name",
				scoreImpact: 3,
				evidence: "Generic greeting detected",
			});
		}

		return indicators;
	}

	/**
	 * Analyze links for phishing indicators
	 *
	 * @param {string[]} links
	 * @param {string} senderEmail
	 * @returns {PhishingIndicator[]}
	 */
	static #analyzeLinks(links, senderEmail) {
		const indicators = [];
		const senderDomain = this.#extractDomain(senderEmail);

		for (const link of links) {
			const linkLower = link.toLowerCase();

			// Check for IP address links
			if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(link)) {
				indicators.push({
					type: "ip_address_link",
					severity: "high",
					description: "Email contains link to IP address (suspicious)",
					scoreImpact: 15,
					evidence: link,
				});
			}

			// Check for suspicious TLDs in links
			for (const tld of PhishingDetector.SUSPICIOUS_TLDS) {
				if (linkLower.includes(tld)) {
					indicators.push({
						type: "suspicious_link_tld",
						severity: "medium",
						description: `Link uses suspicious TLD: ${tld}`,
						scoreImpact: 10,
						evidence: link,
					});
					break;
				}
			}

			// Check for URL shorteners
			const shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"];
			if (shorteners.some(s => linkLower.includes(s))) {
				indicators.push({
					type: "url_shortener",
					severity: "medium",
					description: "Email uses URL shortener (hides true destination)",
					scoreImpact: 8,
					evidence: link,
				});
			}

			// Check for homograph attacks (lookalike characters)
			if (this.#containsHomoglyphs(link)) {
				indicators.push({
					type: "homograph_attack",
					severity: "critical",
					description: "Link contains lookalike characters (homograph attack)",
					scoreImpact: 25,
					evidence: link,
				});
			}

			// Check for domain mismatch with sender
			const linkDomain = this.#extractDomainFromURL(link);
			if (senderDomain && linkDomain && !this.#domainsMatch(senderDomain, linkDomain)) {
				indicators.push({
					type: "domain_mismatch",
					severity: "medium",
					description: `Link domain (${linkDomain}) differs from sender domain (${senderDomain})`,
					scoreImpact: 10,
					evidence: link,
				});
			}

			// Check for data URIs
			if (linkLower.startsWith("data:")) {
				indicators.push({
					type: "data_uri",
					severity: "high",
					description: "Email contains data URI (can hide malicious content)",
					scoreImpact: 18,
					evidence: link.slice(0, 50) + "...",
				});
			}
		}

		return indicators;
	}

	/**
	 * Analyze email headers for phishing indicators
	 *
	 * @param {Map<string, string[]>} headers
	 * @returns {PhishingIndicator[]}
	 */
	static #analyzeHeaders(headers) {
		const indicators = [];

		// Check for missing authentication
		if (!headers.has("authentication-results")) {
			indicators.push({
				type: "no_authentication",
				severity: "medium",
				description: "Email lacks authentication results (SPF/DKIM/DMARC)",
				scoreImpact: 10,
				evidence: "Missing Authentication-Results header",
			});
		}

		// Check for spoofed headers
		const xmailer = headers.get("x-mailer");
		if (xmailer && xmailer.some(m => m.toLowerCase().includes("php"))) {
			indicators.push({
				type: "suspicious_mailer",
				severity: "low",
				description: "Email sent via PHP script (common in spam/phishing)",
				scoreImpact: 5,
				evidence: xmailer.join(", "),
			});
		}

		return indicators;
	}

	/**
	 * Generate recommendations based on indicators
	 *
	 * @param {PhishingIndicator[]} indicators
	 * @param {number} riskScore
	 * @returns {string[]}
	 */
	static #generateRecommendations(indicators, riskScore) {
		const recommendations = [];

		if (riskScore >= 60) {
			recommendations.push("⚠️ HIGH RISK: This email shows strong signs of phishing. Do not click any links or provide information.");
			recommendations.push("Delete this email immediately.");
			recommendations.push("Report this email as phishing to your email provider.");
		} else if (riskScore >= 40) {
			recommendations.push("⚠️ MODERATE RISK: This email has suspicious characteristics.");
			recommendations.push("Verify sender authenticity before clicking links.");
			recommendations.push("Do not provide sensitive information via email.");
		} else if (riskScore >= 20) {
			recommendations.push("⚠️ LOW RISK: Some minor concerns detected.");
			recommendations.push("Exercise caution with links and attachments.");
		} else {
			recommendations.push("✓ This email appears relatively safe.");
			recommendations.push("Always verify unexpected requests independently.");
		}

		// Specific recommendations based on indicators
		if (indicators.some(i => i.type === "sensitive_info_request")) {
			recommendations.push("NEVER provide passwords, SSNs, or credit card info via email.");
		}

		if (indicators.some(i => i.type === "brand_impersonation")) {
			recommendations.push("Contact the company directly using official contact information, not links in this email.");
		}

		if (indicators.some(i => i.type === "url_shortener" || i.type === "ip_address_link")) {
			recommendations.push("Avoid clicking shortened URLs or IP address links.");
		}

		return recommendations;
	}

	/**
	 * Get risk level from score
	 *
	 * @param {number} score
	 * @returns {string}
	 */
	static #getRiskLevel(score) {
		if (score >= 75) return "critical";
		if (score >= 60) return "high";
		if (score >= 40) return "medium";
		if (score >= 20) return "low";
		return "safe";
	}

	/**
	 * Extract domain from email address
	 *
	 * @param {string} email
	 * @returns {string|null}
	 */
	static #extractDomain(email) {
		const match = email.match(/@([^>]+)/);
		return match ? match[1].trim().toLowerCase() : null;
	}

	/**
	 * Extract display name from email
	 *
	 * @param {string} email
	 * @returns {string|null}
	 */
	static #extractDisplayName(email) {
		const match = email.match(/^([^<]+)</);
		return match ? match[1].trim() : null;
	}

	/**
	 * Extract domain from URL
	 *
	 * @param {string} url
	 * @returns {string|null}
	 */
	static #extractDomainFromURL(url) {
		try {
			const urlObj = new URL(url);
			return urlObj.hostname.toLowerCase();
		} catch {
			return null;
		}
	}

	/**
	 * Check if domains match (accounting for subdomains)
	 *
	 * @param {string} domain1
	 * @param {string} domain2
	 * @returns {boolean}
	 */
	static #domainsMatch(domain1, domain2) {
		const parts1 = domain1.split(".").reverse();
		const parts2 = domain2.split(".").reverse();

		// Check if TLD and second-level domain match
		return parts1[0] === parts2[0] && parts1[1] === parts2[1];
	}

	/**
	 * Check if domain is legitimate for a brand
	 *
	 * @param {string} brand
	 * @param {string} domain
	 * @returns {boolean}
	 */
	static #isLegitBrandDomain(brand, domain) {
		// Simplified check - in production would have comprehensive list
		const legitDomains = {
			paypal: ["paypal.com"],
			amazon: ["amazon.com", "amazon.co.uk"],
			microsoft: ["microsoft.com", "outlook.com", "live.com"],
			google: ["google.com", "gmail.com"],
		};

		const validDomains = legitDomains[brand] || [];
		return validDomains.some(valid => domain.endsWith(valid));
	}

	/**
	 * Check for homoglyph attacks
	 *
	 * @param {string} text
	 * @returns {boolean}
	 */
	static #containsHomoglyphs(text) {
		// Check for common homoglyphs (lookalike characters)
		// Cyrillic 'а' vs Latin 'a', etc.
		const homoglyphs = /[а-яёА-ЯЁ]/; // Cyrillic characters
		return homoglyphs.test(text);
	}
}
