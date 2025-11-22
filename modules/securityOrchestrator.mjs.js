/**
 * Security Orchestrator
 *
 * Central orchestration layer that coordinates all security analysis modules
 * to provide comprehensive email security assessment.
 *
 * Integrates: SPF, DKIM, DMARC, Header Analysis, Phishing Detection,
 * DNSBL Checking, VirusTotal, Bayesian Filtering, Rules Engine, and more.
 *
 * Copyright (c) 2025 DKIM Verifier Contributors
 *
 * This software is licensed under the terms of the MIT License.
 */

// @ts-check

import SPFVerifier from "./spf/verifier.mjs.js";
import HeaderAnalyzer from "./headerAnalyzer.mjs.js";
import DNSBL from "./dnsbl.mjs.js";
import PhishingDetector from "./phishingDetector.mjs.js";
import VirusTotalIntegration from "./virusTotalIntegration.mjs.js";
import BayesianFilter from "./bayesianFilter.mjs.js";
import EmailSanitizer from "./emailSanitizer.mjs.js";
import LogicRulesEngine from "./logicRulesEngine.mjs.js";
import Logging from "./logging.mjs.js";
import MsgParser from "./msgParser.mjs.js";

const log = Logging.getLogger("SecurityOrchestrator");

/**
 * @typedef {object} ComprehensiveSecurityReport
 * @property {string} emailId
 * @property {Date} analyzedAt
 * @property {number} overallSecurityScore - 0-100, higher is safer
 * @property {string} securityLevel - critical, high, medium, low, safe
 * @property {string} recommendation
 * @property {AuthenticationResults} authentication
 * @property {HeaderAnalysisResult} headerAnalysis
 * @property {PhishingAnalysisResult} phishingAnalysis
 * @property {DNSBLResult} [dnsblResults]
 * @property {Map<string, VirusTotalResult>} [virusTotalResults]
 * @property {BayesianResult} [bayesianResults]
 * @property {RuleResult[]} [ruleMatches]
 * @property {ThreatSummary} threats
 * @property {string[]} actionableSteps
 */

/**
 * @typedef {object} AuthenticationResults
 * @property {SPFResult} [spf]
 * @property {object} [dkim]
 * @property {object} [dmarc]
 * @property {boolean} allPassed
 * @property {string} summary
 */

/**
 * @typedef {object} ThreatSummary
 * @property {number} criticalThreats
 * @property {number} highThreats
 * @property {number} mediumThreats
 * @property {number} lowThreats
 * @property {string[]} topThreats
 */

/**
 * @typedef {object} OrchestratorOptions
 * @property {boolean} enableSPF
 * @property {boolean} enableDNSBL
 * @property {boolean} enablePhishingDetection
 * @property {boolean} enableVirusTotal
 * @property {boolean} enableBayesian
 * @property {boolean} enableRulesEngine
 * @property {boolean} enableHeaderAnalysis
 * @property {boolean} enableSanitization
 * @property {number} maxAnalysisTimeMs
 */

/**
 * Security Orchestrator - Coordinates all security modules
 */
export default class SecurityOrchestrator {
	/** @type {SPFVerifier} */
	#spfVerifier;

	/** @type {BayesianFilter} */
	#bayesianFilter;

	/** @type {LogicRulesEngine} */
	#rulesEngine;

	/** @type {OrchestratorOptions} */
	#options;

	/**
	 * Initialize the security orchestrator
	 *
	 * @param {Partial<OrchestratorOptions>} [options]
	 */
	constructor(options = {}) {
		this.#options = {
			enableSPF: options.enableSPF ?? true,
			enableDNSBL: options.enableDNSBL ?? true,
			enablePhishingDetection: options.enablePhishingDetection ?? true,
			enableVirusTotal: options.enableVirusTotal ?? false, // Requires API key
			enableBayesian: options.enableBayesian ?? true,
			enableRulesEngine: options.enableRulesEngine ?? true,
			enableHeaderAnalysis: options.enableHeaderAnalysis ?? true,
			enableSanitization: options.enableSanitization ?? false, // On-demand
			maxAnalysisTimeMs: options.maxAnalysisTimeMs ?? 30000, // 30 seconds
		};

		this.#spfVerifier = new SPFVerifier();
		this.#bayesianFilter = new BayesianFilter();
		this.#rulesEngine = new LogicRulesEngine();

		log.info("Security Orchestrator initialized", this.#options);
	}

	/**
	 * Perform comprehensive security analysis on an email
	 *
	 * @param {object} email
	 * @param {string} email.id
	 * @param {string} email.from
	 * @param {string} email.to
	 * @param {string} email.subject
	 * @param {string} email.body
	 * @param {string} email.rawMessage
	 * @param {string} [email.senderIP]
	 * @returns {Promise<ComprehensiveSecurityReport>}
	 */
	async analyze(email) {
		log.info(`Starting comprehensive security analysis for email: ${email.id}`);

		const startTime = Date.now();
		const timeoutPromise = new Promise((_, reject) =>
			setTimeout(() => reject(new Error("Analysis timeout")), this.#options.maxAnalysisTimeMs)
		);

		try {
			// Parse email
			const parsed = MsgParser.parseMsg(email.rawMessage);
			const headers = parsed.headers;

			// Extract links from body
			const links = this.#extractLinks(email.body);

			// Run analyses in parallel where possible
			const analysisPromises = [];

			// 1. Header Analysis (always enabled if option set)
			let headerAnalysisPromise = Promise.resolve(null);
			if (this.#options.enableHeaderAnalysis) {
				headerAnalysisPromise = Promise.resolve(HeaderAnalyzer.analyzeHeaders(headers));
			}

			// 2. SPF Verification (if sender IP available)
			let spfPromise = Promise.resolve(null);
			if (this.#options.enableSPF && email.senderIP) {
				const domain = this.#extractDomain(email.from);
				if (domain) {
					spfPromise = this.#spfVerifier.verify(email.senderIP, domain, email.from)
						.catch(err => {
							log.warn("SPF verification failed", err);
							return null;
						});
				}
			}

			// 3. Phishing Detection
			let phishingPromise = Promise.resolve(null);
			if (this.#options.enablePhishingDetection) {
				phishingPromise = Promise.resolve(PhishingDetector.analyzeEmail({
					subject: email.subject,
					body: email.body,
					from: email.from,
					links,
					headers,
				}));
			}

			// 4. DNSBL Check (if sender IP available)
			let dnsblPromise = Promise.resolve(null);
			if (this.#options.enableDNSBL && email.senderIP) {
				dnsblPromise = DNSBL.checkIP(email.senderIP)
					.catch(err => {
						log.warn("DNSBL check failed", err);
						return null;
					});
			}

			// 5. Bayesian Classification
			let bayesianPromise = Promise.resolve(null);
			if (this.#options.enableBayesian) {
				bayesianPromise = Promise.resolve(
					this.#bayesianFilter.classify(email.subject, email.body, email.from)
				);
			}

			// Wait for all analyses to complete
			const [headerAnalysis, spfResult, phishingAnalysis, dnsblResults, bayesianResults] =
				await Promise.race([
					Promise.all([
						headerAnalysisPromise,
						spfPromise,
						phishingPromise,
						dnsblPromise,
						bayesianPromise,
					]),
					timeoutPromise,
				]);

			// 6. VirusTotal (sequential, rate-limited)
			let virusTotalResults = null;
			if (this.#options.enableVirusTotal && VirusTotalIntegration.hasAPIKey()) {
				virusTotalResults = await this.#analyzeWithVirusTotal(links, email.from);
			}

			// 7. Rules Engine
			let ruleMatches = null;
			if (this.#options.enableRulesEngine) {
				const emailContext = {
					from: email.from,
					to: email.to,
					subject: email.subject,
					body: email.body,
					headers,
					spamScore: bayesianResults?.spamProbability,
					phishingScore: phishingAnalysis?.riskScore,
					tags: [],
					metadata: {},
				};
				ruleMatches = this.#rulesEngine.evaluate(emailContext);
			}

			// Calculate overall security score
			const securityScore = this.#calculateSecurityScore({
				headerAnalysis,
				spfResult,
				phishingAnalysis,
				dnsblResults,
				bayesianResults,
			});

			// Determine security level
			const securityLevel = this.#getSecurityLevel(securityScore);

			// Compile threat summary
			const threats = this.#compileThreatSummary({
				headerAnalysis,
				phishingAnalysis,
				dnsblResults,
				virusTotalResults,
			});

			// Generate recommendations
			const recommendation = this.#generateRecommendation(securityLevel, threats);
			const actionableSteps = this.#generateActionableSteps({
				securityLevel,
				threats,
				phishingAnalysis,
				dnsblResults,
			});

			// Compile authentication results
			const authentication = {
				spf: spfResult,
				dkim: null, // Would come from existing DKIM verifier
				dmarc: null, // Would come from existing DMARC module
				allPassed: spfResult?.result === "pass",
				summary: this.#getAuthenticationSummary(spfResult),
			};

			const analysisTime = Date.now() - startTime;
			log.info(`Security analysis completed in ${analysisTime}ms. Score: ${securityScore}, Level: ${securityLevel}`);

			return {
				emailId: email.id,
				analyzedAt: new Date(),
				overallSecurityScore: securityScore,
				securityLevel,
				recommendation,
				authentication,
				headerAnalysis: headerAnalysis || this.#emptyHeaderAnalysis(),
				phishingAnalysis: phishingAnalysis || this.#emptyPhishingAnalysis(),
				dnsblResults,
				virusTotalResults,
				bayesianResults,
				ruleMatches,
				threats,
				actionableSteps,
			};

		} catch (error) {
			log.error("Security analysis failed", error);

			// Return minimal safe result
			return {
				emailId: email.id,
				analyzedAt: new Date(),
				overallSecurityScore: 50,
				securityLevel: "unknown",
				recommendation: "Analysis failed - exercise caution",
				authentication: { allPassed: false, summary: "Unknown" },
				headerAnalysis: this.#emptyHeaderAnalysis(),
				phishingAnalysis: this.#emptyPhishingAnalysis(),
				threats: { criticalThreats: 0, highThreats: 0, mediumThreats: 0, lowThreats: 0, topThreats: [] },
				actionableSteps: ["Analysis incomplete - manually review this email"],
			};
		}
	}

	/**
	 * Sanitize email content
	 *
	 * @param {string} content
	 * @param {object} options
	 * @returns {SanitizationResult}
	 */
	sanitize(content, options = {}) {
		return EmailSanitizer.sanitizeHTML(content, options);
	}

	/**
	 * Get rules engine for configuration
	 *
	 * @returns {LogicRulesEngine}
	 */
	getRulesEngine() {
		return this.#rulesEngine;
	}

	/**
	 * Get Bayesian filter for training
	 *
	 * @returns {BayesianFilter}
	 */
	getBayesianFilter() {
		return this.#bayesianFilter;
	}

	/**
	 * Extract links from email body
	 *
	 * @param {string} body
	 * @returns {string[]}
	 */
	#extractLinks(body) {
		const urlRegex = /https?:\/\/[^\s<>"']+/gi;
		return [...new Set(body.match(urlRegex) || [])];
	}

	/**
	 * Extract domain from email address
	 *
	 * @param {string} email
	 * @returns {string|null}
	 */
	#extractDomain(email) {
		const match = email.match(/@([^>]+)/);
		return match ? match[1].trim() : null;
	}

	/**
	 * Analyze links with VirusTotal
	 *
	 * @param {string[]} links
	 * @param {string} senderEmail
	 * @returns {Promise<Map<string, VirusTotalResult>>}
	 */
	async #analyzeWithVirusTotal(links, senderEmail) {
		const results = new Map();

		// Limit to first 5 links to avoid rate limits
		const linksToCheck = links.slice(0, 5);

		for (const link of linksToCheck) {
			try {
				const result = await VirusTotalIntegration.scanURL(link);
				results.set(link, result);
			} catch (error) {
				log.warn(`VirusTotal scan failed for ${link}`, error);
			}
		}

		// Also check sender domain
		const domain = this.#extractDomain(senderEmail);
		if (domain) {
			try {
				const result = await VirusTotalIntegration.scanDomain(domain);
				results.set(`domain:${domain}`, result);
			} catch (error) {
				log.warn(`VirusTotal domain check failed for ${domain}`, error);
			}
		}

		return results;
	}

	/**
	 * Calculate overall security score
	 *
	 * @param {object} analyses
	 * @returns {number} 0-100
	 */
	#calculateSecurityScore(analyses) {
		let score = 100;

		// Header analysis impact (max -30)
		if (analyses.headerAnalysis) {
			score = Math.min(score, analyses.headerAnalysis.summary.securityScore);
		}

		// SPF impact (max -20)
		if (analyses.spfResult) {
			if (analyses.spfResult.result === "fail") score -= 20;
			else if (analyses.spfResult.result === "softfail") score -= 10;
			else if (analyses.spfResult.result === "neutral") score -= 5;
		}

		// Phishing analysis impact (max -40)
		if (analyses.phishingAnalysis) {
			score -= analyses.phishingAnalysis.riskScore * 0.4;
		}

		// DNSBL impact (max -30)
		if (analyses.dnsblResults && analyses.dnsblResults.listed) {
			const severity = analyses.dnsblResults.severity;
			if (severity === "critical") score -= 30;
			else if (severity === "high") score -= 20;
			else if (severity === "medium") score -= 10;
			else score -= 5;
		}

		// Bayesian impact (max -20)
		if (analyses.bayesianResults && analyses.bayesianResults.isSpam) {
			score -= analyses.bayesianResults.spamProbability * 20;
		}

		return Math.max(0, Math.min(100, Math.round(score)));
	}

	/**
	 * Get security level from score
	 *
	 * @param {number} score
	 * @returns {string}
	 */
	#getSecurityLevel(score) {
		if (score >= 80) return "safe";
		if (score >= 60) return "low";
		if (score >= 40) return "medium";
		if (score >= 20) return "high";
		return "critical";
	}

	/**
	 * Compile threat summary
	 *
	 * @param {object} analyses
	 * @returns {ThreatSummary}
	 */
	#compileThreatSummary(analyses) {
		let criticalThreats = 0;
		let highThreats = 0;
		let mediumThreats = 0;
		let lowThreats = 0;
		const topThreats = [];

		// Count threats from header analysis
		if (analyses.headerAnalysis) {
			for (const issue of analyses.headerAnalysis.securityIssues) {
				switch (issue.severity) {
					case "critical": criticalThreats++; topThreats.push(issue.description); break;
					case "high": highThreats++; topThreats.push(issue.description); break;
					case "medium": mediumThreats++; break;
					case "low": lowThreats++; break;
				}
			}
		}

		// Count threats from phishing analysis
		if (analyses.phishingAnalysis) {
			for (const indicator of analyses.phishingAnalysis.indicators) {
				switch (indicator.severity) {
					case "critical": criticalThreats++; topThreats.push(indicator.description); break;
					case "high": highThreats++; topThreats.push(indicator.description); break;
					case "medium": mediumThreats++; break;
					case "low": lowThreats++; break;
				}
			}
		}

		// DNSBL threats
		if (analyses.dnsblResults && analyses.dnsblResults.listed) {
			const severity = analyses.dnsblResults.severity;
			if (severity === "critical") { criticalThreats++; topThreats.push("Sender IP on critical blacklist"); }
			else if (severity === "high") { highThreats++; topThreats.push("Sender IP on spam blacklist"); }
			else { mediumThreats++; }
		}

		// VirusTotal threats
		if (analyses.virusTotalResults) {
			for (const [url, result] of analyses.virusTotalResults) {
				if (result.malicious) {
					criticalThreats++;
					topThreats.push(`Malicious link detected: ${url}`);
				}
			}
		}

		return {
			criticalThreats,
			highThreats,
			mediumThreats,
			lowThreats,
			topThreats: topThreats.slice(0, 5),
		};
	}

	/**
	 * Generate overall recommendation
	 *
	 * @param {string} securityLevel
	 * @param {ThreatSummary} threats
	 * @returns {string}
	 */
	#generateRecommendation(securityLevel, threats) {
		switch (securityLevel) {
			case "critical":
				return "⛔ CRITICAL: DO NOT interact with this email. Delete immediately.";
			case "high":
				return "⚠️ HIGH RISK: This email is likely malicious. Do not click links or provide information.";
			case "medium":
				return "⚠️ MODERATE RISK: Exercise extreme caution. Verify sender independently.";
			case "low":
				return "⚠️ LOW RISK: Minor concerns detected. Proceed with caution.";
			case "safe":
				return "✓ SAFE: Email appears legitimate. Standard precautions apply.";
			default:
				return "⚠️ UNKNOWN: Unable to fully assess. Exercise caution.";
		}
	}

	/**
	 * Generate actionable steps
	 *
	 * @param {object} context
	 * @returns {string[]}
	 */
	#generateActionableSteps(context) {
		const steps = [];

		if (context.securityLevel === "critical" || context.securityLevel === "high") {
			steps.push("1. Delete this email immediately");
			steps.push("2. Report as phishing to your email provider");
			steps.push("3. Do not click any links or open attachments");
			steps.push("4. If you already clicked, run antivirus scan and change passwords");
		} else if (context.securityLevel === "medium") {
			steps.push("1. Verify sender authenticity through independent means");
			steps.push("2. Do not provide sensitive information");
			steps.push("3. Hover over links to check true destination before clicking");
			steps.push("4. Contact the supposed sender using known contact information");
		} else {
			steps.push("1. Verify unexpected requests independently");
			steps.push("2. Be cautious with attachments and links");
			steps.push("3. Report suspicious emails to IT/security team");
		}

		return steps;
	}

	/**
	 * Get authentication summary
	 *
	 * @param {SPFResult|null} spfResult
	 * @returns {string}
	 */
	#getAuthenticationSummary(spfResult) {
		if (!spfResult) return "No authentication data available";

		const parts = [];
		if (spfResult) parts.push(`SPF: ${spfResult.result}`);

		return parts.join(", ") || "Unknown";
	}

	/** @returns {HeaderAnalysisResult} */
	#emptyHeaderAnalysis() {
		return {
			receivedPath: [],
			securityIssues: [],
			privacyIssues: [],
			transport: { allHopsEncrypted: false, unencryptedHops: [], weakestTLS: "unknown", hasDowngrade: false, suspiciousHops: [] },
			lintingIssues: [],
			summary: { totalHops: 0, encryptedHops: 0, securityScore: 50, overallAssessment: "Unknown" },
		};
	}

	/** @returns {PhishingAnalysisResult} */
	#emptyPhishingAnalysis() {
		return {
			riskScore: 0,
			riskLevel: "safe",
			indicators: [],
			recommendations: [],
			isLikelyPhishing: false,
		};
	}
}
