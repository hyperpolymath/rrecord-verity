/**
 * Bayesian Spam Filter with Learning
 *
 * Implements a Naive Bayes classifier for spam detection with
 * adaptive learning based on user feedback.
 *
 * Copyright (c) 2025 DKIM Verifier Contributors
 *
 * This software is licensed under the terms of the MIT License.
 */

// @ts-check

import Logging from "./logging.mjs.js";

const log = Logging.getLogger("BayesianFilter");

/**
 * @typedef {object} BayesianResult
 * @property {number} spamProbability - 0-1, probability email is spam
 * @property {boolean} isSpam - true if spam probability > threshold
 * @property {number} hamProbability - 0-1, probability email is ham (legitimate)
 * @property {string[]} spamIndicators - Top spam-indicating tokens
 * @property {string[]} hamIndicators - Top ham-indicating tokens
 * @property {number} confidence - 0-1, confidence in classification
 */

/**
 * @typedef {object} TokenStats
 * @property {number} spamCount - Times seen in spam
 * @property {number} hamCount - Times seen in ham
 * @property {number} probability - Spam probability for this token
 */

/**
 * Bayesian Spam Filter
 */
export default class BayesianFilter {
	/** @type {Map<string, TokenStats>} */
	#tokenDatabase = new Map();

	/** @type {number} */
	#totalSpamMessages = 0;

	/** @type {number} */
	#totalHamMessages = 0;

	/** Spam probability threshold */
	static SPAM_THRESHOLD = 0.9;

	/** Minimum token length */
	static MIN_TOKEN_LENGTH = 3;

	/** Maximum token length */
	static MAX_TOKEN_LENGTH = 50;

	/** Number of most interesting tokens to use for classification */
	static INTERESTING_TOKEN_COUNT = 15;

	/**
	 * Initialize the Bayesian filter
	 *
	 * @param {object} [savedState] - Previously saved filter state
	 */
	constructor(savedState) {
		if (savedState) {
			this.#loadState(savedState);
		}
	}

	/**
	 * Classify an email as spam or ham
	 *
	 * @param {string} subject
	 * @param {string} body
	 * @param {string} [from]
	 * @returns {BayesianResult}
	 */
	classify(subject, body, from = "") {
		log.debug("Classifying email with Bayesian filter");

		// Extract tokens from email
		const tokens = this.#tokenize(subject + " " + body + " " + from);

		if (tokens.size === 0) {
			log.warn("No tokens extracted from email");
			return {
				spamProbability: 0.5,
				hamProbability: 0.5,
				isSpam: false,
				spamIndicators: [],
				hamIndicators: [],
				confidence: 0,
			};
		}

		// Calculate probabilities for each token
		const tokenProbabilities = new Map();
		for (const token of tokens) {
			const prob = this.#getTokenProbability(token);
			tokenProbabilities.set(token, prob);
		}

		// Select most interesting tokens (furthest from 0.5)
		const interestingTokens = this.#getMostInterestingTokens(tokenProbabilities);

		// Calculate combined spam probability using Naive Bayes
		const spamProbability = this.#calculateCombinedProbability(interestingTokens);
		const hamProbability = 1 - spamProbability;

		// Determine spam indicators vs ham indicators
		const spamIndicators = [];
		const hamIndicators = [];
		for (const [token, prob] of interestingTokens) {
			if (prob > 0.5) {
				spamIndicators.push(token);
			} else {
				hamIndicators.push(token);
			}
		}

		// Calculate confidence (how far from 0.5)
		const confidence = Math.abs(spamProbability - 0.5) * 2;

		const isSpam = spamProbability >= BayesianFilter.SPAM_THRESHOLD;

		log.debug(`Bayesian classification: spam=${spamProbability.toFixed(3)}, isSpam=${isSpam}`);

		return {
			spamProbability,
			hamProbability,
			isSpam,
			spamIndicators: spamIndicators.slice(0, 10),
			hamIndicators: hamIndicators.slice(0, 10),
			confidence,
		};
	}

	/**
	 * Train the filter on a spam message
	 *
	 * @param {string} subject
	 * @param {string} body
	 * @param {string} [from]
	 */
	trainSpam(subject, body, from = "") {
		log.debug("Training on spam message");

		const tokens = this.#tokenize(subject + " " + body + " " + from);

		for (const token of tokens) {
			const stats = this.#tokenDatabase.get(token) || { spamCount: 0, hamCount: 0, probability: 0.5 };
			stats.spamCount++;
			this.#tokenDatabase.set(token, stats);
		}

		this.#totalSpamMessages++;
		this.#recalculateProbabilities();
	}

	/**
	 * Train the filter on a legitimate (ham) message
	 *
	 * @param {string} subject
	 * @param {string} body
	 * @param {string} [from]
	 */
	trainHam(subject, body, from = "") {
		log.debug("Training on ham message");

		const tokens = this.#tokenize(subject + " " + body + " " + from);

		for (const token of tokens) {
			const stats = this.#tokenDatabase.get(token) || { spamCount: 0, hamCount: 0, probability: 0.5 };
			stats.hamCount++;
			this.#tokenDatabase.set(token, stats);
		}

		this.#totalHamMessages++;
		this.#recalculateProbabilities();
	}

	/**
	 * Untrain a message (remove from training data)
	 *
	 * @param {string} subject
	 * @param {string} body
	 * @param {boolean} wasSpam
	 * @param {string} [from]
	 */
	untrain(subject, body, wasSpam, from = "") {
		log.debug(`Untraining ${wasSpam ? "spam" : "ham"} message`);

		const tokens = this.#tokenize(subject + " " + body + " " + from);

		for (const token of tokens) {
			const stats = this.#tokenDatabase.get(token);
			if (stats) {
				if (wasSpam && stats.spamCount > 0) {
					stats.spamCount--;
				} else if (!wasSpam && stats.hamCount > 0) {
					stats.hamCount--;
				}

				// Remove token if no longer seen
				if (stats.spamCount === 0 && stats.hamCount === 0) {
					this.#tokenDatabase.delete(token);
				} else {
					this.#tokenDatabase.set(token, stats);
				}
			}
		}

		if (wasSpam && this.#totalSpamMessages > 0) {
			this.#totalSpamMessages--;
		} else if (!wasSpam && this.#totalHamMessages > 0) {
			this.#totalHamMessages--;
		}

		this.#recalculateProbabilities();
	}

	/**
	 * Get filter statistics
	 *
	 * @returns {{totalSpam: number, totalHam: number, uniqueTokens: number, trainingMessages: number}}
	 */
	getStats() {
		return {
			totalSpam: this.#totalSpamMessages,
			totalHam: this.#totalHamMessages,
			uniqueTokens: this.#tokenDatabase.size,
			trainingMessages: this.#totalSpamMessages + this.#totalHamMessages,
		};
	}

	/**
	 * Export filter state for saving
	 *
	 * @returns {object}
	 */
	exportState() {
		return {
			tokens: Array.from(this.#tokenDatabase.entries()),
			totalSpam: this.#totalSpamMessages,
			totalHam: this.#totalHamMessages,
		};
	}

	/**
	 * Reset the filter to untrained state
	 */
	reset() {
		log.info("Resetting Bayesian filter");
		this.#tokenDatabase.clear();
		this.#totalSpamMessages = 0;
		this.#totalHamMessages = 0;
	}

	/**
	 * Tokenize text into individual tokens
	 *
	 * @param {string} text
	 * @returns {Set<string>}
	 */
	#tokenize(text) {
		const tokens = new Set();
		const textLower = text.toLowerCase();

		// Extract words
		const words = textLower.match(/\b[a-z0-9]{3,50}\b/g) || [];
		for (const word of words) {
			if (word.length >= BayesianFilter.MIN_TOKEN_LENGTH &&
				word.length <= BayesianFilter.MAX_TOKEN_LENGTH) {
				tokens.add(word);
			}
		}

		// Extract special patterns
		// URLs
		const urls = text.match(/https?:\/\/[^\s]+/gi) || [];
		for (const url of urls) {
			tokens.add("URL:" + url.toLowerCase().slice(0, 30));
		}

		// Email addresses
		const emails = text.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || [];
		for (const email of emails) {
			const domain = email.split("@")[1];
			if (domain) {
				tokens.add("DOMAIN:" + domain.toLowerCase());
			}
		}

		// Special characters (spam indicators)
		if (/\$\$\$+/.test(text)) tokens.add("MONEY_SIGNS");
		if (/!!!+/.test(text)) tokens.add("EXCLAMATION_MARKS");
		if (/\b[A-Z]{5,}\b/.test(text)) tokens.add("ALL_CAPS_WORDS");

		return tokens;
	}

	/**
	 * Get probability that a token indicates spam
	 *
	 * @param {string} token
	 * @returns {number} 0-1
	 */
	#getTokenProbability(token) {
		const stats = this.#tokenDatabase.get(token);

		if (!stats) {
			// Unknown token - assume neutral
			return 0.4; // Slightly biased toward ham for unknown tokens
		}

		// Use already calculated probability
		return stats.probability;
	}

	/**
	 * Recalculate probabilities for all tokens
	 */
	#recalculateProbabilities() {
		for (const [token, stats] of this.#tokenDatabase) {
			stats.probability = this.#calculateTokenProbability(stats);
			this.#tokenDatabase.set(token, stats);
		}
	}

	/**
	 * Calculate probability for a token using Naive Bayes
	 *
	 * @param {TokenStats} stats
	 * @returns {number}
	 */
	#calculateTokenProbability(stats) {
		if (this.#totalSpamMessages === 0 && this.#totalHamMessages === 0) {
			return 0.5;
		}

		// Probability token appears in spam
		const probInSpam = this.#totalSpamMessages > 0 ?
			stats.spamCount / this.#totalSpamMessages : 0;

		// Probability token appears in ham
		const probInHam = this.#totalHamMessages > 0 ?
			stats.hamCount / this.#totalHamMessages : 0;

		// Use Naive Bayes formula with smoothing
		const smoothing = 0.5; // Laplace smoothing
		const prob = (probInSpam + smoothing) / (probInSpam + probInHam + 2 * smoothing);

		return prob;
	}

	/**
	 * Get most interesting tokens (furthest from neutral 0.5)
	 *
	 * @param {Map<string, number>} tokenProbabilities
	 * @returns {Map<string, number>}
	 */
	#getMostInterestingTokens(tokenProbabilities) {
		const sorted = Array.from(tokenProbabilities.entries())
			.sort((a, b) => {
				// Sort by distance from 0.5
				const distA = Math.abs(a[1] - 0.5);
				const distB = Math.abs(b[1] - 0.5);
				return distB - distA;
			})
			.slice(0, BayesianFilter.INTERESTING_TOKEN_COUNT);

		return new Map(sorted);
	}

	/**
	 * Calculate combined probability using Naive Bayes
	 *
	 * @param {Map<string, number>} tokenProbabilities
	 * @returns {number} Combined spam probability
	 */
	#calculateCombinedProbability(tokenProbabilities) {
		if (tokenProbabilities.size === 0) {
			return 0.5;
		}

		// Use Robinson's method to combine probabilities
		// Avoids underflow issues with many tokens

		let productSpam = 1;
		let productHam = 1;

		for (const prob of tokenProbabilities.values()) {
			productSpam *= prob;
			productHam *= (1 - prob);
		}

		// Combined probability
		const combined = productSpam / (productSpam + productHam);

		return combined;
	}

	/**
	 * Load state from saved data
	 *
	 * @param {object} state
	 */
	#loadState(state) {
		if (state.tokens) {
			this.#tokenDatabase = new Map(state.tokens);
		}
		this.#totalSpamMessages = state.totalSpam || 0;
		this.#totalHamMessages = state.totalHam || 0;
	}
}
