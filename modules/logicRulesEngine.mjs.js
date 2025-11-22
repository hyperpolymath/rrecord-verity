/**
 * Logic Rules Engine (miniKanren-inspired)
 *
 * Declarative logic programming engine for email security rules.
 * Allows users to define custom security rules using logic programming.
 *
 * Inspired by miniKanren and Prolog for declarative rule definition.
 *
 * Copyright (c) 2025 DKIM Verifier Contributors
 *
 * This software is licensed under the terms of the MIT License.
 */

// @ts-check

import Logging from "./logging.mjs.js";

const log = Logging.getLogger("LogicRulesEngine");

/**
 * @typedef {object} Rule
 * @property {string} name
 * @property {Condition[]} conditions
 * @property {Action[]} actions
 * @property {number} priority
 * @property {boolean} enabled
 */

/**
 * @typedef {object} Condition
 * @property {string} type - field, pattern, score, custom
 * @property {string} field - Email field to check
 * @property {string} operator - equals, contains, matches, gt, lt, gte, lte
 * @property {any} value
 * @property {boolean} [negate]
 */

/**
 * @typedef {object} Action
 * @property {string} type - folder, tag, flag, delete, quarantine, notify, score
 * @property {any} value
 */

/**
 * @typedef {object} RuleResult
 * @property {boolean} matched
 * @property {Rule} rule
 * @property {Action[]} actions
 * @property {string} reason
 */

/**
 * @typedef {object} EmailContext
 * @property {string} from
 * @property {string} to
 * @property {string} subject
 * @property {string} body
 * @property {Map<string, string[]>} headers
 * @property {number} [spamScore]
 * @property {number} [phishingScore]
 * @property {string[]} [tags]
 * @property {any} [metadata]
 */

/**
 * Logic Rules Engine - Declarative rule-based email processing
 */
export default class LogicRulesEngine {
	/** @type {Rule[]} */
	#rules = [];

	/** @type {Map<string, Function>} */
	#customPredicates = new Map();

	/**
	 * Initialize rules engine
	 *
	 * @param {Rule[]} [initialRules]
	 */
	constructor(initialRules = []) {
		this.#rules = initialRules;
		this.#registerDefaultPredicates();
	}

	/**
	 * Add a rule to the engine
	 *
	 * @param {Rule} rule
	 */
	addRule(rule) {
		log.debug(`Adding rule: ${rule.name}`);
		this.#rules.push(rule);
		this.#sortRulesByPriority();
	}

	/**
	 * Remove a rule by name
	 *
	 * @param {string} name
	 * @returns {boolean} true if removed
	 */
	removeRule(name) {
		const index = this.#rules.findIndex(r => r.name === name);
		if (index !== -1) {
			this.#rules.splice(index, 1);
			log.debug(`Removed rule: ${name}`);
			return true;
		}
		return false;
	}

	/**
	 * Evaluate all rules against an email
	 *
	 * @param {EmailContext} email
	 * @returns {RuleResult[]}
	 */
	evaluate(email) {
		log.debug("Evaluating rules against email");

		const results = [];

		for (const rule of this.#rules) {
			if (!rule.enabled) {
				continue;
			}

			const result = this.#evaluateRule(rule, email);
			if (result.matched) {
				results.push(result);
			}
		}

		log.debug(`${results.length} rules matched`);
		return results;
	}

	/**
	 * Register a custom predicate function
	 *
	 * @param {string} name
	 * @param {Function} predicate - (email, value) => boolean
	 */
	registerPredicate(name, predicate) {
		this.#customPredicates.set(name, predicate);
		log.debug(`Registered custom predicate: ${name}`);
	}

	/**
	 * Create a rule using declarative syntax
	 *
	 * @param {string} name
	 * @param {number} priority
	 * @returns {RuleBuilder}
	 */
	static createRule(name, priority = 100) {
		return new RuleBuilder(name, priority);
	}

	/**
	 * Export rules to JSON
	 *
	 * @returns {string}
	 */
	exportRules() {
		return JSON.stringify(this.#rules, null, 2);
	}

	/**
	 * Import rules from JSON
	 *
	 * @param {string} json
	 */
	importRules(json) {
		const rules = JSON.parse(json);
		for (const rule of rules) {
			this.addRule(rule);
		}
	}

	/**
	 * Get all rules
	 *
	 * @returns {Rule[]}
	 */
	getRules() {
		return [...this.#rules];
	}

	/**
	 * Evaluate a single rule
	 *
	 * @param {Rule} rule
	 * @param {EmailContext} email
	 * @returns {RuleResult}
	 */
	#evaluateRule(rule, email) {
		// All conditions must be satisfied (AND logic)
		for (const condition of rule.conditions) {
			const satisfied = this.#evaluateCondition(condition, email);

			if (!satisfied) {
				return {
					matched: false,
					rule,
					actions: [],
					reason: `Condition not satisfied: ${condition.field} ${condition.operator} ${condition.value}`,
				};
			}
		}

		// All conditions satisfied
		return {
			matched: true,
			rule,
			actions: rule.actions,
			reason: `All ${rule.conditions.length} condition(s) satisfied`,
		};
	}

	/**
	 * Evaluate a single condition
	 *
	 * @param {Condition} condition
	 * @param {EmailContext} email
	 * @returns {boolean}
	 */
	#evaluateCondition(condition, email) {
		let result = false;

		switch (condition.type) {
			case "field":
				result = this.#evaluateFieldCondition(condition, email);
				break;

			case "pattern":
				result = this.#evaluatePatternCondition(condition, email);
				break;

			case "score":
				result = this.#evaluateScoreCondition(condition, email);
				break;

			case "custom":
				result = this.#evaluateCustomCondition(condition, email);
				break;

			default:
				log.warn(`Unknown condition type: ${condition.type}`);
				result = false;
		}

		// Apply negation if specified
		return condition.negate ? !result : result;
	}

	/**
	 * Evaluate field condition
	 *
	 * @param {Condition} condition
	 * @param {EmailContext} email
	 * @returns {boolean}
	 */
	#evaluateFieldCondition(condition, email) {
		const fieldValue = this.#getFieldValue(condition.field, email);

		if (fieldValue === null || fieldValue === undefined) {
			return false;
		}

		switch (condition.operator) {
			case "equals":
				return fieldValue === condition.value;

			case "contains":
				return String(fieldValue).toLowerCase().includes(String(condition.value).toLowerCase());

			case "startsWith":
				return String(fieldValue).toLowerCase().startsWith(String(condition.value).toLowerCase());

			case "endsWith":
				return String(fieldValue).toLowerCase().endsWith(String(condition.value).toLowerCase());

			case "gt":
				return Number(fieldValue) > Number(condition.value);

			case "lt":
				return Number(fieldValue) < Number(condition.value);

			case "gte":
				return Number(fieldValue) >= Number(condition.value);

			case "lte":
				return Number(fieldValue) <= Number(condition.value);

			default:
				log.warn(`Unknown operator: ${condition.operator}`);
				return false;
		}
	}

	/**
	 * Evaluate pattern condition (regex)
	 *
	 * @param {Condition} condition
	 * @param {EmailContext} email
	 * @returns {boolean}
	 */
	#evaluatePatternCondition(condition, email) {
		const fieldValue = this.#getFieldValue(condition.field, email);

		if (fieldValue === null || fieldValue === undefined) {
			return false;
		}

		try {
			const regex = new RegExp(condition.value, "i");
			return regex.test(String(fieldValue));
		} catch (error) {
			log.error(`Invalid regex pattern: ${condition.value}`, error);
			return false;
		}
	}

	/**
	 * Evaluate score condition
	 *
	 * @param {Condition} condition
	 * @param {EmailContext} email
	 * @returns {boolean}
	 */
	#evaluateScoreCondition(condition, email) {
		const score = email[condition.field];

		if (score === null || score === undefined) {
			return false;
		}

		switch (condition.operator) {
			case "gt":
				return score > condition.value;
			case "lt":
				return score < condition.value;
			case "gte":
				return score >= condition.value;
			case "lte":
				return score <= condition.value;
			case "equals":
				return score === condition.value;
			default:
				return false;
		}
	}

	/**
	 * Evaluate custom predicate condition
	 *
	 * @param {Condition} condition
	 * @param {EmailContext} email
	 * @returns {boolean}
	 */
	#evaluateCustomCondition(condition, email) {
		const predicate = this.#customPredicates.get(condition.field);

		if (!predicate) {
			log.warn(`Unknown custom predicate: ${condition.field}`);
			return false;
		}

		try {
			return predicate(email, condition.value);
		} catch (error) {
			log.error(`Error evaluating custom predicate: ${condition.field}`, error);
			return false;
		}
	}

	/**
	 * Get field value from email context
	 *
	 * @param {string} field
	 * @param {EmailContext} email
	 * @returns {any}
	 */
	#getFieldValue(field, email) {
		// Support dot notation for nested fields
		const parts = field.split(".");
		let value = email;

		for (const part of parts) {
			if (value === null || value === undefined) {
				return null;
			}

			// Handle Map objects (headers)
			if (value instanceof Map) {
				value = value.get(part)?.[0];
			} else {
				value = value[part];
			}
		}

		return value;
	}

	/**
	 * Sort rules by priority (higher priority first)
	 */
	#sortRulesByPriority() {
		this.#rules.sort((a, b) => b.priority - a.priority);
	}

	/**
	 * Register default predicates
	 */
	#registerDefaultPredicates() {
		// Check if email has attachments
		this.registerPredicate("hasAttachments", (email) => {
			const contentType = email.headers.get("content-type")?.[0] || "";
			return contentType.toLowerCase().includes("multipart");
		});

		// Check if email is a reply
		this.registerPredicate("isReply", (email) => {
			return email.subject.toLowerCase().startsWith("re:");
		});

		// Check if email is forwarded
		this.registerPredicate("isForwarded", (email) => {
			return email.subject.toLowerCase().startsWith("fwd:");
		});

		// Check if sender is in list
		this.registerPredicate("senderIn", (email, list) => {
			const from = email.from.toLowerCase();
			return list.some(addr => from.includes(addr.toLowerCase()));
		});

		// Check if email has specific tag
		this.registerPredicate("hasTag", (email, tag) => {
			return email.tags && email.tags.includes(tag);
		});
	}
}

/**
 * Rule Builder - Fluent API for creating rules
 */
class RuleBuilder {
	/** @type {string} */
	#name;

	/** @type {number} */
	#priority;

	/** @type {Condition[]} */
	#conditions = [];

	/** @type {Action[]} */
	#actions = [];

	/**
	 * @param {string} name
	 * @param {number} priority
	 */
	constructor(name, priority) {
		this.#name = name;
		this.#priority = priority;
	}

	/**
	 * Add a field condition
	 *
	 * @param {string} field
	 * @param {string} operator
	 * @param {any} value
	 * @returns {RuleBuilder}
	 */
	when(field, operator, value) {
		this.#conditions.push({
			type: "field",
			field,
			operator,
			value,
		});
		return this;
	}

	/**
	 * Add a pattern (regex) condition
	 *
	 * @param {string} field
	 * @param {string} pattern
	 * @returns {RuleBuilder}
	 */
	matches(field, pattern) {
		this.#conditions.push({
			type: "pattern",
			field,
			operator: "matches",
			value: pattern,
		});
		return this;
	}

	/**
	 * Add a score condition
	 *
	 * @param {string} scoreField
	 * @param {string} operator
	 * @param {number} threshold
	 * @returns {RuleBuilder}
	 */
	score(scoreField, operator, threshold) {
		this.#conditions.push({
			type: "score",
			field: scoreField,
			operator,
			value: threshold,
		});
		return this;
	}

	/**
	 * Add a custom predicate condition
	 *
	 * @param {string} predicateName
	 * @param {any} value
	 * @returns {RuleBuilder}
	 */
	custom(predicateName, value) {
		this.#conditions.push({
			type: "custom",
			field: predicateName,
			operator: "custom",
			value,
		});
		return this;
	}

	/**
	 * Add folder action
	 *
	 * @param {string} folder
	 * @returns {RuleBuilder}
	 */
	moveToFolder(folder) {
		this.#actions.push({
			type: "folder",
			value: folder,
		});
		return this;
	}

	/**
	 * Add tag action
	 *
	 * @param {string} tag
	 * @returns {RuleBuilder}
	 */
	addTag(tag) {
		this.#actions.push({
			type: "tag",
			value: tag,
		});
		return this;
	}

	/**
	 * Add flag action
	 *
	 * @param {string} flag
	 * @returns {RuleBuilder}
	 */
	setFlag(flag) {
		this.#actions.push({
			type: "flag",
			value: flag,
		});
		return this;
	}

	/**
	 * Add delete action
	 *
	 * @returns {RuleBuilder}
	 */
	delete() {
		this.#actions.push({
			type: "delete",
			value: true,
		});
		return this;
	}

	/**
	 * Add quarantine action
	 *
	 * @returns {RuleBuilder}
	 */
	quarantine() {
		this.#actions.push({
			type: "quarantine",
			value: true,
		});
		return this;
	}

	/**
	 * Build the rule
	 *
	 * @returns {Rule}
	 */
	build() {
		return {
			name: this.#name,
			conditions: this.#conditions,
			actions: this.#actions,
			priority: this.#priority,
			enabled: true,
		};
	}
}

// Example usage in comments:
/*
const engine = new LogicRulesEngine();

// Example 1: Move high spam score emails to spam folder
const spamRule = LogicRulesEngine.createRule("HighSpamScore", 100)
	.score("spamScore", "gte", 0.9)
	.moveToFolder("Spam")
	.addTag("spam")
	.build();

engine.addRule(spamRule);

// Example 2: Quarantine phishing emails
const phishingRule = LogicRulesEngine.createRule("PhishingDetection", 200)
	.score("phishingScore", "gte", 60)
	.quarantine()
	.addTag("phishing")
	.build();

engine.addRule(phishingRule);

// Example 3: Tag emails from specific sender
const vipRule = LogicRulesEngine.createRule("VIPSender", 150)
	.when("from", "contains", "@important.com")
	.addTag("vip")
	.setFlag("important")
	.build();

engine.addRule(vipRule);

// Evaluate rules
const email = {
	from: "sender@example.com",
	subject: "Test",
	body: "Email body",
	spamScore: 0.95,
	headers: new Map(),
};

const results = engine.evaluate(email);
for (const result of results) {
	console.log(`Matched rule: ${result.rule.name}`);
	console.log(`Actions:`, result.actions);
}
*/
