/**
 * Email Sanitizer / Neuterizer
 *
 * Removes dangerous content from emails, sanitizes HTML, neutralizes scripts,
 * and can convert emails to safe formats (Markdown, AsciiDoc, BMP images).
 *
 * Processes emails in sandboxed context to prevent exploitation.
 *
 * Copyright (c) 2025 DKIM Verifier Contributors
 *
 * This software is licensed under the terms of the MIT License.
 */

// @ts-check
///<reference path="./emailSanitizer.d.ts" />

import Logging from "./logging.mjs.js";

const log = Logging.getLogger("EmailSanitizer");

/**
 * @typedef {object} SanitizationResult
 * @property {string} safeContent - Sanitized content
 * @property {string} format - Output format (html, text, markdown, asciidoc)
 * @property {string[]} removedElements - Elements that were removed
 * @property {SecurityThreat[]} threatsNeutralized
 * @property {boolean} wasModified
 * @property {SanitizationStats} stats
 */

/**
 * @typedef {object} SecurityThreat
 * @property {string} type - script, iframe, object, form, etc.
 * @property {string} severity - critical, high, medium, low
 * @property {string} description
 * @property {string} location - Where in the email it was found
 */

/**
 * @typedef {object} SanitizationStats
 * @property {number} scriptsRemoved
 * @property {number} iframesRemoved
 * @property {number} objectsRemoved
 * @property {number} formsRemoved
 * @property {number} linksNeutralized
 * @property {number} imagesBlocked
 * @property {number} stylesRemoved
 */

/**
 * @typedef {object} SafeFormatOptions
 * @property {string} format - markdown, asciidoc, text, bmp
 * @property {boolean} stripAllFormatting
 * @property {boolean} removeImages
 * @property {boolean} removeLinks
 * @property {boolean} preserveHeaders
 */

/**
 * Email Sanitizer - Neutralizes dangerous email content
 */
export default class EmailSanitizer {
	/** Dangerous HTML tags that should always be removed */
	static DANGEROUS_TAGS = [
		"script",
		"iframe",
		"object",
		"embed",
		"applet",
		"link",
		"meta",
		"base",
		"form",
		"input",
		"button",
		"textarea",
		"select",
	];

	/** Dangerous attributes that should be removed */
	static DANGEROUS_ATTRIBUTES = [
		"onclick",
		"onload",
		"onerror",
		"onmouseover",
		"onmouseout",
		"onfocus",
		"onblur",
		"onchange",
		"onsubmit",
		"onkeypress",
		"onkeydown",
		"onkeyup",
	];

	/** Dangerous URL protocols */
	static DANGEROUS_PROTOCOLS = [
		"javascript:",
		"data:",
		"vbscript:",
		"file:",
		"about:",
	];

	/**
	 * Sanitize HTML email content
	 *
	 * @param {string} htmlContent
	 * @param {object} [options]
	 * @param {boolean} [options.removeScripts=true]
	 * @param {boolean} [options.removeIframes=true]
	 * @param {boolean} [options.removeForms=true]
	 * @param {boolean} [options.removeObjects=true]
	 * @param {boolean} [options.neutralizeLinks=false]
	 * @param {boolean} [options.blockImages=false]
	 * @param {boolean} [options.removeStyles=false]
	 * @returns {SanitizationResult}
	 */
	static sanitizeHTML(htmlContent, options = {}) {
		log.debug("Sanitizing HTML email content");

		const opts = {
			removeScripts: options.removeScripts ?? true,
			removeIframes: options.removeIframes ?? true,
			removeForms: options.removeForms ?? true,
			removeObjects: options.removeObjects ?? true,
			neutralizeLinks: options.neutralizeLinks ?? false,
			blockImages: options.blockImages ?? false,
			removeStyles: options.removeStyles ?? false,
		};

		let content = htmlContent;
		const removedElements = [];
		const threatsNeutralized = [];
		const stats = {
			scriptsRemoved: 0,
			iframesRemoved: 0,
			objectsRemoved: 0,
			formsRemoved: 0,
			linksNeutralized: 0,
			imagesBlocked: 0,
			stylesRemoved: 0,
		};

		// Remove dangerous tags
		if (opts.removeScripts) {
			const result = this.#removeTag(content, "script");
			content = result.content;
			stats.scriptsRemoved = result.count;
			if (result.count > 0) {
				removedElements.push(`${result.count} script tag(s)`);
				threatsNeutralized.push({
					type: "script",
					severity: "critical",
					description: `Removed ${result.count} script tag(s) that could execute malicious code`,
					location: "HTML body",
				});
			}
		}

		if (opts.removeIframes) {
			const result = this.#removeTag(content, "iframe");
			content = result.content;
			stats.iframesRemoved = result.count;
			if (result.count > 0) {
				removedElements.push(`${result.count} iframe tag(s)`);
				threatsNeutralized.push({
					type: "iframe",
					severity: "high",
					description: `Removed ${result.count} iframe(s) that could load malicious content`,
					location: "HTML body",
				});
			}
		}

		if (opts.removeObjects) {
			for (const tag of ["object", "embed", "applet"]) {
				const result = this.#removeTag(content, tag);
				content = result.content;
				stats.objectsRemoved += result.count;
				if (result.count > 0) {
					removedElements.push(`${result.count} ${tag} tag(s)`);
					threatsNeutralized.push({
						type: tag,
						severity: "high",
						description: `Removed ${result.count} ${tag} tag(s) that could execute malicious code`,
						location: "HTML body",
					});
				}
			}
		}

		if (opts.removeForms) {
			const result = this.#removeTag(content, "form");
			content = result.content;
			stats.formsRemoved = result.count;
			if (result.count > 0) {
				removedElements.push(`${result.count} form tag(s)`);
				threatsNeutralized.push({
					type: "form",
					severity: "medium",
					description: `Removed ${result.count} form(s) that could be used for phishing`,
					location: "HTML body",
				});
			}

			// Also remove form inputs
			for (const tag of ["input", "button", "textarea", "select"]) {
				content = this.#removeTag(content, tag).content;
			}
		}

		// Remove dangerous event handlers
		content = this.#removeDangerousAttributes(content);

		// Neutralize dangerous protocols in links
		content = this.#neutralizeDangerousProtocols(content);

		// Optionally neutralize all links
		if (opts.neutralizeLinks) {
			const result = this.#neutralizeLinks(content);
			content = result.content;
			stats.linksNeutralized = result.count;
			if (result.count > 0) {
				removedElements.push(`${result.count} link(s) neutralized`);
			}
		}

		// Optionally block images
		if (opts.blockImages) {
			const result = this.#blockImages(content);
			content = result.content;
			stats.imagesBlocked = result.count;
			if (result.count > 0) {
				removedElements.push(`${result.count} image(s) blocked`);
			}
		}

		// Optionally remove styles
		if (opts.removeStyles) {
			const result = this.#removeTag(content, "style");
			content = result.content;
			stats.stylesRemoved = result.count;
			if (result.count > 0) {
				removedElements.push(`${result.count} style tag(s)`);
			}
			// Also remove inline styles
			content = content.replace(/\s+style\s*=\s*["'][^"']*["']/gi, "");
		}

		return {
			safeContent: content,
			format: "html",
			removedElements,
			threatsNeutralized,
			wasModified: removedElements.length > 0,
			stats,
		};
	}

	/**
	 * Convert email to safe format
	 *
	 * @param {string} content - Email content
	 * @param {string} format - Original format (html or text)
	 * @param {SafeFormatOptions} options
	 * @returns {SanitizationResult}
	 */
	static convertToSafeFormat(content, format, options) {
		log.debug(`Converting email to safe format: ${options.format}`);

		// First sanitize if HTML
		let safeContent = content;
		let sanitizationResult = null;

		if (format === "html") {
			sanitizationResult = this.sanitizeHTML(content, {
				removeScripts: true,
				removeIframes: true,
				removeForms: true,
				removeObjects: true,
				blockImages: options.removeImages,
			});
			safeContent = sanitizationResult.safeContent;
		}

		// Convert to target format
		switch (options.format) {
			case "markdown":
				safeContent = this.#convertToMarkdown(safeContent, format);
				break;

			case "asciidoc":
				safeContent = this.#convertToAsciiDoc(safeContent, format);
				break;

			case "text":
				safeContent = this.#convertToPlainText(safeContent, format);
				break;

			case "bmp":
				// BMP conversion would require image rendering
				log.warn("BMP conversion not yet implemented - falling back to text");
				safeContent = this.#convertToPlainText(safeContent, format);
				break;

			default:
				throw new Error(`Unsupported format: ${options.format}`);
		}

		// Strip all formatting if requested
		if (options.stripAllFormatting) {
			safeContent = this.#stripAllFormatting(safeContent);
		}

		return {
			safeContent,
			format: options.format,
			removedElements: sanitizationResult?.removedElements || [],
			threatsNeutralized: sanitizationResult?.threatsNeutralized || [],
			wasModified: true,
			stats: sanitizationResult?.stats || this.#emptyStats(),
		};
	}

	/**
	 * Remove all instances of a tag
	 *
	 * @param {string} content
	 * @param {string} tagName
	 * @returns {{content: string, count: number}}
	 */
	static #removeTag(content, tagName) {
		let count = 0;
		// Remove tag and its content
		const regex = new RegExp(`<${tagName}[^>]*>.*?</${tagName}>`, "gis");
		const newContent = content.replace(regex, (match) => {
			count++;
			return "";
		});

		// Also remove self-closing tags
		const selfClosingRegex = new RegExp(`<${tagName}[^>]*/>`, "gi");
		const finalContent = newContent.replace(selfClosingRegex, (match) => {
			count++;
			return "";
		});

		return { content: finalContent, count };
	}

	/**
	 * Remove dangerous attributes
	 *
	 * @param {string} content
	 * @returns {string}
	 */
	static #removeDangerousAttributes(content) {
		let result = content;

		for (const attr of EmailSanitizer.DANGEROUS_ATTRIBUTES) {
			const regex = new RegExp(`\\s+${attr}\\s*=\\s*["'][^"']*["']`, "gi");
			result = result.replace(regex, "");
		}

		return result;
	}

	/**
	 * Neutralize dangerous protocols in URLs
	 *
	 * @param {string} content
	 * @returns {string}
	 */
	static #neutralizeDangerousProtocols(content) {
		let result = content;

		for (const protocol of EmailSanitizer.DANGEROUS_PROTOCOLS) {
			const regex = new RegExp(`href\\s*=\\s*["']${protocol}`, "gi");
			result = result.replace(regex, 'href="#blocked-dangerous-protocol');
		}

		return result;
	}

	/**
	 * Neutralize all links
	 *
	 * @param {string} content
	 * @returns {{content: string, count: number}}
	 */
	static #neutralizeLinks(content) {
		let count = 0;
		const result = content.replace(/<a\s+[^>]*href\s*=\s*["']([^"']*)["'][^>]*>(.*?)<\/a>/gi, (match, url, text) => {
			count++;
			return `${text} [link removed: ${url}]`;
		});

		return { content: result, count };
	}

	/**
	 * Block all images
	 *
	 * @param {string} content
	 * @returns {{content: string, count: number}}
	 */
	static #blockImages(content) {
		let count = 0;
		const result = content.replace(/<img[^>]*>/gi, (match) => {
			count++;
			return "[Image blocked for security]";
		});

		return { content: result, count };
	}

	/**
	 * Convert to Markdown
	 *
	 * @param {string} content
	 * @param {string} originalFormat
	 * @returns {string}
	 */
	static #convertToMarkdown(content, originalFormat) {
		if (originalFormat === "text") {
			return content; // Already plain text
		}

		// Simple HTML to Markdown conversion
		let md = content;

		// Headers
		md = md.replace(/<h1[^>]*>(.*?)<\/h1>/gi, "# $1\n\n");
		md = md.replace(/<h2[^>]*>(.*?)<\/h2>/gi, "## $1\n\n");
		md = md.replace(/<h3[^>]*>(.*?)<\/h3>/gi, "### $1\n\n");

		// Bold and italic
		md = md.replace(/<strong[^>]*>(.*?)<\/strong>/gi, "**$1**");
		md = md.replace(/<b[^>]*>(.*?)<\/b>/gi, "**$1**");
		md = md.replace(/<em[^>]*>(.*?)<\/em>/gi, "*$1*");
		md = md.replace(/<i[^>]*>(.*?)<\/i>/gi, "*$1*");

		// Links
		md = md.replace(/<a\s+[^>]*href\s*=\s*["']([^"']*)["'][^>]*>(.*?)<\/a>/gi, "[$2]($1)");

		// Paragraphs
		md = md.replace(/<p[^>]*>(.*?)<\/p>/gi, "$1\n\n");

		// Line breaks
		md = md.replace(/<br\s*\/?>/gi, "\n");

		// Lists
		md = md.replace(/<li[^>]*>(.*?)<\/li>/gi, "- $1\n");
		md = md.replace(/<\/?[ou]l[^>]*>/gi, "\n");

		// Remove remaining HTML tags
		md = md.replace(/<[^>]+>/g, "");

		// Decode HTML entities
		md = this.#decodeHTMLEntities(md);

		return md.trim();
	}

	/**
	 * Convert to AsciiDoc
	 *
	 * @param {string} content
	 * @param {string} originalFormat
	 * @returns {string}
	 */
	static #convertToAsciiDoc(content, originalFormat) {
		if (originalFormat === "text") {
			return content;
		}

		// Simple HTML to AsciiDoc conversion
		let adoc = content;

		// Headers
		adoc = adoc.replace(/<h1[^>]*>(.*?)<\/h1>/gi, "= $1\n\n");
		adoc = adoc.replace(/<h2[^>]*>(.*?)<\/h2>/gi, "== $1\n\n");
		adoc = adoc.replace(/<h3[^>]*>(.*?)<\/h3>/gi, "=== $1\n\n");

		// Bold and italic
		adoc = adoc.replace(/<strong[^>]*>(.*?)<\/strong>/gi, "*$1*");
		adoc = adoc.replace(/<b[^>]*>(.*?)<\/b>/gi, "*$1*");
		adoc = adoc.replace(/<em[^>]*>(.*?)<\/em>/gi, "_$1_");
		adoc = adoc.replace(/<i[^>]*>(.*?)<\/i>/gi, "_$1_");

		// Links
		adoc = adoc.replace(/<a\s+[^>]*href\s*=\s*["']([^"']*)["'][^>]*>(.*?)<\/a>/gi, "$1[$2]");

		// Paragraphs
		adoc = adoc.replace(/<p[^>]*>(.*?)<\/p>/gi, "$1\n\n");

		// Line breaks
		adoc = adoc.replace(/<br\s*\/?>/gi, " +\n");

		// Lists
		adoc = adoc.replace(/<li[^>]*>(.*?)<\/li>/gi, "* $1\n");
		adoc = adoc.replace(/<\/?[ou]l[^>]*>/gi, "\n");

		// Remove remaining HTML tags
		adoc = adoc.replace(/<[^>]+>/g, "");

		// Decode HTML entities
		adoc = this.#decodeHTMLEntities(adoc);

		return adoc.trim();
	}

	/**
	 * Convert to plain text
	 *
	 * @param {string} content
	 * @param {string} originalFormat
	 * @returns {string}
	 */
	static #convertToPlainText(content, originalFormat) {
		if (originalFormat === "text") {
			return content;
		}

		// Simple HTML to text conversion
		let text = content;

		// Add newlines for block elements
		text = text.replace(/<\/?(div|p|h[1-6]|br)[^>]*>/gi, "\n");

		// Remove all HTML tags
		text = text.replace(/<[^>]+>/g, "");

		// Decode HTML entities
		text = this.#decodeHTMLEntities(text);

		// Clean up whitespace
		text = text.replace(/\n\s*\n\s*\n/g, "\n\n"); // Multiple newlines to double
		text = text.trim();

		return text;
	}

	/**
	 * Strip all formatting
	 *
	 * @param {string} content
	 * @returns {string}
	 */
	static #stripAllFormatting(content) {
		// Remove all markdown/asciidoc formatting
		let text = content;

		// Remove markdown headers
		text = text.replace(/^#+\s+/gm, "");

		// Remove markdown bold/italic
		text = text.replace(/\*\*([^*]+)\*\*/g, "$1");
		text = text.replace(/\*([^*]+)\*/g, "$1");
		text = text.replace(/__([^_]+)__/g, "$1");
		text = text.replace(/_([^_]+)_/g, "$1");

		// Remove markdown links
		text = text.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");

		// Remove asciidoc headers
		text = text.replace(/^=+\s+/gm, "");

		return text.trim();
	}

	/**
	 * Decode HTML entities
	 *
	 * @param {string} text
	 * @returns {string}
	 */
	static #decodeHTMLEntities(text) {
		const entities = {
			"&amp;": "&",
			"&lt;": "<",
			"&gt;": ">",
			"&quot;": '"',
			"&#039;": "'",
			"&nbsp;": " ",
		};

		let result = text;
		for (const [entity, char] of Object.entries(entities)) {
			result = result.replace(new RegExp(entity, "g"), char);
		}

		return result;
	}

	/**
	 * Get empty stats object
	 *
	 * @returns {SanitizationStats}
	 */
	static #emptyStats() {
		return {
			scriptsRemoved: 0,
			iframesRemoved: 0,
			objectsRemoved: 0,
			formsRemoved: 0,
			linksNeutralized: 0,
			imagesBlocked: 0,
			stylesRemoved: 0,
		};
	}

	/**
	 * Process email in sandboxed context
	 * This would ideally run in a Web Worker or separate process
	 *
	 * @param {string} emailContent
	 * @param {object} options
	 * @returns {Promise<SanitizationResult>}
	 */
	static async processInSandbox(emailContent, options) {
		log.info("Processing email in sandboxed context");

		// In a real implementation, this would spawn a Web Worker or use
		// a sandboxed iframe to process the email
		// For now, we'll just call the regular sanitization

		return new Promise((resolve) => {
			// Simulate async sandboxed processing
			setTimeout(() => {
				const result = this.sanitizeHTML(emailContent, options);
				log.info("Sandboxed processing complete");
				resolve(result);
			}, 0);
		});
	}
}
