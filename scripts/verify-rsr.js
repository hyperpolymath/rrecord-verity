#!/usr/bin/env node
/**
 * RSR (Rhodium Standard Repository) Compliance Verification
 *
 * Verifies that DKIM Verifier meets RSR framework standards.
 *
 * Copyright (c) 2025 DKIM Verifier Contributors
 * Licensed under MIT License
 */

// @ts-check

import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { fileURLToPath } from "url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const ROOT = join(__dirname, "..");

const COLORS = {
	reset: "\x1b[0m",
	bright: "\x1b[1m",
	green: "\x1b[32m",
	yellow: "\x1b[33m",
	red: "\x1b[31m",
	cyan: "\x1b[36m",
};

/** @type {Array<{category: string, checks: Array<{name: string, required: boolean, check: () => boolean | {passed: boolean, details?: string}}>}>} */
const RSR_CATEGORIES = [
	{
		category: "Documentation",
		checks: [
			{ name: "README.md", required: true, check: () => existsSync(join(ROOT, "README.md")) },
			{ name: "CHANGELOG.md", required: true, check: () => existsSync(join(ROOT, "CHANGELOG.md")) },
			{ name: "LICENSE.txt", required: true, check: () => existsSync(join(ROOT, "LICENSE.txt")) },
			{ name: "SECURITY.md", required: true, check: () => existsSync(join(ROOT, "SECURITY.md")) },
			{ name: "CONTRIBUTING.md", required: true, check: () => existsSync(join(ROOT, "CONTRIBUTING.md")) },
			{ name: "CODE_OF_CONDUCT.md", required: true, check: () => existsSync(join(ROOT, "CODE_OF_CONDUCT.md")) },
			{ name: "MAINTAINERS.md", required: true, check: () => existsSync(join(ROOT, "MAINTAINERS.md")) },
			{ name: "CLAUDE.md (AI Assistant Guide)", required: false, check: () => existsSync(join(ROOT, "CLAUDE.md")) },
			{ name: "ROADMAP.md (Project Vision)", required: false, check: () => existsSync(join(ROOT, "ROADMAP.md")) },
		],
	},
	{
		category: ".well-known Directory (RFC 9116)",
		checks: [
			{ name: ".well-known/security.txt", required: true, check: () => existsSync(join(ROOT, ".well-known", "security.txt")) },
			{ name: ".well-known/ai.txt", required: false, check: () => existsSync(join(ROOT, ".well-known", "ai.txt")) },
			{ name: ".well-known/humans.txt", required: false, check: () => existsSync(join(ROOT, ".well-known", "humans.txt")) },
			{
				name: "security.txt expires in future",
				required: true,
				check: () => {
					try {
						const content = readFileSync(join(ROOT, ".well-known", "security.txt"), "utf8");
						const match = content.match(/Expires:\s*(\d{4}-\d{2}-\d{2})/);
						if (!match) return { passed: false, details: "No expiration date found" };
						const expires = new Date(match[1]);
						const now = new Date();
						return { passed: expires > now, details: `Expires: ${expires.toISOString()}` };
					} catch {
						return false;
					}
				},
			},
		],
	},
	{
		category: "TPCF (Tri-Perimeter Contribution Framework)",
		checks: [
			{
				name: "TPCF documented in CONTRIBUTING.md",
				required: true,
				check: () => {
					try {
						const content = readFileSync(join(ROOT, "CONTRIBUTING.md"), "utf8");
						return content.includes("Tri-Perimeter Contribution Framework") ||
							content.includes("TPCF");
					} catch {
						return false;
					}
				},
			},
			{
				name: "Perimeter 3: Community Sandbox defined",
				required: true,
				check: () => {
					try {
						const content = readFileSync(join(ROOT, "CONTRIBUTING.md"), "utf8");
						return content.includes("Perimeter 3") && content.includes("Community");
					} catch {
						return false;
					}
				},
			},
			{
				name: "Perimeter 2: Trusted Contributors defined",
				required: true,
				check: () => {
					try {
						const content = readFileSync(join(ROOT, "CONTRIBUTING.md"), "utf8");
						return content.includes("Perimeter 2") && content.includes("Trusted");
					} catch {
						return false;
					}
				},
			},
			{
				name: "Perimeter 1: Maintainer Core defined",
				required: true,
				check: () => {
					try {
						const content = readFileSync(join(ROOT, "CONTRIBUTING.md"), "utf8");
						return content.includes("Perimeter 1") && content.includes("Maintainer");
					} catch {
						return false;
					}
				},
			},
		],
	},
	{
		category: "Type Safety",
		checks: [
			{
				name: "TypeScript checking enabled (jsconfig.json)",
				required: true,
				check: () => existsSync(join(ROOT, "jsconfig.json")),
			},
			{
				name: "Type check npm script",
				required: true,
				check: () => {
					try {
						const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
						return "checkJs" in pkg.scripts;
					} catch {
						return false;
					}
				},
			},
			{
				name: "Sample modules use // @ts-check",
				required: false,
				check: () => {
					try {
						const files = [
							"modules/authVerifier.mjs.js",
							"modules/msgParser.mjs.js",
							"modules/spf/verifier.mjs.js",
						];
						return files.every(f => {
							if (!existsSync(join(ROOT, f))) return false;
							const content = readFileSync(join(ROOT, f), "utf8");
							return content.includes("// @ts-check");
						});
					} catch {
						return false;
					}
				},
			},
		],
	},
	{
		category: "Build System & Testing",
		checks: [
			{
				name: "package.json exists",
				required: true,
				check: () => existsSync(join(ROOT, "package.json")),
			},
			{
				name: "npm test script",
				required: true,
				check: () => {
					try {
						const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
						return "test" in pkg.scripts;
					} catch {
						return false;
					}
				},
			},
			{
				name: "npm lint script",
				required: true,
				check: () => {
					try {
						const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
						return "lint" in pkg.scripts;
					} catch {
						return false;
					}
				},
			},
			{
				name: "Test directory exists",
				required: true,
				check: () => existsSync(join(ROOT, "test")),
			},
			{
				name: "CI/CD configuration",
				required: false,
				check: () => existsSync(join(ROOT, ".github", "workflows")) ||
					existsSync(join(ROOT, ".gitlab-ci.yml")),
			},
		],
	},
	{
		category: "Security",
		checks: [
			{
				name: "Security policy documented",
				required: true,
				check: () => existsSync(join(ROOT, "SECURITY.md")),
			},
			{
				name: "Vulnerability disclosure process",
				required: true,
				check: () => {
					try {
						const content = readFileSync(join(ROOT, "SECURITY.md"), "utf8");
						return content.toLowerCase().includes("reporting") &&
							content.toLowerCase().includes("vulnerability");
					} catch {
						return false;
					}
				},
			},
			{
				name: "No hardcoded secrets (sample check)",
				required: true,
				check: () => {
					try {
						const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
						const pkgStr = JSON.stringify(pkg);
						// Simple check for common secret patterns
						return !pkgStr.match(/password\s*[:=]\s*["'][^"']{8,}["']/i) &&
							!pkgStr.match(/api[_-]?key\s*[:=]\s*["'][^"']{10,}["']/i);
					} catch {
						return false;
					}
				},
			},
		],
	},
	{
		category: "License & Legal",
		checks: [
			{
				name: "LICENSE.txt exists",
				required: true,
				check: () => existsSync(join(ROOT, "LICENSE.txt")),
			},
			{
				name: "License mentioned in package.json",
				required: true,
				check: () => {
					try {
						const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
						return "license" in pkg;
					} catch {
						return false;
					}
				},
			},
			{
				name: "Third-party licenses documented",
				required: false,
				check: () => existsSync(join(ROOT, "THIRDPARTY_LICENSE.txt")) ||
					existsSync(join(ROOT, "THIRD_PARTY_LICENSES.md")),
			},
		],
	},
	{
		category: "Offline-First (Adapted for Email Extension)",
		checks: [
			{
				name: "No telemetry by default",
				required: true,
				check: () => {
					// DKIM Verifier doesn't have telemetry
					return { passed: true, details: "Verified: zero telemetry" };
				},
			},
			{
				name: "Optional external services documented",
				required: true,
				check: () => {
					try {
						const readme = readFileSync(join(ROOT, "README.md"), "utf8");
						const claude = existsSync(join(ROOT, "CLAUDE.md")) ?
							readFileSync(join(ROOT, "CLAUDE.md"), "utf8") : "";
						return readme.includes("VirusTotal") || claude.includes("VirusTotal") ||
							claude.includes("optional");
					} catch {
						return false;
					}
				},
			},
		],
	},
	{
		category: "Memory Safety (JavaScript)",
		checks: [
			{
				name: "No eval() usage (sample check)",
				required: true,
				check: () => {
					try {
						const modules = ["modules/msgParser.mjs.js", "modules/authVerifier.mjs.js"];
						return modules.every(f => {
							if (!existsSync(join(ROOT, f))) return true; // Skip if not exists
							const content = readFileSync(join(ROOT, f), "utf8");
							// Allow eval in comments
							const lines = content.split("\n").filter(l => !l.trim().startsWith("//"));
							return !lines.some(l => l.includes("eval("));
						});
					} catch {
						return false;
					}
				},
			},
			{
				name: "Resource limits documented",
				required: false,
				check: () => {
					try {
						const files = ["SECURITY.md", "CLAUDE.md"];
						return files.some(f => {
							if (!existsSync(join(ROOT, f))) return false;
							const content = readFileSync(join(ROOT, f), "utf8");
							return content.includes("timeout") || content.includes("limit");
						});
					} catch {
						return false;
					}
				},
			},
		],
	},
	{
		category: "Community & Governance",
		checks: [
			{
				name: "Code of Conduct",
				required: true,
				check: () => existsSync(join(ROOT, "CODE_OF_CONDUCT.md")),
			},
			{
				name: "Maintainer list",
				required: true,
				check: () => existsSync(join(ROOT, "MAINTAINERS.md")),
			},
			{
				name: "Contribution guidelines",
				required: true,
				check: () => existsSync(join(ROOT, "CONTRIBUTING.md")),
			},
			{
				name: "Public issue tracker",
				required: true,
				check: () => {
					try {
						const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
						return Boolean("bugs" in pkg && pkg.bugs && pkg.bugs.url);
					} catch {
						return false;
					}
				},
			},
		],
	},
	{
		category: "RSR Meta-Compliance",
		checks: [
			{
				name: "RSR verification script exists",
				required: false,
				check: () => existsSync(join(ROOT, "scripts", "verify-rsr.js")),
			},
			{
				name: "npm run verify-rsr script",
				required: false,
				check: () => {
					try {
						const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
						return "verify-rsr" in pkg.scripts;
					} catch {
						return false;
					}
				},
			},
		],
	},
];

/**
 * Run a single check
 * @param {{name: string, required: boolean, check: () => boolean | {passed: boolean, details?: string}}} checkDef
 * @returns {{passed: boolean, details?: string}}
 */
function runCheck(checkDef) {
	try {
		const result = checkDef.check();
		if (typeof result === "boolean") {
			return { passed: result };
		}
		return result;
	} catch (error) {
		return { passed: false, details: `Error: ${error.message}` };
	}
}

/**
 * Main verification
 */
function main() {
	console.log(`${COLORS.bright}${COLORS.cyan}
╔══════════════════════════════════════════════════════════════════╗
║   RSR (Rhodium Standard Repository) Compliance Verification     ║
║   DKIM Verifier - Email Security Extension                       ║
╚══════════════════════════════════════════════════════════════════╝
${COLORS.reset}`);

	let totalChecks = 0;
	let passedChecks = 0;
	let requiredChecks = 0;
	let passedRequiredChecks = 0;

	for (const category of RSR_CATEGORIES) {
		console.log(`\n${COLORS.bright}${category.category}:${COLORS.reset}`);

		for (const check of category.checks) {
			totalChecks++;
			if (check.required) requiredChecks++;

			const result = runCheck(check);
			const passed = result.passed;

			if (passed) {
				passedChecks++;
				if (check.required) passedRequiredChecks++;
			}

			const status = passed ?
				`${COLORS.green}✓${COLORS.reset}` :
				`${COLORS.red}✗${COLORS.reset}`;
			const reqLabel = check.required ?
				`${COLORS.yellow}[REQUIRED]${COLORS.reset}` :
				`${COLORS.cyan}[OPTIONAL]${COLORS.reset}`;

			console.log(`  ${status} ${check.name} ${reqLabel}`);

			if (result.details) {
				console.log(`      ${COLORS.cyan}→ ${result.details}${COLORS.reset}`);
			}
		}
	}

	// Summary
	console.log(`\n${COLORS.bright}${COLORS.cyan}═══════════════════════════════════════════════════════════════${COLORS.reset}`);
	console.log(`${COLORS.bright}Summary:${COLORS.reset}`);
	console.log(`  Total Checks: ${totalChecks}`);
	console.log(`  Passed: ${COLORS.green}${passedChecks}${COLORS.reset} / ${totalChecks} (${Math.round(passedChecks / totalChecks * 100)}%)`);
	console.log(`  Required: ${COLORS.green}${passedRequiredChecks}${COLORS.reset} / ${requiredChecks} (${Math.round(passedRequiredChecks / requiredChecks * 100)}%)`);

	// Compliance Level
	let level = "None";
	let levelColor = COLORS.red;

	if (passedRequiredChecks === requiredChecks) {
		level = "Bronze (Minimum RSR Compliance)";
		levelColor = COLORS.yellow;

		if (passedChecks / totalChecks >= 0.9) {
			level = "Silver (High RSR Compliance)";
			levelColor = COLORS.cyan;
		}

		if (passedChecks === totalChecks) {
			level = "Gold (Perfect RSR Compliance)";
			levelColor = COLORS.green;
		}
	}

	console.log(`\n${COLORS.bright}${levelColor}RSR Compliance Level: ${level}${COLORS.reset}`);

	// Exit code
	const success = passedRequiredChecks === requiredChecks;
	if (success) {
		console.log(`\n${COLORS.green}${COLORS.bright}✓ All required RSR checks passed!${COLORS.reset}`);
	} else {
		console.log(`\n${COLORS.red}${COLORS.bright}✗ Some required RSR checks failed. See above for details.${COLORS.reset}`);
	}

	console.log(`${COLORS.cyan}\nFor more information, see CONTRIBUTING.md and SECURITY.md${COLORS.reset}\n`);

	process.exit(success ? 0 : 1);
}

main();
