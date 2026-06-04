// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
/**
 * Type definitions for SPF Verifier
 */

declare module SPFVerifier {
	export interface SPFResult {
		result: "none" | "neutral" | "pass" | "fail" | "softfail" | "temperror" | "permerror";
		explanation?: string;
		mechanism?: string;
		dnsLookups: number;
		warnings?: string[];
	}
}

export default SPFVerifier;
