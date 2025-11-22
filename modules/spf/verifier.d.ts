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
