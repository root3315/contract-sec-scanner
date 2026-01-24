#!/usr/bin/env node
/**
 * Contract Security Scanner - Main Entry Point
 *
 * A comprehensive security vulnerability scanner for Solidity smart contracts.
 * Detects common security issues including reentrancy, access control problems,
 * integer overflows, and other vulnerabilities.
 *
 * Usage:
 *   npx ts-node src/index.ts <path-to-solidity-file-or-directory>
 *   node dist/index.js <path>
 */
import { SecurityScanner, createScanner } from './scanner';
import type { ScannerOptions } from './scanner';
import type { Severity } from './rules';
import { SECURITY_RULES, getAllCategories, getRulesByCategory } from './rules';
import type { ScanResult, Finding } from './utils';
import { readSolidityFile, findSolidityFiles, formatFinding, formatSummary, resultsToJson } from './utils';
interface CliOptions {
    help: boolean;
    version: boolean;
    output: string;
    format: 'text' | 'json';
    exclude: string[];
    minSeverity: Severity;
    categories: string[];
    verbose: boolean;
    deepScan: boolean;
    noSnippets: boolean;
}
export { SecurityScanner, createScanner, SECURITY_RULES, getAllCategories, getRulesByCategory, readSolidityFile, findSolidityFiles, formatFinding, formatSummary, resultsToJson };
export type { ScannerOptions, ScanResult, Finding, Severity, CliOptions };
//# sourceMappingURL=index.d.ts.map