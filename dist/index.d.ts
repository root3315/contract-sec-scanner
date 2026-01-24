#!/usr/bin/env node
/**
 * Contract Security Scanner - Main Entry Point
 *
 * A comprehensive security vulnerability scanner for Solidity smart contracts.
 * Detects common security issues including reentrancy, access control problems,
 * integer overflows, and other vulnerabilities using both regex and AST-based analysis.
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
import { readSolidityFile, findSolidityFiles, formatFinding, formatSummary, resultsToJson, parseSolidityToAST } from './utils';
import { analyzeAST, type ASTAnalysisContext, type SourceUnit, type ASTNode } from './ast';
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
    noAST: boolean;
}
export { SecurityScanner, createScanner, SECURITY_RULES, getAllCategories, getRulesByCategory, readSolidityFile, findSolidityFiles, formatFinding, formatSummary, resultsToJson, parseSolidityToAST, analyzeAST };
export type { ScannerOptions, ScanResult, Finding, Severity, CliOptions, ASTAnalysisContext, SourceUnit, ASTNode };
export { findNodesByType, hasModifier, isStateChangingFunction, hasTxOrigin, hasBlockTimestamp, hasExternalCall, hasStateWrite, hasAssembly, hasSelfDestruct, isOldSolidityVersion, findPublicStateVariables, findUnprotectedFunctions, findLoopsWithExternalCalls, findDivisionBeforeMultiplication, getPragmaSolidityVersion } from './ast';
//# sourceMappingURL=index.d.ts.map