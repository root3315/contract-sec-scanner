/**
 * Utility functions for the contract security scanner.
 * Provides file operations, formatting, and helper methods.
 */
import type { Severity } from './rules';
import type { SourceUnit } from './ast';
export interface FileResult {
    filePath: string;
    content: string;
    error?: string;
}
export interface ScanResult {
    filePath: string;
    findings: Finding[];
    scanTime: number;
}
export interface Finding {
    ruleId: string;
    ruleName: string;
    severity: Severity;
    line: number;
    column: number;
    message: string;
    recommendation: string;
    snippet?: string;
}
/**
 * Read a Solidity file and return its content.
 */
export declare function readSolidityFile(filePath: string): FileResult;
/**
 * Recursively find all Solidity files in a directory.
 */
export declare function findSolidityFiles(dirPath: string, excludeDirs?: string[]): string[];
/**
 * Get line and column number from a character index in source code.
 */
export declare function getPositionFromIndex(source: string, index: number): {
    line: number;
    column: number;
};
/**
 * Extract a code snippet around a specific position.
 */
export declare function getSnippet(source: string, index: number, contextLines?: number): string;
/**
 * Format severity with ANSI colors for terminal output.
 */
export declare function formatSeverity(severity: Severity): string;
/**
 * Format a finding for console output.
 */
export declare function formatFinding(finding: Finding, filePath: string): string;
/**
 * Format scan summary for console output.
 */
export declare function formatSummary(results: ScanResult[]): string;
/**
 * Convert findings to JSON format for export.
 */
export declare function resultsToJson(results: ScanResult[]): string;
/**
 * Check if a line is a comment or empty.
 */
export declare function isNonCodeLine(line: string): boolean;
/**
 * Remove comments from source code for analysis.
 */
export declare function stripComments(source: string): string;
/**
 * Validate that source code appears to be valid Solidity.
 */
export declare function isValidSolidity(source: string): boolean;
/**
 * Extract contract names from source code.
 */
export declare function extractContractNames(source: string): string[];
/**
 * Parse Solidity source code into a simplified AST representation.
 * Uses a heuristic approach since we don't depend on external Solidity parsers.
 */
export declare function parseSolidityToAST(source: string): SourceUnit | null;
/**
 * Get line count of source code.
 */
export declare function getLineCount(source: string): number;
/**
 * Get character count excluding whitespace and comments.
 */
export declare function getCodeSize(source: string): number;
/**
 * Check if source contains specific pattern.
 */
export declare function containsPattern(source: string, pattern: RegExp): boolean;
/**
 * Find all occurrences of a pattern in source.
 */
export declare function findAllOccurrences(source: string, pattern: RegExp): Array<{
    index: number;
    match: string;
    line: number;
}>;
//# sourceMappingURL=utils.d.ts.map