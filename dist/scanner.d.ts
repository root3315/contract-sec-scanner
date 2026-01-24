/**
 * Core scanner implementation for Solidity smart contract security analysis.
 * Applies security rules to detect vulnerabilities in contract source code.
 */
import type { SecurityRule, Severity } from './rules';
import type { Finding, ScanResult } from './utils';
export interface ScannerOptions {
    excludeRules?: string[];
    minSeverity?: Severity;
    includeSnippets?: boolean;
    scanComments?: boolean;
}
export interface ScannerStats {
    rulesApplied: number;
    patternsMatched: number;
    contractsScanned: number;
    functionsAnalyzed: number;
}
export declare class SecurityScanner {
    private options;
    private stats;
    constructor(options?: ScannerOptions);
    /**
     * Scan Solidity source code for security vulnerabilities.
     */
    scan(source: string, filePath?: string): ScanResult;
    /**
     * Scan multiple files and aggregate results.
     */
    scanFiles(files: Array<{
        path: string;
        content: string;
    }>): ScanResult[];
    /**
     * Apply a single security rule to source code.
     */
    private applyRule;
    /**
     * Find all matches of a pattern, handling global flag properly.
     */
    private findAllMatches;
    /**
     * Get active rules based on options.
     */
    private getActiveRules;
    /**
     * Get scanner statistics.
     */
    getStats(): ScannerStats;
    /**
     * Reset scanner statistics.
     */
    reset(): void;
    /**
     * Get available rules for filtering.
     */
    getAvailableRules(): SecurityRule[];
    /**
     * Check for specific vulnerability types.
     */
    scanForVulnerability(source: string, vulnerabilityType: string): Finding[];
    /**
     * Perform deep analysis on a specific function.
     */
    analyzeFunction(source: string, functionName: string): Finding[];
    /**
     * Check for reentrancy patterns specifically.
     */
    checkReentrancy(source: string): Finding[];
    /**
     * Analyze access control patterns.
     */
    checkAccessControl(source: string): Finding[];
}
export declare function createScanner(options?: ScannerOptions): SecurityScanner;
//# sourceMappingURL=scanner.d.ts.map