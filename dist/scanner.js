"use strict";
/**
 * Core scanner implementation for Solidity smart contract security analysis.
 * Applies security rules to detect vulnerabilities in contract source code.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityScanner = void 0;
exports.createScanner = createScanner;
const rules_1 = require("./rules");
const utils_1 = require("./utils");
class SecurityScanner {
    options;
    stats;
    constructor(options = {}) {
        this.options = {
            excludeRules: [],
            minSeverity: 'info',
            includeSnippets: true,
            scanComments: false,
            ...options
        };
        this.stats = {
            rulesApplied: 0,
            patternsMatched: 0,
            contractsScanned: 0,
            functionsAnalyzed: 0
        };
    }
    /**
     * Scan Solidity source code for security vulnerabilities.
     */
    scan(source, filePath = 'unknown') {
        const startTime = performance.now();
        const findings = [];
        const analysisSource = this.options.scanComments
            ? source
            : (0, utils_1.stripComments)(source);
        if (!(0, utils_1.isValidSolidity)(source)) {
            return {
                filePath,
                findings: [{
                        ruleId: 'VALIDATION-001',
                        ruleName: 'Invalid Solidity Source',
                        severity: 'high',
                        line: 1,
                        column: 1,
                        message: 'Source code does not appear to be valid Solidity',
                        recommendation: 'Ensure file contains pragma solidity and contract/library/interface definition'
                    }],
                scanTime: performance.now() - startTime
            };
        }
        const contractNames = (0, utils_1.extractContractNames)(source);
        this.stats.contractsScanned += contractNames.length;
        const functionPattern = /function\s+(\w+)\s*\([^)]*\)/g;
        while (functionPattern.exec(source) !== null) {
            this.stats.functionsAnalyzed++;
        }
        const activeRules = this.getActiveRules();
        this.stats.rulesApplied = activeRules.length;
        for (const rule of activeRules) {
            const ruleFindings = this.applyRule(rule, analysisSource, filePath);
            findings.push(...ruleFindings);
        }
        findings.sort((a, b) => {
            const severityDiff = rules_1.SEVERITY_ORDER[a.severity] - rules_1.SEVERITY_ORDER[b.severity];
            if (severityDiff !== 0)
                return severityDiff;
            return a.line - b.line;
        });
        return {
            filePath,
            findings,
            scanTime: performance.now() - startTime
        };
    }
    /**
     * Scan multiple files and aggregate results.
     */
    scanFiles(files) {
        const results = [];
        for (const file of files) {
            const result = this.scan(file.content, file.path);
            results.push(result);
        }
        return results;
    }
    /**
     * Apply a single security rule to source code.
     */
    applyRule(rule, source, filePath) {
        const findings = [];
        const matches = this.findAllMatches(rule.pattern, source);
        for (const match of matches) {
            const position = (0, utils_1.getPositionFromIndex)(source, match.index);
            const snippet = this.options.includeSnippets
                ? (0, utils_1.getSnippet)(source, match.index)
                : undefined;
            findings.push({
                ruleId: rule.id,
                ruleName: rule.name,
                severity: rule.severity,
                line: position.line,
                column: position.column,
                message: rule.description,
                recommendation: rule.recommendation,
                snippet
            });
            this.stats.patternsMatched++;
        }
        return findings;
    }
    /**
     * Find all matches of a pattern, handling global flag properly.
     */
    findAllMatches(pattern, source) {
        const matches = [];
        const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
        let match;
        while ((match = regex.exec(source)) !== null) {
            matches.push({
                index: match.index,
                match: match[0]
            });
            if (match[0].length === 0) {
                regex.lastIndex++;
            }
        }
        return matches;
    }
    /**
     * Get active rules based on options.
     */
    getActiveRules() {
        let rules = rules_1.SECURITY_RULES.filter(rule => !this.options.excludeRules?.includes(rule.id));
        if (this.options.minSeverity) {
            const minSeverityLevel = rules_1.SEVERITY_ORDER[this.options.minSeverity];
            rules = rules.filter(rule => rules_1.SEVERITY_ORDER[rule.severity] <= minSeverityLevel);
        }
        return rules;
    }
    /**
     * Get scanner statistics.
     */
    getStats() {
        return { ...this.stats };
    }
    /**
     * Reset scanner statistics.
     */
    reset() {
        this.stats = {
            rulesApplied: 0,
            patternsMatched: 0,
            contractsScanned: 0,
            functionsAnalyzed: 0
        };
    }
    /**
     * Get available rules for filtering.
     */
    getAvailableRules() {
        return rules_1.SECURITY_RULES;
    }
    /**
     * Check for specific vulnerability types.
     */
    scanForVulnerability(source, vulnerabilityType) {
        const relevantRules = rules_1.SECURITY_RULES.filter(rule => rule.category.toLowerCase().includes(vulnerabilityType.toLowerCase()));
        const findings = [];
        const analysisSource = (0, utils_1.stripComments)(source);
        for (const rule of relevantRules) {
            const ruleFindings = this.applyRule(rule, analysisSource, 'inline');
            findings.push(...ruleFindings);
        }
        return findings;
    }
    /**
     * Perform deep analysis on a specific function.
     */
    analyzeFunction(source, functionName) {
        const functionPattern = new RegExp(`function\\s+${functionName}\\s*\\([^)]*\\)\\s*(?:[^{]*?)\\{([\\s\\S]*?)\\}`, 'g');
        const findings = [];
        let match;
        while ((match = functionPattern.exec(source)) !== null) {
            const functionBody = match[0];
            const functionStart = match.index;
            const position = (0, utils_1.getPositionFromIndex)(source, functionStart);
            const criticalPatterns = [
                { pattern: /\bcall\b\s*\{/, ruleId: 'FUNC-CALL-001', message: 'Function contains low-level call' },
                { pattern: /\bdelegatecall\b/, ruleId: 'FUNC-DELEGATE-001', message: 'Function uses delegatecall' },
                { pattern: /\bselfdestruct\b/, ruleId: 'FUNC-DESTRUCT-001', message: 'Function can self-destruct' },
                { pattern: /assembly\s*\{/, ruleId: 'FUNC-ASSEMBLY-001', message: 'Function contains inline assembly' }
            ];
            for (const { pattern, ruleId, message } of criticalPatterns) {
                if (pattern.test(functionBody)) {
                    const matchIndex = functionBody.search(pattern);
                    const snippet = (0, utils_1.getSnippet)(functionBody, matchIndex, 1);
                    findings.push({
                        ruleId,
                        ruleName: 'Critical Function Pattern',
                        severity: 'high',
                        line: position.line,
                        column: position.column,
                        message,
                        recommendation: 'Review this function carefully for security implications',
                        snippet
                    });
                }
            }
        }
        return findings;
    }
    /**
     * Check for reentrancy patterns specifically.
     */
    checkReentrancy(source) {
        const findings = [];
        const stateChangeAfterCall = /(?:call|send|transfer)\s*\([^)]*\)[^}]*\b(?:balance|allowance|totalSupply)\s*=/gi;
        const matches = this.findAllMatches(stateChangeAfterCall, source);
        for (const match of matches) {
            const position = (0, utils_1.getPositionFromIndex)(source, match.index);
            findings.push({
                ruleId: 'REENTRANCY-DEEP-001',
                ruleName: 'State Change After External Call',
                severity: 'critical',
                line: position.line,
                column: position.column,
                message: 'State variable modified after external call - potential reentrancy',
                recommendation: 'Apply checks-effects-interactions pattern: update state before external calls'
            });
        }
        const missingGuard = /function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*(?:view|pure)?\s*(?!\s*(?:view|pure|nonReentrant|constant))/g;
        const stateChangingFunctions = this.findAllMatches(missingGuard, source);
        for (const match of stateChangingFunctions) {
            const funcMatch = /function\s+(\w+)/.exec(match.match);
            if (funcMatch) {
                const functionName = funcMatch[1];
                const hasStateWrite = new RegExp(`function\\s+${functionName}[^{]*\\{[\\s\\S]*?(?:=|\\+\\+|--|\\+=|-=)`).test(source);
                if (hasStateWrite) {
                    const position = (0, utils_1.getPositionFromIndex)(source, match.index);
                    findings.push({
                        ruleId: 'REENTRANCY-GUARD-001',
                        ruleName: 'Missing Reentrancy Guard',
                        severity: 'high',
                        line: position.line,
                        column: position.column,
                        message: `State-changing function "${functionName}" lacks nonReentrant modifier`,
                        recommendation: 'Add nonReentrant modifier from OpenZeppelin Contracts'
                    });
                }
            }
        }
        return findings;
    }
    /**
     * Analyze access control patterns.
     */
    checkAccessControl(source) {
        const findings = [];
        const sensitiveFunctions = [
            'withdraw', 'transferOwnership', 'setOwner', 'pause', 'unpause',
            'mint', 'burn', 'blacklist', 'whitelist', 'setFee', 'updateAddress'
        ];
        for (const funcName of sensitiveFunctions) {
            const pattern = new RegExp(`function\\s+${funcName}\\s*\\([^)]*\\)\\s*(?:public|external)(?!\\s*(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernance))`, 'i');
            const matches = this.findAllMatches(pattern, source);
            for (const match of matches) {
                const position = (0, utils_1.getPositionFromIndex)(source, match.index);
                findings.push({
                    ruleId: 'ACCESS-SENSITIVE-001',
                    ruleName: 'Unprotected Sensitive Function',
                    severity: 'high',
                    line: position.line,
                    column: position.column,
                    message: `Function "${funcName}" should have access control`,
                    recommendation: 'Add onlyOwner or role-based access control modifier'
                });
            }
        }
        if (/tx\.origin\s*(?:==|!=)/.test(source)) {
            const match = /tx\.origin\s*(?:==|!=)/.exec(source);
            if (match) {
                const position = (0, utils_1.getPositionFromIndex)(source, match.index);
                findings.push({
                    ruleId: 'ACCESS-TXORIGIN-001',
                    ruleName: 'Unsafe tx.origin Usage',
                    severity: 'critical',
                    line: position.line,
                    column: position.column,
                    message: 'tx.origin should not be used for authorization',
                    recommendation: 'Use msg.sender instead of tx.origin for access control'
                });
            }
        }
        return findings;
    }
}
exports.SecurityScanner = SecurityScanner;
function createScanner(options) {
    return new SecurityScanner(options);
}
//# sourceMappingURL=scanner.js.map