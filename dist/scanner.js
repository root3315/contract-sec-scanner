"use strict";
/**
 * Core scanner implementation for Solidity smart contract security analysis.
 * Combines regex-based pattern matching with AST-based structural analysis.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityScanner = void 0;
exports.createScanner = createScanner;
const rules_1 = require("./rules");
const utils_1 = require("./utils");
const ast_1 = require("./ast");
class SecurityScanner {
    options;
    stats;
    astCache;
    constructor(options = {}) {
        this.options = {
            excludeRules: [],
            minSeverity: 'info',
            includeSnippets: true,
            scanComments: false,
            useAST: true,
            ...options
        };
        this.stats = {
            rulesApplied: 0,
            patternsMatched: 0,
            contractsScanned: 0,
            functionsAnalyzed: 0,
            astNodesAnalyzed: 0
        };
        this.astCache = new Map();
    }
    /**
     * Scan Solidity source code for security vulnerabilities.
     * Combines regex-based and AST-based analysis.
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
        let astContext = null;
        if (this.options.useAST) {
            try {
                const ast = (0, ast_1.parseSolidityToAST)(source);
                if (ast) {
                    astContext = (0, ast_1.analyzeAST)(ast, source);
                    this.stats.astNodesAnalyzed += countASTNodes(ast);
                    const astFindings = this.runASTAnalysis(astContext, source, filePath);
                    findings.push(...astFindings);
                }
            }
            catch (e) {
                // AST parsing failed, fall back to regex-only analysis
            }
        }
        const activeRules = this.getActiveRules();
        this.stats.rulesApplied = activeRules.length;
        for (const rule of activeRules) {
            const ruleFindings = this.applyRule(rule, analysisSource, filePath);
            findings.push(...ruleFindings);
        }
        if (astContext) {
            const deepFindings = this.runDeepASTAnalysis(astContext, source, filePath);
            findings.push(...deepFindings);
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
            functionsAnalyzed: 0,
            astNodesAnalyzed: 0
        };
        this.astCache.clear();
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
    /**
     * Run AST-based security analysis.
     */
    runASTAnalysis(context, source, filePath) {
        const findings = [];
        for (const func of context.functions) {
            if (func.kind !== 'function' || !func.body)
                continue;
            if ((0, ast_1.hasTxOrigin)(func.body)) {
                const pos = (0, utils_1.getPositionFromIndex)(source, parseInt(func.src.split(':')[0], 10));
                findings.push({
                    ruleId: 'AST-ACCESS-001',
                    ruleName: 'Unsafe tx.origin (AST)',
                    severity: 'critical',
                    line: pos.line,
                    column: pos.column,
                    message: 'Function uses tx.origin for authorization which is vulnerable to phishing',
                    recommendation: 'Use msg.sender instead of tx.origin'
                });
            }
            if ((0, ast_1.hasBlockTimestamp)(func.body)) {
                const pos = (0, utils_1.getPositionFromIndex)(source, parseInt(func.src.split(':')[0], 10));
                findings.push({
                    ruleId: 'AST-TIMESTAMP-001',
                    ruleName: 'Timestamp Dependency (AST)',
                    severity: 'medium',
                    line: pos.line,
                    column: pos.column,
                    message: 'Function logic depends on block.timestamp which miners can manipulate',
                    recommendation: 'Avoid using block.timestamp for critical logic'
                });
            }
            if ((0, ast_1.hasAssembly)(func.body)) {
                const pos = (0, utils_1.getPositionFromIndex)(source, parseInt(func.src.split(':')[0], 10));
                findings.push({
                    ruleId: 'AST-ASSEMBLY-001',
                    ruleName: 'Inline Assembly (AST)',
                    severity: 'high',
                    line: pos.line,
                    column: pos.column,
                    message: 'Function contains inline assembly which bypasses Solidity safety checks',
                    recommendation: 'Review assembly code carefully for security implications'
                });
            }
            if ((0, ast_1.hasSelfDestruct)(func.body)) {
                const pos = (0, utils_1.getPositionFromIndex)(source, parseInt(func.src.split(':')[0], 10));
                findings.push({
                    ruleId: 'AST-DESTRUCT-001',
                    ruleName: 'Selfdestruct (AST)',
                    severity: 'critical',
                    line: pos.line,
                    column: pos.column,
                    message: 'Function can self-destruct the contract',
                    recommendation: 'Ensure selfdestruct is properly access-controlled'
                });
            }
            if ((0, ast_1.hasExternalCall)(func.body) && (0, ast_1.isStateChangingFunction)(func)) {
                const hasGuard = (0, ast_1.hasModifier)(func, 'nonReentrant');
                if (!hasGuard) {
                    const pos = (0, utils_1.getPositionFromIndex)(source, parseInt(func.src.split(':')[0], 10));
                    findings.push({
                        ruleId: 'AST-REENTR-001',
                        ruleName: 'Missing Reentrancy Guard (AST)',
                        severity: 'high',
                        line: pos.line,
                        column: pos.column,
                        message: `State-changing function "${func.name || 'anonymous'}" with external call lacks nonReentrant modifier`,
                        recommendation: 'Add nonReentrant modifier from OpenZeppelin Contracts'
                    });
                }
            }
        }
        const stateVarNames = context.stateVariables.map(v => v.name);
        for (const func of context.functions) {
            if (!func.body)
                continue;
            if ((0, ast_1.hasStateWrite)(func.body, stateVarNames) && (0, ast_1.hasExternalCall)(func.body)) {
                const pos = (0, utils_1.getPositionFromIndex)(source, parseInt(func.src.split(':')[0], 10));
                const stateWriteBeforeCall = checkStateWriteBeforeExternalCall(func.body);
                if (!stateWriteBeforeCall) {
                    findings.push({
                        ruleId: 'AST-REENTR-002',
                        ruleName: 'Reentrancy Pattern (AST)',
                        severity: 'critical',
                        line: pos.line,
                        column: pos.column,
                        message: 'State is modified after external call - potential reentrancy vulnerability',
                        recommendation: 'Apply checks-effects-interactions pattern: update state before external calls'
                    });
                }
            }
        }
        const unprotected = (0, ast_1.findUnprotectedFunctions)(context, [
            'withdraw', 'transferOwnership', 'setOwner', 'pause', 'unpause',
            'mint', 'burn', 'blacklist', 'whitelist', 'setFee', 'updateAddress',
            'destroy', 'selfdestruct'
        ]);
        for (const func of unprotected) {
            const pos = (0, utils_1.getPositionFromIndex)(source, parseInt(func.src.split(':')[0], 10));
            findings.push({
                ruleId: 'AST-ACCESS-002',
                ruleName: 'Unprotected Sensitive Function (AST)',
                severity: 'high',
                line: pos.line,
                column: pos.column,
                message: `Sensitive function "${func.name || 'anonymous'}" lacks access control modifier`,
                recommendation: 'Add onlyOwner or role-based access control modifier'
            });
        }
        const loopFunctions = (0, ast_1.findLoopsWithExternalCalls)(context);
        for (const func of loopFunctions) {
            const pos = (0, utils_1.getPositionFromIndex)(source, parseInt(func.src.split(':')[0], 10));
            findings.push({
                ruleId: 'AST-DOS-001',
                ruleName: 'Unbounded Loop with External Call (AST)',
                severity: 'high',
                line: pos.line,
                column: pos.column,
                message: `Function "${func.name || 'anonymous'}" contains external call inside loop - potential DoS`,
                recommendation: 'Avoid external calls in loops. Use pull pattern instead.'
            });
        }
        const publicVars = (0, ast_1.findPublicStateVariables)(context.stateVariables);
        for (const v of publicVars) {
            const pos = (0, utils_1.getPositionFromIndex)(source, parseInt(v.src.split(':')[0], 10));
            findings.push({
                ruleId: 'AST-STORAGE-001',
                ruleName: 'Public State Variable (AST)',
                severity: 'info',
                line: pos.line,
                column: pos.column,
                message: `State variable "${v.name}" is public, creating automatic getter`,
                recommendation: 'Consider making sensitive state variables private or internal'
            });
        }
        if ((0, ast_1.isOldSolidityVersion)(context.pragmas)) {
            const version = (0, ast_1.getPragmaSolidityVersion)(context.pragmas);
            findings.push({
                ruleId: 'AST-VERSION-001',
                ruleName: 'Old Solidity Version (AST)',
                severity: 'medium',
                line: 1,
                column: 1,
                message: `Contract uses Solidity ${version} which lacks built-in overflow protection`,
                recommendation: 'Upgrade to Solidity 0.8+ for built-in overflow protection'
            });
        }
        return findings;
    }
    /**
     * Run deeper AST analysis for complex patterns.
     */
    runDeepASTAnalysis(context, source, filePath) {
        const findings = [];
        for (const contract of context.contracts) {
            for (const node of contract.nodes) {
                if (node.nodeType === 'FunctionDefinition') {
                    const func = node;
                    if (!func.body)
                        continue;
                    const divBeforeMult = (0, ast_1.findDivisionBeforeMultiplication)(func.body);
                    for (const divNode of divBeforeMult) {
                        const pos = (0, utils_1.getPositionFromIndex)(source, parseInt(divNode.src.split(':')[0], 10));
                        findings.push({
                            ruleId: 'AST-LOGIC-001',
                            ruleName: 'Division Before Multiplication (AST)',
                            severity: 'low',
                            line: pos.line,
                            column: pos.column,
                            message: 'Division before multiplication causes precision loss',
                            recommendation: 'Multiply before divide: (a * b) / c'
                        });
                    }
                }
            }
        }
        return findings;
    }
}
exports.SecurityScanner = SecurityScanner;
function countASTNodes(ast) {
    let count = 0;
    function traverse(node) {
        count++;
        const children = getNodeChildren(node);
        children.forEach(traverse);
    }
    traverse(ast);
    return count;
}
function getNodeChildren(node) {
    const children = [];
    if ('nodes' in node && Array.isArray(node.nodes)) {
        children.push(...node.nodes);
    }
    if ('statements' in node && Array.isArray(node.statements)) {
        children.push(...node.statements);
    }
    if ('body' in node && node.body && typeof node.body === 'object' && 'nodeType' in node.body) {
        children.push(node.body);
    }
    if ('parameters' in node && node.parameters && typeof node.parameters === 'object' && 'nodeType' in node.parameters) {
        const params = node.parameters;
        if (params.parameters)
            children.push(...params.parameters);
    }
    if ('expression' in node && node.expression && typeof node.expression === 'object' && 'nodeType' in node.expression) {
        children.push(node.expression);
    }
    if ('arguments' in node && Array.isArray(node.arguments)) {
        children.push(...node.arguments);
    }
    if ('leftExpression' in node && node.leftExpression && typeof node.leftExpression === 'object') {
        children.push(node.leftExpression);
    }
    if ('rightExpression' in node && node.rightExpression && typeof node.rightExpression === 'object') {
        children.push(node.rightExpression);
    }
    if ('subExpression' in node && node.subExpression && typeof node.subExpression === 'object') {
        children.push(node.subExpression);
    }
    if ('condition' in node && node.condition && typeof node.condition === 'object') {
        children.push(node.condition);
    }
    if ('trueBody' in node && node.trueBody && typeof node.trueBody === 'object') {
        children.push(node.trueBody);
    }
    if ('falseBody' in node && node.falseBody && typeof node.falseBody === 'object') {
        children.push(node.falseBody);
    }
    if ('initialValue' in node && node.initialValue && typeof node.initialValue === 'object') {
        children.push(node.initialValue);
    }
    if ('initializationExpression' in node && node.initializationExpression) {
        children.push(node.initializationExpression);
    }
    if ('loopExpression' in node && node.loopExpression) {
        children.push(node.loopExpression);
    }
    if ('leftHandSide' in node && node.leftHandSide && typeof node.leftHandSide === 'object') {
        children.push(node.leftHandSide);
    }
    if ('rightHandSide' in node && node.rightHandSide && typeof node.rightHandSide === 'object') {
        children.push(node.rightHandSide);
    }
    if ('modifiers' in node && Array.isArray(node.modifiers)) {
        children.push(...node.modifiers);
    }
    if ('baseContracts' in node && Array.isArray(node.baseContracts)) {
        children.push(...node.baseContracts);
    }
    if ('members' in node && Array.isArray(node.members)) {
        children.push(...node.members);
    }
    if ('clauses' in node && Array.isArray(node.clauses)) {
        children.push(...node.clauses);
    }
    if ('eventCall' in node && node.eventCall && typeof node.eventCall === 'object') {
        children.push(node.eventCall);
    }
    if ('errorCall' in node && node.errorCall && typeof node.errorCall === 'object') {
        children.push(node.errorCall);
    }
    if ('operations' in node && Array.isArray(node.operations)) {
        children.push(...node.operations);
    }
    if ('ast' in node && node.ast && typeof node.ast === 'object' && 'nodeType' in node.ast) {
        children.push(node.ast);
    }
    if ('trueExpression' in node && node.trueExpression && typeof node.trueExpression === 'object') {
        children.push(node.trueExpression);
    }
    if ('falseExpression' in node && node.falseExpression && typeof node.falseExpression === 'object') {
        children.push(node.falseExpression);
    }
    if ('baseExpression' in node && node.baseExpression && typeof node.baseExpression === 'object') {
        children.push(node.baseExpression);
    }
    if ('indexExpression' in node && node.indexExpression && typeof node.indexExpression === 'object') {
        children.push(node.indexExpression);
    }
    if ('components' in node && Array.isArray(node.components)) {
        const comps = node.components;
        children.push(...comps.filter((c) => c !== null));
    }
    if ('typeName' in node && node.typeName && typeof node.typeName === 'object' && 'nodeType' in node.typeName) {
        children.push(node.typeName);
    }
    if ('declarations' in node && Array.isArray(node.declarations)) {
        const decls = node.declarations;
        children.push(...decls.filter((d) => d !== null));
    }
    return children;
}
function checkStateWriteBeforeExternalCall(node) {
    let foundWrite = false;
    let foundCallAfterWrite = false;
    function traverse(n) {
        if (foundCallAfterWrite)
            return;
        if (n.nodeType === 'Assignment') {
            foundWrite = true;
        }
        if (n.nodeType === 'FunctionCall') {
            const call = n;
            if (call.expression?.nodeType === 'MemberAccess') {
                const memberName = call.expression.memberName;
                if (memberName && ['call', 'delegatecall', 'staticcall', 'transfer', 'send'].includes(memberName)) {
                    if (foundWrite) {
                        foundCallAfterWrite = true;
                    }
                }
            }
        }
        const children = getNodeChildren(n);
        for (const child of children) {
            traverse(child);
        }
    }
    traverse(node);
    return !foundCallAfterWrite;
}
function createScanner(options) {
    return new SecurityScanner(options);
}
//# sourceMappingURL=scanner.js.map