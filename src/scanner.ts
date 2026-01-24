/**
 * Core scanner implementation for Solidity smart contract security analysis.
 * Combines regex-based pattern matching with AST-based structural analysis.
 */

import type { SecurityRule, Severity } from './rules';
import { SECURITY_RULES, SEVERITY_ORDER } from './rules';
import type { Finding, ScanResult } from './utils';
import {
  getPositionFromIndex,
  getSnippet,
  stripComments,
  isValidSolidity,
  extractContractNames
} from './utils';
import {
  parseSolidityToAST,
  analyzeAST,
  findUnprotectedFunctions,
  findLoopsWithExternalCalls,
  findDivisionBeforeMultiplication,
  hasTxOrigin,
  hasBlockTimestamp,
  hasExternalCall,
  hasStateWrite,
  hasAssembly,
  hasSelfDestruct,
  isOldSolidityVersion,
  findPublicStateVariables,
  getPragmaSolidityVersion,
  findNodesByType,
  hasModifier,
  isStateChangingFunction,
  type ASTAnalysisContext,
  type SourceUnit,
  type FunctionDefinition
} from './ast';

export interface ScannerOptions {
  excludeRules?: string[];
  minSeverity?: Severity;
  includeSnippets?: boolean;
  scanComments?: boolean;
  useAST?: boolean;
}

export interface ScannerStats {
  rulesApplied: number;
  patternsMatched: number;
  contractsScanned: number;
  functionsAnalyzed: number;
  astNodesAnalyzed: number;
}

export class SecurityScanner {
  private options: ScannerOptions;
  private stats: ScannerStats;
  private astCache: Map<string, SourceUnit>;

  constructor(options: ScannerOptions = {}) {
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
  scan(source: string, filePath: string = 'unknown'): ScanResult {
    const startTime = performance.now();
    const findings: Finding[] = [];

    const analysisSource = this.options.scanComments
      ? source
      : stripComments(source);

    if (!isValidSolidity(source)) {
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

    const contractNames = extractContractNames(source);
    this.stats.contractsScanned += contractNames.length;

    const functionPattern = /function\s+(\w+)\s*\([^)]*\)/g;
    while (functionPattern.exec(source) !== null) {
      this.stats.functionsAnalyzed++;
    }

    let astContext: ASTAnalysisContext | null = null;
    if (this.options.useAST) {
      try {
        const ast = parseSolidityToAST(source);
        if (ast) {
          astContext = analyzeAST(ast, source);
          this.stats.astNodesAnalyzed += countASTNodes(ast);
          
          const astFindings = this.runASTAnalysis(astContext, source, filePath);
          findings.push(...astFindings);
        }
      } catch (e) {
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
      const severityDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      if (severityDiff !== 0) return severityDiff;
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
  scanFiles(files: Array<{ path: string; content: string }>): ScanResult[] {
    const results: ScanResult[] = [];

    for (const file of files) {
      const result = this.scan(file.content, file.path);
      results.push(result);
    }

    return results;
  }

  /**
   * Apply a single security rule to source code.
   */
  private applyRule(rule: SecurityRule, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const matches = this.findAllMatches(rule.pattern, source);

    for (const match of matches) {
      const position = getPositionFromIndex(source, match.index);
      const snippet = this.options.includeSnippets
        ? getSnippet(source, match.index)
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
  private findAllMatches(pattern: RegExp, source: string): Array<{ index: number; match: string }> {
    const matches: Array<{ index: number; match: string }> = [];
    const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');

    let match: RegExpExecArray | null;
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
  private getActiveRules(): SecurityRule[] {
    let rules = SECURITY_RULES.filter(rule =>
      !this.options.excludeRules?.includes(rule.id)
    );

    if (this.options.minSeverity) {
      const minSeverityLevel = SEVERITY_ORDER[this.options.minSeverity];
      rules = rules.filter(rule =>
        SEVERITY_ORDER[rule.severity] <= minSeverityLevel
      );
    }

    return rules;
  }

  /**
   * Get scanner statistics.
   */
  getStats(): ScannerStats {
    return { ...this.stats };
  }

  /**
   * Reset scanner statistics.
   */
  reset(): void {
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
  getAvailableRules(): SecurityRule[] {
    return SECURITY_RULES;
  }

  /**
   * Check for specific vulnerability types.
   */
  scanForVulnerability(source: string, vulnerabilityType: string): Finding[] {
    const relevantRules = SECURITY_RULES.filter(rule =>
      rule.category.toLowerCase().includes(vulnerabilityType.toLowerCase())
    );

    const findings: Finding[] = [];
    const analysisSource = stripComments(source);

    for (const rule of relevantRules) {
      const ruleFindings = this.applyRule(rule, analysisSource, 'inline');
      findings.push(...ruleFindings);
    }

    return findings;
  }

  /**
   * Perform deep analysis on a specific function.
   */
  analyzeFunction(source: string, functionName: string): Finding[] {
    const functionPattern = new RegExp(
      `function\\s+${functionName}\\s*\\([^)]*\\)\\s*(?:[^{]*?)\\{([\\s\\S]*?)\\}`,
      'g'
    );

    const findings: Finding[] = [];
    let match: RegExpExecArray | null;

    while ((match = functionPattern.exec(source)) !== null) {
      const functionBody = match[0];
      const functionStart = match.index;

      const position = getPositionFromIndex(source, functionStart);

      const criticalPatterns = [
        { pattern: /\bcall\b\s*\{/, ruleId: 'FUNC-CALL-001', message: 'Function contains low-level call' },
        { pattern: /\bdelegatecall\b/, ruleId: 'FUNC-DELEGATE-001', message: 'Function uses delegatecall' },
        { pattern: /\bselfdestruct\b/, ruleId: 'FUNC-DESTRUCT-001', message: 'Function can self-destruct' },
        { pattern: /assembly\s*\{/, ruleId: 'FUNC-ASSEMBLY-001', message: 'Function contains inline assembly' }
      ];

      for (const { pattern, ruleId, message } of criticalPatterns) {
        if (pattern.test(functionBody)) {
          const matchIndex = functionBody.search(pattern);
          const snippet = getSnippet(functionBody, matchIndex, 1);

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
  checkReentrancy(source: string): Finding[] {
    const findings: Finding[] = [];

    const stateChangeAfterCall = /(?:call|send|transfer)\s*\([^)]*\)[^}]*\b(?:balance|allowance|totalSupply)\s*=/gi;
    const matches = this.findAllMatches(stateChangeAfterCall, source);

    for (const match of matches) {
      const position = getPositionFromIndex(source, match.index);

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
          const position = getPositionFromIndex(source, match.index);
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
  checkAccessControl(source: string): Finding[] {
    const findings: Finding[] = [];

    const sensitiveFunctions = [
      'withdraw', 'transferOwnership', 'setOwner', 'pause', 'unpause',
      'mint', 'burn', 'blacklist', 'whitelist', 'setFee', 'updateAddress'
    ];

    for (const funcName of sensitiveFunctions) {
      const pattern = new RegExp(
        `function\\s+${funcName}\\s*\\([^)]*\\)\\s*(?:public|external)(?!\\s*(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernance))`,
        'i'
      );

      const matches = this.findAllMatches(pattern, source);

      for (const match of matches) {
        const position = getPositionFromIndex(source, match.index);
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
        const position = getPositionFromIndex(source, match.index);
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
  private runASTAnalysis(context: ASTAnalysisContext, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    for (const func of context.functions) {
      if (func.kind !== 'function' || !func.body) continue;

      if (hasTxOrigin(func.body)) {
        const pos = getPositionFromIndex(source, parseInt(func.src.split(':')[0], 10));
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

      if (hasBlockTimestamp(func.body)) {
        const pos = getPositionFromIndex(source, parseInt(func.src.split(':')[0], 10));
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

      if (hasAssembly(func.body)) {
        const pos = getPositionFromIndex(source, parseInt(func.src.split(':')[0], 10));
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

      if (hasSelfDestruct(func.body)) {
        const pos = getPositionFromIndex(source, parseInt(func.src.split(':')[0], 10));
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

      if (hasExternalCall(func.body) && isStateChangingFunction(func)) {
        const hasGuard = hasModifier(func, 'nonReentrant');
        if (!hasGuard) {
          const pos = getPositionFromIndex(source, parseInt(func.src.split(':')[0], 10));
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
      if (!func.body) continue;
      
      if (hasStateWrite(func.body, stateVarNames) && hasExternalCall(func.body)) {
        const pos = getPositionFromIndex(source, parseInt(func.src.split(':')[0], 10));
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

    const unprotected = findUnprotectedFunctions(context, [
      'withdraw', 'transferOwnership', 'setOwner', 'pause', 'unpause',
      'mint', 'burn', 'blacklist', 'whitelist', 'setFee', 'updateAddress',
      'destroy', 'selfdestruct'
    ]);

    for (const func of unprotected) {
      const pos = getPositionFromIndex(source, parseInt(func.src.split(':')[0], 10));
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

    const loopFunctions = findLoopsWithExternalCalls(context);
    for (const func of loopFunctions) {
      const pos = getPositionFromIndex(source, parseInt(func.src.split(':')[0], 10));
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

    const publicVars = findPublicStateVariables(context.stateVariables);
    for (const v of publicVars) {
      const pos = getPositionFromIndex(source, parseInt(v.src.split(':')[0], 10));
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

    if (isOldSolidityVersion(context.pragmas)) {
      const version = getPragmaSolidityVersion(context.pragmas);
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
  private runDeepASTAnalysis(context: ASTAnalysisContext, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    for (const contract of context.contracts) {
      for (const node of contract.nodes) {
        if (node.nodeType === 'FunctionDefinition') {
          const func = node as FunctionDefinition;
          if (!func.body) continue;

          const divBeforeMult = findDivisionBeforeMultiplication(func.body);
          for (const divNode of divBeforeMult) {
            const pos = getPositionFromIndex(source, parseInt(divNode.src.split(':')[0], 10));
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

function countASTNodes(ast: SourceUnit): number {
  let count = 0;
  function traverse(node: { nodeType: string; [key: string]: unknown }): void {
    count++;
    const children = getNodeChildren(node);
    children.forEach(traverse);
  }
  traverse(ast);
  return count;
}

function getNodeChildren(node: { nodeType: string; [key: string]: unknown }): Array<{ nodeType: string; [key: string]: unknown }> {
  const children: Array<{ nodeType: string; [key: string]: unknown }> = [];
  
  if ('nodes' in node && Array.isArray(node.nodes)) {
    children.push(...node.nodes as Array<{ nodeType: string; [key: string]: unknown }>);
  }
  if ('statements' in node && Array.isArray(node.statements)) {
    children.push(...node.statements as Array<{ nodeType: string; [key: string]: unknown }>);
  }
  if ('body' in node && node.body && typeof node.body === 'object' && 'nodeType' in node.body) {
    children.push(node.body as { nodeType: string; [key: string]: unknown });
  }
  if ('parameters' in node && node.parameters && typeof node.parameters === 'object' && 'nodeType' in node.parameters) {
    const params = node.parameters as { nodeType: string; parameters?: Array<{ nodeType: string; [key: string]: unknown }> };
    if (params.parameters) children.push(...params.parameters);
  }
  if ('expression' in node && node.expression && typeof node.expression === 'object' && 'nodeType' in node.expression) {
    children.push(node.expression as { nodeType: string; [key: string]: unknown });
  }
  if ('arguments' in node && Array.isArray(node.arguments)) {
    children.push(...node.arguments as Array<{ nodeType: string; [key: string]: unknown }>);
  }
  if ('leftExpression' in node && node.leftExpression && typeof node.leftExpression === 'object') {
    children.push(node.leftExpression as { nodeType: string; [key: string]: unknown });
  }
  if ('rightExpression' in node && node.rightExpression && typeof node.rightExpression === 'object') {
    children.push(node.rightExpression as { nodeType: string; [key: string]: unknown });
  }
  if ('subExpression' in node && node.subExpression && typeof node.subExpression === 'object') {
    children.push(node.subExpression as { nodeType: string; [key: string]: unknown });
  }
  if ('condition' in node && node.condition && typeof node.condition === 'object') {
    children.push(node.condition as { nodeType: string; [key: string]: unknown });
  }
  if ('trueBody' in node && node.trueBody && typeof node.trueBody === 'object') {
    children.push(node.trueBody as { nodeType: string; [key: string]: unknown });
  }
  if ('falseBody' in node && node.falseBody && typeof node.falseBody === 'object') {
    children.push(node.falseBody as { nodeType: string; [key: string]: unknown });
  }
  if ('initialValue' in node && node.initialValue && typeof node.initialValue === 'object') {
    children.push(node.initialValue as { nodeType: string; [key: string]: unknown });
  }
  if ('initializationExpression' in node && node.initializationExpression) {
    children.push(node.initializationExpression as { nodeType: string; [key: string]: unknown });
  }
  if ('loopExpression' in node && node.loopExpression) {
    children.push(node.loopExpression as { nodeType: string; [key: string]: unknown });
  }
  if ('leftHandSide' in node && node.leftHandSide && typeof node.leftHandSide === 'object') {
    children.push(node.leftHandSide as { nodeType: string; [key: string]: unknown });
  }
  if ('rightHandSide' in node && node.rightHandSide && typeof node.rightHandSide === 'object') {
    children.push(node.rightHandSide as { nodeType: string; [key: string]: unknown });
  }
  if ('modifiers' in node && Array.isArray(node.modifiers)) {
    children.push(...node.modifiers as Array<{ nodeType: string; [key: string]: unknown }>);
  }
  if ('baseContracts' in node && Array.isArray(node.baseContracts)) {
    children.push(...node.baseContracts as Array<{ nodeType: string; [key: string]: unknown }>);
  }
  if ('members' in node && Array.isArray(node.members)) {
    children.push(...node.members as Array<{ nodeType: string; [key: string]: unknown }>);
  }
  if ('clauses' in node && Array.isArray(node.clauses)) {
    children.push(...node.clauses as Array<{ nodeType: string; [key: string]: unknown }>);
  }
  if ('eventCall' in node && node.eventCall && typeof node.eventCall === 'object') {
    children.push(node.eventCall as { nodeType: string; [key: string]: unknown });
  }
  if ('errorCall' in node && node.errorCall && typeof node.errorCall === 'object') {
    children.push(node.errorCall as { nodeType: string; [key: string]: unknown });
  }
  if ('operations' in node && Array.isArray(node.operations)) {
    children.push(...node.operations as Array<{ nodeType: string; [key: string]: unknown }>);
  }
  if ('ast' in node && node.ast && typeof node.ast === 'object' && 'nodeType' in node.ast) {
    children.push(node.ast as { nodeType: string; [key: string]: unknown });
  }
  if ('trueExpression' in node && node.trueExpression && typeof node.trueExpression === 'object') {
    children.push(node.trueExpression as { nodeType: string; [key: string]: unknown });
  }
  if ('falseExpression' in node && node.falseExpression && typeof node.falseExpression === 'object') {
    children.push(node.falseExpression as { nodeType: string; [key: string]: unknown });
  }
  if ('baseExpression' in node && node.baseExpression && typeof node.baseExpression === 'object') {
    children.push(node.baseExpression as { nodeType: string; [key: string]: unknown });
  }
  if ('indexExpression' in node && node.indexExpression && typeof node.indexExpression === 'object') {
    children.push(node.indexExpression as { nodeType: string; [key: string]: unknown });
  }
  if ('components' in node && Array.isArray(node.components)) {
    const comps = node.components as Array<{ nodeType: string; [key: string]: unknown } | null>;
    children.push(...comps.filter((c): c is { nodeType: string; [key: string]: unknown } => c !== null));
  }
  if ('typeName' in node && node.typeName && typeof node.typeName === 'object' && 'nodeType' in node.typeName) {
    children.push(node.typeName as { nodeType: string; [key: string]: unknown });
  }
  if ('declarations' in node && Array.isArray(node.declarations)) {
    const decls = node.declarations as Array<{ nodeType: string; [key: string]: unknown } | null>;
    children.push(...decls.filter((d): d is { nodeType: string; [key: string]: unknown } => d !== null));
  }

  return children;
}

function checkStateWriteBeforeExternalCall(node: { nodeType: string; [key: string]: unknown }): boolean {
  let foundWrite = false;
  let foundCallAfterWrite = false;

  function traverse(n: { nodeType: string; [key: string]: unknown }): void {
    if (foundCallAfterWrite) return;

    if (n.nodeType === 'Assignment') {
      foundWrite = true;
    }

    if (n.nodeType === 'FunctionCall') {
      const call = n as { expression?: { nodeType?: string; memberName?: string } };
      if (call.expression?.nodeType === 'MemberAccess') {
        const memberName = (call.expression as { memberName?: string }).memberName;
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

export function createScanner(options?: ScannerOptions): SecurityScanner {
  return new SecurityScanner(options);
}
