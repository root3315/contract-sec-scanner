"use strict";
/**
 * Utility functions for the contract security scanner.
 * Provides file operations, formatting, and helper methods.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.readSolidityFile = readSolidityFile;
exports.findSolidityFiles = findSolidityFiles;
exports.getPositionFromIndex = getPositionFromIndex;
exports.getSnippet = getSnippet;
exports.formatSeverity = formatSeverity;
exports.formatFinding = formatFinding;
exports.formatSummary = formatSummary;
exports.resultsToJson = resultsToJson;
exports.isNonCodeLine = isNonCodeLine;
exports.stripComments = stripComments;
exports.isValidSolidity = isValidSolidity;
exports.extractContractNames = extractContractNames;
exports.parseSolidityToAST = parseSolidityToAST;
exports.getLineCount = getLineCount;
exports.getCodeSize = getCodeSize;
exports.containsPattern = containsPattern;
exports.findAllOccurrences = findAllOccurrences;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/**
 * Read a Solidity file and return its content.
 */
function readSolidityFile(filePath) {
    const absolutePath = path.resolve(filePath);
    if (!fs.existsSync(absolutePath)) {
        return {
            filePath: absolutePath,
            content: '',
            error: `File not found: ${absolutePath}`
        };
    }
    const ext = path.extname(absolutePath).toLowerCase();
    if (ext !== '.sol') {
        return {
            filePath: absolutePath,
            content: '',
            error: `Not a Solidity file: ${absolutePath}`
        };
    }
    try {
        const content = fs.readFileSync(absolutePath, 'utf-8');
        return { filePath: absolutePath, content };
    }
    catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        return {
            filePath: absolutePath,
            content: '',
            error: `Failed to read file: ${errorMessage}`
        };
    }
}
/**
 * Recursively find all Solidity files in a directory.
 */
function findSolidityFiles(dirPath, excludeDirs = []) {
    const solidityFiles = [];
    const absolutePath = path.resolve(dirPath);
    if (!fs.existsSync(absolutePath)) {
        return solidityFiles;
    }
    const stats = fs.statSync(absolutePath);
    if (stats.isFile()) {
        if (path.extname(absolutePath).toLowerCase() === '.sol') {
            solidityFiles.push(absolutePath);
        }
        return solidityFiles;
    }
    const entries = fs.readdirSync(absolutePath, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(absolutePath, entry.name);
        if (entry.isDirectory()) {
            if (!excludeDirs.includes(entry.name)) {
                solidityFiles.push(...findSolidityFiles(fullPath, excludeDirs));
            }
        }
        else if (entry.isFile() && entry.name.endsWith('.sol')) {
            solidityFiles.push(fullPath);
        }
    }
    return solidityFiles;
}
/**
 * Get line and column number from a character index in source code.
 */
function getPositionFromIndex(source, index) {
    const lines = source.substring(0, index).split('\n');
    const line = lines.length;
    const column = lines[lines.length - 1].length + 1;
    return { line, column };
}
/**
 * Extract a code snippet around a specific position.
 */
function getSnippet(source, index, contextLines = 2) {
    const lines = source.split('\n');
    const position = getPositionFromIndex(source, index);
    const startLine = Math.max(0, position.line - contextLines - 1);
    const endLine = Math.min(lines.length, position.line + contextLines);
    const snippetLines = lines.slice(startLine, endLine);
    const lineNumberWidth = endLine.toString().length;
    return snippetLines
        .map((line, i) => {
        const lineNum = startLine + i + 1;
        const marker = lineNum === position.line ? ' >' : '  ';
        const paddedNum = lineNum.toString().padStart(lineNumberWidth, ' ');
        return `${marker} ${paddedNum} | ${line}`;
    })
        .join('\n');
}
/**
 * Format severity with ANSI colors for terminal output.
 */
function formatSeverity(severity) {
    const colors = {
        critical: '\x1b[31m\x1b[1m',
        high: '\x1b[31m',
        medium: '\x1b[33m',
        low: '\x1b[36m',
        info: '\x1b[34m'
    };
    const reset = '\x1b[0m';
    return `${colors[severity]}${severity.toUpperCase()}${reset}`;
}
/**
 * Format a finding for console output.
 */
function formatFinding(finding, filePath) {
    const severityFormatted = formatSeverity(finding.severity);
    let output = `\n[${severityFormatted}] ${finding.ruleName}`;
    output += `\n  Rule: ${finding.ruleId}`;
    output += `\n  Location: ${filePath}:${finding.line}:${finding.column}`;
    output += `\n  Issue: ${finding.message}`;
    output += `\n  Fix: ${finding.recommendation}`;
    if (finding.snippet) {
        output += `\n  Code:\n${finding.snippet.split('\n').map(l => '    ' + l).join('\n')}`;
    }
    return output;
}
/**
 * Format scan summary for console output.
 */
function formatSummary(results) {
    const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
    const filesScanned = results.length;
    const bySeverity = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    };
    for (const result of results) {
        for (const finding of result.findings) {
            bySeverity[finding.severity]++;
        }
    }
    const totalScanTime = results.reduce((sum, r) => sum + r.scanTime, 0);
    let output = '\n';
    output += '═'.repeat(60) + '\n';
    output += '                    SCAN SUMMARY\n';
    output += '═'.repeat(60) + '\n';
    output += `Files Scanned:    ${filesScanned}\n`;
    output += `Total Findings:   ${totalFindings}\n`;
    output += `Scan Time:        ${totalScanTime.toFixed(2)}ms\n`;
    output += '─'.repeat(60) + '\n';
    output += `Critical:         ${formatSeverity('critical')} ${bySeverity.critical}\n`;
    output += `High:             ${formatSeverity('high')} ${bySeverity.high}\n`;
    output += `Medium:           ${formatSeverity('medium')} ${bySeverity.medium}\n`;
    output += `Low:              ${formatSeverity('low')} ${bySeverity.low}\n`;
    output += `Info:             ${formatSeverity('info')} ${bySeverity.info}\n`;
    output += '═'.repeat(60) + '\n';
    return output;
}
/**
 * Convert findings to JSON format for export.
 */
function resultsToJson(results) {
    return JSON.stringify(results, null, 2);
}
/**
 * Check if a line is a comment or empty.
 */
function isNonCodeLine(line) {
    const trimmed = line.trim();
    return trimmed === '' || trimmed.startsWith('//') || trimmed.startsWith('*');
}
/**
 * Remove comments from source code for analysis.
 */
function stripComments(source) {
    let result = source.replace(/\/\/.*$/gm, '');
    result = result.replace(/\/\*[\s\S]*?\*\//g, '');
    return result;
}
/**
 * Validate that source code appears to be valid Solidity.
 */
function isValidSolidity(source) {
    const hasPragma = /pragma\s+solidity/.test(source);
    const hasContract = /\bcontract\b/.test(source);
    const hasLibrary = /\blibrary\b/.test(source);
    const hasInterface = /\binterface\b/.test(source);
    return hasPragma && (hasContract || hasLibrary || hasInterface);
}
/**
 * Extract contract names from source code.
 */
function extractContractNames(source) {
    const contractPattern = /\b(?:contract|library|interface)\s+(\w+)/g;
    const names = [];
    let match;
    while ((match = contractPattern.exec(source)) !== null) {
        names.push(match[1]);
    }
    return names;
}
/**
 * Parse Solidity source code into a simplified AST representation.
 * Uses a heuristic approach since we don't depend on external Solidity parsers.
 */
function parseSolidityToAST(source) {
    if (!isValidSolidity(source)) {
        return null;
    }
    const ast = {
        id: 0,
        nodeType: 'SourceUnit',
        src: `0:${source.length}:0`,
        nodes: [],
        absolutePath: 'source.sol'
    };
    let nodeId = 1;
    const pragmaMatches = [...source.matchAll(/pragma\s+solidity\s+([^\n;]+)/g)];
    for (const match of pragmaMatches) {
        ast.nodes.push({
            id: nodeId++,
            nodeType: 'PragmaDirective',
            src: `${match.index}:${match[0].length}:0`
        });
    }
    const contractRegex = /\b(contract|library|interface)\s+(\w+)(?:\s+(?:is|extends)\s+([^{]+))?\s*\{/g;
    let contractMatch;
    while ((contractMatch = contractRegex.exec(source)) !== null) {
        const contractType = contractMatch[1];
        const contractName = contractMatch[2];
        const inherits = contractMatch[3];
        const contractStart = contractMatch.index;
        const braceStart = source.indexOf('{', contractStart);
        if (braceStart === -1)
            continue;
        let braceCount = 1;
        let contractEnd = braceStart + 1;
        while (contractEnd < source.length && braceCount > 0) {
            if (source[contractEnd] === '{')
                braceCount++;
            else if (source[contractEnd] === '}')
                braceCount--;
            contractEnd++;
        }
        const contractBody = source.substring(braceStart + 1, contractEnd - 1);
        const contractSrc = `${contractStart}:${contractEnd - contractStart}:0`;
        const contractNode = {
            id: nodeId++,
            nodeType: 'ContractDefinition',
            src: contractSrc,
            name: contractName,
            contractKind: contractType,
            nodes: [],
            baseContracts: []
        };
        if (inherits) {
            const inheritNames = inherits.split(/\s*,\s*/).map(s => s.trim()).filter(Boolean);
            for (const name of inheritNames) {
                contractNode.baseContracts.push({
                    id: nodeId++,
                    nodeType: 'InheritanceSpecifier',
                    src: `${source.indexOf(name)}:${name.length}:0`,
                    baseName: {
                        id: nodeId++,
                        nodeType: 'Identifier',
                        src: `${source.indexOf(name)}:${name.length}:0`,
                        name
                    }
                });
            }
        }
        const funcRegex = /function\s+(\w+)?\s*\(([^)]*)\)\s*(?:external|public|private|internal)?\s*(?:view|pure|payable)?\s*(?:override)?\s*(?:returns\s*\([^)]*\))?\s*\{/g;
        let funcMatch;
        while ((funcMatch = funcRegex.exec(contractBody)) !== null) {
            const funcName = funcMatch[1] || '';
            const params = funcMatch[2] || '';
            const funcStartInBody = funcMatch.index;
            const funcStart = braceStart + 1 + funcStartInBody;
            const funcBraceStart = contractBody.indexOf('{', funcStartInBody);
            if (funcBraceStart === -1)
                continue;
            let funcBraceCount = 1;
            let funcEnd = funcStartInBody + funcBraceStart + 1;
            while (funcEnd < contractBody.length && funcBraceCount > 0) {
                if (contractBody[funcEnd] === '{')
                    funcBraceCount++;
                else if (contractBody[funcEnd] === '}')
                    funcBraceCount--;
                funcEnd++;
            }
            const funcSrc = `${funcStart}:${funcEnd - funcStartInBody}:0`;
            const visibilityMatch = funcMatch[0].match(/\b(external|public|private|internal)\b/);
            const mutabilityMatch = funcMatch[0].match(/\b(view|pure|payable)\b/);
            const modifierMatches = funcMatch[0].match(/\b(\w+)\b(?=\s*\()/g) || [];
            const funcNode = {
                id: nodeId++,
                nodeType: 'FunctionDefinition',
                src: funcSrc,
                name: funcName || undefined,
                visibility: (visibilityMatch?.[1] || 'public'),
                stateMutability: mutabilityMatch?.[1],
                kind: funcName ? 'function' : 'constructor',
                implemented: true,
                parameters: {
                    id: nodeId++,
                    nodeType: 'ParameterList',
                    src: `${funcMatch.index + funcMatch[0].indexOf('(')}:${params.length + 2}:0`,
                    parameters: parseParameters(params, nodeId, source)
                },
                modifiers: [],
                body: {
                    id: nodeId++,
                    nodeType: 'Block',
                    src: `${funcStart + funcBraceStart}:${funcEnd - funcBraceStart}:0`,
                    statements: []
                }
            };
            for (const mod of modifierMatches) {
                if (!['function', 'constructor', 'fallback', 'receive'].includes(mod)) {
                    funcNode.modifiers.push({
                        id: nodeId++,
                        nodeType: 'ModifierInvocation',
                        src: `${source.indexOf(mod)}:${mod.length}:0`,
                        modifierName: {
                            id: nodeId++,
                            nodeType: 'Identifier',
                            src: `${source.indexOf(mod)}:${mod.length}:0`,
                            name: mod
                        }
                    });
                }
            }
            contractNode.nodes.push(funcNode);
        }
        const varRegex = /\b(?:mapping\s*\([^)]+\)|uint(?:256)?|int(?:256)?|address|bool|bytes(?:32)?|string)\s+(?:public\s+)?(\w+)\s*[;=]/g;
        let varMatch;
        while ((varMatch = varRegex.exec(contractBody)) !== null) {
            const varName = varMatch[1];
            const varType = varMatch[0].replace(varName, '').trim().replace(/\s+public\s+/, ' ');
            const isPublic = varMatch[0].includes('public');
            const varSrc = `${braceStart + 1 + varMatch.index}:${varMatch[0].length}:0`;
            contractNode.nodes.push({
                id: nodeId++,
                nodeType: 'VariableDeclaration',
                src: varSrc,
                name: varName,
                visibility: isPublic ? 'public' : 'internal',
                stateVariable: true,
                constant: false,
                typeName: {
                    id: nodeId++,
                    nodeType: 'ElementaryTypeName',
                    src: `${braceStart + 1 + varMatch.index}:${varType.length}:0`,
                    typeDescriptions: {
                        typeString: varType
                    }
                }
            });
        }
        ast.nodes.push(contractNode);
    }
    return ast;
}
function parseParameters(paramsStr, startId, source) {
    const params = [];
    if (!paramsStr.trim())
        return params;
    const paramParts = paramsStr.split(',').map(p => p.trim()).filter(Boolean);
    let offset = 0;
    for (const part of paramParts) {
        const nameMatch = part.match(/(?:\w+\s+)?(\w+)/);
        if (nameMatch) {
            params.push({
                id: startId++,
                nodeType: 'VariableDeclaration',
                src: `${offset}:${part.length}:0`,
                name: nameMatch[1],
                visibility: 'internal',
                stateVariable: false,
                typeName: {
                    id: startId++,
                    nodeType: 'ElementaryTypeName',
                    src: `${offset}:${part.length - nameMatch[1].length}:0`,
                    typeDescriptions: {
                        typeString: part.replace(nameMatch[1], '').trim()
                    }
                }
            });
        }
        offset += part.length + 1;
    }
    return params;
}
/**
 * Get line count of source code.
 */
function getLineCount(source) {
    return source.split('\n').length;
}
/**
 * Get character count excluding whitespace and comments.
 */
function getCodeSize(source) {
    const stripped = stripComments(source);
    return stripped.replace(/\s/g, '').length;
}
/**
 * Check if source contains specific pattern.
 */
function containsPattern(source, pattern) {
    return pattern.test(source);
}
/**
 * Find all occurrences of a pattern in source.
 */
function findAllOccurrences(source, pattern) {
    const results = [];
    const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    let match;
    while ((match = regex.exec(source)) !== null) {
        const line = source.substring(0, match.index).split('\n').length;
        results.push({
            index: match.index,
            match: match[0],
            line
        });
        if (match[0].length === 0) {
            regex.lastIndex++;
        }
    }
    return results;
}
//# sourceMappingURL=utils.js.map