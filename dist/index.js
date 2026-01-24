#!/usr/bin/env node
"use strict";
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
exports.getPragmaSolidityVersion = exports.findDivisionBeforeMultiplication = exports.findLoopsWithExternalCalls = exports.findUnprotectedFunctions = exports.findPublicStateVariables = exports.isOldSolidityVersion = exports.hasSelfDestruct = exports.hasAssembly = exports.hasStateWrite = exports.hasExternalCall = exports.hasBlockTimestamp = exports.hasTxOrigin = exports.isStateChangingFunction = exports.hasModifier = exports.findNodesByType = exports.analyzeAST = exports.parseSolidityToAST = exports.resultsToJson = exports.formatSummary = exports.formatFinding = exports.findSolidityFiles = exports.readSolidityFile = exports.getRulesByCategory = exports.getAllCategories = exports.SECURITY_RULES = exports.createScanner = exports.SecurityScanner = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const scanner_1 = require("./scanner");
Object.defineProperty(exports, "SecurityScanner", { enumerable: true, get: function () { return scanner_1.SecurityScanner; } });
Object.defineProperty(exports, "createScanner", { enumerable: true, get: function () { return scanner_1.createScanner; } });
const rules_1 = require("./rules");
Object.defineProperty(exports, "SECURITY_RULES", { enumerable: true, get: function () { return rules_1.SECURITY_RULES; } });
Object.defineProperty(exports, "getAllCategories", { enumerable: true, get: function () { return rules_1.getAllCategories; } });
Object.defineProperty(exports, "getRulesByCategory", { enumerable: true, get: function () { return rules_1.getRulesByCategory; } });
const utils_1 = require("./utils");
Object.defineProperty(exports, "readSolidityFile", { enumerable: true, get: function () { return utils_1.readSolidityFile; } });
Object.defineProperty(exports, "findSolidityFiles", { enumerable: true, get: function () { return utils_1.findSolidityFiles; } });
Object.defineProperty(exports, "formatFinding", { enumerable: true, get: function () { return utils_1.formatFinding; } });
Object.defineProperty(exports, "formatSummary", { enumerable: true, get: function () { return utils_1.formatSummary; } });
Object.defineProperty(exports, "resultsToJson", { enumerable: true, get: function () { return utils_1.resultsToJson; } });
Object.defineProperty(exports, "parseSolidityToAST", { enumerable: true, get: function () { return utils_1.parseSolidityToAST; } });
const ast_1 = require("./ast");
Object.defineProperty(exports, "analyzeAST", { enumerable: true, get: function () { return ast_1.analyzeAST; } });
const VERSION = '1.0.0';
function printBanner() {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║           Contract Security Scanner v${VERSION}              ║
║     Solidity Smart Contract Vulnerability Detection       ║
║            AST-based + Pattern Analysis Engine            ║
╚═══════════════════════════════════════════════════════════╝
`);
}
function printHelp() {
    console.log(`
Contract Security Scanner - Analyze Solidity contracts for vulnerabilities

USAGE:
  contract-sec-scanner <path> [options]

ARGUMENTS:
  path              Path to Solidity file (.sol) or directory to scan

OPTIONS:
  -h, --help        Show this help message
  -v, --version     Show version number
  -o, --output      Output file path (default: stdout)
  -f, --format      Output format: text, json (default: text)
  -e, --exclude     Exclude rule IDs (comma-separated)
  -m, --min-sev     Minimum severity: critical, high, medium, low, info
  -c, --category    Scan specific categories only (comma-separated)
  --deep            Enable deep analysis (slower, more thorough)
  --no-snippets     Don't include code snippets in output
  --no-ast          Disable AST-based analysis (regex only)
  --verbose         Show detailed scan information

EXAMPLES:
  contract-sec-scanner ./contracts/Token.sol
  contract-sec-scanner ./src/contracts --format json -o report.json
  contract-sec-scanner . --min-sev high --exclude INTEGER-001
  contract-sec-scanner ./defi --category "Reentrancy,Access Control"
  contract-sec-scanner ./protocol --deep --verbose --no-ast

AVAILABLE CATEGORIES:
  ${(0, rules_1.getAllCategories)().join(', ')}

RULE COUNTS BY SEVERITY:
  Critical:  ${rules_1.SECURITY_RULES.filter(r => r.severity === 'critical').length}
  High:      ${rules_1.SECURITY_RULES.filter(r => r.severity === 'high').length}
  Medium:    ${rules_1.SECURITY_RULES.filter(r => r.severity === 'medium').length}
  Low:       ${rules_1.SECURITY_RULES.filter(r => r.severity === 'low').length}
  Info:      ${rules_1.SECURITY_RULES.filter(r => r.severity === 'info').length}
`);
}
function parseArgs(args) {
    const options = {
        help: false,
        version: false,
        output: '',
        format: 'text',
        exclude: [],
        minSeverity: 'info',
        categories: [],
        verbose: false,
        deepScan: false,
        noSnippets: false,
        noAST: false
    };
    let i = 0;
    while (i < args.length) {
        const arg = args[i];
        switch (arg) {
            case '-h':
            case '--help':
                options.help = true;
                break;
            case '-v':
            case '--version':
                options.version = true;
                break;
            case '-o':
            case '--output':
                options.output = args[++i] || '';
                break;
            case '-f':
            case '--format':
                const format = args[++i]?.toLowerCase();
                if (format === 'text' || format === 'json') {
                    options.format = format;
                }
                break;
            case '-e':
            case '--exclude':
                options.exclude = (args[++i] || '').split(',').map(s => s.trim()).filter(Boolean);
                break;
            case '-m':
            case '--min-sev':
                const sev = args[++i]?.toLowerCase();
                if (['critical', 'high', 'medium', 'low', 'info'].includes(sev)) {
                    options.minSeverity = sev;
                }
                break;
            case '-c':
            case '--category':
                options.categories = (args[++i] || '').split(',').map(s => s.trim()).filter(Boolean);
                break;
            case '--deep':
                options.deepScan = true;
                break;
            case '--no-snippets':
                options.noSnippets = true;
                break;
            case '--no-ast':
                options.noAST = true;
                break;
            case '--verbose':
                options.verbose = true;
                break;
        }
        i++;
    }
    return options;
}
function getTargetPath(args) {
    for (const arg of args) {
        if (!arg.startsWith('-')) {
            return arg;
        }
    }
    return null;
}
function runDeepAnalysis(scanner, source) {
    const deepFindings = [
        ...scanner.checkReentrancy(source),
        ...scanner.checkAccessControl(source)
    ];
    if (deepFindings.length > 0) {
        return [{
                filePath: 'deep-analysis',
                findings: deepFindings,
                scanTime: 0
            }];
    }
    return [];
}
function scanTarget(targetPath, options) {
    const scannerOptions = {
        excludeRules: options.exclude,
        minSeverity: options.minSeverity,
        includeSnippets: !options.noSnippets,
        scanComments: false,
        useAST: !options.noAST
    };
    const scanner = (0, scanner_1.createScanner)(scannerOptions);
    const results = [];
    const resolvedPath = path.resolve(targetPath);
    if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path does not exist: ${resolvedPath}`);
        process.exit(1);
    }
    const solidityFiles = (0, utils_1.findSolidityFiles)(resolvedPath, ['node_modules', '.git', 'dist', 'build']);
    if (solidityFiles.length === 0) {
        console.error(`No Solidity files found in: ${resolvedPath}`);
        process.exit(1);
    }
    if (options.verbose) {
        console.log(`Found ${solidityFiles.length} Solidity file(s) to scan...\n`);
    }
    for (const filePath of solidityFiles) {
        const fileResult = (0, utils_1.readSolidityFile)(filePath);
        if (fileResult.error) {
            if (options.verbose) {
                console.warn(`Skipping ${filePath}: ${fileResult.error}`);
            }
            continue;
        }
        const result = scanner.scan(fileResult.content, fileResult.filePath);
        results.push(result);
        if (options.deepScan) {
            const deepResults = runDeepAnalysis(scanner, fileResult.content);
            results.push(...deepResults);
        }
        if (options.verbose) {
            const contracts = (0, utils_1.extractContractNames)(fileResult.content);
            console.log(`Scanned: ${path.basename(filePath)}`);
            if (contracts.length > 0) {
                console.log(`  Contracts: ${contracts.join(', ')}`);
            }
            console.log(`  Findings: ${result.findings.length}`);
        }
    }
    const stats = scanner.getStats();
    if (options.verbose) {
        console.log(`\nScanner Stats:`);
        console.log(`  Rules Applied: ${stats.rulesApplied}`);
        console.log(`  Patterns Matched: ${stats.patternsMatched}`);
        console.log(`  Contracts Scanned: ${stats.contractsScanned}`);
        console.log(`  Functions Analyzed: ${stats.functionsAnalyzed}`);
        console.log(`  AST Nodes Analyzed: ${stats.astNodesAnalyzed}`);
    }
    return results;
}
function outputResults(results, options) {
    let output;
    if (options.format === 'json') {
        output = (0, utils_1.resultsToJson)(results);
    }
    else {
        const parts = [];
        for (const result of results) {
            if (result.findings.length > 0) {
                for (const finding of result.findings) {
                    parts.push((0, utils_1.formatFinding)(finding, result.filePath));
                }
            }
        }
        output = parts.join('\n') + (0, utils_1.formatSummary)(results);
    }
    if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.writeFileSync(outputPath, output, 'utf-8');
        console.log(`Results written to: ${outputPath}`);
    }
    else {
        console.log(output);
    }
}
function main() {
    const args = process.argv.slice(2);
    const options = parseArgs(args);
    if (options.help) {
        printBanner();
        printHelp();
        process.exit(0);
    }
    if (options.version) {
        console.log(`contract-sec-scanner v${VERSION}`);
        process.exit(0);
    }
    const targetPath = getTargetPath(args);
    if (!targetPath) {
        printBanner();
        console.error('Error: No target path specified.');
        console.error('Use --help for usage information.');
        process.exit(1);
    }
    printBanner();
    console.log(`Scanning: ${path.resolve(targetPath)}\n`);
    const results = scanTarget(targetPath, options);
    const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
    const criticalCount = results.reduce((sum, r) => sum + r.findings.filter((f) => f.severity === 'critical').length, 0);
    const highCount = results.reduce((sum, r) => sum + r.findings.filter((f) => f.severity === 'high').length, 0);
    outputResults(results, options);
    if (criticalCount > 0 || highCount > 0) {
        console.log(`\n⚠️  Found ${criticalCount} critical and ${highCount} high severity issues.`);
        console.log('Review and fix these vulnerabilities before deploying to mainnet.');
        process.exit(1);
    }
    else if (totalFindings > 0) {
        console.log(`\n✓ Scan complete. Found ${totalFindings} issue(s) to review.`);
        process.exit(0);
    }
    else {
        console.log('\n✓ No security issues detected.');
        process.exit(0);
    }
}
var ast_2 = require("./ast");
Object.defineProperty(exports, "findNodesByType", { enumerable: true, get: function () { return ast_2.findNodesByType; } });
Object.defineProperty(exports, "hasModifier", { enumerable: true, get: function () { return ast_2.hasModifier; } });
Object.defineProperty(exports, "isStateChangingFunction", { enumerable: true, get: function () { return ast_2.isStateChangingFunction; } });
Object.defineProperty(exports, "hasTxOrigin", { enumerable: true, get: function () { return ast_2.hasTxOrigin; } });
Object.defineProperty(exports, "hasBlockTimestamp", { enumerable: true, get: function () { return ast_2.hasBlockTimestamp; } });
Object.defineProperty(exports, "hasExternalCall", { enumerable: true, get: function () { return ast_2.hasExternalCall; } });
Object.defineProperty(exports, "hasStateWrite", { enumerable: true, get: function () { return ast_2.hasStateWrite; } });
Object.defineProperty(exports, "hasAssembly", { enumerable: true, get: function () { return ast_2.hasAssembly; } });
Object.defineProperty(exports, "hasSelfDestruct", { enumerable: true, get: function () { return ast_2.hasSelfDestruct; } });
Object.defineProperty(exports, "isOldSolidityVersion", { enumerable: true, get: function () { return ast_2.isOldSolidityVersion; } });
Object.defineProperty(exports, "findPublicStateVariables", { enumerable: true, get: function () { return ast_2.findPublicStateVariables; } });
Object.defineProperty(exports, "findUnprotectedFunctions", { enumerable: true, get: function () { return ast_2.findUnprotectedFunctions; } });
Object.defineProperty(exports, "findLoopsWithExternalCalls", { enumerable: true, get: function () { return ast_2.findLoopsWithExternalCalls; } });
Object.defineProperty(exports, "findDivisionBeforeMultiplication", { enumerable: true, get: function () { return ast_2.findDivisionBeforeMultiplication; } });
Object.defineProperty(exports, "getPragmaSolidityVersion", { enumerable: true, get: function () { return ast_2.getPragmaSolidityVersion; } });
if (require.main === module) {
    main();
}
//# sourceMappingURL=index.js.map