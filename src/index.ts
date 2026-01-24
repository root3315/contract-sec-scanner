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

import * as fs from 'fs';
import * as path from 'path';
import { SecurityScanner, createScanner } from './scanner';
import type { ScannerOptions } from './scanner';
import type { Severity } from './rules';
import { SECURITY_RULES, getAllCategories, getRulesByCategory } from './rules';
import type { ScanResult, Finding } from './utils';
import {
  readSolidityFile,
  findSolidityFiles,
  formatFinding,
  formatSummary,
  resultsToJson,
  isValidSolidity,
  extractContractNames
} from './utils';

const VERSION = '1.0.0';

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

function printBanner(): void {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║           Contract Security Scanner v${VERSION}              ║
║     Solidity Smart Contract Vulnerability Detection       ║
╚═══════════════════════════════════════════════════════════╝
`);
}

function printHelp(): void {
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
  --verbose         Show detailed scan information

EXAMPLES:
  contract-sec-scanner ./contracts/Token.sol
  contract-sec-scanner ./src/contracts --format json -o report.json
  contract-sec-scanner . --min-sev high --exclude INTEGER-001
  contract-sec-scanner ./defi --category "Reentrancy,Access Control"

AVAILABLE CATEGORIES:
  ${getAllCategories().join(', ')}

RULE COUNTS BY SEVERITY:
  Critical:  ${SECURITY_RULES.filter(r => r.severity === 'critical').length}
  High:      ${SECURITY_RULES.filter(r => r.severity === 'high').length}
  Medium:    ${SECURITY_RULES.filter(r => r.severity === 'medium').length}
  Low:       ${SECURITY_RULES.filter(r => r.severity === 'low').length}
  Info:      ${SECURITY_RULES.filter(r => r.severity === 'info').length}
`);
}

function parseArgs(args: string[]): CliOptions {
  const options: CliOptions = {
    help: false,
    version: false,
    output: '',
    format: 'text',
    exclude: [],
    minSeverity: 'info',
    categories: [],
    verbose: false,
    deepScan: false,
    noSnippets: false
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
        const sev = args[++i]?.toLowerCase() as Severity;
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
      case '--verbose':
        options.verbose = true;
        break;
    }

    i++;
  }

  return options;
}

function getTargetPath(args: string[]): string | null {
  for (const arg of args) {
    if (!arg.startsWith('-')) {
      return arg;
    }
  }
  return null;
}

function runDeepAnalysis(scanner: SecurityScanner, source: string): ScanResult[] {
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

function scanTarget(targetPath: string, options: CliOptions): ScanResult[] {
  const scannerOptions: ScannerOptions = {
    excludeRules: options.exclude,
    minSeverity: options.minSeverity,
    includeSnippets: !options.noSnippets,
    scanComments: false
  };

  const scanner = createScanner(scannerOptions);
  const results: ScanResult[] = [];

  const resolvedPath = path.resolve(targetPath);
  
  if (!fs.existsSync(resolvedPath)) {
    console.error(`Error: Path does not exist: ${resolvedPath}`);
    process.exit(1);
  }

  const solidityFiles = findSolidityFiles(resolvedPath, ['node_modules', '.git', 'dist', 'build']);
  
  if (solidityFiles.length === 0) {
    console.error(`No Solidity files found in: ${resolvedPath}`);
    process.exit(1);
  }

  if (options.verbose) {
    console.log(`Found ${solidityFiles.length} Solidity file(s) to scan...\n`);
  }

  for (const filePath of solidityFiles) {
    const fileResult = readSolidityFile(filePath);
    
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
      const contracts = extractContractNames(fileResult.content);
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
  }

  return results;
}

function outputResults(results: ScanResult[], options: CliOptions): void {
  let output: string;

  if (options.format === 'json') {
    output = resultsToJson(results);
  } else {
    const parts: string[] = [];
    
    for (const result of results) {
      if (result.findings.length > 0) {
        for (const finding of result.findings) {
          parts.push(formatFinding(finding, result.filePath));
        }
      }
    }

    output = parts.join('\n') + formatSummary(results);
  }

  if (options.output) {
    const outputPath = path.resolve(options.output);
    fs.writeFileSync(outputPath, output, 'utf-8');
    console.log(`Results written to: ${outputPath}`);
  } else {
    console.log(output);
  }
}

function main(): void {
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
  const criticalCount = results.reduce(
    (sum, r) => sum + r.findings.filter((f: Finding) => f.severity === 'critical').length,
    0
  );
  const highCount = results.reduce(
    (sum, r) => sum + r.findings.filter((f: Finding) => f.severity === 'high').length,
    0
  );

  outputResults(results, options);

  if (criticalCount > 0 || highCount > 0) {
    console.log(`\n⚠️  Found ${criticalCount} critical and ${highCount} high severity issues.`);
    console.log('Review and fix these vulnerabilities before deploying to mainnet.');
    process.exit(1);
  } else if (totalFindings > 0) {
    console.log(`\n✓ Scan complete. Found ${totalFindings} issue(s) to review.`);
    process.exit(0);
  } else {
    console.log('\n✓ No security issues detected.');
    process.exit(0);
  }
}

export {
  SecurityScanner,
  createScanner,
  SECURITY_RULES,
  getAllCategories,
  getRulesByCategory,
  readSolidityFile,
  findSolidityFiles,
  formatFinding,
  formatSummary,
  resultsToJson
};

export type {
  ScannerOptions,
  ScanResult,
  Finding,
  Severity,
  CliOptions
};

if (require.main === module) {
  main();
}
