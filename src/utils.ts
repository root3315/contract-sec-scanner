/**
 * Utility functions for the contract security scanner.
 * Provides file operations, formatting, and helper methods.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { Severity } from './rules';

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
export function readSolidityFile(filePath: string): FileResult {
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
  } catch (err) {
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
export function findSolidityFiles(dirPath: string, excludeDirs: string[] = []): string[] {
  const solidityFiles: string[] = [];
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
    } else if (entry.isFile() && entry.name.endsWith('.sol')) {
      solidityFiles.push(fullPath);
    }
  }

  return solidityFiles;
}

/**
 * Get line and column number from a character index in source code.
 */
export function getPositionFromIndex(source: string, index: number): { line: number; column: number } {
  const lines = source.substring(0, index).split('\n');
  const line = lines.length;
  const column = lines[lines.length - 1].length + 1;
  return { line, column };
}

/**
 * Extract a code snippet around a specific position.
 */
export function getSnippet(source: string, index: number, contextLines: number = 2): string {
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
export function formatSeverity(severity: Severity): string {
  const colors: Record<Severity, string> = {
    critical: '\x1b[31m\x1b[1m', // Bold Red
    high: '\x1b[31m',            // Red
    medium: '\x1b[33m',          // Yellow
    low: '\x1b[36m',             // Cyan
    info: '\x1b[34m'             // Blue
  };
  const reset = '\x1b[0m';
  return `${colors[severity]}${severity.toUpperCase()}${reset}`;
}

/**
 * Format a finding for console output.
 */
export function formatFinding(finding: Finding, filePath: string): string {
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
export function formatSummary(results: ScanResult[]): string {
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
export function resultsToJson(results: ScanResult[]): string {
  return JSON.stringify(results, null, 2);
}

/**
 * Check if a line is a comment or empty.
 */
export function isNonCodeLine(line: string): boolean {
  const trimmed = line.trim();
  return trimmed === '' || trimmed.startsWith('//') || trimmed.startsWith('*');
}

/**
 * Remove comments from source code for analysis.
 */
export function stripComments(source: string): string {
  // Remove single-line comments
  let result = source.replace(/\/\/.*$/gm, '');
  // Remove multi-line comments
  result = result.replace(/\/\*[\s\S]*?\*\//g, '');
  return result;
}

/**
 * Validate that source code appears to be valid Solidity.
 */
export function isValidSolidity(source: string): boolean {
  const hasPragma = /pragma\s+solidity/.test(source);
  const hasContract = /\bcontract\b/.test(source);
  const hasLibrary = /\blibrary\b/.test(source);
  const hasInterface = /\binterface\b/.test(source);
  
  return hasPragma && (hasContract || hasLibrary || hasInterface);
}

/**
 * Extract contract names from source code.
 */
export function extractContractNames(source: string): string[] {
  const contractPattern = /\b(?:contract|library|interface)\s+(\w+)/g;
  const names: string[] = [];
  let match: RegExpExecArray | null;
  
  while ((match = contractPattern.exec(source)) !== null) {
    names.push(match[1]);
  }
  
  return names;
}
