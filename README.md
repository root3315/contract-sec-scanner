# Contract Security Scanner

A comprehensive static analysis tool for detecting security vulnerabilities in Solidity smart contracts.

## Features

- **20 Security Rules** covering common vulnerability patterns
- **Pattern-based Detection** using regular expressions for fast scanning
- **Severity Classification** (Critical, High, Medium, Low, Info)
- **Deep Analysis** mode for thorough reentrancy and access control checks
- **Multiple Output Formats** (text and JSON)
- **Batch Scanning** of directories with multiple contracts

## Installation

```bash
# Clone or download the project
cd contract-sec-scanner

# Install dependencies
npm install

# Build the project
npm run build
```

## Usage

### Basic Scan

Scan a single Solidity file:

```bash
npx ts-node src/index.ts ./contracts/Token.sol
```

Scan a directory:

```bash
npx ts-node src/index.ts ./src/contracts/
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-v, --version` | Show version number |
| `-o, --output <file>` | Write results to file |
| `-f, --format <text|json>` | Output format (default: text) |
| `-e, --exclude <rules>` | Exclude rule IDs (comma-separated) |
| `-m, --min-sev <level>` | Minimum severity level |
| `-c, --category <cats>` | Scan specific categories only |
| `--deep` | Enable deep analysis mode |
| `--no-snippets` | Don't include code snippets |
| `--verbose` | Show detailed scan information |

### Examples

```bash
# Scan with JSON output
npx ts-node src/index.ts ./contracts -f json -o report.json

# Only show critical and high severity issues
npx ts-node src/index.ts ./contracts --min-sev high

# Exclude specific rules
npx ts-node src/index.ts ./contracts --exclude INTEGER-001,LOGIC-001

# Deep analysis for thorough checking
npx ts-node src/index.ts ./defi-protocol --deep --verbose

# Scan only reentrancy and access control issues
npx ts-node src/index.ts ./contracts --category "Reentrancy,Access Control"
```

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Entry Point                         │
│                         (index.ts)                           │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
    ┌─────────────────┐ ┌─────────────┐ ┌───────────┐
    │    Scanner      │ │    Rules    │ │   Utils   │
    │   (scanner.ts)  │ │  (rules.ts) │ │ (utils.ts)│
    └─────────────────┘ └─────────────┘ └───────────┘
```

### Detection Process

1. **File Discovery**: Recursively finds all `.sol` files in the target path
2. **Source Parsing**: Reads and validates Solidity source code
3. **Rule Application**: Applies regex patterns from security rules
4. **Deep Analysis** (optional): Performs additional context-aware checks
5. **Result Aggregation**: Collects and sorts findings by severity
6. **Output**: Formats results for console or file output

### Security Rules

The scanner includes 20 rules across multiple categories:

| Category | Rules | Examples |
|----------|-------|----------|
| Reentrancy | 2 | Missing nonReentrant, State change after call |
| Integer Overflow | 2 | Unchecked arithmetic, Old Solidity version |
| Access Control | 3 | Missing onlyOwner, tx.origin usage |
| External Calls | 3 | Unchecked call, Unsafe transfer |
| Timestamp | 1 | block.timestamp manipulation |
| Randomness | 1 | Weak randomness sources |
| Denial of Service | 2 | Unbounded loops |
| Logic Errors | 2 | Division before multiplication |
| Best Practices | 4 | Deprecated functions, Public variables |

### Severity Levels

- **Critical**: Immediate security risk, must fix before deployment
- **High**: Significant vulnerability, should fix before deployment
- **Medium**: Potential issue, review recommended
- **Low**: Minor concern, consider fixing
- **Info**: Informational, no immediate action required

## Programmatic Usage

```typescript
import { createScanner, SECURITY_RULES } from './src/index';

// Create scanner with options
const scanner = createScanner({
  minSeverity: 'high',
  includeSnippets: true
});

// Scan source code
const result = scanner.scan(sourceCode, 'MyContract.sol');

// Access findings
for (const finding of result.findings) {
  console.log(`${finding.severity}: ${finding.ruleName}`);
  console.log(`  Line ${finding.line}: ${finding.message}`);
}

// Deep analysis
const reentrancyIssues = scanner.checkReentrancy(sourceCode);
const accessIssues = scanner.checkAccessControl(sourceCode);

// Get statistics
const stats = scanner.getStats();
console.log(`Scanned ${stats.contractsScanned} contracts`);
```

## Running Tests

```bash
# Run tests with ts-node
npx ts-node tests/scanner.test.ts

# Or build first and run compiled tests
npm run build
node tests/scanner.test.js
```

## Project Structure

```
contract-sec-scanner/
├── src/
│   ├── index.ts      # CLI entry point and exports
│   ├── scanner.ts    # Core scanning logic
│   ├── rules.ts      # Security rule definitions
│   └── utils.ts      # Helper utilities
├── tests/
│   └── scanner.test.ts
├── package.json
├── tsconfig.json
└── README.md
```

## Limitations

- **Static Analysis Only**: Does not execute code or detect runtime issues
- **Pattern-Based**: May produce false positives or miss complex vulnerabilities
- **No AST Parsing**: Uses regex patterns instead of full Solidity parser
- **Single File Scope**: Does not analyze cross-contract interactions

## Contributing

To add new security rules:

1. Add rule definition to `src/rules.ts`
2. Include pattern, severity, and recommendation
3. Test against known vulnerable contracts
4. Update documentation

## License

MIT
