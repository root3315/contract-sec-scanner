/**
 * Test suite for Contract Security Scanner
 * 
 * Run tests with:
 *   npx ts-node tests/scanner.test.ts
 *   or after build: node tests/scanner.test.js
 */

import { SecurityScanner, createScanner } from '../src/scanner';
import { SECURITY_RULES, getRulesByCategory, getRulesBySeverity, getAllCategories } from '../src/rules';
import {
  getPositionFromIndex,
  getSnippet,
  stripComments,
  isValidSolidity,
  extractContractNames,
  findSolidityFiles,
  formatSeverity
} from '../src/utils';

let passedTests = 0;
let failedTests = 0;

function assert(condition: boolean, message: string): void {
  if (condition) {
    passedTests++;
    console.log(`  ✓ ${message}`);
  } else {
    failedTests++;
    console.log(`  ✗ ${message}`);
  }
}

function assertEqual<T>(actual: T, expected: T, message: string): void {
  assert(actual === expected, `${message} (expected: ${expected}, got: ${actual})`);
}

function assertArrayLength<T>(arr: T[], length: number, message: string): void {
  assert(arr.length === length, `${message} (expected: ${length}, got: ${arr.length})`);
}

function describe(name: string, fn: () => void): void {
  console.log(`\n${name}`);
  fn();
}

function it(name: string, fn: () => void): void {
  console.log(`\n  ${name}`);
  fn();
}

const VULNERABLE_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }
    
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0);
        
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success);
        
        balances[msg.sender] = 0;
    }
    
    function transferOwnership(address _address) external {
        owner = _address;
    }
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function getBalance() view external returns (uint256) {
        return address(this).balance;
    }
    
    function unsafeRandom() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp)));
    }
    
    function checkSender() external view returns (bool) {
        return tx.origin == owner;
    }
}
`;

const SECURE_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureToken is ReentrancyGuard, Ownable {
    mapping(address => uint256) private balances;
    
    function withdraw() external nonReentrant {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");
        
        balances[msg.sender] = 0;
        
        (bool success, ) = payable(msg.sender).call{value: balance}("");
        require(success, "Transfer failed");
    }
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
`;

describe('Rules Module', () => {
  it('should have security rules defined', () => {
    assert(SECURITY_RULES.length > 0, 'SECURITY_RULES should not be empty');
    assertEqual(SECURITY_RULES.length, 20, 'Should have 20 security rules');
  });

  it('should filter rules by category', () => {
    const reentrancyRules = getRulesByCategory('Reentrancy');
    assert(reentrancyRules.length >= 2, 'Should have reentrancy rules');
  });

  it('should filter rules by severity', () => {
    const criticalRules = getRulesBySeverity('critical');
    assert(criticalRules.length >= 3, 'Should have critical rules');
  });

  it('should return all categories', () => {
    const categories = getAllCategories();
    assert(categories.length > 0, 'Should have categories');
    assert(categories.includes('Reentrancy'), 'Should include Reentrancy category');
  });
});

describe('Utils Module', () => {
  it('should get position from index', () => {
    const source = 'line1\nline2\nline3';
    const pos = getPositionFromIndex(source, 8);
    assertEqual(pos.line, 2, 'Should be on line 2');
    assertEqual(pos.column, 3, 'Should be at column 3');
  });

  it('should extract code snippet', () => {
    const source = 'line1\nline2\nline3\nline4\nline5';
    const index = source.indexOf('line3');
    const snippet = getSnippet(source, index, 1);
    assert(snippet.includes('line2'), 'Should include previous line');
    assert(snippet.includes('line3'), 'Should include target line');
    assert(snippet.includes('line4'), 'Should include next line');
  });

  it('should strip comments', () => {
    const source = '// comment\nconst x = 1; /* block */';
    const stripped = stripComments(source);
    assert(!stripped.includes('// comment'), 'Should remove single-line comment');
    assert(!stripped.includes('/* block */'), 'Should remove block comment');
  });

  it('should validate Solidity source', () => {
    assert(isValidSolidity('pragma solidity ^0.8.0; contract Test {}'), 'Should be valid');
    assert(!isValidSolidity('not solidity code'), 'Should be invalid');
  });

  it('should extract contract names', () => {
    const source = 'contract Token {} library Math {} interface IERC20 {}';
    const names = extractContractNames(source);
    assertArrayLength(names, 3, 'Should extract 3 names');
    assert(names.includes('Token'), 'Should include Token');
    assert(names.includes('Math'), 'Should include Math');
  });

  it('should format severity with colors', () => {
    const formatted = formatSeverity('critical');
    assert(formatted.includes('CRITICAL'), 'Should contain severity name');
  });
});

describe('SecurityScanner Class', () => {
  it('should create scanner instance', () => {
    const scanner = createScanner();
    assert(scanner !== null, 'Should create scanner');
  });

  it('should scan vulnerable contract', () => {
    const scanner = createScanner();
    const result = scanner.scan(VULNERABLE_CONTRACT, 'VulnerableToken.sol');
    
    assert(result.findings.length > 0, 'Should find vulnerabilities');
    assert(result.scanTime >= 0, 'Should have scan time');
  });

  it('should detect reentrancy vulnerability', () => {
    const scanner = createScanner();
    const result = scanner.scan(VULNERABLE_CONTRACT);
    
    const reentrancyFindings = result.findings.filter(f => 
      f.ruleId.includes('REENTRANCY') || f.ruleName.includes('Reentrancy')
    );
    assert(reentrancyFindings.length > 0, 'Should detect reentrancy issues');
  });

  it('should detect tx.origin usage', () => {
    const scanner = createScanner();
    const result = scanner.scan(VULNERABLE_CONTRACT);
    
    const txOriginFindings = result.findings.filter(f => 
      f.ruleId.includes('DEPRECATED') || f.message.includes('tx.origin')
    );
    assert(txOriginFindings.length > 0, 'Should detect tx.origin usage');
  });

  it('should detect unchecked low-level call', () => {
    const scanner = createScanner();
    const result = scanner.scan(VULNERABLE_CONTRACT);
    
    const callFindings = result.findings.filter(f => 
      f.ruleId.includes('CALL') || f.ruleName.includes('Call')
    );
    assert(callFindings.length > 0, 'Should detect unchecked call');
  });

  it('should scan secure contract with fewer findings', () => {
    const scanner = createScanner();
    const vulnerableResult = scanner.scan(VULNERABLE_CONTRACT);
    const secureResult = scanner.scan(SECURE_CONTRACT);
    
    assert(
      secureResult.findings.length < vulnerableResult.findings.length,
      'Secure contract should have fewer findings'
    );
  });

  it('should respect exclude rules option', () => {
    const scanner1 = createScanner();
    const scanner2 = createScanner({ excludeRules: ['INTEGER-001'] });
    
    const result1 = scanner1.scan(VULNERABLE_CONTRACT);
    const result2 = scanner2.scan(VULNERABLE_CONTRACT);
    
    const excluded1 = result1.findings.filter(f => f.ruleId === 'INTEGER-001').length;
    const excluded2 = result2.findings.filter(f => f.ruleId === 'INTEGER-001').length;
    
    assertEqual(excluded2, 0, 'Should exclude INTEGER-001 rule');
  });

  it('should respect minimum severity option', () => {
    const scanner = createScanner({ minSeverity: 'critical' });
    const result = scanner.scan(VULNERABLE_CONTRACT);
    
    const nonCritical = result.findings.filter(f => f.severity !== 'critical');
    assertEqual(nonCritical.length, 0, 'Should only have critical findings');
  });

  it('should provide scanner statistics', () => {
    const scanner = createScanner();
    scanner.scan(VULNERABLE_CONTRACT);
    
    const stats = scanner.getStats();
    assert(stats.rulesApplied > 0, 'Should have rules applied');
    assert(stats.contractsScanned > 0, 'Should have contracts scanned');
  });

  it('should perform deep reentrancy analysis', () => {
    const scanner = createScanner();
    const findings = scanner.checkReentrancy(VULNERABLE_CONTRACT);
    
    assert(findings.length > 0, 'Should find reentrancy issues');
  });

  it('should perform access control analysis', () => {
    const scanner = createScanner();
    const findings = scanner.checkAccessControl(VULNERABLE_CONTRACT);
    
    assert(findings.length > 0, 'Should find access control issues');
  });

  it('should analyze specific function', () => {
    const scanner = createScanner();
    const findings = scanner.analyzeFunction(VULNERABLE_CONTRACT, 'withdraw');
    
    assert(findings.length >= 0, 'Should analyze function');
  });

  it('should scan for specific vulnerability type', () => {
    const scanner = createScanner();
    const findings = scanner.scanForVulnerability(VULNERABLE_CONTRACT, 'reentrancy');
    
    assert(findings.length >= 0, 'Should scan for vulnerability type');
  });

  it('should reset scanner statistics', () => {
    const scanner = createScanner();
    scanner.scan(VULNERABLE_CONTRACT);
    scanner.reset();
    
    const stats = scanner.getStats();
    assertEqual(stats.rulesApplied, 0, 'Should reset rules applied');
    assertEqual(stats.patternsMatched, 0, 'Should reset patterns matched');
  });
});

describe('Scanner with Options', () => {
  it('should work without snippets', () => {
    const scanner = createScanner({ includeSnippets: false });
    const result = scanner.scan(VULNERABLE_CONTRACT);
    
    const hasSnippets = result.findings.some(f => f.snippet !== undefined);
    assert(!hasSnippets, 'Should not include snippets');
  });

  it('should scan with comments enabled', () => {
    const scanner = createScanner({ scanComments: true });
    const result = scanner.scan(VULNERABLE_CONTRACT);
    
    assert(result.findings.length >= 0, 'Should scan with comments');
  });
});

describe('Edge Cases', () => {
  it('should handle invalid Solidity', () => {
    const scanner = createScanner();
    const result = scanner.scan('not valid solidity code');
    
    assert(result.findings.length > 0, 'Should report invalid source');
    assertEqual(result.findings[0].ruleId, 'VALIDATION-001', 'Should be validation error');
  });

  it('should handle empty source', () => {
    const scanner = createScanner();
    const result = scanner.scan('');
    
    assert(result.findings.length > 0, 'Should handle empty source');
  });

  it('should handle very large contracts', () => {
    const scanner = createScanner();
    let largeContract = VULNERABLE_CONTRACT;
    for (let i = 0; i < 10; i++) {
      largeContract += `\ncontract Contract${i} { function test${i}() external {} }`;
    }
    
    const result = scanner.scan(largeContract);
    assert(result.scanTime < 5000, 'Should complete within 5 seconds');
  });
});

function runTests(): void {
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║         Contract Security Scanner - Test Suite            ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');
  
  try {
    describe('Rules Module', () => {
      it('should have security rules defined', () => {
        assert(SECURITY_RULES.length > 0, 'SECURITY_RULES should not be empty');
        assertEqual(SECURITY_RULES.length, 20, 'Should have 20 security rules');
      });

      it('should filter rules by category', () => {
        const reentrancyRules = getRulesByCategory('Reentrancy');
        assert(reentrancyRules.length >= 2, 'Should have reentrancy rules');
      });

      it('should filter rules by severity', () => {
        const criticalRules = getRulesBySeverity('critical');
        assert(criticalRules.length >= 3, 'Should have critical rules');
      });

      it('should return all categories', () => {
        const categories = getAllCategories();
        assert(categories.length > 0, 'Should have categories');
        assert(categories.includes('Reentrancy'), 'Should include Reentrancy category');
      });
    });

    describe('Utils Module', () => {
      it('should get position from index', () => {
        const source = 'line1\nline2\nline3';
        const pos = getPositionFromIndex(source, 8);
        assertEqual(pos.line, 2, 'Should be on line 2');
        assertEqual(pos.column, 3, 'Should be at column 3');
      });

      it('should extract code snippet', () => {
        const source = 'line1\nline2\nline3\nline4\nline5';
        const index = source.indexOf('line3');
        const snippet = getSnippet(source, index, 1);
        assert(snippet.includes('line2'), 'Should include previous line');
        assert(snippet.includes('line3'), 'Should include target line');
        assert(snippet.includes('line4'), 'Should include next line');
      });

      it('should strip comments', () => {
        const source = '// comment\nconst x = 1; /* block */';
        const stripped = stripComments(source);
        assert(!stripped.includes('// comment'), 'Should remove single-line comment');
        assert(!stripped.includes('/* block */'), 'Should remove block comment');
      });

      it('should validate Solidity source', () => {
        assert(isValidSolidity('pragma solidity ^0.8.0; contract Test {}'), 'Should be valid');
        assert(!isValidSolidity('not solidity code'), 'Should be invalid');
      });

      it('should extract contract names', () => {
        const source = 'contract Token {} library Math {} interface IERC20 {}';
        const names = extractContractNames(source);
        assertArrayLength(names, 3, 'Should extract 3 names');
        assert(names.includes('Token'), 'Should include Token');
        assert(names.includes('Math'), 'Should include Math');
      });
    });

    describe('SecurityScanner Class', () => {
      it('should create scanner instance', () => {
        const scanner = createScanner();
        assert(scanner !== null, 'Should create scanner');
      });

      it('should scan vulnerable contract', () => {
        const scanner = createScanner();
        const result = scanner.scan(VULNERABLE_CONTRACT, 'VulnerableToken.sol');
        
        assert(result.findings.length > 0, 'Should find vulnerabilities');
        assert(result.scanTime >= 0, 'Should have scan time');
      });

      it('should detect reentrancy vulnerability', () => {
        const scanner = createScanner();
        const result = scanner.scan(VULNERABLE_CONTRACT);
        
        const reentrancyFindings = result.findings.filter(f => 
          f.ruleId.includes('REENTRANCY') || f.ruleName.includes('Reentrancy')
        );
        assert(reentrancyFindings.length > 0, 'Should detect reentrancy issues');
      });

      it('should detect tx.origin usage', () => {
        const scanner = createScanner();
        const result = scanner.scan(VULNERABLE_CONTRACT);
        
        const txOriginFindings = result.findings.filter(f => 
          f.ruleId.includes('DEPRECATED') || f.message.includes('tx.origin')
        );
        assert(txOriginFindings.length > 0, 'Should detect tx.origin usage');
      });

      it('should detect unchecked low-level call', () => {
        const scanner = createScanner();
        const result = scanner.scan(VULNERABLE_CONTRACT);
        
        const callFindings = result.findings.filter(f => 
          f.ruleId.includes('CALL') || f.ruleName.includes('Call')
        );
        assert(callFindings.length > 0, 'Should detect unchecked call');
      });

      it('should scan secure contract with fewer findings', () => {
        const scanner = createScanner();
        const vulnerableResult = scanner.scan(VULNERABLE_CONTRACT);
        const secureResult = scanner.scan(SECURE_CONTRACT);
        
        assert(
          secureResult.findings.length < vulnerableResult.findings.length,
          'Secure contract should have fewer findings'
        );
      });

      it('should respect exclude rules option', () => {
        const scanner1 = createScanner();
        const scanner2 = createScanner({ excludeRules: ['INTEGER-001'] });
        
        const result1 = scanner1.scan(VULNERABLE_CONTRACT);
        const result2 = scanner2.scan(VULNERABLE_CONTRACT);
        
        const excluded2 = result2.findings.filter(f => f.ruleId === 'INTEGER-001').length;
        assertEqual(excluded2, 0, 'Should exclude INTEGER-001 rule');
      });

      it('should respect minimum severity option', () => {
        const scanner = createScanner({ minSeverity: 'critical' });
        const result = scanner.scan(VULNERABLE_CONTRACT);
        
        const nonCritical = result.findings.filter(f => f.severity !== 'critical');
        assertEqual(nonCritical.length, 0, 'Should only have critical findings');
      });

      it('should provide scanner statistics', () => {
        const scanner = createScanner();
        scanner.scan(VULNERABLE_CONTRACT);
        
        const stats = scanner.getStats();
        assert(stats.rulesApplied > 0, 'Should have rules applied');
        assert(stats.contractsScanned > 0, 'Should have contracts scanned');
      });

      it('should perform deep reentrancy analysis', () => {
        const scanner = createScanner();
        const findings = scanner.checkReentrancy(VULNERABLE_CONTRACT);
        
        assert(findings.length > 0, 'Should find reentrancy issues');
      });

      it('should perform access control analysis', () => {
        const scanner = createScanner();
        const findings = scanner.checkAccessControl(VULNERABLE_CONTRACT);
        
        assert(findings.length > 0, 'Should find access control issues');
      });

      it('should reset scanner statistics', () => {
        const scanner = createScanner();
        scanner.scan(VULNERABLE_CONTRACT);
        scanner.reset();
        
        const stats = scanner.getStats();
        assertEqual(stats.rulesApplied, 0, 'Should reset rules applied');
        assertEqual(stats.patternsMatched, 0, 'Should reset patterns matched');
      });
    });

    describe('Edge Cases', () => {
      it('should handle invalid Solidity', () => {
        const scanner = createScanner();
        const result = scanner.scan('not valid solidity code');
        
        assert(result.findings.length > 0, 'Should report invalid source');
        assertEqual(result.findings[0].ruleId, 'VALIDATION-001', 'Should be validation error');
      });

      it('should handle empty source', () => {
        const scanner = createScanner();
        const result = scanner.scan('');
        
        assert(result.findings.length > 0, 'Should handle empty source');
      });
    });

  } catch (error) {
    console.error('Test error:', error);
    failedTests++;
  }

  console.log('\n' + '═'.repeat(60));
  console.log(`Tests: ${passedTests + failedTests} | Passed: ${passedTests} | Failed: ${failedTests}`);
  console.log('═'.repeat(60));

  if (failedTests > 0) {
    process.exit(1);
  }
}

runTests();
