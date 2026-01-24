"use strict";
/**
 * Security rule definitions for Solidity smart contract scanning.
 * Each rule defines a pattern to detect and its severity level.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SEVERITY_ORDER = exports.SECURITY_RULES = void 0;
exports.getRulesByCategory = getRulesByCategory;
exports.getRulesBySeverity = getRulesBySeverity;
exports.getRuleById = getRuleById;
exports.getAllCategories = getAllCategories;
exports.SECURITY_RULES = [
    {
        id: 'REENTRANCY-001',
        name: 'Reentrancy Vulnerability',
        description: 'Function performs external call before state update, enabling reentrancy attacks',
        severity: 'critical',
        pattern: /\bcall\b\s*\{[^}]*\}[^}]*\b(?:balance|totalSupply|allowance)\b\s*=/i,
        category: 'Reentrancy',
        recommendation: 'Use checks-effects-interactions pattern. Update state before external calls.',
        swcId: 'SWC-107'
    },
    {
        id: 'REENTRANCY-002',
        name: 'Missing Reentrancy Guard',
        description: 'State-changing function lacks nonReentrant modifier',
        severity: 'high',
        pattern: /function\s+\w+\s*\([^)]*\)\s*(?:public|external)\s*(?!.*nonReentrant)/i,
        category: 'Reentrancy',
        recommendation: 'Add nonReentrant modifier from OpenZeppelin to state-changing functions.',
        swcId: 'SWC-107'
    },
    {
        id: 'INTEGER-001',
        name: 'Unchecked Integer Arithmetic',
        description: 'Arithmetic operation without SafeMath or Solidity 0.8+ checked arithmetic',
        severity: 'medium',
        pattern: /pragma\s+solidity\s+\^?0\.[4-7]\.[0-9]+/,
        category: 'Integer Overflow',
        recommendation: 'Use Solidity 0.8+ or SafeMath library for arithmetic operations.',
        swcId: 'SWC-101'
    },
    {
        id: 'INTEGER-002',
        name: 'Potential Integer Overflow',
        description: 'Addition operation that may overflow in older Solidity versions',
        severity: 'high',
        pattern: /(?<!require\([^)]*)\b[a-zA-Z_]\w*\s*\+\s*[a-zA-Z_]\w*(?![^;]*require)/,
        category: 'Integer Overflow',
        recommendation: 'Use SafeMath.add() or Solidity 0.8+ built-in overflow protection.',
        swcId: 'SWC-101'
    },
    {
        id: 'ACCESS-001',
        name: 'Missing Access Control',
        description: 'Critical function lacks owner-only or role-based access control',
        severity: 'high',
        pattern: /function\s+(?:withdraw|transferOwnership|set[A-Z]\w*|destroy|selfdestruct)\s*\([^)]*\)\s*(?:public|external)(?!\s*(?:onlyOwner|onlyAdmin|onlyRole))/i,
        category: 'Access Control',
        recommendation: 'Add onlyOwner or appropriate access control modifier.',
        swcId: 'SWC-105'
    },
    {
        id: 'ACCESS-002',
        name: 'Unprotected Constructor',
        description: 'Constructor uses public visibility instead of internal/protected',
        severity: 'medium',
        pattern: /constructor\s*\([^)]*\)\s*public/i,
        category: 'Access Control',
        recommendation: 'Change constructor visibility to internal or remove visibility specifier.',
        swcId: 'SWC-105'
    },
    {
        id: 'CALL-001',
        name: 'Unchecked Low-Level Call',
        description: 'Low-level call result is not checked for success',
        severity: 'critical',
        pattern: /\b(?:call|delegatecall|staticcall)(?:\s*\{[^}]*\})?\s*\([^)]*\)\s*(?:;|=[^;]*)/,
        category: 'External Calls',
        recommendation: 'Always check the return value of low-level calls.',
        swcId: 'SWC-104'
    },
    {
        id: 'CALL-002',
        name: 'Use of Unsafe Transfer',
        description: 'Using transfer() or send() which may fail with custom receive functions',
        severity: 'medium',
        pattern: /\.transfer\s*\(|\.send\s*\(/,
        category: 'External Calls',
        recommendation: 'Use call{value: amount}("") with proper error handling.',
        swcId: 'SWC-104'
    },
    {
        id: 'CALL-003',
        name: 'Delegatecall to Untrusted Target',
        description: 'Delegatecall with dynamic or user-controlled address',
        severity: 'critical',
        pattern: /delegatecall\s*\([^)]*(?:msg\.sender|_address|target|impl)/i,
        category: 'External Calls',
        recommendation: 'Only use delegatecall with trusted, immutable addresses.',
        swcId: 'SWC-112'
    },
    {
        id: 'TIMESTAMP-001',
        name: 'Timestamp Dependency',
        description: 'Logic depends on block.timestamp which miners can manipulate',
        severity: 'medium',
        pattern: /block\.timestamp\s*(?:[<>=!]+|\+\s*\d+|-\s*\d+)/,
        category: 'Timestamp Manipulation',
        recommendation: 'Avoid using block.timestamp for critical logic. Use block.number for time estimates.',
        swcId: 'SWC-116'
    },
    {
        id: 'RANDOM-001',
        name: 'Weak Randomness',
        description: 'Using block properties for randomness which is predictable',
        severity: 'high',
        pattern: /(?:block\.(?:timestamp|number|difficulty)|keccak256\s*\([^)]*block\.)/i,
        category: 'Randomness',
        recommendation: 'Use Chainlink VRF or commit-reveal schemes for randomness.',
        swcId: 'SWC-120'
    },
    {
        id: 'DENIAL-001',
        name: 'Unbounded Loop',
        description: 'Loop iterates over dynamic array without limit, potential DoS',
        severity: 'high',
        pattern: /for\s*\(\s*[^;]*;\s*[^;]*<\s*(?:\w+\.length|length)\s*;\s*[^)]*\)/,
        category: 'Denial of Service',
        recommendation: 'Limit loop iterations or use pull pattern for batch operations.',
        swcId: 'SWC-113'
    },
    {
        id: 'DENIAL-002',
        name: 'Unchecked External Call in Loop',
        description: 'External call inside loop may cause partial execution failure',
        severity: 'high',
        pattern: /for\s*\([^)]*\)\s*\{[^}]*\b(?:call|transfer|send)\s*\(/s,
        category: 'Denial of Service',
        recommendation: 'Avoid external calls in loops. Use pull pattern instead.',
        swcId: 'SWC-113'
    },
    {
        id: 'FRONT-001',
        name: 'Missing Slippage Protection',
        description: 'Swap/trade function without slippage check',
        severity: 'medium',
        pattern: /function\s+(?:swap|trade|exchange)\s*\([^)]*(?!.*slippage|.*minAmount|.*minimum)/i,
        category: 'Front-running',
        recommendation: 'Add slippage protection with minimum amount parameters.',
        swcId: 'SWC-114'
    },
    {
        id: 'LOGIC-001',
        name: 'Division Before Multiplication',
        description: 'Division before multiplication may cause precision loss',
        severity: 'low',
        pattern: /\b\w+\s*\/\s*\w+\s*\*\s*\w+/,
        category: 'Logic Error',
        recommendation: 'Multiply before divide to maintain precision: (a * b) / c',
        swcId: 'SWC-101'
    },
    {
        id: 'LOGIC-002',
        name: 'Incorrect Equality Check',
        description: 'Using == for address comparison instead of !=',
        severity: 'low',
        pattern: /if\s*\(\s*msg\.sender\s*==\s*address\(0\)\s*\)/,
        category: 'Logic Error',
        recommendation: 'Check for non-zero address: msg.sender != address(0)',
        swcId: 'SWC-101'
    },
    {
        id: 'DEPRECATED-001',
        name: 'Deprecated Function Usage',
        description: 'Using deprecated Solidity functions',
        severity: 'medium',
        pattern: /\bsha3\s*\(|\bsuicide\s*\(/i,
        category: 'Best Practices',
        recommendation: 'Use keccak256() instead of sha3(), selfdestruct() instead of suicide().',
        swcId: 'SWC-111'
    },
    {
        id: 'DEPRECATED-002',
        name: 'Deprecated tx.origin Check',
        description: 'Using tx.origin for authorization which is vulnerable to phishing',
        severity: 'critical',
        pattern: /tx\.origin\s*(?:==|!=)/,
        category: 'Access Control',
        recommendation: 'Use msg.sender instead of tx.origin for authorization checks.',
        swcId: 'SWC-115'
    },
    {
        id: 'STORAGE-001',
        name: 'Public State Variable',
        description: 'State variable is public, creating automatic getter',
        severity: 'info',
        pattern: /(?:uint|address|bool|bytes|string|int)\s+(?:public\s+)?\w+\s*;/,
        category: 'Information Exposure',
        recommendation: 'Consider making sensitive state variables private or internal.',
        swcId: 'SWC-100'
    },
    {
        id: 'STORAGE-002',
        name: 'Uninitialized Storage Pointer',
        description: 'Local variable may unintentionally reference storage',
        severity: 'high',
        pattern: /(?:mapping|struct)\s+\w+\s+storage\s+\w+\s*=/,
        category: 'Storage',
        recommendation: 'Explicitly declare storage or memory keywords.',
        swcId: 'SWC-109'
    }
];
exports.SEVERITY_ORDER = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
};
function getRulesByCategory(category) {
    return exports.SECURITY_RULES.filter(rule => rule.category === category);
}
function getRulesBySeverity(severity) {
    return exports.SECURITY_RULES.filter(rule => rule.severity === severity);
}
function getRuleById(id) {
    return exports.SECURITY_RULES.find(rule => rule.id === id);
}
function getAllCategories() {
    const categories = new Set(exports.SECURITY_RULES.map(rule => rule.category));
    return Array.from(categories).sort();
}
//# sourceMappingURL=rules.js.map