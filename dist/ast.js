"use strict";
/**
 * AST-based parser for Solidity smart contract analysis.
 * Provides accurate structural analysis beyond regex pattern matching.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseSrc = parseSrc;
exports.extractASTElements = extractASTElements;
exports.findNodesByType = findNodesByType;
exports.findNodesByProperty = findNodesByProperty;
exports.hasModifier = hasModifier;
exports.hasExternalCall = hasExternalCall;
exports.hasStateWrite = hasStateWrite;
exports.hasSelfCall = hasSelfCall;
exports.hasTxOrigin = hasTxOrigin;
exports.hasTxOriginInSource = hasTxOriginInSource;
exports.hasBlockTimestamp = hasBlockTimestamp;
exports.hasBlockTimestampInSource = hasBlockTimestampInSource;
exports.hasUncheckedCall = hasUncheckedCall;
exports.hasAssembly = hasAssembly;
exports.hasAssemblyInSource = hasAssemblyInSource;
exports.hasSelfDestruct = hasSelfDestruct;
exports.hasSelfDestructInSource = hasSelfDestructInSource;
exports.hasExternalCallInSource = hasExternalCallInSource;
exports.getFunctionBodyNode = getFunctionBodyNode;
exports.getNodeChildren = getNodeChildren;
exports.isStateChangingFunction = isStateChangingFunction;
exports.isPayableFunction = isPayableFunction;
exports.hasFallbackOrReceive = hasFallbackOrReceive;
exports.getInheritanceChain = getInheritanceChain;
exports.findUnprotectedFunctions = findUnprotectedFunctions;
exports.findLoopsWithExternalCalls = findLoopsWithExternalCalls;
exports.findDivisionBeforeMultiplication = findDivisionBeforeMultiplication;
exports.getPragmaSolidityVersion = getPragmaSolidityVersion;
exports.isOldSolidityVersion = isOldSolidityVersion;
exports.findPublicStateVariables = findPublicStateVariables;
exports.findUninitializedStoragePointers = findUninitializedStoragePointers;
exports.analyzeAST = analyzeAST;
exports.parseSolidityToAST = parseSolidityToAST;
function parseSrc(src) {
    const parts = src.split(':');
    const start = parseInt(parts[0], 10);
    const length = parseInt(parts[1], 10);
    const line = (src.match(/\n/g) || []).length + 1;
    const lastNewLine = src.lastIndexOf('\n');
    const column = lastNewLine >= 0 ? src.length - lastNewLine : src.length;
    return { start, length, line, column };
}
function extractASTElements(ast) {
    const context = {
        source: '',
        ast,
        contracts: [],
        functions: [],
        stateVariables: [],
        modifiers: [],
        events: [],
        structs: [],
        enums: [],
        imports: [],
        pragmas: []
    };
    for (const node of ast.nodes) {
        extractFromNode(node, context);
    }
    return context;
}
function extractFromNode(node, context) {
    switch (node.nodeType) {
        case 'ContractDefinition': {
            const contract = node;
            context.contracts.push(contract);
            for (const child of contract.nodes) {
                if (child.nodeType === 'FunctionDefinition') {
                    context.functions.push(child);
                }
                else if (child.nodeType === 'VariableDeclaration') {
                    const varDecl = child;
                    if (varDecl.stateVariable) {
                        context.stateVariables.push(varDecl);
                    }
                }
                else if (child.nodeType === 'ModifierDefinition') {
                    context.modifiers.push(child);
                }
                else if (child.nodeType === 'EventDefinition') {
                    context.events.push(child);
                }
                else if (child.nodeType === 'StructDefinition') {
                    context.structs.push(child);
                }
                else if (child.nodeType === 'EnumDefinition') {
                    context.enums.push(child);
                }
                extractFromNode(child, context);
            }
            break;
        }
        case 'ImportDirective':
            context.imports.push(node);
            break;
        case 'PragmaDirective':
            context.pragmas.push(node);
            break;
        default:
            break;
    }
}
function findNodesByType(ast, nodeTypes) {
    const results = [];
    function traverse(node) {
        if (nodeTypes.includes(node.nodeType)) {
            results.push(node);
        }
        const children = getNodeChildren(node);
        for (const child of children) {
            traverse(child);
        }
    }
    for (const node of ast.nodes) {
        traverse(node);
    }
    return results;
}
function findNodesByProperty(ast, property, value) {
    const results = [];
    function traverse(node) {
        const nodeValue = node[property];
        if (nodeValue === value) {
            results.push(node);
        }
        const children = getNodeChildren(node);
        for (const child of children) {
            traverse(child);
        }
    }
    for (const node of ast.nodes) {
        traverse(node);
    }
    return results;
}
function hasModifier(funcDef, modifierName) {
    if (!funcDef.modifiers)
        return false;
    return funcDef.modifiers.some(mod => mod.modifierName?.name === modifierName);
}
function hasExternalCall(node) {
    if (node.nodeType === 'FunctionCall') {
        const call = node;
        if (call.expression.nodeType === 'MemberAccess') {
            const access = call.expression;
            if (access.memberName === 'call' ||
                access.memberName === 'delegatecall' ||
                access.memberName === 'staticcall') {
                return true;
            }
        }
    }
    const children = getNodeChildren(node);
    return children.some(hasExternalCall);
}
function hasStateWrite(node, stateVars) {
    if (node.nodeType === 'Assignment') {
        const assignment = node;
        if (assignment.leftHandSide.nodeType === 'Identifier') {
            const id = assignment.leftHandSide;
            if (stateVars.includes(id.name)) {
                return true;
            }
        }
        if (assignment.leftHandSide.nodeType === 'MemberAccess') {
            const access = assignment.leftHandSide;
            if (stateVars.includes(access.memberName)) {
                return true;
            }
        }
    }
    const children = getNodeChildren(node);
    return children.some(child => hasStateWrite(child, stateVars));
}
function hasSelfCall(node) {
    if (node.nodeType === 'FunctionCall') {
        const call = node;
        if (call.expression.nodeType === 'MemberAccess') {
            const access = call.expression;
            if (access.expression.nodeType === 'Identifier') {
                const id = access.expression;
                if (id.name === 'this') {
                    return true;
                }
            }
        }
    }
    const children = getNodeChildren(node);
    return children.some(hasSelfCall);
}
function hasTxOrigin(node) {
    if (node.nodeType === 'MemberAccess') {
        const access = node;
        if (access.memberName === 'origin' &&
            access.expression.nodeType === 'Identifier') {
            const id = access.expression;
            if (id.name === 'tx') {
                return true;
            }
        }
    }
    const srcContent = node.src || '';
    if (typeof srcContent === 'string') {
        const parts = srcContent.split(':');
        if (parts.length >= 2) {
            const start = parseInt(parts[0], 10);
            const length = parseInt(parts[1], 10);
            if (!isNaN(start) && !isNaN(length)) {
                return false;
            }
        }
    }
    const children = getNodeChildren(node);
    return children.some(hasTxOrigin);
}
function hasTxOriginInSource(source) {
    return /tx\.origin\s*(?:==|!=)/.test(source);
}
function hasBlockTimestamp(node) {
    if (node.nodeType === 'MemberAccess') {
        const access = node;
        if (access.memberName === 'timestamp' &&
            access.expression.nodeType === 'Identifier') {
            const id = access.expression;
            if (id.name === 'block') {
                return true;
            }
        }
    }
    const children = getNodeChildren(node);
    return children.some(hasBlockTimestamp);
}
function hasBlockTimestampInSource(source) {
    return /block\.timestamp/.test(source);
}
function hasUncheckedCall(node) {
    if (node.nodeType === 'FunctionCall') {
        const call = node;
        if (call.expression.nodeType === 'MemberAccess') {
            const access = call.expression;
            if (['call', 'delegatecall', 'staticcall'].includes(access.memberName)) {
                return true;
            }
        }
    }
    const children = getNodeChildren(node);
    return children.some(hasUncheckedCall);
}
function hasAssembly(node) {
    return node.nodeType === 'InlineAssembly' ||
        getNodeChildren(node).some(hasAssembly);
}
function hasAssemblyInSource(source) {
    return /\bassembly\s*\{/.test(source);
}
function hasSelfDestruct(node) {
    if (node.nodeType === 'FunctionCall') {
        const call = node;
        if (call.expression.nodeType === 'Identifier') {
            const id = call.expression;
            if (id.name === 'selfdestruct' || id.name === 'suicide') {
                return true;
            }
        }
    }
    const children = getNodeChildren(node);
    return children.some(hasSelfDestruct);
}
function hasSelfDestructInSource(source) {
    return /\b(?:selfdestruct|suicide)\s*\(/.test(source);
}
function hasExternalCallInSource(source) {
    return /\b(?:call|delegatecall|staticcall)(?:\s*\{[^}]*\})?\s*\(/.test(source);
}
function getFunctionBodyNode(funcDef) {
    return funcDef.body || null;
}
function getNodeChildren(node) {
    const children = [];
    switch (node.nodeType) {
        case 'SourceUnit':
            return node.nodes;
        case 'ContractDefinition':
            return node.nodes;
        case 'FunctionDefinition': {
            const func = node;
            if (func.body)
                children.push(func.body);
            if (func.parameters) {
                children.push(func.parameters);
                children.push(...func.parameters.parameters);
            }
            if (func.modifiers)
                children.push(...func.modifiers);
            return children;
        }
        case 'Block':
            return node.statements;
        case 'ExpressionStatement':
            return [node.expression];
        case 'FunctionCall': {
            const call = node;
            children.push(call.expression);
            children.push(...call.arguments);
            return children;
        }
        case 'MemberAccess':
            return [node.expression];
        case 'BinaryOperation': {
            const bin = node;
            return [bin.leftExpression, bin.rightExpression];
        }
        case 'UnaryOperation':
            return [node.subExpression];
        case 'IfStatement': {
            const stmt = node;
            children.push(stmt.condition);
            children.push(stmt.trueBody);
            if (stmt.falseBody)
                children.push(stmt.falseBody);
            return children;
        }
        case 'ForStatement': {
            const stmt = node;
            if (stmt.initializationExpression)
                children.push(stmt.initializationExpression);
            if (stmt.condition)
                children.push(stmt.condition);
            if (stmt.loopExpression)
                children.push(stmt.loopExpression);
            children.push(stmt.body);
            return children;
        }
        case 'WhileStatement': {
            const stmt = node;
            return [stmt.condition, stmt.body];
        }
        case 'Assignment': {
            const assign = node;
            return [assign.leftHandSide, assign.rightHandSide];
        }
        case 'VariableDeclarationStatement': {
            const stmt = node;
            if (stmt.initialValue)
                children.push(stmt.initialValue);
            return children;
        }
        case 'ReturnStatement': {
            const ret = node;
            if (ret.expression)
                children.push(ret.expression);
            return children;
        }
        case 'ParameterList':
            return node.parameters;
        case 'TryStatement': {
            const stmt = node;
            children.push(stmt.expression);
            children.push(...stmt.clauses);
            return children;
        }
        case 'TryCatchClause': {
            const clause = node;
            children.push(clause.block);
            if (clause.parameters)
                children.push(clause.parameters);
            return children;
        }
        case 'EmitStatement':
            return [node.eventCall];
        case 'RevertStatement':
            return [node.errorCall];
        case 'InlineAssembly':
            return [node.ast];
        case 'AssemblyBlock':
            return node.operations;
        default:
            return children;
    }
}
function isStateChangingFunction(funcDef) {
    if (funcDef.stateMutability === 'view' ||
        funcDef.stateMutability === 'pure') {
        return false;
    }
    if (funcDef.body) {
        return containsStateWrite(funcDef.body);
    }
    return true;
}
function containsStateWrite(node) {
    if (node.nodeType === 'Assignment') {
        return true;
    }
    const children = getNodeChildren(node);
    return children.some(containsStateWrite);
}
function isPayableFunction(funcDef) {
    return funcDef.stateMutability === 'payable';
}
function hasFallbackOrReceive(contracts) {
    const fallbacks = [];
    for (const contract of contracts) {
        for (const node of contract.nodes) {
            if (node.nodeType === 'FunctionDefinition') {
                const func = node;
                if (func.kind === 'fallback' || func.kind === 'receive') {
                    fallbacks.push(func);
                }
            }
        }
    }
    return fallbacks;
}
function getInheritanceChain(contract) {
    const chain = [];
    if (contract.baseContracts) {
        for (const base of contract.baseContracts) {
            if (base.nodeType === 'InheritanceSpecifier') {
                const spec = base;
                if (spec.baseName.nodeType === 'Identifier') {
                    chain.push(spec.baseName.name);
                }
            }
        }
    }
    return chain;
}
function findUnprotectedFunctions(context, sensitiveNames) {
    const unprotected = [];
    for (const func of context.functions) {
        if (func.visibility !== 'external' && func.visibility !== 'public') {
            continue;
        }
        if (func.kind !== 'function') {
            continue;
        }
        const funcName = func.name || '';
        const isSensitive = sensitiveNames.some(name => funcName.toLowerCase().includes(name.toLowerCase()));
        if (!isSensitive) {
            continue;
        }
        const hasProtection = func.modifiers?.some(mod => {
            if (mod.nodeType === 'ModifierInvocation') {
                const inv = mod;
                const modifierName = inv.modifierName?.name || '';
                return ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyGovernance', 'nonReentrant']
                    .some(prot => modifierName.includes(prot));
            }
            return false;
        });
        if (!hasProtection) {
            unprotected.push(func);
        }
    }
    return unprotected;
}
function findLoopsWithExternalCalls(context) {
    const problematic = [];
    for (const func of context.functions) {
        if (!func.body)
            continue;
        const hasLoopWithCall = checkLoopForExternalCall(func.body);
        if (hasLoopWithCall) {
            problematic.push(func);
        }
    }
    return problematic;
}
function checkLoopForExternalCall(node) {
    if (node.nodeType === 'ForStatement' ||
        node.nodeType === 'WhileStatement' ||
        node.nodeType === 'DoWhileStatement') {
        const body = node.body;
        return containsExternalCallInNode(body);
    }
    const children = getNodeChildren(node);
    return children.some(checkLoopForExternalCall);
}
function containsExternalCallInNode(node) {
    if (node.nodeType === 'FunctionCall') {
        const call = node;
        if (call.expression.nodeType === 'MemberAccess') {
            const access = call.expression;
            if (['call', 'delegatecall', 'staticcall', 'transfer', 'send'].includes(access.memberName)) {
                return true;
            }
        }
    }
    const children = getNodeChildren(node);
    return children.some(containsExternalCallInNode);
}
function findDivisionBeforeMultiplication(node) {
    const findings = [];
    function traverse(current) {
        if (current.nodeType === 'BinaryOperation') {
            const bin = current;
            if (bin.operator === '/' &&
                bin.rightExpression.nodeType === 'BinaryOperation') {
                const right = bin.rightExpression;
                if (right.operator === '*') {
                    findings.push(current);
                }
            }
        }
        const children = getNodeChildren(current);
        children.forEach(traverse);
    }
    traverse(node);
    return findings;
}
function getPragmaSolidityVersion(pragmas) {
    for (const pragma of pragmas) {
        if (pragma.literals && pragma.literals[0] === 'solidity') {
            return pragma.literals.slice(1).join(' ');
        }
    }
    return null;
}
function isOldSolidityVersion(pragmas) {
    const version = getPragmaSolidityVersion(pragmas);
    if (!version)
        return false;
    const match = version.match(/\^?0\.([0-9]+)\./);
    if (match) {
        const minor = parseInt(match[1], 10);
        return minor < 8;
    }
    return false;
}
function findPublicStateVariables(stateVars) {
    return stateVars.filter(v => v.visibility === 'public');
}
function findUninitializedStoragePointers(context) {
    const uninitialized = [];
    for (const stateVar of context.stateVariables) {
        if (stateVar.typeName) {
            const typeDesc = stateVar.typeName.typeDescriptions?.typeString || '';
            if (typeDesc.includes('mapping') || typeDesc.includes('struct')) {
                if (!stateVar.value) {
                    uninitialized.push(stateVar);
                }
            }
        }
    }
    return uninitialized;
}
function analyzeAST(ast, source) {
    const context = extractASTElements(ast);
    context.source = source;
    return context;
}
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
        const literals = ['solidity', ...match[0].split(/\s+/).slice(1)];
        ast.nodes.push({
            id: nodeId++,
            nodeType: 'PragmaDirective',
            src: `${match.index}:${match[0].length}:0`,
            literals
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
function isValidSolidity(source) {
    const hasPragma = /pragma\s+solidity/.test(source);
    const hasContract = /\bcontract\b/.test(source);
    const hasLibrary = /\blibrary\b/.test(source);
    const hasInterface = /\binterface\b/.test(source);
    return hasPragma && (hasContract || hasLibrary || hasInterface);
}
//# sourceMappingURL=ast.js.map