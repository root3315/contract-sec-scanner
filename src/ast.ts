/**
 * AST-based parser for Solidity smart contract analysis.
 * Provides accurate structural analysis beyond regex pattern matching.
 */

export interface ASTNode {
  id: number;
  nodeType: string;
  src: string;
  file?: number | string;
  scope?: number;
  [key: string]: unknown;
}

export interface SourceUnit extends ASTNode {
  nodeType: 'SourceUnit';
  nodes: ASTNode[];
  absolutePath?: string;
  exportedSymbols?: Record<string, number[]>;
}

export interface ContractDefinition extends ASTNode {
  nodeType: 'ContractDefinition';
  name: string;
  baseContracts?: ASTNode[];
  contractKind?: 'contract' | 'library' | 'interface';
  nodes: ASTNode[];
  abstract?: boolean;
}

export interface FunctionDefinition extends ASTNode {
  nodeType: 'FunctionDefinition';
  name?: string;
  visibility: 'public' | 'private' | 'internal' | 'external';
  stateMutability?: 'pure' | 'view' | 'nonpayable' | 'payable';
  parameters: ParameterList;
  returnParameters?: ParameterList;
  body?: Block;
  modifiers?: ASTNode[];
  implemented?: boolean;
  kind: 'function' | 'constructor' | 'fallback' | 'receive';
}

export interface ParameterList extends ASTNode {
  nodeType: 'ParameterList';
  parameters: VariableDeclaration[];
}

export interface VariableDeclaration extends ASTNode {
  nodeType: 'VariableDeclaration';
  name: string;
  typeName?: TypeName;
  visibility: 'public' | 'private' | 'internal' | 'external';
  stateVariable: boolean;
  constant?: boolean;
  mutable?: boolean;
  value?: ASTNode;
}

export interface TypeName extends ASTNode {
  nodeType: string;
  typeDescriptions?: TypeDescriptions;
}

export interface TypeDescriptions {
  typeIdentifier?: string;
  typeString?: string;
}

export interface Block extends ASTNode {
  nodeType: 'Block';
  statements: Statement[];
}

export type Statement = 
  | ExpressionStatement
  | VariableDeclarationStatement
  | IfStatement
  | ForStatement
  | WhileStatement
  | ReturnStatement
  | BreakContinue
  | PlaceholderStatement;

export interface ExpressionStatement extends ASTNode {
  nodeType: 'ExpressionStatement';
  expression: Expression;
}

export interface VariableDeclarationStatement extends ASTNode {
  nodeType: 'VariableDeclarationStatement';
  declarations: (VariableDeclaration | null)[];
  initialValue?: Expression;
}

export interface IfStatement extends ASTNode {
  nodeType: 'IfStatement';
  condition: Expression;
  trueBody: Statement;
  falseBody?: Statement;
}

export interface ForStatement extends ASTNode {
  nodeType: 'ForStatement';
  initializationExpression?: ASTNode;
  condition?: Expression;
  loopExpression?: ExpressionStatement;
  body: Statement;
}

export interface WhileStatement extends ASTNode {
  nodeType: 'WhileStatement';
  condition: Expression;
  body: Statement;
}

export interface ReturnStatement extends ASTNode {
  nodeType: 'ReturnStatement';
  expression?: Expression;
}

export interface BreakContinue extends ASTNode {
  nodeType: 'Break' | 'Continue';
}

export interface PlaceholderStatement extends ASTNode {
  nodeType: 'PlaceholderStatement';
}

export type Expression = 
  | Assignment
  | FunctionCall
  | MemberAccess
  | Identifier
  | Literal
  | BinaryOperation
  | UnaryOperation
  | Conditional
  | IndexAccess
  | NewExpression
  | TupleExpression;

export interface Assignment extends ASTNode {
  nodeType: 'Assignment';
  operator: '=' | '+=' | '-=' | '*=' | '/=' | '%=' | '|=' | '&=' | '^=' | '<<=' | '>>=';
  leftHandSide: Expression;
  rightHandSide: Expression;
}

export interface FunctionCall extends ASTNode {
  nodeType: 'FunctionCall';
  expression: Expression;
  arguments: Expression[];
  names: string[];
  kind?: 'functionCall' | 'typeConversion' | 'structConstructorCall';
}

export interface MemberAccess extends ASTNode {
  nodeType: 'MemberAccess';
  expression: Expression;
  memberName: string;
  referencedDeclaration?: number;
}

export interface Identifier extends ASTNode {
  nodeType: 'Identifier';
  name: string;
  referencedDeclaration?: number;
  typeDescriptions?: TypeDescriptions;
}

export interface Literal extends ASTNode {
  nodeType: 'Literal';
  value?: string;
  kind?: 'number' | 'string' | 'bool' | 'hexString';
}

export interface BinaryOperation extends ASTNode {
  nodeType: 'BinaryOperation';
  operator: string;
  leftExpression: Expression;
  rightExpression: Expression;
}

export interface UnaryOperation extends ASTNode {
  nodeType: 'UnaryOperation';
  operator: string;
  subExpression: Expression;
  prefix: boolean;
}

export interface Conditional extends ASTNode {
  nodeType: 'Conditional';
  condition: Expression;
  trueExpression: Expression;
  falseExpression: Expression;
}

export interface IndexAccess extends ASTNode {
  nodeType: 'IndexAccess';
  baseExpression: Expression;
  indexExpression: Expression;
}

export interface NewExpression extends ASTNode {
  nodeType: 'NewExpression';
  typeName: TypeName;
}

export interface TupleExpression extends ASTNode {
  nodeType: 'TupleExpression';
  components: (Expression | null)[];
  isInlineArray: boolean;
}

export interface ModifierDefinition extends ASTNode {
  nodeType: 'ModifierDefinition';
  name: string;
  parameters?: ParameterList;
  body?: Block;
  visibility: 'internal' | 'public';
}

export interface EventDefinition extends ASTNode {
  nodeType: 'EventDefinition';
  name: string;
  parameters: ParameterList;
  anonymous: boolean;
}

export interface StructDefinition extends ASTNode {
  nodeType: 'StructDefinition';
  name: string;
  members: VariableDeclaration[];
}

export interface EnumDefinition extends ASTNode {
  nodeType: 'EnumDefinition';
  name: string;
  members: ASTNode[];
}

export interface InheritanceSpecifier extends ASTNode {
  nodeType: 'InheritanceSpecifier';
  baseName: Identifier;
  arguments?: Expression[];
}

export interface ModifierInvocation extends ASTNode {
  nodeType: 'ModifierInvocation';
  modifierName: Identifier;
  arguments?: Expression[];
}

export interface UsingForDirective extends ASTNode {
  nodeType: 'UsingForDirective';
  libraryName?: Identifier;
  typeName?: TypeName;
  global?: boolean;
}

export interface ImportDirective extends ASTNode {
  nodeType: 'ImportDirective';
  file?: string;
  source?: string;
  unitAlias?: string;
  symbolAliases?: string[][];
}

export interface PragmaDirective extends ASTNode {
  nodeType: 'PragmaDirective';
  literals?: string[];
}

export interface DoWhileStatement extends ASTNode {
  nodeType: 'DoWhileStatement';
  condition: Expression;
  body: Statement;
}

export interface EmitStatement extends ASTNode {
  nodeType: 'EmitStatement';
  eventCall: FunctionCall;
}

export interface TryStatement extends ASTNode {
  nodeType: 'TryStatement';
  expression: FunctionCall;
  clauses: TryCatchClause[];
}

export interface TryCatchClause extends ASTNode {
  nodeType: 'TryCatchClause';
  name?: string;
  parameters?: ParameterList;
  block: Block;
}

export interface RevertStatement extends ASTNode {
  nodeType: 'RevertStatement';
  errorCall: FunctionCall;
}

export interface AssemblyBlock extends ASTNode {
  nodeType: 'AssemblyBlock';
  operations: ASTNode[];
}

export interface InlineAssembly extends ASTNode {
  nodeType: 'InlineAssembly';
  ast: ASTNode;
  evmVersion?: string;
  flags?: string[];
}

export interface ASTPosition {
  start: number;
  length: number;
  line: number;
  column: number;
}

export interface ASTAnalysisContext {
  source: string;
  ast: SourceUnit;
  contracts: ContractDefinition[];
  functions: FunctionDefinition[];
  stateVariables: VariableDeclaration[];
  modifiers: ModifierDefinition[];
  events: EventDefinition[];
  structs: StructDefinition[];
  enums: EnumDefinition[];
  imports: ImportDirective[];
  pragmas: PragmaDirective[];
}

export interface ASTFinding {
  node: ASTNode;
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  position?: ASTPosition;
}

export function parseSrc(src: string): ASTPosition {
  const parts = src.split(':');
  const start = parseInt(parts[0], 10);
  const length = parseInt(parts[1], 10);
  
  const line = (src.match(/\n/g) || []).length + 1;
  const lastNewLine = src.lastIndexOf('\n');
  const column = lastNewLine >= 0 ? src.length - lastNewLine : src.length;
  
  return { start, length, line, column };
}

export function extractASTElements(ast: SourceUnit): ASTAnalysisContext {
  const context: ASTAnalysisContext = {
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

function extractFromNode(node: ASTNode, context: ASTAnalysisContext): void {
  switch (node.nodeType) {
    case 'ContractDefinition': {
      const contract = node as ContractDefinition;
      context.contracts.push(contract);
      
      for (const child of contract.nodes) {
        if (child.nodeType === 'FunctionDefinition') {
          context.functions.push(child as FunctionDefinition);
        } else if (child.nodeType === 'VariableDeclaration') {
          const varDecl = child as VariableDeclaration;
          if (varDecl.stateVariable) {
            context.stateVariables.push(varDecl);
          }
        } else if (child.nodeType === 'ModifierDefinition') {
          context.modifiers.push(child as ModifierDefinition);
        } else if (child.nodeType === 'EventDefinition') {
          context.events.push(child as EventDefinition);
        } else if (child.nodeType === 'StructDefinition') {
          context.structs.push(child as StructDefinition);
        } else if (child.nodeType === 'EnumDefinition') {
          context.enums.push(child as EnumDefinition);
        }
        extractFromNode(child, context);
      }
      break;
    }
    case 'ImportDirective':
      context.imports.push(node as ImportDirective);
      break;
    case 'PragmaDirective':
      context.pragmas.push(node as PragmaDirective);
      break;
    default:
      break;
  }
}

export function findNodesByType(ast: SourceUnit, nodeTypes: string[]): ASTNode[] {
  const results: ASTNode[] = [];
  
  function traverse(node: ASTNode): void {
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

export function findNodesByProperty(
  ast: SourceUnit,
  property: string,
  value: unknown
): ASTNode[] {
  const results: ASTNode[] = [];
  
  function traverse(node: ASTNode): void {
    const nodeValue = (node as { [key: string]: unknown })[property];
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

export function hasModifier(
  funcDef: FunctionDefinition,
  modifierName: string
): boolean {
  if (!funcDef.modifiers) return false;
  return funcDef.modifiers.some(
    mod => (mod as ModifierInvocation).modifierName?.name === modifierName
  );
}

export function hasExternalCall(node: ASTNode): boolean {
  if (node.nodeType === 'FunctionCall') {
    const call = node as FunctionCall;
    if (call.expression.nodeType === 'MemberAccess') {
      const access = call.expression as MemberAccess;
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

export function hasStateWrite(node: ASTNode, stateVars: string[]): boolean {
  if (node.nodeType === 'Assignment') {
    const assignment = node as Assignment;
    if (assignment.leftHandSide.nodeType === 'Identifier') {
      const id = assignment.leftHandSide as Identifier;
      if (stateVars.includes(id.name)) {
        return true;
      }
    }
    if (assignment.leftHandSide.nodeType === 'MemberAccess') {
      const access = assignment.leftHandSide as MemberAccess;
      if (stateVars.includes(access.memberName)) {
        return true;
      }
    }
  }
  
  const children = getNodeChildren(node);
  return children.some(child => hasStateWrite(child, stateVars));
}

export function hasSelfCall(node: ASTNode): boolean {
  if (node.nodeType === 'FunctionCall') {
    const call = node as FunctionCall;
    if (call.expression.nodeType === 'MemberAccess') {
      const access = call.expression as MemberAccess;
      if (access.expression.nodeType === 'Identifier') {
        const id = access.expression as Identifier;
        if (id.name === 'this') {
          return true;
        }
      }
    }
  }
  
  const children = getNodeChildren(node);
  return children.some(hasSelfCall);
}

export function hasTxOrigin(node: ASTNode): boolean {
  if (node.nodeType === 'MemberAccess') {
    const access = node as MemberAccess;
    if (access.memberName === 'origin' && 
        access.expression.nodeType === 'Identifier') {
      const id = access.expression as Identifier;
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

export function hasTxOriginInSource(source: string): boolean {
  return /tx\.origin\s*(?:==|!=)/.test(source);
}

export function hasBlockTimestamp(node: ASTNode): boolean {
  if (node.nodeType === 'MemberAccess') {
    const access = node as MemberAccess;
    if (access.memberName === 'timestamp' &&
        access.expression.nodeType === 'Identifier') {
      const id = access.expression as Identifier;
      if (id.name === 'block') {
        return true;
      }
    }
  }

  const children = getNodeChildren(node);
  return children.some(hasBlockTimestamp);
}

export function hasBlockTimestampInSource(source: string): boolean {
  return /block\.timestamp/.test(source);
}

export function hasUncheckedCall(node: ASTNode): boolean {
  if (node.nodeType === 'FunctionCall') {
    const call = node as FunctionCall;
    if (call.expression.nodeType === 'MemberAccess') {
      const access = call.expression as MemberAccess;
      if (['call', 'delegatecall', 'staticcall'].includes(access.memberName)) {
        return true;
      }
    }
  }

  const children = getNodeChildren(node);
  return children.some(hasUncheckedCall);
}

export function hasAssembly(node: ASTNode): boolean {
  return node.nodeType === 'InlineAssembly' ||
         getNodeChildren(node).some(hasAssembly);
}

export function hasAssemblyInSource(source: string): boolean {
  return /\bassembly\s*\{/.test(source);
}

export function hasSelfDestruct(node: ASTNode): boolean {
  if (node.nodeType === 'FunctionCall') {
    const call = node as FunctionCall;
    if (call.expression.nodeType === 'Identifier') {
      const id = call.expression as Identifier;
      if (id.name === 'selfdestruct' || id.name === 'suicide') {
        return true;
      }
    }
  }

  const children = getNodeChildren(node);
  return children.some(hasSelfDestruct);
}

export function hasSelfDestructInSource(source: string): boolean {
  return /\b(?:selfdestruct|suicide)\s*\(/.test(source);
}

export function hasExternalCallInSource(source: string): boolean {
  return /\b(?:call|delegatecall|staticcall)(?:\s*\{[^}]*\})?\s*\(/.test(source);
}

export function getFunctionBodyNode(funcDef: FunctionDefinition): Block | null {
  return funcDef.body || null;
}

export function getNodeChildren(node: ASTNode): ASTNode[] {
  const children: ASTNode[] = [];
  
  switch (node.nodeType) {
    case 'SourceUnit':
      return (node as SourceUnit).nodes;
    
    case 'ContractDefinition':
      return (node as ContractDefinition).nodes;
    
    case 'FunctionDefinition': {
      const func = node as FunctionDefinition;
      if (func.body) children.push(func.body);
      if (func.parameters) {
        children.push(func.parameters);
        children.push(...func.parameters.parameters);
      }
      if (func.modifiers) children.push(...func.modifiers);
      return children;
    }
    
    case 'Block':
      return (node as Block).statements;
    
    case 'ExpressionStatement':
      return [(node as ExpressionStatement).expression];
    
    case 'FunctionCall': {
      const call = node as FunctionCall;
      children.push(call.expression);
      children.push(...call.arguments);
      return children;
    }
    
    case 'MemberAccess':
      return [(node as MemberAccess).expression];
    
    case 'BinaryOperation': {
      const bin = node as BinaryOperation;
      return [bin.leftExpression, bin.rightExpression];
    }
    
    case 'UnaryOperation':
      return [(node as UnaryOperation).subExpression];
    
    case 'IfStatement': {
      const stmt = node as IfStatement;
      children.push(stmt.condition);
      children.push(stmt.trueBody);
      if (stmt.falseBody) children.push(stmt.falseBody);
      return children;
    }
    
    case 'ForStatement': {
      const stmt = node as ForStatement;
      if (stmt.initializationExpression) children.push(stmt.initializationExpression);
      if (stmt.condition) children.push(stmt.condition);
      if (stmt.loopExpression) children.push(stmt.loopExpression);
      children.push(stmt.body);
      return children;
    }
    
    case 'WhileStatement': {
      const stmt = node as WhileStatement;
      return [stmt.condition, stmt.body];
    }
    
    case 'Assignment': {
      const assign = node as Assignment;
      return [assign.leftHandSide, assign.rightHandSide];
    }
    
    case 'VariableDeclarationStatement': {
      const stmt = node as VariableDeclarationStatement;
      if (stmt.initialValue) children.push(stmt.initialValue);
      return children;
    }
    
    case 'ReturnStatement': {
      const ret = node as ReturnStatement;
      if (ret.expression) children.push(ret.expression);
      return children;
    }
    
    case 'ParameterList':
      return (node as ParameterList).parameters;
    
    case 'TryStatement': {
      const stmt = node as TryStatement;
      children.push(stmt.expression);
      children.push(...stmt.clauses);
      return children;
    }
    
    case 'TryCatchClause': {
      const clause = node as TryCatchClause;
      children.push(clause.block);
      if (clause.parameters) children.push(clause.parameters);
      return children;
    }
    
    case 'EmitStatement':
      return [(node as EmitStatement).eventCall];
    
    case 'RevertStatement':
      return [(node as RevertStatement).errorCall];
    
    case 'InlineAssembly':
      return [(node as InlineAssembly).ast];
    
    case 'AssemblyBlock':
      return (node as AssemblyBlock).operations;
    
    default:
      return children;
  }
}

export function isStateChangingFunction(funcDef: FunctionDefinition): boolean {
  if (funcDef.stateMutability === 'view' || 
      funcDef.stateMutability === 'pure') {
    return false;
  }
  
  if (funcDef.body) {
    return containsStateWrite(funcDef.body);
  }
  
  return true;
}

function containsStateWrite(node: ASTNode): boolean {
  if (node.nodeType === 'Assignment') {
    return true;
  }
  
  const children = getNodeChildren(node);
  return children.some(containsStateWrite);
}

export function isPayableFunction(funcDef: FunctionDefinition): boolean {
  return funcDef.stateMutability === 'payable';
}

export function hasFallbackOrReceive(contracts: ContractDefinition[]): FunctionDefinition[] {
  const fallbacks: FunctionDefinition[] = [];
  
  for (const contract of contracts) {
    for (const node of contract.nodes) {
      if (node.nodeType === 'FunctionDefinition') {
        const func = node as FunctionDefinition;
        if (func.kind === 'fallback' || func.kind === 'receive') {
          fallbacks.push(func);
        }
      }
    }
  }
  
  return fallbacks;
}

export function getInheritanceChain(contract: ContractDefinition): string[] {
  const chain: string[] = [];
  
  if (contract.baseContracts) {
    for (const base of contract.baseContracts) {
      if (base.nodeType === 'InheritanceSpecifier') {
        const spec = base as InheritanceSpecifier;
        if (spec.baseName.nodeType === 'Identifier') {
          chain.push(spec.baseName.name);
        }
      }
    }
  }
  
  return chain;
}

export function findUnprotectedFunctions(
  context: ASTAnalysisContext,
  sensitiveNames: string[]
): FunctionDefinition[] {
  const unprotected: FunctionDefinition[] = [];
  
  for (const func of context.functions) {
    if (func.visibility !== 'external' && func.visibility !== 'public') {
      continue;
    }
    
    if (func.kind !== 'function') {
      continue;
    }
    
    const funcName = func.name || '';
    const isSensitive = sensitiveNames.some(
      name => funcName.toLowerCase().includes(name.toLowerCase())
    );
    
    if (!isSensitive) {
      continue;
    }
    
    const hasProtection = func.modifiers?.some(mod => {
      if (mod.nodeType === 'ModifierInvocation') {
        const inv = mod as ModifierInvocation;
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

export function findLoopsWithExternalCalls(context: ASTAnalysisContext): FunctionDefinition[] {
  const problematic: FunctionDefinition[] = [];
  
  for (const func of context.functions) {
    if (!func.body) continue;
    
    const hasLoopWithCall = checkLoopForExternalCall(func.body);
    if (hasLoopWithCall) {
      problematic.push(func);
    }
  }
  
  return problematic;
}

function checkLoopForExternalCall(node: ASTNode): boolean {
  if (node.nodeType === 'ForStatement' || 
      node.nodeType === 'WhileStatement' || 
      node.nodeType === 'DoWhileStatement') {
    
    const body = (node as ForStatement | WhileStatement | DoWhileStatement).body;
    return containsExternalCallInNode(body);
  }
  
  const children = getNodeChildren(node);
  return children.some(checkLoopForExternalCall);
}

function containsExternalCallInNode(node: ASTNode): boolean {
  if (node.nodeType === 'FunctionCall') {
    const call = node as FunctionCall;
    if (call.expression.nodeType === 'MemberAccess') {
      const access = call.expression as MemberAccess;
      if (['call', 'delegatecall', 'staticcall', 'transfer', 'send'].includes(access.memberName)) {
        return true;
      }
    }
  }
  
  const children = getNodeChildren(node);
  return children.some(containsExternalCallInNode);
}

export function findDivisionBeforeMultiplication(node: ASTNode): ASTNode[] {
  const findings: ASTNode[] = [];
  
  function traverse(current: ASTNode): void {
    if (current.nodeType === 'BinaryOperation') {
      const bin = current as BinaryOperation;
      if (bin.operator === '/' && 
          bin.rightExpression.nodeType === 'BinaryOperation') {
        const right = bin.rightExpression as BinaryOperation;
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

export function getPragmaSolidityVersion(pragmas: PragmaDirective[]): string | null {
  for (const pragma of pragmas) {
    if (pragma.literals && pragma.literals[0] === 'solidity') {
      return pragma.literals.slice(1).join(' ');
    }
  }
  return null;
}

export function isOldSolidityVersion(pragmas: PragmaDirective[]): boolean {
  const version = getPragmaSolidityVersion(pragmas);
  if (!version) return false;
  
  const match = version.match(/\^?0\.([0-9]+)\./);
  if (match) {
    const minor = parseInt(match[1], 10);
    return minor < 8;
  }
  
  return false;
}

export function findPublicStateVariables(stateVars: VariableDeclaration[]): VariableDeclaration[] {
  return stateVars.filter(v => v.visibility === 'public');
}

export function findUninitializedStoragePointers(context: ASTAnalysisContext): VariableDeclaration[] {
  const uninitialized: VariableDeclaration[] = [];
  
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

export function analyzeAST(ast: SourceUnit, source: string): ASTAnalysisContext {
  const context = extractASTElements(ast);
  context.source = source;
  return context;
}

export function parseSolidityToAST(source: string): SourceUnit | null {
  if (!isValidSolidity(source)) {
    return null;
  }

  const ast: SourceUnit = {
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
  let contractMatch: RegExpExecArray | null;

  while ((contractMatch = contractRegex.exec(source)) !== null) {
    const contractType = contractMatch[1];
    const contractName = contractMatch[2];
    const inherits = contractMatch[3];
    const contractStart = contractMatch.index;

    const braceStart = source.indexOf('{', contractStart);
    if (braceStart === -1) continue;

    let braceCount = 1;
    let contractEnd = braceStart + 1;

    while (contractEnd < source.length && braceCount > 0) {
      if (source[contractEnd] === '{') braceCount++;
      else if (source[contractEnd] === '}') braceCount--;
      contractEnd++;
    }

    const contractBody = source.substring(braceStart + 1, contractEnd - 1);
    const contractSrc = `${contractStart}:${contractEnd - contractStart}:0`;

    const contractNode: any = {
      id: nodeId++,
      nodeType: 'ContractDefinition',
      src: contractSrc,
      name: contractName,
      contractKind: contractType as 'contract' | 'library' | 'interface',
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
    let funcMatch: RegExpExecArray | null;

    while ((funcMatch = funcRegex.exec(contractBody)) !== null) {
      const funcName = funcMatch[1] || '';
      const params = funcMatch[2] || '';
      const funcStartInBody = funcMatch.index;
      const funcStart = braceStart + 1 + funcStartInBody;

      const funcBraceStart = contractBody.indexOf('{', funcStartInBody);
      if (funcBraceStart === -1) continue;

      let funcBraceCount = 1;
      let funcEnd = funcStartInBody + funcBraceStart + 1;

      while (funcEnd < contractBody.length && funcBraceCount > 0) {
        if (contractBody[funcEnd] === '{') funcBraceCount++;
        else if (contractBody[funcEnd] === '}') funcBraceCount--;
        funcEnd++;
      }

      const funcSrc = `${funcStart}:${funcEnd - funcStartInBody}:0`;
      const visibilityMatch = funcMatch[0].match(/\b(external|public|private|internal)\b/);
      const mutabilityMatch = funcMatch[0].match(/\b(view|pure|payable)\b/);
      const modifierMatches = funcMatch[0].match(/\b(\w+)\b(?=\s*\()/g) || [];

      const funcNode: any = {
        id: nodeId++,
        nodeType: 'FunctionDefinition',
        src: funcSrc,
        name: funcName || undefined,
        visibility: (visibilityMatch?.[1] || 'public') as 'public' | 'private' | 'internal' | 'external',
        stateMutability: mutabilityMatch?.[1] as 'pure' | 'view' | 'nonpayable' | 'payable' | undefined,
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
    let varMatch: RegExpExecArray | null;

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

function parseParameters(paramsStr: string, startId: number, source: string): any[] {
  const params: any[] = [];
  if (!paramsStr.trim()) return params;

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

function isValidSolidity(source: string): boolean {
  const hasPragma = /pragma\s+solidity/.test(source);
  const hasContract = /\bcontract\b/.test(source);
  const hasLibrary = /\blibrary\b/.test(source);
  const hasInterface = /\binterface\b/.test(source);
  return hasPragma && (hasContract || hasLibrary || hasInterface);
}
