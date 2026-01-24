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
export type Statement = ExpressionStatement | VariableDeclarationStatement | IfStatement | ForStatement | WhileStatement | ReturnStatement | BreakContinue | PlaceholderStatement;
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
export type Expression = Assignment | FunctionCall | MemberAccess | Identifier | Literal | BinaryOperation | UnaryOperation | Conditional | IndexAccess | NewExpression | TupleExpression;
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
export declare function parseSrc(src: string): ASTPosition;
export declare function extractASTElements(ast: SourceUnit): ASTAnalysisContext;
export declare function findNodesByType(ast: SourceUnit, nodeTypes: string[]): ASTNode[];
export declare function findNodesByProperty(ast: SourceUnit, property: string, value: unknown): ASTNode[];
export declare function hasModifier(funcDef: FunctionDefinition, modifierName: string): boolean;
export declare function hasExternalCall(node: ASTNode): boolean;
export declare function hasStateWrite(node: ASTNode, stateVars: string[]): boolean;
export declare function hasSelfCall(node: ASTNode): boolean;
export declare function hasTxOrigin(node: ASTNode): boolean;
export declare function hasTxOriginInSource(source: string): boolean;
export declare function hasBlockTimestamp(node: ASTNode): boolean;
export declare function hasBlockTimestampInSource(source: string): boolean;
export declare function hasUncheckedCall(node: ASTNode): boolean;
export declare function hasAssembly(node: ASTNode): boolean;
export declare function hasAssemblyInSource(source: string): boolean;
export declare function hasSelfDestruct(node: ASTNode): boolean;
export declare function hasSelfDestructInSource(source: string): boolean;
export declare function hasExternalCallInSource(source: string): boolean;
export declare function getFunctionBodyNode(funcDef: FunctionDefinition): Block | null;
export declare function getNodeChildren(node: ASTNode): ASTNode[];
export declare function isStateChangingFunction(funcDef: FunctionDefinition): boolean;
export declare function isPayableFunction(funcDef: FunctionDefinition): boolean;
export declare function hasFallbackOrReceive(contracts: ContractDefinition[]): FunctionDefinition[];
export declare function getInheritanceChain(contract: ContractDefinition): string[];
export declare function findUnprotectedFunctions(context: ASTAnalysisContext, sensitiveNames: string[]): FunctionDefinition[];
export declare function findLoopsWithExternalCalls(context: ASTAnalysisContext): FunctionDefinition[];
export declare function findDivisionBeforeMultiplication(node: ASTNode): ASTNode[];
export declare function getPragmaSolidityVersion(pragmas: PragmaDirective[]): string | null;
export declare function isOldSolidityVersion(pragmas: PragmaDirective[]): boolean;
export declare function findPublicStateVariables(stateVars: VariableDeclaration[]): VariableDeclaration[];
export declare function findUninitializedStoragePointers(context: ASTAnalysisContext): VariableDeclaration[];
export declare function analyzeAST(ast: SourceUnit, source: string): ASTAnalysisContext;
export declare function parseSolidityToAST(source: string): SourceUnit | null;
//# sourceMappingURL=ast.d.ts.map