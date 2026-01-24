/**
 * Security rule definitions for Solidity smart contract scanning.
 * Each rule defines a pattern to detect and its severity level.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface SecurityRule {
    id: string;
    name: string;
    description: string;
    severity: Severity;
    pattern: RegExp;
    category: string;
    recommendation: string;
    swcId?: string;
}
export declare const SECURITY_RULES: SecurityRule[];
export declare const SEVERITY_ORDER: Record<Severity, number>;
export declare function getRulesByCategory(category: string): SecurityRule[];
export declare function getRulesBySeverity(severity: Severity): SecurityRule[];
export declare function getRuleById(id: string): SecurityRule | undefined;
export declare function getAllCategories(): string[];
//# sourceMappingURL=rules.d.ts.map