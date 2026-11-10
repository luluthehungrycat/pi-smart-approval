export type Decision = 'SMART_ALLOW' | 'SMART_ASK' | 'SMART_DENY' | 'HARD_DENY';
export type Manual = 'ALWAYS_ALLOW' | 'ALWAYS_ASK' | 'ALWAYS_DENY';
export interface Rule { tool: string; action: Manual; key?: string; path?: string }
export interface AnalysisConfig { enabled: boolean; provider?: string; model?: string; maxCalls: number; maxInputChars: number; timeoutMs: number }
export interface Config {
  version: 1; smart: boolean; timeoutMs: number; reviewDeny: boolean;
  writable: string[]; readOnly: string[]; skillPaths: string[]; rules: Rule[];
  trustedAgents: { path: string; digest: string }[];
  analysis: AnalysisConfig; decisionModel: AnalysisConfig;
}
export interface Environment { cwd: string; home: string; agentDir: string; configDir: string; extensionDir: string }
export interface Call { tool: string; input: Record<string, unknown> }
export interface Evaluation {
  decision: Decision; reason: string; key: string; resources: string[];
  protected: boolean; opaque: boolean; outside: boolean; technical: boolean;
  fingerprint: string; persistent: boolean;
}
export interface Pending { id: string; key: string; tool: string; session: string; created: number; status: 'pending' | 'reviewed' | 'rejected'; reason: string }
export interface Advisory { decision: Decision; category: string; reasoning: string; confidence: number; resources: string[]; observations: string[] }
