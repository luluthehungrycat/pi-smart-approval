export type Decision = 'SMART_ALLOW' | 'SMART_ASK' | 'SMART_DENY' | 'HARD_DENY';
export type Manual = 'ALWAYS_ALLOW' | 'ALWAYS_ASK' | 'ALWAYS_DENY';
export interface Rule { tool: string; action: Manual; key?: string; path?: string }
export interface AnalysisConfig { enabled: boolean; provider?: string; model?: string; maxCalls: number; maxInputChars: number; timeoutMs: number }
export interface Config {
  version: 1; smart: boolean; timeoutMs: number; reviewDeny: boolean;
  writable: string[]; readOnly: string[]; skillPaths: string[]; rules: Rule[];
  trustedAgents: { path: string; digest: string }[];
  analysis: AnalysisConfig; decisionModel: AnalysisConfig;
  // Optional (backwards compatible). When true, a model may auto-allow only the deterministic 'model' shell tier.
  shellModelAssist?: boolean;
}
// shellEnv: the environment Pi's bash tool inherits. Defaults to process.env when omitted.
export interface Environment { cwd: string; home: string; agentDir: string; configDir: string; extensionDir: string; shellEnv?: Record<string, string | undefined> }
export interface Call { tool: string; input: Record<string, unknown> }
export interface Evaluation {
  decision: Decision; reason: string; key: string; resources: string[];
  protected: boolean; opaque: boolean; outside: boolean; technical: boolean;
  fingerprint: string; persistent: boolean;
  // Key that a persistent ALWAYS_ALLOW rule must carry. For shell it also binds the shell environment digest.
  ruleKey: string;
  // Present for parsed simple shell commands only. Contains no raw arguments beyond flag words.
  shell?: { program: string; flags: string[]; tier?: 'auto' | 'model'; grantable: boolean; context: string };
}
export interface Pending { id: string; key: string; tool: string; session: string; created: number; status: 'pending' | 'reviewed' | 'rejected'; reason: string }
export interface Advisory { decision: Decision; category: string; reasoning: string; confidence: number; resources: string[]; observations: string[] }
