import { readFileSync } from 'node:fs';
import { canonical, hash } from './filesystem.ts';
import { stable } from './policy.ts';
import { validateRule } from './config.ts';
import type { Environment, Rule, Config } from './types.ts';
export function agentDigest(path: string, env: Environment): string { return hash(readFileSync(canonical(path, env), 'utf8')); }
export function trustedRules(path: string, metadata: any, config: Config, env: Environment, sourceDigest: string): Rule[] {
  const real = canonical(path, env); const digest = agentDigest(real, env);
  if (sourceDigest !== digest || !config.trustedAgents.some(t => canonical(t.path, env) === real && t.digest === digest)) return [];
  const rules: Rule[] = [];
  // Exact digest rules are the portable extension-specific frontmatter format.
  for (const r of metadata.smartApprovalRules ?? []) { validateRule(r); rules.push(r); }
  // Conservative subset of Claude-style permission declarations, never tools:/allowed-tools:.
  for (const [group, action] of [['allow', 'ALWAYS_ALLOW'], ['ask', 'ALWAYS_ASK'], ['deny', 'ALWAYS_DENY']] as const) {
    const entries = metadata.permissions?.[group] ?? [];
    if (!Array.isArray(entries)) throw new Error('Invalid agent permission declaration');
    for (const entry of entries) {
      if (typeof entry !== 'string') throw new Error('Invalid agent permission');
      const match = /^(Bash|Read)\(([^*\n]+)\)$/.exec(entry);
      if (!match) continue; // Wildcards and other dialects are not interpreted as grants.
      const tool = match[1] === 'Bash' ? 'bash' : 'read';
      const input = tool === 'bash' ? { command: match[2] } : { path: match[2] };
      rules.push({ tool, action, key: hash(stable({ call: { tool, input }, cwd: env.cwd })) });
    }
  }
  return rules;
}
