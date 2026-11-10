import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import type { Config, AnalysisConfig, Rule } from './types.ts';
export const defaults = (): Config => ({ version: 1, smart: true, timeoutMs: 120000, reviewDeny: false, writable: [], readOnly: [], skillPaths: [], rules: [], trustedAgents: [], analysis: { enabled: false, maxCalls: 10, maxInputChars: 4000, timeoutMs: 10000 }, decisionModel: { enabled: false, maxCalls: 10, maxInputChars: 4000, timeoutMs: 10000 } });
function object(v: unknown): asserts v is Record<string, any> { if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('Expected object'); }
function keys(v: Record<string, any>, allowed: string[]) { if (Object.keys(v).some(k => !allowed.includes(k))) throw new Error('Unknown configuration field'); }
function paths(v: unknown): asserts v is string[] { if (!Array.isArray(v) || v.some(p => typeof p !== 'string' || !isAbsolute(p) || p.includes('\0'))) throw new Error('Paths must be absolute strings'); }
function integer(n: unknown, min: number, max: number) { if (!Number.isInteger(n) || Number(n) < min || Number(n) > max) throw new Error('Invalid numeric setting'); }
function analysis(v: unknown, dedicated = false): asserts v is AnalysisConfig {
  object(v); keys(v, ['enabled', 'provider', 'model', 'maxCalls', 'maxInputChars', 'timeoutMs']);
  if (typeof v.enabled !== 'boolean') throw new Error('Invalid analysis enabled');
  integer(v.maxCalls, 0, 1000); integer(v.maxInputChars, 100, 16000); integer(v.timeoutMs, 10, 120000);
  for (const k of ['provider', 'model']) if (v[k] !== undefined && (typeof v[k] !== 'string' || !v[k])) throw new Error('Invalid model selection');
  if (!!v.provider !== !!v.model || (dedicated && v.enabled && !v.model)) throw new Error('Dedicated provider/model pair required');
}
export function validateRule(v: unknown): asserts v is Rule {
  object(v); keys(v, ['tool', 'action', 'key', 'path']);
  if (typeof v.tool !== 'string' || !v.tool || !['ALWAYS_ALLOW', 'ALWAYS_ASK', 'ALWAYS_DENY'].includes(v.action)) throw new Error('Invalid manual rule');
  if (v.key !== undefined && (typeof v.key !== 'string' || !/^[a-f0-9]{64}$/.test(v.key))) throw new Error('Rule key must be an exact operation digest');
  if (v.path !== undefined) paths([v.path]);
  if (v.action === 'ALWAYS_ALLOW' && !v.key) throw new Error('Allow rules require exact operation keys');
}
export function validateConfig(v: unknown): Config {
  object(v); keys(v, Object.keys(defaults()));
  if (v.version !== 1 || typeof v.smart !== 'boolean' || typeof v.reviewDeny !== 'boolean') throw new Error('Unsupported/invalid configuration');
  integer(v.timeoutMs, 10, 3600000);
  for (const k of ['writable', 'readOnly', 'skillPaths']) paths(v[k]);
  if (!Array.isArray(v.rules)) throw new Error('Invalid rules'); v.rules.forEach(validateRule);
  if (!Array.isArray(v.trustedAgents)) throw new Error('Invalid trust');
  for (const t of v.trustedAgents) { object(t); keys(t, ['path', 'digest']); paths([t.path]); if (!/^[a-f0-9]{64}$/.test(t.digest)) throw new Error('Invalid trust digest'); }
  analysis(v.analysis); analysis(v.decisionModel, true);
  return structuredClone(v) as Config;
}
export function loadConfig(path: string): Config {
  try { return validateConfig(JSON.parse(readFileSync(path, 'utf8'))); }
  catch (e: any) { if (e.code === 'ENOENT') return defaults(); throw e; }
}
// Project policy is restriction-only, even when the project itself is trusted.
export function projectRestrictions(path: string, global: Config): Config {
  let v: any; try { v = JSON.parse(readFileSync(path, 'utf8')); } catch (e: any) { if (e.code === 'ENOENT') return global; throw e; }
  object(v); keys(v, ['version', 'readOnly', 'rules']);
  if (v.version !== 1) throw new Error('Invalid project policy version');
  paths(v.readOnly ?? []);
  if (!Array.isArray(v.rules ?? [])) throw new Error('Invalid project rules');
  for (const r of v.rules ?? []) { validateRule(r); if (r.action === 'ALWAYS_ALLOW') throw new Error('Project cannot grant permissions'); }
  return { ...global, readOnly: [...global.readOnly, ...(v.readOnly ?? [])], rules: [...global.rules, ...(v.rules ?? [])] };
}
