import { resolve } from 'node:path';
import { canonical, expand, hash, inside, multipleLinks, protectedPath, sensitive, stamp } from './filesystem.ts';
import type { Call, Config, Environment, Evaluation } from './types.ts';
export function stable(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + stable((v as any)[k])).join(',') + '}';
}
export function shellRisk(command: string): { decision: Evaluation['decision']; reason: string } {
  // These are veto signatures, NOT a shell parser or proof of safety. Unrecognized syntax still asks.
  if (/\bmkfs(?:\.[\w]+)?\b|\bdd\b[^\n]*\bof=\/dev\//i.test(command) || /\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\s+(?:--\s+)?\/(?:\s|$)/i.test(command)) return { decision: 'HARD_DENY', reason: 'Recognized host-volume destruction signature' };
  if (/\b(rm|unlink|shred|sudo|chmod|chown|kill|pkill|systemctl|docker|kubectl|ssh|scp|rsync|terraform)\b|git\s+(reset|clean|checkout|restore|push|rebase)\b|\b(curl|wget)\b.*[|].*\b(sh|bash|python)\b/i.test(command)) return { decision: 'SMART_DENY', reason: 'Destructive, privileged, remote, or download-execution operation' };
  if (/\bgit\s+(status|diff|log|show|branch)\b/.test(command)) return { decision: 'SMART_ASK', reason: 'Git inspection/branch operation; repository config, helpers and external diff may execute code' };
  if (/\b(npm|pnpm|yarn|pip|uv|apt|brew|node|python|bash|sh|eval|exec|curl|wget)\b/.test(command)) return { decision: 'SMART_ASK', reason: 'Package, interpreter, network, or shell operation with indirect effects' };
  return { decision: 'SMART_ASK', reason: 'Shell effects cannot be proven, including composition, expansions and inherited shell configuration' };
}
export function evaluate(call: Call, config: Config, env: Environment, hardOverride = false): Evaluation {
  const result = evaluateInternal(call, config, env, hardOverride);
  // Bind grants/advice to the effective scope and invariant flags as well as file/policy state.
  return { ...result, fingerprint: hash(stable(result)) };
}
function evaluateInternal(call: Call, config: Config, env: Environment, hardOverride = false): Evaluation {
  const key = hash(stable({ call, cwd: env.cwd }));
  const out: Evaluation = { decision: 'SMART_ASK', reason: 'Unknown tool effects require operation-specific review', key, resources: [], protected: false, opaque: true, outside: true, technical: false, fingerprint: '', persistent: false };
  try {
    const file = ['read', 'write', 'edit'].includes(call.tool);
    const write = ['write', 'edit'].includes(call.tool);
    if (file) {
      if (typeof call.input.path !== 'string') throw new Error('Missing file path');
      const path = canonical(call.input.path, env);
      const lexical = resolve(expand(call.input.path, env));
      out.resources = [path]; out.opaque = false; out.outside = false;
      out.protected = write && (protectedPath(path, env) || protectedPath(lexical, env));
      if (multipleLinks(path)) throw new Error('Multiply linked file cannot be authorized reliably');
      // Restrict special files; pipes/devices must not hang or affect the host through file tools.
      out.fingerprint = hash(stable([path, stamp(path), lexical, stamp(lexical), config]));
      if (sensitive(path) || sensitive(lexical)) { out.decision = 'SMART_DENY'; out.reason = 'Sensitive resource'; }
      else { out.decision = 'SMART_ALLOW'; out.reason = write ? 'Ordinary file mutation' : 'Read-only file inspection'; }
      if (write) {
        const roots = [canonical(env.cwd, env), ...config.writable.map(p => canonical(p, env))];
        const excluded = config.readOnly.map(p => canonical(p, env));
        out.outside = !roots.some(r => inside(path, r)) || excluded.some(r => inside(path, r) || inside(lexical, r));
      }
    } else {
      if (call.tool === 'bash') {
        if (typeof call.input.command !== 'string') throw new Error('Missing shell command');
        Object.assign(out, shellRisk(call.input.command));
      }
      out.fingerprint = hash(stable([call, config, env]));
    }
    if (out.decision === 'HARD_DENY') {
      if (!hardOverride) return out;
      out.decision = 'SMART_DENY'; out.reason = 'Hard veto explicitly disabled; underlying destructive operation still requires authorization';
    }
    // Manual DENY remains effective on protected config. No other permission may auto-authorize it.
    const matches = config.rules.filter(r => (r.tool === '*' || r.tool === call.tool) && (!r.key || r.key === key) && (!r.path || out.resources.some(p => inside(p, canonical(r.path!, env)))));
    if (matches.some(r => r.action === 'ALWAYS_DENY')) { out.decision = 'SMART_DENY'; out.reason = 'Manual ALWAYS_DENY'; return { ...out, technical: true }; }
    if (out.protected) { out.decision = 'SMART_ASK'; out.reason = 'Protected Pi configuration: fresh approval of this exact modification is mandatory'; return out; }
    if (matches.some(r => r.action === 'ALWAYS_ASK')) { out.decision = 'SMART_ASK'; out.reason = 'Manual ALWAYS_ASK'; return out; }
    // An opaque tool might modify Pi config or bypass writable scope. Never reuse permissions for it.
    if (out.opaque) return out;
    if (out.outside) {
      if (out.decision !== 'SMART_DENY') out.decision = 'SMART_ASK';
      out.reason = 'Outside writable scope or explicitly read-only; exact operation approval required'; return out;
    }
    out.persistent = out.decision !== 'SMART_DENY';
    if (matches.some(r => r.action === 'ALWAYS_ALLOW')) { out.decision = 'SMART_ALLOW'; out.reason = 'Exact manual operation rule within authorized scope'; }
    else if (!config.smart && out.decision === 'SMART_ALLOW') { out.decision = 'SMART_ASK'; out.reason = 'Smart auto-approval disabled (enforcement remains active)'; }
    return out;
  } catch {
    return { ...out, decision: 'SMART_DENY', technical: true, reason: 'Security validation failed: invalid, ambiguous, inaccessible, or multiply linked path/arguments' };
  }
}
