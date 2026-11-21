import { resolve } from 'node:path';
import { canonical, expand, hash, inside, multipleLinks, protectedPath, sensitive, stamp } from './filesystem.ts';
import { analyzeShell } from './shell.ts';
import type { Call, Config, Environment, Evaluation } from './types.ts';
// Programs whose exact invocation still delegates to arbitrary other commands or remote/privileged
// effects. They never receive session or persistent grants, only fresh one-time review.
const UNGRANTABLE = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'csh', 'tcsh', 'eval', 'exec', 'env', 'sudo', 'su', 'doas', 'pkexec', 'xargs', 'nohup', 'timeout', 'nice', 'ionice', 'watch', 'command', 'builtin', 'source', 'setsid', 'stdbuf', 'chroot', 'unshare', 'nsenter', 'ssh', 'scp', 'sftp', 'rsync', 'curl', 'wget', 'nc', 'ncat', 'socat', 'telnet', 'ftp', 'busybox', 'script', 'expect', 'at', 'batch', 'crontab']);
const INLINE_CODE = new Set(['-c', '-e', '-p', '-E', '--eval', '--print', '--command', '-r', '-x', '-m']);
const INTERPRETERS = /^(?:node|nodejs|deno|bun|python[0-9.]*|pypy[0-9.]*|perl|ruby|php|lua|luajit|tclsh|osascript|pwsh|powershell|awk|gawk|mawk|nawk|sed|jq|vim|vi|nvim|emacs|ed|ex)$/;
// The shell Pi spawns inherits this environment. Function exports, BASH_ENV/ENV, loader injection or a
// relative/workspace PATH entry can change what a literal command runs, so they disable shell reuse.
export function shellContext(env: Environment): { digest: string; safe: boolean } {
  const e = env.shellEnv ?? process.env;
  const names = Object.keys(e).filter(k => /^BASH_FUNC_/.test(k)).sort();
  const path = e.PATH ?? '';
  const entries = path.split(':');
  const cwd = (() => { try { return canonical(env.cwd, env); } catch { return env.cwd; } })();
  const safe = !names.length && !e.BASH_ENV && !e.ENV && !e.LD_PRELOAD && !e.LD_LIBRARY_PATH && !e.LD_AUDIT && !e.SHELLOPTS && !e.BASHOPTS && !!path &&
    entries.every(p => p.startsWith('/') && !p.split('/').includes('..') && !inside(p, cwd) && !inside(p, env.cwd));
  const digest = hash(stable({ PATH: path, SHELL: e.SHELL ?? null, HOME: e.HOME ?? null, BASH_ENV: e.BASH_ENV ?? null, ENV: e.ENV ?? null, LD_PRELOAD: e.LD_PRELOAD ?? null, LD_LIBRARY_PATH: e.LD_LIBRARY_PATH ?? null, LD_AUDIT: e.LD_AUDIT ?? null, SHELLOPTS: e.SHELLOPTS ?? null, BASHOPTS: e.BASHOPTS ?? null, functions: names.map(n => [n, e[n]]) }));
  return { digest, safe };
}
// Words that look like filesystem paths in a non-routine command. Used only to RESTRICT reuse, never to allow.
function pathLike(word: string): string | undefined {
  const value = word.startsWith('-') && word.includes('=') ? word.slice(word.indexOf('=') + 1) : word;
  return value.includes('/') || value.startsWith('.') ? value : undefined;
}
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
  const out: Evaluation = { decision: 'SMART_ASK', reason: 'Unknown tool effects require operation-specific review', key, resources: [], protected: false, opaque: true, outside: true, technical: false, fingerprint: '', persistent: false, ruleKey: key };
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
      let context = '';
      if (call.tool === 'bash') {
        if (typeof call.input.command !== 'string') throw new Error('Missing shell command');
        const command = call.input.command;
        const risk = shellRisk(command); Object.assign(out, risk);
        const ctx = shellContext(env); context = ctx.digest;
        out.ruleKey = hash(stable({ call, cwd: env.cwd, shell: ctx.digest }));
        const parsed = analyzeShell(command);
        // Only parsed literal simple commands that no veto signature matched become non-opaque.
        // Complex, ambiguous or vetoed shell stays opaque: fresh one-time review only.
        if (parsed.simple && ctx.safe && out.decision === 'SMART_ASK') {
          const [program, ...args] = parsed.argv;
          const root = canonical(env.cwd, env);
          const scoped = (raw: string) => {
            try {
              const p = canonical(raw, env); const lexical = resolve(expand(raw, env));
              return inside(p, root) && inside(lexical, root) && !sensitive(p) && !sensitive(lexical) && !protectedPath(p, env) && !protectedPath(lexical, env) && !multipleLinks(p) ? p : undefined;
            } catch { return undefined; }
          };
          const grantable = !UNGRANTABLE.has(program) && !(INTERPRETERS.test(program) && args.some(a => INLINE_CODE.has(a) || /^--?(?:eval|exec|print|command)=/.test(a)));
          const mentioned = args.map(pathLike).filter((p): p is string => p !== undefined);
          const resolved = mentioned.map(scoped);
          if (grantable && resolved.every(Boolean)) {
            out.opaque = false; out.outside = false; out.resources = resolved as string[];
            out.reason = risk.reason + '. Exact simple command: reviewable, but its effects are not sandboxed or proven';
            out.shell = { program, flags: [], grantable: true, context: ctx.digest };
            // Recursive grep reads file contents below a directory, which could include sensitive files
            // the read tool would deny. Keep it at human review.
            const recursiveRead = program === 'grep' && args.some(a => /^-[A-Za-z]*r/.test(a));
            if (parsed.routine && !recursiveRead) {
              const routinePaths = parsed.paths.map(scoped);
              if (routinePaths.every(Boolean)) {
                out.resources = [...new Set([...(routinePaths as string[]), ...out.resources])];
                out.shell.tier = parsed.routine;
                out.shell.flags = args.filter(a => /^-[A-Za-z0-9-]{1,20}$/.test(a));
                if (parsed.routine === 'auto') { out.decision = 'SMART_ALLOW'; out.reason = 'Routine read-only shell command inside the workspace (deterministic allowlist)'; }
                else out.reason = 'Routine-eligible read-only shell command; deterministic scope checked, human or enabled model assessment required';
              }
            }
          }
        }
      }
      // The shell digest stands in for the inherited environment; never hash the full environment.
      out.fingerprint = hash(stable([call, config, { ...env, shellEnv: null }, context]));
    }
    if (out.decision === 'HARD_DENY') {
      if (!hardOverride) return out;
      out.decision = 'SMART_DENY'; out.reason = 'Hard veto explicitly disabled; underlying destructive operation still requires authorization';
    }
    // Manual DENY remains effective on protected config. No other permission may auto-authorize it.
    const matches = config.rules.filter(r => (r.tool === '*' || r.tool === call.tool) && (!r.key || r.key === key || r.key === out.ruleKey) && (!r.path || out.resources.some(p => inside(p, canonical(r.path!, env)))));
    // A persistent allow must carry the exact rule key (for shell: command, cwd and shell environment digest).
    const allowRule = matches.some(r => r.action === 'ALWAYS_ALLOW' && r.key === out.ruleKey);
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
    if (allowRule) { out.decision = 'SMART_ALLOW'; out.reason = 'Exact manual operation rule within authorized scope'; }
    else if (!config.smart && out.decision === 'SMART_ALLOW') { out.decision = 'SMART_ASK'; out.reason = 'Smart auto-approval disabled (enforcement remains active)'; }
    return out;
  } catch {
    return { ...out, decision: 'SMART_DENY', technical: true, reason: 'Security validation failed: invalid, ambiguous, inaccessible, or multiply linked path/arguments' };
  }
}
