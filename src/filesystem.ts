import { lstatSync, realpathSync, statSync } from 'node:fs';
import { resolve, join, dirname, sep, isAbsolute, parse } from 'node:path';
import { createHash } from 'node:crypto';
import type { Environment } from './types.ts';
export const hash = (s: string) => createHash('sha256').update(s).digest('hex');
export function inside(path: string, root: string): boolean { return path === root || path.startsWith(root.endsWith(sep) ? root : root + sep); }
export function expand(raw: string, env: Environment): string {
  if (!raw || raw.includes('\0') || /^file:/i.test(raw.replace(/^@/, ''))) throw new Error('Invalid/unsupported path spelling');
  let p = raw.replace(/^@/, '').replace(/[\u00a0\u2000-\u200a\u202f\u205f\u3000]/g, ' ');
  if (p === '~' || p.startsWith('~/')) p = env.home + p.slice(1);
  return isAbsolute(p) ? p : env.cwd + sep + p;
}
// Walk before collapsing '..': reject ambiguous spelling rather than authorize a different target.
export function canonical(raw: string, env: Environment): string {
  const expanded = expand(raw, env);
  if (expanded.split(sep).includes('..')) throw new Error('Parent traversal requires an unambiguous absolute path');
  const target = resolve(expanded);
  let ancestor = target; const tail: string[] = [];
  for (;;) {
    try {
      lstatSync(ancestor); // A dangling symlink must fail, not be treated as a missing file.
      return join(realpathSync(ancestor), ...tail);
    } catch (e: any) {
      if (e.code !== 'ENOENT') throw e;
      // lstat succeeds for dangling links; realpath ENOENT must fail closed.
      try { if (lstatSync(ancestor).isSymbolicLink()) throw new Error('Dangling symlink'); } catch (x: any) { if (x.code !== 'ENOENT') throw x; }
      if (ancestor === parse(ancestor).root) throw e;
      tail.unshift(ancestor.slice(dirname(ancestor).length + (dirname(ancestor) === sep ? 0 : 1)));
      ancestor = dirname(ancestor);
    }
  }
}
export function stamp(path: string): string {
  let p = path; const records: unknown[] = [];
  for (;;) {
    try {
      const s = lstatSync(p);
      // Ancestor identity/mode matters; unrelated sibling creation must not expire approval.
      records.push(p === path && !s.isDirectory() ? [p, s.dev, s.ino, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs] : [p, s.dev, s.ino, s.mode]);
    }
    catch (e: any) { if (e.code !== 'ENOENT') throw e; records.push([p, 'missing']); }
    if (dirname(p) === p) break; p = dirname(p);
  }
  return hash(JSON.stringify(records));
}
export function protectedPath(path: string, env: Environment): boolean {
  if (inside(path, canonical(env.extensionDir, env))) return true;
  const agent = canonical(env.agentDir, env);
  // Global skills are content, not Pi policy. Project .pi content stays protected.
  const skills = join(agent, 'skills');
  if (inside(path, skills)) {
    const nested = path.slice(skills.length).split(sep);
    return nested.includes(env.configDir) || nested.includes('.pi');
  }
  const components = path.split(sep);
  return components.includes(env.configDir) || components.includes('.pi') || inside(path, agent);
}
export function sensitive(path: string): boolean {
  return /(?:^|\/)(?:\.ssh|\.aws|\.gnupg|\.kube|\.env(?:\.[^/]*)?|auth\.json|credentials(?:\.json)?|id_rsa|id_ed25519)(?:\/|$)/i.test(path) || inside(path, '/proc') || inside(path, '/dev') || inside(path, '/sys');
}
export function multipleLinks(path: string): boolean {
  try { const s = statSync(path); if (!s.isFile() && !s.isDirectory()) throw new Error('Special file'); return s.isFile() && s.nlink > 1; } catch (e: any) { if (e.code === 'ENOENT') return false; throw e; }
}
