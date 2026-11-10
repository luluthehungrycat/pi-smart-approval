import { mkdirSync, lstatSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync, unlinkSync, readdirSync, readFileSync, constants } from 'node:fs';
import { dirname, join, resolve, parse } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Pending } from './types.ts';
function noSymlinks(path: string) {
  let p = resolve(path);
  while (p !== parse(p).root) {
    try { if (lstatSync(p).isSymbolicLink()) throw new Error('Storage symlinks are not allowed'); }
    catch (e: any) { if (e.code !== 'ENOENT') throw e; }
    p = dirname(p);
  }
}
export function privateDir(path: string) {
  noSymlinks(path); mkdirSync(path, { recursive: true, mode: 0o700 });
  const s = lstatSync(path);
  if (!s.isDirectory() || (s.mode & 0o077) || (process.getuid && s.uid !== process.getuid())) throw new Error('State directory must be owned by current user and mode 0700');
}
export function atomicJSON(path: string, data: unknown) {
  privateDir(dirname(path)); noSymlinks(path);
  try { const s = lstatSync(path); if (!s.isFile() || s.nlink !== 1 || (s.mode & 0o077)) throw new Error('Unsafe storage target'); }
  catch (e: any) { if (e.code !== 'ENOENT') throw e; }
  const temp = join(dirname(path), '.' + randomUUID() + '.tmp');
  let fd: number | undefined;
  try {
    fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    writeFileSync(fd, JSON.stringify(data, null, 2) + '\n'); fsyncSync(fd); closeSync(fd); fd = undefined;
    renameSync(temp, path);
    const dir = openSync(dirname(path), constants.O_RDONLY); try { fsyncSync(dir); } finally { closeSync(dir); }
  } finally { if (fd !== undefined) closeSync(fd); try { unlinkSync(temp); } catch (e: any) { if (e.code !== 'ENOENT') throw e; } }
}
export class Store {
  root: string;
  constructor(root: string) { this.root = root; privateDir(root); privateDir(join(root, 'pending')); privateDir(join(root, 'audit')); }
  pending(record: Pending) { atomicJSON(join(this.root, 'pending', this.id(record.id) + '.json'), record); }
  list(): Pending[] {
    return readdirSync(join(this.root, 'pending')).filter(n => /^[a-f0-9-]{36}\.json$/.test(n)).map(n => {
      const p = join(this.root, 'pending', n); noSymlinks(p);
      const v = JSON.parse(readFileSync(p, 'utf8'));
      if (v.id + '.json' !== n || typeof v.key !== 'string' || typeof v.tool !== 'string' || !['pending', 'reviewed', 'rejected'].includes(v.status)) throw new Error('Corrupt pending record');
      return v as Pending;
    }).sort((a, b) => b.created - a.created);
  }
  remove(id: string) { unlinkSync(join(this.root, 'pending', this.id(id) + '.json')); }
  audit(record: { key: string; tool: string; decision: string; reason: string; allowed: boolean }) {
    // No raw arguments, contents, paths, model text, or credentials on disk.
    atomicJSON(join(this.root, 'audit', Date.now() + '-' + randomUUID() + '.json'), { ...record, time: Date.now() });
    const names = readdirSync(join(this.root, 'audit')).filter(n => /^\d+-[a-f0-9-]{36}\.json$/.test(n)).sort();
    for (const n of names.slice(0, -200)) unlinkSync(join(this.root, 'audit', n));
  }
  recent(): unknown[] {
    return readdirSync(join(this.root, 'audit')).filter(n => /^\d+-[a-f0-9-]{36}\.json$/.test(n)).sort().slice(-20).reverse().map(n => {
      const p = join(this.root, 'audit', n); noSymlinks(p); return JSON.parse(readFileSync(p, 'utf8'));
    });
  }
  private id(id: string) { if (!/^[a-f0-9-]{36}$/.test(id)) throw new Error('Invalid pending id'); return id; }
}
