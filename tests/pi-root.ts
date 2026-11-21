// Locate an installed @earendil-works/pi-coding-agent package for the lifecycle integration test.
// Read-only filesystem lookups only: never executes `pi`, `npm` or any other program.
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';

export const PACKAGE = '@earendil-works/pi-coding-agent';
export const LOADER = 'dist/core/extensions/loader.js';
const isPiRoot = (dir: string): boolean => {
  try { return JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).name === PACKAGE && existsSync(join(dir, LOADER)); } catch { return false; }
};

export function candidatePiRoots(env: NodeJS.ProcessEnv = process.env, home = homedir()): string[] {
  const out: string[] = [];
  // 1. A `pi` on PATH that is (a link to) a file inside the npm package: walk up to the package root.
  for (const dir of (env.PATH ?? '').split(delimiter)) {
    if (!dir) continue;
    let p: string; try { p = realpathSync(join(dir, 'pi')); } catch { continue; }
    for (let d = dirname(p); d !== dirname(d); d = dirname(d)) if (d.endsWith(join('node_modules', PACKAGE))) { out.push(d); break; }
  }
  // 2. Pi's managed installer: ~/.pi/agent/install/releases/<current-version>/node_modules/<package>.
  try {
    const version = readFileSync(join(home, '.pi/agent/install/current-version'), 'utf8').trim();
    if (/^[0-9A-Za-z.+-]+$/.test(version)) out.push(join(home, '.pi/agent/install/releases', version, 'node_modules', PACKAGE));
  } catch {}
  // 3. Common global npm prefixes, including the one of the running Node binary.
  for (const prefix of [dirname(dirname(process.execPath)), join(home, '.local'), join(home, '.npm-global'), '/usr/local', '/usr']) out.push(join(prefix, 'lib/node_modules', PACKAGE));
  return [...new Set(out)];
}

// An explicit PI_SMART_APPROVAL_TEST_PI_ROOT always wins and must be valid; otherwise auto-detect.
export function findPiRoot(env: NodeJS.ProcessEnv = process.env, home = homedir()): { root?: string; error?: string; source?: string } {
  const explicit = env.PI_SMART_APPROVAL_TEST_PI_ROOT;
  if (explicit) return isPiRoot(explicit) ? { root: explicit, source: 'PI_SMART_APPROVAL_TEST_PI_ROOT' } : { error: `PI_SMART_APPROVAL_TEST_PI_ROOT=${explicit} is not a ${PACKAGE} package containing ${LOADER}` };
  const root = candidatePiRoots(env, home).find(isPiRoot);
  return root ? { root, source: 'auto-detected' } : {};
}
