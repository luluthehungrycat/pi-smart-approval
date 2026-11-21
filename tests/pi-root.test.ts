import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { findPiRoot, PACKAGE, LOADER } from './pi-root.ts';

// Inert fake package layouts only; nothing is executed.
function fakePackage(dir: string) {
  mkdirSync(join(dir, dirname(LOADER)), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: PACKAGE })); writeFileSync(join(dir, LOADER), '');
  mkdirSync(join(dir, 'dist/bundle'), { recursive: true }); writeFileSync(join(dir, 'dist/bundle/cli.js'), '');
}
function fixture(t: any) { const root = mkdtempSync(join(tmpdir(), 'pi-root-test-')); t.after(() => rmSync(root, { recursive: true, force: true })); return root; }

test('finds an npm install through a `pi` symlink on PATH', t => {
  const root = fixture(t); const home = join(root, 'home'); const pkg = join(home, '.local/lib/node_modules', PACKAGE);
  fakePackage(pkg); mkdirSync(join(root, 'bin')); symlinkSync(join(pkg, 'dist/bundle/cli.js'), join(root, 'bin/pi'));
  assert.deepEqual(findPiRoot({ PATH: join(root, 'bin') }, join(root, 'other-home')), { root: pkg, source: 'auto-detected' });
});
test('finds the managed installer release named by current-version', t => {
  const root = fixture(t); const pkg = join(root, '.pi/agent/install/releases/9.9.9/node_modules', PACKAGE);
  fakePackage(pkg); writeFileSync(join(root, '.pi/agent/install/current-version'), '9.9.9\n');
  assert.equal(findPiRoot({ PATH: '' }, root).root, pkg);
});
test('explicit variable must be valid; nothing found means skip', t => {
  const root = fixture(t);
  assert.match(findPiRoot({ PI_SMART_APPROVAL_TEST_PI_ROOT: join(root, 'missing'), PATH: '' }, root).error ?? '', /is not a/);
  assert.equal(findPiRoot({ PI_SMART_APPROVAL_TEST_PI_ROOT: '', PATH: '' }, root).error, undefined);
  const wrong = join(root, 'pkg'); fakePackage(wrong); writeFileSync(join(wrong, 'package.json'), JSON.stringify({ name: 'other' }));
  assert.ok(findPiRoot({ PI_SMART_APPROVAL_TEST_PI_ROOT: wrong, PATH: '' }, root).error);
});
