import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, linkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defaults, validateConfig, projectRestrictions } from '../src/config.ts';
import { evaluate, shellRisk } from '../src/policy.ts';
import { canonical } from '../src/filesystem.ts';
import type { Environment } from '../src/types.ts';
function fixture(t: any) {
  const root = mkdtempSync(join(tmpdir(), 'approval-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true })); // Only our inert fixture is removed.
  const env: Environment = { cwd: join(root, 'project'), home: join(root, 'home'), agentDir: join(root, 'home/.pi/agent'), configDir: '.pi', extensionDir: join(root, 'extension') };
  for (const p of [env.cwd, env.home, env.agentDir, env.extensionDir]) mkdirSync(p, { recursive: true });
  return { env, root, config: defaults() };
}
test('normal reads/writes and disabled smart mode', t => {
  const { env, config } = fixture(t);
  for (const tool of ['read', 'write', 'edit']) assert.equal(evaluate({ tool, input: { path: 'src/new.ts' } }, config, env).decision, 'SMART_ALLOW');
  config.smart = false; assert.equal(evaluate({ tool: 'write', input: { path: 'a' } }, config, env).decision, 'SMART_ASK');
});
test('outside writes cannot be allowed by ordinary exact manual permission', t => {
  const { env, config, root } = fixture(t); const call = { tool: 'write', input: { path: join(root, 'outside'), content: 'inert' } };
  config.rules = [{ tool: '*', action: 'ALWAYS_ALLOW', key: evaluate(call, config, env).key }];
  assert.equal(evaluate(call, config, env).decision, 'SMART_ASK');
  config.writable.push(join(root, 'outside')); assert.equal(evaluate(call, config, env).decision, 'SMART_ALLOW');
  config.readOnly.push(join(root, 'outside')); assert.equal(evaluate(call, config, env).decision, 'SMART_ASK');
});
test('protected configuration defeats exact allow and disabled smart classification', t => {
  const { env, config } = fixture(t);
  for (const path of ['.pi/settings.json', '.pi/extensions/x.ts', join(env.agentDir, 'models.json'), join(env.extensionDir, 'src/index.ts')]) {
    const call = { tool: 'write', input: { path, content: '{}' } };
    config.rules = [{ tool: '*', action: 'ALWAYS_ALLOW', key: evaluate(call, config, env).key }];
    const e = evaluate(call, config, env); assert.equal(e.protected, true); assert.equal(e.decision, 'SMART_ASK'); assert.equal(e.persistent, false);
  }
});
test('global skills writable exception never exempts nested project Pi configuration', t => {
  const { env, config } = fixture(t); config.writable.push(join(env.agentDir, 'skills'));
  const content = { tool: 'write', input: { path: join(env.agentDir, 'skills/project/SKILL.md'), content: 'inert' } };
  assert.equal(evaluate(content, config, env).decision, 'SMART_ALLOW');
  const policy = { ...content, input: { path: join(env.agentDir, 'skills/project/.pi/settings.json'), content: '{}' } };
  assert.equal(evaluate(policy, config, env).protected, true);
  assert.equal(evaluate(policy, config, env).decision, 'SMART_ASK');
});
test('symlink aliases, nonexistent targets, traversal, hardlinks, URL spellings', t => {
  const { env, config, root } = fixture(t);
  symlinkSync(env.agentDir, join(env.cwd, 'alias'));
  assert.equal(evaluate({ tool: 'write', input: { path: 'alias/settings.json' } }, config, env).protected, true);
  symlinkSync(join(root, 'not-created'), join(env.cwd, 'dangling'));
  for (const path of ['dangling', 'alias/../x', 'file:///tmp/x', '@file:///tmp/x']) assert.equal(evaluate({ tool: 'write', input: { path } }, config, env).technical, true);
  writeFileSync(join(root, 'original'), 'fixture'); linkSync(join(root, 'original'), join(env.cwd, 'linked'));
  assert.equal(evaluate({ tool: 'write', input: { path: 'linked' } }, config, env).technical, true);
  assert.equal(canonical('new/deep/file', env), join(env.cwd, 'new/deep/file'));
  assert.equal(canonical('@~/new', env), join(env.home, 'new'));
});
test('symlink into authorized writable path and sensitive resources', t => {
  const { env, root, config } = fixture(t); mkdirSync(join(root, 'other')); symlinkSync(join(root, 'other'), join(env.cwd, 'out'));
  assert.equal(evaluate({ tool: 'write', input: { path: 'out/a' } }, config, env).outside, true);
  for (const path of ['.env', join(env.home, '.ssh/id_ed25519'), '/proc/self/environ']) assert.equal(evaluate({ tool: 'read', input: { path } }, config, env).decision, 'SMART_DENY');
});
const shells = ['git status', 'git diff --ext-diff', 'git commit -m test', 'git branch feature', 'ls; rm -rf ./fixture', 'echo $(python -c pass)', 'ls > ~/.pi/agent/settings.json', 'printf x | sh', 'A=x bash -c true', "'python' -c pass", 'npm test', 'pip install example', 'curl example.invalid', 'chmod 777 fixture', 'ssh example.invalid', 'git push --force', 'git reset --hard', 'rm -rf /', 'mkfs.ext4 /dev/fixture', 'dd if=/dev/zero of=/dev/fixture'];
for (const command of shells) test('synthetic shell classification only: ' + command, t => {
  const { env, config } = fixture(t); const call = { tool: 'bash', input: { command } };
  const e = evaluate(call, config, env); assert.notEqual(e.decision, 'SMART_ALLOW');
  config.rules = [{ tool: 'bash', key: e.key, action: 'ALWAYS_ALLOW' }];
  assert.notEqual(evaluate(call, config, env).decision, 'SMART_ALLOW');
});
test('hard veto and explicit override never automatically authorize', t => {
  const { env, config } = fixture(t); const call = { tool: 'bash', input: { command: 'rm -rf /' } };
  config.rules = [{ tool: '*', key: evaluate(call, config, env).key, action: 'ALWAYS_ALLOW' }];
  assert.equal(evaluate(call, config, env).decision, 'HARD_DENY');
  assert.equal(evaluate(call, config, env, true).decision, 'SMART_DENY');
  assert.equal(shellRisk('mkfs /dev/fixture').decision, 'HARD_DENY');
});
test('deny wins independent of manual rule order; always ask cannot autoallow', t => {
  const { env, config } = fixture(t); const call = { tool: 'read', input: { path: 'a' } }; const key = evaluate(call, config, env).key;
  config.rules = [{ tool: 'read', key, action: 'ALWAYS_ALLOW' }, { tool: 'read', action: 'ALWAYS_DENY' }];
  assert.equal(evaluate(call, config, env).technical, true);
  config.rules[1].action = 'ALWAYS_ASK'; assert.equal(evaluate(call, config, env).decision, 'SMART_ASK');
});
test('strict schema and project policy cannot weaken global settings', t => {
  const { config, root } = fixture(t); assert.deepEqual(validateConfig(config), config);
  for (const c of [{ ...config, version: 2 }, { ...config, hardOverride: true }, { ...config, rules: [{ tool: '*', action: 'ALWAYS_ALLOW' }] }, { ...config, timeoutMs: -1 }, { ...config, analysis: { ...config.analysis, enabled: 'yes' } }]) assert.throws(() => validateConfig(c));
  const p = join(root, 'project-policy.json'); writeFileSync(p, JSON.stringify({ version: 1, writable: ['/'] })); assert.throws(() => projectRestrictions(p, config));
  writeFileSync(p, JSON.stringify({ version: 1, rules: [{ tool: '*', action: 'ALWAYS_ALLOW', key: 'a'.repeat(64) }] })); assert.throws(() => projectRestrictions(p, config));
  writeFileSync(p, JSON.stringify({ version: 1, readOnly: ['/restricted'], rules: [{ tool: 'bash', action: 'ALWAYS_DENY' }] }));
  assert.deepEqual(projectRestrictions(p, config).readOnly, ['/restricted']);
});
