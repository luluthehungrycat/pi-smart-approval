import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defaults } from '../src/config.ts';
import { Approver, display } from '../src/approval.ts';
import { Store, atomicJSON } from '../src/storage.ts';
import { Analyzer, bounded, validateAdvisory } from '../src/analysis.ts';
import { evaluate } from '../src/policy.ts';
import { trustedRules, agentDigest } from '../src/agents.ts';
import type { ApprovalPort } from '../src/approval.ts';
function setup(t: any) {
  const root = mkdtempSync(join(tmpdir(), 'approval-test-')); t.after(() => rmSync(root, { recursive: true, force: true }));
  const env = { cwd: join(root, 'cwd'), home: join(root, 'home'), agentDir: join(root, 'home/.pi/agent'), configDir: '.pi', extensionDir: join(root, 'extension') };
  mkdirSync(env.cwd); mkdirSync(env.home); const config = defaults(); const records: any[] = []; let prompts = 0;
  const port: ApprovalPort = { interactive: true, session: 'synthetic-session', select: async () => { prompts++; return 'Allow once'; }, pending: r => records.push(r), persist: async () => {} };
  const call = { tool: 'write', input: { path: 'fixture.txt', content: 'inert' } };
  return { root, env, config, port, records, call, prompts: () => prompts };
}
test('headless denies every interactive requirement without waiting', async t => {
  const { env, config, port, call } = setup(t); port.interactive = false; const a = new Approver();
  assert.equal((await a.decide(call, env, () => config, false, port)).allowed, true);
  for (const c of [{ tool: 'bash', input: { command: 'pwd' } }, { tool: 'write', input: { path: '.pi/settings.json', content: '{}' } }]) assert.equal((await a.decide(c, env, () => config, true, port)).code, 'INTERACTIVE_REQUIRED');
});
test('approval timeout denies and records only metadata, never arguments', async t => {
  const { env, config, port, records } = setup(t); config.timeoutMs = 10;
  port.select = async () => new Promise(() => {});
  const result = await new Approver().decide({ tool: 'bash', input: { command: 'echo synthetic-secret' } }, env, () => config, false, port);
  assert.equal(result.code, 'APPROVAL_TIMEOUT'); assert.equal(records.length, 1); assert.ok(!JSON.stringify(records).includes('synthetic-secret'));
});
test('late approval cannot authorize the timed-out call', async t => {
  const { env, config, port } = setup(t); config.timeoutMs = 10; let resolve!: (s: string) => void;
  port.select = () => new Promise(r => { resolve = r; });
  const result = await new Approver().decide({ tool: 'bash', input: { command: 'pwd' } }, env, () => config, false, port);
  resolve('Allow once'); assert.equal(result.allowed, false);
});
test('protected and opaque operations never offer reusable grants', async t => {
  const { env, config, port } = setup(t); const a = new Approver();
  const calls = [{ tool: 'write', input: { path: '.pi/settings.json', content: '{}' } }, { tool: 'bash', input: { command: 'pwd' } }, { tool: 'custom', input: {} }];
  port.select = async (_title, actions) => { assert.deepEqual(actions, ['Allow once', 'Deny']); return 'Allow once'; };
  for (const call of calls) for (let i = 0; i < 2; i++) assert.equal((await a.decide(call, env, () => config, false, port)).allowed, true);
});
test('session grants bind full input and security context', async t => {
  const { env, config, port, call } = setup(t); config.smart = false; let count = 0;
  port.select = async () => { count++; return 'Allow for session'; }; const a = new Approver();
  assert.equal((await a.decide(call, env, () => config, false, port)).allowed, true);
  assert.equal((await a.decide(call, env, () => config, false, port)).allowed, true); assert.equal(count, 1);
  port.interactive = false;
  assert.equal((await a.decide(call, env, () => config, false, port)).code, 'INTERACTIVE_REQUIRED');
  port.interactive = true;
  await a.decide({ ...call, input: { ...call.input, content: 'different' } }, env, () => config, false, port); assert.equal(count, 2);
  config.readOnly.push(env.cwd); port.select = async (_title, actions) => { assert.deepEqual(actions, ['Allow once', 'Deny']); return 'Deny'; };
  assert.equal((await a.decide(call, env, () => config, false, port)).allowed, false);
});
test('policy and path changes during approval invalidate authorization', async t => {
  const { env, config, port, call, root } = setup(t); config.smart = false;
  port.select = async () => { config.reviewDeny = true; return 'Allow once'; };
  assert.equal((await new Approver().decide(call, env, () => config, false, port)).code, 'REVALIDATION_FAILED');
  port.select = async () => { symlinkSync(join(root, 'outside'), join(env.cwd, 'fixture.txt')); return 'Allow once'; };
  assert.equal((await new Approver().decide(call, env, () => config, false, port)).allowed, false);
});
test('writable-root symlink changes invalidate scope even when the decision remains ASK', async t => {
  const { env, config, port, root } = setup(t); config.smart = false;
  const allowed = join(root, 'allowed'); const other = join(root, 'other'); mkdirSync(allowed); mkdirSync(other);
  const alias = join(root, 'root-alias'); symlinkSync(allowed, alias); config.writable.push(alias);
  port.select = async () => { unlinkSync(alias); symlinkSync(other, alias); return 'Allow for session'; };
  const result = await new Approver().decide({ tool: 'write', input: { path: join(allowed, 'inert.txt'), content: 'fixture' } }, env, () => config, false, port);
  assert.equal(result.code, 'REVALIDATION_FAILED');
});
test('SMART_DENY review excludes persistent permission; hard veto excludes all prompts', async t => {
  const { env, config, port } = setup(t); const a = new Approver();
  const call = { tool: 'bash', input: { command: 'rm fixture' } };
  assert.equal((await a.decide(call, env, () => config, false, port)).code, 'SMART_DENY');
  config.reviewDeny = true; port.select = async (_title, actions) => { assert.ok(!actions.includes('Always allow exact operation')); return 'Allow once'; };
  assert.equal((await a.decide(call, env, () => config, false, port)).allowed, true);
  assert.equal((await a.decide({ tool: 'bash', input: { command: 'rm -rf /' } }, env, () => config, false, port)).code, 'HARD_DENY');
});
test('always allow updates policy but requires reissue; restart clears session grants', async t => {
  const { env, config, port, call } = setup(t); config.smart = false; let saved = false;
  port.select = async () => 'Always allow exact operation'; port.persist = async () => { saved = true; };
  assert.equal((await new Approver().decide(call, env, () => config, false, port)).code, 'POLICY_UPDATED_REISSUE'); assert.equal(saved, true);
  port.select = async () => 'Allow for session'; await new Approver().decide(call, env, () => config, false, port);
  port.interactive = false; assert.equal((await new Approver().decide(call, env, () => config, false, port)).allowed, false);
});
test('pending storage survives restart, reviewed records are inert, unsafe storage rejected', t => {
  const { root } = setup(t); const path = join(root, 'state'); const store = new Store(path);
  const p = { id: '12345678-1234-1234-1234-123456789abc', key: 'a'.repeat(64), tool: 'bash', session: 'fixture', created: Date.now(), status: 'pending' as const, reason: 'test' };
  store.pending(p); assert.deepEqual(new Store(path).list(), [p]);
  store.pending({ ...p, status: 'reviewed' }); assert.equal(store.list()[0].status, 'reviewed'); store.remove(p.id); assert.deepEqual(store.list(), []);
  assert.throws(() => store.remove('../outside'));
  symlinkSync(path, join(root, 'alias')); assert.throws(() => new Store(join(root, 'alias')));
  writeFileSync(join(root, 'unsafe.json'), '{}'); assert.throws(() => atomicJSON(join(root, 'unsafe.json'), {}));
});
test('agent trust is explicit, content-bound, revocable; tools metadata cannot grant', t => {
  const { root, env, config } = setup(t); const p = join(root, 'agent.md'); writeFileSync(p, 'inert definition');
  const metadata = { tools: ['bash'], permissions: { allow: ['Bash(git status)', 'Bash(*)', 'Read(README.md)'] } };
  const snapshot = agentDigest(p, env);
  assert.deepEqual(trustedRules(p, metadata, config, env, snapshot), []);
  config.trustedAgents.push({ path: p, digest: snapshot }); assert.equal(trustedRules(p, metadata, config, env, snapshot).length, 2);
  assert.deepEqual(trustedRules(p, metadata, config, env, '0'.repeat(64)), []); // Parsed snapshot must match the trusted bytes.
  writeFileSync(p, 'changed definition'); assert.deepEqual(trustedRules(p, metadata, config, env, snapshot), []);
  config.trustedAgents = []; assert.deepEqual(trustedRules(p, metadata, config, env, agentDigest(p, env)), []);
});
test('aborted calls and UI errors fail closed without pending automatic replay', async t => {
  const { env, config, port, records } = setup(t); const abort = new AbortController(); abort.abort(); port.signal = abort.signal;
  assert.equal((await new Approver().decide({ tool: 'bash', input: { command: 'pwd' } }, env, () => config, false, port)).code, 'ABORTED');
  assert.equal(records.length, 0);
  port.signal = undefined; port.select = async () => { throw new Error('Mock UI unavailable'); };
  assert.equal((await new Approver().decide({ tool: 'bash', input: { command: 'pwd' } }, env, () => config, false, port)).code, 'APPROVAL_UI_FAILURE');
  assert.equal(records.length, 0);
});
test('decision-model typed probabilities, dedicated selection, and malformed results', async t => {
  const { env, config, call } = setup(t); config.smart = false; const e = evaluate(call, config, env);
  const c = { ...config.decisionModel, enabled: true, provider: 'mock', model: 'classifier' };
  const ctx: any = { modelRegistry: { findOfType: (type: string, provider: string, model: string) => { assert.equal(type, 'classifier'); assert.equal(provider, 'mock'); assert.equal(model, 'classifier'); return { provider, id: model }; }, classify: async () => ({ stopReason: 'stop', answers: { risk: { type: 'choice', probabilities: { allow: 0.98, ask: 0.01, deny: 0.01 } } } }) } };
  const a = new Analyzer(); assert.equal((await a.analyze('write', e, c, ctx, true))?.decision, 'SMART_ALLOW');
  ctx.modelRegistry.classify = async () => ({ stopReason: 'stop', answers: { risk: { type: 'choice', probabilities: { allow: 2, ask: -1, deny: 0 } } } });
  assert.equal(await new Analyzer().analyze('write', e, c, ctx, true), undefined);
  assert.equal(await a.analyze('write', { ...e, protected: true }, c, ctx, true), undefined);
});
const valid = { decision: 'SMART_ALLOW', category: 'test', reasoning: 'fixture', confidence: 0.99, resources: [], observations: [] };
test('strict model schema rejects malformed and injected output', () => {
  assert.deepEqual(validateAdvisory(valid), valid);
  for (const v of [null, { ...valid, confidence: NaN }, { ...valid, decision: 'ALLOW_ALL' }, { ...valid, execute: true }, { ...valid, resources: 'all' }]) assert.throws(() => validateAdvisory(v));
  assert.equal(display('\u001b[31m\u202e'), '?[31m?');
});
test('analysis failure/timeout/budget exhaustion never grant permission', async t => {
  const { env, config, call } = setup(t); config.smart = false; const e = evaluate(call, config, env);
  const c = { ...config.analysis, enabled: true, maxCalls: 1, timeoutMs: 10 };
  const analyzer = new Analyzer(); const ctx: any = { model: { provider: 'mock', id: 'mock' }, modelRegistry: { complete: async () => ({ stopReason: 'stop', content: [{ type: 'text', text: 'not json' }] }) } };
  assert.equal(await analyzer.analyze('write', e, c, ctx), undefined); assert.equal(await analyzer.analyze('write', e, c, ctx), undefined); assert.equal(analyzer.calls.llm, 1);
  ctx.modelRegistry.complete = async () => new Promise(() => {}); assert.equal(await new Analyzer().analyze('write', e, c, ctx), undefined);
  await assert.rejects(bounded(async () => new Promise(() => {}), 5));
});
test('safe advisory cache includes policy/model/context; advice cannot bypass approval', async t => {
  const { env, config, port, call } = setup(t); config.smart = false; const e = evaluate(call, config, env); const a = new Analyzer();
  const c = { ...config.analysis, enabled: true }; let count = 0;
  const ctx: any = { model: { provider: 'mock', id: 'mock' }, modelRegistry: { complete: async () => { count++; return { stopReason: 'stop', content: [{ type: 'text', text: JSON.stringify(valid) }], usage: { totalTokens: 10, cost: { total: 0.001 } } }; } } };
  await a.analyze('write', e, c, ctx); await a.analyze('write', e, c, ctx); assert.equal(count, 1);
  await a.analyze('write', { ...e, fingerprint: 'changed' }, c, ctx); assert.equal(count, 2);
  ctx.model.id = 'different'; await a.analyze('write', e, c, ctx); assert.equal(count, 3); assert.equal(a.tokens, 30);
  port.advice = async () => valid; port.select = async () => 'Deny'; assert.equal((await new Approver().decide(call, env, () => config, false, port)).allowed, false);
});
