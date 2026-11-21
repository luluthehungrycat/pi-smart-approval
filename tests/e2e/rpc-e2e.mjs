#!/usr/bin/env node
// Live end-to-end check of the approval and reply flow through a real `pi --mode rpc` process.
//
// Safety: everything runs inside a fresh temporary directory with its own PI_CODING_AGENT_DIR, so no
// host Pi configuration, credentials or sessions are read or written. The model is a local scripted
// OpenAI-compatible server on 127.0.0.1 (no network, no cost). The only commands that can execute are
// inert `touch <marker>` / `ls` inside the temporary workspace; markers prove whether a tool ran.
//
// The RPC client answers dialogs exactly as stock T3 Code's Pi adapter does: select -> {value} or
// {cancelled:true}. Optionally (T3_BRIDGE=path) T3 Code's own injected Pi extension is loaded with
// T3_PI_RUNTIME_MODE to show that Full access produces no second bridge prompt.
//
// Usage: node tests/e2e/rpc-e2e.mjs   (PI_BIN overrides the pi executable)
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync, readdirSync, rmSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const PI = process.env.PI_BIN ?? 'pi';
const bridge = process.env.T3_BRIDGE;
const root = mkdtempSync(join(tmpdir(), 'smart-approval-rpc-e2e-'));
const agentDir = join(root, 'agent'); const ws = join(root, 'workspace'); const ws2 = join(root, 'workspace2');
for (const d of [agentDir, ws, ws2]) mkdirSync(d, { recursive: true });
const results = []; let failures = 0;
const check = (name, ok, detail = '') => { results.push({ name, ok, detail }); if (!ok) failures++; console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`); };

// Scripted model: the user prompt is `RUN <json bash input>`; first reply is that tool call, then "done".
let callSeq = 0;
const server = createServer((req, res) => {
  let body = ''; req.on('data', c => body += c); req.on('end', () => {
    const msgs = JSON.parse(body).messages ?? [];
    const last = msgs[msgs.length - 1];
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    const send = o => res.write('data: ' + JSON.stringify(o) + '\n\n');
    const text = typeof last?.content === 'string' ? last.content : (last?.content ?? []).map(p => p.text ?? '').join('');
    if (last?.role === 'user' && text.startsWith('RUN ')) {
      send({ id: 'x', object: 'chat.completion.chunk', choices: [{ index: 0, delta: { role: 'assistant', tool_calls: [{ index: 0, id: 'call_' + (++callSeq), type: 'function', function: { name: 'bash', arguments: text.slice(4) } }] } }] });
      send({ id: 'x', object: 'chat.completion.chunk', choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] });
    } else {
      send({ id: 'x', object: 'chat.completion.chunk', choices: [{ index: 0, delta: { role: 'assistant', content: 'done' } }] });
      send({ id: 'x', object: 'chat.completion.chunk', choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] });
    }
    res.end('data: [DONE]\n\n');
  });
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
writeFileSync(join(agentDir, 'models.json'), JSON.stringify({ providers: { fake: { baseUrl: `http://127.0.0.1:${port}/v1`, api: 'openai-completions', apiKey: 'inert-test-key', models: [{ id: 'scripted', name: 'scripted', contextWindow: 32000, maxTokens: 1000, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] } } }));
// Short approval timeout so the expiry scenario completes quickly. Created with private permissions.
mkdirSync(join(agentDir, 'smart-approval'), { recursive: true, mode: 0o700 });
const policyPath = join(agentDir, 'smart-approval/config.json');
writeFileSync(policyPath, JSON.stringify({ version: 1, smart: true, timeoutMs: 4000, reviewDeny: false, writable: [], readOnly: [], skillPaths: [], rules: [], trustedAgents: [], analysis: { enabled: false, maxCalls: 10, maxInputChars: 4000, timeoutMs: 10000 }, decisionModel: { enabled: false, maxCalls: 10, maxInputChars: 4000, timeoutMs: 10000 } }), { mode: 0o600 });

function startPi(cwd, runtimeMode) {
  const args = ['--mode', 'rpc', '--no-session', '--no-extensions', '--offline', '--model', 'fake/scripted', '-e', join(repo, 'src/index.ts')];
  if (bridge) args.push('-e', bridge);
  const env = { ...process.env, PI_CODING_AGENT_DIR: agentDir, PI_OFFLINE: '1' };
  delete env.CI; delete env.T3_MCP_URL; delete env.T3_MCP_BEARER_TOKEN;
  if (bridge) { env.T3_PI_RUNTIME_MODE = runtimeMode; env.T3_PI_MCP_EXTENSION_PATH = bridge; }
  const child = spawn(PI, args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
  const waiters = []; const log = [];
  let stderr = ''; child.stderr.on('data', d => { stderr += d; });
  createInterface({ input: child.stdout }).on('line', line => {
    let ev; try { ev = JSON.parse(line); } catch { return; }
    log.push(ev);
    for (const w of [...waiters]) if (w.match(ev)) { waiters.splice(waiters.indexOf(w), 1); w.resolve(ev); }
  });
  const send = o => child.stdin.write(JSON.stringify(o) + '\n');
  const wait = (match, ms = 20000) => new Promise((res, rej) => { const w = { match, resolve: v => { clearTimeout(t); res(v); } }; const t = setTimeout(() => { waiters.splice(waiters.indexOf(w), 1); rej(new Error('timeout waiting; stderr: ' + stderr.slice(-2000))); }, ms); waiters.push(w); });
  return { child, send, wait, log, stderr: () => stderr };
}

// Run one tool call; `answers` is a list of replies (by dialog order): string value, {cancelled}, or 'NO_REPLY'.
async function run(pi, input, answers = [], { userBash = false } = {}) {
  const start = pi.log.length; const dialogs = [];
  const answer = async () => {
    for (;;) {
      const ev = await pi.wait(e => e.type === 'extension_ui_request' && ['select', 'confirm', 'input', 'editor'].includes(e.method), 60000).catch(() => undefined);
      if (!ev) return;
      dialogs.push({ method: ev.method, title: ev.title, options: ev.options, timeout: ev.timeout });
      const ci = answers.findIndex(x => typeof x === 'object' && 'confirmed' in x);
      const a = ev.method === 'confirm' && ci >= 0 ? answers.splice(ci, 1)[0] : answers.shift();
      if (a === undefined || a === 'NO_REPLY') { if (a === 'NO_REPLY') { lateIds.push(ev.id); continue; } return; }
      pi.send(typeof a === 'string' ? { type: 'extension_ui_response', id: ev.id, value: a } : { type: 'extension_ui_response', id: ev.id, ...a });
    }
  };
  const lateIds = [];
  const answering = answer();
  let output;
  if (userBash) {
    pi.send({ id: 'b' + start, type: 'bash', command: input.command });
    output = await pi.wait(e => e.type === 'response' && e.command === 'bash', 60000);
  } else {
    pi.send({ id: 'p' + start, type: 'prompt', message: 'RUN ' + JSON.stringify(input) });
    await pi.wait(e => e.type === 'agent_settled', 60000);
  }
  const events = pi.log.slice(start);
  const end = events.find(e => e.type === 'tool_execution_end');
  // Late reply after expiry must not authorize anything.
  for (const id of lateIds) pi.send({ type: 'extension_ui_response', id, value: 'Allow once' });
  return { dialogs, end, events, output, answering };
}
const blockedCode = r => { const t = r.end?.result?.content?.map(c => c.text).join('') ?? r.output?.data?.output ?? ''; try { return JSON.parse(t).code; } catch { return t.slice(0, 120); } };
const marker = (n, dir = ws) => existsSync(join(dir, n));
const OPTIONS = ['Allow once', 'Allow for session', 'Always allow exact operation', 'Deny'];
const t = cmd => ({ command: cmd });

try {
  // ---------- session 1 ----------
  let pi = startPi(ws, 'full-access');
  await pi.wait(e => e.type === 'extension_ui_request' && e.method === 'setStatus' && e.statusKey === 'smart-approval', 30000).then(e => check('extension loaded in RPC mode', !/FAIL CLOSED/.test(e.statusText ?? ''), e.statusText));

  let r = await run(pi, t('ls'));
  check('routine `ls`: no dialog, tool ran', r.dialogs.length === 0 && r.end && !r.end.isError, `dialogs=${r.dialogs.length}`);

  r = await run(pi, t('touch m1'), ['Allow for session']);
  check('`touch m1`: one select with all four choices (no T3 bridge confirm in Full access)', r.dialogs.length === 1 && r.dialogs[0].method === 'select' && JSON.stringify(r.dialogs[0].options) === JSON.stringify(OPTIONS), JSON.stringify(r.dialogs.map(d => d.options)));
  check('select carries client-visible timeout', r.dialogs[0]?.timeout === 4000, String(r.dialogs[0]?.timeout));
  check('`touch m1` Allow for session: tool ran', marker('m1') && !r.end?.isError);
  unlinkSync(join(ws, 'm1'));

  r = await run(pi, t('touch m1'));
  check('repeated exact `touch m1`: no dialog, tool ran (session grant)', r.dialogs.length === 0 && marker('m1'), `dialogs=${r.dialogs.length}`);

  r = await run(pi, t('touch m2'), ['Deny']);
  check('altered `touch m2`: prompted again; Deny blocks and tool did not run', r.dialogs.length === 1 && !marker('m2') && blockedCode(r) === 'USER_DENIED', blockedCode(r));

  r = await run(pi, t('touch m5'), ['Allow everything']);
  check('invalid reply value: blocked, tool did not run', !marker('m5') && blockedCode(r) === 'INVALID_APPROVAL_REPLY', blockedCode(r));

  r = await run(pi, t('touch m6'), [{ cancelled: true }]);
  check('cancelled reply: blocked, tool did not run', !marker('m6') && blockedCode(r) === 'APPROVAL_CANCELLED', blockedCode(r));

  r = await run(pi, t('touch m4'), ['NO_REPLY']);
  await new Promise(res => setTimeout(res, 500));
  const pending = readdirSync(join(agentDir, 'smart-approval/pending'));
  check('no reply: expires, blocked, late reply ignored, metadata-only pending record', !marker('m4') && blockedCode(r) === 'APPROVAL_TIMEOUT' && pending.length === 1 && !readFileSync(join(agentDir, 'smart-approval/pending', pending[0]), 'utf8').includes('m4'), blockedCode(r));

  r = await run(pi, t('touch m3'), ['Always allow exact operation', 'Save permanent exact rule']);
  const saved = JSON.parse(readFileSync(policyPath, 'utf8')).rules;
  check('Always allow: second explicit select shows scope, rule saved, tool ran', r.dialogs.length === 2 && /Scope: Exact command text/.test(r.dialogs[1].title) && saved.length === 1 && saved[0].tool === 'bash' && marker('m3'), JSON.stringify(r.dialogs.map(d => d.options)));

  r = await run(pi, t('touch m8'), ['Always allow exact operation', 'Cancel (do not run)']);
  check('Always allow then Cancel: nothing saved, tool did not run', !marker('m8') && JSON.parse(readFileSync(policyPath, 'utf8')).rules.length === 1 && blockedCode(r) === 'PERSIST_CANCELLED', blockedCode(r));

  r = await run(pi, t('touch m9'), ['Allow once']);
  check('Allow once: tool ran', marker('m9'));
  unlinkSync(join(ws, 'm9'));
  r = await run(pi, t('touch m9'), ['Deny']);
  check('Allow once created no reusable grant: prompted again', r.dialogs.length === 1 && !marker('m9'));

  r = await run(pi, t('ls; touch m10'), ['Allow once']);
  check('complex shell: only Allow once / Deny offered', JSON.stringify(r.dialogs[0]?.options) === JSON.stringify(['Allow once', 'Deny']), JSON.stringify(r.dialogs[0]?.options));

  r = await run(pi, t('touch m11'), ['Allow once'], { userBash: true });
  check('RPC `bash` command (user_bash) goes through the same dialog and runs on Allow once', r.dialogs.length === 1 && marker('m11'), JSON.stringify(r.output?.data?.exitCode));
  r = await run(pi, t('touch m12'), ['Deny'], { userBash: true });
  check('RPC `bash` command denied: did not run', !marker('m12') && r.output?.data?.exitCode === 1);
  pi.child.kill('SIGTERM');

  // ---------- session 2: persistent grant reload ----------
  unlinkSync(join(ws, 'm3'));
  pi = startPi(ws, 'full-access');
  await pi.wait(e => e.type === 'extension_ui_request' && e.method === 'setStatus' && e.statusKey === 'smart-approval', 30000);
  r = await run(pi, t('touch m3'));
  check('after restart: persistent exact rule authorizes `touch m3` without a dialog', r.dialogs.length === 0 && marker('m3'), `dialogs=${r.dialogs.length}`);
  r = await run(pi, t('touch m1'), ['Deny']);
  check('after restart: session grant for `touch m1` is gone (prompted)', r.dialogs.length === 1);
  pi.child.kill('SIGTERM');

  // ---------- session 3: different workspace ----------
  pi = startPi(ws2, 'full-access');
  await pi.wait(e => e.type === 'extension_ui_request' && e.method === 'setStatus' && e.statusKey === 'smart-approval', 30000);
  r = await run(pi, t('touch m3'), ['Deny']);
  check('different workspace: persistent rule does not apply (prompted, denied, not run)', r.dialogs.length === 1 && !marker('m3', ws2));
  pi.child.kill('SIGTERM');

  // ---------- session 4: T3 approval-required mode (documents double prompt) ----------
  if (bridge) {
    pi = startPi(ws, 'approval-required');
    await pi.wait(e => e.type === 'extension_ui_request' && e.method === 'setStatus' && e.statusKey === 'smart-approval', 30000);
    r = await run(pi, t('touch m13'), ['Allow once', { confirmed: true }]);
    check('T3 approval-required: bridge confirm and smart-approval select both appear (documented)', r.dialogs.some(d => d.method === 'confirm') && r.dialogs.some(d => d.method === 'select'), r.dialogs.map(d => d.method).join(','));
    pi.child.kill('SIGTERM');
  }
} catch (e) {
  check('harness', false, String(e?.stack ?? e));
} finally {
  server.close();
  rmSync(root, { recursive: true, force: true });
  console.log(`\n${results.length - failures}/${results.length} checks passed`);
  process.exit(failures ? 1 : 0);
}
