import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { CONFIG_DIR_NAME, getAgentDir, parseFrontmatter } from '@earendil-works/pi-coding-agent';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { loadConfig, projectRestrictions, validateConfig } from './config.ts';
import { Store, atomicJSON } from './storage.ts';
import { Approver, display } from './approval.ts';
import { Analyzer } from './analysis.ts';
import { agentDigest, trustedRules } from './agents.ts';
import { canonical, hash } from './filesystem.ts';
import { stable, evaluate } from './policy.ts';
import type { Config, Call, Environment } from './types.ts';
const WARNING = 'DANGER: hard-deny veto disabled for this session. Host-volume destruction may reach manual review. This is NOT a sandbox. Other policy checks remain active. You accept responsibility.';
export default function smartApproval(pi: ExtensionAPI) {
  pi.registerFlag('smart-approval-hard-override', { type: 'boolean', default: false, description: 'Disable hard veto for this session; requires explicit acknowledgment' });
  pi.registerFlag('smart-approval-acknowledge-risk', { type: 'boolean', default: false, description: 'Explicit acknowledgment of responsibility for hard override' });
  let store: Store | undefined; let startupError = true; let hardOverride = false; let activeAgent: string | undefined;
  let approver = new Approver(); let analyzer = new Analyzer();
  let sessionWritable: string[] = [];
  let approvalQueue: Promise<unknown> = Promise.resolve();
  let generation = 0;
  const stateRoot = join(getAgentDir(), 'smart-approval');
  const configPath = join(stateRoot, 'config.json');
  const env = (ctx: ExtensionContext): Environment => ({ cwd: ctx.cwd, home: homedir(), agentDir: getAgentDir(), configDir: CONFIG_DIR_NAME, extensionDir: resolve(dirname(fileURLToPath(import.meta.url)), '..') });
  function config(ctx: ExtensionContext): Config {
    const global = loadConfig(configPath);
    // Only the two verified Pi discovery locations receive default global write access.
    global.writable = [...new Set([join(homedir(), '.agents/skills'), join(getAgentDir(), 'skills'), ...global.writable, ...sessionWritable])];
    let effective = projectRestrictions(join(ctx.cwd, CONFIG_DIR_NAME, 'smart-approval.json'), global);
    if (activeAgent) {
      const source = readFileSync(canonical(activeAgent, env(ctx)), 'utf8');
      const { frontmatter } = parseFrontmatter(source);
      effective = { ...effective, rules: [...effective.rules, ...trustedRules(activeAgent, frontmatter, effective, env(ctx), hash(source))] };
    }
    return effective;
  }
  const interactive = (ctx: ExtensionContext) => ctx.mode === 'tui' && ctx.hasUI && !process.env.CI;
  async function save(ctx: ExtensionContext, value: Config, previous: Config) {
    if (!interactive(ctx)) throw new Error('Manual TUI approval required');
    const validated = validateConfig(value);
    if (!await ctx.ui.confirm('Modify protected global approval policy?', display(JSON.stringify(validated, null, 2)), { timeout: 120000 })) throw new Error('Policy update cancelled');
    if (stable(loadConfig(configPath)) !== stable(previous)) throw new Error('Policy changed during review; start again');
    atomicJSON(configPath, validated);
  }
  function status(ctx: ExtensionContext) { ctx.ui.setStatus('smart-approval', startupError ? 'approval: FAIL CLOSED' : `approval: soft protection${hardOverride ? ' ⚠ HARD OVERRIDE' : ''}`); }
  pi.on('session_start', async (_event, ctx) => {
    generation++;
    approver = new Approver(); analyzer = new Analyzer(); activeAgent = undefined; hardOverride = false; startupError = true; sessionWritable = [];
    try { store = new Store(stateRoot); config(ctx); startupError = false; }
    catch { ctx.ui.notify('Smart Approval initialization failed. All intercepted calls are denied. Check policy schema and private storage permissions.', 'error'); }
    const requested = process.env.PI_SMART_APPROVAL_HARD_OVERRIDE === 'true' || pi.getFlag('smart-approval-hard-override') === true;
    if (requested) {
      const ack = process.env.PI_SMART_APPROVAL_ACKNOWLEDGE_RISK === 'true' || pi.getFlag('smart-approval-acknowledge-risk') === true;
      if (ctx.mode === 'tui') ctx.ui.notify(WARNING, 'warning'); else process.stderr.write('[smart-approval] ' + WARNING + '\n');
      hardOverride = ack && (!interactive(ctx) || await ctx.ui.confirm('Accept hard override responsibility?', WARNING, { timeout: 120000 }));
    }
    status(ctx);
  });
  pi.on('session_shutdown', () => { generation++; store = undefined; startupError = true; hardOverride = false; activeAgent = undefined; sessionWritable = []; approver = new Approver(); });
  pi.on('session_tree', () => { approver = new Approver(); });
  async function gateNow(call: Call, ctx: ExtensionContext) {
    try {
      if (startupError || !store || process.platform !== 'linux') throw new Error('Unavailable security engine');
      const currentGeneration = generation;
      const result = await approver.decide(call, env(ctx), () => config(ctx), hardOverride, {
        interactive: interactive(ctx), session: ctx.sessionManager.getSessionId(), signal: ctx.signal,
        select: (title, actions, signal) => ctx.ui.select(title, actions, { signal }),
        pending: r => store!.pending(r),
        persist: async (tool, key) => { const previous = loadConfig(configPath); const c = structuredClone(previous); c.rules.push({ tool, key, action: 'ALWAYS_ALLOW' }); await save(ctx, c, previous); },
        advice: async (e, c) => {
          const d = await analyzer.analyze(call.tool, e, c.decisionModel, ctx, true);
          return d && d.confidence >= 0.9 ? d : (await analyzer.analyze(call.tool, e, c.analysis, ctx)) ?? d;
        },
      });
      if (currentGeneration !== generation || startupError || !store) throw new Error('Stale approval');
      store.audit({ key: result.evaluation.key, tool: /^[a-z_]{1,40}$/.test(call.tool) ? call.tool : 'custom', decision: result.evaluation.decision, reason: result.evaluation.reason, allowed: result.allowed });
      if (!result.allowed) return { block: true as const, reason: JSON.stringify({ extension: 'smart-approval', code: result.code, decision: result.evaluation.decision, reason: result.evaluation.reason, key: result.evaluation.key }) };
      const last = evaluate(call, config(ctx), env(ctx), hardOverride);
      if (ctx.signal?.aborted || last.technical || last.key !== result.evaluation.key || last.fingerprint !== result.evaluation.fingerprint || last.decision !== result.evaluation.decision) throw new Error('Final revalidation failed');
    } catch { return { block: true as const, reason: JSON.stringify({ extension: 'smart-approval', code: 'SECURITY_ENGINE_FAILURE', reason: 'Fail closed: policy, trust, UI, revalidation or storage failure' }) }; }
  }
  function gate(call: Call, ctx: ExtensionContext) {
    // Serialize decisions/dialogs. This does not serialize Pi's actual tool execution.
    const queuedGeneration = generation;
    const current = approvalQueue.then(() => queuedGeneration === generation ? gateNow(call, ctx) : { block: true as const, reason: JSON.stringify({ extension: 'smart-approval', code: 'STALE_SESSION' }) });
    approvalQueue = current.then(() => undefined, () => undefined);
    return current;
  }
  pi.on('tool_call', (event, ctx) => gate({ tool: event.toolName, input: event.input }, ctx));
  pi.on('user_bash', async (event, ctx) => {
    const blocked = await gate({ tool: 'bash', input: { command: event.command } }, ctx);
    if (blocked) return { result: { output: blocked.reason, exitCode: 1, cancelled: false, truncated: false } };
  });
  pi.on('resources_discover', (_event, ctx) => {
    try { if (startupError) return; return { skillPaths: config(ctx).skillPaths }; }
    catch { startupError = true; status(ctx); return; }
  });
  pi.registerCommand('pending-approvals', {
    description: 'Review expired requests; never replay or grant permissions',
    handler: async (_args, ctx) => {
      if (!interactive(ctx) || !store) return;
      try {
        const list = store.list();
        const options = list.map(p => `${p.id} ${p.status} ${p.tool} ${new Date(p.created).toISOString()}`);
        const choice = await ctx.ui.select('Expired requests (arguments deliberately not stored)', options);
        const p = list[options.indexOf(choice ?? '')]; if (!p) return;
        const action = await ctx.ui.select(display(`Session: ${p.session}\nKey: ${p.key}\n${p.reason}\nSuperseded: unknown. Reviewing never authorizes or replays the call. Reissue and obtain fresh policy validation/approval.`), ['Mark reviewed — reconsider/reissue manually', 'Reject', 'Remove']);
        if (action === 'Remove') store.remove(p.id);
        else if (action) store.pending({ ...p, status: action === 'Reject' ? 'rejected' : 'reviewed' });
      } catch { ctx.ui.notify('Pending storage unavailable or corrupt; no operation authorized', 'error'); }
    },
  });
  pi.registerCommand('smart-approval', {
    description: 'Approval settings, exact rules, writable paths, model budgets and agent trust',
    handler: async (_args, ctx) => {
      if (!interactive(ctx)) return;
      try {
        const previous = loadConfig(configPath);
        const action = await ctx.ui.select(`Soft interception only. ${hardOverride ? 'HARD OVERRIDE ACTIVE.' : 'Hard veto active.'}\nAnalysis: ${JSON.stringify({ calls: analyzer.calls, tokens: analyzer.tokens, reportedCost: analyzer.reportedCost, failures: analyzer.failures })}\nGlobal policy: ${configPath}\nActive agent: ${activeAgent ?? 'none'}`, ['Edit global settings JSON', 'Manage global content paths', 'Add session writable path', 'Clear session writable paths', 'Recent decisions', 'Trust and activate agent', 'Activate trusted agent', 'Deactivate agent', 'Hard override toggle', 'Reload/diagnose policy']);
        if (action === 'Edit global settings JSON') {
          const text = await ctx.ui.editor('Version 1 global policy — changes require separate manual confirmation', JSON.stringify(previous, null, 2));
          if (text) await save(ctx, validateConfig(JSON.parse(text)), previous);
        } else if (action === 'Manage global content paths') {
          const candidates = ['.agents/skills', '.pi/agent/skills', '.claude/skills', '.config/opencode/skills', '.agents/agents', '.claude/agents', '.config/opencode/agents'].map(p => join(homedir(), p));
          const path = await ctx.ui.select('Discovery is separate; these controls change write authorization only', candidates);
          if (path) {
            const setting = await ctx.ui.select(path, ['Writable', 'Read-only']);
            if (setting) { const c = structuredClone(previous); c.writable = c.writable.filter(p => p !== path); c.readOnly = c.readOnly.filter(p => p !== path); (setting === 'Writable' ? c.writable : c.readOnly).push(path); await save(ctx, c, previous); }
          }
        } else if (action === 'Add session writable path') {
          const path = await ctx.ui.input('Absolute path to authorize for this session only (global read-only restrictions remain)');
          if (path) { const real = canonical(path, env(ctx)); if (await ctx.ui.confirm('Authorize session writes?', display(real), { timeout: 120000 })) sessionWritable.push(real); }
        } else if (action === 'Clear session writable paths') sessionWritable = [];
        else if (action === 'Recent decisions') {
          await ctx.ui.select('Recent decisions (argument-free, at most 20)', (store?.recent() ?? []).map(r => display(JSON.stringify(r))));
        } else if (action === 'Trust and activate agent') {
          const path = await ctx.ui.input('Absolute Markdown agent path (full file hash binds trust)');
          if (path) { const real = canonical(path, env(ctx)); const source = readFileSync(real, 'utf8'); const c = structuredClone(previous); const digest = hash(source);
            if (source.length > 24000) throw new Error('Agent too large to review');
            if (await ctx.ui.confirm('Review untrusted agent definition before trusting', display(source), { timeout: 120000 })) {
              c.trustedAgents = c.trustedAgents.filter(t => t.path !== real); c.trustedAgents.push({ path: real, digest }); await save(ctx, c, previous); activeAgent = real;
            }
          }
        } else if (action === 'Activate trusted agent') {
          const selected = await ctx.ui.select('Explicit session agent context (child agents are not inferred)', loadConfig(configPath).trustedAgents.map(t => t.path));
          if (selected) { const c = loadConfig(configPath); if (!c.trustedAgents.some(t => t.path === selected && t.digest === agentDigest(selected, env(ctx)))) throw new Error('Agent changed; trust again'); activeAgent = selected; }
        } else if (action === 'Deactivate agent') activeAgent = undefined;
        else if (action === 'Hard override toggle') hardOverride = hardOverride ? false : await ctx.ui.confirm('Accept responsibility?', WARNING, { timeout: 120000 });
        config(ctx); startupError = false; approver = new Approver(); status(ctx);
      } catch { ctx.ui.notify('Settings rejected or cancelled. Existing enforcement remains; check schema, trust hash and storage permissions.', 'error'); }
    },
  });
}
