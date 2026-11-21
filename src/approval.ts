import { randomUUID } from 'node:crypto';
import { evaluate } from './policy.ts';
import { bounded, DeadlineExpired } from './analysis.ts';
import type { Call, Config, Environment, Evaluation, Advisory, Pending } from './types.ts';
export interface ApprovalPort {
  interactive: boolean; session: string; signal?: AbortSignal;
  // timeoutMs lets dialog-capable clients (Pi TUI, Pi RPC/T3 Code) show and enforce the same expiry.
  select(title: string, actions: string[], signal: AbortSignal, timeoutMs?: number): Promise<string | undefined>;
  pending(record: Pending): void;
  persist(tool: string, key: string): Promise<void>;
  advice?(evaluation: Evaluation, config: Config): Promise<Advisory | undefined>;
}
export interface Outcome { allowed: boolean; evaluation: Evaluation; code: string; action?: string }
export const ACTIONS = { once: 'Allow once', session: 'Allow for session', always: 'Always allow exact operation', deny: 'Deny' } as const;
export const SAVE = { yes: 'Save permanent exact rule', no: 'Cancel (do not run)' } as const;
export function display(s: string): string { return s.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]/g, '?'); }
// Grace period so the client-side dialog timeout resolves first and is recognized as expiry.
const UI_GRACE_MS = 1000;
export function scopeText(call: Call, e: Evaluation, env: Environment): string {
  if (call.tool === 'bash') return `Exact command text and all other arguments, working directory ${env.cwd}, shell environment digest ${e.shell?.context.slice(0, 16) ?? 'n/a'}, current policy and trust. Any change to these requires review again. The shell is not sandboxed: a grant covers every direct and indirect effect of this exact command.`;
  return `Exact ${call.tool} arguments, working directory ${env.cwd}, resources ${e.resources.join(', ') || 'none'}, their current filesystem state, current policy and trust.`;
}
export class Approver {
  private grants = new Set<string>();
  async decide(call: Call, env: Environment, getConfig: () => Config, hardOverride: boolean, port: ApprovalPort): Promise<Outcome> {
    const config = getConfig();
    const e = evaluate(call, config, env, hardOverride);
    const deny = (code: string, action?: string): Outcome => ({ allowed: false, evaluation: e, code, action });
    if (port.signal?.aborted) return deny('ABORTED');
    if (e.technical || e.decision === 'HARD_DENY') return deny(e.technical ? 'VALIDATION_OR_POLICY_DENY' : 'HARD_DENY');
    if (e.decision === 'SMART_DENY' && !config.reviewDeny) return deny('SMART_DENY');
    if (!port.interactive && e.decision !== 'SMART_ALLOW') return deny('INTERACTIVE_REQUIRED');
    // Shell reuse additionally requires a parsed simple command and no veto signature.
    const reusable = !e.opaque && !e.protected && !e.outside && e.reason !== 'Manual ALWAYS_ASK' && (call.tool !== 'bash' || (e.shell?.grantable === true && e.decision === 'SMART_ASK'));
    const grantKey = e.key + e.fingerprint;
    let allowed = e.decision === 'SMART_ALLOW' || (reusable && this.grants.has(grantKey));
    let code = e.decision === 'SMART_ALLOW' ? 'AUTHORIZED' : 'AUTHORIZED_SESSION_GRANT';
    let action: string | undefined;
    // Model assessment may only allow inside the deterministic 'model' shell tier, never past a veto.
    let advice: Advisory | undefined;
    // Model failure is treated as no advice: the human prompt still applies.
    if (!allowed) { try { advice = await port.advice?.(e, config); } catch { advice = undefined; } }
    if (!allowed && config.smart && config.shellModelAssist === true && reusable && e.shell?.tier === 'model' && e.decision === 'SMART_ASK' && advice?.decision === 'SMART_ALLOW' && advice.confidence >= 0.95) { allowed = true; code = 'AUTHORIZED_MODEL_ASSIST'; }
    if (!allowed) {
      const actions: string[] = [ACTIONS.once];
      if (reusable) actions.push(ACTIONS.session);
      if (reusable && e.persistent && e.decision !== 'SMART_DENY') actions.push(ACTIONS.always);
      actions.push(ACTIONS.deny);
      // Full arguments are shown locally, never persisted or sent to auxiliary models.
      const args = JSON.stringify(call.input, null, 2);
      if (args.length > 24000) return deny('OPERATION_TOO_LARGE_TO_REVIEW');
      const scope = reusable ? `\nReuse scope (session/permanent): ${scopeText(call, e, env)}` : '\nReuse: not offered (complex, ambiguous, vetoed, protected or outside-scope operation)';
      const title = display(`${e.decision}: ${call.tool}\n${e.reason}\nResources: ${e.resources.join(', ') || 'unknown (may include Pi configuration and outside writes)'}\nOutside scope: ${e.outside}\nOperation key: ${e.key}${scope}\nArguments (untrusted data):\n${args}${advice ? '\nAdvisory only: ' + JSON.stringify(advice) : ''}`);
      const ask = async (t: string, options: string[]) => {
        const started = Date.now();
        try {
          const choice = await bounded(signal => port.select(t, options, signal, config.timeoutMs), config.timeoutMs + UI_GRACE_MS, port.signal);
          if (port.signal?.aborted) return { error: 'ABORTED' };
          // Client-side expiry resolves undefined; treat it as timeout rather than an explicit answer.
          if (choice === undefined && Date.now() - started >= config.timeoutMs) return { error: 'APPROVAL_TIMEOUT' };
          if (choice === undefined) return { error: 'APPROVAL_CANCELLED' };
          if (!options.includes(choice)) return { error: 'INVALID_APPROVAL_REPLY' };
          return { choice };
        } catch (error) {
          if (port.signal?.aborted) return { error: 'ABORTED' };
          return { error: error instanceof DeadlineExpired ? 'APPROVAL_TIMEOUT' : 'APPROVAL_UI_FAILURE' };
        }
      };
      const first = await ask(title, actions);
      if (first.error === 'APPROVAL_TIMEOUT') {
        port.pending({ id: randomUUID(), key: e.key, tool: /^[a-zA-Z0-9_-]{1,80}$/.test(call.tool) ? call.tool : 'custom', session: port.session, created: Date.now(), status: 'pending', reason: e.reason });
        return deny('APPROVAL_TIMEOUT');
      }
      if (first.error) return deny(first.error);
      action = first.choice;
      if (action === ACTIONS.deny) return deny('USER_DENIED', action);
      if (action === ACTIONS.always) {
        // Persistent changes need a second, explicit confirmation that shows the saved scope.
        const confirm = await ask(display(`Save a permanent ALWAYS_ALLOW rule?\nTool: ${call.tool}\nRule key: ${e.ruleKey}\nScope: ${scopeText(call, e, env)}\nThe rule is stored in the global smart-approval policy and can be removed there.`), [SAVE.yes, SAVE.no]);
        if (confirm.error) return deny(confirm.error === 'APPROVAL_TIMEOUT' ? 'PERSIST_CONFIRMATION_TIMEOUT' : confirm.error, action);
        if (confirm.choice !== SAVE.yes) return deny('PERSIST_CANCELLED', action);
      }
      code = action === ACTIONS.session ? 'AUTHORIZED_SESSION' : action === ACTIONS.always ? 'AUTHORIZED_PERSISTENT' : 'AUTHORIZED_ONCE';
    }
    // Reload policy/trust and restat immediately before handing control back to Pi.
    const fresh = evaluate(call, getConfig(), env, hardOverride);
    if (port.signal?.aborted || fresh.key !== e.key || fresh.fingerprint !== e.fingerprint || fresh.decision !== e.decision || fresh.technical) return deny('REVALIDATION_FAILED', action);
    if (action === ACTIONS.always) {
      try { await port.persist(call.tool, e.ruleKey); } catch { return deny('PERSIST_FAILED', action); }
      // The saved rule must now independently authorize exactly this operation.
      const saved = evaluate(call, getConfig(), env, hardOverride);
      if (port.signal?.aborted || saved.technical || saved.key !== e.key || saved.ruleKey !== e.ruleKey || saved.decision !== 'SMART_ALLOW') return deny('REVALIDATION_FAILED', action);
      return { allowed: true, evaluation: saved, code, action };
    }
    if (action === ACTIONS.session && reusable) this.grants.add(grantKey);
    return { allowed: true, evaluation: fresh, code, action };
  }
}
