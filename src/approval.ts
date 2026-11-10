import { randomUUID } from 'node:crypto';
import { evaluate } from './policy.ts';
import { bounded, DeadlineExpired } from './analysis.ts';
import type { Call, Config, Environment, Evaluation, Advisory, Pending } from './types.ts';
export interface ApprovalPort {
  interactive: boolean; session: string; signal?: AbortSignal;
  select(title: string, actions: string[], signal: AbortSignal): Promise<string | undefined>;
  pending(record: Pending): void;
  persist(tool: string, key: string): Promise<void>;
  advice?(evaluation: Evaluation, config: Config): Promise<Advisory | undefined>;
}
export interface Outcome { allowed: boolean; evaluation: Evaluation; code: string }
export function display(s: string): string { return s.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, '?'); }
export class Approver {
  private grants = new Set<string>();
  async decide(call: Call, env: Environment, getConfig: () => Config, hardOverride: boolean, port: ApprovalPort): Promise<Outcome> {
    const config = getConfig();
    const e = evaluate(call, config, env, hardOverride);
    const deny = (code: string): Outcome => ({ allowed: false, evaluation: e, code });
    if (port.signal?.aborted) return deny('ABORTED');
    if (e.technical || e.decision === 'HARD_DENY') return deny(e.technical ? 'VALIDATION_OR_POLICY_DENY' : 'HARD_DENY');
    if (e.decision === 'SMART_DENY' && !config.reviewDeny) return deny('SMART_DENY');
    if (!port.interactive && e.decision !== 'SMART_ALLOW') return deny('INTERACTIVE_REQUIRED');
    const reusable = !e.opaque && !e.protected && !e.outside && e.reason !== 'Manual ALWAYS_ASK';
    const grantKey = e.key + e.fingerprint;
    let allowed = e.decision === 'SMART_ALLOW' || (reusable && this.grants.has(grantKey));
    let action: string | undefined;
    if (!allowed) {
      if (!port.interactive) return deny('INTERACTIVE_REQUIRED');
      const advice = await port.advice?.(e, config);
      const actions = ['Allow once'];
      if (reusable) actions.push('Allow for session');
      if (reusable && e.persistent && e.decision !== 'SMART_DENY') actions.push('Always allow exact operation');
      actions.push('Deny');
      // Full arguments are shown locally, never persisted or sent to auxiliary models.
      const args = JSON.stringify(call.input, null, 2);
      if (args.length > 24000) return deny('OPERATION_TOO_LARGE_TO_REVIEW');
      const title = display(`${e.decision}: ${call.tool}\n${e.reason}\nResources: ${e.resources.join(', ') || 'unknown (may include Pi configuration and outside writes)'}\nOutside scope: ${e.outside}\nOperation key: ${e.key}\nArguments (untrusted data):\n${args}${advice ? '\nAdvisory only: ' + JSON.stringify(advice) : ''}`);
      let timedOut = false;
      try { action = await bounded(signal => port.select(title, actions, signal), config.timeoutMs, port.signal); }
      catch (error) {
        if (port.signal?.aborted) return deny('ABORTED');
        if (!(error instanceof DeadlineExpired)) return deny('APPROVAL_UI_FAILURE');
        timedOut = true;
      }
      if (timedOut) {
        port.pending({ id: randomUUID(), key: e.key, tool: /^[a-zA-Z0-9_-]{1,80}$/.test(call.tool) ? call.tool : 'custom', session: port.session, created: Date.now(), status: 'pending', reason: e.reason });
        return deny('APPROVAL_TIMEOUT');
      }
      allowed = !!action && actions.includes(action) && action !== 'Deny';
      if (!allowed) return deny('USER_DENIED');
    }
    // Reload policy/trust and restat immediately before handing control back to Pi.
    const fresh = evaluate(call, getConfig(), env, hardOverride);
    if (port.signal?.aborted || fresh.key !== e.key || fresh.fingerprint !== e.fingerprint || fresh.decision !== e.decision || fresh.technical) return deny('REVALIDATION_FAILED');
    if (action === 'Always allow exact operation') { await port.persist(call.tool, e.key); return deny('POLICY_UPDATED_REISSUE'); }
    if (action === 'Allow for session' && reusable) this.grants.add(grantKey);
    return { allowed: true, evaluation: fresh, code: 'AUTHORIZED' };
  }
}
