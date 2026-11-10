# Pi Smart Approval

A dependency-free TypeScript extension for **Pi 1.5.1 on Linux / Node ≥22.19**. Provides deterministic tool approval, soft filesystem write scopes, timed dialogs, pending-request review, explicit agent trust, and optional advisory models. No Pi core changes.

**This is an advisory interception layer, NOT a sandbox or a complete security boundary.** It cannot constrain an approved subprocess, a hostile extension, a remote agent, or changes made after its hook returns. Read [SECURITY.md](SECURITY.md) before relying on it. This is an initial security foundation, not an independently audited security product.

## Install

For an explicit, one-process load (no installation or config change):

```sh
pi -e /absolute/path/to/pi-smart-approval/src/index.ts
```

For persistent installation, manually add the repository's absolute directory to your global Pi `settings.json` `extensions` array, preserving existing entries. Alternatively place the repository under `~/.pi/agent/extensions/pi-smart-approval/`; its package manifest declares `src/index.ts`. Install globally rather than relying on project extensions: untrusted projects skip project-local extension loading. Do not load the extension twice. No `npm install` or build is required.

Loading during a running session requires Pi's supported reload mechanism; simply creating these files does not protect the current coding session. This implementation has not modified your real Pi configuration or installed itself globally.

## Default behavior

- Built-in `read`: auto-allow ordinary files; sensitive resources deny by default.
- Built-in `write`/`edit`: ordinary files under CWD are writable; outside writes ask.
- Verified global skills directories `~/.agents/skills` and `${getAgentDir()}/skills` are additional default writable roots. Discovery and write permission are independent.
- Protected Pi state and this extension's source always require fresh manual approval for mutations.
- **Every shell command and unknown/custom tool asks at least once per invocation**, regardless of ordinary allow/session rules. Even `git status` may invoke a configured filesystem monitor; shell startup files and subprocess effects are not statically provable. Known destructive/remote operations default to deny.
- `SMART_DENY` is blocked unless `reviewDeny` is enabled. `HARD_DENY` is a separate veto for narrowly recognized host-volume destruction signatures.
- Only local TUI sessions with `hasUI` and no nonempty `CI` variable can approve. RPC/print/JSON/CI never wait for approval and deny calls needing human input.
- `smart: false` disables automatic smart allows, **not enforcement**. There is no general YOLO switch.

## Commands

### `/smart-approval`

Shows enforcement status, policy path, active agent, and auxiliary-model usage. Offers:

- Edit the complete versioned settings JSON (rules, scope, discovery paths, model selections, budgets, timeout, deny-review). Saving requires separate explicit confirmation of the full policy.
- Per-directory write controls for candidate global skills and agent locations.
- Add/clear session-only writable paths (existing read-only restrictions remain).
- Inspect the last 20 audit decisions.
- Trust/revoke (via settings), activate, or deactivate an agent definition.
- Toggle hard override with a responsibility warning; diagnose/reload policy.

JSON editing is the settings interface for advanced fields; there is no graphical model or rule builder. All persistent changes use private atomic writes. Concurrent changes detected during confirmation reject the save.

### Approval dialogs

Show decision, effect/risk, canonical resources, outside-scope status, an exact operation digest, full arguments (locally only), and any model advice. Actions:

- Allow once / Deny.
- Session approval for reusable, fully modeled operations.
- Always allow the **exact tool+arguments+CWD digest**, only for eligible non-deny operations within authorized scope.

Protected configuration, outside-scope writes, opaque tools, and explicit `ALWAYS_ASK` never receive reusable approval options. SMART_DENY never offers persistence. Creating an always-allow rule requires a **second protected-policy confirmation**, denies the original request with `POLICY_UPDATED_REISSUE`, and requires the agent to reissue it. It does not silently execute an operation after changing policy.

### `/pending-approvals`

An approval expires after 120 seconds by default, returns `APPROVAL_TIMEOUT`, and stores metadata. The command lists requests, allows review/rejection/removal, and displays session/key/time/reason. **Reviewing grants no permission and never replays anything.** Ask the agent to reconsider and reissue; it must pass current validation and approval again. Supersession is reported as unknown.

For privacy, raw arguments, file contents, and resource paths are not stored. Consequently exact details must be inspected in the originating transcript using the operation key. Full offline reconstruction is intentionally unavailable. Pending records survive restart; session grants, active agent selection, and hard override do not persist.

## Configuration

Global policy: `${getAgentDir()}/smart-approval/config.json` (normally `~/.pi/agent/smart-approval/config.json`). Missing file uses safe defaults. Invalid files deny intercepted calls. State directories must be owned by the current user, mode `0700`; files written by the extension use `0600`. No automatic policy migrations or permissive fallback.

See [configuration reference](docs/CONFIGURATION.md), [minimal example](examples/minimal.json), and [stricter example](examples/strict.json). Paths in policy JSON must be absolute; replace example placeholders before use. Change policy through `/smart-approval`, or edit it yourself outside the agent. Global settings are reloaded for every decision and immediately revalidated before returning authorization.

Project `.pi/smart-approval.json` is **restriction-only**: version, additional `readOnly` paths, and ask/deny rules. It cannot grant permissions or enable models/overrides. Even a trusted project cannot weaken global policy. Invalid project policy fails closed.

### Hard override

Off by default. TUI activation warns and requires confirmation. Environment activation requires both exact boolean strings:

```sh
PI_SMART_APPROVAL_HARD_OVERRIDE=true \
PI_SMART_APPROVAL_ACKNOWLEDGE_RISK=true \
pi -e /absolute/path/to/pi-smart-approval/src/index.ts
```

Pi 1.5.1 supports extension flags; equivalent flags are `--smart-approval-hard-override --smart-approval-acknowledge-risk`. A warning is printed to stderr outside TUI; interactive activation additionally confirms responsibility. These only disable the hard veto: the operation becomes SMART_DENY and still needs deny-review enabled and fresh authorization. Headless runs cannot authorize it. Override is never written to policy. Environment/CLI flags explicitly request activation again on reload; TUI-only override is discarded.

### Optional models

Disabled by default. `analysis.enabled: true` uses the invoking session's current model; configure both `provider` and `model` to select a dedicated one. `decisionModel.enabled` requires an explicit provider/model pair referring to a Pi **classifier** model. Decision model runs first; only low-confidence/unavailable answers escalate to the optional LLM.

Calls use supported `ctx.modelRegistry.complete()` / `classify()` APIs with separate context. No conversation messages, raw arguments, paths, or source contents are sent: only tool category, deterministic reason, scope status and resource count. This deliberately sacrifices classification precision for privacy. Output is strictly validated and **display-only**: it cannot promote an ambiguous operation to automatic execution or override deterministic requirements. Failures leave the deterministic approval requirement unchanged.

Per-layer call budgets, bounded inputs, 256 output-token LLM limits, timeouts, and an in-memory safe-advice cache constrain usage. `/smart-approval` shows calls, returned tokens, provider-reported catalog cost, and failures. No dollar-accurate spending cap or guaranteed classifier token cap is claimed. Unreported costs/aborted requests may still be billable. No paid calls were made during development.

## Agent/skills interoperability

See [compatibility investigation](docs/COMPATIBILITY.md). Pi does not provide a universal active-subagent identity or core Markdown-agent permission model. Trust and agent activation are therefore **explicit for this session only**; no source is inferred from tool arguments. A child process must load its own protection extension.

Trust binds the canonical path and SHA-256 of the **entire definition**. Any edit invalidates translated permissions. Remove the record in settings to revoke. `tools:` and `allowed-tools:` never grant authority. Supported frontmatter subset:

```yaml
---
name: reviewer
permissions:
  ask:
    - "Bash(git status)"
  allow:
    - "Read(README.md)"
---
```

Only exact `Bash(command)` and `Read(path)` entries are translated; wildcards/other dialects do not grant anything. `smartApprovalRules` can contain rules from this extension's schema. All inherited permissions remain subject to hard veto, config approval, filesystem scope and opaque-effect restrictions.

## Verification

```sh
npm test
# Optional installed-Pi loader + mocked lifecycle integration:
PI_SMART_APPROVAL_TEST_PI_ROOT=/absolute/path/to/node_modules/@earendil-works/pi-coding-agent npm test
```

Tests execute no destructive payloads and no paid model requests. Shell attacks are strings evaluated by pure functions; filesystem tests use inert temporary fixtures only. Integration tests load the actual installed extension loader and invoke handlers with mocked contexts; they do not execute approved tools or constitute end-to-end TUI/OS isolation validation.

## Troubleshooting

- **Too many shell prompts:** expected. Use structured file tools; use OS isolation for less restrictive subprocess workflows. Do not replace the opaque-effects guard with a command-name allowlist.
- **`SECURITY_ENGINE_FAILURE`:** check schema/version, private storage permissions, changed agent files, and diagnostic command. No raw exceptions/arguments are logged.
- **`REVALIDATION_FAILED`:** file, symlink, policy, trust, or session state changed during review. Reconsider and reissue.
- **No prompt:** RPC/CI/headless is denied rather than waiting; a `CI` value of `"false"` still counts as CI. Unset it only when genuinely interactive.
- **Global skills stay read-only:** check `readOnly`; removing a path from `writable` does not disable built-in default roots. Add a read-only exclusion instead.
- **Changed skill discovery list:** use Pi `/reload`. Filesystem authorization changes apply on the next call; resource discovery changes require reload.

See [security boundary](SECURITY.md) and [remaining limitations/upstream proposals](docs/COMPATIBILITY.md).
