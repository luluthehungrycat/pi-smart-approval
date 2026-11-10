# Investigation, compatibility, and remaining work

## Evidence inspected locally

Installed package: `@earendil-works/pi-coding-agent` **1.5.1**, Node **22.23.2**. Installation inspected under `/home/hermes/.pi/agent/install/releases/1.5.1/node_modules/`. No Pi core modifications.

Read installed README; extension, model, skills, security and containerization docs; extension examples (`permission-gate`, `protected-paths`, `timed-confirm`, `structured-output`, `jev-router`, subagent agent discovery); and relevant compiled source/types:

- `dist/core/agent-session.js`: `_beforeToolCall` constructs tool events and invokes extension gate; nested execution uses the same lifecycle.
- `dist/core/extensions/runner.js`: `emitToolCall` awaits handlers and stops on block; input mutations propagate. Handler errors propagate to fail-safe tool handling. `emitUserBash` uses first handled result.
- `dist/core/extensions/wrapper.js`: adapting custom tools does not create a private alternative gate; AgentSession owns interception.
- `dist/core/extensions/loader.js`: supported TypeScript loading and host module aliases; CLI-flag registration.
- `dist/core/model-registry.d.ts`, `model-runtime.js`: supported `complete`, `find`, `findOfType`, `classify` interfaces with resolved provider/auth.
- `dist/utils/paths.js`, `core/tools/path-utils.js`: built-in @/tilde/unicode-space/file-URL handling. This extension matches the common spellings and rejects URLs/traversal instead of risking inconsistent resolution.
- `dist/core/skills.js`, `package-manager.js`: skill discovery and first-discovered collision handling.
- `dist/config.js`: `getAgentDir()`, `CONFIG_DIR_NAME`, `PI_CODING_AGENT_DIR` support.

## API feasibility findings

| Requirement | Verified implementation / limit |
|---|---|
| Block before execution | `tool_call` returns `{block:true,reason}`; built-ins, custom and supported nested `ctx.executeTool` calls share interception |
| Modify arguments | Supported in place, with no subsequent validation; this is a remaining bypass if a later trusted extension mutates input |
| Subprocess/remote enforcement | No per-syscall interception; parent tool approval does not govern child/remote effects |
| User `!` / `!!` | `user_bash` can return an inert error result, but an earlier handler can consume it |
| Dialogs | `ctx.ui.select/confirm/input/editor`; AbortSignal closes expiry dialogs; local TUI only here |
| Persistence | Pi offers session `appendEntry`; this implementation instead uses private per-record JSON for cross-session pending/audit and a versioned atomic policy file |
| Auxiliary model | Separate registry `complete`/`classify` calls, no main-conversation mutation; providers are trusted and can run configured credential commands |
| CLI flags | `registerFlag/getFlag` genuinely supported in 1.5.1; implemented two explicit boolean flags |
| CI/RPC | `ctx.mode` and `hasUI`; conservative local-TUI-only approval, nonempty CI disables it |
| Protected config | Structured file effects checked; opaque effects require fresh blanket review; internals/startup/privileged extensions cannot be reliably intercepted |
| Existing approvals/sandbox | Example permission gates are regex demonstrations, not comprehensive enforcement. Project trust controls resource loading, not execution. Gondolin/container options exist but are not automatically enabled here |

## Skill discovery

Verified default locations include `${getAgentDir()}/skills`, trusted project `.pi/skills`, `~/.agents/skills`, and trusted ancestor project `.agents/skills` through the repository root. Settings/package/CLI paths contribute additional resources. `loadSkills` retains the **first discovered same-name skill** and reports collisions; resource/package composition determines the full input order. It is unsafe to promise a universal cross-package/project precedence order based only on two path names.

`resources_discover` can append ordered custom `skillPaths`. It cannot replace already loaded defaults or reliably reorder all collisions. This extension exposes only that supported behavior, not a fictitious precedence switch. Use Pi's own resource settings to disable unwanted duplicates, then reload. The extension's `writable`/`readOnly` settings do not alter discovery.

`~/.claude/skills` and `~/.config/opencode/skills` are not installed-Pi defaults. They may be added deliberately as custom discovery paths and independently authorized for writes.

## Markdown agents

Pi core has no universal Markdown-agent loader/permission inheritance contract. Its supplied subagent example discovers `${getAgentDir()}/agents/*.md` and the nearest project `.pi/agents/*.md`, with name/description/tools/model frontmatter and Markdown body; this is example-extension behavior, not core `.agents`, Claude or OpenCode compatibility.

The candidate `~/.agents/agents`, `~/.claude/agents`, `~/.config/opencode/agents` are exposed as opt-in content write locations, not invented discovery backends. Definitions anywhere may be manually reviewed, hash-trusted and activated in the settings interface. No child-session identity is inferred and no automatically selected frontmatter can self-grant authority. Only a conservative exact permission subset and validated `smartApprovalRules` are translated. Unsupported dialects/wildcards never grant permissions.

## Decision models

The installed Pi documentation/catalog interfaces identify **TypeSafe Jev** (`typesafe/jev-latest` as provider/model), **Cloudflare Clef** (Workers AI/OpenRouter), and their typed classifier protocols. They answer questions with probabilities, unlike chat completions. The implementation uses Pi's classifier registry adapter instead of inventing an OpenAI chat contract for them. Selection requires an explicit provider/model pair and actual catalog presence. Authentication/network availability is only checked by Pi at runtime; local catalog support is not a live-service verification.

LiquidAI/d1 availability/interface/suitability was **not verified** and no d1-specific compatibility is claimed. No Requesty API request was made; Requesty model availability and cost/latency advantages remain unverified. No key was printed/read from shell initialization, no paid evaluations ran, and development API cost was $0. Consequently there is no evidence yet that specialized models improve this task's latency or accuracy. Advisory input intentionally contains little context, so do not expect strong classification accuracy.

## Verification boundary

`npm test` runs dependency-free policy/controller/storage/model-mock tests. An optional integration test imports the **actual installed Pi loader**, loads `src/index.ts`, confirms command/flag registration, and invokes lifecycle handlers using mocked contexts and a temporary `PI_CODING_AGENT_DIR`. It verifies headless/nested-call-event denials, `user_bash` interception, expiry storage, restart, and corrupt-policy fail-closed behavior without executing tools.

This verifies loadability and handler behavior, not a real interactive terminal session, paid-provider compatibility, remote sandbox semantics, or complete filesystem containment. Static TypeScript checking has not been performed; the installed loader transpilation and Node strip-types test execution are verified. No destructive integration runs were attempted because isolation was not verified.

## Intentional restrictions / incomplete acceptance items

- Shell, grep/find/ls and arbitrary custom tools are opaque, fresh-review-only. Fine-grained safe shell parsing and validated read-only command adapters are not implemented. This increases friction but avoids unsupported safety claims.
- Models advise the human; model-driven automatic authorization is not implemented. Deterministic structured file operations remain fast.
- Advanced settings use a validated JSON editor, not dedicated rule/model/budget widgets. There is no configurable dollar-exact cost ceiling or paid-model benchmark.
- Pending review stores only metadata; full original arguments and automatic supersession detection are unavailable. Review never grants future permission; reissue is explicit.
- Active-agent context is manual; no automatic cross-agent permission propagation. Full Claude/OpenCode permission dialect compatibility is not claimed.
- No OS backend, Windows/macOS authorization support, tamper-evident audit, cross-process policy transaction, or independent security audit. Non-Linux intercepted calls fail closed.
- Public Pi APIs cannot guarantee separate human approval of every indirect config modification after approving arbitrary code, nor eliminate TOCTOU. These acceptance goals require a stronger execution boundary, not more regexes.

## Narrow upstream proposals / next safe steps

1. Add a **final immutable execution authorization hook**, after all mutating handlers and immediately at execution, with normalized effects/source identity. Revalidate every sibling at execution rather than preflight alone.
2. Provide structured filesystem operations with descriptor-relative `openat`/no-follow semantics and per-operation approval at the actual mutation boundary; expose a supported broker/sandbox backend covering built-in/custom/nested tools and user shell.
3. Add explicit parent/child policy propagation and trusted active-agent identity to delegated sessions, including remote runtime capability negotiation.
4. Make security-extension load failure fatal in a user-selected required-policy mode. No extension can enforce its own mandatory loading.
5. Before relaxing opaque review, implement and test a sandboxed command backend, verify mounts/network/environment, and conduct an independent adversarial review. Do not infer containment from passing mock tests.
