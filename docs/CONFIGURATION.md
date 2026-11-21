# Configuration v1 and precedence

All global fields are required when a file exists; unknown fields are rejected. The minimal example is the complete default schema. A missing file—not a partial file—selects defaults. There is no migration to apply automatically.

| Field | Meaning |
|---|---|
| `version` | Exactly `1` |
| `smart` | Boolean; false asks instead of ordinary deterministic auto-allows |
| `timeoutMs` | Approval timeout, integer 10–3,600,000; default 120,000 |
| `reviewDeny` | Boolean, default false; enables manual review of SMART_DENY, not technical/manual-deny failures |
| `writable` | Additional absolute writable roots, recursively; exact files can be listed |
| `readOnly` | Absolute excluded write roots, including under CWD/default global skills roots |
| `skillPaths` | Absolute additional discovery paths returned through `resources_discover`; not write permissions |
| `rules` | Array of manual rules below |
| `trustedAgents` | `{path: absolutePath, digest: SHA256_of_entire_file}` records; activation is separately session-only |
| `analysis` | Optional chat analysis configuration |
| `decisionModel` | Optional typed-classifier configuration; explicit provider/model required when enabled |
| `shellModelAssist` | Optional boolean, absent/false by default. When true, `smart` is true, the call is reusable and in the deterministic shell `model` tier, and an enabled analysis or decision model returns `SMART_ALLOW` with confidence at least 0.95, the call may be authorized without a dialog. It cannot override vetoes, protected paths, scope checks, `ALWAYS_ASK`, or unattended denial. Existing configuration files remain valid without this field. |

An analysis configuration contains `enabled`, `maxCalls` (integer 0–1000), `maxInputChars` (100–16000), `timeoutMs` (10–120000), and optional **paired** `provider` and `model` nonempty strings. Defaults: disabled, 10 calls per session, 4000 input characters and 10000 ms. LLM output limit is fixed at 256 tokens. Classifier state is small/fixed metadata; its protocol has no verified strict token ceiling. Provider availability/auth is resolved by Pi, not stored here. Use Pi's model configuration for compatible endpoints.

## Rules

```json
{
  "tool": "write",
  "action": "ALWAYS_ASK",
  "path": "/absolute/project/security"
}
```

`tool` is an exact tool name or `*`. `action` is `ALWAYS_ALLOW`, `ALWAYS_ASK`, or `ALWAYS_DENY`. Optional `path` is a canonical resource-prefix boundary, **not a glob**. Optional `key` is the 64-character lowercase hex operation digest shown in dialogs/denials. Matching requires all supplied selectors.

An ALWAYS_ALLOW rule **requires** `key`. The digest covers deterministic sorted JSON of the complete call `{tool,input}` and CWD. Thus changing content, arguments, timeout, or path spelling changes the operation. A key is not a secret; do not use it as authentication. Broad allow rules without exact keys are invalid, even when intended as exceptions. To make an exceptional permanent SMART_DENY allowance, deliberately add an exact rule through settings; opaque/config/outside guards still apply.

Order of rules does not confer priority. Deny wins over ask, which wins over allow. Agent-derived rules have no privileged precedence. ALWAYS_DENY cannot be undone through reviewDeny.

## Deterministic precedence

1. Unreliable validation, unsupported platform, multiply linked/special files, invalid configuration, engine/UI/storage failures: block, no approval fallback.
2. Recognized HARD_DENY signatures: block unless explicitly acknowledged session override is active. Override maps to SMART_DENY, never to allow.
3. Matching ALWAYS_DENY: block without review. Protected Pi mutation: fresh exact-operation manual approval, no reusable grants. (A deterministic hard or sensitive denial can be stricter; config is never auto-authorized.)
4. Matching ALWAYS_ASK requires fresh approval; it cannot be satisfied by session grants. Matching exact allow is considered only after invariant checks.
5. Opaque or unknown effects (including complex/vetoed shell syntax and custom tools) require fresh review or default denial, irrespective of ordinary permissions. A conservative deterministic literal shell tier can auto-allow selected read-only commands inside the workspace; a separate restricted grep/find tier requires review, except for the narrowly gated `shellModelAssist` behavior described above. Opaque review explicitly includes possible configuration and outside writes.
6. Writes outside authorized roots or under a read-only exclusion require fresh path-specific approval; tool allow rules cannot bypass this. An approved one-off operation is the explicit path authorization.
7. Within authorized scope, exact manual allow may override a smart classification. Otherwise valid session grants apply only to nonopaque, nonprotected, in-scope, non-ALWAYS_ASK operations; grants include operation and filesystem/policy fingerprint. Shell grants additionally bind the shell environment digest and are invalidated by effective policy changes or session restart/tree change.
8. Deterministic safe file operations auto-allow when smart mode is enabled. Sensitive resources SMART_DENY by default.
9. Optional model advice is display-only except for the explicit, narrowly scoped `shellModelAssist` condition. Unknown operations fall back to ask. Unattended operations needing review deny immediately.

## Shell classification and grants

The tokenizer accepts one literal command only: ASCII input, space/tab separators, unquoted characters `[A-Za-z0-9_./=:,@%+-]`, and single-quoted literal words. Double quotes, backslashes, expansions, shell composition, newlines, environment assignments, and quoted or path-qualified program names make the command opaque. Opaque and veto-signature commands get fresh one-time review only. Recognized path operands must canonicalize inside CWD and must not be sensitive, protected Pi configuration, or multiply linked; symlink escapes fail scope checks.

The deterministic auto tier covers `pwd`, `true`, `whoami`, argument-free `date`, `echo`, restricted-flag `uname` and `ls`, and restricted read-only `cat`, `head`, `tail`, `wc`, `stat`, `file`, `du`, and `diff`. Operand requirements and permitted flags are enforced by the parser. `grep` with restricted flags and explicit path operands, and `find` with restricted roots/predicates, form the model tier; `find` predicates are limited to `-name`, `-iname`, `-path`, `-ipath`, `-type`, `-maxdepth`, `-mindepth`, and `-print` (no `-exec`, `-delete`, or other predicates). Recursive grep is excluded. Model-tier calls need human approval unless `shellModelAssist` is true, smart mode is enabled, and an enabled decision or analysis model returns `SMART_ALLOW` with confidence ≥0.95. Model failure or timeout leaves human approval in place. Model input has no operands, patterns, or paths; it contains program/validated flags/tier/scope metadata and sanitized classification metadata. Vetoes, `ALWAYS_DENY`/`ALWAYS_ASK`, protected paths and scope restrictions cannot be overridden. Unattended sessions deny this tier.

An unsafe inherited environment disables shell auto-allow and reuse: exported `BASH_FUNC_*`, `BASH_ENV`, `ENV`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `SHELLOPTS`, `BASHOPTS`, empty `PATH`, or relative, parent-traversing, or workspace `PATH` entries.

Simple, non-vetoed shell commands can offer session or permanent exact grants unless the program is ungrantable (including shells, `eval`, `exec`, `env`, `sudo`, `xargs`, `nohup`, `timeout`, `ssh`, `curl`, and `wget`), an interpreter uses inline-code flags, or an argument names an outside, sensitive, or protected path. Session grants bind exact tool input, CWD, shell-environment digest, and effective policy; policy changes invalidate them and session restart/tree change clears them. The dialog states the reuse scope and that the shell is not sandboxed: a grant covers every direct and indirect effect of that exact command. Allow once creates no grant.

Persistent shell `ALWAYS_ALLOW` rules use a rule key over the complete call, CWD, and shell-environment digest. This differs from the operation key shown for general identification; a plain bash operation key does not authorize a persistent shell allow. `ALWAYS_DENY` and `ALWAYS_ASK` may match either key. Saving a permanent rule requires a second select confirmation showing its tool, rule key, and scope. Cancel, timeout, or invalid reply saves nothing and blocks execution (`PERSIST_CANCELLED`, `PERSIST_CONFIRMATION_TIMEOUT`, or `INVALID_APPROVAL_REPLY`). Saving checks that global policy has not changed, appends the exact rule, then re-evaluates the call; it runs only if that rule now authorizes it.

For SMART_DENY, manual review must be enabled **before** any reusable session approval is considered. SMART_DENY persistence is unavailable in the approval dialog. File hardlinks and technical failures cannot be manually excused.

## Roots and path handling

CWD, `~/.agents/skills`, and `${getAgentDir()}/skills` are default writable. `readOnly` subtracts from those roots; it takes priority over `writable`/session additions. Roots and resources are canonicalized. Existing symlinks resolve through realpath; nonexistent suffixes use their existing ancestor. Dangling links, permission errors, `..` traversal spellings, file URLs, multiply-linked files and special files fail closed. Use an unambiguous absolute path instead of `..` or `file://`.

A listed file root authorizes that exact file; a directory root authorizes descendants. Protection checks use both lexical and canonical spelling so aliases cannot hide `.pi` content. The entire installed extension directory is protected. Global agent state outside its skills subtree is protected. CWD/root checks are independent of tool-level rules.

The global path controls also list Claude/OpenCode skills and agent locations. They are **not default writable/discovered**, because installed Pi does not automatically discover them. Add custom paths in `writable` or `skillPaths` according to the distinct intent. Session-only additions disappear on restart/reload.

## Project configuration

Only this shape is allowed:

```json
{
  "version": 1,
  "readOnly": ["/absolute/project/security"],
  "rules": [{"tool": "bash", "action": "ALWAYS_DENY"}]
}
```

It is read at `${cwd}/${CONFIG_DIR_NAME}/smart-approval.json`. No model/trust/scope grants or overrides are accepted. Unknown/permissive fields block execution rather than silently being ignored. Its modification is itself protected.

## Persistence and privacy

Global policy saves require the manual full-policy confirmation. A pre-save snapshot comparison detects policy changes during review. Files are atomically written via exclusive private temporary files and rename, with fsync. Storage directory symlinks, unsafe modes, wrong directory ownership, and multiply linked existing storage files reject writes. This is not a cross-process transaction or defense against a hostile same-UID process racing filesystem calls.

Audit records retain the last 200 decisions, showing only tool category, decision, fixed reason, timestamp, allow/deny and digest. Pending records contain id/key/tool/session/time/status/fixed reason. Raw arguments and paths are not retained. Pending records require manual removal and have no execution capability. Concurrent records have unique names; audit is not tamper-evident.

Session approvals are memory-only and clear on runtime replacement/tree changes. Policy/trust and target/ancestor identities are rechecked after review and again before the tool hook returns. This does not eliminate the remaining time-of-check/time-of-use window described in SECURITY.md.
