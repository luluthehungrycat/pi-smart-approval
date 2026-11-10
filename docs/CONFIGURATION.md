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
5. Unknown effects (shell/custom tools) require fresh review or default denial, irrespective of ordinary permissions. Every opaque review explicitly includes possible configuration and outside writes.
6. Writes outside authorized roots or under a read-only exclusion require fresh path-specific approval; tool allow rules cannot bypass this. An approved one-off operation is the explicit path authorization.
7. Within authorized scope, exact manual allow may override a smart classification. Otherwise valid session grants apply only to nonopaque, nonprotected, in-scope, non-ALWAYS_ASK operations; grants include operation and filesystem/policy fingerprint.
8. Deterministic safe file operations auto-allow when smart mode is enabled. Sensitive resources SMART_DENY by default.
9. Optional model advice is display-only, never an authority. Unknown operations fall back to ask. Unattended operations needing review deny immediately.

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
