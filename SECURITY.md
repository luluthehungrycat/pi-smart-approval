# Security threat model and soft enforcement boundary

## Intended use

Reduce accidental or model-induced unsafe tool execution in a **trusted Pi runtime**. The user, Pi core, Node, OS, loaded extensions/providers, shell tool implementations, and host policy configuration are trusted. Repository contents, agent definitions, model responses, and tool outputs are not permission authorities.

Protected properties within the intercepted path:

- A policy failure returns a blocking result, not permissive fallback.
- Hard veto cannot be lifted by ordinary approvals or models.
- Known Pi mutations require a fresh local human decision, not cached/session permission.
- Structured file writes are checked against canonical writable scope independently of ordinary permissions.
- Expiry ends the original authorization attempt; pending review cannot execute it.
- Unattended callers cannot satisfy interactive requirements.
- Agent grants require explicit path+whole-file-digest trust and session activation.

These properties do **not** imply containment of a malicious tool or an approved program.

## What can bypass soft protection

1. **Approved shell/custom tools.** They run with Pi's OS privileges and may write any accessible path, start background processes, transmit secrets, change policy, create hardlinks, or act remotely. Their effects are not observed or confined after approval. Every such call therefore requires fresh review, explicitly including possible Pi configuration/outside writes. A human approving an opaque command approves its indirect effects; the extension cannot enumerate or separately approve each effect.
2. **Other extensions and Pi internals.** Direct `fs`, `pi.exec`, startup hooks, credential/config persistence, package installation, model credential commands, or raw tool factory `.execute()` calls bypass model-tool events. Extension code is fully privileged. Built-in names can be overridden by another extension; assuming their structured effects then requires trusting that override.
3. **Later handlers.** Pi lets a later `tool_call` handler mutate already-approved arguments without revalidation. Load-order advice is not a security guarantee. An earlier `user_bash` handler may also handle execution before this extension sees it.
4. **Other processes/agents.** A delegate invocation is intercepted only as one opaque tool call. Its subprocesses, remote machine, or child Pi session do not inherit interception automatically. Install protection separately in each runtime and use OS isolation.
5. **TOCTOU/concurrency.** Pi preflights siblings then executes concurrently. This extension serializes approval decisions, not execution. A symlink, mount, directory, or inode can change after final validation or between sibling preflight and execution. Canonical paths/stat fingerprints narrow the window but cannot close it through this API. Hardlinks with link count greater than one are rejected at check time, but a new alias could be created afterwards. Atomic rename/subprocess temporary writes are not enumerated by an opaque shell call.
6. **Reading/leaking secrets.** Sensitive path checks are heuristic. Credentials can be embedded in normal files or outputs, or read indirectly by programs. The main Pi session itself may record raw tool arguments/results. Redacting this extension's persistence does not redact Pi transcripts or prevent network exfiltration.
7. **Availability/removal.** This extension cannot prevent `--no-extensions`, loading a different runtime, uninstalling it, or failing to load at startup. Pi startup/config discovery occurs before this gate. Unsupported platforms deny if loaded, but the gate cannot protect a process that did not load it.
8. **Same-UID attackers.** No protection against a hostile user/process rewriting loaded code/state, racing storage operations, mount changes, ptrace, process environment changes, or tampering with the audit. Policy storage is private and atomic, not cryptographically protected or a cross-process lock.

HARD_DENY uses narrowly recognized literal disk/root destruction signatures, not complete shell semantic analysis. Obfuscated variants can classify SMART_DENY/SMART_ASK instead, but are never auto-allowed. Do not interpret a missing hard-veto signature as proof of safety.

## Stronger enforcement

Run **the entire Pi process** in a verified VM/container/bubblewrap environment with only required mounts and a restricted network. Keep host credential/config directories out, drop capabilities, avoid privileged mode, and use narrowly scoped credentials. Approving arbitrary execution in a directory is not sufficient isolation.

Pi's supplied Gondolin example delegates built-in tools to a microVM but leaves Pi/extensions on the host; it also inherits environment variables, potentially including secrets. It is not automatically compatible with host-local path assumptions here. No sandbox backend has been enabled or verified by this repository. Do not run destructive test payloads based on the mere presence of a container.

## Safe testing policy

Unit tests contain adversarial commands only as synthetic input strings. Test handlers are called directly with mocked contexts; tools are never executed to prove denial. Temporary fixture cleanup is limited to directories created by the tests. No live credentials, real destructive commands, paid models, host configuration changes, or downloaded scripts are involved.

See docs/COMPATIBILITY.md for the proposed upstream execution-boundary gate needed for stronger supported enforcement.
