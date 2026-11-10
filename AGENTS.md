AGENTS.md — Pi Smart Approval Extension

Project purpose

This repository develops a security-conscious smart approval and filesystem protection extension for Pi Agent.

"prompt.txt" is the authoritative product specification. Read it before planning or implementing changes.

This file defines persistent development instructions for all coding agents working on the repository.

Development principles

1. Security before convenience. Never weaken enforcement merely to make tests pass or reduce approval friction.
2. Fail closed. If a required security decision cannot be made reliably, deny execution rather than assuming safety.
3. Deterministic rules first. Use LLM or specialized decision-model analysis only where it meaningfully improves classification.
4. Least privilege. Authorize specific operations and resources, not unrestricted access to entire tools.
5. No security theater. Clearly distinguish advisory tool interception from actual OS-enforced isolation.
6. Compatibility. Prefer Pi's supported extension APIs over modifying Pi core.
7. Maintainability. Keep policy evaluation, filesystem protection, model analysis, UI, and persistence modular and independently testable.

Mandatory safety rules

Never execute real destructive or dangerous tool calls to test SMART_DENY or HARD_DENY unless operating inside a verified, appropriately isolated bubblewrap, Gondolin, microVM, or hardened container environment.

Without verified isolation, use mocks, dry-run evaluation, synthetic tool calls, and inert fixtures.

Never experiment with destructive operations against the host filesystem, real credentials, production repositories, or external systems.

Do not weaken or disable security checks to make integration testing easier.

Do not execute downloaded scripts without appropriate inspection and authorization.

Do not expose API keys, credentials, or sensitive configuration in logs, commits, test fixtures, or model prompts.

The "REQUESTY_API_KEY" environment variable may be used for explicitly authorized, budget-conscious decision-model testing. Never print its value or dump ".bashrc".

Non-negotiable policy invariants

- HARD_DENY takes precedence over normal permissions.
- A hard-deny override requires explicit activation and does not itself authorize execution.
- Changes to Pi configuration always require manual approval, regardless of smart classification or ordinary allow rules.
- Untrusted agent frontmatter cannot grant permissions.
- Project configuration cannot silently weaken global security policy.
- Unattended execution must deny operations requiring interactive approval.
- Expired approval requests must never trigger automatic execution.
- Model-based decisions cannot override deterministic security invariants.
- Writable filesystem scope must be checked independently of broad tool-level approval.

Architecture and implementation

Before introducing new dependencies or architectural components, inspect the existing implementation and determine whether Pi's extension API already provides the required functionality.

Prefer pure, testable functions for policy evaluation.

Separate the following concerns:

- Tool interception and normalization.
- Deterministic policy evaluation.
- Filesystem scope validation.
- Optional model-assisted risk analysis.
- Approval interaction and persistence.
- Configuration and trust management.
- Audit logging.

Use typed interfaces and structured decision results.

Document policy precedence and the rationale for security-sensitive decisions.

Avoid hidden global state and unnecessary dependencies.

Testing discipline

Every security-sensitive change requires appropriate regression tests.

Cover both authorized behavior and attempts to bypass restrictions.

Test shell composition, path traversal, symlinks, configuration modifications, permission inheritance, unattended execution, and model-analysis failures.

Use mocked tool execution for dangerous scenarios.

Tests must never rely on actual destructive side effects to prove a denial.

A passing test suite is not sufficient evidence that the extension provides complete filesystem isolation.

Working with coding agents

Before implementing a substantial change:

1. Read "prompt.txt", this file, and relevant existing source code.
2. Inspect the current implementation and tests.
3. Identify affected security invariants.
4. Make the smallest coherent change.
5. Add or update tests.
6. Run safe verification.
7. Summarize changes, test results, and remaining limitations.

Do not claim a feature is implemented unless it has been verified.

Do not claim security guarantees beyond the demonstrated enforcement boundary.

If a requirement cannot be implemented reliably using Pi's public extension API, document the limitation and propose a safer alternative.

Repository hygiene

- Never commit credentials or local environment files containing secrets.
- Keep generated artifacts and temporary test files out of version control.
- Avoid unrelated refactoring during security-sensitive changes.
- Preserve backwards compatibility where reasonable.
- Document configuration schema changes and migrations.
- Do not modify the project's security requirements without explicit user authorization.

Definition of done

A feature is complete only when its implementation, tests, documentation, and known limitations are consistent.

Security-critical behavior must be demonstrably enforced within the documented threat model.

When uncertain, report the uncertainty instead of silently choosing a permissive interpretation.
