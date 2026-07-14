# ADR-0007: Application is the sole Tool executor

- Status: Accepted
- Owners: Agent Security, Tool Policy

## Context

Provider runtimes may contain built-in shell, web, search, plugin, MCP,
filesystem, updater, memory, or worktree capabilities that bypass application
policy and evidence capture.

## Decision

Models and provider runtimes may emit only provider-neutral typed action
proposals. The application canonicalizes arguments, derives tenant and
credential scope, checks Skill declaration and Tool Grant, consumes any exact
one-use approval, creates the Execution, invokes the registered adapter, and
returns a redacted result. Provider built-ins are disabled and capability-
probed before startup and per release profile.

Unknown runtime events, unavailable disablement, or a bypass probe fail closed.
The model cannot select tenant, credentials, network hosts, Artifact keys, or a
fallback runtime.

## Verification and consequences

Runtime conformance requests every forbidden built-in capability and asserts
zero provider-side execution. All side effects have an application Execution,
policy decision, attempt token, audit event, and immutable result reference.

