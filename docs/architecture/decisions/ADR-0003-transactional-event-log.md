# ADR-0003: Transactional Run event log

- Status: Accepted
- Owner: Orchestration Platform

## Context

SSE reconnect, worker recovery, and auditability require one durable truth for
state and emitted events without a dual-write gap.

## Decision

Every Run state mutation and its `run_events` append commit in one PostgreSQL
transaction. Events receive a unique, monotonic per-Run sequence. Redis is only
a wake-up and lease mechanism; it is not event truth. SSE reads the durable log,
resumes strictly after `Last-Event-ID`, and returns 410 beyond retention.

Workers use a heartbeat lease plus monotonic attempt token. Completion commits
only when the token still owns the Run. Recovery reconciles state but never
automatically replays side-effecting Tool or Python execution.

## Verification and consequences

Protocol tests kill workers between writes, duplicate delivery, reconnect at
every sequence, and submit stale completion. Consumers must be idempotent by
event identity; new attempts create new immutable Execution records.

