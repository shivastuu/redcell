# ADR 0001 — LangGraph for the attacker orchestration (not CrewAI/AutoGen)

**Status:** accepted · **Date:** 2026-07

## Context
The attacker orchestration must be traced, gated, budgeted, and deterministically
replayable. An interviewer's first jab is "isn't this just N chatbots talking?"

## Decision
Use **LangGraph** (explicit `StateGraph`: nodes, edges, typed shared state, durable
checkpointing) with a supervisor topology.

## Why not the alternatives
- **CrewAI / AutoGen** optimize for "agents role-playing a team," which hides the
  control flow. We can't cleanly answer "which exact tool call breached, at which
  node" in a conversation-centric framework.
- **Hand-rolled** would reinvent checkpointing, retries, and streaming, and lose
  trace integration — for no benefit. (The one thing we DO keep hand-rolled is the
  verifier: it must be dumb, deterministic, and dependency-light.)

## Consequences
- Every hand-off is a place to attach an OTel span and a verifier hook.
- Durable checkpointing enables the frozen-corpus replay and safe crash-resume
  (content-addressed `attempt_id` + idempotent reducer → never re-fire an attack).
- We depend on LangGraph's API surface — pinned in the lockfile; version verified
  (**v1.x as of 2026**, not the stale 0.x some docs still show).
