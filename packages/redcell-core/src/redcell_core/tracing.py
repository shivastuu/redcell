"""Observability — LangSmith-first, optional, and a no-op offline.

LangGraph auto-instruments to LangSmith when these env vars are set — so the
`coordinator.py` graph traces itself for free:

    export LANGSMITH_TRACING=true
    export LANGSMITH_API_KEY=lsv2_...        # keep this in .env, NEVER in code/screenshots
    export LANGSMITH_PROJECT="redcell"

This `@traced` decorator adds spans to the parts that AREN'T LangGraph (the RLVR
search and the deterministic verifier) so the offline sim campaign is observable
too. It is a pure no-op unless LANGSMITH_TRACING is truthy AND `langsmith` is
installed — so nothing here affects the zero-install path.

(Langfuse/OTel remains a drop-in alternative; see docs/architecture.md.)
"""
from __future__ import annotations

import os
from functools import wraps


def _enabled() -> bool:
    return os.getenv("LANGSMITH_TRACING", "").lower() in ("1", "true", "yes")


def traced(name: str | None = None, run_type: str = "chain"):
    def deco(fn):
        cached = None

        @wraps(fn)
        def inner(*args, **kwargs):
            nonlocal cached
            if _enabled():
                if cached is None:
                    try:
                        from langsmith import traceable
                        cached = traceable(name=name or fn.__name__, run_type=run_type)(fn)
                    except ImportError:
                        cached = fn
                return cached(*args, **kwargs)
            return fn(*args, **kwargs)
        return inner
    return deco
