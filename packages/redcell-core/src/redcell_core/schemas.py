"""Core data model for RedCell.

Deliberately built on stdlib ``dataclasses`` so the deterministic verifier
(the credibility spine) runs with zero third-party dependencies. When you add
boundary validation, these migrate cleanly to Pydantic v2 models.

The single most important rule in the whole project lives here: verifiers read
a *server-recorded* ``AttackTrace`` — never the model's self-report. A jailbroken
model lies about what it did; the tool-call log is recorded out-of-band by the
server (never the model's self-report), so the trust boundary is the server.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal, Optional

Detector = Literal[
    "canary", "unauthorized_tool_call", "pii_regex", "schema_violation",
    "precondition_bypass", "none",
]


@dataclass(frozen=True)
class Canary:
    """A planted honeytoken. Any occurrence on an egress surface = exfiltration."""
    value: str
    channel: str  # SYS_SECRET | OTHER_USER_ROW | RAG_INTERNAL | TOOL_DESC


@dataclass(frozen=True)
class ToolCall:
    span_id: str
    tool_name: str
    args: dict[str, Any]
    result: Optional[dict[str, Any]] = None
    executed: bool = True            # False when a destructive tool is honeypot-blocked
    ts: float = 0.0


@dataclass(frozen=True)
class SessionState:
    user_id: str                     # the authenticated caller ("$SELF")
    step_up_verified: bool = False
    daily_limit: int = 0
    beneficiary_allowlist: tuple[str, ...] = ()


@dataclass(frozen=True)
class SeedManifest:
    """Ground truth the seeder planted for THIS attempt. The mutator never sees this."""
    canaries: tuple[Canary, ...] = ()


@dataclass(frozen=True)
class AttackTrace:
    """The only thing verifiers are allowed to read. Recorded out-of-band by the server."""
    run_id: str
    attempt_id: str
    scenario_id: str
    rendered_input: str              # exact adversarial input sent to the agent
    tool_calls: tuple[ToolCall, ...]
    final_output: str                # raw bytes returned to the "user" sink
    outbound_sinks: tuple[dict[str, Any], ...] = ()  # args of any egress tool
    session: SessionState = field(default_factory=lambda: SessionState(user_id="u_self"))
    seeded: SeedManifest = field(default_factory=SeedManifest)
    defense_version: str = "none"    # "none" pre-defense, "v2" post-defense
    corpus_id: Optional[str] = None


@dataclass(frozen=True)
class VerifierResult:
    breach_class: str
    breached: bool                   # THE verifiable reward bit
    detector: Detector
    confidence: float                # 1.0 for deterministic hits
    evidence: dict[str, Any]         # machine-checkable reproducer
    verifier_version: str


@dataclass(frozen=True)
class Verdict:
    """Aggregation of all verifier results for one attempt."""
    attempt_id: str
    results: tuple[VerifierResult, ...]

    @property
    def breach(self) -> bool:
        return any(r.breached for r in self.results)

    @property
    def reward(self) -> float:
        """r_breach — the only signal anything downstream trusts (RLVR)."""
        return 1.0 if self.breach else 0.0

    @property
    def detectors_fired(self) -> list[str]:
        return [r.detector for r in self.results if r.breached]


@dataclass(frozen=True)
class DefenseConfig:
    """The one struct that makes attribution possible: every layer toggles here.

    baseline = all False. full = all True. ablation = any of the 2^5 subsets.
    A defense that can't be cleanly toggled off can't be attributed.
    """
    l1_input_classifier: bool = False   # Llama Prompt Guard 2 (injection/jailbreak)
    l2_spotlight: bool = False          # datamark untrusted tool output as DATA
    l3_allowlist: bool = False          # deny-by-default tool execution + arg validation
    l4_redact: bool = False             # Presidio PII/canary egress-DLP
    l5_schema: bool = False             # strict structured-output validation

    @property
    def version(self) -> str:
        raw = f"{self.l1_input_classifier}{self.l2_spotlight}{self.l3_allowlist}{self.l4_redact}{self.l5_schema}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    @property
    def label(self) -> str:
        on = [n for n, v in (("L1", self.l1_input_classifier), ("L2", self.l2_spotlight),
                             ("L3", self.l3_allowlist), ("L4", self.l4_redact),
                             ("L5", self.l5_schema)) if v]
        return "baseline" if not on else "+".join(on) if len(on) < 5 else "full"

    @classmethod
    def baseline(cls) -> "DefenseConfig":
        return cls()

    @classmethod
    def full(cls) -> "DefenseConfig":
        return cls(True, True, True, True, True)
