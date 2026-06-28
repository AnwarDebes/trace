"""The TRACE engine: a drop-in certifying guardrail for an agent session.

``TRACEEngine`` wires the two guards and the ledger together behind a tiny
interface an agent runtime can call on every turn:

    eng = TRACEEngine(session_id="s1", policy=pol, content_guard=cg,
                      adapter=adp, key=KEY, mode="enforce")
    res = eng.guard_input(user_text)          # before the model sees input
    ...
    sv  = eng.observe(tool_call, provider="anthropic")  # after each tool call
    ...
    cert = eng.seal()                          # at end of session

In ``monitor`` mode the engine only records and reports; in ``enforce`` mode it
also returns ``allow=False`` so the runtime can block the offending input or
tool call.  Either way it produces a signed, hash-chained certificate of the
whole session that anyone can verify with :func:`trace.ledger.verify_ledger`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from .policy import Policy
from .behavior_guard import BehaviorGuard, StepVerdict
from .content_guard import ContentGuard, ContentVerdict
from .adapters import ToolCallAdapter
from .ledger import CertificateLedger, SessionCertificate


@dataclass
class InputDecision:
    allow: bool
    verdict: ContentVerdict


class TRACEEngine:
    def __init__(
        self,
        session_id: str,
        policy: Policy,
        content_guard: Optional[ContentGuard] = None,
        adapter: Optional[ToolCallAdapter] = None,
        key: Optional[bytes] = None,
        mode: str = "monitor",
    ):
        if mode not in ("monitor", "enforce"):
            raise ValueError("mode must be 'monitor' or 'enforce'")
        self.session_id = session_id
        self.policy = policy
        self.content_guard = content_guard
        self.adapter = adapter
        self.mode = mode
        self.behavior = BehaviorGuard(policy)
        self.ledger = CertificateLedger(session_id, policy, key=key)
        self._content_total = 0
        self._content_flagged = 0

    # ---- content channel ----
    def guard_input(self, text: str) -> InputDecision:
        if self.content_guard is None:
            raise RuntimeError("no content guard configured")
        v = self.content_guard.verdict(text)
        audit = self.content_guard.audit(text)
        self.ledger.append_content(text=text, label=v.label, margin=v.margin,
                                   fired=audit["fired"], literals=audit["literals"])
        self._content_total += 1
        self._content_flagged += int(v.unsafe)
        allow = (not v.unsafe) if self.mode == "enforce" else True
        return InputDecision(allow=allow, verdict=v)

    # ---- behaviour channel ----
    def observe(self, call: dict, provider: str = "openai") -> StepVerdict:
        if self.adapter is None:
            raise RuntimeError("no adapter configured")
        events = self.adapter.step_events(call, provider=provider)
        return self.observe_events(events)

    def observe_events(self, events: Dict[str, bool]) -> StepVerdict:
        sv = self.behavior.step(events)
        self.ledger.append_behavior(step=sv.step, events=events,
                                    violated_now=sv.violated_now)
        return sv

    def allow_step(self, sv: StepVerdict) -> bool:
        if self.mode == "monitor":
            return True
        return sv.ok and sv.session_ok

    # ---- sealing ----
    def content_summary(self) -> dict:
        return {"n_content_checks": self._content_total,
                "n_flagged": self._content_flagged}

    def seal(self) -> SessionCertificate:
        return self.ledger.seal(behavior_verdict=self.behavior.verdict(),
                                content_summary=self.content_summary())

    def audit_bundle(self) -> dict:
        cert = self.seal()
        return {"ledger": self.ledger.to_dict(), "certificate": cert}
