"""TRACE behaviour guard: an online temporal monitor over an agent's actions.

The behaviour guard compiles a :class:`~trace.policy.Policy` into a bank of
bounded-memory monitors (:mod:`trace.ltl`) and advances all of them one agent
step at a time.  It is the *trajectory* channel of TRACE: where the content
guard inspects a single piece of text, the behaviour guard watches the *shape*
of the whole session and catches violations that no individual step reveals
(slow-roll exfiltration, missing audit logs, out-of-order privileged actions).

The guard itself stores only the monitor states: memory constant in the
trajectory length.  The per-step events are persisted by the certificate ledger
(:mod:`trace.ledger`), which is the append-only audit artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .policy import Policy
from .ltl import Violation


@dataclass
class StepVerdict:
    step: int
    ok: bool                       # all monitors satisfied right now
    violated_now: List[str]        # monitor names violated at this step
    session_ok: bool               # no monitor has EVER been violated


class BehaviorGuard:
    """Streaming policy monitor.  One per agent session."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self.monitors = policy.compile()
        self._step = -1

    def reset(self) -> None:
        for m in self.monitors:
            m.reset()
        self._step = -1

    def step(self, events: Dict[str, bool]) -> StepVerdict:
        self._step += 1
        violated_now: List[str] = []
        for m in self.monitors:
            ok = m.update(events, step=self._step)
            if not ok:
                violated_now.append(m.name)
        return StepVerdict(
            step=self._step,
            ok=len(violated_now) == 0,
            violated_now=violated_now,
            session_ok=self.session_ok,
        )

    @property
    def session_ok(self) -> bool:
        return all(not m.ever_violated for m in self.monitors)

    @property
    def violations(self) -> List[Violation]:
        out: List[Violation] = []
        for m in self.monitors:
            out.extend(m.violations)
        return out

    @property
    def memory_bytes(self) -> int:
        """Total mutable monitor state: the inline footprint of the guard."""
        return sum(m.memory_bytes for m in self.monitors)

    def verdict(self) -> dict:
        return {
            "session_ok": self.session_ok,
            "n_violations": len(self.violations),
            "violations": [{"monitor": v.monitor, "step": v.step, "detail": v.detail}
                           for v in self.violations],
            "per_monitor": {m.name: {"ever_violated": m.ever_violated}
                            for m in self.monitors},
        }
