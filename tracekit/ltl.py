"""Online, bounded-memory monitors for finite-trace temporal safety policies.

Each monitor consumes a stream of Boolean *events* (one dictionary per agent
step) and maintains a verdict incrementally.  Every monitor uses memory that is
**constant in the length of the trajectory**: it depends only on the policy
parameters (a window size or a response deadline), never on how many steps the
agent has taken.  This is what makes TRACE deployable *inline*: an agent can run
for a million steps and the monitor state stays a few hundred bytes.

The monitors implement the standard bounded fragments of finite-trace LTL
(LTLf) used in runtime verification (Bauer, Leucker & Schallhart, 2011;
De Giacomo & Vardi, 2013):

    Always(p)                  invariant            G p
    Never(e)                   absence              G !e
    BoundedCount(e, k, w)      rate / count bound   "<= k occurrences of e per w steps"
    Response(t, r, d)          bounded response     G (t -> F_{<= d} r)
    Precedence(a, b)           precedence / latch   !b W a   (b only after a)

Safety semantics: a violation is **latched** (``ever_violated`` stays true)
because, for a safety property, a finite bad prefix can never be undone.  The
instantaneous ``ok`` field still reports whether the property holds *right now*
(useful for sliding-window properties).  Every monitor is fully described by a
serialisable ``spec`` so an independent verifier can reconstruct it and replay
the recorded event stream: TRACE certificates rely on this.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Violation:
    monitor: str
    step: int
    detail: str


class Monitor:
    """Base class.  Subclasses implement ``_update`` and ``spec``."""

    def __init__(self, name: str):
        self.name = name
        self.ever_violated = False
        self.ok = True
        self.violations: List[Violation] = []
        self._step = -1

    # serialisation ---------------------------------------------------- #
    @property
    def spec(self) -> dict:
        raise NotImplementedError

    @staticmethod
    def from_spec(spec: dict) -> "Monitor":
        kind = spec["kind"]
        cls = _REGISTRY[kind]
        return cls._from_spec(spec)

    @classmethod
    def _from_spec(cls, spec: dict) -> "Monitor":
        raise NotImplementedError

    # streaming -------------------------------------------------------- #
    def reset(self) -> None:
        self.ever_violated = False
        self.ok = True
        self.violations = []
        self._step = -1
        self._reset_state()

    def _reset_state(self) -> None:
        pass

    def update(self, events: Dict[str, bool], step: Optional[int] = None) -> bool:
        """Advance one step.  Returns the instantaneous ``ok`` after this step."""
        self._step = step if step is not None else self._step + 1
        ok_now = self._update(events)
        self.ok = ok_now
        if not ok_now and not self.ever_violated:
            self.ever_violated = True
        if not ok_now:
            self.violations.append(Violation(self.name, self._step, self._detail(events)))
        return ok_now

    def _update(self, events: Dict[str, bool]) -> bool:
        raise NotImplementedError

    def _detail(self, events: Dict[str, bool]) -> str:
        return ""

    @property
    def memory_bytes(self) -> int:
        """Best-effort bound on the monitor's mutable state size (for the
        systems analysis).  Constant in trajectory length by construction."""
        return 64


# ---------------------------------------------------------------------- #
class Always(Monitor):
    """G p: predicate ``p`` must hold at every step."""

    def __init__(self, pred: str, name: Optional[str] = None):
        super().__init__(name or f"always({pred})")
        self.pred = pred

    @property
    def spec(self) -> dict:
        return {"kind": "always", "name": self.name, "pred": self.pred}

    @classmethod
    def _from_spec(cls, spec):
        return cls(spec["pred"], name=spec.get("name"))

    def _update(self, events):
        return bool(events.get(self.pred, False))

    def _detail(self, events):
        return f"predicate '{self.pred}' false"


class Never(Monitor):
    """G !e: event ``e`` must never occur."""

    def __init__(self, event: str, name: Optional[str] = None):
        super().__init__(name or f"never({event})")
        self.event = event

    @property
    def spec(self) -> dict:
        return {"kind": "never", "name": self.name, "event": self.event}

    @classmethod
    def _from_spec(cls, spec):
        return cls(spec["event"], name=spec.get("name"))

    def _update(self, events):
        return not bool(events.get(self.event, False))

    def _detail(self, events):
        return f"forbidden event '{self.event}' occurred"


class BoundedCount(Monitor):
    """At most ``max_count`` occurrences of ``event`` in any sliding window of
    ``window`` steps.  Memory: O(window), a ring buffer of the window's
    Boolean values plus a running count.  Catches slow-roll / distributed
    abuse that every single step looks innocent for."""

    def __init__(self, event: str, max_count: int, window: int, name: Optional[str] = None):
        super().__init__(name or f"count_le({event},{max_count},{window})")
        self.event = event
        self.max_count = int(max_count)
        self.window = int(window)
        self._buf: deque = deque(maxlen=self.window)
        self._count = 0

    @property
    def spec(self) -> dict:
        return {"kind": "bounded_count", "name": self.name, "event": self.event,
                "max_count": self.max_count, "window": self.window}

    @classmethod
    def _from_spec(cls, spec):
        return cls(spec["event"], spec["max_count"], spec["window"], name=spec.get("name"))

    def _reset_state(self):
        self._buf = deque(maxlen=self.window)
        self._count = 0

    def _update(self, events):
        v = 1 if events.get(self.event, False) else 0
        if len(self._buf) == self.window:
            self._count -= self._buf[0]   # value about to be evicted
        self._buf.append(v)
        self._count += v
        return self._count <= self.max_count

    def _detail(self, events):
        return f"{self._count} occurrences of '{self.event}' in window {self.window} (> {self.max_count})"

    @property
    def memory_bytes(self):
        return 64 + self.window  # one byte per windowed flag


class Response(Monitor):
    """Bounded response: G (trigger -> F_{<= deadline} response).  Whenever
    ``trigger`` fires, ``response`` must fire within ``deadline`` steps.  Memory:
    O(deadline) outstanding deadline counters.  Models obligations such as
    'every sensitive read must be followed by an audit-log within k steps'."""

    def __init__(self, trigger: str, response: str, deadline: int, name: Optional[str] = None):
        super().__init__(name or f"response({trigger}->{response},{deadline})")
        self.trigger = trigger
        self.response = response
        self.deadline = int(deadline)
        self._pending: deque = deque()   # remaining-step counters

    @property
    def spec(self) -> dict:
        return {"kind": "response", "name": self.name, "trigger": self.trigger,
                "response": self.response, "deadline": self.deadline}

    @classmethod
    def _from_spec(cls, spec):
        return cls(spec["trigger"], spec["response"], spec["deadline"], name=spec.get("name"))

    def _reset_state(self):
        self._pending = deque()

    def _update(self, events):
        # 1. Enqueue this step's trigger FIRST so a same-step response can
        #    discharge it: finite-trace F_{<=deadline} evaluated at the trigger
        #    position includes that position, so deadline=0 means "respond now".
        if events.get(self.trigger, False):
            self._pending.append(self.deadline)
        # 2. A response discharges the OLDEST outstanding obligation (FIFO): each
        #    trigger needs its own response, so N triggers require N responses.
        #    This is the faithful semantics for an audit-logging obligation (one
        #    log entry per sensitive action) and prevents a later response from
        #    masking an earlier unanswered trigger.
        if events.get(self.response, False) and self._pending:
            self._pending.popleft()
        # 3. Decrement remaining time; an obligation that drops below 0 expired.
        expired = False
        new_pending = deque()
        for rem in self._pending:
            rem -= 1
            if rem < 0:
                expired = True
            else:
                new_pending.append(rem)
        self._pending = new_pending
        return not expired

    def _detail(self, events):
        return f"'{self.trigger}' not answered by '{self.response}' within {self.deadline} steps"

    @property
    def memory_bytes(self):
        return 64 + 4 * (self.deadline + 1)


class Precedence(Monitor):
    """!second W first: ``second`` may only occur once ``first`` has occurred
    (a latch).  Models 'no transfer before authorisation', 'no tool call before
    consent'.  Memory: O(1)."""

    def __init__(self, first: str, second: str, name: Optional[str] = None):
        super().__init__(name or f"precedence({first}<{second})")
        self.first = first
        self.second = second
        self._seen_first = False

    @property
    def spec(self) -> dict:
        return {"kind": "precedence", "name": self.name,
                "first": self.first, "second": self.second}

    @classmethod
    def _from_spec(cls, spec):
        return cls(spec["first"], spec["second"], name=spec.get("name"))

    def _reset_state(self):
        self._seen_first = False

    def _update(self, events):
        if events.get(self.first, False):
            self._seen_first = True
        if events.get(self.second, False) and not self._seen_first:
            return False
        return True

    def _detail(self, events):
        return f"'{self.second}' occurred before '{self.first}'"


_REGISTRY = {
    "always": Always,
    "never": Never,
    "bounded_count": BoundedCount,
    "response": Response,
    "precedence": Precedence,
}
