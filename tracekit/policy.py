"""A small declarative policy language for agent safety.

A :class:`Policy` is a list of named temporal constraints over Boolean *events*.
Events are produced per step by an adapter (:mod:`trace.adapters`) from whatever
the agent actually did: a tool call, a retrieved document, a generated action.
The policy never mentions models or features; it speaks only of events, so the
same policy moves unchanged across agents and providers.

Builder helpers return serialisable specs; :meth:`Policy.compile` instantiates
the online monitors of :mod:`trace.ltl`.  The whole policy serialises to JSON so
it can be embedded in a session certificate and replayed by an auditor.

Example
-------
>>> from trace.policy import Policy, always, bounded_count, response, precedence
>>> pol = Policy("data-handling-v1", [
...     always("within_scope"),
...     bounded_count("export", max_count=2, window=50),
...     response("sensitive_read", "audit_log", deadline=3),
...     precedence("authorize", "transfer"),
... ])
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set

from .ltl import Monitor


def always(pred: str, name: str | None = None) -> dict:
    return {"kind": "always", "name": name or f"always({pred})", "pred": pred}


def never(event: str, name: str | None = None) -> dict:
    return {"kind": "never", "name": name or f"never({event})", "event": event}


def bounded_count(event: str, max_count: int, window: int, name: str | None = None) -> dict:
    return {"kind": "bounded_count",
            "name": name or f"count_le({event},{max_count},{window})",
            "event": event, "max_count": int(max_count), "window": int(window)}


def response(trigger: str, response: str, deadline: int, name: str | None = None) -> dict:
    return {"kind": "response",
            "name": name or f"response({trigger}->{response},{deadline})",
            "trigger": trigger, "response": response, "deadline": int(deadline)}


def precedence(first: str, second: str, name: str | None = None) -> dict:
    return {"kind": "precedence",
            "name": name or f"precedence({first}<{second})",
            "first": first, "second": second}


_EVENT_FIELDS = ("pred", "event", "trigger", "response", "first", "second")


@dataclass
class Policy:
    name: str
    constraints: List[dict] = field(default_factory=list)

    def event_names(self) -> Set[str]:
        names: Set[str] = set()
        for c in self.constraints:
            for f in _EVENT_FIELDS:
                if f in c:
                    names.add(c[f])
        return names

    def compile(self) -> List[Monitor]:
        return [Monitor.from_spec(c) for c in self.constraints]

    def to_dict(self) -> dict:
        return {"name": self.name, "constraints": [dict(c) for c in self.constraints]}

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        return cls(name=d["name"], constraints=[dict(c) for c in d["constraints"]])
