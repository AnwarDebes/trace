"""Model-agnostic adapters: turn a tool call into policy events.

TRACE is meant to drop into *any* agent.  Agents differ only in the wire format
of their tool/function calls; the safety-relevant content is the same: a tool
name plus arguments.  An adapter normalises the three dominant formats
(OpenAI / DeepSeek function-calling, Anthropic ``tool_use``) into a canonical
``{name, arguments}`` record, then maps that record to the Boolean *events* a
:class:`~trace.policy.Policy` speaks in.

The mapping is declarative and auditable: a capability table assigns each tool
the events it can raise (``read``, ``write``, ``export`` ...), and a small set
of argument rules raise data-dependent events (e.g. an external recipient raises
``export`` and clears ``within_scope``).  Because the *events* are what the
ledger records, the choice of agent/provider never appears in the audit trail.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class ToolCall:
    name: str
    arguments: dict


# -- provider parsers --------------------------------------------------- #
def _loads(arguments) -> dict:
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        try:
            return json.loads(arguments) if arguments.strip() else {}
        except json.JSONDecodeError:
            return {"_raw": arguments}
    return {}


def parse_openai(call: dict) -> ToolCall:
    """OpenAI / DeepSeek chat tool call: ``{"function": {"name", "arguments"}}``
    or the function object directly."""
    fn = call.get("function", call)
    return ToolCall(name=fn.get("name", ""), arguments=_loads(fn.get("arguments", {})))


def parse_deepseek(call: dict) -> ToolCall:
    """DeepSeek uses the OpenAI-compatible schema."""
    return parse_openai(call)


def parse_anthropic(call: dict) -> ToolCall:
    """Anthropic ``tool_use`` block: ``{"type":"tool_use","name","input"}``."""
    return ToolCall(name=call.get("name", ""), arguments=_loads(call.get("input", {})))


PARSERS: Dict[str, Callable[[dict], ToolCall]] = {
    "openai": parse_openai,
    "deepseek": parse_deepseek,
    "anthropic": parse_anthropic,
}


# -- capability mapping ------------------------------------------------- #
@dataclass
class AdapterConfig:
    """Declarative tool-capability table.

    capabilities : tool name -> list of event tags it raises (e.g. ``["read"]``).
    scope_allowlist : tools the agent is authorised to use; a call outside it
        clears ``within_scope``.
    external_recipient_keys : argument keys whose value, if it names an external
        destination, raises ``export`` / ``target_external``.
    internal_domains : substrings marking an internal (non-export) destination.
    arg_rules : optional custom hook ``(ToolCall) -> {event: bool}`` for
        deployment-specific events.
    """
    capabilities: Dict[str, List[str]] = field(default_factory=dict)
    scope_allowlist: List[str] = field(default_factory=list)
    external_recipient_keys: List[str] = field(default_factory=lambda: ["to", "recipient", "url", "dest", "address"])
    internal_domains: List[str] = field(default_factory=lambda: ["internal", "localhost", "127.0.0.1"])
    arg_rules: Optional[Callable[[ToolCall], Dict[str, bool]]] = None


class ToolCallAdapter:
    """Normalise any provider's tool call into a canonical event dict."""

    def __init__(self, config: AdapterConfig):
        self.config = config

    def parse(self, call: dict, provider: str = "openai") -> ToolCall:
        parser = PARSERS.get(provider)
        if parser is None:
            raise ValueError(f"unknown provider '{provider}' (have {list(PARSERS)})")
        return parser(call)

    def to_events(self, tc: ToolCall) -> Dict[str, bool]:
        caps = self.config.capabilities.get(tc.name, [])
        events: Dict[str, bool] = {}
        # static capability tags map straight to events; ``export`` is derived
        # below from the recipient (data leaving the trust boundary), so a tool
        # may be *capable* of egress yet not raise ``export`` for an internal one.
        for tag in caps:
            if tag != "export":
                events[tag] = True
        # scope
        events["within_scope"] = (not self.config.scope_allowlist) or (tc.name in self.config.scope_allowlist)
        # external recipient detection
        external = False
        has_recipient = False
        for k in self.config.external_recipient_keys:
            if k in tc.arguments:
                has_recipient = True
                # A recipient may be a single address or a list of them (a common
                # provider shape for ``to``/``cc``).  Evaluate each address on its
                # own: ``external`` fires if ANY recipient is outside the trust
                # boundary, so mixing one internal-looking address into a list can
                # no longer mask a genuinely external one.  ``None``/whitespace is
                # normalised to empty (no real destination), matching ``""``.
                raw = tc.arguments[k]
                vals = raw if isinstance(raw, (list, tuple)) else [raw]
                for item in vals:
                    s = "" if item is None else str(item).strip().lower()
                    if s and not any(d in s for d in self.config.internal_domains):
                        external = True
        if external:
            events["target_external"] = True
        # ``export`` fires iff an egress-capable tool sends data outside: either to
        # an external recipient, or with no recipient field at all (unconditional
        # egress such as a broadcast/upload).
        if "export" in caps and (external or not has_recipient):
            events["export"] = True
        if self.config.arg_rules is not None:
            for k, v in self.config.arg_rules(tc).items():
                events[k] = bool(v)
        return events

    def step_events(self, call: dict, provider: str = "openai") -> Dict[str, bool]:
        return self.to_events(self.parse(call, provider))
