"""TRACE: Tsetlin Runtime Assurance & Certification Engine.

A certifying runtime guardrail for agentic AI: an interpretable, CPU-only,
sub-millisecond monitor that emits tamper-evident, independently-verifiable
certificates over an agent's inputs and its trajectory of tool calls.

Built on the Echo-Trace Tsetlin Automaton (ETTA) primitive from THGTM
(Debes, 2026).
"""

from .automata import ETTABank, EchoTraceAutomaton
from .tm import TsetlinMachine, TMConfig, to_literals
from .booleanize import BooleanVocabulizer, tokenize
from .content_guard import ContentGuard, ContentGuardConfig, ContentVerdict
from .ltl import (
    Monitor, Always, Never, BoundedCount, Response, Precedence, Violation,
)
from .policy import Policy, always, never, bounded_count, response, precedence
from .behavior_guard import BehaviorGuard, StepVerdict
from .adapters import (
    ToolCall, ToolCallAdapter, AdapterConfig,
    parse_openai, parse_anthropic, parse_deepseek,
)
from .ledger import (
    CertificateLedger, LedgerEntry, SessionCertificate,
    verify_ledger, merkle_root, cnf_receipt, canonical, sha256_hex, hmac_hex,
)
from .engine import TRACEEngine, InputDecision

__version__ = "1.1.0"

__all__ = [
    "ETTABank", "EchoTraceAutomaton",
    "TsetlinMachine", "TMConfig", "to_literals",
    "BooleanVocabulizer", "tokenize",
    "ContentGuard", "ContentGuardConfig", "ContentVerdict",
    "Monitor", "Always", "Never", "BoundedCount", "Response", "Precedence", "Violation",
    "Policy", "always", "never", "bounded_count", "response", "precedence",
    "BehaviorGuard", "StepVerdict",
    "ToolCall", "ToolCallAdapter", "AdapterConfig",
    "parse_openai", "parse_anthropic", "parse_deepseek",
    "CertificateLedger", "LedgerEntry", "SessionCertificate",
    "verify_ledger", "merkle_root", "cnf_receipt", "canonical", "sha256_hex", "hmac_hex",
    "TRACEEngine", "InputDecision",
]
