"""Tamper-evident certificate ledger for agent sessions.

Every decision TRACE makes (a content verdict, a behaviour step) is appended
to a hash-chained, HMAC-signed ledger.  The construction follows the
tamper-evident logging line of work (Schneier & Kelsey, 1999; Crosby & Wallach,
2009) and Certificate Transparency (RFC 6962):

    entry_hash[i] = SHA256( entry_hash[i-1] || canonical(payload[i]) )
    signature[i]  = HMAC-SHA256( key, entry_hash[i] )

and the whole session is summarised by a binary Merkle root over the entry
hashes, signed once.  The resulting :class:`SessionCertificate` is small,
self-contained, and, crucially, **independently verifiable without the
model**: an auditor holding the shared secret key (HMAC is symmetric, so the
verification key *is* the signing key: this gives authentication, not
non-repudiation) can

  1. recompute the hash chain and detect any modified / inserted / deleted /
     reordered entry (the chain or the Merkle root breaks);
  2. re-evaluate every content CNF receipt (AND of included literal values);
  3. replay the recorded event stream through the policy monitors and confirm
     the recorded verdict matches.

Because each receipt is self-contained and signed, *later* online updates to the
guard cannot retroactively invalidate a sealed certificate.  This is the bridge
from a one-shot decision to a verifiable session-level audit trail required by,
e.g., EU AI Act Article 12 (record-keeping) and Article 26 (deployer logs).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from .policy import Policy
from .behavior_guard import BehaviorGuard

GENESIS = "0" * 64


# ---------------------------------------------------------------------- #
# primitives
# ---------------------------------------------------------------------- #
def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def merkle_root(leaf_hashes: List[str]) -> str:
    """Binary Merkle root over hex leaf hashes (duplicate-last padding)."""
    if not leaf_hashes:
        return GENESIS
    level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def cnf_receipt(clause_id: int, includes: List[int], values: List[int]) -> dict:
    """A minimal CNF certificate that ``clause_id`` output equals the AND of its
    included literal values.  ``includes`` and ``values`` are aligned."""
    out = 1
    for v in values:
        if not v:
            out = 0
            break
    dimacs = "\n".join([f"p cnf {len(includes)} {len(includes)}"] +
                       [f"{i + 1} 0" for i in includes])
    return {"clause_id": int(clause_id), "includes": [int(i) for i in includes],
            "values": [int(v) for v in values], "output": out, "cnf": dimacs}


# ---------------------------------------------------------------------- #
# ledger entries
# ---------------------------------------------------------------------- #
@dataclass
class LedgerEntry:
    index: int
    kind: str                       # "content" | "behavior"
    payload: dict                   # canonical, model-free content of the decision
    prev_hash: str = GENESIS
    entry_hash: str = ""
    signature: Optional[str] = None

    def compute_hash(self, prev_hash: str) -> str:
        self.prev_hash = prev_hash
        body = {"index": self.index, "kind": self.kind,
                "payload": self.payload, "prev_hash": prev_hash}
        self.entry_hash = sha256_hex(canonical(body))
        return self.entry_hash

    def sign(self, key: bytes) -> "LedgerEntry":
        self.signature = hmac_hex(key, self.entry_hash.encode())
        return self


@dataclass
class SessionCertificate:
    session_id: str
    policy: dict
    n_entries: int
    chain_head: str                 # last entry_hash
    merkle_root: str
    behavior_verdict: dict
    content_summary: dict
    signature: Optional[str] = None

    def _root_body(self) -> dict:
        return {"session_id": self.session_id, "policy": self.policy,
                "n_entries": self.n_entries, "chain_head": self.chain_head,
                "merkle_root": self.merkle_root,
                "behavior_verdict": self.behavior_verdict,
                "content_summary": self.content_summary}

    def sign(self, key: bytes) -> "SessionCertificate":
        self.signature = hmac_hex(key, canonical(self._root_body()))
        return self

    def verify_signature(self, key: bytes) -> bool:
        if self.signature is None:
            return False
        return hmac.compare_digest(self.signature,
                                   hmac_hex(key, canonical(self._root_body())))


# ---------------------------------------------------------------------- #
# the ledger
# ---------------------------------------------------------------------- #
class CertificateLedger:
    """Append-only, hash-chained ledger for one agent session."""

    def __init__(self, session_id: str, policy: Policy, key: Optional[bytes] = None):
        self.session_id = session_id
        self.policy = policy
        self.key = key
        self.entries: List[LedgerEntry] = []
        self._head = GENESIS

    def _append(self, kind: str, payload: dict) -> LedgerEntry:
        e = LedgerEntry(index=len(self.entries), kind=kind, payload=payload)
        e.compute_hash(self._head)
        if self.key is not None:
            e.sign(self.key)
        self.entries.append(e)
        self._head = e.entry_hash
        return e

    def append_content(self, text: str, label: int, margin: int,
                       fired: Dict[int, "object"], literals) -> LedgerEntry:
        """Record a content-guard decision with CNF receipts for fired clauses."""
        lits = [int(v) for v in literals]
        receipts = []
        for cid, mask in fired.items():
            idx = [int(i) for i in range(len(mask)) if mask[i]]
            receipts.append(cnf_receipt(cid, idx, [lits[i] for i in idx]))
        payload = {"text_sha256": sha256_hex(text.encode("utf-8", "replace")),
                   "label": int(label), "margin": int(margin),
                   "receipts": receipts}
        return self._append("content", payload)

    def append_behavior(self, step: int, events: Dict[str, bool],
                        violated_now: List[str]) -> LedgerEntry:
        payload = {"step": int(step),
                   "events": {k: int(bool(v)) for k, v in sorted(events.items())},
                   "violated_now": sorted(violated_now)}
        return self._append("behavior", payload)

    def seal(self, behavior_verdict: dict, content_summary: dict) -> SessionCertificate:
        root = merkle_root([e.entry_hash for e in self.entries])
        cert = SessionCertificate(
            session_id=self.session_id,
            policy=self.policy.to_dict(),
            n_entries=len(self.entries),
            chain_head=self._head,
            merkle_root=root,
            behavior_verdict=behavior_verdict,
            content_summary=content_summary,
        )
        if self.key is not None:
            cert.sign(self.key)
        return cert

    def to_dict(self) -> dict:
        return {"session_id": self.session_id, "policy": self.policy.to_dict(),
                "entries": [asdict(e) for e in self.entries]}

    @staticmethod
    def entries_from_dict(d: dict) -> List[LedgerEntry]:
        return [LedgerEntry(**e) for e in d["entries"]]


# ---------------------------------------------------------------------- #
# independent verification
# ---------------------------------------------------------------------- #
def verify_ledger(ledger_dict: dict, cert: SessionCertificate,
                  key: Optional[bytes] = None) -> Tuple[bool, dict]:
    """Re-verify a sealed ledger from scratch, model-free.

    Returns (ok, info).  ``info`` reports which checks passed and pinpoints the
    first failing entry, so tampering is not just detected but localised.
    """
    entries = CertificateLedger.entries_from_dict(ledger_dict)
    info: dict = {"chain_ok": True, "sig_ok": True, "merkle_ok": True,
                  "content_ok": True, "behavior_ok": True,
                  "first_bad_entry": None, "notes": []}

    # 1. hash chain + signatures
    prev = GENESIS
    for e in entries:
        body = {"index": e.index, "kind": e.kind, "payload": e.payload, "prev_hash": prev}
        recomputed = sha256_hex(canonical(body))
        if recomputed != e.entry_hash or e.prev_hash != prev:
            info["chain_ok"] = False
            info["first_bad_entry"] = e.index
            info["notes"].append(f"hash/chain mismatch at entry {e.index}")
            break
        if key is not None:
            if e.signature != hmac_hex(key, e.entry_hash.encode()):
                info["sig_ok"] = False
                info["first_bad_entry"] = e.index
                info["notes"].append(f"bad signature at entry {e.index}")
                break
        prev = e.entry_hash

    # 2. Merkle root + chain head
    root = merkle_root([e.entry_hash for e in entries])
    if root != cert.merkle_root:
        info["merkle_ok"] = False
        info["notes"].append("merkle root mismatch")
    if entries and entries[-1].entry_hash != cert.chain_head:
        info["chain_ok"] = False
        info["notes"].append("chain head mismatch")
    if key is not None and not cert.verify_signature(key):
        info["sig_ok"] = False
        info["notes"].append("session certificate signature invalid")

    # 3. content CNF receipts replay
    for e in entries:
        if e.kind != "content":
            continue
        for r in e.payload.get("receipts", []):
            out = 1
            for v in r["values"]:
                if not v:
                    out = 0
                    break
            if out != r["output"]:
                info["content_ok"] = False
                info["notes"].append(f"content receipt replay mismatch at entry {e.index}")
                break

    # 4. behaviour monitor replay (model-free)
    policy = Policy.from_dict(cert.policy)
    guard = BehaviorGuard(policy)
    for e in entries:
        if e.kind != "behavior":
            continue
        events = {k: bool(v) for k, v in e.payload["events"].items()}
        sv = guard.step(events)
        recorded = set(e.payload.get("violated_now", []))
        if set(sv.violated_now) != recorded:
            info["behavior_ok"] = False
            info["notes"].append(f"behaviour replay mismatch at step {e.payload['step']}")
            break
    if guard.session_ok != cert.behavior_verdict.get("session_ok", guard.session_ok):
        info["behavior_ok"] = False
        info["notes"].append("session behaviour verdict mismatch")

    ok = all(info[k] for k in ("chain_ok", "sig_ok", "merkle_ok",
                               "content_ok", "behavior_ok"))
    info["ok"] = ok
    return ok, info
