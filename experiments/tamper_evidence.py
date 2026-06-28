"""Experiment E4: Tamper-evidence of the certificate ledger.

I seal realistic agent sessions, then apply each of six tamper operations many
times at random positions and check that independent verification
(:func:`tracekit.verify_ledger`, model-free, key-holding auditor) detects every
one and localises the first bad entry.

Precise security claim (stated exactly to avoid over-claiming): the ledger gives
**tamper-evidence** (any modification/insertion/deletion/reordering breaks the
SHA-256 hash chain and/or the Merkle root) and **symmetric authentication** via
HMAC-SHA-256 (RFC 2104).  HMAC is *repudiable*: any party holding the shared key
could have produced the log, so this is integrity + authentication, NOT
non-repudiation.  Non-repudiation is a drop-in upgrade: replace the HMAC over
the Merkle root with an asymmetric signature (e.g. Ed25519), which I do not
implement here to avoid a cryptographic dependency.  I measure verification
latency and its scaling in the number of entries.
"""

from __future__ import annotations

import copy
import sys
import time
import numpy as np

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from tracekit import (Policy, always, bounded_count, response, precedence,
                      TRACEEngine, verify_ledger)
from tracekit.ledger import canonical, sha256_hex, GENESIS
from experiments._common import summarize, write_results, host_info

KEY = b"trace-experiment-key-E4"
POLICY = Policy("full", [always("within_scope"),
                         bounded_count("export", 2, 50),
                         response("sensitive_read", "audit_log", 3),
                         precedence("authorize", "transfer")])
TAMPERS = ["modify_event", "modify_receipt_value", "modify_verdict",
           "delete_entry", "insert_entry", "reorder_entries"]


def build_session(rng) -> tuple:
    """A mixed session: a few content checks + a behaviour trajectory."""
    eng = TRACEEngine(f"sess-{int(rng.integers(1e9))}", POLICY, key=KEY)
    n_content = int(rng.integers(2, 5))
    for _ in range(n_content):
        # record content entries directly to exercise content CNF receipts
        lits = rng.integers(0, 2, size=16).astype(np.int8)
        fired = {0: (lits[:16] == 1)}
        eng.ledger.append_content(text="x" * int(rng.integers(5, 40)),
                                  label=int(lits[0]), margin=int(rng.integers(-5, 6)),
                                  fired=fired, literals=lits)
        eng._content_total += 1
    n_steps = int(rng.integers(20, 40))
    for t in range(n_steps):
        ev = {"within_scope": True, "read": bool(rng.random() < 0.4),
              "export": bool(rng.random() < 0.03),
              "sensitive_read": False, "audit_log": False,
              "authorize": False, "transfer": False}
        eng.observe_events(ev)
    cert = eng.seal()
    bundle = {"ledger": eng.ledger.to_dict(), "certificate": cert}
    return bundle


def apply_tamper(bundle, kind, rng) -> dict:
    led = copy.deepcopy(bundle["ledger"])
    entries = led["entries"]
    behavior_idx = [i for i, e in enumerate(entries) if e["kind"] == "behavior"]
    content_idx = [i for i, e in enumerate(entries) if e["kind"] == "content"]

    if kind == "modify_event" and behavior_idx:
        i = int(rng.choice(behavior_idx))
        ev = entries[i]["payload"]["events"]
        k = rng.choice(list(ev.keys()))
        ev[k] = 1 - ev[k]
    elif kind == "modify_receipt_value" and content_idx:
        i = int(rng.choice(content_idx))
        recs = entries[i]["payload"]["receipts"]
        if recs and recs[0]["values"]:
            recs[0]["values"][0] = 1 - recs[0]["values"][0]
        else:
            entries[i]["payload"]["label"] ^= 1
    elif kind == "modify_verdict" and behavior_idx:
        i = int(rng.choice(behavior_idx))
        entries[i]["payload"]["violated_now"] = ["always(within_scope)"]
    elif kind == "delete_entry" and len(entries) > 2:
        del entries[int(rng.integers(0, len(entries)))]
    elif kind == "insert_entry":
        i = int(rng.integers(0, len(entries)))
        forged = copy.deepcopy(entries[i])
        forged["payload"] = copy.deepcopy(entries[i]["payload"])
        entries.insert(i, forged)
    elif kind == "reorder_entries" and len(entries) > 3:
        i, j = sorted(rng.choice(len(entries), size=2, replace=False))
        entries[i], entries[j] = entries[j], entries[i]
    return led


def main(n_sessions=40):
    rng = np.random.default_rng(7)
    out = {"host": host_info(), "n_sessions": n_sessions, "tampers": {},
           "security_property": ("tamper-evidence (SHA-256 hash chain + Merkle root) "
                                 "+ symmetric authentication (HMAC-SHA-256, RFC 2104; "
                                 "repudiable, not non-repudiation)")}

    # 0. sanity: untampered logs always verify
    clean_ok = 0
    verify_times = []
    sizes = []
    for _ in range(n_sessions):
        b = build_session(rng)
        t0 = time.perf_counter()
        ok, info = verify_ledger(b["ledger"], b["certificate"], key=KEY)
        verify_times.append((time.perf_counter() - t0) * 1e6)
        sizes.append(len(b["ledger"]["entries"]))
        clean_ok += int(ok)
    out["clean_verify_rate"] = clean_ok / n_sessions
    out["verify_latency_us"] = summarize(verify_times)
    out["mean_entries_per_session"] = float(np.mean(sizes))
    out["bytes_per_entry_estimate"] = None

    # per-entry size estimate
    import json as _json
    b = build_session(rng)
    enc = _json.dumps(b["ledger"]).encode()
    out["bytes_per_entry_estimate"] = len(enc) / max(1, len(b["ledger"]["entries"]))

    # 1. tamper detection
    for kind in TAMPERS:
        detected = 0
        localised = 0          # detected AND attributed to an entry or structural cause
        entry_localised = 0    # strictly pinpointed to a specific first bad entry
        trials = 0
        for _ in range(n_sessions):
            b = build_session(rng)
            tampered = apply_tamper(b, kind, rng)
            if tampered == b["ledger"]:
                continue                                   # no-op (e.g. nothing to reorder)
            trials += 1
            ok, info = verify_ledger(tampered, b["certificate"], key=KEY)
            entry_hit = info.get("first_bad_entry") is not None
            # a structural failure (Merkle / chain head / replay) localises the
            # *cause* even when there is no single bad entry to point at, e.g.
            # deleting the tail leaves the forward chain valid but breaks the
            # Merkle root and chain head.
            structural = (not info["merkle_ok"] or not info["chain_ok"]
                          or not info["content_ok"] or not info["behavior_ok"])
            detected += int(not ok)
            localised += int(entry_hit or structural)
            entry_localised += int(entry_hit)
        out["tampers"][kind] = {"trials": trials,
                                "detection_rate": detected / max(1, trials),
                                "localised_rate": localised / max(1, trials),
                                "entry_localised_rate": entry_localised / max(1, trials)}
        print(f"{kind:22s} detection {detected}/{trials}")

    # 2. forged signature without the key (attacker cannot re-sign).  The attacker
    #    tampers a payload and recomputes a VALID entry hash (hashing is keyless),
    #    so the chain check passes for that entry and verification *reaches* the
    #    per-entry HMAC check, which fails on the forged signature.  This
    #    isolates "cannot re-sign" instead of letting the hash chain catch it.
    forged_detected = 0
    forged_by_sig = 0
    for _ in range(n_sessions):
        b = build_session(rng)
        led = copy.deepcopy(b["ledger"])
        if led["entries"]:
            i = int(rng.integers(0, len(led["entries"])))
            e = led["entries"][i]
            e["payload"]["label"] = 99                        # tamper the payload
            prev = led["entries"][i - 1]["entry_hash"] if i > 0 else GENESIS
            body = {"index": e["index"], "kind": e["kind"],
                    "payload": e["payload"], "prev_hash": prev}
            e["entry_hash"] = sha256_hex(canonical(body))     # valid hash...
            e["signature"] = "0" * 64                         # ...but forged HMAC
        ok, info = verify_ledger(led, b["certificate"], key=KEY)
        forged_detected += int(not ok)
        forged_by_sig += int(not ok and not info["sig_ok"])   # caught by the signature
    out["forged_signature_detection_rate"] = forged_detected / n_sessions
    out["forged_signature_caught_by_sig_rate"] = forged_by_sig / n_sessions
    print(f"forged-signature detection {forged_detected}/{n_sessions} "
          f"(signature-isolated {forged_by_sig}/{n_sessions})")

    write_results("tamper_evidence", out)
    return out


if __name__ == "__main__":
    main(n_sessions=20 if "--quick" in sys.argv else 40)
