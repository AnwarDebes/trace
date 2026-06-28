import copy
import numpy as np
from tracekit import (Policy, always, bounded_count, TRACEEngine, verify_ledger,
                      merkle_root, CertificateLedger)

KEY = b"unit-test-key"
POL = Policy("p", [always("within_scope"), bounded_count("export", 2, 50)])


def _session():
    eng = TRACEEngine("s", POL, key=KEY)
    for t in range(8):
        eng.observe_events({"within_scope": True, "export": t < 4})  # 4 exports -> violation
    cert = eng.seal()
    return eng, cert


def test_clean_session_verifies():
    eng, cert = _session()
    ok, info = verify_ledger(eng.ledger.to_dict(), cert, key=KEY)
    assert ok and info["chain_ok"] and info["merkle_ok"] and info["behavior_ok"]


def test_violation_recorded():
    eng, cert = _session()
    assert not cert.behavior_verdict["session_ok"]


def test_tamper_event_detected():
    eng, cert = _session()
    led = copy.deepcopy(eng.ledger.to_dict())
    for e in led["entries"]:
        if e["kind"] == "behavior":
            k = next(iter(e["payload"]["events"]))
            e["payload"]["events"][k] ^= 1
            break
    ok, info = verify_ledger(led, cert, key=KEY)
    assert not ok


def test_delete_entry_detected():
    eng, cert = _session()
    led = copy.deepcopy(eng.ledger.to_dict())
    del led["entries"][2]
    ok, _ = verify_ledger(led, cert, key=KEY)
    assert not ok


def test_reorder_detected():
    eng, cert = _session()
    led = copy.deepcopy(eng.ledger.to_dict())
    led["entries"][1], led["entries"][2] = led["entries"][2], led["entries"][1]
    ok, _ = verify_ledger(led, cert, key=KEY)
    assert not ok


def test_forged_signature_detected():
    eng, cert = _session()
    led = copy.deepcopy(eng.ledger.to_dict())
    led["entries"][0]["payload"]["margin"] = 999
    led["entries"][0]["signature"] = "0" * 64
    ok, _ = verify_ledger(led, cert, key=KEY)
    assert not ok


def test_wrong_key_fails_signature():
    eng, cert = _session()
    ok, info = verify_ledger(eng.ledger.to_dict(), cert, key=b"wrong-key")
    assert not ok and not info["sig_ok"]


def test_merkle_root_changes_with_data():
    r1 = merkle_root(["a" * 64, "b" * 64])
    r2 = merkle_root(["a" * 64, "c" * 64])
    assert r1 != r2


def test_enforce_mode_blocks_violation_step():
    eng = TRACEEngine("s", POL, key=KEY, mode="enforce")
    sv = None
    for t in range(5):
        sv = eng.observe_events({"within_scope": True, "export": True})
    assert not eng.allow_step(sv)


def test_content_entry_receipt_replays():
    eng = TRACEEngine("s", POL, key=KEY)
    lits = np.array([1, 0, 1, 1, 0, 0], dtype=np.int8)
    eng.ledger.append_content("hello", label=1, margin=3, fired={0: (lits == 1)}, literals=lits)
    eng._content_total += 1
    cert = eng.seal()
    ok, info = verify_ledger(eng.ledger.to_dict(), cert, key=KEY)
    assert ok and info["content_ok"]
