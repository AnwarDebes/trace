"""Cross-check: a ledger written by the browser port must pass TRACE's own
Python verifier, and an edited copy must fail it at the edited entry.
Run after `npm test` (which writes tests/out/bundle.json)."""
import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tracekit.ledger import verify_ledger, SessionCertificate  # noqa: E402

bundle = json.loads((pathlib.Path(__file__).parent / "out" / "bundle.json").read_text())
cert = SessionCertificate(**bundle["certificate"])
ok, info = verify_ledger(bundle["ledger"], cert, key=b"demo-session-key")
assert ok, info
edited = copy.deepcopy(bundle["ledger"])
target = next(e for e in edited["entries"] if e["kind"] == "behavior" and e["payload"]["events"].get("export"))
target["payload"]["events"]["export"] = 0
bad, info2 = verify_ledger(edited, cert, key=b"demo-session-key")
assert not bad and info2["first_bad_entry"] == target["index"], info2
print(f"python verify_ledger: browser ledger of {len(bundle['ledger']['entries'])} entries passes; edit at entry {target['index']} caught")
