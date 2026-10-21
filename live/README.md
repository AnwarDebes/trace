# TRACE live

A simulated agent session under TRACE, in the browser: the content guard, the
temporal monitors and the certificate ledger, ported to JavaScript from `tracekit`
and run against scripted tool calls in three providers' wire formats.

**Open it:** https://anwardebes.github.io/trace/

## What runs where

| File | Ported from | Role |
|---|---|---|
| `guard.js` | `content_guard.py`, `tm.py` | The content guard: 200 clauses over 256 word features, inference only |
| `ltl.js` | `ltl.py`, `policy.py`, `behavior_guard.py` | Always, Never, BoundedCount, Response and Precedence monitors with constant memory |
| `engine.js` | `adapters.py`, `engine.py` | Provider wire formats to events, and the engine that wires guard, monitors and ledger together |
| `ledger.js`, `crypto.js` | `ledger.py` | Hash chain, HMAC-SHA256 signatures, Merkle root, certificate and the model-free verifier |
| `scenarios.js` | `demo/quickstart.py` | The policy, the capability table and the five sessions |
| `app.js`, `app.css`, `index.html` | | The page |

The guard model, `trace-model.json`, was trained with `tracekit` on the train split
of deepset/prompt-injections (84% accuracy on its test split).

## The ledger is the real format

`crypto.js` reproduces Python's canonical JSON (`json.dumps(sort_keys=True,
separators=(",", ":"))`, ASCII escaping included), so a session downloaded from the
page verifies with the Python package:

```bash
python -c "import json; from tracekit.ledger import verify_ledger, SessionCertificate as C; \
b=json.load(open('trace-session.json')); print(verify_ledger(b['ledger'], C(**b['certificate']), key=b'demo-session-key')[0])"
```

## Tests

```bash
cd live && npm test                  # monitor semantics, the five sessions, ledger and tamper checks
python tests/crosscheck.py           # the JavaScript ledger passes tracekit's verify_ledger
```

CI runs both before every deployment.

## Scope

The agent is scripted; the guard, monitors and ledger that judge it are not. The
HMAC key is shared and shown on the page, so a certificate proves integrity to
whoever holds the key, not who wrote it (the paper discusses the Ed25519 upgrade).
