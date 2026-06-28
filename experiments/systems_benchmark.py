"""Experiment E5: Systems characterisation on a CPU.

Measures, on the host CPU (disclosed), the deployment cost of TRACE:

  * content-guard single-sample latency vs clause budget (and the resulting
    model size and test F1), the accuracy / latency / footprint trade-off;
  * behaviour-guard per-step update latency and monitor memory;
  * certificate-ledger append latency and verification latency vs #entries;
  * throughput (decisions / second) and an explicitly-labelled ENERGY PROXY.

The energy proxy is latency x an *assumed* CPU power; it is an order-of-
magnitude figure, not a measurement (no RAPL / Power-Gadget access here).  The
measured endpoint of the TM hardware story is the 8.6 nJ/frame 65 nm ASIC of
Tunheim et al. (2025), reported in the paper for context.
"""

from __future__ import annotations

import sys
import time
import numpy as np

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from tracekit import (ContentGuard, ContentGuardConfig, Policy, always,
                      bounded_count, response, precedence, BehaviorGuard,
                      TRACEEngine, verify_ledger)
from experiments._common import load_dataset, summarize, prf1, write_results, host_info

ASSUMED_CPU_WATTS = 15.0          # i7-1165G7 PL1 base power; proxy only


def _latency_us(fn, samples, repeats=5):
    ts = []
    for _ in range(repeats):
        for s in samples:
            t0 = time.perf_counter()
            fn(s)
            ts.append((time.perf_counter() - t0) * 1e6)
    ts = np.array(ts)
    return {"median_us": float(np.median(ts)), "p99_us": float(np.percentile(ts, 99)),
            "mean_us": float(ts.mean()), "n": len(ts)}


def content_sweep(data, budgets=(100, 200, 400, 800), seed=0):
    rows = []
    Xtr, ytr = data["train"]; Xte, yte = data["test"]
    for C in budgets:
        cg = ContentGuard(ContentGuardConfig(n_clauses=C, threshold=25, s=5.0,
                                             max_features=256, epochs=25, seed=seed))
        cg.fit(Xtr, ytr)
        f1 = prf1(yte, cg.predict(Xte))["f1"]
        lat = _latency_us(lambda t: cg.verdict(t), Xte[:40])
        bits = cg.tm.bank.n_clauses * cg.tm.bank.n_literals
        e_uj = lat["median_us"] * 1e-6 * ASSUMED_CPU_WATTS * 1e6   # micro-Joules
        rows.append({"n_clauses": C, "test_f1": f1, "latency": lat,
                     "model_kb": bits / 8 / 1024, "throughput_per_s": 1e6 / lat["median_us"],
                     "energy_proxy_uJ": e_uj})
        print(f"  clauses={C:4d} F1={f1:.3f} lat={lat['median_us']:.1f}us "
              f"size={bits/8/1024:.1f}KB thru={1e6/lat['median_us']:.0f}/s")
    return rows


def behavior_latency():
    pol = Policy("full", [always("within_scope"), bounded_count("export", 2, 50),
                          response("sensitive_read", "audit_log", 3),
                          precedence("authorize", "transfer")])
    g = BehaviorGuard(pol)
    rng = np.random.default_rng(0)
    evs = [{"within_scope": True, "read": bool(rng.random() < .4),
            "export": bool(rng.random() < .05), "sensitive_read": bool(rng.random() < .1),
            "audit_log": bool(rng.random() < .1), "authorize": bool(rng.random() < .05),
            "transfer": bool(rng.random() < .05)} for _ in range(2000)]
    i = {"n": 0}
    def stepfn(_):
        g.step(evs[i["n"] % len(evs)]); i["n"] += 1
    lat = _latency_us(stepfn, range(2000), repeats=1)
    return {"latency": lat, "monitor_memory_bytes": g.memory_bytes,
            "throughput_per_s": 1e6 / lat["median_us"],
            "energy_proxy_uJ": lat["median_us"] * 1e-6 * ASSUMED_CPU_WATTS * 1e6}


def ledger_scaling(sizes=(50, 100, 200, 400, 800)):
    pol = Policy("full", [always("within_scope"), bounded_count("export", 2, 100)])
    KEY = b"sys-bench-key"
    rows = []
    rng = np.random.default_rng(1)
    for n in sizes:
        eng = TRACEEngine(f"s{n}", pol, key=KEY)
        t0 = time.perf_counter()
        for _ in range(n):
            eng.observe_events({"within_scope": True, "export": bool(rng.random() < 0.02)})
        append_us = (time.perf_counter() - t0) / n * 1e6
        bundle = {"ledger": eng.ledger.to_dict(), "certificate": eng.seal()}
        t1 = time.perf_counter()
        ok, _ = verify_ledger(bundle["ledger"], bundle["certificate"], key=KEY)
        verify_us = (time.perf_counter() - t1) * 1e6
        import json as _json
        nbytes = len(_json.dumps(bundle["ledger"]).encode())
        rows.append({"n_entries": n, "append_us_per_entry": append_us,
                     "verify_total_us": verify_us, "verify_us_per_entry": verify_us / n,
                     "bytes_per_entry": nbytes / n, "verify_ok": bool(ok)})
        print(f"  ledger n={n:4d} append={append_us:.1f}us/e verify={verify_us:.0f}us "
              f"({verify_us/n:.1f}us/e) {nbytes/n:.0f}B/e")
    return rows


def main(quick=False):
    out = {"host": host_info(), "assumed_cpu_watts": ASSUMED_CPU_WATTS,
           "note_energy": "energy_proxy = latency * assumed_cpu_watts; ORDER-OF-MAGNITUDE proxy, not measured"}
    data = load_dataset("prompt_injection")
    print("content sweep:")
    out["content_sweep"] = content_sweep(data, budgets=(100, 200) if quick else (100, 200, 400, 800))
    print("behaviour latency:")
    out["behavior"] = behavior_latency()
    print(f"  step median {out['behavior']['latency']['median_us']:.2f}us "
          f"mem {out['behavior']['monitor_memory_bytes']}B")
    print("ledger scaling:")
    out["ledger_scaling"] = ledger_scaling(sizes=(50, 100) if quick else (50, 100, 200, 400, 800))
    write_results("systems_benchmark", out)
    return out


if __name__ == "__main__":
    main(quick="--quick" in sys.argv)
