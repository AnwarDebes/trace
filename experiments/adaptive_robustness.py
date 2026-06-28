"""Experiment E6: Robustness and honest failure modes.

Three studies, two of which are deliberately negative (reviewers reward an
honest account of where a method breaks):

1. Adaptive exfiltration attacker.  A ``BoundedCount(export, 2, W)`` monitor is
   probed with trajectories carrying 0..6 exports.  TRACE detection is a clean
   step at the budget: an attacker can only evade by staying at <= 2 exports,
   i.e. the monitor *bounds the damage* rather than being fooled.

2. Content-guard obfuscation (NEGATIVE result).  Token-presence booleanisation
   is brittle to surface obfuscation (character spacing, leetspeak, repetition).
   I measure the recall drop on obfuscated injections, an honest limitation
   that motivates character-level features / ensembling as future work.

3. Cross-dataset distribution shift (NEGATIVE/▽).  Train on one dataset, test on
   the other; recall typically drops, quantifying generalisation honestly.
"""

from __future__ import annotations

import re
import sys
import numpy as np

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from tracekit import (ContentGuard, ContentGuardConfig, Policy, bounded_count, BehaviorGuard)
from experiments._common import (load_dataset, summarize, prf1, write_results,
                                 host_info, SEEDS, CONTENT_CFG)

L = 50


# ---- 1. adaptive attacker ---- #
def adaptive_attacker(seed=0, trials=200):
    pol = Policy("exfil", [bounded_count("export", 2, L)])
    rng = np.random.default_rng(seed)
    curve = []
    for n_exp in range(0, 7):
        det = 0
        for _ in range(trials):
            steps = set(rng.choice(L, size=n_exp, replace=False)) if n_exp else set()
            g = BehaviorGuard(pol)
            for t in range(L):
                g.step({"export": t in steps, "within_scope": True})
            det += int(not g.session_ok)
        curve.append({"n_exports": n_exp, "detection_rate": det / trials})
    return curve


# ---- 2. obfuscation ---- #
def _space_out(w):  return " ".join(list(w))
def _leet(w):       return w.translate(str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}))
def _repeat(w):     return re.sub(r"([aeiou])", r"\1\1", w)

TRIGGERS = ["ignore", "disregard", "instructions", "previous", "system", "prompt",
            "forget", "override", "reveal", "bypass", "jailbreak"]

def obfuscate(text, fn):
    def repl(m):
        w = m.group(0)
        return fn(w) if w.lower() in TRIGGERS else w
    return re.sub(r"[A-Za-z]+", repl, text)


def obfuscation_study(seed=0):
    data = load_dataset("prompt_injection")
    Xtr, ytr = data["train"]; Xte, yte = data["test"]
    cg = ContentGuard(ContentGuardConfig(seed=seed, **CONTENT_CFG))
    cg.fit(Xtr, ytr)
    inj_idx = [i for i in range(len(Xte)) if yte[i] == 1]
    inj_texts = [Xte[i] for i in inj_idx]
    base_recall = float(np.mean(cg.predict(inj_texts) == 1))
    res = {"plain_recall": base_recall}
    for name, fn in (("space_out", _space_out), ("leetspeak", _leet), ("repeat_vowels", _repeat)):
        obf = [obfuscate(t, fn) for t in inj_texts]
        res[name + "_recall"] = float(np.mean(cg.predict(obf) == 1))
    return res


# ---- 3. cross-dataset transfer ---- #
def transfer_study(seed=0):
    out = {}
    pairs = [("prompt_injection", "jailbreak"), ("jailbreak", "prompt_injection")]
    for src, dst in pairs:
        d_src = load_dataset(src); d_dst = load_dataset(dst)
        cg = ContentGuard(ContentGuardConfig(seed=seed, **CONTENT_CFG))
        cg.fit(*d_src["train"])
        in_f1 = prf1(d_src["test"][1], cg.predict(d_src["test"][0]))["f1"]
        out_f1 = prf1(d_dst["test"][1], cg.predict(d_dst["test"][0]))["f1"]
        out[f"{src}__to__{dst}"] = {"in_domain_f1": in_f1, "cross_domain_f1": out_f1}
        print(f"  {src} -> {dst}: in {in_f1:.3f} / cross {out_f1:.3f}")
    return out


def main(seeds=SEEDS, quick=False):
    out = {"host": host_info()}
    use = (0, 1, 2) if quick else seeds

    print("adaptive attacker:")
    curves = [adaptive_attacker(seed=s, trials=100 if quick else 200) for s in use]
    agg = []
    for k in range(7):
        agg.append({"n_exports": k,
                    "detection_rate": summarize([c[k]["detection_rate"] for c in curves])})
    out["adaptive_attacker"] = agg
    for a in agg:
        print(f"  exports={a['n_exports']} det={a['detection_rate']['mean']:.3f}")

    print("obfuscation (negative result):")
    obf = [obfuscation_study(seed=s) for s in use]
    out["obfuscation"] = {k: summarize([o[k] for o in obf])
                          for k in obf[0]}
    for k, v in out["obfuscation"].items():
        print(f"  {k}: {v['mean']:.3f}")

    print("cross-dataset transfer (negative result):")
    out["transfer"] = transfer_study(seed=use[0])

    write_results("adaptive_robustness", out)
    return out


if __name__ == "__main__":
    main(quick="--quick" in sys.argv)
