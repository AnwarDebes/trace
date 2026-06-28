"""Experiment E3: Component ablation.

A reviewer needs to see that each TRACE component earns its place rather than
the whole system winning for unclear reasons.  I build composite agent sessions
whose threats arrive on two independent channels:

  content channel  : the user input is benign or a prompt injection
                     (drawn from the real deepset/prompt-injections test set);
  behaviour channel: the tool-call trajectory is benign or a slow-roll
                     exfiltration.

There are four session types (benign/benign, inject/benign, benign/exfil,
inject/exfil).  I compare three configurations:

  content-only  : flag the session iff the content guard flags the input;
  behaviour-only: flag the session iff the LTL monitor flags the trajectory;
  TRACE (both)  : flag iff either fires.

The expectation (and the point of the ablation) is that each single channel
is blind to the other's attack, while the combination covers both.  12 seeds;
mean +/- std per cell and overall.
"""

from __future__ import annotations

import sys
import numpy as np

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from tracekit import (ContentGuard, ContentGuardConfig, Policy, bounded_count, BehaviorGuard)
from experiments._common import (load_dataset, summarize, write_results, host_info,
                                 SEEDS, CONTENT_CFG)

L = 50
N_PER_CELL = 60


def gen_traj(rng, exfil):
    n = rng.integers(3, 6) if exfil else rng.integers(0, 3)
    steps = set(rng.choice(L, size=int(n), replace=False)) if n else set()
    return [{"export": t in steps, "within_scope": True} for t in range(L)]


def behavior_flag(pol, traj):
    g = BehaviorGuard(pol)
    for s in traj:
        g.step(s)
    return not g.session_ok


def run_seed(seed, data):
    Xtr, ytr = data["train"]; Xte, yte = data["test"]
    cg = ContentGuard(ContentGuardConfig(seed=seed, **CONTENT_CFG))
    cg.fit(Xtr, ytr)
    pol = Policy("exfil", [bounded_count("export", 2, L)])
    rng = np.random.default_rng(5000 + seed)

    inj_pool = [Xte[i] for i in range(len(Xte)) if yte[i] == 1]
    ben_pool = [Xte[i] for i in range(len(Xte)) if yte[i] == 0]

    def pick(pool):
        return pool[int(rng.integers(0, len(pool)))]

    cells = {"benign_benign": (False, False), "inject_benign": (True, False),
             "benign_exfil": (False, True), "inject_exfil": (True, True)}
    config_flags = {c: {"content_only": [], "behavior_only": [], "trace": []} for c in cells}

    for cell, (inj, exfil) in cells.items():
        for _ in range(N_PER_CELL):
            text = pick(inj_pool if inj else ben_pool)
            traj = gen_traj(rng, exfil)
            c_flag = cg.verdict(text).unsafe
            b_flag = behavior_flag(pol, traj)
            config_flags[cell]["content_only"].append(int(c_flag))
            config_flags[cell]["behavior_only"].append(int(b_flag))
            config_flags[cell]["trace"].append(int(c_flag or b_flag))
    return config_flags


def main(seeds=SEEDS):
    data = load_dataset("prompt_injection")
    cells = ["benign_benign", "inject_benign", "benign_exfil", "inject_exfil"]
    configs = ["content_only", "behavior_only", "trace"]
    acc = {c: {cfg: [] for cfg in configs} for c in cells}

    for seed in seeds:
        cf = run_seed(seed, data)
        for c in cells:
            for cfg in configs:
                # detection rate for attack cells; false-positive rate for benign_benign
                acc[c][cfg].append(float(np.mean(cf[c][cfg])))
        print(f"seed {seed} done")

    out = {"host": host_info(), "seeds": list(seeds), "n_per_cell": N_PER_CELL,
           "cells": {}, "interpretation": {
               "benign_benign": "false-positive rate (lower better)",
               "inject_benign": "detection rate (content attack)",
               "benign_exfil": "detection rate (behaviour attack)",
               "inject_exfil": "detection rate (dual-channel attack)"}}
    for c in cells:
        out["cells"][c] = {cfg: summarize(acc[c][cfg]) for cfg in configs}
    # overall attack recall (across the three attack cells) and benign FPR
    attack_cells = ["inject_benign", "benign_exfil", "inject_exfil"]
    for cfg in configs:
        recalls = []
        for seed_i in range(len(seeds)):
            vals = [acc[c][cfg][seed_i] for c in attack_cells]
            recalls.append(float(np.mean(vals)))
        out.setdefault("overall_attack_recall", {})[cfg] = summarize(recalls)

    print("\n            content-only  behavior-only  TRACE")
    for c in cells:
        r = out["cells"][c]
        print(f"{c:16s} {r['content_only']['mean']:.3f}        "
              f"{r['behavior_only']['mean']:.3f}        {r['trace']['mean']:.3f}")
    print("overall recall:",
          {k: round(v['mean'], 3) for k, v in out["overall_attack_recall"].items()})
    write_results("ablation", out)
    return out


if __name__ == "__main__":
    main(seeds=(0, 1, 2) if "--quick" in sys.argv else SEEDS)
