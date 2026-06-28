"""Generate every paper figure from results/*.json.

Run after experiments/run_all.py.  Writes paper/figures/*.pdf and *.png.
Each figure is guarded so a missing result file is skipped, not fatal.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results"
FIG = ROOT / "paper" / "figures"
FIG.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({"font.size": 11, "axes.grid": True, "grid.alpha": 0.3,
                     "figure.dpi": 130, "savefig.bbox": "tight"})

TEAL, RED, GREY, AMBER = "#0d9488", "#dc2626", "#94a3b8", "#d97706"


def load(name):
    p = RES / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def save(fig, name):
    for ext in ("pdf", "png"):
        fig.savefig(FIG / f"{name}.{ext}")
    plt.close(fig)
    print(f"  figure {name}")


def fig_content_guard():
    d = load("content_guard")
    if not d:
        return
    datasets = list(d["datasets"])
    models = ["trace", "logreg", "linsvc", "majority"]
    colors = {"trace": TEAL, "logreg": GREY, "linsvc": AMBER, "majority": "#cbd5e1"}
    fig, axes = plt.subplots(1, len(datasets), figsize=(5 * len(datasets), 4), squeeze=False)
    for j, ds in enumerate(datasets):
        ax = axes[0][j]
        summ = d["datasets"][ds]["summary"]
        xs = np.arange(len(models))
        means = [summ[m]["f1"]["mean"] for m in models]
        errs = [summ[m]["f1"]["std"] for m in models]
        ax.bar(xs, means, yerr=errs, capsize=4,
               color=[colors[m] for m in models], edgecolor="black", linewidth=0.5)
        ax.set_xticks(xs); ax.set_xticklabels(["TRACE", "LogReg", "LinSVC", "Majority"], rotation=15)
        ax.set_ylim(0, 1.05); ax.set_ylabel("test F1")
        ax.set_title(f"{ds}  (n_test={d['datasets'][ds]['n_test']})")
        for x, m in zip(xs, means):
            ax.text(x, m + 0.02, f"{m:.2f}", ha="center", fontsize=9)
    fig.suptitle("Content guard: detection F1 on real prompt-injection / jailbreak data (12 seeds)")
    save(fig, "content_guard")


def fig_behavior():
    d = load("behavior_trajectory")
    if not d:
        return
    fams = list(d["families"])
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for ax, metric, title in ((axes[0], "asr", "Attack Success Rate (lower better)"),
                              (axes[1], "fpr", "False-Positive Rate (lower better)")):
        xs = np.arange(len(fams)); w = 0.35
        pc = [d["families"][f]["summary"]["per_call"][metric]["mean"] for f in fams]
        pce = [d["families"][f]["summary"]["per_call"][metric]["std"] for f in fams]
        tr = [d["families"][f]["summary"]["trace"][metric]["mean"] for f in fams]
        tre = [d["families"][f]["summary"]["trace"][metric]["std"] for f in fams]
        ax.bar(xs - w/2, pc, w, yerr=pce, capsize=3, label="per-call (memoryless)",
               color=RED, edgecolor="black", linewidth=0.5)
        ax.bar(xs + w/2, tr, w, yerr=tre, capsize=3, label="TRACE (online LTL)",
               color=TEAL, edgecolor="black", linewidth=0.5)
        ax.set_xticks(xs); ax.set_xticklabels(fams, rotation=18, fontsize=9)
        ax.set_ylim(0, 1.08); ax.set_title(title)
        ax.legend(fontsize=9)
    fig.suptitle("Trajectory verification: the per-call paradigm trades ASR for FPR; TRACE keeps both low")
    save(fig, "behavior_trajectory")


def fig_ablation():
    d = load("ablation")
    if not d:
        return
    cells = ["benign_benign", "inject_benign", "benign_exfil", "inject_exfil"]
    labels = ["benign/benign\n(FPR)", "inject/benign", "benign/exfil", "inject/exfil"]
    cfgs = ["content_only", "behavior_only", "trace"]
    colors = {"content_only": AMBER, "behavior_only": GREY, "trace": TEAL}
    fig, ax = plt.subplots(figsize=(8, 4.2))
    xs = np.arange(len(cells)); w = 0.26
    for i, cfg in enumerate(cfgs):
        means = [d["cells"][c][cfg]["mean"] for c in cells]
        errs = [d["cells"][c][cfg]["std"] for c in cells]
        ax.bar(xs + (i - 1) * w, means, w, yerr=errs, capsize=3,
               label=cfg.replace("_", "-"), color=colors[cfg], edgecolor="black", linewidth=0.5)
    ax.set_xticks(xs); ax.set_xticklabels(labels)
    ax.set_ylabel("flag rate"); ax.set_ylim(0, 1.08)
    ax.set_title("Component ablation: each channel is blind to the other's attack")
    ax.legend()
    save(fig, "ablation")


def fig_systems():
    d = load("systems_benchmark")
    if not d:
        return
    sweep = d["content_sweep"]
    cs = [r["n_clauses"] for r in sweep]
    lat = [r["latency"]["median_us"] for r in sweep]
    f1 = [r["test_f1"] for r in sweep]
    fig, ax1 = plt.subplots(figsize=(7, 4.2))
    ax1.plot(cs, lat, "o-", color=TEAL, label="latency")
    ax1.set_xlabel("clauses"); ax1.set_ylabel("median latency (us)", color=TEAL)
    ax1.tick_params(axis="y", labelcolor=TEAL)
    ax2 = ax1.twinx(); ax2.grid(False)
    ax2.plot(cs, f1, "s--", color=RED, label="test F1")
    ax2.set_ylabel("test F1", color=RED); ax2.tick_params(axis="y", labelcolor=RED)
    ax2.set_ylim(0, 1.0)
    ax1.set_title("Content guard: latency / accuracy vs clause budget")
    save(fig, "systems")

    led = d.get("ledger_scaling")
    if led:
        n = [r["n_entries"] for r in led]
        vpe = [r["verify_us_per_entry"] for r in led]
        bpe = [r["bytes_per_entry"] for r in led]
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.plot(n, vpe, "o-", color=TEAL, label="verify us / entry")
        ax.plot(n, bpe, "s--", color=GREY, label="bytes / entry")
        ax.set_xlabel("ledger entries"); ax.set_ylabel("per-entry cost")
        ax.set_title("Certificate ledger: verification is linear, constant per entry")
        ax.legend()
        save(fig, "ledger_scaling")


def fig_adaptive():
    d = load("adaptive_robustness")
    if not d:
        return
    aa = d["adaptive_attacker"]
    n = [r["n_exports"] for r in aa]
    det = [r["detection_rate"]["mean"] for r in aa]
    err = [r["detection_rate"]["std"] for r in aa]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
    ax1.errorbar(n, det, yerr=err, fmt="o-", color=TEAL, capsize=3)
    ax1.axvline(2.5, color=RED, ls="--", lw=1, label="budget k=2")
    ax1.set_xlabel("# exports in trajectory"); ax1.set_ylabel("detection rate")
    ax1.set_ylim(-0.05, 1.08); ax1.set_title("Adaptive attacker vs BoundedCount(k=2)")
    ax1.legend()

    tr = d["transfer"]
    dirs = list(tr.keys())
    short = {"prompt_injection": "p-inj", "jailbreak": "jail"}
    labels = []
    for k in dirs:
        a, b = k.split("__to__")
        labels.append(f"{short.get(a, a)}\n$\\rightarrow$ {short.get(b, b)}")
    xs = np.arange(len(dirs)); w = 0.35
    indom = [tr[k]["in_domain_f1"] for k in dirs]
    cross = [tr[k]["cross_domain_f1"] for k in dirs]
    ax2.bar(xs - w/2, indom, w, label="in-domain", color=TEAL, edgecolor="black", linewidth=0.5)
    ax2.bar(xs + w/2, cross, w, label="cross-domain", color=AMBER, edgecolor="black", linewidth=0.5)
    ax2.set_xticks(xs); ax2.set_xticklabels(labels, fontsize=9)
    ax2.set_ylim(0, 1.05); ax2.set_ylabel("content-guard F1")
    ax2.set_title("Honest failure: distribution shift")
    ax2.legend(fontsize=9)
    save(fig, "adaptive_robustness")


def main():
    print("building figures...")
    for fn in (fig_content_guard, fig_behavior, fig_ablation,
               fig_systems, fig_adaptive):
        try:
            fn()
        except Exception as e:
            print(f"  [skip] {fn.__name__}: {type(e).__name__}: {e}")
    print("done ->", FIG)


if __name__ == "__main__":
    main()
