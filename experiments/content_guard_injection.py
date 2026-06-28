"""Experiment E1: Content guard on REAL prompt-injection / jailbreak data.

Claim under test: a Tsetlin content guard reaches detection quality competitive
with strong CPU baselines (logistic regression, linear SVM over binary bag of
words) while being (a) interpretable down to per-decision conjunctive clauses,
(b) tiny, and (c) sub-millisecond on a CPU.  I do NOT claim to beat multi-
billion-parameter GPU guardrails on raw accuracy; their published numbers are
reported in the paper for context only (different data/splits).

Protocol: two real, Apache-2.0 datasets (deepset/prompt-injections,
jackhhao/jailbreak-classification); 12 seeds; mean +/- std + 95% CI; Mann-Whitney
U test of TRACE-F1 vs the best baseline F1.  Latency and model size measured on
the host CPU.  Interpretability shown by extracting learned clauses.
"""

from __future__ import annotations

import sys
import time
import numpy as np

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from tracekit import ContentGuard, ContentGuardConfig
from experiments._common import (load_dataset, summarize, mannwhitney, prf1,
                                 write_results, host_info, SEEDS, CONTENT_CFG)

DATASETS = ["prompt_injection", "jailbreak"]

# Fixed a-priori hyperparameters (disclosed; not tuned on any test split).
CG_CFG = CONTENT_CFG


def _median_latency_us(predict_one, samples, repeats=3) -> dict:
    times = []
    for _ in range(repeats):
        for s in samples:
            t0 = time.perf_counter()
            predict_one(s)
            times.append((time.perf_counter() - t0) * 1e6)
    times = np.array(times)
    return {"median_us": float(np.median(times)), "p99_us": float(np.percentile(times, 99)),
            "mean_us": float(times.mean())}


def run_trace(train, test, seed):
    Xtr, ytr = train
    Xte, yte = test
    cfg = ContentGuardConfig(seed=seed, **CG_CFG)
    cg = ContentGuard(cfg)
    cg.fit(Xtr, ytr)
    yp = cg.predict(Xte)
    m = prf1(yte, yp)
    lat = _median_latency_us(lambda t: cg.verdict(t), Xte[:50])
    # model size: include bits over all clauses
    inc_bits = cg.tm.bank.n_clauses * cg.tm.bank.n_literals
    m["latency"] = lat
    m["model_bytes"] = int(np.ceil(inc_bits / 8))
    m["n_features"] = cg.vec.n_features
    return m, cg


def run_sklearn(train, test, seed, kind):
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.svm import LinearSVC
    from sklearn.dummy import DummyClassifier
    Xtr, ytr = train
    Xte, yte = test
    vec = CountVectorizer(binary=True, ngram_range=(1, 2), max_features=4000)
    Ztr = vec.fit_transform(Xtr)
    Zte = vec.transform(Xte)
    if kind == "logreg":
        clf = LogisticRegression(max_iter=2000, C=1.0, random_state=seed)
    elif kind == "linsvc":
        clf = LinearSVC(C=1.0, random_state=seed)
    else:
        clf = DummyClassifier(strategy="most_frequent")
    clf.fit(Ztr, ytr)
    yp = clf.predict(Zte)
    m = prf1(yte, yp)
    lat = _median_latency_us(lambda t: clf.predict(vec.transform([t])), Xte[:50])
    m["latency"] = lat
    if hasattr(clf, "coef_"):
        m["model_bytes"] = int(np.asarray(clf.coef_).size * 8)   # float64 weights
        m["n_features"] = int(np.asarray(clf.coef_).shape[-1])
    else:
        m["model_bytes"] = 0
        m["n_features"] = 0
    return m, (vec, clf)


def main(seeds=SEEDS):
    out = {"host": host_info(), "config": CG_CFG, "seeds": list(seeds), "datasets": {}}
    models = ["trace", "logreg", "linsvc", "majority"]

    for ds in DATASETS:
        print(f"\n=== {ds} ===")
        data = load_dataset(ds)
        per_model = {m: {"f1": [], "accuracy": [], "precision": [], "recall": [],
                         "fpr": [], "latency_us": [], "model_bytes": [], "n_features": []}
                     for m in models}
        example_clauses = None
        example_logreg_tokens = None

        for seed in seeds:
            mt, cg = run_trace(data["train"], data["test"], seed)
            for k in ("f1", "accuracy", "precision", "recall", "fpr"):
                per_model["trace"][k].append(mt[k])
            per_model["trace"]["latency_us"].append(mt["latency"]["median_us"])
            per_model["trace"]["model_bytes"].append(mt["model_bytes"])
            per_model["trace"]["n_features"].append(mt["n_features"])
            if example_clauses is None:
                example_clauses = cg.explain(top_k=8)

            for kind in ("logreg", "linsvc", "majority"):
                ms, fitted = run_sklearn(data["train"], data["test"], seed, kind)
                for k in ("f1", "accuracy", "precision", "recall", "fpr"):
                    per_model[kind][k].append(ms[k])
                per_model[kind]["latency_us"].append(ms["latency"]["median_us"])
                per_model[kind]["model_bytes"].append(ms["model_bytes"])
                per_model[kind]["n_features"].append(ms["n_features"])
                if kind == "logreg" and example_logreg_tokens is None:
                    vec, clf = fitted
                    coef = np.asarray(clf.coef_).ravel()
                    names = np.array(vec.get_feature_names_out())
                    top = names[np.argsort(coef)[-10:][::-1]]
                    example_logreg_tokens = [str(t) for t in top]
            print(f"  seed {seed}: trace F1={mt['f1']:.3f} acc={mt['accuracy']:.3f} | "
                  f"logreg F1={per_model['logreg']['f1'][-1]:.3f}")

        summary = {}
        for m in models:
            summary[m] = {k: summarize(per_model[m][k])
                          for k in ("f1", "accuracy", "precision", "recall", "fpr",
                                    "latency_us", "model_bytes", "n_features")}
        # significance: TRACE vs best baseline by mean F1
        baselines = [m for m in models if m != "trace"]
        best_base = max(baselines, key=lambda m: summary[m]["f1"]["mean"])
        sig = mannwhitney(per_model["trace"]["f1"], per_model[best_base]["f1"])

        out["datasets"][ds] = {
            "n_train": len(data["train"][0]), "n_test": len(data["test"][0]),
            "summary": summary,
            "best_baseline": best_base,
            "trace_vs_best_baseline_f1": sig,
            "example_trace_clauses": example_clauses,
            "example_logreg_top_tokens": example_logreg_tokens,
        }
        print(f"  TRACE  F1 {summary['trace']['f1']['mean']:.3f}+-{summary['trace']['f1']['std']:.3f}"
              f"  acc {summary['trace']['accuracy']['mean']:.3f}"
              f"  lat {summary['trace']['latency_us']['mean']:.1f}us"
              f"  size {summary['trace']['model_bytes']['mean']/1024:.1f}KB")
        print(f"  {best_base:8s} F1 {summary[best_base]['f1']['mean']:.3f}"
              f"  (TRACE vs {best_base}: p={sig['p_value']:.3g})")

    write_results("content_guard", out)
    return out


if __name__ == "__main__":
    quick = "--quick" in sys.argv
    main(seeds=(0, 1, 2) if quick else SEEDS)
