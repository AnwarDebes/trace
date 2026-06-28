"""Run every TRACE experiment end-to-end and regenerate results/*.json.

    python -u experiments/run_all.py            # full (>=12 seeds)
    python -u experiments/run_all.py --quick    # fast smoke (3 seeds)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments import (content_guard_injection, behavior_trajectory_suite,
                         ablation, tamper_evidence, systems_benchmark,
                         adaptive_robustness)


def main():
    quick = "--quick" in sys.argv
    steps = [
        ("E1 content guard (real data)", lambda: content_guard_injection.main(
            seeds=(0, 1, 2) if quick else content_guard_injection.SEEDS)),
        ("E2 behaviour trajectory suite", lambda: behavior_trajectory_suite.main(
            seeds=(0, 1, 2) if quick else behavior_trajectory_suite.SEEDS)),
        ("E3 component ablation", lambda: ablation.main(
            seeds=(0, 1, 2) if quick else ablation.SEEDS)),
        ("E4 tamper evidence", lambda: tamper_evidence.main(
            n_sessions=20 if quick else 40)),
        ("E5 systems benchmark", lambda: systems_benchmark.main(quick=quick)),
        ("E6 adaptive robustness", lambda: adaptive_robustness.main(quick=quick)),
    ]
    t0 = time.perf_counter()
    for name, fn in steps:
        print("\n" + "=" * 70 + f"\n{name}\n" + "=" * 70)
        s = time.perf_counter()
        fn()
        print(f"[{name}] done in {time.perf_counter()-s:.1f}s")
    print(f"\nALL EXPERIMENTS done in {time.perf_counter()-t0:.1f}s")


if __name__ == "__main__":
    main()
