"""Download and cache real prompt-injection / jailbreak datasets for offline,
fully-reproducible experiments.

I pull HuggingFace's auto-converted parquet (no `datasets` dependency), then
normalise every source to a two-column CSV ``text,label`` (label: 1 = unsafe /
injection / jailbreak, 0 = benign) under ``data/<name>/``.  A ``manifest.json``
records the source URL, license, row counts, and a SHA-256 of each cached file
so provenance is auditable.  Re-running is idempotent (cached files are kept).

Datasets (both permissively licensed):
  * deepset/prompt-injections        (Apache-2.0)  546 train / 116 test
  * jackhhao/jailbreak-classification (Apache-2.0) larger jailbreak corpus
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import urllib.request
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = ROOT / "data"

PARQUET = "https://huggingface.co/datasets/{ds}/resolve/refs%2Fconvert%2Fparquet/default/{split}/0000.parquet"

SOURCES = {
    "prompt_injection": {
        "ds": "deepset/prompt-injections",
        "license": "apache-2.0",
        "text_col": "text",
        "label_col": "label",
        "label_map": None,                 # already 0/1
    },
    "jailbreak": {
        "ds": "jackhhao/jailbreak-classification",
        "license": "apache-2.0",
        "text_col": "prompt",
        "label_col": "type",
        "label_map": {"benign": 0, "jailbreak": 1},
    },
}


def _download_parquet(ds: str, split: str) -> pd.DataFrame:
    url = PARQUET.format(ds=ds, split=split)
    with urllib.request.urlopen(url, timeout=60) as r:
        raw = r.read()
    return pd.read_parquet(io.BytesIO(raw))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _normalise(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    tcol, lcol = cfg["text_col"], cfg["label_col"]
    # column-name fallbacks across dataset revisions
    if tcol not in df.columns:
        tcol = next(c for c in df.columns if df[c].dtype == object)
    if lcol not in df.columns:
        lcol = [c for c in df.columns if c != tcol][0]
    out = pd.DataFrame({"text": df[tcol].astype(str)})
    labels = df[lcol]
    if cfg["label_map"] is not None:
        labels = labels.astype(str).str.lower().map(cfg["label_map"])
    out["label"] = labels.astype(int)
    out = out.dropna().reset_index(drop=True)
    return out


def fetch_one(name: str, cfg: dict, force: bool = False) -> dict:
    out_dir = DATA / name
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "manifest.json"
    if manifest_path.exists() and not force:
        print(f"[{name}] cached -> {out_dir}")
        return json.loads(manifest_path.read_text())

    info = {"name": name, "source": cfg["ds"], "license": cfg["license"], "splits": {}}
    for split in ("train", "test"):
        try:
            df = _normalise(_download_parquet(cfg["ds"], split), cfg)
        except Exception as e:                       # some datasets ship only one split
            print(f"[{name}] split '{split}' unavailable: {type(e).__name__}: {e}")
            continue
        csv_path = out_dir / f"{split}.csv"
        df.to_csv(csv_path, index=False)
        info["splits"][split] = {
            "rows": int(len(df)),
            "pos": int((df["label"] == 1).sum()),
            "neg": int((df["label"] == 0).sum()),
            "sha256": _sha256(csv_path),
            "file": csv_path.name,
        }
        print(f"[{name}] {split}: {len(df)} rows "
              f"({int((df['label']==1).sum())} unsafe / {int((df['label']==0).sum())} benign)")
    manifest_path.write_text(json.dumps(info, indent=2))
    return info


def main(force: bool = False):
    DATA.mkdir(exist_ok=True)
    for name, cfg in SOURCES.items():
        fetch_one(name, cfg, force=force)
    print("Done. Cached under", DATA)


if __name__ == "__main__":
    main(force="--force" in sys.argv)
