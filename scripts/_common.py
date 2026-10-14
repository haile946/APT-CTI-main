"""Shared helpers for the experiment scripts (path setup, data, enrichment)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cti_pipeline import data as data_mod  # noqa: E402
from cti_pipeline import enrich as enrich_mod  # noqa: E402
from cti_pipeline.config import Config, load_config  # noqa: E402
from cti_pipeline.enrich import CTI_FEATURES, ReplaySettings, build_sightings, enrich  # noqa: E402
from cti_pipeline.store import IocRecord  # noqa: E402

PROCESSED = ROOT / "data" / "processed"
TABLES = ROOT / "results" / "tables"
FIGURES = ROOT / "results" / "figures"


def base_parser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--dataset", default="unsw_nb15", choices=["unsw_nb15", "cicids2017"])
    p.add_argument("--max-rows", type=int, default=400_000, help="stratified subsample cap (0 = all)")
    p.add_argument("--n-estimators", type=int, default=200)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--config", default=None)
    return p


def get_config(args) -> Config:
    cfg = load_config(args.config)
    cfg.model.n_estimators = args.n_estimators
    cfg.model.seed = args.seed
    cfg.data.max_rows = args.max_rows
    return cfg


def dataset_dir(cfg: Config, name: str) -> Path:
    return Path(cfg.data.unsw_dir if name == "unsw_nb15" else cfg.data.cic_dir)


def get_flows(cfg: Config, name: str) -> "data_mod.pd.DataFrame":
    """Load (and cache) the canonical flow frame for a dataset."""
    PROCESSED.mkdir(parents=True, exist_ok=True)
    cache = PROCESSED / f"{name}_rows{cfg.data.max_rows}_seed{cfg.model.seed}.parquet"
    if cache.exists():
        df = data_mod.pd.read_parquet(cache)
        print(f"[data] {name}: {len(df):,} flows (cached)")
        return df
    t0 = time.time()
    df = data_mod.load_dataset(name, dataset_dir(cfg, name),
                               max_rows=cfg.data.max_rows, seed=cfg.model.seed)
    df.to_parquet(cache, index=False)
    print(f"[data] {name}: {len(df):,} flows loaded in {time.time() - t0:.1f}s")
    return df


def get_sighting_frame(cfg: Config, name: str):
    """Full un-subsampled (src_ip, dst_ip, ts, label) frame.

    Historical note: this used to be the label source for controlled
    injection.  It is not split-aware, so using it would build the IoC set
    from test-split labels (target leakage).  The experiments now take their
    labels from ``split_first(...).eligible`` only; this loader is retained
    for offline inspection and must not be used to derive indicators.
    """
    PROCESSED.mkdir(parents=True, exist_ok=True)
    cache = PROCESSED / f"{name}_sightings.parquet"
    if cache.exists():
        return data_mod.pd.read_parquet(cache)
    t0 = time.time()
    df = data_mod.load_sighting_frame(name, dataset_dir(cfg, name))
    df.to_parquet(cache, index=False)
    print(f"[data] {name}: sighting frame {len(df):,} flows in {time.time() - t0:.1f}s")
    return df


def get_live_records(cfg: Config, poll: bool = True) -> list[IocRecord]:
    """Poll live feeds once (or reuse today's snapshot) and return their IoCs."""
    from cti_pipeline.collector import load_snapshots, poll_once
    from cti_pipeline.net import ensure_doh

    snapshot_dir = Path(cfg.cti.snapshot_dir)
    ensure_doh()
    if poll:
        report, records = poll_once(cfg.cti)
        Path(cfg.cti.snapshot_dir).mkdir(parents=True, exist_ok=True)
        (Path(cfg.cti.snapshot_dir) / "last_poll.json").write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        ok = sum(1 for p in report.polls if p["ok"])
        print(f"[feeds] polled {ok}/{len(report.polls)} feeds, "
              f"{len(records)} IoC records -> store {cfg.cti.db_path}")
        for p in report.polls:
            print(f"    {p['source']:10s} ok={p['ok']!s:5s} n={p['n_records']:6d} {p['error']}")
        return records
    records = load_snapshots(snapshot_dir)
    print(f"[feeds] offline mode: {len(records)} IoC records from snapshots")
    return records


def make_settings(interval_min: float, cfg: Config) -> ReplaySettings:
    return ReplaySettings(
        interval_s=float(interval_min) * 60.0,
        ttl_s=cfg.replay.ttl_hours * 3600.0,
        half_life_s=cfg.replay.freshness_half_life_h * 3600.0,
        t0=0.0,
    )


def get_sightings(cfg: Config, flows, live_records: list[IocRecord],
                  injection: str | None = None, eligible=None):
    """Build the IoC sighting timeline.

    ``eligible`` is the set of rows allowed to contribute **label-derived**
    indicators - it must be the train+validation split.  Omitting it would
    build the injected IoC set (IPs, timestamps, synthetic confidence) from
    the ground-truth labels of *every* row, including the test split, so each
    test flow would carry CTI features computed from its own label.  That is
    target leakage, so controlled injection without ``eligible`` raises
    instead of silently falling back to the full frame.

    The un-subsampled sighting frame is no longer used as a label source: it
    has no split information, so it cannot be made leak-free.
    """
    injection = cfg.replay.injection if injection is None else injection
    if injection == "controlled":
        if eligible is None:
            raise ValueError(
                "controlled injection derives IoCs from ground-truth labels; "
                "pass eligible=<train+val rows> so test-split labels cannot "
                "leak into the CTI features (see docs/METHODOLOGY.md)")
        source = eligible
    else:
        source = flows.iloc[0:0]        # no label-derived indicators at all
    return build_sightings(
        source, live_records, injection=injection,
        injection_rate=cfg.replay.injection_rate,
        benign_ioc_rate=cfg.replay.benign_ioc_rate,
        seed=cfg.replay.seed,
    )


def split_first(cfg: Config, flows):
    """Split **before** enrichment, and derive the indicator pool from it.

    Returns ``(splits, y, eligible)`` where ``eligible`` are the
    train+validation rows.  Enrichment has to be given this subset: the
    split must exist first, otherwise the injected IoC set is built from the
    test-split labels (target leakage - see ``get_sightings``).
    """
    from cti_pipeline.model import make_splits

    y = flows["label"].to_numpy()
    splits = make_splits(y, cfg.data.test_size, cfg.data.val_size, cfg.model.seed)
    eligible = flows.iloc[np.concatenate([splits.train, splits.val])]
    return splits, y, eligible


def build_enriched(
    cfg: Config,
    flows,
    live_records: list[IocRecord],
    interval_min: float = 5.0,
    injection: str | None = None,
    sightings=None,
    eligible=None,
):
    """Enrich flows at a given poll interval; return (frame_with_cti, sightings, summary).

    Pass ``eligible`` (see ``split_first``) whenever ``injection`` is the
    controlled one - it is required for that path.
    """
    if sightings is None:
        sightings, summary = get_sightings(cfg, flows, live_records,
                                           injection=injection,
                                           eligible=eligible)
        sightings_map = sightings
    elif isinstance(sightings, tuple):
        sightings_map, summary = sightings[0], sightings[1]
    else:
        sightings_map, summary = sightings, {}
    # poll grid is aligned to the start of the replay, not to the Unix epoch
    from dataclasses import replace
    settings = replace(make_settings(interval_min, cfg),
                       t0=float(flows["ts"].min()))
    feats = enrich(flows, sightings_map, settings)
    frame = flows.copy()
    for col in CTI_FEATURES:
        frame[col] = feats[col].to_numpy()
    frame.attrs.update(feats.attrs)
    frame.attrs["sightings"] = summary
    return frame, (sightings_map, summary), summary


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=float), encoding="utf-8")
    print(f"[write] {path}")
