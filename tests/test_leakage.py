"""Regression tests for the two Critical methodology fixes.

C1  **target leakage.**  The controlled-injection IoC set (which IPs become
    indicators, when they are first sighted, and their synthetic confidence)
    is derived from ground-truth ``label``.  It used to be built from the
    *entire* frame - train, validation *and test* rows - so every test flow
    whose endpoint happened to be published carried CTI features computed from
    its own ground truth.  The pool is now restricted to train+val rows and
    ``_common.get_sightings`` refuses to run without that restriction.

    Two secondary leaks in the same code path are covered here too:
      * a sighting whose poll boundary landed exactly on a flow's own
        timestamp was visible to that very flow (``ceil`` + ``side="right"``);
      * test labels also fed the benign-noise pool and the confidence model.

C2  **live_feeds_only duplicate.**  The E2 variant dropped all six CTI
    columns, so it was a byte-for-byte copy of ``traffic_only`` and E2
    published the traffic-only model twice as the "live feeds" result.

Run::

    python tests/test_leakage.py          # exit code 0 = all checks passed
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
for _extra in (ROOT / "src", ROOT / "scripts"):
    if str(_extra) not in sys.path:
        sys.path.insert(0, str(_extra))

from _common import get_sightings, split_first  # noqa: E402
from cti_pipeline.config import Config  # noqa: E402
from cti_pipeline.enrich import (  # noqa: E402
    CTI_FEATURES, ReplaySettings, build_sightings, enrich,
)
from run_e2_ablation import variant_designs  # noqa: E402

INTERVAL_S = 60.0


def base_config(**replay_overrides) -> Config:
    cfg = Config()
    cfg.replay.injection = "controlled"
    cfg.replay.injection_rate = 1.0        # deterministic indicator pool
    cfg.replay.benign_ioc_rate = 0.0       # no synthetic feed noise here
    cfg.replay.seed = 42
    for key, value in replay_overrides.items():
        setattr(cfg.replay, key, value)
    return cfg


def settings(cfg: Config, t0: float = 0.0) -> ReplaySettings:
    return ReplaySettings(
        interval_s=INTERVAL_S,
        ttl_s=cfg.replay.ttl_hours * 3600.0,
        half_life_s=cfg.replay.freshness_half_life_h * 3600.0,
        t0=t0,
    )


def same_sightings(a: dict, b: dict) -> bool:
    if set(a) != set(b):
        return False
    for key in a:
        ta, ca, sa = a[key]
        tb, cb, sb = b[key]
        if not (np.array_equal(ta, tb) and np.array_equal(ca, cb)
                and np.array_equal(sa, sb)):
            return False
    return True


def matched(feats: pd.DataFrame, i: int) -> float:
    """1.0 when flow *i* matches an indicator on either endpoint."""
    return float(feats["ioc_src_match"].iloc[i]) + float(feats["ioc_dst_match"].iloc[i])


def make_synthetic_flows(n: int = 6000, seed: int = 11) -> pd.DataFrame:
    """A flow frame with repeated attacker IPs *and* singleton attacker IPs.

    The singletons matter: an IP that only ever appears in test-split rows is
    the clearest possible demonstration of the leak - nothing but a test label
    could ever put it in the indicator pool.
    """
    rng = np.random.default_rng(seed)
    ts = np.arange(n, dtype="float64")                 # 1 s per flow, t0 = 0
    label = np.zeros(n, dtype="int8")
    label[rng.choice(n, size=int(n * 0.06), replace=False)] = 1

    atk = [f"198.51.100.{i}" for i in range(1, 31)]            # reused attacker
    victim = [f"203.0.113.{i}" for i in range(1, 201)]
    benign_src = [f"10.1.{i // 250}.{i % 250 + 1}" for i in range(1, 501)]
    benign_dst = [f"10.2.{i // 250}.{i % 250 + 1}" for i in range(1, 501)]

    src = np.empty(n, dtype=object)
    dst = np.empty(n, dtype=object)
    singleton = 0
    for i in range(n):
        if label[i]:
            if i % 3 == 0:                        # unique IP for this one row
                src[i] = f"192.0.2.{singleton + 1}"
                singleton += 1
                dst[i] = victim[int(rng.integers(0, len(victim)))]
            else:
                src[i] = atk[int(rng.integers(0, len(atk)))]
                dst[i] = victim[int(rng.integers(0, len(victim)))]
        else:
            src[i] = benign_src[int(rng.integers(0, len(benign_src)))]
            dst[i] = benign_dst[int(rng.integers(0, len(benign_dst)))]

    return pd.DataFrame({
        "src_ip": src, "dst_ip": dst, "ts": ts, "label": label,
        "dur": rng.random(n),
    })


def malicious_ips(frame: pd.DataFrame) -> set[str]:
    mal = frame.loc[frame["label"] == 1]
    return set(pd.concat([mal["src_ip"], mal["dst_ip"]]).dropna().astype(str))


# ---------------------------------------------------------------------------
# C1 - fence
# ---------------------------------------------------------------------------
def test_fence_rejects_unrestricted_labels():
    """Controlled injection without an explicit row restriction must raise."""
    cfg = base_config()
    flows = make_synthetic_flows()
    try:
        get_sightings(cfg, flows, [])
    except ValueError as exc:
        assert "test" in str(exc).lower(), f"unhelpful message: {exc}"
    else:
        raise AssertionError(
            "controlled injection ran without `eligible` - the leak fence is gone")


def test_injection_none_needs_no_eligible():
    """The live-feeds-only path (E2 variant B) stays usable without a split."""
    cfg = base_config()
    flows = make_synthetic_flows(n=400)
    sightings, summary = get_sightings(cfg, flows, [], injection="none")
    assert summary["injection"] == "none"
    assert sightings == {}
    assert summary["n_sightings_injected"] == 0


def test_split_excludes_test_rows():
    cfg = base_config()
    flows = make_synthetic_flows()
    splits, y, eligible = split_first(cfg, flows)
    assert len(y) == len(flows)
    assert set(eligible.index) & set(splits.test) == set()
    assert len(eligible) == len(splits.train) + len(splits.val)


def test_indicator_pool_excludes_test_only_ips():
    """No IP that appears only in test rows may reach the indicator pool."""
    cfg = base_config()
    flows = make_synthetic_flows()
    splits, _, eligible = split_first(cfg, flows)

    test_only = malicious_ips(flows) - malicious_ips(eligible)
    assert test_only, "fixture problem: no test-only malicious IP found"

    sightings, _ = get_sightings(cfg, flows, [], eligible=eligible)
    leaked = test_only & set(sightings)
    assert not leaked, (
        f"{len(leaked)} test-only IPs are indicators, e.g. {sorted(leaked)[:3]}")

    # the check must have teeth: the old (full-frame) source does leak them
    leaky, _ = build_sightings(flows, [], injection="controlled",
                               injection_rate=cfg.replay.injection_rate,
                               benign_ioc_rate=cfg.replay.benign_ioc_rate,
                               seed=cfg.replay.seed)
    assert test_only & set(leaky), "fixture problem: leaky source did not leak"


def test_features_invariant_to_test_label_flip():
    """Flipping *only* test-split labels must not change any CTI feature."""
    cfg = base_config()
    flows = make_synthetic_flows()
    splits, _, eligible = split_first(cfg, flows)

    flipped = flows.copy()
    flipped.loc[splits.test, "label"] = 1 - flipped.loc[splits.test, "label"]

    s_fix, sum_fix = get_sightings(cfg, flows, [], eligible=eligible)
    s_alt, sum_alt = get_sightings(cfg, flipped, [], eligible=eligible)
    assert same_sightings(s_fix, s_alt), "indicator pool depends on test labels"
    assert sum_fix == sum_alt, "sightings summary depends on test labels"

    st = settings(cfg, t0=float(flows["ts"].min()))
    f_fix = enrich(flows, s_fix, st)
    f_alt = enrich(flipped, s_alt, st)
    for col in CTI_FEATURES:
        assert np.allclose(f_fix[col].to_numpy(), f_alt[col].to_numpy()), (
            f"feature {col} changes when only test labels change")


def test_test_only_endpoint_never_flags():
    """End-to-end leak demonstration on a hand-built frame.

    Two test-split rows share an IP that exists nowhere else.  Under the old
    full-frame source the second row is flagged by a sighting derived from
    test labels; under the fixed source neither row is ever flagged, and
    flipping the test labels changes nothing.
    """
    cfg = base_config()
    frame = pd.DataFrame({
        "src_ip": ["9.9.9.9", "9.9.9.9", "192.0.2.200", "192.0.2.200"],
        "dst_ip": ["10.9.9.9", "10.9.9.9", "10.9.9.8", "10.9.9.8"],
        "ts": [0.0, 100.0, 1000.0, 1100.0],
        "label": [1, 1, 1, 1],
    })
    eligible = frame.iloc[:2]          # train+val: only 9.9.9.9 is known
    st = settings(cfg, t0=0.0)

    fixed = enrich(frame, get_sightings(cfg, frame, [], eligible=eligible)[0], st)
    assert matched(fixed, 2) == 0.0, "a test-only IP reached the indicator pool"
    assert matched(fixed, 3) == 0.0, "a test-only IP reached the indicator pool"
    assert fixed["feed_age_score"].iloc[2:].sum() == 0

    flip = frame.copy()
    flip.loc[2:, "label"] = 0
    leaky = enrich(frame, build_sightings(flows=frame, live_records=[],
                                          injection="controlled",
                                          injection_rate=1.0,
                                          benign_ioc_rate=0.0, seed=42)[0], st)
    leaky_flip = enrich(frame, build_sightings(flows=flip, live_records=[],
                                               injection="controlled",
                                               injection_rate=1.0,
                                               benign_ioc_rate=0.0, seed=42)[0], st)
    assert matched(leaky, 3) == 1.0, (
        "fixture problem: old source should flag row 3 via test labels")
    assert matched(leaky_flip, 3) == 0.0, (
        "fixture problem: flipping test labels should clear that flag")

    fixed_flip = enrich(frame, get_sightings(cfg, flip, [], eligible=eligible)[0], st)
    for col in CTI_FEATURES:
        assert np.allclose(fixed[col].to_numpy(), fixed_flip[col].to_numpy()), (
            f"fixed path: {col} reacts to test labels")


def test_no_self_visibility_on_poll_boundary():
    """A flow must never be flagged by its own sighting (strict causality)."""
    cfg = base_config()
    frame = pd.DataFrame({
        "src_ip": ["192.0.2.201", "192.0.2.201"],
        "dst_ip": ["10.9.9.7", "10.9.9.7"],
        "ts": [600.0, 700.0],          # 600 s sits exactly on a poll boundary
        "label": [1, 1],
    })
    sightings, _ = get_sightings(cfg, frame, [], eligible=frame)
    feats = enrich(frame, sightings, settings(cfg, t0=0.0))
    assert matched(feats, 0) == 0.0, (
        "the flow at t=600 sees its own sighting at t=600")
    # ...but a later flow with the same IP still sees it (age 100 s)
    assert matched(feats, 1) == 1.0
    assert abs(float(feats["feed_age_score"].iloc[1]) - 0.5 ** (100.0 / (6.0 * 3600))) < 1e-6


def test_no_zero_age_matches_anywhere():
    """Global invariant: every matched flow is strictly *after* its sighting."""
    cfg = base_config()
    flows = make_synthetic_flows(n=3000)
    _, _, eligible = split_first(cfg, flows)
    sightings, _ = get_sightings(cfg, flows, [], eligible=eligible)
    feats = enrich(flows, sightings, settings(cfg, t0=float(flows["ts"].min())))
    age = np.asarray(feats.attrs["age_seconds"], dtype="float64")
    matched = ((feats["ioc_src_match"] + feats["ioc_dst_match"]) > 0).to_numpy()
    assert matched.any(), "fixture problem: nothing matched"
    assert np.isfinite(age[matched]).all()
    assert (age[matched] > 0).all(), (
        f"{int((age[matched] <= 0).sum())} flows have age <= 0 (own sighting)")


# ---------------------------------------------------------------------------
# C2 - live_feeds_only must keep the live CTI columns
# ---------------------------------------------------------------------------
def _enriched_pair(n: int = 400, seed: int = 3) -> tuple[pd.DataFrame, pd.DataFrame]:
    rng = np.random.default_rng(seed)
    base = pd.DataFrame({
        "src_ip": [f"10.0.0.{i % 250 + 1}" for i in range(n)],
        "dst_ip": [f"10.1.0.{i % 250 + 1}" for i in range(n)],
        "ts": np.arange(n, dtype="float64"),
        "dur": rng.random(n),
        "proto": rng.choice(["tcp", "udp", "icmp"], size=n),
        "label": rng.integers(0, 2, size=n),
    })
    frame = base.copy()
    frame["ioc_src_match"] = rng.integers(0, 2, size=n).astype("float32")
    frame["ioc_dst_match"] = rng.integers(0, 2, size=n).astype("float32")
    frame["feed_age_score"] = rng.random(n).astype("float32")
    frame["feed_confidence"] = rng.random(n).astype("float32")
    frame["source_count"] = rng.integers(0, 4, size=n).astype("float32")
    frame["reputation_bucket"] = rng.integers(0, 4, size=n).astype("float32")

    frame_live = base.copy()                       # no feed returned anything
    for col in CTI_FEATURES:
        frame_live[col] = np.zeros(n, dtype="float32")
    return frame, frame_live


def test_live_feeds_only_keeps_cti_columns():
    """C2: the variant exists to carry live CTI - it must not drop it."""
    frame, frame_live = _enriched_pair()
    _, variants = variant_designs(frame, frame_live)
    missing = set(CTI_FEATURES) - set(variants["live_feeds_only"].columns)
    assert not missing, f"live_feeds_only dropped the CTI columns: {sorted(missing)}"
    assert set(CTI_FEATURES).isdisjoint(variants["traffic_only"].columns)


def test_live_feeds_only_is_not_a_duplicate_of_traffic_only():
    frame, frame_live = _enriched_pair()
    _, variants = variant_designs(frame, frame_live)
    assert not variants["live_feeds_only"].equals(variants["traffic_only"]), (
        "live_feeds_only is byte-identical to traffic_only - the C2 bug is back")
    live_cti = variants["live_feeds_only"][list(CTI_FEATURES)].to_numpy()
    assert live_cti.sum() == 0, "fixture problem: live-only CTI should be zero here"
    ctrl_cti = variants["traffic_cti"][list(CTI_FEATURES)].to_numpy()
    assert ctrl_cti.sum() > 0, "fixture problem: controlled CTI should be populated"
    assert set(variants) == {"traffic_only", "traffic_cti",
                             "traffic_cti_no_match", "live_feeds_only"}


def main() -> int:
    tests = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    failures = 0
    for fn in tests:
        try:
            fn()
        except Exception:  # noqa: BLE001 - report every failure, not just the first
            failures += 1
            print(f"[FAIL] {fn.__name__}")
            traceback.print_exc()
        else:
            print(f"[ ok ] {fn.__name__}")
    print(f"\n{len(tests) - failures}/{len(tests)} leakage checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
