"""Regression tests for the four hardening fixes in the scoring path.

Covers what ``test_service.py`` does not (it exercises the happy path only):

1. **Path exposure** - ``serve.py`` must serve only the allowlist, never
   ``.git/``, configs or model bundles, and must refuse a non-loopback bind
   without a token.
2. **Crash resilience** - a failing batch or a dead sink must not stop the
   service; the failure has to be counted and surfaced instead.
3. **Tail robustness** - truncation/rotation restarts the read, a record
   split across two reads is parsed exactly once, a ragged CSV row is
   rejected rather than scored as a flow of zeros, and ``parse_errors``
   actually increments.
4. **Sink latency** - webhook delivery is queued, so emitting cannot block
   the scoring loop, and the queue is bounded.

Run:  python deploy/test_hardening.py
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import flow_adapters as fa          # noqa: E402
import service as svc               # noqa: E402
import sinks as sk                  # noqa: E402

PY = sys.executable
TMP = Path(tempfile.mkdtemp(prefix="aptcti_hardening_"))
RESULTS: list[bool] = []


def check(label: str, got, want, extra: str = "") -> None:
    ok = got == want
    RESULTS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}: got {got!r}, want {want!r}"
          + (f"  {extra}" if extra else ""))


FLOW = ('{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,'
        '"dst_port":443,"proto":"tcp","ts":1700000000,"dur":1.5,'
        '"sbytes":100,"dbytes":200,"Spkts":5,"Dpkts":6}\n')
CSV_HEADER = ("src_ip,dst_ip,src_port,dst_port,proto,ts,dur,sbytes,dbytes,"
              "Spkts,Dpkts")


# --------------------------------------------------------------- serve.py
def get(url: str, token: str | None = None):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url)
    if token:
        req.add_header("X-Auth-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as exc:                       # noqa: BLE001
        return type(exc).__name__


def test_serve_exposure() -> None:
    print("=== serve.py: path exposure + fail-closed bind ===")
    p = subprocess.Popen([PY, "serve.py", "--no-poll", "--no-browser",
                          "--port", "8791"], cwd=ROOT,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(3.0)
        base = "http://127.0.0.1:8791"
        check("GET /", get(base + "/"), 200)
        check("GET /__status", get(base + "/__status"), 200)
        check(".git/config blocked", get(base + "/.git/config"), 404)
        check("config/default.yaml blocked", get(base + "/config/default.yaml"), 404)
        check("deploy/config.yaml blocked", get(base + "/deploy/config.yaml"), 404)
        check("model bundle blocked", get(base + "/model/deploy_unsw_full.joblib"), 404)
        check("source blocked", get(base + "/src/cti_pipeline/config.py"), 404)
        check("traversal blocked", get(base + "/../../Windows/win.ini"), 404)
        check("allowlisted results served",
              get(base + "/results/tables/feed_poll.json"), 200)
    finally:
        p.terminate()
        time.sleep(1.0)

    p = subprocess.Popen([PY, "serve.py", "--no-poll", "--no-browser",
                          "--port", "8792", "--token", "s3cr3t"], cwd=ROOT,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(3.0)
        base = "http://127.0.0.1:8792"
        check("shell stays public", get(base + "/"), 200)
        check("__status without token", get(base + "/__status"), 401)
        check("__status wrong token", get(base + "/__status", "nope"), 401)
        check("__status right token", get(base + "/__status", "s3cr3t"), 200)
        check("static without token", get(base + "/results/tables/feed_poll.json"), 401)
        check("static with token",
              get(base + "/results/tables/feed_poll.json", "s3cr3t"), 200)
        check("config blocked even with token",
              get(base + "/config/default.yaml", "s3cr3t"), 404)
    finally:
        p.terminate()
        time.sleep(1.0)

    r = subprocess.run([PY, "serve.py", "--no-poll", "--no-browser",
                        "--host", "0.0.0.0", "--port", "8793"],
                       cwd=ROOT, capture_output=True, text=True, timeout=60)
    check("non-loopback bind refused without token", r.returncode, 2)


# ---------------------------------------------------------------- tailer
def tailer(name: str, content: str, fmt: str = "jsonl"):
    path = TMP / name
    path.write_text(content, encoding="utf-8")
    return path, svc.FileTailer(path, fmt, False, {"parse_errors": 0})


def test_tailer() -> None:
    print("=== FileTailer: truncation, rotation, partial lines, errors ===")
    path, t = tailer("partial.jsonl", FLOW[:80])
    got = t.read()
    check("incomplete record not parsed", len(got), 0)
    check("bytes read but held back", t.pos, 80)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(FLOW[80:])
    got = t.read()
    check("record completed across reads", len(got), 1)
    check("src_ip preserved", got[0]["src_ip"] if got else None, "10.0.0.1")
    check("no duplicate on next read", len(t.read()), 0)

    path, t = tailer("nonl.jsonl", FLOW.rstrip("\n"))
    check("file ending without newline still yields last row", len(t.read()), 1)

    path, t = tailer("trunc.jsonl", FLOW * 3)
    t.read()
    path.write_text(FLOW, encoding="utf-8")          # logrotate copytruncate
    check("restarts after truncation", len(t.read()), 1)
    check("truncation counted", t.resets, 1)

    path, t = tailer("rot.jsonl", FLOW * 3)
    t.read()
    new = TMP / "rot.jsonl.new"
    new.write_text(FLOW, encoding="utf-8")
    os.replace(new, path)                            # rename + recreate
    check("restarts after rotation", len(t.read()), 1)
    check("rotation counted", t.resets, 1)

    stats = {"parse_errors": 0}
    fa.parse_chunk("not json at all\n", "jsonl", stats)
    check("jsonl decode failure counted", stats["parse_errors"], 1)

    stats = {"parse_errors": 0}
    fa.parse_chunk('{"no_ips": true}\n', "jsonl", stats)
    check("valid non-flow record is not an error", stats["parse_errors"], 0)

    stats = {"parse_errors": 0}
    fa.parse_chunk('{"event_type":"dns"}\n', "eve", stats)
    check("valid non-flow eve event is not an error", stats["parse_errors"], 0)

    stats = {"parse_errors": 0}
    fa.parse_chunk('{"src_ip":"1.1.1.1"}\n', "eve", stats)
    check("non-eve input flagged", stats["parse_errors"], 1)

    stats = {"parse_errors": 0}
    ok_csv = CSV_HEADER + "\n10.0.0.1,10.0.0.2,1,2,tcp,1700000000,1.5,100,200,5,6\n"
    check("clean CSV row parsed", len(fa.from_csv_rows(ok_csv, stats)), 1)
    check("clean CSV row not an error", stats["parse_errors"], 0)

    stats = {"parse_errors": 0}
    ragged = CSV_HEADER + "\n10.0.0.1,10.0.0.2,1,2,tcp\n"
    check("ragged CSV row rejected (no flow of zeros)",
          len(fa.from_csv_rows(ragged, stats)), 0)
    check("ragged CSV row counted", stats["parse_errors"], 1)

    check("half JSON is not complete", fa.is_complete('{"src_ip":', "jsonl"), False)
    check("whole JSON is complete", fa.is_complete(FLOW.strip(), "jsonl"), True)


# ------------------------------------------------------------ crash guards
def make_service(input_path: Path):
    args = argparse.Namespace(input=str(input_path), format=None, replay=False,
                              health_host=None, health_port=None,
                              online_feeds=False)
    return svc.Service(svc.load_deploy_config(ROOT / "deploy" / "config.yaml"),
                       args), args


class BrokenSink:
    count = 0

    def emit(self, alert):
        raise ConnectionError("SIEM down")


def test_crash_resilience() -> None:
    print("=== crash resilience: guards must hold ===")
    s, _ = make_service(TMP / "inbox_a.jsonl")
    check("stats initialised before tailer", s.stats.get("parse_errors"), 0)

    def boom(_):
        raise RuntimeError("simulated SHAP failure")

    s.score_batch = boom
    s._score_safe([{"src_ip": "1.1.1.1"}])           # must not raise
    check("failing batch swallowed", s.stats["score_errors"], 1)
    check("failure surfaced in status",
          "simulated SHAP" in (s.stats["last_error"] or ""), True)
    check("service still reports alive", s.status()["alive"], True)

    s2, _ = make_service(TMP / "inbox_b.jsonl")
    s2.sink = sk.Fanout([BrokenSink()])              # every emit raises
    s2.attributor = None
    s2.bundle.theta = -1.0                           # force every flow to alert
    frame = [{
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1,
        "dst_port": 443, "proto": "tcp", "ts": 1700000000, "dur": 1.5,
        "sbytes": 100, "dbytes": 200, "Spkts": 5, "Dpkts": 6,
        "service": "-", "state": "CON",
    }]
    raised = False
    try:
        s2.score_batch(frame * 8)
    except Exception:                                # noqa: BLE001
        raised = True
    check("dead sink does not abort the batch", raised, False)
    st = s2.sink.stats()["Fanout"]
    check("sink failures counted", st["errors"] > 0, True, str(st))
    check("last sink error recorded", "BrokenSink" in st["last_error"], True)


# ------------------------------------------------------------- async sink
def test_webhook_not_blocking() -> None:
    print("=== webhook: bounded queue, no hot-path blocking ===")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(128)
    held: list = []

    def swallow() -> None:
        while True:
            try:
                conn, _ = srv.accept()
                held.append(conn)
            except OSError:
                return

    threading.Thread(target=swallow, daemon=True).start()
    port = srv.getsockname()[1]

    # accepts and never answers -> every POST blocks until the client timeout
    hk = sk.WebhookSink(f"http://127.0.0.1:{port}/webhook", timeout_s=1.5,
                        queue_size=5)
    t0 = time.time()
    for i in range(50):
        hk.emit({"alert_id": i})
    elapsed = time.time() - t0
    check("50 emits stay non-blocking", elapsed < 2.0, True,
          f"{elapsed:.2f}s (inline code would need up to 75s)")
    check("queue bounded", hk.pending <= 5, True, f"pending={hk.pending}")
    check("overflow counted, not grown", hk.dropped > 0, True,
          f"dropped={hk.dropped}")
    check("sink stats exposed",
          "WebhookSink" in sk.Fanout([hk]).stats(), True)

    t0 = time.time()
    hk.close(timeout=1.0)
    check("close() returns promptly", time.time() - t0 < 8.0, True)
    srv.close()
    for conn in held:
        conn.close()

    # a failing endpoint must still account for every alert
    hk2 = sk.WebhookSink("http://", timeout_s=2.0, queue_size=10)
    for i in range(5):
        hk2.emit({"alert_id": i})
    hk2.close()
    check("close() empties the queue", hk2.pending, 0)
    check("every alert accounted for",
          hk2.count + hk2.errors + hk2.dropped, 5,
          f"delivered={hk2.count} errors={hk2.errors} dropped={hk2.dropped}")


def main() -> int:
    test_serve_exposure()
    test_tailer()
    test_crash_resilience()
    test_webhook_not_blocking()
    failed = RESULTS.count(False)
    print(f"\n{len(RESULTS) - failed}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
