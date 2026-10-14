"""Alert sinks: JSONL file, webhook POST, syslog UDP."""
from __future__ import annotations

import json
import socket
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


class JsonlSink:
    """Append-only JSONL with optional size-based rotation + retention.

    Rotation renames the file to ``<stem>-YYYYMMDD-HHMMSS.jsonl`` and starts
    fresh; the newest ``keep_files`` archives are retained, older ones are
    deleted (retention policy for regulated environments).
    """

    def __init__(self, path: str | Path, rotate_mb: float = 0.0,
                 keep_files: int = 0):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rotate_bytes = int(float(rotate_mb) * 1_048_576) if rotate_mb else 0
        self.keep_files = max(0, int(keep_files))
        self._lock = threading.Lock()
        self.count = 0
        self.rotations = 0

    def emit(self, alert: dict) -> None:
        line = json.dumps(alert, default=float, ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self.count += 1
            if (self.rotate_bytes and self.path.exists()
                    and self.path.stat().st_size >= self.rotate_bytes):
                self._rotate_locked()

    def _rotate_locked(self) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        archive = self.path.with_name(
            f"{self.path.stem}-{ts}{self.path.suffix}")
        n = 1
        while archive.exists():                       # same-second collisions
            archive = self.path.with_name(
                f"{self.path.stem}-{ts}-{n}{self.path.suffix}")
            n += 1
        self.path.rename(archive)
        self.rotations += 1
        if self.keep_files:
            archives = sorted(
                self.path.parent.glob(f"{self.path.stem}-*{self.path.suffix}"),
                key=lambda p: p.name, reverse=True)
            for old in archives[self.keep_files:]:
                old.unlink(missing_ok=True)


class WebhookSink:
    """POST each alert to a SIEM/automation endpoint (best effort + one retry).

    Delivery runs on a background worker with a bounded queue.  The previous
    inline implementation called ``requests.post`` once per alert inside the
    scoring loop, so a slow endpoint stalled tailing for up to
    ``timeout_s * 2`` per alert - a burst of 50 alerts meant minutes without
    reading the sensor log.  The queue absorbs bursts; if the endpoint stays
    down, the oldest alerts are dropped and counted in ``dropped`` instead of
    growing memory without limit.

    Works with https:// URLs (requests verifies certificates); set
    ``token`` to send it as an ``Authorization: Bearer`` header.
    """

    def __init__(self, url: str, timeout_s: float = 5.0, token: str = "",
                 queue_size: int = 1000):
        self.url = url
        self.timeout_s = timeout_s
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.count = 0
        self.errors = 0
        self.dropped = 0
        self._size = max(1, int(queue_size))
        self._q: deque = deque()
        self._cv = threading.Condition()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="webhook-sink")
        self._thread.start()

    @property
    def pending(self) -> int:
        with self._cv:
            return len(self._q)

    def emit(self, alert: dict) -> None:
        """Enqueue only - never blocks the scoring loop."""
        with self._cv:
            if len(self._q) >= self._size:
                self._q.popleft()
                self.dropped += 1
            self._q.append(alert)
            self._cv.notify()

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._q and not self._stop.is_set():
                    self._cv.wait(0.5)
                if self._stop.is_set() and not self._q:
                    return
                alert = self._q.popleft()
            self._post(alert)

    def _post(self, alert: dict) -> None:
        try:
            import requests
            r = requests.post(self.url, json=alert, headers=self.headers,
                              timeout=self.timeout_s)
            if r.status_code >= 500:
                requests.post(self.url, json=alert, headers=self.headers,
                              timeout=self.timeout_s)
            self.count += 1
        except Exception:                                   # noqa: BLE001
            self.errors += 1

    def close(self, timeout: float = 5.0) -> None:
        """Drain what is already queued, then stop the worker.

        If delivery is still too slow to finish within ``timeout``, whatever
        remains is moved to ``dropped`` so no alert disappears uncounted.  A
        final join covers the in-flight POST so the counters are final by the
        time this returns instead of drifting in afterwards.
        """
        self._stop.set()
        with self._cv:
            self._cv.notify_all()
        self._thread.join(timeout)
        with self._cv:
            if self._q:
                self.dropped += len(self._q)
                self._q.clear()
        self._thread.join(self.timeout_s + 1.0)


class SyslogSink:
    """RFC3164-ish UDP syslog (works with rsyslog/syslog-ng collectors)."""

    PRI = 134  # daemon.notice

    def __init__(self, host: str, port: int = 514):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.count = 0
        self.errors = 0

    def emit(self, alert: dict) -> None:
        try:
            ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
            body = json.dumps(alert, default=float, ensure_ascii=False)
            msg = f"<{self.PRI}>{ts} apt-cti-score: {body[:8000]}"
            self.sock.sendto(msg.encode("utf-8", errors="replace"), self.addr)
            self.count += 1
        except OSError:
            self.errors += 1


class Fanout:
    """Emit to every configured sink; failures never break scoring.

    A sink that raises must not abort the batch, but it must not disappear
    either - failures are counted and the last error text is kept so
    ``/__status`` can show that alerts are being lost.
    """

    def __init__(self, sinks: list):
        self.sinks = sinks
        self.count = 0
        self.errors = 0
        self.last_error = ""

    def emit(self, alert: dict) -> None:
        self.count += 1
        for s in self.sinks:
            try:
                s.emit(alert)
            except Exception as exc:                       # noqa: BLE001
                self.errors += 1
                self.last_error = f"{type(s).__name__}: {exc}"[:200]

    def stats(self) -> dict:
        """Per-sink counters for /__status (queue depth, drops, errors)."""
        out = {"Fanout": {"count": self.count, "errors": self.errors,
                          "last_error": self.last_error}}
        for s in self.sinks:
            name = type(s).__name__
            d = {k: getattr(s, k) for k in ("count", "errors", "dropped")
                 if hasattr(s, k)}
            if hasattr(s, "pending"):
                d["pending"] = s.pending
            if d:
                out[name] = d
        return out

    def close(self, timeout: float = 5.0) -> None:
        """Flush async sinks (webhook queue) on shutdown."""
        for s in self.sinks:
            close = getattr(s, "close", None)
            if callable(close):
                try:
                    close(timeout)
                except Exception:                           # noqa: BLE001
                    pass
