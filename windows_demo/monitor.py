"""Real sandbox monitor with optional watchdog and a polling fallback."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
import threading
import time
from typing import Callable

from .demo_config import (
    BUSINESS_HOURS,
    CRITICAL_SCORE,
    HIGH_SCORE,
    MEDIUM_SCORE,
    OFF_HOURS_WEIGHT,
    POLL_INTERVAL_SECONDS,
    ROLLING_WINDOW_SECONDS,
    SENSITIVE_KEYWORDS,
    SENSITIVE_WEIGHT,
    DemoPaths,
)
from .live_mtd import MutationGuard

try:  # Optional dependency; polling remains fully functional without it.
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - depends on the local environment
    FileSystemEventHandler = None
    Observer = None


@dataclass
class Activity:
    timestamp: float
    event_type: str
    path: Path
    dest_path: Path | None = None


class ThreatTracker:
    """Explainable, context-aware rolling-window score used by both UI and tests."""

    def __init__(
        self,
        paths: DemoPaths,
        is_decoy: Callable[[Path], bool],
        clock_hour: Callable[[], int] | None = None,
    ):
        self.paths = paths
        self.is_decoy = is_decoy
        self.clock_hour = clock_hour or (lambda: time.localtime().tm_hour)
        self.activities: deque[Activity] = deque()
        self.score = 0.0
        self.level = "LOW"
        self.critical = False
        self.lock = threading.Lock()

    def _level_for_score(self) -> str:
        if self.critical or self.score >= CRITICAL_SCORE:
            return "CRITICAL"
        if self.score >= HIGH_SCORE:
            return "HIGH"
        if self.score >= MEDIUM_SCORE:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def is_sensitive(path: Path) -> bool:
        name = path.name.lower()
        return any(keyword in name for keyword in SENSITIVE_KEYWORDS)

    def off_hours(self) -> bool:
        return self.clock_hour() not in BUSINESS_HOURS

    def _weight(self, item: Activity) -> float:
        return SENSITIVE_WEIGHT if self.is_sensitive(item.path) else 1.0

    def context_label(self) -> str:
        return "off-hours" if self.off_hours() else "business hours"

    def record(self, event_type: str, path: Path, dest_path: Path | None = None) -> dict:
        now = time.monotonic()
        path = self.paths.safe(path)
        if dest_path is not None:
            dest_path = self.paths.safe(dest_path)
        with self.lock:
            self.activities.append(Activity(now, event_type, path, dest_path))
            cutoff = now - ROLLING_WINDOW_SECONDS
            while self.activities and self.activities[0].timestamp < cutoff:
                self.activities.popleft()
            if self.is_decoy(path) or (dest_path is not None and self.is_decoy(dest_path)):
                self.critical = True
                self.score = max(self.score, CRITICAL_SCORE)
                reason = "DECOY TRIGGERED"
            else:
                recent = list(self.activities)
                distinct = {str(item.path) for item in recent}
                modifications = sum(self._weight(item) for item in recent if item.event_type == "modified")
                moves = sum(self._weight(item) for item in recent if item.event_type == "moved")
                # Small activity is normal. Rapid breadth and repeated moves are not.
                # Context: sensitive files weigh more, and so does activity off-hours.
                raw = modifications * 0.8 + moves * 1.5 + max(0, len(distinct) - 2) * 1.0
                if self.off_hours():
                    raw *= OFF_HOURS_WEIGHT
                self.score = min(CRITICAL_SCORE, raw)
                reason = "rapid activity" if self.score >= MEDIUM_SCORE else "normal activity"
            old_level = self.level
            self.level = self._level_for_score()
            return {
                "score": self.score,
                "level": self.level,
                "previous_level": old_level,
                "reason": reason,
                "context": self.context_label(),
                "sensitive": self.is_sensitive(path),
                "recent_events": len(self.activities),
                "distinct_files": len({str(item.path) for item in self.activities}),
            }

    def snapshot(self) -> dict:
        with self.lock:
            now = time.monotonic()
            cutoff = now - ROLLING_WINDOW_SECONDS
            while self.activities and self.activities[0].timestamp < cutoff:
                self.activities.popleft()
            return {
                "score": self.score,
                "level": self.level,
                "context": self.context_label(),
                "recent_events": len(self.activities),
                "distinct_files": len({str(item.path) for item in self.activities}),
            }

    def reset(self) -> None:
        with self.lock:
            self.activities.clear()
            self.score = 0.0
            self.level = "LOW"
            self.critical = False


def _snapshot(root: Path) -> dict[Path, tuple[int, int, int]]:
    result: dict[Path, tuple[int, int, int]] = {}
    if not root.exists():
        return result
    for path in root.rglob("*"):
        if path.is_file():
            try:
                stat = path.stat()
                result[path.resolve()] = (stat.st_mtime_ns, stat.st_size, getattr(stat, "st_ino", 0))
            except FileNotFoundError:
                pass
    return result


class SandboxMonitor:
    """Watch only the sandbox and forward normalized events to a callback."""

    def __init__(
        self,
        paths: DemoPaths,
        callback: Callable[[str, Path, Path | None], None],
        guard: MutationGuard | None = None,
        prefer_watchdog: bool = True,
    ):
        self.paths = paths
        self.callback = callback
        self.guard = guard or MutationGuard()
        self.prefer_watchdog = prefer_watchdog
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._observer = None
        self.backend = "polling"

    def _emit(self, event_type: str, path: Path, dest_path: Path | None = None) -> None:
        try:
            path = self.paths.safe(path)
            if dest_path is not None:
                dest_path = self.paths.safe(dest_path)
        except ValueError:
            return
        if self.guard.active():
            return
        self.callback(event_type, path, dest_path)

    def _poll(self) -> None:
        previous = _snapshot(self.paths.sandbox)
        while not self._stop.wait(POLL_INTERVAL_SECONDS):
            current = _snapshot(self.paths.sandbox)
            removed = set(previous) - set(current)
            added = set(current) - set(previous)
            moved_pairs: list[tuple[Path, Path]] = []
            for old in list(removed):
                old_inode = previous[old][2]
                match = next((new for new in added if current[new][2] == old_inode and old_inode), None)
                if match:
                    moved_pairs.append((old, match))
                    removed.remove(old)
                    added.remove(match)
            for old, new in moved_pairs:
                self._emit("moved", old, new)
            for path in sorted(added):
                self._emit("created", path)
            for path in sorted(removed):
                self._emit("deleted", path)
            for path in set(previous) & set(current):
                if previous[path][:2] != current[path][:2]:
                    self._emit("modified", path)
            previous = current

    def start(self) -> None:
        if self._thread or self._observer:
            return
        self.paths.sandbox.mkdir(parents=True, exist_ok=True)
        if self.prefer_watchdog and Observer is not None:
            monitor = self

            class Handler(FileSystemEventHandler):
                def on_created(self, event):
                    if not event.is_directory:
                        monitor._emit("created", Path(event.src_path))

                def on_modified(self, event):
                    if not event.is_directory:
                        monitor._emit("modified", Path(event.src_path))

                def on_deleted(self, event):
                    if not event.is_directory:
                        monitor._emit("deleted", Path(event.src_path))

                def on_moved(self, event):
                    if not event.is_directory:
                        monitor._emit("moved", Path(event.src_path), Path(event.dest_path))

            self._observer = Observer()
            self._observer.schedule(Handler(), str(self.paths.sandbox), recursive=True)
            self._observer.start()
            self.backend = "watchdog"
        else:
            self._stop.clear()
            self._thread = threading.Thread(target=self._poll, name="mtd-sandbox-monitor", daemon=True)
            self._thread.start()
            self.backend = "polling"

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2)
            self._observer = None
        if self._thread:
            self._stop.set()
            self._thread.join(timeout=2)
            self._thread = None

