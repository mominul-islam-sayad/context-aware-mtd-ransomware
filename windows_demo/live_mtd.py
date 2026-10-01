"""Sandbox generation and safe file-level Moving Target Defense."""
from __future__ import annotations

from contextlib import contextmanager
import random
import shutil
import threading
import time
from pathlib import Path

from .demo_config import (
    DECOY_SPECS,
    PROTECTED_FILE_NAMES,
    DemoPaths,
    HIGH_MUTATION_SECONDS,
    MEDIUM_MUTATION_SECONDS,
    NORMAL_MUTATION_SECONDS,
)


SAMPLE_CONTENT = (
    "Synthetic course-project data. This file is harmless and belongs only "
    "to the MTD live demo sandbox.\n"
)


class SandboxManager:
    """Create, inspect, and reset the generated demo files."""

    def __init__(self, paths: DemoPaths | None = None, seed: int = 7):
        self.paths = paths or DemoPaths()
        self.rng = random.Random(seed)

    def reset(self) -> None:
        """Recreate the sandbox, after validating the deletion target."""
        self.paths.safe(self.paths.sandbox, allow_root=True)
        if self.paths.sandbox.exists():
            shutil.rmtree(self.paths.sandbox)
        self.paths.protected.mkdir(parents=True, exist_ok=True)
        self.paths.decoys.mkdir(parents=True, exist_ok=True)
        for index, name in enumerate(PROTECTED_FILE_NAMES, start=1):
            path = self.paths.safe(self.paths.protected / name)
            path.write_text(
                f"{SAMPLE_CONTENT} Protected sample {index}: {name}\n",
                encoding="utf-8",
            )
        for name, relative_dir in DECOY_SPECS:
            directory = self.paths.safe(self.paths.sandbox / relative_dir, allow_root=True)
            directory.mkdir(parents=True, exist_ok=True)
            path = self.paths.safe(directory / name)
            path.write_text(
                f"{SAMPLE_CONTENT} Decoy marker for harmless detection: {name}\n",
                encoding="utf-8",
            )

    def protected_files(self) -> list[Path]:
        if not self.paths.protected.exists():
            return []
        return sorted(
            self.paths.safe(path)
            for path in self.paths.protected.rglob("*")
            if path.is_file()
        )

    def decoy_files(self) -> list[Path]:
        if not self.paths.decoys.exists():
            return []
        return sorted(
            self.paths.safe(path)
            for path in self.paths.decoys.rglob("*")
            if path.is_file()
        )

    def stats(self) -> dict[str, int]:
        return {"protected": len(self.protected_files()), "decoys": len(self.decoy_files())}


class MutationGuard:
    """Short, thread-safe suppression window for defender-generated events."""

    def __init__(self, grace_seconds: float = 0.25):
        self.grace_seconds = grace_seconds
        self._lock = threading.Lock()
        self._suppressed_until = 0.0

    @contextmanager
    def suppress(self):
        with self._lock:
            self._suppressed_until = max(
                self._suppressed_until, time.monotonic() + self.grace_seconds
            )
        try:
            yield
        finally:
            with self._lock:
                self._suppressed_until = max(
                    self._suppressed_until, time.monotonic() + self.grace_seconds
                )

    def active(self) -> bool:
        with self._lock:
            return time.monotonic() < self._suppressed_until


class LiveMTD:
    """File-level MTD mutations restricted to generated sandbox files."""

    def __init__(self, manager: SandboxManager, guard: MutationGuard | None = None, seed: int = 11):
        self.manager = manager
        self.paths = manager.paths
        self.guard = guard or MutationGuard()
        self.rng = random.Random(seed)
        self.mutation_count = 0
        self.last_mutation = 0.0
        self.level = "LOW"

    def set_level(self, level: str) -> None:
        self.level = level

    def interval_seconds(self) -> float:
        if self.level == "HIGH":
            return HIGH_MUTATION_SECONDS
        if self.level == "MEDIUM":
            return MEDIUM_MUTATION_SECONDS
        return NORMAL_MUTATION_SECONDS

    def due(self) -> bool:
        return time.monotonic() - self.last_mutation >= self.interval_seconds()

    def is_decoy(self, path: Path) -> bool:
        try:
            self.paths.safe(path).relative_to(self.paths.decoys)
            return True
        except ValueError:
            return False

    def mutate(self, reason: str = "adaptive interval") -> bool:
        """Rename a few generated files and rotate one decoy location."""
        protected = self.manager.protected_files()
        decoys = self.manager.decoy_files()
        changed = False
        with self.guard.suppress():
            for source in protected[:2]:
                destination = source.with_name(
                    f"{source.stem}.mtd_{self.rng.randrange(1000, 9999)}{source.suffix}"
                )
                source = self.paths.safe(source)
                destination = self.paths.safe(destination)
                if source.exists() and not destination.exists():
                    source.replace(destination)
                    changed = True
            if decoys:
                source = self.rng.choice(decoys)
                relative_dir = self.rng.choice(("decoys", "decoys/finance", "decoys/projects"))
                target_dir = self.paths.safe(self.paths.sandbox / relative_dir, allow_root=True)
                target_dir.mkdir(parents=True, exist_ok=True)
                destination = self.paths.safe(target_dir / source.name)
                if source != destination and source.exists() and not destination.exists():
                    source.replace(destination)
                    changed = True
        if changed:
            self.mutation_count += 1
            self.last_mutation = time.monotonic()
        return changed

