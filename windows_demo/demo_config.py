"""Central configuration and path-safety helpers for the live demo.

The live prototype intentionally has a small, explicit configuration surface.
Every filesystem operation is checked against ``windows_demo/sandbox``.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_ROOT = (Path(__file__).resolve().parent / "sandbox").resolve()
PROTECTED_ROOT = SANDBOX_ROOT / "protected"
DECOYS_ROOT = SANDBOX_ROOT / "decoys"
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "live_demo.log"

ROLLING_WINDOW_SECONDS = 3.0
POLL_INTERVAL_SECONDS = 0.10
NORMAL_MUTATION_SECONDS = 8.0
MEDIUM_MUTATION_SECONDS = 4.0
HIGH_MUTATION_SECONDS = 1.5

# Explainable score thresholds. A decoy event always maps directly to CRITICAL.
MEDIUM_SCORE = 4.0
HIGH_SCORE = 9.0
CRITICAL_SCORE = 18.0

# Context awareness: WHAT is touched and WHEN it happens change event weights.
SENSITIVE_KEYWORDS = ("budget", "employee", "finance", "customer", "hr")
SENSITIVE_WEIGHT = 1.5
BUSINESS_HOURS = range(8, 19)  # 08:00-18:59 local time
OFF_HOURS_WEIGHT = 1.5

PROTECTED_FILE_NAMES = (
    "report1.txt", "report2.txt", "budget.csv", "notes.txt", "project.txt",
    "employee.txt", "presentation.txt", "data.csv", "image1.txt", "backup.txt",
)

DECOY_SPECS = (
    ("HR_CONFIDENTIAL_DECOY.txt", "decoys"),
    ("FINANCE_BACKUP_DECOY.txt", "decoys/finance"),
    ("IMPORTANT_DOCUMENT_DECOY.txt", "decoys/finance/archive"),
    ("CUSTOMER_DATA_DECOY.txt", "decoys/projects"),
)


@dataclass(frozen=True)
class DemoPaths:
    """Absolute paths used by one demo instance."""

    sandbox: Path = SANDBOX_ROOT
    protected: Path = PROTECTED_ROOT
    decoys: Path = DECOYS_ROOT

    def __post_init__(self) -> None:
        object.__setattr__(self, "sandbox", Path(self.sandbox).resolve())
        object.__setattr__(self, "protected", Path(self.protected).resolve())
        object.__setattr__(self, "decoys", Path(self.decoys).resolve())

    def safe(self, candidate: os.PathLike | str, *, allow_root: bool = False) -> Path:
        """Return a resolved path only when it remains inside this sandbox."""
        path = Path(candidate).resolve(strict=False)
        try:
            relative = path.relative_to(self.sandbox)
        except ValueError as exc:
            raise ValueError(f"path is outside the demo sandbox: {path}") from exc
        if not allow_root and relative == Path("."):
            raise ValueError("the sandbox root itself is not a file target")
        return path

    def safe_child(self, base: Path, relative: str) -> Path:
        base = self.safe(base, allow_root=True)
        return self.safe(base / relative)


def ensure_project_paths() -> None:
    """Create only the project-owned log directory."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)

