"""Harmless subprocess that creates ransomware-like activity in the demo sandbox."""
from __future__ import annotations

import argparse
from pathlib import Path
import random
import sys
import time


def safe_path(root: Path, candidate: Path) -> Path:
    root = root.resolve()
    path = candidate.resolve(strict=False)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"live attacker refused path outside sandbox: {path}") from exc
    return path


def run(root: Path, seed: int = 21) -> int:
    root = root.resolve()
    protected = safe_path(root, root / "protected")
    decoys = safe_path(root, root / "decoys")
    rng = random.Random(seed)
    if not protected.exists() or not decoys.exists():
        return 2

    # Touch a small batch first so the defense visibly moves LOW -> MEDIUM/HIGH.
    files = [safe_path(root, p) for p in protected.rglob("*") if p.is_file()][:5]
    for index, source in enumerate(files):
        if not source.exists():
            continue
        source.write_bytes(source.read_bytes() + f"\nDEMO_ACTIVITY_{index}\n".encode())
        time.sleep(0.08)
        renamed = safe_path(root, source.with_name(source.stem + ".locked_demo"))
        if source.exists() and not renamed.exists():
            source.replace(renamed)
        time.sleep(0.08)

    # A decoy is intentionally modified: this is the reliable trigger because
    # ordinary file watchers do not expose file-open/read events.
    time.sleep(0.25)
    decoy_files = [safe_path(root, p) for p in decoys.rglob("*") if p.is_file()]
    if decoy_files:
        target = rng.choice(decoy_files)
        target.write_bytes(target.read_bytes() + b"\nSAFE_DECOY_TRIGGER\n")

    # Remain alive briefly so the parent can demonstrate process termination.
    for _ in range(30):
        time.sleep(0.2)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe MTD live-demo activity generator")
    parser.add_argument("--sandbox", required=True, type=Path)
    args = parser.parse_args()
    try:
        return run(args.sandbox)
    except (OSError, ValueError) as exc:
        print(f"live attacker stopped safely: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

