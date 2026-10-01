"""Tkinter dashboard for the safe Windows live MTD demonstration."""
from __future__ import annotations

import logging
from pathlib import Path
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText

from .demo_config import LOG_FILE, PROJECT_ROOT, DemoPaths, ensure_project_paths
from .live_mtd import LiveMTD, MutationGuard, SandboxManager
from .monitor import SandboxMonitor, ThreatTracker


class DemoController:
    """Non-GUI controller kept small so the behavior is testable."""

    def __init__(self, paths: DemoPaths | None = None, event_sink=None):
        ensure_project_paths()
        self.manager = SandboxManager(paths)
        self.paths = self.manager.paths
        self.guard = MutationGuard()
        self.mtd = LiveMTD(self.manager, self.guard)
        self.tracker = ThreatTracker(self.paths, self.mtd.is_decoy)
        self.monitor = SandboxMonitor(self.paths, self._on_file_event, self.guard)
        self.event_sink = event_sink or (lambda message: None)
        self.protection_started = False
        self.attacker: subprocess.Popen | None = None
        self.contained = False
        self._last_level = "LOW"
        self._stop_lock = threading.Lock()

        self.logger = logging.getLogger(f"mtd-live-{id(self)}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s", "%Y-%m-%d %H:%M:%S"))
        self.logger.handlers[:] = [handler]

    def log(self, message: str) -> None:
        self.logger.info(message)
        self.event_sink(message)

    def initialize(self) -> None:
        self.stop_protection()
        self.stop_attacker()
        self.manager.reset()
        self.tracker.reset()
        self.mtd.mutation_count = 0
        self.mtd.last_mutation = time.monotonic()
        self.mtd.set_level("LOW")
        self._last_level = "LOW"
        self.contained = False
        self.log("Sandbox initialized")

    def start_protection(self) -> None:
        if not self.paths.protected.exists():
            self.manager.reset()
            self.log("Sandbox initialized")
        if not self.protection_started:
            self.monitor.start()
            self.protection_started = True
            self.log(f"Protection started ({self.monitor.backend} monitor)")

    def stop_protection(self) -> None:
        if self.protection_started:
            self.monitor.stop()
            self.protection_started = False
            self.log("Protection stopped")

    def _on_file_event(self, event_type: str, path: Path, dest_path: Path | None) -> None:
        result = self.tracker.record(event_type, path, dest_path)
        shown = path.name if dest_path is None else f"{path.name} -> {dest_path.name}"
        context = result["context"] + (", sensitive file" if result["sensitive"] else "")
        self.log(
            f"File {event_type}: {shown} | score={result['score']:.1f} | "
            f"threat={result['level']} | context={context}"
        )
        if result["level"] != self._last_level:
            self._last_level = result["level"]
            self.mtd.set_level(result["level"])
            self.log(f"Threat level: {result['level']}")
            if result["level"] in {"MEDIUM", "HIGH"}:
                self.log("MTD mutation triggered")
                self.mtd.mutate(reason=f"threat level {result['level']}")
        if result["reason"] == "DECOY TRIGGERED":
            if self.contained:
                return
            self.contained = True
            self.log("DECOY TRIGGERED")
            self.log("CRITICAL THREAT DETECTED")
            self._kill_switch()

    def start_attacker(self) -> bool:
        """Launch the harmless attacker. Protection is NOT started automatically,
        so an attack with protection stopped shows the undefended outcome."""
        if self.attacker and self.attacker.poll() is None:
            self.log(f"Attack simulator already running (PID {self.attacker.pid})")
            return False
        if not self.paths.protected.exists():
            self.manager.reset()
            self.log("Sandbox initialized")
        if not self.protection_started:
            self.log("WARNING: protection is STOPPED - attack will run undefended")
        self.contained = False
        script = Path(__file__).resolve().with_name("live_attacker.py")
        self.attacker = subprocess.Popen(
            [sys.executable, str(script), "--sandbox", str(self.paths.sandbox)],
            cwd=str(PROJECT_ROOT),
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        self.log(f"Attack simulator started (PID {self.attacker.pid})")
        threading.Thread(
            target=self._watch_attacker, args=(self.attacker,), name="mtd-attack-watch", daemon=True
        ).start()
        return True

    def damaged_files(self) -> int:
        """Protected files the attacker has renamed to *.locked_demo."""
        return sum(path.name.endswith(".locked_demo") for path in self.manager.protected_files())

    def _watch_attacker(self, process: subprocess.Popen) -> None:
        """Report the outcome when the attacker exits on its own (i.e. was not blocked)."""
        process.wait()
        with self._stop_lock:
            if self.attacker is not process:
                return  # the kill-switch or Stop already handled it
            self.attacker = None
        total = len(self.manager.protected_files())
        self.log("ATTACK COMPLETED - NOT BLOCKED")
        self.log(f"Files damaged: {self.damaged_files()}/{total} protected files locked (.locked_demo)")

    def stop_attacker(self) -> None:
        with self._stop_lock:
            process = self.attacker
            self.attacker = None
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                self.log("ATTACK SIMULATOR TERMINATED")

    def _kill_switch(self) -> None:
        self.log("RANSOMWARE-LIKE ACTIVITY DETECTED")
        self.log("KILL-SWITCH ACTIVATED")
        self.stop_attacker()
        self.log("ATTACK BLOCKED")
        total = len(self.manager.protected_files())
        self.log(f"Files damaged before block: {self.damaged_files()}/{total}")

    def status(self) -> dict:
        threat = self.tracker.snapshot()
        return {
            "protection": "ACTIVE" if self.protection_started else "STOPPED",
            "threat": threat["level"],
            "score": threat["score"],
            "mutation_rate": f"every {self.mtd.interval_seconds():.1f}s",
            "protected": self.manager.stats()["protected"],
            "decoys": self.manager.stats()["decoys"],
            "attack": "RUNNING" if self.attacker and self.attacker.poll() is None else "STOPPED",
            "context": threat["context"],
            "mutations": self.mtd.mutation_count,
        }

    def close(self) -> None:
        self.stop_attacker()
        self.stop_protection()
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)


class Dashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Context-Aware Multi-Layered MTD for Ransomware Mitigation")
        self.geometry("760x560")
        self.controller = DemoController(event_sink=self._append_log)
        self.vars = {key: tk.StringVar(value="-") for key in (
            "protection", "threat", "mutation_rate", "protected", "decoys", "attack", "context"
        )}
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._exit)
        self.after(250, self._refresh)

    def _build_ui(self):
        tk.Label(self, text=self.title(), font=("Segoe UI", 16, "bold")).pack(pady=10)
        status = tk.Frame(self)
        status.pack(fill="x", padx=15)
        labels = (
            ("Protection Status", "protection"), ("Threat Level", "threat"),
            ("Mutation Rate", "mutation_rate"), ("Protected Files", "protected"),
            ("Active Decoys", "decoys"), ("Attack Status", "attack"),
            ("Time Context", "context"),
        )
        for row, (label, key) in enumerate(labels):
            tk.Label(status, text=f"{label}:", anchor="w", width=20).grid(row=row // 2, column=(row % 2) * 2, sticky="w", padx=4, pady=3)
            tk.Label(status, textvariable=self.vars[key], anchor="w", width=23).grid(row=row // 2, column=(row % 2) * 2 + 1, sticky="w", padx=4, pady=3)
        buttons = tk.Frame(self)
        buttons.pack(fill="x", padx=15, pady=10)
        actions = (
            ("Initialize Sandbox", self._initialize), ("Start Protection", self.controller.start_protection),
            ("Stop Protection", self.controller.stop_protection), ("Simulate Attack", self.controller.start_attacker),
            ("Reset Sandbox", self._initialize), ("Open Log", self._open_log), ("Exit", self._exit),
        )
        for index, (label, command) in enumerate(actions):
            tk.Button(buttons, text=label, command=command, width=18).grid(row=index // 3, column=index % 3, padx=3, pady=3)
        tk.Label(self, text="Live event log", anchor="w").pack(fill="x", padx=15)
        self.log_text = ScrolledText(self, height=20, state="disabled", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def _append_log(self, message: str):
        self.after(0, self._append_log_ui, message)

    def _append_log_ui(self, message: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _initialize(self):
        try:
            self.controller.initialize()
        except Exception as exc:
            messagebox.showerror("Sandbox error", str(exc))

    def _refresh(self):
        status = self.controller.status()
        for key, value in status.items():
            if key in self.vars:
                self.vars[key].set(str(value))
        self.after(250, self._refresh)

    def _open_log(self):
        try:
            import os
            os.startfile(str(LOG_FILE))
        except (AttributeError, OSError) as exc:
            messagebox.showinfo("Log path", f"{LOG_FILE}\n\n{exc}")

    def _exit(self):
        self.controller.close()
        self.destroy()


def main() -> None:
    try:
        Dashboard().mainloop()
    except tk.TclError as exc:
        raise SystemExit(
            "Tkinter could not start. Install the standard Windows CPython "
            "distribution (including Tcl/Tk), then recreate .venv. "
            f"Details: {exc}"
        ) from exc


if __name__ == "__main__":
    main()
