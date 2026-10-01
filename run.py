"""
Usage:
    python run.py demo     one attack per defense configuration, with event log
    python run.py bench    full benchmark (results.csv, results_fp.csv, results.png)
"""
import csv
import random
import shutil
import sys
import tempfile
import time

from attacker import MODES, Attacker
from mtd import CONFIGS, ProcessSuspended, VirtualFS, build_workspace

TRIALS = 20
# "spoof" = DFS ransomware that runs under the trusted backup agent's identity,
# i.e. the worst case for the context layer's process allow-list.
ATTACKS = MODES + ["spoof"]
USER_HOUR = 10      # normal user works during business hours
BACKUP_HOUR = 2     # backup jobs are scheduled at night


def attack_hour(seed):
    """Spread attack trials over the whole day (0, 5, 10, 15, 20, 1, 6, ...)."""
    return (seed * 5) % 24


def one_trial(cfg, mode, seed):
    root = tempfile.mkdtemp(prefix="mtd_")
    try:
        files = build_workspace(root, seed)
        vfs = VirtualFS(root, files, cfg, seed, hour=attack_hour(seed))
        pid = "backup" if mode == "spoof" else "attacker"
        res = Attacker(vfs, "dfs" if mode == "spoof" else mode, seed, pid=pid).run()
        damaged = vfs.audit(files)
        return {
            "damaged_pct": 100 * damaged / len(files),
            "detected": pid in vfs.detect_tick,
            "detect_ops": vfs.detect_tick.get(pid),
            "stopped": res["stopped"],
            "mutations": vfs.mutations,
            "events": vfs.events,
            "total": len(files),
            "damaged": damaged,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def legit_workload(vfs, files, rng, ops=1000):
    """Normal user: mostly reads/edits text, rarely saves a high-entropy file (photo/zip)."""
    names = list(files)
    binary = set()                      # files the user saved as photo/zip: read-only afterwards
    for _ in range(ops):
        f, r = rng.choice(names), rng.random()
        if r < 0.70 or f in binary:
            vfs.user_read(f)
        elif r < 0.995:
            vfs.user_write(f, vfs.user_read(f) + b" edit")
        else:
            vfs.user_write(f, rng.randbytes(2000))
            binary.add(f)


def backup_workload(vfs, files, rng, passes=3, pid="backup"):
    """Night-time backup agent: walks the whole tree and reads every file it sees.
    It does not know which files are decoys and races against MTD renames."""
    for _ in range(passes):
        frontier = [""]
        while frontier:
            rel = frontier.pop(0)
            try:
                entries = vfs.listdir(pid, rel)
            except FileNotFoundError:
                continue
            for name, is_dir in entries:
                child = (rel + "/" if rel else "") + name
                if is_dir:
                    frontier.append(child)
                    continue
                try:
                    vfs.read(pid, child)    # archive is written to a separate backup disk
                except FileNotFoundError:
                    pass


WORKLOADS = {
    "user": (legit_workload, USER_HOUR),
    "backup": (backup_workload, BACKUP_HOUR),
}


def legit_trial(cfg, seed, workload="user"):
    run_workload, hour = WORKLOADS[workload]
    root = tempfile.mkdtemp(prefix="mtd_")
    try:
        files = build_workspace(root, seed)
        vfs = VirtualFS(root, files, cfg, seed, hour=hour)
        t0 = time.perf_counter()
        killed = False
        try:
            run_workload(vfs, files, random.Random(seed))
        except ProcessSuspended:
            killed = True
        return time.perf_counter() - t0, killed
    finally:
        shutil.rmtree(root, ignore_errors=True)


def demo():
    print("One BFS attack against each configuration (seed 1):\n")
    for cfg in CONFIGS:
        r = one_trial(cfg, "bfs", 1)
        print(f"[{cfg.name}] damaged {r['damaged']}/{r['total']} files "
              f"({r['damaged_pct']:.0f}%), mutations={r['mutations']}, "
              f"detected={r['detected']}, stopped={r['stopped']}")
        for tick, msg in r["events"][:4]:
            print(f"     op {tick}: {msg}")
    print("\nTrusted night-time backup scan (no attack) against the defended configurations:\n")
    for cfg in CONFIGS[2:]:
        _, killed = legit_trial(cfg, 1, "backup")
        print(f"[{cfg.name}] backup agent {'KILLED (false positive)' if killed else 'allowed'}")
    print("\nRun `python run.py bench` for the full evaluation.")


def bench():
    rows = []
    print(f"Benchmark: {TRIALS} trials per cell, 60 real files + decoys per trial, "
          "attacks spread over 24 h\n")
    print(f"{'config':<20}{'attack':<8}{'damaged %':>10}{'detected %':>12}{'stopped %':>11}{'detect @op':>12}")
    print("-" * 73)
    print("Note: ext assumes the attacker knows the original document extensions. "
          "L1 removes those extensions, so ext skipping files is an expected "
          "known-name failure, not a simulator artifact. spoof is DFS ransomware "
          "running under the trusted backup agent's identity.\n")
    for cfg in CONFIGS:
        for mode in ATTACKS:
            trials = [one_trial(cfg, mode, s) for s in range(TRIALS)]
            dmg = sum(t["damaged_pct"] for t in trials) / TRIALS
            det = 100 * sum(t["detected"] for t in trials) / TRIALS
            stp = 100 * sum(t["stopped"] for t in trials) / TRIALS
            ticks = [t["detect_ops"] for t in trials if t["detect_ops"]]
            avg_tick = sum(ticks) / len(ticks) if ticks else None
            rows.append([cfg.name, mode, round(dmg, 1), round(det, 1), round(stp, 1),
                         round(avg_tick, 1) if avg_tick else ""])
            print(f"{cfg.name:<20}{mode:<8}{dmg:>10.1f}{det:>12.1f}{stp:>11.1f}"
                  f"{(f'{avg_tick:.0f}' if avg_tick else '-'):>12}")
        print()

    # false positives on benign workloads (no attacker present)
    fp_rows = []
    print("False-positive kills on benign workloads (no attacker):")
    print(f"  {'config':<20}{'user (10:00)':>14}{'backup (02:00)':>16}")
    for cfg in CONFIGS[2:]:
        fp = {}
        for workload in WORKLOADS:
            killed = [legit_trial(cfg, s, workload)[1] for s in range(TRIALS)]
            fp[workload] = 100 * sum(killed) / TRIALS
            fp_rows.append([cfg.name, workload, fp[workload]])
        print(f"  {cfg.name:<20}{fp['user']:>13.0f}%{fp['backup']:>15.0f}%")

    # overhead on the normal user workload
    base_cfg, full_cfg = CONFIGS[0], CONFIGS[-1]
    base_t = [legit_trial(base_cfg, s)[0] for s in range(10)]
    full_t = [legit_trial(full_cfg, s)[0] for s in range(10)]
    b, f = sum(base_t) / len(base_t), sum(full_t) / len(full_t)
    print(f"\nNormal-user workload (1000 ops): time baseline {b*1000:.0f} ms vs "
          f"{full_cfg.name} {f*1000:.0f} ms  (overhead {100*(f-b)/b:.0f}%)")

    with open("results.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["config", "attack", "damaged_pct", "detected_pct", "stopped_pct", "detect_op"])
        w.writerows(rows)
    with open("results_fp.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["config", "workload", "false_positive_kill_pct"])
        w.writerows(fp_rows)
    print("\nSaved results.csv and results_fp.csv")

    try:
        plot(rows, fp_rows)
        print("Saved results.png")
    except ImportError:
        print("(install matplotlib for a chart: pip install matplotlib)")


# categorical slots 1-5 of the reference palette, fixed order: color follows the config
CONFIG_COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]


def plot(rows, fp_rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ink, muted, grid = "#0b0b0b", "#52514e", "#e4e3df"
    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(12, 4.8), gridspec_kw={"width_ratios": [3, 1.3]})
    width = 0.8 / len(CONFIGS)
    for i, cfg in enumerate(CONFIGS):
        vals = [r[2] for r in rows if r[0] == cfg.name]
        xs = [x + (i - (len(CONFIGS) - 1) / 2) * width for x in range(len(ATTACKS))]
        ax1.bar(xs, vals, width * 0.9, label=cfg.name, color=CONFIG_COLORS[i])
    ax1.set_xticks(range(len(ATTACKS)))
    ax1.set_xticklabels(ATTACKS)
    ax1.set_ylabel("files damaged (%)", color=muted)
    ax1.set_xlabel("attacker traversal mode", color=muted)
    ax1.set_title("Ransomware damage by defense configuration", color=ink, loc="left")

    defended = CONFIGS[2:]
    workloads = list(WORKLOADS)
    width2 = 0.8 / len(defended)
    for i, cfg in enumerate(defended):
        vals = [r[2] for r in fp_rows if r[0] == cfg.name]
        xs = [x + (i - (len(defended) - 1) / 2) * width2 for x in range(len(workloads))]
        bars = ax2.bar(xs, vals, width2 * 0.9, color=CONFIG_COLORS[CONFIGS.index(cfg)])
        ax2.bar_label(bars, fmt="%.0f%%", fontsize=8, color=muted)
    ax2.set_xticks(range(len(workloads)))
    ax2.set_xticklabels(["normal user\n(10:00)", "backup agent\n(02:00)"])
    ax2.set_ylabel("false-positive kills (%)", color=muted)
    ax2.set_ylim(0, 110)
    ax2.set_title("Benign workloads killed", color=ink, loc="left")

    for ax in (ax1, ax2):
        ax.spines[["top", "right"]].set_visible(False)
        ax.spines[["left", "bottom"]].set_color(grid)
        ax.tick_params(colors=muted)
        ax.yaxis.grid(True, color=grid, linewidth=0.8)
        ax.set_axisbelow(True)
    fig.legend(*ax1.get_legend_handles_labels(), loc="lower center", ncol=len(CONFIGS),
               frameon=False, labelcolor=ink)
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    fig.savefig("results.png", dpi=150)


if __name__ == "__main__":
    {"demo": demo, "bench": bench}.get(
        sys.argv[1] if len(sys.argv) > 1 else "demo", demo
    )()
