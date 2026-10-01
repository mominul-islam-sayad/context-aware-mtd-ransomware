# A Context-Aware, Multi-Layered Moving Target Defense Architecture for Ransomware Mitigation

This is a small Computer Security course project with two deliberately separate
parts:

1. **Research simulation:** the original `VirtualFS` experiment, which makes
   reproducible L1-L4 benchmark measurements without touching real files.
2. **Windows live prototype:** a safe Tkinter demonstration that monitors only
   generated files under `windows_demo/sandbox/` and stops only its own harmless
   attack subprocess.

It is not production ransomware protection and it does not use real malware.

## Security problem and MTD idea

Ransomware benefits from knowing where valuable files are and from being able to
modify many files quickly. Moving Target Defense reduces that advantage by
changing the attack surface while observing behavior. This project demonstrates:

- **L1:** randomized internal names and harmless header mutation in the research
  simulation.
- **L2:** multi-depth decoys/honeyfiles.
- **L3:** an explainable rolling-window suspicion score that shortens the mutation
  interval as activity becomes more aggressive.
- **L4:** a kill-switch that suspends the simulated attacker in the research
  layer, or terminates only the live-demo subprocess.
- **Context awareness (CTX):** every suspicious event is weighted by its
  context instead of being counted the same way everywhere:
  - **Who** acted: an allow-listed tool (the backup agent) weighs 0.2x and may
    *read* a decoy without being killed; writing or renaming a decoy is always
    fatal, and its stale accesses caused by MTD renames are not scored.
  - **What** was touched: sensitive documents (budget, invoice, client,
    policy) weigh 1.5x.
  - **When** it happened: off-hours activity (outside 08:00-18:59) weighs 1.5x
    and makes MTD rotate 1.5x faster; activity while the user is idle weighs
    1.25x.

  The live demo applies the *what* and *when* parts (sensitive files and
  off-hours raise the rolling score and are shown in the log and dashboard).

## Installation on Windows

Install standard Windows CPython 3.9 or newer (including Tcl/Tk) and make sure
`py` or `python` works in PowerShell. From this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

After activation, the commands below can also be run explicitly through
`.venv\Scripts\python.exe` if the Windows `py` launcher is not configured.

`watchdog` is optional. If it is unavailable, the live demo automatically uses
its standard-library polling monitor. No administrator privileges, Linux, WSL,
Docker, or external services are required.

## Run the original research simulation

```powershell
python run.py demo
```

The safe research attacker supports `dfs`, `bfs`, `random`, and `ext` traversal
modes. The `ext` mode is intentionally documented: it assumes the attacker
knows the original document extensions. After L1 randomizes names/extensions,
that attacker skips files, so its low damage is an expected stale-knowledge
result rather than a hidden benchmark artifact.

## Run the benchmark

```powershell
python run.py bench
```

The benchmark compares five configurations (baseline, L1, static L1+L2+L4,
FULL adaptive, FULL context-aware) against five attacks (`dfs`, `bfs`,
`random`, `ext`, and `spoof`, which is DFS ransomware running under the trusted
backup agent's identity). Attack trials are spread over the whole day so the
time-of-day context is exercised. Two benign workloads measure false positives:
a normal user at 10:00 and a trusted backup agent scanning the disk at 02:00.
The benchmark uses operation ticks rather than wall-clock time so trials are
reproducible. Outputs: `results.csv`, `results_fp.csv`, and `results.png`.

Results (20 trials per cell):

| Configuration | Damaged (dfs/bfs/random) | Detected at op | Spoof damage | Backup agent killed |
|---|---|---|---|---|
| baseline | 100% | - | 100% | n/a |
| L1+L2+L4 static | 7.6-8.9% | 16-19 | 7.6% | 100% |
| FULL adaptive | 5.6-6.5% | 12-13 | 5.7% | 100% |
| **FULL context-aware** | **3.4-4.0%** | **8-10** | 10.2% | **0%** |

All defended configurations stop 100% of attacks and kill 0% of normal-user
workloads. Context awareness removes the backup false positive and lowers
damage; the cost is the `spoof` case, where malware that hijacks a trusted
identity is only caught when it writes a decoy (still stopped 100%, but with
10.2% damage).

## Launch the Windows live demo

```powershell
python -m windows_demo.app
```

The convenience command below is equivalent:

```powershell
python run.py live
```

The GUI buttons are:

- **Initialize Sandbox:** creates 10 synthetic protected files and 4 decoys.
- **Start Protection / Stop Protection:** starts or stops monitoring only the
  project sandbox.
- **Simulate Attack:** starts `windows_demo/live_attacker.py` as a subprocess.
  It does not start protection; with protection stopped the attack runs
  undefended and its `.locked_demo` renames remain until **Reset Sandbox**.
- **Reset Sandbox:** stops protection/attacker, deletes only the validated demo
  sandbox, and recreates clean files.
- **Open Log:** opens `logs/live_demo.log`.

For a visible demonstration, initialize the sandbox, start protection, perform
a normal edit inside `windows_demo/sandbox/protected/`, then click **Simulate
Attack**. The harmless subprocess rapidly modifies/renames generated files and
then modifies a decoy. The monitor reports the rolling score, raises the threat
level, triggers a safe mutation, logs `DECOY TRIGGERED`, and terminates only the
subprocess it started.

## Live demo safety design

All live paths are resolved and checked to remain below
`windows_demo/sandbox/`. The demo never monitors Documents, Desktop, Downloads,
Windows directories, external drives, network shares, or arbitrary user paths.
Defender-generated renames are wrapped in a short thread-safe suppression window
so they are not scored as attacker activity. The monitor reports created,
modified, moved, and deleted files and maintains a three-second rolling window.

The live score is intentionally simple:

- small isolated activity: LOW;
- rapid modifications across several files: MEDIUM;
- repeated rapid moves and broad activity: HIGH;
- decoy modification, or the critical score threshold: CRITICAL.

The thresholds live in `windows_demo/demo_config.py` so they are easy to explain
and change for a classroom demonstration.

## Tests

The tests use Python's standard `unittest` module and cover path containment,
file/decoy generation, scoring, escalation, mutation, reset, monitoring, the
attacker subprocess, the kill-switch, and the context layer (who/what/when
weights, off-hours mutation speed-up, trusted backup allowed, unknown and
spoofed attackers still stopped):

```powershell
py -m unittest discover -s tests -v
```

## Project structure

```text
mtd_project/
├── mtd.py                    # original VirtualFS L1-L4 simulation
├── attacker.py               # original safe research attacker
├── run.py                    # demo/benchmark (+ benign user/backup workloads) + live command
├── results.csv               # benchmark output: attacks
├── results_fp.csv            # benchmark output: false positives
├── results.png               # benchmark chart
├── windows_demo/
│   ├── app.py                # Tkinter dashboard and controller
│   ├── demo_config.py        # paths and score/mutation thresholds
│   ├── live_attacker.py      # harmless subprocess attacker
│   ├── live_mtd.py           # sandbox generation and file-level MTD
│   ├── monitor.py            # watchdog backend + polling fallback
│   └── sandbox/               # generated files only; safe to reset
├── logs/live_demo.log       # live event log
├── tests/                    # live-demo tests + context-simulation tests
├── requirements.txt
└── README.md
```

## Five-minute teacher demonstration

1. Run `python -m windows_demo.app`.
2. Click **Initialize Sandbox** and show the protected and decoy counts.
3. Click **Start Protection**; make one harmless edit to a protected sample.
4. Point out that the status remains LOW and no process is killed.
5. Click **Simulate Attack**.
6. Show rapid file events, MEDIUM/HIGH scoring, and an MTD mutation.
7. Show `DECOY TRIGGERED`, `CRITICAL THREAT DETECTED`, `KILL-SWITCH ACTIVATED`,
   `ATTACK SIMULATOR TERMINATED`, and `ATTACK BLOCKED` in the live log.
8. Click **Open Log** to show the persisted timestamped log.
9. Click **Reset Sandbox** and show that counts and threat state return to the
   initial state.

## Limitations and future work

The research layer is a user-space model: real processes could bypass it
because they do not have to use `VirtualFS`. The live layer is a small Windows
prototype that monitors file changes, not file-open events, so the attacker
intentionally writes to a decoy. File-change events do not say which process
made them, so the live demo cannot apply the *who* (process trust) context;
that part exists only in the research simulation, where trust is a fixed
allow-list of process ids rather than code-signing verification. Polling/watchdog timing is not kernel-grade,
the score is heuristic, the sample data is synthetic, and the kill-switch only
controls the subprocess started by this demo. There is no network defense,
authentication, kernel driver, machine learning, or enterprise policy engine.

Possible future work includes stronger Windows event integration (process
attribution for the live context layer), signed-binary trust instead of a
process-id allow-list, durable metadata recovery, richer benign-workload calibration, and a controlled lab
comparison with additional safe attack patterns.
