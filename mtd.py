"""
Context-aware, multi-layered Moving Target Defense (MTD) for ransomware mitigation.
User-space SIMULATION: every file access goes through VirtualFS, which applies
four defense layers plus a context layer. Pure standard library, works on
Windows/Linux/Mac.

  L1  extension + magic-byte mutation
  L2  multi-depth decoy (honeyfile) traps
  L3  adaptive mutation rate from write-entropy / stale-access suspicion
  L4  kill-switch: suspend the offending process on decoy touch / high suspicion
  CTX context awareness: every suspicious event is weighted by WHO acted
      (trusted tool vs unknown process), WHAT was touched (sensitive file) and
      WHEN (off-hours, no recent user activity); off-hours also speed up MTD
"""
import hashlib
import math
import os
import random
from collections import Counter

KNOWN_EXT = [".docx", ".pdf", ".xlsx", ".txt", ".csv", ".pptx", ".jpg"]
DECOY_STEMS = ["passwords", "budget_2025", "payroll", "backup_keys",
               "customers", "tax_return", "contracts"]
WORDS = ("alpha report budget client invoice meeting project data summary "
         "quarter review plan notes draft team policy").split()
TOKEN_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"

# ---------- context model ----------
SENSITIVE_STEMS = {"budget", "invoice", "client", "policy"}   # high-value documents
BUSINESS_HOURS = range(8, 19)        # 08:00-18:59 counts as normal working time
TRUSTED_WEIGHT = 0.2                 # allow-listed tool (backup agent)
SENSITIVE_WEIGHT = 1.5
OFF_HOURS_WEIGHT = 1.5
USER_IDLE_WEIGHT = 1.25              # nobody is at the keyboard
OFF_HOURS_MUTATION_SPEEDUP = 1.5     # MTD rotates faster at night


class ProcessSuspended(Exception):
    """Raised when the kill-switch (L4) has suspended the calling process."""


def shannon(data: bytes) -> float:
    """Shannon entropy in bits/byte (text ~4.3, encrypted data ~7.9)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def text_blob(rng, words=300) -> bytes:
    return " ".join(rng.choice(WORDS) for _ in range(words)).encode()


def build_workspace(root, seed=0, depth=3, branch=2, files_per_dir=4):
    """Create a test directory tree. Returns {logical_path: sha256 of original}."""
    rng = random.Random(seed)
    files = {}

    def walk(rel, level):
        os.makedirs(os.path.join(root, *rel.split("/")) if rel else root, exist_ok=True)
        for _ in range(files_per_dir):
            name = f"{rng.choice(WORDS)}_{len(files)}{rng.choice(KNOWN_EXT)}"
            path = (rel + "/" if rel else "") + name
            data = text_blob(rng)
            with open(os.path.join(root, *path.split("/")), "wb") as f:
                f.write(data)
            files[path] = hashlib.sha256(data).hexdigest()
        if level < depth:
            for i in range(branch):
                walk((rel + "/" if rel else "") + f"d{i}", level + 1)

    walk("", 0)
    return files


class Config:
    def __init__(self, name, l1=False, l2=False, l3=False, l4=False, ctx=False,
                 base=60, min_iv=8, kill=5.0, n_decoys=10, window=80,
                 trusted=("backup",)):
        self.name, self.l1, self.l2, self.l3, self.l4 = name, l1, l2, l3, l4
        self.ctx = ctx            # context-aware weighting (who / what / when)
        self.trusted = set(trusted)  # allow-listed process ids
        self.base = base          # normal mutation interval (in operations)
        self.min_iv = min_iv      # fastest interval under attack
        self.kill = kill          # L3 suspicion score that triggers the kill-switch
        self.n_decoys = n_decoys
        self.window = window      # suspicion memory (in operations)


CONFIGS = [
    Config("baseline"),
    Config("L1", l1=True),
    Config("L1+L2+L4 static", l1=True, l2=True, l4=True),
    Config("FULL adaptive", l1=True, l2=True, l3=True, l4=True),
    Config("FULL context-aware", l1=True, l2=True, l3=True, l4=True, ctx=True),
]


class VirtualFS:
    def __init__(self, root, files, cfg, seed=0, hour=10):
        self.root, self.cfg = root, cfg
        self.rng = random.Random(seed)
        self.hour = hour                   # simulated wall-clock hour (0-23)
        self.last_user = None              # tick of the last legitimate-user operation
        self.map = {k: k for k in files}   # logical path -> current physical path
        self.keys = {}                     # logical path -> header scramble key
        self.decoys = set()
        self.tick = 0                      # one tick per filesystem operation
        self.last_mut = 0
        self.mutations = 0
        self.hits = {}                     # pid -> [(tick, weight)]
        self.suspended = set()
        self.detect_tick = {}
        self.events = []
        self.dirs = [os.path.relpath(d, root).replace(os.sep, "/") for d, _, _ in os.walk(root)]
        self.dirs = ["" if d == "." else d for d in self.dirs]
        if cfg.l1 or cfg.l2:
            self._mutate()

    # ---------- helpers ----------
    def _p(self, rel):
        return os.path.join(self.root, *rel.split("/")) if rel else self.root

    def _token(self):
        return "".join(self.rng.choice(TOKEN_CHARS) for _ in range(5))

    def _xor(self, logical, data):
        key = self.keys.get(logical)
        if not key:
            return data
        return bytes(a ^ b for a, b in zip(data[:8], key)) + data[8:]

    def _log(self, msg):
        self.events.append((self.tick, msg))

    # ---------- CTX: context awareness ----------
    def _off_hours(self):
        return self.hour not in BUSINESS_HOURS

    def _sensitive(self, rel):
        name = rel.rsplit("/", 1)[-1]
        return name.split("_", 1)[0] in SENSITIVE_STEMS   # stem survives L1 renames

    def _user_idle(self):
        return self.last_user is None or self.tick - self.last_user > self.cfg.window

    def _context(self, pid, rel=None):
        """Weight for one suspicious event: who acted, on what, and when."""
        if not self.cfg.ctx:
            return 1.0
        weight = 1.0
        if pid in self.cfg.trusted:
            weight *= TRUSTED_WEIGHT
        if rel is not None and self._sensitive(rel):
            weight *= SENSITIVE_WEIGHT
        if self._off_hours():
            weight *= OFF_HOURS_WEIGHT
        if self._user_idle():
            weight *= USER_IDLE_WEIGHT
        return weight

    # ---------- L3: suspicion ----------
    def _susp(self, pid):
        lo = self.tick - self.cfg.window
        return sum(w for t, w in self.hits.get(pid, []) if t > lo)

    def _interval(self):
        base = self.cfg.base
        if self.cfg.ctx and self._off_hours():
            base = int(base / OFF_HOURS_MUTATION_SPEEDUP)
        if not self.cfg.l3:
            return base
        worst = max((self._susp(p) for p in self.hits), default=0.0)
        return max(self.cfg.min_iv, int(base / (1 + worst)))

    def _bump(self, pid, weight, why, rel=None):
        if why == "stale" and (pid == "user" or (self.cfg.ctx and pid in self.cfg.trusted)):
            return    # a trusted scanner racing MTD renames is expected, not suspicious
        weight *= self._context(pid, rel)
        self.hits.setdefault(pid, []).append((self.tick, weight))
        if self.cfg.l3 and self._susp(pid) >= self.cfg.kill:
            self._detect(pid, f"suspicion {self._susp(pid):.1f} >= {self.cfg.kill}")

    # ---------- L4: detection / kill-switch ----------
    def _detect(self, pid, reason):
        self.detect_tick.setdefault(pid, self.tick)
        self._log(f"DETECT {pid}: {reason}")
        if self.cfg.l4:
            self.suspended.add(pid)
            self._log(f"KILL-SWITCH suspended {pid}")
            raise ProcessSuspended(pid)

    # ---------- gate on every operation ----------
    def _gate(self, pid, rel=None, op="read"):
        if pid in self.suspended:
            raise ProcessSuspended(pid)
        self.tick += 1
        if (self.cfg.l1 or self.cfg.l2) and self.tick - self.last_mut >= self._interval():
            self._mutate()
        if rel is not None and rel in self.decoys and pid != "user":
            if self.cfg.ctx and pid in self.cfg.trusted and op == "read":
                # A trusted backup agent scanning the disk may read a honeyfile.
                # It is logged and scored, but only a write/rename is fatal.
                self._log(f"CONTEXT {pid}: trusted read of decoy {rel}")
                self._bump(pid, 1.0, "decoy-read", rel)
            else:
                self._detect(pid, f"decoy touched: {rel}")

    def _score_write(self, pid, data, rel=None):
        if shannon(data) >= 7.0:          # looks encrypted/compressed
            self._bump(pid, 1.0, "entropy", rel)

    # ---------- L1 + L2: mutation ----------
    def _mutate(self):
        self.mutations += 1
        self.last_mut = self.tick
        if self.cfg.l1:
            for logical, rel in list(self.map.items()):
                if rel.endswith(".locked"):
                    continue
                d = rel.rpartition("/")[0]
                stem = logical.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                new = (d + "/" if d else "") + stem + "." + self._token()
                try:
                    with open(self._p(rel), "r+b") as f:
                        head = f.read(8)
                        head = self._xor(logical, head)             # undo old header scramble
                        self.keys[logical] = self.rng.randbytes(8)  # new header scramble
                        f.seek(0)
                        f.write(self._xor(logical, head))
                except FileNotFoundError:
                    continue
                os.replace(self._p(rel), self._p(new))
                self.map[logical] = new
        if self.cfg.l2:
            for rel in self.decoys:
                try:
                    os.remove(self._p(rel))
                except FileNotFoundError:
                    pass
            self.decoys.clear()
            for _ in range(self.cfg.n_decoys):        # new random depths every time
                d = self.rng.choice(self.dirs)
                ext = "." + self._token() if self.cfg.l1 else self.rng.choice(KNOWN_EXT)
                name = f"{self.rng.choice(DECOY_STEMS)}_{self.rng.randint(100, 999)}{ext}"
                rel = (d + "/" if d else "") + name
                with open(self._p(rel), "wb") as f:
                    f.write(text_blob(self.rng, 150))
                self.decoys.add(rel)

    # ---------- API used by ANY process (attacker sees physical names) ----------
    def listdir(self, pid, rel=""):
        self._gate(pid)
        return sorted((e.name, e.is_dir()) for e in os.scandir(self._p(rel)))

    def read(self, pid, rel):
        self._gate(pid, rel, "read")
        if not os.path.exists(self._p(rel)):
            self._stale(pid, rel)
        with open(self._p(rel), "rb") as f:
            return f.read()

    def write(self, pid, rel, data):
        self._gate(pid, rel, "write")
        if not os.path.exists(self._p(rel)):
            self._stale(pid, rel)
        with open(self._p(rel), "wb") as f:
            f.write(data)
        self._score_write(pid, data, rel)

    def rename(self, pid, old, new):
        self._gate(pid, old, "rename")
        if not os.path.exists(self._p(old)):
            self._stale(pid, old)
        os.replace(self._p(old), self._p(new))
        for logical, phys in self.map.items():
            if phys == old:
                self.map[logical] = new

    def _stale(self, pid, rel=None):
        """Access to a name that no longer exists = attacker using old knowledge."""
        self._bump(pid, 0.5, "stale", rel)
        raise FileNotFoundError

    # ---------- API for the legitimate user (uses stable logical names) ----------
    def user_read(self, logical):
        self._gate("user")
        self.last_user = self.tick
        with open(self._p(self.map[logical]), "rb") as f:
            return self._xor(logical, f.read())

    def user_write(self, logical, data):
        self._gate("user")
        self.last_user = self.tick
        with open(self._p(self.map[logical]), "wb") as f:
            f.write(self._xor(logical, data))
        self._score_write("user", data, logical)

    # ---------- evaluation ----------
    def audit(self, originals):
        """Number of real files whose content no longer matches the original."""
        damaged = 0
        for logical, h in originals.items():
            try:
                with open(self._p(self.map[logical]), "rb") as f:
                    ok = hashlib.sha256(self._xor(logical, f.read())).hexdigest() == h
            except FileNotFoundError:
                ok = False
            damaged += not ok
        return damaged
