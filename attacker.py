"""
SAFE ransomware simulator. It only touches files inside the test workspace and
only through VirtualFS. No real malware is used anywhere in this project.

Traversal modes (from the slide-deck gap analysis):
  dfs    depth-first walk, encrypts everything
  bfs    breadth-first walk, encrypts everything
  random random directory / file order, encrypts everything
  ext    depth-first, only encrypts files with known document extensions
"""
import hashlib
import os
import random
from collections import deque

from mtd import KNOWN_EXT, ProcessSuspended

MODES = ["dfs", "bfs", "random", "ext"]


def encrypt(data: bytes, key: bytes) -> bytes:
    """Toy stream cipher (SHA-256 counter keystream). Output looks random."""
    stream = bytearray()
    ctr = 0
    while len(stream) < len(data):
        stream += hashlib.sha256(key + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return bytes(a ^ b for a, b in zip(data, stream))


class Attacker:
    def __init__(self, vfs, mode="dfs", seed=0, pid="attacker"):
        self.vfs, self.mode, self.pid = vfs, mode, pid
        self.rng = random.Random(seed)
        self.stopped = False    # stopped by the kill-switch

    def run(self):
        key = self.rng.randbytes(16)
        frontier = deque([""])
        try:
            while frontier:
                if self.mode == "bfs":
                    rel = frontier.popleft()
                elif self.mode == "random":
                    i = self.rng.randrange(len(frontier))
                    frontier[i], frontier[-1] = frontier[-1], frontier[i]
                    rel = frontier.pop()
                else:                                   # dfs and ext
                    rel = frontier.pop()
                try:
                    entries = self.vfs.listdir(self.pid, rel)
                except FileNotFoundError:
                    continue
                if self.mode == "random":
                    self.rng.shuffle(entries)
                for name, is_dir in entries:
                    child = (rel + "/" if rel else "") + name
                    if is_dir:
                        frontier.append(child)
                        continue
                    if name.endswith(".locked"):
                        continue
                    if self.mode == "ext" and os.path.splitext(name)[1].lower() not in KNOWN_EXT:
                        continue
                    try:
                        data = self.vfs.read(self.pid, child)
                        self.vfs.write(self.pid, child, encrypt(data, key))
                        self.vfs.rename(self.pid, child, child + ".locked")
                    except FileNotFoundError:
                        pass            # name already changed by MTD: stale knowledge
        except ProcessSuspended:
            self.stopped = True
        return {"stopped": self.stopped}
