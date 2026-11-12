"""Bounded sequential result reuse over one actual sealed HIA native image.

This module is a research executor, not an authority issuer. Its resident quota
covers fixed 64-byte payload slots; Python metadata, the mapped ELF, and native
transient allocations are separate costs. No persistent foreign-buffer ABI or
matrix-packing implementation is implied by this scalar result-cache profile.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import os
from pathlib import Path
import struct
import time

from .hia_native_differential import _pin_native_artifact

MAX_SIZE = 1_048_576
ENTRY = struct.Struct("<32sQIIQQ")
assert ENTRY.size == 64


class CacheError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CacheError(message)


def bounded_int(value, low, high, label):
    require(type(value) is int and low <= value <= high, label)
    return value


def oracle(n, seed):
    """Independent period-256 arithmetic, not generated HIA or cached output."""
    bounded_int(n, 0, MAX_SIZE, "size outside the registered domain")
    bounded_int(seed, 0, 0xffffffff, "seed outside u32")
    blocks, tail = divmod(n, 256)
    return blocks * 32640 + sum((seed + i) % 256 for i in range(tail))


class NativeKernel:
    def __init__(self, artifact, expected_sha256):
        started = time.monotonic_ns()
        require(type(expected_sha256) is str and len(expected_sha256) == 64
                and set(expected_sha256) <= set("0123456789abcdef"), "bad native identity")
        image, _, fd = _pin_native_artifact(Path(artifact))
        try:
            self.sha256 = sha256(image).hexdigest()
            require(self.sha256 == expected_sha256, "native image identity mismatch")
            self.library = ctypes.CDLL("/proc/self/fd/" + str(fd), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            self.function = self.library.calculate
            self.function.argtypes = (ctypes.c_size_t, ctypes.c_uint32)
            self.function.restype = ctypes.c_uint64
        except BaseException:
            os.close(fd)
            raise
        # Retain the descriptor while dlopen retains this path. Reusing its fd
        # for a different image could otherwise hit a loader pathname cache.
        # This bounded study loads one image per process; process exit releases it.
        self.sealed_fd = fd
        self.load_ns = time.monotonic_ns() - started
        self.calls = 0
        self.native_ns = 0

    def evaluate(self, n, seed):
        bounded_int(n, 0, MAX_SIZE, "size outside the registered domain")
        bounded_int(seed, 0, 0xffffffff, "seed outside u32")
        before = time.monotonic_ns()
        result = int(self.function(n, seed))
        elapsed = time.monotonic_ns() - before
        self.calls += 1
        self.native_ns += elapsed
        require(result < (1 << 63), "HIA returned a refusal or allocation error")
        require(result == oracle(n, seed), "actual HIA output disagrees with independent arithmetic")
        return result


class ResultCache:
    def __init__(self, kernel, n, seeds, *, slots=2, generation=1):
        self.n = bounded_int(n, 0, MAX_SIZE, "size")
        require(type(seeds) is list and 1 <= len(seeds) <= 8, "seed list")
        self.seeds = [bounded_int(v, 0, 0xffffffff, "seed") for v in seeds]
        self.epochs = [1] * len(seeds)
        self.slots = bounded_int(slots, 0, len(seeds), "slot count")
        self.generation = bounded_int(generation, 1, 0xffffffffffffffff, "generation")
        self.kernel = kernel
        require(type(kernel.sha256) is str and len(kernel.sha256) == 64, "kernel hash")
        self.code = bytes.fromhex(kernel.sha256)
        self.arena = bytearray(self.slots * ENTRY.size)
        self.owners = [None] * self.slots
        self.closed = False
        self.preparations = self.reuses = self.invalidations = self.retirements = 0
        self.executions = self.direct_calls = 0

    def _check(self, ident, epoch):
        require(not self.closed, "cache is closed")
        bounded_int(ident, 0, len(self.seeds) - 1, "object id")
        require(type(epoch) is int and epoch == self.epochs[ident], "stale object epoch")

    def _slot(self, ident):
        return next((i for i, owner in enumerate(self.owners) if owner == ident), None)

    def _record(self, ident, result):
        return ENTRY.pack(self.code, self.n, self.seeds[ident], self.epochs[ident], self.generation, result)

    def ready(self):
        return sorted(i for i in self.owners if i is not None)

    def prepare(self, ident, epoch):
        self._check(ident, epoch)
        slot = self._slot(ident)
        if slot is not None:
            self.read(ident, epoch)
            return False
        require(None in self.owners, "resident payload quota exceeded")
        generation, seed = self.generation, self.seeds[ident]
        result = self.kernel.evaluate(self.n, seed)
        # Recheck after the real call; sequential generation/epoch may not drift.
        self._check(ident, epoch)
        require(generation == self.generation and seed == self.seeds[ident], "state changed during preparation")
        slot = self.owners.index(None)
        self.arena[slot*ENTRY.size:(slot+1)*ENTRY.size] = self._record(ident, result)
        self.owners[slot] = ident
        self.preparations += 1
        return True

    def read(self, ident, epoch):
        self._check(ident, epoch)
        slot = self._slot(ident)
        require(slot is not None, "result is not resident")
        row = ENTRY.unpack_from(self.arena, slot * ENTRY.size)
        expected = (self.code, self.n, self.seeds[ident], epoch, self.generation)
        require(row[:5] == expected, "resident key, code identity, or generation differs")
        require(row[5] == oracle(self.n, self.seeds[ident]), "resident value corruption")
        self.reuses += 1
        return row[5]

    def run(self, ident, epoch, dispatch):
        self._check(ident, epoch)
        require(type(dispatch) is str and dispatch in ("direct", "cached"), "unknown executor dispatch")
        if dispatch == "cached":
            result = self.read(ident, epoch)
        else:
            result = self.kernel.evaluate(self.n, self.seeds[ident])
            self.direct_calls += 1
        require(result == oracle(self.n, self.seeds[ident]), "final output mismatch")
        self.executions += 1
        return result

    def retire(self, ident, epoch):
        self._check(ident, epoch)
        slot = self._slot(ident)
        if slot is None:
            return False
        self.arena[slot*ENTRY.size:(slot+1)*ENTRY.size] = bytes(ENTRY.size)
        self.owners[slot] = None
        self.retirements += 1
        return True

    def mutate(self, ident, epoch, seed):
        self._check(ident, self.epochs[ident] if type(ident) is int and 0 <= ident < len(self.epochs) else -1)
        bounded_int(epoch, self.epochs[ident] + 1, 0xffffffff, "nonmonotonic data epoch")
        bounded_int(seed, 0, 0xffffffff, "new seed")
        invalidated = self.retire(ident, self.epochs[ident])
        self.seeds[ident], self.epochs[ident] = seed, epoch
        self.invalidations += int(invalidated)
        return invalidated

    def advance_generation(self, generation):
        require(not self.closed, "cache is closed")
        bounded_int(generation, self.generation + 1, 0xffffffffffffffff, "nonmonotonic generation")
        for ident in self.ready():
            self.retire(ident, self.epochs[ident])
        self.generation = generation

    def snapshot(self):
        return {"generation": self.generation, "n": self.n, "seeds": list(self.seeds),
                "epochs": list(self.epochs), "ready": self.ready(), "closed": self.closed,
                "resident_payload_bytes": len(self.ready()) * ENTRY.size,
                "allocated_payload_bytes": len(self.arena), "quota_payload_bytes": self.slots * ENTRY.size,
                "preparations": self.preparations, "reuses": self.reuses,
                "invalidations": self.invalidations, "retirements": self.retirements,
                "executions": self.executions, "direct_calls": self.direct_calls}

    def close(self):
        if self.closed:
            return
        for ident in self.ready():
            self.retire(ident, self.epochs[ident])
        self.arena.clear()
        self.closed = True
