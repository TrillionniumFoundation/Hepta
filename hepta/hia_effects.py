"""The source checker's effect/resource decisions are implemented in HIA.

``native/effect_closure.hiaasm`` is the single algorithmic authority. This
module transports function/edge records and reconstructs diagnostic values;
it contains no effect fixed-point or resource-conflict implementation.

Ordinary Linux x86-64 checks execute the HIA program natively. The existing
Python Core assembler/direct emitter and system linker are still bootstrap
dependencies for its first in-process build. Other hosts, hosts without a
linker, and graphs outside the existing 1-MiB native byte ABI interpret the
same HIA source. A native failure never retries through an alternative path.
Neither execution route constitutes a complete self-hosted source checker.
"""
from __future__ import annotations

import ctypes
from functools import lru_cache
from hashlib import sha256
import os
from pathlib import Path
import platform
import shutil
import struct
import tempfile
import threading
from typing import NamedTuple


SOURCE = Path(__file__).with_name("native") / "effect_closure.hiaasm"
MAGIC = 3550613244766531912
EFFECT_ORDER = ("alloc", "block", "ffi", "io", "panic", "spawn", "unsafe", "write")
RESOURCE_ORDER = (("heap_allocations", "alloc"), ("may_block", "block"), ("may_spawn", "spawn"))
NATIVE_MAX_EXTENT = 1 << 20  # The pre-existing borrowed-byte export boundary.
_BUILD_LOCK = threading.Lock()
_NATIVE = None


class EffectDecision(NamedTuple):
    inferred: int
    missing: int
    worker_forbidden: int
    resource_conflicts: int


def effect_mask(effects) -> int:
    """Encode the existing eight effect names; unknown declarations stay local."""
    return sum(1 << index for index, name in enumerate(EFFECT_ORDER) if name in effects)


def effect_names(mask: int) -> set[str]:
    return {name for index, name in enumerate(EFFECT_ORDER) if mask & (1 << index)}


@lru_cache(maxsize=1)
def _program():
    # The installed package, including its HIA source, is a process-lifetime
    # snapshot just like imported Python modules. An upgrade requires restart.
    from .hia_agent_assembly import assemble_program
    source = SOURCE.read_bytes()
    return assemble_program(source), source


class _NativeEffects:
    """One retained sealed code owner; all calls have private data buffers."""

    def __init__(self):
        import fcntl
        from .hia_program_native import emit_program_machine, compile_program_machine
        program, source = _program()
        machine = emit_program_machine(program, foreign_buffer_exports=(("f0", NATIVE_MAX_EXTENT),))
        with tempfile.TemporaryDirectory(prefix="hia-effects-") as directory:
            output = Path(directory) / "effect_closure.so"
            receipt = compile_program_machine(machine, program=program, output=output, linker="ld")
            image = output.read_bytes()
        if (receipt.get("artifact_sha256") != sha256(image).hexdigest()
                or receipt.get("artifact_bytes") != len(image)
                or receipt.get("core_sha256") != program.sha256):
            raise RuntimeError("HIA effect build receipt does not bind the captured executable")
        self.source_sha256 = sha256(source).hexdigest()
        self.image_sha256 = sha256(image).hexdigest()
        self.bootstrap_receipt = receipt
        # Keep the descriptor until process exit as well as the loader owner.
        # Reusing a /proc/self/fd/N name while dlopen retains an earlier object
        # could otherwise select the earlier object from the loader's cache.
        descriptor = os.memfd_create("hia-effect-closure", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            position = 0
            while position < len(image):
                written = os.write(descriptor, image[position:])
                if written <= 0:
                    raise OSError("short write while retaining HIA effect image")
                position += written
            fcntl.fcntl(descriptor, getattr(fcntl, "F_ADD_SEALS", 1033), 0x0f)
            if fcntl.fcntl(descriptor, getattr(fcntl, "F_GET_SEALS", 1034)) & 0x0f != 0x0f:
                raise OSError("HIA effect image was not sealed")
            library = ctypes.CDLL(f"/proc/self/fd/{descriptor}", mode=os.RTLD_LOCAL | os.RTLD_NOW)
            entry = library.f0
            entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
            entry.restype = ctypes.c_uint64
        except BaseException:
            os.close(descriptor)
            raise
        self.descriptor, self.library, self.entry = descriptor, library, entry

    def call(self, wire: bytes, output: bytearray, workspace: bytearray) -> int:
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        out = (ctypes.c_ubyte * len(output)).from_buffer(output)
        work = (ctypes.c_ubyte * len(workspace)).from_buffer(workspace)
        result = self.entry(source, len(wire), out, len(output), work, len(workspace))
        if result >> 32:
            raise RuntimeError(f"HIA effect invocation violated native byte ABI: {result >> 32}")
        return result


def _native_host() -> bool:
    return (platform.system() == "Linux" and platform.machine() == "x86_64"
            and ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_size_t) == 8
            and hasattr(os, "memfd_create"))


def _native_linker_available() -> bool:
    linker = shutil.which("ld")
    return linker is not None and Path(linker).is_file() and os.access(linker, os.X_OK)


def _native_engine():
    global _NATIVE
    with _BUILD_LOCK:
        if _NATIVE is None:
            _NATIVE = _NativeEffects()
        return _NATIVE


def _vm_call(wire: bytes, output: bytearray, workspace: bytearray) -> int:
    """Host the same verified HIA program on three distinct borrowed roots."""
    from .hia_program_runtime import _Machine, _Owner, _View
    program, _ = _program()
    # Each function is queued initially and at most once per new effect bit;
    # each edge is traversed at most nine times. The fixed HIA helpers perform
    # eight byte steps per word. 8192 ticks per input byte dominates the static
    # loop/call inventory, including admission and result publication.
    machine = _Machine(program, 65536 + 8192 * len(wire), 0, None, 16)
    roots = (_Owner(-1, bytearray(wire)), _Owner(-2, output), _Owner(-3, workspace))
    views = tuple(_View(root, index != 0) for index, root in enumerate(roots))
    values = machine.invoke(machine.functions["f0"], list(views))
    if (len(values) != 1 or type(values[0]) is not int
            or machine.owners or machine.chains or machine.loans_started != machine.loans_ended
            or bytes(roots[0].data) != wire
            or any(not root.active or not view.active or view.parent is not root
                   or view.mutable is not (index != 0)
                   for index, (root, view) in enumerate(zip(roots, views)))):
        raise RuntimeError("HIA effect VM violated its borrowed-buffer contract")
    machine.report("f0", "returned", values=values, external_roots=roots)
    return values[0]


def _invoke(wire: bytes, output: bytearray, workspace: bytearray, *, execution="auto") -> int:
    """Select an execution substrate before the call; never retry a failure."""
    _, captured_source = _program()
    if SOURCE.read_bytes() != captured_source:
        raise RuntimeError("HIA effect source changed after import; restart to bind the new package")
    if execution not in {"auto", "native", "vm"}:
        raise ValueError("unknown HIA effect execution substrate")
    eligible = (_native_host() and max(len(wire), len(output), len(workspace)) <= NATIVE_MAX_EXTENT
                and (_NATIVE is not None or _native_linker_available()))
    if execution == "native" and not eligible:
        raise ValueError("HIA effect invocation is outside the existing native byte profile")
    if execution == "native" or execution == "auto" and eligible:
        return _native_engine().call(wire, output, workspace)
    return _vm_call(wire, output, workspace)


def decide(rows, edges, *, execution="auto") -> tuple[EffectDecision, ...]:
    """Compute every effect/resource decision from raw records in HIA.

    rows=(local mask, declared mask, resource-presence mask), edges=(caller,
    callee). There is no caller-selected executable and no old-algorithm route.
    Invalid records are refused by HIA before any result bytes are published.
    """
    rows, edges = tuple(rows), tuple(edges)
    n, e = len(rows), len(edges)
    wire = bytearray(32 + 24 * n + 16 * e)
    struct.pack_into("<4Q", wire, 0, MAGIC, 1, n, e)
    for index, row in enumerate(rows):
        if (type(row) is not tuple or len(row) != 3
                or any(type(value) is not int or not 0 <= value < 1 << 64 for value in row)):
            raise ValueError("effect input record requires three u64 values")
        struct.pack_into("<3Q", wire, 32 + 24 * index, *row)
    for index, edge in enumerate(edges):
        if (type(edge) is not tuple or len(edge) != 2
                or any(type(value) is not int or not 0 <= value < 1 << 64 for value in edge)):
            raise ValueError("effect call edge requires two u64 indices")
        struct.pack_into("<2Q", wire, 32 + 24 * n + 16 * index, *edge)
    output = bytearray(32 * n)
    workspace = bytearray(96 + 32 * n + 8 * e)
    status = _invoke(bytes(wire), output, workspace, execution=execution)
    if status != 0:
        raise ValueError(f"HIA effect analysis refused its records: {status}")
    decisions = tuple(EffectDecision(*struct.unpack_from("<4Q", output, 32 * index)) for index in range(n))
    if any(row.inferred > 255 or row.missing > 255 or row.worker_forbidden > 255
           or row.resource_conflicts > 7 for row in decisions):
        raise RuntimeError("HIA effect analysis returned malformed masks")
    return decisions


def analyze_effects(functions, local_effects, calls) -> dict[str, EffectDecision]:
    """Transport the source checker's complete graph without deciding it."""
    from .checker import EFFECTS
    if set(EFFECT_ORDER) != EFFECTS:
        raise RuntimeError("source effect vocabulary differs from the HIA semantic pass")
    names = tuple(functions)
    indexes = {name: index for index, name in enumerate(names)}
    if set(local_effects) != set(names) or set(calls) != set(names):
        raise RuntimeError("source checker effect graph is incomplete")
    if any(set(local_effects[name]) - EFFECTS for name in names):
        raise RuntimeError("source checker produced an unknown local effect")
    rows = tuple((effect_mask(local_effects[name]), effect_mask(functions[name].effects),
                  sum(1 << index for index, (clause, _) in enumerate(RESOURCE_ORDER)
                      if clause in functions[name].resources)) for name in names)
    edges = tuple((indexes[name], indexes[callee])
                  for name in names for callee in sorted(calls[name]))
    return dict(zip(names, decide(rows, edges)))
