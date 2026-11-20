"""Fresh Linux/x86 ISA admission outside the native kernel hot path.

CPUID and XGETBV run in an isolated baseline-instruction subprocess, once on
each CPU in its allowed affinity.  No serialized build report is an execution
permission.  The probe, Linux scheduler and CPU instruction behavior are part
of the explicit platform trust base; the SIMD checker proves different facts.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import platform
import sys


class VerifiedCPURejected(ValueError):
    pass


# SysV void probe(uint32_t out[5]). Save RBX in caller-saved R9, retain the
# output pointer in R8, check leaf availability, and execute XGETBV only after
# CPUID.1:ECX.OSXSAVE. Writes: max_basic, leaf1_ecx, xcr0_lo, xcr0_hi, leaf7_ebx.
# No AVX instruction is used by this probe. GNU as independently reproduces
# these bytes in the regression test; production does not invoke an assembler.
_PROBE_BYTES = bytes.fromhex(
    "4989f84989d931c00fa241890085c07433b8010000000fa241894804"
    "f7c100000008740d31c90f01d0418940084189500c41833807720d"
    "b80700000031c90fa2418958104c89cbc3")
_RAW_KEYS = ("max_basic", "leaf1_ecx", "xcr0_lo", "xcr0_hi", "leaf7_ebx")
_FEATURES = frozenset(("sse2", "avx", "avx2", "avx512f", "avx512bw", "avx512dq", "avx512vl"))
_WORKER = "import runpy,sys; runpy.run_path(sys.argv[1])['_main']()"
_MAX_CPUS = 1024


def _require(condition, message):
    if not condition:
        raise VerifiedCPURejected(message)


def decode_cpu_features(raw):
    """Derive usable features from hardware bits AND enabled OS state."""
    _require(type(raw) is dict and set(raw) == set(_RAW_KEYS), "malformed raw CPU observation")
    _require(all(type(raw[k]) is int and 0 <= raw[k] < (1 << 32) for k in _RAW_KEYS),
             "CPU observations must be unsigned 32-bit words")
    maximum, ecx, low, high, ebx = (raw[k] for k in _RAW_KEYS)
    xcr0 = low | (high << 32)
    features = {"sse2"}  # The admitted Linux AMD64 platform already requires it.
    avx_state = (maximum >= 1 and ecx & 0x1c000000 == 0x1c000000 and xcr0 & 6 == 6)
    if avx_state:
        features.add("avx")
        if maximum >= 7 and ebx & (1 << 5):
            features.add("avx2")
        if maximum >= 7 and xcr0 & 0xe6 == 0xe6 and ebx & (1 << 16):
            features.add("avx512f")
            for name, bit in (("avx512bw", 30), ("avx512dq", 17), ("avx512vl", 31)):
                if ebx & (1 << bit):
                    features.add(name)
    return sorted(features), xcr0


def _probe_process():
    _require(platform.system() == "Linux" and platform.machine().lower() in ("x86_64", "amd64"),
             "CPU admission requires Linux x86-64")
    original = os.sched_getaffinity(0)
    _require(0 < len(original) <= _MAX_CPUS, "CPU affinity is empty or exceeds probe bounds")
    memory = mmap.mmap(-1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                       prot=mmap.PROT_READ | mmap.PROT_WRITE)
    try:
        memory.write(_PROBE_BYTES)
        address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
        libc = ctypes.CDLL(None, use_errno=True)
        protect = libc.mprotect
        protect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
        protect.restype = ctypes.c_int
        if protect(address, mmap.PAGESIZE, mmap.PROT_READ | mmap.PROT_EXEC):
            raise OSError(ctypes.get_errno(), "CPU probe executable mapping refused")
        probe = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint32))(address)
        rows = []
        try:
            for cpu in sorted(original):
                os.sched_setaffinity(0, {cpu})
                _require(os.sched_getaffinity(0) == {cpu}, "CPU probe pinning did not take effect")
                words = (ctypes.c_uint32 * len(_RAW_KEYS))()
                probe(words)
                rows.append({"cpu": cpu, "raw": dict(zip(_RAW_KEYS, map(int, words)))})
        finally:
            os.sched_setaffinity(0, original)
        _require(os.sched_getaffinity(0) == original, "CPU probe did not restore its own affinity")
        return {"schema": "hepta.hia.fresh-x86-probe.v1", "affinity": sorted(original), "cpus": rows,
                "probe_sha256": sha256(_PROBE_BYTES).hexdigest()}
    finally:
        memory.close()


def _main():
    print(json.dumps(_probe_process(), sort_keys=True))


def probe_host_isa():
    """Obtain new observations; a fault in CPUID/XGETBV only kills the worker."""
    from .clang_capture import run_bounded
    _require(platform.system() == "Linux" and platform.machine().lower() in ("x86_64", "amd64"),
             "CPU admission requires Linux x86-64")
    source = Path(__file__).resolve()
    from .hia_loaded_source import loaded_source_identity
    source_hash = loaded_source_identity(__name__, (source.name,))[source.name]
    affinity = sorted(os.sched_getaffinity(0))
    result = run_bounded([sys.executable, "-I", "-B", "-c", _WORKER, str(source)],
                         timeout=20, stdout_limit=1048576, stderr_limit=65536)
    _require(result.returncode == 0, "fresh CPU probe failed: " + result.stderr[-2000:])
    _require(source_hash == loaded_source_identity(__name__, (source.name,))[source.name],
             "CPU probe source changed")
    try:
        observed = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise VerifiedCPURejected("fresh CPU probe returned invalid JSON") from exc
    _require(type(observed) is dict and observed.get("schema") == "hepta.hia.fresh-x86-probe.v1",
             "fresh CPU probe schema differs")
    _require(observed.get("affinity") == affinity == sorted(os.sched_getaffinity(0)) and
             observed.get("probe_sha256") == sha256(_PROBE_BYTES).hexdigest(),
             "CPU affinity or probe identity changed")
    rows = observed.get("cpus")
    _require(type(rows) is list and len(rows) == len(affinity) and
             [r.get("cpu") for r in rows if type(r) is dict] == affinity,
             "fresh CPU observations do not cover the allowed affinity")
    common, xcr0 = set(_FEATURES), (1 << 64) - 1
    for row in rows:
        features, enabled = decode_cpu_features(row.get("raw"))
        common.intersection_update(features)
        xcr0 &= enabled
    return {**observed, "source_sha256": source_hash,
            "common_features": sorted(common), "common_xcr0": xcr0,
            "scope": "fresh observations for every CPU in the calling thread's current affinity"}


def require_host_isa(required_cpu_features, required_xcr0_mask):
    """Require instruction-derived features against new actual observations."""
    _require(type(required_cpu_features) in (tuple, list) and
             all(type(f) is str and f in _FEATURES for f in required_cpu_features),
             "unknown required CPU feature")
    _require(type(required_xcr0_mask) is int and required_xcr0_mask in (0, 6, 0xe6),
             "unknown required XCR0 mask")
    evidence = probe_host_isa()
    _require(set(required_cpu_features) <= set(evidence["common_features"]) and
             evidence["common_xcr0"] & required_xcr0_mask == required_xcr0_mask,
             "CPU or operating system does not enable the decoded kernel's instruction set")
    return evidence


def resolve_target_isa(requested):
    _require(type(requested) is str and requested in ("native", "sse2", "avx2", "avx512"),
             "target ISA must be native, sse2, avx2 or avx512")
    if requested != "native":
        return requested
    features = set(probe_host_isa()["common_features"])
    if {"avx", "avx2", "avx512f", "avx512bw"} <= features:
        return "avx512"
    return "avx2" if {"avx", "avx2"} <= features else "sse2"

# The isolated runpy worker compiles this source directly; package consumers bind it.
if __package__:
    from .hia_loaded_source import register_loaded_module as _register_loaded_source
    _register_loaded_source(__name__)
