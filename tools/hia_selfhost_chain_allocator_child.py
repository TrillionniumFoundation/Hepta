"""One disposable ordinary-ELF allocator-contract witness, not a service.

Only parent-built test artifacts are passed here. The helper imports no HIA
compiler and does not change the production loader. Shared counters retain
actual NULL-call and output observations if a defined allocation trap terminates
the child. It does not catch a signal or claim cleanup after a trap.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import resource
import sys
import time

EVENT_CAPACITY = 32768
STAT_BYTES = 16 * 8
STATS_BYTES = STAT_BYTES + EVENT_CAPACITY * 4 * 8


def shared(path, size, initial=b""):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.ftruncate(fd, size)
        region = mmap.mmap(fd, size, flags=mmap.MAP_SHARED,
                           prot=mmap.PROT_READ | mmap.PROT_WRITE)
    finally:
        os.close(fd)
    region[:len(initial)] = initial
    return region


def main():
    request = json.loads(Path(sys.argv[1]).read_text())
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Linux may still invoke a piped system crash handler with RLIMIT_CORE=0.
    # Deliberate UD2 witnesses must remain real SIGILL failures without spawning
    # host crash collectors or copying caller buffers into diagnostic dumps.
    process_libc = ctypes.CDLL(None, use_errno=True)
    process_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    process_libc.prctl.restype = ctypes.c_int
    if process_libc.prctl(4, 0, 0, 0, 0) or process_libc.prctl(3, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "disable disposable native child core dumps")
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 << 20, 16 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    image_path = Path(request["image"])
    image = image_path.read_bytes()
    assert 0 < len(image) <= 4 << 20
    assert sha256(image).hexdigest() == request["image_sha256"]
    assert type(request["allocation_fail_at"]) is int and 0 <= request["allocation_fail_at"] <= 10000
    assert request["event_capacity"] == EVENT_CAPACITY
    output_region = shared(request["output"], 8, bytes([0xa5]) * 8)
    counters_region = shared(request["counters"], STATS_BYTES)
    output = (ctypes.c_ubyte * 8).from_buffer(output_region)
    counters = (ctypes.c_uint64 * 16).from_buffer(counters_region)
    events = (ctypes.c_uint64 * (EVENT_CAPACITY * 4)).from_buffer(counters_region, STAT_BYTES)
    library = ctypes.CDLL(str(image_path), mode=os.RTLD_LOCAL | os.RTLD_NOW)
    begin = library.hia_test_begin
    begin.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
    begin.restype = None
    entry = library.f0
    entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
    entry.restype = ctypes.c_uint64
    empty_input = ctypes.create_string_buffer(1)
    empty_workspace = ctypes.create_string_buffer(1)
    forbidden = [name for name in sys.modules if name == "hepta" or name.startswith("hepta.")]
    assert not forbidden
    begin(request["allocation_fail_at"], counters, events, EVENT_CAPACITY)
    start = time.monotonic_ns()
    returned = entry(empty_input, 0, output, 8, empty_workspace, 0)
    elapsed = time.monotonic_ns() - start
    output_region.flush(); counters_region.flush()
    assert sha256(image_path.read_bytes()).hexdigest() == request["image_sha256"]
    print(json.dumps({"status": "returned", "result_u64": returned,
        "core_u32": returned & 0xffffffff, "abi_status": returned >> 32,
        "return_encoding": request["return_encoding"],
        "output_hex": bytes(output).hex(), "image_sha256": request["image_sha256"],
        "native_elapsed_ns": elapsed, "forbidden_compiler_modules_loaded": forbidden,
        "loader_scope": "ordinary explicitly linked own fixture only; no loader adversarial cases"}))


if __name__ == "__main__":
    main()

