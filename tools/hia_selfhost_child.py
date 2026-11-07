"""Disposable loader for the fixed HIA bootstrap byte ABI.

This file intentionally imports no HIA parser, verifier, authoring aid, emitter,
or object writer. It copies bytes, maps a supplied native image, and calls its
three-buffer entrypoint. It is a qualification helper, not a security sandbox
or a public service for running arbitrary submitted executable files.
"""
from __future__ import annotations

import ctypes
import fcntl
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import resource
import sys
import time

MAX_BYTES = 1 << 20


def main():
    request = json.loads(Path(sys.argv[1]).read_text())
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 << 20, 16 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    image = Path(request["image"]).read_bytes()
    source = Path(request["source"]).read_bytes()
    assert sha256(image).hexdigest() == request["image_sha256"]
    assert sha256(source).hexdigest() == request["source_sha256"]
    assert 0 < len(image) <= 4 * MAX_BYTES and len(source) <= MAX_BYTES
    capacity, workspace_size = request["capacity"], request["workspace_size"]
    assert type(capacity) is int and 0 <= capacity <= MAX_BYTES
    assert type(workspace_size) is int and 0 <= workspace_size <= MAX_BYTES
    signature = [ctypes.c_void_p, ctypes.c_uint64] * 3
    if request["format"] in {"seed-shared", "linked-selfhost"}:
        # Seal the exact checked seed bytes before handing them to the loader.
        fd = os.memfd_create("hia-bootstrap-seed", os.MFD_ALLOW_SEALING)
        try:
            offset = 0
            while offset < len(image):
                offset += os.write(fd, image[offset:])
            # Linux UAPI values are used when this Python build omits the names.
            all_seals = 0x0f  # SEAL_SEAL | SEAL_SHRINK | SEAL_GROW | SEAL_WRITE
            fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), all_seals)
            assert fcntl.fcntl(fd, getattr(fcntl, "F_GET_SEALS", 1034)) & all_seals == all_seals
            library = ctypes.CDLL("/proc/self/fd/" + str(fd), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            entry = library.f0
            entry.argtypes, entry.restype = signature, ctypes.c_uint64
        finally:
            os.close(fd)
    else:
        assert request["format"] == "flat-x86-64"
        mapped = mmap.mmap(-1, len(image), prot=mmap.PROT_READ | mmap.PROT_WRITE)
        mapped.write(image)
        address = ctypes.addressof(ctypes.c_char.from_buffer(mapped))
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        libc.mprotect.restype = ctypes.c_int
        if libc.mprotect(address, len(image), mmap.PROT_READ | mmap.PROT_EXEC):
            raise OSError(ctypes.get_errno(), "mprotect")
        entry = ctypes.CFUNCTYPE(ctypes.c_uint64, *signature)(address)
    source_array = ctypes.create_string_buffer(source, max(1, len(source)))
    output_initial = bytes.fromhex(request["output_initial_hex"]) if "output_initial_hex" in request else bytes([0xa5]) * capacity
    assert len(output_initial) == capacity
    workspace_initial = bytes([request.get("workspace_fill", 0)]) * workspace_size
    if request.get("observe_trap_writes", False):
        # Qualification-only observation: a shared file keeps actual output bytes
        # observable after UD2 terminates this child. No signal is intercepted.
        fd = os.open(request["output"], os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.ftruncate(fd, max(1, capacity))
            shared_output = mmap.mmap(fd, max(1, capacity), flags=mmap.MAP_SHARED,
                                      prot=mmap.PROT_READ | mmap.PROT_WRITE)
            shared_output[:capacity] = output_initial
            output = (ctypes.c_char * max(1, capacity)).from_buffer(shared_output)
        finally:
            os.close(fd)
    else:
        output = ctypes.create_string_buffer(output_initial, max(1, capacity))
    workspace = ctypes.create_string_buffer(workspace_initial, max(1, workspace_size))
    forbidden = [name for name in sys.modules if name.startswith("hepta.") or name.startswith("generate_hia_")]
    assert not forbidden, forbidden
    started = time.monotonic_ns()
    returned = entry(source_array, len(source), output, capacity, workspace, workspace_size)
    elapsed = time.monotonic_ns() - started
    output_bytes, workspace_bytes = output.raw[:capacity], workspace.raw[:workspace_size]
    if request.get("observe_trap_writes", False):
        shared_output.flush()
    else:
        Path(request["output"]).write_bytes(output_bytes)
    fields = {str(i): int.from_bytes(workspace_bytes[i:i + 8], "little")
              for i in (0, 8, 16, 24, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 224, 1024)
              if workspace_size >= i + 8}
    print(json.dumps({
        "status": "returned", "result_u64": returned,
        "abi_status": returned >> 32,
        "return_encoding": "packed-ABI-status-and-u32" if request["format"] == "seed-shared" else "zero-extended-u32",
        "core_u32": returned & 0xffffffff,
        "source_sha256": sha256(source).hexdigest(),
        "image_sha256": sha256(image).hexdigest(),
        "output_sha256": sha256(output_bytes).hexdigest(),
        "source_unchanged": source_array.raw[:len(source)] == source,
        "output_unchanged": output_bytes == output_initial,
        "workspace_header": fields, "native_elapsed_ns": elapsed,
        "forbidden_compiler_modules_loaded": forbidden,
        "loader_operations": "copy; sealed shared loader or RW-to-RX mmap; fixed ABI call",
        "limits": {"cpu_seconds": 10, "address_bytes": 256 << 20,
                   "stack_bytes": 8 << 20, "output_capacity": capacity,
                   "workspace_bytes": workspace_size},
    }, sort_keys=True))


if __name__ == "__main__":
    main()
