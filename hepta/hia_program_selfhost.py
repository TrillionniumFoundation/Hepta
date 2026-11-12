"""Explicit, pinned native HIA compilation for bounded primitive Core v8.

The selected syscall-only executable owns representation lowering, semantic
checking, machine code and ELF emission. This Python adapter still owns public
Core verification, source custody, process lifetime and local publication. Its
operator-pinned manifest is executable authority, not a correctness proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
import fcntl
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import stat
import struct
import subprocess
import sys
import tempfile
import time

from .artifact_publication import publish_verified, verify_published, withdraw_own_link
from .clang_capture import _posix_observe, _require_posix_ownership, _terminate
from .hia_json_preflight_native import _source_resource_path
from .object_symbols import inspect_object_symbols

SCHEMA = "hepta.hia.program-selfhost-compiler.v1"
PROFILE = "hepta.hia.program.selfhost-elf-linux-x86_64.v1"
TARGET = "x86_64-unknown-linux-gnu"
SOURCE_FILES = (
    "examples/hia_bootstrap/selfhost.hiaasm",
    "examples/hia_bootstrap/core_json_frontend.hiaasm",
    "examples/hia_bootstrap/core_json_cli_packer.hiaasm",
    "docs/HIA_SELFHOST_CORE_SUPPORT.json",
)
MAX_MANIFEST_BYTES = 16384
MAX_SOURCE_BYTES = 1 << 20
MAX_EXECUTABLE_BYTES = 1 << 20
MAX_INPUT_BYTES = 8 << 20
MAX_OBJECT_BYTES = 1 << 20
MAX_STDERR_BYTES = 65536
IMPORTS = frozenset({"calloc", "free"})
# Linux UAPI values are stable even when a Python build omits these names.
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
REQUIRED_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008


class SelfhostBuildRejected(ValueError):
    def __init__(self, code, message):
        self.code = code
        self.capture = None
        super().__init__(code + ": " + message)


def _reject(code, message):
    raise SelfhostBuildRejected(code, message)


def _digest(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def _path(value):
    value = Path(value)
    if ".." in value.parts or "\0" in str(value):
        _reject("E_HIA_SELFHOST_PATH", "parent traversal is not a compiler path")
    return value.absolute()


def _identity(info):
    return tuple(getattr(info, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns"))


def _open_directory(path):
    path = _path(path)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                                | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class _OutputDirectory:
    """Keep every staging/publication effect in the admitted directory inode."""
    def __init__(self, path):
        self.path = _path(path)
        self.fd = _open_directory(self.path)
        info = os.fstat(self.fd)
        self.identity = (info.st_dev, info.st_ino)
        # The optional native publication child must resolve the owner's
        # retained descriptor, not the same descriptor number in its own table.
        self.anchor = Path("/proc/" + str(os.getpid()) + "/fd/" + str(self.fd))

    def check(self):
        descriptor = _open_directory(self.path)
        try:
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != self.identity:
                _reject("E_HIA_SELFHOST_OUTPUT", "output parent changed during compilation")
        finally:
            os.close(descriptor)

    def close(self):
        os.close(self.fd)


@dataclass(frozen=True)
class _Snapshot:
    path: Path
    raw: bytes
    identity: tuple


def _read(path, limit):
    """Open every directory and the file without following any symlink."""
    path = _path(path)
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                                | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | os.O_CLOEXEC, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid not in (0, os.getuid()) or before.st_mode & 0o022
                    or not 0 < before.st_size <= limit):
                _reject("E_HIA_SELFHOST_FILE", "compiler input must be an owned bounded regular file")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if len(raw) != before.st_size or _identity(before) != _identity(after):
                _reject("E_HIA_SELFHOST_STALE", "compiler input changed during read")
        observed = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if _identity(observed) != _identity(before):
            _reject("E_HIA_SELFHOST_STALE", "compiler pathname changed during read")
        return _Snapshot(path, raw, _identity(before))
    finally:
        os.close(directory)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("E_HIA_SELFHOST_MANIFEST", "duplicate compiler manifest field")
        result[key] = value
    return result


def _decode(raw):
    def constant(_value):
        _reject("E_HIA_SELFHOST_MANIFEST", "nonfinite compiler manifest value")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=constant)


def _inspect_executable(raw):
    """Closed executable layout emitted by the HIA Core-JSON packer."""
    if (not 176 < len(raw) <= MAX_EXECUTABLE_BYTES
            or raw[:16] != b"\x7fELF\x02\x01\x01" + bytes(9)
            or struct.unpack_from("<HHIQQQIHHHHHH", raw, 16) !=
               (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
            or struct.unpack_from("<IIQQQQQQ", raw, 64) !=
               (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096)
            or struct.unpack_from("<IIQQQQQQ", raw, 120) !=
               (0x6474e551, 6, 0, 0, 0, 0, 0, 16)):
        _reject("E_HIA_SELFHOST_EXECUTABLE", "compiler is not the closed syscall-only ELF profile")


def manifest_value(executable, *, compiler_sha256, frontend_sha256, packer_sha256,
                   source_sha256, cold_report_sha256):
    """Build a selection record; callers retain their actual qualification scope.

    A null cold digest is a development build, never a fabricated cold pass.
    Runtime pins select trusted bytes; they do not independently prove the
    declared provenance or promote a development image into a release.
    """
    raw = Path(executable).read_bytes()
    _inspect_executable(raw)
    return {"schema": SCHEMA, "profile": PROFILE, "target": TARGET,
            "output_profile": "elf", "executable_path": Path(executable).name,
            "executable_sha256": sha256(raw).hexdigest(), "executable_bytes": len(raw),
            "compiler_sha256": compiler_sha256, "frontend_sha256": frontend_sha256,
            "packer_sha256": packer_sha256, "source_sha256": source_sha256,
            "cold_report_sha256": cold_report_sha256}


class _Selection:
    def __init__(self, path, expected_sha256):
        if (sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}
                or sys.byteorder != "little" or ctypes.sizeof(ctypes.c_void_p) != 8
                or not hasattr(os, "memfd_create")):
            _reject("E_HIA_SELFHOST_TARGET", "sealed native compilation requires Linux x86-64 LP64")
        if not _digest(expected_sha256):
            _reject("E_HIA_SELFHOST_PIN", "an exact lowercase compiler manifest SHA256 is required")
        manifest = _read(path, MAX_MANIFEST_BYTES)
        if sha256(manifest.raw).hexdigest() != expected_sha256:
            _reject("E_HIA_SELFHOST_PIN", "compiler manifest differs from the operator pin")
        value = _decode(manifest.raw)
        fields = {"schema", "profile", "target", "output_profile", "executable_path",
                  "executable_sha256", "executable_bytes", "compiler_sha256",
                  "frontend_sha256", "packer_sha256", "source_sha256", "cold_report_sha256"}
        if (type(value) is not dict or set(value) != fields
                or value["schema"] != SCHEMA or value["profile"] != PROFILE
                or value["target"] != TARGET or value["output_profile"] != "elf"
                or type(value["executable_path"]) is not str or not value["executable_path"]
                or Path(value["executable_path"]).name != value["executable_path"]
                or value["executable_path"] in {".", ".."}
                or any(not _digest(value[key]) for key in (
                    "executable_sha256", "compiler_sha256", "frontend_sha256", "packer_sha256"))
                or type(value["executable_bytes"]) is not int
                or not 176 < value["executable_bytes"] <= MAX_EXECUTABLE_BYTES
                or type(value["source_sha256"]) is not dict
                or set(value["source_sha256"]) != set(SOURCE_FILES)
                or any(not _digest(digest) for digest in value["source_sha256"].values())
                or value["cold_report_sha256"] is not None and not _digest(value["cold_report_sha256"])):
            _reject("E_HIA_SELFHOST_MANIFEST", "unsupported native compiler selection contract")
        self.snapshots = [(manifest, MAX_MANIFEST_BYTES)]
        for name in SOURCE_FILES:
            snapshot = _read(_source_resource_path(name), MAX_SOURCE_BYTES)
            if sha256(snapshot.raw).hexdigest() != value["source_sha256"][name]:
                _reject("E_HIA_SELFHOST_SOURCE", "installed compiler source differs: " + name)
            self.snapshots.append((snapshot, MAX_SOURCE_BYTES))
        executable = _read(manifest.path.parent / value["executable_path"], MAX_EXECUTABLE_BYTES)
        if (len(executable.raw) != value["executable_bytes"]
                or sha256(executable.raw).hexdigest() != value["executable_sha256"]):
            _reject("E_HIA_SELFHOST_EXECUTABLE", "compiler executable differs from the operator-pinned bytes")
        _inspect_executable(executable.raw)
        self.snapshots.append((executable, MAX_EXECUTABLE_BYTES))
        self.value, self.sha256, self.executable = value, expected_sha256, executable.raw
        self.check()

    def check(self):
        for original, limit in self.snapshots:
            if _read(original.path, limit) != original:
                _reject("E_HIA_SELFHOST_STALE", "compiler selection changed during the operation")


def _sealed_executable(raw):
    fd = os.memfd_create("hia-selfhost-compiler", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                _reject("E_HIA_SELFHOST_CAPTURE", "short executable capture")
            offset += count
        os.fchmod(fd, 0o500)
        fcntl.fcntl(fd, F_ADD_SEALS, REQUIRED_SEALS)
        seals = fcntl.fcntl(fd, F_GET_SEALS)
        if seals & REQUIRED_SEALS != REQUIRED_SEALS or os.pread(fd, len(raw) + 1, 0) != raw:
            _reject("E_HIA_SELFHOST_CAPTURE", "kernel seal or captured executable readback failed")
        return fd, seals
    except BaseException:
        os.close(fd)
        raise


def _run(fd, wire, timeout_seconds, cwd):
    """Bound all streams and retain leader ownership through group cleanup.

    The admitted compiler has no fork/clone operation. This is lifetime control
    of that trusted compiler, not a sandbox for arbitrary operator-selected code.
    """
    _require_posix_ownership()
    started = time.monotonic()
    deadline = started + timeout_seconds
    proc = subprocess.Popen(["/proc/self/fd/" + str(fd)], pass_fds=(fd,),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={"PATH": ""}, cwd=cwd, start_new_session=True, close_fds=True)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    written, eof = 0, set()
    failure = None
    try:
        with selectors.DefaultSelector() as selector:
            for stream, event, name in ((proc.stdin, selectors.EVENT_WRITE, "stdin"),
                                        (proc.stdout, selectors.EVENT_READ, "stdout"),
                                        (proc.stderr, selectors.EVENT_READ, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event, name)
            while True:
                now = time.monotonic()
                if now >= deadline:
                    _reject("E_HIA_SELFHOST_TIMEOUT", "native compilation exceeded its wall-time budget")
                terminal = _posix_observe(proc)
                if terminal is not None and not selector.get_map():
                    break
                for key, _mask in selector.select(min(0.02, deadline - now)):
                    stream, name = key.fileobj, key.data
                    if name == "stdin":
                        try:
                            count = os.write(stream.fileno(), wire[written:written + 65536])
                            written += count
                        except BrokenPipeError:
                            count = 0
                        except BlockingIOError:
                            continue
                        if written == len(wire) or count == 0:
                            selector.unregister(stream)
                            stream.close()
                    else:
                        limit = MAX_OBJECT_BYTES if name == "stdout" else MAX_STDERR_BYTES
                        try:
                            chunk = os.read(stream.fileno(), min(65536, limit + 1 - len(captured[name])))
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
                            eof.add(name)
                        else:
                            captured[name].extend(chunk)
                            if len(captured[name]) > limit:
                                _reject("E_HIA_SELFHOST_OUTPUT_LIMIT", "native compiler exceeded its " + name + " budget")
        elapsed = time.monotonic() - started
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            _terminate(proc)
        except BaseException as cleanup_error:
            if failure is None:
                raise
            failure.add_note("Native compiler cleanup failed: " + str(cleanup_error))
        finally:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()
        if isinstance(failure, SelfhostBuildRejected):
            failure.capture = {
                "returncode": proc.returncode, "wall_seconds": time.monotonic() - started,
                "stdin_bytes": len(wire), "stdin_written_bytes": written,
                "stdout_bytes_retained": len(captured["stdout"]),
                "stderr_bytes_retained": len(captured["stderr"]),
                "stdout_sha256": sha256(captured["stdout"]).hexdigest(),
                "stderr_sha256": sha256(captured["stderr"]).hexdigest(),
                "stdout_complete": "stdout" in eof, "stderr_complete": "stderr" in eof,
                "leader_reaped": proc.returncode is not None,
                "execution": "sealed-memfd-exec"}
    stdout, stderr = bytes(captured["stdout"]), bytes(captured["stderr"])
    receipt = {"returncode": proc.returncode, "wall_seconds": elapsed,
               "stdin_bytes": len(wire), "stdin_written_bytes": written,
               "stdin_sha256": sha256(wire).hexdigest(),
               "stdout_bytes": len(stdout), "stdout_sha256": sha256(stdout).hexdigest(),
               "stderr_bytes": len(stderr), "stderr_sha256": sha256(stderr).hexdigest(),
               "stdout_complete": "stdout" in eof, "stderr_complete": "stderr" in eof,
               "leader_reaped": proc.returncode is not None,
               "execution": "sealed-memfd-exec", "runtime_executable_dependencies": []}
    if proc.returncode != 0 or stderr or eof != {"stdout", "stderr"} or written != len(wire):
        error = SelfhostBuildRejected("E_HIA_SELFHOST_COMPILE",
            "native compiler refused input or failed (exit %s)" % proc.returncode)
        error.capture = receipt
        raise error
    return stdout, receipt


def build_program_selfhost(document, output, *, manifest, manifest_sha256,
                           timeout_seconds=30, target=TARGET, kind="object",
                           machine_plan=None, foreign_buffer_exports=()):
    """Compile an explicit bounded v8 scalar object without the Python emitter."""
    if (target != TARGET or kind != "object" or machine_plan is not None
            or foreign_buffer_exports):
        _reject("E_HIA_SELFHOST_PROFILE", "selfhost supports canonical scalar ELF objects only")
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 3600):
        _reject("E_HIA_SELFHOST_BUDGET", "compilation deadline must be finite and in (0,3600] seconds")
    destination = _path(output)
    if (destination.exists() or destination.is_symlink() or not destination.parent.is_dir()
            or destination.parent.resolve() != destination.parent):
        _reject("E_HIA_SELFHOST_OUTPUT", "output must be a new path under an existing nonsymlink directory")
    from .hia_program import verify_program, SCALARS
    program = verify_program(document)
    value = program.as_dict()
    if value["schema"] != "hepta.hia.program.v8" or program.structured_bytes is not None:
        _reject("E_HIA_SELFHOST_PROFILE", "selfhost accepts explicit primitive Core v8, not nominal input")
    exports = sorted(program.scalar_entrypoints)
    functions = {function["name"]: function for function in value["functions"]}
    if not 1 <= len(exports) <= 128:
        _reject("E_HIA_SELFHOST_PROFILE", "selfhost requires one to 128 scalar entrypoints")
    for name in exports:
        fn = functions[name]
        if (len(fn["params"]) > 16 or len(fn["returns"]) > 1
                or any(p["type"] not in SCALARS - {"unit"} for p in fn["params"])
                or any(t not in SCALARS for t in fn["returns"])):
            _reject("E_HIA_SELFHOST_PROFILE", "export is outside the selfhost scalar ABI: " + name)
    value["exports"] = exports
    wire = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")
    if len(wire) > MAX_INPUT_BYTES:
        _reject("E_HIA_SELFHOST_PROFILE", "native Core wire exceeds 8 MiB")
    directory = _OutputDirectory(destination.parent)
    try:
        selection = _Selection(manifest, manifest_sha256)
        fd, seals = _sealed_executable(selection.executable)
        try:
            directory.check()
            with tempfile.TemporaryDirectory(prefix=".hia-selfhost-", dir=directory.anchor) as temporary:
                data, capture = _run(fd, wire, timeout_seconds, temporary)
                symbols = inspect_object_symbols(data, "ELF64", 62)
                if symbols["defined"] != frozenset(exports) or not symbols["undefined"] <= IMPORTS:
                    _reject("E_HIA_SELFHOST_OBJECT", "native object import/export inventory differs")
                selection.check()
                directory.check()
                stage = Path(temporary) / "program.o"
                captured_destination = directory.anchor / destination.name
                with stage.open("xb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                publication = publish_verified(stage, captured_destination, data)
                try:
                    selection.check()
                    directory.check()
                    verify_published(stage, destination, data)
                    directory.check()
                except BaseException:
                    withdraw_own_link(stage, captured_destination)
                    raise
        finally:
            os.close(fd)
    finally:
        directory.close()
    return {"schema": "hepta.hia.program.selfhost-native.v1", "ok": True,
            "status": "native_emitted_not_executed", "profile": PROFILE,
            "target": TARGET, "kind": "object", "output": str(destination),
            "input_sha256": program.input_sha256, "core_sha256": program.sha256,
            "compiler_wire_sha256": sha256(wire).hexdigest(),
            "compiler_manifest_sha256": selection.sha256,
            "compiler_executable_sha256": selection.value["executable_sha256"],
            "compiler_source_sha256": selection.value["source_sha256"],
            "compiler_cold_report_sha256": selection.value["cold_report_sha256"],
            "compiler_provenance": {key: selection.value[key] for key in (
                "compiler_sha256", "frontend_sha256", "packer_sha256")},
            "artifact_sha256": publication["sha256"], "artifact_bytes": publication["bytes"],
            "object_sha256": sha256(data).hexdigest(), "exports": exports,
            "binary_inventory": {name: sorted(values) for name, values in symbols.items()},
            "capture": capture, "kernel_executable_seals": seals,
            "claims": {"native_representation_and_codegen": True,
                "python_emitter_used": False, "external_linker_used": False,
                "fallback_used": False, "compiler_executed": True,
                "generated_program_executed": False, "hosted_cli_and_publication": True,
                "operator_pin_is_correctness_proof": False,
                "whole_native_delivery_qualified": False, "production_activated": False}}
