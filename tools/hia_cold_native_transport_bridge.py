"""Explicit hosted-owner selector for the HIA native cold transport R3.

Default observer imports keep their original execute functions. An explicit
manifest AND explicit development authorization select this candidate. There
is no fallback after selection. This does not qualify cold or whole-native.

The native extension's sealed code descriptor has an explicit module-lifetime
owner. It contains code bytes only, never invocation arguments or exceptions.
"""
from __future__ import annotations

import builtins
import fcntl
from hashlib import sha256
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import types
import _io

SELECTOR = "HEPTA_HIA_COLD_NATIVE_TRANSPORT_MANIFEST"
DEVELOPMENT = "HEPTA_HIA_COLD_NATIVE_TRANSPORT_ALLOW_DEVELOPMENT"
MODULE = "_hia_cold_native_transport"
SCHEMA = "hepta.cold-native-transport.hosted-build.r3"
_LOCK = threading.RLock()
_LOADING = False
_BROKEN = False
_CODE_OWNER = None
_EPOCH = object()

SOURCE_INPUTS = (
    "tools/hia_cold_native_transport.h", "tools/hia_cold_native_transport.c",
    "tools/hia_cold_native_transport_driver.c", "tools/hia_cold_native_transport_python.c",
    "tools/hia_cold_native_transport_handoff_controls.c",
    "tools/hia_cold_native_transport_bridge.py", "tools/generate_hia_cold_native_transport.py",
    "tools/build_hia_cold_native_transport.py", "tools/hia_cold_native_transport_evidence.py",
    "tools/qualify_hia_cold_native_transport.py", "tools/read_hia_cold_native_transport.py",
    "examples/hia_bootstrap/cold_native_transport.hepta",
    "tools/hia_selfhost_native_observer.py", "tools/hia_selfhost_linked_observer.py",
    "tools/qualify_hia_selfhost.py", "tools/replay_hia_selfhost_cold.py", "tools/hia_selfhost_child.py",
    "tools/build_hia_json_preflight.py", "tools/build_hia_source_build.py",
    "tools/generate_hia_selfhost.py", "tools/generate_hia_native_observer.py",
    "tools/generate_hia_linked_observer.py", "tools/hia_native_observer_template.S",
    "tools/hia_linked_observer_bridge.S",
    "tests/test_hia_selfhost_native_observer.py", "tests/test_hia_selfhost_linked_observer.py",
    "tests/test_hia_linked_observer_build_custody.py",
    "tests/test_hia_cold_native_transport.py",
    "tests/fixtures/cold_native_transport_original_gates_v3.json",
    "tests/fixtures/cold_native_transport_controls_v3.json",
    "tools/run_hia_unittest_gate.py",
)


def _after_fork():
    global _LOCK, _LOADING, _BROKEN, _EPOCH
    # The explicit profile never reuses a parent load authority in a child.
    # An in-progress parent initializer cannot publish in this new epoch.
    _LOCK = threading.RLock()
    _LOADING = False
    _BROKEN = True
    _EPOCH = object()


os.register_at_fork(after_in_child=_after_fork)


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate manifest key: " + name)
        result[name] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def _pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def _regular(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("expected a regular source or artifact")
        pieces = []
        while True:
            piece = os.read(fd, 65536)
            if not piece:
                break
            pieces.append(piece)
        raw = b"".join(pieces)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or len(raw) != after.st_size):
            raise ValueError("source or artifact changed during its actual read")
        return raw
    finally:
        os.close(fd)


def _expect(raw, expected):
    if (type(expected) is not dict or type(expected.get("bytes")) is not int
            or type(expected.get("sha256")) is not str or _pin(raw) != expected):
        raise ValueError("complete consumed source bytes differ")
    return raw


def _canonical_io():
    # This is an explicit canonical-runtime admission, not proof against
    # arbitrary pre-admission reflection or hostile native code in this process.
    if (_io.__spec__.origin != "built-in" or _io.open is not io.open
            or builtins.open is not io.open
            or type(io.open) is not types.BuiltinFunctionType
            or io.open.__self__ is not _io
            or io.FileIO is not _io.FileIO
            or io.BufferedReader is not _io.BufferedReader
            or io.BufferedWriter is not _io.BufferedWriter):
        raise ValueError("native bridge requires the original builtin _io capability family")
    for cls, name in ((io.FileIO, "FileIO"), (io.BufferedReader, "BufferedReader"), (io.BufferedWriter, "BufferedWriter")):
        if type(cls) is not type or cls.__module__ != "_io" or cls.__name__ != name:
            raise ValueError("native bridge's binary stream class is not canonical")
        for method in ("close", "fileno"):
            if type(getattr(cls, method)) is not types.MethodDescriptorType:
                raise ValueError("native bridge requires actual _io method descriptors")
        if type(getattr(cls, "closed")) is not types.GetSetDescriptorType:
            raise ValueError("native bridge requires the actual _io closed-state descriptor")
    return {
        "runtime": "canonical CPython builtin _io",
        "extra_queries": ["actual binary owner.closed after close", "actual owner.fileno before handoff",
                          "actual failed raw FileIO.closed after its original error-path close"],
        "raw_buffer_boundary": "canonical CPython 3.14 supplied-fd FileIO then actual default-size Buffered owner",
        "arbitrary_provider_or_reflection_equivalence": False,
    }


class _Captured:
    def __init__(self, manifest_path, *, expected_raw=None, expected_artifacts=None):
        self.path = Path(manifest_path).resolve(strict=True)
        self.raw = _regular(self.path)
        if expected_raw is not None and self.raw != expected_raw:
            raise ValueError("native cold manifest differs from the actual phase input bytes")
        self.value = _json(self.raw)
        value = self.value
        if (value.get("schema") != SCHEMA
                or value.get("status") != "BUILT_NOT_QUALIFIED_EXPLICIT_DEVELOPMENT"
                or value.get("whole_native") is not False):
            raise ValueError("unknown or overstated native cold manifest")
        if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
            raise ValueError("this hosted bridge is bound to CPython 3.14")
        self.root = Path(value["source_root"]).resolve(strict=True)
        self.inputs = {}
        for relative, expected in value["inputs"].items():
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
                raise ValueError("noncanonical source input")
            self.inputs[relative] = _expect(_regular(self.root / path), expected)
        if tuple(value["inputs"]) != tuple(sorted(SOURCE_INPUTS)) or set(self.inputs) != set(SOURCE_INPUTS):
            raise ValueError("native cold source closure or canonical order differs")
        self.artifacts = {}
        for name in ("policy", "extension"):
            item = value[name]
            path = Path(item["path"]).resolve(strict=True)
            self.artifacts[name] = (path, _expect(_regular(path), item["pin"]))
        if expected_artifacts is not None and (
                set(expected_artifacts) != {"policy", "extension"}
                or any(self.artifacts[name][1] != raw for name, raw in expected_artifacts.items())):
            raise ValueError("native cold executable artifacts differ from the actual phase inputs")
        runtime = value["runtime"]
        executable = Path(sys.executable).resolve(strict=True)
        executable_raw = _expect(_regular(executable), runtime["pin"])
        if (str(executable) != runtime["path"] or sys.version != runtime["version"]):
            raise ValueError("native cold runtime identity differs")
        subprocess_path = Path(subprocess.__file__).resolve(strict=True)
        subprocess_raw = _expect(_regular(subprocess_path), runtime["subprocess_pin"])
        if str(subprocess_path) != runtime["subprocess_path"]:
            raise ValueError("native cold subprocess semantics are not the admitted runtime")
        self.runtime_files = {
            executable: executable_raw, subprocess_path: subprocess_raw
        }
        self.io_scope = _canonical_io()
        self.unchanged()

    def unchanged(self):
        if _regular(self.path) != self.raw:
            raise ValueError("native cold manifest changed")
        for relative, raw in self.inputs.items():
            if _regular(self.root / relative) != raw:
                raise ValueError("native cold source changed: " + relative)
        for path, raw in self.artifacts.values():
            if _regular(path) != raw:
                raise ValueError("native cold built artifact changed")
        for path, raw in self.runtime_files.items():
            if _regular(path) != raw:
                raise ValueError("native cold runtime changed")


class _CodeOwner:
    """Visible module-lifetime ownership of the exact sealed extension bytes."""
    def __init__(self, captured):
        self.pid = os.getpid()
        self.binary = captured.artifacts["extension"][1]
        self.binary_pin = _pin(self.binary)
        self.fd = None
        self.state = "RESERVED"
        self.module = None

    def check(self):
        if self.pid != os.getpid() or self.state != "MODULE_LIFETIME" or self.fd is None:
            raise ValueError("native extension owner is not current")
        if (fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) != 15
                or os.pread(self.fd, len(self.binary) + 1, 0) != self.binary):
            raise ValueError("native extension's actually executed descriptor changed")

    def close_failed_load(self):
        fd, self.fd = self.fd, None
        self.state = "FAILED_CLOSED"
        if fd is not None:
            os.close(fd)


def _extension(captured):
    global _LOADING, _BROKEN, _CODE_OWNER
    epoch, creator = _EPOCH, os.getpid()
    lock = _LOCK
    with lock:
        captured.unchanged()
        if epoch is not _EPOCH or creator != os.getpid():
            raise ValueError("native extension load changed process epoch")
        if _CODE_OWNER is not None:
            _CODE_OWNER.check()
            if (_CODE_OWNER.binary != captured.artifacts["extension"][1]
                    or sys.modules.get(MODULE) is not _CODE_OWNER.module):
                raise ValueError("this process already owns a different native extension")
            return _CODE_OWNER.module
        if _LOADING or _BROKEN or MODULE in sys.modules:
            raise ValueError("recursive, partial or unowned native extension load")
        _LOADING = True
        owner = _CodeOwner(captured)
        loaded = None
        try:
            owner.fd = os.memfd_create("hia-cold-native-transport-r3",
                                      os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            owner.state = "OPEN"
            offset = 0
            while offset < len(owner.binary):
                count = os.write(owner.fd, owner.binary[offset:])
                if count <= 0:
                    raise OSError("short native extension descriptor write")
                offset += count
            fcntl.fcntl(owner.fd, fcntl.F_ADD_SEALS, 15)
            path = "/proc/self/fd/" + str(owner.fd)
            loader = importlib.machinery.ExtensionFileLoader(MODULE, path)
            spec = importlib.util.spec_from_file_location(MODULE, path, loader=loader)
            if (spec is None or fcntl.fcntl(owner.fd, fcntl.F_GET_SEALS) != 15
                    or os.pread(owner.fd, len(owner.binary) + 1, 0) != owner.binary):
                raise ValueError("native extension descriptor differs before load")
            captured.unchanged()
            _BROKEN = True
            loaded = importlib.util.module_from_spec(spec)
            sys.modules[MODULE] = loaded
            loader.exec_module(loaded)
            if (loaded.__spec__ is not spec or loaded.__loader__ is not loader
                    or loaded.__file__ != path
                    or loaded.ABI != 3 or loaded.ACTIONS != 25
                    or loaded.MAJOR != 3 or loaded.MINOR != 14
                    or fcntl.fcntl(owner.fd, fcntl.F_GET_SEALS) != 15
                    or os.pread(owner.fd, len(owner.binary) + 1, 0) != owner.binary):
                raise ValueError("native extension load identity differs")
            captured.unchanged()
            if epoch is not _EPOCH or creator != os.getpid() or owner.pid != creator:
                raise ValueError("native extension initializer cannot publish after fork")
            owner.module = loaded
            owner.state = "MODULE_LIFETIME"
            loaded.__hia_code_owner__ = owner
            _CODE_OWNER = owner
            _BROKEN = False
            return loaded
        except BaseException:
            if loaded is not None and sys.modules.get(MODULE) is loaded:
                del sys.modules[MODULE]
            owner.close_failed_load()
            raise
        finally:
            if epoch is _EPOCH:
                _LOADING = False


class _Profile:
    def __init__(self, manifest_path, *, expected_raw=None, expected_artifacts=None):
        self.captured = _Captured(manifest_path, expected_raw=expected_raw,
                                  expected_artifacts=expected_artifacts)
        module = _extension(self.captured)
        self.native = module.Profile(self.captured.artifacts["policy"][1],
                                     sha256(self.captured.raw).hexdigest())
        self.pid = os.getpid()
        self.thread = threading.get_ident()
        self.module = module

    def session(self, *args):
        if self.pid != os.getpid() or self.thread != threading.get_ident():
            raise ValueError("native cold execute scope crossed process/thread")
        # Existing invoke() immutable source/image checks remain unchanged.
        # This verifies this additional native policy/code authority as well.
        self.captured.unchanged()
        _CODE_OWNER.check()
        _canonical_io()
        return self.native.session(*args)

    def statistics(self):
        self.captured.unchanged()
        _CODE_OWNER.check()
        return self.native.statistics()


def _bind_profile(kind, namespace, profile):
    if kind not in {"flat", "linked"}:
        raise ValueError("unknown native observer execute route")
    actual_root = Path(namespace["ROOT"]).resolve(strict=True)
    if profile.captured.root != actual_root:
        raise ValueError("native execute module is outside the admitted source root")
    if kind == "flat":
        def execute(executable_bytes, request, *, cwd, timeout=20, arguments=(), output_fd=None):
            session = profile.session(executable_bytes, request, cwd, timeout,
                                      arguments, output_fd, None, False)
            return session.run()
    else:
        def execute(executable_bytes, request, *, cwd, timeout=20, arguments=(), output_fd=None, snapshot_fd=None):
            session = profile.session(executable_bytes, request, cwd, timeout,
                                      arguments, output_fd, snapshot_fd, True)
            return session.run()
    # Genuine new Python functions, with new source/code identity. No __wrapped__
    # identity fiction and no retained original business function in the closure.
    execute.hia_cold_native_profile = profile
    execute.hia_cold_native_route = kind
    return execute


def bind_execute(kind, namespace):
    path = os.environ.get(SELECTOR)
    if path is None:
        return namespace["execute"]
    if not path or os.environ.get(DEVELOPMENT) != "1":
        raise ValueError("native cold transport requires explicit development selection")
    return _bind_profile(kind, namespace, _Profile(path))


def bind_phase_inputs(data, inputs):
    """Consume only this fresh phase's three explicitly signed artifact inputs.

    The caller has already read every original phase input and source manifest.
    No inherited external native image or environment selector is consulted.
    """
    required = ("native_transport_manifest", "native_transport_policy", "native_transport_extension")
    if any(name not in data or name not in inputs for name in required):
        raise ValueError("explicit native transport phase inputs are incomplete")
    profile = _Profile(inputs[required[0]]["path"], expected_raw=data[required[0]],
                       expected_artifacts={"policy": data[required[1]], "extension": data[required[2]]})
    from tools import hia_selfhost_native_observer as flat
    from tools import hia_selfhost_linked_observer as linked
    flat.execute = _bind_profile("flat", vars(flat), profile)
    linked.execute = _bind_profile("linked", vars(linked), profile)
    return profile
