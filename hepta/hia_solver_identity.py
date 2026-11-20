"""Bind identified Z3 source and its native library to their first execution.

Only a fresh standard-source import of the pinned Linux Z3 package can acquire
this identity. A process that imported Z3 before this monitor was installed
must start a new process; it cannot retroactively label that execution.
This is an import/load contract under a trusted Python interpreter and OS,
not protection against arbitrary in-process monkeypatches or hostile loaders.
"""
from __future__ import annotations

import atexit
import ctypes
from hashlib import sha256
import importlib.abc
import importlib.machinery
import os
from pathlib import Path
import stat
import sys
import threading
import types

from .hia_loaded_source import (_code_shape, loaded_source_identity,
                                register_loaded_module)


PROFILE = "hia.loaded-z3.python-source-and-library.linux.v1"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_LIBRARY_BYTES = 128 * 1024 * 1024
MAX_MODULES = 64
_LOCK = threading.RLock()
_MODULES = {}
_NATIVE = None
_CORE_IMPORTS = {}
_PRELOADED = tuple(name for name in sys.modules if name == "z3" or name.startswith("z3."))
_FAILURE = None
_AUDIT_READY = False
_AUDIT_TOKEN = object()


class VerifiedSolverRejected(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise VerifiedSolverRejected("E_HIA_VERIFIED_SOLVER: " + message)


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_descriptor(descriptor, limit):
    before = os.fstat(descriptor)
    _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit,
             "solver input is not a bounded regular file")
    chunks, offset = [], 0
    while offset <= limit:
        chunk = os.pread(descriptor, min(65536, limit + 1 - offset), offset)
        if not chunk:
            break
        chunks.append(chunk); offset += len(chunk)
    raw = b"".join(chunks)
    after = os.fstat(descriptor)
    _require(_metadata(before) == _metadata(after) and len(raw) == before.st_size,
             "solver input changed during stable capture")
    return raw, _metadata(after)


def _capture(path, limit):
    path = Path(path).resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        raw, metadata = _read_descriptor(descriptor, limit)
        _require(_metadata(path.stat()) == metadata, "solver pathname changed during capture")
        return {"path": path, "fd": descriptor, "metadata": metadata,
                "sha256": sha256(raw).hexdigest(), "raw": raw, "limit": limit}
    except BaseException:
        os.close(descriptor)
        raise


def _recheck_file(record):
    try:
        _require(_metadata(record["path"].stat()) == record["metadata"],
                 "solver source or library pathname changed after load")
        raw, metadata = _read_descriptor(record["fd"], record["limit"])
        _require(metadata == record["metadata"] and sha256(raw).hexdigest() == record["sha256"],
                 "solver source or library bytes changed after load")
        _require(_metadata(record["path"].stat()) == metadata,
                 "solver pathname changed during recheck")
    except OSError as exc:
        raise VerifiedSolverRejected("E_HIA_VERIFIED_SOLVER: retained solver file is unavailable") from exc


def _maps():
    _require(sys.platform == "linux", "loaded solver identity requires Linux mappings")
    try:
        with Path("/proc/self/maps").open("rb") as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        _require(len(raw) <= 8 * 1024 * 1024, "process mapping inventory is too large")
        rows = []
        for line in raw.decode().splitlines():
            fields = line.split(None, 5)
            _require(len(fields) >= 5, "incomplete process mapping row")
            left, right = (int(value, 16) for value in fields[0].split("-"))
            major, minor = (int(value, 16) for value in fields[3].split(":"))
            rows.append((left, right, fields[1], int(fields[2], 16), major, minor,
                         int(fields[4]), fields[5] if len(fields) == 6 else ""))
        return rows
    except (OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, VerifiedSolverRejected):
            raise
        raise VerifiedSolverRejected("E_HIA_VERIFIED_SOLVER: process mappings are unavailable") from exc


def _same_file(row, record):
    device, inode = record["metadata"][:2]
    return row[4:7] == (os.major(device), os.minor(device), inode)


def _audit(event, args):
    global _AUDIT_READY, _FAILURE
    if event == "hepta.hia_solver_identity.monitor" and args == (_AUDIT_TOKEN,):
        _AUDIT_READY = True
        return
    if event != "ctypes.dlopen":
        return
    with _LOCK:
        captures = _CORE_IMPORTS.get(threading.get_ident())
        if captures is None:
            return
        record = None
        try:
            _require(_FAILURE is None, "solver load already failed; start a new process")
            _require(len(args) == 1 and type(args[0]) is str and Path(args[0]).is_absolute(),
                     "solver native load requires an observed absolute pathname")
            record = _capture(args[0], MAX_LIBRARY_BYTES)
            # The native file's hash and pinned descriptor suffice after
            # capture; keep source bytes only for executable Python modules.
            record.pop("raw")
            rows = _maps()
            _require(not any(_same_file(row, record) for row in rows),
                     "solver library was already mapped before controlled load; start a new process")
            _require(not any(Path(row[7].removesuffix(" (deleted)")).name.startswith("libz3")
                             for row in rows if row[7]),
                     "another solver library was already mapped; start a new process")
            captures.append(record)
        except BaseException as exc:
            if record is not None:
                os.close(record["fd"])
            _FAILURE = "native capture failed: " + type(exc).__name__
            raise


def _native_function(module):
    function = module.Z3_get_version.__defaults__[0].f
    libraries = [item for item in function._objects.values() if hasattr(item, "_name")]
    _require(len(libraries) == 1 and type(libraries[0]) is ctypes.CDLL,
             "ambiguous actual solver library handle")
    return function, libraries[0]


def _bind_native(module, captures):
    global _NATIVE
    _require(_FAILURE is None and _NATIVE is None, "solver native load did not complete exactly once")
    function, library = _native_function(module)
    path = Path(library._name).resolve(strict=True)
    selected = [record for record in captures if record["path"] == path]
    _require(len(selected) == 1, "actual solver handle has no unique pre-load file capture")
    record = selected[0]
    for other in captures:
        if other is not record:
            os.close(other["fd"])
    _recheck_file(record)
    address = ctypes.cast(function, ctypes.c_void_p).value
    rows = [row for row in _maps() if _same_file(row, record)]
    executable = [row for row in rows if "x" in row[2]]
    _require(executable and all(row[2] == "r-xp" for row in executable),
             "solver executable mappings are not private read/execute file mappings")
    anchors = [row for row in executable if row[0] <= address < row[1]]
    _require(len(anchors) == 1, "actual solver symbol is outside the captured library mapping")
    _NATIVE = {"file": record, "module": module, "function": function, "library": library,
               "address": address, "executable": tuple(row[:7] for row in executable)}


def _recheck_native():
    _require(_NATIVE is not None, "solver native library has no controlled load binding")
    record = _NATIVE["file"]
    _recheck_file(record)
    function, library = _native_function(_NATIVE["module"])
    _require(function is _NATIVE["function"] and library is _NATIVE["library"] and
             Path(library._name).resolve(strict=True) == record["path"] and
             ctypes.cast(function, ctypes.c_void_p).value == _NATIVE["address"],
             "actual solver handle or native function was replaced")
    executable = tuple(row[:7] for row in _maps() if _same_file(row, record) and "x" in row[2])
    _require(executable == _NATIVE["executable"], "solver executable mapping changed after load")


class _SolverLoader(importlib.machinery.SourceFileLoader):
    def exec_module(self, module):
        global _FAILURE
        record = None
        core = self.name == "z3.z3core"
        captures = []
        try:
            with _LOCK:
                _require(not _PRELOADED, "Z3 was imported before controlled admission; start a new process")
                _require(_FAILURE is None and self.name not in _MODULES,
                         "solver reload or prior failed import requires a new process")
                _require(_AUDIT_READY, "solver load audit is unavailable")
                _require(len(_MODULES) < MAX_MODULES, "solver module inventory is too large")
            record = _capture(self.path, MAX_SOURCE_BYTES)
            code = self.get_code(self.name)
            _require(type(code) is types.CodeType, "solver loader did not return executable Python code")
            expected = compile(record["raw"], code.co_filename, "exec", dont_inherit=True,
                               optimize=sys.flags.optimize)
            _require(_code_shape(code) == _code_shape(expected),
                     "solver executed code differs from retained source (stale bytecode)")
            _recheck_file(record)
            if core:
                with _LOCK:
                    _require(threading.get_ident() not in _CORE_IMPORTS, "nested solver native import")
                    _CORE_IMPORTS[threading.get_ident()] = captures
            try:
                # Execute the exact compared object. Calling exec_module again
                # would let a loader fetch a different code object after check.
                exec(code, module.__dict__)
            finally:
                if core:
                    with _LOCK:
                        _CORE_IMPORTS.pop(threading.get_ident(), None)
            _recheck_file(record)
            if core:
                _bind_native(module, captures)
            with _LOCK:
                _MODULES[self.name] = {"module": module, "namespace": module.__dict__,
                                       "file": record, "code": code, "loader": self}
        except BaseException as exc:
            with _LOCK:
                _FAILURE = "solver import failed: " + type(exc).__name__
            if record is not None:
                os.close(record["fd"])
            for captured in captures:
                if _NATIVE is None or captured is not _NATIVE["file"]:
                    try:
                        os.close(captured["fd"])
                    except OSError:
                        pass
            raise


class _SolverFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        global _FAILURE
        if fullname != "z3" and not fullname.startswith("z3."):
            return None
        if target is not None or fullname in _MODULES:
            _FAILURE = "solver reload attempted"
            raise VerifiedSolverRejected("E_HIA_VERIFIED_SOLVER: solver reload requires a new process")
        _require(not _PRELOADED and _FAILURE is None,
                 "solver was preloaded or changed; start a new process")
        specification = importlib.machinery.PathFinder.find_spec(fullname, path)
        if specification is None:
            return None
        _require(type(specification.loader) is importlib.machinery.SourceFileLoader,
                 "solver needs a standard source loader")
        specification.loader = _SolverLoader(fullname, specification.loader.path)
        return specification


def solver_identity(z, *, expected_version):
    """Recheck code, pinned files and actual mappings, returning fresh evidence."""
    monitor = loaded_source_identity(__name__, ("hia_solver_identity.py",))
    with _LOCK:
        _require(not _PRELOADED, "Z3 was imported before controlled admission; start a new process")
        _require(_FAILURE is None and _AUDIT_READY, "solver import/load binding failed; start a new process")
        _require("z3" in _MODULES and _MODULES["z3"]["module"] is z,
                 "solver package has no completed controlled import")
        names = {name for name in sys.modules if name == "z3" or name.startswith("z3.")}
        _require(names == set(_MODULES), "solver module inventory differs from controlled imports")
        package = _MODULES["z3"]["file"]["path"].parent
        files = {}
        for name, row in _MODULES.items():
            module, namespace, record = row["module"], row["namespace"], row["file"]
            _recheck_file(record)
            _require(sys.modules.get(name) is module and module.__dict__ is namespace and
                     namespace.get("__name__") == name and module.__loader__ is row["loader"] and
                     Path(module.__file__).resolve(strict=True) == record["path"] and
                     record["path"].parent == package,
                     "solver module object, loader or source location changed")
            files[record["path"].name] = record
        _require(set(files) == {path.name for path in package.glob("*.py")},
                 "solver source inventory differs from executed modules")
        _recheck_native()
        _require(z.get_version_string() == expected_version, "the pinned Z3 version is required")
        digest = sha256()
        for filename, record in sorted(files.items()):
            digest.update(filename.encode() + b"\0" + record["raw"] + b"\0")
        native = _NATIVE["file"]
        device, inode, size = native["metadata"][:3]
        return {"name": "Z3", "version": expected_version,
                "binding_sha256": digest.hexdigest(), "library_sha256": native["sha256"],
                "load_binding": {"profile": PROFILE, "controlled_import": True,
                    "binding_code_matches_source": True,
                    "binding_files": {name: row["sha256"] for name, row in sorted(files.items())},
                    "monitor_sha256": monitor["hia_solver_identity.py"],
                    "preloaded_solver_authorized": False,
                    "library": {"device_major": os.major(device), "device_minor": os.minor(device),
                        "inode": inode, "source_size": size, "anchor_symbol": "Z3_get_version",
                        "mapped_executable_segments": len(_NATIVE["executable"]),
                        "file_identity_rechecked": True, "loaded_mapping_bound": True}}}


def _close_files():
    records = [row["file"] for row in _MODULES.values()]
    if _NATIVE is not None:
        records.append(_NATIVE["file"])
    for record in records:
        try:
            os.close(record["fd"])
        except OSError:
            pass


register_loaded_module(__name__)
if not _PRELOADED:
    sys.addaudithook(_audit)
    sys.audit("hepta.hia_solver_identity.monitor", _AUDIT_TOKEN)
    sys.meta_path.insert(0, _SolverFinder())
atexit.register(_close_files)
