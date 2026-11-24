"""Source-bound CPython transport for the selected complete Slot owner.

The extension is a mechanical caller, not a second Slot policy. Its supported
profile is explicit and narrower than the package's unselected Python support.
Loading happens at the existing selected-adapter/callable construction boundary;
the exact original argument signature still binds before admission or HIA entry.
"""
from __future__ import annotations
import builtins
from hashlib import sha256
import importlib
import importlib.machinery
import importlib.util
import fcntl
import json
from pathlib import Path
import platform
import stat
import sys
import sysconfig
import threading
import types

ABI = "hepta.slot.mechanical.cpython-gil-linux.v1"
SCHEMA = "hepta.slot.mechanical.build.v2"
SOURCES = (
    "hepta/native/slot_mechanical.c",
    "hepta/hia_slot_continuations.py",
    "hepta/hia_slot_mechanical.py",
    "hepta/hia_slot_operations_native.py",
    "hepta/hia_slot_operations_selection.py",
    "hepta/hia_slot_operations_protocol.py",
    "hepta/hia_slot_operation_series.py",
    "hepta/hia_native_delivery.py",
    "hepta/hia_native_helpers.py",
    "hepta/hia_mechanical_worker_bundle.py",
    "hepta/native/slot_mechanical_build.py",
)
_PACKAGE = Path(__file__).resolve().parent
_EXTENSION = None
_CAPTURED = None
_LOADING = False
_SEALED = None
_LOADER_CUSTODY = []
_BROKEN_LOAD = False
_EXPORTED = ()
_EXPORT_NAMES = ('admission_files', 'admission_check', 'execution_counters', 'bind', 'run_frame', 'start', 'begin', 'ack', 'returned', 'propagating', 'failed', 'pending', 'bad_port', 'sql_prepare', 'sql_borrow', 'sql_arguments', 'and_true', 'keep_rhs', 'and_done', 'lease_open', 'lease_opcode', 'iteration_open', 'iteration_item', 'iteration_end', 'unwind')
_LOCK = threading.RLock()
# A fork never inherits a locked loader lock or an in-progress admission.
_EPOCH = object()

def _reset_loader():
    global _LOCK, _LOADING, _EPOCH
    _LOCK = threading.RLock()
    _LOADING = False
    _EPOCH = object()

import os as _os
if hasattr(_os, "register_at_fork"):
    _os.register_at_fork(after_in_child=_reset_loader)


def _profile():
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if (sys.implementation.name != "cpython" or sys.platform != "linux"
            or not (3, 11) <= sys.version_info[:2] <= (3, 14)
            or bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
            or platform.machine() != "x86_64"
            or sysconfig.get_config_var("SIZEOF_VOID_P") != 8
            or type(suffix) is not str or not suffix.startswith(".")
            or "/" in suffix):
        raise RuntimeError("selected Slot mechanical transport has no admitted CPython/GIL/Linux profile")
    return {
        "implementation": "cpython", "python": list(sys.version_info[:3]),
        "platform": sys.platform, "machine": platform.machine(),
        "soabi": sysconfig.get_config_var("SOABI"),
        "extension_suffix": suffix, "gil_disabled": False,
    }


def _regular(path):
    if path != path.resolve(strict=True):
        raise ValueError("Slot authority must use its exact canonical package path")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("Slot transport authority is not a single regular file")
    with path.open("rb") as stream:
        opened = _os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("Slot transport authority changed before read")
        raw = stream.read()
        after = _os.fstat(stream.fileno())
    current = path.lstat()
    if path != path.resolve(strict=True):
        raise ValueError("Slot authority path changed during capture")
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
              "st_mode", "st_nlink")
    if (any(getattr(before, key) != getattr(after, key) for key in fields)
            or any(getattr(after, key) != getattr(current, key) for key in fields)
            or len(raw) != after.st_size):
        raise ValueError("Slot transport authority changed during read")
    return raw


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate Slot mechanical identity key")
        result[key] = value
    return result


def _source_path(name):
    prefix = "hepta/"
    if type(name) is not str or name not in SOURCES or not name.startswith(prefix):
        raise ValueError("undeclared Slot mechanical source")
    return _PACKAGE / name[len(prefix):]


def _bundle():
    profile = _profile()
    manifest_path = _PACKAGE / "_slot_mechanical_build.json"
    manifest_raw = _regular(manifest_path)
    manifest = json.loads(manifest_raw, object_pairs_hook=_pairs)
    expected_keys = {"schema", "abi", "profile", "binary", "sources",
                     "compiler_commands", "compiler_executables",
                     "build_scope", "product_qualification_claimed"}
    if (type(manifest) is not dict or set(manifest) != expected_keys
            or manifest["schema"] != SCHEMA or manifest["abi"] != ABI
            or manifest["profile"] != profile
            or manifest["build_scope"] != "CPYTHON_MECHANICAL_EXTENSION_ONLY"
            or manifest["product_qualification_claimed"] is not False):
        raise ValueError("Slot mechanical build/profile identity differs")
    binary = manifest["binary"]
    expected_name = "_hia_slot_mechanical" + profile["extension_suffix"]
    if (type(binary) is not dict or set(binary) != {"name", "bytes", "sha256"}
            or binary["name"] != expected_name):
        raise ValueError("Slot mechanical executable identity differs")
    executable = _PACKAGE / expected_name
    executable_raw = _regular(executable)
    if (type(binary["bytes"]) is not int or binary["bytes"] != len(executable_raw)
            or binary["sha256"] != sha256(executable_raw).hexdigest()):
        raise ValueError("Slot mechanical executable changed")
    sources = manifest["sources"]
    if type(sources) is not dict or tuple(sources) != tuple(sorted(SOURCES)):
        raise ValueError("Slot mechanical source closure differs")
    source_raw = {}
    for name in SOURCES:
        raw = _regular(_source_path(name))
        pin = sources[name]
        if (type(pin) is not dict or set(pin) != {"bytes", "sha256"}
                or type(pin["bytes"]) is not int or pin["bytes"] != len(raw)
                or pin["sha256"] != sha256(raw).hexdigest()):
            raise ValueError("Slot mechanical source changed: " + name)
        source_raw[name] = raw
    commands = manifest["compiler_commands"]
    executables = manifest["compiler_executables"]
    if (type(commands) is not list or not commands
            or any(type(row) is not list or not row or
                   any(type(value) is not str for value in row) for row in commands)
            or type(executables) is not dict or not executables):
        raise ValueError("Slot mechanical compiler receipt is incomplete")
    # Re-read exact captured bytes. No expected pin is derived from a later
    # file read and paired with earlier parsed data.
    if (_regular(manifest_path) != manifest_raw
            or _regular(executable) != executable_raw
            or any(_regular(_source_path(name)) != raw for name, raw in source_raw.items())):
        raise ValueError("Slot mechanical authority changed during complete admission")
    return {"manifest": manifest_raw, "binary": executable_raw,
            "sources": source_raw, "path": executable, "profile": profile}


def _capture_exports(module):
    constants = {"ABI": ABI, "MAJOR": sys.version_info.major,
                 "MINOR": sys.version_info.minor, "MODES": 15, "PORTS": 136}
    values = vars(module)
    for name, expected in constants.items():
        actual = values.get(name)
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError("mechanical runtime constant differs")
    result = []
    for name in _EXPORT_NAMES:
        value = values.get(name)
        if type(value) is not types.BuiltinFunctionType or value.__self__ is not module:
            raise ValueError("mechanical C export has a different live binding")
        result.append((name, value))
    return tuple(result)


def _check_exports(module):
    current = _capture_exports(module)
    if len(current) != len(_EXPORTED) or any(
            name != saved_name or value is not saved
            for (name, value), (saved_name, saved) in zip(current, _EXPORTED)):
        raise ValueError("mechanical executed export changed")

def _require_authority(captured):
    from .hia_native_helpers import pinned_mechanical_bridge
    return pinned_mechanical_bridge("slot-mechanical", ABI).current(captured)


def _close_loader_descriptor(owner):
    # The obligation was reserved before memfd_create. Never retry an uncertain
    # close: the number may already refer to another descriptor.
    if owner[2]:
        raise RuntimeError("mechanical descriptor close was already attempted")
    owner[2] = True
    try:
        _os.close(owner[0])
    except BaseException:
        owner[3] = "CLOSE_UNCONFIRMED"
        raise
    else:
        owner[3] = "CLOSED"
        # Keep the tiny closed record as a precise mechanical cleanup receipt.
        # It owns no business object, traceback or original provider resource.


def _load_sealed(captured):
    """Load only the already administrator-pinned bytes, not a raced pathname."""
    global _BROKEN_LOAD
    name = "hepta._hia_slot_mechanical"
    if name in sys.modules:
        raise ValueError("unowned mechanical extension module already exists")
    if not hasattr(_os, "memfd_create"):
        raise RuntimeError("mechanical ABI requires the Linux sealed-descriptor primitive")
    owner = [None, None, False, "RESERVED"]
    _LOADER_CUSTODY.append(owner)  # reserve before the descriptor side effect
    loaded = None
    try:
        fd = _os.memfd_create("hia-slot-mechanical", _os.MFD_CLOEXEC | _os.MFD_ALLOW_SEALING)
        owner[0], owner[3] = fd, "OPEN"
        raw = captured["binary"]
        position = 0
        while position < len(raw):
            written = _os.write(fd, raw[position:])
            if written <= 0:
                raise OSError("short mechanical executable descriptor write")
            position += written
        seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                 | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        path = "/proc/self/fd/" + str(fd)
        loader = importlib.machinery.ExtensionFileLoader(name, path)
        spec = importlib.util.spec_from_file_location(name, path, loader=loader)
        if (spec is None or fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals
                or _os.pread(fd, len(raw) + 1, 0) != raw):
            raise ValueError("mechanical executable descriptor differs before linker load")
        _require_authority(captured)  # final fresh complete check before any C code
        _BROKEN_LOAD = True          # a partial linker/init attempt is not retried
        loaded = importlib.util.module_from_spec(spec)
        sys.modules[name] = loaded
        loader.exec_module(loaded)
        if (loaded.__loader__ is not loader or loaded.__spec__ is not spec
                or loaded.__file__ != path or fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals
                or _os.pread(fd, len(raw) + 1, 0) != raw):
            raise ValueError("mechanical executed descriptor differs")
        owner[1], owner[3] = seals, "LINKED"
        return loaded, owner, seals
    except BaseException:
        if loaded is not None and sys.modules.get(name) is loaded:
            del sys.modules[name]
        if owner[0] is not None:
            _close_loader_descriptor(owner)
        else:
            owner[3] = "NOT_CREATED"
        raise


def extension():
    global _EXTENSION, _CAPTURED, _LOADING, _SEALED, _BROKEN_LOAD, _EXPORTED
    with _LOCK:
        if _EXTENSION is not None:
            # The admitted immutable capsule retains the exact schema, profile,
            # source and executable observations.  Its native file capability
            # repeats fresh byte/stat checks; no receipt is parsed again.
            captured = _CAPTURED
            _require_authority(captured)
            fd, seals = _SEALED
            if (fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals
                    or _os.pread(fd, len(captured["binary"]) + 1, 0) != captured["binary"]):
                raise ValueError("loaded mechanical executable custody changed")
            _check_exports(_EXTENSION)
            return _EXTENSION
        captured = _bundle()
        _require_authority(captured)
        if _LOADING or _BROKEN_LOAD:
            raise RuntimeError("recursive or previously incomplete mechanical linker admission")
        _LOADING = True
        epoch = _EPOCH
        loaded = None
        owner = None
        try:
            loaded, owner, seals = _load_sealed(captured)
            fd = owner[0]
            if (_EPOCH is not epoch or loaded.ABI != ABI
                    or loaded.MAJOR != sys.version_info.major
                    or loaded.MINOR != sys.version_info.minor
                    or loaded.MODES != 15 or loaded.PORTS != 136):
                raise ValueError("Slot mechanical loaded module/epoch differs")
            after = _bundle()
            _require_authority(after)
            if after != captured:
                raise ValueError("Slot mechanical authority changed during module load")
            exports = _capture_exports(loaded)
            _EXTENSION, _CAPTURED, _SEALED, _EXPORTED = loaded, captured, (fd, seals), exports
            owner[3] = "MODULE_LIFETIME"
            owner = None  # _LOADER_CUSTODY owns the actual descriptor for this loaded module
            _BROKEN_LOAD = False
            return loaded
        finally:
            if owner is not None:
                if sys.modules.get("hepta._hia_slot_mechanical") is loaded:
                    del sys.modules["hepta._hia_slot_mechanical"]
                _close_loader_descriptor(owner)
            if _EPOCH is epoch:
                _LOADING = False


def preload_if_present():
    """Ordinary imports never load unpinned C; v5 construction does it explicitly."""
    return None


def admit_runtime():
    loaded = extension()
    _require_authority(_CAPTURED)
    if loaded is not _EXTENSION:
        raise ValueError("selected Slot mechanical authority changed")
    return None


def _private_globals():
    module = extension()
    return {
        "_HIA_SLOT_EXCEPTION": builtins.BaseException,
        "_HIA_SLOT_START": module.start, "_HIA_SLOT_BEGIN": module.begin,
        "_HIA_SLOT_ACK": module.ack, "_HIA_SLOT_RETURN": module.returned,
        "_HIA_SLOT_PROPAGATING": module.propagating,
        "_HIA_SLOT_FAILED": module.failed, "_HIA_SLOT_PENDING": module.pending,
        "_HIA_SLOT_BAD_PORT": module.bad_port,
        "_HIA_SLOT_SQL_PREPARE": module.sql_prepare,
        "_HIA_SLOT_SQL_BORROW": module.sql_borrow,
        "_HIA_SLOT_SQL_ARGUMENTS": module.sql_arguments,
        "_HIA_SLOT_AND_TRUE": module.and_true,
        "_HIA_SLOT_KEEP_RHS": module.keep_rhs, "_HIA_SLOT_AND_DONE": module.and_done,
        "_HIA_SLOT_LEASE_OPEN": module.lease_open,
        "_HIA_SLOT_LEASE_OPCODE": module.lease_opcode,
        "_HIA_SLOT_ITERATION_OPEN": module.iteration_open,
        "_HIA_SLOT_ITERATION_ITEM": module.iteration_item,
        "_HIA_SLOT_ITERATION_END": module.iteration_end,
        "_HIA_SLOT_UNWIND": module.unwind,
    }


def _function(template, namespace, name, qualname, module, *, definition=None):
    # Use the actual original module dictionary: later dynamic provider/global
    # rebinding remains visible. No copied namespace, closure or user receiver.
    if type(namespace) is not dict:
        raise TypeError("Slot continuation requires its declared module namespace")
    for key, value in _private_globals().items():
        if key in namespace and namespace[key] is not value:
            raise ValueError("Slot mechanical primitive binding changed")
        namespace[key] = value
    if definition is not None:
        # Reuse only definition state. The complete loader/authority/export and
        # private-global checks above run on every lookup, including after fork.
        if (type(definition) is not types.FunctionType
                or definition.__globals__ is not namespace
                or definition.__code__ is not template.__code__
                or definition.__closure__ is not None
                or definition.__defaults__ is not template.__defaults__
                or definition.__kwdefaults__ is not template.__kwdefaults__
                or definition.__name__ != name
                or definition.__qualname__ != qualname
                or definition.__module__ != module
                or definition.__doc__ != "HIA-selected real-signature mechanical continuation."):
            raise ValueError("Slot mechanical definition identity changed")
        return definition
    function = types.FunctionType(template.__code__, namespace, name, template.__defaults__)
    function.__kwdefaults__ = template.__kwdefaults__
    function.__qualname__, function.__module__ = qualname, module
    function.__doc__ = "HIA-selected real-signature mechanical continuation."
    return function


def bind(template, binding, frame_type, unknown, mode, name, qualname, module, *, admission,
         definition=None):
    from . import hia_slot_ledger_native
    function = _function(template, vars(hia_slot_ledger_native), name, qualname, module,
                         definition=definition)
    return extension().bind(function, binding, frame_type, unknown, admission, mode)


def prepare_frame(frame):
    """Private raw-Frame compatibility; public calls never use this staging."""
    from .hia_slot_continuations import CONTINUATIONS
    from .hia_slot_operations_native import SlotOperationsUnknown
    template = CONTINUATIONS[frame.mode]
    function = _function(template, frame.namespace.namespace, template.__name__,
                         "NativeSlotLedgerStore." + template.__name__,
                         "hepta.hia_slot_ledger_native")
    code = function.__code__
    positional = tuple(frame.data[name] for name in code.co_varnames[:code.co_argcount])
    keyword_names = code.co_varnames[code.co_argcount:
                                   code.co_argcount + code.co_kwonlyargcount]
    keywords = {name: frame.data[name] for name in keyword_names}
    if code.co_flags & 0x08:  # CO_VARKEYWORDS, original _call only
        values = frame.data["values"]
        if type(values) is not dict or set(values) & set(keywords):
            raise TypeError("raw Slot variadic staging differs from its original signature")
        keywords.update(values)
    return function, positional, keywords, admit_runtime, SlotOperationsUnknown


# Import the templates while the real package namespace is still available.
from .hia_slot_continuations import CONTINUATIONS
