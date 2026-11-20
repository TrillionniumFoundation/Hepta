"""Source-bound CPython transport for the selected HIA byte-image caller.

The extension is a mechanical caller, not an HIA policy implementation. Its supported
profile is explicit and narrower than the package's unselected Python support.
Loading happens at the existing selected-adapter/callable construction boundary;
the original HIA image and buffer checks retain their own authority.
"""
from __future__ import annotations
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

ABI = "hepta.native-image.three-writable-buffers.v1"
SCHEMA = "hepta.native-image.build.v1"
SOURCES = ('hepta/native/native_image.c', 'hepta/native/native_carrier_build.py', 'hepta/hia_native_image.py', 'hepta/hia_native_helpers.py', 'hepta/hia_native_carrier_worker_bundle.py', 'hepta/hia_service_artifact_native.py', 'hepta/hia_service_artifact_bridge.py')
_PACKAGE = Path(__file__).resolve().parent
_EXTENSION = None
_CAPTURED = None
_LOADING = False
_SEALED = None
_LOADER_CUSTODY = []
_BROKEN_LOAD = False
_EXPORTED = ()
_EXPORT_NAMES = ('Buffer', 'Image')
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
        raise RuntimeError("selected Native image mechanical transport has no admitted CPython/GIL/Linux profile")
    return {
        "implementation": "cpython", "python": list(sys.version_info[:3]),
        "platform": sys.platform, "machine": platform.machine(),
        "soabi": sysconfig.get_config_var("SOABI"),
        "extension_suffix": suffix, "gil_disabled": False,
    }


def _regular(path, maximum=8 << 20):
    if path != path.resolve(strict=True):
        raise ValueError("Native image authority must use its exact canonical package path")
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= maximum):
        raise ValueError("Native image transport authority is not a single regular file")
    with path.open("rb") as stream:
        opened = _os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("Native image transport authority changed before read")
        raw = stream.read()
        after = _os.fstat(stream.fileno())
    current = path.lstat()
    if path != path.resolve(strict=True):
        raise ValueError("Native image authority path changed during capture")
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
              "st_mode", "st_nlink")
    if (any(getattr(before, key) != getattr(after, key) for key in fields)
            or any(getattr(after, key) != getattr(current, key) for key in fields)
            or len(raw) != after.st_size):
        raise ValueError("Native image transport authority changed during read")
    return raw


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate Native image mechanical identity key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError('nonfinite native image build identity')


def _source_path(name):
    prefix = "hepta/"
    if type(name) is not str or name not in SOURCES or not name.startswith(prefix):
        raise ValueError("undeclared Native image mechanical source")
    return _PACKAGE / name[len(prefix):]


def _bundle():
    profile = _profile()
    manifest_path = _PACKAGE / "_native_image_build.json"
    manifest_raw = _regular(manifest_path)
    manifest = json.loads(manifest_raw, object_pairs_hook=_pairs, parse_constant=_constant)
    expected_keys = {"schema", "abi", "profile", "binary", "sources",
                     "compiler_commands", "compiler_executables",
                     "build_scope", "product_qualification_claimed"}
    if (type(manifest) is not dict or set(manifest) != expected_keys
            or manifest["schema"] != SCHEMA or manifest["abi"] != ABI
            or type(manifest["profile"]) is not dict
            or json.dumps(manifest["profile"], sort_keys=True, allow_nan=False)
                != json.dumps(profile, sort_keys=True, allow_nan=False)
            or manifest["build_scope"] != "CPYTHON_MECHANICAL_EXTENSION_ONLY"
            or manifest["product_qualification_claimed"] is not False):
        raise ValueError("Native image mechanical build/profile identity differs")
    binary = manifest["binary"]
    expected_name = "_hia_native_image" + profile["extension_suffix"]
    if (type(binary) is not dict or set(binary) != {"name", "bytes", "sha256"}
            or binary["name"] != expected_name):
        raise ValueError("Native image mechanical executable identity differs")
    executable = _PACKAGE / expected_name
    executable_raw = _regular(executable, 1 << 20)
    if (type(binary["bytes"]) is not int or binary["bytes"] != len(executable_raw)
            or binary["sha256"] != sha256(executable_raw).hexdigest()):
        raise ValueError("Native image mechanical executable changed")
    sources = manifest["sources"]
    if type(sources) is not dict or tuple(sources) != tuple(sorted(SOURCES)):
        raise ValueError("Native image mechanical source closure differs")
    source_raw = {}
    for name in SOURCES:
        raw = _regular(_source_path(name))
        pin = sources[name]
        if (type(pin) is not dict or set(pin) != {"bytes", "sha256"}
                or type(pin["bytes"]) is not int or pin["bytes"] != len(raw)
                or pin["sha256"] != sha256(raw).hexdigest()):
            raise ValueError("Native image mechanical source changed: " + name)
        source_raw[name] = raw
    commands = manifest["compiler_commands"]
    executables = manifest["compiler_executables"]
    if (type(commands) is not list or not commands
            or any(type(row) is not list or not row or
                   any(type(value) is not str for value in row) for row in commands)
            or type(executables) is not dict or not executables):
        raise ValueError("Native image mechanical compiler receipt is incomplete")
    # Re-read exact captured bytes. No expected pin is derived from a later
    # file read and paired with earlier parsed data.
    if (_regular(manifest_path) != manifest_raw
            or _regular(executable, 1 << 20) != executable_raw
            or any(_regular(_source_path(name)) != raw for name, raw in source_raw.items())):
        raise ValueError("Native image mechanical authority changed during complete admission")
    return {"manifest": manifest_raw, "binary": executable_raw,
            "sources": source_raw, "path": executable, "profile": profile}


def _capture_exports(module):
    values = vars(module)
    if type(values.get('ABI')) is not str or values['ABI'] != ABI:
        raise ValueError('native image ABI constant differs')
    captured = []
    for name in _EXPORT_NAMES:
        value = values.get(name)
        if (type(value) is not type or value.__module__ != 'hepta._hia_native_image'
                or value.__name__ != name or value.__qualname__ != name
                or not value.__flags__ & (1 << 14)):
            raise ValueError('native image type binding or real GC visibility differs')
        captured.append((name, value))
        # Capture every actual heap-type entry. A replaced special method or
        # descriptor is not repaired from an earlier successful admission.
        for member, item in vars(value).items():
            captured.append((name + '.' + member, item))
    return tuple(captured)


def _check_exports(module):
    current = _capture_exports(module)
    if len(current) != len(_EXPORTED) or any(
            name != saved_name or value is not saved
            for (name, value), (saved_name, saved) in zip(current, _EXPORTED)):
        raise ValueError("mechanical executed export changed")

def _require_authority(captured):
    from .hia_native_helpers import pinned_mechanical_bridge
    return pinned_mechanical_bridge("native-image", ABI).current(captured)


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
    name = "hepta._hia_native_image"
    if name in sys.modules:
        raise ValueError("unowned mechanical extension module already exists")
    if not hasattr(_os, "memfd_create"):
        raise RuntimeError("mechanical ABI requires the Linux sealed-descriptor primitive")
    owner = [None, None, False, "RESERVED"]
    _LOADER_CUSTODY.append(owner)  # reserve before the descriptor side effect
    loaded = None
    try:
        fd = _os.memfd_create("hia-native-image", _os.MFD_CLOEXEC | _os.MFD_ALLOW_SEALING)
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
        captured = _bundle()
        _require_authority(captured)
        if _EXTENSION is not None:
            if captured != _CAPTURED:
                raise ValueError("selected Native image mechanical authority changed")
            fd, seals = _SEALED
            if (fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals
                    or _os.pread(fd, len(captured["binary"]) + 1, 0) != captured["binary"]):
                raise ValueError("loaded mechanical executable custody changed")
            _check_exports(_EXTENSION)
            return _EXTENSION
        if _LOADING or _BROKEN_LOAD:
            raise RuntimeError("recursive or previously incomplete mechanical linker admission")
        _LOADING = True
        epoch = _EPOCH
        loaded = None
        owner = None
        try:
            loaded, owner, seals = _load_sealed(captured)
            fd = owner[0]
            if _EPOCH is not epoch or loaded.ABI != ABI:
                raise ValueError("Native image mechanical loaded module/epoch differs")
            after = _bundle()
            _require_authority(after)
            if after != captured:
                raise ValueError("Native image mechanical authority changed during module load")
            exports = _capture_exports(loaded)
            _EXTENSION, _CAPTURED, _SEALED, _EXPORTED = loaded, captured, (fd, seals), exports
            owner[3] = "MODULE_LIFETIME"
            owner = None  # _LOADER_CUSTODY owns the actual descriptor for this loaded module
            _BROKEN_LOAD = False
            return loaded
        finally:
            if owner is not None:
                if sys.modules.get("hepta._hia_native_image") is loaded:
                    del sys.modules["hepta._hia_native_image"]
                _close_loader_descriptor(owner)
            if _EPOCH is epoch:
                _LOADING = False


def preload_if_present():
    """Ordinary imports never load unpinned C; explicit capsule construction does it."""
    return None


def admit_runtime():
    loaded = extension()
    actual = _bundle()
    _require_authority(actual)
    if actual != _CAPTURED or loaded is not _EXTENSION:
        raise ValueError("selected Native image mechanical authority changed")
    return None


def selected_extension():
    """Select a live explicit v6; lost authority never becomes an old route."""
    from . import hia_native_helpers as authority
    if type(authority._MECHANICAL_SELECTED) is not bool:
        raise ValueError('mechanical route selection is not an exact flag')
    scope, constructing, active = (authority._MECHANICAL_SCOPE,
                                  authority._MECHANICAL_BUILD, authority._ACTIVE)
    if not authority._MECHANICAL_SELECTED:
        if scope is not None or constructing is not None:
            raise ValueError('mechanical authority exists outside its explicit selection')
        return None
    authority._check_scope_owner()
    if constructing is not None:
        if scope is not None or active is not None:
            raise ValueError('mechanical constructor overlaps another authority')
        binding = constructing
    else:
        binding = scope
        if binding is not None and active is not binding:
            raise ValueError('mechanical scope lost its original authority')
    if binding is None or authority._SCOPE_OWNER is None:
        raise ValueError('selected mechanical route has no live original authority')
    from .hia_native_carrier_worker_bundle import NativeCarrierWorkerBinding
    if type(binding) is NativeCarrierWorkerBinding:
        authority.selected_mechanical_bridge('native-image', ABI).current(_bundle())
        return extension()
    from .hia_mechanical_worker_bundle import NativeMechanicalWorkerBinding
    if type(binding) is NativeMechanicalWorkerBinding:
        binding.check_owner()
        return None
    raise ValueError('selected mechanical route has an unregistered authority type')
