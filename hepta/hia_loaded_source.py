"""Bind proof-source identities to the Python modules actually imported.

Ordinary imports passively retain the executing top-level code object and a
stable source snapshot. A proof identity request compares that code (including
nested functions and constant initializers) with an independent compilation
of the snapshot. This catches a timestamp-valid stale pyc without
relying on its header, loader cache, or a hash of source that was never run.
Later identity requests require the same module object and unchanged source.

This is a package-loading contract for a fresh, trusted Python process. It
does not authenticate arbitrary monkeypatches, a compromised interpreter,
import machinery or filesystem, or retrofit these checks into an old process
that started before this mechanism was installed. Reloads fail closed;
installing a changed checker requires a new process.
"""
from __future__ import annotations

from hashlib import sha256
import importlib
import os
from pathlib import Path
import stat
import struct
import sys
import threading
import types

try:
    from .hia_native_admission_io import resolve_path as _admission_resolve
except ModuleNotFoundError as error:
    if error.name != __package__ + '.hia_native_admission_io':
        raise

    def _admission_resolve(path, *, strict):
        return Path(path).resolve(strict=strict)

try:
    import posix as _source_io
except ImportError:
    _source_io = os


PROFILE = "hia.loaded-python-source.v1"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
_LOCK = threading.RLock()
_MODULES = {}
_TAINTED = set()
_VERIFIED = set()


class VerifiedSourceRejected(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise VerifiedSourceRejected("E_HIA_VERIFIED_SOURCE: " + message)


def _open_source_without_symlinks(path):
    """Open each absolute source component without following directory aliases."""
    raw = os.fspath(path)
    _require(type(raw) is str and raw.startswith("/"),
             "registered source must be an absolute path")
    components = raw.split("/")[1:]
    _require(bool(components) and all(name not in ("", ".", "..") for name in components),
             "registered source has an ambiguous path component")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    _require(nofollow and directory and _source_io.open in os.supports_dir_fd,
             "descriptor-relative source opening is unavailable")
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | nofollow | directory | close_on_exec
    source_flags = os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0) | close_on_exec
    source_flags |= getattr(os, "O_BINARY", 0)
    parent = _source_io.open("/", directory_flags)
    try:
        for name in components[:-1]:
            following = _source_io.open(name, directory_flags, dir_fd=parent)
            _source_io.close(parent)
            parent = following
        return _source_io.open(components[-1], source_flags, dir_fd=parent)
    finally:
        _source_io.close(parent)


def _read_source(path):
    """Read one bounded regular source through a single stable descriptor."""
    try:
        descriptor = _open_source_without_symlinks(path)
        try:
            before = _source_io.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_SOURCE_BYTES,
                     "registered source is not a bounded ordinary file")
            chunks, remaining = [], MAX_SOURCE_BYTES + 1
            while remaining:
                block = _source_io.read(descriptor, min(65536, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            raw = b"".join(chunks)
            after = _source_io.fstat(descriptor)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                      value.st_mtime_ns, value.st_ctime_ns)
            _require(identity(before) == identity(after) and len(raw) == before.st_size,
                     "registered source changed during capture")
            return raw
        finally:
            _source_io.close(descriptor)
    except OSError as exc:
        raise VerifiedSourceRejected("E_HIA_VERIFIED_SOURCE: registered source is unavailable") from exc


def _constant_shape(value):
    """Preserve constant types and floating-point bits, including signed zero."""
    typ = type(value)
    if typ is types.CodeType:
        return ("code", _code_shape(value))
    if typ is slice:
        return ("slice", _constant_shape(value.start),
                _constant_shape(value.stop), _constant_shape(value.step))
    if typ is tuple:
        return ("tuple", tuple(_constant_shape(item) for item in value))
    if typ is frozenset:
        return ("frozenset", frozenset(_constant_shape(item) for item in value))
    if typ is float:
        return ("float", struct.pack("!d", value))
    if typ is complex:
        return ("complex", struct.pack("!dd", value.real, value.imag))
    _require(typ in (type(None), type(Ellipsis), bool, int, str, bytes),
             "unreviewed Python code constant")
    return (typ.__name__, value)


def _code_shape(code):
    """Compare the complete executable tree, not only exported function names."""
    fields = ("co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_nlocals",
              "co_stacksize", "co_flags", "co_code", "co_names", "co_varnames",
              "co_freevars", "co_cellvars", "co_name", "co_qualname", "co_filename",
              "co_firstlineno", "co_linetable", "co_exceptiontable")
    return (tuple(getattr(code, field) for field in fields),
            tuple(_constant_shape(item) for item in code.co_consts))


def register_loaded_module(name):
    """Called once by a module's own top-level execution, after definitions."""
    frame = sys._getframe(1)
    try:
        namespace = frame.f_globals
        module = sys.modules.get(name)
        _require(type(module) is types.ModuleType and module.__dict__ is namespace and
                 namespace.get("__name__") == name and frame.f_code.co_name == "<module>",
                 "registration must come from the actual module execution")
        source = _admission_resolve(namespace["__file__"], strict=True)
        _require(source.suffix == ".py", "registered modules require retained Python source")
        with _LOCK:
            if name in _MODULES or name in _TAINTED:
                _TAINTED.add(name)
                raise VerifiedSourceRejected("E_HIA_VERIFIED_SOURCE: module reload requires a new process")
            raw = _read_source(source)
            # Ordinary compiler imports only retain immutable observations.
            # Compilation/comparison happens when a proof asks for an identity.
            _MODULES[name] = (module, namespace, source, sha256(raw).hexdigest(),
                              frame.f_code, raw)
    finally:
        del frame


def _module_identity(name):
    with _LOCK:
        _require(name not in _TAINTED, "reloaded module cannot authorize a source identity")
        record = _MODULES.get(name)
        _require(record is not None, "module has no executed-source binding: " + name)
        module, namespace, source, digest, executed_code, raw = record
        _require(sys.modules.get(name) is module and module.__dict__ is namespace and
                 namespace.get("__name__") == name and
                 _admission_resolve(namespace.get("__file__", ""), strict=False) == source,
                 "registered module object or source location was replaced: " + name)
        _require(sha256(_read_source(source)).hexdigest() == digest,
                 "loaded module source changed; start a new process: " + name)
        if name not in _VERIFIED:
            expected = compile(raw, executed_code.co_filename, "exec", dont_inherit=True,
                               optimize=sys.flags.optimize)
            _require(_code_shape(executed_code) == _code_shape(expected),
                     "executed module code differs from its retained source (stale bytecode)")
            _VERIFIED.add(name)
        return digest


def loaded_source_identity(owner, filenames):
    """Return hashes only for registered, still-matching sibling modules.

    Dependencies not yet imported must establish their own executing-code
    binding. The source-binding implementation is included in every map.
    """
    _module_identity(__name__)
    _require(type(owner) is str and "." in owner, "a package module owner is required")
    _module_identity(owner)
    package = owner.rsplit(".", 1)[0]
    names = tuple(filenames) + ("hia_loaded_source.py",)
    result = {}
    for filename in names:
        _require(type(filename) is str and filename.endswith(".py") and
                 filename[:-3].isidentifier(), "source identity requires a sibling Python filename")
        name = package + "." + filename[:-3]
        if name not in sys.modules:
            importlib.import_module(name)
        result[filename] = _module_identity(name)
    return result


def loaded_checker_identity(owner, filenames, helpers):
    """Bind executing bridge modules and the selected, admitted HIA images."""
    active = [(name, module, image) for name, module, image in helpers if image is not None]
    adapters = [module for _, module, _ in active]
    if active:
        adapters.append('hia_json_preflight_native.py')
    result = loaded_source_identity(owner, (*filenames, *adapters))
    for name, _, image in active:
        result[f'native_{name}_source_sha256'] = image.admitted_source_sha256
        result[f'native_{name}_image_sha256'] = image.image_sha256
    return result


register_loaded_module(__name__)
