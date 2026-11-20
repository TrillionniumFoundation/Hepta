"""Load independently checked kernel images through immutable Linux memfds.

Every load validates the supplied bytes and freshly admits the decoded ISA.
Successful mappings are kept in a bounded process-lifetime registry, avoiding
both a writable pathname race and reuse of a /proc/self/fd name by dlopen.
The returned ctypes function has no solver or CPU probe in its hot path.
"""
from __future__ import annotations

from .hia_loaded_source import loaded_source_identity

import atexit
import ctypes
from dataclasses import dataclass
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import threading

from .hia_verified_cpu import require_host_isa
from .hia_verified_simd_check import validate_verified_simd_artifact
from .hia_safe_core_elf import bind_final_artifact
from .hia_safe_core import (ARTIFACT_PROFILE_V2, ARTIFACT_PROFILE_V3, ARTIFACT_PROFILE_V4, ARTIFACT_PROFILE_V5,
                           _unsigned_profile_version, validate_safe_core_artifact)
from .hia_program import verify_program


MAX_LOADED_IMAGES = 64
MAX_LOADED_IMAGE_BYTES = 64 * 1024 * 1024
MAX_IMAGE_BYTES = 8 * 1024 * 1024
# Linux UAPI values are stable even when the host Python was built with libc
# feature macros that omit these names from its fcntl module.
F_ADD_SEALS = getattr(fcntl, 'F_ADD_SEALS', 1033)
F_GET_SEALS = getattr(fcntl, 'F_GET_SEALS', 1034)
IMAGE_SEALS = (getattr(fcntl, 'F_SEAL_SEAL', 0x0001) |
               getattr(fcntl, 'F_SEAL_SHRINK', 0x0002) |
               getattr(fcntl, 'F_SEAL_GROW', 0x0004) |
               getattr(fcntl, 'F_SEAL_WRITE', 0x0008))
_LOCK = threading.RLock()
_IMAGES = {}
_TOTAL_BYTES = 0


class VerifiedKernelLoadRejected(ValueError):
    pass


@dataclass(frozen=True)
class LoadedVerifiedSIMD:
    function: object
    validation: dict
    cpu_admission: dict
    image_sha256: str
    mapping_admission: dict


@dataclass(frozen=True)
class LoadedVerifiedScalar:
    function: object
    validation: dict
    cpu_admission: dict
    image_sha256: str
    mapping_admission: dict
    parameter_types: tuple[str, ...]
    return_type: str


def _require(condition, message):
    if not condition:
        raise VerifiedKernelLoadRejected(message)


def _close_at_exit():
    for entry in _IMAGES.values():
        try:
            os.close(entry['fd'])
        except OSError:
            pass


atexit.register(_close_at_exit)


class _LinkMap(ctypes.Structure):
    _fields_ = [('load_bias', ctypes.c_size_t), ('name', ctypes.c_void_p),
                ('dynamic', ctypes.c_void_p), ('next', ctypes.c_void_p), ('previous', ctypes.c_void_p)]


def _loader_functions():
    # These are the GNU/Linux loader operations in the declared platform TCB,
    # never symbols resolved through the supplied kernel's handle.
    system = ctypes.CDLL(None)
    info = system['dlinfo']
    info.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p)
    info.restype = ctypes.c_int
    opening = system['dlopen']
    opening.argtypes = (ctypes.c_char_p, ctypes.c_int)
    opening.restype = ctypes.c_void_p
    closing = system['dlclose']
    closing.argtypes = (ctypes.c_void_p,)
    closing.restype = ctypes.c_int
    return info, opening, closing


def _reject_cached_path(path):
    # ctypes.CDLL always adds RTLD_NOW. A previous, unrelated object cached
    # under the same fd pathname must be rejected BEFORE that can upgrade its
    # lazy bindings or before any target dlsym could execute a GNU IFUNC.
    _, opening, closing = _loader_functions()
    handle = opening(os.fsencode(path), os.RTLD_NOLOAD | os.RTLD_LAZY | os.RTLD_LOCAL)
    if handle:
        closing(handle)  # balance this NOLOAD lookup's reference only
        raise VerifiedKernelLoadRejected('loader pathname already refers to a cached object')


def _checked_function(library, fd, validation, binding, *, argument_types=None):
    # Bind the loader handle before resolving or constructing a callable.
    # dlsym on an unbound handle could itself execute a GNU IFUNC resolver.
    info, _, _ = _loader_functions()
    link_map = ctypes.POINTER(_LinkMap)()
    _require(info(library._handle, 2, ctypes.byref(link_map)) == 0 and bool(link_map),
             'GNU loader did not expose this handle mapping')  # RTLD_DI_LINKMAP
    address = link_map.contents.load_bias + binding['text_vaddr'] + binding['entry']
    _require(type(address) is int and address > 0 and binding['entry'] == 0,
             'loaded direct entry is unavailable')
    with Path('/proc/self/maps').open('rb') as stream:
        maps = stream.read(4 * 1024 * 1024 + 1)
    _require(len(maps) <= 4 * 1024 * 1024, 'process mapping inventory exceeds loader bounds')
    matches = []
    try:
        for line in maps.splitlines():
            fields = line.split(maxsplit=5)
            left, right = (int(part, 16) for part in fields[0].split(b'-'))
            if left <= address < right:
                major, minor = (int(part, 16) for part in fields[3].split(b':'))
                matches.append((left, right, fields[1].decode('ascii'), int(fields[2], 16),
                                major, minor, int(fields[4])))
    except (ValueError, IndexError, UnicodeError) as exc:
        raise VerifiedKernelLoadRejected('unreadable process mapping identity') from exc
    _require(len(matches) == 1, 'loaded entry has no unique process mapping')
    left, right, permissions, offset, major, minor, inode = matches[0]
    st = os.fstat(fd)
    _require((major, minor, inode) == (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino) and
             permissions == 'r-xp' and address + len(binding['text']) <= right and
             offset + address - left == binding['binding']['linked_text_file_offset'],
             'loaded symbol does not come from the exact sealed ELF mapping')
    _require(ctypes.string_at(address, len(binding['text'])) == binding['text'],
             'mapped machine text differs from the independently checked final bytes')
    if argument_types is None:
        argument_types = ([ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p,
                           ctypes.c_uint64, ctypes.c_uint64] if validation['kind'] == 'copy_u8' else
                          [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64])
    function = ctypes.CFUNCTYPE(ctypes.c_uint64, *argument_types)(address)
    function.restype = ctypes.c_uint64
    function.argtypes = argument_types
    return function, {'device_major': major, 'device_minor': minor, 'inode': inode,
                      'permissions': permissions, 'entry_file_offset': offset + address - left,
                      'mapped_text_sha256': sha256(binding['text']).hexdigest(),
                      'sealed_image_and_loaded_symbol_bound': True}


def load_verified_simd_kernel(document, object_bytes, final_bytes, *, timeout_ms=15000):
    """Return a direct callable only after fresh proof, CPU admission and seals.

    This API intentionally accepts original proof inputs, not an old JSON
    validation result. The CPU admission covers the current allowed affinity;
    callers must retain an ISA-compatible execution environment thereafter.
    """
    _require(type(object_bytes) is bytes and type(final_bytes) is bytes and
             64 <= len(object_bytes) <= MAX_IMAGE_BYTES and 64 <= len(final_bytes) <= MAX_IMAGE_BYTES,
             'bounded immutable object and final ELF bytes are required')
    source = Path(__file__).resolve()
    identity = loaded_source_identity(__name__, (source.name, "hia_verified_cpu.py"))
    validation = validate_verified_simd_artifact(document, object_bytes, final_bytes,
                                                 timeout_ms=timeout_ms)
    _require(validation.get('ok') is True and validation.get('complete') is True,
             'independent final-byte validation did not complete')
    binding = bind_final_artifact(object_bytes, final_bytes, validation['subject']['entry_symbol'])
    _require(binding['binding'] == validation['image_binding'], 'fresh ELF binding differs from validation')
    features = validation.get('required_cpu_features')
    mask = validation.get('required_xcr0_mask')
    _require(type(features) is list and type(mask) is int,
             'independent decoder did not provide ISA requirements')
    admission = require_host_isa(features, mask)
    digest = sha256(final_bytes).hexdigest()
    export = validation['subject']['entry_symbol']
    kind = validation['kind']
    _require(kind in ('sum_u8', 'all_zero_u8', 'copy_u8'), 'unrecognized loaded ABI')

    def recheck():
        current = loaded_source_identity(__name__, tuple(identity))
        _require(identity == current, 'loader source changed')
        _require(admission['source_sha256'] == current['hia_verified_cpu.py'],
                 'CPU admission source changed')
        checker_identity = validation['checker']['source_identity']
        checker_owner = (__package__ + ".hia_verified_simd_check"
                         if validation['schema'] == "hepta.hia.verified-simd-machine-validation.v1"
                         else __package__ + ".hia_safe_core")
        _require(loaded_source_identity(checker_owner, tuple(checker_identity)) == checker_identity,
                 'independent checker source changed before loading')
        _require(admission['affinity'] == sorted(os.sched_getaffinity(0)),
                 'allowed CPU affinity changed before loading')

    recheck()
    key = (digest, export, kind)
    function, mapping = _load_sealed_image(key, final_bytes, validation, binding, recheck)
    return LoadedVerifiedSIMD(function, validation, admission, digest, mapping)


def load_verified_scalar_kernel(document, object_bytes, final_bytes, *, timeout_ms=15000):
    """Load one unsigned Safe Core v2/v3 scalar direct entry after fresh proof.

    The callable takes zero to six raw uint64 SysV argument words and returns
    a canonical uint64 result. The independently proved machine body masks
    narrow arguments to their declared Core widths, including bool's low bit.
    Checked arithmetic may call the modeled nonreturning libc abort. No
    producer, serialized proof receipt or alternate profile grants admission.
    """
    _require(type(object_bytes) is bytes and type(final_bytes) is bytes and
             64 <= len(object_bytes) <= MAX_IMAGE_BYTES and 64 <= len(final_bytes) <= MAX_IMAGE_BYTES,
             'bounded immutable object and final ELF bytes are required')
    source = Path(__file__).resolve()
    identity = loaded_source_identity(__name__, (source.name, "hia_verified_cpu.py"))
    checked = verify_program(document)
    functions = checked.as_dict()['functions']
    _require(len(functions) == 1, 'one unsigned scalar function is required')
    function = functions[0]
    parameter_types = tuple(param['type'] for param in function['params'])
    returns = function['returns']
    unsigned = frozenset(('bool', 'u8', 'u16', 'u32', 'u64', 'usize'))
    _require(len(parameter_types) <= 6 and all(typ in unsigned for typ in parameter_types) and
             len(returns) == 1 and returns[0] in unsigned,
             'unsigned scalar arguments and one return within six ABI words are required; no borrowed ranges')
    profile_version = _unsigned_profile_version(checked)
    artifact_profile = {2: ARTIFACT_PROFILE_V2, 3: ARTIFACT_PROFILE_V3,
                        4: ARTIFACT_PROFILE_V4, 5: ARTIFACT_PROFILE_V5}[profile_version]
    validation = validate_safe_core_artifact(checked, object_bytes, final_bytes,
                                             timeout_ms=timeout_ms, profile_version=profile_version)
    _require(validation.get('ok') is True and validation.get('complete') is True and
             validation.get('profile') == artifact_profile,
             'independent scalar final-byte validation did not complete')
    export = function['name']
    binding = bind_final_artifact(object_bytes, final_bytes, export)
    _require(binding['binding'] == validation['image_binding'], 'fresh ELF binding differs from validation')
    _require(binding['entry'] == 0 and binding['binding']['function_shape'] == 'direct_entry',
             'scalar loading requires a direct scalar entry, without a wrapper')
    # Safe Core's independent decoder admits only baseline x86-64 integer
    # instructions. No optional SIMD feature or XCR0 state is needed.
    admission = require_host_isa([], 0)
    digest = sha256(final_bytes).hexdigest()

    def recheck():
        current = loaded_source_identity(__name__, tuple(identity))
        _require(identity == current, 'loader source changed')
        _require(admission['source_sha256'] == current['hia_verified_cpu.py'],
                 'CPU admission source changed')
        checker_identity = validation['checker']['source_identity']
        checker_owner = (__package__ + ".hia_verified_simd_check"
                         if validation['schema'] == "hepta.hia.verified-simd-machine-validation.v1"
                         else __package__ + ".hia_safe_core")
        _require(loaded_source_identity(checker_owner, tuple(checker_identity)) == checker_identity,
                 'independent checker source changed before loading')
        _require(admission['affinity'] == sorted(os.sched_getaffinity(0)),
                 'allowed CPU affinity changed before loading')

    recheck()
    key = (digest, export, ('scalar-safe-core-v' + str(profile_version), parameter_types, returns[0]))
    callable_, mapping = _load_sealed_image(
        key, final_bytes, validation, binding, recheck,
        argument_types=[ctypes.c_uint64] * len(parameter_types))
    return LoadedVerifiedScalar(callable_, validation, admission, digest, mapping,
                                parameter_types, returns[0])


def _load_sealed_image(key, final_bytes, validation, binding, recheck, *, argument_types=None):
    """Share the same bounded registry and pre-dlopen binding for both APIs."""
    global _TOTAL_BYTES
    digest = key[0]
    with _LOCK:
        # Even a reused immutable mapping has just passed a new validation and
        # CPU probe above. A cached report never grants admission to a new CPU.
        if key not in _IMAGES:
            _require(len(_IMAGES) < MAX_LOADED_IMAGES and
                     _TOTAL_BYTES + len(final_bytes) <= MAX_LOADED_IMAGE_BYTES,
                     'verified image registry resource limit reached')
            _require(hasattr(os, 'memfd_create') and hasattr(os, 'MFD_ALLOW_SEALING'),
                     'immutable loading requires Linux sealed memfd support')
            fd = os.memfd_create('hia-verified-' + digest[:16], os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            library = None
            try:
                remaining = memoryview(final_bytes)
                while remaining:
                    count = os.write(fd, remaining)
                    _require(count > 0, 'short write while creating verified mapping')
                    remaining = remaining[count:]
                seals = IMAGE_SEALS
                fcntl.fcntl(fd, F_ADD_SEALS, seals)
                _require(fcntl.fcntl(fd, F_GET_SEALS) & seals == seals and
                         os.fstat(fd).st_size == len(final_bytes) and
                         sha256(os.pread(fd, len(final_bytes), 0)).hexdigest() == digest,
                         'verified image sealing or byte readback failed')
                recheck()
                path = '/proc/' + str(os.getpid()) + '/fd/' + str(fd)
                _reject_cached_path(path)
                library = ctypes.CDLL(path, mode=os.RTLD_LOCAL | os.RTLD_NOW)
                function, mapping = _checked_function(library, fd, validation, binding,
                                                      argument_types=argument_types)
                recheck()
            except BaseException:
                if library is not None:
                    # No callable has escaped this failed admission.
                    import _ctypes
                    _ctypes.dlclose(library._handle)
                os.close(fd)
                raise
            _IMAGES[key] = {'fd': fd, 'library': library, 'bytes': len(final_bytes)}
            _TOTAL_BYTES += len(final_bytes)
        else:
            recheck()
            entry = _IMAGES[key]
            function, mapping = _checked_function(entry['library'], entry['fd'], validation, binding,
                                                  argument_types=argument_types)
        recheck()
        return function, mapping

# Bind this executing module, including its top-level constants, to retained source.
from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
