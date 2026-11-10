"""Explicitly installed Linux x86-64 HIA JSON-preflight candidate.

The native image is trusted executable code, not a sandbox for submitted files.
A local manifest binds the source and executable hashes. That binding is not an
all-input refinement proof; independent qualification remains mandatory.
The compiled HIA program only checks syntax/budgets: it builds no JSON values.
"""
from __future__ import annotations
import ctypes
from functools import lru_cache
from hashlib import sha256
import json
import mmap
from pathlib import Path
import platform
import struct

MAX_BYTES = 8 << 20
MAX_NODES = 1 << 20
MAX_DEPTH = 128
MAX_IMAGE_BYTES = 1 << 20
SCHEMA = 'hepta.hia.json-preflight-native.v1'
def _source_resource_path(name):
    """Source-owned checkout or installed-package resource, never cwd/HOME.

    The installed path remains package-owned even if an individual resource
    is missing; there is no source-tree fallback for selected native images.
    """
    root = Path(__file__).resolve().parent.parent
    resource_root = root if (root / "pyproject.toml").is_file() else root / "hepta" / "_data"
    return resource_root / name


SOURCE = _source_resource_path('examples/hia_bootstrap/json_preflight.hiaasm')


def scratch_sizes(size: int, maximum: int, depth: int) -> tuple[int, int]:
    bound = min(maximum, size // 4 + 1)
    slots = 2
    while slots < bound * 2:
        slots *= 2
    return slots * 8, 128 + (depth + 1) * 32


class NativeHiaJsonImage:
    """Pinned immutable code, private per-call scratch; concurrent calls allowed."""
    def __init__(self, image: bytes, expected_sha256: str):
        if (platform.system() != 'Linux' or platform.machine() != 'x86_64'
                or ctypes.sizeof(ctypes.c_void_p) != 8):
            raise ValueError('native HIA JSON image requires Linux x86-64 LP64')
        if (type(image) is not bytes or not 0 < len(image) <= MAX_IMAGE_BYTES
                or sha256(image).hexdigest() != expected_sha256):
            raise ValueError('native HIA JSON executable identity mismatch')
        self.image_sha256 = expected_sha256
        mapped = mmap.mmap(-1, len(image), prot=mmap.PROT_READ | mmap.PROT_WRITE)
        mapped.write(image)
        address = ctypes.addressof(ctypes.c_char.from_buffer(mapped))
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        libc.mprotect.restype = ctypes.c_int
        if libc.mprotect(address, len(image), mmap.PROT_READ | mmap.PROT_EXEC):
            code = ctypes.get_errno()
            mapped.close()
            raise OSError(code, 'mprotect native HIA JSON preflight')
        self._mapping = mapped
        self._entry = ctypes.CFUNCTYPE(ctypes.c_uint64, *([ctypes.c_void_p, ctypes.c_uint64] * 3))(address)


class NativeJsonPreflight(NativeHiaJsonImage):
    """Syntax-only result protocol, separate from the JSON value-arena ABI."""

    def status(self, wire: bytes, *, max_nodes: int, max_depth: int) -> int:
        """Return the actual HIA status; reject unsupported host ABI inputs first."""
        if (type(wire) is not bytes or len(wire) > MAX_BYTES
                or type(max_nodes) is not int or not 1 <= max_nodes <= MAX_NODES
                or type(max_depth) is not int or not 0 <= max_depth <= MAX_DEPTH):
            raise ValueError('outside native HIA JSON preflight profile')
        key_bytes, stack_bytes = scratch_sizes(len(wire), max_nodes, max_depth)
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        keys = ctypes.create_string_buffer(key_bytes)
        state = ctypes.create_string_buffer(stack_bytes)
        struct.pack_into('<QQ', state, 48, max_nodes, max_depth)
        result = self._entry(source, len(wire), keys, key_bytes, state, stack_bytes)
        if result not in (0, 1, 2, 3, 4):
            raise RuntimeError('invalid native HIA JSON preflight return')
        return result

    def admit(self, wire: bytes, *, max_nodes: int, max_depth: int) -> None:
        result = self.status(wire, max_nodes=max_nodes, max_depth=max_depth)
        if result == 2:
            raise OverflowError('HIA JSON exceeds node/depth budget before decoding')
        if result == 4:
            raise ValueError('HIA JSON preflight: duplicate decoded object key')
        if result == 3:
            raise RuntimeError('native HIA JSON preflight rejected its declared scratch profile')
        if result:
            raise ValueError('HIA JSON preflight: invalid JSON syntax or Unicode')


def _unique_manifest_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate native HIA JSON manifest field')
        value[key] = item
    return value


@lru_cache(maxsize=3)
def _load_manifest(path: str, raw: bytes, source_sha: str, schema: str, factory):
    value = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != schema
            or any(type(value[k]) is not str or len(value[k]) != 64
                   or any(c not in '0123456789abcdef' for c in value[k])
                   for k in ('source_sha256', 'image_sha256', 'compiler_sha256'))
            or type(value['image_path']) is not str):
        raise ValueError('invalid native HIA JSON manifest')
    if source_sha != value['source_sha256']:
        raise ValueError('native HIA JSON source identity mismatch')
    image_path = Path(path).parent / value['image_path']
    with image_path.open('rb') as handle:
        image = handle.read(MAX_IMAGE_BYTES + 1)
    return factory(image, value['image_sha256'])


def _installed_json_image(manifest_path: str, source: Path, schema: str, factory):
    """Cache immutable code, but rebind source bytes on every selection.

    Source identity is part of the cache key: a warm cached image must not
    hide drift of the source it claims to implement. Loaded code stays pinned;
    changing its disk file does not replace an already immutable mapping.
    """
    path = Path(manifest_path).resolve(strict=True)
    with path.open('rb') as handle:
        raw = handle.read(16385)
    if len(raw) > 16384:
        raise ValueError('native HIA JSON manifest exceeds size limit')
    return _load_manifest(str(path), raw, sha256(source.read_bytes()).hexdigest(), schema, factory)


def installed_preflight(manifest_path: str) -> NativeJsonPreflight:
    """Only an operator-selected local artifact; never selected by JSON payload."""
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeJsonPreflight)
