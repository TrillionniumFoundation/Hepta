"""Explicit source-bound selection for the HIA Core Function and Emitter control owners.

Image selection, source identity and object primitive execution are hosted
mechanical boundaries. No Function lowering policy is implemented here.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path

from .hia_core_lowering_native import NativeCoreLowering, MAGIC, POOL_MAGIC
from .hia_json_preflight_native import (
    NativeHiaJsonImage, _load_manifest, _source_resource_path,
    _unique_manifest_pairs)

SELECTOR = 'HEPTA_HIA_CORE_LOWERING_MANIFEST'
SCHEMA = 'hepta.hia.core-lowering-native.v2'
UNIT_SCHEMA = 'hepta.hia.core-lowering-unit-native.v2'
ABI_SOURCE = 'hepta/hia_core_lowering_abi.json'
_UNSELECTED = object()
_OWNER = ContextVar('hia_core_lowering_selected_owner', default=_UNSELECTED)
_OWNER_CACHE = []
_MODE_ARITIES = (
    ('_reject', 2), ('_words', 1), ('_bounds', 1), ('_normalize', 3),
    ('_prologue', 2), ('_Function.__init__', 4), ('_Function.allocate', 2),
    ('_Function.label', 2), ('_Function.block_label', 2),
    ('_Function.load', 4), ('_Function.store', 4), ('_Function.immediate', 4),
    ('_Function.copy', 3), ('_Function.fail_if', 2),
    ('_Function.compare_imm', 3), ('_Function.range_check', 4),
    ('_Function.narrow_result', 3), ('_Function.condition_value', 2),
    ('_Function.edge', 3), ('_Function.operation', 2),
    ('_Function.allocate_buffer', 4), ('_Function.range_guard', 4),
    ('_Function.bulk', 3), ('_Function.push_chain', 3),
    ('_Function.pop_chain', 3), ('_Function.drop_chain', 2),
    ('_Function.render', 1), ('_native_globals', 0),
    ('_Emitter.__init__', 6), ('_Emitter.ordered_blocks', 2),
    ('_Emitter.label', 2), ('_Emitter.function_symbol', 2),
    ('_Emitter.wrapper', 2), ('_Emitter.render', 1),
    ('_native_generator_0', 1), ('_native_generator_1', 1),
)
_GENERATOR_MODES = ('_native_generator_0', '_native_generator_1')


def _json(raw):
    return json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def checked_abi(raw):
    value = _json(raw)
    if (type(value) is not dict or set(value) != {
            'schema', 'protocol_magic', 'pool_magic', 'packet_bytes',
            'workspace_bytes', 'output_bytes', 'pool_bytes', 'literal_count',
            'units', 'modes', 'generator_modes'}
            or value['schema'] != 'hepta.hia.core-lowering-abi.v2'
            or type(value['protocol_magic']) is not int or value['protocol_magic'] != MAGIC
            or type(value['pool_magic']) is not int or value['pool_magic'] != POOL_MAGIC
            or type(value['packet_bytes']) is not int or value['packet_bytes'] != 128):
        raise ValueError('native Core lowering ABI identity differs')
    for name, minimum in (('workspace_bytes', 1024), ('output_bytes', 128),
                          ('pool_bytes', 16), ('literal_count', 3)):
        if type(value[name]) is not int or not minimum <= value[name] <= 1048576:
            raise ValueError('native Core lowering ABI extent differs: ' + name)
    units = value['units']
    if (type(units) is not list or not units
            or any(type(name) is not str or name != 'core_lowering_' + format(i, '03d')
                   for i, name in enumerate(units))):
        raise ValueError('native Core lowering unit inventory differs')
    if (type(value['generator_modes']) is not list
            or value['generator_modes'] != list(_GENERATOR_MODES)):
        raise ValueError('native Core lowering generator mode inventory differs')
    expected_modes = {name: {'number': index, 'arity': arity}
                      for index, (name, arity) in enumerate(_MODE_ARITIES, 1)}
    modes = value['modes']
    if (type(modes) is not dict or set(modes) != set(expected_modes)
            or any(type(row) is not dict or set(row) != {'number', 'arity'}
                   or type(row['number']) is not int or type(row['arity']) is not int
                   for row in modes.values()) or modes != expected_modes):
        raise ValueError('native Core lowering mode inventory differs')
    return value


def source_names(abi):
    return tuple('examples/hia_bootstrap/' + name + '.hiaasm'
                 for name in ('core_lowering_pool', *abi['units']))


def _bounded_manifest(path):
    with path.open('rb') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('native Core lowering manifest exceeds size limit')
    return raw


@dataclass(frozen=True)
class _Loaded:
    abi: dict
    names: tuple
    images: tuple
    abi_sha256: str
    source_hashes: tuple
    bundle_sha256: str


@lru_cache(maxsize=3)
def _load_bundle(path, raw, abi_raw, unit_inputs):
    abi = checked_abi(abi_raw)
    bundle = _json(raw)
    names = ('core_lowering_pool', *abi['units'])
    expected_paths = {name: name + '/manifest.json' for name in names}
    if (type(bundle) is not dict or set(bundle) != {
            'schema', 'abi_sha256', 'compiler_sha256', 'unit_manifests'}
            or bundle['schema'] != SCHEMA
            or not _digest(bundle['abi_sha256'])
            or not _digest(bundle['compiler_sha256'])
            or type(bundle['unit_manifests']) is not dict
            or bundle['unit_manifests'] != expected_paths):
        raise ValueError('native Core lowering bundle manifest differs')
    abi_sha = sha256(abi_raw).hexdigest()
    if bundle['abi_sha256'] != abi_sha:
        raise ValueError('native Core lowering ABI source identity mismatch')
    if tuple(row[0] for row in unit_inputs) != names:
        raise ValueError('native Core lowering complete image order differs')
    images, source_hashes = [], []
    for name, unit_path, unit_raw, source_sha in unit_inputs:
        unit = _json(unit_raw)
        if type(unit) is not dict or unit.get('compiler_sha256') != bundle['compiler_sha256']:
            raise ValueError('native Core lowering compiler identity differs across units')
        image = _load_manifest(unit_path, unit_raw, source_sha, UNIT_SCHEMA, NativeHiaJsonImage)
        images.append(image)
        source_hashes.append((name, source_sha))
    return _Loaded(abi, tuple(names), tuple(images), abi_sha,
                   tuple(source_hashes), sha256(raw).hexdigest())


def installed_core_lowering(manifest_path, namespace):
    """Re-admit all package sources and manifests; pin immutable mapped code.

    Disk image mutation does not replace an existing mapping with an unchanged
    cache key. A new unit manifest key forces fresh image admission. Source and
    ABI bytes are read on every selection, including a warm loaded bundle.
    """
    if type(namespace) is not dict:
        raise TypeError('native Core lowering requires an actual module namespace')
    path = Path(manifest_path).resolve(strict=True)
    raw = _bounded_manifest(path)
    abi_raw = _source_resource_path(ABI_SOURCE).read_bytes()
    abi = checked_abi(abi_raw)
    # Do not follow manifest-controlled paths before admitting its fixed shape.
    bundle = _json(raw)
    names = ('core_lowering_pool', *abi['units'])
    paths = {name: name + '/manifest.json' for name in names}
    if (type(bundle) is not dict or set(bundle) != {
            'schema', 'abi_sha256', 'compiler_sha256', 'unit_manifests'}
            or bundle.get('schema') != SCHEMA
            or not _digest(bundle.get('abi_sha256'))
            or not _digest(bundle.get('compiler_sha256'))
            or bundle.get('unit_manifests') != paths
            or bundle['abi_sha256'] != sha256(abi_raw).hexdigest()):
        raise ValueError('native Core lowering bundle or ABI source identity differs')
    inputs = []
    for name in names:
        unit_path = (path.parent / paths[name]).resolve(strict=True)
        unit_raw = _bounded_manifest(unit_path)
        relative = 'examples/hia_bootstrap/' + name + '.hiaasm'
        inputs.append((name, str(unit_path), unit_raw,
                       sha256(_source_resource_path(relative).read_bytes()).hexdigest()))
    loaded = _load_bundle(str(path), raw, abi_raw, tuple(inputs))
    for previous_loaded, previous_namespace, owner in _OWNER_CACHE:
        if previous_loaded is loaded and previous_namespace is namespace:
            return owner
    owner = NativeCoreLowering(loaded.images[1:], loaded.images[0], loaded.abi, namespace)
    owner._admitted_bundle = loaded
    _OWNER_CACHE.append((loaded, namespace, owner))
    if len(_OWNER_CACHE) > 3:
        del _OWNER_CACHE[0]
    return owner


def selected_core_lowering(namespace):
    owner = _OWNER.get()
    if owner is not _UNSELECTED:
        return owner
    path = os.environ.get(SELECTOR)
    return installed_core_lowering(path, namespace) if path else None


def active_core_lowering():
    """Helpers outside an admitted ordinary emit retain their original entry."""
    owner = _OWNER.get()
    return None if owner is _UNSELECTED else owner


@contextmanager
def native_core_lowering_scope(namespace):
    owner = selected_core_lowering(namespace)
    token = _OWNER.set(owner)
    try:
        yield
    finally:
        _OWNER.reset(token)


def native_implementation_identity(namespace):
    owner = selected_core_lowering(namespace)
    if owner is None:
        return b''
    loaded = owner._admitted_bundle
    abi_sha = sha256(_source_resource_path(ABI_SOURCE).read_bytes()).hexdigest()
    if abi_sha != loaded.abi_sha256:
        raise ValueError('native Core lowering ABI source identity mismatch')
    expected_sources = dict(loaded.source_hashes)
    values = ['native-core-lowering-v2', abi_sha, loaded.bundle_sha256]
    for name, image in zip(loaded.names, loaded.images):
        relative = 'examples/hia_bootstrap/' + name + '.hiaasm'
        source_sha = sha256(_source_resource_path(relative).read_bytes()).hexdigest()
        if source_sha != expected_sources[name]:
            raise ValueError('native Core lowering source identity mismatch')
        values.extend((relative, source_sha, image.image_sha256))
    return ('\0'.join(values)).encode('ascii')
