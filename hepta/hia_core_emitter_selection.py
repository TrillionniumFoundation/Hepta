"""Fresh admission and whole-operation capture for the native Core emitter.
A captured absence is explicit; callbacks cannot replace the selected owner.
Each new operation independently admits its current manifest/source/image.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path

from .hia_core_emitter_native import NativeCoreEmitter, SOURCE, SCHEMA, SELECTOR
from .hia_json_preflight_native import (
    MAX_IMAGE_BYTES, _installed_json_image, _unique_manifest_pairs)

_UNSELECTED = object()
_OWNER = ContextVar('hia_core_emitter_selected_owner', default=_UNSELECTED)
_OWNER_CACHE = []


@dataclass(frozen=True, eq=False)
class _Admission:
    owner: NativeCoreEmitter
    checker_owner: object


def _bounded(path, maximum):
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('native Core emitter input exceeds its private extent')
    return raw


def _manifest(raw):
    value = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA or type(value['image_path']) is not str
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(c not in '0123456789abcdef' for c in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('native Core emitter manifest identity differs')
    return value


def _admit(manifest_path, namespace=None):
    """Freshly bind disk inputs and keep the admitted RX mapping immutable."""
    if namespace is None:
        from . import hia_program_native
        namespace = vars(hia_program_native)
    if type(namespace) is not dict:
        raise TypeError('native Core emitter requires an actual module namespace')
    path = Path(manifest_path).resolve(strict=True)
    raw = _bounded(path, 16384)
    manifest = _manifest(raw)
    source = SOURCE.read_bytes()
    image_path = (path.parent / manifest['image_path']).resolve(strict=True)
    image_raw = _bounded(image_path, MAX_IMAGE_BYTES)
    if (sha256(source).hexdigest() != manifest['source_sha256']
            or sha256(image_raw).hexdigest() != manifest['image_sha256']):
        raise ValueError('native Core emitter source or image identity differs')
    loaded = _installed_json_image(str(path), SOURCE, SCHEMA, NativeCoreEmitter)
    if (loaded.admitted_source_sha256 != manifest['source_sha256']
            or loaded.image_sha256 != manifest['image_sha256']
            or _bounded(path, 16384) != raw or SOURCE.read_bytes() != source
            or _bounded(image_path, MAX_IMAGE_BYTES) != image_raw):
        raise ValueError('native Core emitter admission inputs changed')
    owner = loaded if loaded.namespace is namespace else None
    if owner is None:
        for previous, previous_namespace, candidate in _OWNER_CACHE:
            if previous is loaded and previous_namespace is namespace:
                owner = candidate
                break
    if owner is None:
        # A namespace view shares only immutable code/table and the reentrant
        # exception-delivery mapping. Each call owns independent HIA arenas.
        owner = object.__new__(NativeCoreEmitter)
        owner.__dict__.update(loaded.__dict__)
        owner._bind_namespace(namespace)
        _OWNER_CACHE.append((loaded, namespace, owner))
        if len(_OWNER_CACHE) > 3:
            del _OWNER_CACHE[0]
    from .hia_checker_identity import hold_native_owner
    # Each admission retains its own exact record. A reused image must not
    # overwrite metadata belonging to a different already-captured selection.
    return _Admission(owner, hold_native_owner(SELECTOR, owner, raw, source))


def installed_core_emitter(manifest_path, namespace=None):
    return _admit(manifest_path, namespace).owner


def _selected_admission(namespace):
    captured = _OWNER.get()
    if captured is not _UNSELECTED:
        return captured
    path = os.environ.get(SELECTOR)
    return _admit(path, namespace) if path else None


def selected_core_emitter(namespace):
    admitted = _selected_admission(namespace)
    return None if admitted is None else admitted.owner


def active_core_emitter():
    admitted = _OWNER.get()
    return None if admitted is _UNSELECTED or admitted is None else admitted.owner


def captured_checker_owner():
    """Expose only the actual scope's capability, including captured absence."""
    admitted = _OWNER.get()
    if admitted is _UNSELECTED:
        return False, None
    return True, None if admitted is None else admitted.checker_owner


@contextmanager
def native_core_emitter_scope(namespace):
    admitted = _selected_admission(namespace)
    previous = _OWNER.get()
    try:
        # Save the prior value before set(): a lost STORE of its return token
        # must not leave the surrounding operation with a leaked selection.
        _OWNER.set(admitted)
        yield
    finally:
        _OWNER.set(previous)


def native_implementation_identity(namespace):
    owner = selected_core_emitter(namespace)
    if owner is None:
        return b''
    source_sha = sha256(SOURCE.read_bytes()).hexdigest()
    if source_sha != owner.admitted_source_sha256:
        raise ValueError('native Core emitter source identity mismatch')
    return ('core-emitter-native-v1\0' + source_sha + '\0' + owner.image_sha256).encode('ascii')
