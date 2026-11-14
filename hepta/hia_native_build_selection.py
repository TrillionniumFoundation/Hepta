"""Fresh native-build admission and immutable whole-build selection capture."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path

from .hia_native_build_native import NativeBuild, SOURCE, SCHEMA, SELECTOR
from .hia_json_preflight_native import MAX_IMAGE_BYTES, _installed_json_image, _unique_manifest_pairs

_UNSELECTED = object()
_OWNER = ContextVar('hia_native_build_captured_owner', default=_UNSELECTED)
_VIEWS = []


@dataclass(frozen=True, eq=False)
class _Admission:
    owner: NativeBuild
    checker_owner: object


def _bounded(path, maximum):
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('native build admission exceeds its private input extent')
    return raw


def _admit(manifest_path, namespace=None):
    if namespace is None:
        from . import hia_program_native
        namespace = vars(hia_program_native)
    if type(namespace) is not dict:
        raise TypeError('native build requires its actual module namespace')
    path = Path(manifest_path).resolve(strict=True)
    raw = _bounded(path, 16384)
    record = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    if (type(record) is not dict or set(record) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or record['schema'] != SCHEMA or type(record['image_path']) is not str
            or any(type(record[key]) is not str or len(record[key]) != 64
                   or any(c not in '0123456789abcdef' for c in record[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('native build manifest identity differs')
    # Resolve only after the original sibling-basename safety rule is checked.
    name = record['image_path']
    if not name or name in ('.', '..') or Path(name).name != name or any(ord(c) < 32 for c in name):
        raise ValueError('native build executable is not a sibling basename')
    source = SOURCE.read_bytes()
    image_path = (path.parent / name).resolve(strict=True)
    image = _bounded(image_path, MAX_IMAGE_BYTES)
    if sha256(source).hexdigest() != record['source_sha256'] or sha256(image).hexdigest() != record['image_sha256']:
        raise ValueError('native build source or executable identity differs')
    loaded = _installed_json_image(str(path), SOURCE, SCHEMA, NativeBuild)
    if (loaded.admitted_source_sha256 != record['source_sha256']
            or loaded.image_sha256 != record['image_sha256']
            or _bounded(path, 16384) != raw or SOURCE.read_bytes() != source
            or _bounded(image_path, MAX_IMAGE_BYTES) != image):
        raise ValueError('native build admission inputs changed')
    owner = loaded if loaded.namespace is namespace else None
    if owner is None:
        for prior, prior_namespace, view in _VIEWS:
            if prior is loaded and prior_namespace is namespace:
                owner = view
                break
    if owner is None:
        owner = object.__new__(NativeBuild)
        owner.__dict__.update(loaded.__dict__)
        owner._bind_namespace(namespace)
        _VIEWS.append((loaded, namespace, owner))
        if len(_VIEWS) > 3:
            del _VIEWS[0]
    from .hia_checker_identity import hold_native_owner
    return _Admission(owner, hold_native_owner(SELECTOR, owner, raw, source))


def installed_native_build(manifest_path, namespace=None):
    return _admit(manifest_path, namespace).owner


def _selected(namespace):
    captured = _OWNER.get()
    if captured is not _UNSELECTED:
        return captured
    path = os.environ.get(SELECTOR)
    return _admit(path, namespace) if path else None


def selected_native_build(namespace=None):
    admission = _selected(namespace)
    return None if admission is None else admission.owner


def active_native_build():
    admission = _OWNER.get()
    return None if admission is _UNSELECTED or admission is None else admission.owner


def captured_checker_owner():
    admission = _OWNER.get()
    if admission is _UNSELECTED:
        return False, None
    return True, None if admission is None else admission.checker_owner


@contextmanager
def native_build_scope(namespace=None):
    admission = _selected(namespace)
    prior = _OWNER.get()
    try:
        _OWNER.set(admission)
        yield
    finally:
        _OWNER.set(prior)


def native_implementation_identity(namespace=None):
    owner = selected_native_build(namespace)
    if owner is None:
        return b''
    source_sha = sha256(SOURCE.read_bytes()).hexdigest()
    if source_sha != owner.admitted_source_sha256:
        raise ValueError('native build source identity mismatch')
    return ('native-build-coordinator-v1\0' + source_sha + '\0' + owner.image_sha256).encode('ascii')
