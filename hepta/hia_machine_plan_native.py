"""Source-bound loader and whole-emission capture for HIA machine plans.

Each fresh selection reads the exact manifest, source and executable. A scope
holds its actual immutable mapping and checker capability, including an
explicit absence; a foreign callback cannot silently change that selection.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path

from .hia_machine_plan_control_native import (
    SOURCE, SCHEMA, SELECTOR, NativeMachinePlanControl,
)
from .hia_json_preflight_native import (
    MAX_IMAGE_BYTES, _installed_json_image, _unique_manifest_pairs,
)

NativeMachinePlan = NativeMachinePlanControl
_UNSELECTED = object()
_SELECTION = ContextVar('hia_machine_plan_admitted_selection', default=_UNSELECTED)


@dataclass(frozen=True, eq=False)
class _Admission:
    owner: NativeMachinePlanControl
    checker_owner: object


def _bounded(path, maximum):
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('native machine-plan admission exceeds its private input extent')
    return raw


def _admit(manifest_path):
    path = Path(manifest_path).resolve(strict=True)
    raw = _bounded(path, 16384)
    manifest = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    if (type(manifest) is not dict or set(manifest) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or manifest['schema'] != SCHEMA or type(manifest['image_path']) is not str
            or any(type(manifest[key]) is not str or len(manifest[key]) != 64
                   or any(c not in '0123456789abcdef' for c in manifest[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native HIA JSON manifest')
    source = SOURCE.read_bytes()
    if sha256(source).hexdigest() != manifest['source_sha256']:
        raise ValueError('native HIA JSON source identity mismatch')
    image_path = (path.parent / manifest['image_path']).resolve(strict=True)
    image = _bounded(image_path, MAX_IMAGE_BYTES)
    if sha256(image).hexdigest() != manifest['image_sha256']:
        raise ValueError('native HIA JSON executable identity mismatch')
    owner = _installed_json_image(str(path), SOURCE, SCHEMA, NativeMachinePlan)
    if (owner.admitted_source_sha256 != manifest['source_sha256']
            or owner.image_sha256 != manifest['image_sha256']
            or _bounded(path, 16384) != raw or SOURCE.read_bytes() != source
            or _bounded(image_path, MAX_IMAGE_BYTES) != image):
        raise ValueError('native machine-plan admission inputs changed')
    from .hia_checker_identity import hold_native_owner
    return _Admission(owner, hold_native_owner(SELECTOR, owner, raw, source))


def installed_machine_plan(manifest_path):
    return _admit(manifest_path).owner


def _selected_admission():
    captured = _SELECTION.get()
    if captured is not _UNSELECTED:
        return captured
    path = os.environ.get(SELECTOR)
    return _admit(path) if path else None


def selected_machine_plan():
    captured = _selected_admission()
    return None if captured is None else captured.owner


def captured_checker_owner():
    captured = _SELECTION.get()
    if captured is _UNSELECTED:
        return False, None
    return True, None if captured is None else captured.checker_owner


@contextmanager
def native_machine_plan_scope():
    captured = _selected_admission()
    previous = _SELECTION.get()
    try:
        # Keep the previous value independently of set()'s returned token:
        # losing its STORE acknowledgement must still unwind this scope.
        _SELECTION.set(captured)
        yield
    finally:
        _SELECTION.set(previous)
