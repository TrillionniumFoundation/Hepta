"""Selected snapshot-bound HIA patching with mandatory native Core admission.

The image parses exact bytes, checks snapshot SHA and edits, and produces the
candidate. Native whole-Core admission checks both original and candidate.
Host object conversion, custody, publication and the Agent journal remain host.
"""
from __future__ import annotations
import ctypes
import os
from pathlib import Path
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/core_patch.hiaasm')
SCHEMA = 'hepta.hia.core-patch-native.v1'
SELECTOR = 'HEPTA_HIA_CORE_PATCH_MANIFEST'
MAGIC = int.from_bytes(b'HIAPAT01', 'little')
MAX_COMPONENT = 8 << 20
MAX_WIRE = 2 * MAX_COMPONENT + 3
MAX_NODES = 524289
MAX_DEPTH = 129
ERROR_MESSAGES = {
    0xffffffff: 'invalid JSON syntax or Unicode',
    0xfffffffe: 'patch input, node, depth or output capacity exceeded',
    0xfffffffd: 'native patch scratch or invocation profile refused',
    0xfffffffc: 'duplicate JSON field',
    0xfffffffb: 'patch envelope or fields are invalid',
    0xfffffffa: 'invalid expected snapshot digest',
    0xfffffff9: 'stale base snapshot',
    0xfffffff8: 'patch needs 1..64 edits',
    0xfffffff7: 'unknown edit action',
    0xfffffff6: 'invalid, absent or duplicate function identity',
    0xfffffff5: 'invalid or absent block identity',
    0xfffffff4: 'invalid operation index',
    0xfffffff3: 'overlapping or duplicate edits',
    0xfffffff2: 'interface change needs explicit v2 migrate policy',
}


def scratch_sizes(size):
    """Allocation bounds; actual per-component quotas are enforced in HIA."""
    bound = min(MAX_NODES, (size + 1) // 2 + 1)
    key_bound = min(MAX_NODES, size // 4 + 1)
    slots = 2
    while slots < key_bound * 2:
        slots *= 2
    output = max(8192, size + 32, slots * 8)
    arena = max(8192, 128 + (MAX_DEPTH + 1) * 32,
                64 + bound * 56 + size + 8192)
    return output, arena


def envelope(original, patch):
    if type(original) is not bytes or type(patch) is not bytes:
        raise TypeError('native patch requires immutable original and patch bytes')
    if len(original) > MAX_COMPONENT or len(patch) > MAX_COMPONENT:
        from .hia_program_tools import HIAEditRejected
        raise HIAEditRejected('E_HIA_EDIT: patch component exceeds 8 MiB')
    return b'[' + original + b',' + patch + b']'


class NativeCorePatch(NativeHiaJsonImage):
    def transform(self, wire, *, extract=False):
        from .hia_program_tools import HIAEditRejected
        if type(wire) is not bytes or type(extract) is not bool:
            raise TypeError('exact JSON bytes and boolean extraction mode required')
        if len(wire) > MAX_WIRE:
            raise HIAEditRejected('E_HIA_EDIT: patch envelope exceeds 16 MiB framing budget')
        output_size, arena_size = scratch_sizes(len(wire))
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(output_size)
        arena = ctypes.create_string_buffer(arena_size)
        struct.pack_into('<Q', arena, 0, int(not extract))
        code = self._entry(source, len(wire), output, output_size, arena, arena_size)
        if code in ERROR_MESSAGES:
            raise HIAEditRejected('E_HIA_EDIT: ' + ERROR_MESSAGES[code])
        if not 34 <= code <= min(output_size, MAX_COMPONENT + 32):
            raise RuntimeError('invalid native patch result extent')
        magic, schema, policy, edits = struct.unpack_from('<4Q', output.raw)
        if magic != MAGIC or (extract and (schema, policy, edits) != (0, 0, 0)):
            raise RuntimeError('invalid native patch result header')
        if not extract and (schema not in (1, 2) or policy not in (0, 1)
                            or not 1 <= edits <= 64 or (schema == 1 and policy)):
            raise RuntimeError('invalid native patch result policy')
        return output.raw[32:code], schema, policy, edits


def installed_core_patch(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeCorePatch)


def selected_prepare_patch(original, request):
    """Return None only when unselected; a selected rejection never falls back.

    The admission manifest has a fixed adjacent name, not an executable or path
    taken from the patch. Both images are independently admitted against their
    exact current source bytes; adjacency alone does not prove a common build.
    A source digest grants neither
    semantic admission nor external publication authority.
    """
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    from .hia_program_tools import (bounded_json_wire, decode_json,
        MAX_INPUT_BYTES, PATCH_SCHEMA, PATCH_SCHEMA_V2, HIAEditRejected)
    from .hia_core_admission_native import installed_core_admission
    try:
        image = installed_core_patch(selected)
        admission = installed_core_admission(str(Path(selected).resolve(strict=True).parent / 'admission-manifest.json'))
        if type(request) is str:
            raw = request.encode('utf-8')
        elif type(request) is bytes:
            raw = request
        else:
            raw = bounded_json_wire(request, MAX_INPUT_BYTES, ensure_ascii=False, sort_keys=False)
        combined = envelope(original.canonical_bytes, raw)
        base, _, _, _ = image.transform(combined, extract=True)
        admission.admit(base)
        candidate, version, policy, count = image.transform(combined)
        admission.admit(candidate)
        # Materialization occurs only after all native policy and semantic
        # checks. The host does not construct or mutate the candidate tree.
        return decode_json(candidate), (PATCH_SCHEMA if version == 1 else PATCH_SCHEMA_V2), ('migrate' if policy else 'preserve'), count
    except HIAEditRejected:
        raise
    except (ValueError, OSError, UnicodeError) as exc:
        raise HIAEditRejected('E_HIA_EDIT: selected native patch or whole-Core admission refused: ' + str(exc)) from exc
