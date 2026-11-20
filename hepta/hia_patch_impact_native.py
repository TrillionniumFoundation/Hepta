"""Detached verified-fact transport for HIA's complete patch impact owner.

The native image compares original function/signature bytes, sorts identities,
builds both call graphs and computes their transitive union. This adapter only
serializes observations and materializes native-selected indices and bitsets.
Fresh Core/patch verification, receipt authentication and final report hashing
remain at the existing public boundary.
"""
from __future__ import annotations

import ctypes
import json
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_program_tools import function_signature

SOURCE = _source_resource_path('examples/hia_bootstrap/patch_impact.hepta')
SCHEMA = 'hepta.hia.patch-impact-native.v1'
SELECTOR = 'HEPTA_HIA_PATCH_IMPACT_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIAPIM01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAPIR01', 'little')


def sizes(old, count):
    area = count * ((count + 7) // 8)
    return 16 + count * 16 + area * 2, 64 + (old + count) * 48 + count * 16 + area * 2


def _text(value):
    raw = value.encode('utf-8')
    return struct.pack('<Q', len(raw)) + raw


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False, ensure_ascii=False)


def packet(before, after, phase):
    """Preserve original names/bytes and every operation in declaration order."""
    parts = [struct.pack('<4Q', REQUEST_MAGIC, phase, len(before), len(after))]
    for functions in (before, after):
        for function in functions.values():
            parts.extend((_text(function['name']), _text(_canonical(function)),
                          _text(_canonical(function_signature(function, include_return_loans=True)))))
            operations = [op for block in function['blocks'] for op in block['ops']] if phase else ()
            parts.append(struct.pack('<Q', len(operations)))
            for operation in operations:
                parts.extend((_text(operation['op']), _text(operation['attrs'].get('function', ''))))
    return b''.join(parts)


class NativePatchImpact(NativeHiaJsonImage):
    def observe(self, before, after, *, phase):
        from .hia_patch_impact import _reject
        raw = packet(before, after, phase)
        output_size, state_size = sizes(len(before), len(after))
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        initial = b'\xa5' * output_size
        output = ctypes.create_string_buffer(initial, output_size)
        workspace = ctypes.create_string_buffer(state_size)
        code = self._entry(source, len(raw), output, output_size, workspace, state_size)
        if source.raw != raw or type(code) is not int or code not in (0, 1, 2, 3, 4):
            raise RuntimeError('invalid patch impact ABI or changed verified facts')
        if code:
            if output.raw != initial:
                raise RuntimeError('refused patch impact published output')
            if code == 2:
                _reject('invalid function inventory')
            if code == 3:
                _reject('patch unexpectedly removed a function')
            if code == 4:
                _reject('verified program has unlisted callee')
            raise RuntimeError('native patch impact refused its verified-fact transport')
        magic, count = struct.unpack_from('<2Q', output.raw)
        if magic != RESULT_MAGIC or count != len(after):
            raise RuntimeError('invalid patch impact result identity')
        records = [struct.unpack_from('<2Q', output.raw, 16 + i * 16) for i in range(count)]
        if (len({index for index, _ in records}) != count
                or any(index >= count or flags > (7 if phase else 3) for index, flags in records)):
            raise RuntimeError('invalid patch impact result indices or flags')
        names = list(after)
        ordered = [names[index] for index, _ in records]
        result = {'direct_changed_functions': [name for name, (_, flags) in zip(ordered, records) if flags & 1],
                  'interface_changed_functions': [name for name, (_, flags) in zip(ordered, records) if flags & 2]}
        if phase:
            result['potentially_affected_functions'] = [name for name, (_, flags) in zip(ordered, records) if flags & 4]
            result['unaffected_by_static_callgraph'] = [name for name, (_, flags) in zip(ordered, records) if not flags & 4]
            stride = (count + 7) // 8
            area = count * stride
            for graph, field in enumerate(('old_call_edges', 'new_call_edges')):
                start = 16 + count * 16 + graph * area
                result[field] = [{'caller': caller, 'callee': callee}
                    for i, caller in enumerate(ordered) for j, callee in enumerate(ordered)
                    if output.raw[start + i * stride + j // 8] & (1 << (j & 7))]
                if count % 8 and any(output.raw[start + i * stride + stride - 1] >> (count % 8) for i in range(count)):
                    raise RuntimeError('invalid patch impact padding bits')
        elif output.raw[16 + count * 16:] != bytes(output_size - 16 - count * 16):
            raise RuntimeError('metadata-only patch impact published call graphs')
        return result


def installed_patch_impact(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativePatchImpact)
