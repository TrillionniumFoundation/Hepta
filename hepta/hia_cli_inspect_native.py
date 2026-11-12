"""Native ordinary-inspect report owner with adjacent full Core verification.

The captured input contains only canonical Core bytes and, when present, the
original structured bytes. No host-computed digest, schema/profile, export list,
operation count or report field authorizes the native transformation.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
import json
import os
import struct

from .hia_agent_store import _agent_resource_path
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

SOURCE = _agent_resource_path('examples/hia_bootstrap/cli_inspect.hepta')
SCHEMA = 'hepta.hia.cli-inspect-native.v1'
SELECTOR = 'HEPTA_HIA_CLI_INSPECT_MANIFEST'
MAGIC = int.from_bytes(b'HIAINSQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAINSR1', 'little')
MAX_BYTES = 8 << 20


def capture_request(checked):
    core, structured = checked.canonical_bytes, checked.structured_bytes
    if type(core) is not bytes or not 0 < len(core) <= MAX_BYTES:
        raise ValueError('invalid admitted inspect Core byte capture')
    if structured is not None and (type(structured) is not bytes or not 0 < len(structured) <= MAX_BYTES):
        raise ValueError('invalid admitted inspect structured byte capture')
    original = b'' if structured is None else structured
    return struct.pack('<8Q', MAGIC, 1, len(core), len(original),
                       int(structured is not None), 0, 0, 0) + core + original


def storage_sizes(core_size, structured_size):
    if (type(core_size) is not int or type(structured_size) is not int
            or not 0 < core_size <= MAX_BYTES or not 0 <= structured_size <= MAX_BYTES):
        raise ValueError('inspect captured spans exceed the original byte bounds')
    largest = max(core_size, structured_size)
    nodes = min(262144, ((largest + 1) >> 1) + 1)
    workspace = ((64 + nodes * 56 + largest + 15) & -16) + 32768
    # Four times the input covers copied Core fields and each operation index.
    # The extra MiB covers duplicated <=1024 names, default return-loan arrays
    # and fixed report syntax; 4 MiB also bounds the original decoder key table.
    output = max(4 << 20, 4 * largest + (1 << 20))
    return output, workspace


@dataclass(frozen=True)
class InspectReceipt:
    payload_wire: bytes
    header: bytes
    functions: int
    blocks: int
    operations: int
    structured: bool


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate native inspect output field')
        result[key] = value
    return result


def _constant(_value):
    raise ValueError('nonfinite native inspect output')


class NativeCliInspect(NativeHiaJsonImage):
    def transition(self, request):
        if type(request) is not bytes or not 64 <= len(request) <= 64 + 2 * MAX_BYTES:
            raise ValueError('inspect transport is outside captured-byte bounds')
        words = struct.unpack_from('<8Q', request)
        if (words[:2] != (MAGIC, 1) or words[4] not in (0, 1)
                or words[5:] != (0, 0, 0) or (words[3] != 0) != bool(words[4])
                or len(request) != 64 + words[2] + words[3]):
            raise ValueError('inspect captured-span framing mismatch')
        output_size, workspace_size = storage_sizes(words[2], words[3])
        source = ctypes.create_string_buffer(request, len(request))
        output = ctypes.create_string_buffer(output_size)
        workspace = ctypes.create_string_buffer(workspace_size)
        result = self._entry(source, len(request), output, output_size, workspace, workspace_size)
        if source.raw != request:
            raise ValueError('native inspect modified captured input')
        if not 64 < result <= output_size:
            raise RuntimeError('native inspect rejected its private captured profile: ' + hex(result))
        header = output.raw[:64]
        actual = struct.unpack('<8Q', header)
        if (actual[:2] != (RESULT_MAGIC, 1) or actual[2] != result - 64
                or actual[6] != words[4] or actual[7] != 0):
            raise ValueError('invalid complete native inspect publication')
        return InspectReceipt(output.raw[64:result], header, *actual[3:6], bool(actual[6]))

    def inspect_checked(self, checked):
        receipt = self.transition(capture_request(checked))
        # Foreign object materialization only. The complete serialized report,
        # including both digests and all policy choices, was produced by HIA.
        value = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant).decode(
            receipt.payload_wire.decode('utf-8'))
        if type(value) is not dict:
            raise ValueError('native inspect result is not an object')
        return value


def installed_cli_inspect(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeCliInspect)


def selected_inspect(checked):
    if SELECTOR not in os.environ:
        return None
    selected = os.environ[SELECTOR]
    if not selected:
        raise ValueError('native inspect selection must not be empty')
    return installed_cli_inspect(selected).inspect_checked(checked)
