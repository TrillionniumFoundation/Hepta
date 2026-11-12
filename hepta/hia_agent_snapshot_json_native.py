"""Explicit raw-JSON HIA snapshot image; no foreign payload decoder.

The output arena is private scratch until success and may change on refusal.
Only admitted payload bytes are returned. This is not the Agent's transactional
editing/persistence implementation or a replacement for the manifest trust root.
"""
import ctypes
from pathlib import Path
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, scratch_sizes

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/agent_snapshot_json.hepta')
SCHEMA = 'hepta.hia.agent-snapshot-json-native.v1'
MAX_BYTES = 8 << 20
MAX_NODES = 1 << 20
MAX_DEPTH = 128
MAX_EXTENT = 1 << 20


class NativeAgentSnapshotJson(NativeHiaJsonImage):
    def materialize(self, wire):
        if type(wire) is not bytes or len(wire) > MAX_BYTES:
            raise ValueError('outside native Agent snapshot JSON wire profile')
        capacity = max(MAX_EXTENT, 64 + min(MAX_NODES, len(wire)) * 56 + len(wire))
        workspace = max(128 + (MAX_DEPTH + 1) * 48, scratch_sizes(len(wire), MAX_NODES, MAX_DEPTH)[0])
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(capacity)
        scratch = ctypes.create_string_buffer(workspace)
        result = self._entry(source, len(wire), output, capacity, scratch, workspace)
        if result == 4294967295:
            raise ValueError('native Agent snapshot JSON or descriptor refused')
        if result == 4294967294:
            raise OverflowError('native Agent snapshot JSON capacity refused')
        if result > MAX_EXTENT:
            raise RuntimeError('invalid native Agent snapshot JSON result')
        return output.raw[:result]


def installed_snapshot_json(manifest_path):
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeAgentSnapshotJson)
