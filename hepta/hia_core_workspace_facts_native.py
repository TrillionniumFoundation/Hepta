"""Explicit native JSON-to-Core-workspace-facts bridge; no payload decoder.

Facts are not a verified Core program, a module policy result or an admission
receipt. Names/visibility/cycles still require the HIA module graph, followed by
whole-Core checking. Caller-supplied manifests select locally trusted code.
"""
import ctypes
from pathlib import Path
from .hia_core_module_graph_native import CoreModuleRejected
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/core_workspace_facts.hiaasm')
SCHEMA = 'hepta.hia.core-workspace-facts-native.v1'
MAX_BYTES = 8 << 20
ARENA_BYTES = (64 << 20) + 4096
WORKSPACE_BYTES = (16 << 20) + 8192


class NativeCoreWorkspaceFacts(NativeHiaJsonImage):
    def normalize(self, wire):
        if type(wire) is not bytes or len(wire) > MAX_BYTES:
            raise CoreModuleRejected('outside native Core workspace JSON byte profile')
        source = ctypes.create_string_buffer(wire, max(1,len(wire)))
        arena = ctypes.create_string_buffer(ARENA_BYTES)
        scratch = ctypes.create_string_buffer(WORKSPACE_BYTES)
        result = self._entry(source,len(wire),arena,ARENA_BYTES,scratch,WORKSPACE_BYTES)
        if result == 4294967295:
            raise CoreModuleRejected('native Core workspace JSON framing rejected')
        if result == 4294967294:
            raise CoreModuleRejected('native Core workspace JSON arena capacity refused')
        if not 80 <= result <= MAX_BYTES:
            raise CoreModuleRejected('invalid native Core workspace JSON result')
        return ctypes.string_at(arena,result)


def installed_workspace_facts(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeCoreWorkspaceFacts)
