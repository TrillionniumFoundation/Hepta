"""Explicit native workspace representation; semantic compilation is mandatory."""
import ctypes
from pathlib import Path
from .hia_core_module_graph_native import CoreModuleRejected
from .hia_json_preflight_native import NativeHiaJsonImage,_installed_json_image

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/core_workspace_materialize.hepta')
SCHEMA='hepta.hia.core-workspace-materialize-native.v1'
ARENA_BYTES=88<<20
WORKSPACE_BYTES=(16<<20)+8192
MAX_WIRE_BYTES=8<<20
MAX_ASSEMBLY_BYTES=1<<20


class NativeCoreWorkspaceMaterializer(NativeHiaJsonImage):
    def render(self,wire):
        if type(wire) is not bytes or len(wire)>MAX_WIRE_BYTES:
            raise CoreModuleRejected('outside native workspace JSON byte profile')
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        arena=ctypes.create_string_buffer(ARENA_BYTES)
        scratch=ctypes.create_string_buffer(WORKSPACE_BYTES)
        result=self._entry(source,len(wire),arena,ARENA_BYTES,scratch,WORKSPACE_BYTES)
        if not 0<result<=MAX_ASSEMBLY_BYTES:
            raise CoreModuleRejected('native workspace policy/primitive-v8 representation refused: '+str(result))
        return ctypes.string_at(arena,result)


def installed_materializer(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeCoreWorkspaceMaterializer)
