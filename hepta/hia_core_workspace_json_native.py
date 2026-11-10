"""Raw-byte transport for native workspace JSON linking, not native Core checking.

The HIA image owns JSON/schema/framing, graph facts, name/privacy/cycle policy,
capture-avoiding public ABI names, call substitution and linked JSON rendering.
Python only bounds/allocates immutable transport and independently checks the
returned Core. There is no fallback to the old host workspace materializer.
"""
from __future__ import annotations
import ctypes
from hashlib import sha256
from pathlib import Path
from .hia_core_module_graph_native import CoreModuleRejected, ERRORS
from .hia_json_decode_native import arena_sizes
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, scratch_sizes
from .hia_program import verify_program
from .hia_program_tools import bounded_json_wire

SOURCE = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_workspace_json.hiaasm'
SCHEMA = 'hepta.hia.core-workspace-json-native.v1'
MAX_BYTES = 8 << 20
# Exact upper bounds of the unchanged graph packet/result limits and private
# function/call/name tables, not a second JSON traversal or host name resolver.
PRIVATE_BYTES = MAX_BYTES + 64 + 8*(1024+4096+16384+1024+1024+1024) + 48*1024 + 8*16384 + 8


class NativeCoreWorkspaceJson(NativeHiaJsonImage):
    def run(self, wire):
        if type(wire) is not bytes or len(wire) > MAX_BYTES:
            raise CoreModuleRejected('outside native Core workspace JSON byte profile')
        arena, _ = arena_sizes(len(wire), 1 << 20, 128)
        keys, _ = scratch_sizes(len(wire), 1 << 20, 128)
        source = ctypes.create_string_buffer(wire,max(1,len(wire)))
        output = ctypes.create_string_buffer(max(MAX_BYTES,keys,8192))
        state = ctypes.create_string_buffer(arena+PRIVATE_BYTES)
        status = self._entry(source,len(wire),output,len(output),state,len(state))
        if status >= 0xffff0000:
            error = {0xffffffef:'invalid primitive Core workspace JSON framing',
                     0xffffffee:'linked Core JSON output exceeds 8 MiB'}.get(status,ERRORS.get(status,'JSON syntax/Unicode/budget rejection'))
            raise CoreModuleRejected('E_HIA_CORE_WORKSPACE_JSON: '+error)
        if not 0 < status <= MAX_BYTES:
            raise CoreModuleRejected('invalid native Core workspace JSON return')
        return output.raw[:status]


def installed_workspace_json(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeCoreWorkspaceJson)


def link_workspace(document, *, native):
    if type(document) is str:
        raw=document.encode('utf-8')
    elif type(document) is bytes:
        raw=document
    else:
        raw=bounded_json_wire(document,MAX_BYTES)
    linked=native.run(raw)
    verified=verify_program(linked)
    return verified,{
        'schema':'hepta.hia.core-workspace-json-link.v1','status':'VERIFIED_UNPUBLISHED',
        'workspace_sha256':sha256(raw).hexdigest(),
        'linked_core_sha256':verified.sha256,'native_linked_json_sha256':sha256(linked).hexdigest(),
        'native_image_sha256':native.image_sha256,
        'JSON_framing_fact_encoding_graph_policy_and_Core_materialization':'HIA_NATIVE',
        'host_general_Core_verification_and_filesystem_build_install_bridge':True,
        'original_external_export_names_preserved':True,
        'reference_module_policy_or_materialization_fallback':False,
        'nominal_type_linking_package_filesystem_locks_native_install':'OPEN',
        'whole_native_workspace_qualified':False,'production_activated':False}
