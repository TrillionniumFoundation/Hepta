"""Select the pinned HIA discovery routes and materialize canonical catalog bytes."""
from __future__ import annotations

import ctypes
import struct

from .hia_agent_store import _agent_resource_path, reject
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_schema import PRIMITIVE_PROFILES

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_discovery.hepta')
SCHEMA = 'hepta.hia.agent-discovery-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_DISCOVERY_MANIFEST'
REQUEST = struct.Struct('<8s5Q')
RESPONSE = struct.Struct('<4Q')
VERSIONS = tuple(PRIMITIVE_PROFILES)

# Indexed by the native discovery ABI. None denotes the catalog just persisted.
RESOURCE_ROLES = (
    ('manifest', None),
    ('resources', 'schema_registry'),
    ('resources', 'assembly_grammar'),
    ('resources', 'core_language'),
    (None, None),
    ('profile_artifacts', 'backend'),
    ('profile_artifacts', 'lowering'),
    ('profile_artifacts', 'target'),
    ('resources', 'byte_bootstrap_guide'),
    ('resources', 'self_hosting_core_guide'),
    ('resources', 'self_hosting_core_support'),
    ('profile_artifacts', 'validation'),
    ('resources', 'machine_validation_guide'),
    ('resources', 'proof_contract_guide'),
    ('resources', 'buffer_lifecycle_guide'),
    ('resources', 'examples'),
    ('resources', 'diagnostics'),
    ('profile_artifacts', 'plan'),
    ('resources', 'plan_schema'),
    ('resources', 'machine_plan_guide'),
    ('resources', 'macro_policy'),
    ('resources', 'macro_policy_guide'),
)

REFUSALS = {
    4294967288: ('E_HIA_CURSOR', 'discovery has no further page for this bounded manifest'),
    4294967289: ('E_HIA_PROFILE', 'requested backend profile is unavailable'),
    4294967290: ('E_HIA_OPCODE', 'catalog requires an exact primitive schema'),
}


class NativeAgentDiscovery(NativeHiaJsonImage):
    def plan(self, arguments, installed_backend):
        section = arguments['section'].encode('utf-8')
        requested = arguments.get('backend_profile', '').encode('utf-8', 'surrogatepass')
        installed = installed_backend.encode('utf-8')
        schema = arguments.get('language_schema', '').encode('utf-8', 'surrogatepass')
        flags = ('cursor' in arguments) | (('backend_profile' in arguments) << 1) | (
            ('language_schema' in arguments) << 2)
        frame = REQUEST.pack(b'HIADIS01', flags, len(section), len(requested), len(installed), len(schema))
        header, body = self._render(frame + section + requested + installed + schema)
        version, count, recipe, _ = header
        if not 1 <= version <= len(VERSIONS) or not 1 <= count <= 10 or recipe >> (count * 5):
            raise ValueError('invalid native HIA Agent discovery plan')
        roles = tuple((recipe >> (index * 5)) & 31 for index in range(count))
        if max(roles) >= len(RESOURCE_ROLES) or len(set(roles)) != count:
            raise ValueError('invalid native HIA Agent discovery resource role')
        return VERSIONS[version - 1], body, roles

    def registry(self):
        header, body = self._render(b'HIADISRG')
        if header[:3] != (len(VERSIONS) + 1, 0, 0):
            raise ValueError('invalid native HIA Agent schema registry header')
        return body

    def _render(self, raw):
        source = ctypes.create_string_buffer(raw)
        output = ctypes.create_string_buffer(RESPONSE.size + 65536)
        workspace = ctypes.create_string_buffer(65536)
        width = self._entry(source, len(raw), output, len(output), workspace, len(workspace))
        if width in REFUSALS:
            reject(*REFUSALS[width])
        if not RESPONSE.size < width <= len(output):
            raise ValueError('invalid native HIA Agent discovery response')
        header = RESPONSE.unpack_from(output)
        if header[3] != width - RESPONSE.size:
            raise ValueError('invalid native HIA Agent discovery extent')
        return header, output[RESPONSE.size:width]


def installed_agent_discovery(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentDiscovery)
