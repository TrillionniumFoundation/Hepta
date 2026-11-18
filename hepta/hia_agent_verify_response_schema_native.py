"""Pinned native validation for the full Agent proof response."""
from .hia_agent_schema_native import NativeAgentSchema
from .hia_agent_store import _agent_resource_path
from .hia_json_preflight_native import _installed_json_image


SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_verify_response_schema.hepta')
SCHEMA = 'hepta.hia.agent-verify-response-schema-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_VERIFY_RESPONSE_SCHEMA_MANIFEST'


def installed_agent_verify_response_schema(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentSchema)
