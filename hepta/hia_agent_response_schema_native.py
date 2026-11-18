"""Pinned native validation for ordinary Agent tool responses."""
from .hia_agent_schema_native import NativeAgentSchema
from .hia_agent_store import _agent_resource_path
from .hia_json_preflight_native import _installed_json_image


SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_response_schema.hepta')
SCHEMA = 'hepta.hia.agent-response-schema-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_RESPONSE_SCHEMA_MANIFEST'


def installed_agent_response_schema(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentSchema)
