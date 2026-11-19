"""Pinned HIA schemas for issued workload, objective and cost-policy bytes."""
from .hia_agent_schema_native import NativeAgentSchema
from .hia_agent_store import _agent_resource_path
from .hia_json_preflight_native import _installed_json_image

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_payload_schema.hepta')
SCHEMA = 'hepta.hia.agent-payload-schema-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_PAYLOAD_SCHEMA_MANIFEST'
WORKLOAD_ROLE, OBJECTIVE_ROLE, COST_POLICY_ROLE = 1, 2, 3


def installed_agent_payload_schema(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentSchema)
