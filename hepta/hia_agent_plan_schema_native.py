"""Validate exact issued machine-plan JSON before Core-bound plan admission."""
from .hia_agent_schema_native import NativeAgentSchema
from .hia_agent_store import _agent_resource_path
from .hia_json_preflight_native import _installed_json_image

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_plan_schema.hepta')
SCHEMA = 'hepta.hia.agent-plan-schema-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_PLAN_SCHEMA_MANIFEST'
PLAN_ROLE = 1


class NativeAgentPlanSchema(NativeAgentSchema):
    # Two work arrays of up to 4096 arena indexes for stable merge passes.
    AUXILIARY_BYTES = NativeAgentSchema.AUXILIARY_BYTES + 2 * 4096 * 8


def installed_agent_plan_schema(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentPlanSchema)
