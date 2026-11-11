"""Closed wire contract and discoverable execution profiles for HIA tools.

This small validator implements only the JSON-Schema vocabulary used by the
checked-in catalog. It rejects unsupported vocabulary when loading the catalog;
it is not a general JSON-Schema implementation or a new language checker.
"""
from __future__ import annotations

from hashlib import sha256
import json
import math
from pathlib import Path
import re

from .hia_agent_store import AgentRejected, reject, wire, _agent_resource_path

VERSION = "hepta.hia.agent-native.v1"
ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = _agent_resource_path("docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json")
DISCOVERY_FILES = (
    "HIA_AGENT_NATIVE_TOOL_CATALOG.json", "HIA_AGENT_ASSEMBLY.md", "HIA_PROGRAM.md",
    "HIA_AGENT_MACHINE_PLANS.md", "HIA_AGENT_MACRO_POLICY.md", "HIA_DIRECT_BYTE_BOOTSTRAP.md",
    "HIA_SELF_HOSTING_CORE.md", "HIA_SELFHOST_CORE_SUPPORT.json", "HIA_AGENT_PROOF_RESULTS.md",
    "HIA_SAFE_CORE_MACHINE_VALIDATION.md",
    "HIA_AGENT_BUFFER_LIFECYCLE.md",
)


NATIVE_SOURCE_FILES = (
    'examples/hia_bootstrap/agent_journal.hepta',
    'examples/hia_bootstrap/worker_request.hepta',
    'examples/hia_bootstrap/agent_identity.hepta',
    'examples/hia_bootstrap/agent_slice.hepta',
    'examples/hia_bootstrap/agent_data_json.hepta',
    'examples/hia_bootstrap/agent_binary64.hepta',
    'examples/hia_bootstrap/agent_snapshot_json.hepta',
    'examples/hia_bootstrap/agent_snapshot.hepta',
    'examples/hia_bootstrap/capability_renaming.hepta',
    'examples/hia_bootstrap/core_json_frontend.hepta',
    'examples/hia_bootstrap/core_module_graph.hepta',
    'examples/hia_bootstrap/core_workspace_facts.hepta',
    'examples/hia_bootstrap/core_workspace_json.hepta',
    'examples/hia_bootstrap/core_workspace_materialize.hepta',
    'examples/hia_bootstrap/function_shape.hepta',
    'examples/hia_bootstrap/instruction_policy.hepta',
    'examples/hia_bootstrap/json_canonical.hepta',
    'examples/hia_bootstrap/json_decode.hepta',
    'examples/hia_bootstrap/json_preflight.hepta',
    'examples/hia_bootstrap/program_shape.hepta',
    'examples/hia_bootstrap/sha256.hepta',
    'examples/hia_bootstrap/sha256_stream.hepta',
    'examples/hia_bootstrap/agent_binary64_format.hepta',
    'examples/hia_bootstrap/core_admission.hepta',
    'examples/hia_bootstrap/core_patch.hepta',
    'examples/hia_bootstrap/composite_types.hepta',
    'examples/hia_bootstrap/task_helpers.hepta',
    'examples/hia_bootstrap/composite_function_admit.hepta',
    'examples/hia_bootstrap/composite_function_records.hepta',
    'examples/hia_bootstrap/composite_function_advanced.hepta',
    'examples/hia_bootstrap/composite_function_terms.hepta',
    'examples/hia_bootstrap/composite_function_render.hepta',
    'examples/hia_bootstrap/composite_constructor_owner.hepta',
    'examples/hia_bootstrap/composite_constructor_render.hepta',
    'examples/hia_bootstrap/composite_outer_owner.hepta',
    'examples/hia_bootstrap/composite_outer_render.hepta',
)


# Build-input custody assets, not loadable native image adapters. The streaming
# SHA source is already in NATIVE_SOURCE_FILES and is deliberately not repeated.
PUBLICATION_BUILD_FILES = (
    'examples/hia_bootstrap/artifact_publication_policy.hepta',
    'examples/hia_bootstrap/artifact_publication_packer.hepta',
    'tools/hia_artifact_publication_syscalls.S',
    'tools/generate_hia_artifact_publication.py',
)


def catalog():
    data = CATALOG_PATH.read_bytes()
    value = json.loads(data)
    for tool in value["tools"]:
        check_vocabulary(tool["inputSchema"])
        check_vocabulary(tool["outputSchema"])
    return value, sha256(data).hexdigest()


def installation_manifest():
    """Hash actual installed source bytes, never infer a clean Git commit."""
    entries = {}
    for path in sorted((ROOT / "hepta").rglob("*.py")):
        if path.relative_to(ROOT / "hepta").parts[0] == "_data":
            continue  # Explicit build assets below are data, never Python modules.
        entries[str(path.relative_to(ROOT))] = sha256(path.read_bytes()).hexdigest()
    for filename in DISCOVERY_FILES:
        path = _agent_resource_path("docs/" + filename)
        entries["docs/" + filename] = sha256(path.read_bytes()).hexdigest()
    for native_source in (*NATIVE_SOURCE_FILES, *PUBLICATION_BUILD_FILES):
        entries[native_source] = sha256(_agent_resource_path(native_source).read_bytes()).hexdigest()
    from .hia_program_native import _implementation_hash
    return {"worker_sha256": sha256(wire(entries)).hexdigest(),
            "backend_sha256": _implementation_hash(),
            "catalog_sha256": entries["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"]}


_KEYWORDS = frozenset({"$schema", "type", "properties", "required", "additionalProperties",
    "enum", "const", "pattern", "minLength", "maxLength", "minimum", "maximum", "items",
    "minItems", "maxItems", "uniqueItems", "oneOf", "anyOf", "allOf", "if", "then", "else",
    "not", "contains", "description", "title", "minProperties", "maxProperties"})


def check_vocabulary(schema):
    if type(schema) is bool:
        return
    if type(schema) is not dict or set(schema) - _KEYWORDS:
        raise ValueError("unsupported catalog JSON-Schema vocabulary")
    for key in ("oneOf", "anyOf", "allOf"):
        for sub in schema.get(key, []):
            check_vocabulary(sub)
    for key in ("items", "contains", "if", "then", "else", "not"):
        if key in schema:
            check_vocabulary(schema[key])
    for sub in schema.get("properties", {}).values():
        check_vocabulary(sub)
    if type(schema.get("additionalProperties")) is dict:
        check_vocabulary(schema["additionalProperties"])


def validate(value, schema, label="arguments"):
    def fail(reason):
        reject("E_HIA_SCHEMA", label + ": " + reason)

    def matches(sub):
        try:
            validate(value, sub, label)
            return True
        except AgentRejected:
            return False

    if schema is True:
        return
    if schema is False:
        fail("not allowed")
    typ = schema.get("type")
    valid_type = {"object": type(value) is dict, "array": type(value) is list,
        "string": type(value) is str, "integer": type(value) is int or
            type(value) is float and math.isfinite(value) and value.is_integer(),
        "number": type(value) is int or type(value) is float and math.isfinite(value),
        "boolean": type(value) is bool, "null": value is None}
    if typ is not None and not valid_type.get(typ, False):
        fail("expected " + str(typ))
    if "const" in schema and wire(value) != wire(schema["const"]):
        fail("constant differs")
    if "enum" in schema and not any(wire(value) == wire(v) for v in schema["enum"]):
        fail("not in the declared choices")
    for key, wanted in (("oneOf", 1), ("anyOf", None)):
        if key in schema:
            count = sum(matches(sub) for sub in schema[key])
            if (wanted is not None and count != wanted) or (wanted is None and count == 0):
                # A tagged union can name the actual failing field without
                # relaxing admission or echoing the caller's data.  Reporting
                # only "does not match oneOf" hid the import source/format
                # contract from a real first-use learner.  A uniquely matching
                # discriminator is diagnostic evidence, never a valid branch.
                if count == 0 and type(value) is dict:
                    tagged = []
                    for sub in schema[key]:
                        if type(sub) is not dict:
                            continue
                        tags = {name: child["const"] for name, child in
                            sub.get("properties", {}).items() if type(child) is dict and "const" in child}
                        if tags and all(name in value and wire(value[name]) == wire(tag)
                                        for name, tag in tags.items()):
                            tagged.append(sub)
                    if len(tagged) == 1:
                        validate(value, tagged[0], label)
                fail("does not match " + key)
    for sub in schema.get("allOf", []):
        validate(value, sub, label)
    if "not" in schema and matches(schema["not"]):
        fail("forbidden shape")
    if "if" in schema:
        branch = "then" if matches(schema["if"]) else "else"
        if branch in schema:
            validate(value, schema[branch], label)
    if type(value) is dict:
        missing = set(schema.get("required", [])) - set(value)
        if missing:
            fail("missing fields " + ", ".join(sorted(missing)))
        properties = schema.get("properties", {})
        for name, child in value.items():
            if name in properties:
                validate(child, properties[name], label + "." + name)
            elif schema.get("additionalProperties", True) is False:
                fail("unknown field " + name)
            elif type(schema.get("additionalProperties")) is dict:
                validate(child, schema["additionalProperties"], label + "." + name)
        if len(value) < schema.get("minProperties", 0) or len(value) > schema.get("maxProperties", 1 << 63):
            fail("object field count is outside limits")
    if type(value) is list:
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1 << 63):
            fail("array length is outside limits")
        if schema.get("uniqueItems") and len({wire(item) for item in value}) != len(value):
            fail("duplicate array item")
        for i, item in enumerate(value):
            if "items" in schema:
                validate(item, schema["items"], label + "[" + str(i) + "]")
        if "contains" in schema and not any(_valid(item, schema["contains"]) for item in value):
            fail("array does not contain the required item")
    if type(value) is str:
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1 << 63):
            fail("string length is outside limits")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            fail("string does not match the declared pattern")
    if type(value) in (int, float):
        if (type(value) is float and not math.isfinite(value)) or value < schema.get("minimum", -math.inf) or value > schema.get("maximum", math.inf):
            fail("number is outside limits")


def _valid(value, schema):
    try:
        validate(value, schema)
        return True
    except AgentRejected:
        return False


def input_diagnostic(tool, arguments, *, catalog_document=None):
    """Explain a confirmed local input-schema rejection without changing it.

    A recording MCP bridge may append this to its own rejection response after
    charging the attempt. It must not substitute this validator's success for
    its existing validator, dispatch corrected arguments, refund a call, or
    classify an accepted/unknown server operation as a local rejection.
    """
    document = catalog()[0] if catalog_document is None else catalog_document
    records = [record for record in document["tools"] if record["name"] == tool]
    if len(records) != 1:
        return None
    try:
        validate(arguments, records[0]["inputSchema"])
    except AgentRejected as exc:
        return {"schema": "hepta.hia.agent.input-diagnostic.v1", "tool": tool,
            "message": str(exc)[:4096], "basis": "published inputSchema only",
            "automatic_repair": False, "attempt_refunded": False,
            "recovery": "Use the exact schema and issued references. After a confirmed rejection, changed writer arguments require a new request key; accepted or unknown operations retain their original identity."}
    return None


def obj(properties, required=None):
    return {"type": "object", "properties": properties,
            "required": list(properties) if required is None else required, "additionalProperties": False}


U64 = {"type": "string", "pattern": "^(0|[1-9][0-9]{0,19})$"}
SCALAR = {"anyOf": [{"type": "integer"}, {"type": "boolean"}, {"type": "null"}]}
EXPECTED = {"oneOf": [obj({"status": {"const": "returned"},
    "values": {"type": "array", "items": SCALAR, "maxItems": 1}}),
    obj({"status": {"const": "trapped"}})]}
SCALAR_WORKLOAD_SCHEMA = obj({
    "schema": {"const": "hepta.hia.agent.workload.v1"},
    "cases": {"type": "array", "minItems": 1, "maxItems": 512, "items": obj({
        "function": {"type": "string", "minLength": 1, "maxLength": 128},
        "arguments": {"type": "array", "items": SCALAR, "maxItems": 128},
        "expected": EXPECTED}, ["function", "arguments"])},
    "warmup_iterations": {"type": "integer", "minimum": 0, "maximum": 100},
    "repetitions": {"type": "integer", "minimum": 1, "maximum": 10000},
})
BUFFER_SNAPSHOT = {"oneOf": [
    obj({"bytes_hex": {"type": "string", "pattern": "^(?:[0-9a-f]{2})*$", "maxLength": 2 * 1024**2}}),
    obj({"byte_length": {"type": "integer", "minimum": 0, "maximum": 1024**2},
         "fill_byte": {"type": "integer", "minimum": 0, "maximum": 255}}),
]}
BUFFER_OBSERVATION = obj({
    "argument": {"type": "integer", "minimum": 0, "maximum": 127},
    "kind": {"enum": ["readbuf", "mutbuf"]},
    "byte_length": {"type": "integer", "minimum": 0, "maximum": 1024**2},
    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
})
BUFFER_EXPECTED = {"oneOf": [
    obj({"status": {"const": "returned"},
         "values": {"type": "array", "items": SCALAR, "maxItems": 1},
         "buffers": {"type": "array", "items": BUFFER_OBSERVATION, "maxItems": 8}}, ["status", "values"]),
    obj({"status": {"const": "trapped"},
         "buffers": {"type": "array", "items": BUFFER_OBSERVATION, "maxItems": 8}}, ["status"]),
]}
BUFFER_WORKLOAD_SCHEMA = obj({
    "schema": {"const": "hepta.hia.agent.workload.v2"},
    "foreign_buffer_exports": {"type": "array", "minItems": 1, "maxItems": 128, "items": obj({
        "function": {"type": "string", "minLength": 1, "maxLength": 128},
        "max_buffer_bytes": {"type": "integer", "minimum": 1, "maximum": 1024**2}})},
    "cases": {"type": "array", "minItems": 1, "maxItems": 512, "items": obj({
        "function": {"type": "string", "minLength": 1, "maxLength": 128},
        "arguments": {"type": "array", "items": {"anyOf": [SCALAR, BUFFER_SNAPSHOT]}, "maxItems": 128},
        "expected": BUFFER_EXPECTED}, ["function", "arguments"])},
    "warmup_iterations": {"type": "integer", "minimum": 0, "maximum": 100},
    "repetitions": {"type": "integer", "minimum": 1, "maximum": 10000},
})
WORKLOAD_SCHEMA = {"oneOf": [SCALAR_WORKLOAD_SCHEMA, BUFFER_WORKLOAD_SCHEMA]}
OBJECTIVE_SCHEMA = obj({
    "schema": {"const": "hepta.hia.agent.objective.v1"},
    "metric": {"enum": ["latency_ns", "artifact_bytes"]},
    "required_claims": {"type": "array", "minItems": 1, "maxItems": 4, "uniqueItems": True,
        "items": {"enum": ["core_admission", "behavior_equivalence", "lowering_refinement", "encoding_check"]},
        "contains": {"const": "core_admission"}},
    "allow_unchanged": {"type": "boolean"},
    "min_improvement_ratio": {"type": "number", "minimum": 0, "maximum": 1},
    "require_net_benefit": {"type": "boolean"},
}, ["schema", "metric", "required_claims", "allow_unchanged", "min_improvement_ratio"])
COST_POLICY_SCHEMA = obj({
    "schema": {"const": "hepta.hia.agent.cost-policy.v1"},
    "external_costs": obj({
        "model_tokens": {"anyOf": [{"type": "integer", "minimum": 0, "maximum": 100000000}, {"type": "null"}]},
        "model_wall_ns": {"anyOf": [U64, {"type": "null"}]},
        "discovery_wall_ns": {"anyOf": [U64, {"type": "null"}]},
    }),
    "external_costs_complete": {"type": "boolean"},
    "expected_invocations": U64,
})
BLOCK_PLAN_SCHEMA = obj({
    "schema": {"const": "hepta.hia.agent.block-layout.v1"},
    "core_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "block_order": {"type": "object", "minProperties": 1, "maxProperties": 1024,
        "additionalProperties": {"type": "array", "minItems": 1, "maxItems": 4096,
            "items": {"type": "string", "minLength": 1, "maxLength": 128}, "uniqueItems": True}},
})

# Artifact-referenced plans preserve the eleven-tool wire catalog. Discovery
# publishes the original layout profile and the explicit v2/v3/v4 choices.
MACHINE_PLAN_SCHEMA = obj({
    "schema": {"const": "hepta.hia.agent.machine-plan.v2"},
    "core_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "block_order": {"type": "object", "maxProperties": 1024,
        "additionalProperties": {"type": "array", "minItems": 1, "maxItems": 4096,
            "items": {"type": "string", "minLength": 1, "maxLength": 128}, "uniqueItems": True}},
    "function_order": {"type": "array", "minItems": 1, "maxItems": 1024, "uniqueItems": True,
        "items": {"type": "string", "minLength": 1, "maxLength": 128}},
    "scratch_registers": obj({"r10": {"enum": ["r10", "r11"]}, "r11": {"enum": ["r10", "r11"]}}),
    "instruction_selection": obj({
        "move_immediate": {"enum": ["movabs", "mov32_if_exact"]},
        "alu_immediate": {"enum": ["imm32", "imm8_if_exact"]}}),
    "function_alignment": {"type": "integer", "enum": [1, 16, 32, 64]},
})
VALUE_REGISTER_PLAN_SCHEMA = obj({
    **MACHINE_PLAN_SCHEMA["properties"],
    "schema": {"const": "hepta.hia.agent.machine-plan.v3"},
    "instruction_selection": obj({
        **MACHINE_PLAN_SCHEMA["properties"]["instruction_selection"]["properties"],
        "scalar_select": {"enum": ["branch", "cmov_scalar"]}}),
    "value_registers": {"type": "object", "maxProperties": 1024,
        "additionalProperties": {"type": "object", "maxProperties": 65536,
            "additionalProperties": {"enum": ["rbx", "r12", "r13", "r14", "r15"]}}},
})
LEAF_REGISTER_PLAN_SCHEMA = obj({
    **VALUE_REGISTER_PLAN_SCHEMA["properties"],
    "schema": {"const": "hepta.hia.agent.machine-plan.v4"},
    "value_registers": {"type": "object", "maxProperties": 1024,
        "additionalProperties": {"type": "object", "maxProperties": 65536,
            "additionalProperties": {"enum": ["rbx", "r12", "r13", "r14", "r15", "r8", "r9"]}}},
})
PLAN_SCHEMA = {"oneOf": [BLOCK_PLAN_SCHEMA, MACHINE_PLAN_SCHEMA, VALUE_REGISTER_PLAN_SCHEMA,
                         LEAF_REGISTER_PLAN_SCHEMA]}
