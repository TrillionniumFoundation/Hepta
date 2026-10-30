"""Shared V11 runner configuration; no reference answer enters generation."""
from __future__ import annotations

import hashlib

from experiments.hia_agent_toolstudy_v11_20261030 import prompts
from experiments.hia_agent_toolstudy_v12_20261030 import support
from experiments.hia_agent_toolstudy_v12_20261030.engine import ToolStudyEngine, response_schema
from tools.provider_adapter.llama_cpp_engine import canonical

capacity_schema = "hepta.agent.tool-capacity.v12"
engine_class = ToolStudyEngine


def generation_keywords(query):
    return {"query": query}


def _accepts(schema, value):
    """Capacity-only check of the small emitted JSON-schema vocabulary.

    This does not parse Rust/HIA or admit model code. Its job is to prevent a
    broken decoder contract from silently excluding the control responses.
    Native grammar and whole-source admission remain separate operations.
    """
    if "oneOf" in schema:
        return sum(_accepts(s, value) for s in schema["oneOf"]) == 1
    if "anyOf" in schema:
        return any(_accepts(s, value) for s in schema["anyOf"])
    if "enum" in schema:
        return any(canonical(value) == canonical(item) for item in schema["enum"])
    if "const" in schema:
        return canonical(value) == canonical(schema["const"])
    kind = schema["type"]
    if kind == "string":
        return type(value) is str
    if kind == "array":
        return (type(value) is list and len(value) >= schema.get("minItems", 0)
                and len(value) <= schema.get("maxItems", 10**9)
                and all(_accepts(schema["items"], item) for item in value))
    if kind == "object":
        properties = schema.get("properties", {})
        return (type(value) is dict and set(schema.get("required", [])).issubset(value)
                and (schema.get("additionalProperties") is not False or set(value).issubset(properties))
                and all(_accepts(properties[key], item) for key, item in value.items() if key in properties))
    raise ValueError("E_TOOLSTUDY_V12_UNREGISTERED_SCHEMA_KEYWORD")


def decoder_control(query, language, interface, control_response):
    # Schema construction happens BEFORE looking at the control response.
    # This function is used only by capacity validation, never generation.
    schema = response_schema(language, interface, query)
    if not _accepts(schema, control_response):
        raise ValueError("E_TOOLSTUDY_V12_REFERENCE_EXCLUDED_BY_PUBLIC_CONTRACT")
    return {"schema_sha256": hashlib.sha256(canonical(schema)).hexdigest(),
            "public_contract_reference_valid": True, "answer_used_for_decoder": False,
            "native_grammar_execution_claimed_by_this_control": False}
