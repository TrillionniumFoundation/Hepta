"""Same owned engine with explicitly retained ordered completion request bytes."""
from __future__ import annotations

import hashlib
import json

from experiments.hia_agent_structured_v7_20261029 import contracts_v2 as contracts
from experiments.hia_agent_toolstudy_v8_20261029.engine import response_schema as old_schema
from experiments.hia_agent_toolstudy_v11_20261030.engine import ToolStudyEngine as PreviousEngine
from tools.provider_adapter.llama_cpp_engine import canonical


def response_schema(language, interface, query):
    if language not in {"rust", "hia"} or interface not in {"node", "full"}:
        raise ValueError("E_TOOLSTUDY_V13_INTERFACE")
    schema = contracts.response_schema(query)
    if query["language"] != language:
        raise ValueError("E_TOOLSTUDY_V13_QUERY_LANGUAGE")
    return schema if interface == "node" else old_schema(language, interface)


class ToolStudyEngine(PreviousEngine):
    def __init__(self, **kwargs):
        self.process = None
        try:
            super().__init__(**kwargs)
            self.identity["decoder"] = {
                "mode": contracts.PROFILE,
                "node_schemas": "all public editable IDs/fields, public Rust type grammar, node before changes",
                "full_schemas": {language: old_schema(language, "full") for language in ("hia", "rust")},
                "all_public_editable_nodes_included": True,
                "correct_operations_or_values_embedded": False,
                "reference_selected_nodes_embedded": False,
                "admission_authority_changed": False,
                "actual_completion_wire_bytes_retained": True,
            }
            (self.output / "identity.json").write_bytes(canonical(self.identity) + b"\n")
        except BaseException:
            self.close()
            raise

    def decoder_schema(self, language, interface, query=None):
        if query is None:
            raise ValueError("E_TOOLSTUDY_V13_CAPTURED_QUERY_REQUIRED")
        return response_schema(language, interface, query)

    def completion_body(self, payload):
        node = "edits" in payload["json_schema"].get("properties", {})
        if node:
            contracts.require_selection_first(payload["json_schema"])
        body = contracts.ordered_wire(payload) if node else canonical(payload)
        # Save the exact bytes that will be passed to HTTPConnection. Canonical
        # request JSON is retained separately by the common engine.
        path = self.output / ("transport-" + str(self.generation_count).zfill(3) + ".request.body.json")
        with path.open("xb") as stream:
            stream.write(body)
        self.actual_wire_sha256 = hashlib.sha256(body).hexdigest()
        return body

    def generate(self, messages, *, language, interface, limit=1536, wall_seconds=900, query=None):
        result = super().generate(messages, language=language, interface=interface,
                                  limit=limit, wall_seconds=wall_seconds, query=query)
        stem = "transport-" + str(self.generation_count).zfill(3)
        raw = json.loads((self.output / (stem + ".response.json")).read_bytes())
        settings = raw.get("generation_settings", {})
        settings = settings.get("params", settings)
        check = (contracts.check_actual_grammar(response_schema(language, interface, query),
                                               settings.get("grammar"))
                 if interface == "node" else {"full_wire_unchanged": True})
        record = {"schema": "hepta.agent.selection-first-wire.v1", **check,
                  "actual_request_body_sha256": self.actual_wire_sha256,
                  "query_sha256": query["query_sha256"],
                  "schema_binding": contracts.binding(query) if interface == "node" else None,
                  "model_answer_rewritten": False}
        (self.output / (stem + ".decoder-check.json")).write_bytes(canonical(record) + b"\n")
        result["decoder_wire_check"] = record
        return result
