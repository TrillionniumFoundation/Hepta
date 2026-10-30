"""Same pinned inference; an explicit public-catalogue decoding profile."""
from __future__ import annotations

from experiments.hia_agent_structured_v7_20261029 import contracts
from experiments.hia_agent_toolstudy_v8_20261029.engine import response_schema as old_schema
from experiments.hia_agent_toolstudy_v11_20261030.engine import ToolStudyEngine as PreviousEngine
from tools.provider_adapter.llama_cpp_engine import canonical


def response_schema(language, interface, query):
    if language not in {"rust", "hia"} or interface not in {"node", "full"}:
        raise ValueError("E_TOOLSTUDY_V12_INTERFACE")
    node_schema = contracts.response_schema(query)
    if query["language"] != language:
        raise ValueError("E_TOOLSTUDY_V12_QUERY_LANGUAGE")
    return node_schema if interface == "node" else old_schema(language, interface)


class ToolStudyEngine(PreviousEngine):
    def __init__(self, **kwargs):
        self.process = None
        try:
            super().__init__(**kwargs)
            self.identity["decoder"] = {
                "mode": contracts.PROFILE,
                "node_schemas": "derived from each captured complete public query and retained in every actual request",
                "full_schemas": {language: old_schema(language, "full") for language in ("hia", "rust")},
                "all_public_editable_nodes_included": True,
                "correct_operations_or_values_embedded": False,
                "reference_selected_nodes_embedded": False,
                "admission_authority_changed": False,
            }
            (self.output / "identity.json").write_bytes(canonical(self.identity) + b"\n")
        except BaseException:
            self.close()
            raise

    def decoder_schema(self, language, interface, query=None):
        if query is None:
            raise ValueError("E_TOOLSTUDY_V12_CAPTURED_QUERY_REQUIRED")
        return response_schema(language, interface, query)
