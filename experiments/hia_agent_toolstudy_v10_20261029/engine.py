"""The V8 generator unchanged, with one fail-closed Qwen3 template check."""
from __future__ import annotations
from experiments.hia_agent_toolstudy_v8_20261029.engine import ToolStudyEngine as OriginalEngine
from experiments.hia_agent_toolstudy_v10_20261029 import prompts
from tools.provider_adapter.llama_cpp_engine import canonical


class ToolStudyEngine(OriginalEngine):
    def __init__(self, **kwargs):
        self.template_checks = 0
        self.process = None
        try:
            super().__init__(**kwargs)
            self.identity["official_plain_template"] = prompts.official_template_binding()
            (self.output / "identity.json").write_bytes(canonical(self.identity) + b"\n")
        except BaseException:
            self.close()
            raise

    def request(self, endpoint, payload=None, timeout=10):
        observed = super().request(endpoint, payload, timeout)
        if endpoint == "/apply-template":
            self.template_checks += 1
            valid_request = type(payload) is dict and set(payload) == {"messages"}
            expected = None
            error = None
            try:
                expected = prompts.plain_qwen_template(payload["messages"]) if valid_request else None
            except Exception as exc:
                error = {"type": type(exc).__name__, "message": str(exc)}
            matched = bool(valid_request and error is None and type(observed) is dict and observed.get("prompt") == expected)
            record = {"schema": "hepta.agent.qwen3-plain-template-check.v1", "request": payload,
                      "observed_response": observed, "expected_prompt": expected, "matched": matched,
                      "official_template": {"config_sha256": prompts.TOKENIZER_SHA256, "config_bytes": prompts.TOKENIZER_BYTES},
                      "template_error": error,
                      "model_generation_requested_by_this_check": False, "messages_or_answers_rewritten": False}
            (self.output / ("template-" + str(self.template_checks).zfill(3) + ".json")).write_bytes(canonical(record) + b"\n")
            if not matched:
                raise ValueError("E_TOOLSTUDY_V10_OFFICIAL_TEMPLATE_MISMATCH")
        return observed
