"""Unchanged V8 inference with an explicit, checked Qwen3.5 template branch."""
from __future__ import annotations

from experiments.hia_agent_toolstudy_v8_20261029.engine import ToolStudyEngine as OriginalEngine
from experiments.hia_agent_toolstudy_v11_20261030 import prompts
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
        if endpoint != "/apply-template":
            return super().request(endpoint, payload, timeout)
        self.template_checks += 1
        valid = type(payload) is dict and set(payload) == {"messages"}
        expected = None
        error = None
        observed = None
        sent = None
        try:
            if not valid:
                raise ValueError("E_TOOLSTUDY_V11_TEMPLATE_REQUEST_SCOPE")
            expected = prompts.plain_qwen_template(payload["messages"])
            # The server's apply-template endpoint uses its normal chat-params
            # parser. Only this fixed model-format option is added; visible
            # task messages and every /completion generation field are intact.
            sent = {"messages": payload["messages"],
                    "chat_template_kwargs": {"enable_thinking": False}}
            observed = super().request(endpoint, sent, timeout)
        except Exception as exc:
            error = {"type": type(exc).__name__, "message": str(exc)}
        matched = bool(valid and error is None and type(observed) is dict
                       and observed.get("prompt") == expected)
        record = {
            "schema": "hepta.agent.qwen35-plain-template-check.v1",
            "request": payload, "actual_server_request": sent,
            "observed_response": observed, "expected_prompt": expected,
            "matched": matched, "template_error": error,
            "official_template": prompts.official_template_binding(),
            "model_generation_requested_by_this_check": False,
            "messages_or_answers_rewritten_by_host": False,
        }
        (self.output / ("template-" + str(self.template_checks).zfill(3) + ".json")).write_bytes(
            canonical(record) + b"\n")
        if not matched:
            raise ValueError("E_TOOLSTUDY_V11_OFFICIAL_TEMPLATE_MISMATCH")
        return observed
