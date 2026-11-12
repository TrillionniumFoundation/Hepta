"""Real offline completions with syntax-only file-envelope constraints."""
from __future__ import annotations

import hashlib
import time

from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, canonical, validate_completion
from experiments.hia_agent_factorial_v4_20261028.fixtures import response_schema


class EnvelopeEngine(LlamaCppEngine):
    def __init__(self, **kwargs):
        super().__init__(json_object=True, **kwargs)
        self.identity["decoder"] = {"mode": "syntax-only-file-envelope", "schemas": {k: response_schema(k) for k in ("hia", "rust")},
                                    "correct_operations_or_values_embedded": False}
        (self.output / "identity.json").write_bytes(canonical(self.identity) + b"\n")

    def generate(self, messages, *, language, limit=2048, wall_seconds=240):
        rendered = self.request("/apply-template", {"messages": messages}).get("prompt")
        if type(rendered) is not str:
            raise ValueError("E_FACTORIAL_TEMPLATE")
        ids = self.tokenize(rendered, special=True)
        if not ids or len(ids) + limit > self.context:
            raise ValueError("E_FACTORIAL_CONTEXT: full prompt and maximum output must fit")
        schema = response_schema(language)
        payload = {"prompt": ids, "n_predict": limit, "temperature": 0, "seed": 0, "top_k": 0,
                   "top_p": 1, "min_p": 0, "repeat_penalty": 1, "cache_prompt": False,
                   "return_tokens": True, "stream": False, "stop": [], "ignore_eos": False, "json_schema": schema}
        self.generation_count += 1
        stem = "transport-" + str(self.generation_count).zfill(3)
        with (self.output / (stem + ".request.json")).open("xb") as stream:
            stream.write(canonical({"messages": messages, "rendered_prompt": rendered, "payload": payload}) + b"\n")
        started = time.monotonic_ns()
        raw = self.request("/completion", payload, timeout=wall_seconds)
        self.response_count += 1
        elapsed = time.monotonic_ns() - started
        with (self.output / (stem + ".response.json")).open("xb") as stream:
            stream.write(canonical(raw) + b"\n")
        usage = validate_completion(raw, ids, limit, json_object=True)
        return {"schema": "hepta.agent.factorial.generation.v4", "text": raw["content"], "usage": usage,
                "input_token_ids": ids, "output_token_ids": raw["tokens"], "wall_ns": elapsed,
                "decoder_sha256": hashlib.sha256(canonical(schema)).hexdigest()}
