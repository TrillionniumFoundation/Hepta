"""Owned llama.cpp inference with a registered, answer-free output envelope."""
from __future__ import annotations

import hashlib
import time

from experiments.hia_agent_matched_v3_20261028.fixtures import response_schema
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, canonical, validate_completion


class EnvelopeEngine(LlamaCppEngine):
    def __init__(self, **kwargs):
        super().__init__(json_object=True, **kwargs)
        self.identity["decoder"] = {
            "mode": "per_request_envelope_schema",
            "scope": "files envelope, filenames and content types only; no repair operations, constants or references",
            "schemas": {language: response_schema(language) for language in ("hia", "rust")}}
        (self.output / "identity.json").write_bytes(canonical(self.identity) + b"\n")

    def generate(self, messages, *, language, limit=2048, wall_seconds=180):
        rendered = self.request("/apply-template", {"messages": messages}).get("prompt")
        if type(rendered) is not str:
            raise ValueError("E_MATCHED_TEMPLATE")
        ids = self.tokenize(rendered, special=True)
        if not ids or len(ids) + limit > self.context:
            raise ValueError("E_MATCHED_CONTEXT: full prompt and maximum response must fit")
        schema = response_schema(language)
        payload = {"prompt": ids, "n_predict": limit, "temperature": 0, "seed": 0,
            "top_k": 0, "top_p": 1, "min_p": 0, "repeat_penalty": 1,
            "cache_prompt": False, "return_tokens": True, "stream": False,
            "stop": [], "ignore_eos": False, "json_schema": schema}
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
        return {"schema": "hepta.agent.matched-envelope.generation.v1", "status": "completed",
            "text": raw["content"], "rendered_prompt": rendered, "input_token_ids": ids,
            "output_token_ids": raw["tokens"], "request": payload, "response": raw, "usage": usage,
            "wall_nanoseconds": elapsed,
            "envelope_schema_sha256": hashlib.sha256(canonical(schema)).hexdigest()}
