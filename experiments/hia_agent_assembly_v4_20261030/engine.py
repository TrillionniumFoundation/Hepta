"""Owned llama.cpp inference with a registered, answer-free output envelope."""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import math
import signal
import threading
import time

from experiments.hia_agent_assembly_v4_20261030.fixtures import response_schema
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, canonical, validate_completion


@contextmanager
def generation_deadline(seconds):
    """One hard elapsed deadline, including template/tokenization/response I/O.

    This experiment runs on the Linux main thread and never steals an existing
    timer or unblocks an owner's signal. Socket read timeouts alone do not stop
    drip-fed responses. The monotonic final check also covers late delivery.
    """
    if (type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0
            or threading.current_thread() is not threading.main_thread()
            or not all(hasattr(signal, key) for key in ("SIGALRM", "ITIMER_REAL", "setitimer", "pthread_sigmask"))):
        raise RuntimeError("E_AGENT_DEADLINE_UNAVAILABLE")
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    previous_handler = signal.getsignal(signal.SIGALRM)
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    if previous_timer != (0.0, 0.0) or signal.SIGALRM in blocked:
        raise RuntimeError("E_AGENT_DEADLINE_OWNER_CONFLICT")
    deadline = time.monotonic() + seconds

    def expired(_signal, _frame):
        raise TimeoutError("entire generate wall deadline exceeded")

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("entire generate wall deadline exceeded")
        return value

    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, remaining())
        yield remaining
        remaining()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


class EnvelopeEngine(LlamaCppEngine):
    def __init__(self, **kwargs):
        super().__init__(json_object=True, **kwargs)
        try:
            self.identity["decoder"] = {
                "mode": "per_request_envelope_schema",
                "scope": "files envelope, filenames and content types only; no repair operations, constants or references",
                "schemas": {language: response_schema(language) for language in ("hia", "assembly", "rust")}}
            (self.output / "identity.json").write_bytes(canonical(self.identity) + b"\n")
        except BaseException as error:
            # Assignment to the caller's owner has not completed yet.
            try:
                self.close()
            except BaseException as cleanup:
                error.add_note("owned server cleanup also failed: " + type(cleanup).__name__)
            raise

    def generate(self, messages, *, language, limit=2048, wall_seconds=180):
        started = time.monotonic_ns()
        with generation_deadline(wall_seconds) as remaining:
            result = self._generate(messages, language=language, limit=limit, remaining=remaining)
        result["whole_generate_ns"] = time.monotonic_ns() - started
        result["hard_wall_seconds"] = wall_seconds
        return result

    def _generate(self, messages, *, language, limit, remaining):
        rendered = self.request("/apply-template", {"messages": messages}, timeout=remaining()).get("prompt")
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
        stem = "transport-" + str(self.generation_count + 1).zfill(3)
        with (self.output / (stem + ".request.json")).open("xb") as stream:
            stream.write(canonical({"messages": messages, "rendered_prompt": rendered, "payload": payload}) + b"\n")
        started = time.monotonic_ns()
        timeout = remaining()
        self.generation_count += 1
        raw = self.request("/completion", payload, timeout=timeout)
        self.response_count += 1
        elapsed = time.monotonic_ns() - started
        with (self.output / (stem + ".response.json")).open("xb") as stream:
            stream.write(canonical(raw) + b"\n")
        usage = validate_completion(raw, ids, limit, json_object=True)
        return {"schema": "hepta.agent.assembly-envelope.generation.v1", "status": "completed",
            "text": raw["content"], "rendered_prompt": rendered, "input_token_ids": ids,
            "output_token_ids": raw["tokens"], "request": payload, "response": raw, "usage": usage,
            "wall_nanoseconds": elapsed,
            "envelope_schema_sha256": hashlib.sha256(canonical(schema)).hexdigest()}
