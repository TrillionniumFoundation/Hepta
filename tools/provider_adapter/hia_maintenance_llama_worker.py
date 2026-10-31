#!/usr/bin/env python3
"""One owned, cold local RPC. This worker never imports maintenance tasks."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.hia_agent_codex_transport import canonical, identity, save, strict_json
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine

REQUEST_SCHEMA = "hepta.hia.local-maintenance-model-request.v1"
RECEIPT_SCHEMA = "hepta.hia.local-maintenance-model-receipt.v1"
MODEL_SHA256 = "00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4"


def validate_request(value):
    fields = {"schema", "mode", "text", "runtime", "context", "output_limit", "threads",
              "deadline_monotonic", "evidence_dir", "protocol_sha256"}
    if type(value) is not dict or set(value) != fields or value["schema"] != REQUEST_SCHEMA:
        raise ValueError("E_LOCAL_REQUEST_SHAPE")
    if value["mode"] not in {"generate", "capacity_probe"} or type(value["text"]) is not str:
        raise ValueError("E_LOCAL_REQUEST_MODE_OR_TEXT")
    if not 0 < len(value["text"].encode()) <= 1024**2:
        raise ValueError("E_LOCAL_REQUEST_BYTES")
    if (type(value["context"]) is not int or value["context"] != 8192
            or type(value["output_limit"]) is not int or value["output_limit"] != 1536
            or type(value["threads"]) is not int or value["threads"] != 4):
        raise ValueError("E_LOCAL_FIXED_CONFIGURATION")
    deadline = value["deadline_monotonic"]
    if type(deadline) not in (float, int) or not math.isfinite(deadline):
        raise ValueError("E_LOCAL_DEADLINE")
    runtime = value["runtime"]
    if (type(runtime) is not dict or set(runtime) != {"binary", "model", "model_sha256", "engine_source_sha256", "runtime_files"}
            or any(type(runtime[k]) is not str for k in runtime if k != "runtime_files")
            or type(runtime["runtime_files"]) is not list or not runtime["runtime_files"]
            or runtime["model_sha256"] != MODEL_SHA256):
        raise ValueError("E_LOCAL_RUNTIME_CONFIGURATION")
    if (type(value["evidence_dir"]) is not str or not Path(value["evidence_dir"]).is_absolute()
            or type(value["protocol_sha256"]) is not str or len(value["protocol_sha256"]) != 64):
        raise ValueError("E_LOCAL_REQUEST_BINDING")
    actual_engine = identity(ROOT / "tools/provider_adapter/llama_cpp_engine.py")
    if actual_engine["sha256"] != runtime["engine_source_sha256"]:
        raise ValueError("E_LOCAL_ENGINE_IDENTITY")
    for expected in runtime["runtime_files"]:
        if (type(expected) is not dict or set(expected) != {"path", "bytes", "sha256"}
                or identity(expected["path"]) != expected):
            raise ValueError("E_LOCAL_RUNTIME_IDENTITY_BEFORE_START")
    if str(Path(runtime["binary"]).resolve()) not in {item["path"] for item in runtime["runtime_files"]}:
        raise ValueError("E_LOCAL_BINARY_NOT_BOUND")
    return value


def execute(value, *, engine_class=LlamaCppEngine):
    """The parent owns this worker's entire process group and wall deadline."""
    started = time.monotonic_ns()
    cfg = validate_request(value)
    out = Path(cfg["evidence_dir"])
    out.mkdir(parents=True, exist_ok=False)
    row = {"schema": RECEIPT_SCHEMA, "mode": cfg["mode"], "status": "starting",
           "request_sha256": hashlib.sha256(canonical(cfg)).hexdigest(),
           "text_sha256": hashlib.sha256(cfg["text"].encode()).hexdigest(),
           "protocol_sha256": cfg["protocol_sha256"], "usage": None,
           "unknown_usage": True, "generation_endpoint_attempted": False,
           "completion_received": False, "worker_pid": os.getpid(), "worker_pgid": os.getpgrp(),
           "cold_runtime_per_request": True, "cached_or_reasoning_fields_synthesized": False,
           "requests": [], "inner_cleanup_confirmed": False}
    save(out / "RECEIPT.json", row)
    engine = None

    class DeadlineEngine(engine_class):
        def request(self, endpoint, payload=None, timeout=10):
            if endpoint not in {"/health", "/props", "/apply-template", "/tokenize", "/completion"}:
                raise ValueError("E_LOCAL_ENDPOINT")
            if endpoint == "/completion" and cfg["mode"] != "generate":
                raise ValueError("E_LOCAL_PROBE_CANNOT_GENERATE")
            remaining = cfg["deadline_monotonic"] - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("E_LOCAL_DEADLINE_BEFORE_ENDPOINT:" + endpoint)
            event = {"endpoint": endpoint, "started_monotonic_ns": time.monotonic_ns()}
            row["requests"].append(event)
            if endpoint == "/completion":
                event["completion_admission_pending"] = True
            save(out / "RECEIPT.json", row)
            # Receipt persistence is charged before another admission check.
            remaining = cfg["deadline_monotonic"] - time.monotonic()
            if remaining <= 0:
                event["refused_after_receipt_before_endpoint"] = True
                raise TimeoutError("E_LOCAL_DEADLINE_AFTER_ENDPOINT_RECEIPT:" + endpoint)
            if endpoint == "/completion":
                row["generation_endpoint_attempted"] = True
                event["completion_admission_pending"] = False
            try:
                result = super().request(endpoint, payload, timeout=min(timeout, remaining))
                if endpoint == "/completion":
                    row["completion_received"] = True
                event["returned"] = True
                return result
            finally:
                event["wall_ns"] = time.monotonic_ns() - event["started_monotonic_ns"]

        def generate(self, *args, **kwargs):
            if cfg["mode"] != "generate":
                raise ValueError("E_LOCAL_PROBE_CANNOT_GENERATE")
            return super().generate(*args, **kwargs)

    try:
        if cfg["deadline_monotonic"] <= time.monotonic():
            raise TimeoutError("E_LOCAL_DEADLINE_BEFORE_ENGINE")
        os.environ["LLAMA_ARG_REPACK"] = "0"
        runtime = cfg["runtime"]
        cold_started = time.monotonic_ns()
        engine = DeadlineEngine(binary=runtime["binary"], model=runtime["model"],
                                model_sha256=runtime["model_sha256"], output_dir=out / "engine",
                                threads=4, context=8192, json_object=False)
        row.update(cold_start_wall_ns=time.monotonic_ns() - cold_started,
                   engine_identity=identity(out / "engine/identity.json"),
                   server_pid=engine.process.pid, server_pgid=os.getpgid(engine.process.pid))
        if engine.runtime_identity != runtime["runtime_files"]:
            raise RuntimeError("E_LOCAL_RUNTIME_DIFFERS_FROM_FROZEN_FILES")
        if row["server_pgid"] != row["worker_pgid"]:
            raise RuntimeError("E_LOCAL_SERVER_ESCAPED_OWNED_GROUP")
        messages = [{"role": "user", "content": cfg["text"]}]
        if cfg["mode"] == "capacity_probe":
            rendered = engine.request("/apply-template", {"messages": messages}).get("prompt")
            if type(rendered) is not str:
                raise ValueError("E_LOCAL_TEMPLATE")
            ids = engine.tokenize(rendered, special=True)
            save(out / "CAPACITY.json", {"rendered_prompt": rendered, "input_token_ids": ids,
                                         "input_tokens": len(ids), "output_reserve": 1536,
                                         "fits": bool(ids) and len(ids) + 1536 <= 8192})
            if not ids or len(ids) + 1536 > 8192:
                raise ValueError("E_LOCAL_CONTEXT")
            row.update(status="capacity_probe_complete", input_tokens=len(ids),
                       unknown_usage=False, generation_qualified=False)
        else:
            remaining = cfg["deadline_monotonic"] - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("E_LOCAL_DEADLINE_BEFORE_GENERATE")
            answer = engine.generate(messages, limit=1536, wall_seconds=remaining)
            # Retain actual tokens and raw completion, without repair or a
            # synthetic Codex usage envelope. The parent checks the four fields.
            save(out / "GENERATION.json", answer)
            row.update(status="completed", text=answer["text"], usage=answer["usage"],
                       unknown_usage=False, generation=identity(out / "GENERATION.json"))
        row.update(generation_count=engine.generation_count, response_count=engine.response_count,
                   final_identity=engine.verify_final_identity())
        if not row["final_identity"]["model_unchanged"] or not row["final_identity"]["runtime_unchanged"]:
            raise RuntimeError("E_LOCAL_FINAL_IDENTITY")
    except Exception as error:
        row.update(status="worker_failed", error={"type": type(error).__name__, "message": str(error)})
    finally:
        if engine is not None:
            row.update(generation_count=engine.generation_count, response_count=engine.response_count)
            try:
                engine.close()
                row.update(inner_cleanup_confirmed=engine.process.poll() is not None,
                           server_returncode=engine.process.returncode,
                           socket_removed=not Path(engine.socket_path).exists())
            except Exception as error:
                row["inner_cleanup_error"] = {"type": type(error).__name__, "message": str(error)}
        row["wall_ns"] = time.monotonic_ns() - started
        save(out / "RECEIPT.json", row)
    return row


def main():
    raw = sys.stdin.buffer.read(1024**2 + 1)
    if len(raw) > 1024**2:
        raise ValueError("E_LOCAL_REQUEST_ENVELOPE_BYTES")
    row = execute(strict_json(raw))
    print(canonical({"schema": RECEIPT_SCHEMA, "status": row["status"],
                     "request_sha256": row["request_sha256"]}).decode(), flush=True)
    return 0 if row["status"] in {"completed", "capacity_probe_complete"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
