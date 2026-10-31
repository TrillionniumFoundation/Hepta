"""Local-only usage and outer process ownership for the new maintenance arm."""
from __future__ import annotations

import copy
import hashlib
import math
from pathlib import Path
import sys
import time

from tools.hia_agent_codex_transport import canonical, identity, save, strict_json
from tools import qualify_hia_agent_maintenance as maintenance
from tools.provider_adapter.hia_maintenance_llama_worker import REQUEST_SCHEMA, RECEIPT_SCHEMA
from tools.provider_adapter.llama_cpp_engine import validate_completion, valid_tokens


class LocalTransportFailure(ValueError):
    pass


class LocalAdmissionRefused(LocalTransportFailure):
    def __init__(self, reason):
        super().__init__(reason)
        self.record = {"phase": "model", "owner_call_attempted": False, "reason": reason}


def checked_text(text):
    # Bound the UTF-8 encoding allocation before serializing the fixed envelope.
    if type(text) is not str or not 0 < len(text) <= 1024**2 or len(text.encode()) > 1024**2:
        raise LocalAdmissionRefused("E_LOCAL_INPUT_TEXT_BYTES")
    return text


def checked_usage(value, *, input_limit=6656, output_limit=1536):
    fields = {"input_tokens", "output_tokens", "returned_token_ids", "total_tokens"}
    if (type(value) is not dict or set(value) != fields
            or any(type(v) is not int or v < 0 for v in value.values())
            or not 0 < value["input_tokens"] <= input_limit
            or not 0 < value["output_tokens"] <= output_limit
            or not value["returned_token_ids"] <= value["output_tokens"] <= value["returned_token_ids"] + 1
            or value["total_tokens"] != value["input_tokens"] + value["output_tokens"]):
        raise LocalTransportFailure("E_LOCAL_USAGE")
    return copy.deepcopy(value)


def read_receipt(folder, request):
    path = Path(folder) / "payload/RECEIPT.json"
    if not path.is_file():
        return None
    value = _bounded_json(path, 1024**2)
    if (type(value) is not dict or value.get("schema") != RECEIPT_SCHEMA
            or value.get("mode") != request["mode"]
            or value.get("request_sha256") != hashlib.sha256(canonical(request)).hexdigest()
            or value.get("protocol_sha256") != request["protocol_sha256"]
            or value.get("text_sha256") != hashlib.sha256(request["text"].encode()).hexdigest()):
        raise LocalTransportFailure("E_LOCAL_RECEIPT_BINDING")
    if value.get("usage") is not None:
        value["usage"] = checked_usage(value["usage"])
    return value


def _bounded_read(path, limit=8 * 1024**2):
    if type(limit) is not int or not 0 < limit <= 8 * 1024**2:
        raise LocalTransportFailure("E_LOCAL_READ_LIMIT")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise LocalTransportFailure("E_LOCAL_EVIDENCE_SIZE")
    return raw


def _bounded_json(path, limit=8 * 1024**2):
    return strict_json(_bounded_read(path, limit))


def bound_generation(folder, request):
    """Recover a persisted completion even if final worker metadata was interrupted."""
    payload = Path(folder) / "payload"
    generation = payload / "GENERATION.json"
    if not generation.is_file():
        return None
    generation_bytes = _bounded_read(generation)
    actual = strict_json(generation_bytes)
    native_request = _bounded_json(payload / "engine/transport-001.request.json")
    native_response = _bounded_json(payload / "engine/transport-001.response.raw")
    runtime = _bounded_json(payload / "engine/identity.json")
    ids = actual.get("input_token_ids")
    if (actual.get("schema") != "hepta.gguf-generation.v1" or actual.get("status") != "completed"
            or not valid_tokens(ids) or not 0 < len(ids) <= 6656
            or native_request.get("messages") != [{"role": "user", "content": request["text"]}]
            or native_request.get("rendered_prompt") != actual.get("rendered_prompt")
            or native_request.get("payload") != actual.get("request")
            or native_request.get("payload", {}).get("prompt") != ids
            or native_request.get("payload", {}).get("n_predict") != 1536
            or native_request.get("payload", {}).get("temperature") != 0
            or native_request.get("payload", {}).get("seed") != 0
            or native_request.get("payload", {}).get("cache_prompt") is not False
            or actual.get("response") != native_response
            or actual.get("text") != native_response.get("content")
            or actual.get("output_token_ids") != native_response.get("tokens")
            or runtime.get("model", {}).get("sha256") != request["runtime"]["model_sha256"]
            or runtime.get("runtime_files") != request["runtime"]["runtime_files"]
            or runtime.get("context") != 8192 or runtime.get("threads") != 4
            or runtime.get("decoder") != {"mode": "unconstrained"}):
        raise LocalTransportFailure("E_LOCAL_GENERATION_BINDING")
    observed = checked_usage(validate_completion(native_response, ids, 1536, json_object=False))
    if observed != actual.get("usage"):
        raise LocalTransportFailure("E_LOCAL_GENERATION_USAGE_DRIFT")
    return {"usage": observed, "text": actual["text"],
            "generation": {"path": str(generation.resolve()), "bytes": len(generation_bytes),
                           "sha256": hashlib.sha256(generation_bytes).hexdigest()},
            "generation_endpoint_attempted": True, "completion_received": True}


def observed_prefix(folder, request):
    """Missing/in-progress metadata is unknown, never a false no-request claim."""
    result = {"worker": None, "usage": None, "generation_endpoint_attempted": None,
              "completion_received": None, "generation_count": None, "response_count": None,
              "observability": "unknown", "validation_errors": []}
    try:
        reply = read_receipt(folder, request)
        result["worker"] = reply
        if reply is not None:
            result["usage"] = reply.get("usage")
        if reply is not None and reply.get("status") in {"completed", "worker_failed", "capacity_probe_complete"}:
            for key in ("generation_endpoint_attempted", "completion_received"):
                if type(reply.get(key)) is bool:
                    result[key] = reply[key]
            for key in ("generation_count", "response_count"):
                if type(reply.get(key)) is int and reply[key] >= 0:
                    result[key] = reply[key]
            result["observability"] = "bound_terminal_worker_receipt"
    except Exception as error:
        result["validation_errors"].append({"type": type(error).__name__, "message": str(error)})
    try:
        completion = bound_generation(folder, request)
        if completion is not None:
            result.update(usage=completion["usage"], generation_endpoint_attempted=True, completion_received=True,
                          generation_count=1, response_count=1, observability="bound_generation_artifacts")
    except Exception as error:
        result["validation_errors"].append({"type": type(error).__name__, "message": str(error)})
    return result


def invoke(text, folder, cfg, *, deadline, mode="generate", owned=None):
    """Charge cold initialization and destruction inside each owned request."""
    if mode not in {"generate", "capacity_probe"}:
        raise LocalTransportFailure("E_LOCAL_MODE")
    if type(deadline) not in (float, int) or not math.isfinite(deadline):
        raise LocalTransportFailure("E_LOCAL_DEADLINE")
    owned = maintenance.checked_owned if owned is None else owned
    request_deadline = min(deadline, time.monotonic() + cfg["max_request_wall_seconds"])
    maintenance.admitted_wall_seconds("model", cfg["max_request_wall_seconds"], request_deadline)
    checked_text(text)
    folder = Path(folder)
    request = {"schema": REQUEST_SCHEMA, "mode": mode, "text": text,
               "runtime": cfg["runtime"], "context": 8192, "output_limit": 1536, "threads": 4,
               "deadline_monotonic": request_deadline, "evidence_dir": str((folder / "payload").resolve()),
               "protocol_sha256": cfg["protocol_sha256"]}
    encoded = canonical(request)
    if len(encoded) > 1024**2:
        raise LocalAdmissionRefused("E_LOCAL_REQUEST_ENVELOPE_BYTES")
    request = strict_json(encoded)
    folder.mkdir(parents=True, exist_ok=False)
    save(folder / "REQUEST.json", request)
    argv = [cfg["python"], str(maintenance.ROOT / "tools/provider_adapter/hia_maintenance_llama_worker.py")]
    process = owned("model", argv, maintenance.ROOT, folder / "transport", input_bytes=encoded,
                    wall_seconds=cfg["max_request_wall_seconds"], deadline=request_deadline)
    if not maintenance.cleanup_confirmed(process):
        raise maintenance.CleanupUncertain("model", process, folder / "transport", process.get("wall_ns", 0))
    # Once cleanup is confirmed, later receipt/usage failures must preserve
    # that fact. Only this cell fails; an unknown group still raises above.
    prefix = observed_prefix(folder, request)
    result = {"process": process, "worker": prefix["worker"], "request": request,
              "usage": prefix["usage"], "observed_prefix": prefix, "qualified": False, "mode": mode}
    try:
        reply = read_receipt(folder, request)
        expected = "completed" if mode == "generate" else "capacity_probe_complete"
        if process["status"] != "exited" or reply is None or reply.get("status") != expected:
            return result
        if (reply.get("worker_pid") != process.get("pid") or reply.get("worker_pgid") != process.get("pgid")
                or reply.get("server_pgid") != process.get("pgid")
                or reply.get("inner_cleanup_confirmed") is not True or reply.get("socket_removed") is not True
                or reply.get("final_identity", {}).get("model_unchanged") is not True
                or reply.get("final_identity", {}).get("runtime_unchanged") is not True):
            raise LocalTransportFailure("E_LOCAL_OWNER_OR_FINAL_IDENTITY")
        if mode == "capacity_probe":
            if (type(reply.get("generation_count")) is not int or type(reply.get("response_count")) is not int
                    or reply.get("generation_count") != 0 or reply.get("response_count") != 0
                    or reply.get("generation_endpoint_attempted") is not False or reply.get("usage") is not None):
                raise LocalTransportFailure("E_LOCAL_PROBE_GENERATED")
            capacity = _bounded_json(folder / "payload/CAPACITY.json")
            ids = capacity.get("input_token_ids")
            text = request["text"][:-1] if request["text"].endswith("\n") else request["text"]
            if (not valid_tokens(ids) or not 0 < len(ids) <= 6656
                    or capacity.get("input_tokens") != len(ids) or reply.get("input_tokens") != len(ids)
                    or capacity.get("output_reserve") != 1536 or capacity.get("fits") is not True
                    or type(capacity.get("rendered_prompt")) is not str or text not in capacity["rendered_prompt"]):
                raise LocalTransportFailure("E_LOCAL_PROBE_CAPACITY_BINDING")
        else:
            if (type(reply.get("generation_count")) is not int or type(reply.get("response_count")) is not int
                    or reply.get("generation_count") != 1 or reply.get("response_count") != 1
                    or reply.get("generation_endpoint_attempted") is not True
                    or reply.get("completion_received") is not True or type(reply.get("text")) is not str
                    or reply.get("unknown_usage") is not False or reply.get("usage") is None):
                raise LocalTransportFailure("E_LOCAL_INCOMPLETE_COMPLETION")
            actual = bound_generation(folder, request)
            if (actual is None or actual["generation"] != reply.get("generation")
                    or actual["text"] != reply["text"] or actual["usage"] != reply["usage"]):
                raise LocalTransportFailure("E_LOCAL_GENERATION_CONTENT")
        result["qualified"] = True
    except Exception as error:
        result["validation_error"] = {"type": type(error).__name__, "message": str(error)}
    return result
