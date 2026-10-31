"""Owned, hash-bound, offline llama.cpp subprocess for reproducible agent trials.

The evaluator starts this process itself. No external inference service, remote
model code, generated executable commands, or implicit model download is used.
This is an execution record, not hardware attestation or a model-quality claim.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time


def resource_observation():
    """Best-effort shared-host observations, never per-process OOM attribution."""
    files = ("memory.current", "memory.max", "memory.peak", "memory.events", "cpu.stat", "cpu.max")
    values = {}
    for name in files:
        try:
            values[name] = (Path("/sys/fs/cgroup") / name).read_text()[:16384]
        except OSError as error:
            values[name] = {"unavailable": type(error).__name__}
    return {"observed_unix_ns": time.time_ns(), "cgroup": values,
            "scope": "Shared cgroup counters; a delta does not identify which process caused an event."}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def file_identity(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError("E_GGUF_FILE: ordinary file required")
    with path.open("rb") as stream:
        return {"path": str(path), "bytes": path.stat().st_size,
                "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


def valid_tokens(value):
    return type(value) is list and all(type(x) is int and 0 <= x < 2**31 for x in value)


def validate_completion(raw, input_ids, limit, *, json_object=False):
    """Do not report an accepted generation when the server changes the budget."""
    if type(json_object) is not bool:
        raise ValueError("E_GGUF_CONFIG: json_object must be an explicit bool")
    if (type(raw) is not dict or type(raw.get("content")) is not str
            or not valid_tokens(raw.get("tokens")) or raw.get("truncated") is not False
            or raw.get("stop_type") not in {"eos", "limit"}
            or type(raw.get("tokens_evaluated")) is not int
            or raw["tokens_evaluated"] != len(input_ids)):
        raise ValueError("E_GGUF_RESPONSE: missing or inconsistent generation record")
    settings = raw.get("generation_settings", {})
    sampling = settings.get("params", settings)
    if sampling.get("temperature") != 0 or sampling.get("seed") != 0:
        raise ValueError("E_GGUF_RESPONSE: actual greedy settings differ")
    if json_object and (type(sampling.get("grammar")) is not str
                        or not sampling["grammar"].strip()
                        or sampling.get("grammar_lazy") is not False):
        raise ValueError("E_GGUF_RESPONSE: JSON object grammar was not active for every token")
    # A budget-limited partial JSON object is a completed inference, not a
    # transport failure. Candidate parsing belongs to the study/evaluator.
    # EOS may count as a predicted token without appearing in returned text.
    predicted = raw.get("timings", {}).get("predicted_n")
    if (type(predicted) is not int or not len(raw["tokens"]) <= predicted <= len(raw["tokens"]) + 1
            or not 0 < predicted <= limit):
        raise ValueError("E_GGUF_RESPONSE: output token budget/count differs")
    return {"input_tokens": len(input_ids), "output_tokens": predicted,
            "returned_token_ids": len(raw["tokens"]), "total_tokens": len(input_ids) + predicted}


class LlamaCppEngine:
    def __init__(self, *, binary, model, model_sha256, output_dir, threads=4, context=8192,
                 json_object=False):
        if (type(threads) is not int or not 1 <= threads <= 64 or context != 8192
                or type(json_object) is not bool):
            raise ValueError("E_GGUF_CONFIG")
        self.json_object = json_object
        self.binary = Path(binary).resolve(strict=True)
        self.model = Path(model).resolve(strict=True)
        self.output = Path(output_dir)
        self.output.mkdir(parents=True, exist_ok=False)
        self.lifecycle_started_ns = time.monotonic_ns()
        self.resources_before = resource_observation()
        self.closed = False
        self.model_identity = file_identity(self.model)
        if self.model_identity["sha256"] != model_sha256:
            raise ValueError("E_GGUF_MODEL: model bytes differ from the frozen identity")
        self.runtime_files = sorted({self.binary, *self.binary.parent.glob("*.so*"),
                                     *self.binary.parent.glob("*.dll")})
        self.runtime_identity = [file_identity(p) for p in self.runtime_files]
        self.context, self.process = context, None
        self.generation_count = 0
        self.response_count = 0
        # A private Unix socket plus SO_PEERCRED binds every response to the
        # exact owned PID. No released ephemeral TCP-port reservation can be
        # won by a different localhost listener and mistaken for this engine.
        self.socket_directory = tempfile.TemporaryDirectory(prefix="hepta-gguf-")
        self.socket_path = str(Path(self.socket_directory.name) / "inference.sock")
        self.argv = [str(self.binary), "--model", str(self.model), "--host", self.socket_path,
                     "--ctx-size", str(context), "--parallel", "1",
                     "--threads", str(threads), "--threads-batch", str(threads),
                     "--device", "none", "--offline", "--no-webui", "--no-warmup"]
        version = subprocess.run([str(self.binary), "--version"], capture_output=True, text=True,
                                 timeout=15, check=True)
        self.identity = {"schema": "hepta.owned-gguf-runtime.v1", "argv": self.argv,
                         "model": self.model_identity, "runtime_files": self.runtime_identity,
                         "version_stdout": version.stdout, "version_stderr": version.stderr,
                         "threads": threads, "context": context,
                         "decoder": ({"mode": "json_object", "json_schema": {"type": "object"},
                                      "scope": "syntax_only_no_task_fields_or_answers"}
                                     if json_object else {"mode": "unconstrained"}),
                         "cpu_affinity": sorted(os.sched_getaffinity(0)),
                         "transport": "private_unix_socket_with_linux_so_peercred_pid_uid_check",
                         "scope": "owned process and file hashes, not remote/hardware attestation"}
        self.log = (self.output / "server.log").open("xb")
        try:
            self.process = subprocess.Popen(self.argv, stdin=subprocess.DEVNULL,
                                            stdout=self.log, stderr=self.log)
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("E_GGUF_START: server exited; see retained server.log")
                try:
                    if self.request("/health").get("status") == "ok":
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise TimeoutError("E_GGUF_START: readiness deadline")
            self.identity["pid"] = self.process.pid
            self.identity["properties"] = self.request("/props")
            (self.output / "identity.json").write_bytes(canonical(self.identity) + b"\n")
        except BaseException:
            self.close()
            raise

    def request(self, endpoint, payload=None, timeout=10):
        if endpoint not in {"/health", "/props", "/tokenize", "/apply-template", "/completion"}:
            raise ValueError("E_GGUF_ENDPOINT")
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError("E_GGUF_OWNER: owned inference process is not running")
        data = None if payload is None else canonical(payload)
        connection = http.client.HTTPConnection("localhost", timeout=timeout)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        expired = threading.Event()

        def interrupt_transport():
            # A per-read socket timeout alone permits an indefinitely dripped
            # HTTP body. Interrupt this exact owned socket at the wall limit.
            expired.set()
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(timeout, interrupt_transport)
        timer.daemon = True
        timer.start()
        try:
            sock.connect(self.socket_path)
            if expired.is_set():
                raise TimeoutError("E_GGUF_DEADLINE: owned HTTP transport wall deadline exceeded")
            pid, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if pid != self.process.pid or uid != os.geteuid():
                raise RuntimeError("E_GGUF_OWNER: response peer is not the owned inference process")
            connection.sock = sock
            connection.request("GET" if data is None else "POST", endpoint, body=data,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            try:
                body = response.read(4 * 1024**2 + 1)
                body_complete = response.length == 0 or (response.chunked and response.isclosed())
            except http.client.IncompleteRead as error:
                body, body_complete = error.partial, False
            if endpoint == "/completion":
                destination = self.output / ("transport-" + str(self.generation_count).zfill(3) + ".response.raw")
                with destination.open("xb") as stream:
                    stream.write(body)
                code = self.process.poll()
                self.last_completion_observation = {
                    "completion_sequence": self.generation_count, "body_received": bool(body),
                    "body_complete": body_complete,
                    "http_status": response.status, "body_bytes": len(body),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "owned_process_returncode": code if type(code) is int else None}
            if expired.is_set():
                raise TimeoutError("E_GGUF_DEADLINE: owned HTTP transport wall deadline exceeded")
            if len(body) > 4 * 1024**2:
                raise ValueError("E_GGUF_RESPONSE: response budget exceeded")
            if not body_complete:
                raise ValueError("E_GGUF_RESPONSE: truncated or unframed HTTP response")
            if response.status == 503:
                raise OSError("E_GGUF_NOT_READY")
            if response.status != 200 or self.process.poll() is not None:
                raise RuntimeError("E_GGUF_RESPONSE: owned server failed request")
            return json.loads(body)
        except (OSError, http.client.HTTPException) as error:
            if expired.is_set():
                raise TimeoutError("E_GGUF_DEADLINE: owned HTTP transport wall deadline exceeded") from error
            raise
        finally:
            timer.cancel()
            timer.join()
            connection.close()
            sock.close()

    def tokenize(self, text, *, special=False, timeout=10):
        ids = self.request("/tokenize", {"content": text, "add_special": special,
                                         "parse_special": True}, timeout=timeout).get("tokens")
        if not valid_tokens(ids):
            raise ValueError("E_GGUF_TOKENIZER")
        return ids

    def generate(self, messages, *, limit=1024, wall_seconds=180):
        if (type(limit) is not int or not 1 <= limit <= self.context
                or type(wall_seconds) not in {int, float} or not math.isfinite(wall_seconds)
                or wall_seconds <= 0):
            raise ValueError("E_GGUF_CONFIG: positive finite generation budget required")
        self.attempt_count = getattr(self, "attempt_count", 0) + 1
        started = time.monotonic_ns()
        deadline = time.monotonic() + wall_seconds
        receipt = {"schema": "hepta.gguf-attempt-observation.v1", "attempt": self.attempt_count,
                   "started_unix_ns": time.time_ns(), "wall_limit_seconds": wall_seconds,
                   "status": "started", "completion_requested": False, "response_received": False,
                   "input_tokens": None, "usage": None, "resources_before": resource_observation()}
        path = self.output / ("attempt-" + str(self.attempt_count).zfill(3) + ".json")
        path.write_bytes(canonical(receipt) + b"\n")

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise TimeoutError("E_GGUF_DEADLINE: entire generate wall deadline exceeded")
            return value

        try:
            result = self._generate(messages, limit, remaining, receipt)
            # A complete late response is retained and charged, but cannot pass
            # a registered wall limit. Its observed usage is still known.
            remaining()
            receipt["status"] = "completed"
            result["wall_nanoseconds"] = time.monotonic_ns() - started
            result["wall_scope"] = "template, tokenize, completion and response validation"
            return result
        except BaseException as error:
            receipt.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
            raise
        finally:
            receipt["wall_nanoseconds"] = time.monotonic_ns() - started
            receipt["resources_after"] = resource_observation()
            process = getattr(self, "process", None)
            code = process.poll() if process is not None else None
            receipt["owned_process_returncode"] = code if type(code) is int else None
            path.write_bytes(canonical(receipt) + b"\n")

    def _generate(self, messages, limit, remaining, receipt):
        rendered = self.request("/apply-template", {"messages": messages}, timeout=min(10, remaining())).get("prompt")
        if type(rendered) is not str:
            raise ValueError("E_GGUF_TEMPLATE")
        ids = self.tokenize(rendered, special=True, timeout=min(10, remaining()))
        receipt["input_tokens"] = len(ids)
        if not ids or len(ids) + limit > self.context:
            raise ValueError("E_GGUF_CONTEXT: entire prompt and response must fit")
        # Supplying exact token IDs avoids implicit BOS/template differences.
        payload = {"prompt": ids, "n_predict": limit, "temperature": 0, "seed": 0,
                   "top_k": 0, "top_p": 1, "min_p": 0, "repeat_penalty": 1,
                   "cache_prompt": False, "return_tokens": True, "stream": False,
                   "stop": [], "ignore_eos": False}
        if self.json_object:
            # b11669 server-schema.cpp converts this unconstrained object
            # schema to an output-format grammar. No task fields, allowed
            # replacements or correct answers enter the decoder.
            payload["json_schema"] = {"type": "object"}
        remaining()
        self.generation_count += 1
        receipt["completion_requested"] = True
        receipt["completion_sequence"] = self.generation_count
        stem = "transport-" + str(self.generation_count).zfill(3)
        (self.output / (stem + ".request.json")).write_bytes(canonical({
            "messages": messages, "rendered_prompt": rendered, "payload": payload}) + b"\n")
        started = time.monotonic_ns()
        self.last_completion_observation = None
        try:
            raw = self.request("/completion", payload, timeout=remaining())
        finally:
            observed = self.last_completion_observation
            if observed is not None:
                receipt["transport_observation"] = observed
                receipt["response_received"] = observed["body_complete"]
                self.response_count += int(observed["body_complete"])
        if not receipt["response_received"]:
            # Protocol fixtures and explicitly supplied transports can return
            # a complete object directly without an HTTP observation.
            self.response_count += 1
            receipt["response_received"] = True
        elapsed = time.monotonic_ns() - started
        (self.output / (stem + ".response.json")).write_bytes(canonical(raw) + b"\n")
        usage = validate_completion(raw, ids, limit, json_object=self.json_object)
        receipt["usage"] = usage
        return {"schema": "hepta.gguf-generation.v1", "status": "completed",
                "text": raw["content"], "rendered_prompt": rendered,
                "input_token_ids": ids, "output_token_ids": raw["tokens"],
                "request": payload, "response": raw, "usage": usage,
                "completion_wall_nanoseconds": elapsed}

    def close(self):
        if getattr(self, "closed", False):
            return
        started = time.monotonic_ns()
        before = self.process.poll() if self.process is not None else None
        receipt = {"schema": "hepta.gguf-process-lifecycle.v1",
                   "pid": self.process.pid if self.process is not None else None,
                   "returncode_before_close": before if type(before) is int else None,
                   "termination_requested": False, "kill_requested": False,
                   "resources_before": getattr(self, "resources_before", None)}
        try:
            if self.process is not None and before is None:
                self.process.terminate()
                receipt["termination_requested"] = True
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    receipt["kill_requested"] = True
                    self.process.wait(timeout=10)
            self.closed = True
        finally:
            code = self.process.poll() if self.process is not None else None
            receipt.update(returncode=code if type(code) is int else None,
                           reaped=type(code) is int,
                           completion_requests_started=self.generation_count,
                           completion_responses_received=self.response_count,
                           shutdown_ns=time.monotonic_ns()-started,
                           lifecycle_ns=time.monotonic_ns()-getattr(self, "lifecycle_started_ns", started),
                           resources_after=resource_observation(),
                           oom_cause_established=False)
            (self.output / "lifecycle.json").write_bytes(canonical(receipt) + b"\n")
            if getattr(self, "log", None) is not None:
                self.log.close()
            if getattr(self, "socket_directory", None) is not None:
                self.socket_directory.cleanup()

    def verify_final_identity(self):
        actual = file_identity(self.model)
        runtime = [file_identity(p) for p in self.runtime_files]
        value = {"model_unchanged": actual == self.model_identity,
                 "runtime_unchanged": runtime == self.runtime_identity,
                 "model": actual, "runtime_files": runtime}
        (self.output / "identity-after.json").write_bytes(canonical(value) + b"\n")
        return value

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
