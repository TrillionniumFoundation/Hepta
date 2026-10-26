"""Owned, hash-bound, offline llama.cpp subprocess for reproducible agent trials.

The evaluator starts this process itself. No external inference service, remote
model code, generated executable commands, or implicit model download is used.
This is an execution record, not hardware attestation or a model-quality claim.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


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


def validate_completion(raw, input_ids, limit):
    """Do not report an accepted generation when the server changes the budget."""
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
    # EOS may count as a predicted token without appearing in returned text.
    predicted = raw.get("timings", {}).get("predicted_n")
    if (type(predicted) is not int or not len(raw["tokens"]) <= predicted <= len(raw["tokens"]) + 1
            or not 0 < predicted <= limit):
        raise ValueError("E_GGUF_RESPONSE: output token budget/count differs")
    return {"input_tokens": len(input_ids), "output_tokens": predicted,
            "returned_token_ids": len(raw["tokens"]), "total_tokens": len(input_ids) + predicted}


class LlamaCppEngine:
    def __init__(self, *, binary, model, model_sha256, output_dir, threads=4, context=8192):
        if type(threads) is not int or not 1 <= threads <= 64 or context != 8192:
            raise ValueError("E_GGUF_CONFIG")
        self.binary = Path(binary).resolve(strict=True)
        self.model = Path(model).resolve(strict=True)
        self.output = Path(output_dir)
        self.output.mkdir(parents=True, exist_ok=False)
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
        try:
            sock.connect(self.socket_path)
            pid, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if pid != self.process.pid or uid != os.geteuid():
                raise RuntimeError("E_GGUF_OWNER: response peer is not the owned inference process")
            connection.sock = sock
            connection.request("GET" if data is None else "POST", endpoint, body=data,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read(4 * 1024**2 + 1)
            if len(body) > 4 * 1024**2:
                raise ValueError("E_GGUF_RESPONSE: response budget exceeded")
            if response.status == 503:
                raise OSError("E_GGUF_NOT_READY")
            if response.status != 200 or self.process.poll() is not None:
                raise RuntimeError("E_GGUF_RESPONSE: owned server failed request")
            if endpoint == "/completion":
                with (self.output / ("transport-" + str(self.generation_count).zfill(3) + ".response.raw")).open("xb") as stream:
                    stream.write(body)
            return json.loads(body)
        finally:
            connection.close()
            sock.close()

    def tokenize(self, text, *, special=False):
        ids = self.request("/tokenize", {"content": text, "add_special": special,
                                         "parse_special": True}).get("tokens")
        if not valid_tokens(ids):
            raise ValueError("E_GGUF_TOKENIZER")
        return ids

    def generate(self, messages, *, limit=1024, wall_seconds=180):
        rendered = self.request("/apply-template", {"messages": messages}).get("prompt")
        if type(rendered) is not str:
            raise ValueError("E_GGUF_TEMPLATE")
        ids = self.tokenize(rendered, special=True)
        if not ids or len(ids) + limit > self.context:
            raise ValueError("E_GGUF_CONTEXT: entire prompt and response must fit")
        # Supplying exact token IDs avoids implicit BOS/template differences.
        payload = {"prompt": ids, "n_predict": limit, "temperature": 0, "seed": 0,
                   "top_k": 0, "top_p": 1, "min_p": 0, "repeat_penalty": 1,
                   "cache_prompt": False, "return_tokens": True, "stream": False,
                   "stop": [], "ignore_eos": False}
        self.generation_count += 1
        stem = "transport-" + str(self.generation_count).zfill(3)
        (self.output / (stem + ".request.json")).write_bytes(canonical({
            "messages": messages, "rendered_prompt": rendered, "payload": payload}) + b"\n")
        started = time.monotonic_ns()
        raw = self.request("/completion", payload, timeout=wall_seconds)
        self.response_count += 1
        elapsed = time.monotonic_ns() - started
        (self.output / (stem + ".response.json")).write_bytes(canonical(raw) + b"\n")
        usage = validate_completion(raw, ids, limit)
        return {"schema": "hepta.gguf-generation.v1", "status": "completed",
                "text": raw["content"], "rendered_prompt": rendered,
                "input_token_ids": ids, "output_token_ids": raw["tokens"],
                "request": payload, "response": raw, "usage": usage,
                "wall_nanoseconds": elapsed}

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
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
