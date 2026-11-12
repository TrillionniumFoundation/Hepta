"""Bounded original NDU at each search node, with exact independent readback.

The adapter performs scalar recursive utility and native feasible Pareto
selection. Belief updates, transition probabilities and conditional-risk
aggregation belong to the caller's explicit model. This is not a learned FBSDE.
A digest binds input bytes; it does not authenticate an external observation.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import time

from hepta.hia_native_differential import _pin_native_artifact

Q32 = 1 << 32
LIMIT = 1_000_000 * Q32
MAX_FRAME = 65536
MAX_REQUESTS = 1_000_000
UPSTREAM = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d"

class ValueBackendError(ValueError):
    pass

def _require(ok, reason):
    if not ok:
        raise ValueBackendError("NDU search value: " + reason)

def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def _read(raw):
    _require(type(raw) is bytes and len(raw) <= MAX_FRAME, "frame byte limit")
    def pairs(items):
        result = {}
        for k, v in items:
            _require(k not in result, "duplicate JSON key")
            result[k] = v
        return result
    def bad(value):
        raise ValueBackendError("non-finite JSON: " + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)

def _hash_ok(value):
    return (type(value) is str and len(value) == 64 and value != "0" * 64
            and set(value) <= set("0123456789abcdef"))

def _integer(value, lo, hi, label):
    _require(type(value) is int and lo <= value <= hi, label)
    return value

def q32_product(a, b):
    """Independent exact signed nearest-ties-even product, no floating point."""
    _integer(a, -(1 << 63), (1 << 63) - 1, "Q32 multiplier")
    _integer(b, -(1 << 63), (1 << 63) - 1, "Q32 multiplicand")
    n = a * b
    sign = -1 if n < 0 else 1
    q, r = divmod(abs(n), Q32)
    q += int(2 * r > Q32 or 2 * r == Q32 and q % 2 == 1)
    result = sign * q
    _integer(result, -(1 << 63), (1 << 63) - 1, "Q32 product overflow")
    return result

def normalize_candidates(candidates):
    _require(type(candidates) is list and 1 <= len(candidates) <= 32, "candidate count")
    rows, names = [], set()
    allowed = {"id", "instant_q32", "terminal_q32", "discount_q32", "feasible", "resource_q32", "risk_q32"}
    required = {"id", "instant_q32", "terminal_q32", "discount_q32"}
    for original in candidates:
        _require(type(original) is dict and required <= set(original) <= allowed, "candidate fields")
        row = {"feasible": True, "resource_q32": 0, "risk_q32": 0, **original}
        name = row["id"]
        _require(type(name) is str and 1 <= len(name) <= 64
                 and set(name) <= set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
                 and name not in names, "candidate identity")
        names.add(name)
        for key in ("instant_q32", "terminal_q32"):
            _integer(row[key], -LIMIT, LIMIT, key)
        _integer(row["discount_q32"], 0, Q32, "discount")
        _integer(row["resource_q32"], 0, LIMIT, "resource")
        _integer(row["risk_q32"], 0, Q32, "risk")
        _require(type(row["feasible"]) is bool, "feasible")
        value = row["instant_q32"] + q32_product(row["discount_q32"], row["terminal_q32"])
        _integer(value, -LIMIT, LIMIT, "utility clipping prohibited")
        rows.append(row)
    return rows

def independent_values(candidates, *, resource_budget_q32=LIMIT, risk_ceiling_q32=Q32):
    """Reference for differential testing only; no production action selection."""
    rows = normalize_candidates(candidates)
    _integer(resource_budget_q32, 0, LIMIT, "resource budget")
    _integer(risk_ceiling_q32, 0, Q32, "risk ceiling")
    values = {r["id"]: r["instant_q32"] + q32_product(r["discount_q32"], r["terminal_q32"]) for r in rows}
    eligible = {r["id"]: r["feasible"] and r["resource_q32"] <= resource_budget_q32
                and r["risk_q32"] <= risk_ceiling_q32 for r in rows}
    best = max((values[k] for k in values if eligible[k]), default=None)
    winners = sorted(k for k in values if eligible[k] and values[k] == best)
    return {"values_q32": values, "eligible": eligible, "winners": winners,
            "chosen_id": winners[0] if winners else None}

class NativeValueBackend:
    """One caller-owned sealed process. A malformed/timed-out exchange closes it.

    The returned values and native winners must drive search backups. Reference
    evaluation below verifies them but never substitutes an alternate answer.
    Raw framing, admission, parsing, validation and logging costs are measured.
    """
    def __init__(self, executable, manifest, *, log, timeout=10.0):
        started = time.perf_counter_ns()
        _require(type(timeout) in (int, float) and 0 < timeout <= 60, "timeout")
        self.timeout, self.calls, self.closed, self.failed = timeout, 0, False, False
        self.process, self.fd, self.log, self.err = None, None, None, None
        self.buffer = b""
        self.startup_ns = self.close_ns = self.total_call_ns = 0
        self.returncode = None
        try:
            self.log = Path(log).open("x", encoding="utf-8")
            self.err = tempfile.TemporaryFile()
            data = Path(manifest).read_bytes()
            _require(len(data) <= 1_048_576, "manifest bound")
            report = json.loads(data)
            _require(report.get("schema") == "hepta.hia.ndu-build.v1"
                     and report.get("upstream", {}).get("commit") == UPSTREAM
                     and report.get("original_rust_sources_unchanged") is True
                     and report.get("all_original_non_manifest_inputs_unchanged") is True
                     and report.get("build_inputs_unchanged") is True, "original-source receipt")
            adapter = Path(__file__).resolve().parents[2] / "rust/hia-ndu-value"
            inventory = {str(p.relative_to(adapter)): sha256(p.read_bytes()).hexdigest()
                         for p in sorted(adapter.rglob("*")) if p.is_file()}
            _require(report.get("adapter_files") == inventory, "adapter source binding")
            image, _, self.fd = _pin_native_artifact(Path(executable))
            self.binary_sha256 = sha256(image).hexdigest()
            _require(self.binary_sha256 == report.get("binary_sha256"), "binary identity")
            self.process = subprocess.Popen(["/proc/self/fd/" + str(self.fd), "--value-stream"],
                pass_fds=(self.fd,), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err, bufsize=0)
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
            raw = self._readline(time.monotonic() + timeout)
            self.hello = _read(raw)
            expected_identity = {"profile": "hepta.hia.ndu.value.v1", "upstream_commit": UPSTREAM,
                "maximum_candidates": 32, "maximum_requests": MAX_REQUESTS, "maximum_frame_bytes": MAX_FRAME,
                "scalar_recurrence": "instant + ties_even(discount * continuation / 2^32)",
                "unsafe_code": "forbidden", "authority": "DENY_ALL"}
            _require(self.hello == {"schema": "hepta.hia.ndu.value.hello.v1", "identity": expected_identity,
                                    "authority": "DENY_ALL", "safety_certificate": False}, "protocol identity")
            self.startup_ns = time.perf_counter_ns() - started
            self._record({"event": "hello", "raw_response": raw.decode(), "response_sha256": sha256(raw).hexdigest(),
                          "binary_sha256": self.binary_sha256, "manifest_sha256": sha256(data).hexdigest(),
                          "startup_ns": self.startup_ns})
        except Exception:
            self.failed = True
            self.close()
            raise

    def _record(self, record):
        if self.log is not None:
            self.log.write(_wire(record).decode() + "\n")
            self.log.flush()

    def _readline(self, deadline):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b"\n" not in self.buffer:
                remaining = deadline - time.monotonic()
                _require(remaining > 0 and selector.select(remaining), "response timeout")
                part = os.read(self.process.stdout.fileno(), MAX_FRAME + 1)
                _require(bool(part), "unexpected EOF")
                self.buffer += part
                _require(len(self.buffer) <= MAX_FRAME + 1, "response bound")
        raw, self.buffer = self.buffer.split(b"\n", 1)
        _require(not self.buffer, "unsolicited or extra native frame")
        return raw

    def _send(self, raw, deadline):
        offset = 0
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdin, selectors.EVENT_WRITE)
            while offset < len(raw):
                remaining = deadline - time.monotonic()
                _require(remaining > 0 and selector.select(remaining), "request timeout")
                try:
                    offset += os.write(self.process.stdin.fileno(), raw[offset:])
                except BlockingIOError:
                    continue

    def evaluate(self, candidates, state_digest, preference_digest, *, objective_digest=None,
                 generation=1, resource_budget_q32=LIMIT, risk_ceiling_q32=Q32):
        started = time.perf_counter_ns()
        try:
            _require(not self.closed and self.calls < MAX_REQUESTS, "closed or exhausted session")
            _require(_hash_ok(state_digest) and _hash_ok(preference_digest), "state/preference identity")
            objective_digest = objective_digest or sha256(b"hia.closed-loop.frozen-external-objective.v1").hexdigest()
            _require(_hash_ok(objective_digest), "objective identity")
            _integer(generation, 1, (1 << 32) - 1, "generation")
            _integer(resource_budget_q32, 0, LIMIT, "resource budget")
            _integer(risk_ceiling_q32, 0, Q32, "risk ceiling")
            rows = normalize_candidates(candidates)
            request = {"schema": "hepta.hia.ndu.value.request.v1", "sequence": self.calls + 1,
                "generation": generation, "state_digest": state_digest, "preference_digest": preference_digest,
                "objective_digest": objective_digest, "resource_budget_q32": resource_budget_q32,
                "risk_ceiling_q32": risk_ceiling_q32, "candidates": rows}
            payload = _wire(request)
            _require(len(payload) <= MAX_FRAME, "request bound")
            deadline = time.monotonic() + self.timeout
            exchange_start = time.perf_counter_ns()
            self._send(payload + b"\n", deadline)
            raw = self._readline(deadline)
            roundtrip = time.perf_counter_ns() - exchange_start
            self.calls += 1
            self._record({"event": "exchange", "sequence": self.calls, "request": payload.decode(),
                          "response": raw.decode(), "request_sha256": sha256(payload).hexdigest(),
                          "response_sha256": sha256(raw).hexdigest(), "wire_roundtrip_ns": roundtrip})
            response = _read(raw)
            _require(response.get("schema") == "hepta.hia.ndu.value.response.v1", "native refusal or response schema")
            for k in ("sequence", "generation", "state_digest", "preference_digest", "objective_digest"):
                _require(type(response.get(k)) is type(request[k]) and response[k] == request[k], "response " + k)
            _require(response.get("request_sha256") == sha256(payload).hexdigest()
                     and response.get("upstream_commit") == UPSTREAM, "request/native binding")
            _require(response.get("authority") == "DENY_ALL" and response.get("safety_certificate") is False
                     and response.get("execution_authorized") is False, "authority")
            _require(response.get("entry_points") == ["codex_hepta_ndu::evaluate_recursive_utility",
                     "codex_hepta_ndu::evaluate_candidates_with_policy"] and _hash_ok(response.get("evaluation_digest")), "native provenance")
            expected = independent_values(rows, resource_budget_q32=resource_budget_q32, risk_ceiling_q32=risk_ceiling_q32)
            for k, v in expected.items():
                _require(_wire(response.get(k)) == _wire(v), "independent scalar differential " + k)
            _require(type(response.get("projection_count")) is int and response["projection_count"] == 0, "projection")
            _integer(response.get("native_evaluation_ns"), 0, 60_000_000_000, "native clock")
            paths = response.get("path_receipts")
            _require(type(paths) is list and len(paths) == len(rows) and [r.get("id") for r in paths] == [r["id"] for r in rows]
                     and all(_hash_ok(r.get("recursive_evidence_digest")) for r in paths), "recursive receipt inventory")
            rejected = response.get("rejected")
            _require(type(rejected) is list and sorted(r.get("id") for r in rejected) == sorted(k for k,v in expected["eligible"].items() if not v), "rejected candidate inventory")
            response["values"] = response["values_q32"]
            response["native"] = True
            response["outer_call_ns"] = time.perf_counter_ns() - started
            self.total_call_ns += response["outer_call_ns"]
            self._record({"event": "validated", "sequence": self.calls, "outer_call_ns": response["outer_call_ns"],
                          "values_q32": response["values_q32"], "winners": response["winners"]})
            return response
        except Exception as error:
            self.failed = True
            self._record({"event": "failed", "sequence": self.calls, "error": f"{type(error).__name__}: {error}",
                          "attempt_wall_ns": time.perf_counter_ns() - started})
            self.close()
            raise

    def close(self):
        if self.closed:
            return self.close_ns
        started = time.perf_counter_ns()
        self.closed = True
        killed = False
        if self.process is not None:
            if self.process.stdin is not None:
                try:
                    self.process.stdin.close()
                except OSError:
                    pass
            try:
                self.process.wait(timeout=min(self.timeout, 5))
            except subprocess.TimeoutExpired:
                killed = True
                self.process.kill()
                self.process.wait(timeout=5)
            self.returncode = self.process.returncode
            if self.process.stdout is not None:
                self.process.stdout.close()
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        stderr = b""
        if self.err is not None:
            self.err.seek(0)
            stderr = self.err.read(MAX_FRAME + 1)
            self.err.close()
            self.err = None
        self.close_ns = time.perf_counter_ns() - started
        self._record({"event": "close", "calls": self.calls, "returncode": self.returncode,
            "killed": killed, "stderr": stderr.decode("utf-8", "replace"), "stderr_over_bound": len(stderr)>MAX_FRAME,
            "close_ns": self.close_ns, "total_call_ns": self.total_call_ns,
            "reaped": self.process is None or self.process.poll() is not None})
        if self.log is not None:
            self.log.close()
            self.log = None
        _require(self.failed or self.process is None or self.returncode == 0 and not killed and len(stderr) <= MAX_FRAME,
                 "unclean session exit")
        return self.close_ns

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.failed = self.failed or typ is not None
        self.close()
        return False
