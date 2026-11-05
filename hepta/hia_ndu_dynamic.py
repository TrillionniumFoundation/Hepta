"""Finite native cache experiment: bounded model intake and independent replay.

This module supplies no HIA compiler, program proof, or production activation.
The planner process cannot issue workload commands. A caller independently
checks source identity, model witnesses, actual quota and actual data epochs.
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

from .hia_native_differential import _pin_native_artifact
from .hia_ndu import Q32, candidate, event

UPSTREAM = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d"
MODEL_SCHEMA = "hepta.hia.ndu.dynamic-cache.model.v1"
REQUEST_SCHEMA = "hepta.hia.ndu.dynamic-cache.request.v1"
RESPONSE_SCHEMA = "hepta.hia.ndu.dynamic-cache.response.v1"
REFUSAL_SCHEMA = "hepta.hia.ndu.dynamic-cache.refusal.v1"
MAX_NS = 1_000_000_000_000
MAX_BYTES = 1_048_576
MODES = ("light", "exact_dp", "beam", "beam_ndu")

class DynamicError(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise DynamicError("dynamic-cache v1: " + reason)

def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

def digest(value):
    return sha256(wire(value)).hexdigest()

def read_json(data):
    require(type(data) is bytes and len(data) <= MAX_BYTES, "JSON byte bound")
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def constant(_):
        raise DynamicError("non-finite JSON value")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)

def integer(value, label, ceiling=MAX_NS):
    require(type(value) is int and 0 <= value <= ceiling, label)
    return value

def fields(value, expected, label):
    names = set(expected.split())
    # Bound the mapping before iterating/copying it. Exact string keys avoid
    # executing caller-defined Python equality/hash methods at this boundary.
    require(type(value) is dict and len(value) == len(names), label + " field count")
    require(all(type(key) is str for key in value) and set(value) == names, label + " fields")

def hash_ok(value):
    return type(value) is str and len(value) == 64 and set(value) <= set("0123456789abcdef") and value != "0" * 64

def validate_model(raw):
    fields(raw, "schema generation objective_digest observation_digest workload_sha256 artifacts targets direct_ns packed_ns ready_mask ready_epochs memory_quota_bytes budget_ns sunk_cost_ns completion_value_ns decision session_ready", "model")
    require(type(raw["schema"]) is str and raw["schema"] == MODEL_SCHEMA, "model schema")
    require(all(hash_ok(raw[k]) for k in ("objective_digest", "observation_digest", "workload_sha256")), "model identities")
    require(type(raw["artifacts"]) is list and 1 <= len(raw["artifacts"]) <= 8, "artifact count")
    require(type(raw["targets"]) is list and 1 <= len(raw["targets"]) <= 12, "lookahead bound")
    n, h = len(raw["artifacts"]), len(raw["targets"])
    require(type(raw["session_ready"]) is bool, "session flag")
    integer(raw["generation"], "generation", (1 << 32) - 1)
    require(raw["generation"] > 0, "generation must be nonzero")
    for key in ("ready_epochs", "direct_ns", "packed_ns"):
        require(type(raw[key]) is list and len(raw[key]) == (n if key == "ready_epochs" else h), key + " shape")
        for item in raw[key]:
            integer(item, key, (1 << 32) - 1 if key == "ready_epochs" else MAX_NS)
    for target in raw["targets"]:
        integer(target, "target", n - 1)
    integer(raw["ready_mask"], "ready mask", (1 << n) - 1)
    integer(raw["memory_quota_bytes"], "memory quota", 128 * 1024 * 1024)
    for key in ("budget_ns", "sunk_cost_ns", "completion_value_ns"):
        integer(raw[key], key)
    names = set()
    for index, a in enumerate(raw["artifacts"]):
        fields(a, "id resident_bytes prepare_ns retire_ns epochs", "artifact")
        name = a["id"]
        require(type(name) is str and 1 <= len(name) <= 32 and name not in names
                and set(name) <= set("abcdefghijklmnopqrstuvwxyz0123456789-"), "artifact name")
        names.add(name)
        integer(a["resident_bytes"], "resident bytes", 128 * 1024 * 1024)
        require(a["resident_bytes"] > 0, "zero-sized artifact")
        integer(a["prepare_ns"], "preparation cost")
        integer(a["retire_ns"], "retirement cost")
        require(type(a["epochs"]) is list and len(a["epochs"]) == h, "epoch shape")
        for epoch in a["epochs"]:
            integer(epoch, "epoch", (1 << 32) - 1)
            require(epoch > 0, "zero epoch")
        require(a["epochs"] == sorted(a["epochs"]) and raw["ready_epochs"][index] <= a["epochs"][0], "nonmonotonic data epoch")
        require(bool(raw["ready_mask"] & (1 << index)) == bool(raw["ready_epochs"][index]), "resident epoch consistency")
    require(resident_bytes(raw, raw["ready_mask"]) <= raw["memory_quota_bytes"], "initial resident quota")
    fields(raw["decision"], "gate_ns solve_ns transport_validation_ns startup_ns close_ns", "decision")
    for value in raw["decision"].values():
        integer(value, "decision cost")
    envelope = max(raw["direct_ns"] + raw["packed_ns"]) + sum(raw["decision"].values())
    envelope += sum(a["prepare_ns"] + a["retire_ns"] for a in raw["artifacts"])
    require(envelope * (h + 1) <= MAX_NS, "whole horizon cost envelope")
    payload = wire(raw)
    require(len(payload) <= 65536, "bounded model wire")
    return read_json(payload)

def resident_bytes(model, mask):
    return sum(a["resident_bytes"] for i, a in enumerate(model["artifacts"]) if mask & (1 << i))

def live_mask(model, batch, ready):
    result = ready
    for i, a in enumerate(model["artifacts"]):
        previous = model["ready_epochs"][i] if batch == 0 else a["epochs"][batch - 1]
        if previous != a["epochs"][batch]:
            result &= ~(1 << i)
    return result

def call_cost(model, ready):
    d = model["decision"]
    return d["solve_ns"] + d["transport_validation_ns"] + (0 if ready else d["startup_ns"])

def action(model, batch, ready, target):
    integer(target, "target resident mask", (1 << len(model["artifacts"])) - 1)
    require(resident_bytes(model, target) <= model["memory_quota_bytes"], "selected resident quota")
    live = live_mask(model, batch, ready)
    acquired, retired = target & ~live, ready & (~target | ~live)
    packed = bool(target & (1 << model["targets"][batch])) and model["packed_ns"][batch] < model["direct_ns"][batch]
    result = {"batch": batch, "mode": "skip" if target == live else "invoke", "ready_before": ready,
        "ready_after": target, "invalidated": ready & ~live, "acquired": acquired, "retired": retired,
        "dispatch": "packed" if packed else "direct",
        "execution_ns": model["packed_ns"][batch] if packed else model["direct_ns"][batch],
        "prepare_ns": sum(a["prepare_ns"] for i, a in enumerate(model["artifacts"]) if acquired & (1 << i)),
        "retire_ns": sum(a["retire_ns"] for i, a in enumerate(model["artifacts"]) if retired & (1 << i)),
        "future_decision_ns": call_cost(model, True) if batch > 0 and target != live else 0,
        "gate_ns": model["decision"]["gate_ns"]}
    result["total_ns"] = sum(result[k] for k in ("execution_ns", "prepare_ns", "retire_ns", "future_decision_ns", "gate_ns"))
    return result

def preparation_relaxed_lower_bound(model):
    """Cost lower bound retaining preparation and announced epoch boundaries.

    Relax the shared quota, retirements and future decision costs. In each
    artifact/epoch segment, retaining a valid resident artifact is free; for
    an absent artifact, preparation can recover at most the sum of announced
    direct-to-packed savings. Every feasible original schedule maps into
    this relaxed schedule with no larger cost. This is an arithmetic bound
    for the supplied forecast model, not a wall-time or program-safety proof.
    """
    lower = sum(model["direct_ns"]) + len(model["targets"]) * model["decision"]["gate_ns"]
    for index, artifact in enumerate(model["artifacts"]):
        # The initial cache is useful only when its data version still matches.
        resident = bool(model["ready_mask"] & (1 << index))
        resident = resident and model["ready_epochs"][index] == artifact["epochs"][0]
        epoch = artifact["epochs"][0]
        savings = 0
        for batch, current_epoch in enumerate(artifact["epochs"]):
            if current_epoch != epoch:
                lower -= savings if resident else max(0, savings - artifact["prepare_ns"])
                resident, epoch, savings = False, current_epoch, 0
            if model["targets"][batch] == index:
                savings += max(0, model["direct_ns"][batch] - model["packed_ns"][batch])
        lower -= savings if resident else max(0, savings - artifact["prepare_ns"])
    return lower

def invocation_gate(model):
    """No search or native launch. Supplied optimistic bound, not a deadline proof."""
    ready = model["ready_mask"]
    incumbent = 0
    for batch in range(len(model["targets"])):
        step = action(model, batch, ready, live_mask(model, batch, ready))
        incumbent += step["total_ns"]
        ready = step["ready_after"]
    free_preparation = sum(min(a, b) for a, b in zip(model["direct_ns"], model["packed_ns"]))
    free_preparation += len(model["targets"]) * model["decision"]["gate_ns"]
    lower = preparation_relaxed_lower_bound(model)
    call = call_cost(model, model["session_ready"])
    reserved_close = model["decision"]["close_ns"]
    worthwhile = incumbent - lower > call + (0 if model["session_ready"] else reserved_close)
    affordable = lower + call + reserved_close <= model["budget_ns"]
    return {"invoke": worthwhile and affordable, "incumbent_ns": incumbent,
        "optimistic_execution_lower_ns": lower, "call_estimate_ns": call,
        "free_preparation_lower_ns": free_preparation,
        "lower_bound_kind": "independent-artifact-epoch-preparation-relaxation-v1",
        "gross_saving_upper_ns": incumbent - lower, "budget_affordable": affordable,
        "scope": "supplied deterministic model; may overestimate benefit", "authority": "DENY_ALL"}

def validate_response(model, mode, payload, response):
    """Replay supplied feasibility/cost witnesses, not search completeness.

    `search_complete` is an assertion of the pinned native implementation.
    Qualification separately checks every actual exact-DP minimum using a
    charged independent bottom-up implementation; it is not on this hot path.
    """
    fields(response, "schema mode request_sha256 model_sha256 generation upstream_commit bundle pareto_candidate_ids selected_first_action ndu_evaluation search search_ns construction_ns evaluation_ns service_before_output_ns authority safety_certificate execution_authorized global_program_optimality hia_compiler_qualification", "response")
    require(type(response["schema"]) is str and response["schema"] == RESPONSE_SCHEMA, "response schema")
    fields(response["search"], "states transitions beam_pruned materialized_actions", "search counters")
    for value in response["search"].values():
        integer(value, "search counter")
    for key in ("search_ns", "construction_ns", "evaluation_ns", "service_before_output_ns"):
        integer(response[key], key)
    for key, value in (("mode", mode), ("request_sha256", sha256(payload).hexdigest()),
                       ("model_sha256", digest(model)), ("generation", model["generation"]),
                       ("upstream_commit", UPSTREAM), ("authority", "DENY_ALL")):
        require(type(response.get(key)) is type(value) and response[key] == value, "response " + key)
    require(all(response.get(k) is False for k in ("safety_certificate", "execution_authorized", "global_program_optimality", "hia_compiler_qualification")), "response authority")
    native = response.get("ndu_evaluation")
    require((mode != "beam_ndu" and native is None) or (mode == "beam_ndu" and type(native) is dict
        and native.get("entry_points") == ["codex_hepta_ndu::evaluate_recursive_utility", "codex_hepta_ndu::evaluate_candidates_with_policy"]
        and native.get("authority") == "DENY_ALL" and native.get("safety_certificate") is False), "native provenance")
    bundle = response.get("bundle")
    fields(bundle, "request plans support search_complete authority safety_certificate", "bundle")
    require(bundle["authority"] == "DENY_ALL" and bundle["safety_certificate"] is False
            and bundle["search_complete"] is (mode == "exact_dp"), "bundle claims")
    plans = bundle["plans"]
    require(type(plans) is dict and len(plans) <= (4 if mode in ("beam", "beam_ndu") else 1), "plan count")
    common = call_cost(model, model["session_ready"]) + model["decision"]["close_ns"]
    for identity, plan in plans.items():
        require(type(identity) is str, "plan identity type")
        fields(plan, "actions current_committed_ns close_ns total_ns", "plan")
        require(identity == "dynamic-" + digest(plan)[:24], "plan identity")
        require(type(plan["actions"]) is list and len(plan["actions"]) == len(model["targets"]), "complete witness horizon")
        ready, total = model["ready_mask"], common
        for batch, step in enumerate(plan["actions"]):
            require(type(step) is dict and "ready_after" in step, "step structure")
            expected = action(model, batch, ready, step["ready_after"])
            require(wire(step) == wire(expected), "invalid resource or transition witness")
            total += expected["total_ns"]
            ready = expected["ready_after"]
        require(type(plan["total_ns"]) is int and plan["total_ns"] == total <= model["budget_ns"]
            and type(plan["current_committed_ns"]) is int and plan["current_committed_ns"] == call_cost(model, model["session_ready"])
            and type(plan["close_ns"]) is int and plan["close_ns"] == model["decision"]["close_ns"], "complete cost or budget")
    support = {"model": model, "plans": plans, "search_complete": mode == "exact_dp",
        "scope": "supplied finite cache model; forecast times; no program safety or elapsed-time theorem",
        "authority": "DENY_ALL", "safety_certificate": False}
    require(wire(bundle["support"]) == wire(support), "support identity")
    support_hash = digest(support)
    verification = digest([model["workload_sha256"], model["observation_digest"]])
    candidates, values = [], {}
    for identity in [*sorted(plans), "abstain"]:
        abstain = identity == "abstain"
        variable = 0 if abstain else plans[identity]["total_ns"] - common
        terminal = 0 if abstain else model["completion_value_ns"] * Q32 // 1_000_000
        instant = -(variable * Q32 // 1_000_000)
        candidates.append(candidate(candidate_id=identity, verified=True,
            verification_digest=digest("literal-no-delivery") if abstain else verification,
            support_digest=support_hash, events=[event(identity=identity + support_hash,
                instant_q32=instant, preference_digest=model["objective_digest"])],
            terminal_q32=terminal, resource_cost_q32=variable * Q32 // 1000))
        values[identity] = terminal + instant
    expected_request = {"schema": "hepta.hia.ndu.request.v1", "objective_digest": model["objective_digest"],
        "snapshot_digest": digest(model), "generation": model["generation"],
        "utility_unit": "completion-minus-wall-milliseconds", "resource_unit": "microseconds", "risk_unit": "probability",
        "risk_ceiling_q32": Q32, "resource_budget_q32": max(0, model["budget_ns"] - common) * Q32 // 1000,
        "candidates": candidates}
    require(wire(bundle["request"]) == wire(expected_request), "inner native request")
    winners = sorted(k for k, v in values.items() if v == max(values.values()))
    require(response.get("pareto_candidate_ids") == winners, "candidate winners")
    selected = None
    if winners and "abstain" not in winners:
        first = [plans[name]["actions"][0] for name in winners]
        if len({(a["ready_after"], a["dispatch"]) for a in first}) == 1:
            selected = first[0]
    require("selected_first_action" in response and wire(response["selected_first_action"]) == wire(selected), "action projection")
    return response

class JsonProcess:
    """Two permanently separate roles over a byte-bound sealed native image."""
    def __init__(self, executable, manifest, *, role, log, timeout=30.0):
        started = time.monotonic_ns()
        require(role in ("--planner-stream", "--workload-stream"), "process role")
        self.role, self.timeout, self.calls, self.closed = role, timeout, 0, False
        require(type(timeout) in (int, float) and 0 < timeout <= 120, "process timeout")
        self.buffer = b""
        self.process = None
        self.fd = None
        self.err = tempfile.TemporaryFile()
        self.log = Path(log).open("x", encoding="utf-8")
        try:
            report = read_json(Path(manifest).read_bytes())
            require(report.get("schema") == "hepta.hia.ndu-build.v1"
                and report.get("upstream", {}).get("commit") == UPSTREAM
                and report.get("original_rust_sources_unchanged") is True
                and report.get("all_original_non_manifest_inputs_unchanged") is True, "build source binding")
            adapter = Path(__file__).resolve().parents[1] / "rust/hia-ndu-dynamic-model"
            inventory = {str(p.relative_to(adapter)): sha256(p.read_bytes()).hexdigest()
                         for p in sorted(adapter.rglob("*")) if p.is_file()}
            require(report.get("adapter_files") == inventory, "dynamic adapter source binding")
            image, _, self.fd = _pin_native_artifact(Path(executable))
            require(sha256(image).hexdigest() == report.get("binary_sha256"), "sealed binary identity")
            self.binary_sha256 = report["binary_sha256"]
            self.process = subprocess.Popen(["/proc/self/fd/" + str(self.fd), role], pass_fds=(self.fd,),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err)
            self.hello = read_json(self._readline())
            require(self.hello == {"schema": "hepta.hia.ndu.dynamic-cache.hello.v1", "role": role,
                "upstream_commit": UPSTREAM, "max_frame_bytes": MAX_BYTES, "max_requests": 4096,
                "authority": "DENY_ALL", "safety_certificate": False}, "role or protocol hello")
            self.startup_ns = time.monotonic_ns() - started
            self._record({"event": "hello", "response": self.hello, "startup_ns": self.startup_ns,
                "binary_sha256": self.binary_sha256})
        except BaseException:
            self.close()
            raise

    def _record(self, row):
        self.log.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        self.log.flush()

    def _readline(self):
        deadline = time.monotonic() + self.timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b"\n" not in self.buffer:
                remaining = deadline - time.monotonic()
                require(remaining > 0 and selector.select(remaining), "native response timeout")
                part = os.read(self.process.stdout.fileno(), 65536)
                require(bool(part), "native stream closed")
                self.buffer += part
                require(len(self.buffer) <= MAX_BYTES + 1, "native output bound")
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line

    def ask(self, value):
        require(not self.closed and self.calls < 4096, "closed or exhausted stream")
        started = time.monotonic_ns()
        payload = wire(value)
        require(len(payload) <= MAX_BYTES, "native input bound")
        self.process.stdin.write(payload + b"\n")
        self.process.stdin.flush()
        raw = self._readline()
        response = read_json(raw)
        self.calls += 1
        record = {"event": "exchange", "index": self.calls, "request": payload.decode(),
            "response": raw.decode(), "request_sha256": sha256(payload).hexdigest(),
            "response_sha256": sha256(raw).hexdigest(), "wire_roundtrip_ns": time.monotonic_ns() - started}
        self._record(record)
        return response, record

    def evaluate(self, raw, mode):
        started = time.monotonic_ns()
        require(self.role == "--planner-stream" and mode in MODES, "planning role or mode")
        model = validate_model(raw)
        request = {"schema": REQUEST_SCHEMA, "mode": mode, "model": model}
        payload = wire(request)
        response, record = self.ask(request)
        validated = time.monotonic_ns()
        validate_response(model, mode, payload, response)
        record["validation_ns"] = time.monotonic_ns() - validated
        record["outer_call_ns"] = time.monotonic_ns() - started
        return response, record

    def close(self):
        started = time.monotonic_ns()
        if self.closed:
            return 0
        self.closed = True
        if self.process is not None:
            if self.process.stdin is not None:
                try:
                    self.process.stdin.close()
                except OSError:
                    pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.returncode = self.process.returncode
            if self.process.stdout is not None:
                self.process.stdout.close()
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.err.seek(0)
        stderr = self.err.read(65537)
        self.err.close()
        try:
            self._record({"event": "close", "returncode": getattr(self, "returncode", None),
                "stderr": stderr.decode("utf-8", "replace"), "stderr_over_bound": len(stderr) > 65536,
                "calls": self.calls, "reaped": self.process is None or self.process.poll() is not None})
        finally:
            self.log.close()
        self.close_ns = time.monotonic_ns() - started
        return self.close_ns
