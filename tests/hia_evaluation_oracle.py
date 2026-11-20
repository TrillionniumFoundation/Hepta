"""Independent foreign effects for the frozen 19065 evaluation body.

The original Python method determines expected results and operation order.
No expected port, branch, or state is imported from the replacement machine.
These bounded fixtures do not establish whole-program equivalence.
"""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch


ORIGINAL_METHOD_SHA256 = "ebd52766eb862629cefa2d1a985d727b1926c284970cc4fb3fff8c2400818801"
ORIGINAL_VALUE_SHA256 = "5c5129af1f1c696fa6d1530d4a393764b60f6e1857e3304f0443440731c8150d"


def reference_method(path, service_module, value_path=None):
    raw = Path(path).read_bytes()
    if sha256(raw).hexdigest() != ORIGINAL_METHOD_SHA256:
        raise AssertionError("frozen original evaluation method changed")
    namespace = dict(vars(service_module))
    value_path = Path(value_path) if value_path is not None else Path(path).with_name("hia_evaluation_value_19065.py.txt")
    value_raw = value_path.read_bytes()
    if sha256(value_raw).hexdigest() != ORIGINAL_VALUE_SHA256:
        raise AssertionError("frozen original value observation helper changed")
    exec(compile(value_raw, str(value_path), "exec"), namespace)
    exec(compile(raw, str(path), "exec"), namespace)
    return namespace["_hia_evaluate"]


def returned(value=7, *, resources=None, buffers=None):
    result = {"status": "returned", "values": [value],
              "ledger": {"resources": {} if resources is None else resources}}
    if buffers is not None:
        result["buffers"] = buffers
    return result


def trapped(code="TEST_TRAP", *, buffers=None):
    result = {"status": "trapped", "trap_code": code,
              "ledger": {"resources": {}}}
    if buffers is not None:
        result["buffers"] = buffers
    return result


@dataclass
class Scenario:
    name: str
    baseline_bytes: bytes = b"B" * 32
    candidate_bytes: bytes = b"C" * 16
    metric: str = "artifact_bytes"
    minimum_ratio: object = 0
    cases: list = field(default_factory=lambda: [{"function": "transform", "arguments": [0]}])
    reference_rows: dict = field(default_factory=lambda: {
        "baseline": [returned()], "candidate": [returned()]})
    reference_results: dict = field(default_factory=dict)
    native_results: dict = field(default_factory=dict)
    metadata_changes: dict = field(default_factory=dict)
    context_changes: dict = field(default_factory=dict)
    workload_changes: dict = field(default_factory=dict)
    failure: tuple | None = None
    wall_schedule: tuple = ()
    monotonic_schedule: tuple = ()


def deep_update(target, changes):
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            deep_update(target[key], value)
        else:
            target[key] = deepcopy(value)


class Program:
    def __init__(self, world, label):
        self.world, self.label = world, label

    @property
    def sha256(self):
        self.world.record("program_sha256", self.label)
        return ("a" if self.label == "baseline" else "b") * 64


def frozen(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, Program):
        return {"program": value.label}
    if isinstance(value, dict):
        return {key: frozen(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [frozen(item) for item in value]
    if callable(value):
        return {"callable": value.__name__}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError("unrecorded fixture value: " + type(value).__qualname__)


class World:
    """An observable host, independent of either evaluator's control graph."""

    def __init__(self, scenario, service_module):
        self.spec, self.api = deepcopy(scenario), service_module
        self.trace, self.published, self.counters = [], [], Counter()
        self.native_calls, self.completed = 0, False
        self.monotonic_calls, self.wall_calls = 0, 0
        self.metadata = {}
        self.programs = {label: Program(self, label) for label in ("baseline", "candidate")}
        ref = lambda name: {"id": name, "sha256": sha256(name.encode()).hexdigest()}
        self.args = {"context": ref("context"), "baseline_artifact": ref("baseline"),
                     "candidate_artifact": ref("candidate"), "build_receipt": ref("build"),
                     "verification_receipts": [ref("verification")], "request_key": "fixture-evaluation"}
        self.context = {"ref": self.args["context"], "baseline_core_sha256": "a" * 64,
                        "workload": ref("workload"), "objective": ref("objective"),
                        "budget": {"max_total_wall_ms": 60000, "max_native_wall_ms": 1000,
                                   "max_memory_bytes": "67108864"}}
        deep_update(self.context, self.spec.context_changes)
        self.workload = {"schema": "hepta.hia.agent.workload.v1", "cases": self.spec.cases,
                         "warmup_iterations": 2, "repetitions": 3}
        deep_update(self.workload, self.spec.workload_changes)
        self.objective = {"metric": self.spec.metric, "min_improvement_ratio": self.spec.minimum_ratio}
        self.service = object.__new__(service_module.HIAAgentService)
        self.service.identities = {"fixture_installation": "19065-original"}
        self.service.store = self
        self.db = self
        self.execution_budgets = self
        self.service._context = self.lookup_context
        for name in ("native", "build_receipt", "required_claims", "cost_ledger"):
            setattr(self.service, "_" + name, getattr(self, name))

    def record(self, effect, *args, **kwargs):
        self.counters[effect] += 1
        self.trace.append({"effect": effect, "args": frozen(args), "kwargs": frozen(kwargs)})
        if self.spec.failure is not None:
            name, occurrence, kind = self.spec.failure
            if effect == name and self.counters[effect] == occurrence:
                errors = {"ValueError": ValueError, "KeyboardInterrupt": KeyboardInterrupt,
                          "RuntimeError": RuntimeError, "OSError": OSError}
                raise errors[kind]("fixture failure at " + effect + ":" + str(occurrence))

    def monotonic_ns(self):
        index = self.monotonic_calls
        self.monotonic_calls += 1
        value = (self.spec.monotonic_schedule[index] if index < len(self.spec.monotonic_schedule)
                 else self.monotonic_calls * 1000)
        self.record("monotonic_ns", value)
        return value

    def time_ns(self):
        index = self.wall_calls
        self.wall_calls += 1
        value = (self.spec.wall_schedule[index] if index < len(self.spec.wall_schedule)
                 else 1_000_000_000 + self.wall_calls * 1_000_000)
        self.record("time_ns", value)
        return value

    def lookup_context(self, reference):
        self.record("context", reference)
        assert reference is self.args["context"], "context reference was copied"
        return self.context

    def native(self, reference, context):
        self.record("native", reference, context)
        assert context is self.args["context"], "native context reference was copied"
        label = "baseline" if reference is self.args["baseline_artifact"] else "candidate"
        assert reference is self.args[label + "_artifact"], "artifact reference was copied"
        metadata = {"output_kind": "shared", "signatures": {
            "transform": {"params": ["u8"], "returns": ["u8"]}}}
        deep_update(metadata, self.spec.metadata_changes.get(label, {}))
        self.metadata[label] = metadata
        return getattr(self.spec, label + "_bytes"), metadata, self.programs[label]

    def build_receipt(self, receipt, context, candidate):
        self.record("build_receipt", receipt, context, candidate)
        assert receipt is self.args["build_receipt"] and context is self.args["context"]
        assert candidate is self.args["candidate_artifact"]
        return object()  # Validation has an effect even though the value is unused.

    def required_claims(self, context, candidate, receipts, baseline_sha):
        self.record("required_claims", context, candidate, receipts, baseline_sha)
        assert context is self.context and candidate is self.args["candidate_artifact"]
        assert receipts is self.args["verification_receipts"]
        return self.objective

    def get_json(self, reference):
        self.record("get_json", reference)
        assert reference is self.context["workload"]
        return self.workload, {"fixture": "workload-metadata"}

    def execute(self, statement, parameters):
        self.record("execute", statement, parameters)
        assert statement == "SELECT created_ns FROM contexts WHERE id=?"
        assert parameters == (self.args["context"]["id"],)
        return self

    def fetchone(self):
        self.record("fetchone")
        return {"created_ns": "1000000000"}

    def run_reference_batch(self, program, cases, **kwargs):
        self.record("run_reference_batch", program, cases, **kwargs)
        assert program is self.programs[program.label]
        assert cases is self.workload["cases"], "reference cases were copied"
        if program.label in self.spec.reference_results:
            return deepcopy(self.spec.reference_results[program.label])
        return {"status": "returned", "report": {"complete": True,
                "observations": deepcopy(self.spec.reference_rows[program.label])}}

    def run_native_batch(self, *args, **kwargs):
        raise AssertionError("native runner escaped the execution budget claim")

    def claim(self, context_id, owner, allowance, started):
        self.record("claim", context_id, owner, allowance, started)
        return self

    def run(self, function, data, signatures, cases, **kwargs):
        assert function.__self__ is self and function.__func__ is World.run_native_batch
        labels = [label for label, metadata in self.metadata.items() if signatures is metadata["signatures"]]
        assert len(labels) == 1, "native signatures were copied or replaced"
        label, = labels
        assert data is getattr(self.spec, label + "_bytes"), "native image object changed"
        category = "traps" if len(cases) == 1 and cases[0]["expected"]["status"] == "trapped" else "normal"
        self.native_calls += 1
        self.record("budget_run", label, category, function, data, signatures, cases, **kwargs)
        key = (label, category)
        if key in self.spec.native_results:
            value = self.spec.native_results[key]
            if isinstance(value, list):
                count = self.counters["result:" + label + ":" + category]
                self.counters["result:" + label + ":" + category] += 1
                value = value[count]
            return deepcopy(value)
        if category == "traps":
            outcome = {"status": "trapped", "returncode": -6, "report": None}
            if "buffers" in cases[0]["expected"]:
                outcome["buffer_snapshots"] = [{"buffers": deepcopy(cases[0]["expected"]["buffers"])}]
            return outcome
        return {"status": "returned", "returncode": 0, "report": {
            "completed_cases": len(cases), "total_native_ns": "100" if label == "baseline" else "50",
            "observations": [{**deepcopy(case["expected"]), "mismatch": False} for case in cases]}}

    def complete(self):
        self.record("complete")
        self.completed = True

    @property
    def native_ns(self):
        self.record("native_ns")
        return self.native_calls * 100

    def json(self, value, kind):
        self.record("json", value, kind)
        self.published.append({"kind": kind, "value": deepcopy(value)})
        return {"id": "published-" + str(len(self.published)), "kind": kind,
                "sha256": sha256(kind.encode()).hexdigest()}

    def cost_ledger(self, context, wall, native_wall):
        self.record("cost_ledger", context, wall, native_wall)
        assert context is self.context
        return {"schema": "fixture-cost-ledger", "wall": wall, "native_wall": native_wall,
                "published_prefix": len(self.published), "full_search_cost_complete": False}

    def providers(self):
        from hepta import hia_agent_runner
        stack = ExitStack()
        stack.enter_context(patch.object(self.api.time, "monotonic_ns", self.monotonic_ns))
        stack.enter_context(patch.object(self.api.time, "time_ns", self.time_ns))
        stack.enter_context(patch.object(hia_agent_runner, "run_reference_batch", self.run_reference_batch))
        stack.enter_context(patch.object(hia_agent_runner, "run_native_batch", self.run_native_batch))
        return stack

    def observe(self, invoke):
        with self.providers():
            try:
                result = invoke(self.service, self.args)
            except BaseException as error:
                outcome = {"status": "raised", "type": type(error).__module__ + "." + type(error).__qualname__,
                           "args": frozen(error.args), "code": getattr(error, "code", None),
                           "phase": getattr(error, "phase", None)}
            else:
                outcome = {"status": "returned", "result": frozen(result)}
        return {"outcome": outcome, "trace": self.trace, "published": frozen(self.published),
                "claim_completed": self.completed, "native_calls": self.native_calls}
