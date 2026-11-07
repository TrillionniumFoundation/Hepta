"""Replayable qualification client for the HIA Agent tool contract.

The client contains no compiler, optimizer, machine encoder or native loader. It
can use the in-process worker API for domain tests, or an actual hepta-runtime
stdio MCP endpoint for transport qualification. The scripted scenarios are
integration tests; they are not a claim that an unseen model learned HIA, nor a
measurement of model training exposure or end-to-end optimization economics.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Callable

if __package__:
    from .hia_agent_native_transport import MCPStdio, QualificationFailure
else:
    from hia_agent_native_transport import MCPStdio, QualificationFailure


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "docs" / "HIA_AGENT_NATIVE_TOOL_CATALOG.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def add_program(*, optimized=False, increment=7, typ="u8", module="agent_qualification",
                redundant_additions=0):
    """A small independently specified wrapping function for runtime tests."""
    params = [{"name": "x", "type": typ}]

    def const(name, value):
        return {"op": "const", "args": [], "out": [{"name": name, "type": typ}],
                "attrs": {"value": value}}

    def add(left, right, name):
        return {"op": "int.add.wrap", "args": [left, right],
                "out": [{"name": name, "type": typ}], "attrs": {}}

    if optimized:
        operations = [const("increment", increment)]
    else:
        operations = [const("left", increment - 1), const("right", 1),
                      add("left", "right", "increment")]
    operations.append(add("x", "increment", "initial_answer" if redundant_additions else "answer"))
    if redundant_additions:
        operations.append(const("zero", 0))
        previous = "initial_answer"
        for index in range(redundant_additions):
            following = "answer" if index + 1 == redundant_additions else f"same_value_{index}"
            operations.append(add(previous, "zero", following))
            previous = following
    return {"schema": "hepta.hia.program.v1", "module": module, "functions": [{
        "name": "transform", "params": params, "returns": [typ], "effects": [],
        "entry": "entry", "blocks": [{"id": "entry", "params": params,
            "ops": operations, "term": {"op": "ret", "values": ["answer"]}}]}]}


def branch_program():
    """Two distinct branch targets make a block-layout plan observable."""
    params = [{"name": "choose", "type": "bool"}]
    return {"schema": "hepta.hia.program.v1", "module": "agent_layout", "functions": [{
        "name": "select_value", "params": params, "returns": ["u8"], "effects": [],
        "entry": "entry", "blocks": [
            {"id": "entry", "params": params, "ops": [], "term": {
                "op": "branch", "cond": "choose", "then": {"target": "yes", "args": []},
                "else": {"target": "no", "args": []}}},
            {"id": "yes", "params": [], "ops": [{"op": "const", "args": [],
                "out": [{"name": "yes_value", "type": "u8"}], "attrs": {"value": 19}}],
                "term": {"op": "ret", "values": ["yes_value"]}},
            {"id": "no", "params": [], "ops": [{"op": "const", "args": [],
                "out": [{"name": "no_value", "type": "u8"}], "attrs": {"value": 83}}],
                "term": {"op": "ret", "values": ["no_value"]}},
        ]}]}


def exhaustive_u8_workload(increment=7):
    return {"schema": "hepta.hia.agent.workload.v1", "cases": [
        {"function": "transform", "arguments": [x],
         "expected": {"status": "returned", "values": [(x + increment) & 255]}}
        for x in range(256)], "warmup_iterations": 0, "repetitions": 1}


class ToolClient:
    """Record and schema-check the exact application request and response."""

    def __init__(self, call: Callable, *, catalog_path=CATALOG_PATH, validate=True):
        self._call = call
        self.catalog = json.loads(Path(catalog_path).read_bytes())
        self.tools = {tool["name"]: tool for tool in self.catalog["tools"]}
        self.records = []
        self.validate = validate

    def call(self, tool, arguments, *, expected_status="completed"):
        request = deepcopy(arguments)
        if self.validate:
            from jsonschema import Draft202012Validator
            Draft202012Validator(self.tools[tool]["inputSchema"]).validate(request)
        started = time.monotonic_ns()
        response = self._call(tool, request)
        elapsed = time.monotonic_ns() - started
        self.records.append({"tool": tool, "arguments": request,
                             "response": deepcopy(response), "elapsed_ns": str(elapsed)})
        if self.validate:
            Draft202012Validator(self.tools[tool]["outputSchema"]).validate(response)
        if expected_status is not None and response["status"] != expected_status:
            raise QualificationFailure(f"{tool}: expected {expected_status}, got "
                                       + json.dumps(response, ensure_ascii=False))
        return response

    def result(self, tool, arguments):
        return self.call(tool, arguments)["result"]




class Session:
    """Tool-only conveniences: no local compiler or artifact store access."""

    def __init__(self, client, *, prefix="qualification"):
        self.client = client
        self.prefix = prefix
        self.sequence = 0
        self.discovery = client.result("hia_describe", {"section": "manifest"})
        self.catalog_sha256 = self.discovery["catalog_sha256"]
        self.manifest = self.read_json(self.discovery["manifest"])
        self.profiles = self.manifest["profiles"]
        self.context = None

    def key(self, label):
        self.sequence += 1
        return f"{self.prefix}/{self.sequence}/{label}"

    def arguments(self, *, mutable=True, context=True, **fields):
        args = {"catalog_sha256": self.catalog_sha256}
        if mutable:
            args["request_key"] = self.key("call")
        if context:
            args["context"] = self.context
        args.update(fields)
        return args

    def read(self, artifact, *, max_bytes=65536):
        output = bytearray()
        cursor = None
        while True:
            args = {"catalog_sha256": self.catalog_sha256, "artifact": artifact,
                    "max_bytes": max_bytes}
            if cursor is not None:
                args["cursor"] = cursor
            page = self.client.result("hia_read", args)
            if page["artifact"] != artifact:
                raise QualificationFailure("artifact page identity changed")
            output.extend(page["content"].encode("utf-8") if page["encoding"] == "utf8"
                          else base64.b64decode(page["content"], validate=True))
            cursor = page["next_cursor"]
            if cursor is None:
                break
            if len(output) > 8 * 1024 * 1024:
                raise QualificationFailure("artifact read exceeded declared maximum")
        if sha256(output).hexdigest() != artifact["sha256"]:
            raise QualificationFailure("artifact pages do not match the issued digest")
        return bytes(output)

    def read_json(self, artifact):
        return json.loads(self.read(artifact))

    def artifact(self, content):
        text = content if isinstance(content, str) else json_bytes(content).decode("utf-8")
        return self.client.result("hia_artifact", self.arguments(context=False,
            artifact_profile=self.profiles["artifact"],
            source={"kind": "utf8", "text": text}))["artifact"]

    def freeze(self, workload, *, baseline=None, objective=None, budget=None):
        if objective is None:
            objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
                "required_claims": ["core_admission", "encoding_check"],
                "allow_unchanged": True, "min_improvement_ratio": 0.0}
        cost = {"schema": "hepta.hia.agent.cost-policy.v1", "external_costs": {
            "model_tokens": None, "model_wall_ns": None, "discovery_wall_ns": None},
            "external_costs_complete": False, "expected_invocations": "0"}
        limits = {"max_candidates": 128, "max_model_tokens": 0,
            "max_total_wall_ms": 600000, "max_native_wall_ms": 10000,
            "max_memory_bytes": "536870912", "cost_policy": self.artifact(cost)}
        if budget:
            limits.update(budget)
        result = self.client.result("hia_context", self.arguments(context=False,
            compiler_profile=self.profiles["compiler"], target_profile=self.profiles["target"],
            baseline_program=baseline, workload=self.artifact(workload),
            objective=self.artifact(objective), budget=limits))
        self.context = result["context"]
        return result

    def import_program(self, document, *, format="core-json"):
        source = self.artifact(document)
        return self.client.result("hia_candidate", self.arguments(change={
            "kind": "import", "format": format, "source": source}))["candidate"]

    @property
    def backend(self):
        return self.discovery["backend_profiles"][0]

    def verify(self, candidate, *, base=None, subject=None, claims=None):
        if subject is None:
            subject = {"kind": "core"}
        if claims is None:
            claims = ["core_admission"]
        return self.client.result("hia_verify", self.arguments(candidate=candidate,
            base_program=base, validation_profile=self.profiles["validation"],
            subject=subject, claims=claims))

    def emit(self, candidate, *, receipts=(), codegen=None, kind="shared"):
        if codegen is None:
            codegen = {"kind": "canonical", "lowering_profile": self.profiles["lowering"]}
        return self.client.result("hia_emit", self.arguments(candidate=candidate,
            backend_profile=self.backend, output_kind=kind, codegen=codegen,
            verification_receipts=list(receipts)))

    def encoding(self, candidate, build):
        return self.verify(candidate, subject={"kind": "native_artifact",
            "backend_profile": self.backend, "native_artifact": build["native_artifact"],
            "build_receipt": build["build_receipt"]}, claims=["encoding_check"])

    def evaluate(self, baseline, candidate, *, receipts):
        return self.client.result("hia_evaluate", self.arguments(
            baseline_artifact=baseline["native_artifact"],
            candidate_artifact=candidate["native_artifact"],
            build_receipt=candidate["build_receipt"], verification_receipts=list(receipts)))


def scripted_loop(session):
    """Exercise the 11 tools on an explicit client-selected Core simplification."""
    objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
        "required_claims": ["core_admission", "behavior_equivalence", "encoding_check"],
        "allow_unchanged": True, "min_improvement_ratio": 0.0}
    session.freeze(exhaustive_u8_workload())
    # GNU ld's page layout can keep the full shared-file size unchanged when a
    # few instructions disappear. This explicit synthetic redundancy crosses a
    # page boundary, so the selected artifact_bytes metric measures real file
    # savings instead of silently substituting instruction/text size.
    baseline = session.import_program(add_program(redundant_additions=128))
    session.freeze(exhaustive_u8_workload(), baseline=baseline, objective=objective)
    candidate = session.import_program(add_program(optimized=True))
    view = session.client.result("hia_inspect", session.arguments(mutable=False,
        program=baseline, view="summary"))
    session.read_json(view["view_artifact"])
    baseline_check = session.verify(baseline)
    candidate_check = session.verify(candidate, base=baseline,
        claims=["core_admission", "behavior_equivalence"])
    if any(check["status"] != "proved" for check in candidate_check["checks"]):
        raise QualificationFailure("the complete scalar-u8 transformation domain was not proved")
    baseline_build = session.emit(baseline, receipts=[baseline_check["verification_receipt"]])
    candidate_build = session.emit(candidate, receipts=[candidate_check["verification_receipt"]])
    encoded = session.encoding(candidate, candidate_build)
    receipts = [candidate_check["verification_receipt"], encoded["verification_receipt"]]
    evaluation = session.evaluate(baseline_build, candidate_build, receipts=receipts)
    if not evaluation["planned_workload_complete"]:
        raise QualificationFailure("full u8 workload did not complete")
    if evaluation["outcome"] != "improved":
        raise QualificationFailure("explicit redundant arithmetic removal did not reduce artifact size")
    adoption = session.client.result("hia_adopt", session.arguments(target_slot="qualification",
        expected_current={"generation": "0", "epoch": "0"},
        candidate_artifact=candidate_build["native_artifact"],
        evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))
    stale = session.client.call("hia_adopt", session.arguments(target_slot="qualification",
        expected_current={"generation": "0", "epoch": "0"},
        candidate_artifact=candidate_build["native_artifact"],
        evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts),
        expected_status="rejected")
    rollback = session.client.result("hia_rollback", session.arguments(target_slot="qualification",
        expected_current=adoption["current"], retained_generation=adoption["previous"]["generation"],
        reason="qualification restores retained baseline"))
    return {"baseline": baseline, "candidate": candidate, "baseline_build": baseline_build,
        "candidate_build": candidate_build, "evaluation": evaluation,
        "adoption": adoption, "stale_adoption": stale, "rollback": rollback,
        "measurements": session.read_json(evaluation["measurements"]),
        "full_cost_ledger": session.read_json(evaluation["full_cost_ledger"])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mcp-command-json", help="Administrator-provided JSON argv for actual runtime")
    parser.add_argument("--cwd", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    started = time.monotonic_ns()
    transport = None
    temporary = None
    try:
        if args.mcp_command_json:
            command = json.loads(args.mcp_command_json)
            if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
                parser.error("--mcp-command-json must be a nonempty JSON array of argv strings")
            transport = MCPStdio(command, cwd=args.cwd)
            listing = transport.list_tools()
            client = ToolClient(transport.call)
            mode = "actual_hepta_runtime_stdio_mcp"
            names = {tool["name"] for tool in listing}
            if not set(client.tools) <= names:
                raise QualificationFailure("runtime tools/list is missing HIA tools")
        else:
            from hepta.hia_agent_service import HIAAgentService
            if args.state_root is None:
                temporary = tempfile.TemporaryDirectory(prefix="hia-agent-qualification-")
                args.state_root = Path(temporary.name)
            service = HIAAgentService(args.state_root)
            client = ToolClient(service.call)
            listing = []
            mode = "in_process_domain_service"
        session = Session(client)
        result = scripted_loop(session)
        report = {"schema": "hepta.hia.agent.qualification.v1", "status": "passed",
            "mode": mode, "elapsed_ns": str(time.monotonic_ns() - started),
            "tool_names_observed": sorted({record["tool"] for record in client.records}),
            "tool_call_count": len(client.records), "catalog_sha256": session.catalog_sha256,
            "tools_list": listing, "scenario": result, "calls": client.records,
            "claims": {"scripted_integration_observed": True,
                "fresh_model_learning_test_performed": False,
                "model_training_exposure_known": False,
                "universal_backend_refinement_proved": False,
                "net_optimization_benefit_proved": False}}
        if transport:
            report["mcp_initialize"] = transport.initialized
            report["mcp_protocol_records"] = transport.protocol_records
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        print(json.dumps({"status": "passed", "mode": mode,
                          "calls": len(client.records), "output": str(args.output)}))
    finally:
        if transport:
            transport.close()
        if temporary:
            temporary.cleanup()


if __name__ == "__main__":
    main()
