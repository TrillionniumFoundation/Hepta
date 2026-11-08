"""Run the actual HIA compiler through the copied-byte Agent lifecycle.

This is a scripted, scoped service qualification. It neither starts a fresh
model session nor fabricates provider interaction or billing evidence. The
retained compiler source is imported through the same artifact/verification/
emission/evaluation/adoption surface; a generation lease invokes its f0 entry.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_byte_abi import byte_value, decode_bytes
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import wire
from tools.hia_agent_native_qualification import Session, ToolClient


def qualify(output, *, compiler_source=None, expected_source_sha256=None):
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    inputs = output / "inputs"
    inputs.mkdir()
    source_path = Path(compiler_source or ROOT / "examples/hia_bootstrap/selfhost.hiaasm")
    source = source_path.read_bytes()
    source_hash = sha256(source).hexdigest()
    qualifier_hash = sha256(Path(__file__).read_bytes()).hexdigest()
    if expected_source_sha256 is not None and source_hash != expected_source_sha256:
        raise ValueError("compiler source differs from the explicitly pinned input")
    (inputs / "compiler.hiaasm").write_bytes(source)
    sample = (ROOT / "examples/hia_bootstrap/bytesum.hiaasm").read_bytes()
    (inputs / "sample.hiaasm").write_bytes(sample)
    workspace = b"\0" * (1 << 20)
    cases = [
        {"function": "f0", "arguments": [byte_value(sample), byte_value(b"\xa5" * 4096), byte_value(workspace)]},
        {"function": "f0", "arguments": [byte_value(b"invalid-hia"), byte_value(b"\xa5" * 4096), byte_value(workspace)]},
        {"function": "f0", "arguments": [byte_value(sample), byte_value(b"\xa5"), byte_value(workspace)]},
    ]
    workload = {"schema": "hepta.hia.agent.workload.v2",
        "foreign_buffer_exports": [{"function": "f0", "maximum_bytes": 1 << 20}],
        "cases": cases, "warmup_iterations": 0, "repetitions": 1, "reference_max_steps": 10000000}
    (inputs / "workload.json").write_bytes(wire(workload))
    report = {"schema": "hepta.hia.agent.compiler-byte-lifecycle.v1", "status": "running",
        "qualifier_sha256": qualifier_hash,
        "compiler_source_sha256": source_hash, "sample_source_sha256": sha256(sample).hexdigest(),
        "workload_sha256": sha256(wire(workload)).hexdigest(), "checks": {},
        "scope": "scripted real compiler lifecycle plus finite generated-program consumer; no fresh Agent or general compiler proof",
        "provider_billing": None, "provider_interaction_capture": None,
        "stable_incremental_or_economic_benefit_proved": False}
    started = time.monotonic_ns()
    service = HIAAgentService(output / "state", artifact_roots=(inputs,))
    report["installation"] = service.identities
    journal_path = output / "calls.jsonl"

    def journal(record):
        with journal_path.open("ab") as stream:
            stream.write(wire(record) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    session = Session(ToolClient(service.call, journal=journal), prefix="compiler-byte-lifecycle")

    def artifact(path):
        data = path.read_bytes()
        return session.client.result("hia_artifact", session.arguments(context=False,
            artifact_profile=session.profiles["artifact"], source={"kind": "path", "path": str(path),
                "expected_sha256": sha256(data).hexdigest(), "max_bytes": len(data)}))["artifact"]

    def freeze(baseline):
        objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": ["core_admission", "behavior_equivalence", "encoding_check"],
            "allow_unchanged": True, "min_improvement_ratio": 0.0}
        policy = {"schema": "hepta.hia.agent.cost-policy.v1", "external_costs": {
            "model_tokens": None, "model_wall_ns": None, "discovery_wall_ns": None},
            "external_costs_complete": False, "expected_invocations": "0"}
        result = session.client.result("hia_context", session.arguments(context=False,
            compiler_profile=session.profiles["compiler"], target_profile=session.profiles["target"],
            baseline_program=baseline, workload=artifact(inputs / "workload.json"),
            objective=session.artifact(objective), budget={"max_candidates": 8, "max_model_tokens": 0,
                "max_total_wall_ms": 600000, "max_native_wall_ms": 30000,
                "max_memory_bytes": "536870912", "cost_policy": session.artifact(policy)}))
        session.context = result["context"]

    try:
        freeze(None)
        compiler_ref = artifact(inputs / "compiler.hiaasm")
        baseline = session.client.result("hia_candidate", session.arguments(change={
            "kind": "import", "format": "hia-asm.v1", "source": compiler_ref}))["candidate"]
        freeze(baseline)
        candidate = session.client.result("hia_candidate", session.arguments(change={
            "kind": "import", "format": "hia-asm.v1", "source": compiler_ref}))["candidate"]
        core = session.verify(candidate, base=baseline, claims=["core_admission", "behavior_equivalence"])
        built = session.emit(candidate, receipts=[core["verification_receipt"]])
        encoding = session.encoding(candidate, built)
        receipts = [core["verification_receipt"], encoding["verification_receipt"]]
        evaluation = session.evaluate(built, built, receipts=receipts)
        report.update(context=session.context, baseline=baseline, candidate=candidate, build=built,
                      verification=[core, encoding], evaluation=evaluation)
        measured = session.read_json(evaluation["measurements"])
        (output / "measurements.json").write_bytes(wire(measured))
        (output / "costs.json").write_bytes(session.read(evaluation["full_cost_ledger"]))
        report["checks"]["evaluation_complete"] = evaluation["planned_workload_complete"]
        report["checks"]["unchanged_accepted"] = evaluation["outcome"] == "unchanged"
        values = [row["candidate_vm"].get("values", [None])[0] for row in measured["observations"]]
        report["checks"]["compiler_statuses"] = bool(len(values) == 3 and type(values[0]) is int
            and 0 < values[0] <= 4096 and values[1:] == [0xffffffff, 0xfffffffe])
        if not all(report["checks"].values()):
            raise ValueError("real compiler did not satisfy the frozen finite workload")
        adopted = session.client.result("hia_adopt", session.arguments(target_slot="compiler-byte-lifecycle",
            expected_current={"generation": "0", "epoch": "0"}, candidate_artifact=built["native_artifact"],
            evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))
        report["adoption"] = adopted
        (output / "adoption.json").write_bytes(session.read(adopted["adoption_receipt"]))
        lease = service.acquire_slot("compiler-byte-lifecycle")
        try:
            consumed = service.invoke_lease(lease, "f0", cases[0]["arguments"])
        finally:
            service.release_slot(lease)
        count = consumed["values"][0]
        generated = decode_bytes(consumed["arguments"][1])[:count]
        (output / "generated.bin").write_bytes(generated)
        report["consumer"] = {key: value for key, value in consumed.items() if key != "arguments"}
        report["consumer"]["generated_sha256"] = sha256(generated).hexdigest()
        report["consumer"]["generated_bytes"] = count
        report["checks"]["leased_compiler_output"] = (consumed["status"] == "returned"
            and 0 < count <= 4096 and consumed["buffers"] == measured["observations"][0]["candidate_vm"]["buffers"])
        if not report["checks"]["leased_compiler_output"]:
            raise ValueError("leased compiler output differs from the evaluated byte commitments")
        # The ordinary stdlib-only selfhost consumer does not import an HIA
        # parser, checker or compiler. Execute the actual bytes returned by f0.
        consumers = []
        for index, data in enumerate((b"", b"real consumer", bytes(range(256)))):
            expected = 5381
            for byte in data:
                expected = ((expected * 33) ^ byte) & 0xffffffff
            path = output / ("consumer-" + str(index))
            path.mkdir()
            (path / "input.bin").write_bytes(data)
            request = {"image": str(output / "generated.bin"), "source": str(path / "input.bin"),
                "image_sha256": sha256(generated).hexdigest(), "source_sha256": sha256(data).hexdigest(),
                "format": "flat-x86-64", "capacity": 1, "workspace_size": 1,
                "output": str(path / "output.bin")}
            (path / "request.json").write_bytes(wire(request))
            result = subprocess.run([sys.executable, "-B", "-I", str(ROOT / "tools/hia_selfhost_child.py"),
                str(path / "request.json")], capture_output=True, timeout=30, check=False)
            (path / "stdout.json").write_bytes(result.stdout)
            (path / "stderr.txt").write_bytes(result.stderr)
            observation = json.loads(result.stdout) if result.returncode == 0 else None
            ok = bool(observation is not None and observation.get("core_u32") == expected
                and observation.get("source_unchanged") is True
                and observation.get("output_sha256") == sha256(bytes([expected & 255])).hexdigest()
                and observation.get("forbidden_compiler_modules_loaded") == [])
            report["checks"]["generated_consumer_" + str(index)] = ok
            consumers.append({"source_sha256": sha256(data).hexdigest(), "expected": expected,
                "returncode": result.returncode, "observation": observation,
                "stdout_sha256": sha256(result.stdout).hexdigest(), "stderr_sha256": sha256(result.stderr).hexdigest()})
        report["generated_consumers"] = consumers
        report["status"] = "passed" if all(report["checks"].values()) else "failed"
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        service.close()
        report["checks"]["source_unchanged"] = bool(installation_manifest() == report["installation"]
            and sha256(Path(__file__).read_bytes()).hexdigest() == qualifier_hash)
        if not report["checks"]["source_unchanged"]:
            report.update(status="failed", error={"type": "SourceChanged", "message": "installed source changed during qualification"})
        report["wall_ns"] = str(time.monotonic_ns() - started)
        report["journal_sha256"] = sha256(journal_path.read_bytes()).hexdigest()
        (output / "REPORT.json").write_bytes(wire(report))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--compiler-source")
    parser.add_argument("--expected-source-sha256")
    args = parser.parse_args(argv)
    if args.compiler_source and not args.expected_source_sha256:
        parser.error("an alternate compiler source requires its exact --expected-source-sha256")
    result = qualify(args.output, compiler_source=args.compiler_source,
                     expected_source_sha256=args.expected_source_sha256)
    print(json.dumps({key: result[key] for key in ("status", "checks", "wall_ns")}, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
