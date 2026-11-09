"""Retain a scoped Core -> supplied ELF proof -> adopted native consumer chain.

The three closed instances use data-dependent branches and modular arithmetic.
Each proof quantifies all typed inputs in the existing independent Python/SMT
model. Real consumer observations cover only the declared finite workload.
This does not prove the models, hardware ISA, general compiler or production
loader, and does not activate the configured remote MCP service.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_store import digest, wire
from tools.hia_agent_native_qualification import Session, ToolClient
from tools.qualify_hia_agent_buffer_lifecycle import ColdConsumer, PinnedWorker


def require(value, message):
    if not value:
        raise AssertionError(message)


def program(width):
    """One branch function: ((x+y)^salt) or ((x-y)&salt), modulo width."""
    require(width in (8, 32, 64), "unsupported fixture width")
    typ, salt, threshold = f"u{width}", (1 << width) - 17, 1 << (width - 1)

    def param(name, kind=typ):
        return {"name": name, "type": kind}

    def op(name, args, out, kind=typ, **attrs):
        return {"op": name, "args": args, "out": [param(out, kind)], "attrs": attrs}

    params = [param("x"), param("y")]
    blocks = [{"id": "entry", "params": params,
        "ops": [op("const", [], "threshold", value=threshold),
                op("compare.lt", ["x", "threshold"], "choose", "bool")],
        "term": {"op": "branch", "cond": "choose",
            "then": {"target": "low", "args": ["x", "y"]},
            "else": {"target": "high", "args": ["x", "y"]}}}]
    for label, arithmetic, bits in (("low", "int.add.wrap", "bit.xor"),
                                    ("high", "int.sub.wrap", "bit.and")):
        left, right = label + "_x", label + "_y"
        value, constant, answer = (label + suffix for suffix in ("_value", "_salt", "_answer"))
        blocks.append({"id": label, "params": [param(left), param(right)],
            "ops": [op(arithmetic, [left, right], value), op("const", [], constant, value=salt),
                    op(bits, [value, constant], answer)],
            "term": {"op": "ret", "values": [answer]}})
    return {"schema": "hepta.hia.program.v1", "module": f"closed_branch_u{width}",
        "functions": [{"name": "calculate", "params": params, "returns": [typ],
                       "effects": [], "entry": "entry", "blocks": blocks}]}


def workload(width):
    mask, threshold, salt = (1 << width) - 1, 1 << (width - 1), (1 << width) - 17
    pairs = [(0, 0), (0, mask), (1, mask), (threshold - 1, 1),
             (threshold, 0), (threshold, mask), (mask, 1), (mask, mask)]
    # This arithmetic oracle does not use the Core interpreter or native emitter.
    def expected(x, y):
        return (((x + y) & mask) ^ salt) if x < threshold else (((x - y) & mask) & salt)
    return {"schema": "hepta.hia.agent.workload.v1", "warmup_iterations": 0, "repetitions": 1,
        "cases": [{"function": "calculate", "arguments": [x, y],
                   "expected": {"status": "returned", "values": [expected(x, y)]}}
                  for x, y in pairs]}


def artifact_refs(value):
    if isinstance(value, dict):
        if set(value) == {"id", "sha256", "uri"} and str(value["uri"]).startswith("hia://"):
            yield value
        else:
            for item in value.values():
                yield from artifact_refs(item)
    elif isinstance(value, list):
        for item in value:
            yield from artifact_refs(item)


def export_artifacts(session, records, output):
    """Read issued references; never reconstruct proof inputs by reemission."""
    destination = output / "retained-artifacts"
    destination.mkdir()
    queue, exported, total = list(artifact_refs(records)), {}, 0
    while queue:
        ref = queue.pop(0)
        if ref["id"] in exported:
            require(exported[ref["id"]]["artifact"] == ref, "issued artifact identity changed")
            continue
        require(len(exported) < 256, "artifact graph exceeds qualification limit")
        data = session.read(ref)
        total += len(data)
        require(total <= 64 * 1024 * 1024, "artifact export exceeds qualification limit")
        path = destination / ref["sha256"]
        if path.exists():
            require(path.read_bytes() == data, "artifact digest collision")
        else:
            path.write_bytes(data)
        exported[ref["id"]] = {"artifact": ref, "path": str(path.relative_to(output)), "bytes": len(data)}
        try:
            queue.extend(artifact_refs(json.loads(data)))
        except (ValueError, UnicodeDecodeError):
            pass
    inventory = list(exported.values())
    (output / "artifact-inventory.json").write_bytes(wire(inventory) + b"\n")
    return {"count": len(inventory), "bytes": total, "inventory": "artifact-inventory.json"}


def run_instance(width, output):
    output.mkdir(parents=True, exist_ok=False)
    worker = PinnedWorker(output, ROOT)
    started = time.monotonic_ns()
    report = {"width": width, "status": "started", "installation": worker.identities}
    journal = (output / "tool-transcript.jsonl").open("x")

    def record(row):
        journal.write(json.dumps(row, sort_keys=True) + "\n")
        journal.flush()
        os.fsync(journal.fileno())

    client = ToolClient(worker.call, journal=record)
    try:
        session = Session(client, prefix=f"scalar-chain-u{width}")
        objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": ["core_admission", "lowering_refinement"],
            "allow_unchanged": True, "min_improvement_ratio": 0.0}
        cases = workload(width)
        session.freeze(cases, objective=objective, budget={"max_native_wall_ms": 60000})
        core = session.import_program(program(width))
        admitted = session.verify(core)
        require(all(c["status"] == "proved" for c in admitted["checks"]), "Core admission incomplete")
        built = session.emit(core, receipts=[admitted["verification_receipt"]])
        build = session.read_json(built["build_receipt"])
        proof = session.verify(core, claims=["lowering_refinement"], subject={
            "kind": "native_artifact", "backend_profile": session.backend,
            "native_artifact": built["native_artifact"], "build_receipt": built["build_receipt"]})
        require(len(proof["checks"]) == 1 and proof["checks"][0]["status"] == "proved",
                "independent supplied-final-image proof incomplete")
        check = proof["checks"][0]
        require(check["checker"]["method"] == "independent_safe_core_machine_validation",
                "unexpected proof method")
        evidence = session.read_json(check["evidence_artifact"])
        require(evidence["deadline_met"] and len(evidence["queries"]) == 5,
                "proof lacks timely complete query inventory")
        receipts = [admitted["verification_receipt"], proof["verification_receipt"]]
        evaluated = session.evaluate(built, built, receipts=receipts)
        require(evaluated["outcome"] == "unchanged" and evaluated["planned_workload_complete"],
                "all declared native cases did not qualify")
        slot = f"scalar-chain/u{width}"
        args = session.arguments(target_slot=slot, expected_current={"generation": "0", "epoch": "0"},
            candidate_artifact=built["native_artifact"], evaluation_receipt=evaluated["evaluation_receipt"],
            verification_receipts=receipts)
        adopted = client.result("hia_adopt", args)
        require(client.result("hia_adopt", args) == adopted, "original adoption replay changed")
        receipt = session.read_json(adopted["adoption_receipt"])
        identity = receipt["artifact_identity"]
        binding = evidence["artifact_binding"]
        require(identity["candidate"] == core and identity["core_sha256"] == binding["candidate_core_sha256"]
                and identity["input_sha256"] == binding["input_sha256"], "adopted Core binding differs")
        for key in ("object_artifact", "object_sha256", "final_image_sha256", "native_artifact", "build_receipt"):
            require(identity[key] == binding[key], "adopted proof input differs: " + key)
        require(identity["codegen"]["kind"] == "canonical" and identity["machine_plan_sha256"] is None,
                "unexpected codegen choice")
        require(identity["abi_sha256"] == digest(identity["abi_signatures"])
                and identity["current"] == adopted["current"]
                and identity["projection_is_execution_authority"] is False, "adopted ABI/generation differs")
        require(identity["object_artifact"] == build["object_artifact"], "original object changed")
        consumer = ColdConsumer(output, worker.state, ROOT)
        lease = consumer.call("acquire", target_slot=slot)
        rollback = client.result("hia_rollback", session.arguments(target_slot=slot,
            expected_current=adopted["current"], retained_generation="0", reason="qualification baseline for future calls"))
        observations = []
        for case in cases["cases"]:
            result = consumer.call("invoke", lease=lease, function=case["function"], arguments=case["arguments"])
            require(result["status"] == "returned" and result["values"] == case["expected"]["values"]
                    and result["artifact"] == identity["native_artifact"]
                    and result["generation"] == adopted["current"]["generation"],
                    "consumer return/artifact/generation differs")
            observations.append(result)
        restored = consumer.call("acquire", target_slot=slot)
        require(restored["generation"] == "0", "rollback did not change future acquisitions")
        consumer.call("release", lease=restored)
        consumer.call("release", lease=lease)
        rejected = consumer.call("invoke", expected_status="rejected", lease=lease,
                                 function="calculate", arguments=[0, 0])
        require(rejected["code"] == "E_HIA_LEASE", "released lease was not rejected")
        report.update(status="PASS_SCOPED_PROOF_ADOPTION", core=core, build=built,
            verification=proof, evaluation=evaluated, adoption=adopted, artifact_identity=identity,
            rollback=rollback, consumer_observations=observations, consumer_processes=consumer.sequence,
            released_lease=rejected, original_adoption_replay_identical=True,
            export=export_artifacts(session, client.records[:], output))
        require(installation_manifest() == worker.identities, "installed source changed during qualification")
    except Exception as exc:
        report.update(status="FAILED", error={"type": type(exc).__name__, "message": str(exc)[:4096]})
        raise
    finally:
        journal.close()
        report.update(wall_ns=str(time.monotonic_ns() - started), worker_calls=worker.sequence)
        (output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def run(output):
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.scalar-proof-adoption-qualification.v1", "status": "started",
        "started_at": datetime.now(timezone.utc).isoformat(), "instances": [],
        "family": "three closed unsigned u8/u32/u64 acyclic two-argument branch/arithmetic functions",
        "proof_domain": "all typed inputs per instance in existing independent Core/x86/ELF model",
        "consumer_domain": "eight declared boundary inputs per instance, actual local native lease calls",
        "transport": "pinned fixed-command worker protocol and cold consumer process per operation",
        "host": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "qualifier_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "production_adoption": False, "remote_mcp_qualified": False,
        "whole_language_soundness_proved": False, "kernel_checked_isa_proof": False,
        "owned_resource_liveness_proved": False, "performance_or_NDU_increment_proved": False,
        "full_cost_complete": False,
        "remaining": ["trusted Python Core/x86/ELF models and Z3 soundness", "real caller/stack/loader contract",
            "complete hardware ISA refinement", "whole compiler and owned-resource lifetime refinement",
            "production deployment", "full economic and empirical NDU evaluation"]}
    try:
        for width in (8, 32, 64):
            report["instances"].append(run_instance(width, output / f"u{width}"))
        report["status"] = "PASS_SCOPED_PROOF_ADOPTION"
    except Exception as exc:
        report.update(status="FAILED", error={"type": type(exc).__name__, "message": str(exc)[:4096]})
        raise
    finally:
        report["ended_at"] = datetime.now(timezone.utc).isoformat()
        (output / "REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.output.resolve())
    print(json.dumps({"status": result["status"], "instances": len(result["instances"])}))
