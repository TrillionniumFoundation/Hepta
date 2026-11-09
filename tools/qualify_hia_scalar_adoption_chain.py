#!/usr/bin/env python3
"""Qualify a mathematical capped-add specification through actual native adoption.

The finite family is min(x + y, cap) over unsigned inputs, with an unbounded
mathematical sum. Four Core blocks guard checked subtraction/addition. A client
chooses an explicit different block layout; the existing independent checker
proves its supplied object and final ELF, then the existing owner evaluates,
adopts, invokes, and rolls back that exact artifact. This is a local integration
qualification, not a kernel proof of Python, the ISA, the loader, or production.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import itertools
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

WIDTHS = {"u8": 8, "u32": 32, "u64": 64, "usize": 64}
SPECIFICATION = "min(unsigned(x) + unsigned(y), unsigned(cap)); addition is unbounded"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def capped_add_program(typ):
    require(typ in WIDTHS, "type is outside the existing scalar Agent proof profile")

    def params(*names):
        return [{"name": name, "type": typ} for name in names]

    def operation(op, arguments, name, out_type):
        return {"op": op, "args": arguments, "out": [{"name": name, "type": out_type}], "attrs": {}}

    return {"schema": "hepta.hia.program.v1", "module": "capped_add_chain", "functions": [{
        "name": "capped_add", "params": params("x", "y", "cap"), "returns": [typ],
        "effects": ["trap"], "entry": "entry", "blocks": [
            {"id": "entry", "params": params("x", "y", "cap"),
             "ops": [operation("compare.ge", ["x", "cap"], "already_full", "bool")],
             "term": {"op": "branch", "cond": "already_full",
                      "then": {"target": "limited", "args": ["cap"]},
                      "else": {"target": "room", "args": ["x", "y", "cap"]}}},
            {"id": "room", "params": params("rx", "ry", "rcap"), "ops": [
                operation("int.sub.checked", ["rcap", "rx"], "available", typ),
                operation("compare.gt", ["ry", "available"], "too_large", "bool")],
             "term": {"op": "branch", "cond": "too_large",
                      "then": {"target": "limited", "args": ["rcap"]},
                      "else": {"target": "sum", "args": ["rx", "ry"]}}},
            {"id": "sum", "params": params("sx", "sy"),
             "ops": [operation("int.add.checked", ["sx", "sy"], "answer", typ)],
             "term": {"op": "ret", "values": ["answer"]}},
            {"id": "limited", "params": params("limit"), "ops": [],
             "term": {"op": "ret", "values": ["limit"]}},
        ]}]}


def specification_proof(document, directory, *, timeout_ms=15000):
    """Link the exact admitted Core model to a separately written 65-bit spec.

    Input ABI words remain arbitrary 64-bit values. The existing Core model
    normalizes them to the declared unsigned type; widening before addition
    preserves a carry even for u64/usize. No native samples enter the proof.
    """
    import z3 as z
    from hepta.hia_program import verify_program
    from hepta.hia_safe_core import _Theory, _profile, _checker_source_identity, _solver_identity

    require(type(timeout_ms) is int and 100 <= timeout_ms <= 60000, "invalid proof deadline")
    checked = verify_program(document)
    function, blocks = _profile(checked, foreign_buffer_exports=())
    typ = function["returns"][0]
    require(typ in WIDTHS and function["name"] == "capped_add"
            and function["params"] == [{"name": name, "type": typ} for name in ("x", "y", "cap")],
            "the specification requires exactly three same-width unsigned scalar inputs")
    directory.mkdir(parents=True, exist_ok=False)
    model_identity, solver_identity = _checker_source_identity(), _solver_identity(z)
    theory = _Theory(z, timeout_ms)
    theory.arguments(function)
    complete, aborts, returned, memory = theory.merge(theory.reference(function, blocks, None))
    x, y, cap = (theory.inputs[name] for name in ("x", "y", "cap"))
    widened_sum, widened_cap = z.ZeroExt(1, x) + z.ZeroExt(1, y), z.ZeroExt(1, cap)
    expected = z.If(z.ULE(widened_sum, widened_cap), z.Extract(63, 0, widened_sum), cap)
    obligations = [
        ("unsigned_input_domain_nonvacuous", z.BoolVal(True, ctx=theory.ctx), "sat"),
        ("core_always_returns_and_preserves_caller_bytes", z.Or(z.Not(complete), aborts, memory != theory.memory), "unsat"),
        ("core_equals_unbounded_sum_capped_at_limit", returned != expected, "unsat"),
    ]
    report = {"schema": "hepta.hia.capped-add-specification.v1", "status": "started", "type": typ,
        "specification": SPECIFICATION, "core_sha256": checked.sha256,
        "input_sha256": checked.input_sha256, "checker_source_identity": model_identity,
        "qualification_source_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "solver": solver_identity, "obligations": [], "execution_authority_granted": False,
        "kernel_checked_core_soundness": False}
    write_json(directory / "specification.json", report)
    try:
        for index, (name, query, expected_result) in enumerate(obligations):
            theory.check_time()
            solver = z.Solver(ctx=theory.ctx)
            solver.set(timeout=max(1, int((theory.deadline - time.monotonic()) * 1000)))
            solver.add(query)
            data = (solver.sexpr() + "\n(check-sat)\n").encode()
            filename = f"{index:02d}-{name}.smt2"
            (directory / filename).write_bytes(data)
            started = time.monotonic_ns()
            result = str(solver.check())
            row = {"name": name, "expected": expected_result, "result": result,
                   "query_file": filename, "query_sha256": sha256(data).hexdigest(),
                   "elapsed_ns": str(time.monotonic_ns() - started)}
            report["obligations"].append(row)
            write_json(directory / (filename + ".result.json"), row)
            theory.check_time()
            if result != expected_result:
                report["status"] = "refuted" if result == "sat" else "unknown"
                if result == "sat":
                    model = solver.model()
                    report["counterexample"] = {name: model.eval(value, model_completion=True).as_long()
                                                 for name, value in theory.inputs.items()}
                else:
                    report["reason"] = solver.reason_unknown()
                raise ValueError(name + ": " + result)
        require(model_identity == _checker_source_identity() and solver_identity == _solver_identity(z),
                "checker or solver changed during the specification proof")
        theory.check_time()
        report["status"] = "proved_in_independent_core_model"
        return report
    except BaseException as exc:
        if report["status"] == "started":
            report.update(status="unknown", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        write_json(directory / "specification.json", report)


def witness_vectors(typ):
    maximum = (1 << WIDTHS[typ]) - 1
    values = [0, 1, maximum // 2, maximum - 1, maximum]
    return [list(row) for row in itertools.product(values, repeat=3)]


def source_identity():
    from hepta.hia_agent_contract import installation_manifest
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
        "worktree_status": git("status", "--porcelain=v1", "--untracked-files=all"),
        "installation": installation_manifest(),
        "qualification_source_sha256": sha256(Path(__file__).read_bytes()).hexdigest()}


def qualify_family(typ, directory, row, *, campaign_id, save):
    from hepta.hia_agent_service import HIAAgentService
    from tools.hia_agent_native_qualification import Session, ToolClient, json_bytes

    directory.mkdir()
    document = capped_add_program(typ)
    write_json(directory / "source.hia.json", document)
    row["phase"] = "specification"
    save()
    specification = specification_proof(document, directory / "specification")
    row["specification"] = specification
    vectors = witness_vectors(typ)
    workload = {"schema": "hepta.hia.agent.workload.v1", "cases": [
        {"function": "capped_add", "arguments": vector,
         "expected": {"status": "returned", "values": [min(vector[0] + vector[1], vector[2])]}}
        for vector in vectors], "warmup_iterations": 0, "repetitions": 1}
    objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
        "required_claims": ["core_admission", "behavior_equivalence", "encoding_check", "lowering_refinement"],
        "allow_unchanged": True, "min_improvement_ratio": 0.0}
    client = service = None
    with tempfile.TemporaryDirectory(prefix="hia-capped-chain-") as temporary, \
            (directory / "calls.jsonl").open("xb") as journal:
        def record(event):
            journal.write(json_bytes(event) + b"\n")
            journal.flush()
            os.fsync(journal.fileno())

        try:
            service = HIAAgentService(Path(temporary) / "state")
            client = ToolClient(service.call, journal=record)
            session = Session(client, prefix=campaign_id + "/" + typ)
            row["exports"] = {}

            def capture(reference, filename):
                data = session.read(reference)
                (directory / filename).write_bytes(data)
                row["exports"][filename] = dict(reference)
                return json.loads(data) if filename.endswith(".json") else data

            def capture_proof(reference, name):
                proof = capture(reference, name + "-proof.json")
                for check in proof["checks"]:
                    capture(check["evidence_artifact"], name + "-" + check["claim"] + "-evidence.json")
                    capture(check["assumptions_artifact"], name + "-" + check["claim"] + "-assumptions.json")
                return proof

            capture(session.discovery["manifest"], "installation-manifest.json")
            for name, reference in session.manifest["profile_manifests"].items():
                capture(reference, "profile-" + name + ".json")
            session.freeze(workload)
            candidate = session.import_program(document)
            require(candidate["sha256"] == specification["core_sha256"], "specification and imported Core differ")
            capture(candidate, "core.hia.json")
            frozen = session.freeze(workload, baseline=candidate, objective=objective)
            context_record = capture(frozen["manifest"], "context.json")
            capture(context_record["workload"], "workload.json")
            capture(context_record["objective"], "objective.json")
            capture(context_record["budget"]["cost_policy"], "cost-policy.json")
            row.update(phase="emission", candidate=candidate, context=session.context)
            save()
            core_check = session.verify(candidate, base=candidate,
                                        claims=["core_admission", "behavior_equivalence"])
            require(all(check["status"] == "proved" for check in core_check["checks"]), "Core claims did not pass")
            capture_proof(core_check["verification_receipt"], "core")
            plan = {"schema": "hepta.hia.agent.block-layout.v1", "core_sha256": candidate["sha256"],
                    "block_order": {"capped_add": ["entry", "limited", "room", "sum"]}}
            plan_ref = session.artifact(plan)
            capture(plan_ref, "machine-plan.json")
            plan_check = session.verify(candidate, claims=["lowering_refinement"], subject={
                "kind": "agent_machine_plan", "backend_profile": session.backend,
                "plan_profile": session.profiles["plan"], "plan": plan_ref})
            require(plan_check["checks"][0]["status"] == "proved", "explicit layout was not accepted")
            capture_proof(plan_check["verification_receipt"], "plan")
            canonical = session.emit(candidate, receipts=[core_check["verification_receipt"]])
            planned = session.emit(candidate, receipts=[core_check["verification_receipt"]], codegen={
                "kind": "agent_plan", "plan_profile": session.profiles["plan"], "plan": plan_ref,
                "verification_receipt": plan_check["verification_receipt"]})
            require(canonical["native_artifact"]["sha256"] != planned["native_artifact"]["sha256"],
                    "the two requested layouts did not produce distinct final artifacts")
            row.update(phase="independent_machine_proofs", canonical=canonical, planned=planned)
            save()
            builds, machine_proofs, evidences = {}, {}, {}
            for name, built in (("canonical", canonical), ("planned", planned)):
                build = capture(built["build_receipt"], name + "-build.json")
                builds[name] = build
                capture(build["object_artifact"], name + ".o")
                capture(built["native_artifact"], name + ".so")
                proof = session.verify(candidate, claims=["lowering_refinement"], subject={
                    "kind": "native_artifact", "backend_profile": session.backend,
                    "native_artifact": built["native_artifact"], "build_receipt": built["build_receipt"]})
                machine_proofs[name] = proof
                proof_record = capture(proof["verification_receipt"], name + "-machine-proof.json")
                require(proof_record["checks"][0]["status"] == "proved", "independent " + name + " proof incomplete")
                check = proof_record["checks"][0]
                evidence = capture(check["evidence_artifact"], name + "-machine-evidence.json")
                evidences[name] = evidence
                capture(check["assumptions_artifact"], name + "-assumptions.json")
                for query in evidence["queries"]:
                    capture(query["artifact"], name + "-" + query["name"])
                require(evidence["artifact_binding"]["abi_signatures"] == build["signatures"], "ABI identity differs")
                require(evidence["artifact_binding"]["machine_plan"] == (plan_ref if name == "planned" else None),
                        "proof and emitted plan differ")
            encoded = session.encoding(candidate, planned)
            require(encoded["checks"][0]["status"] == "proved", "actual encoding identity check incomplete")
            capture_proof(encoded["verification_receipt"], "encoding")
            # Conditional plan preservation is required for emission. Only the
            # independent final-image proof is supplied for adoption's lowering claim.
            receipts = [core_check["verification_receipt"], encoded["verification_receipt"],
                        machine_proofs["planned"]["verification_receipt"]]
            row["phase"] = "evaluation"
            save()
            evaluation = session.evaluate(canonical, planned, receipts=receipts)
            row["evaluation"] = evaluation
            require(evaluation["planned_workload_complete"] and evaluation["termination_confirmed"]
                    and evaluation["outcome"] in {"unchanged", "improved"}, "native evaluation was not adoptable")
            capture(evaluation["evaluation_receipt"], "evaluation.json")
            capture(evaluation["measurements"], "measurements.json")
            ledger = capture(evaluation["full_cost_ledger"], "cost-ledger.json")
            slot = campaign_id + "/" + typ + "/slot"
            row["phase"] = "adoption_and_owner_calls"
            save()
            adoption = client.result("hia_adopt", session.arguments(target_slot=slot,
                expected_current={"generation": "0", "epoch": "0"}, candidate_artifact=planned["native_artifact"],
                evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))
            row["adoption"] = adoption
            capture(adoption["adoption_receipt"], "adoption.json")
            lease = service.acquire_slot(slot)
            observations = []
            try:
                for index in (0, 1, 24, 30, 62, 100, 123, 124):
                    vector = vectors[index]
                    started = time.monotonic_ns()
                    observation = service.invoke_lease(lease, "capped_add", vector)
                    observations.append({"arguments": vector, "observation": observation,
                        "elapsed_ns": str(time.monotonic_ns() - started)})
                    require(observation["status"] == "returned"
                            and observation.get("values", observation.get("result")) == [min(vector[0] + vector[1], vector[2])]
                            and observation["artifact"] == planned["native_artifact"]
                            and observation["generation"] == adoption["current"]["generation"],
                            "owner invocation differs from specification or adopted identity")
                rollback = client.result("hia_rollback", session.arguments(target_slot=slot,
                    expected_current=adoption["current"], retained_generation=adoption["previous"]["generation"],
                    reason="qualification restores the independently verified canonical artifact"))
                require(rollback["active_artifact"] == canonical["native_artifact"], "rollback selected another artifact")
                capture(rollback["rollback_receipt"], "rollback.json")
                old = service.invoke_lease(lease, "capped_add", [1, 1, 1])
                require(old["artifact"] == planned["native_artifact"], "rollback changed an in-flight lease")
                restored = service.acquire_slot(slot)
                try:
                    new = service.invoke_lease(restored, "capped_add", [1, 1, 1])
                    require(new["artifact"] == canonical["native_artifact"], "new lease did not select restored baseline")
                finally:
                    service.release_slot(restored)
                for value in (old, new):
                    require(value["status"] == "returned" and value.get("values", value.get("result")) == [1],
                            "rollback owner call returned a wrong value")
                row.update(rollback=rollback, retained_lease_after_rollback=old, new_lease_after_rollback=new)
            finally:
                service.release_slot(lease)
                write_json(directory / "owner-observations.json", observations)
            row.update(status="passed", phase="complete", native_workload_vectors=len(vectors),
                observed_owner_calls=len(observations) + 2,
                identity_chain={"core": candidate, "plan": plan_ref,
                    "plan_sha256": builds["planned"]["native_build"]["machine_plan_sha256"],
                    "object": builds["planned"]["object_artifact"], "final_image": planned["native_artifact"],
                    "target_profile": builds["planned"]["target_profile"],
                    "backend_profile": builds["planned"]["backend_profile"],
                    "abi_signatures": builds["planned"]["signatures"],
                    "context_manifest": frozen["manifest"],
                    "core_proof": core_check["verification_receipt"],
                    "plan_proof": plan_check["verification_receipt"],
                    "encoding_proof": encoded["verification_receipt"],
                    "machine_proof": machine_proofs["planned"]["verification_receipt"],
                    "evaluation_receipt": evaluation["evaluation_receipt"],
                    "adoption_receipt": adoption["adoption_receipt"],
                    "rollback_receipt": rollback["rollback_receipt"],
                    "adoption": adoption, "owner_artifact": observations[0]["observation"]["artifact"]},
                full_search_cost_complete=ledger["full_search_cost_complete"],
                net_optimization_benefit_proved=False)
        finally:
            if client is not None:
                row["tool_call_count"] = len(client.records)
                row["observed_tool_wall_ns"] = str(sum(int(record["elapsed_ns"]) for record in client.records))
            if service is not None:
                service.close()
            save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    parser.add_argument("--types", nargs="+", choices=list(WIDTHS), default=list(WIDTHS))
    parser.add_argument("--campaign-id", required=True)
    args = parser.parse_args(argv)
    from tools.hia_agent_native_qualification import campaign_binding
    campaign_binding(args.campaign_id)
    require(len(set(args.types)) == len(args.types), "duplicate type would duplicate evidence")
    require(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"},
            "the existing Linux x86-64 qualification target is required")
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.scalar-adoption-chain.v2", "status": "started",
        "specification": SPECIFICATION, "types": args.types, "campaign_id": args.campaign_id,
        "mode": "in_process_domain_service_with_actual_native_children", "families": [],
        "source": source_identity(), "claims": {
            "kernel_checked_core_or_hardware_soundness": False,
            "full_compiler_buffer_refinement": False, "foreign_resource_liveness_proved": False,
            "formal_online_endpoint_qualified": False, "fresh_model_learning_observed": False,
            "global_safety_or_production_acceptance": False, "net_optimization_benefit_proved": False,
            "specification_receipt_is_runtime_authority": False}}
    started = time.monotonic_ns()
    def save():
        write_json(args.output / "report.json", report)
    save()
    try:
        for typ in args.types:
            row = {"type": typ, "status": "started"}
            report["families"].append(row)
            qualify_family(typ, args.output / typ, row, campaign_id=args.campaign_id, save=save)
        require(report["source"] == source_identity(), "qualification source changed during execution")
        report["status"] = "passed"
        return 0
    except BaseException as exc:
        report.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        report["elapsed_ns"] = str(time.monotonic_ns() - started)
        save()
        files = [{"path": str(path.relative_to(args.output)), "bytes": path.stat().st_size,
                  "sha256": sha256(path.read_bytes()).hexdigest()}
                 for path in sorted(args.output.rglob("*")) if path.is_file() and path.name != "original-files.json"]
        write_json(args.output / "original-files.json", files)
        print(json.dumps({"status": report["status"], "types": args.types, "output": str(args.output)}))


if __name__ == "__main__":
    raise SystemExit(main())
