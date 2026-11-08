"""Qualify a pinned compiler in an isolated byte-snapshot service lifecycle.

This is a new activation continuation of exact frozen source, not another
fresh-agent study, production deployment or universal machine proof.  Tool calls
use the actual pinned worker protocol in new processes.  Consumer leases use the
existing authorized service API over the same private retained state.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentRejected, wire
from tools.hia_agent_native_qualification import Session, ToolClient
from tools.qualify_hia_selfhost import invoke


PROGRAM = b'''hia-asm.v1 hepta.hia.program.v8 selfhost
fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)
block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)
  v3:usize = const() {"value":0}
  v4:u8 = buffer.load(v0,v3)
  v5:u8 = const() {"value":0}
  v6:bool = compare.ne(v4,v5)
  v7:u32 = const() {"value":700000001}
  v8:u32 = const() {"value":4000000007}
  v9:u32 = select(v6,v7,v8)
  _ = buffer.store(v1,v3,v4)
  ret(v9)
end
'''


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class PinnedWorker:
    def __init__(self, output, source_root):
        self.output, self.source_root = output, source_root
        self.state = output / "state"
        self.identities = installation_manifest()
        self.sequence = 0
        self.profile_sha256 = sha256(wire({"state_root": str(self.state),
            "artifact_roots": [str(source_root)], "installation": self.identities})).hexdigest()

    def call(self, tool, arguments):
        self.sequence += 1
        envelope = {"schema": "hia-agent-worker-request-v1", "tool": tool,
            "arguments": arguments, "profile_sha256": self.profile_sha256,
            "catalog_sha256": self.identities["catalog_sha256"]}
        envelope["request_sha256"] = sha256(wire(envelope)).hexdigest()
        prefix = self.output / ("worker-" + str(self.sequence).zfill(4))
        prefix.with_suffix(".request.json").write_bytes(wire(envelope) + b"\n")
        command = [sys.executable, "-B", "-E", "-s", "-m", "hepta.hia_agent_worker",
            "--state-root", str(self.state), "--artifact-root", str(self.source_root), "--request-json-stdin"]
        for name in ("worker", "backend", "catalog"):
            command += ["--expected-" + name + "-sha256", self.identities[name + "_sha256"]]
        completed = subprocess.run(command, cwd=ROOT, input=wire(envelope), capture_output=True, timeout=600)
        prefix.with_suffix(".stdout.json").write_bytes(completed.stdout)
        prefix.with_suffix(".stderr.log").write_bytes(completed.stderr)
        require(completed.returncode == 0, "pinned worker failed: " + completed.stderr.decode(errors="replace")[:4096])
        report = json.loads(completed.stdout)
        require(report.get("schema") == "hia-agent-worker-report-v1" and report.get("complete") is True,
                "worker did not return its complete protocol report")
        for name in ("tool", "request_sha256", "profile_sha256", "catalog_sha256"):
            require(report.get(name) == envelope[name], "worker correlation mismatch: " + name)
        for name in ("worker_sha256", "backend_sha256", "catalog_sha256"):
            require(report.get(name) == self.identities[name], "worker installation changed: " + name)
        return report["response"]


def run(compiler_source, expected_sha256, output):
    output.mkdir(parents=True, exist_ok=False)
    compiler_source = compiler_source.resolve(strict=True)
    source_bytes = compiler_source.read_bytes()
    require(sha256(source_bytes).hexdigest() == expected_sha256, "compiler source does not match the requested frozen digest")
    worker = PinnedWorker(output, compiler_source.parent)
    prefix = "buffer-continuation/" + sha256(str(output).encode()).hexdigest()[:16]
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.agent.buffer-lifecycle-qualification.v1", "status": "started",
        "started_at": datetime.now(timezone.utc).isoformat(), "compiler_source_sha256": expected_sha256,
        "compiler_source_bytes": len(source_bytes), "installation": worker.identities,
        "transport": "actual pinned fixed-command worker protocol, one fresh process per tool call",
        "remote_mcp_endpoint_qualified": False, "production_adoption": False,
        "original_fresh_agent_study_rewritten": False, "new_fresh_agent_study": False,
        "baseline_kind": "the same frozen compiler Core; activation qualification, not an optimization comparison",
        "full_provider_interaction_available": False, "provider_tokens": None, "provider_fees": None,
        "full_cost_complete": False, "universal_compiler_or_machine_refinement_proved": False}
    journal = (output / "tool-transcript.jsonl").open("x")

    def record(row):
        journal.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        journal.flush()
        os.fsync(journal.fileno())

    def save():
        (output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    client = ToolClient(worker.call, journal=record)
    consumer = None
    try:
        session = Session(client, prefix=prefix)
        malformed = PROGRAM.replace(b"select(v6,v7,v8)", b"select(v7,v7,v8)")
        (output / "consumer-program.hiaasm").write_bytes(PROGRAM)
        cases = [{"function": "f0", "arguments": [
            {"bytes_hex": payload.hex()}, {"byte_length": 8192, "fill_byte": 165},
            {"byte_length": workspace, "fill_byte": 0}], **({"expected": {"status": "returned", "values": [expected]}}
                if expected is not None else {})}
            for payload, workspace, expected in ((PROGRAM, 1048576, None),
                (malformed, 1048576, 4294967295), (PROGRAM, 1024, 4294967294))]
        workload = {"schema": "hepta.hia.agent.workload.v2",
            "foreign_buffer_exports": [{"function": "f0", "max_buffer_bytes": 1048576}],
            "cases": cases, "warmup_iterations": 0, "repetitions": 1}
        objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": ["core_admission", "behavior_equivalence", "encoding_check"],
            "allow_unchanged": True, "min_improvement_ratio": 0}
        report["frozen_workload"] = workload
        report["frozen_objective"] = objective
        save()
        session.freeze(workload, objective=objective, budget={"max_native_wall_ms": 60000})
        source = client.result("hia_artifact", session.arguments(context=False,
            artifact_profile=session.profiles["artifact"], source={"kind": "path", "path": str(compiler_source),
                "expected_sha256": expected_sha256, "max_bytes": len(source_bytes)}))["artifact"]

        def import_frozen():
            return client.result("hia_candidate", session.arguments(change={
                "kind": "import", "format": "hia-asm.v1", "source": source}))["candidate"]

        baseline = import_frozen()
        session.freeze(workload, baseline=baseline, objective=objective, budget={"max_native_wall_ms": 60000})
        candidate = import_frozen()
        verified = session.verify(candidate, base=baseline, claims=["core_admission", "behavior_equivalence"])
        require(all(check["status"] == "proved" for check in verified["checks"]), "exact Core identity was not qualified")
        base_build = session.emit(baseline)
        candidate_build = session.emit(candidate, receipts=[verified["verification_receipt"]])
        encoded = session.encoding(candidate, candidate_build)
        require(encoded["checks"][0]["status"] == "proved", "actual buffer image failed rederivation")
        refinement = session.verify(candidate, claims=["lowering_refinement"], subject={
            "kind": "native_artifact", "backend_profile": session.backend,
            "native_artifact": candidate_build["native_artifact"], "build_receipt": candidate_build["build_receipt"]})
        require(refinement["checks"][0]["status"] == "unsupported", "general compiler refinement unexpectedly changed scope")
        receipts = [verified["verification_receipt"], encoded["verification_receipt"]]
        evaluation = session.evaluate(base_build, candidate_build, receipts=receipts)
        report.update(source_artifact=source, baseline=baseline, candidate=candidate,
            baseline_build=base_build, candidate_build=candidate_build, verification=verified,
            encoding=encoded, independent_machine_refinement=refinement, evaluation=evaluation)
        report["measurements"] = session.read_json(evaluation["measurements"])
        report["cost_ledger"] = session.read_json(evaluation["full_cost_ledger"])
        save()
        require(evaluation["outcome"] == "unchanged" and evaluation["planned_workload_complete"] is True,
                "the complete frozen compiler workload did not qualify")
        slot = prefix + "/nonproduction-compiler"
        adoption_arguments = session.arguments(target_slot=slot,
            expected_current={"generation": "0", "epoch": "0"},
            candidate_artifact=candidate_build["native_artifact"],
            evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts)
        adopted = client.result("hia_adopt", adoption_arguments)
        replay = client.result("hia_adopt", adoption_arguments)
        require(replay == adopted, "adoption did not recover the original retained operation")
        consumer = HIAAgentService(worker.state, artifact_roots=(compiler_source.parent,))
        lease = consumer.acquire_slot(slot)
        rollback = client.result("hia_rollback", session.arguments(target_slot=slot,
            expected_current=adopted["current"], retained_generation="0", reason="retain a nonproduction baseline for future calls"))
        invocation = consumer.invoke_lease(lease, "f0", cases[0]["arguments"])
        require(invocation["status"] == "returned" and invocation["generation"] == "1", "retained compiler lease did not execute")
        size = invocation["values"][0]
        require(0 < size <= 8192, "compiler did not return a bounded native image")
        emitted = session.read(next(row["artifact"] for row in invocation["buffers"] if row["argument"] == 1))[:size]
        image = output / "consumer-program.image.bin"
        image.write_bytes(emitted)
        runs = []
        for condition, expected in ((0, 4000000007), (1, 700000001), (255, 700000001)):
            result, observed = invoke(output, "consumer-" + str(condition), image, bytes([condition]), capacity=1, workspace_size=1)
            require(result["status"] == "returned" and result["core_u32"] == expected
                    and result["source_unchanged"] and observed == bytes([condition]), "new native select consumer disagreed")
            runs.append(result)
        current = consumer.acquire_slot(slot)
        require(current["generation"] == "0", "rollback changed an existing lease or failed to restore future acquisition")
        consumer.release_slot(current)
        consumer.release_slot(lease)
        try:
            consumer.invoke_lease(lease, "f0", cases[0]["arguments"])
        except AgentRejected as exc:
            require(exc.code == "E_HIA_LEASE", "released lease failed for an unrelated reason")
            released = {"status": "rejected", "code": exc.code}
        else:
            raise AssertionError("released compiler lease executed")
        require(installation_manifest() == worker.identities, "installed worker changed during qualification")
        require(sha256(compiler_source.read_bytes()).hexdigest() == expected_sha256, "frozen compiler source changed")
        report.update(status="PASS_SCOPED_NONPRODUCTION_LIFECYCLE", adoption=adopted,
            adoption_replay_identical=True, rollback=rollback, consumer_invocation=invocation,
            consumer_image={"byte_length": size, "sha256": sha256(emitted).hexdigest()},
            consumer_runs=runs, released_lease= released,
            acceptance_scope="same frozen Core activation; exact buffer workload, owned local worker and consumer generations only",
            remaining=["independent full compiler Core-to-machine proof", "production / remote MCP activation",
                       "original missing provider interaction and full cost evidence"])
    except Exception as exc:
        report.update(status="FAILED", error={"type": type(exc).__name__, "message": str(exc)[:4096]})
        raise
    finally:
        if consumer is not None:
            consumer.close()
        journal.close()
        report["worker_calls"] = worker.sequence
        report["wall_ns"] = str(time.monotonic_ns() - started)
        report["ended_at"] = datetime.now(timezone.utc).isoformat()
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler-source", type=Path, required=True)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.compiler_source, args.expected_source_sha256, args.output.resolve())
    print(json.dumps({"status": result["status"], "worker_calls": result["worker_calls"],
                     "compiler_source_sha256": result["compiler_source_sha256"], "wall_ns": result["wall_ns"]}))


if __name__ == "__main__":
    main()
