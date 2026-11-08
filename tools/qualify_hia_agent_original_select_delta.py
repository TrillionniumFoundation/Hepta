"""Recheck the real frozen select-compiler delta against the strict Agent gate.

This preserves the original baseline, candidate and patch identities. It never
substitutes a same-Core activation, weakens required claims, or adopts. A Core
VM counterexample is separate from a qualifying equivalence proof and from a
native evaluation receipt. Original provider interaction/costs are unavailable.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_store import wire
from tools.hia_agent_native_qualification import Session, ToolClient
from tools.qualify_hia_agent_buffer_lifecycle import PinnedWorker, PROGRAM, require

BASE_COMMIT = "d1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6"
BASE_SHA = "85288cfc4b649b2be13175675880f5372f16bf3d9c5d4b78ba21ffa2c90b6b44"
CANDIDATE_SHA = "2dd847d9df46392e4ef4b99c781b45f56c9841ae61127a260be6e8523f042845"
PATCH_SHA = "e74f3c27d6ea7e7ccfc1c9e2a4e7674fecabef08ee0e05236e5a6e2b5bd75cb4"
STRICT_CLAIMS = ["core_admission", "behavior_equivalence", "lowering_refinement", "encoding_check"]


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def vm_witness(directory, label, checked, case):
    """Retain the exact request/stdout/stderr of the existing isolated Core VM."""
    core_path = directory / (label + ".core.json")
    core_path.write_bytes(checked.canonical_bytes)
    request = {"artifact": str(core_path.resolve()), "artifact_sha256": checked.sha256,
        "signatures": {}, "cases": [case], "warmup": 0, "repetitions": 1,
        "mode": "reference", "foreign_buffer_exports": [["f0", 1 << 20]],
        "snapshot_files": [[]]}
    save(directory / (label + ".request.json"), request)
    command = [sys.executable, "-B", "-E", "-s", "-m", "hepta.hia_agent_runner",
               str(os.getpid()), str(512 * 1024 * 1024), "60"]
    started = time.monotonic_ns()
    process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(wire(request), timeout=60)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate(timeout=5)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=5)
        raise
    (directory / (label + ".stdout.json")).write_bytes(stdout)
    (directory / (label + ".stderr.log")).write_bytes(stderr)
    row = {"command": command, "timed_out": timed_out, "returncode": process.returncode,
        "wall_ns": time.monotonic_ns() - started, "request_sha256": sha256(wire(request)).hexdigest(),
        "stdout_sha256": sha256(stdout).hexdigest(), "stderr_sha256": sha256(stderr).hexdigest(),
        "core_sha256": checked.sha256, "native_code_executed": False}
    if not timed_out and process.returncode == 0:
        row["report"] = json.loads(stdout)
        require(row["report"]["artifact_sha256"] == checked.sha256, "VM subject differs")
    save(directory / (label + ".receipt.json"), row)
    return row


def run(original, candidate, patch, output):
    output.mkdir(parents=True, exist_ok=False)
    frozen = output / "frozen-inputs"
    frozen.mkdir()
    inputs, frozen_bytes = {}, {}
    for label, path, expected in (("original", original, BASE_SHA),
                                  ("candidate", candidate, CANDIDATE_SHA),
                                  ("patch", patch, PATCH_SHA)):
        data = path.read_bytes()
        require(sha256(data).hexdigest() == expected, "frozen input differs: " + label)
        target = frozen / (label + (".patch" if label == "patch" else ".hiaasm"))
        target.write_bytes(data)
        target.chmod(0o400)
        frozen_bytes[label] = data
        inputs[label] = {"path": str(target), "sha256": expected, "bytes": len(data)}
    # Apply the exact original multi-file patch only to its compiler-source
    # member. No patch reconstruction or current compiler substitution occurs.
    reconstruction = output / "patch-reconstruction"
    source_path = reconstruction / "examples/hia_bootstrap/selfhost.hiaasm"
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(frozen_bytes["original"])
    command = ["git", "apply", "--include=examples/hia_bootstrap/selfhost.hiaasm", inputs["patch"]["path"]]
    applied = subprocess.run(command, cwd=reconstruction, capture_output=True, timeout=30)
    (output / "patch-apply.stdout.log").write_bytes(applied.stdout)
    (output / "patch-apply.stderr.log").write_bytes(applied.stderr)
    require(applied.returncode == 0 and source_path.read_bytes() == frozen_bytes["candidate"],
            "the frozen patch does not reproduce the candidate compiler exactly")
    programs = {"original": assemble_program(frozen_bytes["original"]),
                "candidate": assemble_program(frozen_bytes["candidate"])}
    require(programs["original"].canonical_bytes != programs["candidate"].canonical_bytes,
            "a reflexive same-Core substitute is forbidden")
    worker = PinnedWorker(output, frozen)
    replay_sources = {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest()
                      for p in sorted((ROOT / "tools").glob("*.py"))}
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.agent.original-select-delta.v1", "status": "started",
        "started_at": datetime.now(timezone.utc).isoformat(), "original_source_commit": BASE_COMMIT,
        "frozen_inputs": inputs, "exact_patch_reconstruction": True,
        "installation": worker.identities, "original_study_rewritten": False,
        "new_fresh_agent_study": False, "same_core_substitution": False,
        "strict_claims_weakened": False, "production_adoption": False,
        "remote_mcp_endpoint_qualified": False, "provider_history_available": False,
        "provider_tokens": None, "provider_fees": None, "full_cost_complete": False,
        "canonical_subjects": {label: {"sha256": program.sha256,
            "schema": program.as_dict()["schema"], "functions": len(program.as_dict()["functions"])}
            for label, program in programs.items()},
        "replay_support_sources": replay_sources,
        "scope": "new strict reenactment on the exact original delta; not a replacement of its historical study"}
    journal = (output / "tool-transcript.jsonl").open("x")

    def record(row):
        journal.write(json.dumps(row, sort_keys=True) + "\n")
        journal.flush()
        os.fsync(journal.fileno())

    client = ToolClient(worker.call, journal=record)
    try:
        session = Session(client, prefix="original-select-delta/" + sha256(str(output).encode()).hexdigest()[:16])
        case = {"function": "f0", "arguments": [
            {"bytes_hex": PROGRAM.hex()}, {"byte_length": 8192, "fill_byte": 165},
            {"byte_length": 1 << 20, "fill_byte": 0}]}
        workload = {"schema": "hepta.hia.agent.workload.v2",
            "foreign_buffer_exports": [{"function": "f0", "max_buffer_bytes": 1 << 20}],
            "cases": [case], "warmup_iterations": 0, "repetitions": 1}
        objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": STRICT_CLAIMS, "allow_unchanged": True, "min_improvement_ratio": 0}
        report.update(frozen_workload=workload, frozen_objective=objective)
        (output / "select-counterexample.hiaasm").write_bytes(PROGRAM)
        save(output / "qualification.json", report)
        session.freeze(workload, objective=objective, budget={"max_native_wall_ms": 60000})

        def import_source(label):
            source = client.result("hia_artifact", session.arguments(context=False,
                artifact_profile=session.profiles["artifact"], source={"kind": "path",
                    "path": inputs[label]["path"], "expected_sha256": inputs[label]["sha256"],
                    "max_bytes": inputs[label]["bytes"]}))["artifact"]
            return client.result("hia_candidate", session.arguments(change={
                "kind": "import", "format": "hia-asm.v1", "source": source}))["candidate"]

        baseline = import_source("original")
        session.freeze(workload, baseline=baseline, objective=objective, budget={"max_native_wall_ms": 60000})
        revised = import_source("candidate")
        verified = session.verify(revised, base=baseline, claims=["core_admission", "behavior_equivalence"])
        statuses = {row["claim"]: row["status"] for row in verified["checks"]}
        require(statuses["core_admission"] == "proved" and statuses["behavior_equivalence"] != "proved",
                "the real extension must not be relabelled as all-input equivalence")
        report.update(baseline=baseline, candidate=revised, verification=verified)
        save(output / "qualification.json", report)
        builds = {"baseline": session.emit(baseline),
                  "candidate": session.emit(revised, receipts=[verified["verification_receipt"]])}
        encoded = session.encoding(revised, builds["candidate"])
        refined = session.verify(revised, claims=["lowering_refinement"], subject={
            "kind": "native_artifact", "backend_profile": session.backend,
            "native_artifact": builds["candidate"]["native_artifact"],
            "build_receipt": builds["candidate"]["build_receipt"]})
        require(encoded["checks"][0]["status"] == "proved", "exact encoding rederivation failed")
        receipts = [verified["verification_receipt"], encoded["verification_receipt"], refined["verification_receipt"]]
        evaluation = client.call("hia_evaluate", session.arguments(
            baseline_artifact=builds["baseline"]["native_artifact"],
            candidate_artifact=builds["candidate"]["native_artifact"],
            build_receipt=builds["candidate"]["build_receipt"], verification_receipts=receipts),
            expected_status="rejected")
        require(evaluation["error"]["code"] == "E_HIA_CLAIM_REQUIRED", "strict evaluation stopped for an unrelated reason")
        report.update(builds=builds, encoding=encoded, native_refinement=refined,
            evaluation_response=evaluation, adoption_attempted=False, adoption_authorized=False)
        save(output / "qualification.json", report)
        # A finite Core-VM difference explains why whole-domain equality is
        # the wrong property for an intentional language extension. It grants
        # neither a positive proof receipt nor an evaluation/adoption receipt.
        references = {label: vm_witness(output, "counterexample-" + label, program, case)
                      for label, program in programs.items()}
        for row in references.values():
            require(row.get("report", {}).get("complete") is True, "counterexample VM did not complete")
            require(row["report"]["native_code_executed"] is False, "counterexample bypassed into native execution")
        before = references["original"]["report"]["observations"][0]
        after = references["candidate"]["report"]["observations"][0]
        require(before["status"] == after["status"] == "returned" and before["values"] == [4294967295]
                and len(after["values"]) == 1 and 0 < after["values"][0] <= 8192,
                "the actual frozen delta lacks the expected select-extension difference")
        with sqlite3.connect("file:" + str(worker.state / "state.sqlite3") + "?mode=ro", uri=True) as db:
            slots = db.execute("SELECT COUNT(*) FROM slots").fetchone()[0]
            leases = db.execute("SELECT COUNT(*) FROM leases").fetchone()[0]
        require(slots == leases == 0 and not any(row["tool"] == "hia_adopt" for row in client.records),
                "strictly blocked delta must not create an adopted generation")
        require(installation_manifest() == worker.identities, "worker identity changed during replay")
        require(all(sha256((ROOT / name).read_bytes()).hexdigest() == expected
                    for name, expected in replay_sources.items()), "replay support source changed")
        require(all(sha256(Path(row["path"]).read_bytes()).hexdigest() == row["sha256"]
                    for row in inputs.values()), "frozen input changed")
        report.update(status="HOLD_REAL_DELTA_STRICT_GATE", counterexample=references,
            select_input_result={"original": before["values"], "candidate": after["values"]},
            empty_slot_count=slots, empty_lease_count=leases,
            desired_unimplemented_properties=["preservation over the original supported source domain",
                "new select-domain admission and emitted behavior conform to the select specification"],
            remaining=["no positive strict behavior-equivalence receipt for this intentional semantic extension",
                "no general compiler Core-to-machine refinement proof",
                "no language-extension proof property in the current four-claim acceptance interface",
                "original provider interaction and complete cost evidence remain unavailable"])
    except Exception as exc:
        report.update(status="FAILED_REPLAY", error={"type": type(exc).__name__, "message": str(exc)[:4096]})
        raise
    finally:
        journal.close()
        report.update(worker_calls=worker.sequence, wall_ns=time.monotonic_ns() - started,
            ended_at=datetime.now(timezone.utc).isoformat(),
            replay_source_sha256=sha256(Path(__file__).read_bytes()).hexdigest())
        save(output / "qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.original.resolve(), args.candidate.resolve(), args.patch.resolve(), args.output.resolve())
    print(json.dumps({"status": report["status"], "worker_calls": report["worker_calls"],
        "select_input_result": report["select_input_result"], "adoption_attempted": report["adoption_attempted"]}))


if __name__ == "__main__":
    main()
