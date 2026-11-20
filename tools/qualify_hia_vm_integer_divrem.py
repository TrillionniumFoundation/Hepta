"""Bounded original-original-freeze-native qualification for the explicit slice."""
from __future__ import annotations
import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tests.hia_vm_integer_divrem_cases import canonical, pin, decode, cases, source_capture, stable

SUPERVISOR = ROOT / "review-evidence/hia-native-rewrite-20261111/workflow_process.py"
SUPERVISOR_SHA256 = "f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80"


def supervisor():
    raw = SUPERVISOR.read_bytes()
    if sha256(raw).hexdigest() != SUPERVISOR_SHA256:
        raise ValueError("retained external workflow process owner differs")
    spec = importlib.util.spec_from_file_location("_divrem_original_workflow_process", SUPERVISOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if SUPERVISOR.read_bytes() != raw:
        raise ValueError("workflow process owner changed during loading")
    return module.run_workflow_step, raw


def qualify(directory, manifest_path, manifest_sha256):
    directory, manifest_path = Path(directory), Path(manifest_path).resolve(strict=True)
    directory.mkdir(mode=0o700)
    run, owner_raw = supervisor()
    captured = source_capture()
    input_raw, rows = cases()
    manifest_raw = manifest_path.read_bytes()
    if sha256(manifest_raw).hexdigest() != manifest_sha256:
        raise ValueError("explicit candidate manifest digest differs")
    planned = [row["id"] for row in rows]
    plan = {
        "schema": "hepta.hia.vm-integer-divrem-plan.v1",
        "planned": planned, "case_inputs": pin(input_raw),
        "source_pins": {k: pin(v) for k, v in captured.items()},
        "supervisor_pin": pin(owner_raw), "manifest_sha256": manifest_sha256,
        "lane_order": ["original-first", "original-second", "native"], "lane_seconds": 600,
        "whole_vm_native": False, "all_input_equivalence_proved": False,
    }
    plan_raw = canonical(plan)
    (directory / "PLAN.json").write_bytes(plan_raw)
    env = {k: v for k, v in os.environ.items()
           if not (k.startswith("HEPTA_HIA_") or k.startswith("PYTHON"))}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    receipts, receipt_pins = {}, {}
    def lane(label):
        command = [sys.executable, str(ROOT / "tests/hia_vm_integer_divrem_cases.py"),
                   "--mode", "finite", "--lane", "native" if label == "native" else "original",
                   "--output", str(directory / label)]
        if label == "native":
            command += ["--manifest", str(manifest_path), "--manifest-sha256", manifest_sha256]
        receipt_path = directory / (label + ".receipt.json")
        receipt = run(command, cwd=ROOT, env=env,
            stdout_path=directory / (label + ".stdout.log"),
            stderr_path=directory / (label + ".stderr.log"),
            receipt_path=receipt_path, seconds=600)
        raw = receipt_path.read_bytes()
        if decode(raw) != receipt:
            raise ValueError("workflow receipt raw binding differs")
        receipts[label], receipt_pins[label] = receipt, pin(raw)
        return receipt["status"] == "WORKFLOW_STEP_COMPLETED"
    first = lane("original-first")
    second = lane("original-second")
    if not first or not second:
        raise RuntimeError("complete original lane failed; candidate not started")
    originals = {}
    for label in ("original-first", "original-second"):
        path = directory / label
        raw = (path / "report.json").read_bytes()
        report = decode(raw)
        streams = {name: (path / name).read_bytes() for name in
                   ("planned.json", "observations.jsonl", "raw-tracebacks.jsonl")}
        if (report["completed"] != 2500 or decode(streams["planned.json"]) != planned
                or any(pin(value) != report["streams"][name] for name, value in streams.items())
                or report["source_pins"] != plan["source_pins"]):
            raise ValueError("complete original evidence raw binding differs")
        originals[label] = {"report": pin(raw),
            "observations": pin(streams["observations.jsonl"]),
            "raw_tracebacks": pin(streams["raw-tracebacks.jsonl"])}
    for key in ("observations", "raw_tracebacks"):
        if originals["original-first"][key] != originals["original-second"][key]:
            raise ValueError("complete independent original passes differ")
    expected = {"schema": "hepta.hia.vm-integer-divrem-originals.v1",
                "plan_pin": pin(plan_raw), "planned": planned,
                "candidate_not_started": True, "lanes": originals}
    expected_raw = canonical(expected)
    (directory / "EXPECTATIONS-FROZEN.json").write_bytes(expected_raw)
    if not lane("native"):
        raise RuntimeError("complete candidate lane failed; original evidence retained")
    candidate_raw = (directory / "native/report.json").read_bytes()
    original_rows = [decode(line) for line in (directory / "original-first/observations.jsonl").read_bytes().splitlines()]
    candidate_rows = [decode(line) for line in (directory / "native/observations.jsonl").read_bytes().splitlines()]
    original_tb = [decode(line) for line in (directory / "original-first/raw-tracebacks.jsonl").read_bytes().splitlines()]
    candidate_tb = [decode(line) for line in (directory / "native/raw-tracebacks.jsonl").read_bytes().splitlines()]
    if any([row["id"] for row in domain] != planned for domain in
           (original_rows, candidate_rows, original_tb, candidate_tb)):
        raise ValueError("complete final domain differs")
    differences, raw_differences = [], []
    with (directory / "semantic-differences.jsonl").open("xb") as output:
        for a, b, ta, tb in zip(original_rows, candidate_rows, original_tb, candidate_tb):
            if canonical(a) != canonical(b):
                differences.append(a["id"])
                output.write(canonical({"id": a["id"], "original": a, "candidate": b}))
            if canonical(ta) != canonical(tb):
                raw_differences.append(a["id"])
    stable(captured)
    if (manifest_path.read_bytes() != manifest_raw or SUPERVISOR.read_bytes() != owner_raw
            or (directory / "EXPECTATIONS-FROZEN.json").read_bytes() != expected_raw):
        raise ValueError("qualification authority changed")
    report = {
        "schema": "hepta.hia.vm-integer-divrem-qualification.v1",
        "status": "PASS_VALUE_TRAP_REPORT_DOMAIN_ONLY" if not differences else "HOLD",
        "plan_pin": pin(plan_raw), "expectations_pin": pin(expected_raw),
        "candidate_report_pin": pin(candidate_raw), "receipt_pins": receipt_pins,
        "semantic_difference_ids": differences, "raw_traceback_difference_ids": raw_differences,
        "semantic_differences_pin": pin((directory / "semantic-differences.jsonl").read_bytes()),
        "runtime": {"version": sys.version, "executable": sys.executable},
        "whole_vm_native": False, "all_input_equivalence_proved": False,
    }
    (directory / "report.json").write_bytes(canonical(report))
    # A second implementation consumes every original/actual stream and all
    # original owned-process receipts. This does not run any producer.
    from tools.read_hia_vm_integer_divrem import read_evidence
    checked = read_evidence(directory, manifest_path, manifest_sha256,
                            sha256((directory / "report.json").read_bytes()).hexdigest())
    (directory / "independent-readback.json").write_bytes(canonical(checked))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    report = qualify(args.output, args.manifest, args.manifest_sha256)
    print(json.dumps({"status": report["status"]}))
    if report["status"] == "HOLD":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
