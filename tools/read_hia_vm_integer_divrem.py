"""Data-only full div/rem finite readback, including both raw traceback streams."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tests.hia_vm_integer_divrem_cases import canonical, pin, decode, cases, source_capture, stable


class Capture:
    def __init__(self):
        self.raw = {}

    def take(self, path, expected=None):
        path = Path(path).resolve(strict=True)
        raw = path.read_bytes()
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("finite readback file exceeds the declared data-only extent")
        if path in self.raw and self.raw[path] != raw:
            raise ValueError("consumed evidence changed on a repeated read")
        if expected is not None and pin(raw) != expected:
            raise ValueError("consumed raw bytes differ from their earlier authority")
        self.raw[path] = raw
        return raw

    def document(self, path, expected=None):
        return decode(self.take(path, expected))

    def stable(self):
        if any(path.read_bytes() != raw for path, raw in self.raw.items()):
            raise ValueError("consumed evidence changed after parsing")

    def ledger(self):
        return {str(path): pin(raw) for path, raw in self.raw.items()}


def _rows(raw, planned):
    lines = raw.splitlines(keepends=True)
    if len(lines) != len(planned) or any(not line.endswith(b"\n") for line in lines):
        raise ValueError("finite stream is incomplete")
    values = [decode(line) for line in lines]
    if any(canonical(value) != line for value, line in zip(values, lines)):
        raise ValueError("finite stream canonical byte encoding differs")
    if [row["id"] for row in values] != planned:
        raise ValueError("finite stream order or complete domain differs")
    return values


def read_evidence(directory, manifest_path, manifest_sha256, producer_report_sha256):
    directory = Path(directory)
    capture = Capture()
    current = source_capture()
    inputs_raw, rows = cases()
    planned = [row["id"] for row in rows]
    manifest_raw = capture.take(manifest_path)
    if sha256(manifest_raw).hexdigest() != manifest_sha256:
        raise ValueError("explicit manifest authority differs")
    manifest = decode(manifest_raw)
    image = Path(manifest_path).resolve().parent / manifest["image_path"]
    if image.name != "vm-integer-divrem.image.bin" or image.parent != Path(manifest_path).resolve().parent:
        raise ValueError("finite image path escapes its fixed directory")
    image_raw = capture.take(image)
    if sha256(image_raw).hexdigest() != manifest["image_sha256"]:
        raise ValueError("finite selected executable differs")
    producer_raw = capture.take(directory / "report.json")
    if sha256(producer_raw).hexdigest() != producer_report_sha256:
        raise ValueError("producer report differs from its external pin")
    producer = decode(producer_raw)
    plan = capture.document(directory / "PLAN.json", producer["plan_pin"])
    if (plan["planned"] != planned or plan["case_inputs"] != pin(inputs_raw)
            or plan["source_pins"] != {k: pin(v) for k, v in current.items()}
            or plan["manifest_sha256"] != manifest_sha256
            or plan["lane_seconds"] != 600
            or plan["lane_order"] != ["original-first", "original-second", "native"]):
        raise ValueError("finite plan differs from the complete frozen inputs/source")
    expected_raw = capture.take(directory / "EXPECTATIONS-FROZEN.json",
                                producer["expectations_pin"])
    expected = decode(expected_raw)
    if (expected["schema"] != "hepta.hia.vm-integer-divrem-originals.v1"
            or expected["plan_pin"] != pin(canonical(plan))
            or expected["candidate_not_started"] is not True
            or expected["planned"] != planned):
        raise ValueError("original-first frozen boundary differs")
    observed, traces = {}, {}
    commands = []
    for label in plan["lane_order"]:
        path = directory / label
        receipt_raw = capture.take(directory / (label + ".receipt.json"),
                                   producer["receipt_pins"][label])
        receipt = decode(receipt_raw)
        command = [sys.executable, str(ROOT / "tests/hia_vm_integer_divrem_cases.py"),
                   "--mode", "finite", "--lane", "native" if label == "native" else "original",
                   "--output", str(path)]
        if label == "native":
            command += ["--manifest", str(Path(manifest_path)), "--manifest-sha256", manifest_sha256]
        if (receipt["schema"] != "hepta.hia.external-workflow-process.v1"
                or receipt["command"] != command or receipt["cwd"] != str(ROOT)
                or receipt["status"] != "WORKFLOW_STEP_COMPLETED"
                or type(receipt["returncode"]) is not int or receipt["returncode"] != 0
                or receipt["timed_out"] is not False
                or receipt["workflow_seconds"] != 600
                or receipt["cleanup"]["complete"] is not True or receipt["cleanup"]["errors"]
                or receipt["cleanup"]["full_process_tree_claimed"] is not False):
            raise ValueError("finite owned process receipt differs or is incomplete")
        for name in ("stdout", "stderr"):
            logpath = directory / (label + "." + name + ".log")
            raw = capture.take(logpath)
            if sha256(raw).hexdigest() != receipt["logs"].get(str(logpath)):
                raise ValueError("finite process log pin differs")
        report_pin = (expected["lanes"][label]["report"] if label != "native"
                      else producer["candidate_report_pin"])
        report_raw = capture.take(path / "report.json", report_pin)
        report = decode(report_raw)
        if (report["status"] != "OBSERVED_COMPLETE_DOMAIN"
                or report["planned"] != 2500 or report["completed"] != 2500
                or report["source_pins"] != plan["source_pins"]
                or report["case_inputs"] != pin(inputs_raw)
                or report["lane"] != ("native" if label == "native" else "original")
                or report["runtime"] != producer["runtime"]):
            raise ValueError("finite observation report differs")
        if label == "native":
            if (report["manifest_sha256"] != manifest_sha256
                    or report["delivery"] != {"native_returns": 2500, "acknowledgements": 2500}):
                raise ValueError("selected finite real-return/ACK inventory differs")
        elif report["manifest_sha256"] is not None or report["delivery"] is not None:
            raise ValueError("an original-only lane selected a candidate image")
        plan_raw = capture.take(path / "planned.json", report["streams"]["planned.json"])
        if decode(plan_raw) != planned:
            raise ValueError("lane inventory differs")
        obs_raw = capture.take(path / "observations.jsonl", report["streams"]["observations.jsonl"])
        tb_raw = capture.take(path / "raw-tracebacks.jsonl", report["streams"]["raw-tracebacks.jsonl"])
        if label != "native" and (pin(obs_raw) != expected["lanes"][label]["observations"]
                                 or pin(tb_raw) != expected["lanes"][label]["raw_tracebacks"]):
            raise ValueError("original stream differs from the pre-candidate freeze")
        observed[label], traces[label] = _rows(obs_raw, planned), _rows(tb_raw, planned)
        commands.append(command)
    if canonical(observed["original-first"]) != canonical(observed["original-second"]):
        raise ValueError("the two complete original observation passes differ")
    if canonical(traces["original-first"]) != canonical(traces["original-second"]):
        raise ValueError("the two original raw traceback passes differ")
    differences = [planned[i] for i in range(2500)
                   if canonical(observed["original-first"][i]) != canonical(observed["native"][i])]
    raw_differences = [planned[i] for i in range(2500)
                      if canonical(traces["original-first"][i]) != canonical(traces["native"][i])]
    if (producer["semantic_difference_ids"] != differences
            or producer["raw_traceback_difference_ids"] != raw_differences
            or producer["status"] != ("PASS_VALUE_TRAP_REPORT_DOMAIN_ONLY" if not differences else "HOLD")):
        raise ValueError("producer summary does not match the complete raw streams")
    difference_raw = capture.take(directory / "semantic-differences.jsonl",
                                  producer["semantic_differences_pin"])
    difference_rows = [decode(line) for line in difference_raw.splitlines()]
    exact_differences = [
        {"id": planned[i], "original": observed["original-first"][i],
         "candidate": observed["native"][i]}
        for i in range(2500) if planned[i] in set(differences)]
    if canonical(difference_rows) != canonical(exact_differences):
        raise ValueError("complete semantic difference stream differs")
    stable(current)
    capture.stable()
    return {
        "schema": "hepta.hia.vm-integer-divrem-readback.v1",
        "evidence_integrity": "PASS",
        "qualification": "PASS_VALUE_TRAP_REPORT_DOMAIN_ONLY" if not differences else "HOLD",
        "planned": 2500, "complete_original_passes": 2, "complete_candidate_passes": 1,
        "semantic_difference_ids": differences, "raw_traceback_difference_ids": raw_differences,
        "raw_traceback_status": "DIFFERENT_RETAINED_OPEN" if raw_differences else "EQUAL_IN_THIS_DOMAIN",
        "producer_report": pin(producer_raw), "expectations": pin(expected_raw),
        "consumed": capture.ledger(), "commands": commands,
        "whole_vm_native": False, "whole_stack_rewritten_in_hia": False,
        "all_input_equivalence_proved": False, "remove_original_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--producer-report-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = read_evidence(args.evidence, args.manifest, args.manifest_sha256,
                               args.producer_report_sha256)
    except Exception as error:
        report = {"schema": "hepta.hia.vm-integer-divrem-readback.v1",
                  "evidence_integrity": "HOLD", "qualification": "HOLD",
                  "error": {"module": type(error).__module__, "type": type(error).__qualname__,
                            "message": str(error)},
                  "whole_vm_native": False, "all_input_equivalence_proved": False}
    with args.output.open("xb") as stream:
        stream.write(canonical(report))
    print(json.dumps({"evidence_integrity": report["evidence_integrity"],
                      "qualification": report["qualification"]}))
    if report["evidence_integrity"] != "PASS" or report["qualification"] == "HOLD":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
