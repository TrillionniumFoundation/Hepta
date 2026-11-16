"""Run every declared v5 admission case in a separate owned fresh process."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    admit_product, canonical, clean_environment, regular_bytes, pin, run_owned, successful_exit, write_json)
from tests.hia_slot_mechanical_admission_controls import CASES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "base-v1", "bridge-bundle", "product-freeze", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--base-sha256", required=True)
    parser.add_argument("--expected-bridge-sha256", required=True)
    parser.add_argument("--product-freeze-sha256", required=True)
    args = parser.parse_args()
    before = admit_product(ROOT, args.product_freeze, args.product_freeze_sha256)
    base_raw = regular_bytes(args.base_v1)
    if sha256(base_raw).hexdigest() != args.base_sha256:
        raise ValueError("supplied original v1 fixture digest differs")
    bridge_raw = regular_bytes(args.bridge_bundle)
    if sha256(bridge_raw).hexdigest() != args.expected_bridge_sha256:
        raise ValueError("explicit source administrator capsule differs")
    bridge = json.loads(bridge_raw)["bridges"][0]
    if bridge["package_path"] != str(args.package.resolve(strict=True)):
        raise ValueError("explicit source package path differs")
    package_inputs = [bridge["build_receipt"], bridge["binary"], *bridge["sources"].values()]
    for item in package_inputs:
        if pin(item["path"]) != {k: item[k] for k in ("bytes", "sha256")}:
            raise ValueError("explicit source executable receipt/closure differs")
    bridge_pin = {"path": str(args.bridge_bundle), "bytes": len(bridge_raw),
                  "sha256": args.expected_bridge_sha256}
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    commands, observations, failures = [], [], []
    write_json(args.evidence / "planned.json", {"cases": [row[0] for row in CASES],
        "case_seconds": 60, "outer_seconds": 1800, "fresh_process_per_case": True,
        "original_Native6_replaced": False, "source_before": before})
    for name, expected_error, expected_loaded in CASES:
        output = args.evidence / name
        command = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_slot_mechanical_admission_controls.py"),
            "--root", str(ROOT), "--package", str(args.package), "--base-v1", str(args.base_v1),
            "--base-sha256", args.base_sha256,
            "--source-capsule", str(args.bridge_bundle),
            "--source-capsule-sha256", args.expected_bridge_sha256,
            "--case", name, "--evidence", str(output)]
        result = run_owned(command, cwd=ROOT, directory=args.evidence / ("child-" + name),
                           timeout_seconds=60, environment=clean_environment())
        commands.append({"case": name, "result": result})
        try:
            if not successful_exit(result):
                raise ValueError("actual admission control did not naturally finish")
            path = output / "report.json"
            raw = regular_bytes(path)
            row = json.loads(raw)
            if (row["schema"] != "hepta.slot.mechanical.admission-case.v1" or row["status"] != "PASS"
                    or row["case"] != name or row["expected_error"] != expected_error
                    or row["expected_loaded"] is not expected_loaded or row["pid"] != result["pid"]
                    or row["pgid"] != result["pid"] or row["argv"] != command[3:]
                    or row["source_capsule"] != bridge_pin
                    or regular_bytes(path) != raw):
                raise ValueError("actual control report/source boundary differs")
            observations.append({"case": name, "path": str(path), "bytes": len(raw),
                                 "sha256": sha256(raw).hexdigest()})
        except Exception as error:
            failures.append({"case": name, "type": type(error).__name__, "message": str(error)})
    stable = admit_product(ROOT, args.product_freeze, args.product_freeze_sha256) == before
    stable = (stable and regular_bytes(args.base_v1) == base_raw
              and regular_bytes(args.bridge_bundle) == bridge_raw
              and all(pin(item["path"]) == {k: item[k] for k in ("bytes", "sha256")}
                      for item in package_inputs))
    for row in observations:
        if pin(row["path"]) != {k: row[k] for k in ("bytes", "sha256")}:
            raise ValueError("control report changed before aggregate")
    report = {"schema": "hepta.slot.mechanical.admission-controls.v1",
        "status": "PASS" if stable and not failures else "HOLD",
        "planned": [row[0] for row in CASES], "started": [row["case"] for row in commands],
        "stopped": [row["case"] for row in commands],
        "commands": commands, "observations": observations, "failures": failures,
        "source_before": before, "source_stable": stable, "source_capsule": bridge_pin,
        "package_inputs": package_inputs,
        "product_freeze": {"path": str(args.product_freeze), **pin(args.product_freeze)},
        "base_bundle": {"path": str(args.base_v1), **pin(args.base_v1)},
        "original_Native6_replaced": False, "whole_native_stack_qualified": False}
    write_json(args.evidence / "report.json", report)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
