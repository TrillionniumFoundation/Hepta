"""Pure-data readback of every actual v5 admission refusal/positive child."""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tools.read_hia_slot_mechanical_installed import Captures, need, integer, same, owned
from tests.hia_slot_operations_qualification_support import write_json, unique_pairs


def readback(evidence, product_root, freeze, freeze_sha256):
    evidence, product_root, freeze = Path(evidence), Path(product_root), Path(freeze)
    captured = Captures()
    try:
        producer = captured.json(evidence / "report.json")
        plan = captured.json(evidence / "planned.json")
        need(producer["schema"] == "hepta.slot.mechanical.admission-controls.v1"
             and producer["status"] == "PASS" and producer["failures"] == []
             and producer["source_stable"] is True, "complete actual controls did not succeed")
        raw = captured.raw(freeze)
        need(sha256(raw).hexdigest() == freeze_sha256, "external source freeze differs")
        fixed = json.loads(raw, object_pairs_hook=unique_pairs)
        need(fixed["schema"] == "hepta.slot-operations.qualification-source-freeze.v1",
             "wrong source freeze schema")
        same(fixed["files"], producer["source_before"])
        same(plan["source_before"], fixed["files"])
        for name, expected in fixed["files"].items():
            need(not Path(name).is_absolute() and ".." not in Path(name).parts, "unsafe source")
            captured.raw(product_root / name, expected)
        controls_path = product_root / "tests/hia_slot_mechanical_admission_controls.py"
        tree = ast.parse(captured.raw(controls_path))
        declarations = [node for node in tree.body if isinstance(node, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "CASES" for t in node.targets)]
        need(len(declarations) == 1, "fixed actual control declaration absent")
        cases = ast.literal_eval(declarations[0].value)
        names = [row[0] for row in cases]
        need(len(names) == len(set(names)) == 25, "complete v5 controls changed")
        for field in ("planned", "started", "stopped"):
            same(producer[field], names)
        same(plan["cases"], names)
        integer(plan["case_seconds"], 60)
        integer(plan["outer_seconds"], 1800)
        need(plan["fresh_process_per_case"] is True and plan["original_Native6_replaced"] is False,
             "new control scheduling/scope differs")
        need(producer["original_Native6_replaced"] is False
             and producer["whole_native_stack_qualified"] is False, "original qualification was replaced")
        same([row["case"] for row in producer["commands"]], names)
        same([row["case"] for row in producer["observations"]], names)
        base = producer["base_bundle"]
        captured.raw(base["path"], {k: base[k] for k in ("bytes", "sha256")})
        source_capsule = producer["source_capsule"]
        capsule = captured.json(source_capsule["path"],
                                {k: source_capsule[k] for k in ("bytes", "sha256")})
        need(capsule["schema"] == "hepta.hia.native-helpers.v5", "source executable capsule differs")
        source_bridge, = capsule["bridges"]
        same(producer["package_inputs"], [source_bridge["build_receipt"], source_bridge["binary"],
                                          *source_bridge["sources"].values()])
        for item in producer["package_inputs"]:
            captured.raw(item["path"], {k: item[k] for k in ("bytes", "sha256")})
        details = []
        for (name, expected_error, loaded), command_row, observation in zip(
                cases, producer["commands"], producer["observations"]):
            command, stdout, stderr = owned(captured, evidence / ("child-" + name),
                                           command_row["result"], 60)
            path = evidence / name / "report.json"
            need(observation["path"] == str(path), "actual child report path differs")
            row = captured.json(path, {k: observation[k] for k in ("bytes", "sha256")})
            need(row["schema"] == "hepta.slot.mechanical.admission-case.v1"
                 and row["status"] == "PASS" and row["case"] == name,
                 "wrong actual admission child")
            same(row["expected_error"], expected_error)
            need(row["expected_loaded"] is loaded
                 and row["fixture_admin_pins_explicit"] is True
                 and row["original_Native6_replaced"] is False
                 and row["whole_native_stack_qualified"] is False, "control scope changed")
            integer(row["pid"], command["pid"])
            integer(row["pgid"], command["pgid"])
            integer(row["ppid"], command["parent_pid"])
            same(row["argv"], command["argv"][3:])
            same(row["base_bundle"], base)
            same(row["source_capsule"], source_capsule)
            need(len(row["linker_calls"]) == (1 if loaded else 0), "actual linker boundary differs")
            for call in row["linker_calls"]:
                need(call["name"] == "hepta._hia_slot_mechanical"
                     and call["origin"].startswith("/proc/self/fd/")
                     and call["origin"].removeprefix("/proc/self/fd/").isdecimal(),
                     "linker consumed an unsealed pathname")
            if expected_error is None:
                need(row["error"] is None, "unexpected child error")
            else:
                kind, text = expected_error.split(":", 1)
                need(row["error"]["type"] == "builtins." + kind
                     and text in row["error"]["message"] and row["error"]["traceback"],
                     "observed rejection is not the intended boundary")
            if name == "healthy":
                need(row["terminal"] == {"native_helpers_sha256": row["supplied_expected_sha256"]},
                     "positive actual scope lacked terminal attestation")
                integer(row["live"]["ports"], 136)
                integer(row["live"]["modes"], 15)
                integer(row["live"]["seals"], 15)
            if name in ("write-failure", "seal-readback-failure", "receipt-last-boundary-drift", "close-failure-no-retry"):
                need(len(row["close_calls"]) == 1, "created descriptor was not closed exactly once")
            details.append({"case": name, "loaded": loaded, "report": observation,
                            "linker_calls": row["linker_calls"], "actual_error": row["error"]})
        captured.stable()
        return {"schema": "hepta.slot.mechanical.admission-readback.v1", "status": "PASS",
                "cases": details, "source_stable": True, "actual_inputs": captured.pins(),
                "original_Native6_replaced": False, "whole_native_stack_qualified": False}
    except Exception as error:
        return {"schema": "hepta.slot.mechanical.admission-readback.v1", "status": "HOLD",
                "failure": {"type": type(error).__name__, "message": str(error)},
                "actual_inputs": captured.pins(), "original_Native6_replaced": False,
                "whole_native_stack_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "product-root", "product-freeze", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--product-freeze-sha256", required=True)
    args = parser.parse_args()
    report = readback(args.evidence, args.product_root, args.product_freeze,
                      args.product_freeze_sha256)
    args.output.mkdir(parents=True, exist_ok=False)
    write_json(args.output / "READBACK.json", report)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
