"""Pure-data independent readback of the complete dual-route owned children."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tools.read_hia_slot_mechanical_installed import (
    Captures, capture_capsule, owned, need, same, digest)
from tools.read_hia_slot_mechanical_observations import mechanical_counters
from tests.hia_slot_operations_qualification_support import unique_pairs, write_json

def readback(evidence, product_root, freeze, freeze_sha256):
    evidence, product_root, freeze = map(Path, (evidence, product_root, freeze))
    captured = Captures()
    report = captured.json(evidence / "report.json")
    need(report["schema"] == "hepta.slot.mechanical.routes.v1"
         and report["status"] == "PASS" and report["failures"] == []
         and report["original_domains_replaced"] is False
         and report["whole_native_stack_qualified"] is False, "route producer incomplete")
    source_raw = captured.raw(freeze)
    need(sha256(source_raw).hexdigest() == freeze_sha256, "actual source freeze differs")
    source = json.loads(source_raw, object_pairs_hook=unique_pairs)
    need(source["schema"] == "hepta.slot-operations.qualification-source-freeze.v1", "source schema differs")
    for relative, expected in source["files"].items():
        need(not Path(relative).is_absolute() and ".." not in Path(relative).parts, "unsafe source name")
        captured.raw(product_root / relative, expected)
    cases = captured.json(product_root / "tests/fixtures/slot_mechanical_dual_route_cases.json")["cases"]
    need(len(cases) == 17 and len(cases) == len(set(cases)), "route scope differs")
    for field in ("planned", "started", "stopped"):
        same(report[field], cases)
    same([row["case"] for row in report["commands"]], cases)
    same(report["product_freeze"], {"path": str(freeze), "sha256": freeze_sha256})
    base_raw = captured.raw(report["base_v1"]["path"])
    need(sha256(base_raw).hexdigest() == report["base_v1"]["sha256"], "base v1 identity differs")
    base = json.loads(base_raw, object_pairs_hook=unique_pairs)
    need(base["schema"] == "hepta.hia.native-helpers.v1", "legacy input was implicitly upgraded")
    selection = [x for x in base["helpers"] if x["selector"] == "HEPTA_HIA_SLOT_OPERATIONS_MANIFEST"]
    need(len(selection) == 1 and selection[0]["manifest_path"] == report["controller"],
         "actual selected controller differs")
    admin = report["v5"]
    capsule, bridge = capture_capsule(captured, admin["path"],
        {k: admin[k] for k in ("bytes", "sha256")}, product_root)
    need(capsule["helpers_bundle"] == report["base_v1"]["path"]
         and capsule["helpers_bundle_sha256"] == report["base_v1"]["sha256"],
         "two routes do not share the explicitly pinned HIA helper input")
    legacy_ok = {"direct-env", "explicit-owner", "v1-scope", "v1-unprimed-to-v5",
                 "raw-frame-legacy", "new-v1-after-v5"}
    c_ok = {"v5-live", "v5-equivalent-scope", "v5-original-provider-error"}
    refused = set(cases) - legacy_ok - c_ok - {"v5-real-receipt-loss"}
    read = []
    for row in report["commands"]:
        name = row["case"]
        child = evidence / name
        command, stdout, stderr = owned(captured, child / "owned", row["result"], 60)
        expected_argv = [command["argv"][0], "-I", "-B",
            str(product_root / "tests/hia_slot_mechanical_route_controls.py"),
            "--case", name, "--controller", report["controller"],
            "--base-v1", report["base_v1"]["path"], "--base-sha256", report["base_v1"]["sha256"],
            "--bridge-bundle", admin["path"], "--expected-bridge-sha256", admin["sha256"],
            "--product-freeze", str(freeze), "--product-freeze-sha256", freeze_sha256,
            "--output", str(child / "observation")]
        same(command["argv"], expected_argv)
        need(Path(command["argv"][0]).is_absolute(), "actual interpreter path is not explicit")
        terminal = json.loads(stdout, object_pairs_hook=unique_pairs)
        same(terminal, {"case": name, "status": "PASS",
                        "report": {k: row["report"][k] for k in ("bytes", "sha256")}})
        need(stderr == b"", "route child emitted unaccounted stderr")
        pin = row["report"]
        need(pin["path"] == str(child / "observation/report.json"), "child report path differs")
        value = captured.json(pin["path"], {k: pin[k] for k in ("bytes", "sha256")})
        need(value["schema"] == "hepta.slot.mechanical.route-control.v1"
             and value["status"] == "PASS" and value["case"] == name, "actual route did not pass")
        same(value["source_before"], source["files"])
        same(value["source_after"], source["files"])
        detail = value["detail"]
        same(detail["argv"], command["argv"][3:])
        for field, expected in (("pid",command["pid"]),("pgid",command["pid"]),("ppid",command["parent_pid"])):
            need(type(detail[field]) is int and detail[field] == expected, "route PID ownership differs")
        need(detail["case"] == name and detail["status"] == "PASS"
             and type(detail["reference_result"]) is int and detail["reference_result"] == 17
             and detail["initial_counters"] is None
             and detail["forbidden_legacy_finish"] == [], "route witness differs")
        need(detail["reference_trace"] != [], "retained original witness did not execute")
        final = detail["final_counters"]
        if final is not None:
            mechanical_counters(final, command["pid"])
            need(sum(final["raw_frame_calls"]) == 0, "public route used C raw-frame bypass")
        if name in legacy_ok:
            same(detail["provider_trace"], detail["reference_trace"])
            need(detail["actual_entries"] and all(x == {"actual_entry_returned": True}
                                                for x in detail["actual_entries"]),
                 "legacy route did not invoke the actual HIA image")
            need(final is None or sum(final["initialized"]) == 0, "legacy callable upgraded to C")
        elif name in c_ok:
            same(detail["provider_trace"], detail["reference_trace"])
            need(detail["actual_entries"] and final is not None
                 and final["public_calls"][5] > 0 and final["initialized"][5] > 0
                 and final["final_receipts"][5] > 0, "v5 did not run actual C/HIA/final receipt")
        elif name in refused:
            need(detail["provider_trace"] == [] and detail["actual_entries"] == []
                 and (final is None or sum(final["initialized"]) == 0),
                 "refused route ran provider or initialized its C session")
        else:
            need(detail["actual_entries"] and detail["provider_trace"] == []
                 and detail["actual_record_loss_is_injected_fault"] is True
                 and final is not None and final["public_calls"][5] > 0
                 and sum(final["final_receipts"]) == 0,
                 "receipt-loss witness lacks actual native entry/sticky loss")
        if name in ("direct-env","explicit-owner","v1-scope","raw-frame-legacy","v5-bad-digest"):
            need(final is None, "legacy/refused load linked C")
        if name == "v5-fork":
            child_fork = detail["fork"]
            need(child_fork["reaped"] is True and child_fork["exit_code"] == 0, "fork not reaped")
            fork = json.loads(child_fork["raw"], object_pairs_hook=unique_pairs)
            need(fork["pid"] == child_fork["pid"] and fork["trace"] == [], "fork witness differs")
            mechanical_counters(fork["counters"], fork["pid"])
            need(sum(fork["counters"]["initialized"]) == 0, "child inherited parent authority")
        read.append({"case": name, "report": pin, "pid": command["pid"], "owned_reaped": True})
    captured.stable()
    return {"schema": "hepta.slot.mechanical.routes-readback.v1", "status": "PASS",
            "complete_cases": cases, "observations": read, "actual_inputs": captured.pins(),
            "original_domains_replaced": False, "whole_native_stack_qualified": False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "product-root", "product-freeze", "output"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--product-freeze-sha256", required=True)
    args = parser.parse_args()
    value = readback(args.evidence, args.product_root, args.product_freeze, args.product_freeze_sha256)
    write_json(args.output, value)

if __name__ == "__main__":
    main()
