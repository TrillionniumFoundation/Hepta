"""Run positive, wrong-code, trap, and unsupported-profile proof controls."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import HIAProgramRejected, SCHEMA, verify_program
from hepta.hia_translation_validation import validate_translation, verify_translation_receipt


def _program():
    params = [{"name": "x", "type": "u32"}, {"name": "y", "type": "u32"}]
    def operation(op, args, out):
        return {"op": op, "args": args, "out": [{"name": out, "type": "u32"}], "attrs": {}}
    return {"schema": SCHEMA, "module": "translation_control", "functions": [{
        "name": "calculate", "params": params, "returns": ["u32"], "effects": ["trap"],
        "entry": "entry", "blocks": [{"id": "entry", "params": params, "ops": [
            operation("int.add.wrap", ["x", "y"], "sum"),
            operation("int.sub.wrap", ["sum", "y"], "result"),
        ], "term": {"op": "ret", "values": ["result"]}}],
    }]}


def qualify(timeout_ms=2000):
    before = _program()
    after = copy.deepcopy(before)
    after["functions"][0]["blocks"][0]["ops"] = []
    after["functions"][0]["blocks"][0]["term"]["values"] = ["x"]
    wrong = copy.deepcopy(after)
    wrong["functions"][0]["blocks"][0]["term"]["values"] = ["y"]
    checked = copy.deepcopy(before)
    checked["functions"][0]["blocks"][0]["ops"][0]["op"] = "int.add.checked"
    loop = copy.deepcopy(after)
    fn = loop["functions"][0]
    fn["blocks"][0]["term"] = {"op": "jump", "target": "loop", "args": []}
    fn["blocks"].append({"id": "loop", "params": [], "ops": [],
                          "term": {"op": "jump", "target": "loop", "args": []}})
    cases = {
        "wrapping_cancellation": validate_translation(before, after, timeout_ms=timeout_ms),
        "safe_but_wrong": validate_translation(before, wrong, timeout_ms=timeout_ms),
        "checked_trap_cannot_be_removed": validate_translation(checked, after, timeout_ms=timeout_ms),
        "unsupported_loop": validate_translation(loop, loop, timeout_ms=timeout_ms),
    }
    expected = {"wrapping_cancellation": "proved", "safe_but_wrong": "disproved",
                "checked_trap_cannot_be_removed": "disproved", "unsupported_loop": "unknown"}
    hostile = copy.deepcopy(cases["wrapping_cancellation"])
    wrong_checked = verify_program(wrong)
    hostile.update(status="proved", after_sha256=wrong_checked.sha256,
                   after_input_sha256=wrong_checked.input_sha256)
    rejected = False
    try:
        verify_translation_receipt(before, wrong, hostile, timeout_ms=timeout_ms)
    except HIAProgramRejected:
        rejected = True
    ok = all(cases[name]["status"] == status for name, status in expected.items()) and rejected
    return {
        "schema": "hepta.hia.translation-validation-qualification.v1", "ok": ok,
        "expected_statuses": expected, "cases": cases,
        "forged_proved_receipt_rejected": rejected,
        "claims": {"selected_scalar_profile_all_input_smt_checks_executed": ok,
                   "native_refinement_proved": False, "resource_bounds_proved": False,
                   "whole_language_soundness_proved": False},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="optional JSON evidence file")
    parser.add_argument("--timeout-ms", type=int, default=2000)
    args = parser.parse_args(argv)
    result = qualify(args.timeout_ms)
    data = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(data, encoding="utf-8")
        print(json.dumps({"ok": result["ok"], "output": str(args.output)}))
    else:
        print(data, end="")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
