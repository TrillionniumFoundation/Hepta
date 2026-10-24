"""Qualify source lowering, standalone JSON verification and native execution.

The native binary is compiled from source through the existing Rust backend.
It is not compiled from the resource graph; equivalence remains unproved.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

from hepta.backend import compile_rust
from hepta.pipeline import analyze_project
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = {"owned_library": ROOT / "examples/owned/main.hepta",
            "returned_views": ROOT / "examples/resource_ir/returned_views.hepta"}


def _first(document: dict, opname: str, function_suffix: str | None = None):
    return next((block, index, operation) for fn in document["functions"]
                if function_suffix is None or fn["name"].endswith(function_suffix)
                for block in fn["blocks"] for index, operation in enumerate(block["ops"])
                if operation["op"] == opname)


def adversarial_checks(owned: dict, views: dict) -> list[dict]:
    checks = []

    def expect(name, document, expected):
        result = verify_resource_ir(document)
        actual = result["diagnostics"][0]["code"] if result["diagnostics"] else None
        checks.append({"case": name, "expected": expected, "actual": actual,
                       "ok": not result["ok"] and actual == expected})

    doc = copy.deepcopy(owned)
    block, index, _ = _first(doc, "drop", "close")
    del block["ops"][index]
    expect("removed_drop", doc, "E_RIR_LEAK")
    doc = copy.deepcopy(owned)
    block, index, op = _first(doc, "move", "forward")
    block["ops"].insert(index + 1, copy.deepcopy(op))
    expect("duplicate_move", doc, "E_RIR_USE_AFTER_MOVE")
    doc = copy.deepcopy(owned)
    block, index, op = _first(doc, "drop", "close")
    close = next(fn for fn in doc["functions"] if fn["name"].endswith("close"))
    typ = next(slot["type"] for slot in close["locals"] if slot["id"] == op["src"])
    block["ops"].insert(index, {"op": "borrow", "id": "attack", "place": {"root": op["src"], "path": []}, "type": typ, "mode": "read"})
    expect("drop_during_loan", doc, "E_RIR_LOAN_CONFLICT")
    doc = copy.deepcopy(owned)
    checksum = next(fn for fn in doc["functions"] if fn["name"].endswith("checksum"))
    header = next(b for b in checksum["blocks"] if b["term"]["op"] == "branch")
    body = next(b for b in checksum["blocks"] if b["id"] == header["term"]["then"])
    body["ops"].append({"op": "borrow", "id": "attack", "place": {"root": "p0", "path": []}, "type": checksum["params"][0]["type"], "mode": "read"})
    expect("loop_backedge_changes_loans", doc, "E_RIR_JOIN")
    doc = copy.deepcopy(owned)
    _first(doc, "unpack")[2]["variant"] = "WrongVariant"
    expect("invalid_enum_payload", doc, "E_RIR_AGGREGATE")
    doc = copy.deepcopy(owned)
    doc["functions"][0]["blocks"][0]["ops"].append({"op": "trust_resource"})
    expect("unknown_operation", doc, "E_RIR_OP")
    doc = copy.deepcopy(views)
    head = next(fn for fn in doc["functions"] if fn["name"] == "head")
    head["locals"].append({"id": "attack", "type": "u8", "mutable": True})
    _first(doc, "borrow", "head")[2]["place"] = {"root": "attack", "path": []}
    expect("borrow_escapes_local", doc, "E_RIR_RETURN")
    return checks


def qualify_resources(directory: Path, *, rustc: str | None = None) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    result = {"schema": "hepta.resource-qualification.v1", "ok": False,
              "generated_at_utc": datetime.now(timezone.utc).isoformat(),
              "platform": {"system": platform.system(), "machine": platform.machine()},
              "source_to_ir_refinement_proved": False, "native_codegen_uses_resource_ir": False,
              "whole_language_soundness_proved": False, "projects": []}
    documents = {}
    for name, path in EXAMPLES.items():
        analysis = analyze_project(path, rustc=rustc, crate_type="bin")
        row = {"name": name, "entry": str(path.relative_to(ROOT)), "native_gate": analysis.report}
        result["projects"].append(row)
        if not analysis.report["ok"]:
            return result
        graph = lower_resource_ir(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
        documents[name] = graph
        graph_path = directory / (name + ".resource-ir.json")
        graph_path.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        # A fresh process only imports the independent graph verifier. It has
        # no frontend result available and reads the serialized graph again.
        code = ("import json,sys; from hepta.resource_ir import verify_resource_ir; "
                "r=verify_resource_ir(json.load(open(sys.argv[1]))); "
                "r['frontend_modules_imported']=[m for m in ('hepta.parser','hepta.checker') if m in sys.modules]; "
                "print(json.dumps(r)); sys.exit(0 if r['ok'] and not r['frontend_modules_imported'] else 1)")
        standalone = subprocess.run([sys.executable, "-c", code, str(graph_path)], cwd=ROOT,
                                    capture_output=True, text=True, timeout=15)
        if standalone.returncode:
            raise RuntimeError("Standalone verifier rejected graph: " + standalone.stdout + standalone.stderr)
        row["resource_verifier"] = json.loads(standalone.stdout)
        row["inputs"] = {str(Path(p).relative_to(ROOT)): hashlib.sha256(data).hexdigest()
                         for p, data in analysis.project.source_bytes.items()}
        binary = directory / (name + ".bin")
        native = compile_rust(analysis.rust, rustc=rustc, crate_type="bin", output=binary)
        row["native_build"] = native
        if not native["ok"]:
            return result
        execution = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
        row["execution"] = {"exit_code": execution.returncode, "stdout": execution.stdout,
                            "stderr": execution.stderr, "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
        if execution.returncode:
            return result
    result["adversarial_checks"] = adversarial_checks(documents["owned_library"], documents["returned_views"])
    result["ok"] = all(check["ok"] for check in result["adversarial_checks"])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite an existing qualification")
    with tempfile.TemporaryDirectory(prefix="hepta-resource-native-") as td:
        try:
            report = qualify_resources(Path(td), rustc=args.rustc)
        except (OSError, RuntimeError, ResourceIRError, subprocess.TimeoutExpired) as exc:
            report = {"schema": "hepta.resource-qualification.v1", "ok": False, "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(report, out, indent=2, sort_keys=True)
        out.write("\n")
    print(json.dumps({"ok": report["ok"], "output": str(args.output)}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
