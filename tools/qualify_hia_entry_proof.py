#!/usr/bin/env python3
"""Prove the locked minimum program and call the same final image."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools import hia_entry_catalog as catalog

CASES = [(2, 3, 5), (35, 7, 42), (0, 0, 0), (4294967295, 1, 0),
         (4294967295, 4294967295, 4294967294)]
PROFILE = "hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v1"

def identity(path):
    raw = Path(path).read_bytes()
    return {"sha256": sha256(raw).hexdigest(), "bytes": len(raw)}

def validate_proof(report, source, object_path, image):
    if report.get("ok") is not True or report.get("status") != "smt_validated_not_executed":
        raise ValueError("supplied-byte checker did not complete its model proof")
    for kind, path in (("source", source), ("object", object_path), ("image", image)):
        expected = identity(path)
        actual = report.get("inputs", {}).get(kind, {})
        if any(actual.get(key) != value for key, value in expected.items()):
            raise ValueError("proof does not bind the exact " + kind + " bytes")
    for name in ("compiler_invoked", "linker_invoked", "native_execution_observed", "adopted"):
        if report.get(name) is not False:
            raise ValueError("unexpected checker scope: " + name)
    if not report.get("unproved_obligations"):
        raise ValueError("checker omitted its remaining obligations")
    validation = report.get("validation", {})
    if validation.get("profile") != PROFILE or validation.get("ok") is not True or validation.get("complete") is not True:
        raise ValueError("unexpected or incomplete supplied-artifact proof profile")
    for kind, path in (("object_sha256", object_path), ("final_image_sha256", image)):
        if validation.get("subject", {}).get(kind) != identity(path)["sha256"]:
            raise ValueError("proof subject differs from the retained artifact")
    obligations = validation.get("obligations", [])
    expected = {"caller_contract_nonvacuous": "sat", "machine_memory_access_bounds": "unsat",
        "sysv_stack_alignment_and_preservation": "unsat", "all_inputs_reach_a_terminal_model_outcome": "unsat",
        "core_to_final_image_return_abort_and_caller_bytes": "unsat"}
    if len(obligations) != len(expected) or any(row.get("name") not in expected or
            row.get("expected") != expected[row["name"]] or row.get("result") != expected[row["name"]]
            for row in obligations) or {row.get("name") for row in obligations} != set(expected):
        raise ValueError("proof obligations did not all complete as expected")

def qualify(selection, hepta_root, runtime_root, output, python=sys.executable):
    source_root, runtime_root = Path(hepta_root).resolve(), Path(runtime_root).resolve()
    output = Path(output).resolve()
    if any(output == root or root in output.parents for root in (source_root, runtime_root)):
        raise ValueError("evidence must be outside the pinned source checkouts")
    output.mkdir(parents=False, exist_ok=False)
    started = time.monotonic()
    report = {"schema": "hepta.hia.entry-proof-smoke.v1", "ok": False,
        "selection": selection, "started_utc": datetime.now(timezone.utc).isoformat(),
        "commands": [], "general_machine_proof": False, "adoption_performed": False,
        "execution_authority_granted": False, "live_endpoint_probed": False}
    def save():
        (output / "REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    def run(name, argv, cwd):
        begin = time.monotonic()
        record = {"name": name, "argv": [str(a) for a in argv], "cwd": str(cwd),
            "started_utc": datetime.now(timezone.utc).isoformat(), "exit_code": None}
        report["commands"].append(record)
        save()
        try:
            with (output / (name + ".stdout")).open("wb") as stdout, (output / (name + ".stderr")).open("wb") as stderr:
                result = subprocess.run(record["argv"], cwd=cwd, stdout=stdout, stderr=stderr, timeout=180)
            record["exit_code"] = result.returncode
        except (subprocess.TimeoutExpired, OSError) as exc:
            record["execution_error"] = {"type": type(exc).__name__, "message": str(exc)}
            record["timed_out"] = isinstance(exc, subprocess.TimeoutExpired)
            raise
        finally:
            record["elapsed_seconds"] = time.monotonic() - begin
            for stream in ("stdout", "stderr"):
                path = output / (name + "." + stream)
                record[stream] = identity(path) if path.exists() else None
            save()
        if result.returncode:
            raise ValueError(name + " failed with exit " + str(result.returncode))
        return (output / (name + ".stdout")).read_text()
    try:
        selected = catalog.release(ROOT, selection)
        report.update(entry=selected, adapter=identity(__file__))
        entry_args = [python, "-B", str(ROOT / selected["entry_argv"][2])]
        if selection != "current":
            entry_args += ["--lock", str(ROOT / selected["lock"]["path"]), "--lock-sha256", selected["lock"]["sha256"]]
        check_args = entry_args + ["check", "--hepta-root", str(source_root), "--runtime-checkout", str(runtime_root)]
        run("release-check-before", check_args, ROOT)
        deps = json.loads(run("dependencies", [python, "-B", "-E", "-s", "-c",
            "import importlib.metadata as m,json,sys; print(json.dumps({'python':sys.version,'jsonschema':m.version('jsonschema'),'z3-solver':m.version('z3-solver')}))"], source_root))
        report["dependencies"] = deps
        if deps["jsonschema"] != "4.25.1" or deps["z3-solver"] != "4.15.4.0":
            raise ValueError("published dependency versions required")
        example = source_root / selected["minimal_program"]["path"]
        if identity(example)["sha256"] != selected["minimal_program"]["sha256"]:
            raise ValueError("minimum program differs from the selected lock")
        cli = [python, "-B", "-E", "-s", "-m", "hepta", "hia"]
        run("verify", cli + ["verify", str(example)], source_root)
        vm = json.loads(run("interpret", cli + ["run", str(example), "--function", "calculate", "--arguments", "[2,3]"], source_root))
        if vm.get("status") != "returned" or vm.get("values") != [5]:
            raise ValueError("minimum interpreter result differs")
        obj, image = output / "calculate.o", output / "calculate-proof.so"
        run("direct-object", cli + ["build", str(example), "--backend", "native", "--target", "x86_64-unknown-linux-gnu", "--kind", "object", "--output", str(obj)], source_root)
        linker = shutil.which("ld")
        if linker is None:
            raise ValueError("GNU ld required")
        report["linker"] = {"path": linker, **identity(linker), "version": run("linker-version", [linker, "--version"], source_root)}
        if "GNU ld" not in report["linker"]["version"]:
            raise ValueError("entry profile requires GNU ld")
        run("link-proof-image", [linker, "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none", "--hash-style=both", str(obj), "-lc", "-o", str(image)], source_root)
        run("supplied-proof", [python, "-B", "-E", "-s", str(source_root / "tools/check_hia_safe_core.py"), "--source", str(example), "--object", str(obj), "--image", str(image), "--output", str(output / "proof")], source_root)
        proof = json.loads((output / "proof/attempt.json").read_text())
        validate_proof(proof, example, obj, image)
        report["proof"] = {"receipt": "proof/attempt.json", **identity(output / "proof/attempt.json"), "profile": PROFILE, "scope": "identified Core/x86/ELF models and solver", "unproved_obligations": proof["unproved_obligations"]}
        report["artifacts"] = {"source": identity(example), "object": identity(obj), "image": identity(image)}
        call_script = """import ctypes, hashlib, json, sys
from pathlib import Path
p=Path(sys.argv[1]); before=hashlib.sha256(p.read_bytes()).hexdigest()
library=ctypes.CDLL(str(p)); fn=library.calculate
fn.argtypes=[ctypes.c_uint32,ctypes.c_uint32]; fn.restype=ctypes.c_uint32
rows=[{'arguments':[a,b],'expected':e,'actual':fn(a,b)} for a,b,e in json.loads(sys.argv[2])]
after=hashlib.sha256(p.read_bytes()).hexdigest()
ok=before==after and all(r['actual']==r['expected'] for r in rows)
print(json.dumps({'ok':ok,'image_sha256':before,'unchanged':before==after,'cases':rows}))
sys.exit(0 if ok else 1)
"""
        native = json.loads(run("native-calls", [python, "-B", "-E", "-s", "-c", call_script, str(image), json.dumps(CASES)], source_root))
        if native.get("ok") is not True or native.get("image_sha256") != report["artifacts"]["image"]["sha256"]:
            raise ValueError("native calls did not consume the proven final image")
        report["native"] = native
        validate_proof(proof, example, obj, image)
        run("release-check-after", check_args, ROOT)
        report.update(ok=True, status="PASS_LOCKED_MINIMUM_PROOF_AND_NATIVE_CALLS", source_unchanged=True, same_proven_image_called=True)
    except Exception as exc:
        report.update(status="FAILED", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        report.update(completed_utc=datetime.now(timezone.utc).isoformat(), elapsed_seconds=time.monotonic() - started)
        save()
    return report

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", choices=tuple(catalog.SELECTIONS), required=True)
    parser.add_argument("--hepta-root", type=Path, required=True)
    parser.add_argument("--runtime-checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args(argv)
    result = qualify(args.selection, args.hepta_root, args.runtime_checkout, args.output, args.python)
    print(json.dumps({key: result.get(key) for key in ("ok", "status", "selection", "error", "elapsed_seconds")}))
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
