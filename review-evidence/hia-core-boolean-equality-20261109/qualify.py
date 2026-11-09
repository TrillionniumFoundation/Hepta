"""Small source-bound native qualification for boolean equality admission.

Retains B0/B1/B2/B3 and the changed-source M1/M2/M3 chain, all compiler
inputs, native child receipts and logs. This is finite evidence only.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.qualify_hia_selfhost import (INVALID, SOURCE, build_seed, compile_stage,
    digest, invoke, mutate_compiler, source_manifest)
from tools.hia_selfhost_select import (boolean_equality_source,
    independent_boolean_equality_reference, qualify_boolean_equality)


def qualify(output):
    started = time.monotonic_ns()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = SOURCE.read_bytes()
    manifest = source_manifest()
    reference = independent_boolean_equality_reference()
    (output / "independent-reference.json").write_text(json.dumps(reference, indent=2, sort_keys=True) + "\n")
    checks, generations, observations = {}, [], []
    report = {"schema": "hepta.hia.boolean-equality-qualification.v1",
        "status": "FAIL", "base_commit": "20eace37747fde9aa0fc9c14cdb0159db30f5161",
        "source_manifest": manifest, "compiler_source_sha256": digest(source),
        "reference": reference, "checks": checks, "generations": generations,
        "observations": observations,
        "scope": {"boolean_equality_and_inequality": True,
            "ordered_boolean_comparisons": False, "general_core_selfhosting": False,
            "all_input_compiler_correctness_proved": False,
            "runtime_security_sandbox": False}}
    try:
        # Retain an actual rejection from the unchanged baseline compiler.
        original = subprocess.run(["git", "show", report["base_commit"] + ":examples/hia_bootstrap/selfhost.hiaasm"],
            cwd=ROOT, capture_output=True, check=True).stdout
        baseline_dir = output / "baseline"
        baseline_dir.mkdir()
        baseline, receipt = build_seed(baseline_dir, original)
        report["baseline_seed"] = receipt
        for opcode in ("compare.eq", "compare.ne"):
            result, _ = invoke(baseline_dir, "old-" + opcode, baseline, boolean_equality_source(opcode),
                image_format="seed-shared")
            checks[result["case"]] = bool(result.get("status") == "returned"
                and result.get("core_u32") == INVALID and result.get("output_unchanged"))
            observations.append(result)
        b0, receipt = build_seed(output)
        report["seed"] = receipt
        previous, format_name = b0, "seed-shared"
        images = {}
        for name in ("B1", "B2", "B3"):
            previous, row = compile_stage(output, name, previous, source, image_format=format_name)
            format_name = "flat-x86-64"
            images[name] = previous
            generations.append(row)
        checks["B1=B2=B3"] = len({digest(images[name].read_bytes()) for name in ("B1", "B2", "B3")}) == 1
        changed = mutate_compiler(source)
        previous = images["B3"]
        for name in ("M1", "M2", "M3"):
            previous, row = compile_stage(output, name, previous, changed)
            images[name] = previous
            generations.append(row)
        checks["M1!=M2"] = images["M1"].read_bytes() != images["M2"].read_bytes()
        checks["M2=M3"] = images["M2"].read_bytes() == images["M3"].read_bytes()
        checks["M3!=B3"] = images["M3"].read_bytes() != images["B3"].read_bytes()
        observations.extend(qualify_boolean_equality(output,
            [(name, images[name]) for name in ("B3", "M3")], checks, reference))
        checks["source_unchanged"] = SOURCE.read_bytes() == source and source_manifest() == manifest
        report["status"] = "PASS" if checks and all(type(value) is bool and value for value in checks.values()) else "FAIL"
    except BaseException as exc:
        report["exception"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        report["elapsed_ns"] = time.monotonic_ns() - started
        (output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.output)
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]),
        "passed": sum(report["checks"].values()), "elapsed_ns": report["elapsed_ns"]}, sort_keys=True))
    raise SystemExit(0 if report["status"] == "PASS" else 1)
