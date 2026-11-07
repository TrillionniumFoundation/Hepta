"""Reproduce the nonreturning-CALL stack check without executing the image.

Run in a fresh process against the indicated Hepta checkout.  The output path
must be new.  Files named candidate.unsafe.* are static negative evidence only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect", choices=("accepted", "rejected"), required=True)
    args = parser.parse_args()
    checkout = args.checkout.resolve(strict=True)
    sys.path.insert(0, str(checkout))
    from hepta.hia_machine_x64 import Code
    from hepta.hia_program import verify_program
    from hepta.hia_program_native import emit_program_machine, compile_program_machine
    from hepta.hia_safe_core import validate_safe_core_image, SafeCoreRejected, _source_identity

    output = args.output.absolute()
    output.mkdir(parents=False, exist_ok=False)
    core = json.loads((checkout / "examples/hia_safe_core/scalar_add.hia.json").read_bytes())
    core["functions"][0]["blocks"][0]["ops"][0]["op"] = "int.add.checked"
    (output / "source.hia.json").write_text(json.dumps(core, sort_keys=True, indent=2) + "\n")
    checked = verify_program(core)
    original = Code.call

    def corrupt_stack(code, symbol):
        if symbol == "abort":
            code.mov_imm("rsp", 0)
        return original(code, symbol)

    report = {
        "schema": "hepta.hia.safe-core-call-stack-reproduction.v1",
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip(),
        "source_identity": _source_identity(),
        "native_execution_performed": False,
        "core_sha256": checked.sha256,
        "expected": args.expect,
    }
    with patch.object(Code, "call", corrupt_stack):
        image = emit_program_machine(checked)
        (output / "candidate.unsafe.o").write_bytes(image.object_bytes)
        (output / "candidate.unsafe.text.bin").write_bytes(image.text_bytes)
        compile_program_machine(image, program=checked, output=output / "candidate.unsafe.so", linker="ld")
        data = (output / "candidate.unsafe.so").read_bytes()
        report["final_image_sha256"] = sha256(data).hexdigest()
        try:
            report["validation"] = validate_safe_core_image(checked, image, data, query_directory=output / "queries")
        except SafeCoreRejected as exc:
            report.update(observed="rejected", error=str(exc), counterexample=exc.counterexample)
        else:
            report.update(observed="accepted")
    report["matched_expectation"] = report["observed"] == args.expect
    (output / "observation.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("observed", "expected", "matched_expectation",
                      "final_image_sha256", "native_execution_performed")}, sort_keys=True))
    return 0 if report["matched_expectation"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
