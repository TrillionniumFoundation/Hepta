#!/usr/bin/env python3
"""Replay retained real kernel frontend bitcode through structured HIA.

Never runs a C frontend or changes the captured build. Equality ignores only
the external ModuleID comment, exactly like the production compiler wrapper.
"""
import argparse
import copy
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import time


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def canonical(path):
    lines = path.read_bytes().splitlines(keepends=True)
    assert lines and lines[0].startswith(b"; ModuleID = ")
    return b"".join(lines[1:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codec", type=Path, required=True)
    parser.add_argument("--llvm-dis", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    candidates = []
    for directory in sorted(args.ledger.iterdir()):
        receipt = directory / "RESULT.json"
        if not receipt.is_file():
            continue
        record = json.loads(receipt.read_bytes())
        if record.get("error", {}).get("message") == "HIA reconstruction changed canonical semantics; no compiler fallback":
            assert (directory / "frontend.bc").is_file()
            assert (directory / "frontend.canonical.ll").is_file()
            candidates.append((directory, record))
    assert candidates, "no real retained canonical failures"
    candidates.sort(key=lambda pair: (pair[0] / "frontend.bc").stat().st_size)
    report = {"schema": "hepta.hia.system.kernel-roundtrip-qualification.v1",
              "status": "RUNNING", "original_failed_units": len(candidates),
              "compiler_frontend_executed": False, "equality_gate_weakened": False,
              "codec": identity(args.codec), "units": [], "rejection_checks": []}
    def save():
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    def run(directory, name, argv, reject=False):
        start = time.monotonic_ns()
        result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=120)
        (directory / (name + ".stdout")).write_bytes(result.stdout)
        (directory / (name + ".stderr")).write_bytes(result.stderr)
        command = {"argv": [str(x) for x in argv], "exit_code": result.returncode,
                   "wall_ns": time.monotonic_ns() - start,
                   "stdout": identity(directory / (name + ".stdout")),
                   "stderr": identity(directory / (name + ".stderr"))}
        (directory / (name + ".command.json")).write_text(json.dumps(command, indent=2) + "\n")
        assert (result.returncode != 0) if reject else (result.returncode == 0), command
    try:
        for original, record in candidates:
            destination = args.output / original.name
            destination.mkdir()
            source = identity(original / "frontend.bc")
            ir = identity(original / "frontend.canonical.ll")
            program = destination / "program.hia.json"
            run(destination, "encode", [args.codec, "encode", original / "frontend.bc", program])
            run(destination, "decode", [args.codec, "decode", program, destination / "rebuilt.bc"])
            run(destination, "disassemble", [args.llvm_dis, destination / "rebuilt.bc",
                                           "-o", destination / "rebuilt.ll"])
            before, after = canonical(original / "frontend.canonical.ll"), canonical(destination / "rebuilt.ll")
            if before != after:
                delta = "".join(difflib.unified_diff(before.decode().splitlines(True),
                                after.decode().splitlines(True), fromfile="captured", tofile="fresh"))
                (destination / "difference.txt").write_text(delta)
            assert before == after, str(destination / "difference.txt")
            assert source == identity(original / "frontend.bc")
            assert ir == identity(original / "frontend.canonical.ll")
            report["units"].append({"source": record["source"], "original_bitcode": source,
                "original_ir": ir, "program": identity(program),
                "rebuilt_ir": identity(destination / "rebuilt.ll"),
                "canonical_sha256": hashlib.sha256(after).hexdigest(), "equal": True})
            save()
        # An ordered edge list is mandatory and must describe a bijection.
        smallest = args.output / candidates[0][0].name
        document = json.loads((smallest / "program.hia.json").read_bytes())
        location = next((fi, bi) for fi, function in enumerate(document["functions"])
                        for bi, block in enumerate(function["blocks"]) if block["use_order"])
        def block(value):
            return value["functions"][location[0]]["blocks"][location[1]]
        alterations = [
            ("missing_field", lambda b: b.pop("use_order")),
            ("missing_edge", lambda b: b["use_order"].pop()),
            ("duplicate_edge", lambda b: b["use_order"].append(copy.deepcopy(b["use_order"][0]))),
            ("operand_overflow", lambda b: b["use_order"][0].update(operand=1 << 40)),
        ]
        for name, alter in alterations:
            changed = copy.deepcopy(document)
            alter(block(changed))
            path = args.output / ("reject-" + name + ".hia.json")
            path.write_text(json.dumps(changed) + "\n")
            run(args.output, "reject-" + name,
                [args.codec, "decode", path, args.output / ("reject-" + name + ".bc")], reject=True)
            report["rejection_checks"].append({"name": name, "status": "PASS"})
            save()
        assert report["codec"] == identity(args.codec)
        report["status"] = "PASS"
    except Exception as error:
        report["status"], report["error"] = "FAIL", str(error)
        raise
    finally:
        save()
    print(json.dumps({"status": report["status"], "real_kernel_units": len(report["units"]),
                      "rejection_checks": len(report["rejection_checks"]),
                      "report": str(args.output / "report.json")}))


if __name__ == "__main__":
    main()
