#!/usr/bin/env python3
"""Qualify typed debug metadata against every captured stock target C -g unit.

No original C frontend is executed. The retained real bitcode, complete original
llvm-dis output, original stock argv, and source identities remain read-only.
"""
from __future__ import annotations
import argparse
from collections import Counter
import copy
import difflib
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time


def identity(path):
    path = Path(path)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def canonical(path):
    lines = Path(path).read_bytes().splitlines(keepends=True)
    assert lines and lines[0].startswith(b"; ModuleID = ")
    return b"".join(lines[1:])


def blocks(document):
    return [block for function in document["functions"] for block in function["blocks"]]


def records(document):
    result = []
    for block in blocks(document):
        for instruction in block["instructions"]:
            result.extend(instruction["debug_records"])
        result.extend(block["trailing_debug_records"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codec", type=Path, required=True)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    parser.add_argument("--census", type=Path, required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    build = json.loads(args.build_receipt.read_bytes())
    assert build["status"] == "PASS" and build["sources_unchanged"] is True
    sources = {name: identity(args.codec.parent / name) for name in build["inputs"]}
    assert all(sources[name]["sha256"] == row["sha256"] for name, row in build["inputs"].items())
    assert identity(args.codec)["sha256"] == build["binary"]["sha256"]
    census = json.loads(args.census.read_bytes())
    assert census["status"] == "CENSUS_COMPLETE" and census["units"]
    report = {"schema": "hepta.hia.native-codec-debug-qualification.v1",
        "status": "RUNNING", "binary": identity(args.codec), "sources": sources,
        "census": identity(args.census), "test_script": identity(__file__),
        "original_debug_flags_preserved": True, "metadata_or_records_stripped": False,
        "compiler_frontend_executed": False,
        "ignored_canonical_lines": "first ModuleID only",
        "actual_units": [], "fixture_cases": [], "mutation_rejections": []}
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
    def roundtrip(bitcode, original_ir, directory):
        directory.mkdir()
        before_bc, before_ir = identity(bitcode), identity(original_ir)
        program = directory / "program.hia.json"
        run(directory, "encode", [args.codec, "encode", bitcode, program])
        run(directory, "decode", [args.codec, "decode", program, directory / "rebuilt.bc"])
        run(directory, "disassemble", [args.llvm_bin / "llvm-dis", directory / "rebuilt.bc",
                                       "-o", directory / "rebuilt.ll"])
        before, after = canonical(original_ir), canonical(directory / "rebuilt.ll")
        if before != after:
            delta = "".join(difflib.unified_diff(before.decode().splitlines(True),
                            after.decode().splitlines(True), fromfile="captured", tofile="fresh"))
            (directory / "difference.txt").write_text(delta)
        assert before == after, str(directory / "difference.txt")
        document = json.loads(program.read_bytes())
        nodes = Counter(m["kind"] for m in document["metadata"] if m["kind"].startswith("DI"))
        debug_records = Counter(r["kind"] for r in records(document))
        expected_records = Counter("dbg_" + kind for kind in
                                   re.findall(r"#dbg_(declare|value|assign|label)\(", before.decode()))
        assert debug_records == expected_records, (debug_records, expected_records)
        assert before_bc == identity(bitcode) and before_ir == identity(original_ir)
        row = {"original_bitcode": before_bc, "original_ir": before_ir,
               "program": identity(program), "rebuilt_ir": identity(directory / "rebuilt.ll"),
               "canonical_equal": True, "canonical_sha256": hashlib.sha256(after).hexdigest(),
               "represented_metadata_node_counts": dict(nodes),
               "debug_record_counts": dict(debug_records),
               "original_captured_inputs_unchanged": True}
        return row, document
    try:
        for index, unit in enumerate(census["units"]):
            assert identity(unit["source"]["path"]) == unit["source"]
            assert identity(unit["frontend_bitcode"]["path"]) == unit["frontend_bitcode"]
            assert identity(unit["frontend_ir"]["path"]) == unit["frontend_ir"]
            original = unit["original_command"]
            tokens = original.get("arguments") or shlex.split(original["command"])
            assert "-g" in tokens, "captured effective-debug unit lost its original -g"
            directory = args.output / ("real-unit-" + str(index).zfill(3))
            row, _ = roundtrip(Path(unit["frontend_bitcode"]["path"]),
                               Path(unit["frontend_ir"]["path"]), directory)
            row.update(source=unit["source"], original_stock_command=original,
                       original_metadata_kind_counts=unit["metadata_kinds"],
                       original_debug_record_kind_counts=unit["debug_record_kinds"])
            report["actual_units"].append(row)
            save()
        preparation = args.output / "fixture-input"
        preparation.mkdir()
        run(preparation, "assemble", [args.llvm_bin / "llvm-as", args.fixture,
                                     "-o", preparation / "fixture.bc"])
        run(preparation, "disassemble", [args.llvm_bin / "llvm-dis", preparation / "fixture.bc",
                                       "-o", preparation / "fixture.ll"])
        row, document = roundtrip(preparation / "fixture.bc", preparation / "fixture.ll",
                                  args.output / "debug-record-fixture")
        assert set(row["debug_record_counts"]) == {"dbg_declare", "dbg_value", "dbg_assign", "dbg_label"}
        report["fixture_cases"].append({"input": identity(args.fixture), **row})
        save()
        altered = [
            ("unknown_di_kind", lambda d: next(m for m in d["metadata"] if m["kind"].startswith("DI")).update(kind="DIOpaqueUnknown")),
            ("unknown_di_field", lambda d: next(m for m in d["metadata"] if m["kind"].startswith("DI")).update(unrepresented=True)),
            ("location_column_overflow", lambda d: next(m for m in d["metadata"] if m["kind"] == "DILocation").update(column=65536)),
            ("unknown_record_kind", lambda d: records(d)[0].update(kind="dbg_opaque")),
            ("unknown_record_field", lambda d: records(d)[0].update(unrepresented=True)),
            ("wrong_variable_metadata", lambda d: next(r for r in records(d) if r["kind"] == "dbg_declare").update(variable=next(m["id"] for m in d["metadata"] if m["kind"] == "DIFile"))),
            ("invalid_expression_opcode", lambda d: next(m for m in d["metadata"] if m["kind"] == "DIExpression").update(elements=["18446744073709551615"])),
        ]
        for name, mutate in altered:
            changed = copy.deepcopy(document)
            mutate(changed)
            path = args.output / ("reject-" + name + ".hia.json")
            path.write_text(json.dumps(changed) + "\n")
            run(args.output, "reject-" + name,
                [args.codec, "decode", path, args.output / ("reject-" + name + ".bc")], reject=True)
            report["mutation_rejections"].append({"name": name, "status": "PASS"})
            save()
        assert report["binary"] == identity(args.codec)
        assert sources == {name: identity(args.codec.parent / name) for name in sources}
        assert report["census"] == identity(args.census)
        report["status"] = "PASS"
    except Exception as error:
        report["status"], report["error"] = "FAIL", str(error)
        raise
    finally:
        save()
    print(json.dumps({"status": report["status"], "actual_units": len(report["actual_units"]),
                      "fixture_cases": len(report["fixture_cases"]),
                      "mutation_rejections": len(report["mutation_rejections"]),
                      "report": str(args.output / "report.json")}))


if __name__ == "__main__":
    main()
