"""One source-generation observation, with immutable per-attempt originals."""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import traceback

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kernel", choices=("control", "format"), default="control")
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    relative = ("tools/generate_hia_cli_control.py", "tools/hia_cli_control_phases.py",
                "tools/hia_cli_unicode_tables.json")
    if args.kernel == "format":
        relative += ("tools/generate_hia_cli_format.py",)
    def pins():
        return {name: sha256((source / name).read_bytes()).hexdigest() for name in relative}
    before = pins()
    report = {"schema": "hia.cli.source-generation-observation.v1",
              "scope": "NEW_RECOVERY_REVISION_SOURCE_AND_CORE_ONLY",
              "status": "HOLD", "source": str(source), "source_before": before,
              "kernel": args.kernel, "base_commit": "e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6",
              "native_compile_performed": False, "native_execution_performed": False,
              "whole_native_delivery_qualified": False}
    started = time.monotonic_ns()
    try:
        sys.path.insert(0, str(source))
        if args.kernel == "control":
            from tools import generate_hia_cli_control as generator
        else:
            from tools import generate_hia_cli_format as generator
        from hepta.hia_agent_assembly import render_assembly
        program = generator.source_program()
        (output / "authoring.py").write_text(program)
        nodes = ast.parse(program).body
        document = generator.document()
        assembly = render_assembly(document)
        (output / ("cli_" + args.kernel + ".hiaasm")).write_text(assembly)
        functions = []
        for index, function in enumerate(document["functions"]):
            names = {value["name"] for value in function["params"]}
            for block in function["blocks"]:
                names.update(value["name"] for value in block["params"])
                names.update(value["name"] for operation in block["ops"] for value in operation["out"])
            functions.append({"name": function["name"], "authoring_name": nodes[index].name,
                              "blocks": len(function["blocks"]), "ssa_definitions": len(names),
                              "operations": sum(len(b["ops"]) for b in function["blocks"])})
        report.update(functions=functions, function_count=len(functions),
                      blocks=sum(f["blocks"] for f in functions),
                      operations=sum(f["operations"] for f in functions),
                      max_function_blocks=max(f["blocks"] for f in functions),
                      max_function_ssa=max(f["ssa_definitions"] for f in functions),
                      assembly_bytes=len(assembly.encode()),
                      assembly_sha256=sha256(assembly.encode()).hexdigest())
        report["unchanged_profile_static_bounds"] = {
            "functions_128": len(functions) <= 128,
            "blocks_1536": report["blocks"] <= 1536,
            "instructions_8192": report["operations"] <= 8192,
            "per_function_blocks_256": report["max_function_blocks"] <= 256,
            "per_function_ssa_2048": report["max_function_ssa"] <= 2048,
            "assembly_1MiB": report["assembly_bytes"] <= 1048576,
        }
        if not all(report["unchanged_profile_static_bounds"].values()):
            raise RuntimeError("generated source exceeds unchanged native profile")
        report["status"] = "SOURCE_CORE_PASS_NATIVE_NOT_RUN"
    except BaseException as error:
        report.update(error_type=type(error).__name__, error=str(error))
        (output / "traceback.log").write_text(traceback.format_exc())
    finally:
        report["elapsed_ns"] = time.monotonic_ns() - started
        report["source_after"] = pins()
        report["source_preserved"] = report["source_after"] == before
        if not report["source_preserved"]:
            report["status"] = "HOLD"
        report["files"] = {path.name: {"bytes": path.stat().st_size,
                                      "sha256": sha256(path.read_bytes()).hexdigest()}
                           for path in sorted(output.iterdir()) if path.is_file()}
        (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key: value for key, value in report.items()
                          if key not in {"functions", "files"}}, sort_keys=True))
    return 0 if report["status"] == "SOURCE_CORE_PASS_NATIVE_NOT_RUN" else 1

if __name__ == "__main__":
    raise SystemExit(main())
