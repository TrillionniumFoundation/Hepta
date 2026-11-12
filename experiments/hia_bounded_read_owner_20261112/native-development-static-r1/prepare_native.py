"""Generate and compile the new bounded-read lifetime owner under original limits.

STATIC UNEXECUTED controller. The supplied original B3 is a development input;
this is not a cold build or proof of an installed/public replacement.
"""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import (_checked_parent, _create_bytes, _create_directory,
    create, measurements, pin, read, require, snapshot, wire)
from native_support import (CANDIDATE, CANDIDATE_TREE, COMPILER_BYTES, COMPILER_SHA,
    GENERATED, LIMITS, NATIVE_LIMITS, OVERLAYS, generated_rows, source_manifest)

QUALIFY_SHA = "a1c76c165856927bfbaded5610568fa79456f15e1eb356dda7a8b882bb602c92"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source_root, args.output
    require(source.is_absolute() and output.is_absolute() and source != output
            and source not in output.parents and ".." not in source.parts
            and ".." not in output.parts, "separate absolute source/evidence roots required")
    with _checked_parent(source / ".source-spine-probe"):
        pass
    _create_directory(output)
    report = {"schema": "hepta.hia.bounded-read-native-development-build.v1",
        "status": "HOLD", "scope": "DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD",
        "candidate_commit": CANDIDATE, "candidate_tree": CANDIDATE_TREE,
        "compiler_limits_changed": False, "compiler_wall_seconds": 20,
        "original_authoring_limits": LIMITS, "original_native_limits": NATIVE_LIMITS,
        "host_successor_compiler_calls": [], "syntax_checked": [],
        "native_component_controls_executed": False, "original_eight_executed": False,
        "cold_qualification": False, "whole_native_delivery_qualified": False}
    rows = before = manifest_raw = manifest_pin = compiler_pin = None
    assembly = None
    generated_published = False
    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                "preparation requires the actual -I -S -B child")
        require(sys.version_info[:3] == (3, 14, 4), "fixed CPython target differs")
        require(os.getcwd() == str(source), "fixed source working directory differs")
        require(not any(key.startswith(("HEPTA_HIA_", "LD_"))
                    or key in ("PYTHONPATH", "PYTHONHOME") for key in os.environ),
                "preparation inherited a selector/loader override")
        rows, manifest_raw, manifest_pin = source_manifest(args.source_manifest)
        before = snapshot(source, rows)
        report["source_before"] = create(output / "source-before.json", wire(before))
        report["source_manifest"] = manifest_pin
        compiler_raw, compiler_pin = read(args.compiler, COMPILER_BYTES)
        require(len(compiler_raw) == COMPILER_BYTES and compiler_pin["sha256"] == COMPILER_SHA,
                "fixed original B3 development input differs")
        report["compiler_before"] = compiler_pin
        for relative in OVERLAYS:
            raw, observed = read(source / relative, 1 << 20)
            ast.parse(raw, filename=str(source / relative))
            report["syntax_checked"].append({"path": relative, **pin(raw)})
        require(read(source / "tools/qualify_hia_selfhost.py", 1 << 20)[1]["sha256"] == QUALIFY_SHA,
                "unchanged native compile supervisor source differs")
        sys.path.insert(0, str(source))
        from tools.generate_hia_bounded_read import document
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        value = document()
        document_raw = wire(value)
        report["core_document"] = create(output / "bounded-read.hia.json", document_raw)
        assembly = render_assembly(value).encode("utf-8")
        report["assembly"] = create(output / "bounded-read.hiaasm", assembly)
        summary, functions = measurements(value, assembly)
        report.update(measurements=summary, functions=functions)
        require(summary["functions"] == 14
                and all(summary[name] <= limit for name, limit in LIMITS.items()),
                "fixed function population or original compiler cap differs")
        report["core_roundtrip"] = assemble_program(assembly).as_dict() == value
        require(report["core_roundtrip"], "complete public Core roundtrip differs")
        second = document()
        require(wire(second) == document_raw and render_assembly(second).encode() == assembly,
                "bounded-read HIA generation is not deterministic")
        report["deterministic_source"] = True
        require(value["functions"][0]["name"] == "f0"
                and [v["type"] for v in value["functions"][0]["params"]]
                    == ["readbuf", "mutbuf", "mutbuf"]
                and value["functions"][0]["returns"] == ["u32"], "entry ABI differs")
        generated = source / GENERATED
        require(not os.path.lexists(generated), "new generated source already exists")
        _create_bytes(generated, assembly, 0o644)
        generated_published = True
        report["generated_source"] = read(generated, 1 << 20)[1]
        expected = generated_rows(rows, assembly)
        prepared = snapshot(source, expected)
        require([row for row in prepared if row["path"] != GENERATED] == before,
                "generation changed a pre-existing source member")
        report["source_generated"] = create(output / "source-generated.json", wire(prepared))
        from tools import qualify_hia_selfhost as qualify
        require(qualify.ROOT == source and qualify.CAPACITY == 1 << 20
                and qualify.NATIVE_OBSERVER is None and qualify.NATIVE_LINKED_OBSERVER is None,
                "original native compiler route or buffers differ")
        def forbid_seed(*unused, **ignored):
            report["host_successor_compiler_calls"].append("build_seed")
            raise AssertionError("host successor compiler forbidden")
        qualify.build_seed = forbid_seed
        image, receipt = qualify.compile_stage(output, "bounded-read", args.compiler, assembly)
        report["native_compile_receipt"] = receipt
        require(receipt.get("status") == "returned" and receipt.get("abi_status") == 0
                and receipt.get("source_unchanged") is True
                and receipt.get("forbidden_compiler_modules_loaded") == []
                and receipt.get("limits") == NATIVE_LIMITS
                and receipt.get("artifact_sha256") == COMPILER_SHA
                and receipt.get("input_sha256") == sha256(assembly).hexdigest()
                and 0 < receipt.get("produced_bytes", 0) <= 1 << 20,
                "original actual native compile result differs")
        image_raw, image_pin = read(image, 1 << 20)
        require(image_pin["sha256"] == receipt["produced_sha256"]
                and len(image_raw) == receipt["produced_bytes"], "compiled image bytes differ")
        report["image"] = image_pin
        manifest = {"schema": "hepta.hia.bounded-read-native.v3",
            "source_sha256": sha256(assembly).hexdigest(), "image_path": image.name,
            "image_sha256": image_pin["sha256"], "compiler_sha256": COMPILER_SHA}
        report["manifest_file"] = create(output / "manifest.json", wire(manifest))
        report["manifest"] = manifest
        report["status"] = "NATIVE_BUILD_PENDING_FINAL_SOURCE_CHECK"
    except BaseException as error:
        report["status"] = "HOLD"
        report["error"] = {"type": type(error).__name__, "text": str(error),
                           "traceback": traceback.format_exc()}
    finally:
        try:
            if rows is not None and before is not None:
                expected = generated_rows(rows, assembly) if generated_published else rows
                after = snapshot(source, expected)
                report["source_after"] = create(output / "source-after.json", wire(after))
                require([row for row in after if row["path"] != GENERATED] == before,
                        "original source changed during preparation")
                report["source_preserved_except_new_resource"] = True
                current_raw, current_pin = read(args.source_manifest, len(manifest_raw))
                require(current_raw == manifest_raw and current_pin == manifest_pin,
                        "fixed source manifest changed")
            if compiler_pin is not None:
                report["compiler_after"] = read(args.compiler, COMPILER_BYTES)[1]
                require(report["compiler_after"] == compiler_pin, "B3 development input changed")
            if report["status"] == "NATIVE_BUILD_PENDING_FINAL_SOURCE_CHECK":
                require(report.get("source_preserved_except_new_resource") is True
                        and not report["host_successor_compiler_calls"],
                        "final source verification is incomplete")
                report["status"] = "NATIVE_DEVELOPMENT_IMAGE_BUILT_NOT_QUALIFICATION"
        except BaseException as error:
            report["status"] = "HOLD"
            report["final_error"] = {"type": type(error).__name__, "text": str(error),
                                     "traceback": traceback.format_exc()}
        create(output / "report.json", wire(report))
    print(json.dumps({"status": report["status"], "measurements": report.get("measurements"),
                      "cold_qualification": False}), flush=True)
    return 0 if report["status"] == "NATIVE_DEVELOPMENT_IMAGE_BUILT_NOT_QUALIFICATION" else 1

if __name__ == "__main__":
    raise SystemExit(main())
