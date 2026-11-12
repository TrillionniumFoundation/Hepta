"""Generate and check one fixed bounded-read source candidate, never native code.

Run only as a fresh -I -S -B child beneath the original 180/3 external owner
and the original workflow helper's separate 60-second source step. This source
is an unexecuted authoring revision, not a replacement for read_bounded.
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

# This path is the fixed private controller directory, bound by the outer
# request before this interpreter is launched. It is not the product source.
sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import (
    _checked_parent, _create_directory, create, measurements, pin, read,
    require, snapshot, wire,
)

MANIFEST_SHA256 = "2e130e0a77516bbf1a5b0ffa772ed849b4e29d45102195c271c5713dac42484c"
BASE_COMMIT = "9704596acc4470bd0042838586602e26bac7b3d1"
BASE_TREE = "c3ca94c57f9bd75f22f2c694e32bca2dfc6b329b"
CANDIDATE_COMMIT = "436398aca7297059eeaca45e5fd8af1e028bf0e6"
CANDIDATE_TREE = "8df3f6a460d757f522224a337630b8a8480cad59"
OVERLAYS = ("hepta/hia_bounded_read_native.py", "tools/generate_hia_bounded_read.py")
EXPECTED_FUNCTIONS = 12
LIMITS = {
    "source_bytes": 1048576, "source_lines": 16384, "functions": 128,
    "blocks": 1536, "max_blocks_per_function": 256, "operations": 8192,
    "max_unique_ssa_names_per_function": 2048,
    "max_function_parameters": 16, "max_block_parameters": 16,
    "max_edge_arguments": 16, "max_operation_arguments": 16,
    "max_return_arguments": 16,
}


def checked_manifest(path):
    raw, metadata = read(path, 821592)
    require(metadata['bytes'] == 821592, 'fixed source manifest extent differs')
    require(sha256(raw).hexdigest() == MANIFEST_SHA256, "fixed source manifest differs")
    value = json.loads(raw)
    require(value["schema"] == "hepta.hia.bounded-read-source-authoring-manifest.v2"
            and value["canonical_base_commit"] == BASE_COMMIT
            and value["canonical_base_tree"] == BASE_TREE
            and value["canonical_candidate_commit"] == CANDIDATE_COMMIT
            and value["canonical_candidate_tree"] == CANDIDATE_TREE
            and value["base_members"] == 4023
            and value["candidate_members"] == 4025
            and value["overlay_paths"] == list(OVERLAYS),
            "fixed source manifest header differs")
    rows = value["files"]
    require(len(rows) == 4025
            and len({row["path"] for row in rows}) == 4025,
            "complete candidate member count differs")
    for row in rows:
        parts = row["path"].split("/")
        require(parts and all(part not in ("", ".", "..") for part in parts)
                and not row["path"].startswith("/")
                and "\0" not in row["path"] and "\\" not in row["path"]
                and parts[0] != ".git"
                and row["mode"] in ("100644", "100755")
                and type(row["size"]) is int and row["size"] >= 0,
                "invalid fixed source manifest member")
    return rows, raw, metadata



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_root
    require(source.is_absolute() and '..' not in source.parts,
            'canonical absolute source path required')
    # Validate the entire path spine without resolving through a symlink.
    with _checked_parent(source / '.source-spine-probe'):
        pass
    require(args.output_dir.name not in ("", ".", ".."), "ordinary evidence directory name required")
    output = args.output_dir
    require(output.is_absolute() and '..' not in output.parts,
            'canonical absolute output path required')
    with _checked_parent(output):
        pass
    require(source != output and source not in output.parents,
            "evidence must not be inside candidate source")
    _create_directory(output)
    report = {
        "schema": "hepta.hia.bounded-read-source-authoring.v2",
        "status": "HOLD", "scope": "NEW_COMPONENT_SOURCE_AUTHORING_ONLY",
        "canonical_base_commit": BASE_COMMIT, "canonical_base_tree": BASE_TREE,
        "canonical_candidate_commit": CANDIDATE_COMMIT,
        "canonical_candidate_tree": CANDIDATE_TREE,
        "complete_source_members": 4025, "baseline_members": 4023,
        "syntax_checked": [], "original_limits": LIMITS,
        "native_compilation_executed": False, "native_execution_executed": False,
        "old_or_new_lifecycle_controls_executed": False,
        "original_eight_test_methods_executed": False,
        "formal_git_consumer_or_clone_qualification": False,
        "cold_qualified": False, "default_activation": False,
        "whole_native_delivery_qualified": False,
    }
    rows = before = manifest_raw = manifest_identity = None
    try:
        require(sys.dont_write_bytecode and sys.flags.isolated and sys.flags.no_site,
                "worker requires a fresh -I -S -B process")
        refused = sorted(key for key in os.environ
                         if key.startswith(("HEPTA_HIA_", "LD_"))
                         or key in ("PYTHONPATH", "PYTHONHOME"))
        require(not refused, "unexpected ambient selector or loader configuration")
        rows, manifest_raw, manifest_identity = checked_manifest(args.source_manifest)
        before = snapshot(source, rows)
        report["source_before"] = create(output / "source-before.json", wire(before))
        report["source_manifest"] = {**pin(manifest_raw), "identity": manifest_identity}
        for relative in OVERLAYS:
            raw, _ = read(source / relative, 1 << 20)
            ast.parse(raw, filename=str(source / relative))
            report["syntax_checked"].append(relative)
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
        require(summary["functions"] == EXPECTED_FUNCTIONS
                and all(summary[name] <= limit for name, limit in LIMITS.items()),
                "original compiler authoring cap or fixed function count differs")
        report["core_roundtrip"] = assemble_program(assembly).as_dict() == value
        require(report["core_roundtrip"], "public complete Core roundtrip differs")
        second = document()
        report["deterministic_source"] = (wire(second) == document_raw
                                          and render_assembly(second).encode() == assembly)
        require(report["deterministic_source"], "generator source bytes are not deterministic")
        require(value["functions"][0]["name"] == "f0"
                and [v["type"] for v in value["functions"][0]["params"]]
                    == ["readbuf", "mutbuf", "mutbuf"]
                and value["functions"][0]["returns"] == ["u32"],
                "public byte ABI entry differs")
        report["status"] = "SOURCE_AUTHORING_PENDING_FINAL_SOURCE_CHECK"
    except BaseException as exception:
        report["status"] = "HOLD"
        report["error"] = {"type": type(exception).__name__,
                           "traceback": traceback.format_exc()}
    finally:
        try:
            if rows is not None:
                after = snapshot(source, rows)
                report["source_after"] = create(output / "source-after.json", wire(after))
                report["source_stable"] = before is not None and after == before
                current_manifest, current_identity = read(args.source_manifest, 821592)
                report["manifest_stable"] = (current_manifest == manifest_raw
                                            and current_identity == manifest_identity)
                require(report["source_stable"] and report["manifest_stable"],
                        "source or manifest changed during authoring")
            else:
                report["source_stable"] = report["manifest_stable"] = False
            if report["status"] == "SOURCE_AUTHORING_PENDING_FINAL_SOURCE_CHECK":
                require(report["source_stable"] and report["manifest_stable"],
                        "final source checks absent")
                report["status"] = "SOURCE_AUTHORING_PASS_NOT_NATIVE_QUALIFIED"
        except BaseException as exception:
            report["status"] = "HOLD"
            report["final_check_error"] = {
                "type": type(exception).__name__, "traceback": traceback.format_exc()}
        create(output / "report.json", wire(report))
        print(json.dumps({"status": report["status"], "scope": report["scope"],
                          "measurements": report.get("measurements"),
                          "source_stable": report.get("source_stable"),
                          "error": report.get("error"),
                          "final_check_error": report.get("final_check_error")}), flush=True)
    return 0 if report["status"] == "SOURCE_AUTHORING_PASS_NOT_NATIVE_QUALIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
