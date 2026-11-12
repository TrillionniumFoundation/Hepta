"""Draft: generate bounded-read Core in a precreated independent source copy.

This worker has no launch/workflow authority. It must run in a fresh -I -S -B
process owned by the unchanged 180-second/3-second-cleanup controller, with a
60-second source-authoring child deadline. No compiler image is loaded or run.
The outer controller and fixed runtime inputs are not yet frozen.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import sys
import traceback

MANIFEST_SHA256 = "bf0ac5d7c9965c10c2b0c6f6467a8adca3d0d7e1539261de412c6b85144e5bc0"
BASE_COMMIT = "acffa9262f31d073f8f0a6f0201eae201039f619"
BASE_TREE = "22a095436c94efc87b1a89aca912c8caab2eed80"
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


def require(value, message):
    if not value:
        raise RuntimeError(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def identity(value):
    return {
        "device": value.st_dev, "inode": value.st_ino, "mode": value.st_mode,
        "uid": value.st_uid, "gid": value.st_gid, "nlink": value.st_nlink,
        "size": value.st_size, "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest(),
            "git_blob_sha1": sha1(b"blob " + str(len(raw)).encode()
                                  + b"\0" + raw).hexdigest()}


def create(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    require(path.read_bytes() == raw, "new evidence readback differs")
    return {"path": str(path), **pin(raw)}


def regular_bytes(path, expected_size=None):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "source or input is not a regular file")
    if expected_size is not None:
        require(before.st_size == expected_size, "source size differs")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        require(identity(opened) == identity(before), "source changed before open")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        require(identity(os.fstat(descriptor)) == identity(opened),
                "source changed during read")
    finally:
        os.close(descriptor)
    require(identity(path.lstat()) == identity(before)
            and len(raw) == before.st_size, "source changed after read")
    return raw, identity(before)


def checked_manifest(path):
    raw, metadata = regular_bytes(path, 821535)
    require(sha256(raw).hexdigest() == MANIFEST_SHA256, "fixed source manifest differs")
    value = json.loads(raw)
    require(value["schema"] == "hepta.hia.bounded-read-source-authoring-manifest.v1"
            and value["canonical_base_commit"] == BASE_COMMIT
            and value["canonical_base_tree"] == BASE_TREE
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


def snapshot(source, rows):
    require(stat.S_ISDIR(source.lstat().st_mode), "source root is not an ordinary directory")
    expected_files = {row["path"] for row in rows}
    expected_directories = set()
    for name in expected_files:
        parts = name.split("/")
        expected_directories.update("/".join(parts[:index])
                                    for index in range(1, len(parts)))
    actual_files, actual_directories = set(), set()
    for directory, names, files in os.walk(source, followlinks=False):
        relative = Path(directory).relative_to(source)
        if relative == Path("."):
            # Object storage itself is outside this byte-copy source audit.
            # No Git HEAD, index, object-consumer or clone claim is made.
            names[:] = [name for name in names if name != ".git"]
            files[:] = [name for name in files if name != ".git"]
        for name in names:
            path = Path(directory) / name
            require(stat.S_ISDIR(path.lstat().st_mode), "source directory is a link or special")
            actual_directories.add(path.relative_to(source).as_posix())
        for name in files:
            actual_files.add((Path(directory) / name).relative_to(source).as_posix())
    require(actual_files == expected_files
            and actual_directories == expected_directories,
            "complete source namespace differs")
    result = []
    for row in rows:
        path = source / row["path"]
        raw, metadata = regular_bytes(path, row["size"])
        observed = pin(raw)
        expected_mode = 0o644 if row["mode"] == "100644" else 0o755
        require(stat.S_IMODE(metadata["mode"]) == expected_mode
                and observed["git_blob_sha1"] == row["git_blob_sha1"]
                and ("sha256" not in row or observed["sha256"] == row["sha256"]),
                "fixed source bytes or mode differ: " + row["path"])
        result.append({"path": row["path"], "mode": row["mode"],
                       **observed, "identity": metadata})
    return result


def measurements(document, assembly):
    functions = []
    for function in document["functions"]:
        values = list(function["params"])
        edges, blocks, operands, returns = [], [], [], []
        for block in function["blocks"]:
            values.extend(block["params"])
            blocks.append(len(block["params"]))
            for operation in block["ops"]:
                values.extend(operation["out"])
                operands.append(len(operation["args"]))
            term = block["term"]
            if term["op"] == "jump":
                edges.append(len(term["args"]))
            elif term["op"] == "branch":
                edges.extend((len(term["then"]["args"]), len(term["else"]["args"])))
            elif term["op"] == "ret":
                returns.append(len(term["values"]))
        names = {value["name"] for value in values}
        indices = [int(name[1:]) for name in names
                   if type(name) is str and name.startswith("v")
                   and name[1:].isascii() and name[1:].isdecimal()]
        functions.append({
            "name": function["name"], "blocks": len(function["blocks"]),
            "operations": sum(len(block["ops"]) for block in function["blocks"]),
            "unique_ssa_names": len(names),
            "function_parameters": len(function["params"]),
            "max_block_parameters": max(blocks, default=0),
            "max_edge_arguments": max(edges, default=0),
            "max_operation_arguments": max(operands, default=0),
            "max_return_arguments": max(returns, default=0),
            "largest_numeric_ssa_index_diagnostic": max(indices, default=None),
        })
    summary = {
        "source_bytes": len(assembly), "source_lines": len(assembly.splitlines()),
        "functions": len(functions), "blocks": sum(row["blocks"] for row in functions),
        "max_blocks_per_function": max((row["blocks"] for row in functions), default=0),
        "operations": sum(row["operations"] for row in functions),
        "max_unique_ssa_names_per_function": max(
            (row["unique_ssa_names"] for row in functions), default=0),
    }
    for name in ("function_parameters", "max_block_parameters", "max_edge_arguments",
                 "max_operation_arguments", "max_return_arguments"):
        output = "max_function_parameters" if name == "function_parameters" else name
        summary[output] = max((row[name] for row in functions), default=0)
    return summary, functions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_root.absolute()
    output = args.output_dir.absolute()
    require(source != output and source not in output.parents,
            "evidence must not be inside candidate source")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {
        "schema": "hepta.hia.bounded-read-source-authoring.v1",
        "status": "HOLD", "scope": "NEW_COMPONENT_SOURCE_AUTHORING_ONLY",
        "canonical_base_commit": BASE_COMMIT, "canonical_base_tree": BASE_TREE,
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
            raw, _ = regular_bytes(source / relative)
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
                current_manifest, current_identity = regular_bytes(args.source_manifest)
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
