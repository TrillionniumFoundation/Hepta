#!/usr/bin/env python3
"""Read-only structural checks for the fixed selfhost/lifecycle merge packet.

This validates text and AST custody. It does not generate HIA, import product
modules, execute tests, or grant native/cold qualification.
"""
import argparse
import ast
from hashlib import sha1, sha256
import json
from pathlib import Path


def identity(raw):
    return {
        "bytes": len(raw),
        "sha256": sha256(raw).hexdigest(),
        "git_blob": sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
    }


def fields(value):
    if isinstance(value, ast.AST):
        return (type(value).__name__, tuple(
            (name, fields(child)) for name, child in ast.iter_fields(value)))
    if isinstance(value, list):
        return tuple(fields(child) for child in value)
    return (type(value).__name__, value)


def inventory(tree):
    result = {}
    for cls in tree.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        for child in cls.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name.startswith("test_"):
                name = cls.name + "." + child.name
                if name in result:
                    raise AssertionError("duplicate test method: " + name)
                result[name] = child
    return result


def definitions(tree):
    return {node.name: node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


def original(root, path, pin):
    if pin is None:
        return None
    raw = (root / path).read_bytes()
    if identity(raw)["git_blob"] != pin["blob"]:
        raise AssertionError("original preimage changed: " + path)
    return raw


def check(packet, main_root, a733_root, candidate_root):
    if packet["status"] != "AUTHORED_NOT_EXECUTED":
        raise AssertionError("wrong candidate packet state")
    reports, parsed = [], {}
    for path, row in packet["files"].items():
        raw = row["after"]["text"].encode("utf-8")
        actual = identity(raw)
        if any(actual[key] != row["after"][key] for key in actual):
            raise AssertionError("packet bytes changed: " + path)
        old_main = original(main_root, path, row["before"]["main"])
        old_a733 = original(a733_root, path, row["before"]["a733"])
        if candidate_root is not None and (candidate_root / path).read_bytes() != raw:
            raise AssertionError("candidate bytes differ: " + path)
        result = {"path": path, **actual, "main_preimage_checked": old_main is not None,
                  "a733_preimage_checked": old_a733 is not None}
        if path.endswith(".py"):
            after = ast.parse(raw, filename=path)
            parsed[path] = after
            result["parsed"] = True
            if path.startswith("tests/"):
                after_ids = inventory(after)
                result["actual_top_level_class_test_ids"] = list(after_ids)
                for label, old in (("main", old_main), ("a733", old_a733)):
                    if old is None:
                        continue
                    before_ids = inventory(ast.parse(old, filename=label + "/" + path))
                    missing = set(before_ids) - set(after_ids)
                    if missing:
                        raise AssertionError((path, label, "missing tests", sorted(missing)))
                    result[label + "_method_ids_preserved"] = True
                if path in (
                        "tests/test_hia_artifact_publication_route.py",
                        "tests/test_hia_reference_fixture_efficiency.py"):
                    before_ids = inventory(ast.parse(old_main))
                    for name, node in before_ids.items():
                        if fields(node) != fields(after_ids[name]):
                            raise AssertionError((path, name, "main method AST changed"))
                    result["all_original_main_test_AST_fields_equal"] = True
            elif row["merge"]["strategy"].startswith("retain exact main"):
                if raw != old_main:
                    raise AssertionError("exact-main choice changed: " + path)
        reports.append(result)

    path = "tools/qualify_hia_selfhost.py"
    old = original(a733_root, path, packet["files"][path]["before"]["a733"])
    before_defs = definitions(ast.parse(old))
    after_defs = definitions(parsed[path])
    for name in ("_compile_observation_size", "compile_stage", "invoke"):
        if fields(before_defs[name]) != fields(after_defs[name]):
            raise AssertionError(("strict receipt or observer function changed", name))

    path = "tests/test_hia_reference_fixture_efficiency.py"
    old = original(a733_root, path, packet["files"][path]["before"]["a733"])
    old_ids = inventory(ast.parse(old))
    new_ids = inventory(parsed[path])
    old_name = "ReferenceFixturePreservationTests.test_complete_compiler_renames_keep_original_and_modified_bytes"
    new_name = "ReferenceFixturePreservationTests.test_v64_compiler_renames_keep_original_and_modified_bytes"
    renamed = new_ids[new_name]
    renamed.name = old_ids[old_name].name
    if fields(renamed) != fields(old_ids[old_name]):
        raise AssertionError("a733 historical fixture/goldens changed")
    current = "ReferenceFixturePreservationTests.test_current_compiler_original_three_passes_match_complete_composed_bytes"
    if fields(old_ids[current]) != fields(new_ids[current]):
        raise AssertionError("a733 original three-pass control changed")

    held = {
        "tools/hia_selfhost_process_owner.py": "6f600ab75894859b9840c0311cc8891a67b6c53a",
        "tools/replay_hia_selfhost_cold.py": "0d53ccbd2e56240280938ab829fe9c9798f02075",
    }
    for path, blob in held.items():
        for root in (main_root, a733_root):
            if identity((root / path).read_bytes())["git_blob"] != blob:
                raise AssertionError("original cold supervisor changed: " + path)
        if candidate_root is not None and identity((candidate_root / path).read_bytes())["git_blob"] != blob:
            raise AssertionError("candidate cold supervisor changed: " + path)
    return {
        "schema": "hepta.selfhost-lifecycle-merge-static-result.v1",
        "status": "PASS",
        "scope": "SOURCE_AST_AND_CUSTODY_ONLY",
        "files": reports,
        "cold_supervisor_original_bytes_preserved": held,
        "product_imports_executed": False,
        "HIA_generated": False,
        "native_or_cold_qualified": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--main-source", type=Path, required=True)
    parser.add_argument("--a733-source", type=Path, required=True)
    parser.add_argument("--candidate-source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    packet_bytes = args.packet.read_bytes()
    expected = "fa39509fa4af2823baea056d72653edfc56a300ca7aaff3b6ab6916d0b62e43b"
    if sha256(packet_bytes).hexdigest() != expected:
        raise AssertionError("fixed source packet differs")
    try:
        report = check(json.loads(packet_bytes), args.main_source, args.a733_source,
                       args.candidate_source)
    except BaseException as error:
        report = {"status": "FAIL", "error_type": type(error).__name__, "error": str(error),
                  "scope": "SOURCE_AST_AND_CUSTODY_ONLY", "native_or_cold_qualified": False}
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        raise
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
