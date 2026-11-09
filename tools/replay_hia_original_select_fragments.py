#!/usr/bin/env python3
"""Recheck pinned copied-fragment evidence with fresh supplied-byte SMT queries.

Does not execute the compiler or any native image and never creates an Agent
acceptance receipt. The original fragment/scaffolding proof boundary is retained.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def replay(source, expected_manifest_sha256, output):
    prefix = output / "empty-bytecode-cache"
    if (not sys.dont_write_bytecode or sys.pycache_prefix is None
            or Path(sys.pycache_prefix).resolve() != prefix.resolve() or list(prefix.rglob("*"))):
        raise ValueError("a fresh isolated source-only import prefix is required")
    sys.path.insert(0, str(ROOT))
    from tools.qualify_hia_original_select_fragments import (
        HASHES, SCHEMA, WIDTHS, digest, projection_object, require, save, select_fragment)
    from hepta.hia_safe_core import validate_safe_core_artifact
    from hepta.hia_safe_core_elf import bind_final_artifact
    from tools.hia_selfhost_select import select_cases
    from tools.qualify_hia_safe_core_cmovne import selection_core, witness_vectors, mathematical_result
    source = source.resolve(strict=True)
    manifest_bytes = (source / "artifact-manifest.json").read_bytes()
    require(digest(manifest_bytes) == expected_manifest_sha256, "retained artifact manifest differs")
    manifest = json.loads(manifest_bytes)
    require(type(manifest) is dict and 1 <= len(manifest) <= 1024, "artifact manifest shape is outside budget")
    for name, expected in manifest.items():
        path = source / name
        require(not Path(name).is_absolute() and path.resolve().is_relative_to(source)
                and path.is_file() and not path.is_symlink(), "artifact path escapes the evidence directory")
        require(path.stat().st_size <= 32 * 1024 * 1024 and digest(path.read_bytes()) == expected,
                "retained artifact bytes differ: " + name)
    report = json.loads((source / "qualification.json").read_bytes())
    require(report["schema"] == SCHEMA and report["status"] == "PASS_SCOPED_COPIED_FRAGMENTS"
            and report["original_agent_four_claim_gate"] == "HOLD"
            and report["agent_proof_receipt_issued"] is False
            and report["evaluation_performed"] is False and report["adoption_authorized"] is False
            and report["whole_compiler_or_original_agent_delta_proved"] is False
            and [row["type"] for row in report["cases"]] == list(WIDTHS), "retained scope or case inventory differs")
    require(report["exact_frozen_input_sha256"] == HASHES, "frozen input identities differ")
    for name, expected in HASHES.items():
        suffix = ".patch" if name == "patch" else ".hiaasm"
        require(digest((source / "frozen-inputs" / (name + suffix)).read_bytes()) == expected,
                "original task input bytes differ")
    require(digest((source / "frozen-c1-seed/B0.so").read_bytes()) == report["candidate_seed_image_sha256"],
            "recorded seed image differs")
    rows = []
    for original in report["cases"]:
        typ = original["type"]
        directory = source / typ
        source_bytes = (directory / "actual-c1-output.input.bin").read_bytes()
        image = (directory / "actual-c1-output.image.bin").read_bytes()
        site = select_fragment(source_bytes, image)
        require(site == original["source_binding"], "copied interval or actual compiler output differs")
        core = selection_core(typ)
        require(core.canonical_bytes == (directory / "specification.core.json").read_bytes()
                and core.sha256 == original["specification_core_sha256"], "selection specification differs")
        obj = (directory / "projection.o").read_bytes()
        final = (directory / "projection.so").read_bytes()
        rederived, projection = projection_object(site)
        require(rederived == obj and projection == original["projection"], "projection scaffolding differs")
        require(digest(obj) == original["projection_object_sha256"]
                and digest(final) == original["projection_image_sha256"], "proof subject differs")
        bound = bind_final_artifact(obj, final, "choose")
        require(bound["text"][projection["copied_text_start"]:projection["copied_text_end"]]
                == bytes.fromhex(site["fragment_hex"]), "linked copied bytes differ")
        old = json.loads((directory / "validation.json").read_bytes())
        fresh = validate_safe_core_artifact(core, obj, final, query_directory=output / (typ + "-queries"))
        require(fresh["ok"] and fresh["complete"] and fresh["status"] == "smt_validated",
                "fresh independent supplied-byte obligations did not pass")
        for key in ("subject", "property", "profile", "assumptions", "checker", "unproved_obligations"):
            require(fresh[key] == old[key], "fresh proof identity or scope changed: " + key)
        require([(r["name"], r["query_sha256"], r["result"]) for r in fresh["obligations"]]
                == [(r["name"], r["query_sha256"], r["result"]) for r in old["obligations"]],
                "replayed SMT obligations changed")
        cases = [row for row in select_cases() if row["type"] == typ]
        witnesses = json.loads((directory / "whole-output-finite-witnesses.json").read_bytes())
        require([row["case"] for row in witnesses] == cases, "whole-output finite case inventory changed")
        for index, case in enumerate(cases):
            label = "whole-output-case-" + str(index)
            actual = json.loads((directory / (label + ".stdout.log")).read_bytes())
            value = int(case["expected"])
            expected_input = (bytes([int(case["condition"])]) + int(case["left"]).to_bytes(8, "little")
                              + int(case["right"]).to_bytes(8, "little"))
            require((directory / (label + ".input.bin")).read_bytes() == expected_input
                    and (directory / (label + ".output.bin")).read_bytes() == value.to_bytes(8, "little")
                    and actual.get("status") == "returned" and actual.get("core_u32") == value & 0xffffffff
                    and actual.get("source_unchanged") is True, "retained whole-output observation differs")
        case = {"type": typ, "kind": "frozen-c1-copied-fragment"}
        native = json.loads((directory / "native-process.json").read_bytes())
        observed = json.loads(native["stdout"])
        vectors = witness_vectors(case)
        require(native["returncode"] == 0 and observed["image_sha256"] == digest(final)
                and observed["vectors"] == vectors
                and observed["results"] == [mathematical_result(case, vector) for vector in vectors],
                "retained projected-image observation differs")
        save(output / (typ + "-validation.json"), fresh)
        rows.append({"type": typ, "status": fresh["status"], "obligations": len(fresh["obligations"]),
                     "compiler_output_sha256": site["compiler_output_sha256"],
                     "whole_generated_program_finite_cases_rechecked": len(cases),
                     "projected_native_cases_rechecked": len(vectors)})
    result = {"schema": "hepta.hia.original-select-copied-fragments-replay.v1", "status": "PASS",
        "manifest_sha256": expected_manifest_sha256, "retained_artifacts_checked": len(manifest),
        "cases": rows, "native_execution_performed": False, "compiler_execution_performed": False,
        "new_agent_receipts": False, "original_agent_four_claim_gate": "HOLD",
        "scope": "fresh independent model checks of the exact copied fragment projections, retaining all preconditions"}
    require(not list(prefix.rglob("*")), "unexpected bytecode in the isolated replay cache")
    save(output / "replay.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.output.resolve()
    if args.worker:
        result = replay(args.input, args.expected_manifest_sha256, output)
        print(json.dumps(result, sort_keys=True))
        return
    output.mkdir(parents=True, exist_ok=False)
    prefix = output / "empty-bytecode-cache"
    prefix.mkdir()
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", "--input", str(args.input.resolve()),
        "--expected-manifest-sha256", args.expected_manifest_sha256, "--output", str(output)]
    process = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False, cwd=ROOT,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPYCACHEPREFIX=str(prefix)))
    (output / "worker-process.json").write_text(json.dumps({"command": command, "returncode": process.returncode,
        "stdout": process.stdout, "stderr": process.stderr}, indent=2, sort_keys=True) + "\n")
    print(process.stdout, end="")
    if process.returncode:
        print(process.stderr, end="", file=sys.stderr)
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
