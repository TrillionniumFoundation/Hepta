"""Recheck source against the exact graphs retained by validate_resources.

The input qualification owns native execution evidence. This gate adds fresh
source/graph correspondence; it neither duplicates execution nor substitutes
another lowerer. A source replay is not a refinement proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from hepta.ast import HeptaError
from hepta.modules import load_project
from hepta.pipeline import compiler_hash
from hepta.resource_ir import read_resource_ir
from hepta.resource_source import _CLAIMS, verify_resource_source
from tools.evidence_checks import is_sha, native_build, normalized_errors, require, strict_equal
from tools.validate_resources import EXAMPLES, ROOT


def _path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _new_report(input_path: Path) -> dict:
    return {"schema": "hepta.resource-source-qualification.v1", "status": "failed",
            "input": str(input_path), "input_sha256": None,
            "whole_language_soundness_proved": False, "source_to_ir_refinement_proved": False,
            "projects": [{"name": name, "entry": str(path.relative_to(ROOT)),
                          "status": "not_run", "source_replay": None}
                         for name, path in EXAMPLES.items()]}


def _input(path: Path, expected_hash: str | None = None) -> tuple[bytes, dict]:
    from tools.release_check import require_qualification, _strict_json

    with _path(path).open("rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    require(len(raw) <= 16 * 1024 * 1024, "Input qualification exceeds 16 MiB")
    if expected_hash is not None:
        require(is_sha(expected_hash) and hashlib.sha256(raw).hexdigest() == expected_hash,
                "Input qualification bytes differ from their retained identity")
    previous = _strict_json(raw)
    require(isinstance(previous, dict), "Input qualification must be a JSON object")
    require_qualification("independent_resource_ir", previous)
    return raw, previous


def _validate_row(row: dict, previous: dict, current_compiler: str) -> None:
    from tools.release_check import _frontend_checked

    name = row["name"]
    require(row.get("status") == "passed" and row.get("entry") == previous["entry"]
            and strict_equal(row.get("resource_ir"), previous["resource_ir"]),
            "Source replay row differs from its original executed project")
    replay = row["source_replay"]
    observed = hashlib.sha256(json.dumps(
        {k: v for k, v in replay.items() if k != "sha256"}, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    require(replay.get("schema") == "hepta.resource-source-validation.v1"
            and replay.get("sha256") == observed and replay.get("ok") is True
            and replay.get("source_binding_verified") is True and replay.get("diagnostics") == []
            and replay.get("binding_scope") == "exact_current_source_resource_projection_replay"
            and strict_equal(replay.get("claims"), _CLAIMS),
            "Source replay lacks its exact closed claims or retained result")
    try:
        project = load_project(EXAMPLES[name])
    except HeptaError as exc:
        raise ValueError("Current project could not be loaded: " + str(exc)) from exc
    source_hash = project.sources[str(project.entry)]
    inputs = {str(Path(path).relative_to(ROOT)): value for path, value in project.sources.items()}
    binding = replay["source_binding"]
    validation = replay["source_validation"]
    original = previous["native_gate"]
    verified = {k: v for k, v in previous["resource_verifier"].items() if k != "frontend_modules_imported"}
    require(_frontend_checked(validation, allow_external=True)
            and validation.get("schema") == "hepta.check.v1"
            and validation.get("compiler_sha256") == current_compiler
            and original.get("compiler_sha256") == current_compiler
            and validation.get("source_sha256") == original["source_sha256"] == source_hash
            and validation.get("path") == str(project.entry)
            and strict_equal(validation.get("project"), project.report())
            and strict_equal(original.get("project"), project.report())
            and strict_equal(previous["inputs"], inputs),
            "Native execution and fresh replay must identify this current compiler and complete source project")
    claims = {"whole_language_soundness_proved": False, "all_programs_faster_than_rust": False,
              "hardware_execution_verified": False, "bounded_cancellation_latency_proved": False,
              "deadlock_freedom_proved": False}
    require(strict_equal(validation.get("claims"), claims) and strict_equal(original.get("claims"), claims),
            "Native source checks must retain their exact bounded claims")
    native_build(validation["backend"], "rust", check_only=True, crate_type="rlib",
                 source_sha256=validation["rust_sha256"])
    require(validation["backend"].get("crate_type") == "rlib"
            and strict_equal(validation["backend"]["toolchain"], previous["native_build"]["toolchain"])
            and strict_equal(original["backend"]["toolchain"], previous["native_build"]["toolchain"])
            and validation["backend"]["target"] == previous["native_build"]["target"],
            "Fresh replay and executed native program use different native toolchains or targets")
    require(strict_equal(replay.get("resource_verification"), verified)
            and binding.get("source_sha256") == source_hash
            and binding.get("project_sha256") == project.identity
            and binding.get("compiler_sha256") == current_compiler
            and strict_equal(binding.get("source_inventory"), project.sources)
            and binding.get("resource_ir_sha256") == previous["resource_ir"]["canonical_sha256"]
            and binding.get("native_reference") == "rustc_checked"
            and binding.get("canonical_semantic_schema") == "hepta.hsir.v0"
            and is_sha(binding.get("canonical_semantic_sha256"))
            and strict_equal(binding.get("external_obligations"), verified["external_obligations"])
            and isinstance(binding.get("canonical_external_obligations"), list)
            and isinstance(binding.get("canonical_foreign_assumptions"), list),
            "Source replay lacks complete current source, semantic and resource identities")
    external = bool(binding["external_obligations"] or binding["canonical_external_obligations"]
                    or binding["canonical_foreign_assumptions"])
    require(replay["status"] == ("source_replayed_with_external_assumptions" if external else "source_replayed")
            and project.unchanged(), "Source replay status or source path bindings changed")


def qualify(input_path: Path, *, rustc: str | None = None) -> dict:
    result = _new_report(input_path)
    errors = (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError,
              IndexError, OverflowError, RecursionError, HeptaError, subprocess.TimeoutExpired)
    try:
        raw, previous = _input(input_path)
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    except errors as exc:
        result["validation_error"] = str(exc)
        return result
    originals = {row["name"]: row for row in previous["projects"]}
    current_compiler = compiler_hash()
    for row in result["projects"]:
        original = originals[row["name"]]
        row["resource_ir"] = original["resource_ir"]
        try:
            graph = read_resource_ir(_path(original["resource_ir"]["path"]))
            row["source_replay"] = verify_resource_source(EXAMPLES[row["name"]], graph, rustc=rustc)
            row["status"] = "passed"
            _validate_row(row, original, current_compiler)
        except errors as exc:
            row["status"] = "failed"
            row["validation_error"] = str(exc)
    if all(row["status"] == "passed" for row in result["projects"]):
        result["status"] = "passed"
        try:
            validate_report(result)
        except errors as exc:
            result["status"] = "failed"
            result["validation_error"] = str(exc)
    return result


@normalized_errors
def validate_report(report: dict) -> None:
    """Check retained observations against current files, without native reruns.

    This is consistency validation, not authentication of hostile JSON.
    The independent producer owns execution; source replay cannot promote an
    older compiler's native run to execution by the current candidate.
    """
    require(isinstance(report, dict), "Source qualification must be a JSON object")
    rows = report.get("projects", [])
    if (report.get("schema") != "hepta.resource-source-qualification.v1"
            or report.get("status") != "passed" or len(rows) != len(EXAMPLES)
            or {row.get("name") for row in rows} != set(EXAMPLES)
            or report.get("whole_language_soundness_proved") is not False
            or report.get("source_to_ir_refinement_proved") is not False):
        raise ValueError("Three complete source-bound resource replays are required")
    require(isinstance(report.get("input"), str) and bool(report["input"])
            and is_sha(report.get("input_sha256")), "Input qualification identity is missing")
    raw, previous = _input(Path(report["input"]), report["input_sha256"])
    originals = {row["name"]: row for row in previous["projects"]}
    current_compiler = compiler_hash()
    for row in rows:
        _validate_row(row, originals[row["name"]], current_compiler)
    require(_path(report["input"]).read_bytes() == raw and compiler_hash() == current_compiler,
            "Qualification input or compiler changed during report validation")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qualification", type=Path)
    parser.add_argument("--rustc")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output already exists")
    try:
        result = qualify(args.qualification, rustc=args.rustc)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError,
            IndexError, OverflowError, RecursionError, HeptaError, subprocess.TimeoutExpired) as exc:
        result = _new_report(args.qualification)
        result["validation_error"] = str(exc)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as destination:
        json.dump(result, destination, indent=2, sort_keys=True)
        destination.write("\n")
    print(json.dumps({"status": result["status"], "output": str(args.output)}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
