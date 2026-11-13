#!/usr/bin/env python3
"""Run and retain one unchanged product Gate selected only by target.json.

The retained supervisor owns its started POSIX process group for 5400 seconds.
It makes no full-process-tree or whole-native-product completion claim.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import types
import unittest

TARGET_SCHEMA = "hepta.hia.verified-increment-audit-target.v1"
PRODUCT_REPOSITORY = "TrillionniumFoundation/Hepta"
SUPERVISOR = "review-evidence/hia-native-rewrite-20261111/workflow_process.py"
SOURCE_CHECKER = "tools/hia_core_source_identity.py"
HARNESS_FILES = {
    ".github/workflows/audit.yml": "audit.yml",
    "prepare-dependencies.sh": "prepare-dependencies.sh",
    "run-gate.py": "run-gate.py",
    "target.json": "target.json",
    "README.md": "README.md",
}


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def git_raw(root, *arguments):
    return subprocess.check_output(["git", "--no-replace-objects", *arguments], cwd=root)


def git(root, *arguments):
    return git_raw(root, *arguments).decode().strip()


def load_target(path):
    value = json.loads(Path(path).read_bytes())
    if (not isinstance(value, dict) or set(value) != {"schema", "repository", "commit", "tree"}
            or value["schema"] != TARGET_SCHEMA or value["repository"] != PRODUCT_REPOSITORY
            or not all(isinstance(value[name], str) and re.fullmatch(r"[0-9a-f]{40}", value[name])
                       for name in ("commit", "tree"))):
        raise ValueError("target.json must name the product and full immutable commit/tree SHA-1 values")
    return value


def require_native_runner():
    if sys.version_info[:2] != (3, 14) or sys.platform != "linux" or platform.machine() != "x86_64":
        raise ValueError("requires the provisioned Linux x86_64 Python 3.14 runner")


def source_admission(root, target):
    """Reuse the product's checker from its immutable Git blob, before imports.

    Loading that exact blob avoids trusting a modified working-tree checker to
    approve itself. Its existing _source_state implementation checks every raw
    HEAD blob, executable mode, regular file and parent, independently of index
    hints and filters. This harness does not replace that implementation.
    """
    root = Path(root).resolve(strict=True)
    if git(root, "rev-parse", "HEAD") != target["commit"]:
        raise ValueError("source HEAD differs from target.json")
    if git(root, "rev-parse", target["commit"] + "^{tree}") != target["tree"]:
        raise ValueError("source tree differs from target.json")
    checker_bytes = git_raw(root, "cat-file", "blob", target["commit"] + ":" + SOURCE_CHECKER)
    checker = types.ModuleType("source_identity_from_raw_target")
    checker.__file__ = str(root / SOURCE_CHECKER)
    exec(compile(checker_bytes, "<raw target:" + SOURCE_CHECKER + ">", "exec"), checker.__dict__)
    observed = checker._source_state(root=root)
    if observed["head"] != target["commit"] or observed["tree"] != target["tree"] or observed["status"]:
        raise ValueError("raw source identity changed or the product worktree is dirty")
    return {
        "scope": "COMPLETE_RAW_HEAD_BLOB_BYTES_AND_EXECUTABLE_MODES_NO_TEST_EXECUTION",
        "target": target,
        "source_checker_git_blob_sha256": hashlib.sha256(checker_bytes).hexdigest(),
        "actual_source": observed,
    }


def resolve(args):
    target = load_target(args.target)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as stream:
            for key in ("repository", "commit", "tree"):
                stream.write(key + "=" + target[key] + "\n")
    print(json.dumps(target, indent=2, sort_keys=True))
    return 0


def preflight(args):
    target = load_target(args.target)
    report = source_admission(args.source, target)
    report.update(python=sys.version, target_file_sha256=sha(args.target))
    write_json(args.output, report)
    print(json.dumps({"head": target["commit"], "tree": target["tree"],
                      "admitted_files": len(report["actual_source"]["files"])}))
    return 0


def run(args):
    require_native_runner()
    target_path = args.target.resolve(strict=True)
    target = load_target(target_path)
    target_sha = sha(target_path)
    root = args.source.resolve(strict=True)
    environment_path = args.environment.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(root):
        raise ValueError("output must be a new directory outside the source checkout")
    before = source_admission(root, target)
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "source-before.json", before)
    environment = json.loads(environment_path.read_bytes())
    if not isinstance(environment, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in environment.items()):
        raise ValueError("environment.json must contain string variables")
    preparation_path = environment_path.parent / "preparation.json"
    preparation = json.loads(preparation_path.read_bytes())
    if (preparation.get("target") != target or preparation.get("target_file_sha256") != target_sha
            or preparation.get("environment") != environment
            or preparation.get("native_identity_admission_completed") is not True
            or preparation.get("current_stream_handshake_and_close_completed") is not True):
        raise ValueError("native preparation does not bind this exact target and environment")
    os.environ.update(environment)
    os.environ["PATH"] = "/usr/lib/llvm-20/bin:" + os.environ.get("PATH", "")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.dont_write_bytecode = True
    os.chdir(root)
    sys.path.insert(0, str(root))

    # Native test availability is frozen at first import. The full declared
    # selector list is loaded after environment configuration, without edits.
    from tools import qualify_hia_verified_increment as gate
    from tools.run_hia_unittest_gate import load_declared_suite
    suite, planned = load_declared_suite(gate.MODULES)
    pending, skips, expected_failures = [suite], [], []
    while pending:
        case = pending.pop()
        if isinstance(case, unittest.TestSuite):
            pending.extend(reversed(list(case)))
            continue
        method = getattr(case, case._testMethodName)
        if getattr(case, "__unittest_skip__", False) or getattr(method, "__unittest_skip__", False):
            skips.append({"id": case.id(), "reason": getattr(case, "__unittest_skip_why__", "") or getattr(method, "__unittest_skip_why__", "")})
        if getattr(case, "__unittest_expecting_failure__", False) or getattr(method, "__unittest_expecting_failure__", False):
            expected_failures.append(case.id())
    write_json(output / "discovery.json", {
        "schema": "hepta.hia.verified-increment-discovery-only.v1",
        "scope": "READ_ONLY_DISCOVERY_NO_TEST_BODY_EXECUTION_NO_PASS_CLAIM",
        "target": target, "python": sys.version,
        "selectors": list(gate.MODULES), "selector_count": len(gate.MODULES),
        "planned_test_ids": list(planned), "planned_test_count": len(planned),
        "planned_test_ids_sha256": gate._ids_digest(planned),
        "declared_skips": skips, "declared_expected_failures": expected_failures,
    })
    with (output / "planned-test-ids.txt").open("x", encoding="utf-8") as stream:
        stream.write("\n".join(planned) + "\n")
    if skips or expected_failures:
        raise RuntimeError("native preconditions are not ready; complete discovery retained, no test selection changed")
    del suite, pending, case, method

    supervisor_path = root / SUPERVISOR
    spec = importlib.util.spec_from_file_location("retained_workflow_process", supervisor_path)
    supervisor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(supervisor)
    command = [sys.executable, "-B", "tools/qualify_hia_verified_increment.py", "--output", str(output / "gate")]
    versions = {name: subprocess.check_output([name, "--version"], text=True).splitlines()[0]
                for name in ("clang", "cc", "cargo", "rustc")}
    write_json(output / "harness.json", {
        "schema": "hepta.hia.external-verified-increment-harness.v1",
        "scope": "UNCHANGED_COMPLETE_DECLARED_GATE_WITH_RETAINED_5400_SECOND_WORKFLOW_OWNER",
        "target": target, "target_file_sha256": target_sha,
        "command": command, "python": sys.version, "tool_versions": versions,
        "harness_sha256": sha(Path(__file__)),
        "supervisor_path": str(supervisor_path), "supervisor_sha256": sha(supervisor_path),
        "environment_file": str(environment_path), "environment_sha256": sha(environment_path),
        "preparation_sha256": sha(preparation_path), "native_environment": environment,
        "workflow_seconds": 5400,
        "cleanup_scope": "started POSIX process group only",
        "full_process_tree_claimed": False,
        "product_gate_or_budget_modified": False,
    })
    owner = supervisor.run_workflow_step(
        command, cwd=root, env=dict(os.environ), seconds=5400,
        stdout_path=output / "gate.stdout", stderr_path=output / "gate.stderr",
        receipt_path=output / "process-owner.json",
    )
    result_path = output / "gate/result.json"
    result = json.loads(result_path.read_bytes()) if result_path.is_file() else None
    after, source_error = None, None
    try:
        after = source_admission(root, target)
        write_json(output / "source-after.json", after)
    except Exception as error:
        source_error = {"type": type(error).__name__, "message": str(error)}
    target_unchanged = sha(target_path) == target_sha and load_target(target_path) == target
    passed = bool(owner["status"] == "WORKFLOW_STEP_COMPLETED" and result is not None
                  and result.get("passed") is True
                  and result.get("git_base") == target["commit"] and result.get("git_tree") == target["tree"]
                  and result.get("test_identity", {}).get("planned_sha256") == gate._ids_digest(planned)
                  and result.get("tests_planned") == len(planned) and result.get("tests") == len(planned)
                  and after == before and source_error is None and target_unchanged)
    write_json(output / "harness-result.json", {
        "scope": "FINITE_IMPLEMENTATION_REGRESSION_GATE_ONLY_NO_WHOLE_NATIVE_COMPLETION_CLAIM",
        "target": target, "gate_result_present": result is not None,
        "gate_result_sha256": sha(result_path) if result_path.is_file() else None,
        "owner_status": owner["status"], "owner_timed_out": owner["timed_out"],
        "owner_cleanup_scope": owner["cleanup"]["scope"],
        "full_process_tree_claimed": False, "source_admission_after_error": source_error,
        "complete_source_unchanged": after == before, "target_file_unchanged": target_unchanged,
        "passed": passed,
    })
    return 0 if passed else 1


def collect(args):
    """Copy only retained evidence; no Git checkout, native target or cache."""
    harness = args.harness.resolve(strict=True)
    audit = args.audit_root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    copied, missing, excluded_nonregular = {}, [], []

    def copy_file(source, destination):
        source, destination = Path(source), Path(destination)
        if not source.exists() and not source.is_symlink():
            missing.append(str(source))
            return
        if not stat.S_ISREG(source.lstat().st_mode):
            excluded_nonregular.append(str(source))
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied[str(destination.relative_to(output))] = {"bytes": destination.stat().st_size, "sha256": sha(destination)}

    def copy_directory(source, destination):
        if not source.is_dir() or source.is_symlink():
            missing.append(str(source))
            return
        for path in sorted(source.rglob("*")):
            if path.is_symlink() or path.is_file():
                copy_file(path, destination / path.relative_to(source))

    # Flatten only the workflow's leading dot-directory so upload-artifact's
    # default hidden-file exclusion cannot silently omit the executed script.
    for relative, destination in HARNESS_FILES.items():
        copy_file(harness / relative, output / "harness" / destination)
    for directory in ("setup", "evidence", "gate-run"):
        copy_directory(audit / directory, output / directory)
    dependencies = audit / "dependencies"
    copy_directory(dependencies / "logs", output / "dependencies/logs")
    for name in ("environment.json", "environment.sh", "github.env", "preparation.json", "preparation-exit.txt",
                 "preparation-target.json", "preparation-source-before.json", "preparation-source-after.json"):
        copy_file(dependencies / name, output / "dependencies" / name)
    for profile in ("ranking", "recursive", "finite", "stream"):
        build = dependencies / (profile + "-build")
        destination = output / "dependencies" / (profile + "-build")
        for name in ("build-receipt.json", "build-failure.json", "identity.json", "build-commands.json"):
            copy_file(build / name, destination / name)
        command_directory = "command-evidence" if profile == "ranking" else "commands"
        copy_directory(build / command_directory, destination / command_directory)
    metadata = {name: os.environ.get(name) for name in (
        "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        "GITHUB_EVENT_NAME", "GITHUB_SERVER_URL", "GITHUB_WORKFLOW")}
    write_json(output / "artifact-manifest.json", {
        "schema": "hepta.hia.verified-increment-audit-artifact.v1",
        "scope": "ALLOWLISTED_ORIGINAL_BUILD_AND_GATE_EVIDENCE_NOT_A_PASS_CLAIM",
        "github_run": metadata, "files": copied,
        "missing_optional_or_not_reached_paths": missing,
        "excluded_nonregular_paths": excluded_nonregular,
        "harness_workflow_original_path": ".github/workflows/audit.yml",
        "harness_workflow_artifact_path": "harness/audit.yml",
        "copied_source_checkouts": False, "copied_cargo_caches_or_targets": False,
        "copied_credentials_or_complete_environment": False,
        "full_process_tree_claimed": False,
    })
    print(json.dumps({"artifact_directory": str(output), "retained_files": len(copied)}))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    target_parser = commands.add_parser("resolve")
    target_parser.add_argument("--target", type=Path, required=True)
    target_parser.add_argument("--github-output", type=Path)
    target_parser.set_defaults(operation=resolve)
    preflight_parser = commands.add_parser("preflight")
    preflight_parser.add_argument("--target", type=Path, required=True)
    preflight_parser.add_argument("--source", type=Path, required=True)
    preflight_parser.add_argument("--output", type=Path, required=True)
    preflight_parser.set_defaults(operation=preflight)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--target", type=Path, required=True)
    run_parser.add_argument("--source", type=Path, required=True)
    run_parser.add_argument("--environment", type=Path, required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.set_defaults(operation=run)
    collect_parser = commands.add_parser("collect")
    collect_parser.add_argument("--harness", type=Path, required=True)
    collect_parser.add_argument("--audit-root", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.set_defaults(operation=collect)
    args = parser.parse_args()
    return args.operation(args)


if __name__ == "__main__":
    raise SystemExit(main())
