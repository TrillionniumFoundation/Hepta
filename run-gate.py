#!/usr/bin/env python3
"""Run the unchanged retained v4 --full workflow at one immutable product target.

The original per-step supervisors and all budgets remain authoritative. This
external harness adds prerequisite preparation, read-only discovery and an
independent audit of the original verbose test log; it never edits the suite.
"""
from __future__ import annotations

import argparse
import ast
from decimal import Decimal
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
import tarfile
import time
import unittest

TARGET_SCHEMA = "hepta.hia.full-retained-audit-target.v1"
PRODUCT_REPOSITORY = "TrillionniumFoundation/Hepta"
SUPERVISOR = "review-evidence/hia-native-rewrite-20261111/workflow_process.py"
RUNNER = "review-evidence/hia-native-rewrite-20261111/run_hia_qualification_v4.py"
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


# These selectors postdate the retained v4 environment list. They point only to
# the report the unchanged v4 will actually create, never a development image.
EXTRA_COLD_COMPONENTS = (
    "BYTE_WRAPPER", "CLI", "CORE_EMITTER", "CORE_LOWERING",
    "EXECUTION_OBSERVATION", "JSON_WIRE", "LINKED_OBSERVER", "MACHINE_ENCODING",
    "MACHINE_INSTRUCTIONS", "MACHINE_OBJECT", "MACHINE_PLAN", "MACHINE_STATE",
    "NATIVE_CONTINUATION", "NATIVE_MAPPING", "WORKER_REPORT", "WORKER_SCHEDULING",
)


def ids_digest(values):
    return hashlib.sha256(("\n".join(values) + "\n").encode("utf-8")).hexdigest()


def retained_environment(root, environment, cold_path):
    """Mirror the original v4's static environment for pre-discovery only.

    The real v4 still performs its original assignments and removals itself.
    Reading those lists from its admitted source avoids a stale second copy.
    """
    tree = ast.parse((root / RUNNER).read_bytes(), filename=RUNNER)
    removed = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name = getattr(node.targets[0], "id", None)
            if name in {"development_selectors", "production_selectors"}:
                values = ast.literal_eval(node.value)
                if not isinstance(values, tuple) or not all(isinstance(x, str) for x in values):
                    raise ValueError("retained v4 selector declaration changed shape")
                removed[name] = values
    original_cold = []
    for node in tree.body:
        if (isinstance(node, ast.For) and getattr(node.target, "id", None) == "name"
                and isinstance(node.iter, ast.Tuple)):
            body = ast.get_source_segment((root / RUNNER).read_text(), node)
            if "environment['HEPTA_HIA_' + name + '_COLD_REPORT'] = str(cold)" in body:
                original_cold.append(ast.literal_eval(node.iter))
    if set(removed) != {"development_selectors", "production_selectors"} or len(original_cold) != 1:
        raise ValueError("cannot independently identify the original v4 environment declaration")
    names = original_cold[0]
    if not names or not all(isinstance(x, str) and re.fullmatch(r"[A-Z_]+", x) for x in names):
        raise ValueError("retained cold component declaration differs")
    result = dict(environment)
    for group in removed.values():
        for name in group:
            result.pop(name, None)
    cold_variables = {"HEPTA_HIA_" + name + "_COLD_REPORT": str(cold_path)
                      for name in (*names, *EXTRA_COLD_COMPONENTS)}
    result.update(cold_variables)
    result.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1", PYTHON_COLORS="0", NO_COLOR="1")
    return result, {
        "original_cold_components": list(names), "additional_cold_components": list(EXTRA_COLD_COMPONENTS),
        "cold_variables": cold_variables, "original_discarded_selector_lists": removed,
        "same_run_future_cold_report": str(cold_path), "development_image_substitution": False,
    }


def discover(args):
    """Read the complete original discovery in a disposable interpreter."""
    require_native_runner()
    target = load_target(args.target)
    root = args.source.resolve(strict=True)
    before = source_admission(root, target)
    os.chdir(root)
    sys.path.insert(0, str(root))
    loader = unittest.TestLoader()
    suite = loader.discover("tests", top_level_dir=".")
    count = suite.countTestCases()
    pending, rows, skips, expected_failures = [suite], [], [], []
    while pending:
        case = pending.pop()
        if isinstance(case, unittest.TestSuite):
            pending.extend(reversed(list(case)))
            continue
        method = getattr(case, case._testMethodName)
        short = case.shortDescription()
        description = str(case) + ("\n" + short if short else "")
        rows.append({"id": case.id(), "str": str(case), "short_description": short,
                     "verbose_description": description})
        if getattr(case, "__unittest_skip__", False) or getattr(method, "__unittest_skip__", False):
            skips.append({"id": case.id(), "reason": getattr(case, "__unittest_skip_why__", "")
                          or getattr(method, "__unittest_skip_why__", "")})
        if getattr(case, "__unittest_expecting_failure__", False) or getattr(method, "__unittest_expecting_failure__", False):
            expected_failures.append(case.id())
    planned = [row["id"] for row in rows]
    unique = len(planned) == len(set(planned))
    unique_descriptions = len(rows) == len({row["str"] for row in rows})
    after = source_admission(root, target)
    ready = bool(planned and count == len(planned) and unique and unique_descriptions
                 and not loader.errors and not skips and not expected_failures and after == before)
    write_json(args.output, {
        "schema": "hepta.hia.complete-retained-discovery-only.v1",
        "scope": "FULL_UNITTEST_DISCOVERY_NO_TEST_BODY_EXECUTION_NO_PASS_CLAIM",
        "target": target, "python": sys.version, "method": "unittest.TestLoader().discover('tests', top_level_dir='.')",
        "planned_test_count": len(planned), "suite_count_test_cases": count,
        "planned_test_ids": planned, "planned_test_ids_sha256": ids_digest(planned),
        "test_descriptions": rows, "unique_test_ids": unique,
        "unique_verbose_first_lines": unique_descriptions, "loader_errors": loader.errors,
        "declared_skips": skips, "declared_expected_failures": expected_failures,
        "complete_source_unchanged": after == before, "prerequisites_ready": ready,
    })
    (args.output.parent / "planned-test-ids.txt").write_text("\n".join(planned) + "\n", encoding="utf-8")
    print(json.dumps({"planned": len(planned), "prerequisites_ready": ready, "test_body_executed": False}))
    return 0 if ready else 1


def audit_verbose_stderr(raw, discovery):
    """Identify visible starts and terminal statuses without instrumenting tests.

    The original unittest runner writes a frozen description followed by
    ' ... ' and its status. Diagnostic stderr can intervene. We accept exactly
    one unambiguous terminal-status line per observed method window; any
    unknown, duplicate, reordered, incomplete or ambiguous description/status
    makes equivalence false. This observes logs, not in-process callbacks.
    """
    planned = discovery["planned_test_ids"]
    rows = discovery["test_descriptions"]
    by_first_line = {row["str"]: row for row in rows}
    errors, starts, observations = [], [], []
    try:
        log = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        return {"equivalent": False, "errors": ["original stderr is not UTF-8: " + str(error)],
                "observed_started_ids": [], "observed_completed_ids": [], "observations": []}
    # The full suite uses ordinary TestCase instances; nested subtest diagnostic
    # lines are indented and are not silently promoted to top-level methods.
    candidates = list(re.finditer(r"(?m)^(\S+ \(tests\.[^()\r\n]+\))(.*)$", log))
    for match in candidates:
        first = match.group(1)
        row = by_first_line.get(first)
        if row is None:
            errors.append({"reason": "unrecognized unittest-looking method line", "offset": match.start(), "line": match.group(0)})
            starts.append({"offset": match.start(), "id": None, "marker_end": None})
            continue
        marker = row["verbose_description"] + " ... "
        valid = log.startswith(marker, match.start())
        if not valid:
            errors.append({"reason": "original verbose description differs from discovery", "id": row["id"], "offset": match.start()})
        starts.append({"offset": match.start(), "id": row["id"],
                       "marker_end": match.start() + len(marker) if valid else None})
    completed = []
    status_pattern = re.compile(r"(?m)^(ok|FAIL|ERROR|expected failure|unexpected success|skipped(?: .*)?)\r?$")
    for index, start in enumerate(starts):
        end = starts[index + 1]["offset"] if index + 1 < len(starts) else len(log)
        statuses = []
        if start["marker_end"] is not None:
            window = log[start["marker_end"]:end]
            statuses = [{"status": m.group(1), "offset": start["marker_end"] + m.start()}
                        for m in status_pattern.finditer(window)]
        observation = {**start, "window_end": end, "terminal_status_candidates": statuses}
        if start["id"] is not None and len(statuses) == 1:
            completed.append(start["id"])
            observation["completion_observed"] = True
        else:
            observation["completion_observed"] = False
            errors.append({"reason": "missing or ambiguous terminal status", "id": start["id"], "candidates": len(statuses)})
        observations.append(observation)
    observed = [row["id"] for row in starts]
    exact_started = observed == planned
    exact_completed = completed == planned
    all_ok = bool(observations) and all(len(row["terminal_status_candidates"]) == 1
                                       and row["terminal_status_candidates"][0]["status"] == "ok"
                                       for row in observations)
    return {
        "schema": "hepta.hia.retained-original-verbose-method-identity.v1",
        "scope": "INDEPENDENT_ORIGINAL_STDERR_OBSERVATION_NOT_TEST_RUNNER_CALLBACKS",
        "original_stderr_sha256": hashlib.sha256(raw).hexdigest(),
        "planned_test_ids_sha256": ids_digest(planned), "planned_count": len(planned),
        "observed_started_ids": observed, "observed_completed_ids": completed,
        "observed_started_count": len(observed), "observed_completed_count": len(completed),
        "observed_started_ids_sha256": ids_digest(observed) if all(isinstance(x, str) for x in observed) else None,
        "observed_completed_ids_sha256": ids_digest(completed),
        "started_matches_planned_in_order": exact_started,
        "completed_matches_planned_in_order": exact_completed,
        "all_observed_terminal_statuses_ok": all_ok,
        "observations": observations, "errors": errors,
        "equivalent": bool(exact_started and exact_completed and all_ok and not errors),
    }


def read_optional_json(path):
    path = Path(path)
    if not path.is_file():
        return None, "file was not produced"
    try:
        return json.loads(path.read_bytes()), None
    except (OSError, ValueError) as error:
        return None, repr(error)


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
    prepared = json.loads(environment_path.read_bytes())
    if not isinstance(prepared, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in prepared.items()):
        raise ValueError("environment.json must contain string variables")
    preparation_path = environment_path.parent / "preparation.json"
    preparation = json.loads(preparation_path.read_bytes())
    required_preparation = (
        "native_identity_admission_completed", "current_stream_handshake_and_close_completed",
        "raw_model_handshake_and_close_completed", "dynamic_policy_handshake_and_close_completed",
        "verification_tools_installed_by_original_pinned_bootstrap",
    )
    if (preparation.get("target") != target or preparation.get("target_file_sha256") != target_sha
            or preparation.get("environment") != prepared
            or not all(preparation.get(name) is True for name in required_preparation)):
        raise ValueError("native preparation does not bind this exact target and environment")
    base_env = dict(os.environ)
    base_env.update(prepared)
    base_env["PATH"] = "/usr/lib/llvm-20/bin:" + base_env.get("PATH", "")
    qualification_output = output / "qualification"
    environment, binding = retained_environment(root, base_env, qualification_output / "cold.json")
    write_json(output / "cold-environment-binding.json", binding)
    command = [sys.executable, "-B", str(root / RUNNER), "--source", str(root),
               "--output", str(qualification_output), "--full"]
    write_json(output / "harness-start.json", {
        "schema": "hepta.hia.external-full-retained-harness.v1",
        "scope": "UNCHANGED_ORIGINAL_V4_FULL_RETAINED_WORKFLOW_NO_WHOLE_NATIVE_CLAIM",
        "target": target, "target_file_sha256": target_sha, "command": command,
        "python": sys.version, "harness_sha256": sha(Path(__file__)),
        "original_runner_path": str(root / RUNNER), "original_runner_sha256": sha(root / RUNNER),
        "original_supervisor_path": str(root / SUPERVISOR), "original_supervisor_sha256": sha(root / SUPERVISOR),
        "environment_file_sha256": sha(environment_path), "preparation_sha256": sha(preparation_path),
        "prepared_native_environment": prepared,
        "unchanged_original_budgets_seconds": {"ordinary_step": 1800, "cold_step_outer": 240,
                                               "cold_qualification": 180, "cold_cleanup": 3,
                                               "final_full_discovery_step": 5400},
        "whole_orchestrator_5400_second_limit_added": False,
        "cleanup_scope": "each retained supervisor's started POSIX process group only; original cold owner retains its separate proof",
        "full_process_tree_claimed": False, "product_gate_or_budget_modified": False,
    })
    discovery_command = [sys.executable, "-B", str(Path(__file__).resolve()), "discover",
                         "--target", str(target_path), "--source", str(root),
                         "--output", str(output / "discovery.json")]
    with (output / "discovery.stdout").open("xb") as stdout, (output / "discovery.stderr").open("xb") as stderr:
        discovery_process = subprocess.run(discovery_command, cwd=root, env=environment, stdout=stdout, stderr=stderr)
    discovery, discovery_error = read_optional_json(output / "discovery.json")
    if discovery_process.returncode != 0 or discovery is None or discovery.get("prerequisites_ready") is not True:
        write_json(output / "harness-result.json", {
            "target": target, "passed": False, "stage": "pre-discovery",
            "discovery_returncode": discovery_process.returncode, "discovery_error": discovery_error,
            "original_v4_executed": False, "whole_native_delivery_qualified": False,
        })
        return 1
    if source_admission(root, target) != before:
        raise ValueError("complete source changed during separate discovery")
    started = time.monotonic()
    launch_error, returncode = None, None
    with (output / "v4.stdout").open("xb") as stdout, (output / "v4.stderr").open("xb") as stderr:
        try:
            completed = subprocess.run(command, cwd=root, env=environment, stdout=stdout, stderr=stderr)
            returncode = completed.returncode
        except OSError as error:
            launch_error = repr(error)
    elapsed = time.monotonic() - started
    qualification, qualification_error = read_optional_json(qualification_output / "QUALIFICATION.json")
    full_result, full_result_error = read_optional_json(qualification_output / "full-retained-regression.json")
    stderr_path = qualification_output / "full-retained-regression.stderr.log"
    identity = (audit_verbose_stderr(stderr_path.read_bytes(), discovery) if stderr_path.is_file()
                else {"equivalent": False, "errors": ["original full-suite stderr was not produced"]})
    write_json(output / "full-method-identity.json", identity)
    after, source_error = None, None
    try:
        after = source_admission(root, target)
        write_json(output / "source-after.json", after)
    except Exception as error:
        source_error = {"type": type(error).__name__, "message": str(error)}
    target_unchanged = sha(target_path) == target_sha and load_target(target_path) == target
    empty_anomalies = bool(isinstance(full_result, dict) and all(full_result.get(key) == [] for key in (
        "errors", "failures", "skipped", "expected_failures", "unexpected_successes")))
    original_passed = bool(isinstance(qualification, dict)
                          and qualification.get("status") == "FULL_RETAINED_PASS"
                          and qualification.get("full_retained_regression_requested") is True
                          and qualification.get("full_retained_regression_executed") is True
                          and qualification.get("full_retained_regression_qualified") is True
                          and qualification.get("source_preserved") is True
                          and qualification.get("harness_preserved") is True
                          and qualification.get("whole_native_delivery_qualified") is False
                          and qualification.get("source_identity", {}).get("head") == target["commit"]
                          and qualification.get("source_identity", {}).get("tree") == target["tree"])
    count = discovery["planned_test_count"]
    full_passed = bool(empty_anomalies and full_result.get("successful") is True
                       and full_result.get("expected_tests") == count and full_result.get("tests_run") == count)
    passed = bool(returncode == 0 and launch_error is None and original_passed and full_passed
                  and identity.get("equivalent") is True and source_error is None
                  and after == before and target_unchanged)
    write_json(output / "harness-result.json", {
        "schema": "hepta.hia.external-full-retained-outcome.v1",
        "scope": "FULL_RETAINED_REGRESSION_ONLY_NOT_WHOLE_NATIVE_PRODUCT_COMPLETION",
        "target": target, "original_v4_executed": True, "returncode": returncode,
        "launch_error": launch_error, "elapsed_seconds": elapsed, "original_v4_passed": original_passed,
        "qualification_error": qualification_error, "full_suite_result_error": full_result_error,
        "planned_test_count": count, "full_suite_count_and_zero_anomalies_passed": full_passed,
        "ordered_method_identity_equivalent": identity.get("equivalent") is True,
        "complete_source_unchanged": after == before, "source_after_error": source_error,
        "target_file_unchanged": target_unchanged,
        "original_qualification_sha256": sha(qualification_output / "QUALIFICATION.json") if qualification else None,
        "whole_native_delivery_qualified": False, "full_process_tree_claimed": False, "passed": passed,
    })
    print(json.dumps({"passed": passed, "original_v4_passed": original_passed,
                      "planned": count, "observed_order_equivalent": identity.get("equivalent") is True}))
    return 0 if passed else 1


def collect(args):
    """Retain original evidence, preserving executable modes in a tar archive."""
    harness = args.harness.resolve(strict=True)
    audit = args.audit_root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    evidence = output / "evidence"
    evidence.mkdir()
    copied, directory_metadata, missing, excluded_nonregular, excluded_directories = {}, {}, [], [], []

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
        mode = stat.S_IMODE(source.stat().st_mode)
        if stat.S_IMODE(destination.stat().st_mode) != mode:
            raise ValueError("copy did not preserve original mode: " + str(source))
        copied[str(destination.relative_to(evidence))] = {
            "bytes": destination.stat().st_size, "sha256": sha(destination),
            "mode_octal": format(mode, "04o"), "mtime_ns": source.stat().st_mtime_ns}

    def remember_directory(source, destination):
        destination.mkdir(parents=True, exist_ok=True)
        observed = source.stat()
        directory_metadata[str(destination.relative_to(evidence))] = {
            "source": str(source), "mode_octal": format(stat.S_IMODE(observed.st_mode), "04o"),
            "mtime_ns": observed.st_mtime_ns}

    def copy_directory(source, destination, exclude=()):
        source, destination = Path(source), Path(destination)
        if not source.is_dir() or source.is_symlink():
            missing.append(str(source))
            return
        for directory, names, files in os.walk(source, followlinks=False):
            directory = Path(directory)
            remember_directory(directory, destination / directory.relative_to(source))
            for name in list(names):
                path = directory / name
                relative = path.relative_to(source).as_posix()
                if path.is_symlink():
                    excluded_nonregular.append(str(path))
                    names.remove(name)
                elif relative in exclude or name in {".git", "__pycache__"}:
                    excluded_directories.append({"path": str(path), "reason": "complete source checkout or cache, reproducible from pinned source"})
                    names.remove(name)
            for name in sorted(files):
                path = directory / name
                copy_file(path, destination / path.relative_to(source))

    for relative, destination in HARNESS_FILES.items():
        copy_file(harness / relative, evidence / "harness" / destination)
    for directory in ("setup", "evidence"):
        copy_directory(audit / directory, evidence / directory)
    copy_directory(audit / "full-run", evidence / "full-run", exclude=(
        "qualification/source-reproduction", "qualification/cold.cold/source"))
    dependencies = audit / "dependencies"
    copy_directory(dependencies / "logs", evidence / "dependencies/logs")
    for name in ("environment.json", "environment.sh", "github.env", "preparation.json", "preparation-exit.txt",
                 "preparation-target.json", "preparation-source-before.json", "preparation-source-after.json",
                 "verification-tools.json", "raw-model-readiness.json"):
        copy_file(dependencies / name, evidence / "dependencies" / name)
    for profile in ("ranking", "recursive", "finite", "stream", "raw-model", "dynamic-policy"):
        build = dependencies / (profile + "-build")
        destination = evidence / "dependencies" / (profile + "-build")
        if build.is_dir() and not build.is_symlink():
            remember_directory(build, destination)
        for name in ("build-receipt.json", "build-failure.json", "identity.json", "build-commands.json"):
            copy_file(build / name, destination / name)
        # Retain only the six observed final images, never their target/cache
        # directories. The original receipt keeps the original path and hash.
        identity_path = build / ("build-receipt.json" if profile in {"ranking", "raw-model", "dynamic-policy"} else "identity.json")
        identity, identity_error = read_optional_json(identity_path)
        if isinstance(identity, dict) and isinstance(identity.get("binary"), str):
            binary = Path(identity["binary"])
            if binary.resolve().is_relative_to(dependencies):
                copy_file(binary, destination / "native-image")
            else:
                excluded_nonregular.append("receipt binary outside dependency directory: " + str(binary))
        command_directory = "command-evidence" if profile in {"ranking", "raw-model", "dynamic-policy"} else "commands"
        copy_directory(build / command_directory, destination / command_directory)
    metadata = {name: os.environ.get(name) for name in (
        "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        "GITHUB_EVENT_NAME", "GITHUB_SERVER_URL", "GITHUB_WORKFLOW")}
    manifest = {
        "schema": "hepta.hia.full-retained-audit-artifact.v1",
        "scope": "ORIGINAL_SUCCESS_FAILURE_AND_PARTIAL_EVIDENCE_NOT_A_PASS_CLAIM",
        "github_run": metadata, "files": copied, "original_evidence_directories": directory_metadata,
        "missing_optional_or_not_reached_paths": missing,
        "excluded_nonregular_paths": excluded_nonregular, "excluded_directories": excluded_directories,
        "harness_workflow_original_path": ".github/workflows/audit.yml",
        "harness_workflow_artifact_path": "harness/audit.yml",
        "copied_source_checkouts": False, "copied_cargo_cache_or_target_directories": False,
        "six_receipt_selected_native_images_retained_when_present": True,
        "copied_credentials_or_complete_environment": False,
        "native_qualification_evidence_files_retained": True,
        "original_executable_modes_preserved_in_tar": True, "full_process_tree_claimed": False,
    }
    # Apply original directory metadata only after every copy is complete,
    # deepest first, so a read-only evidence directory cannot block a child copy.
    for relative in sorted(directory_metadata, key=lambda x: len(Path(x).parts), reverse=True):
        source = Path(directory_metadata[relative]["source"])
        destination = evidence / relative
        shutil.copystat(source, destination, follow_symlinks=False)
        if (stat.S_IMODE(destination.stat().st_mode) != int(directory_metadata[relative]["mode_octal"], 8)
                or destination.stat().st_mtime_ns != directory_metadata[relative]["mtime_ns"]):
            raise ValueError("original evidence directory metadata did not survive copying")
    write_json(evidence / "artifact-manifest.json", manifest)
    write_json(output / "artifact-manifest.json", manifest)
    archive_members = {}
    for path in [evidence, *sorted(evidence.rglob("*"))]:
        observed = path.stat()
        name = "evidence" if path == evidence else "evidence/" + path.relative_to(evidence).as_posix()
        archive_members[name] = {
            "kind": "directory" if path.is_dir() else "file", "mode": stat.S_IMODE(observed.st_mode),
            "mtime_ns": observed.st_mtime_ns,
            "bytes": observed.st_size if path.is_file() else 0,
            "sha256": sha(path) if path.is_file() else None,
        }
    archive = output / "original-evidence.tar.gz"

    def preserve_nanosecond_mtime(info):
        expected = archive_members[info.name]
        seconds, nanoseconds = divmod(expected["mtime_ns"], 1_000_000_000)
        info.pax_headers["mtime"] = str(seconds) + "." + format(nanoseconds, "09d")
        return info

    # A tar inside the GitHub artifact preserves executable bits and original
    # directory metadata that the service's outer ZIP otherwise normalizes.
    with tarfile.open(archive, "w:gz", compresslevel=6, format=tarfile.PAX_FORMAT) as bundle:
        bundle.add(evidence, arcname="evidence", recursive=True, filter=preserve_nanosecond_mtime)
    seen = set()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            if member.name not in archive_members or member.name in seen:
                raise ValueError("unexpected or duplicate archived member")
            seen.add(member.name)
            expected = archive_members[member.name]
            if member.mode != expected["mode"] or int(Decimal(member.pax_headers["mtime"]) * 1_000_000_000) != expected["mtime_ns"]:
                raise ValueError("archive changed original mode or timestamp: " + member.name)
            if expected["kind"] == "directory":
                if not member.isdir():
                    raise ValueError("archive replaced an evidence directory")
            else:
                if not member.isfile() or member.size != expected["bytes"]:
                    raise ValueError("archive changed a file type or size")
                with bundle.extractfile(member) as stream:
                    if hashlib.file_digest(stream, "sha256").hexdigest() != expected["sha256"]:
                        raise ValueError("archive changed original evidence bytes")
    if seen != set(archive_members):
        raise ValueError("archive omitted original evidence members")
    write_json(output / "collection-receipt.json", {
        "archive": archive.name, "bytes": archive.stat().st_size, "sha256": sha(archive),
        "artifact_manifest_sha256": sha(output / "artifact-manifest.json"),
        "retained_file_count": len(copied), "verified_archive_member_count": len(seen),
        "all_archived_bytes_hashes_types_modes_and_mtimes_read_back": True,
        "original_modes_recorded_and_archived": True,
        "failure_or_interrupted_results_not_rewritten": True,
    })
    # Widen only the disposable staging directories after full archive readback,
    # then remove that verified copy. Never chmod or remove original evidence.
    for directory, names, _ in os.walk(evidence):
        os.chmod(directory, stat.S_IMODE(Path(directory).stat().st_mode) | stat.S_IRWXU)
        for name in names:
            path = Path(directory) / name
            os.chmod(path, stat.S_IMODE(path.stat().st_mode) | stat.S_IRWXU)
    shutil.rmtree(evidence)
    print(json.dumps({"artifact_directory": str(output), "retained_files": len(copied), "archive_sha256": sha(archive)}))
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
    discovery_parser = commands.add_parser("discover")
    discovery_parser.add_argument("--target", type=Path, required=True)
    discovery_parser.add_argument("--source", type=Path, required=True)
    discovery_parser.add_argument("--output", type=Path, required=True)
    discovery_parser.set_defaults(operation=discover)
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
