#!/usr/bin/env python3
"""Run the unchanged retained v4 --full workflow at one immutable product target.

The original per-step supervisors and all budgets remain authoritative. This
external harness adds prerequisite preparation, read-only discovery and an
independent audit of the original verbose test log; it never edits the suite.
"""
from __future__ import annotations

import argparse
import ast
import base64
import csv
from decimal import Decimal
import hashlib
import importlib.util
import io
import json
import marshal
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
import zipfile

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
    "BOUNDED_MEMORY", "SCALAR_PROFILE", "GENERATION_RETENTION",
    "PUBLICATION_MEASUREMENT", "SHA256_STREAM_DIFFERENTIAL",
    "FULL_COST", "PATCH_IMPACT", "CLI_DISCOVERY_JSON", "STATIC_BUDGET", "STORE_LIFECYCLE",
    "DEFAULT_RELEASE", "SERVICE_CONTEXT", "COST_LEDGER", "EVALUATION", "NATIVE_TRANSPORT",
    "NATIVE_BUILD_ADMISSION",
)

DEFAULT_RELEASE_SOURCE_CLASS = "tests.test_hia_default_native_release.DefaultReleaseSourceTests"
DEFAULT_RELEASE_NATIVE_CLASS = "tests.test_hia_default_native_release.DefaultReleaseNativeTests"
SERVICE_CONTEXT_SOURCE_CLASS = "tests.test_hia_service_context_native.ServiceContextSourceTests"
SERVICE_CONTEXT_NATIVE_CLASS = "tests.test_hia_service_context_native.ServiceContextNativeTests"
COST_LEDGER_SOURCE_CLASS = "tests.test_hia_cost_ledger_native.CostLedgerSourceTests"
COST_LEDGER_NATIVE_CLASS = "tests.test_hia_cost_ledger_native.CostLedgerNativeTests"
EVALUATION_SOURCE_CLASS = "tests.test_hia_evaluation_native.EvaluationSourceTests"
EVALUATION_NATIVE_CLASS = "tests.test_hia_evaluation_native.EvaluationNativeTests"
NATIVE_TRANSPORT_SOURCE_CLASS = "tests.test_hia_native_transport_failures.NativeTransportSourceTests"
NATIVE_TRANSPORT_NATIVE_CLASS = "tests.test_hia_native_transport_failures.NativeTransportNativeTests"
NATIVE_BUILD_ADMISSION_SOURCE_CLASS = "tests.test_hia_native_build_admission_native.NativeBuildAdmissionSourceTests"
NATIVE_BUILD_ADMISSION_NATIVE_CLASS = "tests.test_hia_native_build_admission_native.NativeBuildAdmissionNativeTests"

# These classes occur only in complete discovery, not the source/native tuples
# extracted by the unchanged v4. Keep their actual same-run build evidence for
# the missing caller gates; never substitute a separately prepared fixture.
FULL_DISCOVERY_EVIDENCE = {
    "native-mapping": ("tests.test_hia_native_mapping_native.NativeMappingNativeTests",
                       "HEPTA_HIA_NATIVE_MAPPING_EVIDENCE"),
    "scalar-profile": ("tests.test_hia_scalar_profile_native.ScalarProfileNativeTests",
                       "HEPTA_HIA_SCALAR_PROFILE_EVIDENCE"),
    "publication-measurement": ("tests.test_hia_publication_measurement_native.PublicationMeasurementNativeTests",
                                "HEPTA_HIA_PUBLICATION_MEASUREMENT_EVIDENCE"),
    "generation-retention": ("tests.test_hia_generation_retention_native.GenerationRetentionNativeTests",
                             "HEPTA_HIA_GENERATION_RETENTION_EVIDENCE"),
    "sha256-stream-differential": ("tests.test_hia_sha256_stream_transition_equivalence.Sha256StreamTransitionNativeTests",
                                   "HEPTA_HIA_SHA256_STREAM_DIFFERENTIAL_EVIDENCE"),
    "full-cost": ("tests.test_hia_full_cost_native.FullCostNativeTests",
                  "HEPTA_HIA_FULL_COST_EVIDENCE"),
    "patch-impact": ("tests.test_hia_patch_impact_native.PatchImpactNativeTests",
                     "HEPTA_HIA_PATCH_IMPACT_EVIDENCE"),
    "cli-discovery-json": ("tests.test_hia_cli_discovery_json.CliDiscoveryJsonNativeTests",
                           "HEPTA_HIA_CLI_DISCOVERY_JSON_EVIDENCE"),
    "static-budget": ("tests.test_hia_static_budget_native.StaticBudgetNativeTests",
                      "HEPTA_HIA_STATIC_BUDGET_EVIDENCE"),
    "store-lifecycle": ("tests.test_hia_store_lifecycle_native.StoreLifecycleNativeTests",
                        "HEPTA_HIA_STORE_LIFECYCLE_EVIDENCE"),
    "default-release": (DEFAULT_RELEASE_NATIVE_CLASS, "HEPTA_HIA_DEFAULT_RELEASE_EVIDENCE"),
    "service-context": (SERVICE_CONTEXT_NATIVE_CLASS, "HEPTA_HIA_SERVICE_CONTEXT_EVIDENCE"),
    "cost-ledger": (COST_LEDGER_NATIVE_CLASS, "HEPTA_HIA_COST_LEDGER_EVIDENCE"),
    "evaluation": (EVALUATION_NATIVE_CLASS, "HEPTA_HIA_EVALUATION_EVIDENCE"),
    "native-transport": (NATIVE_TRANSPORT_NATIVE_CLASS, "HEPTA_HIA_NATIVE_TRANSPORT_EVIDENCE"),
    "native-build-admission": (NATIVE_BUILD_ADMISSION_NATIVE_CLASS, "HEPTA_HIA_NATIVE_BUILD_ADMISSION_EVIDENCE"),
}
# The selected CLI callers use a separate fixture under the same evidence root.
# They remain their own complete class in the original full discovery.
ADDITIONAL_FULL_DISCOVERY_CLASSES = (
    "tests.test_hia_cli_discovery_selection.CliDiscoverySelectionNativeTests",
)
ADDITIONAL_DISCARDED_SELECTORS = (
    "HEPTA_HIA_BOUNDED_MEMORY_MANIFEST", "HEPTA_HIA_SCALAR_PROFILE_MANIFEST",
    "HEPTA_HIA_GENERATION_RETENTION_MANIFEST", "HEPTA_HIA_PUBLICATION_MEASUREMENT_MANIFEST",
    "HEPTA_HIA_NATIVE_MAPPING_MANIFEST", "HEPTA_HIA_SHA256_STREAM_MANIFEST",
    "HEPTA_HIA_SCALAR_PROFILE_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_GENERATION_RETENTION_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_PUBLICATION_MEASUREMENT_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_NATIVE_MAPPING_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_SHA256_STREAM_DIFFERENTIAL_COMPILER",
    "HEPTA_HIA_FULL_COST_MANIFEST", "HEPTA_HIA_PATCH_IMPACT_MANIFEST",
    "HEPTA_HIA_CLI_DISCOVERY_JSON_MANIFEST",
    "HEPTA_HIA_FULL_COST_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_PATCH_IMPACT_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_CLI_DISCOVERY_JSON_DEVELOPMENT_MANIFEST",
    "HEPTA_HIA_CLI_DISCOVERY_JSON_COLD_FIXTURE",
    "HEPTA_HIA_CLI_DISCOVERY_CALLERS_CLI_MANIFEST",
    "HEPTA_HIA_CLI_DISCOVERY_CALLERS_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_STATIC_BUDGET_MANIFEST", "HEPTA_HIA_STATIC_BUDGET_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_STORE_LIFECYCLE_MANIFEST", "HEPTA_HIA_STORE_LIFECYCLE_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_DEFAULT_RELEASE_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_SERVICE_CONTEXT_MANIFEST", "HEPTA_HIA_SERVICE_CONTEXT_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_COST_LEDGER_MANIFEST", "HEPTA_HIA_COST_LEDGER_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_EVALUATION_MANIFEST", "HEPTA_HIA_EVALUATION_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_NATIVE_TRANSPORT_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST", "HEPTA_HIA_NATIVE_BUILD_ADMISSION_DEVELOPMENT_COMPILER",
)


def component_workflow_coverage(root):
    workflow = (root / ".github/workflows/hia-core.yml").read_text()
    blocks = re.findall(r"          names = \((.*?)\n          \)", workflow, re.S)
    if len(blocks) != 2:
        raise ValueError("expected the original two extracted workflow groups")
    named = [re.findall(r"'(tests\.[^']+)'", block) for block in blocks]
    if DEFAULT_RELEASE_SOURCE_CLASS not in named[0]:
        raise ValueError("default-release source class must remain in the first extracted source tuple")
    if SERVICE_CONTEXT_SOURCE_CLASS not in named[0]:
        raise ValueError("service-context source class must remain in the first extracted source tuple")
    if COST_LEDGER_SOURCE_CLASS not in named[0]:
        raise ValueError("cost-ledger source class must remain in the first extracted source tuple")
    if EVALUATION_SOURCE_CLASS not in named[0]:
        raise ValueError("evaluation source class must remain in the first extracted source tuple")
    if NATIVE_TRANSPORT_SOURCE_CLASS not in named[0]:
        raise ValueError("native-transport source class must remain in the first extracted source tuple")
    if NATIVE_BUILD_ADMISSION_SOURCE_CLASS not in named[0]:
        raise ValueError("native-build-admission source class must remain in the first extracted source tuple")
    groups = [node for node in ast.walk(ast.parse((root / RUNNER).read_bytes()))
              if isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], "id", None) == "groups"]
    if len(groups) != 1:
        raise ValueError("cannot identify the unchanged original component groups")
    original_groups = ast.literal_eval(groups[0].value)
    before_full = [*named[0], *named[1], *(item for group in original_groups.values() for item in group)]
    required_classes = {name: row[0] for name, row in FULL_DISCOVERY_EVIDENCE.items()}
    required_classes.update({name: name for name in ADDITIONAL_FULL_DISCOVERY_CLASSES})
    repeated = {name: [selector for selector in before_full
                       if selector == test_class or test_class.startswith(selector + ".")
                       or selector.startswith(test_class + ".")]
                for name, test_class in required_classes.items()}
    if any(repeated.values()):
        raise ValueError("retained component evidence would be reused before full discovery: " + repr(repeated))
    return {"source_workflow_selectors": named[0], "native_workflow_selectors": named[1],
            "original_component_groups": original_groups,
            "required_full_discovery_classes": required_classes,
            "default_release_source_class_in_first_source_tuple": True,
            "service_context_source_class_in_first_source_tuple": True,
            "cost_ledger_source_class_in_first_source_tuple": True,
            "evaluation_source_class_in_first_source_tuple": True,
            "native_transport_source_class_in_first_source_tuple": True,
            "native_build_admission_source_class_in_first_source_tuple": True,
            "retained_native_classes_first_execute_in_full_discovery": True,
            "extra_component_suite_reruns": False}


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
    discarded_additional = [name for name in ADDITIONAL_DISCARDED_SELECTORS if name in result]
    for name in ADDITIONAL_DISCARDED_SELECTORS:
        result.pop(name, None)
    cold_variables = {"HEPTA_HIA_" + name + "_COLD_REPORT": str(cold_path)
                      for name in (*names, *EXTRA_COLD_COMPONENTS)}
    evidence_variables = {variable: str(cold_path.parent / "full-discovery-components" / name)
                          for name, (_, variable) in FULL_DISCOVERY_EVIDENCE.items()}
    result.update(cold_variables)
    result.update(evidence_variables)
    result.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1", PYTHON_COLORS="0", NO_COLOR="1")
    return result, {
        "original_cold_components": list(names), "additional_cold_components": list(EXTRA_COLD_COMPONENTS),
        "cold_variables": cold_variables, "original_discarded_selector_lists": removed,
        "additional_discarded_selectors": discarded_additional,
        "full_discovery_evidence_variables": evidence_variables,
        "component_workflow_coverage": component_workflow_coverage(root),
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


def read_pinned_json(path, pins):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    pins[str(path)] = hashlib.sha256(raw).hexdigest()
    return json.loads(raw)


def require_observed_component_methods(discovery, identity):
    """Reuse actual full-suite observations; do not execute these suites twice."""
    classes = [row[0] for row in FULL_DISCOVERY_EVIDENCE.values()]
    classes.append("tests.test_hia_bounded_memory_native.BoundedMemoryNativeTests")
    classes.extend(ADDITIONAL_FULL_DISCOVERY_CLASSES)
    classes.append(COST_LEDGER_SOURCE_CLASS)
    classes.append(EVALUATION_SOURCE_CLASS)
    classes.append(NATIVE_TRANSPORT_SOURCE_CLASS)
    classes.append(NATIVE_BUILD_ADMISSION_SOURCE_CLASS)
    checked = {}
    for name in classes:
        planned = [item for item in discovery["planned_test_ids"] if item.startswith(name + ".")]
        observed = [row for row in identity["observations"]
                    if isinstance(row.get("id"), str) and row["id"].startswith(name + ".")]
        if name == SERVICE_CONTEXT_NATIVE_CLASS and len(planned) != 12:
            raise ValueError("service-context requires all twelve original native methods")
        if ((name == COST_LEDGER_NATIVE_CLASS and len(planned) != 9)
                or (name == COST_LEDGER_SOURCE_CLASS and len(planned) != 3)):
            raise ValueError("cost-ledger requires all nine native and three source methods")
        if ((name == EVALUATION_SOURCE_CLASS and len(planned) != 3)
                or (name == EVALUATION_NATIVE_CLASS and len(planned) != 7)):
            raise ValueError("evaluation requires all three source and seven native methods")
        if ((name == NATIVE_TRANSPORT_SOURCE_CLASS and len(planned) != 1)
                or (name == NATIVE_TRANSPORT_NATIVE_CLASS and len(planned) != 6)):
            raise ValueError("native-transport requires its source and all six native methods")
        if ((name == NATIVE_BUILD_ADMISSION_SOURCE_CLASS and len(planned) != 3)
                or (name == NATIVE_BUILD_ADMISSION_NATIVE_CLASS and len(planned) != 7)):
            raise ValueError("native-build-admission requires all three source and seven native methods")
        if (not planned or [row["id"] for row in observed] != planned
                or (name == DEFAULT_RELEASE_NATIVE_CLASS and len(planned) != 12)
                or not all(row.get("completion_observed") is True
                           and len(row["terminal_status_candidates"]) == 1
                           and row["terminal_status_candidates"][0]["status"] == "ok" for row in observed)):
            raise ValueError("complete same-run component methods did not pass: " + name)
        checked[name] = planned
    return checked


def require_cold_component(manifest_path, source_name, cold_sha, compiler_sha, sources, pins):
    manifest_path = Path(manifest_path)
    manifest = read_pinned_json(manifest_path, pins)
    build = read_pinned_json(manifest_path.with_name("build.json"), pins)
    image = (manifest_path.parent / manifest["image_path"]).resolve(strict=True)
    if image.parent != manifest_path.parent.resolve():
        raise ValueError("component image escapes its admitted build directory")
    pins[str(image)] = sha(image)
    if (build.get("scope") != "MATCHING_SOURCE_COLD_COMPONENT"
            or build.get("cold_report_sha256") != cold_sha or build.get("source_manifest") != sources
            or build.get("manifest") != manifest or manifest.get("compiler_sha256") != compiler_sha
            or manifest.get("source_sha256") != sources[source_name]
            or manifest.get("image_sha256") != pins[str(image)]):
        raise ValueError("full-discovery component does not bind this same cold: " + str(manifest_path))
    return str(manifest_path)


def release_bytes(path, pins):
    """Capture real artifact bytes for the supplemental final readback."""
    path = Path(path)
    if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("default-release artifact is not a regular file: " + str(path))
    path = path.resolve(strict=True)
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if str(path) in pins and pins[str(path)] != digest:
        raise ValueError("default-release captured artifact changed: " + str(path))
    pins[str(path)] = digest
    return raw


def release_json(path, pins):
    return json.loads(release_bytes(path, pins))


def require_release_record(files, record, *, installed=False):
    """Check every recorded byte, including pip's target-directory script row."""
    rows = list(csv.reader(io.StringIO(files[record].decode("utf-8"), newline="")))
    observed = set()
    for row in rows:
        if len(row) != 3:
            raise ValueError("default-release RECORD row shape differs")
        name, digest, size = row
        # pip --target retains this script row relative to its temporary
        # site-packages directory, then moves the actual script to bin/hia.
        if installed and name == "../../bin/hia":
            name = "bin/hia"
        if name not in files or name in observed:
            raise ValueError("default-release RECORD has an absent or duplicate member")
        observed.add(name)
        expected = base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b"=").decode("ascii")
        if ((name == record and (digest or size)) or (name != record
                and (digest != "sha256=" + expected or size != str(len(files[name]))))):
            raise ValueError("default-release RECORD hash or length differs: " + name)
    if observed != set(files):
        raise ValueError("default-release RECORD omits actual members")


def release_wheel(path, pins):
    raw = release_bytes(path, pins)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        names = [item.filename for item in members]
        if (len(names) != len(set(names)) or any(item.is_dir()
                or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG)
                or Path(item.filename).is_absolute() or ".." in Path(item.filename).parts
                or "\\" in item.filename or Path(item.filename).as_posix() != item.filename
                for item in members)):
            raise ValueError("default-release wheel member inventory differs")
        files = {name: archive.read(name) for name in names}
    records = [name for name in files if name.endswith(".dist-info/RECORD")]
    if len(records) != 1:
        raise ValueError("default-release wheel requires exactly one RECORD")
    require_release_record(files, records[0])
    return files, records[0].removesuffix("/RECORD")


def require_release_installation(directory, expected, files, distribution, wheel, wheel_sha, pins):
    directory = Path(directory).resolve(strict=True)
    actual = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("default-release installed member is a symlink")
        if path.is_file():
            actual[path.relative_to(directory).as_posix()] = release_bytes(path, pins)
    if {name: hashlib.sha256(raw).hexdigest() for name, raw in actual.items()} != expected:
        raise ValueError("default-release installation changed since original observation")
    record = distribution + "/RECORD"
    extras = {"bin/hia", *(distribution + "/" + name for name in ("INSTALLER", "REQUESTED", "direct_url.json"))}
    if (set(actual) != set(files) | extras
            or any(actual.get(name) != raw for name, raw in files.items() if name != record)):
        raise ValueError("default-release installed product bytes differ from the real wheel")
    require_release_record(actual, record, installed=True)
    origin = json.loads(actual[distribution + "/direct_url.json"])
    if (origin.get("url") != wheel.as_uri()
            or origin.get("archive_info", {}).get("hashes", {}).get("sha256") != wheel_sha):
        raise ValueError("default-release installation names another wheel")
    return {"path": str(directory), "actual_files": len(actual), "record_sha256": pins[str(directory / record)]}


def require_release_compilation(directory, label, source_name, input_names, root, compiler, sources, pins):
    """Read existing compiler transport evidence; never compile or invoke again."""
    from tools.build_hia_source_build import _check_pack_output, _check_compile_receipt
    directory = Path(directory)
    build = release_json(directory / "build.json", pins)
    manifest = release_json(directory / "manifest.json", pins)
    receipt = release_json(directory / (label + ".receipt.json"), pins)
    request = release_json(directory / (label + ".request.json"), pins)
    source = release_bytes(root / source_name, pins)
    image_path = directory / (label + ".image.bin")
    image = release_bytes(image_path, pins)
    output = release_bytes(directory / (label + ".output.bin"), pins)
    artifact = release_bytes(compiler, pins)
    if (build.get("native_compile_receipt") != receipt
            or build.get("component_inputs") != {name: sources[name] for name in input_names}
            or manifest.get("image_path") != image_path.name
            or receipt.get("produced_image") != str(image_path)
            or release_bytes(directory / (label + ".input.bin"), pins) != source
            or request != {"capacity": 1048576, "format": "flat-x86-64", "image": str(compiler),
                "image_sha256": hashlib.sha256(artifact).hexdigest(),
                "output": str(directory / (label + ".output.bin")),
                "source": str(directory / (label + ".input.bin")),
                "source_sha256": sources[source_name], "workspace_fill": 0, "workspace_size": 1048576}
            or _check_pack_output(receipt, output, artifact=artifact, source=source) != image):
        raise ValueError("default-release compiler transport differs from actual source and image")
    _check_compile_receipt(receipt, compiler=artifact, source=source, produced=image)
    return manifest


def require_release_callers(directory, root, package, manifest, sources, discovery, files, distribution, pins):
    """Reuse all 38 nested observations and their original verbose log."""
    from tools.qualify_hia_full_cost_callers import ORIGINAL_MODULES
    directory = Path(directory)
    report = release_json(directory / "report.json", pins)
    child = release_json(directory / "child-report.json", pins)
    descriptions = [row for module in ORIGINAL_MODULES for row in discovery["test_descriptions"]
                    if row["id"].startswith(module + ".")]
    planned = [row["id"] for row in descriptions]
    original_pins = {module.replace(".", "/") + ".py": sources[module.replace(".", "/") + ".py"]
                     for module in ORIGINAL_MODULES}
    for name, digest in original_pins.items():
        if hashlib.sha256(release_bytes(root / name, pins)).hexdigest() != digest:
            raise ValueError("default-release original caller source differs")
    shared = ("scope", "compiler_sha256", "cold_report_sha256", "wheel_sha256",
              "default_bundle_sha256", "source_manifest")
    installed = directory / "installed"
    if (report.get("schema") != "hepta.hia.default-native-original-callers.v1"
            or report.get("status") != "PASS" or report.get("child_returncode") != 0
            or any(report.get(key) != package[key] for key in shared)
            or any(report.get(key) != value for key, value in child.items())
            or report.get("package_build_sha256") != pins[str(directory.parent / "build/build.json")]
            or report.get("native_image_sha256") != manifest["image_sha256"]
            or report.get("original_modules") != list(ORIGINAL_MODULES)
            or report.get("original_caller_pins") != original_pins
            or len(planned) != 38 or len(set(planned)) != 38
            or not all(any(row.startswith(module + ".") for row in planned) for module in ORIGINAL_MODULES)
            or not (report.get("planned") == report.get("started") == report.get("stopped") == planned)
            or type(report.get("actual_tests")) is not int or report["actual_tests"] != 38
            or any(report.get(key) != [] for key in ("errors", "failures", "skipped",
                                                    "expected_failures", "unexpected_successes"))
            or not all(type(report.get(key)) is int and report[key] > 0
                       for key in ("native_arm_calls", "native_decision_calls"))
            or not all(report.get(key) is True for key in ("no_native_selector_environment",
                "retained_python_arithmetic_forbidden", "source_wheel_and_installation_unchanged"))
            or report.get("retained_reference_bodies_removed") is not False
            or report.get("whole_native_delivery_qualified") is not False
            or report.get("product_module") != str(installed / "hepta/hia_full_cost_gate.py")
            or report.get("native_source") != str(installed / "hepta/_data/examples/hia_bootstrap/full_cost.hepta")):
        raise ValueError("default-release original 38 no-selector caller observations differ")
    observed = audit_verbose_stderr(release_bytes(directory / "tests.log", pins),
        {"planned_test_ids": planned, "test_descriptions": descriptions})
    if observed["equivalent"] is not True:
        raise ValueError("default-release original verbose log does not contain all 38 successful methods")
    for name in ("install.stdout", "install.stderr", "child.stdout", "child.stderr"):
        release_bytes(directory / name, pins)
    installation = require_release_installation(installed, report["installation_before"], files,
        distribution, Path(package["wheel"]), package["wheel_sha256"], pins)
    return {"report": str(directory / "report.json"), "actual_tests": 38,
            "native_arm_calls": report["native_arm_calls"], "native_decision_calls": report["native_decision_calls"],
            "original_verbose_identity": observed, "installation": installation,
            "no_native_selector_environment": True, "test_bodies_rerun_by_supplement": False}


def require_default_release(directory, root, cold_path, compiler, sources, discovery, pins):
    """Admit the real candidate produced by the first full native class only."""
    from hepta.hia_default_native import BUNDLE_RESOURCE, PIN_SCHEMA, SELECTOR, TARGET, render_pin
    from tools.build_hia_default_release import encoded
    from tools.build_hia_full_cost import INPUTS as COST_INPUTS
    from tools.build_hia_patch_impact import INPUTS as PATCH_INPUTS
    directory = Path(directory)
    package_path = directory / "build/build.json"
    package = release_json(package_path, pins)
    cold_raw = release_bytes(cold_path, pins)
    cold_sha, compiler_sha = pins[str(cold_path)], hashlib.sha256(release_bytes(compiler, pins)).hexdigest()
    scope = "MATCHING_SOURCE_COLD_COMPONENT"
    source_sha = hashlib.sha256(encoded(sources)).hexdigest()
    if (package.get("schema") != "hepta.hia.default-native-wheel-build.v1"
            or package.get("scope") != scope or package.get("cold_report_sha256") != cold_sha
            or package.get("compiler_sha256") != compiler_sha or package.get("source_manifest") != sources
            or package.get("source_identity_sha256") != source_sha or package.get("target") != TARGET
            or package.get("wheel_tag") != "py3-none-linux_x86_64"
            or package.get("matching_source_cold_component") is not True
            or any(package.get(key) is not False for key in ("ordinary_source_default_changed",
                "retained_reference_bodies_removed", "installed_default_qualification_completed",
                "whole_native_delivery_qualified", "production_activated"))):
        raise ValueError("default-release package does not bind this matching-source cold")
    components = {}
    for label, relative, source_name, inputs in (
            ("full-cost", "build/component", "examples/hia_bootstrap/full_cost.hepta", COST_INPUTS),
            ("patch-impact", "other-owner", "examples/hia_bootstrap/patch_impact.hepta", PATCH_INPUTS)):
        location = directory / relative
        components[label] = require_cold_component(location / "manifest.json", source_name,
            cold_sha, compiler_sha, sources, pins)
        require_release_compilation(location, label, source_name, inputs, root, compiler, sources, pins)
    manifest_raw = release_bytes(directory / "build/component/manifest.json", pins)
    manifest = json.loads(manifest_raw)
    component_raw = release_bytes(directory / "build/component/build.json", pins)
    image_raw = release_bytes(directory / "build/component/full-cost.image.bin", pins)
    wheel = Path(package["wheel"])
    if wheel.parent != directory / "build" or not wheel.name.endswith("-1hiafullcostcold-py3-none-linux_x86_64.whl"):
        raise ValueError("default-release wheel path or platform build tag differs")
    files, distribution = release_wheel(wheel, pins)
    bases = list((directory / "build/base-wheel").glob("*.whl"))
    if len(bases) != 1:
        raise ValueError("default-release ordinary base wheel is absent or ambiguous")
    base, base_distribution = release_wheel(bases[0], pins)
    if (base_distribution != distribution or pins[str(wheel)] != package.get("wheel_sha256")
            or pins[str(bases[0])] != package.get("base_wheel_sha256")
            or {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()} != package.get("members")):
        raise ValueError("default-release real wheel bytes or members differ from construction")
    pin_name = "hepta/hia_default_native_pin.py"
    source_python = {name: digest for name, digest in sources.items()
                     if name.startswith("hepta/") and name.endswith(".py")}
    for name, digest in source_python.items():
        if name not in base or hashlib.sha256(base[name]).hexdigest() != digest:
            raise ValueError("default-release base wheel changed or omitted source Python")
    for name, raw in base.items():
        if name.startswith("hepta/"):
            source_name = name.removeprefix("hepta/_data/") if name.startswith("hepta/_data/") else name
            if sources.get(source_name) != hashlib.sha256(raw).hexdigest():
                raise ValueError("default-release base wheel has unbound product bytes")
        elif not name.startswith(distribution + "/"):
            raise ValueError("default-release base wheel has unexpected members")
    if base.get(pin_name) != render_pin(None):
        raise ValueError("default-release ordinary source pin is no longer portable")
    prefix = "hepta/" + str(Path(BUNDLE_RESOURCE).parent) + "/"
    bundle = encoded({"schema": "hepta.hia.native-helpers.v1", "target": TARGET,
        "abi": "hia-byte-six-argument-v1", "helpers": [{"selector": SELECTOR,
            "manifest_path": "manifest.json", "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}]})
    bundle_sha = hashlib.sha256(bundle).hexdigest()
    pin = (PIN_SCHEMA, TARGET, BUNDLE_RESOURCE, bundle_sha, scope, cold_sha, source_sha)
    pin_raw = render_pin(pin)
    provenance = {"schema": "hepta.hia.default-native-package-provenance.v1", "scope": scope,
        "target": TARGET, "source_identity_sha256": source_sha, "source_manifest": sources,
        "compiler_sha256": compiler_sha, "cold_report_sha256": cold_sha,
        "component_build_sha256": hashlib.sha256(component_raw).hexdigest(),
        "default_bundle_sha256": bundle_sha, "pin_template_sha256": sources[pin_name],
        "derived_pin_sha256": hashlib.sha256(pin_raw).hexdigest(),
        "runtime_source_transformations": {pin_name: "data-only pin derived by the cold-bound builder"},
        "retained_reference_bodies_removed": False, "whole_native_delivery_qualified": False,
        "production_activated": False}
    derived = {pin_name: pin_raw, prefix + "bundle.json": bundle, prefix + "manifest.json": manifest_raw,
        prefix + "full-cost.image.bin": image_raw, prefix + "component-build.json": component_raw,
        prefix + "cold-report.json": cold_raw, prefix + "provenance.json": encoded(provenance),
        distribution + "/WHEEL": ("Wheel-Version: 1.0\nGenerator: hepta.default-native-candidate.v1\n"
            "Root-Is-Purelib: false\nBuild: 1hiafullcostcold\nTag: py3-none-linux_x86_64\n").encode()}
    if (package.get("pin") != list(pin) or package.get("default_bundle_sha256") != bundle_sha
            or package.get("derived_package_members") != sorted(derived)
            or set(files) != set(base) | set(derived)
            or any(files.get(name) != raw for name, raw in derived.items())
            or any(files[name] != raw for name, raw in base.items()
                   if name not in derived and name != distribution + "/RECORD")):
        raise ValueError("default-release derived pin, image, provenance or preserved source differs")
    custody = release_json(directory / "component-custody.json", pins)
    if (custody.get("schema") != "hepta.hia.default-native-release-test-custody.v1"
            or any(custody.get(key) != package[key] for key in ("scope", "compiler_sha256",
                "cold_report_sha256", "wheel", "wheel_sha256", "default_bundle_sha256"))
            or custody.get("package_build_sha256") != pins[str(package_path)]
            or custody.get("source_manifest_before") != sources or custody.get("source_manifest_after") != sources
            or custody.get("installed_files_before") != custody.get("installed_files_after")
            or custody.get("source_and_installation_unchanged") is not True
            or custody.get("independent_VM_both_protocols_before_image_construction") is not True
            or custody.get("retained_reference_bodies_removed") is not False
            or custody.get("whole_native_delivery_qualified") is not False):
        raise ValueError("default-release full-class source and installation custody differs")
    installation = require_release_installation(directory / "installed", custody["installed_files_before"],
        files, distribution, wheel, package["wheel_sha256"], pins)
    callers = require_release_callers(directory / "original-callers", root, package, manifest, sources,
                                     discovery, files, distribution, pins)
    return {"scope": scope, "package_build": str(package_path), "wheel": str(wheel),
        "wheel_sha256": package["wheel_sha256"], "default_bundle_sha256": bundle_sha,
        "native_image_sha256": manifest["image_sha256"], "source_identity_sha256": source_sha,
        "same_cold_components": components, "installation": installation, "original_callers": callers,
        "full_native_methods": 12, "test_bodies_rerun_by_supplement": False,
        "ordinary_source_default_changed": False, "retained_reference_bodies_removed": False,
        "whole_native_delivery_qualified": False, "passed": True}


def service_context_installed_record(actual, files, distribution, installed):
    """Validate pip's derived caches without executing their code objects."""
    record = distribution + "/RECORD"
    extras = {"bin/hia", *(distribution + "/" + name for name in ("INSTALLER", "REQUESTED", "direct_url.json"))}
    caches = set(actual) - set(files) - extras
    metadata, origins = {}, set()
    attributes = ("co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_nlocals", "co_stacksize",
                  "co_flags", "co_code", "co_names", "co_varnames", "co_filename", "co_name", "co_qualname",
                  "co_firstlineno", "co_linetable", "co_exceptiontable", "co_freevars", "co_cellvars")
    def same_code(left, right):
        return (type(left) is types.CodeType and type(right) is types.CodeType and left == right
                and all(getattr(left, key) == getattr(right, key) for key in attributes)
                and all(same_code(a, b) for a, b in zip(left.co_consts, right.co_consts)
                        if type(a) is types.CodeType or type(b) is types.CodeType))
    for name in caches:
        cache_path = installed / name
        source_path = Path(importlib.util.source_from_cache(str(cache_path)))
        source_name = source_path.relative_to(installed).as_posix()
        if source_name not in files or not source_name.endswith(".py"):
            raise ValueError("service-context installed cache has no wheel source")
        levels = [level for level in (0, 1, 2) if cache_path == Path(importlib.util.cache_from_source(
            str(source_path), optimization="" if level == 0 else str(level)))]
        raw, source = actual[name], files[source_name]
        flags = int.from_bytes(raw[4:8], "little")
        if (len(levels) != 1 or len(raw) < 16 or raw[:4] != importlib.util.MAGIC_NUMBER
                or flags not in (0, 1, 3)
                or (flags & 1 and raw[8:16] != importlib.util.source_hash(source))
                or (not flags and (int.from_bytes(raw[8:12], "little") != int(source_path.stat().st_mtime) & 0xffffffff
                                   or int.from_bytes(raw[12:16], "little") != len(source) & 0xffffffff))):
            raise ValueError("service-context installed cache header differs from its actual source")
        body = io.BytesIO(raw[16:])
        code = marshal.load(body)
        if (body.read() or type(code) is not types.CodeType
                or not Path(code.co_filename).is_absolute() or ".." in Path(code.co_filename).parts
                or Path(code.co_filename).as_posix() != code.co_filename
                or any(ord(char) < 32 for char in code.co_filename)
                or not code.co_filename.endswith("/" + source_name)
                or not same_code(code, compile(source, code.co_filename, "exec", dont_inherit=True, optimize=levels[0]))):
            raise ValueError("service-context installed cache code differs from its wheel source")
        origin = code.co_filename[:-(len(source_name) + 1)]
        origins.add(origin)
        metadata[name] = {"source_member": source_name, "co_filename": code.co_filename,
                          "header_hex": raw[:16].hex(), "optimization": levels[0],
                          "source_sha256": hashlib.sha256(source).hexdigest(),
                          "cache_sha256": hashlib.sha256(raw).hexdigest()}
    if len(origins) > 1:
        raise ValueError("service-context cache filename metadata spans different installation origins")
    # Cache rows legitimately have no hash/size in pip's original RECORD. Every
    # such row must be one of the independently verified derived code objects.
    retained, observed = [], set()
    for row in csv.reader(io.StringIO(actual[record].decode("utf-8"), newline="")):
        if len(row) != 3:
            raise ValueError("service-context installed RECORD row shape differs")
        if row[0] in caches:
            if row[0] in observed or row[1:] != ["", ""]:
                raise ValueError("service-context cache RECORD row differs")
            observed.add(row[0])
        else:
            retained.append(row)
    if observed != caches:
        raise ValueError("service-context RECORD omits a derived cache")
    ordinary = {name: raw for name, raw in actual.items() if name not in caches}
    if (set(ordinary) != set(files) | extras
            or any(ordinary.get(name) != raw for name, raw in files.items() if name != record)):
        raise ValueError("service-context installed production bytes differ from its real wheel")
    normalized = io.StringIO(newline="")
    csv.writer(normalized).writerows(retained)
    ordinary[record] = normalized.getvalue().encode("utf-8")
    require_release_record(ordinary, record, installed=True)
    return {"files": metadata, "compilation_origins": sorted(origins)}


def require_service_context_installation(directory, root, sources, manifest, pins):
    """Read the already executed wheel/worker/bundle observation without reruns."""
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    directory = Path(directory)
    location = directory / "installation"
    custody = release_json(location / "installed-custody.json", pins)
    wheels = sorted((location / "wheels").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("service-context requires its one actual installed wheel")
    wheel = wheels[0]
    files, distribution = release_wheel(wheel, pins)
    required = ("real_public_context_lookup_budget_remaining", "references_poisoned",
                "actual_installed_JSON_worker_context_request", "administrator_bundle_scope_restored",
                "installed_source_and_child_manifest_drift_refused")
    if (custody.get("wheel_sha256") != pins[str(wheel)]
            or custody.get("native_image_sha256") != manifest["image_sha256"]
            or any(custody.get(key) is not True for key in required)):
        raise ValueError("service-context installed observations differ from the actual wheel/image")
    for name, raw in files.items():
        if name.startswith("hepta/"):
            source_name = name.removeprefix("hepta/_data/") if name.startswith("hepta/_data/") else name
            if sources.get(source_name) != hashlib.sha256(raw).hexdigest():
                raise ValueError("service-context wheel contains unbound production source")
        elif not name.startswith(distribution + "/"):
            raise ValueError("service-context wheel contains an unexpected member")
    installed = location / "installed"
    actual = {}
    for path in sorted(installed.rglob("*")):
        if path.is_symlink():
            raise ValueError("service-context installed member is a symlink")
        if path.is_file():
            actual[path.relative_to(installed).as_posix()] = release_bytes(path, pins)
    caches = service_context_installed_record(actual, files, distribution, installed)
    origin = json.loads(actual[distribution + "/direct_url.json"])
    if (origin.get("url") != wheel.as_uri()
            or origin.get("archive_info", {}).get("hashes", {}).get("sha256") != pins[str(wheel)]):
        raise ValueError("service-context installation names another wheel")
    child = location / "context.json"
    child_raw = release_bytes(child, pins)
    image = release_bytes(location / manifest["image_path"], pins)
    bundle = release_json(location / "helpers.json", pins)
    if (child_raw != release_bytes(directory / "built/manifest.json", pins)
            or hashlib.sha256(image).hexdigest() != manifest["image_sha256"]
            or bundle != {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
                "selector": "HEPTA_HIA_SERVICE_CONTEXT_MANIFEST", "manifest_path": child.name,
                "manifest_sha256": hashlib.sha256(child_raw).hexdigest()}]}):
        raise ValueError("service-context administrator bundle differs from its executed component")
    return {"wheel": str(wheel), "wheel_sha256": pins[str(wheel)],
            "actual_wheel_members": len(files), "actual_installed_files": len(actual),
            "verified_derived_cache_files": len(caches["files"]),
            "actual_cache_metadata": caches, "cache_code_objects_executed": False,
            "installed_product_bytes_match_source_and_wheel": True,
            "four_public_routes_and_actual_JSON_worker_observed": True,
            "test_bodies_rerun_by_supplement": False}


def service_context_composition_observations(directory, expected_scope, pins):
    report = release_json(Path(directory) / "composition.json", pins)
    counts = report.get("actual_native_entries", {})
    if (report.get("scope") != expected_scope
            or report.get("original_context_wall_ms") != 3000
            or report.get("context_store_execution_and_candidate_budget_composed") is not True
            or report.get("all_retained_policy_references_forbidden") is not True
            or report.get("whole_native_delivery_qualified") is not False
            or type(counts) is not dict or set(counts) != {"NativeServiceContextImage",
                "NativeStoreLifecycleImage", "NativeExecutionBudgetImage", "NativeCandidateBudgetImage"}
            or any(type(value) is not int or value <= 0 for value in counts.values())):
        raise ValueError("service-context four-owner composition observations differ")
    return report


def require_service_context_composition(directory, root, cold_path, compiler, sources, pins):
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    from tools.build_hia_store_lifecycle import INPUTS as STORE_INPUTS
    from tools.build_hia_source_build import _check_pack_output, _check_compile_receipt
    directory = Path(directory)
    composition = directory / "four-owner-composition"
    report = service_context_composition_observations(composition, "MATCHING_SOURCE_COLD_COMPONENT", pins)
    manifests = {"HEPTA_HIA_SERVICE_CONTEXT_MANIFEST": directory / "built/manifest.json",
                 "HEPTA_HIA_STORE_LIFECYCLE_MANIFEST": composition / "store/manifest.json"}
    source_name = "examples/hia_bootstrap/store_lifecycle.hepta"
    require_cold_component(manifests["HEPTA_HIA_STORE_LIFECYCLE_MANIFEST"], source_name,
                           sha(cold_path), sha(compiler), sources, pins)
    require_release_compilation(composition / "store", "store-lifecycle", source_name,
                                STORE_INPUTS, root, compiler, sources, pins)
    for selector, label, source_name in (
            ("HEPTA_HIA_EXECUTION_BUDGET_MANIFEST", "execution-budget", "examples/hia_bootstrap/execution_budget.hepta"),
            ("HEPTA_HIA_CANDIDATE_BUDGET_MANIFEST", "candidate-budget", "examples/hia_bootstrap/candidate_budget.hepta")):
        location = composition / label
        manifest_path = location / "manifest.json"
        manifest = release_json(manifest_path, pins)
        build = release_json(location / "build.json", pins)
        request = release_json(location / (label + ".request.json"), pins)
        receipt = release_json(location / (label + ".receipt.json"), pins)
        source = release_bytes(root / source_name, pins)
        artifact = release_bytes(compiler, pins)
        image_path = location / (label + ".image.bin")
        image = release_bytes(image_path, pins)
        output = release_bytes(location / (label + ".output.bin"), pins)
        if (build.get("schema") != "hepta.hia." + label + "-build.v1"
                or build.get("status") != "NATIVE_CANDIDATE_BUILT"
                or build.get("source_manifest") != sources or build.get("cold_report_sha256") != sha(cold_path)
                or build.get("manifest") != manifest or build.get("native_compile_receipt") != receipt
                or manifest.get("schema") != "hepta.hia." + label + "-native.v1"
                or manifest.get("compiler_sha256") != hashlib.sha256(artifact).hexdigest()
                or manifest.get("source_sha256") != sources[source_name]
                or manifest.get("image_path") != image_path.name
                or manifest.get("image_sha256") != hashlib.sha256(image).hexdigest()
                or receipt.get("produced_image") != str(image_path)
                or release_bytes(location / (label + ".input.bin"), pins) != source
                or request != {"capacity": 1048576, "format": "flat-x86-64", "image": str(compiler),
                    "image_sha256": hashlib.sha256(artifact).hexdigest(), "output": str(location / (label + ".output.bin")),
                    "source": str(location / (label + ".input.bin")), "source_sha256": sources[source_name],
                    "workspace_fill": 0, "workspace_size": 1048576}
                or _check_pack_output(receipt, output, artifact=artifact, source=source) != image):
            raise ValueError("service-context composed budget does not bind the same cold compiler transport")
        _check_compile_receipt(receipt, compiler=artifact, source=source, produced=image)
        manifests[selector] = manifest_path
    bundle = release_json(composition / "bundle.json", pins)
    expected = {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
        "selector": selector, "manifest_path": str(path.resolve()),
        "manifest_sha256": hashlib.sha256(release_bytes(path, pins)).hexdigest()}
        for selector, path in sorted(manifests.items())]}
    if bundle != expected:
        raise ValueError("service-context four-owner bundle differs from the executed cold components")
    raw_count = 0
    for path in sorted(composition.rglob("*")):
        if path.is_symlink():
            raise ValueError("service-context composition evidence contains a symlink")
        if path.is_file():
            release_bytes(path, pins)
            raw_count += 1
    return {"scope": "MATCHING_SOURCE_COLD_COMPONENT", "actual_native_entries": report["actual_native_entries"],
            "original_context_wall_ms": 3000, "all_retained_policy_references_forbidden": True,
            "raw_composition_evidence_files": raw_count, "bundle": str(composition / "bundle.json"),
            "test_bodies_rerun_by_supplement": False, "passed": True}


def require_service_context_component(directory, root, cold_path, compiler, sources, pins):
    from tools.build_hia_service_context import INPUTS, SOURCE_NAME
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    require_cold_component(manifest_path, SOURCE_NAME, sha(cold_path), sha(compiler), sources, pins)
    manifest = require_release_compilation(directory / "built", "service-context", SOURCE_NAME,
                                          INPUTS, root, compiler, sources, pins)
    custody = release_json(directory / "component-custody.json", pins)
    if (manifest.get("schema") != "hepta.hia.service-context-native.v1"
            or custody.get("schema") != "hepta.hia.service-context-test-custody.v1"
            or custody.get("scope") != "MATCHING_SOURCE_COLD_COMPONENT"
            or custody.get("compiler_sha256") != sha(compiler)
            or custody.get("compiler_unchanged") is not True
            or custody.get("image_sha256") != manifest["image_sha256"]
            or custody.get("whole_native_delivery_qualified") is not False):
        raise ValueError("service-context first-full component custody differs")
    effects = release_json(directory / "original-effects.json", pins)
    if (effects.get("modes") != 4 or effects.get("foreign_failure_points") != 37
            or any(effects.get(key) is not True for key in (
                "actual_SQLite_rows_compared", "fixed_schema_and_buffer_providers",
                "exception_identity_cause_context_notes_preserved",
                "original_effect_order_and_partial_mutations_preserved"))):
        raise ValueError("service-context original foreign-effect observations differ")
    installation = require_service_context_installation(directory, root, sources, manifest, pins)
    composition = require_service_context_composition(directory, root, cold_path, compiler, sources, pins)
    return {"scope": "MATCHING_SOURCE_COLD_COMPONENT", "manifest": str(manifest_path),
            "image_sha256": manifest["image_sha256"], "installation": installation,
            "four_owner_composition": composition,
            "original_foreign_failure_points": 37, "test_bodies_rerun_by_supplement": False,
            "whole_native_delivery_qualified": False, "passed": True}


def require_service_context_caller_observations(directory, root, sources, discovery, manifest_path, pins):
    """Check frozen original methods, source pins and actual existing entries/log."""
    from tools.qualify_hia_service_context_callers import FIXTURE_NAME, FIXTURE_SHA256
    from tools.build_hia_service_context import INPUTS
    from tools.hia_selfhost_contract import file_digests
    directory = Path(directory)
    manifest_path = Path(manifest_path)
    manifest = release_json(manifest_path, pins)
    report = release_json(directory / "report.json", pins)
    fixture_path = root / FIXTURE_NAME
    original = release_json(fixture_path, pins)
    modules = original.get("modules", [])
    original_names = {name.replace(".", "/") + ".py" for name in modules}
    if (pins[str(fixture_path)] != FIXTURE_SHA256
            or sources.get(FIXTURE_NAME) != FIXTURE_SHA256
            or original.get("schema") != "hepta.hia.service-context-original-callers.v1"
            or len(modules) != 4 or len(original_names) != 4
            or len(original.get("ordered_ids", [])) != 50
            or set(original.get("source_sha256", {})) != original_names
            or any((name in sources and sources[name] != digest)
                   or hashlib.sha256(release_bytes(root / name, pins)).hexdigest() != digest
                   for name, digest in original["source_sha256"].items())):
        raise ValueError("service-context original four-module/50-method source inventory differs")
    # Some original test modules enter cold custody through this frozen caller
    # inventory rather than a second individual source-manifest key. Both the
    # inventory's exact bytes and every referenced caller byte are mandatory.
    bindings = {**sources, **original["source_sha256"]}
    descriptions = [row for module in modules for row in discovery["test_descriptions"]
                    if row["id"].startswith(module + ".")]
    planned = [row["id"] for row in descriptions]
    source_names = set(file_digests(root)) | {"tools/qualify_hia_service_context_callers.py", FIXTURE_NAME,
                                             *INPUTS, *original_names}
    source_pins = {name: hashlib.sha256(release_bytes(root / name, pins)).hexdigest() for name in source_names}
    bundle_pins = {}
    for path in sorted(manifest_path.parent.rglob("*")):
        if path.is_symlink():
            raise ValueError("service-context caller build contains a symlink")
        if path.is_file():
            bundle_pins[str(path)] = hashlib.sha256(release_bytes(path, pins)).hexdigest()
    modes, events, integers = (report.get(name, {}) for name in
                              ("native_mode_frames", "actual_machine_mode_events", "actual_integer_operations"))
    if (report.get("status") != "PASS" or planned != original["ordered_ids"]
            or len(planned) != 50 or len(set(planned)) != 50
            or report.get("original_modules") != modules
            or not (report.get("planned") == report.get("started") == report.get("stopped") == planned)
            or type(report.get("actual_tests")) is not int or report["actual_tests"] != 50
            or any(report.get(key) != [] for key in ("errors", "failures", "skipped",
                                                    "expected_failures", "unexpected_successes", "reference_calls"))
            or report.get("reference_poison_scope")
                != "test process; subprocesses inherit selector, not Python patches"
            or report.get("all_original_modules_unfiltered") is not True
            or report.get("original_test_budgets_changed") is not False
            or report.get("source_and_bundle_unchanged") is not True
            or report.get("foreign_schema_profile_buffer_sqlite_clock_budget_effects_still_hosted") is not True
            or report.get("whole_native_delivery_qualified") is not False
            or manifest.get("schema") != "hepta.hia.service-context-native.v1"
            or manifest.get("source_sha256") != sources["examples/hia_bootstrap/service_context.hepta"]
            or report.get("native_image_sha256") != manifest["image_sha256"]
            or bundle_pins.get(str(manifest_path.parent / manifest["image_path"])) != manifest["image_sha256"]
            or report.get("source_pins") != source_pins or not bundle_pins
            or report.get("bundle_pins") != bundle_pins
            or any(bindings.get(name) != digest for name, digest in source_pins.items())
            or type(modes) is not dict or set(modes) != {"1", "2", "3", "4"}
            or any(type(value) is not int or value <= 0 for value in modes.values())
            or type(events) is not dict
            or not set(events) <= {mode + ":" + event for mode in modes for event in ("0", "1", "2", "3")}
            or any(type(value) is not int or value <= 0 for value in events.values())
            or any(events.get(mode + ":0") != modes[mode]
                   or type(events.get(mode + ":1")) is not int or type(events.get(mode + ":2")) is not int
                   or events[mode + ":1"] != events[mode + ":2"] + events.get(mode + ":3", 0)
                   for mode in modes)
            or type(integers) is not dict or not {"1", "2", "3", "4", "5", "6", "8"} <= set(integers)
            or not set(integers) <= {str(number) for number in range(1, 9)}
            or any(type(value) is not int or value <= 0 for value in integers.values())):
        raise ValueError("service-context original 50 caller observations or captured inputs differ")
    observed = audit_verbose_stderr(release_bytes(directory / "tests.log", pins),
        {"planned_test_ids": planned, "test_descriptions": descriptions})
    if observed["equivalent"] is not True:
        raise ValueError("service-context original verbose log does not contain all 50 successful methods")
    return {"actual_tests": 50, "mode_frames": modes, "actual_control_entries": sum(events.values()),
            "actual_integer_entries": sum(integers.values()), "source_pin_count": len(source_pins),
            "bundle_pin_count": len(bundle_pins), "original_verbose_identity": observed,
            "callers_bound_through_frozen_inventory": sorted(original_names - set(sources)),
            "original_test_budgets_changed": False, "test_bodies_rerun_by_readback": False}


def require_cost_ledger_installation(directory, root, sources, manifest, pins):
    """Read the real installed worker's receipts, without invoking it again."""
    from hepta import hia_agent_contract as contract
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    directory = Path(directory)
    location = directory / "test_actual_installed_wheel_and_original_worker_use_pinned_ledger"
    observation = release_json(location / "installed-observation.json", pins)
    wheels = sorted((location / "wheels").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("cost-ledger requires its one actual installed wheel")
    wheel = wheels[0]
    files, distribution = release_wheel(wheel, pins)
    for name, raw in files.items():
        if name.startswith("hepta/"):
            source_name = name.removeprefix("hepta/_data/") if name.startswith("hepta/_data/") else name
            if sources.get(source_name) != hashlib.sha256(raw).hexdigest():
                raise ValueError("cost-ledger wheel contains unbound production source")
        elif not name.startswith(distribution + "/"):
            raise ValueError("cost-ledger wheel contains an unexpected member")
    installed = location / "installed"
    actual = {}
    for path in sorted(installed.rglob("*")):
        if path.is_symlink():
            raise ValueError("cost-ledger installed member is a symlink")
        if path.is_file():
            actual[path.relative_to(installed).as_posix()] = release_bytes(path, pins)
    record = distribution + "/RECORD"
    extras = {"bin/hia", *(distribution + "/" + name for name in ("INSTALLER", "REQUESTED", "direct_url.json"))}
    if (set(actual) != set(files) | extras
            or any(actual.get(name) != raw for name, raw in files.items() if name != record)):
        raise ValueError("cost-ledger installed product bytes differ from its real wheel")
    require_release_record(actual, record, installed=True)
    origin = json.loads(actual[distribution + "/direct_url.json"])
    if (origin.get("url") != wheel.as_uri()
            or origin.get("archive_info", {}).get("hashes", {}).get("sha256") != pins[str(wheel)]):
        raise ValueError("cost-ledger installation names another wheel")
    manifest_path = directory / "built/manifest.json"
    manifest_raw = release_bytes(manifest_path, pins)
    image = release_bytes(manifest_path.parent / manifest["image_path"], pins)
    bundle_path = location / "bundle.json"
    bundle = release_json(bundle_path, pins)
    bundle_sha = pins[str(bundle_path)]
    if (json.loads(manifest_raw) != manifest
            or hashlib.sha256(image).hexdigest() != manifest["image_sha256"]
            or bundle != {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
                "selector": "HEPTA_HIA_COST_LEDGER_MANIFEST", "manifest_path": str(manifest_path),
                "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}]}
            or observation.get("wheel") != str(wheel)
            or observation.get("wheel_sha256") != pins[str(wheel)]
            or observation.get("bundle_sha256") != bundle_sha
            or observation.get("actual_installed_source_sha256")
                != sources["examples/hia_bootstrap/cost_ledger.hepta"]
            or observation.get("old_reference_forbidden") is not True
            or observation.get("original_worker_replay") is not True
            or observation.get("whole_native_delivery_qualified") is not False):
        raise ValueError("cost-ledger installed observation or administrator bundle differs")
    # Derive the worker identity from its actual wheel bytes. This reads data;
    # it does not import the installed package or invoke an installation probe.
    entries = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()
               if name.startswith("hepta/") and name.endswith(".py") and not name.startswith("hepta/_data/")}
    resources = ["docs/" + name for name in contract.DISCOVERY_FILES]
    for group in ("NATIVE_SOURCE_FILES", "SOURCE_BUILD_FILES", "COMPILER_BUILD_FILES", "PUBLICATION_BUILD_FILES",
                  "BACKEND_BUILD_FILES", "EMITTER_BUILD_FILES", "BYTE_WRAPPER_BUILD_FILES",
                  "MACHINE_OBJECT_BUILD_FILES", "EXECUTION_OBSERVATION_BUILD_FILES", "CONTINUATION_BUILD_FILES"):
        resources.extend(getattr(contract, group))
    for name in resources:
        entries[name] = hashlib.sha256(files["hepta/_data/" + name]).hexdigest()
    worker_sha = hashlib.sha256(json.dumps(entries, ensure_ascii=False, sort_keys=True,
                                           separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
    first = release_json(location / "first-report.json", pins)
    replay = release_json(location / "replay-report.json", pins)
    counts = []
    for name in ("first_native_stderr", "replay_native_stderr"):
        stderr = observation.get(name)
        markers = re.findall(r"^LEDGER_NATIVE_ADDITIONS=(0|[1-9][0-9]*)$", stderr, re.M) if type(stderr) is str else []
        if len(markers) != 1:
            raise ValueError("cost-ledger worker requires one actual native-addition marker per invocation")
        counts.append(int(markers[0]))
    response = first.get("response", {})
    ledger = response.get("result", {}).get("full_cost_ledger", {})
    if (first != replay or first.get("schema") != "hia-agent-worker-report-v1"
            or first.get("tool") != "hia_evaluate" or first.get("complete") is not True
            or first.get("native_helpers_sha256") != bundle_sha
            or first.get("worker_sha256") != worker_sha
            or first.get("catalog_sha256") != entries["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"]
            or first.get("profile_sha256") != "a" * 64
            or any(type(first.get(name)) is not str or re.fullmatch(r"[0-9a-f]{64}", first[name]) is None
                   for name in ("backend_sha256", "request_sha256"))
            or response.get("status") != "completed" or response.get("contract_version") != contract.VERSION
            or type(response.get("request_id")) is not str or not response["request_id"]
            or type(ledger.get("id")) is not str or not ledger["id"]
            or type(ledger.get("uri")) is not str or not ledger["uri"].startswith("hia://artifacts/")
            or type(ledger.get("sha256")) is not str or re.fullmatch(r"[0-9a-f]{64}", ledger["sha256"]) is None
            or counts[0] <= 0 or counts[1] != 0):
        raise ValueError("cost-ledger actual installed worker/replay receipts differ")
    return {"wheel": str(wheel), "wheel_sha256": pins[str(wheel)],
            "actual_wheel_members": len(files), "actual_installed_files": len(actual),
            "installed_record_sha256": pins[str(installed / record)],
            "installed_product_bytes_match_source_and_wheel": True,
            "worker_identity_derived_from_actual_wheel": worker_sha,
            "first_worker_native_additions": counts[0], "replay_worker_native_additions": counts[1],
            "native_observation_scope": "installed hia_evaluate worker process NativeCostLedger.add calls",
            "reference_poison_scope": "installed worker process only; descendant poison is not observed",
            "worker_replay_receipts_identical": True, "retained_ledger_artifact_reference": ledger,
            "ledger_artifact_body_retained_by_fixture": False, "request_body_retained_by_fixture": False,
            "test_bodies_rerun_by_supplement": False, "whole_native_delivery_qualified": False}


def require_cost_ledger_component(directory, root, cold_path, compiler, sources, pins):
    from tools.build_hia_cost_ledger import INPUTS, SOURCE_NAME
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    require_cold_component(manifest_path, SOURCE_NAME, sha(cold_path), sha(compiler), sources, pins)
    manifest = require_release_compilation(directory / "built", "cost-ledger", SOURCE_NAME,
                                          INPUTS, root, compiler, sources, pins)
    build = release_json(directory / "built/build.json", pins)
    custody = release_json(directory / "component-custody.json", pins)
    if (manifest.get("schema") != "hepta.hia.cost-ledger-native.v1"
            or build.get("schema") != "hepta.hia.cost-ledger-build.v1"
            or build.get("foreign_sqlite_json_object_conversion_and_allocation_hosted") is not True
            or build.get("ledger_control_comparisons_and_signed_accumulation_owned_by_hia") is not True
            or build.get("whole_stack_rewritten_in_hia") is not False
            or build.get("all_input_equivalence_proved") is not False
            or custody.get("schema") != "hepta.hia.cost-ledger-test-custody.v1"
            or custody.get("manifest") != str(manifest_path)
            or custody.get("matching_cold_report") != str(cold_path)
            or custody.get("compiler_sha256") != sha(compiler)
            or custody.get("compiler_unchanged") is not True
            or custody.get("source_manifest_before") != sources or custody.get("source_manifest_after") != sources
            or custody.get("source_and_compiler_unchanged") is not True
            or custody.get("test_result_owned_by_outer_runner") is not True
            or custody.get("foreign_sqlite_json_int_str_and_objects_hosted") is not True
            or custody.get("whole_native_delivery_qualified") is not False):
        raise ValueError("cost-ledger first-full component source/compiler custody differs")
    installation = require_cost_ledger_installation(directory, root, sources, manifest, pins)
    return {"scope": "MATCHING_SOURCE_COLD_COMPONENT", "manifest": str(manifest_path),
            "image_sha256": manifest["image_sha256"], "installation": installation,
            "source_and_compiler_custody_verified": True, "test_result_owned_by_original_full_runner": True,
            "test_bodies_rerun_by_supplement": False, "whole_native_delivery_qualified": False, "passed": True}


def require_cost_ledger_caller_observations(directory, root, sources, discovery, manifest_path, pins):
    """Bind all seven ordinary modules to their frozen 81 ordered identities."""
    from tools.qualify_hia_cost_ledger_callers import FIXTURE_NAME, FIXTURE_SHA256
    from tools.build_hia_cost_ledger import INPUTS
    from tools.hia_selfhost_contract import file_digests
    directory = Path(directory)
    manifest_path = Path(manifest_path)
    manifest = release_json(manifest_path, pins)
    report = release_json(directory / "report.json", pins)
    fixture_path = root / FIXTURE_NAME
    original = release_json(fixture_path, pins)
    modules = original.get("modules", [])
    original_names = {name.replace(".", "/") + ".py" for name in modules}
    original_sources = original.get("original_source_sha256", {})
    separate = original.get("explicit_scope_integration_modules", {})
    separate_names = {name.replace(".", "/") + ".py" for name in separate}
    if (pins[str(fixture_path)] != FIXTURE_SHA256 or sources.get(FIXTURE_NAME) != FIXTURE_SHA256
            or original.get("schema") != "hepta.hia.cost-ledger-original-callers.v1"
            or len(modules) != 7 or len(original_names) != 7 or len(original.get("ordered_ids", [])) != 81
            or len(separate) != 4 or original_names & separate_names
            or set(original_sources) != original_names | separate_names
            or original.get("whole_project_dynamic_caller_closure_claimed") is not False
            or any((name in sources and sources[name] != original_sources[name])
                   or hashlib.sha256(release_bytes(root / name, pins)).hexdigest() != original_sources[name]
                   for name in original_names)):
        raise ValueError("cost-ledger frozen seven-module/81-method source inventory differs")
    # The other four modules own explicit administrator bundles. Preserve their
    # declared inventory in full discovery without injecting this ledger into
    # them or pretending that this ordinary-caller command executes their cases.
    for module, declared in separate.items():
        planned_separate = [row["id"] for row in discovery["test_descriptions"]
                            if row["id"].startswith(module + ".")]
        if (not planned_separate or planned_separate != declared.get("ordered_ids")
                or declared.get("gate") != "unchanged full discovery and original owner gates"
                or declared.get("selection_boundary")
                    != "original explicit administrator bundles exclude COST_LEDGER; preserved without image injection"):
            raise ValueError("cost-ledger separate administrator-scope inventory differs")
    bindings = {**sources, **{name: original_sources[name] for name in original_names}}
    descriptions = [row for module in modules for row in discovery["test_descriptions"]
                    if row["id"].startswith(module + ".")]
    planned = [row["id"] for row in descriptions]
    source_names = set(file_digests(root)) | {"tools/qualify_hia_cost_ledger_callers.py", FIXTURE_NAME,
                                             *INPUTS, *original_names}
    source_pins = {name: hashlib.sha256(release_bytes(root / name, pins)).hexdigest() for name in source_names}
    bundle_pins = {}
    for path in sorted(manifest_path.parent.rglob("*")):
        if path.is_symlink():
            raise ValueError("cost-ledger caller build contains a symlink")
        if path.is_file():
            bundle_pins[str(path)] = hashlib.sha256(release_bytes(path, pins)).hexdigest()
    events, frames = report.get("actual_native_event_counts", {}), report.get("actual_ledger_frames")
    if (report.get("schema") != "hepta.hia.cost-ledger-seven-ordinary-callers.v1"
            or report.get("status") != "PASS" or planned != original["ordered_ids"]
            or len(planned) != 81 or len(set(planned)) != 81 or report.get("original_modules") != modules
            or not (report.get("planned") == report.get("started") == report.get("stopped") == planned)
            or type(report.get("actual_tests")) is not int or report["actual_tests"] != 81
            or any(report.get(key) != [] for key in ("errors", "failures", "skipped",
                                                    "expected_failures", "unexpected_successes", "reference_calls"))
            or report.get("reference_poison_scope")
                != "test process; subprocesses inherit selector, not Python patches"
            or report.get("retained_ledger_body_forbidden") is not True
            or report.get("all_seven_ordinary_modules_unfiltered") is not True
            or report.get("original_test_budgets_changed") is not False
            or report.get("source_and_bundle_unchanged") is not True
            or report.get("separate_original_administrator_scope_gates") != separate
            or report.get("whole_project_dynamic_caller_closure_claimed") is not False
            or report.get("whole_native_delivery_qualified") is not False
            or manifest.get("schema") != "hepta.hia.cost-ledger-native.v1"
            or manifest.get("source_sha256") != sources["examples/hia_bootstrap/cost_ledger.hepta"]
            or report.get("native_image_sha256") != manifest["image_sha256"]
            or bundle_pins.get(str(manifest_path.parent / manifest["image_path"])) != manifest["image_sha256"]
            or report.get("source_pins") != source_pins or not bundle_pins or report.get("bundle_pins") != bundle_pins
            or any(bindings.get(name) != digest for name, digest in source_pins.items())
            or type(frames) is not int or frames <= 0 or type(events) is not dict
            or not {"0", "1", "2", "10", "11"} <= set(events) <= {"0", "1", "2", "3", "10", "11"}
            or any(type(value) is not int or value <= 0 for value in events.values())
            or events["0"] != frames or events["1"] != events["2"] + events.get("3", 0)):
        raise ValueError("cost-ledger original 81 caller observations or captured inputs differ")
    observed = audit_verbose_stderr(release_bytes(directory / "tests.log", pins),
        {"planned_test_ids": planned, "test_descriptions": descriptions})
    if observed["equivalent"] is not True:
        raise ValueError("cost-ledger original verbose log does not contain all 81 successful methods")
    return {"actual_tests": 81, "actual_ledger_frames": frames, "actual_native_event_counts": events,
            "actual_control_entries": sum(value for event, value in events.items() if event not in ("10", "11")),
            "actual_native_additions": events["10"], "actual_native_comparisons": events["11"],
            "source_pin_count": len(source_pins), "bundle_pin_count": len(bundle_pins),
            "original_verbose_identity": observed,
            "callers_bound_through_frozen_inventory": sorted(original_names - set(sources)),
            "separate_administrator_scope_inventories": separate,
            "reference_poison_scope": report["reference_poison_scope"],
            "whole_project_dynamic_caller_closure_claimed": False, "original_test_budgets_changed": False,
            "test_bodies_rerun_by_readback": False, "whole_native_delivery_qualified": False}


def evaluation_json_bytes(value):
    """Keep JSON bool/int/float distinctions in retained observations."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def evaluation_native_counts(raw):
    prefix = b"EVALUATION_NATIVE_COUNTS="
    found = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    if len(found) != 1:
        raise ValueError("evaluation worker needs one original native observation marker")
    value = json.loads(found[0])
    if (type(value) is not dict or set(value) != {"frames", "continuations", "integers", "native_results"}
            or any(type(value[key]) is not int or value[key] < 0
                   for key in ("frames", "continuations", "integers"))
            or type(value["native_results"]) is not list):
        raise ValueError("evaluation worker native observation shape differs")
    return value


def evaluation_installed_bytes(location, sources, observation, pins):
    wheels = sorted((location / "wheels").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("evaluation needs the one actual installed wheel")
    wheel = wheels[0]
    files, distribution = release_wheel(wheel, pins)
    for name, raw in files.items():
        if name.startswith("hepta/"):
            source_name = name.removeprefix("hepta/_data/") if name.startswith("hepta/_data/") else name
            if sources.get(source_name) != hashlib.sha256(raw).hexdigest():
                raise ValueError("evaluation wheel contains unbound production source")
        elif not name.startswith(distribution + "/"):
            raise ValueError("evaluation wheel contains an unexpected member")
    installed = location / "installed"
    actual = {}
    for path in sorted(installed.rglob("*")):
        if path.is_symlink():
            raise ValueError("evaluation installed member is a symlink")
        if path.is_file():
            actual[path.relative_to(installed).as_posix()] = release_bytes(path, pins)
    record = distribution + "/RECORD"
    member = "hepta/_data/examples/hia_bootstrap/evaluation.hepta"
    extras = {"bin/hia", *(distribution + "/" + name for name in ("INSTALLER", "REQUESTED", "direct_url.json"))}
    if (set(actual) != set(files) | extras or member not in files
            or any(actual.get(name) != raw for name, raw in files.items() if name not in (record, member))
            or actual.get(member) != files[member] + b"\n"):
        raise ValueError("evaluation installed bytes differ beyond the one-LF source control")
    # Validate the original RECORD against the exact pre-drift bytes in memory.
    # The deliberate final mutation and every other actual byte remain pinned.
    recorded = dict(actual)
    recorded[member] = files[member]
    require_release_record(recorded, record, installed=True)
    origin = json.loads(actual[distribution + "/direct_url.json"])
    drift = observation.get("installed_source_drift", {})
    if (origin.get("url") != wheel.as_uri()
            or origin.get("archive_info", {}).get("hashes", {}).get("sha256") != pins[str(wheel)]
            or observation.get("wheel") != str(wheel) or observation.get("wheel_sha256") != pins[str(wheel)]
            or drift.get("before_sha256") != sources["examples/hia_bootstrap/evaluation.hepta"]
            or drift["before_sha256"] != hashlib.sha256(files[member]).hexdigest()
            or drift.get("after_sha256") != hashlib.sha256(actual[member]).hexdigest()):
        raise ValueError("evaluation wheel origin or exact source drift hashes differ")
    return files, {"wheel": str(wheel), "wheel_sha256": pins[str(wheel)],
        "actual_wheel_members": len(files), "actual_installed_files": len(actual),
        "all_other_installed_product_bytes_equal_wheel": True,
        "installed_RECORD_checked_against_exact_pre_drift_bytes": True,
        "only_intentional_installed_mutation": {"member": member, "change": "append exactly one LF",
            "before_sha256": drift["before_sha256"], "after_sha256": drift["after_sha256"]}}


def evaluation_worker_streams(location, worker_sha, catalog_sha, bundle_sha, version, pins):
    logs, counts = {}, {}
    labels = ("first", "replay", "lost-ack-valueerror", "lost-ack-replay",
              "process-lost-after-native", "unknown-replay", "changed-installed-source")
    for label in ("wheel", "install", *labels):
        logs[label] = {stream: release_bytes(location / (label + "." + stream), pins)
                       for stream in ("stdout", "stderr")}
        if label in labels:
            counts[label] = evaluation_native_counts(logs[label]["stderr"])
    zero = {"frames": 0, "continuations": 0, "integers": 0, "native_results": []}
    for label in ("replay", "lost-ack-replay", "unknown-replay", "changed-installed-source"):
        if counts[label] != zero:
            raise ValueError("evaluation replay or changed-source refusal executed a native operation")
    for label, expected_results in (("first", 2), ("lost-ack-valueerror", 1), ("process-lost-after-native", 1)):
        row = counts[label]
        if (row["frames"] != 1 or row["continuations"] <= 0 or row["integers"] <= 0
                or len(row["native_results"]) != expected_results
                or any(type(item) is not dict or item.get("started") is not True
                       or item.get("termination_confirmed") is not True or item.get("status") != "returned"
                       or type(item.get("wall_ns")) is not str
                       or re.fullmatch(r"[1-9][0-9]*", item["wall_ns"]) is None
                       for item in row["native_results"])):
            raise ValueError("evaluation lacks actual completed original native-runner observations")
    reports = {label: json.loads(logs[label]["stdout"])
               for label in ("first", "replay", "lost-ack-replay", "unknown-replay")}
    for report in reports.values():
        if (report.get("schema") != "hia-agent-worker-report-v1" or report.get("tool") != "hia_evaluate"
                or report.get("complete") is not True or report.get("native_helpers_sha256") != bundle_sha
                or report.get("worker_sha256") != worker_sha or report.get("catalog_sha256") != catalog_sha
                or report.get("profile_sha256") != "a" * 64
                or any(type(report.get(key)) is not str or re.fullmatch(r"[0-9a-f]{64}", report[key]) is None
                       for key in ("backend_sha256", "request_sha256"))
                or report.get("response", {}).get("contract_version") != version
                or type(report.get("response", {}).get("request_id")) is not str
                or not report["response"]["request_id"]):
            raise ValueError("evaluation actual installed worker identity or report differs")
    if (evaluation_json_bytes(reports["first"]) != evaluation_json_bytes(reports["replay"])
            or len({reports[label]["request_sha256"]
                    for label in ("first", "lost-ack-replay", "unknown-replay")}) != 3
            or b"ValueError: controlled lost native acknowledgement" not in logs["lost-ack-valueerror"]["stderr"]
            or b"hepta.hia_evaluation_native.EvaluationUnknown:" not in logs["lost-ack-valueerror"]["stderr"]):
        raise ValueError("evaluation normal replay or lost acknowledgement correlation differs")
    return reports, counts, logs


def evaluation_worker_loss(observation, reports, counts, logs):
    budgets = {}
    for key, lost, replay in (("native_ack_exception", "lost-ack-valueerror", "lost-ack-replay"),
                              ("process_loss", "process-lost-after-native", "unknown-replay")):
        row = observation.get(key, {})
        budget = row.get("retained_budget", {})
        response = reports[replay]["response"]
        if (evaluation_json_bytes(row.get("actual_native_counts")) != evaluation_json_bytes(counts[lost])
                or evaluation_json_bytes(row.get("replay_counts")) != evaluation_json_bytes(counts[replay])
                or evaluation_json_bytes(row.get("replay")) != evaluation_json_bytes(reports[replay])
                or logs[lost]["stdout"] != b""
                or response.get("status") != "rejected"
                or response.get("error", {}).get("code") != "E_HIA_REQUEST_UNKNOWN"
                or set(budget) != {"context_id", "owner", "used_native_ns"}
                or type(budget["context_id"]) is not str or not budget["context_id"]
                or type(budget["owner"]) is not str or re.fullmatch(r"[0-9a-f]{64}", budget["owner"]) is None
                or budget["used_native_ns"] != "0"):
            raise ValueError("evaluation unconfirmed effect was completed, retried or refunded")
        budgets[key] = budget
    drift = observation.get("installed_source_drift", {})
    if (drift.get("native_counts") != counts["changed-installed-source"]
            or type(drift.get("worker_exit_code")) is not int or drift["worker_exit_code"] == 0
            or logs["changed-installed-source"]["stdout"] != b""):
        raise ValueError("evaluation exact installed-source refusal record differs")
    return budgets


def require_evaluation_installation(directory, root, sources, manifest, pins):
    """Read real wheel/worker artifacts; the original full test owns execution."""
    from hepta import hia_agent_contract as contract
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    directory = Path(directory)
    location = directory / "test_actual_installed_worker_replay_process_loss_and_source_pinning"
    observation = release_json(location / "installed-observations.json", pins)
    files, installation = evaluation_installed_bytes(location, sources, observation, pins)
    manifest_path = directory / "built/manifest.json"
    manifest_raw = release_bytes(manifest_path, pins)
    image = release_bytes(manifest_path.parent / manifest["image_path"], pins)
    bundle_path = location / "bundle.json"
    bundle = release_json(bundle_path, pins)
    bundle_sha = pins[str(bundle_path)]
    if (json.loads(manifest_raw) != manifest or manifest.get("schema") != "hepta.hia.evaluation-native.v1"
            or manifest.get("source_sha256") != sources["examples/hia_bootstrap/evaluation.hepta"]
            or hashlib.sha256(image).hexdigest() != manifest["image_sha256"]
            or bundle != {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
                "selector": "HEPTA_HIA_EVALUATION_MANIFEST", "manifest_path": str(manifest_path),
                "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}]}
            or observation.get("bundle_sha256") != bundle_sha
            or any(observation.get(key) is not True for key in (
                "retained_body_forbidden_in_actual_child", "authoring_imports_forbidden_in_actual_child",
                "original_worker_used"))
            or observation.get("whole_native_delivery_qualified") is not False):
        raise ValueError("evaluation installed observation or exact administrator bundle differs")
    entries = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()
               if name.startswith("hepta/") and name.endswith(".py") and not name.startswith("hepta/_data/")}
    resources = ["docs/" + name for name in contract.DISCOVERY_FILES]
    for group in ("NATIVE_SOURCE_FILES", "SOURCE_BUILD_FILES", "COMPILER_BUILD_FILES", "PUBLICATION_BUILD_FILES",
                  "BACKEND_BUILD_FILES", "EMITTER_BUILD_FILES", "BYTE_WRAPPER_BUILD_FILES",
                  "MACHINE_OBJECT_BUILD_FILES", "EXECUTION_OBSERVATION_BUILD_FILES", "CONTINUATION_BUILD_FILES"):
        resources.extend(getattr(contract, group))
    for name in resources:
        entries[name] = hashlib.sha256(files["hepta/_data/" + name]).hexdigest()
    worker_sha = hashlib.sha256(evaluation_json_bytes(entries)).hexdigest()
    reports, counts, logs = evaluation_worker_streams(location, worker_sha,
        entries["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"], bundle_sha, contract.VERSION, pins)
    for name in ("first", "replay"):
        if (evaluation_json_bytes(observation.get(name, {}).get("report")) != evaluation_json_bytes(reports[name])
                or evaluation_json_bytes(observation[name].get("counts")) != evaluation_json_bytes(counts[name])):
            raise ValueError("evaluation worker observations disagree with original streams")
    result = reports["first"]["response"].get("result", {})
    measurement = observation["first"].get("measurement", {})
    if (reports["first"]["response"].get("status") != "completed"
            or measurement.get("planned_workload_complete") is not True
            or measurement.get("universal_equivalence_or_native_refinement_proved") is not False
            or result.get("planned_workload_complete") is not True or result.get("adopted") is not False
            or result.get("outcome") != measurement.get("outcome")
            or result.get("measurements", {}).get("sha256")
                != hashlib.sha256(evaluation_json_bytes(measurement)).hexdigest()
            or any(evaluation_json_bytes(measurement.get("native_runs", {}).get(label, {}).get("normal"))
                   != evaluation_json_bytes(counts["first"]["native_results"][index])
                   for index, label in enumerate(("baseline", "candidate")))):
        raise ValueError("evaluation measurement is not bound to actual native worker results")
    for key in ("measurements", "evaluation_receipt", "full_cost_ledger"):
        ref = result.get(key, {})
        if (type(ref.get("id")) is not str or not ref["id"]
                or type(ref.get("uri")) is not str or not ref["uri"].startswith("hia://artifacts/")
                or type(ref.get("sha256")) is not str or re.fullmatch(r"[0-9a-f]{64}", ref["sha256"]) is None):
            raise ValueError("evaluation worker artifact reference differs")
    budgets = evaluation_worker_loss(observation, reports, counts, logs)
    return {**installation, "worker_identity_derived_from_actual_wheel": worker_sha,
            "native_counts_from_original_stderr": counts, "retained_unknown_budget_rows": budgets,
            "measurement_body_matches_actual_artifact_reference": True,
            "other_artifact_bodies_or_request_bytes_retained": False,
            "normal_worker_and_replay_reports_identical": True,
            "unknown_replays_execute_no_native_operation": True,
            "unknown_budget_equality_after_replay_owned_by_original_full_test": True,
            "unknown_budget_after_rows_separately_retained": False,
            "process_exit_73_and_ACK_exit_1_owned_by_original_full_test": True,
            "loss_process_returncodes_separately_serialized": False,
            "source_drift_exit_code_recorded_by_original_test": observation["installed_source_drift"]["worker_exit_code"],
            "retained_body_poison_scope": "actual installed worker process; descendant poisoning is not observed",
            "native_observation_scope": "actual installed evaluation image and original runner results",
            "test_bodies_rerun_by_readback": False, "whole_native_delivery_qualified": False}


def require_evaluation_control_observations(directory, pins):
    """Compare retained complete traces, without running either evaluator."""
    from tests.hia_evaluation_scenarios import scenarios
    directory = Path(directory)
    records = release_json(directory / "test_complete_111_original_foreign_effect_traces_and_first_errors/complete-observations.json", pins)
    names = [case.name for case in scenarios()]
    if (len(names) != 111 or len(set(names)) != 111 or type(records) is not list
            or [row.get("case") for row in records] != names
            or any(set(row) != {"case", "expected", "actual"}
                   or evaluation_json_bytes(row["expected"]) != evaluation_json_bytes(row["actual"])
                   for row in records)):
        raise ValueError("evaluation complete original 111 foreign-effect traces differ")
    vm = release_json(directory / "test_actual_native_full_buffers_and_state_match_independent_VM/vm-native-entry-counts.json", pins)
    if (set(vm) != {"continuation", "integer"} or any(type(value) is not int for value in vm.values())
            or vm != {"continuation": 962, "integer": 130}):
        raise ValueError("evaluation original six-case VM/native entry observations differ")
    reference = next(row["expected"] for row in records if row["case"] == "artifact_improved")
    folder = directory / "test_lost_native_run_and_publication_ACK_never_repeat_or_complete"
    expected_names, loss_records = set(), {}
    for port, effect, calls, completed, publications in (
            ("normal_run", "budget_run", 1, False, 0),
            ("normal_report_arithmetic", "budget_run", 1, False, 0),
            ("measurements", "json", 2, True, 1)):
        index = next(index for index, row in enumerate(reference["trace"]) if row["effect"] == effect)
        for failure in ("KeyboardInterrupt", "ValueError", "OSError", "OverflowError"):
            name = port + "-" + failure + ".json"
            expected_names.add(name)
            row = release_json(folder / name, pins)
            error_type = ("builtins.KeyboardInterrupt" if failure == "KeyboardInterrupt"
                          else "hepta.hia_evaluation_native.EvaluationUnknown")
            if (row.get("outcome", {}).get("status") != "raised" or row["outcome"].get("type") != error_type
                    or evaluation_json_bytes(row.get("trace")) != evaluation_json_bytes(reference["trace"][:index + 1])
                    or type(row.get("native_calls")) is not int or row["native_calls"] != calls
                    or row.get("claim_completed") is not completed
                    or evaluation_json_bytes(row.get("published")) != evaluation_json_bytes(reference["published"][:publications])):
                raise ValueError("evaluation lost acknowledgement or arithmetic boundary differs: " + name)
            loss_records[name] = {"exception": error_type, "actual_native_calls": calls,
                                  "claim_completed_before_loss": completed, "publications": publications}
    if {path.name for path in folder.glob("*.json")} != expected_names:
        raise ValueError("evaluation loss matrix lacks the complete twelve controls")
    return {"independent_original_trace_count": 111, "full_trace_payloads_compared": True,
            "original_VM_native_cases": 6, "actual_VM_native_entry_counts": vm,
            "actual_VM_native_entries": sum(vm.values()),
            "full_return_output_and_state_buffer_equality_owned_by_original_full_test": True,
            "raw_VM_return_output_and_state_buffers_separately_retained": False,
            "lost_observation_controls": loss_records,
            "nonrepeat_after_loss_owned_by_original_full_test": True,
            "test_bodies_rerun_by_readback": False, "all_input_equivalence_proved": False}


def evaluation_composition_observations(directory, expected_scope, pins):
    report = release_json(Path(directory) / "composition.json", pins)
    selectors = {"HEPTA_HIA_" + name + "_MANIFEST" for name in (
        "STORE_LIFECYCLE", "SERVICE_CONTEXT", "EXECUTION_BUDGET", "CANDIDATE_BUDGET", "COST_LEDGER", "EVALUATION")}
    counts = report.get("actual_native_entries", {})
    before, after, delta = (report.get(key, {}) for key in (
        "entries_before_replay", "entries_after_replay", "replay_additional_entries"))
    if (report.get("schema") != "hepta.hia.evaluation-six-owner-composition.v1"
            or report.get("scope") != expected_scope or report.get("original_context_wall_ms") != 3000
            or report.get("original_native_wall_ms") != 1000
            or any(type(row) is not dict or set(row) != selectors for row in (counts, before, after, delta))
            or any(type(value) is not int or value <= 0 for row in (counts, before, after) for value in row.values())
            or any(type(value) is not int or value != 0 for value in delta.values())
            or before != after or any(counts[key] < after[key] for key in selectors)
            or report.get("durable_changes_on_replay") != 0 or type(report.get("durable_changes_on_replay")) is not int
            or report.get("reference_calls") != []
            or any(report.get(key) is not True for key in (
                "all_six_retained_policy_references_forbidden",
                "hosted_request_journal_sqlite_runner_and_object_protocols_retained",
                "source_and_compiler_custody_owned_by_outer_component"))
            or report.get("whole_native_delivery_qualified") is not False):
        raise ValueError("evaluation six-owner composition or exact native replay differs")
    first = report.get("first_response", {})
    result = first.get("result", {})
    if (first.get("status") != "completed"
            or evaluation_json_bytes(first) != evaluation_json_bytes(report.get("replayed_response"))
            or any(result.get(key) is not True for key in (
                "report_complete", "planned_workload_complete", "termination_confirmed"))
            or result.get("adopted") is not False):
        raise ValueError("evaluation composed public response or replay differs")
    documents = {"measurements": report.get("measurements", {}), "full_cost_ledger": report.get("ledger", {}),
                 "evaluation_receipt": report.get("evaluation_receipt", {})}
    for name, value in documents.items():
        if result.get(name, {}).get("sha256") != hashlib.sha256(evaluation_json_bytes(value)).hexdigest():
            raise ValueError("evaluation composed artifact body differs from its actual reference: " + name)
    measurement, ledger, receipt = (documents[name] for name in ("measurements", "full_cost_ledger", "evaluation_receipt"))
    if (measurement.get("planned_cases") != 1 or len(measurement.get("observations", [])) != 1
            or measurement.get("planned_workload_complete") is not True
            or measurement.get("universal_equivalence_or_native_refinement_proved") is not False
            or ledger.get("full_search_cost_complete") is not False or ledger.get("net_optimization_benefit_proved") is not False
            or ledger.get("context") != measurement.get("context") or receipt.get("context") != ledger.get("context")
            or receipt.get("measurements") != result["measurements"]
            or receipt.get("full_cost_ledger") != result["full_cost_ledger"]):
        raise ValueError("evaluation composed artifact contracts or cross-references differ")
    for arm in ("baseline", "candidate"):
        run = measurement.get("native_runs", {}).get(arm, {}).get("normal", {})
        if run.get("started") is not True or run.get("termination_confirmed") is not True or run.get("status") != "returned":
            raise ValueError("evaluation composed native runner was not actually completed")
    budget = report.get("budget_before_replay", {})
    if (set(budget) != {"context_id", "owner", "used_native_ns"} or budget.get("owner") is not None
            or budget.get("context_id") != ledger.get("context", {}).get("id")
            or type(budget.get("used_native_ns")) is not str or re.fullmatch(r"[1-9][0-9]*", budget["used_native_ns"]) is None
            or budget["used_native_ns"] != ledger.get("native_child_wall_ns")
            or evaluation_json_bytes(budget) != evaluation_json_bytes(report.get("budget_after_replay"))):
        raise ValueError("evaluation composed native budget was not confirmed and preserved on replay")
    return report


def require_evaluation_budget_build(location, label, source_name, root, cold_path, compiler, sources, pins):
    from tools.build_hia_source_build import _check_pack_output, _check_compile_receipt
    location = Path(location)
    manifest_path = location / "manifest.json"
    manifest = release_json(manifest_path, pins)
    build = release_json(location / "build.json", pins)
    request = release_json(location / (label + ".request.json"), pins)
    receipt = release_json(location / (label + ".receipt.json"), pins)
    source, artifact = release_bytes(root / source_name, pins), release_bytes(compiler, pins)
    image_path = location / (label + ".image.bin")
    image, output = release_bytes(image_path, pins), release_bytes(location / (label + ".output.bin"), pins)
    if (build.get("schema") != "hepta.hia." + label + "-build.v1"
            or build.get("status") != "NATIVE_CANDIDATE_BUILT"
            or build.get("source_manifest") != sources or build.get("cold_report_sha256") != sha(cold_path)
            or build.get("manifest") != manifest or build.get("native_compile_receipt") != receipt
            or manifest.get("schema") != "hepta.hia." + label + "-native.v1"
            or manifest.get("compiler_sha256") != hashlib.sha256(artifact).hexdigest()
            or manifest.get("source_sha256") != sources[source_name]
            or manifest.get("image_path") != image_path.name
            or manifest.get("image_sha256") != hashlib.sha256(image).hexdigest()
            or receipt.get("produced_image") != str(image_path)
            or release_bytes(location / (label + ".input.bin"), pins) != source
            or request != {"capacity": 1048576, "format": "flat-x86-64", "image": str(compiler),
                "image_sha256": hashlib.sha256(artifact).hexdigest(), "output": str(location / (label + ".output.bin")),
                "source": str(location / (label + ".input.bin")), "source_sha256": sources[source_name],
                "workspace_fill": 0, "workspace_size": 1048576}
            or _check_pack_output(receipt, output, artifact=artifact, source=source) != image):
        raise ValueError("evaluation composed budget lacks the same-cold original compiler transport")
    _check_compile_receipt(receipt, compiler=artifact, source=source, produced=image)
    return manifest_path


def evaluation_composition_bundle(composition, report, manifests, pins):
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    composition = Path(composition)
    bundle_path = composition / "bundle.json"
    bundle = release_json(bundle_path, pins)
    expected = {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
        "selector": selector, "manifest_path": str(path.resolve()),
        "manifest_sha256": hashlib.sha256(release_bytes(path, pins)).hexdigest()}
        for selector, path in sorted(manifests.items())]}
    if (bundle != expected or report.get("bundle") != str(bundle_path)
            or report.get("bundle_sha256") != pins[str(bundle_path)]
            or report.get("manifests") != {selector: str(path) for selector, path in manifests.items()}):
        raise ValueError("evaluation six-owner composition bundle differs from its actual builds")
    return pins[str(bundle_path)]


def require_evaluation_composition(directory, root, cold_path, compiler, sources, pins):
    from tools.build_hia_store_lifecycle import INPUTS as STORE_INPUTS
    from tools.build_hia_service_context import INPUTS as CONTEXT_INPUTS
    from tools.build_hia_cost_ledger import INPUTS as LEDGER_INPUTS
    directory = Path(directory)
    composition = directory / "test_six_owner_public_evaluation_and_exact_replay_forbid_all_retained_policies/six-owner-composition"
    report = evaluation_composition_observations(composition, "MATCHING_SOURCE_COLD_COMPONENT", pins)
    manifests = {"HEPTA_HIA_EVALUATION_MANIFEST": directory / "built/manifest.json"}
    for selector, label, source_name, inputs in (
            ("STORE_LIFECYCLE", "store-lifecycle", "store_lifecycle", STORE_INPUTS),
            ("SERVICE_CONTEXT", "service-context", "service_context", CONTEXT_INPUTS),
            ("COST_LEDGER", "cost-ledger", "cost_ledger", LEDGER_INPUTS)):
        manifest_path = composition / label / "manifest.json"
        source_name = "examples/hia_bootstrap/" + source_name + ".hepta"
        require_cold_component(manifest_path, source_name, sha(cold_path), sha(compiler), sources, pins)
        require_release_compilation(manifest_path.parent, label, source_name, inputs, root, compiler, sources, pins)
        manifests["HEPTA_HIA_" + selector + "_MANIFEST"] = manifest_path
    for selector, label, source_name in (
            ("EXECUTION_BUDGET", "execution-budget", "execution_budget"),
            ("CANDIDATE_BUDGET", "candidate-budget", "candidate_budget")):
        manifests["HEPTA_HIA_" + selector + "_MANIFEST"] = require_evaluation_budget_build(
            composition / label, label, "examples/hia_bootstrap/" + source_name + ".hepta",
            root, cold_path, compiler, sources, pins)
    bundle_sha = evaluation_composition_bundle(composition, report, manifests, pins)
    return {"bundle_sha256": bundle_sha, "manifests": report["manifests"],
            "actual_native_entries": report["actual_native_entries"], "replay_additional_entries": report["replay_additional_entries"],
            "actual_artifact_bodies_bound_to_response": True, "native_budget_before_after_retained_and_equal": True,
            "native_observation_scope": "test-process fixture construction, public evaluation and cleanup across six admitted images",
            "all_original_context_and_native_budgets_preserved": True, "whole_native_delivery_qualified": False,
            "test_bodies_rerun_by_readback": False}


def require_evaluation_component(directory, root, cold_path, compiler, sources, pins):
    from tools.build_hia_evaluation import INPUTS, SOURCE_NAME
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    require_cold_component(manifest_path, SOURCE_NAME, sha(cold_path), sha(compiler), sources, pins)
    manifest = require_release_compilation(directory / "built", "evaluation", SOURCE_NAME,
                                          INPUTS, root, compiler, sources, pins)
    build = release_json(directory / "built/build.json", pins)
    custody = release_json(directory / "component-custody.json", pins)
    if (manifest.get("schema") != "hepta.hia.evaluation-native.v1"
            or build.get("schema") != "hepta.hia.evaluation-build.v1"
            or any(build.get(key) is not True for key in (
                "evaluation_control_branches_and_ordered_effects_owned_by_hia", "exact_integer_arithmetic_owned_by_hia",
                "binary64_true_division_and_comparison_hosted", "foreign_object_protocols_and_providers_hosted"))
            or any(build.get(key) is not False for key in (
                "retained_evaluation_body_invoked", "whole_stack_rewritten_in_hia", "all_input_equivalence_proved"))
            or custody.get("schema") != "hepta.hia.evaluation-test-custody.v1"
            or custody.get("manifest") != str(manifest_path) or custody.get("matching_cold_report") != str(cold_path)
            or custody.get("compiler_sha256") != sha(compiler) or custody.get("compiler_unchanged") is not True
            or custody.get("source_manifest_before") != sources or custody.get("source_manifest_after") != sources
            or custody.get("source_and_compiler_unchanged") is not True
            or custody.get("test_result_owned_by_outer_runner") is not True
            or custody.get("foreign_object_protocols_providers_and_binary64_hosted") is not True
            or custody.get("all_input_equivalence_proved") is not False
            or custody.get("whole_native_delivery_qualified") is not False):
        raise ValueError("evaluation first-full source/compiler custody or boundary declaration differs")
    controls = require_evaluation_control_observations(directory, pins)
    installation = require_evaluation_installation(directory, root, sources, manifest, pins)
    composition = require_evaluation_composition(directory, root, cold_path, compiler, sources, pins)
    return {"scope": "MATCHING_SOURCE_COLD_COMPONENT", "manifest": str(manifest_path),
            "image_sha256": manifest["image_sha256"], "controls": controls, "installation": installation,
            "six_owner_composition": composition,
            "source_and_compiler_custody_verified": True, "test_result_owned_by_original_full_runner": True,
            "test_bodies_rerun_by_supplement": False, "whole_native_delivery_qualified": False, "passed": True}


def evaluation_original_inventory(root, sources, discovery, pins):
    from tools.qualify_hia_evaluation_callers import FIXTURE_NAME, FIXTURE_SHA256, admit_original_sources
    fixture_path = root / FIXTURE_NAME
    original = release_json(fixture_path, pins)
    modules = original.get("ordinary_modules", [])
    inventory = original.get("modules", {})
    separate = original.get("explicit_scope_modules", [])
    if (pins[str(fixture_path)] != FIXTURE_SHA256 or sources.get(FIXTURE_NAME) != FIXTURE_SHA256
            or original.get("schema") != "hepta.hia.evaluation-original-callers-review.v1"
            or original.get("base_commit") != "19065d2f97c92d3cf28a4de1fe7387c2d5c66a02"
            or len(modules) != 7 or len(set(modules)) != 7 or len(separate) != 5 or len(set(separate)) != 5
            or set(modules) & set(separate) or set(inventory) != set(modules) | set(separate)
            or original.get("ordinary_count") != 81 or len(original.get("ordinary_ordered_ids", [])) != 81
            or original.get("all_original_tests") != 183 or len(original.get("all_original_ordered_ids", [])) != 183
            or original.get("whole_project_dynamic_caller_closure_claimed") is not False):
        raise ValueError("evaluation frozen complete 183-method inventory differs")
    original_files = {row["path"]: row["sha256"] for row in inventory.values()}
    adjustments = admit_original_sources(root, original_files)
    for module, row in inventory.items():
        observed = [item["id"] for item in discovery["test_descriptions"] if item["id"].startswith(module + ".")]
        if (row.get("path") != module.replace(".", "/") + ".py" or row.get("count") != len(observed)
                or observed != row.get("ordered_ids")):
            raise ValueError("evaluation complete original caller module changed: " + module)
    descriptions = [row for module in modules for row in discovery["test_descriptions"]
                    if row["id"].startswith(module + ".")]
    planned = [row["id"] for row in descriptions]
    if planned != original["ordinary_ordered_ids"] or len(planned) != 81 or len(set(planned)) != 81:
        raise ValueError("evaluation original complete 81-method order differs")
    return original, original_files, adjustments, descriptions, planned


def evaluation_event_accounting(report, planned):
    frames, events = report.get("actual_evaluation_frames"), report.get("actual_native_event_counts", {})
    allowed = {"continuation:" + str(event) for event in range(4)} | {"integer:" + str(event) for event in range(1, 9)}
    mandatory = allowed - {"continuation:3"}
    if (type(frames) is not int or frames <= 0 or type(events) is not dict
            or not mandatory <= set(events) <= allowed
            or any(type(value) is not int or value <= 0 for value in events.values())
            or events["continuation:0"] != frames
            or events["continuation:1"] != events["continuation:2"] + events.get("continuation:3", 0)):
        raise ValueError("evaluation actual native frame/event observations differ")
    frame_rows, event_rows = report.get("frames_by_original_test", {}), report.get("native_event_counts_by_original_test", {})
    totals = {}
    if (type(frame_rows) is not dict or not set(frame_rows) <= set(planned)
            or any(type(value) is not int or value <= 0 for value in frame_rows.values())
            or sum(frame_rows.values()) != frames or type(event_rows) is not dict
            or not set(event_rows) <= set(planned)):
        raise ValueError("evaluation native frames lack original caller identities")
    for identity, row in event_rows.items():
        if (type(row) is not dict or not set(row) <= allowed
                or any(type(value) is not int or value <= 0 for value in row.values())
                or row.get("continuation:0", 0) != frame_rows.get(identity, 0)
                or row.get("continuation:1", 0) != row.get("continuation:2", 0) + row.get("continuation:3", 0)):
            raise ValueError("evaluation per-method native event accounting differs")
        for key, value in row.items():
            totals[key] = totals.get(key, 0) + value
    if totals != events:
        raise ValueError("evaluation aggregate counts differ from original per-test observations")
    return frames, events


def require_evaluation_caller_observations(directory, root, sources, discovery, manifest_path, pins):
    from tools.qualify_hia_evaluation_callers import FIXTURE_NAME
    from tools.build_hia_evaluation import INPUTS, SOURCE_NAME
    from tools.hia_selfhost_contract import file_digests
    directory, manifest_path = Path(directory), Path(manifest_path)
    manifest = release_json(manifest_path, pins)
    build = release_json(manifest_path.with_name("build.json"), pins)
    report = release_json(directory / "report.json", pins)
    original, original_files, adjustments, descriptions, planned = evaluation_original_inventory(
        root, sources, discovery, pins)
    names = set(file_digests(root)) | {*INPUTS, *original_files, FIXTURE_NAME,
                                      "tools/qualify_hia_evaluation_callers.py"}
    source_pins = {name: hashlib.sha256(release_bytes(root / name, pins)).hexdigest() for name in names}
    bundle_pins = {}
    for path in sorted(manifest_path.parent.rglob("*")):
        if path.is_symlink():
            raise ValueError("evaluation caller build contains a symlink")
        if path.is_file():
            bundle_pins[str(path)] = hashlib.sha256(release_bytes(path, pins)).hexdigest()
    scopes = {"MATCHING_SOURCE_COLD_SEVEN_ORDINARY_EVALUATION_CALLER_MODULES",
              "EXPLICIT_DEVELOPMENT_SEVEN_ORDINARY_EVALUATION_CALLER_MODULES"}
    expected_build_scope = ("MATCHING_SOURCE_COLD_COMPONENT" if report.get("scope", "").startswith("MATCHING_SOURCE_COLD_")
                            else "DEVELOPMENT_COMPONENT")
    if (report.get("schema") != "hepta.hia.evaluation-seven-ordinary-callers.v1"
            or report.get("status") != "PASS" or report.get("scope") not in scopes
            or build.get("scope") != expected_build_scope
            or report.get("original_baseline_commit") != original["base_commit"]
            or report.get("original_modules") != original["ordinary_modules"]
            or not (report.get("planned") == report.get("started") == report.get("stopped") == planned)
            or type(report.get("actual_tests")) is not int or report["actual_tests"] != 81
            or any(report.get(key) != [] for key in (
                "errors", "failures", "skipped", "expected_failures", "unexpected_successes", "reference_calls"))
            or report.get("retained_evaluation_body_forbidden") is not True
            or report.get("reference_poison_scope") != "test process; subprocesses inherit selector, not Python patches"
            or report.get("all_seven_ordinary_modules_unfiltered") is not True
            or report.get("original_test_budgets_changed") is not False or report.get("source_and_bundle_unchanged") is not True
            or report.get("original_registry_count_assertion_adjustments") != adjustments
            or report.get("separate_original_administrator_scope_gates") != original["explicit_scope_modules"]
            or report.get("whole_project_dynamic_caller_closure_claimed") is not False
            or report.get("whole_native_delivery_qualified") is not False
            or manifest.get("schema") != "hepta.hia.evaluation-native.v1"
            or manifest.get("source_sha256") != sources[SOURCE_NAME]
            or report.get("native_image_sha256") != manifest["image_sha256"]
            or bundle_pins.get(str(manifest_path.parent / manifest["image_path"])) != manifest["image_sha256"]
            or report.get("source_pins") != source_pins or not bundle_pins or report.get("bundle_pins") != bundle_pins
            or any(name in sources and sources[name] != digest for name, digest in source_pins.items())
            or any(name not in sources and name not in original_files for name in source_pins)):
        raise ValueError("evaluation complete 81 caller observations or captured inputs differ")
    frames, events = evaluation_event_accounting(report, planned)
    observed = audit_verbose_stderr(release_bytes(directory / "tests.log", pins),
        {"planned_test_ids": planned, "test_descriptions": descriptions})
    if observed["equivalent"] is not True:
        raise ValueError("evaluation original verbose log lacks all 81 successful methods in order")
    return {"actual_tests": 81, "actual_evaluation_frames": frames, "actual_native_event_counts": events,
            "actual_control_entries": sum(value for key, value in events.items() if key.startswith("continuation:")),
            "actual_integer_entries": sum(value for key, value in events.items() if key.startswith("integer:")),
            "source_pin_count": len(source_pins), "bundle_pin_count": len(bundle_pins),
            "original_verbose_identity": observed, "complete_original_inventory_count": 183,
            "original_registry_count_assertion_adjustments": adjustments,
            "separate_administrator_scope_inventory_modules": original["explicit_scope_modules"],
            "reference_poison_scope": report["reference_poison_scope"], "observed_report_scope": report["scope"],
            "original_test_budgets_changed": False, "whole_project_dynamic_caller_closure_claimed": False,
            "test_bodies_rerun_by_readback": False, "whole_native_delivery_qualified": False}


def native_transport_custody_observations(directory, root, cold_path, compiler, sources, pins):
    """Read real source/build custody; cold admission remains a separate required gate."""
    from tools.build_hia_store_lifecycle import INPUTS as STORE_INPUTS
    from tools.build_hia_service_context import INPUTS as CONTEXT_INPUTS
    from tools.build_hia_cost_ledger import INPUTS as LEDGER_INPUTS
    from tools.hia_selfhost_contract import file_digests
    directory = Path(directory)
    expected_cold = None if cold_path is None else str(cold_path)
    scope = "DEVELOPMENT_COMPONENT" if cold_path is None else "MATCHING_SOURCE_COLD_COMPONENT"
    compiler_sha = hashlib.sha256(release_bytes(compiler, pins)).hexdigest()
    custody = release_json(directory / "component-custody.json", pins)
    names = set(file_digests(root)) | {"tests/test_hia_native_transport_failures.py"}
    expected_sources = {name: hashlib.sha256(release_bytes(root / name, pins)).hexdigest() for name in names}
    manifests, build_files = {}, {}
    for name, label, source_name, inputs in (
            ("context", "service-context", "service_context", CONTEXT_INPUTS),
            ("ledger", "cost-ledger", "cost_ledger", LEDGER_INPUTS),
            ("store", "store-lifecycle", "store_lifecycle", STORE_INPUTS)):
        manifest_path = directory / name / "manifest.json"
        source_name = "examples/hia_bootstrap/" + source_name + ".hepta"
        manifest = require_release_compilation(manifest_path.parent, label, source_name, inputs, root, compiler, sources, pins)
        build = release_json(manifest_path.with_name("build.json"), pins)
        image = release_bytes(manifest_path.parent / (label + ".image.bin"), pins)
        if (build.get("scope") != scope or build.get("manifest") != manifest
                or build.get("cold_report_sha256") != (None if cold_path is None else sha(cold_path))
                or build.get("source_manifest") != (None if cold_path is None else sources)
                or manifest.get("compiler_sha256") != compiler_sha
                or manifest.get("source_sha256") != sources[source_name]
                or manifest.get("image_sha256") != hashlib.sha256(image).hexdigest()):
            raise ValueError("native transport actual build scope or image differs")
        manifests[name] = str(manifest_path)
        for path in sorted(manifest_path.parent.rglob("*")):
            if path.is_symlink():
                raise ValueError("native transport captured build contains a symlink")
            if path.is_file():
                build_files[str(path)] = hashlib.sha256(release_bytes(path, pins)).hexdigest()
    if (custody.get("schema") != "hepta.hia.native-transport-test-custody.v1"
            or custody.get("matching_cold_report") != expected_cold
            or custody.get("compiler_sha256") != compiler_sha or custody.get("manifests") != manifests
            or custody.get("source_before") != expected_sources or custody.get("source_after") != expected_sources
            or any(sources.get(name) != digest for name, digest in expected_sources.items())
            or custody.get("build_files") != build_files or not build_files
            or custody.get("source_compiler_and_build_unchanged") is not True
            or custody.get("test_result_owned_by_outer_runner") is not True
            or custody.get("whole_native_delivery_qualified") is not False):
        raise ValueError("native transport source/compiler/three-build custody differs")
    return {"scope": scope, "manifests": manifests,
            "source_pin_count": len(expected_sources), "build_pin_count": len(build_files),
            "source_compiler_and_build_custody_verified": True,
            "native_fault_control_results_owned_by_original_full_runner": True,
            "test_bodies_rerun_by_supplement": False, "additional_caller_command": False,
            "whole_native_delivery_qualified": False, "passed": True}


def require_native_transport_component(directory, root, cold_path, compiler, sources, pins):
    directory = Path(directory)
    for name, source_name in (("context", "service_context"), ("ledger", "cost_ledger"),
                              ("store", "store_lifecycle")):
        require_cold_component(directory / name / "manifest.json", "examples/hia_bootstrap/" + source_name + ".hepta",
                               sha(cold_path), sha(compiler), sources, pins)
    return native_transport_custody_observations(directory, root, cold_path, compiler, sources, pins)


def native_build_admission_controls(directory, pins):
    """Read the complete original observations; never execute either policy."""
    from tests.hia_native_build_admission_scenarios import scenarios
    directory = Path(directory)
    cases = [case["name"] for case in scenarios()]
    records = release_json(directory / "test_complete_original_foreign_effect_traces_and_first_errors/complete-observations.json", pins)
    if (len(cases) != 303 or len(set(cases)) != 303 or type(records) is not list
            or [row.get("case") for row in records] != cases):
        raise ValueError("native-build-admission complete original 303-case inventory differs")
    expected = {}
    for row in records:
        if (set(row) != {"case", "expected", "actual"}
                or row["expected"].get("name") != row["case"]
                or evaluation_json_bytes(row["expected"]) != evaluation_json_bytes(row["actual"])):
            raise ValueError("native-build-admission original full trace, alias or exception differs")
        expected[row["case"]] = row["expected"]
    counts = release_json(directory / "test_actual_native_full_buffers_match_independent_VM/vm-native-entry-counts.json", pins)
    if counts != {"continuation": 592} or type(counts.get("continuation")) is not int:
        raise ValueError("native-build-admission original six VM comparisons differ")
    rows = release_json(directory / "test_lost_ACK_native_errors_retain_unknown_and_foreign_errors_confirm/native-and-foreign-exceptions.json", pins)
    errors = ("ValueError", "TypeError", "OSError", "OverflowError", "RecursionError",
              "OperationalError", "MixedRejected", "RuntimeError", "KeyboardInterrupt", "SystemExit")
    ports = (("signatures_scalar", "signature_scalar_publish"), ("native_ordinary", "native_get"),
             ("inputs_ordinary", "build_object_get"))
    if type(rows) is not list or len(rows) != 40:
        raise ValueError("native-build-admission complete 30+10 failure controls are absent")
    for row, (case, port, error) in zip(rows[:30], ((case, port, error) for case, port in ports for error in errors)):
        raised = error if error in ("RuntimeError", "KeyboardInterrupt", "SystemExit") else "NativeBuildAdmissionUnknown"
        events, trace = row.get("events", []), row.get("trace", [])
        if (row.get("case") != case or row.get("port") != port or row.get("injected") != error
                or row.get("raised") != raised
                or row.get("original_exception_or_cause_identity_retained") is not True
                or row.get("unknown_custody_retained") is not True
                or not events or events[0] != 0 or events[-1] != 2
                or any(type(value) is not int or value not in (0, 1, 2) for value in events)
                or not trace or evaluation_json_bytes(trace) != evaluation_json_bytes(expected[case]["trace"][:len(trace)])):
            raise ValueError("native-build-admission lost ACK was confirmed, misclassified or replayed")
    for row, error in zip(rows[30:], errors):
        events = row.get("events", [])
        if (row.get("foreign") != error or row.get("same_exception_object") is not True
                or row.get("confirmed_phase") != 5 or not events or events[0] != 0 or events[-1] != 3
                or any(type(value) is not int or value not in (0, 1, 2, 3) for value in events)):
            raise ValueError("native-build-admission confirmed foreign exception differs")
    return {"original_complete_cases": 303, "canonical_full_trace_and_alias_comparison": True,
            "original_independent_VM_cases": 6, "actual_VM_native_entry_counts": counts,
            "VM_output_and_state_buffer_comparison_owned_by_original_full_test": True,
            "raw_VM_buffers_separately_retained": False, "lost_ACK_cases": 30,
            "confirmed_foreign_exception_cases": 10, "test_bodies_rerun_by_readback": False}


def native_build_admission_wheel(location, sources, observation, pins):
    wheels = sorted((location / "wheels").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("native-build-admission needs the one actual installed wheel")
    wheel = wheels[0]
    files, distribution = release_wheel(wheel, pins)
    source_python = {name for name in sources if name.startswith("hepta/") and name.endswith(".py")}
    if not source_python <= set(files):
        raise ValueError("native-build-admission wheel omitted production Python source")
    for name, raw in files.items():
        if name.startswith("hepta/"):
            source_name = name.removeprefix("hepta/_data/") if name.startswith("hepta/_data/") else name
            if sources.get(source_name) != hashlib.sha256(raw).hexdigest():
                raise ValueError("native-build-admission wheel has unbound production bytes")
        elif not name.startswith(distribution + "/"):
            raise ValueError("native-build-admission wheel has unexpected members")
    installed, actual = location / "installed", {}
    for path in sorted(installed.rglob("*")):
        if path.is_symlink():
            raise ValueError("native-build-admission installed file is a symlink")
        if path.is_file():
            actual[path.relative_to(installed).as_posix()] = release_bytes(path, pins)
    record = distribution + "/RECORD"
    member = "hepta/_data/examples/hia_bootstrap/native_build_admission.hepta"
    extras = {"bin/hia", *(distribution + "/" + name for name in ("INSTALLER", "REQUESTED", "direct_url.json"))}
    if (set(actual) != set(files) | extras or member not in files
            or any(actual.get(name) != raw for name, raw in files.items() if name not in (record, member))
            or actual.get(member) != files[member] + b"\n"):
        raise ValueError("native-build-admission installation differs beyond its exact one-LF control")
    recorded = dict(actual)
    recorded[member] = files[member]
    require_release_record(recorded, record, installed=True)
    origin = json.loads(actual[distribution + "/direct_url.json"])
    drift = observation.get("installed_source_drift", {})
    if (origin.get("url") != wheel.as_uri()
            or origin.get("archive_info", {}).get("hashes", {}).get("sha256") != pins[str(wheel)]
            or observation.get("wheel") != str(wheel) or observation.get("wheel_sha256") != pins[str(wheel)]
            or drift.get("before_sha256") != sources["examples/hia_bootstrap/native_build_admission.hepta"]
            or drift["before_sha256"] != hashlib.sha256(files[member]).hexdigest()
            or drift.get("after_sha256") != hashlib.sha256(actual[member]).hexdigest()):
        raise ValueError("native-build-admission installed wheel origin or source drift differs")
    return files, {"wheel": str(wheel), "wheel_sha256": pins[str(wheel)], "actual_wheel_members": len(files),
        "actual_installed_files": len(actual), "all_other_product_bytes_equal_wheel": True,
        "installed_RECORD_checked_against_exact_pre_drift_bytes": True,
        "only_intentional_installed_mutation": {"member": member, "change": "append exactly one LF",
            "before_sha256": drift["before_sha256"], "after_sha256": drift["after_sha256"]}}


def native_build_admission_counts(raw):
    prefix = b"NATIVE_BUILD_COUNTS="
    found = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    if len(found) != 1:
        raise ValueError("native-build-admission worker has no unique original observation marker")
    counts = json.loads(found[0])
    if (set(counts) != {"frames", "entries", "modes", "object_observations", "unknown_frames"}
            or any(type(counts[key]) is not int or counts[key] < 0
                   for key in ("frames", "entries", "object_observations", "unknown_frames"))
            or type(counts["modes"]) is not dict or not set(counts["modes"]) <= {"1", "2", "3", "4"}
            or any(type(value) is not int or value <= 0 for value in counts["modes"].values())
            or sum(counts["modes"].values()) != counts["frames"]):
        raise ValueError("native-build-admission worker native count shape differs")
    return counts


def native_build_admission_worker_streams(location, worker_sha, catalog_sha, bundle_sha, version, pins):
    names = ("wheel", "install", "first", "replay", "native_ack", "native_ack-replay",
             "process_loss", "process_loss-replay", "changed-installed-source")
    logs = {name: {suffix: release_bytes(location / (name + "." + suffix), pins)
                   for suffix in ("stdout", "stderr")} for name in names}
    counts = {name: native_build_admission_counts(logs[name]["stderr"]) for name in names[2:]}
    zero = {"frames": 0, "entries": 0, "modes": {}, "object_observations": 0, "unknown_frames": 0}
    if (counts["first"] != {"frames": 2, "entries": 458, "modes": {"4": 2}, "object_observations": 2, "unknown_frames": 0}
            or counts["replay"] != {"frames": 1, "entries": 229, "modes": {"4": 1}, "object_observations": 1, "unknown_frames": 0}
            or any(counts[name] != zero for name in ("native_ack-replay", "process_loss-replay", "changed-installed-source"))):
        raise ValueError("native-build-admission ordinary revalidation or unknown replay counts differ")
    for name in ("native_ack", "process_loss"):
        row = counts[name]
        if (row["frames"] != 1 or row["modes"] != {"4": 1} or row["object_observations"] != 1
                or row["unknown_frames"] != 1 or not 0 < row["entries"] < counts["replay"]["entries"]
                or logs[name]["stdout"]):
            raise ValueError("native-build-admission lost worker did not retain the observed unfinished frame")
    if (counts["native_ack"]["entries"] != counts["process_loss"]["entries"] + 1
            or b"ValueError: controlled lost object observation acknowledgement" not in logs["native_ack"]["stderr"]
            or b"NativeBuildAdmissionUnknown" not in logs["native_ack"]["stderr"]
            or logs["changed-installed-source"]["stdout"]):
        raise ValueError("native-build-admission actual lost ACK or source-drift streams differ")
    reports = {name: json.loads(logs[name]["stdout"]) for name in (
        "first", "replay", "native_ack-replay", "process_loss-replay")}
    for report in reports.values():
        if (report.get("schema") != "hia-agent-worker-report-v1" or report.get("tool") != "hia_verify"
                or report.get("complete") is not True or report.get("worker_sha256") != worker_sha
                or report.get("catalog_sha256") != catalog_sha or report.get("native_helpers_sha256") != bundle_sha
                or report.get("profile_sha256") != "a" * 64
                or report.get("response", {}).get("contract_version") != version
                or re.fullmatch(r"[0-9a-f]{64}", str(report.get("request_sha256"))) is None
                or re.fullmatch(r"[0-9a-f]{64}", str(report.get("backend_sha256"))) is None):
            raise ValueError("native-build-admission installed worker identity or request correlation differs")
    if (evaluation_json_bytes(reports["first"]) != evaluation_json_bytes(reports["replay"])
            or len({reports[name]["request_sha256"] for name in ("first", "native_ack-replay", "process_loss-replay")}) != 3
            or len({report["backend_sha256"] for report in reports.values()}) != 1):
        raise ValueError("native-build-admission replay request or worker identities are inconsistent")
    return reports, counts, logs


def native_build_admission_worker_journals(observation, reports, counts):
    for name in ("first", "replay"):
        row = observation.get(name, {})
        if (evaluation_json_bytes(row.get("report")) != evaluation_json_bytes(reports[name])
                or evaluation_json_bytes(row.get("counts")) != evaluation_json_bytes(counts[name])):
            raise ValueError("native-build-admission installed report disagrees with actual streams")
    first = reports["first"].get("response", {})
    checks = first.get("result", {}).get("checks", [])
    if (first.get("status") != "completed" or first.get("result", {}).get("adopted") is not False
            or len(checks) != 1 or checks[0].get("claim") != "encoding_check" or checks[0].get("status") != "proved"
            or checks[0].get("execution_authority_granted") is not False or checks[0].get("global_safety_proved") is not False):
        raise ValueError("native-build-admission original installed verification result differs")
    replay = observation.get("replay", {})
    retained = replay.get("retained_before", {})
    request = retained.get("request", {})
    if (replay.get("read_only_original_verification_revalidation") is not True
            or set(retained) != {"request", "artifacts", "costs"}
            or any(type(retained[name]) is not int or retained[name] <= 0 for name in ("artifacts", "costs"))
            or request.get("tool") != "hia_verify" or request.get("state") != "completed"
            or first.get("request_id") != "r-" + str(request.get("digest"))
            or type(request.get("response")) is not str
            or evaluation_json_bytes(json.loads(request["response"])) != evaluation_json_bytes(first)
            or evaluation_json_bytes(retained) != evaluation_json_bytes(replay.get("retained_after"))):
        raise ValueError("native-build-admission normal replay changed its retained request or row counts")
    journals = {}
    for name, code in (("native_ack", 1), ("process_loss", 73)):
        row = observation.get(name, {})
        report, request = reports[name + "-replay"], row.get("request_before", {})
        if (type(row.get("lost_worker_exit_code")) is not int or row["lost_worker_exit_code"] != code
                or evaluation_json_bytes(row.get("native_counts")) != evaluation_json_bytes(counts[name])
                or evaluation_json_bytes(row.get("replay_counts")) != evaluation_json_bytes(counts[name + "-replay"])
                or evaluation_json_bytes(row.get("replay")) != evaluation_json_bytes(report)
                or report.get("response", {}).get("status") != "rejected"
                or report["response"].get("error", {}).get("code") != "E_HIA_REQUEST_UNKNOWN"
                or request.get("state") != "running" or request.get("response") is not None
                or request.get("tool") != "hia_verify"
                or report["response"].get("request_id") != "r-" + str(request.get("digest"))
                or evaluation_json_bytes(request) != evaluation_json_bytes(row.get("request_after"))):
            raise ValueError("native-build-admission unknown intent was completed or re-executed")
        journals[name] = request
    drift = observation.get("installed_source_drift", {})
    if (type(drift.get("worker_exit_code")) is not int or drift["worker_exit_code"] == 0
            or evaluation_json_bytes(drift.get("native_counts")) != evaluation_json_bytes(counts["changed-installed-source"])):
        raise ValueError("native-build-admission installed source drift did not refuse before native execution")
    return journals


def require_native_build_admission_installation(directory, sources, manifest, pins):
    from hepta import hia_agent_contract as contract
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    directory = Path(directory)
    location = directory / "test_actual_installed_worker_unknown_replay_and_source_pinning"
    observation = release_json(location / "installed-observations.json", pins)
    files, installation = native_build_admission_wheel(location, sources, observation, pins)
    manifest_path = directory / "built/manifest.json"
    manifest_raw = release_bytes(manifest_path, pins)
    image = release_bytes(manifest_path.parent / manifest["image_path"], pins)
    bundle_path = location / "bundle.json"
    bundle = release_json(bundle_path, pins)
    bundle_sha = pins[str(bundle_path)]
    if (json.loads(manifest_raw) != manifest or manifest.get("schema") != "hepta.hia.native-build-admission.v1"
            or manifest.get("source_sha256") != sources["examples/hia_bootstrap/native_build_admission.hepta"]
            or manifest.get("image_sha256") != hashlib.sha256(image).hexdigest()
            or bundle != {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
                "selector": "HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST", "manifest_path": str(manifest_path),
                "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}]}
            or observation.get("bundle_sha256") != bundle_sha
            or any(observation.get(key) is not True for key in (
                "all_four_references_forbidden_in_actual_child", "authoring_imports_forbidden_in_actual_child", "original_worker_used"))
            or observation.get("whole_native_delivery_qualified") is not False):
        raise ValueError("native-build-admission installed bundle or observed child scope differs")
    entries = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()
               if name.startswith("hepta/") and name.endswith(".py") and not name.startswith("hepta/_data/")}
    resources = ["docs/" + name for name in contract.DISCOVERY_FILES]
    for group in ("NATIVE_SOURCE_FILES", "SOURCE_BUILD_FILES", "COMPILER_BUILD_FILES", "PUBLICATION_BUILD_FILES",
                  "BACKEND_BUILD_FILES", "EMITTER_BUILD_FILES", "BYTE_WRAPPER_BUILD_FILES",
                  "MACHINE_OBJECT_BUILD_FILES", "EXECUTION_OBSERVATION_BUILD_FILES", "CONTINUATION_BUILD_FILES"):
        resources.extend(getattr(contract, group))
    for name in resources:
        entries[name] = hashlib.sha256(files["hepta/_data/" + name]).hexdigest()
    worker_sha = hashlib.sha256(evaluation_json_bytes(entries)).hexdigest()
    reports, counts, logs = native_build_admission_worker_streams(location, worker_sha,
        entries["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"], bundle_sha, contract.VERSION, pins)
    journals = native_build_admission_worker_journals(observation, reports, counts)
    return {**installation, "worker_identity_derived_from_actual_wheel": worker_sha,
            "actual_native_counts_from_original_stderr": counts, "retained_unknown_request_rows": journals,
            "normal_replay_performs_original_one_mode4_read_only_revalidation": True,
            "normal_replay_request_row_and_artifact_cost_row_counts_unchanged": True,
            "complete_artifact_and_cost_table_contents_separately_retained": False,
            "unknown_replay_zero_native_entries_and_unchanged_running_intent": True,
            "loss_worker_exit_codes_separately_serialized_by_original_parent": {"native_ack": 1, "process_loss": 73},
            "raw_request_envelopes_or_all_proof_artifact_bodies_retained": False,
            "journal_key_binding_to_original_envelope_owned_by_full_test": True,
            "retained_body_poison_scope": "actual installed worker process; descendant poisoning is not observed",
            "native_observation_scope": "actual installed admission image and completed Store object reads; not execution of the admitted artifact",
            "test_bodies_rerun_by_readback": False, "whole_native_delivery_qualified": False}


def native_build_admission_composition_observations(directory, expected_scope, pins):
    report = release_json(Path(directory) / "composition.json", pins)
    selectors = {"HEPTA_HIA_" + name + "_MANIFEST" for name in (
        "STORE_LIFECYCLE", "SERVICE_CONTEXT", "EXECUTION_BUDGET", "CANDIDATE_BUDGET", "COST_LEDGER", "EVALUATION", "NATIVE_BUILD_ADMISSION")}
    counts = report.get("actual_native_entries", {})
    before, after, delta = (report.get(key, {}) for key in (
        "entries_before_replay", "entries_after_replay", "replay_additional_entries"))
    if (report.get("schema") != "hepta.hia.native-build-admission-seven-owner-composition.v1"
            or report.get("scope") != expected_scope or report.get("original_context_wall_ms") != 3000
            or report.get("original_native_wall_ms") != 1000
            or any(type(row) is not dict or set(row) != selectors for row in (counts, before, after, delta))
            or any(type(value) is not int or value <= 0 for row in (counts, before, after) for value in row.values())
            or any(type(value) is not int or value != 0 for value in delta.values())
            or before != after or any(counts[key] < after[key] for key in selectors)
            or report.get("durable_changes_on_replay") != 0 or type(report.get("durable_changes_on_replay")) is not int
            or report.get("reference_calls") != []
            or any(report.get(key) is not True for key in (
                "all_seven_retained_policy_references_forbidden", "all_four_admission_retained_bodies_forbidden",
                "hosted_request_journal_sqlite_runner_and_object_protocols_retained",
                "source_and_compiler_custody_owned_by_outer_component"))
            or report.get("whole_native_delivery_qualified") is not False):
        raise ValueError("native-build-admission seven-owner composition or exact native replay differs")
    first = report.get("first_response", {})
    result = first.get("result", {})
    adoption = report.get("adoption_response", {})
    if (first.get("status") != "completed"
            or adoption.get("status") != "completed"
            or evaluation_json_bytes(adoption) != evaluation_json_bytes(report.get("adoption_replay"))
            or adoption.get("result", {}).get("active_artifact") != result.get("candidate_artifact")
            or evaluation_json_bytes(first) != evaluation_json_bytes(report.get("replayed_response"))
            or any(result.get(key) is not True for key in (
                "report_complete", "planned_workload_complete", "termination_confirmed"))
            or result.get("adopted") is not False):
        raise ValueError("native-build-admission composed public response or replay differs")
    documents = {"measurements": report.get("measurements", {}), "full_cost_ledger": report.get("ledger", {}),
                 "evaluation_receipt": report.get("evaluation_receipt", {})}
    for name, value in documents.items():
        if result.get(name, {}).get("sha256") != hashlib.sha256(evaluation_json_bytes(value)).hexdigest():
            raise ValueError("native-build-admission composed artifact body differs from its actual reference: " + name)
    measurement, ledger, receipt = (documents[name] for name in ("measurements", "full_cost_ledger", "evaluation_receipt"))
    if (type(measurement.get("planned_cases")) is not int or measurement.get("planned_cases") != 1 or len(measurement.get("observations", [])) != 1
            or measurement.get("planned_workload_complete") is not True
            or measurement.get("universal_equivalence_or_native_refinement_proved") is not False
            or ledger.get("full_search_cost_complete") is not False or ledger.get("net_optimization_benefit_proved") is not False
            or ledger.get("context") != measurement.get("context") or receipt.get("context") != ledger.get("context")
            or receipt.get("candidate_artifact") != result.get("candidate_artifact")
            or receipt.get("measurements") != result["measurements"]
            or receipt.get("full_cost_ledger") != result["full_cost_ledger"]):
        raise ValueError("native-build-admission composed artifact contracts or cross-references differ")
    for arm in ("baseline", "candidate"):
        run = measurement.get("native_runs", {}).get(arm, {}).get("normal", {})
        if run.get("started") is not True or run.get("termination_confirmed") is not True or run.get("status") != "returned":
            raise ValueError("native-build-admission composed native runner was not actually completed")
    budget = report.get("budget_before_replay", {})
    if (set(budget) != {"context_id", "owner", "used_native_ns"} or budget.get("owner") is not None
            or budget.get("context_id") != ledger.get("context", {}).get("id")
            or type(budget.get("used_native_ns")) is not str or re.fullmatch(r"[1-9][0-9]*", budget["used_native_ns"]) is None
            or budget["used_native_ns"] != ledger.get("native_child_wall_ns")
            or evaluation_json_bytes(budget) != evaluation_json_bytes(report.get("budget_after_replay"))):
        raise ValueError("native-build-admission composed native budget was not confirmed and preserved on replay")
    return report


def native_build_admission_bundle(location, report, manifests, pins):
    try:
        return evaluation_composition_bundle(location, report, manifests, pins)
    except ValueError as error:
        raise ValueError("native-build-admission actual seven-owner bundle differs from its manifests") from error


def require_native_build_admission_composition(directory, root, cold_path, compiler, sources, pins):
    from tools.build_hia_store_lifecycle import INPUTS as STORE_INPUTS
    from tools.build_hia_service_context import INPUTS as CONTEXT_INPUTS
    from tools.build_hia_cost_ledger import INPUTS as LEDGER_INPUTS
    from tools.build_hia_evaluation import INPUTS as EVALUATION_INPUTS
    directory = Path(directory)
    composition = directory / "test_seven_owner_public_evaluation_and_exact_replay_forbid_all_retained_policies/seven-owner-composition"
    report = native_build_admission_composition_observations(composition, "MATCHING_SOURCE_COLD_COMPONENT", pins)
    manifests = {"HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST": directory / "built/manifest.json"}
    for selector, label, source_name, inputs in (
            ("STORE_LIFECYCLE", "store-lifecycle", "store_lifecycle", STORE_INPUTS),
            ("SERVICE_CONTEXT", "service-context", "service_context", CONTEXT_INPUTS),
            ("COST_LEDGER", "cost-ledger", "cost_ledger", LEDGER_INPUTS),
            ("EVALUATION", "evaluation", "evaluation", EVALUATION_INPUTS)):
        manifest_path = composition / label / "manifest.json"
        source_name = "examples/hia_bootstrap/" + source_name + ".hepta"
        require_cold_component(manifest_path, source_name, sha(cold_path), sha(compiler), sources, pins)
        require_release_compilation(manifest_path.parent, label, source_name, inputs, root, compiler, sources, pins)
        manifests["HEPTA_HIA_" + selector + "_MANIFEST"] = manifest_path
    for selector, label, source_name in (
            ("EXECUTION_BUDGET", "execution-budget", "execution_budget"),
            ("CANDIDATE_BUDGET", "candidate-budget", "candidate_budget")):
        manifests["HEPTA_HIA_" + selector + "_MANIFEST"] = require_evaluation_budget_build(
            composition / label, label, "examples/hia_bootstrap/" + source_name + ".hepta",
            root, cold_path, compiler, sources, pins)
    bundle_sha = native_build_admission_bundle(composition, report, manifests, pins)
    return {"bundle_sha256": bundle_sha, "manifests": report["manifests"],
            "actual_native_entries": report["actual_native_entries"], "replay_additional_entries": report["replay_additional_entries"],
            "actual_artifact_bodies_bound_to_response": True, "native_budget_before_after_retained_and_equal": True,
            "native_observation_scope": "test-process fixture construction, public emit/verify/evaluate/adopt and cleanup across seven admitted images",
            "all_original_context_and_native_budgets_preserved": True, "whole_native_delivery_qualified": False,
            "evaluation_replay_native_and_SQL_deltas_retained": True,
            "adoption_replay_zero_native_and_SQL_writes_owned_by_original_full_method": True,
            "adoption_replay_native_and_SQL_deltas_separately_serialized": False,
            "test_bodies_rerun_by_readback": False}


def native_build_admission_custody(directory, root, cold_path, compiler, sources, pins):
    from tools.build_hia_native_build_admission import INPUTS, SOURCE_NAME
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    manifest = require_release_compilation(directory / "built", "native_build_admission", SOURCE_NAME,
                                          INPUTS, root, compiler, sources, pins)
    build = release_json(directory / "built/build.json", pins)
    custody = release_json(directory / "component-custody.json", pins)
    scope = "DEVELOPMENT_COMPONENT" if cold_path is None else "MATCHING_SOURCE_COLD_COMPONENT"
    image_sha = hashlib.sha256(release_bytes(manifest_path.parent / manifest["image_path"], pins)).hexdigest()
    if (manifest.get("schema") != "hepta.hia.native-build-admission.v1"
            or manifest.get("source_sha256") != sources[SOURCE_NAME] or manifest.get("compiler_sha256") != sha(compiler)
            or manifest.get("image_sha256") != image_sha or build.get("schema") != "hepta.hia.native-build-admission-build.v1"
            or build.get("scope") != scope or build.get("manifest") != manifest
            or build.get("source_manifest") != (None if cold_path is None else sources)
            or build.get("cold_report_sha256") != (None if cold_path is None else sha(cold_path))
            or any(build.get(key) is not True for key in (
                "control_branches_and_ordered_effects_owned_by_hia", "four_complete_original_acceptance_policies_owned_by_hia",
                "core_abi_store_hash_providers_hosted", "foreign_object_protocols_and_providers_hosted"))
            or any(build.get(key) is not False for key in (
                "retained_four_bodies_invoked", "whole_stack_rewritten_in_hia", "all_input_equivalence_proved"))
            or custody.get("schema") != "hepta.hia.native-build-admission-test-custody.v1"
            or custody.get("manifest") != str(manifest_path)
            or custody.get("matching_cold_report") != (None if cold_path is None else str(cold_path))
            or custody.get("compiler_sha256") != sha(compiler) or custody.get("compiler_unchanged") is not True
            or custody.get("source_manifest_before") != sources or custody.get("source_manifest_after") != sources
            or custody.get("source_and_compiler_unchanged") is not True
            or custody.get("test_result_owned_by_outer_runner") is not True
            or custody.get("foreign_object_protocols_and_Core_ABI_Store_hash_providers_hosted") is not True
            or custody.get("all_input_equivalence_proved") is not False or custody.get("whole_native_delivery_qualified") is not False):
        raise ValueError("native-build-admission first-full build or source/compiler custody differs")
    return manifest


def require_native_build_admission_component(directory, root, cold_path, compiler, sources, pins):
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    require_cold_component(manifest_path, "examples/hia_bootstrap/native_build_admission.hepta",
                           sha(cold_path), sha(compiler), sources, pins)
    manifest = native_build_admission_custody(directory, root, cold_path, compiler, sources, pins)
    return {"scope": "MATCHING_SOURCE_COLD_COMPONENT", "manifest": str(manifest_path),
            "image_sha256": manifest["image_sha256"],
            "controls": native_build_admission_controls(directory, pins),
            "installation": require_native_build_admission_installation(directory, sources, manifest, pins),
            "seven_owner_composition": require_native_build_admission_composition(directory, root, cold_path, compiler, sources, pins),
            "source_and_compiler_custody_verified": True, "test_result_owned_by_original_full_runner": True,
            "test_bodies_rerun_by_supplement": False, "whole_native_delivery_qualified": False, "passed": True}


def native_build_admission_original_inventory(root, sources, discovery, pins):
    from tools.qualify_hia_native_build_admission_callers import FIXTURE_NAME, FIXTURE_SHA256, admit_original_sources
    fixture_path = root / FIXTURE_NAME
    original = release_json(fixture_path, pins)
    modules = original.get("ordinary_modules", [])
    inventory = original.get("modules", {})
    separate = original.get("separate_scope_modules", [])
    if (FIXTURE_SHA256 != "262c3df1e051fe52797c91dd053f2d79c0704fe5b20a85f799d6d40c1c4bb2a9"
            or pins[str(fixture_path)] != FIXTURE_SHA256 or sources.get(FIXTURE_NAME) != FIXTURE_SHA256
            or original.get("schema") != "hepta.hia.native-build-admission-original-callers-review.v1"
            or original.get("base_commit") != "aac7550ee2e5d5c3d0e42567ee35e2acfa28f759"
            or original.get("base_tree") != "33f0f17090a42da252f053d7bcc241185181952d"
            or len(modules) != 9 or len(set(modules)) != 9 or len(separate) != 8 or len(set(separate)) != 8
            or set(modules) & set(separate) or set(inventory) != set(modules) | set(separate)
            or original.get("ordinary_count") != 112 or len(original.get("ordinary_ordered_ids", [])) != 112
            or original.get("all_original_tests") != 240 or original.get("separate_scope_count") != 128
            or original.get("whole_project_dynamic_caller_closure_claimed") is not False):
        raise ValueError("native-build-admission frozen complete 240-method inventory differs")
    all_ids = [identity for module in (*modules, *separate) for identity in inventory[module]["ordered_ids"]]
    if (len(all_ids) != 240 or len(set(all_ids)) != 240
            or sum(inventory[module]["count"] for module in separate) != 128):
        raise ValueError("native-build-admission complete separate caller inventory differs")
    original_files = {row["path"]: row["sha256"] for row in inventory.values()}
    adjustments = admit_original_sources(root, original_files)
    for module, row in inventory.items():
        observed = [item["id"] for item in discovery["test_descriptions"] if item["id"].startswith(module + ".")]
        if (row.get("path") != module.replace(".", "/") + ".py" or row.get("count") != len(observed)
                or observed != row.get("ordered_ids")):
            raise ValueError("native-build-admission complete original caller module changed: " + module)
    descriptions = [row for module in modules for row in discovery["test_descriptions"]
                    if row["id"].startswith(module + ".")]
    planned = [row["id"] for row in descriptions]
    if planned != original["ordinary_ordered_ids"] or len(planned) != 112 or len(set(planned)) != 112:
        raise ValueError("native-build-admission original complete 112-method order differs")
    return original, original_files, adjustments, descriptions, planned



def native_build_admission_event_accounting(report, planned):
    frames = report.get("actual_native_build_admission_frames")
    events = report.get("actual_native_event_counts", {})
    modes = report.get("frames_by_mode", {})
    allowed = {"continuation:" + str(event) for event in range(4)}
    mandatory = allowed - {"continuation:3"}
    if (type(frames) is not int or frames <= 0 or type(events) is not dict
            or not mandatory <= set(events) <= allowed
            or any(type(value) is not int or value <= 0 for value in events.values())
            or events["continuation:0"] != frames
            or events["continuation:1"] != events["continuation:2"] + events.get("continuation:3", 0)
            or type(modes) is not dict or set(modes) != {"1", "2", "3", "4"}
            or any(type(value) is not int or value <= 0 for value in modes.values())
            or sum(modes.values()) != frames):
        raise ValueError("native-build-admission actual frame, mode or native event observations differ")
    frame_rows = report.get("frames_by_original_test", {})
    event_rows = report.get("native_event_counts_by_original_test", {})
    if (type(frame_rows) is not dict or not set(frame_rows) <= set(planned)
            or any(type(value) is not int or value <= 0 for value in frame_rows.values())
            or sum(frame_rows.values()) != frames or type(event_rows) is not dict
            or set(event_rows) != set(frame_rows)):
        raise ValueError("native-build-admission frame counts lack original caller identities")
    totals = {}
    for identity, row in event_rows.items():
        if (type(row) is not dict or not set(row) <= allowed
                or any(type(value) is not int or value <= 0 for value in row.values())
                or row.get("continuation:0", 0) != frame_rows[identity]
                or row.get("continuation:1", 0) != row.get("continuation:2", 0) + row.get("continuation:3", 0)):
            raise ValueError("native-build-admission per-method native event accounting differs")
        for key, value in row.items():
            totals[key] = totals.get(key, 0) + value
    if totals != events:
        raise ValueError("native-build-admission aggregate entries differ from per-test observations")
    return frames, events


def require_native_build_admission_callers(directory, root, sources, discovery, manifest_path, pins):
    from tools.qualify_hia_native_build_admission_callers import FIXTURE_NAME
    from tools.build_hia_native_build_admission import INPUTS, SOURCE_NAME
    from tools.hia_selfhost_contract import file_digests
    directory, manifest_path = Path(directory), Path(manifest_path)
    manifest = release_json(manifest_path, pins)
    build = release_json(manifest_path.with_name("build.json"), pins)
    report = release_json(directory / "report.json", pins)
    original, original_files, adjustments, descriptions, planned = native_build_admission_original_inventory(
        root, sources, discovery, pins)
    names = set(file_digests(root)) | {*INPUTS, *original_files, FIXTURE_NAME,
                                      "tools/qualify_hia_native_build_admission_callers.py"}
    source_pins = {name: hashlib.sha256(release_bytes(root / name, pins)).hexdigest() for name in names}
    bundle_pins = {}
    for path in sorted(manifest_path.parent.rglob("*")):
        if path.is_symlink():
            raise ValueError("native-build-admission caller build contains a symlink")
        if path.is_file():
            bundle_pins[str(path)] = hashlib.sha256(release_bytes(path, pins)).hexdigest()
    scopes = {"MATCHING_SOURCE_COLD_NINE_ORDINARY_NATIVE_BUILD_ADMISSION_CALLER_MODULES",
              "EXPLICIT_DEVELOPMENT_NINE_ORDINARY_NATIVE_BUILD_ADMISSION_CALLER_MODULES"}
    expected_build_scope = ("MATCHING_SOURCE_COLD_COMPONENT" if report.get("scope", "").startswith("MATCHING_SOURCE_COLD_")
                            else "DEVELOPMENT_COMPONENT")
    if (report.get("schema") != "hepta.hia.native-build-admission-nine-ordinary-callers.v1"
            or report.get("status") != "PASS" or report.get("scope") not in scopes
            or build.get("scope") != expected_build_scope
            or report.get("original_baseline_commit") != original["base_commit"]
            or report.get("original_modules") != original["ordinary_modules"]
            or not (report.get("planned") == report.get("started") == report.get("stopped") == planned)
            or type(report.get("actual_tests")) is not int or report["actual_tests"] != 112
            or any(report.get(key) != [] for key in (
                "errors", "failures", "skipped", "expected_failures", "unexpected_successes", "reference_calls"))
            or report.get("all_four_retained_bodies_forbidden") is not True
            or report.get("reference_poison_scope") != "test process; subprocesses inherit selector, not Python patches"
            or report.get("all_nine_ordinary_modules_unfiltered") is not True
            or report.get("original_test_budgets_changed") is not False or report.get("source_and_bundle_unchanged") is not True
            or report.get("original_registry_count_assertion_adjustments") != adjustments
            or report.get("separate_original_administrator_scope_gates") != original["separate_scope_modules"]
            or report.get("whole_project_dynamic_caller_closure_claimed") is not False
            or report.get("whole_native_delivery_qualified") is not False
            or manifest.get("schema") != "hepta.hia.native-build-admission.v1"
            or manifest.get("source_sha256") != sources[SOURCE_NAME]
            or report.get("native_image_sha256") != manifest["image_sha256"]
            or bundle_pins.get(str(manifest_path.parent / manifest["image_path"])) != manifest["image_sha256"]
            or report.get("source_pins") != source_pins or not bundle_pins or report.get("bundle_pins") != bundle_pins
            or any(name in sources and sources[name] != digest for name, digest in source_pins.items())
            or any(name not in sources and name not in original_files for name in source_pins)):
        raise ValueError("native-build-admission complete 112 caller observations or captured inputs differ")
    frames, events = native_build_admission_event_accounting(report, planned)
    observed = audit_verbose_stderr(release_bytes(directory / "tests.log", pins),
        {"planned_test_ids": planned, "test_descriptions": descriptions})
    if observed["equivalent"] is not True:
        raise ValueError("native-build-admission original verbose log lacks all 112 successful methods in order")
    return {"actual_tests": 112, "actual_native_build_admission_frames": frames, "actual_native_event_counts": events,
            "actual_control_entries": sum(value for key, value in events.items() if key.startswith("continuation:")),
            "frames_by_mode": report["frames_by_mode"],
            "source_pin_count": len(source_pins), "bundle_pin_count": len(bundle_pins),
            "original_verbose_identity": observed, "complete_original_inventory_count": 240,
            "original_registry_count_assertion_adjustments": adjustments,
            "separate_administrator_scope_inventory_modules": original["separate_scope_modules"],
            "reference_poison_scope": report["reference_poison_scope"], "observed_report_scope": report["scope"],
            "original_test_budgets_changed": False, "whole_project_dynamic_caller_closure_claimed": False,
            "test_bodies_rerun_by_readback": False, "whole_native_delivery_qualified": False}



def require_discovery_fixture(path, cold_path, cold_sha, compiler_sha, sources, pins):
    """Use the product's original strict fixture admission, bound to this run."""
    from tools.qualify_hia_cli_discovery_json import admit_fixture
    fixture = read_pinned_json(path, pins)
    if admit_fixture(path) != fixture:
        raise ValueError("discovery fixture changed during independent readback")
    authority = fixture["authority"]
    if (authority.get("cold_report") != str(cold_path.resolve(strict=True))
            or authority.get("cold_report_sha256") != cold_sha
            or authority.get("compiler_sha256") != compiler_sha
            or authority.get("source_manifest") != sources):
        raise ValueError("discovery fixture belongs to another cold execution")
    for row in [*authority["input_bindings"], *fixture["build"]["input_bindings"]]:
        path = str(Path(row["path"]).resolve(strict=True))
        digest = sha(path)
        if digest != row["sha256"] or (path in pins and pins[path] != digest):
            raise ValueError("discovery input differs from its original binding")
        pins[path] = digest
    return fixture


def require_discovery_cli_companion(directory, authority, root, pins):
    """Read actual CLI control/format compilation under the same cold compiler."""
    from tools.build_hia_cli_native import SOURCES, owner_sources
    from tools.hia_cli_discovery_custody import admit_compilation
    directory = Path(directory)
    bundle = read_pinned_json(directory / "manifest.json", pins)
    build = read_pinned_json(directory / "build.json", pins)
    if (build.get("scope") != "MATCHING_SOURCE_COLD_BUILD"
            or build.get("cold_report_sha256") != authority["cold_report_sha256"]
            or build.get("compiler_sha256") != authority["compiler_sha256"]
            or build.get("source_manifest") != authority["source_manifest"]
            or build.get("owner_sources_before") != owner_sources()
            or build.get("owner_sources_after") != owner_sources()
            or build.get("bundle") != bundle or set(build.get("children", {})) != set(SOURCES)):
        raise ValueError("CLI companion does not bind this same cold execution")
    for name, source_name in SOURCES.items():
        manifest_path = directory / name / "manifest.json"
        manifest = read_pinned_json(manifest_path, pins)
        if (bundle.get(name + "_manifest") != name + "/manifest.json"
                or bundle.get(name + "_manifest_sha256") != sha(manifest_path)
                or manifest.get("compiler_sha256") != authority["compiler_sha256"]
                or manifest.get("source_sha256") != authority["source_manifest"][source_name]):
            raise ValueError("CLI companion child/source identity differs")
        image = directory / name / ("cli-" + name + ".image.bin")
        if manifest.get("image_path") != image.name or manifest.get("image_sha256") != sha(image):
            raise ValueError("CLI companion executable identity differs")
        receipt, observations = admit_compilation(directory / name, "cli-" + name,
            authority["compiler"], (root / source_name).read_bytes(), image)
        if build["children"][name] != {"manifest": manifest, "native_compile_receipt": receipt}:
            raise ValueError("CLI companion receipt differs from actual compiler output")
        for row in observations:
            if row["path"] in pins and pins[row["path"]] != row["sha256"]:
                raise ValueError("CLI companion input changed after its earlier admission")
            pins[row["path"]] = row["sha256"]
        pins[str(image.resolve())] = sha(image)
    return str(directory / "manifest.json")


def supplemental(args):
    """Run additional caller gates and original bounded CLI qualification."""
    require_native_runner()
    target = load_target(args.target)
    root = args.source.resolve(strict=True)
    full = args.full_run.resolve(strict=True)
    output = full / "supplemental"
    if full.is_relative_to(root):
        raise ValueError("supplemental evidence must stay outside the product checkout")
    output.mkdir(exist_ok=False)
    before, error, source_error = None, None, None
    pins, commands, methods, companions, added_components = {}, [], {}, {}, {}
    default_release = service_context = cost_ledger = None
    evaluation = None
    native_transport = None
    native_build_admission = None
    sha_image_bound = False
    try:
        if read_pinned_json(args.target, pins) != target:
            raise ValueError("target.json changed before supplemental admission")
        before = source_admission(root, target)
        start = read_pinned_json(full / "harness-start.json", pins)
        prepared = read_pinned_json(args.environment, pins)
        preparation = read_pinned_json(args.environment.parent / "preparation.json", pins)
        if (start.get("target") != target or start.get("target_file_sha256") != sha(args.target)
                or start.get("environment_file_sha256") != sha(args.environment)
                or start.get("preparation_sha256") != sha(args.environment.parent / "preparation.json")
                or start.get("prepared_native_environment") != prepared
                or preparation.get("target") != target or preparation.get("environment") != prepared):
            raise ValueError("supplemental prerequisites differ from the original full run")
        steps = read_pinned_json(full / "qualification/steps.json", pins)
        if len(steps) != 35 or steps[-1].get("name") != "full-retained-regression":
            raise ValueError("the original full 35-stage execution was not reached")
        discovery = read_pinned_json(full / "discovery.json", pins)
        identity = read_pinned_json(full / "full-method-identity.json", pins)
        methods = require_observed_component_methods(discovery, identity)
        cold_path = full / "qualification/cold.json"
        cold = read_pinned_json(cold_path, pins)
        nested_path = Path(cold["nested_report"])
        nested = read_pinned_json(nested_path, pins)
        compiler = Path(nested["generations"][-1]["produced_image"]).resolve(strict=True)
        compiler_sha = sha(compiler)
        pins[str(compiler)] = compiler_sha
        sys.path.insert(0, str(root))
        from tools.build_hia_json_preflight import admit_cold_build
        sources = admit_cold_build(compiler.read_bytes(), cold_path.read_bytes())
        environment, binding = retained_environment(root, dict(os.environ, **prepared), cold_path)
        environment["PATH"] = "/usr/lib/llvm-20/bin:" + environment.get("PATH", "")
        original_binding = read_pinned_json(full / "cold-environment-binding.json", pins)
        if (binding["cold_variables"] != original_binding["cold_variables"]
                or binding["full_discovery_evidence_variables"] != original_binding["full_discovery_evidence_variables"]):
            raise ValueError("supplemental consumers do not use the original same-run cold binding")
        retained = cold_path.parent / "full-discovery-components"
        cold_sha = sha(cold_path)
        specifications = (
            ("HEPTA_HIA_SCALAR_PROFILE_MANIFEST", "scalar-profile/candidate/build/manifest.json", "scalar_profile"),
            ("HEPTA_HIA_PUBLICATION_MEASUREMENT_MANIFEST", "publication-measurement/PublicationMeasurementNativeTests/candidate/manifest.json", "publication_measurement"),
            ("HEPTA_HIA_NATIVE_MAPPING_MANIFEST", "native-mapping/candidate/build/manifest.json", "native_mapping"),
        )
        for selector, relative, component in specifications:
            companions[selector] = require_cold_component(retained / relative,
                "examples/hia_bootstrap/" + component + ".hepta", cold_sha, compiler_sha, sources, pins)
        for name, relative, component in (
                ("full-cost", "full-cost/built/manifest.json", "full_cost"),
                ("patch-impact", "patch-impact/build/manifest.json", "patch_impact"),
                ("static-budget", "static-budget/build/manifest.json", "static_budget"),
                ("store-lifecycle", "store-lifecycle/built/manifest.json", "store_lifecycle"),
                ("installed-patch-impact", "full-cost/patch-built/manifest.json", "patch_impact")):
            added_components[name] = require_cold_component(retained / relative,
                "examples/hia_bootstrap/" + component + ".hepta", cold_sha, compiler_sha, sources, pins)
        for name in ("full-cost", "patch-impact", "static-budget", "store-lifecycle"):
            custody = read_pinned_json(retained / name / "component-custody.json", pins)
            if (custody.get("schema") != "hepta.hia." + name + "-test-custody.v1"
                    or custody.get("compiler_unchanged") is not True
                    or custody.get("compiler_sha256") != compiler_sha
                    or custody.get("matching_cold_report") != str(cold_path)
                    or custody.get("manifest") != added_components[name]
                    or custody.get("test_result_owned_by_outer_runner") is not True
                    or (name == "full-cost" and custody.get("patch_manifest")
                        != added_components["installed-patch-impact"])):
                raise ValueError("full-discovery component custody differs: " + name)
        default_release = require_default_release(retained / "default-release", root, cold_path,
                                                  compiler, sources, discovery, pins)
        service_context = require_service_context_component(retained / "service-context", root, cold_path,
                                                            compiler, sources, pins)
        added_components["service-context"] = service_context["manifest"]
        cost_ledger = require_cost_ledger_component(retained / "cost-ledger", root, cold_path,
                                                  compiler, sources, pins)
        added_components["cost-ledger"] = cost_ledger["manifest"]
        evaluation = require_evaluation_component(retained / "evaluation", root, cold_path,
                                                  compiler, sources, pins)
        added_components["evaluation"] = evaluation["manifest"]
        native_transport = require_native_transport_component(retained / "native-transport", root,
                                                              cold_path, compiler, sources, pins)
        native_build_admission = require_native_build_admission_component(retained / "native-build-admission", root,
                                                                         cold_path, compiler, sources, pins)
        added_components["native-build-admission"] = native_build_admission["manifest"]
        discovery_root = retained / "cli-discovery-json"
        for name in ("CliDiscoveryJsonNativeTests", "CliDiscoverySelectionFixture"):
            fixture_path = discovery_root / name / "cold-fixture/FIXTURE.json"
            fixture = require_discovery_fixture(fixture_path, cold_path, cold_sha, compiler_sha, sources, pins)
            added_components[name] = str(fixture_path)
        added_components["cli-discovery-companion"] = require_discovery_cli_companion(
            discovery_root / "CliDiscoverySelectionFixture/cli-companion", fixture["authority"], root, pins)
        cli_observations = read_pinned_json(
            discovery_root / "CliDiscoverySelectionFixture/ORDINARY_CLI.json", pins)
        if (cli_observations.get("status") != "PASS"
                or cli_observations.get("scope") != "MATCHING_SOURCE_COLD_FIXTURE"
                or cli_observations.get("actual_native_json_calls") != 20
                or cli_observations.get("retained_semantic_calls") != 0
                or cli_observations.get("host_json_constructor_calls") != 0):
            raise ValueError("complete selected CLI discovery observations are missing")
        stream = read_pinned_json(retained / "sha256-stream-differential/observations.json", pins)
        if (stream.get("actualCold") is not True or stream.get("cold_report_selected") is not True
                or stream.get("cold_report_sha256") != cold_sha
                or stream.get("nested_report_sha256") != sha(nested_path)
                or stream.get("cold_source_manifest") != sources
                or stream.get("candidate_source_sha256") != sources["examples/hia_bootstrap/sha256_stream.hepta"]
                or stream.get("source_and_compiler_unchanged") is not True
                or stream.get("cold_readback_error") is not None
                or not stream.get("observations") or not stream.get("foreign_alias_observations")):
            raise ValueError("the real SHA stream differential did not complete against this cold")
        spec = importlib.util.spec_from_file_location("unchanged_product_workflow_process", root / SUPERVISOR)
        supervisor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(supervisor)
        jobs = (
            ("sha256-stream-production-build", ["tools/build_hia_sha256.py", "--candidate", "sha256_stream",
                "--compiler", str(compiler), "--cold-report", str(cold_path),
                "--output", str(output / "sha256-stream-build")], {}),
            ("scalar-profile-callers", ["tools/qualify_hia_scalar_profile_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "scalar-profile-callers")], {}),
            ("bounded-memory-callers", ["tools/qualify_hia_bounded_memory_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "bounded-memory-callers")], {}),
            ("generation-retention-callers", ["tools/qualify_hia_generation_retention_callers.py",
                "--cold-report", str(cold_path), "--require-companion-policies",
                "--evidence", str(output / "generation-retention-callers")], companions),
            ("full-cost-callers", ["tools/qualify_hia_full_cost_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "full-cost-callers")], {}),
            ("patch-impact-callers", ["tools/qualify_hia_patch_impact_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "patch-impact-callers")], {}),
            ("cli-discovery-original-groups", ["tools/qualify_hia_cli_discovery_json.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "cli-discovery-original-groups")], {}),
            ("cli-discovery-callers", ["tools/qualify_hia_cli_discovery_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "cli-discovery-callers")], {}),
            ("static-budget-callers", ["tools/qualify_hia_static_budget_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "static-budget-callers")], {}),
            ("store-lifecycle-callers", ["tools/qualify_hia_store_lifecycle_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "store-lifecycle-callers")], {}),
        )
        service_context_jobs = (
            ("service-context-callers", ["tools/qualify_hia_service_context_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "service-context-callers")], {}),
        )
        cost_ledger_jobs = (
            ("cost-ledger-callers", ["tools/qualify_hia_cost_ledger_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "cost-ledger-callers")], {}),
        )
        evaluation_jobs = (
            ("evaluation-callers", ["tools/qualify_hia_evaluation_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "evaluation-callers")], {}),
        )
        native_build_admission_jobs = (
            ("native-build-admission-callers", ["tools/qualify_hia_native_build_admission_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "native-build-admission-callers")], {}),
        )
        for name, arguments, selection in (*jobs, *service_context_jobs, *cost_ledger_jobs, *evaluation_jobs,
                                           *native_build_admission_jobs):
            command = [sys.executable, "-B", *arguments]
            record = {"name": name, "command": command, "passed": False}
            try:
                owner = supervisor.run_workflow_step(command, cwd=root, env=dict(environment, **selection),
                    stdout_path=output / (name + ".stdout"), stderr_path=output / (name + ".stderr"),
                    receipt_path=output / (name + ".owner.json"), seconds=1800)
                record["owner"] = owner
                record["passed"] = (owner.get("status") == "WORKFLOW_STEP_COMPLETED"
                    and owner.get("returncode") == 0 and owner.get("timed_out") is False
                    and owner.get("cleanup", {}).get("complete") is True)
                if name.endswith("-callers") and name != "cli-discovery-callers":
                    report = read_pinned_json(output / name / "report.json", pins)
                    record["actual_tests"] = report.get("actual_tests")
                    expected_scope = {
                        "scalar-profile-callers": "MATCHING_SOURCE_COLD_ORIGINAL_SCALAR_PROFILE_CALLERS",
                        "bounded-memory-callers": "MATCHING_SOURCE_COLD_ORIGINAL_VM_MEMORY_CALLERS",
                        "generation-retention-callers": "MATCHING_SOURCE_COLD_ORIGINAL_GENERATION_CALLERS",
                        "full-cost-callers": "MATCHING_SOURCE_COLD_ORIGINAL_FULL_COST_CALLERS",
                        "patch-impact-callers": "MATCHING_SOURCE_COLD_ORIGINAL_PATCH_IMPACT_CALLERS",
                        "static-budget-callers": "MATCHING_SOURCE_COLD_ORIGINAL_STATIC_BUDGET_CALLERS",
                        "store-lifecycle-callers": "MATCHING_SOURCE_COLD_ORIGINAL_STORE_LIFECYCLE_CALLERS",
                        "service-context-callers": "MATCHING_SOURCE_COLD_ORIGINAL_SERVICE_CONTEXT_CALLERS",
                        "cost-ledger-callers": "MATCHING_SOURCE_COLD_SEVEN_ORDINARY_COST_LEDGER_CALLER_MODULES",
                        "evaluation-callers": "MATCHING_SOURCE_COLD_SEVEN_ORDINARY_EVALUATION_CALLER_MODULES",
                        "native-build-admission-callers": "MATCHING_SOURCE_COLD_NINE_ORDINARY_NATIVE_BUILD_ADMISSION_CALLER_MODULES",
                    }[name]
                    record["passed"] = bool(record["passed"] and report.get("status") == "PASS"
                        and report.get("scope") == expected_scope
                        and report.get("planned") == report.get("started") == report.get("stopped")
                        and type(report.get("actual_tests")) is int
                        and report.get("actual_tests") == len(report.get("planned", [])) > 0
                        and len(report["planned"]) == len(set(report["planned"]))
                        and all(report.get(key) == [] for key in ("errors", "failures", "skipped",
                                                                  "expected_failures", "unexpected_successes")))
                    if name in ("full-cost-callers", "patch-impact-callers", "static-budget-callers"):
                        component = {
                            "full-cost-callers": "full_cost",
                            "patch-impact-callers": "patch_impact",
                            "static-budget-callers": "static_budget",
                        }[name]
                        manifest_path = output / name / "qualified/manifest.json"
                        require_cold_component(manifest_path, "examples/hia_bootstrap/" + component + ".hepta",
                                               cold_sha, compiler_sha, sources, pins)
                        manifest = read_pinned_json(manifest_path, pins)
                        counts = {
                            "full_cost": ("native_arm_calls", "native_decision_calls"),
                            "patch_impact": ("native_change_calls", "native_graph_calls"),
                            "static_budget": ("native_topological_calls", "native_function_calls",
                                              "native_frame_calls", "native_profile_calls", "native_policy_calls"),
                        }[component]
                        forbidden = {
                            "full_cost": "retained_python_arithmetic_bodies_forbidden",
                            "patch_impact": "retained_python_impact_bodies_forbidden",
                            "static_budget": "retained_python_resource_bodies_forbidden",
                        }[component]
                        record["passed"] = bool(record["passed"]
                            and report.get("all_original_modules_unfiltered") is True
                            and report.get("source_and_bundle_unchanged") is True and report.get(forbidden) is True
                            and report.get("native_image_sha256") == manifest["image_sha256"]
                            and all(type(report.get(key)) is int and report[key] > 0 for key in counts))
                    elif name == "store-lifecycle-callers":
                        from tools.qualify_hia_store_lifecycle_callers import FIXTURE_NAME, FIXTURE_SHA256
                        fixture_path = root / FIXTURE_NAME
                        original = read_pinned_json(fixture_path, pins)
                        if (sha(fixture_path) != FIXTURE_SHA256
                                or original.get("schema") != "hepta.hia.store-lifecycle-original-callers.v1"
                                or len(original.get("ordered_ids", [])) != 50
                                or any(sha(root / path) != digest
                                       for path, digest in original["source_sha256"].items())):
                            raise ValueError("original Store caller source or ordered 50-method inventory differs")
                        manifest_path = output / name / "qualified/manifest.json"
                        require_cold_component(manifest_path, "examples/hia_bootstrap/store_lifecycle.hepta",
                                               cold_sha, compiler_sha, sources, pins)
                        manifest = read_pinned_json(manifest_path, pins)
                        modes = report.get("native_mode_frames", {})
                        events = report.get("actual_machine_mode_events", {})
                        record["reference_poison_scope"] = report.get("reference_poison_scope")
                        record["passed"] = bool(record["passed"]
                            and report.get("original_modules") == original["modules"]
                            and report.get("planned") == original["ordered_ids"]
                            and report.get("actual_tests") == 50
                            and report.get("all_original_modules_unfiltered") is True
                            and report.get("original_test_budgets_changed") is False
                            and report.get("source_and_bundle_unchanged") is True
                            and report.get("native_image_sha256") == manifest["image_sha256"]
                            and report.get("reference_calls") == []
                            and report.get("reference_poison_scope")
                                == "test process; subprocesses inherit selector, not Python patches"
                            and type(modes) is dict and set(modes) == {"1", "2"}
                            and all(type(value) is int and value > 0 for value in modes.values())
                            and type(events) is dict
                            and all(type(events.get(key)) is int and events[key] > 0 for key in ("1:1", "2:1"))
                            and all(type(value) is int and value > 0 for value in events.values()))
                    elif name == "service-context-callers":
                        from tools.build_hia_service_context import INPUTS, SOURCE_NAME
                        manifest_path = output / name / "qualified/manifest.json"
                        require_cold_component(manifest_path, SOURCE_NAME, cold_sha, compiler_sha, sources, pins)
                        require_release_compilation(manifest_path.parent, "service-context", SOURCE_NAME,
                                                    INPUTS, root, compiler, sources, pins)
                        record["service_context_original_observations"] = require_service_context_caller_observations(
                            output / name, root, sources, discovery, manifest_path, pins)
                    elif name == "cost-ledger-callers":
                        from tools.build_hia_cost_ledger import INPUTS, SOURCE_NAME
                        manifest_path = output / name / "qualified/manifest.json"
                        require_cold_component(manifest_path, SOURCE_NAME, cold_sha, compiler_sha, sources, pins)
                        require_release_compilation(manifest_path.parent, "cost-ledger", SOURCE_NAME,
                                                    INPUTS, root, compiler, sources, pins)
                        record["cost_ledger_original_observations"] = require_cost_ledger_caller_observations(
                            output / name, root, sources, discovery, manifest_path, pins)
                    elif name == "evaluation-callers":
                        from tools.build_hia_evaluation import INPUTS, SOURCE_NAME
                        manifest_path = output / name / "qualified/manifest.json"
                        require_cold_component(manifest_path, SOURCE_NAME, cold_sha, compiler_sha, sources, pins)
                        require_release_compilation(manifest_path.parent, "evaluation", SOURCE_NAME,
                                                    INPUTS, root, compiler, sources, pins)
                        record["evaluation_original_observations"] = require_evaluation_caller_observations(
                            output / name, root, sources, discovery, manifest_path, pins)
                    elif name == "native-build-admission-callers":
                        from tools.build_hia_native_build_admission import INPUTS, SOURCE_NAME
                        manifest_path = output / name / "qualified/manifest.json"
                        require_cold_component(manifest_path, SOURCE_NAME, cold_sha, compiler_sha, sources, pins)
                        require_release_compilation(manifest_path.parent, "native_build_admission", SOURCE_NAME,
                                                    INPUTS, root, compiler, sources, pins)
                        record["native_build_admission_original_observations"] = require_native_build_admission_callers(
                            output / name, root, sources, discovery, manifest_path, pins)
                elif name == "cli-discovery-original-groups":
                    from tools import qualify_hia_cli_discovery_json as original_discovery
                    report = read_pinned_json(output / name / "REPORT.json", pins)
                    fixture = require_discovery_fixture(output / name / "fixture/FIXTURE.json",
                        cold_path, cold_sha, compiler_sha, sources, pins)
                    groups = report.get("groups", [])
                    record["observed_groups"] = [item.get("group") for item in groups]
                    record["passed"] = bool(record["passed"]
                        and report.get("status") == "MATCHING_SOURCE_COLD_CLI_DISCOVERY_JSON_PASS"
                        and report.get("scope") == "MATCHING_SOURCE_COLD_CLI_DISCOVERY_JSON"
                        and report.get("qualification_complete") is True
                        and report.get("authority") == fixture["authority"]
                        and report.get("source_before") == report.get("source_after") == sources
                        and report.get("source_and_inputs_unchanged") is True
                        and report.get("expected_ids") == list(original_discovery.EXPECTED_IDS)
                        and report.get("expected_count") == 4
                        and report.get("machine_cases") == 61 and report.get("vm_cases") == 6
                        and report.get("vm_steps") == 10000000 and report.get("vm_heap_bytes") == 8 << 20
                        and report.get("vm_call_depth") == 128 and report.get("buffer_capacity") == 1048576
                        and report.get("compile_seconds") == 20
                        and report.get("group_seconds") == 180 and report.get("cleanup_seconds") == 3
                        and original_discovery._owner_pass(report.get("preparation_owner", {}))
                        and [item.get("group") for item in groups] == list(original_discovery.GROUPS))
                    for item in groups:
                        group = item["group"]
                        request_path = output / name / group / "REQUEST.json"
                        read_pinned_json(request_path, pins)
                        observations = read_pinned_json(output / name / group / "REPORT.json", pins)
                        if observations != item["observations"]:
                            raise ValueError("original CLI group observations differ from their retained file")
                        original_discovery.admit_result(observations, group, sha(request_path))
                        record["passed"] = bool(record["passed"] and item.get("status") == "PASS"
                            and original_discovery._owner_pass(item.get("owner", {})))
                elif name == "cli-discovery-callers":
                    from tools import qualify_hia_cli_discovery_json as original_discovery
                    from tools.hia_cli_discovery_custody import owner_sources as discovery_sources
                    from tools.qualify_hia_cli_discovery_callers import EXPECTED_IDS
                    report = read_pinned_json(output / name / "REPORT.json", pins)
                    request_path = output / name / "REQUEST.json"
                    read_pinned_json(request_path, pins)
                    tests = read_pinned_json(output / name / "TESTS.json", pins)
                    native = read_pinned_json(output / name / "controls/ORDINARY_CLI.json", pins)
                    fixture = require_discovery_fixture(output / name / "json-fixture/FIXTURE.json",
                        cold_path, cold_sha, compiler_sha, sources, pins)
                    require_discovery_cli_companion(output / name / "cli", fixture["authority"], root, pins)
                    record["actual_tests"] = tests.get("actual_tests")
                    record["passed"] = bool(record["passed"] and report.get("status") == "PASS"
                        and report.get("scope") == "MATCHING_SOURCE_COLD_ORDINARY_CLI_DISCOVERY_CALLERS"
                        and report.get("matching_cold") is True and report.get("source_and_inputs_unchanged") is True
                        and report.get("source_before") == report.get("source_after") == discovery_sources()
                        and report.get("tests") == tests and report.get("native_observations") == native
                        and original_discovery._owner_pass(report.get("process_owner", {}))
                        and tests.get("status") == "PASS" and tests.get("source_and_inputs_unchanged") is True
                        and tests.get("scope") == "MATCHING_SOURCE_COLD_ORDINARY_CLI_DISCOVERY_CALLERS"
                        and tests.get("request_sha256") == sha(request_path)
                        and tests.get("planned") == tests.get("started") == tests.get("stopped") == list(EXPECTED_IDS)
                        and type(tests.get("actual_tests")) is int and tests["actual_tests"] == len(EXPECTED_IDS)
                        and all(tests.get(key) == [] for key in original_discovery.ANOMALIES)
                        and native.get("status") == "PASS" and native.get("actual_native_json_calls") == 20
                        and native.get("scope") == "MATCHING_SOURCE_COLD_FIXTURE"
                        and native.get("retained_semantic_calls") == 0 and native.get("host_json_constructor_calls") == 0)
            except Exception as failure:
                record.update(passed=False, error={"type": type(failure).__name__, "message": str(failure)})
            commands.append(record)
            write_json(output / (name + ".result.json"), record)
        manifest_path = output / "sha256-stream-build/manifest.json"
        manifest = read_pinned_json(manifest_path, pins)
        build = read_pinned_json(manifest_path.with_name("build.json"), pins)
        image = manifest_path.parent / manifest["image_path"]
        pins[str(image)] = sha(image)
        sha_image_bound = bool(build.get("status") == "NATIVE_CANDIDATE_BUILT"
            and build.get("cold_report_sha256") == cold_sha and build.get("source_manifest") == sources
            and build.get("manifest") == manifest and manifest.get("compiler_sha256") == compiler_sha
            and manifest.get("source_sha256") == stream["candidate_source_sha256"]
            and manifest.get("image_sha256") == pins[str(image)] == stream["images"]["candidate"])
        if not sha_image_bound:
            raise ValueError("production SHA stream image differs from the actual same-cold execution witness")
    except Exception as failure:
        error = {"type": type(failure).__name__, "message": str(failure)}
    try:
        source_unchanged = before is not None and source_admission(root, target) == before
        readback = bool(pins) and all(sha(Path(path)) == digest for path, digest in pins.items())
    except Exception as failure:
        source_unchanged, readback = False, False
        source_error = {"type": type(failure).__name__, "message": str(failure)}
    passed = bool(error is None and source_error is None and source_unchanged and readback
                  and sha_image_bound and default_release is not None and default_release["passed"]
                  and service_context is not None and service_context["passed"]
                  and cost_ledger is not None and cost_ledger["passed"]
                  and evaluation is not None and evaluation["passed"]
                  and native_transport is not None and native_transport["passed"]
                  and native_build_admission is not None and native_build_admission["passed"]
                  and len(commands) == 14 and all(row["passed"] for row in commands))
    write_json(output / "supplemental-result.json", {
        "schema": "hepta.hia.same-cold-supplemental-callers.v1", "target": target,
        "scope": "MISSING_CALLER_GATES_AND_PRODUCTION_SHA_BINDING_AFTER_UNCHANGED_ORIGINAL_FULL",
        "passed": passed, "error": error, "source_error": source_error,
        "complete_source_unchanged": source_unchanged, "all_captured_inputs_read_back": readback,
        "reused_complete_full_discovery_methods": methods, "same_cold_companion_manifests": companions,
        "new_full_discovery_component_inputs": added_components,
        "default_release_full_discovery_artifact_readback": default_release,
        "service_context_full_discovery_artifact_readback": service_context,
        "cost_ledger_full_discovery_artifact_readback": cost_ledger,
        "evaluation_full_discovery_artifact_readback": evaluation,
        "native_transport_full_discovery_artifact_readback": native_transport,
        "native_build_admission_full_discovery_artifact_readback": native_build_admission,
        "production_sha_image_matches_actual_executed_differential_image": sha_image_bound,
        "commands": commands, "captured_inputs": pins, "original_35_stages_modified": False,
        "original_component_test_suites_rerun": False,
        "original_10_supplemental_jobs_modified": False,
        "service_context_job_11_modified": False,
        "cost_ledger_job_12_modified": False,
        "evaluation_job_13_modified": False,
        "service_context_original_caller_gate_attempted": any(
            row["name"] == "service-context-callers" for row in commands),
        "cost_ledger_seven_ordinary_caller_gate_attempted": any(
            row["name"] == "cost-ledger-callers" for row in commands),
        "evaluation_seven_ordinary_caller_gate_attempted": any(
            row["name"] == "evaluation-callers" for row in commands),
        "native_build_admission_nine_ordinary_caller_gate_attempted": any(
            row["name"] == "native-build-admission-callers" for row in commands),
        "additional_bounded_cli_groups_observed": next((row.get("observed_groups", [])
            for row in commands if row["name"] == "cli-discovery-original-groups"), []),
        "additional_bounded_cli_caller_gate_attempted": any(
            row["name"] == "cli-discovery-callers" for row in commands),
        "per_command_workflow_seconds": 1800,
        "all_input_equivalence_proved": False, "whole_native_delivery_qualified": False,
    })
    print(json.dumps({"supplemental_passed": passed, "commands": len(commands), "error": error}))
    return 0 if passed else 1


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
    supplemental_parser = commands.add_parser("supplemental")
    supplemental_parser.add_argument("--target", type=Path, required=True)
    supplemental_parser.add_argument("--source", type=Path, required=True)
    supplemental_parser.add_argument("--environment", type=Path, required=True)
    supplemental_parser.add_argument("--full-run", type=Path, required=True)
    supplemental_parser.set_defaults(operation=supplemental)
    collect_parser = commands.add_parser("collect")
    collect_parser.add_argument("--harness", type=Path, required=True)
    collect_parser.add_argument("--audit-root", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.set_defaults(operation=collect)
    args = parser.parse_args()
    return args.operation(args)


if __name__ == "__main__":
    raise SystemExit(main())
