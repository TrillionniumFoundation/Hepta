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
import struct
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
    "NATIVE_BUILD_ADMISSION", "NATIVE_BUILD_DISPATCH", "EMISSION", "STORE_ARTIFACT_PROFILE",
    "NATIVE_DELIVERY", "STORE_NATIVE_DELIVERY",
    "STORE_TRANSACTION", "ARTIFACT_DELIVERY",
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
NATIVE_BUILD_DISPATCH_SOURCE_CLASS = "tests.test_hia_native_build_dispatch.NativeBuildDispatchSourceTests"
NATIVE_BUILD_DISPATCH_NATIVE_CLASS = "tests.test_hia_native_build_dispatch.NativeBuildDispatchNativeTests"
EMISSION_SOURCE_CLASS = "tests.test_hia_emission_native.EmissionSourceTests"
EMISSION_NATIVE_CLASS = "tests.test_hia_emission_native.EmissionNativeTests"
STORE_ARTIFACT_PROFILE_SOURCE_CLASS = "tests.test_hia_store_artifact_profile_native.StoreArtifactProfileSourceTests"
STORE_ARTIFACT_PROFILE_NATIVE_CLASS = "tests.test_hia_store_artifact_profile_native.StoreArtifactProfileNativeTests"
NATIVE_DELIVERY_SOURCE_CLASS = "tests.test_hia_native_delivery.NativeDeliverySourceTests"
NATIVE_DELIVERY_NATIVE_CLASS = "tests.test_hia_native_delivery.NativeDeliveryNativeTests"
STORE_NATIVE_DELIVERY_SOURCE_CLASS = "tests.test_hia_store_native_delivery.StoreNativeDeliverySourceTests"
STORE_NATIVE_DELIVERY_NATIVE_CLASS = "tests.test_hia_store_native_delivery.StoreNativeDeliveryNativeTests"
STORE_TRANSACTION_SOURCE_CLASS = "tests.test_hia_store_transaction_native.StoreTransactionSourceTests"
STORE_TRANSACTION_NATIVE_CLASS = "tests.test_hia_store_transaction_native.StoreTransactionNativeTests"
ARTIFACT_DELIVERY_SOURCE_CLASS = "tests.test_hia_artifact_delivery.ArtifactDeliverySourceTests"
ARTIFACT_DELIVERY_NATIVE_CLASS = "tests.test_hia_artifact_delivery.ArtifactDeliveryNativeTests"
# Filled only after the actual composed source and GitHub commit/tree are frozen.
# A draft fixture or an unbound target cannot enter a formal same-cold reader.
FINAL_DELIVERY_FREEZE = {'five_source_sha256': {'hepta/artifact_publication_native.py': '3ede824779490e60d6cbaa17ce30ee3fcec166175fb8dc7f6b016743b2a94532',
                        'hepta/hia_agent_store.py': 'daeeca1b6a0e0e901a4958c115efeee877ba95fea3617b5226575f04482f2486',
                        'hepta/hia_native_delivery.py': '4c217d213f16cc499649b509f553e4209882d6929281610d19150703e4e6ec46',
                        'hepta/hia_store_lifecycle_native.py': '9ce14c14745cf50ae8ea1b32f7ea60d4ff4c3e95c66eb320f0f457d1dcc06df7',
                        'hepta/hia_store_lifecycle_selection.py': '6f56b91061c0be019ea5dceb86613d307793a4bf691228101776a46885887c7b'},
 'product_commit': 'bb3120d26cfd483b5cd85a13c72c90a24d119603',
 'product_tree': '11d957ccbab3b0a765285d549306b45353483012',
 'successor_fixture_sha256': '5560d263335d7c48a575eeb5a7a3a47f6c2122588608f837efb185bb371ef859',
 'successor_helper_sha256': '692f5bce0f4c58263a22f2e91f0c8d7699a83b23a282818768bd83f15887199e'}
FINAL_STORE_SOURCE_PATHS = ("hepta/artifact_publication_native.py", "hepta/hia_agent_store.py",
                           "hepta/hia_store_lifecycle_selection.py")
FINAL_STORE_SHARED_PATHS = ("hepta/hia_native_delivery.py", "hepta/hia_store_lifecycle_native.py")
FINAL_STORE_PATHS = FINAL_STORE_SOURCE_PATHS + FINAL_STORE_SHARED_PATHS
FINAL_STORE_ORIGINAL = "tests/fixtures/store_native_delivery_original_c019.json"
FINAL_STORE_ORIGINAL_SHA256 = "5fccb548e4b98fd6de5ad2eb4dc88e1adac41112b1f2c850e8254d6b10853b54"
FINAL_STORE_SUCCESSOR = "tests/fixtures/store_delivery_successor_provenance.json"
FINAL_STORE_SUCCESSOR_HELPER = "tests/hia_store_delivery_successor.py"
FINAL_DELIVERY_CALLER_JOBS = ("store-transaction-callers", "store-transaction-separate-callers",
                            "artifact-delivery-callers")

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
    "native-build-dispatch": (NATIVE_BUILD_DISPATCH_NATIVE_CLASS, "HEPTA_HIA_NATIVE_BUILD_DISPATCH_EVIDENCE"),
    "emission": (EMISSION_NATIVE_CLASS, "HEPTA_HIA_EMISSION_EVIDENCE"),
    "store-artifact-profile": (STORE_ARTIFACT_PROFILE_NATIVE_CLASS, "HEPTA_HIA_STORE_ARTIFACT_PROFILE_EVIDENCE"),
    "native-delivery": (NATIVE_DELIVERY_NATIVE_CLASS, "HEPTA_HIA_NATIVE_DELIVERY_EVIDENCE"),
    "store-native-delivery": (STORE_NATIVE_DELIVERY_NATIVE_CLASS, "HEPTA_HIA_STORE_NATIVE_DELIVERY_EVIDENCE"),
    "store-transaction": (STORE_TRANSACTION_NATIVE_CLASS, "HEPTA_HIA_STORE_TRANSACTION_EVIDENCE"),
    "artifact-delivery": (ARTIFACT_DELIVERY_NATIVE_CLASS, "HEPTA_HIA_ARTIFACT_DELIVERY_EVIDENCE"),
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
    "HEPTA_HIA_NATIVE_BUILD_DISPATCH_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_EMISSION_MANIFEST", "HEPTA_HIA_EMISSION_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST", "HEPTA_HIA_STORE_ARTIFACT_PROFILE_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_NATIVE_DELIVERY_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_STORE_NATIVE_DELIVERY_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_STORE_TRANSACTION_MANIFEST", "HEPTA_HIA_STORE_TRANSACTION_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_ARTIFACT_DELIVERY_DEVELOPMENT_COMPILER",
    "HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST", "HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST",
)


def component_workflow_coverage(root):
    final_delivery_target_binding(root, {})
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
    if NATIVE_BUILD_DISPATCH_SOURCE_CLASS not in named[0]:
        raise ValueError("native-build-dispatch source class must remain in the first extracted source tuple")
    if EMISSION_SOURCE_CLASS not in named[0]:
        raise ValueError("emission source class must remain in the first extracted source tuple")
    if STORE_ARTIFACT_PROFILE_SOURCE_CLASS not in named[0]:
        raise ValueError("Store artifact/profile source class must remain in the first extracted source tuple")
    if NATIVE_DELIVERY_SOURCE_CLASS not in named[0]:
        raise ValueError("D0-D3 delivery source class must remain in the first extracted source tuple")
    if STORE_NATIVE_DELIVERY_SOURCE_CLASS not in named[0]:
        raise ValueError("D4 Store delivery source class must remain in the first extracted source tuple")
    if STORE_TRANSACTION_SOURCE_CLASS not in named[0] or ARTIFACT_DELIVERY_SOURCE_CLASS not in named[0]:
        raise ValueError("transaction and artifact delivery require their complete source classes in the first tuple")
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
            "native_build_dispatch_source_class_in_first_source_tuple": True,
            "emission_source_class_in_first_source_tuple": True,
            "store_artifact_profile_source_class_in_first_source_tuple": True,
            "native_delivery_source_class_in_first_source_tuple": True,
            "store_native_delivery_source_class_in_first_source_tuple": True,
            "store_transaction_source_class_in_first_source_tuple": True,
            "artifact_delivery_source_class_in_first_source_tuple": True,
            "coverage_scope": "SOURCE_AND_NATIVE_GROUPS_BEFORE_FIRST_FULL_DISCOVERY",
            "post_full_delivery_original_152_supplement_added": True,
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
    classes.append(NATIVE_BUILD_DISPATCH_SOURCE_CLASS)
    classes.append(EMISSION_SOURCE_CLASS)
    classes.append(STORE_ARTIFACT_PROFILE_SOURCE_CLASS)
    classes.extend((NATIVE_DELIVERY_SOURCE_CLASS, STORE_NATIVE_DELIVERY_SOURCE_CLASS,
                    STORE_TRANSACTION_SOURCE_CLASS, ARTIFACT_DELIVERY_SOURCE_CLASS))
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
        if ((name == NATIVE_BUILD_DISPATCH_SOURCE_CLASS and len(planned) != 2)
                or (name == NATIVE_BUILD_DISPATCH_NATIVE_CLASS and len(planned) != 3)):
            raise ValueError("native-build-dispatch requires both source and all three native methods")
        if ((name == EMISSION_SOURCE_CLASS and len(planned) != 3)
                or (name == EMISSION_NATIVE_CLASS and len(planned) != 8)):
            raise ValueError("emission requires all three source and eight native methods")
        if ((name == STORE_ARTIFACT_PROFILE_SOURCE_CLASS and len(planned) != 3)
                or (name == STORE_ARTIFACT_PROFILE_NATIVE_CLASS and len(planned) != 8)):
            raise ValueError("Store artifact/profile requires all three source and eight native methods")
        if ((name in (NATIVE_DELIVERY_SOURCE_CLASS, STORE_NATIVE_DELIVERY_SOURCE_CLASS) and len(planned) != 3)
                or (name in (NATIVE_DELIVERY_NATIVE_CLASS, STORE_NATIVE_DELIVERY_NATIVE_CLASS) and len(planned) != 8)):
            raise ValueError("each delivery class requires all three source and eight native methods")
        if ((name in (STORE_TRANSACTION_SOURCE_CLASS, ARTIFACT_DELIVERY_SOURCE_CLASS) and len(planned) != 3)
                or (name in (STORE_TRANSACTION_NATIVE_CLASS, ARTIFACT_DELIVERY_NATIVE_CLASS) and len(planned) != 8)):
            raise ValueError("transaction and artifact delivery each require exactly three source and eight native methods")
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
    if counts != {"continuation": 665} or type(counts.get("continuation")) is not int:
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
    if (counts["first"] != {"frames": 6, "entries": 506, "modes": {"2": 2, "3": 2, "4": 2}, "object_observations": 2, "unknown_frames": 0}
            or counts["replay"] != {"frames": 3, "entries": 253, "modes": {"2": 1, "3": 1, "4": 1}, "object_observations": 1, "unknown_frames": 0}
            or any(counts[name] != zero for name in ("native_ack-replay", "process_loss-replay", "changed-installed-source"))):
        raise ValueError("native-build-admission ordinary revalidation or unknown replay counts differ")
    for name in ("native_ack", "process_loss"):
        row = counts[name]
        if (row["frames"] != 3 or row["modes"] != {"2": 1, "3": 1, "4": 1} or row["object_observations"] != 1
                or row["unknown_frames"] != 2 or not 0 < row["entries"] < counts["replay"]["entries"]
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
            or any(build.get(key) is not True for key in (
                "dynamic_method_and_global_lookup_preserved", "original_method_calls_enter_selected_native_child_owners",
                "active_causal_native_loss_propagated_without_exception_type_inference",
                "runtime_comprehension_protocols_observed_without_version_threshold",
                "normal_and_short_circuit_iterator_release_owned_by_hia"))
            or build.get("retained_body_claim_scope") != "canonical selected route; explicit foreign callables remain unconstrained"
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


def native_build_dispatch_observations(directory, root, sources, pins):
    """Read separately frozen original cases without executing either owner."""
    from tests.hia_native_build_admission_scenarios import scenarios
    directory, root = Path(directory), Path(root)
    fixture_name = "tests/fixtures/hia_native_build_dispatch_cases_aac7550.json"
    oracle_name = "tests/hia_native_build_dispatch_oracle.py"
    fixture_digest = "f42756d516f2ac3227445da1bc12a37120877c313c0c2fd765f2fa468bab04ec"
    oracle_digest = "751c323f838240866dc0e4d22dd4c683d17393ea92356677308f4df20eac74ab"
    fixture_raw = release_bytes(root / fixture_name, pins)
    oracle_raw = release_bytes(root / oracle_name, pins)
    if (hashlib.sha256(fixture_raw).hexdigest() != fixture_digest
            or hashlib.sha256(oracle_raw).hexdigest() != oracle_digest
            or sources.get(fixture_name) != fixture_digest
            or sources.get(oracle_name) != oracle_digest):
        raise ValueError("native-build-dispatch independently frozen original files differ")
    fixture = json.loads(fixture_raw)
    names = [row["name"] for row in fixture["cases"]]
    ordinary = [row["name"] for row in scenarios()]
    if (len(names) != 205 or len(set(names)) != 205
            or len(ordinary) != 303 or len(set(ordinary)) != 303
            or fixture.get("candidate_execution_before_freeze") is not False
            or fixture.get("existing_303_cases_or_expected_modified") is not False):
        raise ValueError("native-build-dispatch complete original inventories differ")
    location = directory / "test_frozen_dispatch_runtime_and_original_default_observations"
    matrices = (("complete-observations.json", names), ("retained-303-observations.json", ordinary))
    expected = {}
    for filename, planned in matrices:
        rows = release_json(location / filename, pins)
        if type(rows) is not list or [row.get("case") for row in rows] != planned:
            raise ValueError("native-build-dispatch complete observation order differs: " + filename)
        for row in rows:
            if (set(row) != {"case", "expected", "actual"}
                    or row["expected"].get("name") != row["case"]
                    or evaluation_json_bytes(row["expected"]) != evaluation_json_bytes(row["actual"])):
                raise ValueError("native-build-dispatch original trace, binding, lifetime or exception differs")
            expected[row["case"]] = row["expected"]
    counts = release_json(location / "entry-counts.json", pins)
    modes = {"mode_1", "mode_2", "mode_3", "mode_4"}
    events = {"event_0", "event_1", "event_2", "event_3"}
    if (type(counts) is not dict or set(counts) != modes | events
            or any(type(value) is not int or value < 0 for value in counts.values())
            or counts["event_0"] != sum(counts[name] for name in modes)
            or counts["event_0"] <= 0 or counts["event_1"] <= 0
            or counts["event_1"] != counts["event_2"] + counts["event_3"]):
        raise ValueError("native-build-dispatch actual canonical and override native event accounting differs")
    errors = ("ValueError", "TypeError", "OSError", "OverflowError", "RecursionError",
              "OperationalError", "MixedRejected", "RuntimeError", "KeyboardInterrupt", "SystemExit")
    calls = ((2, "dispatch_signatures_call"), (3, "dispatch_native_call"),
             (4, "dispatch_build_inputs_call"))
    failures = release_json(directory /
        "test_lost_override_ACK_retains_unknown_without_retry_or_false_foreign_rejection/unknown-overrides.json", pins)
    if type(failures) is not list or len(failures) != 30:
        raise ValueError("native-build-dispatch complete three-call lost-ACK controls are absent")
    for row, (mode, port, error) in zip(failures,
            ((mode, port, error) for mode, port in calls for error in errors)):
        case = "dispatch." + str(mode) + ".instance_function"
        raised = error if error in ("RuntimeError", "KeyboardInterrupt", "SystemExit") else "NativeBuildAdmissionUnknown"
        observed, trace = row.get("events", []), row.get("trace", [])
        if (row.get("case") != case or row.get("port") != port or row.get("injected") != error
                or row.get("raised") != raised
                or row.get("original_exception_or_cause_identity_retained") is not True
                or row.get("unknown_custody_retained") is not True
                or not observed or observed[0] != 0 or observed[-1] != 2
                or any(type(value) is not int or value not in (0, 1, 2) for value in observed)
                or not trace or sum(item.get("event") == "dispatch.call" for item in trace) != 1
                or evaluation_json_bytes(trace) != evaluation_json_bytes(expected[case]["trace"][:len(trace)])):
            raise ValueError("native-build-dispatch override was retried, rejected or lost original exception identity")
    return {"independent_original_dispatch_and_runtime_cases": 205,
            "unchanged_original_canonical_cases": 303, "actual_native_event_counts": counts,
            "full_trace_alias_lifetime_and_exception_comparison": True,
            "foreign_override_lost_ACK_cases": 30, "test_bodies_rerun_by_readback": False,
            "all_python_versions_tested": False, "all_input_equivalence_proved": False}


def native_build_dispatch_nested_losses(directory, pins):
    """Verify child and ancestor outcomes from the actual nested call records."""
    from hepta.hia_native_build_admission_protocol import PORT, PORTS
    directory = Path(directory)
    location = directory / "test_nested_native_loss_propagates_causally_and_foreign_errors_keep_identity"
    unknown = release_json(location / "nested-native-loss.json", pins)
    foreign = release_json(location / "nested-confirmed-foreign.json", pins)
    originals = release_json(directory /
        "test_frozen_dispatch_runtime_and_original_default_observations/retained-303-observations.json", pins)
    expected = {row["case"]: row["expected"] for row in originals}
    errors = ("ValueError", "TypeError", "OSError", "OverflowError", "RecursionError",
              "OperationalError", "MixedRejected", "RuntimeError", "KeyboardInterrupt", "SystemExit")
    plan = [(outer, child, error) for outer, child in ((3, 2), (4, 3), (4, 2)) for error in errors]
    if type(unknown) is not list or type(foreign) is not list or len(unknown) != 30 or len(foreign) != 30:
        raise ValueError("native-build-dispatch complete nested unknown and foreign controls are absent")
    for rows, is_unknown in ((unknown, True), (foreign, False)):
        for row, (outer, child, error) in zip(rows, plan):
            modes = list(range(outer, child - 1, -1))
            events, trace = row.get("events", []), row.get("trace", [])
            case = "inputs_ordinary" if outer == 3 else "receipt_ordinary"
            if (row.get("outer_mode") != outer or row.get("failed_mode") != child
                    or row.get("injected") != error or not events or not trace
                    or any(type(event) is not dict or set(event) != {"mode", "event", "port"}
                           or any(type(event[key]) is not int for key in event)
                           or event["mode"] not in modes or event["event"] not in (0, 1, 2, 3)
                           or not 0 <= event["port"] <= len(PORTS) for event in events)
                    or [event["mode"] for event in events if event["event"] == 0] != modes
                    or any(event["port"] != 0 for event in events if event["event"] == 0)
                    or evaluation_json_bytes(trace) != evaluation_json_bytes(expected[case]["trace"][:len(trace)])):
                raise ValueError("native-build-dispatch nested identity, native event order or original trace differs")
            if is_unknown:
                port = "native_get" if child == 2 else "build_get"
                raised = error if error in ("RuntimeError", "KeyboardInterrupt", "SystemExit") else "NativeBuildAdmissionUnknown"
                if (row.get("failed_port") != port or row.get("raised") != raised
                        or row.get("active_causal_frames") != modes
                        or row.get("original_exception_or_cause_identity_retained") is not True
                        or row.get("all_causal_unknown_custody_retained") is not True
                        or row.get("no_confirmed_foreign_exception_event") is not True
                        or any(event["event"] == 3 for event in events)
                        or events[-1] != {"mode": child, "event": 2, "port": PORT[port]}):
                    raise ValueError("native-build-dispatch inner loss was confirmed or lost causal custody")
            else:
                confirmed = [event["mode"] for event in events if event["event"] == 3]
                if (row.get("same_exception_object") is not True
                        or row.get("all_causal_custody_released") is not True
                        or row.get("confirmed_frames") != list(reversed(modes))
                        or confirmed != list(reversed(modes))):
                    raise ValueError("native-build-dispatch genuine foreign exception did not unwind all owners exactly")
                for mode in modes:
                    frame_events = [event["event"] for event in events if event["mode"] == mode]
                    if (frame_events[-1] != 3 or frame_events.count(1) != frame_events.count(2) + 1):
                        raise ValueError("native-build-dispatch confirmed nested frame event accounting differs")
    return {"native_loss_cases": 30, "confirmed_foreign_exception_cases": 30,
            "outer_child_pairs": [[3, 2], [4, 3], [4, 2]],
            "all_active_ancestors_retain_unknown_without_foreign_rejection": True,
            "genuine_foreign_exception_identity_and_inner_first_confirmation_preserved": True,
            "test_bodies_rerun_by_readback": False}


def native_build_dispatch_custody(directory, root, cold_path, compiler, sources, pins):
    from tools.build_hia_native_build_admission import INPUTS, SOURCE_NAME
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    manifest = require_release_compilation(directory / "built", "native_build_admission", SOURCE_NAME,
                                          INPUTS, root, compiler, sources, pins)
    build = release_json(directory / "built/build.json", pins)
    custody = release_json(directory / "component-custody.json", pins)
    scope = "DEVELOPMENT_COMPONENT" if cold_path is None else "MATCHING_SOURCE_COLD_COMPONENT"
    facts = custody.get("runtime_protocol_facts")
    if (manifest.get("schema") != "hepta.hia.native-build-admission.v1"
            or manifest.get("source_sha256") != sources[SOURCE_NAME]
            or manifest.get("compiler_sha256") != sha(compiler)
            or build.get("schema") != "hepta.hia.native-build-admission-build.v1"
            or build.get("scope") != scope or build.get("manifest") != manifest
            or build.get("source_manifest") != (None if cold_path is None else sources)
            or build.get("cold_report_sha256") != (None if cold_path is None else sha(cold_path))
            or any(build.get(key) is not True for key in (
                "dynamic_method_and_global_lookup_preserved", "original_method_calls_enter_selected_native_child_owners",
                "active_causal_native_loss_propagated_without_exception_type_inference",
                "runtime_comprehension_protocols_observed_without_version_threshold",
                "normal_and_short_circuit_iterator_release_owned_by_hia"))
            or any(build.get(key) is not False for key in (
                "retained_four_bodies_invoked", "whole_stack_rewritten_in_hia", "all_input_equivalence_proved"))
            or build.get("retained_body_claim_scope") != "canonical selected route; explicit foreign callables remain unconstrained"
            or custody.get("schema") != "hepta.hia.native-build-dispatch-test-custody.v1"
            or custody.get("manifest") != str(manifest_path)
            or custody.get("matching_cold_report") != (None if cold_path is None else str(cold_path))
            or custody.get("compiler_sha256") != sha(compiler)
            or custody.get("source_manifest_before") != sources
            or custody.get("source_manifest_after") != sources
            or custody.get("source_and_compiler_unchanged") is not True
            or custody.get("test_result_owned_by_outer_runner") is not True
            or custody.get("canonical_and_explicit_foreign_override_scopes_distinct") is not True
            or custody.get("all_python_versions_tested") is not False
            or custody.get("all_input_equivalence_proved") is not False
            or custody.get("whole_native_delivery_qualified") is not False
            or not isinstance(custody.get("python_version"), str) or not custody["python_version"]
            or type(facts) is not dict or set(facts) != {
                "generator_reiterations", "list_reiterations", "dict_reiterations"}
            or any(type(value) is not int or not 0 <= value < 2**64 for value in facts.values())):
        raise ValueError("native-build-dispatch same-source compilation or runtime custody differs")
    return manifest, custody


def require_native_build_dispatch_component(directory, root, cold_path, compiler, sources, pins):
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    require_cold_component(manifest_path, "examples/hia_bootstrap/native_build_admission.hepta",
                           sha(cold_path), sha(compiler), sources, pins)
    manifest, custody = native_build_dispatch_custody(directory, root, cold_path, compiler, sources, pins)
    controls = native_build_dispatch_observations(directory, root, sources, pins)
    nested = native_build_dispatch_nested_losses(directory, pins)
    return {"scope": "MATCHING_SOURCE_COLD_COMPONENT", "manifest": str(manifest_path),
            "image_sha256": manifest["image_sha256"], "controls": controls,
            "nested_native_loss_controls": nested,
            "python_version": custody["python_version"],
            "runtime_protocol_facts": custody["runtime_protocol_facts"],
            "source_and_compiler_custody_verified": True,
            "test_result_owned_by_original_full_runner": True,
            "test_bodies_rerun_by_supplement": False,
            "whole_native_delivery_qualified": False, "passed": True}


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


EMISSION_ORIGINAL_DIRECTORY = "tests/fixtures/hia_emission_original_73f1634/"
EMISSION_ORIGINAL_SHA256 = {
    "hia_emission_original_oracle.py": "c2aa8bda736a211adbcfcfd156de47e576cbb348f26f4370649782016ba4b1e2",
    "original-freeze.json": "dec08c099ea1d262f1a3d32dc34801c816484bda6724fac60f5a8a1d5d8c4048",
    "hia_emission_compile_73f1634.py.txt": "5286d998c3f3bed72e217b4fb774662003c6db225352bb26c32bba30f789023d",
    "hia_emission_emit_73f1634.py.txt": "7c5968a59d591a1d056c5d1fad7b580f55c6c1032b636315df2878e2bb185679",
    "cases.json": "a4e54267dbcfebced157c2f48dd8d9680364bb03fd7104ab4f509045554bfe68",
}


def emission_original_inputs(root, sources, pins):
    documents = {}
    for filename, digest in EMISSION_ORIGINAL_SHA256.items():
        name = EMISSION_ORIGINAL_DIRECTORY + filename
        raw = release_bytes(root / name, pins)
        if hashlib.sha256(raw).hexdigest() != digest or sources.get(name) != digest:
            raise ValueError("emission independently frozen original input differs: " + name)
        documents[filename] = raw
    original = json.loads(documents["original-freeze.json"])
    cases = json.loads(documents["cases.json"])
    rows = cases.get("cases", [])
    if (original.get("schema") != "hepta.hia.emission-original-freeze.v1"
            or original.get("base_commit") != "73f16346e7f84fa13305777a4595e2d1b422dee9"
            or original.get("base_tree") != "979fcc94c1c6a045e7f6740c97d30c0fdded2dd3"
            or cases.get("candidate_execution_before_freeze") is not False
            or type(rows) is not list or len(rows) != 954
            or any(type(row) is not dict or type(row.get("name")) is not str
                   or type(row.get("mode")) is not int or row["mode"] not in (1, 2) for row in rows)
            or len({row["name"] for row in rows}) != 954):
        raise ValueError("emission complete original 954-case identity differs")
    protocol_name = "hepta/hia_emission_protocol.py"
    raw = release_bytes(root / protocol_name, pins)
    if sources.get(protocol_name) != hashlib.sha256(raw).hexdigest():
        raise ValueError("emission protocol is outside the same source custody")
    nodes = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == "PORTS" for target in node.targets)]
    if len(nodes) != 1:
        raise ValueError("emission fixed foreign-port declaration is ambiguous")
    ports = ast.literal_eval(nodes[0].value)
    if (type(ports) is not tuple or len(ports) != 84 or len(set(ports)) != 84
            or any(type(name) is not str or not name for name in ports)):
        raise ValueError("emission fixed foreign-port inventory differs")
    return original, rows, {name: index + 1 for index, name in enumerate(ports)}


def emission_custody(directory, root, cold_path, compiler, sources, pins):
    from tools.build_hia_emission import INPUTS, SOURCE_NAME
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    manifest = require_release_compilation(directory / "built", "emission", SOURCE_NAME,
                                          INPUTS, root, compiler, sources, pins)
    build = release_json(directory / "built/build.json", pins)
    custody = release_json(directory / "component-custody.json", pins)
    scope = "DEVELOPMENT_COMPONENT" if cold_path is None else "MATCHING_SOURCE_COLD_COMPONENT"
    causal_scope = "active same-process same-thread EmissionFrame ancestors"
    facts = custody.get("runtime_protocol_facts", {})
    if (manifest.get("schema") != "hepta.hia.emission-native.v1"
            or manifest.get("source_sha256") != sources[SOURCE_NAME]
            or manifest.get("compiler_sha256") != sha(compiler)
            or manifest.get("image_sha256") != hashlib.sha256(release_bytes(manifest_path.parent / manifest["image_path"], pins)).hexdigest()
            or build.get("schema") != "hepta.hia.emission-build.v1"
            or build.get("scope") != scope or build.get("manifest") != manifest
            or build.get("source_manifest") != (None if cold_path is None else sources)
            or build.get("cold_report_sha256") != (None if cold_path is None else sha(cold_path))
            or any(build.get(key) is not True for key in (
                "two_complete_original_control_methods_owned_by_hia",
                "control_branches_loops_and_cleanup_continuations_owned_by_hia",
                "core_emitter_linker_store_filesystem_clock_hash_providers_hosted",
                "foreign_object_and_numeric_protocols_hosted",
                "dynamic_compile_lookup_and_keyword_presence_preserved",
                "runtime_context_and_comprehension_facts_observed_without_version_threshold",
                "active_exception_context_preserved_during_native_issued_cleanup",
                "active_causal_native_loss_propagated_without_exception_type_inference"))
            or build.get("retained_body_claim_scope") != "canonical selected route; explicit foreign callables remain unconstrained"
            or build.get("causal_native_loss_scope") != "active same-process same-thread integrated D0-D3 invocation ancestors"
            or build.get("cross_owner_native_delivery_loss_tracking_implemented") is not True
            or build.get("remaining_store_artifact_profile_and_D5_owners_integrated") is not False
            or any(build.get(key) is not False for key in (
                "retained_two_bodies_invoked", "whole_stack_rewritten_in_hia", "all_input_equivalence_proved",
                "all_python_versions_tested"))
            or custody.get("schema") != "hepta.hia.emission-test-custody.v1"
            or custody.get("manifest") != str(manifest_path)
            or custody.get("matching_cold_report") != (None if cold_path is None else str(cold_path))
            or custody.get("compiler_sha256") != sha(compiler)
            or custody.get("source_manifest_before") != sources or custody.get("source_manifest_after") != sources
            or custody.get("source_and_compiler_unchanged") is not True
            or custody.get("test_result_owned_by_outer_runner") is not True
            or custody.get("canonical_and_explicit_foreign_override_scopes_distinct") is not True
            or custody.get("causal_native_loss_scope") != causal_scope
            or any(custody.get(key) is not False for key in (
                "all_python_versions_tested", "all_input_equivalence_proved", "whole_native_delivery_qualified",
                "cross_owner_native_delivery_loss_tracking_implemented"))
            or type(custody.get("python_version")) is not str or not custody["python_version"]
            or (cold_path is not None and custody["python_version"] != sys.version)
            or type(facts) is not dict or set(facts) != {"context_lookup_order", "generator_reiterations"}
            or facts.get("context_lookup_order") not in ([1, 2], [2, 1])
            or any(type(value) is not int for value in facts["context_lookup_order"])
            or type(facts.get("generator_reiterations")) is not int or facts["generator_reiterations"] < 0):
        raise ValueError("emission first-full build, causal scope or source/compiler custody differs")
    return manifest, custody


def emission_observation_rows(path, names, modes, pins, originals=None):
    records = release_json(path, pins)
    if (type(records) is not list or [row.get("case") for row in records] != names
            or len(names) != len(set(names))):
        raise ValueError("emission complete ordered observation inventory differs")
    result = {}
    for row in records:
        if (set(row) != {"case", "expected", "actual"}
                or row["expected"].get("name") != row["case"]
                or type(row["expected"].get("mode")) is not int
                or row["expected"]["mode"] != modes[row["case"]]
                or evaluation_json_bytes(row["expected"]) != evaluation_json_bytes(row["actual"])
                or (originals is not None and evaluation_json_bytes(row["expected"])
                    != evaluation_json_bytes(originals[row["case"]]))):
            raise ValueError("emission original full trace, return alias or exception differs")
        result[row["case"]] = row["expected"]
    return result


def emission_events(events, modes, ports):
    if type(events) is not list or not events:
        raise ValueError("emission native event trace is absent")
    pending, opened = {}, []
    for row in events:
        if (type(row) is not dict or set(row) != {"mode", "event", "port"}
                or any(type(value) is not int for value in row.values())
                or row["mode"] not in modes or row["event"] not in range(4)
                or row["port"] not in ({0} if row["event"] == 0 else set(ports.values()))):
            raise ValueError("emission native event type, mode or port differs")
        mode, event, port = row["mode"], row["event"], row["port"]
        if event == 0:
            if mode in pending:
                raise ValueError("emission failure control has a duplicate frame initialization")
            pending[mode] = None
            opened.append(mode)
        elif mode not in pending:
            raise ValueError("emission event precedes its frame initialization")
        elif event == 1:
            if pending[mode] is not None:
                raise ValueError("emission claimed a second effect before acknowledging the first")
            pending[mode] = port
        else:
            if pending[mode] != port:
                raise ValueError("emission acknowledgement differs from its claimed effect")
            pending[mode] = None
    if opened != modes:
        raise ValueError("emission causal initialization order differs")
    return pending


def emission_control_observations(directory, root, sources, pins):
    directory = Path(directory)
    _, cases, ports = emission_original_inputs(root, sources, pins)
    names = [row["name"] for row in cases]
    modes = {row["name"]: row["mode"] for row in cases}
    complete = directory / "test_954_independent_original_provider_and_cleanup_observations"
    expected = emission_observation_rows(complete / "complete-observations.json", names, modes, pins)
    counts = release_json(complete / "entry-counts.json", pins)
    if (type(counts) is not dict or set(counts) != {"event_0", "event_1", "event_2", "event_3", "mode_1", "mode_2"}
            or any(type(value) is not int or value <= 0 for value in counts.values())
            or counts["mode_1"] != 431 or counts["mode_2"] != 649 or counts["event_0"] != 1080
            or counts["event_1"] != counts["event_2"] + counts["event_3"]):
        raise ValueError("emission complete 954-case actual frame/event accounting differs")
    vm_names = ["compile.object", "compile.with.compile_failure_exit_bare_raise",
                "compile.with.read_failure_suppressed", "emit.plan", "composed.plan_exports_receipts",
                "composed.override_after_binding"]
    vm = directory / "test_actual_native_full_buffers_match_independent_VM"
    emission_observation_rows(vm / "vm-native-observations.json", vm_names, modes, pins, expected)
    vm_counts = release_json(vm / "vm-native-entry-counts.json", pins)
    if vm_counts != {"continuation": 512} or type(vm_counts.get("continuation")) is not int:
        raise ValueError("emission original six full-buffer VM comparisons differ")
    public = directory / "test_public_canonical_routes_preserve_overrides_without_retained_fallback"
    public_names = ["compile.shared", "compile.object", "emit.canonical", "emit.plan", "composed.canonical",
                    "composed.override_before_binding", "composed.override_after_binding"]
    emission_observation_rows(public / "public-observations.json", public_names, modes, pins, expected)
    original_manifest = release_bytes(directory / "built/manifest.json", pins)
    original_image_name = json.loads(original_manifest)["image_path"]
    if (release_bytes(public / "manifest.json", pins) != original_manifest
            or release_bytes(public / original_image_name, pins)
                != release_bytes(directory / "built" / original_image_name, pins) + b"\0"):
        raise ValueError("emission explicit image-drift control is not the original one-NUL mutation")
    protocol = release_json(directory / "test_owner_thread_and_forged_receipt_refuse_before_foreign_effects/protocol-observations.json", pins)
    if (set(protocol) != {"foreign_thread_refused_before_effect", "forged_initial_receipt_refused_before_effect",
                         "no_new_unknown_effect_custody"} or any(value is not True for value in protocol.values())):
        raise ValueError("emission owner-thread or initial-receipt control differs")
    errors = ("ValueError", "TypeError", "OSError", "OverflowError", "RecursionError", "OperationalError",
              "MixedRejected", "RuntimeError", "KeyboardInterrupt", "SystemExit")
    plans = (("compile.shared", "compile_call"), ("compile.shared", "compile_read"),
             ("compile.shared", "compile_exit_normal"), ("compile.shared", "compile_store_object"),
             ("compile.with.compile_failure_unsuppressed", "compile_exit_exception"),
             ("emit.canonical", "emit_native_put"), ("emit.canonical", "emit_receipt_put"))
    location = directory / "test_lost_ACK_preserves_effects_and_foreign_errors_follow_original_cleanup"
    unknown = release_json(location / "native-loss.json", pins)
    foreign = release_json(location / "confirmed-foreign.json", pins)
    if type(unknown) is not list or len(unknown) != 70 or type(foreign) is not list or len(foreign) != 60:
        raise ValueError("emission complete 70 native-loss and 60 foreign controls are absent")
    for row, (name, port, error) in zip(unknown, ((name, port, error) for name, port in plans for error in errors)):
        events, trace = row.get("events", []), row.get("trace", [])
        emission_events(events, [modes[name]], ports)
        raised = error if error in ("RuntimeError", "KeyboardInterrupt", "SystemExit") else "EmissionUnknown"
        if (row.get("case") != name or row.get("port") != port or row.get("injected") != error
                or row.get("raised") != raised or events[-1] != {"mode": modes[name], "event": 2, "port": ports[port]}
                or any(row.get(key) is not True for key in ("original_exception_or_cause_identity_retained",
                    "unknown_custody_retained", "no_replay_or_cleanup_after_loss"))
                or not trace or evaluation_json_bytes(trace) != evaluation_json_bytes(expected[name]["trace"][:len(trace)])
                or evaluation_json_bytes(row.get("store_effects"))
                    != evaluation_json_bytes(expected[name]["store_effects"][:len(row.get("store_effects", []))])):
            raise ValueError("emission lost native ACK was confirmed, replayed or changed its actual effect prefix")
        temporaries = row.get("temporaries", [])
        if port in ("compile_call", "compile_read") and temporaries != [{"entered": True, "exited": False, "exit_calls": 0}]:
            raise ValueError("emission lost body ACK invented temporary-directory cleanup")
    foreign_plans = [(name, port, error) for name, port in plans if port != "compile_exit_exception" for error in errors]
    for row, (name, port, error) in zip(foreign, foreign_plans):
        events = row.get("events", [])
        pending = emission_events(events, [modes[name]], ports)
        if (row.get("case") != name or row.get("port") != port or row.get("injected") != error
                or any(value is not None for value in pending.values())
                or [event["port"] for event in events if event["event"] == 3] != [ports[port]]
                or any(row.get(key) is not True for key in (
                    "same_exception_object", "confirmed_custody_released", "original_cleanup_completed"))):
            raise ValueError("emission confirmed foreign exception lost identity, cleanup or acknowledgement")
    nested = emission_nested_observations(directory, expected["composed.canonical"], ports, errors, pins)
    return {"original_complete_cases": 954, "actual_native_counts": counts,
            "canonical_full_trace_alias_and_exception_comparison": True,
            "original_independent_VM_cases": 6, "actual_VM_native_entry_counts": vm_counts,
            "VM_output_and_state_buffer_comparison_owned_by_original_full_test": True,
            "raw_VM_buffers_separately_retained": False,
            "public_default_and_override_cases": 7, "invalid_selectors_and_scope_refusal_owned_by_full_test": True,
            "post_effect_native_loss_cases": 70, "confirmed_foreign_exception_cases": 60,
            "same_owner_nested_observations": nested, "protocol_observations": protocol,
            "cross_owner_native_delivery_loss_tracking_implemented": False,
            "test_bodies_rerun_by_readback": False}


def emission_nested_observations(directory, expected, ports, errors, pins):
    location = Path(directory) / "test_nested_compile_native_loss_fences_ancestors_and_foreign_errors_confirm"
    unknown = release_json(location / "nested-native-loss.json", pins)
    foreign = release_json(location / "nested-confirmed-foreign.json", pins)
    plans = [(port, error) for port in ("compile_call", "compile_exit_normal", "compile_store_object") for error in errors]
    if type(unknown) is not list or type(foreign) is not list or len(unknown) != 30 or len(foreign) != 30:
        raise ValueError("emission complete nested 30 native-loss and 30 foreign controls are absent")
    for row, (port, error) in zip(unknown, plans):
        events, trace = row.get("events", []), row.get("trace", [])
        emission_events(events, [2, 1], ports)
        raised = error if error in ("RuntimeError", "KeyboardInterrupt", "SystemExit") else "EmissionUnknown"
        message = ("nested compile boundary failure" if raised == error
                   else "native emission continuation observation failed")
        unwind = {"event": "raise", "index": 1, "operation": "service._compile.call.original",
                  "error": {"exception": raised, "args": {"tuple": [message]}}}
        if (row.get("port") != port or row.get("injected") != error or row.get("raised") != raised
                or row.get("active_causal_frames") != [2, 1]
                or events[-1] != {"mode": 1, "event": 2, "port": ports[port]}
                or any(event["event"] == 3 for event in events)
                or any(row.get(key) is not True for key in ("original_exception_or_cause_identity_retained",
                    "all_causal_unknown_custody_retained", "no_replay_after_loss"))
                or not trace or evaluation_json_bytes(trace[-1]) != evaluation_json_bytes(unwind)
                or evaluation_json_bytes(trace[:-1]) != evaluation_json_bytes(expected["trace"][:len(trace) - 1])
                or evaluation_json_bytes(row.get("store_effects"))
                    != evaluation_json_bytes(expected["store_effects"][:len(row.get("store_effects", []))])):
            raise ValueError("emission nested native loss failed to retain both same-owner ancestors")
    for row, (port, error) in zip(foreign, plans):
        events = row.get("events", [])
        pending = emission_events(events, [2, 1], ports)
        if (row.get("port") != port or row.get("injected") != error
                or row.get("confirmed_frames") != [1, 2]
                or [event["mode"] for event in events if event["event"] == 3] != [1, 2]
                or any(value is not None for value in pending.values())
                or row.get("same_exception_object") is not True or row.get("all_causal_custody_released") is not True):
            raise ValueError("emission nested genuine foreign exception was misclassified or retained")
    return {"native_loss_cases": 30, "confirmed_foreign_cases": 30,
            "same_owner_causal_frames": [2, 1], "cross_owner_native_delivery_loss_tracking_implemented": False,
            "original_effect_prefix_and_exact_observed_outer_call_unwind": True,
            "test_bodies_rerun_by_readback": False}


def emission_wheel(location, sources, observation, pins):
    wheels = sorted((location / "wheels").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("emission needs the one actual installed wheel")
    wheel = wheels[0]
    files, distribution = release_wheel(wheel, pins)
    source_python = {name for name in sources if name.startswith("hepta/") and name.endswith(".py")}
    if not source_python <= set(files):
        raise ValueError("emission wheel omitted production Python source")
    for name, raw in files.items():
        if name.startswith("hepta/"):
            source_name = name.removeprefix("hepta/_data/") if name.startswith("hepta/_data/") else name
            if sources.get(source_name) != hashlib.sha256(raw).hexdigest():
                raise ValueError("emission wheel has unbound production bytes")
        elif not name.startswith(distribution + "/"):
            raise ValueError("emission wheel has unexpected members")
    installed, actual = location / "installed", {}
    for path in sorted(installed.rglob("*")):
        if path.is_symlink():
            raise ValueError("emission installed file is a symlink")
        if path.is_file():
            actual[path.relative_to(installed).as_posix()] = release_bytes(path, pins)
    record = distribution + "/RECORD"
    member = "hepta/_data/examples/hia_bootstrap/emission.hepta"
    extras = {"bin/hia", *(distribution + "/" + name for name in ("INSTALLER", "REQUESTED", "direct_url.json"))}
    if (set(actual) != set(files) | extras or member not in files
            or any(actual.get(name) != raw for name, raw in files.items() if name not in (record, member))
            or actual.get(member) != files[member] + b"\n"):
        raise ValueError("emission installation differs beyond its exact one-LF control")
    recorded = dict(actual)
    recorded[member] = files[member]
    require_release_record(recorded, record, installed=True)
    origin = json.loads(actual[distribution + "/direct_url.json"])
    drift = observation.get("installed_source_drift", {})
    if (origin.get("url") != wheel.as_uri()
            or origin.get("archive_info", {}).get("hashes", {}).get("sha256") != pins[str(wheel)]
            or observation.get("wheel") != str(wheel) or observation.get("wheel_sha256") != pins[str(wheel)]
            or drift.get("before_sha256") != sources["examples/hia_bootstrap/emission.hepta"]
            or drift["before_sha256"] != hashlib.sha256(files[member]).hexdigest()
            or drift.get("after_sha256") != hashlib.sha256(actual[member]).hexdigest()):
        raise ValueError("emission installed wheel origin or source drift differs")
    return files, {"wheel": str(wheel), "wheel_sha256": pins[str(wheel)], "actual_wheel_members": len(files),
        "actual_installed_files": len(actual), "all_other_product_bytes_equal_wheel": True,
        "installed_RECORD_checked_against_exact_pre_drift_bytes": True,
        "only_intentional_installed_mutation": {"member": member, "change": "append exactly one LF",
            "before_sha256": drift["before_sha256"], "after_sha256": drift["after_sha256"]}}


def emission_worker_counts(raw):
    prefix = b"EMISSION_COUNTS="
    found = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    if len(found) != 1:
        raise ValueError("emission worker has no unique original count marker")
    counts = json.loads(found[0])
    if (type(counts) is not dict
            or set(counts) != {"frames", "entries", "modes", "native_publications", "unknown_frames"}
            or any(type(counts[key]) is not int or counts[key] < 0
                   for key in ("frames", "entries", "native_publications", "unknown_frames"))
            or type(counts["modes"]) is not dict or not set(counts["modes"]) <= {"1", "2"}
            or any(type(value) is not int or value <= 0 for value in counts["modes"].values())
            or sum(counts["modes"].values()) != counts["frames"]):
        raise ValueError("emission worker native count shape differs")
    return counts


def emission_worker_streams(location, worker_sha, catalog_sha, bundle_sha, version, pins):
    names = ("wheel", "install", "first", "replay", "native_ack", "native_ack-replay",
             "process_loss", "process_loss-replay", "changed-installed-source")
    logs = {name: {suffix: release_bytes(location / (name + "." + suffix), pins)
                  for suffix in ("stdout", "stderr")} for name in names}
    counts = {name: emission_worker_counts(logs[name]["stderr"]) for name in names[2:]}
    zero = {"frames": 0, "entries": 0, "modes": {}, "native_publications": 0, "unknown_frames": 0}
    if (counts["first"] != {"frames": 2, "entries": 116, "modes": {"1": 1, "2": 1},
                            "native_publications": 1, "unknown_frames": 0}
            or any(counts[name] != zero for name in ("replay", "native_ack-replay", "process_loss-replay",
                                                    "changed-installed-source"))):
        raise ValueError("emission original installed route or zero-entry replay differs")
    for name, entries in (("native_ack", 112), ("process_loss", 111)):
        if (counts[name] != {"frames": 2, "entries": entries, "modes": {"1": 1, "2": 1},
                             "native_publications": 1, "unknown_frames": 1}
                or logs[name]["stdout"]):
            raise ValueError("emission actual lost worker did not retain the unfinished publication")
    if (b"ValueError: controlled lost native publication acknowledgement" not in logs["native_ack"]["stderr"]
            or b"EmissionUnknown" not in logs["native_ack"]["stderr"]
            or logs["changed-installed-source"]["stdout"]):
        raise ValueError("emission actual lost acknowledgement or source-drift streams differ")
    reports = {name: json.loads(logs[name]["stdout"]) for name in (
        "first", "replay", "native_ack-replay", "process_loss-replay")}
    for report in reports.values():
        if (report.get("schema") != "hia-agent-worker-report-v1" or report.get("tool") != "hia_emit"
                or report.get("complete") is not True or report.get("worker_sha256") != worker_sha
                or report.get("catalog_sha256") != catalog_sha or report.get("native_helpers_sha256") != bundle_sha
                or report.get("profile_sha256") != "a" * 64
                or report.get("response", {}).get("contract_version") != version
                or re.fullmatch(r"[0-9a-f]{64}", str(report.get("request_sha256"))) is None
                or re.fullmatch(r"[0-9a-f]{64}", str(report.get("backend_sha256"))) is None):
            raise ValueError("emission installed worker or request identity differs")
    if (evaluation_json_bytes(reports["first"]) != evaluation_json_bytes(reports["replay"])
            or len({reports[name]["request_sha256"] for name in ("first", "native_ack-replay", "process_loss-replay")}) != 3
            or len({report["backend_sha256"] for report in reports.values()}) != 1):
        raise ValueError("emission installed replay identities are inconsistent")
    return reports, counts


def emission_retained_state(state):
    if (type(state) is not dict or set(state) != {"request", "artifact_kinds", "artifacts", "costs"}
            or state["request"] is not None and type(state["request"]) is not dict
            or type(state["artifact_kinds"]) is not dict or type(state["artifacts"]) is not list
            or type(state["costs"]) is not int or state["costs"] < 0
            or any(type(key) is not str or type(value) is not int or value <= 0
                   for key, value in state["artifact_kinds"].items())):
        raise ValueError("emission retained journal/artifact/cost observation shape differs")
    ids, kinds = [], {}
    for row in state["artifacts"]:
        if (type(row) is not dict or set(row) != {"id", "uri", "sha256", "content_key", "kind", "metadata"}
                or any(type(value) is not str for value in row.values())
                or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None):
            raise ValueError("emission complete retained artifact row differs")
        ids.append(row["id"])
        kinds[row["kind"]] = kinds.get(row["kind"], 0) + 1
    if ids != sorted(ids) or len(ids) != len(set(ids)) or kinds != state["artifact_kinds"]:
        raise ValueError("emission retained artifact row inventory differs from its kind counts")
    return state


def emission_publication_delta(before, after, kinds):
    emission_retained_state(before)
    emission_retained_state(after)
    if before["request"] is not None:
        raise ValueError("emission publication control already had a request intent")
    old = {row["id"]: row for row in before["artifacts"]}
    new = {row["id"]: row for row in after["artifacts"]}
    if any(evaluation_json_bytes(row) != evaluation_json_bytes(new.get(identity)) for identity, row in old.items()):
        raise ValueError("emission publication changed a previously retained artifact")
    for kind, amount in kinds.items():
        if after["artifact_kinds"].get(kind, 0) - before["artifact_kinds"].get(kind, 0) != amount:
            raise ValueError("emission observed publication count differs: " + kind)


def emission_worker_journals(observation, reports, counts):
    for name in ("first", "replay"):
        row = observation.get(name, {})
        if (evaluation_json_bytes(row.get("report")) != evaluation_json_bytes(reports[name])
                or evaluation_json_bytes(row.get("counts")) != evaluation_json_bytes(counts[name])):
            raise ValueError("emission installed observation differs from actual worker streams")
    first = reports["first"].get("response", {})
    result = first.get("result", {})
    if (first.get("status") != "completed" or result.get("linker_used") is not True
            or result.get("adopted") is not False or result.get("codegen_backend") != "hia-direct"
            or any(result.get(key) is not False for key in (
                "external_assembler_used", "llvm_codegen_used", "native_execution_observed"))):
        raise ValueError("emission installed original publication response differs")
    replay = observation.get("replay", {})
    retained = emission_retained_state(replay.get("retained_before"))
    request = retained["request"] or {}
    emission_retained_state(replay.get("retained_after"))
    if (request.get("tool") != "hia_emit" or request.get("state") != "completed"
            or first.get("request_id") != "r-" + str(request.get("digest"))
            or type(request.get("response")) is not str
            or evaluation_json_bytes(json.loads(request["response"])) != evaluation_json_bytes(first)
            or evaluation_json_bytes(retained) != evaluation_json_bytes(replay.get("retained_after"))
            or evaluation_json_bytes(observation["first"].get("retained_after")) != evaluation_json_bytes(retained)):
        raise ValueError("emission normal replay changed its complete retained observation")
    emission_publication_delta(observation["first"].get("retained_before"), retained,
                               {"build-object": 1, "native": 1, "build-receipt": 1})
    for key, kind in (("native_artifact", "native"), ("build_receipt", "build-receipt")):
        reference = result.get(key, {})
        rows = [row for row in retained["artifacts"] if row["id"] == reference.get("id")]
        if len(rows) != 1 or rows[0]["kind"] != kind or any(rows[0][name] != reference.get(name) for name in ("id", "uri", "sha256")):
            raise ValueError("emission response publication is absent from actual retained artifact rows")
    journals = {}
    for name, code in (("native_ack", 1), ("process_loss", 73)):
        row = observation.get(name, {})
        before = emission_retained_state(row.get("retained_before_replay"))
        after = emission_retained_state(row.get("retained_after_replay"))
        report, request = reports[name + "-replay"], before["request"] or {}
        emission_publication_delta(row.get("retained_before_attempt"), before,
                                   {"build-object": 1, "native": 1, "build-receipt": 0})
        if (type(row.get("lost_worker_exit_code")) is not int or row["lost_worker_exit_code"] != code
                or evaluation_json_bytes(row.get("native_counts")) != evaluation_json_bytes(counts[name])
                or evaluation_json_bytes(row.get("replay_counts")) != evaluation_json_bytes(counts[name + "-replay"])
                or evaluation_json_bytes(row.get("replay")) != evaluation_json_bytes(report)
                or report.get("response", {}).get("status") != "rejected"
                or report["response"].get("error", {}).get("code") != "E_HIA_REQUEST_UNKNOWN"
                or request.get("state") != "running" or request.get("response") is not None
                or request.get("tool") != "hia_emit"
                or report["response"].get("request_id") != "r-" + str(request.get("digest"))
                or evaluation_json_bytes(request) != evaluation_json_bytes(after["request"])
                or evaluation_json_bytes(before["artifacts"]) != evaluation_json_bytes(after["artifacts"])):
            raise ValueError("emission unknown publication was completed, replayed or lost its retained artifacts")
        journals[name] = request
    drift = observation.get("installed_source_drift", {})
    if (type(drift.get("worker_exit_code")) is not int or drift["worker_exit_code"] != 2
            or evaluation_json_bytes(drift.get("native_counts")) != evaluation_json_bytes(counts["changed-installed-source"])):
        raise ValueError("emission installed source drift did not reject before native execution")
    return journals


def require_emission_installation(directory, sources, manifest, pins):
    from hepta import hia_agent_contract as contract
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    directory = Path(directory)
    location = directory / "test_actual_installed_worker_publication_loss_replay_and_source_pinning"
    observation = release_json(location / "installed-observations.json", pins)
    files, installation = emission_wheel(location, sources, observation, pins)
    manifest_path = directory / "built/manifest.json"
    manifest_raw = release_bytes(manifest_path, pins)
    image = release_bytes(manifest_path.parent / manifest["image_path"], pins)
    bundle_path = location / "bundle.json"
    bundle = release_json(bundle_path, pins)
    bundle_sha = pins[str(bundle_path)]
    if (json.loads(manifest_raw) != manifest or manifest.get("schema") != "hepta.hia.emission-native.v1"
            or manifest.get("source_sha256") != sources["examples/hia_bootstrap/emission.hepta"]
            or manifest.get("image_sha256") != hashlib.sha256(image).hexdigest()
            or bundle != {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
                "selector": "HEPTA_HIA_EMISSION_MANIFEST", "manifest_path": str(manifest_path),
                "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}]}
            or observation.get("bundle_sha256") != bundle_sha
            or any(observation.get(key) is not True for key in (
                "both_references_forbidden_in_actual_child", "authoring_imports_forbidden_in_actual_child", "original_worker_used"))
            or observation.get("qualification_topology") != "fresh-wheel actual installed worker with emission helper"
            or observation.get("whole_native_delivery_qualified") is not False):
        raise ValueError("emission actual installed child bundle or observed scope differs")
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
    reports, counts = emission_worker_streams(location, worker_sha,
        entries["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"], bundle_sha, contract.VERSION, pins)
    journals = emission_worker_journals(observation, reports, counts)
    return {**installation, "worker_identity_derived_from_actual_wheel": worker_sha,
            "actual_native_counts_from_original_stderr": counts, "retained_unknown_request_rows": journals,
            "actual_process_loss_exit_code": 73, "actual_native_ack_failure_exit_code": 1,
            "normal_and_unknown_replay_native_entries": 0,
            "normal_replay_complete_retained_observation_preserved": True,
            "unknown_replay_request_and_artifact_rows_preserved": True,
            "retained_database_snapshot_scope": "original complete method serialized rows; temporary database removed after test",
            "raw_request_envelopes_separately_retained": False,
            "qualification_topology": "fresh-wheel actual installed worker with emission helper",
            "installed_eight_owner_worker_observed": False,
            "cross_owner_native_delivery_loss_tracking_implemented": False,
            "test_bodies_rerun_by_readback": False, "whole_native_delivery_qualified": False}



def emission_composition_observations(directory, expected_scope, pins):
    report = release_json(Path(directory) / "composition.json", pins)
    selectors = {"HEPTA_HIA_" + name + "_MANIFEST" for name in (
        "STORE_LIFECYCLE", "SERVICE_CONTEXT", "EXECUTION_BUDGET", "CANDIDATE_BUDGET", "COST_LEDGER", "EVALUATION", "NATIVE_BUILD_ADMISSION", "EMISSION")}
    counts = report.get("actual_native_entries", {})
    before, after, delta = (report.get(key, {}) for key in (
        "entries_before_replay", "entries_after_replay", "replay_additional_entries"))
    if (report.get("schema") != "hepta.hia.emission-eight-owner-composition.v1"
            or report.get("qualification_topology") != "source-process eight-owner public composition"
            or report.get("installed_eight_owner_worker_observed") is not False
            or report.get("cross_owner_native_delivery_loss_tracking_implemented") is not False
            or report.get("scope") != expected_scope or report.get("original_context_wall_ms") != 3000
            or report.get("original_native_wall_ms") != 1000
            or any(type(row) is not dict or set(row) != selectors for row in (counts, before, after, delta))
            or any(type(value) is not int or value <= 0 for row in (counts, before, after) for value in row.values())
            or any(type(value) is not int or value != 0 for value in delta.values())
            or before != after or any(counts[key] < after[key] for key in selectors)
            or report.get("durable_changes_on_replay") != 0 or type(report.get("durable_changes_on_replay")) is not int
            or report.get("reference_calls") != []
            or any(report.get(key) is not True for key in (
                "all_eight_retained_policy_references_forbidden", "all_four_admission_retained_bodies_forbidden",
                "both_emission_retained_bodies_forbidden",
                "hosted_request_journal_sqlite_runner_and_object_protocols_retained",
                "source_and_compiler_custody_owned_by_outer_component"))
            or report.get("whole_native_delivery_qualified") is not False):
        raise ValueError("emission eight-owner composition or exact native replay differs")
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
        raise ValueError("emission composed public response or replay differs")
    adoption_before, adoption_after, adoption_delta = (report.get(key, {}) for key in (
        "adoption_entries_before_replay", "adoption_entries_after_replay", "adoption_replay_additional_entries"))
    if (any(type(row) is not dict or set(row) != selectors for row in (adoption_before, adoption_after, adoption_delta))
            or any(type(value) is not int or value <= 0 for row in (adoption_before, adoption_after) for value in row.values())
            or any(type(value) is not int or value != 0 for value in adoption_delta.values())
            or adoption_before != adoption_after or any(counts[key] < adoption_after[key] for key in selectors)
            or type(report.get("adoption_durable_changes_on_replay")) is not int
            or report["adoption_durable_changes_on_replay"] != 0):
        raise ValueError("emission composed adoption replay native or durable delta differs")
    for arm in ("baseline", "candidate"):
        emitted = report.get(arm + "_emission", {})
        if (emitted.get("linker_used") is not True or emitted.get("adopted") is not False
                or evaluation_json_bytes(emitted.get("native_artifact")) != evaluation_json_bytes(result.get(arm + "_artifact"))):
            raise ValueError("emission composed evaluation does not use its actual emitted artifact")
    documents = {"measurements": report.get("measurements", {}), "full_cost_ledger": report.get("ledger", {}),
                 "evaluation_receipt": report.get("evaluation_receipt", {})}
    for name, value in documents.items():
        if result.get(name, {}).get("sha256") != hashlib.sha256(evaluation_json_bytes(value)).hexdigest():
            raise ValueError("emission composed artifact body differs from its actual reference: " + name)
    measurement, ledger, receipt = (documents[name] for name in ("measurements", "full_cost_ledger", "evaluation_receipt"))
    if (type(measurement.get("planned_cases")) is not int or measurement.get("planned_cases") != 1 or len(measurement.get("observations", [])) != 1
            or measurement.get("planned_workload_complete") is not True
            or measurement.get("universal_equivalence_or_native_refinement_proved") is not False
            or ledger.get("full_search_cost_complete") is not False or ledger.get("net_optimization_benefit_proved") is not False
            or ledger.get("context") != measurement.get("context") or receipt.get("context") != ledger.get("context")
            or receipt.get("candidate_artifact") != result.get("candidate_artifact")
            or receipt.get("measurements") != result["measurements"]
            or receipt.get("full_cost_ledger") != result["full_cost_ledger"]):
        raise ValueError("emission composed artifact contracts or cross-references differ")
    for arm in ("baseline", "candidate"):
        run = measurement.get("native_runs", {}).get(arm, {}).get("normal", {})
        if run.get("started") is not True or run.get("termination_confirmed") is not True or run.get("status") != "returned":
            raise ValueError("emission composed native runner was not actually completed")
    budget = report.get("budget_before_replay", {})
    if (set(budget) != {"context_id", "owner", "used_native_ns"} or budget.get("owner") is not None
            or budget.get("context_id") != ledger.get("context", {}).get("id")
            or type(budget.get("used_native_ns")) is not str or re.fullmatch(r"[1-9][0-9]*", budget["used_native_ns"]) is None
            or budget["used_native_ns"] != ledger.get("native_child_wall_ns")
            or evaluation_json_bytes(budget) != evaluation_json_bytes(report.get("budget_after_replay"))):
        raise ValueError("emission composed native budget was not confirmed and preserved on replay")
    return report


def emission_event_accounting(report, planned):
    frames = report.get("actual_emission_frames")
    events = report.get("actual_native_event_counts", {})
    modes = report.get("frames_by_mode", {})
    allowed = {"continuation:" + str(event) for event in range(4)}
    mandatory = allowed - {"continuation:3"}
    if (type(frames) is not int or frames <= 0 or type(events) is not dict
            or not mandatory <= set(events) <= allowed
            or any(type(value) is not int or value <= 0 for value in events.values())
            or events["continuation:0"] != frames
            or events["continuation:1"] != events["continuation:2"] + events.get("continuation:3", 0)
            or type(modes) is not dict or set(modes) != {"1", "2"}
            or any(type(value) is not int or value <= 0 for value in modes.values())
            or sum(modes.values()) != frames):
        raise ValueError("emission actual frame, mode or native event observations differ")
    frame_rows = report.get("frames_by_original_test", {})
    event_rows = report.get("native_event_counts_by_original_test", {})
    if (type(frame_rows) is not dict or not set(frame_rows) <= set(planned)
            or any(type(value) is not int or value <= 0 for value in frame_rows.values())
            or sum(frame_rows.values()) != frames or type(event_rows) is not dict
            or set(event_rows) != set(frame_rows)):
        raise ValueError("emission frame counts lack original caller identities")
    totals = {}
    for identity, row in event_rows.items():
        if (type(row) is not dict or not set(row) <= allowed
                or any(type(value) is not int or value <= 0 for value in row.values())
                or row.get("continuation:0", 0) != frame_rows[identity]
                or row.get("continuation:1", 0) != row.get("continuation:2", 0) + row.get("continuation:3", 0)):
            raise ValueError("emission per-method native event accounting differs")
        for key, value in row.items():
            totals[key] = totals.get(key, 0) + value
    if totals != events:
        raise ValueError("emission aggregate entries differ from per-test observations")
    return frames, events


def require_emission_callers(directory, root, sources, discovery, manifest_path, pins):
    from tools.qualify_hia_emission_callers import FIXTURE_NAME
    from tools.build_hia_emission import INPUTS, SOURCE_NAME
    from tools.hia_selfhost_contract import file_digests
    directory, manifest_path = Path(directory), Path(manifest_path)
    manifest = release_json(manifest_path, pins)
    build = release_json(manifest_path.with_name("build.json"), pins)
    report = release_json(directory / "report.json", pins)
    original, original_files, adjustments, descriptions, planned = emission_original_inventory(
        root, sources, discovery, pins)
    names = set(file_digests(root)) | {*INPUTS, *original_files, FIXTURE_NAME,
                                      "tools/qualify_hia_emission_callers.py"}
    source_pins = {name: hashlib.sha256(release_bytes(root / name, pins)).hexdigest() for name in names}
    bundle_pins = {}
    for path in sorted(manifest_path.parent.rglob("*")):
        if path.is_symlink():
            raise ValueError("emission caller build contains a symlink")
        if path.is_file():
            bundle_pins[str(path)] = hashlib.sha256(release_bytes(path, pins)).hexdigest()
    scopes = {"MATCHING_SOURCE_COLD_NINE_ORDINARY_EMISSION_CALLER_MODULES",
              "EXPLICIT_DEVELOPMENT_NINE_ORDINARY_EMISSION_CALLER_MODULES"}
    expected_build_scope = ("MATCHING_SOURCE_COLD_COMPONENT" if report.get("scope", "").startswith("MATCHING_SOURCE_COLD_")
                            else "DEVELOPMENT_COMPONENT")
    if (report.get("schema") != "hepta.hia.emission-nine-ordinary-callers.v1"
            or report.get("status") != "PASS" or report.get("scope") not in scopes
            or build.get("scope") != expected_build_scope
            or report.get("original_baseline_commit") != original["base_commit"]
            or report.get("original_modules") != original["ordinary_modules"]
            or not (report.get("planned") == report.get("started") == report.get("stopped") == planned)
            or type(report.get("actual_tests")) is not int or report["actual_tests"] != 112
            or any(report.get(key) != [] for key in (
                "errors", "failures", "skipped", "expected_failures", "unexpected_successes", "reference_calls"))
            or report.get("both_retained_bodies_forbidden") is not True
            or report.get("reference_poison_scope") != "test process; subprocesses inherit selector, not Python patches"
            or report.get("all_nine_ordinary_modules_unfiltered") is not True
            or report.get("original_test_budgets_changed") is not False or report.get("source_and_bundle_unchanged") is not True
            or report.get("original_registry_count_assertion_adjustments") != adjustments
            or report.get("separate_original_administrator_scope_gates") != original["separate_scope_modules"]
            or report.get("whole_project_dynamic_caller_closure_claimed") is not False
            or report.get("whole_native_delivery_qualified") is not False
            or manifest.get("schema") != "hepta.hia.emission-native.v1"
            or manifest.get("source_sha256") != sources[SOURCE_NAME]
            or report.get("native_image_sha256") != manifest["image_sha256"]
            or bundle_pins.get(str(manifest_path.parent / manifest["image_path"])) != manifest["image_sha256"]
            or report.get("source_pins") != source_pins or not bundle_pins or report.get("bundle_pins") != bundle_pins
            or any(name in sources and sources[name] != digest for name, digest in source_pins.items())
            or any(name not in sources and name not in original_files for name in source_pins)):
        raise ValueError("emission complete 112 caller observations or captured inputs differ")
    frames, events = emission_event_accounting(report, planned)
    observed = audit_verbose_stderr(release_bytes(directory / "tests.log", pins),
        {"planned_test_ids": planned, "test_descriptions": descriptions})
    if observed["equivalent"] is not True:
        raise ValueError("emission original verbose log lacks all 112 successful methods in order")
    return {"actual_tests": 112, "actual_emission_frames": frames, "actual_native_event_counts": events,
            "actual_control_entries": sum(value for key, value in events.items() if key.startswith("continuation:")),
            "frames_by_mode": report["frames_by_mode"],
            "source_pin_count": len(source_pins), "bundle_pin_count": len(bundle_pins),
            "original_verbose_identity": observed, "complete_original_inventory_count": 240,
            "original_registry_count_assertion_adjustments": adjustments,
            "separate_administrator_scope_inventory_modules": original["separate_scope_modules"],
            "reference_poison_scope": report["reference_poison_scope"], "observed_report_scope": report["scope"],
            "original_test_budgets_changed": False, "whole_project_dynamic_caller_closure_claimed": False,
            "test_bodies_rerun_by_readback": False, "whole_native_delivery_qualified": False}


def emission_original_inventory(root, sources, discovery, pins):
    from tools.qualify_hia_emission_callers import FIXTURE_NAME, FIXTURE_SHA256, admit_original_sources
    original, _, _ = emission_original_inputs(root, sources, pins)
    modules = original.get("ordinary_modules", [])
    separate = original.get("separate_scope_modules", [])
    inventory = original.get("callers", {})
    if (FIXTURE_NAME != EMISSION_ORIGINAL_DIRECTORY + "original-freeze.json"
            or FIXTURE_SHA256 != EMISSION_ORIGINAL_SHA256["original-freeze.json"]
            or len(modules) != 9 or len(set(modules)) != 9 or len(separate) != 8 or len(set(separate)) != 8
            or set(modules) & set(separate) or set(inventory) != set(modules) | set(separate)
            or original.get("ordinary_count") != 112 or original.get("separate_scope_count") != 128):
        raise ValueError("emission complete frozen ordinary/separate caller inventory differs")
    all_ids = [identity for module in (*modules, *separate) for identity in inventory[module]["recorded_ids"]]
    if (len(all_ids) != 240 or len(set(all_ids)) != 240
            or sum(len(inventory[module]["recorded_ids"]) for module in separate) != 128):
        raise ValueError("emission complete original 240-method inventory differs")
    original_files = {row["path"]: row["sha256"] for row in inventory.values()}
    adjustments = admit_original_sources(root, original)
    for module, row in inventory.items():
        observed = [item["id"] for item in discovery["test_descriptions"] if item["id"].startswith(module + ".")]
        if row.get("path") != module.replace(".", "/") + ".py" or observed != row.get("recorded_ids"):
            raise ValueError("emission complete original caller module differs: " + module)
    descriptions = [row for module in modules for row in discovery["test_descriptions"]
                    if row["id"].startswith(module + ".")]
    planned = [row["id"] for row in descriptions]
    if planned != original.get("ordinary_ordered_ids") or len(planned) != 112 or len(set(planned)) != 112:
        raise ValueError("emission original complete 112-method order differs")
    return original, original_files, adjustments, descriptions, planned


def require_emission_composition(directory, root, cold_path, compiler, sources, pins):
    from tools.build_hia_native_build_admission import INPUTS as ADMISSION_INPUTS
    from tools.build_hia_store_lifecycle import INPUTS as STORE_INPUTS
    from tools.build_hia_service_context import INPUTS as CONTEXT_INPUTS
    from tools.build_hia_cost_ledger import INPUTS as LEDGER_INPUTS
    from tools.build_hia_evaluation import INPUTS as EVALUATION_INPUTS
    directory = Path(directory)
    composition = directory / "test_eight_owner_emission_evaluation_adoption_and_exact_replay/eight-owner-composition"
    report = emission_composition_observations(composition, "MATCHING_SOURCE_COLD_COMPONENT", pins)
    manifests = {"HEPTA_HIA_EMISSION_MANIFEST": directory / "built/manifest.json"}
    for selector, label, compile_label, source_name, inputs in (
            ("NATIVE_BUILD_ADMISSION", "native-build-admission", "native_build_admission", "native_build_admission", ADMISSION_INPUTS),
            ("STORE_LIFECYCLE", "store-lifecycle", "store-lifecycle", "store_lifecycle", STORE_INPUTS),
            ("SERVICE_CONTEXT", "service-context", "service-context", "service_context", CONTEXT_INPUTS),
            ("COST_LEDGER", "cost-ledger", "cost-ledger", "cost_ledger", LEDGER_INPUTS),
            ("EVALUATION", "evaluation", "evaluation", "evaluation", EVALUATION_INPUTS)):
        manifest_path = composition / label / "manifest.json"
        source_name = "examples/hia_bootstrap/" + source_name + ".hepta"
        require_cold_component(manifest_path, source_name, sha(cold_path), sha(compiler), sources, pins)
        require_release_compilation(manifest_path.parent, compile_label, source_name, inputs, root, compiler, sources, pins)
        manifests["HEPTA_HIA_" + selector + "_MANIFEST"] = manifest_path
    for selector, label, source_name in (
            ("EXECUTION_BUDGET", "execution-budget", "execution_budget"),
            ("CANDIDATE_BUDGET", "candidate-budget", "candidate_budget")):
        manifests["HEPTA_HIA_" + selector + "_MANIFEST"] = require_evaluation_budget_build(
            composition / label, label, "examples/hia_bootstrap/" + source_name + ".hepta",
            root, cold_path, compiler, sources, pins)
    bundle_sha = evaluation_composition_bundle(composition, report, manifests, pins)
    return {"bundle_sha256": bundle_sha, "manifests": report["manifests"],
            "actual_native_entries": report["actual_native_entries"],
            "replay_additional_entries": report["replay_additional_entries"],
            "adoption_replay_additional_entries": report["adoption_replay_additional_entries"],
            "actual_artifact_bodies_bound_to_response": True, "actual_emissions_bound_to_evaluated_artifacts": True,
            "native_budget_before_after_retained_and_equal": True,
            "qualification_topology": "source-process eight-owner public composition",
            "installed_eight_owner_worker_observed": False,
            "cross_owner_native_delivery_loss_tracking_implemented": False,
            "all_original_context_and_native_budgets_preserved": True,
            "evaluation_and_adoption_replay_native_and_SQL_deltas_retained": True,
            "test_bodies_rerun_by_readback": False, "whole_native_delivery_qualified": False}


def require_emission_component(directory, root, cold_path, compiler, sources, pins):
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    require_cold_component(manifest_path, "examples/hia_bootstrap/emission.hepta",
                           sha(cold_path), sha(compiler), sources, pins)
    manifest, custody = emission_custody(directory, root, cold_path, compiler, sources, pins)
    return {"scope": "MATCHING_SOURCE_COLD_COMPONENT", "manifest": str(manifest_path),
            "image_sha256": manifest["image_sha256"], "runtime_protocol_facts": custody["runtime_protocol_facts"],
            "controls": emission_control_observations(directory, root, sources, pins),
            "installation": require_emission_installation(directory, sources, manifest, pins),
            "eight_owner_composition": require_emission_composition(directory, root, cold_path, compiler, sources, pins),
            "source_and_compiler_custody_verified": True, "test_result_owned_by_original_full_runner": True,
            "test_bodies_rerun_by_supplement": False,
            "cross_owner_native_delivery_loss_tracking_implemented": False,
            "whole_native_delivery_qualified": False, "passed": True}



# Independently frozen originals, preceding the Store candidate.
STORE_PROFILE_ORIGINAL_SHA256 = {
    "tests/fixtures/hia_store_artifact_profile_cases_73f1634.json": "378d441cdfc4f8fcef3034ae69f464497ba3e5ec2858058024b3fd6f7ef1a280",
    "tests/hia_store_artifact_profile_oracle.py": "26c1b4ac5970f21a9a258da07d92b87ed8ea5a4db4526b94144a7d76db24b84c",
    "tests/hia_store_literal_call_oracle.py": "eca4a77776efd3003c7bb3dc4089f49ec1955b0c94a5dc84e31344dc0c5519c9",
    "tests/hia_store_limit_oracle.py": "5b2a0671e64d2c64a42895f2964584ecef54547fb70eb0298b81c13e098aea80",
    "tests/fixtures/hia_agent_store_73f1634.py.txt": "5feb5b2d06db497b895ba209bdd7b0ed1b7ed29ad29466aca356f5c3fb21657a",
    "tests/fixtures/hia_store_artifact_profile_callers_73f1634.json": "acbb8c221d80788ef96eb4b596c24fc1c3eb410229e605b2f01ef77e5530b7d6",
    "tests/fixtures/AgentStore.put.py.txt": "c75c43cd27942c1073f6b9318ada1188fc5df4012e7900b07e0d321546371469",
    "tests/fixtures/AgentStore.json.py.txt": "bd8b0f704df24e194e060f24ec3119874cfdd93dad878672665efdaa01972821",
    "tests/fixtures/AgentStore._ref.py.txt": "6d5952f35a71c9b85d40e35b88fd4b6e2b94d051e424bbc1db887d4eab516c7e",
    "tests/fixtures/AgentStore.get.py.txt": "76694223a11fe72176ad9b12ce9ccc76043027ba1dc5c96853332766a9f79b31",
    "tests/fixtures/AgentStore.get_json.py.txt": "e1c1c9245d1a9301c06665c1bc40c32b10d4e086db6c13bc6d3b7e5531fe8c33",
    "tests/fixtures/AgentStore.resolve_uri.py.txt": "370c9a9ce102ed064cda59466c0f1377c1fe0752e2c5f09e980dd45b7d19c8c4",
    "tests/fixtures/AgentStore.profile.py.txt": "f32b5820994bf22a57cdb6cdb2e241d5a0ea7775c39fa0a4cae3dea751d16d40",
    "tests/fixtures/AgentStore.check_profile.py.txt": "5f91d4feaead7e35d141a0edfdd754ed6b40c5f3d8879895a2897e5ba1962dee",
}
STORE_PROFILE_LIMIT_CASES_SHA256 = "7dafcf4bfab7566695a15814ab7e9e888b367afdaed6b1e1f35ec12ec8ca2333"
STORE_PROFILE_MODES = {str(number) for number in range(1, 17)}


def store_profile_original_inputs(root, sources, pins):
    documents = {}
    for name, digest in STORE_PROFILE_ORIGINAL_SHA256.items():
        raw = release_bytes(root / name, pins)
        if hashlib.sha256(raw).hexdigest() != digest or sources.get(name) != digest:
            raise ValueError("Store independently frozen original input differs: " + name)
        documents[name] = raw
    original = json.loads(documents["tests/fixtures/hia_store_artifact_profile_cases_73f1634.json"])
    rows = original.get("cases", [])
    methods = ("put", "json", "_ref", "get", "get_json", "resolve_uri", "profile", "check_profile")
    if (original.get("schema") != "hepta.hia.store-artifact-profile-original-inputs.v1"
            or original.get("base_commit") != "73f16346e7f84fa13305777a4595e2d1b422dee9"
            or original.get("base_tree") != "979fcc94c1c6a045e7f6740c97d30c0fdded2dd3"
            or original.get("candidate_graph_or_candidate_results_used") is not False
            or original.get("case_count") != 463 or type(rows) is not list or len(rows) != 463
            or any(type(row) is not dict or type(row.get("name")) is not str
                   or row.get("method") not in methods for row in rows)
            or len({row["name"] for row in rows}) != 463
            or original.get("method_files") != {name: STORE_PROFILE_ORIGINAL_SHA256[
                "tests/fixtures/AgentStore." + name + ".py.txt"] for name in methods}):
        raise ValueError("Store complete frozen 463-case source inventory differs")
    protocol_name = "hepta/hia_store_artifact_profile_protocol.py"
    raw = release_bytes(root / protocol_name, pins)
    if sources.get(protocol_name) != hashlib.sha256(raw).hexdigest():
        raise ValueError("Store fixed protocol is outside the admitted source")
    nodes = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == "PORTS" for target in node.targets)]
    if len(nodes) != 1:
        raise ValueError("Store fixed port inventory is ambiguous")
    ports = ast.literal_eval(nodes[0].value)
    if (type(ports) is not tuple or len(ports) != 138 or len(set(ports)) != 138
            or any(type(name) is not str or not name for name in ports)):
        raise ValueError("Store complete fixed 138-port inventory differs")
    # Only pure frozen input-list constructors; no original/candidate body.
    from tests.hia_store_literal_call_oracle import cases as literal_cases
    from tests.hia_store_limit_oracle import cases as limit_cases
    literal, limits = literal_cases(), limit_cases()
    if (len(literal) != 160 or len({row["name"] for row in literal}) != 160
            or len(limits) != 41 or len({row["name"] for row in limits}) != 41
            or hashlib.sha256(evaluation_json_bytes(limits)).hexdigest() != STORE_PROFILE_LIMIT_CASES_SHA256):
        raise ValueError("Store frozen literal-call or dynamic-limit case inputs differ")
    return rows, literal, limits, {name: index + 1 for index, name in enumerate(ports)}


def store_profile_custody(directory, root, cold_path, compiler, sources, pins):
    from tools.build_hia_store_artifact_profile import INPUTS, SOURCE_NAME
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    manifest = require_release_compilation(directory / "built", "store_artifact_profile", SOURCE_NAME,
                                          INPUTS, root, compiler, sources, pins)
    build = release_json(directory / "built/build.json", pins)
    custody = release_json(directory / "component-custody.json", pins)
    scope = "DEVELOPMENT_COMPONENT" if cold_path is None else "MATCHING_SOURCE_COLD_COMPONENT"
    if (manifest.get("schema") != "hepta.hia.store-artifact-profile.v1"
            or manifest.get("source_sha256") != sources[SOURCE_NAME]
            or manifest.get("compiler_sha256") != sha(compiler)
            or manifest.get("image_sha256") != hashlib.sha256(release_bytes(
                manifest_path.parent / manifest["image_path"], pins)).hexdigest()
            or build.get("schema") != "hepta.hia.store-artifact-profile-build.v1"
            or build.get("scope") != scope or build.get("manifest") != manifest
            or build.get("source_manifest") != (None if cold_path is None else sources)
            or build.get("cold_report_sha256") != (None if cold_path is None else sha(cold_path))
            or build.get("original_artifact_limit_bytes") != 67108864
            or any(build.get(key) is not True for key in (
                "eight_complete_original_methods_owned_by_hia",
                "control_branches_reference_iteration_and_cleanup_owned_by_hia",
                "argument_continuations_owned_by_hia", "literal_calls_preserve_original_dynamic_methods",
                "canonical_nested_calls_enter_selected_native_children",
                "filesystem_sql_hash_json_and_object_protocols_hosted",
                "original_dynamic_limit_global_binding_and_opaque_comparison_preserved",
                "same_owner_active_causal_native_loss_fenced"))
            or any(build.get(key) is not False for key in (
                "transaction_context_manager_migrated", "new_production_wall_cap",
                "cross_owner_causal_loss_closure_qualified", "retained_eight_bodies_invoked_on_selected_canonical_route",
                "explicit_foreign_overrides_restricted", "whole_stack_rewritten_in_hia", "all_input_equivalence_proved"))
            or custody.get("schema") != "hepta.hia.store-artifact-profile-test-custody.v1"
            or custody.get("manifest") != str(manifest_path)
            or custody.get("matching_cold_report") != (None if cold_path is None else str(cold_path))
            or custody.get("compiler_sha256") != sha(compiler)
            or custody.get("source_manifest_before") != sources or custody.get("source_manifest_after") != sources
            or any(custody.get(key) is not True for key in ("compiler_unchanged", "source_and_compiler_unchanged",
                "test_result_owned_by_outer_runner", "filesystem_SQL_hash_JSON_and_object_protocols_hosted"))
            or any(custody.get(key) is not False for key in ("transaction_context_manager_migrated",
                "cross_owner_causal_loss_closure_qualified", "all_input_equivalence_proved", "whole_native_delivery_qualified"))):
        raise ValueError("Store first-full build, hosted boundaries or source/compiler custody differs")
    return manifest, custody


def store_profile_rows(records, cases, literal=False):
    if (type(records) is not list or [row.get("case") for row in records] != [case["name"] for case in cases]
            or any(type(row) is not dict or set(row) != {"case", "expected", "actual"} for row in records)):
        raise ValueError("Store complete ordered finite observation inventory differs")
    for row, case in zip(records, cases):
        if (type(row["expected"]) is not dict or row["expected"].get("name") != case["name"]
                or set(row["expected"]) != ({"name", "outcome", "trace"} if literal else {"name", "method", "outcome", "state", "trace"})
                or (not literal and row["expected"].get("method") != case["method"])
                or evaluation_json_bytes(row["expected"]) != evaluation_json_bytes(row["actual"])):
            raise ValueError("Store original full trace, alias, state or exception comparison differs")
    return {row["case"]: row["expected"] for row in records}


def store_profile_positive_counts(value, allowed, required=()):
    if (type(value) is not dict or not set(required) <= set(value) <= set(allowed)
            or any(type(amount) is not int or amount <= 0 for amount in value.values())):
        raise ValueError("Store exact positive native count inventory differs")
    return value


def store_profile_events(events, ports):
    if type(events) is not list or not events:
        raise ValueError("Store actual native event sequence is absent")
    pending, opened = {}, []
    for row in events:
        if (type(row) is not dict or set(row) != {"mode", "event", "port"}
                or any(type(value) is not int for value in row.values())
                or str(row["mode"]) not in STORE_PROFILE_MODES or row["event"] not in range(4)
                or row["port"] not in ({0} if row["event"] == 0 else set(ports.values()))):
            raise ValueError("Store actual native event mode, type or port differs")
        mode, event, port = row["mode"], row["event"], row["port"]
        if event == 0:
            # Completed argument continuations may reuse their mode, without
            # replacing an instance with an unacknowledged effect.
            if pending.get(mode) is not None:
                raise ValueError("Store reinitialized an outstanding native effect")
            pending[mode] = None
            opened.append(mode)
        elif mode not in pending:
            raise ValueError("Store event precedes its actual initialization")
        elif event == 1:
            if pending[mode] is not None:
                raise ValueError("Store claimed a second unacknowledged effect")
            pending[mode] = port
        else:
            if pending[mode] != port:
                raise ValueError("Store native acknowledgement differs from its claimed effect")
            pending[mode] = None
    return pending, opened


def store_profile_transport_observations(directory, expected, ports, pins):
    record = release_json(Path(directory) / "test_lost_ACK_foreign_errors_and_active_same_owner_ancestors/native-and-foreign-exceptions.json", pins)
    rows = record.get("records", [])
    if (record.get("schema") != "hepta.hia.store-artifact-profile-transport-controls.v1"
            or record.get("native_cases") != 30 or record.get("foreign_cases") != 30
            or record.get("caught_native_child_cases") != 10 or type(rows) is not list or len(rows) != 70
            or record.get("cross_owner_causal_closure_claimed") is not False):
        raise ValueError("Store complete 30 native/30 foreign/10 same-owner controls differ")
    errors = ("ValueError", "TypeError", "OSError", "OverflowError", "RecursionError", "OperationalError",
              "MixedRejected", "RuntimeError", "KeyboardInterrupt", "SystemExit")
    plans = (("put.native", "put_native_put", "native.file.store-put", 1),
             ("put.fallback", "put_stream_fsync", "os.fsync.file", 1),
             ("profile.native", "profile_insert", "sql.execute.insert-profile", 7))
    prefixes, states = {}, {}
    for name, port, event, mode in plans:
        trace = expected[name]["trace"]
        ends = [index for index, row in enumerate(trace) if row.get("event") == event and row.get("occurrence") == 1]
        if len(ends) != 1:
            raise ValueError("Store original durable effect prefix is ambiguous")
        prefixes[name] = trace[:ends[0] + 1]
        pairs = expected[name]["state"]["dict"]
        if name == "put.native":
            pairs = pairs[:4]
        elif name == "put.fallback":
            pairs = [[key, True if key == "temporary_exists" else value] for key, value in pairs[:6]]
        states[name] = {"dict": pairs}
    for index, (name, port, event, mode, error) in enumerate(
            (name, port, event, mode, error) for name, port, event, mode in plans for error in errors):
        native, foreign = rows[index], rows[index + 30]
        events = native.get("events", [])
        pending, opened = store_profile_events(events, ports)
        raised = error if error in ("RuntimeError", "KeyboardInterrupt", "SystemExit") else "StoreArtifactProfileUnknown"
        if (native.get("lane") != "native" or native.get("case") != name or native.get("port") != port
                or native.get("error") != error or native.get("raised") != raised or opened[0] != mode
                or events[-1] != {"mode": mode, "event": 2, "port": ports[port]}
                or any(row["event"] == 3 for row in events)
                or native.get("unknown_custody_retained") is not True
                or native.get("no_retry_or_automatic_cleanup") is not True
                or evaluation_json_bytes(native.get("trace")) != evaluation_json_bytes(prefixes[name])
                or evaluation_json_bytes(native.get("state")) != evaluation_json_bytes(states[name])):
            raise ValueError("Store native delivery loss confirmed, retried or cleaned up the observed durable effect")
        foreign_events = foreign.get("events", [])
        trace, state = prefixes[name], states[name]
        if name == "put.fallback":
            trace = [*trace,
                {"event": "stream.exit", "occurrence": 1, "active_exception": "observed-3",
                 "values": {"tuple": [error, "observed-3", True]}},
                {"event": "path.unlink", "occurrence": 1, "active_exception": "observed-3",
                 "values": {"tuple": [{"opaque": "path:artifacts/.write-00000000000000000000000000000001"},
                                      {"dict": [["missing_ok", True]]}]}}]
            state = {"dict": [[key, False if key == "temporary_exists" else value]
                               for key, value in state["dict"]] + [["stream_exited", True]]}
        if (foreign.get("lane") != "foreign" or foreign.get("case") != name or foreign.get("port") != port
                or foreign.get("error") != error or foreign.get("same_exception_object") is not True
                or type(foreign.get("confirmed_phase")) is not int or foreign["confirmed_phase"] != 5
                or type(foreign_events) is not list or 3 not in foreign_events
                or any(type(value) is not int or value not in range(4) for value in foreign_events)
                or evaluation_json_bytes(foreign.get("trace")) != evaluation_json_bytes(trace)
                or evaluation_json_bytes(foreign.get("state")) != evaluation_json_bytes(state)):
            raise ValueError("Store original foreign exception identity, confirmation or cleanup differs")
    trace = expected["json.native"]["trace"]
    ends = [index for index, row in enumerate(trace) if row.get("event") == "sql.execute.insert-artifact"
            and row.get("occurrence") == 1]
    if len(ends) != 1:
        raise ValueError("Store original JSON child publication is ambiguous")
    for row, error in zip(rows[60:], errors):
        events = row.get("events", [])
        pending, opened = store_profile_events(events, ports)
        if (row.get("lane") != "caught-native-child" or row.get("error") != error
                or row.get("actual_public_child_frame_observed") is not True
                or row.get("parent_and_child_fenced") is not True or opened[:3] != [2, 9, 1]
                or events[-1] != {"mode": 1, "event": 2, "port": ports["put_insert"]}
                or any(event["event"] == 3 for event in events) or pending.get(2) is None
                or evaluation_json_bytes(row.get("trace")) != evaluation_json_bytes(trace[:ends[0] + 1])):
            raise ValueError("Store swallowed same-owner child loss did not retain its actual causal ancestor")
    return {"post_effect_native_loss_cases": 30, "confirmed_foreign_exception_cases": 30,
            "caught_public_same_owner_child_loss_cases": 10,
            "complete_original_effect_prefixes_and_exact_foreign_cleanup_checked": True,
            "foreign_exception_identity_and_custody_owned_by_original_complete_test": True,
            "cross_owner_causal_loss_closure_qualified": False, "test_bodies_rerun_by_readback": False}


def store_profile_control_observations(directory, root, sources, pins, runtime=None):
    directory = Path(directory)
    cases, literal_cases, limit_cases, ports = store_profile_original_inputs(root, sources, pins)
    location = directory / "test_complete_463_original_effects_first_errors_and_cleanup_order"
    complete = release_json(location / "complete-observations.json", pins)
    expected = store_profile_rows(complete.get("records"), cases)
    counts = store_profile_positive_counts(complete.get("actual_native_entries_by_event"), set("0123"), set("0123"))
    modes = store_profile_positive_counts(complete.get("actual_frames_by_mode"), STORE_PROFILE_MODES, STORE_PROFILE_MODES)
    if (complete.get("schema") != "hepta.hia.store-artifact-profile-original-comparison.v1"
            or complete.get("case_count") != 463 or complete.get("retained_eight_bodies_forbidden") is not True
            or complete.get("all_input_equivalence_proved") is not False
            or counts != {"0": 1196, "1": 12519, "2": 12021, "3": 498}
            or modes != {"1": 330, "2": 35, "3": 212, "4": 96, "5": 34, "6": 22, "7": 29, "8": 36,
                         "9": 30, "10": 100, "11": 58, "12": 94, "13": 59, "14": 22, "15": 17, "16": 22}
            or type(complete.get("runtime")) is not str or not complete["runtime"]
            or runtime is not None and complete["runtime"] != runtime):
        raise ValueError("Store complete original comparison or physical native count differs")
    limits = release_json(location / "dynamic-limit-observations.json", pins)
    store_profile_rows(limits.get("records"), limit_cases)
    limit_counts = store_profile_positive_counts(limits.get("actual_native_entries_by_event"), set("0123"), set("0123"))
    if (limits.get("schema") != "hepta.hia.store-dynamic-limit-native-comparison.v1"
            or limits.get("case_count") != 41 or limits.get("cases_sha256") != STORE_PROFILE_LIMIT_CASES_SHA256
            or limits.get("oracle_sha256") != STORE_PROFILE_ORIGINAL_SHA256["tests/hia_store_limit_oracle.py"]
            or limits.get("runtime") != complete["runtime"] or limit_counts != {"0": 41, "1": 157, "2": 116, "3": 41}
            or any(limits.get(key) is not True for key in ("original_guard_global_reads_and_opaque_comparison_preserved",
                "earlier_463_and_160_fixtures_unchanged", "accepted_branch_stops_at_next_original_admission_effect"))
            or limits.get("all_input_equivalence_proved") is not False):
        raise ValueError("Store original dynamic limit and first-error observations differ")
    literal = release_json(directory / "test_frozen_160_literal_calls_cold_and_warm_profiles/literal-call-observations.json", pins)
    rows = literal.get("records", [])
    if (literal.get("schema") != "hepta.hia.store-artifact-profile-literal-call-comparison.v1"
            or literal.get("runtime") != complete["runtime"] or literal.get("cases_per_profile") != 160
            or literal.get("cold_and_warm_interpreter_profiles_compared") is not True
            or literal.get("exception_attributes_normalized") is not False
            or literal.get("all_execution_histories_proved") is not False
            or type(rows) is not list or len(rows) != 320
            or [(row.get("profile"), row.get("case")) for row in rows]
               != [(profile, case["name"]) for profile in ("cold", "warm") for case in literal_cases]
            or any(set(row) != {"profile", "case", "expected", "actual"} for row in rows)):
        raise ValueError("Store original complete 160 cold and 160 warm literal-call inventory differs")
    for offset in (0, 160):
        store_profile_rows([{key: value for key, value in row.items() if key != "profile"}
                            for row in rows[offset:offset + 160]], literal_cases, literal=True)
    vm = release_json(directory / "test_actual_native_full_buffers_match_independent_VM/vm-native-observations.json", pins)
    if (set(vm) != {"cases", "entries", "input_output_and_state_compared_at_every_entry"}
            or vm.get("cases") != ["put.native", "put.fallback.link-exists.same", "ref.ordinary", "get.native",
                                   "profile.native", "check_profile.native"]
            or type(vm.get("entries")) is not int or vm["entries"] != 533
            or vm.get("input_output_and_state_compared_at_every_entry") is not True):
        raise ValueError("Store original six independent full-buffer VM cases differ")
    public = directory / "test_eight_public_routes_poisoned_reference_and_selector_pinning"
    public_record = release_json(public / "public-observations.json", pins)
    public_modes = store_profile_positive_counts(public_record.get("frames_by_mode"), STORE_PROFILE_MODES, map(str, range(1, 9)))
    if (any(public_record.get(key) is not True for key in ("all_eight_public_routes_observed",
            "all_eight_reference_bodies_forbidden", "empty_missing_changed_and_outside_scope_refused"))
            or public_modes != {"1": 3, "2": 2, "3": 9, "4": 4, "5": 2, "6": 1, "7": 1, "8": 1,
                                "9": 2, "12": 3, "13": 4, "15": 1, "16": 1}):
        raise ValueError("Store complete public routes or selector pinning differs")
    manifest_raw = release_bytes(directory / "built/manifest.json", pins)
    image_name = json.loads(manifest_raw)["image_path"]
    if (release_bytes(public / "manifest.json", pins) != manifest_raw
            or release_bytes(public / image_name, pins) != release_bytes(directory / "built" / image_name, pins) + b"\0"):
        raise ValueError("Store selector drift differs from the original exact one-NUL mutation")
    protocol = release_json(directory / "test_thread_finished_replay_bad_packets_and_unclaimed_ACK_refuse/protocol-observations.json", pins)
    invalid = protocol.get("invalid_packets", [])
    if (protocol.get("foreign_thread_refused_without_poisoning_creator") is not True
            or protocol.get("finished_replay_and_unclaimed_ACK_no_foreign_effect") is not True
            or type(invalid) is not list or len(invalid) != 8
            or [row.get("case") for row in invalid] != ["bad-magic", "bad-mode-low", "bad-mode-high", "initial-sequence",
                    "initial-port", "initial-observation", "reserved-one", "reserved-two"]
            or any(type(row.get("status")) is not int or row["status"] != 4294967293
                   or row.get("all_buffers_unchanged") is not True for row in invalid)):
        raise ValueError("Store original thread, replay or eight unchanged-buffer refusal controls differ")
    location = directory / "test_real_store_eight_methods_original_SQL_files_and_reference_authority"
    real = release_json(location / "store-observations.json", pins)
    store_profile_positive_counts(real.get("frames_by_mode"), STORE_PROFILE_MODES, STORE_PROFILE_MODES)
    bundle = release_json(location / "bundle.json", pins)
    from hepta.hia_native_helpers import SCHEMA, TARGET, ABI
    if (real.get("bundle_sha256") != pins[str(location / "bundle.json")]
            or bundle != {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
                "selector": "HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST",
                "manifest_path": str(directory / "built/manifest.json"),
                "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}]}
            or any(real.get(key) is not True for key in ("all_eight_public_routes_real_files_and_SQL",
                "all_eight_reference_bodies_forbidden", "namespace_and_kind_precedence_preserved",
                "native_artifact_file_provider_covered_by_separate_original_18_method_gate"))):
        raise ValueError("Store actual SQL/files bundle or original provider gate scope differs")
    return {"original_complete_cases": 463, "dynamic_limit_cases": 41,
            "literal_call_cases_per_cold_and_warm_profile": 160,
            "actual_native_entries_by_event": counts, "actual_frames_by_mode": modes,
            "dynamic_limit_native_entries_by_event": limit_counts,
            "independent_VM_cases": 6, "actual_VM_native_entries": 533,
            "VM_full_buffer_comparison_owned_by_original_complete_test": True,
            "raw_VM_buffers_separately_retained": False,
            "public_selector_observations": public_record, "protocol_observations": protocol,
            "real_SQL_files_observations": real,
            "transport": store_profile_transport_observations(directory, expected, ports, pins),
            "runtime": complete["runtime"], "test_bodies_rerun_by_readback": False,
            "all_input_equivalence_proved": False, "cross_owner_causal_loss_closure_qualified": False}


def store_profile_wheel(location, sources, observation, pins):
    wheels = sorted((location / "wheels").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("Store needs the one actual installed wheel")
    wheel = wheels[0]
    files, distribution = release_wheel(wheel, pins)
    source_python = {name for name in sources if name.startswith("hepta/") and name.endswith(".py")}
    if not source_python <= set(files):
        raise ValueError("Store wheel omitted production Python source")
    for name, raw in files.items():
        if name.startswith("hepta/"):
            source_name = name.removeprefix("hepta/_data/") if name.startswith("hepta/_data/") else name
            if sources.get(source_name) != hashlib.sha256(raw).hexdigest():
                raise ValueError("Store wheel has unbound production bytes")
        elif not name.startswith(distribution + "/"):
            raise ValueError("Store wheel has unexpected members")
    installed, actual = location / "installed", {}
    for path in sorted(installed.rglob("*")):
        if path.is_symlink():
            raise ValueError("Store installed file is a symlink")
        if path.is_file():
            actual[path.relative_to(installed).as_posix()] = release_bytes(path, pins)
    record = distribution + "/RECORD"
    member = "hepta/_data/examples/hia_bootstrap/store_artifact_profile.hepta"
    extras = {"bin/hia", *(distribution + "/" + name for name in ("INSTALLER", "REQUESTED", "direct_url.json"))}
    if (set(actual) != set(files) | extras or member not in files
            or any(actual.get(name) != raw for name, raw in files.items() if name not in (record, member))
            or actual.get(member) != files[member] + b"\n"):
        raise ValueError("Store installation differs beyond its exact one-LF control")
    recorded = dict(actual)
    recorded[member] = files[member]
    require_release_record(recorded, record, installed=True)
    origin = json.loads(actual[distribution + "/direct_url.json"])
    drift = observation.get("installed_source_drift", {})
    if (origin.get("url") != wheel.as_uri()
            or origin.get("archive_info", {}).get("hashes", {}).get("sha256") != pins[str(wheel)]
            or observation.get("wheel") != str(wheel) or observation.get("wheel_sha256") != pins[str(wheel)]
            or drift.get("before_sha256") != sources["examples/hia_bootstrap/store_artifact_profile.hepta"]
            or drift["before_sha256"] != hashlib.sha256(files[member]).hexdigest()
            or drift.get("after_sha256") != hashlib.sha256(actual[member]).hexdigest()):
        raise ValueError("Store installed wheel origin or source drift differs")
    return files, {"wheel": str(wheel), "wheel_sha256": pins[str(wheel)], "actual_wheel_members": len(files),
        "actual_installed_files": len(actual), "all_other_product_bytes_equal_wheel": True,
        "installed_RECORD_checked_against_exact_pre_drift_bytes": True,
        "only_intentional_installed_mutation": {"member": member, "change": "append exactly one LF",
            "before_sha256": drift["before_sha256"], "after_sha256": drift["after_sha256"]}}


def store_profile_worker_counts(raw):
    prefix = b"STORE_ARTIFACT_COUNTS="
    found = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    if len(found) != 1:
        raise ValueError("Store installed worker has no unique original count marker")
    counts = json.loads(found[0])
    if (type(counts) is not dict or set(counts) != {"startup", "request", "request_artifact_inserts", "unknown_frames"}
            or any(type(counts[key]) is not int or counts[key] < 0 for key in ("request_artifact_inserts", "unknown_frames"))):
        raise ValueError("Store installed worker count shape differs")
    for phase in ("startup", "request"):
        row = counts[phase]
        if (type(row) is not dict or set(row) != {"entries", "modes"}
                or type(row["entries"]) is not int or row["entries"] < 0):
            raise ValueError("Store installed startup/request count shape differs")
        store_profile_positive_counts(row["modes"], STORE_PROFILE_MODES)
        if (row["entries"] == 0) != (not row["modes"]) or row["entries"] < sum(row["modes"].values()):
            raise ValueError("Store installed entries disagree with their physical frames")
    return counts


def store_profile_worker_streams(location, worker_sha, catalog_sha, bundle_sha, version, pins):
    names = ("wheel", "install", "first", "replay", "uri-read", "native_ack", "native_ack-replay",
             "process_loss", "process_loss-replay", "changed-installed-source")
    logs = {name: {suffix: release_bytes(location / (name + "." + suffix), pins)
                  for suffix in ("stdout", "stderr")} for name in names}
    counts = {name: store_profile_worker_counts(logs[name]["stderr"]) for name in names[2:]}
    startup = {"entries": 3714, "modes": {"1": 27, "2": 17, "3": 54, "4": 27, "7": 7,
                                           "9": 17, "13": 27, "14": 27, "15": 7}}
    first_modes = {"1": 1, "3": 2, "4": 1, "5": 1, "8": 1, "10": 1, "11": 1,
                   "12": 1, "13": 1, "14": 1, "16": 1}
    requests = {"first": {"entries": 250, "modes": first_modes},
                "uri-read": {"entries": 170, "modes": {"3": 3, "4": 2, "6": 1, "13": 2, "14": 2}},
                "native_ack": {"entries": 223, "modes": {**first_modes, "3": 1}},
                "process_loss": {"entries": 222, "modes": {**first_modes, "3": 1}}}
    for name, row in counts.items():
        expected = {"startup": startup if name != "changed-installed-source" else {"entries": 0, "modes": {}},
                    "request": requests.get(name, {"entries": 0, "modes": {}}),
                    "request_artifact_inserts": int(name in ("first", "native_ack", "process_loss")),
                    "unknown_frames": int(name in ("native_ack", "process_loss"))}
        if row != expected:
            raise ValueError("Store installed startup, request, durable-insert or custody count differs: " + name)
    if (any(logs[name]["stdout"] for name in ("native_ack", "process_loss", "changed-installed-source"))
            or b"ValueError: controlled lost durable Store insertion acknowledgement" not in logs["native_ack"]["stderr"]
            or b"StoreArtifactProfileUnknown" not in logs["native_ack"]["stderr"]):
        raise ValueError("Store installed lost acknowledgement or source-drift streams differ")
    reports = {name: json.loads(logs[name]["stdout"]) for name in (
        "first", "replay", "uri-read", "native_ack-replay", "process_loss-replay")}
    for name, report in reports.items():
        if (report.get("schema") != "hia-agent-worker-report-v1"
                or report.get("tool") != ("hia_resource_read" if name == "uri-read" else "hia_artifact")
                or report.get("complete") is not True or report.get("worker_sha256") != worker_sha
                or report.get("catalog_sha256") != catalog_sha or report.get("native_helpers_sha256") != bundle_sha
                or report.get("profile_sha256") != "a" * 64
                or report.get("response", {}).get("contract_version") != version
                or re.fullmatch(r"[0-9a-f]{64}", str(report.get("request_sha256"))) is None
                or re.fullmatch(r"[0-9a-f]{64}", str(report.get("backend_sha256"))) is None):
            raise ValueError("Store installed worker or request identity differs")
    if (evaluation_json_bytes(reports["first"]) != evaluation_json_bytes(reports["replay"])
            or len({reports[name]["request_sha256"] for name in ("first", "uri-read", "native_ack-replay", "process_loss-replay")}) != 4
            or len({report["backend_sha256"] for report in reports.values()}) != 1):
        raise ValueError("Store installed original/replay request identities are inconsistent")
    return reports, counts


def store_profile_retained_state(state):
    if (type(state) is not dict or set(state) != {"request", "artifacts", "costs"}
            or any(type(state[key]) is not int or state[key] < 0 for key in ("artifacts", "costs"))):
        raise ValueError("Store retained journal/artifact/cost observation shape differs")
    request = state["request"]
    if request is not None and (type(request) is not dict
            or set(request) != {"key", "digest", "tool", "state", "response", "started_ns"}
            or any(re.fullmatch(r"[0-9a-f]{64}", str(request.get(key))) is None for key in ("key", "digest"))
            or request.get("tool") != "hia_artifact" or request.get("state") not in ("running", "completed")
            or type(request.get("started_ns")) is not str or not request["started_ns"].isdecimal()
            or (request["response"] is not None and type(request["response"]) is not str)):
        raise ValueError("Store complete retained request row differs")
    return state


def store_profile_worker_journals(observation, reports, counts):
    for name in ("first", "replay", "uri_read"):
        stream_name = "uri-read" if name == "uri_read" else name
        row = observation.get(name, {})
        if (type(row.get("worker_exit_code")) is not int or row["worker_exit_code"] != 0
                or evaluation_json_bytes(row.get("report")) != evaluation_json_bytes(reports[stream_name])
                or evaluation_json_bytes(row.get("counts")) != evaluation_json_bytes(counts[stream_name])):
            raise ValueError("Store installed observation differs from actual worker streams or exit")
    payload = "durable Store native owner — 雪"
    payload_sha = hashlib.sha256(payload.encode()).hexdigest()
    first = reports["first"].get("response", {})
    result = first.get("result", {})
    artifact = result.get("artifact", {})
    if (first.get("status") != "completed" or result.get("byte_length") != str(len(payload.encode()))
            or result.get("content_admitted_as_program") is not False
            or result.get("execution_authority_granted") is not False
            or type(artifact) is not dict or set(artifact) != {"id", "uri", "sha256"}
            or not str(artifact.get("id", "")).startswith("a-")
            or not str(artifact.get("uri", "")).startswith("hia://artifacts/")
            or artifact.get("sha256") != payload_sha):
        raise ValueError("Store original installed artifact response differs")
    before = store_profile_retained_state(observation["first"].get("before"))
    after = store_profile_retained_state(observation["first"].get("after"))
    request = after["request"] or {}
    replay = observation["replay"]
    store_profile_retained_state(replay.get("before"))
    store_profile_retained_state(replay.get("after"))
    if (before["request"] is not None or after["artifacts"] != before["artifacts"] + 1
            or after["costs"] != before["costs"] + 1 or request.get("state") != "completed"
            or first.get("request_id") != "r-" + str(request.get("digest"))
            or type(request.get("response")) is not str
            or evaluation_json_bytes(json.loads(request["response"])) != evaluation_json_bytes(first)
            or evaluation_json_bytes(replay.get("before")) != evaluation_json_bytes(after)
            or evaluation_json_bytes(replay.get("after")) != evaluation_json_bytes(after)
            or replay.get("zero_request_owner_calls_not_zero_startup_calls") is not True):
        raise ValueError("Store completed request or exact replay changed its retained observations")
    uri = reports["uri-read"].get("response", {})
    content = uri.get("result", {})
    if (uri.get("status") != "completed" or content.get("artifact") != artifact
            or content.get("content") != payload or content.get("encoding") != "utf8"
            or content.get("next_cursor", "missing") is not None
            or observation["uri_read"].get("durable_payload_sha256") != payload_sha):
        raise ValueError("Store resource URI did not return the actual published payload identity")
    journals = {}
    for name, code in (("native_ack", 1), ("process_loss", 73)):
        row = observation.get(name, {})
        original = store_profile_retained_state(row.get("original_state"))
        before = store_profile_retained_state(row.get("before_replay"))
        after = store_profile_retained_state(row.get("after_replay"))
        report, request = reports[name + "-replay"], before["request"] or {}
        if (type(row.get("lost_worker_exit_code")) is not int or row["lost_worker_exit_code"] != code
                or type(row.get("replay_worker_exit_code")) is not int or row["replay_worker_exit_code"] != 0
                or evaluation_json_bytes(row.get("counts")) != evaluation_json_bytes(counts[name])
                or evaluation_json_bytes(row.get("replay_counts")) != evaluation_json_bytes(counts[name + "-replay"])
                or evaluation_json_bytes(row.get("replay")) != evaluation_json_bytes(report)
                or original["request"] is not None or before["artifacts"] != original["artifacts"] + 1
                or before["costs"] != original["costs"]
                or report.get("response", {}).get("status") != "rejected"
                or report["response"].get("error", {}).get("code") != "E_HIA_REQUEST_UNKNOWN"
                or request.get("state") != "running" or request.get("response") is not None
                or report["response"].get("request_id") != "r-" + str(request.get("digest"))
                or evaluation_json_bytes(request) != evaluation_json_bytes(after["request"])
                or before["artifacts"] != after["artifacts"] or after["costs"] != before["costs"] + 1):
            raise ValueError("Store unknown durable publication was completed, lost, repeated or changed replay accounting")
        journals[name] = request
    drift = observation.get("installed_source_drift", {})
    if (type(drift.get("worker_exit_code")) is not int or drift["worker_exit_code"] != 2
            or evaluation_json_bytes(drift.get("counts")) != evaluation_json_bytes(counts["changed-installed-source"])
            or drift.get("exact_change") != "one appended LF in packaged Store HIA source"):
        raise ValueError("Store packaged source drift did not reject before startup/request native execution")
    return journals


def require_store_profile_installation(directory, sources, manifest, pins):
    from hepta import hia_agent_contract as contract
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    directory = Path(directory)
    location = directory / "test_actual_installed_worker_publication_URI_unknown_replay_and_source_drift"
    observation = release_json(location / "installed-observations.json", pins)
    files, installation = store_profile_wheel(location, sources, observation, pins)
    manifest_path = directory / "built/manifest.json"
    manifest_raw = release_bytes(manifest_path, pins)
    image = release_bytes(manifest_path.parent / manifest["image_path"], pins)
    bundle_path = location / "bundle.json"
    bundle = release_json(bundle_path, pins)
    bundle_sha = pins[str(bundle_path)]
    if (observation.get("schema") != "hepta.hia.store-artifact-profile-installed-observations.v1"
            or json.loads(manifest_raw) != manifest or manifest.get("schema") != "hepta.hia.store-artifact-profile.v1"
            or manifest.get("source_sha256") != sources["examples/hia_bootstrap/store_artifact_profile.hepta"]
            or manifest.get("image_sha256") != hashlib.sha256(image).hexdigest()
            or bundle != {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
                "selector": "HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST", "manifest_path": str(manifest_path),
                "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}]}
            or observation.get("bundle_sha256") != bundle_sha
            or any(observation.get(key) is not True for key in ("all_eight_public_modes_observed",
                "retained_eight_bodies_forbidden_in_actual_child", "authoring_imports_forbidden_in_actual_child",
                "original_worker_used", "startup_and_request_native_counts_separated"))
            or observation.get("whole_native_delivery_qualified") is not False):
        raise ValueError("Store actual fresh-wheel child bundle or observed scope differs")
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
    reports, counts = store_profile_worker_streams(location, worker_sha,
        entries["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"], bundle_sha, contract.VERSION, pins)
    journals = store_profile_worker_journals(observation, reports, counts)
    return {**installation, "worker_identity_derived_from_actual_wheel": worker_sha,
            "actual_native_counts_from_original_stderr": counts, "retained_unknown_request_rows": journals,
            "actual_native_ack_failure_exit_code": 1, "actual_process_loss_exit_code": 73,
            "normal_and_unknown_replay_request_native_entries": 0,
            "replay_worker_startup_native_entries": 3714,
            "normal_replay_complete_retained_observation_preserved": True,
            "unknown_replay_request_row_and_artifact_count_preserved": True,
            "unknown_replay_original_cost_delta": 1,
            "retained_database_snapshot_scope": "full request rows and artifact/cost counts serialized by original complete method; temporary databases removed",
            "complete_artifact_rows_or_payload_separately_retained": False,
            "raw_request_envelopes_separately_retained": False,
            "qualification_topology": "fresh-wheel original worker with Store artifact/profile helper",
            "cross_owner_causal_loss_closure_qualified": False,
            "test_bodies_rerun_by_readback": False, "whole_native_delivery_qualified": False}


def store_profile_original_inventory(root, sources, discovery, pins):
    from tools.qualify_hia_store_artifact_profile_callers import FIXTURE_NAME, FIXTURE_SHA256, ARTIFACT_MODULE, admit_original_sources
    raw = release_bytes(root / FIXTURE_NAME, pins)
    if (FIXTURE_NAME != "tests/fixtures/hia_store_artifact_profile_callers_73f1634.json"
            or FIXTURE_SHA256 != STORE_PROFILE_ORIGINAL_SHA256[FIXTURE_NAME]
            or hashlib.sha256(raw).hexdigest() != FIXTURE_SHA256 or sources.get(FIXTURE_NAME) != FIXTURE_SHA256):
        raise ValueError("Store complete original caller freeze identity differs")
    original = json.loads(raw)
    ordinary = original.get("prior_ordinary_9_modules", [])
    separate = original.get("prior_separate_8_modules", [])
    inventory = original.get("modules", {})
    selected = [*ordinary, ARTIFACT_MODULE]
    if (original.get("schema") != "hepta.hia.store-artifact-profile-caller-freeze.v1"
            or original.get("base_commit") != "73f16346e7f84fa13305777a4595e2d1b422dee9"
            or original.get("base_tree") != "979fcc94c1c6a045e7f6740c97d30c0fdded2dd3"
            or len(ordinary) != 9 or len(set(ordinary)) != 9 or len(separate) != 8 or len(set(separate)) != 8
            or len(set(selected) | set(separate)) != 18 or not set(selected + separate) <= set(inventory)
            or original.get("candidate_module_count") != 40
            or original.get("candidate_complete_module_method_count") != 612
            or original.get("every_listed_method_claimed_to_enter_Store_artifact_owner") is not False
            or original.get("whole_project_dynamic_caller_closure_claimed") is not False):
        raise ValueError("Store original selected/separate caller scopes differ")
    ordinary_ids = [name for module in ordinary for name in inventory[module]["ordered_ids"]]
    artifact_ids = inventory[ARTIFACT_MODULE]["ordered_ids"]
    separate_ids = [name for module in separate for name in inventory[module]["ordered_ids"]]
    planned = [*ordinary_ids, *artifact_ids]
    if (len(ordinary_ids) != 112 or len(artifact_ids) != 18 or len(separate_ids) != 128
            or len(set(planned + separate_ids)) != 258
            or ordinary_ids != original.get("prior_ordinary_112_ordered_ids")
            or separate_ids != original.get("prior_separate_128_ordered_ids")):
        raise ValueError("Store original 112 + 18 and separate 128 ordered IDs differ")
    adjustments = admit_original_sources(root, original)
    original_files = {}
    for module in selected + separate:
        row = inventory[module]
        observed = [item["id"] for item in discovery["test_descriptions"] if item["id"].startswith(module + ".")]
        if (row.get("source") != module.replace(".", "/") + ".py"
                or observed != row.get("ordered_ids") or type(row.get("count")) is not int
                or row["count"] != len(observed)):
            raise ValueError("Store complete retained original caller module differs: " + module)
        original_files[row["source"]] = row["sha256"]
    descriptions = [row for module in selected for row in discovery["test_descriptions"]
                    if row["id"].startswith(module + ".")]
    if [row["id"] for row in descriptions] != planned:
        raise ValueError("Store current complete discovery changed original 130 ordering")
    return original, selected, original_files, adjustments, descriptions, planned


def store_profile_event_accounting(report, planned):
    allowed = {"continuation:" + str(number) for number in range(4)}
    events = store_profile_positive_counts(report.get("actual_native_event_counts"), allowed, allowed - {"continuation:3"})
    modes = store_profile_positive_counts(report.get("frames_by_mode"), STORE_PROFILE_MODES)
    frames = report.get("actual_store_artifact_profile_frames")
    if (type(frames) is not int or frames <= 0 or sum(modes.values()) != frames
            or events["continuation:0"] != frames
            or events["continuation:1"] != events["continuation:2"] + events.get("continuation:3", 0)):
        raise ValueError("Store aggregate physical frame and native entry accounting differs")
    frame_rows = store_profile_positive_counts(report.get("frames_by_original_test"), planned)
    event_rows = report.get("native_event_counts_by_original_test")
    mode_rows = report.get("modes_by_original_test")
    if (sum(frame_rows.values()) != frames or type(event_rows) is not dict or type(mode_rows) is not dict
            or set(event_rows) != set(planned) or set(mode_rows) != set(frame_rows)
            or any((identity in frame_rows) != bool(row) for identity, row in event_rows.items())):
        raise ValueError("Store complete per-test frame/event/mode observation keys differ")
    total_events, total_modes = {}, {}
    for identity, row in event_rows.items():
        store_profile_positive_counts(row, allowed)
        mode_row = store_profile_positive_counts(mode_rows.get(identity, {}), STORE_PROFILE_MODES)
        if (row.get("continuation:0", 0) != frame_rows.get(identity, 0)
                or row.get("continuation:1", 0) != row.get("continuation:2", 0) + row.get("continuation:3", 0)
                or sum(mode_row.values()) != frame_rows.get(identity, 0)):
            raise ValueError("Store per-original-method native observations are inconsistent")
        for key, value in row.items():
            total_events[key] = total_events.get(key, 0) + value
        for key, value in mode_row.items():
            total_modes[key] = total_modes.get(key, 0) + value
    if total_events != events or total_modes != modes:
        raise ValueError("Store aggregates differ from their complete per-method entries")
    return frames, events


def store_profile_caller_record(directory, root, sources, discovery, manifest_path, pins):
    """Read an honest complete terminal record, including a failed historical run.

    This function never qualifies a run. The public require wrapper separately
    demands matching current cold, no anomalies and all 130 verbose statuses ok.
    """
    from tools.qualify_hia_store_artifact_profile_callers import FIXTURE_NAME, ARTIFACT_MODULE
    from tools.build_hia_store_artifact_profile import INPUTS, SOURCE_NAME
    from tools.hia_selfhost_contract import file_digests
    directory, manifest_path = Path(directory), Path(manifest_path)
    manifest = release_json(manifest_path, pins)
    build = release_json(manifest_path.with_name("build.json"), pins)
    report = release_json(directory / "report.json", pins)
    original, selected, original_files, adjustments, descriptions, planned = store_profile_original_inventory(
        root, sources, discovery, pins)
    names = set(file_digests(root)) | {*INPUTS, *original_files, FIXTURE_NAME,
                                      "tools/qualify_hia_store_artifact_profile_callers.py"}
    source_pins = {name: hashlib.sha256(release_bytes(root / name, pins)).hexdigest() for name in names}
    bundle_pins = {}
    for path in sorted(manifest_path.parent.rglob("*")):
        if path.is_symlink():
            raise ValueError("Store original caller build contains a symlink")
        if path.is_file():
            bundle_pins[str(path)] = hashlib.sha256(release_bytes(path, pins)).hexdigest()
    scopes = {"MATCHING_SOURCE_COLD_TEN_ORIGINAL_STORE_ARTIFACT_PROFILE_CALLER_MODULES",
              "EXPLICIT_DEVELOPMENT_TEN_ORIGINAL_STORE_ARTIFACT_PROFILE_CALLER_MODULES"}
    expected_scope = ("MATCHING_SOURCE_COLD_COMPONENT" if report.get("scope", "").startswith("MATCHING_SOURCE_COLD_")
                      else "DEVELOPMENT_COMPONENT")
    if (report.get("schema") != "hepta.hia.store-artifact-profile-ten-original-callers.v1"
            or report.get("status") not in ("PASS", "FAIL") or report.get("scope") not in scopes
            or build.get("scope") != expected_scope
            or report.get("original_baseline_commit") != original["base_commit"]
            or report.get("original_modules") != selected
            or not (report.get("planned") == report.get("started") == report.get("stopped") == planned)
            or type(report.get("actual_tests")) is not int or report["actual_tests"] != 130
            or report.get("reference_calls") != []
            or report.get("all_eight_retained_bodies_forbidden") is not True
            or report.get("reference_poison_scope") != "test process; subprocesses retain their original environment and do not inherit Python patches"
            or report.get("all_ten_original_modules_unfiltered") is not True
            or report.get("original_test_budgets_changed") is not False
            or type(report.get("original_artifact_bytes_limit")) is not int or report["original_artifact_bytes_limit"] != 67108864
            or type(report.get("original_store_subprocess_deadline_seconds")) is not int or report["original_store_subprocess_deadline_seconds"] != 60
            or report.get("new_production_wall_cap") is not False or report.get("original_18_fixture_setup_replaced") is not False
            or report.get("source_and_bundle_unchanged") is not True
            or report.get("original_registry_count_assertion_adjustments") != adjustments
            or report.get("separate_original_administrator_scope_gates") != original["prior_separate_8_modules"]
            or report.get("separate_original_administrator_scope_ordered_ids") != original["prior_separate_128_ordered_ids"]
            or report.get("whole_project_dynamic_caller_closure_claimed") is not False
            or report.get("whole_native_delivery_qualified") is not False
            or manifest.get("schema") != "hepta.hia.store-artifact-profile.v1"
            or manifest.get("source_sha256") != sources[SOURCE_NAME]
            or report.get("native_image_sha256") != manifest["image_sha256"]
            or bundle_pins.get(str(manifest_path.parent / manifest["image_path"])) != manifest["image_sha256"]
            or report.get("source_pins") != source_pins or not bundle_pins or report.get("bundle_pins") != bundle_pins
            or any(name in sources and sources[name] != digest for name, digest in source_pins.items())
            or any(name not in sources and name not in original_files for name in source_pins)):
        raise ValueError("Store original complete 130-method caller observations or captured inputs differ")
    frames, events = store_profile_event_accounting(report, planned)
    ordinary_ids = original["prior_ordinary_112_ordered_ids"]
    artifact_ids = original["modules"][ARTIFACT_MODULE]["ordered_ids"]
    groups = {}
    for key, modules, ids in (("ordinary_112", original["prior_ordinary_9_modules"], ordinary_ids),
                              ("artifact_store_18", [ARTIFACT_MODULE], artifact_ids)):
        total = sum(sum(report["native_event_counts_by_original_test"].get(name, {}).values()) for name in ids)
        if total <= 0:
            raise ValueError("Store original caller group observed no native entries")
        groups[key] = {"modules": modules, "ordered_ids": ids,
                       "original_source_sha256": {original["modules"][module]["source"]:
                           original["modules"][module]["sha256"] for module in modules},
                       "actual_native_entries": total}
    if evaluation_json_bytes(report.get("original_groups")) != evaluation_json_bytes(groups):
        raise ValueError("Store original ordinary112/artifact18 groups or actual observations differ")
    observed = audit_verbose_stderr(release_bytes(directory / "tests.log", pins),
        {"planned_test_ids": planned, "test_descriptions": descriptions})
    if (observed.get("errors") or observed.get("started_matches_planned_in_order") is not True
            or observed.get("completed_matches_planned_in_order") is not True):
        raise ValueError("Store original verbose log does not independently account for all 130 methods")
    statuses = {row["id"]: row["terminal_status_candidates"][0]["status"] for row in observed["observations"]}
    for key, status in (("errors", "ERROR"), ("failures", "FAIL"), ("skipped", "skipped"),
                        ("expected_failures", "expected failure"), ("unexpected_successes", "unexpected success")):
        values = report.get(key)
        if type(values) is not list:
            raise ValueError("Store original caller anomaly collection is absent")
        ids = values if key == "unexpected_successes" else [row[0] for row in values]
        expected = [identity for identity, value in statuses.items()
                    if value == status or status == "skipped" and value.startswith("skipped ")]
        if ids != expected:
            raise ValueError("Store serialized anomalies differ from the actual original verbose terminal statuses")
    clean = all(report[key] == [] for key in ("errors", "failures", "skipped", "expected_failures", "unexpected_successes"))
    if (report["status"] == "PASS") != (clean and observed["equivalent"]):
        raise ValueError("Store reported qualification status contradicts its original terminal observations")
    return {"actual_tests": 130, "actual_store_artifact_profile_frames": frames,
            "actual_native_event_counts": events, "frames_by_mode": report["frames_by_mode"],
            "original_groups": groups, "source_pin_count": len(source_pins), "bundle_pin_count": len(bundle_pins),
            "original_verbose_identity": observed, "complete_selected_and_separate_original_inventory_count": 258,
            "original_registry_count_assertion_adjustments": adjustments,
            "separate_administrator_scope_inventory_modules": original["prior_separate_8_modules"],
            "reference_poison_scope": report["reference_poison_scope"], "observed_report_scope": report["scope"],
            "observed_report_status": report["status"],
            "original_artifact_fixture_cold_selector": report["original_artifact_fixture_cold_selector"],
            "anomalies": {key: report[key] for key in ("errors", "failures", "skipped", "expected_failures", "unexpected_successes")},
            "historical_record_readback_is_qualification": False,
            "original_test_budgets_changed": False, "whole_project_dynamic_caller_closure_claimed": False,
            "test_bodies_rerun_by_readback": False, "whole_native_delivery_qualified": False}


def require_store_profile_callers(directory, root, sources, discovery, manifest_path, cold_path, pins):
    result = store_profile_caller_record(directory, root, sources, discovery, manifest_path, pins)
    build = release_json(Path(manifest_path).with_name("build.json"), pins)
    if (cold_path is None or result["observed_report_status"] != "PASS"
            or result["observed_report_scope"] != "MATCHING_SOURCE_COLD_TEN_ORIGINAL_STORE_ARTIFACT_PROFILE_CALLER_MODULES"
            or build.get("scope") != "MATCHING_SOURCE_COLD_COMPONENT"
            or build.get("source_manifest") != sources or build.get("cold_report_sha256") != sha(cold_path)
            or result["original_artifact_fixture_cold_selector"] != str(cold_path)
            or result["original_verbose_identity"].get("equivalent") is not True
            or any(result["anomalies"].values())):
        raise ValueError("Store requires the actual same-current-cold complete 130 PASS; DEV or failed originals cannot qualify")
    return {**result, "both_Store_and_original_artifact18_fixtures_use_same_current_cold": True,
            "all_130_original_methods_successful_in_exact_order": True}


def require_store_profile_component(directory, root, cold_path, compiler, sources, pins):
    directory = Path(directory)
    manifest_path = directory / "built/manifest.json"
    require_cold_component(manifest_path, "examples/hia_bootstrap/store_artifact_profile.hepta",
                           sha(cold_path), sha(compiler), sources, pins)
    manifest, custody = store_profile_custody(directory, root, cold_path, compiler, sources, pins)
    return {"scope": "MATCHING_SOURCE_COLD_COMPONENT", "manifest": str(manifest_path),
            "image_sha256": manifest["image_sha256"],
            "controls": store_profile_control_observations(directory, root, sources, pins, runtime=sys.version),
            "installation": require_store_profile_installation(directory, sources, manifest, pins),
            "source_and_compiler_custody_verified": True, "test_result_owned_by_original_full_runner": True,
            "test_bodies_rerun_by_supplement": False, "transaction_context_manager_migrated": False,
            "cross_owner_causal_loss_closure_qualified": False,
            "whole_native_delivery_qualified": False, "passed": True}



# Delivery acceptance adds readback only. None of these helpers runs a product
# suite, creates a component, loads an image, or supplies a development selector.
DELIVERY_OWNERS = (
    'service_context', 'store_lifecycle', 'cost_ledger', 'evaluation',
    'native_build_admission', 'emission', 'execution_budget', 'candidate_budget', 'agent_journal',
)
DELIVERY_COMPONENT_MODULES = (
    'tests.test_hia_service_context_native', 'tests.test_hia_store_lifecycle_native',
    'tests.test_hia_cost_ledger_native', 'tests.test_hia_evaluation_native',
    'tests.test_hia_native_build_admission_native', 'tests.test_hia_native_build_dispatch',
    'tests.test_hia_emission_native', 'tests.test_hia_native_transport_failures',
    'tests.test_hia_execution_budget_native', 'tests.test_hia_candidate_budget_native',
    'tests.test_hia_agent_journal_native',
)
DELIVERY_CALLERS = ('service_context', 'cost_ledger', 'evaluation',
                    'native_build_admission', 'emission', 'agent_journal')
DELIVERY_METHODS = {
    'frames': 'test_six_real_frames_block_swallowed_and_replaced_cross_owner_loss',
    'cleanup': 'test_active_except_cleanup_cannot_suppress_cross_owner_loss',
    'safe': 'test_safe_preentry_confirmed_refusal_and_foreign_unknown_do_not_publish',
    'requests': 'test_both_journals_keep_running_intent_after_swallowed_and_replaced_loss',
    'journal_gaps': 'test_final_serialization_and_sql_before_ack_cannot_hide_loss',
    'budgets': 'test_budget_invocations_follow_actual_parent_and_keep_original_sql_refusals',
    'ancestry': 'test_stale_thread_and_fork_contexts_do_not_adopt_inherited_custody',
    'installed': 'test_actual_installed_worker_pinned_bundle_blocks_cross_owner_loss',
}
STORE_DELIVERY_METHODS = {
    'frames': 'test_all_seven_frame_families_bidirectional_actual_loss',
    'cleanup': 'test_literal_children_and_active_exit_cannot_swallow_or_replace_loss',
    'initialization': 'test_native_init_pending_and_preentry_refusal_keep_distinct_custody',
    'safe': 'test_ordinary_foreign_and_confirmed_child_keep_original_exception_identity',
    'ancestry': 'test_prepared_frames_implicit_release_thread_and_fork_ancestry',
    'requests': 'test_both_original_journals_keep_unknown_intent_and_no_replay',
    'installed': 'test_actual_installed_worker_store_peer_journal_bundle',
    'installed_process': 'test_actual_worker_process_loss_and_packaged_source_drift',
}


def delivery_literal_values(path, names, pins):
    """Read narrow constant declarations, without importing product code."""
    tree = ast.parse(release_bytes(path, pins))
    declarations = {node.targets[0].id: node.value for node in tree.body
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)}
    active = set()
    def value(node, local):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in local:
                return local[node.id]
            if node.id in active or node.id not in declarations:
                raise ValueError('delivery constant dependency is missing or cyclic')
            active.add(node.id)
            try:
                return value(declarations[node.id], local)
            finally:
                active.remove(node.id)
        if isinstance(node, (ast.Tuple, ast.List)):
            result = []
            for item in node.elts:
                if isinstance(item, ast.Starred):
                    result.extend(value(item.value, local))
                else:
                    result.append(value(item, local))
            return tuple(result) if isinstance(node, ast.Tuple) else result
        if isinstance(node, ast.Dict) and all(key is not None for key in node.keys):
            return {value(key, local): value(item, local) for key, item in zip(node.keys, node.values)}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return value(node.left, local) + value(node.right, local)
        if isinstance(node, ast.JoinedStr):
            result = []
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    result.append(part.value)
                elif isinstance(part, ast.FormattedValue) and part.conversion == -1 and part.format_spec is None:
                    item = value(part.value, local)
                    if type(item) is not str:
                        raise ValueError('delivery declaration requires exact string substitution')
                    result.append(item)
                else:
                    raise ValueError('unsupported delivery constant formatting')
            return ''.join(result)
        if isinstance(node, ast.GeneratorExp) and len(node.generators) == 1:
            loop = node.generators[0]
            if isinstance(loop.target, ast.Name) and not loop.ifs and not loop.is_async:
                return tuple(value(node.elt, dict(local, **{loop.target.id: item}))
                             for item in value(loop.iter, local))
        raise ValueError('delivery declaration is not a supported static constant: ' + type(node).__name__)
    return {name: value(ast.Name(id=name, ctx=ast.Load()), {}) for name in names}


def delivery_original_inventory(root, pins, *, store=False):
    root = Path(root)
    module = 'tests/test_hia_store_native_delivery.py' if store else 'tests/test_hia_native_delivery.py'
    fixture = ('tests/fixtures/store_native_delivery_original_c019.json' if store else
               'tests/fixtures/native_delivery_original_9c46166.json')
    constants = delivery_literal_values(root / module, ('ORIGINAL_SHA256',), pins)
    raw = release_bytes(root / fixture, pins)
    original = json.loads(raw)
    if hashlib.sha256(raw).hexdigest() != constants['ORIGINAL_SHA256']:
        raise ValueError('delivery frozen original fixture digest differs')
    expected_base = ('c0195643083e1d4c68679237edfa77143dc7b1c6' if store else
                     '9c461664adc27e576d33fba6618b3764672eea9d')
    if original.get('base_commit') != expected_base or original.get('runtime_execution_before_freeze') is not False:
        raise ValueError('delivery original fixture identity differs')
    if store:
        inventory = original.get('original_caller_inventory', {})
        components = inventory.get('D0_D3_component_ordered_152', {})
        if (original.get('base_tree') != '7a37b1ced47251fdc58e50624a5f77be56af374a'
                or original.get('D0_D3_original_component_modules') != list(DELIVERY_COMPONENT_MODULES)
                or len(inventory.get('ordinary_ordered_112', [])) != 112
                or len(inventory.get('store_ordinary_and_artifact_ordered_130', [])) != 130
                or len(inventory.get('artifact_publication_ordered_18', [])) != 18
                or len(inventory.get('separate_ordered_128', [])) != 128
                or len(inventory.get('lifecycle_ordered_50', [])) != 50
                or len(original.get('unchanged_files', {})) != 89
                or original.get('whole_native_delivery_qualified') is not False):
            raise ValueError('Store delivery complete original inventory differs')
    else:
        components = original.get('component_ordered_ids', {})
        if (original.get('component_modules') != list(DELIVERY_COMPONENT_MODULES)
                or len(original.get('ordinary_ordered_ids', [])) != 112
                or len(original.get('unchanged_files', {})) != 64):
            raise ValueError('D0-D3 complete original inventory differs')
    ids = [item for name in DELIVERY_COMPONENT_MODULES for item in components.get(name, [])]
    if set(components) != set(DELIVERY_COMPONENT_MODULES) or len(ids) != 152 or len(set(ids)) != 152:
        raise ValueError('delivery requires exactly the frozen eleven complete modules / 152 ordered methods')
    helper_tree = ast.parse(release_bytes(root / 'hepta/hia_native_helpers.py', pins))
    helpers = [node.value for node in helper_tree.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == 'HELPERS' for target in node.targets)]
    if len(helpers) != 1 or not isinstance(helpers[0], ast.Dict) or any(key is None for key in helpers[0].keys):
        raise ValueError('delivery helper registry must remain an explicit dictionary')
    helper_count, previous = len(helpers[0].keys), 39 if store else 38
    adjustments = []
    composition = final_store_composition(root, original, pins) if store else None
    for name, expected in original['unchanged_files'].items():
        body = release_bytes(root / name, pins)
        digest = hashlib.sha256(body).hexdigest()
        if composition is not None and name in composition['source_adjustments']:
            fixed = composition['source_adjustments'][name]
            if len(body) != fixed['current_bytes'] or digest != fixed['current_sha256']:
                raise ValueError('final Store successor changed after complete composition admission: ' + name)
            continue
        if len(body) == expected['bytes'] and digest == expected['sha256']:
            continue
        old = ('        self.assertEqual(len(HELPERS), ' + str(previous) + ')\n').encode()
        new = ('        self.assertEqual(len(HELPERS), ' + str(helper_count) + ')\n').encode()
        restored = body.replace(new, old, 1)
        if (name != 'tests/test_hia_worker_native_helpers.py' or helper_count < previous
                or body.count(new) != 1 or len(restored) != expected['bytes']
                or hashlib.sha256(restored).hexdigest() != expected['sha256']):
            raise ValueError('delivery original test, fixture or caller changed: ' + name)
        adjustment = {'path': name, 'original_sha256': expected['sha256'], 'current_sha256': digest,
                      'original_helper_count': previous, 'current_helper_count': helper_count,
                      'sole_permitted_change': 'one exact registry-count assertion decimal literal'}
        if not store:
            adjustment['all_other_source_bytes_unchanged'] = True
        adjustments.append(adjustment)
    result = {**original, 'registry_count_adjustments': adjustments}
    if composition is not None:
        result.update(successor_source_adjustments=composition['source_adjustments'],
                      shared_source_adjustments=composition['shared_adjustments'],
                      shared_dependency_review=composition['shared_dependency_review'],
                      final_store_composition=composition['identity'])
    return result


def delivery_source_identity(root, sources, original, pins, *, store=False):
    expected = {name: digest for name, digest in sources.items() if name != 'docs/HIA_SELFHOST_CORE_SUPPORT.json'}
    extra = {'tests/test_hia_native_delivery.py', 'tests/hia_native_delivery_cases.py',
             'tests/fixtures/native_delivery_original_9c46166.json', 'tools/qualify_hia_native_delivery.py'}
    if store:
        extra |= set(original['unchanged_files']) | set(original['shared_dependency_review']) | {
            'hepta/hia_native_delivery.py', 'tests/test_hia_store_native_delivery.py',
            'tests/hia_store_native_delivery_cases.py', 'tests/fixtures/store_native_delivery_original_c019.json',
            'hepta/hia_store_artifact_profile_native.py', 'tools/build_hia_store_artifact_profile.py',
            FINAL_STORE_SUCCESSOR_HELPER, FINAL_STORE_SUCCESSOR}
    for name in extra:
        digest = hashlib.sha256(release_bytes(Path(root) / name, pins)).hexdigest()
        if name in expected and expected[name] != digest:
            raise ValueError('delivery extra source differs from the admitted source contract')
        expected[name] = digest
    return expected


def delivery_compile_readback(directory, owner, root, compiler, sources, pins, *, cold_path=None, development=False):
    """Check actual original receipt/output bytes with no image execution or product import."""
    if type(development) is not bool or development == (cold_path is not None):
        raise ValueError('delivery readback requires exactly one explicit source scope')
    directory, root, compiler = Path(directory), Path(root), Path(compiler)
    special = owner in ('execution_budget', 'candidate_budget', 'agent_journal')
    labels = {'service_context': 'service-context', 'store_lifecycle': 'store-lifecycle',
              'cost_ledger': 'cost-ledger'}
    label = labels.get(owner, owner)
    if special:
        label = 'agent-journal' if owner == 'agent_journal' else (owner if development else owner.replace('_', '-'))
    source_name = 'examples/hia_bootstrap/' + owner + '.hepta'
    source, artifact = release_bytes(root / source_name, pins), release_bytes(compiler, pins)
    source_sha, compiler_sha = hashlib.sha256(source).hexdigest(), hashlib.sha256(artifact).hexdigest()
    manifest = release_json(directory / 'manifest.json', pins)
    receipt = release_json(directory / (label + '.receipt.json'), pins)
    request = release_json(directory / (label + '.request.json'), pins)
    image_path = directory / (label + '.image.bin')
    image, output = release_bytes(image_path, pins), release_bytes(directory / (label + '.output.bin'), pins)
    build = release_json(directory / ('development-build.json' if special and development else 'build.json'), pins)
    schemas = {'native_build_admission': 'hepta.hia.native-build-admission.v1',
               'store_artifact_profile': 'hepta.hia.store-artifact-profile.v1',
               'agent_journal': 'hepta.hia.agent-journal-native.v2'}
    schema = schemas.get(owner, 'hepta.hia.' + owner.replace('_', '-') + '-native.v1')
    expected_manifest = {'schema': schema, 'source_sha256': source_sha, 'image_path': image_path.name,
                         'image_sha256': hashlib.sha256(image).hexdigest(), 'compiler_sha256': compiler_sha}
    size = len(image)
    if (manifest != expected_manifest or source_sha != sources.get(source_name)
            or build.get('manifest') != manifest or build.get('native_compile_receipt') != receipt
            or not 0 < size <= len(output) <= 1048576 or output[:size] != image
            or release_bytes(directory / (label + '.input.bin'), pins) != source
            or request != {'capacity': 1048576, 'format': 'flat-x86-64', 'image': str(compiler),
                'image_sha256': compiler_sha, 'output': str(directory / (label + '.output.bin')),
                'source': str(directory / (label + '.input.bin')), 'source_sha256': source_sha,
                'workspace_fill': 0, 'workspace_size': 1048576}
            or receipt.get('status') != 'returned' or type(receipt.get('abi_status')) is not int
            or receipt['abi_status'] != 0 or type(receipt.get('core_u32')) is not int or receipt['core_u32'] != size
            or type(receipt.get('result_u64')) is not int or receipt['result_u64'] != size
            or receipt.get('format') != 'flat-x86-64' or receipt.get('return_encoding') != 'zero-extended-u32'
            or receipt.get('output_sha256') != hashlib.sha256(output).hexdigest()
            or receipt.get('artifact_sha256') != compiler_sha or receipt.get('image_sha256') != compiler_sha
            or receipt.get('input_sha256') != source_sha or receipt.get('source_sha256') != source_sha
            or type(receipt.get('input_bytes')) is not int or receipt['input_bytes'] != len(source)
            or receipt.get('source_unchanged') is not True or receipt.get('forbidden_compiler_modules_loaded') != []
            or type(receipt.get('produced_bytes')) is not int or receipt['produced_bytes'] != size
            or receipt.get('produced_sha256') != manifest['image_sha256']
            or receipt.get('produced_image') != str(image_path)):
        raise ValueError('delivery actual compiler request, receipt, full output or image differs: ' + owner)
    if not special:
        inputs = delivery_literal_values(root / ('tools/build_hia_' + owner + '.py'), ('INPUTS',), pins)['INPUTS']
        if (type(inputs) is not tuple or any(type(name) is not str for name in inputs)
                or len(inputs) != len(set(inputs))
                or build.get('component_inputs') != {name: sources[name] for name in inputs}):
            raise ValueError('delivery original builder input inventory differs: ' + owner)
    if development:
        if (build.get('scope') != 'DEVELOPMENT_COMPONENT'
                or (special and build.get('matching_current_source_cold_qualified') is not False)
                or (not special and (build.get('cold_report_sha256') is not None
                                     or build.get('source_manifest') is not None))):
            raise ValueError('delivery development evidence has been relabeled')
    else:
        if (build.get('cold_report_sha256') != hashlib.sha256(release_bytes(cold_path, pins)).hexdigest()
                or build.get('source_manifest') != sources
                or (special and (build.get('status') != 'NATIVE_CANDIDATE_BUILT'
                                  or build.get('profile') != 'selfhost-core-linux-x86_64-v92p-native-closed-output-before-exec'))
                or (not special and build.get('scope') != 'MATCHING_SOURCE_COLD_COMPONENT')):
            raise ValueError('delivery build is not bound to the same current-source cold: ' + owner)
    return manifest


def delivery_custody(directory, root, compiler, sources, pins, *, cold_path=None, development=False, store=False):
    if type(development) is not bool or development == (cold_path is not None):
        raise ValueError('delivery custody requires explicit DEV or the real same-run cold')
    directory = Path(directory)
    original = delivery_original_inventory(root, pins, store=store)
    expected_sources = delivery_source_identity(root, sources, original, pins, store=store)
    owners = (('store_artifact_profile',) if store else ()) + DELIVERY_OWNERS
    custody = release_json(directory / 'component-custody.json', pins)
    manifests, build_files = {}, {}
    for owner in owners:
        path = directory / ('build-' + owner) / 'manifest.json'
        delivery_compile_readback(path.parent, owner, root, compiler, sources, pins,
                                  cold_path=cold_path, development=development)
        manifests[owner] = str(path)
        for item in sorted(path.parent.rglob('*')):
            if item.is_symlink():
                raise ValueError('delivery captured build contains a symlink')
            if item.is_file():
                build_files[str(item)] = hashlib.sha256(release_bytes(item, pins)).hexdigest()
    schema = 'hepta.hia.' + ('store-native-delivery' if store else 'native-delivery') + '-custody.v1'
    stable = 'source_compiler_cold_and_build_unchanged' if store else 'source_compiler_and_build_unchanged'
    if (custody.get('schema') != schema
            or custody.get('scope') != ('DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT')
            or custody.get('matching_cold_report') != (None if development else str(cold_path))
            or custody.get('compiler_sha256') != hashlib.sha256(release_bytes(compiler, pins)).hexdigest()
            or custody.get('manifests') != manifests or release_json(directory / 'manifests.json', pins) != manifests
            or custody.get('build_files') != build_files or not build_files
            or custody.get('source_before') != expected_sources or custody.get('source_after') != expected_sources
            or custody.get(stable) is not True or custody.get('test_result_owned_by_outer_runner') is not True
            or custody.get('whole_native_delivery_qualified') is not False):
        raise ValueError('delivery source, compiler, cold or complete build custody differs')
    if store:
        if (custody.get('matching_cold_sha256') != (None if development else sha(cold_path))
                or custody.get('implemented_scope') != 'D4 Store active delivery with explicit D0-D3 dependencies'
                or any(custody.get(key) is not False for key in (
                    'artifact_provider_D5_delivery_qualified',
                    'independent_worker_finally_close_resource_association_qualified',
                    'opaque_provider_internal_effects_qualified'))):
            raise ValueError('Store delivery custody overstates the implemented boundary')
    elif (custody.get('implemented_scope') != ['D0', 'D1', 'D2', 'D3']
            or custody.get('store_artifact_profile_D4_integrated') is not False
            or custody.get('remaining_D5_integrated') is not False):
        raise ValueError('D0-D3 custody overstates its owner boundary')
    return {'scope': custody['scope'], 'manifests': manifests,
            'original_inventory': original, 'source_identity': expected_sources,
            'source_pin_count': len(expected_sources), 'build_pin_count': len(build_files),
            'custody_verified': True, 'matching_cold_qualified': not development,
            'whole_native_delivery_qualified': False}


def delivery_child_observations(directory, kind, pins, *, store=False):
    methods = STORE_DELIVERY_METHODS if store else DELIVERY_METHODS
    directory = Path(directory) / methods[kind]
    report = release_json(directory / 'observations.json', pins)
    if (report.get('schema') != 'hepta.hia.' + ('store-native-delivery' if store else 'native-delivery') + '-child.v1'
            or report.get('kind') != kind or report.get('status') != 'PASS'
            or json.loads(release_bytes(directory / 'stdout.log', pins)) != {'kind': kind, 'status': 'PASS'}):
        raise ValueError('delivery child observations or raw completion stdout differs: ' + kind)
    release_bytes(directory / 'stderr.log', pins)
    # The child's return code is asserted by its original complete Native class,
    # not separately serialized here; a PASS JSON alone is never full authority.
    return report


def delivery_headers(rows, *, width=4, events=None, nonempty=True):
    if (type(rows) is not list or (nonempty and not rows)
            or any(type(row) is not list or len(row) != width
                   or any(type(word) is not int or not 0 <= word < 1 << 64 for word in row)
                   or (events is not None and row[1] not in events) for row in rows)):
        raise ValueError('delivery actual native entry observations differ')
    return rows


def delivery_math_observations(rows, *, store=False):
    if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
            or set(rows[0]) != {'native_return', 'request_bytes'}
            or type(rows[0]['native_return']) is not int or type(rows[0]['request_bytes']) is not int
            or rows[0]['native_return'] <= 0 or rows[0]['request_bytes'] <= 0):
        raise ValueError('delivery requires the actual returned child arithmetic observation')


def delivery_running_request(row):
    if (type(row) is not dict or row.get('state') != 'running' or row.get('response') is not None
            or type(row.get('key')) is not str or type(row.get('digest')) is not str
            or not re.fullmatch('[0-9a-f]{64}', row['key']) or not re.fullmatch('[0-9a-f]{64}', row['digest'])
            or type(row.get('started_ns')) is not str or not row['started_ns'].isdecimal() or int(row['started_ns']) <= 0):
        raise ValueError('delivery request intent is not retained as running/unknown')


def delivery_store_snapshot_delta(before, retained, after, *, completed, payload_sha):
    """Check serialized durable rows; the original test owns the live SQLite read."""
    keys = {'request', 'artifacts', 'profiles', 'costs'}
    if (any(type(value) is not dict or set(value) != keys for value in (before, retained, after))
            or any(type(value[key]) is not list for value in (before, retained, after)
                   for key in ('artifacts', 'profiles', 'costs'))
            or before['request'] is not None or retained['profiles'] != before['profiles']
            or len(retained['artifacts']) != len(before['artifacts']) + 1
            or any(row not in retained['artifacts'] for row in before['artifacts'])
            or after['request'] != retained['request'] or after['artifacts'] != retained['artifacts']
            or after['profiles'] != retained['profiles']):
        raise ValueError('Store delivery durable publication or replay rows differ')
    added = [row for row in retained['artifacts'] if row not in before['artifacts']]
    if (len(added) != 1 or added[0].get('sha256') != payload_sha
            or type(payload_sha) is not str or not re.fullmatch('[0-9a-f]{64}', payload_sha)):
        raise ValueError('Store delivery durable payload digest differs from its sole added artifact')
    if completed:
        if (retained['request'].get('state') != 'completed'
                or type(retained['request'].get('response')) is not str
                or len(retained['costs']) != len(before['costs']) + 1
                or any(row not in retained['costs'] for row in before['costs']) or after != retained):
            raise ValueError('Store delivery normal request or exact replay differs')
    else:
        delivery_running_request(retained['request'])
        if (retained['costs'] != before['costs'] or len(after['costs']) != len(retained['costs']) + 1
                or any(row not in after['costs'] for row in retained['costs'])):
            raise ValueError('Store delivery unknown request cost/intent preservation differs')


def delivery_control_observations(directory, root, pins, *, store=False):
    methods = STORE_DELIVERY_METHODS if store else DELIVERY_METHODS
    reports = {kind: delivery_child_observations(directory, kind, pins, store=store)
               for kind in methods if not kind.startswith('installed')}
    if not store:
        rows = reports['frames'].get('cases', [])
        expected = [(parent, ('cost_ledger', 'service_context', 'evaluation')[index % 3], behavior)
                    for index, parent in enumerate(DELIVERY_OWNERS[:6])
                    for behavior in ('swallow', 'replace', 'memory')]
        if [(row.get('parent'), row.get('child'), row.get('behavior')) for row in rows] != expected:
            raise ValueError('D0-D3 six-family / eighteen original frame cases differ')
        for row in rows:
            delivery_headers(row.get('actual_parent_calls'), events={1})
            delivery_math_observations(row.get('actual_child_calls'))
            if (row.get('ack_or_foreign_error_ack_after_loss') is not False
                    or row.get('owner_retained') is not True
                    or row.get('memory_error_identity_preserved') is not (row['behavior'] == 'memory')):
                raise ValueError('D0-D3 frame acknowledgement or exception identity differs')
        cleanup = reports['cleanup'].get('cases', [])
        ports = delivery_literal_values(Path(root) / 'hepta/hia_emission_protocol.py', ('PORTS',), pins)['PORTS']
        exit_port = ports.index('compile_exit_exception') + 1
        if [row.get('behavior') for row in cleanup] != ['suppress', 'replace']:
            raise ValueError('D0-D3 complete active-except cleanup cases differ')
        for row in cleanup:
            calls = delivery_headers(row.get('parent_calls'))
            delivery_math_observations(row.get('child_calls'))
            if (row.get('active_exception_identity') != [True, True, True] or row.get('store_effects') != []
                    or not any(call[1] == 1 and call[3] == exit_port for call in calls)
                    or any(call[1] in (2, 3) and call[3] == exit_port for call in calls)):
                raise ValueError('D0-D3 cleanup acknowledged an unconfirmed child effect')
        safe = reports['safe']
        confirmed = safe.get('confirmed_arithmetic_followed_by_foreign_error', [])
        if (type(safe.get('preentry_native_calls')) is not int or safe['preentry_native_calls'] != 0
                or safe.get('native_refusal_confirmed') is not True
                or [row.get('owner') for row in confirmed] != list(DELIVERY_OWNERS[:6])
                or any(row.get('foreign_exception_identity_preserved') is not True
                       or row.get('confirmed_terminal') != 5 or row.get('loss') is not False for row in confirmed)):
            raise ValueError('D0-D3 preentry/confirmed foreign exception controls differ')
        requests = reports['requests'].get('cases', [])
        if [(row.get('lane'), row.get('behavior')) for row in requests] != [
                (lane, behavior) for lane in ('ordinary', 'native') for behavior in ('swallow', 'replace', 'memory')]:
            raise ValueError('D0-D3 both original journal lanes are required')
        for row in requests:
            delivery_running_request(row.get('request'))
            calls = delivery_headers(row.get('calls'), width=2)
            if (type(row.get('context_count')) is not int or row['context_count'] != 1 or any(call[0] == 3 for call in calls)
                    or calls[-1] != [2, 44]
                    or row.get('replay', {}).get('error', {}).get('code') != 'E_HIA_REQUEST_UNKNOWN'
                    or row.get('error_type') != ('MemoryError' if row['behavior'] == 'memory' else 'NativeDeliveryUnknown')
                    or row.get('memory_error_identity_preserved') is not (row['behavior'] == 'memory')):
                raise ValueError('D0-D3 lost SQL ACK was cached, replayed, or reclassified')
        gaps = reports['journal_gaps'].get('cases', [])
        expected_gaps = [('ordinary', 'terminal-serialization'), ('native', 'terminal-serialization'),
                         ('native', 'native-ack'), ('native', 'before-ack-lookup'), ('native', 'foreign-sql')]
        if (len(gaps) != 9 or [(row.get('lane'), row.get('boundary')) for row in gaps[:5]] != expected_gaps
                or [(row.get('operation'), row.get('after')) for row in gaps[5:]] != [
                    (operation, after) for operation in ('reserved', 'committed_inline') for after in (False, True)]):
            raise ValueError('D0-D3 complete serialization/SQL/exact activation cases differ')
        for row in gaps[:2]:
            delivery_running_request(row.get('request'))
            delivery_math_observations(row.get('child_calls'))
        for row, observed, count in zip(gaps[2:5], ('actual-native-ack-return', 'lookup-after-running-insert', 'foreign-sql-refusal'), (0, 0, 1)):
            if row.get('request') is not None or type(row.get('cost_count')) is not int or row['cost_count'] != count or row.get('observed') != [observed]:
                raise ValueError('D0-D3 original reservation rollback/foreign refusal differs')
        for row in gaps[5:]:
            stage = 2 if row['operation'] == 'reserved' else 7
            calls = row.get('calls')
            if (row.get('lane') != 'native' or row.get('boundary') != 'exact-ACK-activation'
                    or row.get('stage') != stage or row.get('active_after_call') is not False
                    or row.get('memory_error_identity_preserved') is not True
                    or row.get('complete') is not row['after'] or type(calls) is not list
                    or any(type(number) is not int for number in calls) or (stage in calls) is not row['after']
                    or type(row.get('new_lost_records')) is not int
                    or (row['new_lost_records'] != 0 if row['after'] else row['new_lost_records'] <= 0)):
                raise ValueError('D0-D3 actual ACK activation confirmation boundary differs')
            if row['operation'] == 'reserved':
                if row.get('request') is not None:
                    raise ValueError('D0-D3 reserved failure fabricated an intent')
            else:
                delivery_running_request(row.get('request'))
        budgets = reports['budgets'].get('cases', [])
        if len(budgets) != 5:
            raise ValueError('D0-D3 original execution/candidate budget cases are missing')
        first = budgets[0]
        if (first.get('owner') != 'execution' or first.get('entry_events') != [5, 6]
                or first.get('long_lived_store_constructed_outside_parent') is not True
                or first.get('stored') != {'context_id': 'context-execution', 'owner': 'a' * 64, 'used_native_ns': '0'}):
            raise ValueError('D0-D3 execution outcome ACK or owner retention differs')
        if [(row.get('lane'), row.get('failure')) for row in budgets[1:]] != [
                (lane, failure) for lane in ('ordinary', 'native') for failure in ('native', 'foreign')]:
            raise ValueError('D0-D3 complete candidate native/foreign boundary differs')
        for row in budgets[1:]:
            if row.get('owner') != 'candidate' or type(row.get('attempts')) is not int or row['attempts'] != 1:
                raise ValueError('D0-D3 candidate original attempt was refunded or repeated')
            if row['failure'] == 'native':
                delivery_running_request(row.get('request'))
                if row.get('native_events') != [0, 1, 2, 3, 2, 4]:
                    raise ValueError('D0-D3 candidate actual commit ACK is missing')
            elif (row.get('native_events') != [] or row.get('request', {}).get('state') != 'completed'
                    or json.loads(row['request']['response']).get('error', {}).get('code') != 'E_HIA_CANDIDATE_BUDGET_UNKNOWN'):
                raise ValueError('D0-D3 original foreign SQL refusal was reclassified')
        ancestry = reports['ancestry']
        guards = ancestry.get('owner_creator_guards', [])
        if ([row.get('owner') for row in guards] != list(DELIVERY_OWNERS[:6])
                or any(row.get('matches_original_direct_guard') is not True or row.get('native_entries') != 0
                       or row.get('causal_loss') is not False or not row.get('exception_type') or not row.get('message') for row in guards)
                or any(ancestry.get(key) is not True for key in ('late_frame_current_parent_poisoned',
                                                              'stale_parent_unpoisoned', 'new_thread_unpoisoned'))
                or ancestry.get('fork') != {'status': 'PASS', 'old_pid_unchanged': True,
                                           'inherited_owner_retained': True, 'new_parent_absent': True}):
            raise ValueError('D0-D3 creator/stale/thread/fork custody differs')
        delivery_math_observations(ancestry.get('actual_child_calls'))
        return {'cases_by_kind': {'frames': 18, 'cleanup': 2, 'safe_foreign': 6, 'requests': 6,
                                 'journal_gaps': 9, 'budgets': 5, 'creator_guards': 6},
                'actual_child_observations_read_back': True,
                'child_return_codes_owned_by_complete_original_Native8_assertions': True,
                'unserialized_SQL_counts_and_post_replay_rows_owned_by_original_methods': True,
                'all_pairs_of_six_frame_families_claimed': False, 'passed': True}

    rows = reports['frames'].get('cases', [])
    expected = [(parent, child, behavior, fault) for peer in DELIVERY_OWNERS[:6]
                for parent, child in (('store_artifact_profile', peer), (peer, 'store_artifact_profile'))
                for behavior in ('swallow', 'replace') for fault in ('ValueError', 'RuntimeError', 'KeyboardInterrupt')]
    if ([(row.get('parent'), row.get('child'), row.get('behavior'), row.get('fault_class')) for row in rows] != expected
            or reports['frames'].get('actual_both_directions') is not True
            or reports['frames'].get('all_seven_frame_families') is not True):
        raise ValueError('D4 complete bidirectional Store/six-peer/72-frame matrix differs')
    for row in rows:
        parent = delivery_headers(row.get('parent_calls'), width=5, events={1})
        child = delivery_headers(row.get('child_calls'), width=5)
        if (len(parent) != 1 or [call[1] for call in child] != [1, 2]
                or any(call[4] <= 0 for call in parent + child)
                or any(row.get(key) is not True for key in ('same_actual_loss_origin', 'no_parent_ACK_or_event3',
                                                           'no_replay_entry', 'unknown_owner_retained'))):
            raise ValueError('D4 actual child ACK and fenced parent observations differ')
    ports = delivery_literal_values(Path(root) / 'hepta/hia_store_artifact_profile_protocol.py', ('PORTS',), pins)['PORTS']
    cleanup = reports['cleanup'].get('cases', [])
    if ([(row.get('boundary'), row.get('behavior')) for row in cleanup] != [
            ('literal-public-put', 'swallow'), ('literal-public-put', 'replace'),
            ('active-except-exit', 'suppress'), ('active-except-exit', 'replace')]
            or reports['cleanup'].get('native_artifact_provider_D5_exercised') is not False):
        raise ValueError('D4 complete literal/active-except cleanup boundary differs')
    for row in cleanup:
        literal = row['boundary'] == 'literal-public-put'
        target = ports.index('json_call_put' if literal else 'put_exit_exception') + 1
        calls = delivery_headers(row.get('parent_and_argument_entries' if literal else 'calls'), width=5)
        delivery_math_observations(row.get('child_calls'), store=True)
        if (not any(call[1] == 1 and call[3] == target for call in calls)
                or any(call[1] in (2, 3) and call[3] == target for call in calls)
                or not row.get('trace') or (literal and (row.get('ACK_after_loss') is not False
                    or not any(call[1] == 0 for call in calls)))
                or (not literal and (row.get('active_exception_identity') != [[True, True, True]]
                    or row.get('no_cleanup_retry') is not True or row.get('temporary_retained') is not True))):
            raise ValueError('D4 literal or cleanup loss received an ACK or released custody')
    initialization = reports['initialization']
    cases = initialization.get('cases', [])
    if (len(cases) != 2 or initialization.get('exception_class_used_to_infer_loss') is not False
            or cases[0] != {'boundary': 'safe-packet-allocation', 'actual_entries': 0,
                            'owner_reservation_retired': True, 'ancestor_loss': False}
            or cases[1].get('boundary') != 'actual-init-receipt-loss'
            or cases[1].get('effect_started') is not False or cases[1].get('init_unknown_owner_retained') is not True
            or cases[1].get('same_actual_ancestor_origin') is not True or cases[1].get('replay_entries') != []):
        raise ValueError('D4 preentry and actual init receipt loss were conflated')
    if len(delivery_headers(cases[1].get('actual_entries'), width=5, events={0})) != 1:
        raise ValueError('D4 init must record exactly one real native return')
    safe = reports['safe']
    foreign = safe.get('confirmed_foreign_cases', [])
    if [row.get('fault_class') for row in foreign] != [
            'ValueError', 'MemoryError', 'RuntimeError', 'KeyboardInterrupt', 'SystemExit', 'StoreArtifactProfileUnknown']:
        raise ValueError('D4 original six foreign exception classes are missing')
    for row in foreign:
        calls = delivery_headers(row.get('parent_and_child_entries'), width=5)
        if (row.get('confirmed_child_phase') != 4 or row.get('parent_confirmed_phase') != 5
                or row.get('same_exception_object') is not True or row.get('loss') is not False
                or not any(call[1] == 3 for call in calls)):
            raise ValueError('D4 confirmed child and original foreign exception identity differ')
    unavailable = safe.get('foreign_observation_storage', {})
    delivery_headers(unavailable.get('calls'), width=5, events={1})
    if (unavailable.get('same_MemoryError_object') is not True or unavailable.get('original_foreign_class') != 'ValueError'
            or unavailable.get('retained_unknown_observation') is not True or unavailable.get('no_event3') is not True):
        raise ValueError('D4 failed foreign observation storage was misclassified')
    ancestry = reports['ancestry']
    cases = ancestry.get('cases', [])
    if (len(cases) != 4 or ancestry.get('no_global_custody_clear') is not True
            or [row.get('boundary') for row in cases] != ['prepared-before-actual-invocation',
                'implicit-release-between-ports', 'copied-thread-context', 'fork-with-parent-representation-locks-held']
            or cases[0].get('actual_parent_lost') is not True or cases[0].get('old_parent_lost') is not False
            or cases[1].get('observed') != [{'actual_owner': True, 'ambient_observation': False,
                'transport_error_type_preserved': True, 'original_native_cause_preserved': True, 'callback_failure': None}]
            or cases[1].get('temporary_retained') is not True
            or cases[2].get('observed') != ['StoreArtifactProfileUnknown-with-zero-entry', 'fresh-independent-finished']
            or cases[2].get('foreign_thread_cannot_poison_creator') is not True
            or cases[3] != {'boundary': 'fork-with-parent-representation-locks-held', 'status': 'PASS',
                           'fresh_parent': None, 'inherited_creator_unchanged': True, 'inherited_owner_retained': True}):
        raise ValueError('D4 prepared/implicit-release/thread/fork attribution differs')
    delivery_math_observations(cases[0].get('actual_child_calls'), store=True)
    delivery_math_observations(cases[1].get('child_calls'), store=True)
    delivery_headers(cases[1].get('calls'), width=5)
    delivery_headers(cases[2].get('fresh_thread_actual_entries'), width=5)
    requests = reports['requests']
    rows = requests.get('cases', [])
    if (requests.get('ordinary_and_native_journal_lanes') is not True
            or requests.get('resources_retained_until_disposable_process_exit') is not True
            or [(row.get('lane'), row.get('behavior')) for row in rows] != [
                (lane, behavior) for lane in ('ordinary', 'native') for behavior in ('swallow', 'replace', 'memory')]):
        raise ValueError('D4 complete two-journal six-case durable request matrix differs')
    for row in rows:
        delivery_math_observations(row.get('actual_peer_calls'), store=True)
        calls = delivery_headers(row.get('Store_calls'), width=5)
        if (row.get('MemoryError_identity_preserved') is not (row['behavior'] == 'memory')
                or row.get('raised') != ('MemoryError' if row['behavior'] == 'memory' else 'StoreArtifactProfileUnknown')
                or type(row.get('actual_publication_inserts')) is not int or row['actual_publication_inserts'] != 1 or any(call[1] == 3 for call in calls)
                or row.get('replay_Store_entries') != []
                or row.get('replay', {}).get('error', {}).get('code') != 'E_HIA_REQUEST_UNKNOWN'
                or row.get('native_artifact_provider_D5_not_selected') is not True):
            raise ValueError('D4 actual publication loss was completed, repeated, or reclassified')
        delivery_store_snapshot_delta(row.get('before'), row.get('retained_before_replay'), row.get('after_replay'),
                                      completed=False, payload_sha=row.get('durable_payload_sha256'))
    return {'cases_by_kind': {'frames': 72, 'cleanup': 4, 'initialization': 2,
                             'safe_foreign': 6, 'foreign_observation_storage': 1, 'ancestry': 4, 'requests': 6},
            'actual_child_observations_read_back': True,
            'child_return_codes_owned_by_complete_original_Native8_assertions': True,
            'durable_rows_are_original_live_read_snapshots_not_a_new_SQL_execution': True,
            'provider_D5_and_independent_worker_close_qualified': False, 'passed': True}


def delivery_counter_line(path, prefix, pins):
    raw = release_bytes(path, pins)
    rows = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    if len(rows) != 1:
        raise ValueError('delivery raw child stderr lacks its unique actual counter record')
    return json.loads(rows[0])


def delivery_worker_observations(directory, report, shared_sha, pins, *, store=False, adapter_sha=None):
    """Bind serialized observations to the real worker/replay stdout and stderr."""
    directory = Path(directory)
    modes = ['exit'] if report.get('kind') == 'installed_process' else ['normal', 'swallow', 'replace']
    rows = report.get('cases', [])
    if ([row.get('mode') for row in rows] != modes
            or report.get('all_D0_D3_owners_exercised_in_installed_child') is not False
            or report.get('whole_native_delivery_qualified') is not False):
        raise ValueError('delivery installed case inventory or scope differs')
    if store:
        if (report.get('scope') != 'actual installed worker; Store publication effect invokes context arithmetic; native journal'
                or any(report.get(key) is not True for key in ('startup_and_request_entries_separated',
                    'retained_Store_and_journal_bodies_forbidden_in_actual_child',
                    'authoring_and_test_imports_forbidden_in_actual_child'))
                or any(report.get(key) is not False for key in ('provider_internal_post_effect_delivery_qualified',
                    'independent_worker_finally_close_resource_link_qualified', 'remaining_D5_integrated'))):
            raise ValueError('D4 installed report overstates its provider/worker scope')
    elif report.get('scope') != 'actual installed worker; emission to context; native request journal':
        raise ValueError('D0-D3 installed scope differs')
    prefix = b'D4_COUNTS=' if store else b'DELIVERY_COUNTS='
    actual_rows = []
    for row in rows:
        mode = row['mode']
        first = release_bytes(directory / ('worker-' + mode + '.stdout'), pins)
        replay = release_bytes(directory / ('replay-' + mode + '.stdout'), pins)
        counts = delivery_counter_line(directory / ('worker-' + mode + '.stderr'), prefix, pins)
        replay_counts = delivery_counter_line(directory / ('replay-' + mode + '.stderr'), prefix, pins)
        replay_report = json.loads(replay)
        if (counts != row.get('counts') or replay_counts != row.get('replay_counts')
                or replay_report != row.get('replay_report')
                or replay_report.get('schema') != 'hia-agent-worker-report-v1'
                or replay_report.get('complete') is not True
                or replay_report.get('tool') != ('hia_artifact' if store else 'hia_emit')
                or replay_report.get('native_helpers_sha256') != report.get('bundle_sha256')
                or type(row.get('worker_exit')) is not int
                or counts.get('shared_module_sha256') != shared_sha
                or replay_counts.get('shared_module_sha256') != shared_sha):
            raise ValueError('delivery worker raw observations or pinned bundle/source differ')
        if store:
            scalar_counts = {'Store_unknown_frames', 'lost_returns', 'publication_inserts',
                             'shared_lost_records', 'shared_pending_native_records', 'swallowed'}
            for current in (counts, replay_counts):
                if (set(current) != scalar_counts | {'startup', 'request', 'shared_module_sha256', 'Store_adapter_sha256'}
                        or current.get('Store_adapter_sha256') != adapter_sha
                        or any(type(current[key]) is not int or current[key] < 0 for key in scalar_counts)
                        or any(type(current.get(phase)) is not dict or set(current[phase]) != {'store', 'context', 'journal'}
                               or any(type(value) is not int or value < 0 for value in current[phase].values())
                               for phase in ('startup', 'request'))):
                    raise ValueError('D4 actual startup/request counters or installed adapter digest differ')
            if (counts['startup']['store'] <= 0 or any(counts['request'][name] <= 0 for name in ('store', 'context', 'journal'))
                    or counts['publication_inserts'] != 1 or replay_counts['startup']['store'] <= 0
                    or replay_counts['request']['store'] != 0 or replay_counts['request']['context'] != 0
                    or replay_counts['publication_inserts'] != 0 or replay_counts['lost_returns'] != 0
                    or type(row.get('replay_exit')) is not int or row['replay_exit'] != 0
                    or row.get('native_artifact_provider_not_selected_or_qualified') is not True
                    or row.get('independent_worker_finally_close_preserved_not_resource_fenced') is not True):
                raise ValueError('D4 actual first request/replay entries or provider boundary differs')
            delivery_store_snapshot_delta(row.get('before'), row.get('retained_before_replay'), row.get('after_replay'),
                                          completed=mode == 'normal', payload_sha=row.get('durable_payload_sha256'))
            payload = ('installed D4 durable artifact — 雪 ' + mode).encode()
            if hashlib.sha256(payload).hexdigest() != row['durable_payload_sha256']:
                raise ValueError('D4 durable artifact is not the original installed control payload')
            if mode == 'normal':
                first_report = json.loads(first)
                if (row['worker_exit'] != 0 or first_report != row.get('worker_report')
                        or first_report.get('response', {}).get('status') != 'completed'
                        or first_report.get('native_helpers_sha256') != report['bundle_sha256']
                        or first_report.get('response') != replay_report.get('response')
                        or json.loads(row['retained_before_replay']['request']['response']) != first_report['response']
                        or counts['lost_returns'] != 0 or counts['shared_lost_records'] != 0):
                    raise ValueError('D4 normal actual worker completion or exact replay differs')
            else:
                if (first != b'' or row.get('worker_report') is not None
                        or row['worker_exit'] != (73 if mode == 'exit' else 1) or counts['lost_returns'] != 1
                        or replay_report.get('response', {}).get('error', {}).get('code') != 'E_HIA_REQUEST_UNKNOWN'):
                    raise ValueError('D4 process/native loss did not remain an unknown intent')
                if mode == 'exit':
                    if counts['shared_pending_native_records'] < 1 or counts['swallowed'] != 0:
                        raise ValueError('D4 process exit lacks its pending actual native handoff')
                elif counts['swallowed'] != 1 or counts['shared_lost_records'] < 3 or counts['Store_unknown_frames'] < 1:
                    raise ValueError('D4 swallowed/replaced actual child loss was not causally retained')
        else:
            numeric = {'context', 'emission', 'journal', 'lost', 'swallowed', 'unknown_records'}
            for current in (counts, replay_counts):
                if (set(current) != numeric | {'shared_module_sha256'}
                        or any(type(current[name]) is not int or current[name] < 0 for name in numeric)):
                    raise ValueError('D0-D3 installed actual counter shape differs')
            if (any(counts[name] <= 0 for name in ('context', 'emission', 'journal'))
                    or any(replay_counts[name] != 0 for name in ('context', 'emission', 'lost'))):
                raise ValueError('D0-D3 installed selected entries or no-reentry replay differs')
            if mode == 'normal':
                first_report = json.loads(first)
                if (row['worker_exit'] != 0 or first != replay
                        or first_report.get('response', {}).get('status') != 'completed'
                        or row.get('request', {}).get('state') != 'completed'
                        or json.loads(row['request']['response']) != first_report['response']
                        or counts['lost'] != 0 or counts['unknown_records'] != 0):
                    raise ValueError('D0-D3 actual normal worker or byte-exact replay differs')
            else:
                delivery_running_request(row.get('request'))
                if (row['worker_exit'] == 0 or first != b'' or counts['lost'] != 1 or counts['swallowed'] != 1
                        or counts['unknown_records'] < 3
                        or replay_report.get('response', {}).get('error', {}).get('code') != 'E_HIA_REQUEST_UNKNOWN'):
                    raise ValueError('D0-D3 installed native loss was cached as a response')
        actual_rows.append({'mode': mode, 'worker_exit': row['worker_exit'], 'counts': counts,
                            'replay_counts': replay_counts, 'replay_exit': row.get('replay_exit') if store else None})
    return {'actual_worker_modes': modes, 'actual_counts_and_raw_logs': actual_rows,
            'replay_exit_separately_serialized': store,
            'unserialized_replay_exit_and_live_DB_equality_owned_by_original_method': not store,
            'actual_child_owner_scope': ['store_artifact_profile', 'service_context', 'agent_journal'] if store
                                       else ['service_context', 'emission', 'agent_journal'],
            'all_D0_D3_owners_exercised_in_installed_child': False,
            'provider_D5_and_independent_worker_close_qualified': False, 'passed': True}


def delivery_installation(directory, root, manifests, sources, pins, *, store=False, process_loss=False):
    kind = 'installed_process' if process_loss else 'installed'
    report = delivery_child_observations(directory, kind, pins, store=store)
    directory = Path(directory) / (STORE_DELIVERY_METHODS if store else DELIVERY_METHODS)[kind]
    root = Path(root)
    wheels = sorted((directory / 'wheels').glob('*.whl'))
    if len(wheels) != 1 or report.get('wheel') != str(wheels[0]):
        raise ValueError('delivery requires the one actual built and installed wheel')
    wheel = wheels[0]
    files, distribution = release_wheel(wheel, pins)
    wheel_sha = pins[str(wheel.resolve())]
    if report.get('wheel_sha256') != wheel_sha:
        raise ValueError('delivery wheel hash differs')
    product_names = [name for name in files if name.startswith('hepta/')]
    for name in product_names:
        source_name = name.removeprefix('hepta/_data/') if name.startswith('hepta/_data/') else name
        expected = release_bytes(root / source_name, pins)
        if files[name] != expected or (source_name in sources and hashlib.sha256(expected).hexdigest() != sources[source_name]):
            raise ValueError('delivery packaged product bytes differ from admitted source: ' + name)
    installed = directory / 'installed'
    observed = {}
    for path in sorted(installed.rglob('*')):
        if path.is_symlink():
            raise ValueError('delivery actual installation contains a symlink')
        if path.is_file():
            observed[path.relative_to(installed).as_posix()] = hashlib.sha256(release_bytes(path, pins)).hexdigest()
    installation = require_release_installation(installed, observed, files, distribution, wheel, wheel_sha, pins)
    shared_sha = sources['hepta/hia_native_delivery.py']
    if store:
        expected_installed = {}
        for name in ('hepta/hia_native_delivery.py', 'hepta/hia_store_artifact_profile_native.py',
                     'hepta/hia_store_artifact_profile_protocol.py'):
            body = files[name]
            expected_installed[name] = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                'wheel_record': [name, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b'=').decode(), str(len(body))]}
        if report.get('installed_files') != expected_installed:
            raise ValueError('D4 installed three-file source/RECORD observation differs')
    elif (report.get('installed_shared_module') != str(installed / 'hepta/hia_native_delivery.py')
            or report.get('installed_shared_sha256') != shared_sha):
        raise ValueError('D0-D3 installed shared module differs')
    constants = delivery_literal_values(root / 'hepta/hia_native_helpers.py', ('SCHEMA', 'TARGET', 'ABI'), pins)
    owners = ('store_artifact_profile', 'service_context', 'agent_journal') if store else ('service_context', 'emission', 'agent_journal')
    expected_bundle = {'schema': constants['SCHEMA'], 'target': constants['TARGET'], 'abi': constants['ABI'],
        'helpers': [{'selector': 'HEPTA_HIA_' + owner.upper() + '_MANIFEST', 'manifest_path': manifests[owner],
                     'manifest_sha256': hashlib.sha256(release_bytes(manifests[owner], pins)).hexdigest()} for owner in owners]}
    bundle_path = directory / 'bundle.json'
    if (report.get('bundle') != str(bundle_path) or release_json(bundle_path, pins) != expected_bundle
            or report.get('bundle_sha256') != pins[str(bundle_path.resolve())]):
        raise ValueError('delivery installed bundle changes the actual three selected manifests')
    case_source = root / ('tests/hia_store_native_delivery_cases.py' if store else 'tests/hia_native_delivery_cases.py')
    if store:
        script = delivery_literal_values(case_source, ('INSTALLED_CONTROL',), pins)['INSTALLED_CONTROL']
    else:
        tree = ast.parse(release_bytes(case_source, pins))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_installed')
        assignments = [node.value for node in function.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == 'script' for target in node.targets)]
        if len(assignments) != 1:
            raise ValueError('delivery original installed worker script declaration differs')
        script = ast.literal_eval(assignments[0])
    if (type(script) is not str or release_bytes(directory / 'worker-control.py', pins) != script.encode()
            or (store and report.get('worker_control_sha256') != hashlib.sha256(script.encode()).hexdigest())):
        raise ValueError('delivery real child poison/instrumentation script differs from its full original method')
    for name in ('wheel.stdout', 'wheel.stderr', 'install.stdout', 'install.stderr'):
        release_bytes(directory / name, pins)
    worker = delivery_worker_observations(directory, report, shared_sha, pins, store=store,
        adapter_sha=sources['hepta/hia_store_artifact_profile_native.py'] if store else None)
    drift_readback = None
    if process_loss:
        row, = report['cases']
        drift = row.get('source_drift', {})
        original = files['hepta/_data/examples/hia_bootstrap/store_artifact_profile.hepta']
        counts = delivery_counter_line(directory / 'source-drift.stderr', b'D4_COUNTS=', pins)
        release_bytes(directory / 'source-drift.stdout', pins)
        if (type(drift.get('worker_exit')) is not int or drift['worker_exit'] == 0
                or drift.get('counts') != counts or drift.get('exact_change') != 'one appended LF'
                or drift.get('before_sha256') != hashlib.sha256(original).hexdigest()
                or drift.get('after_sha256') != hashlib.sha256(original + b'\n').hexdigest()
                or counts.get('shared_module_sha256') != shared_sha
                or counts.get('Store_adapter_sha256') != sources['hepta/hia_store_artifact_profile_native.py']
                or any(type(counts.get(phase)) is not dict or set(counts[phase]) != {'store', 'context', 'journal'}
                       or any(type(value) is not int or value != 0 for value in counts[phase].values())
                       for phase in ('startup', 'request'))):
            raise ValueError('D4 exact installed LF drift or zero-entry refusal differs')
        # Unlike older owner fixtures, this control restores the original byte
        # string in finally; the actual installed tree above must match wheel.
        drift_readback = {'exact_appended_LF_digests_verified': True, 'installed_source_restored_and_wheel_exact': True,
                          'worker_exit': drift['worker_exit'], 'startup_and_request_entries_zero': True,
                          'unserialized_post_drift_DB_equality_owned_by_original_method': True}
    return {'wheel': str(wheel), 'wheel_sha256': wheel_sha, 'packaged_product_members_verified': len(product_names),
            'installation': installation, 'worker': worker, 'source_drift': drift_readback,
            'test_body_rerun': False, 'whole_native_delivery_qualified': False, 'passed': True}


def require_native_delivery_component(directory, root, cold_path, compiler, sources, pins, *, store=False):
    """Production entry: DEV is never an acceptable substitute for same cold."""
    if cold_path is None:
        raise ValueError('delivery full-discovery admission requires the same current-source cold report')
    cold = release_json(cold_path, pins)
    if cold.get('source_manifest') != sources or cold.get('status') != 'COLD_SELFHOST_REPLAY_PASS':
        raise ValueError('delivery full-discovery cold identity differs')
    custody = delivery_custody(directory, root, compiler, sources, pins, cold_path=cold_path, store=store)
    controls = delivery_control_observations(directory, root, pins, store=store)
    installed = delivery_installation(directory, root, custody['manifests'], sources, pins, store=store)
    process_loss = (delivery_installation(directory, root, custody['manifests'], sources, pins, store=True, process_loss=True)
                    if store else None)
    return {'scope': custody['scope'], 'source_pin_count': custody['source_pin_count'],
            'build_pin_count': custody['build_pin_count'], 'manifests': custody['manifests'],
            'controls': controls, 'installed': installed, 'installed_process_loss': process_loss,
            'complete_original_Native8_authority_required': True, 'source_cold_build_custody_verified': True,
            'focused_test_bodies_rerun_by_supplement': False, 'D4_original_Store11_separate_gate_required': store,
            'remaining_D5_qualified': False, 'whole_native_delivery_qualified': False, 'passed': True}


def delivery_description_subset(discovery, ordered_ids):
    rows = discovery.get('test_descriptions', [])
    indexed = {row['id']: row for row in rows}
    if len(indexed) != len(rows) or len(set(ordered_ids)) != len(ordered_ids) or not ordered_ids:
        raise ValueError('delivery original discovery descriptions are duplicate or empty')
    if any(name not in indexed or name not in discovery.get('planned_test_ids', []) for name in ordered_ids):
        raise ValueError('delivery original method is absent from the unchanged complete discovery')
    return {'planned_test_ids': ordered_ids, 'test_descriptions': [indexed[name] for name in ordered_ids]}


def delivery_caller_method_log(directory, ordered_ids, expected_scope, discovery, pins):
    """Read every original caller method from its own retained verbose log."""
    directory = Path(directory)
    report = release_json(directory / 'report.json', pins)
    if (report.get('status') != 'PASS' or report.get('scope') != expected_scope
            or not (report.get('planned') == report.get('started') == report.get('stopped') == ordered_ids)
            or not ordered_ids or len(set(ordered_ids)) != len(ordered_ids)
            or type(report.get('actual_tests')) is not int or report['actual_tests'] != len(ordered_ids)
            or any(report.get(key) != [] for key in ('errors', 'failures', 'skipped',
                'expected_failures', 'unexpected_successes', 'reference_calls'))
            or report.get('source_and_bundle_unchanged') is not True
            or report.get('original_test_budgets_changed') is not False
            or report.get('reference_poison_scope') != 'test process; subprocesses inherit selector, not Python patches'
            or report.get('whole_native_delivery_qualified') is not False):
        raise ValueError('delivery complete original caller method observations differ')
    log = release_bytes(directory / 'tests.log', pins)
    identity = audit_verbose_stderr(log, delivery_description_subset(discovery, ordered_ids))
    if identity.get('equivalent') is not True:
        raise ValueError('delivery retained caller tests.log differs from its complete original methods')
    return {'complete_original_method_count': len(ordered_ids), 'ordered_ids_sha256': ids_digest(ordered_ids),
            'actual_verbose_log': str(directory / 'tests.log'), 'actual_verbose_sha256': hashlib.sha256(log).hexdigest(),
            'native_entries_and_full_source_build_readback_required_separately': True,
            'same_cold_qualified': expected_scope.startswith('MATCHING_SOURCE_COLD_'), 'passed': True}


def delivery_gate_readback(directory, group, root, compiler, expected_sources, original, discovery, pins, *,
                           cold_path=None, development=False, development_manifests=None, python_executable=None):
    """Strict original 152 / six-group supervisor and raw-log readback, with explicit scope."""
    if (group not in ('components', 'callers') or type(development) is not bool
            or development == (cold_path is not None) or type(python_executable) is not str or not python_executable):
        raise ValueError('delivery group readback requires the exact group, interpreter and source scope')
    directory, root, compiler = Path(directory), Path(root), Path(compiler)
    report = release_json(directory / 'report.json', pins)
    scope = ('EXPLICIT_DEVELOPMENT_D0_D3_' if development else 'MATCHING_SOURCE_COLD_D0_D3_') + group.upper()
    selectors = list(DELIVERY_COMPONENT_MODULES) if group == 'components' else [
        'tools/qualify_hia_' + name + '_callers.py' for name in DELIVERY_CALLERS]
    records = report.get('stages', [])
    compiler_sha = hashlib.sha256(release_bytes(compiler, pins)).hexdigest()
    expected_manifest_pins = {}
    if development:
        if type(development_manifests) is not dict or set(development_manifests) != set(DELIVERY_OWNERS):
            raise ValueError('delivery DEV readback requires all actual focused same-source manifest paths')
        for owner in DELIVERY_OWNERS:
            path = Path(development_manifests[owner])
            manifest = release_json(path, pins)
            image = path.parent / manifest['image_path']
            raw = release_bytes(image, pins)
            if (image.resolve().parent != path.resolve().parent
                    or manifest.get('source_sha256') != expected_sources['examples/hia_bootstrap/' + owner + '.hepta']
                    or manifest.get('compiler_sha256') != compiler_sha
                    or manifest.get('image_sha256') != hashlib.sha256(raw).hexdigest()):
                raise ValueError('delivery original group DEV image/source identity differs')
            expected_manifest_pins[str(path)] = pins[str(path.resolve())]
            expected_manifest_pins[str(image)] = pins[str(image.resolve())]
    elif development_manifests is not None:
        raise ValueError('delivery cold group cannot accept development manifests')
    if (report.get('schema') != 'hepta.hia.native-delivery-gate.v1' or report.get('status') != 'PASS'
            or report.get('scope') != scope or report.get('outer_allowance_seconds') != 1800
            or type(report.get('elapsed_seconds')) not in (int, float) or not 0 <= report['elapsed_seconds'] < 1800
            or report.get('compiler_sha256') != compiler_sha
            or report.get('source_before') != expected_sources or report.get('source_after') != expected_sources
            or report.get('source_and_build_unchanged') is not True or report.get('manifest_pins') != expected_manifest_pins
            or report.get('original_registry_count_adjustments') != original['registry_count_adjustments']
            or report.get('original_assertions_inputs_and_timeouts_changed') is not False
            or report.get('whole_native_delivery_qualified') is not False
            or [row.get('selector') for row in records] != selectors):
        raise ValueError('delivery original group is incomplete, changed, over budget, or not in the required source scope')
    result, all_ids = [], []
    for index, record in enumerate(records, 1):
        selector = record['selector']
        stem = f'{index:02d}-' + selector.replace('/', '_').replace('.', '_')
        if group == 'components':
            path = directory / (stem + '.json')
            selection = ['--development-compiler', str(compiler)] if development else ['--cold-report', str(cold_path)]
            command = [python_executable, '-B', str(root / 'tools/qualify_hia_native_delivery.py'),
                       '--group', group, '--evidence', str(directory), '--execute-module', selector,
                       '--stage-report', str(path), *selection]
        else:
            owner = DELIVERY_CALLERS[index - 1]
            if owner == 'agent_journal':
                path = directory / 'agent-journal-callers.json'
                selection = (['--manifest', development_manifests[owner], '--development'] if development
                             else ['--cold-report', str(cold_path)])
                command = [python_executable, '-B', str(root / selector), '--output', str(path), *selection]
            else:
                path = directory / (owner + '-callers') / 'report.json'
                selection = (['--development-manifest', development_manifests[owner]] if development
                             else ['--cold-report', str(cold_path)])
                command = [python_executable, '-B', str(root / selector), '--evidence', str(path.parent), *selection]
        expected_journal_env = (development_manifests['agent_journal'] if development
                                and selector == 'tests.test_hia_agent_journal_native' else None)
        stdout = release_bytes(directory / (stem + '.stdout'), pins)
        stderr = release_bytes(directory / (stem + '.stderr'), pins)
        if (record.get('command') != command or record.get('status') != 'PASS'
                or type(record.get('exit_code')) is not int or record['exit_code'] != 0
                or type(record.get('supervised_pid')) is not int or record['supervised_pid'] <= 0
                or record.get('timed_out') is not False or record.get('report') != str(path)
                or record.get('report_present') is not True
                or record.get('owned_process_group_killed_on_timeout') is not False
                or record.get('cleanup_pipes_unconfirmed') is not False
                or record.get('escaped_process_sessions_qualified') is not False
                or record.get('journal_development_manifest_environment') != expected_journal_env
                or record.get('stdout_sha256') != hashlib.sha256(stdout).hexdigest()
                or record.get('stderr_sha256') != hashlib.sha256(stderr).hexdigest()):
            raise ValueError('delivery stage command, process result or actual stdout/stderr differs: ' + selector)
        observed = release_json(path, pins)
        if observed.get('status') != 'PASS':
            raise ValueError('delivery stage report is missing or not PASS: ' + selector)
        if group == 'components':
            planned = original['component_ordered_ids'][selector]
            if (observed.get('schema') != 'hepta.hia.native-delivery-stage.v1'
                    or observed.get('selector') != selector
                    or not (observed.get('planned') == observed.get('started') == observed.get('stopped') == planned)
                    or observed.get('outcomes') != [[name, 'ok'] for name in planned]
                    or type(observed.get('testsRun')) is not int or observed['testsRun'] != len(planned)
                    or observed.get('unstarted') != [] or observed.get('unterminated') != []
                    or observed.get('anomalies') != {key: [] for key in ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')}
                    or observed.get('source_before') != expected_sources or observed.get('source_after') != expected_sources
                    or observed.get('source_unchanged') is not True
                    or observed.get('original_registry_count_adjustments') != original['registry_count_adjustments']
                    or observed.get('original_deadlines_changed') is not False
                    or type(observed.get('elapsed_seconds')) not in (int, float)
                    or not 0 <= observed['elapsed_seconds'] < 1800):
                raise ValueError('delivery complete original module observations differ: ' + selector)
            all_ids.extend(planned)
        else:
            planned = observed.get('chosen_test_ids') if owner == 'agent_journal' else observed.get('planned')
            if type(planned) is not list or not planned:
                raise ValueError('delivery original caller inventory is absent')
        # The five owner callers intentionally write tests.log; their outer
        # stderr is still captured and hashed, but is not a method transcript.
        # Only the unchanged journal caller uses its process stderr directly.
        method_log = path.parent / 'tests.log' if group == 'callers' and owner != 'agent_journal' else directory / (stem + '.stderr')
        method_raw = release_bytes(method_log, pins)
        identity = audit_verbose_stderr(method_raw, delivery_description_subset(discovery, planned))
        if identity.get('equivalent') is not True:
            raise ValueError('delivery actual original verbose log is incomplete or reordered: ' + selector)
        result.append({'selector': selector, 'report': str(path), 'report_sha256': pins[str(path.resolve())],
                       'method_count': len(planned), 'ordered_ids_sha256': ids_digest(planned),
                       'raw_stderr_sha256': hashlib.sha256(stderr).hexdigest(),
                       'method_log': str(method_log), 'method_log_sha256': hashlib.sha256(method_raw).hexdigest(),
                       'complete_verbose_identity_verified': True})
    if group == 'components' and (len(all_ids) != 152 or len(set(all_ids)) != 152):
        raise ValueError('delivery group did not execute all 152 frozen original methods')
    return {'scope': scope, 'group': group, 'stages': result,
            'complete_original_method_count': 152 if group == 'components' else sum(row['method_count'] for row in result),
            'outer_allowance_seconds': 1800, 'elapsed_seconds': report['elapsed_seconds'],
            'same_cold_qualified': not development, 'escaped_process_sessions_qualified': False,
            'all_original_assertions_inputs_and_timeouts_unchanged': True,
            'whole_native_delivery_qualified': False, 'passed': True}


def delivery_journal_callers(directory, root, sources, discovery, journal_manifest, pins):
    """The unchanged journal qualifier deletes its temporary build; do not invent a receipt."""
    directory, root = Path(directory), Path(root)
    report = release_json(directory / 'agent-journal-callers.json', pins)
    modules = delivery_literal_values(root / 'tools/qualify_hia_agent_journal_callers.py', ('DEFAULT_MODULES',), pins)['DEFAULT_MODULES']
    if type(modules) is not tuple or len(modules) != 8 or len(set(modules)) != 8:
        raise ValueError('delivery journal requires its eight complete original modules')
    planned = [name for module in modules for name in discovery['planned_test_ids'] if name.startswith(module + '.')]
    if any(not any(name.startswith(module + '.') for name in planned) for module in modules):
        raise ValueError('delivery journal original module is absent from full discovery')
    manifest = release_json(journal_manifest, pins)
    names = ('hepta/hia_agent_journal_native.py', 'hepta/hia_agent_service.py', 'hepta/hia_agent_store.py',
             'hepta/hia_agent_contract.py', 'tools/generate_hia_agent_journal.py',
             'tools/qualify_hia_agent_journal_callers.py', 'examples/hia_bootstrap/agent_journal.hepta')
    source_pins = {name: hashlib.sha256(release_bytes(root / name, pins)).hexdigest() for name in names}
    tools = delivery_literal_values(root / 'hepta/hia_agent_journal_native.py', ('TOOLS',), pins)['TOOLS']
    drivers, stages, by_test = (report.get(name) for name in ('selected_driver_calls', 'actual_native_stage_returns', 'per_test_entries'))
    if (report.get('schema') != 'hepta.hia.agent-journal-selected-callers.v1'
            or report.get('status') != 'PASS' or report.get('scope') != 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
            or not (report.get('loaded_test_ids') == report.get('chosen_test_ids') == report.get('executed_test_ids') == planned)
            or any(type(report.get(key)) is not int or report[key] != len(planned) for key in ('tests_run', 'tests_loaded', 'tests_chosen'))
            or report.get('explicit_development_exclusions') != {}
            or any(report.get(key) != [] for key in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
            or report.get('manifest') != manifest or report.get('image_sha256') != manifest.get('image_sha256')
            or report.get('source_sha256') != source_pins
            or any(name in sources and sources[name] != digest for name, digest in source_pins.items())
            or report.get('retained_call_owner_forbidden') is not True
            or report.get('all_eleven_tools_entered_selected_driver') is not True
            or report.get('subprocesses_inherit_selector') is not True
            or any(report.get(key) is not False for key in ('subprocess_stage_entries_in_parent_counters',
                                                          'default_whole_regression_claimed', 'sqlite_durability_replaced'))
            or type(drivers) is not dict or not set(tools[:-1]) <= set(drivers)
            or any(type(value) is not int or value <= 0 for value in drivers.values())
            or type(stages) is not dict or not stages or any(type(key) is not str or not key.isdecimal()
                or type(value) is not int or value <= 0 for key, value in stages.items())
            or type(by_test) is not dict or not set(by_test) <= set(planned) | {'outside-test'}):
        raise ValueError('delivery complete journal caller inventory/source/native observations differ')
    for counts in by_test.values():
        if type(counts) is not dict or not set(counts) <= {'selected_driver', 'native_stage'} or any(type(value) is not int or value <= 0 for value in counts.values()):
            raise ValueError('delivery per-test journal actual counters differ')
    if (sum(drivers.values()) != sum(row.get('selected_driver', 0) for row in by_test.values())
            or sum(stages.values()) != sum(row.get('native_stage', 0) for row in by_test.values())):
        raise ValueError('delivery journal global counters differ from all original test observations')
    return {'complete_original_modules': list(modules), 'complete_original_method_count': len(planned),
            'ordered_ids_sha256': ids_digest(planned), 'selected_driver_calls': drivers, 'actual_native_stage_returns': stages,
            'actual_caller_embedded_manifest_matches_same_cold_focused_image': True,
            'caller_temporary_build_receipt_retained': False,
            'cold_builder_admission_owned_by_unchanged_original_caller_command': True,
            'subprocess_native_entries_in_parent_counters': False, 'passed': True}


def require_native_delivery_group(directory, group, root, cold_path, compiler, sources, discovery, pins, focused_manifests):
    if cold_path is None:
        raise ValueError('delivery production supplemental groups require the actual same-run cold')
    original = delivery_original_inventory(root, pins)
    expected_sources = delivery_source_identity(root, sources, original, pins)
    record = delivery_gate_readback(directory, group, root, compiler, expected_sources, original, discovery, pins,
                                   cold_path=cold_path, python_executable=sys.executable)
    if group == 'components':
        record['existing_component_build_and_effect_assertions_owned_by_complete_original_152'] = True
        return record
    readers = {'service_context': require_service_context_caller_observations,
               'cost_ledger': require_cost_ledger_caller_observations,
               'evaluation': require_evaluation_caller_observations,
               'native_build_admission': require_native_build_admission_callers,
               'emission': require_emission_callers}
    scopes = {'service_context': 'MATCHING_SOURCE_COLD_ORIGINAL_SERVICE_CONTEXT_CALLERS',
              'cost_ledger': 'MATCHING_SOURCE_COLD_SEVEN_ORDINARY_COST_LEDGER_CALLER_MODULES',
              'evaluation': 'MATCHING_SOURCE_COLD_SEVEN_ORDINARY_EVALUATION_CALLER_MODULES',
              'native_build_admission': 'MATCHING_SOURCE_COLD_NINE_ORDINARY_NATIVE_BUILD_ADMISSION_CALLER_MODULES',
              'emission': 'MATCHING_SOURCE_COLD_NINE_ORDINARY_EMISSION_CALLER_MODULES'}
    caller_readbacks = {}
    for owner in DELIVERY_CALLERS[:-1]:
        child = Path(directory) / (owner + '-callers')
        observed = release_json(child / 'report.json', pins)
        if observed.get('scope') != scopes[owner]:
            raise ValueError('delivery original caller did not select this same-source cold: ' + owner)
        manifest_path = child / 'qualified/manifest.json'
        delivery_compile_readback(manifest_path.parent, owner, root, compiler, sources, pins, cold_path=cold_path)
        method_log = delivery_caller_method_log(child, observed['planned'], scopes[owner], discovery, pins)
        caller_readbacks[owner] = {'actual_method_log': method_log,
                                  'unchanged_owner_reader': readers[owner](child, root, sources, discovery, manifest_path, pins)}
    caller_readbacks['agent_journal'] = delivery_journal_callers(directory, root, sources, discovery,
                                                                focused_manifests['agent_journal'], pins)
    record['complete_six_caller_group_readbacks'] = caller_readbacks
    record['existing_five_caller_reader_bodies_reused_unchanged'] = True
    record['journal_caller_actual_image_compared_to_retained_same_cold_focused_build'] = True
    return record


# BEGIN FINAL DELIVERY INDEPENDENT READBACK
def final_delivery_target_binding(root, pins):
    """A formal invocation cannot invent the still-pending composed release."""
    fixed = FINAL_DELIVERY_FREEZE
    fields = {'product_commit', 'product_tree', 'successor_fixture_sha256',
              'successor_helper_sha256', 'five_source_sha256'}
    if (type(fixed) is not dict or set(fixed) != fields
            or any(type(fixed.get(k)) is not str or re.fullmatch('[0-9a-f]{40}', fixed[k]) is None
                   for k in ('product_commit', 'product_tree'))
            or any(type(fixed.get(k)) is not str or re.fullmatch('[0-9a-f]{64}', fixed[k]) is None
                   for k in ('successor_fixture_sha256', 'successor_helper_sha256'))
            or type(fixed.get('five_source_sha256')) is not dict
            or set(fixed['five_source_sha256']) != set(FINAL_STORE_PATHS)
            or any(type(v) is not str or re.fullmatch('[0-9a-f]{64}', v) is None
                   for v in fixed['five_source_sha256'].values())):
        raise ValueError('final delivery composition and published target are pending; formal admission refused')
    root = Path(root)
    if (git(root, 'rev-parse', 'HEAD') != fixed['product_commit']
            or git(root, 'rev-parse', 'HEAD^{tree}') != fixed['product_tree']):
        raise ValueError('final delivery source differs from the frozen published commit/tree')
    for name, digest in ((FINAL_STORE_SUCCESSOR, fixed['successor_fixture_sha256']),
                         (FINAL_STORE_SUCCESSOR_HELPER, fixed['successor_helper_sha256']),
                         *fixed['five_source_sha256'].items()):
        if hashlib.sha256(release_bytes(root / name, pins)).hexdigest() != digest:
            raise ValueError('final delivery composed input differs: ' + name)
    value = release_json(root / FINAL_STORE_SUCCESSOR, pins)
    if (value.get('state') != 'FROZEN_COMPOSED_SOURCE'
            or value.get('schema') != 'hepta.hia.store-delivery-successor.v1'
            or set(value.get('files', {})) != set(FINAL_STORE_PATHS)
            or {n: row.get('new_sha256') for n, row in value['files'].items()} != fixed['five_source_sha256']):
        raise ValueError('final delivery provenance remains draft or changes the composition')
    return dict(fixed)


def final_reverse_store_patch(raw, record, original):
    """Independent complete-byte reverse admission; no product helper import."""
    if (type(record) is not dict
            or set(record) != {'old_sha256', 'new_sha256', 'old_bytes', 'new_bytes', 'hunks'}
            or type(record['old_bytes']) is not int or type(record['new_bytes']) is not int
            or record['old_bytes'] != original['bytes'] or record['old_sha256'] != original['sha256']
            or record['new_bytes'] != len(raw) or record['new_sha256'] != hashlib.sha256(raw).hexdigest()
            or type(record['hunks']) is not list or not record['hunks']):
        raise ValueError('final Store complete source identity differs')
    old_at = new_at = 0
    parts = []
    for hunk in record['hunks']:
        if (type(hunk) is not dict or set(hunk) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or type(hunk['old_offset']) is not int or type(hunk['new_offset']) is not int
                or hunk['new_offset'] < new_at):
            raise ValueError('final Store reverse-patch shape or order differs')
        decoded = []
        for key in ('old_hex', 'new_hex'):
            value = hunk[key]
            if type(value) is not str or len(value) % 2 or re.fullmatch('[0-9a-f]*', value) is None:
                raise ValueError('final Store reverse-patch bytes are not canonical')
            decoded.append(bytes.fromhex(value))
        old, new = decoded
        gap = hunk['new_offset'] - new_at
        if (old == new or hunk['old_offset'] != old_at + gap
                or hunk['new_offset'] + len(new) > len(raw)
                or raw[hunk['new_offset']:hunk['new_offset'] + len(new)] != new):
            raise ValueError('final Store reverse-patch actual bytes differ')
        parts.extend((raw[new_at:hunk['new_offset']], old))
        old_at, new_at = hunk['old_offset'] + len(old), hunk['new_offset'] + len(new)
    parts.append(raw[new_at:])
    result = b''.join(parts)
    if len(result) != original['bytes'] or hashlib.sha256(result).hexdigest() != original['sha256']:
        raise ValueError('final Store patch does not restore the independently frozen complete original')
    return result


def final_store_definition_pins(raw):
    module, lines = ast.parse(raw), raw.splitlines(keepends=True)
    def pin(node):
        first = min([node.lineno] + [item.lineno for item in node.decorator_list]) - 1
        body = b''.join(lines[first:node.end_lineno])
        return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    result = {n.name: pin(n) for n in module.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    frames = [n for n in module.body if isinstance(n, ast.ClassDef) and n.name == 'StoreArtifactProfileFrame']
    if len(frames) != 1:
        raise ValueError('final Store adapter frame identity differs')
    for node in frames[0].body:
        if isinstance(node, ast.FunctionDef) and node.name in (
                '_global', 'argument', 'effect', '_release', '_confirmed_foreign_failure'):
            result['StoreArtifactProfileFrame.' + node.name] = pin(node)
    return result


def final_store_composition(root, original, pins):
    root = Path(root)
    original_raw = release_bytes(root / FINAL_STORE_ORIGINAL, pins)
    if (hashlib.sha256(original_raw).hexdigest() != FINAL_STORE_ORIGINAL_SHA256
            or evaluation_json_bytes(json.loads(original_raw)) != evaluation_json_bytes(original)):
        raise ValueError('final Store original inventory was changed')
    if (len(original.get('unchanged_files', {})) != 89
            or len(original.get('shared_dependency_review', {})) != 22
            or len(original.get('unchanged_adapter_definitions', {})) != 21):
        raise ValueError('final Store original complete source sets differ')
    originals = {n: original['unchanged_files'][n] for n in FINAL_STORE_SOURCE_PATHS}
    originals.update({n: original['shared_dependency_review'][n] for n in FINAL_STORE_SHARED_PATHS})
    captured = {n: release_bytes(root / n, pins) for n in FINAL_STORE_PATHS}
    unchanged = all(len(captured[n]) == originals[n]['bytes']
                    and hashlib.sha256(captured[n]).hexdigest() == originals[n]['sha256'] for n in FINAL_STORE_PATHS)
    adjustments, extra = {}, {}
    if not unchanged:
        fixed = FINAL_DELIVERY_FREEZE
        if type(fixed) is not dict:
            raise ValueError('final Store successor is not frozen; draft admission refused')
        for name, key in ((FINAL_STORE_SUCCESSOR, 'successor_fixture_sha256'),
                          (FINAL_STORE_SUCCESSOR_HELPER, 'successor_helper_sha256')):
            extra[name] = release_bytes(root / name, pins)
            if hashlib.sha256(extra[name]).hexdigest() != fixed.get(key):
                raise ValueError('final Store successor helper or fixture is not frozen')
        value = json.loads(extra[FINAL_STORE_SUCCESSOR])
        if (value.get('schema') != 'hepta.hia.store-delivery-successor.v1'
                or value.get('state') != 'FROZEN_COMPOSED_SOURCE'
                or value.get('original_commit') != 'c0195643083e1d4c68679237edfa77143dc7b1c6'
                or type(value.get('files')) is not dict or set(value['files']) != set(FINAL_STORE_PATHS)
                or {n: row.get('new_sha256') for n, row in value['files'].items()} != fixed.get('five_source_sha256')):
            raise ValueError('final Store successor is not the one complete reviewed composition')
        for name in FINAL_STORE_PATHS:
            final_reverse_store_patch(captured[name], value['files'][name], originals[name])
            adjustments[name] = {'path': name, 'original_sha256': originals[name]['sha256'],
                'current_sha256': value['files'][name]['new_sha256'], 'current_bytes': value['files'][name]['new_bytes'],
                'reversible_patch_fixture_sha256': fixed['successor_fixture_sha256']}
    shared = dict(original['shared_dependency_review'])
    for name in FINAL_STORE_SHARED_PATHS:
        if name in adjustments:
            shared[name] = {'bytes': adjustments[name]['current_bytes'], 'sha256': adjustments[name]['current_sha256']}
    for name, expected in shared.items():
        raw = release_bytes(root / name, pins)
        if {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} != expected:
            raise ValueError('final Store shared dependency outside reviewed combination changed: ' + name)
    definitions = final_store_definition_pins(release_bytes(root / 'hepta/hia_store_artifact_profile_native.py', pins))
    if definitions != original['unchanged_adapter_definitions']:
        raise ValueError('one of the complete 21 original Store definitions changed')
    if any(release_bytes(root / n, pins) != raw for n, raw in {FINAL_STORE_ORIGINAL: original_raw, **captured, **extra}.items()):
        raise ValueError('final Store source/fixture changed during complete composition admission')
    return {'source_adjustments': {n: adjustments[n] for n in FINAL_STORE_SOURCE_PATHS if n in adjustments},
        'shared_adjustments': {n: adjustments[n] for n in FINAL_STORE_SHARED_PATHS if n in adjustments},
        'shared_dependency_review': shared,
        'identity': {'scope': 'ORIGINAL_C019' if unchanged else 'FROZEN_FIVE_FILE_COMPOSED_SUCCESSOR',
            'all_five_current_sha256': {n: hashlib.sha256(raw).hexdigest() for n, raw in captured.items()},
            'all_21_original_definitions_unchanged': True, 'all_22_shared_members_checked': True,
            'source_fixture_reread': True}}


def final_source_inputs(root, sources, module, name, pins, *, matching_source=True):
    names = delivery_literal_values(Path(root) / module, (name,), pins)[name]
    if (type(names) not in (tuple, list) or not names or len(names) != len(set(names))
            or any(type(n) is not str or Path(n).is_absolute() or '..' in Path(n).parts for n in names)):
        raise ValueError('final delivery input declaration is not a unique relative-path inventory')
    values = {n: hashlib.sha256(release_bytes(Path(root) / n, pins)).hexdigest() for n in names}
    if matching_source and any(sources.get(n) != digest for n, digest in values.items()):
        raise ValueError('final delivery inputs are not all bound by the same current cold source')
    return values


def final_compile_transport(directory, label, source_name, root, compiler, sources, pins):
    directory, root, compiler = Path(directory), Path(root), Path(compiler)
    source, artifact = release_bytes(root / source_name, pins), release_bytes(compiler, pins)
    source_sha, compiler_sha = hashlib.sha256(source).hexdigest(), hashlib.sha256(artifact).hexdigest()
    image_path, output_path = directory / (label + '.image.bin'), directory / (label + '.output.bin')
    image, output = release_bytes(image_path, pins), release_bytes(output_path, pins)
    receipt = release_json(directory / (label + '.receipt.json'), pins)
    request = release_json(directory / (label + '.request.json'), pins)
    size = len(image)
    expected = {'capacity': 1048576, 'format': 'flat-x86-64', 'image': str(compiler),
        'image_sha256': compiler_sha, 'output': str(output_path),
        'source': str(directory / (label + '.input.bin')), 'source_sha256': source_sha,
        'workspace_fill': 0, 'workspace_size': 1048576}
    if (source_sha != sources.get(source_name) or request != expected
            or release_bytes(directory / (label + '.input.bin'), pins) != source
            or not 0 < size <= len(output) <= 1048576 or output[:size] != image
            or receipt.get('status') != 'returned' or receipt.get('format') != 'flat-x86-64'
            or receipt.get('return_encoding') != 'zero-extended-u32'
            or any(type(receipt.get(k)) is not int or receipt[k] != v for k, v in (
                ('abi_status', 0), ('core_u32', size), ('result_u64', size), ('input_bytes', len(source)), ('produced_bytes', size)))
            or any(receipt.get(k) != v for k, v in (
                ('artifact_sha256', compiler_sha), ('image_sha256', compiler_sha), ('source_sha256', source_sha),
                ('input_sha256', source_sha), ('output_sha256', hashlib.sha256(output).hexdigest()),
                ('produced_sha256', hashlib.sha256(image).hexdigest()), ('produced_image', str(image_path))))
            or receipt.get('source_unchanged') is not True or receipt.get('forbidden_compiler_modules_loaded') != []):
        raise ValueError('final delivery raw compiler request/receipt/full output/image differs: ' + label)
    return {'image_path': str(image_path), 'image_sha256': hashlib.sha256(image).hexdigest(),
            'source_sha256': source_sha, 'compiler_sha256': compiler_sha, 'receipt': receipt,
            'image': image, 'full_output_sha256': hashlib.sha256(output).hexdigest()}


def final_same_cold(cold_path, compiler, sources, pins):
    if cold_path is None:
        raise ValueError('formal final delivery requires the same original cold; DEV is not qualified')
    cold = release_json(cold_path, pins)
    nested = release_json(cold.get('nested_report', ''), pins)
    generations = nested.get('generations', [])
    if (cold.get('status') != 'COLD_SELFHOST_REPLAY_PASS' or cold.get('source_manifest') != sources
            or type(generations) is not list or not generations
            or Path(generations[-1].get('produced_image', '')).resolve(strict=True) != Path(compiler).resolve(strict=True)):
        raise ValueError('final delivery does not use this current-source original cold compiler')
    return hashlib.sha256(release_bytes(cold_path, pins)).hexdigest()


def final_positive_counts(value, *, required=(), exact_keys=False):
    if (type(value) is not dict or any(type(k) is not str or type(v) is not int or v < 0 for k, v in value.items())
            or any(value.get(k, 0) <= 0 for k in required) or (exact_keys and set(value) != set(required))):
        raise ValueError('final delivery actual nonnegative native/provider counts differ')
    return sum(value.values())


def final_complete_ids(planned, started, stopped, expected):
    if (type(expected) is not list or not expected or len(expected) != len(set(expected))
            or any(type(n) is not str for n in expected)
            or planned != expected or started != expected or stopped != expected):
        raise ValueError('final delivery complete original planned/started/stopped IDs differ')
    return len(expected)


def final_verbose_log(path, expected, discovery, pins):
    raw = release_bytes(path, pins)
    observed = audit_verbose_stderr(raw, delivery_description_subset(discovery, expected))
    text = raw.decode('utf-8', errors='strict')
    if (observed.get('equivalent') is not True
            or len(re.findall(r'^Ran ' + str(len(expected)) + r' tests? in [0-9.]+s$', text, re.M)) != 1
            or re.search(r'^OK\s*$', text, re.M) is None
            or re.search(r'^(?:FAILED|ERROR:|FAIL:|UNEXPECTED SUCCESS:)', text, re.M)):
        raise ValueError('final delivery actual verbose unittest log is incomplete/nonpassing: ' + str(path))
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
            'complete_ok_methods': len(expected), 'identity': observed}


def final_file_pins(record, pins):
    if type(record) is not dict or not record:
        raise ValueError('final delivery retained file pins absent')
    for name, digest in record.items():
        if type(name) is not str or type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None:
            raise ValueError('final delivery retained file pin shape differs')
        if hashlib.sha256(release_bytes(name, pins)).hexdigest() != digest:
            raise ValueError('final delivery retained file changed: ' + name)
    return len(record)


def store_transaction_build_readback(directory, root, compiler, sources, pins, *, cold_path=None, development=False):
    if type(development) is not bool or development == (cold_path is not None):
        raise ValueError('transaction readback requires explicit DEV or matching current cold')
    directory = Path(directory)
    observed = final_compile_transport(directory, 'store_transaction',
        'examples/hia_bootstrap/store_transaction.hepta', root, compiler, sources, pins)
    manifest, build = release_json(directory / 'manifest.json', pins), release_json(directory / 'build.json', pins)
    expected = {'schema': 'hepta.hia.store-transaction.v1', 'source_sha256': observed['source_sha256'],
        'image_path': 'store_transaction.image.bin', 'image_sha256': observed['image_sha256'],
        'compiler_sha256': observed['compiler_sha256']}
    inputs = final_source_inputs(root, sources, 'tools/build_hia_store_transaction.py', 'INPUTS', pins)
    if (manifest != expected or build.get('schema') != 'hepta.hia.store-transaction-build.v1'
            or build.get('manifest') != manifest or build.get('component_inputs') != inputs
            or build.get('native_compile_receipt') != observed['receipt']
            or build.get('scope') != ('DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT')
            or build.get('source_manifest') != (None if development else sources)
            or build.get('cold_report_sha256') != (None if development else hashlib.sha256(release_bytes(cold_path, pins)).hexdigest())
            or any(build.get(k) is not True for k in ('complete_original_transaction_control_owned_by_hia',
                'lock_BEGIN_yield_COMMIT_ROLLBACK_exit_suppression_owned_by_hia',
                'original_SQL_literals_and_dynamic_method_calls_preserved', 'sqlite_lock_object_and_generator_protocols_hosted',
                'body_observation_custody_reserved_before_BEGIN', 'explicit_resource_loss_blocks_resume_and_retirement'))
            or any(build.get(k) is not False for k in ('selected_public_route_invokes_retained_original',
                'new_replay_retry_SQL_or_production_deadline', 'all_python_versions_tested',
                'all_input_equivalence_proved', 'whole_native_stack_qualified'))):
        raise ValueError('transaction actual source/manifest/build/cold custody differs')
    return manifest


def store_transaction_fixture(root, pins):
    directory = 'tests/fixtures/hia_store_transaction_original_c019/'
    expected = {'transaction.c019.py.txt': '23d89d8ae63bf196203cbd53a5cc8970083470a77fdd16625eb96d618e0a5587',
        'source-identity.json': '19ed5a96773d51eeb96f3db2fce6c1cd17003a0c05eb78e14590033bc229fc5b',
        'cases.json': '494474bdff4c988e1124a8398c3254089da7aedfad46d725f47c67d069de1672',
        'freeze.json': '99d0ec1470b452c1add79c71c4aae752ddb97e22ac4eaa2ceb574fd32cd78e98'}
    for name, digest in expected.items():
        if hashlib.sha256(release_bytes(Path(root) / directory / name, pins)).hexdigest() != digest:
            raise ValueError('transaction independent original fixture changed: ' + name)
    for name, digest in {
        'tests/hia_store_transaction_oracle.py':'afa2a0cfc72ef5d4e30f56ed44d5febdf726f570f73cf28448d2f074e47017ce',
        'tests/hia_store_transaction_scenarios.py':'e853b839210c150c2e42712fe73e46dbb0c99b6859e0a1705e7b102223837ed7'}.items():
        if hashlib.sha256(release_bytes(Path(root)/name,pins)).hexdigest()!=digest:
            raise ValueError('transaction frozen independent original observer changed: '+name)
    cases = release_json(Path(root) / directory / 'cases.json', pins)
    if type(cases) is not list or len(cases) != 521 or len({x['id'] for x in cases}) != 521:
        raise ValueError('transaction requires the complete original 521 unique cases')
    return cases


def store_transaction_histories(directory, root, compiler, manifest_path, manifest, sources, scope, pins):
    root, directory, manifest_path = Path(root), Path(directory), Path(manifest_path)
    cases = store_transaction_fixture(root, pins)
    identities = [row['id'] for row in cases]
    at = directory / 'test_complete_521_frozen_originals_through_selected_public_binding'
    rows = release_json(at / 'isolated-histories.json', pins)
    aggregate = release_json(at / 'native-counts.json', pins)
    if type(rows) is not list or [r.get('history') for r in rows] != ['H0', 'H1']:
        raise ValueError('transaction requires both complete dedicated H0/H1 histories')
    anchors = delivery_literal_values(root / 'tests/hia_store_transaction_history.py', ('KNOWN_H0_ORIGINALS',), pins)['KNOWN_H0_ORIGINALS']
    total, frame_totals, output = {}, {}, []
    manifest_sha = hashlib.sha256(release_bytes(manifest_path, pins)).hexdigest()
    runner_raw = release_bytes(root / 'tests/hia_store_transaction_history.py', pins)
    for row in rows:
        name = row['history']; location = at / name
        report_path = location / 'report.json'
        report = release_json(report_path, pins)
        start = release_json(location / 'start.json', pins)
        expected_raw = release_bytes(location / 'originals-521.json', pins)
        actual_raw = release_bytes(location / 'actuals-521.json', pins)
        expected, actual = json.loads(expected_raw), json.loads(actual_raw)
        comparisons = release_json(location / 'complete-observations.json', pins)
        command = release_json(at / (name + '-command.json'), pins)
        stdout = release_json(at / (name + '-stdout.log'), pins)
        release_bytes(at / (name + '-stderr.log'), pins)
        if (row.get('returncode') != 0 or type(row.get('returncode')) is not int
                or row.get('report') != str(report_path) or row.get('report_sha256') != hashlib.sha256(release_bytes(report_path, pins)).hexdigest()
                or row.get('status') != 'PASS' or report.get('status') != 'PASS' or report.get('exception') is not None
                or report.get('schema') != 'hepta.hia.transaction-isolated-history.v1'
                or report.get('history') != name or report.get('build_scope') != scope
                or report.get('manifest_path') != str(manifest_path) or report.get('manifest_sha256') != manifest_sha
                or report.get('compiler_sha256') != manifest['compiler_sha256'] or report.get('image_sha256') != manifest['image_sha256']
                or report.get('source_before') != sources or report.get('source_after') != sources
                or report.get('runner_sha256') != hashlib.sha256(runner_raw).hexdigest()
                or release_bytes(location / 'runner.py', pins) != runner_raw
                or evaluation_json_bytes(release_json(location / 'inputs-521.json', pins)) != evaluation_json_bytes(cases)
                or any(evaluation_json_bytes(report.get(k)) != evaluation_json_bytes(v) for k, v in start.items())):
            raise ValueError('transaction original history child/source/manifest identity differs: ' + name)
        if (expected_raw != actual_raw or type(expected) is not list or len(expected) != 521
                or [x.get('id') for x in expected] != identities or report.get('case_order') != identities
                or any(type(report.get(k)) is not int or report[k] != 521 for k in ('original_count','actual_count','comparison_count','declared_original_count'))
                or report.get('differences') != [] or type(report.get('guards')) is not dict or any(report['guards'].values())
                or report.get('originals_sha256') != hashlib.sha256(expected_raw).hexdigest()
                or report.get('actuals_sha256') != hashlib.sha256(actual_raw).hexdigest()
                or type(comparisons) is not list or [x.get('case') for x in comparisons] != identities
                or evaluation_json_bytes([x.get('expected') for x in comparisons]) != evaluation_json_bytes(expected)
                or evaluation_json_bytes([x.get('actual') for x in comparisons]) != evaluation_json_bytes(actual)
                or any(x.get('equal') is not True for x in comparisons)
                or any(report.get(k) is not True for k in ('source_image_manifest_build_and_compiler_unchanged',
                    'expected_written_before_native_mapping','expected_file_unchanged_after_candidate',
                    'both_retained_aliases_poisoned','history_equal','held_cleanup_equal',
                    'no_compilation_performed_in_child','not_all_possible_call_histories_or_python_builds_proved',
                    'no_reset_no_new_warmup_loop_no_exception_attribute_normalization'))
                or report.get('historical_R1_actual_used_as_expected') is not False):
            raise ValueError('transaction complete independent 521 original comparisons differ: ' + name)
        if (type(command.get('timeout_seconds')) is not int or command['timeout_seconds'] != 120
                or command.get('same_one_parent_build') is not True or command.get('new_interpreter_process') is not True
                or command.get('command') != [report['executable'], '-B', '-m', 'tests.hia_store_transaction_history',
                    '--history', name, '--manifest', str(manifest_path), '--expected-manifest-sha256', manifest_sha,
                    '--compiler', str(compiler), '--output', str(location)]):
            raise ValueError('transaction child command or original 120-second limit differs')
        if stdout != {k: report[k] for k in ('history','status','original_count','actual_count','differences','actual_frames','elapsed_seconds')}:
            raise ValueError('transaction actual child stdout differs from the retained report')
        for stem, count in (('history', 0 if name == 'H0' else 4), ('held-cleanup', 0 if name == 'H0' else 2)):
            before, after = release_json(location / ('original-' + stem + '.json'), pins), release_json(location / ('candidate-' + stem + '.json'), pins)
            if type(before) is not list or len(before) != count or evaluation_json_bytes(before) != evaluation_json_bytes(after):
                raise ValueError('transaction declared history/held cleanup differs')
            if stem == 'held-cleanup' and any(x.get('cleanup_error') is not None or x.get('observations_frozen_before_cleanup') is not True for x in before):
                raise ValueError('transaction held cleanup failed or preceded observation freeze')
        events = report.get('actual_native_entry_events')
        count = final_positive_counts(events, required=tuple(map(str, range(6))), exact_keys=True)
        if (report.get('actual_native_entry_attempts') != events or events['1'] != events['2'] + events['3']
                or report.get('actual_native_return_codes') != {'96': count}
                or type(report.get('actual_frames')) is not int or report['actual_frames'] <= 0
                or final_positive_counts(report.get('actual_frames_by_phase')) != report['actual_frames']
                or report.get('count_scope') != 'this fresh child; original fork-grandchild entries are not merged or invented'):
            raise ValueError('transaction actual frame/native receipt counts differ')
        by_phase = {}
        for counts in report.get('actual_native_entry_events_by_phase', {}).values():
            final_positive_counts(counts)
            for key, number in counts.items(): by_phase[key] = by_phase.get(key, 0) + number
        if by_phase != events:
            raise ValueError('transaction phase counters do not sum to actual child entries')
        if name == 'H0' and report.get('python') in anchors:
            if (report['originals_sha256'] != anchors[report['python']]
                    or report.get('known_exact_runtime_H0_anchor') != anchors[report['python']]
                    or report.get('known_exact_runtime_H0_anchor_checked') is not True):
                raise ValueError('transaction exact-runtime H0 original anchor differs')
        for key in ('original_count','actual_count','actual_frames','process','originals_sha256','actuals_sha256'):
            if evaluation_json_bytes(row.get(key)) != evaluation_json_bytes(report.get(key)):
                raise ValueError('transaction parent summary does not match its actual child')
        if row.get('events') != events:
            raise ValueError('transaction parent summary native events differ')
        for key, number in events.items(): total[key] = total.get(key, 0) + number
        frame_totals[name] = report['actual_frames']
        output.append({'history': name, 'originals_sha256': report['originals_sha256'],
            'actual_frames': report['actual_frames'], 'actual_entries': count, 'actual_python': report['python'],
            'raw_original_and_actual_equal': True, 'complete_cases': 521})
    if (aggregate.get('events') != total or aggregate.get('actual_frames_by_history') != frame_totals
            or aggregate.get('unique_frozen_cases') != 521 or aggregate.get('declared_histories') != ['H0','H1']
            or aggregate.get('count_scope') != 'two dedicated history child processes'
            or any(aggregate.get(k) is not True for k in ('parent_process_entries_not_included',
                'fork_grandchild_entries_not_invented','same_complete_521_cases_in_each_history',
                'all_521_include_actual_thread_Context_fork_gi_running_and_cleanup_observations'))):
        raise ValueError('transaction combined history counters or declared scope differ')
    return {'histories': output, 'unique_cases': 521, 'actual_events': total,
            'historical_R1_HOLD_not_relabelled': True, 'all_interpreter_histories_claimed': False}


def final_helper_bundle(path, helpers, pins):
    expected = {'schema': 'hepta.hia.native-helpers.v1', 'target': 'linux-x86_64-lp64',
        'abi': 'hia-byte-six-argument-v1', 'helpers': [{'selector': selector, 'manifest_path': str(manifest),
            'manifest_sha256': hashlib.sha256(release_bytes(manifest, pins)).hexdigest()} for selector, manifest in helpers]}
    if release_json(path, pins) != expected:
        raise ValueError('final delivery actual helper bundle differs from its exact admitted images')
    return hashlib.sha256(release_bytes(path, pins)).hexdigest()


def store_transaction_controls(directory, root, compiler, sources, manifest_path, pins, *, cold_path=None, development=False):
    directory = Path(directory)
    errors = ['ValueError','MemoryError','RuntimeError','KeyboardInterrupt','SystemExit']
    at = directory / 'test_safe_initial_preparation_and_confirmed_foreign_errors_preserve_identity'
    safe = release_json(at / 'safe-preparation-and-confirmed.json', pins)
    if safe != [{'effects': [], 'entries': 0, 'error': e, 'same_error': True, 'unused_custody_released': True} for e in errors]:
        raise ValueError('transaction complete safe preparation controls differ')
    at = directory / 'test_actual_handoff_and_foreign_ACK_loss_retain_without_cleanup_or_replay'
    loss = release_json(at / 'native-and-foreign-ACK-loss.json', pins)
    if loss != {'native_losses': [{'actual_entries': 1, 'automatic_cleanup_or_replay': False, 'error': e, 'retained': True} for e in errors],
                'foreign_ACK_error_preserved': True, 'foreign_ACK_events': ['enter','BEGIN IMMEDIATE'],
                'unconfirmed_resources_retained_not_claimed_cleaned': True}:
        raise ValueError('transaction complete native/foreign ACK loss observations differ')
    at = directory / 'test_body_resume_allocation_loss_uses_pre_BEGIN_reservation'
    if release_json(at / 'body-observation.json', pins) != {'COMMIT_ROLLBACK_unlock_not_attempted': True,
            'events': ['enter','BEGIN IMMEDIATE'], 'pre_BEGIN_token_retained': True, 'same_MemoryError': True}:
        raise ValueError('transaction pre-BEGIN reservation or no-cleanup-on-loss differs')
    at = directory / 'test_actual_public_SQL_pinned_bundle_restoration_and_source_drift'
    sql = release_json(at / 'public-SQL.json', pins)
    expected_sql = delivery_literal_values(Path(root) / 'tests/hia_store_transaction_history.py', ('SQL_STATEMENTS',), pins)['SQL_STATEMENTS']
    pin = final_helper_bundle(at / 'bundle.json', [('HEPTA_HIA_STORE_TRANSACTION_MANIFEST', manifest_path)], pins)
    if (sql.get('statements') != list(expected_sql) or final_positive_counts(sql.get('counts'), required=('entries',)) <= 0
            or sql.get('bundle_sha256') != pin or any(sql.get(k) is not True for k in ('scope_restored',
                'retained_body_poisoned','nested_BEGIN_did_not_rollback_the_existing_transaction'))):
        raise ValueError('transaction actual SQL/dynamic error order or bundle scope differs')
    if release_json(at / 'manifest-drift.json', pins) != {
            'source_drift_refused_by_actual_owner_loader_before_effect': True,
            'source_drift_selection': 'explicit_public_selector_without_pinned_scope',
            'source_drift_retained_body_poisoned': True,
            'compiler_metadata_drift_refused_by_explicit_bundle_attestation': True,
            'original_scope_finally_automatically_attests_terminal': False, 'probe_effects': []}:
        raise ValueError('transaction actual standalone source drift or explicit bundle attestation differs')
    at = directory / 'test_actual_cross_owner_swallowed_replaced_and_suppressed_loss_blocks_commit_and_close'
    child_manifest = at / 'child-built/manifest.json'
    delivery_compile_readback(child_manifest.parent, 'store_artifact_profile', root, compiler, sources, pins,
                              cold_path=cold_path, development=development)
    final_helper_bundle(at / 'bundle.json', [('HEPTA_HIA_STORE_TRANSACTION_MANIFEST', manifest_path),
        ('HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST', child_manifest)], pins)
    crossing = release_json(at / 'cross-owner-observations.json', pins)
    if type(crossing) is not list or [x.get('mode') for x in crossing] != ['swallow','replace','with-suppress']:
        raise ValueError('transaction requires all three actual cross-owner loss dispositions')
    for row in crossing:
        if (evaluation_json_bytes(release_json(at / (row['mode'] + '.stdout'), pins)) != evaluation_json_bytes(row)
                or row.get('caught') != 'StoreTransactionUnknown' or row.get('close_calls') != []
                or row.get('events') != ['CREATE TABLE cross_owner_probe(value INTEGER)', 'BEGIN IMMEDIATE',
                                         'INSERT INTO cross_owner_probe VALUES (1)']
                or final_positive_counts(row.get('counts'), required=('child','transaction'), exact_keys=True) <= 0
                or type(row.get('retained_transaction_frames')) is not int or row['retained_transaction_frames'] <= 0
                or row.get('fork') != ({'exact_inherited_unknown_rejected': True, 'no_inherited_native_ancestry': True} if row['mode']=='swallow' else None)
                or row.get('unknown_resources_only_retained_until_process_exit') is not True):
            raise ValueError('transaction cross-owner loss was hidden, retried, committed or cleaned')
        release_bytes(at / (row['mode'] + '.stderr'), pins)
    at = directory / 'test_native_packet_and_full_buffer_differential_rejects_replay_and_drift'
    packets = release_json(at / 'full-packets-and-buffers.json', pins)
    labels = ['request-short','request-long','output-short','state-short','state-long','nonzero-initial-state',
        'bad-magic','reserved-first','reserved-last','bad-mode','zero-identity','initialize','unclaimed-ACK','claim',
        'duplicate-claim','state-checksum-drift','actual-confirmed-body-resume','body-resume-replay']
    if type(packets) is not list or [x.get('case') for x in packets] != labels:
        raise ValueError('transaction requires all 18 original whole-packet/buffer controls')
    for index, row in enumerate(packets):
        expected = (79 if index == 0 else 81 if index == 1 else 80,
                    95 if index == 2 else 96, 127 if index == 3 else 129 if index == 4 else 128)
        data = []
        for key, size in zip(('request','output','state'), expected):
            value = row.get(key)
            if type(value) is not str or re.fullmatch('[0-9a-f]{' + str(2 * size) + '}', value) is None:
                raise ValueError('transaction retained full buffer extent or encoding differs')
            data.append(bytes.fromhex(value))
        if (row.get('complete_buffers_equal_to_independent_VM') is not True or type(row.get('code')) is not int
                or row['code'] != (0xfffffffd if index < 11 or index == 15 else 96)
                or (index in (12,14,17) and int.from_bytes(data[1][8:16], 'little') != 1)):
            raise ValueError('transaction original native/VM packet refusal differs')
    return {'safe_preparation': 5, 'native_ACK_losses': 5, 'foreign_ACK_loss': True,
        'cross_owner_cases': 3, 'full_packet_VM_controls': 18, 'scope_and_drift_checked': True,
        'nonserialized_terminal_effect_assertions_owned_by_complete_full_method': True}


def final_wheel_installation(wheel, installed, root, sources, pins, *, record_sha=None):
    wheel, installed = Path(wheel).resolve(strict=True), Path(installed).resolve(strict=True)
    files, distribution = release_wheel(wheel, pins)
    actual = {p.relative_to(installed).as_posix(): hashlib.sha256(release_bytes(p, pins)).hexdigest()
              for p in sorted(installed.rglob('*')) if p.is_file()}
    result = require_release_installation(installed, actual, files, distribution, wheel,
                                          hashlib.sha256(release_bytes(wheel, pins)).hexdigest(), pins)
    if record_sha is not None and result['record_sha256'] != record_sha:
        raise ValueError('final delivery installed RECORD differs from the actual observation')
    expected = {n for n in sources if n.startswith('hepta/') and n.endswith('.py') and not n.startswith('hepta/_data/')}
    observed = {n for n in files if n.startswith('hepta/') and n.endswith('.py') and not n.startswith('hepta/_data/')}
    if observed != expected:
        raise ValueError('final delivery wheel added/deleted a current production module')
    for name, raw in files.items():
        original = name[len('hepta/_data/'):] if name.startswith('hepta/_data/') else name
        if original in sources and hashlib.sha256(raw).hexdigest() != sources[original]:
            raise ValueError('final delivery installed production/resource source differs: ' + name)
    return files, distribution, result


def store_transaction_installation(directory, root, manifest_path, manifest, sources, pins):
    at = Path(directory) / 'test_actual_installed_wheel_worker_and_durable_COMMIT_acknowledgement_loss'
    observation = release_json(at / 'installation.json', pins)
    if (Path(observation.get('installed', '')).resolve(strict=True) != (at / 'installed').resolve(strict=True)
            or Path(observation.get('wheel', '')).resolve(strict=True).parent != (at / 'wheels').resolve(strict=True)
            or observation.get('scope') != 'actual installed original worker hia_artifact and exact replay; transaction selected'
            or observation.get('whole_native_stack_qualified') is not False):
        raise ValueError('transaction installed worker evidence location or scope differs')
    wheel = Path(observation['wheel'])
    files, dist, installation = final_wheel_installation(wheel, observation['installed'], root, sources, pins,
        record_sha=observation.get('installed_RECORD_sha256'))
    if (observation.get('wheel_sha256') != hashlib.sha256(release_bytes(wheel, pins)).hexdigest()
            or observation.get('wheel_files_checked_against_installed') != {
                n: hashlib.sha256(raw).hexdigest() for n, raw in files.items() if n != dist + '/RECORD'}
            or files.get('hepta/_data/examples/hia_bootstrap/store_transaction.hepta')
               != release_bytes(Path(root) / 'examples/hia_bootstrap/store_transaction.hepta', pins)):
        raise ValueError('transaction actual wheel/source byte readback differs')
    worker_identity = final_installed_worker_identity(files, root, pins)
    pin = final_helper_bundle(at / 'bundle.json', [('HEPTA_HIA_STORE_TRANSACTION_MANIFEST', manifest_path)], pins)
    if observation.get('bundle_sha256') != pin:
        raise ValueError('transaction installed worker used another bundle')
    rows = observation.get('observations', {})
    if set(rows) != {'success','replay','lost_commit','unknown_replay'}:
        raise ValueError('transaction installed worker requires all four actual branches')
    logs, reports, counts = {}, {}, {}
    for key, label in (('success','first'),('replay','replay'),('lost_commit','lost-commit'),('unknown_replay','unknown-replay')):
        stdout, stderr = release_bytes(at / (label + '.stdout'), pins), release_bytes(at / (label + '.stderr'), pins)
        logs[key] = (stdout, stderr)
        recorded = [json.loads(line[len(b'TRANSACTION_COUNTS='):]) for line in stderr.splitlines() if line.startswith(b'TRANSACTION_COUNTS=')]
        if len(recorded) != 1 or recorded[0] != rows[key].get('counts'):
            raise ValueError('transaction actual installed worker counter stream differs')
        counts[key] = recorded[0]
        final_positive_counts(recorded[0].get('startup'))
        final_positive_counts(recorded[0].get('request'), required=('0','1','2'))
        if key != 'lost_commit':
            reports[key] = json.loads(stdout)
            if (evaluation_json_bytes(reports[key]) != evaluation_json_bytes(rows[key].get('report'))
                    or reports[key].get('schema') != 'hia-agent-worker-report-v1'
                    or reports[key].get('tool') != 'hia_artifact' or reports[key].get('complete') is not True
                    or reports[key].get('native_helpers_sha256') != pin
                    or reports[key].get('worker_sha256') != worker_identity['worker_sha256']
                    or reports[key].get('catalog_sha256') != worker_identity['catalog_sha256']
                    or recorded[0].get('close_calls') != 1 or recorded[0].get('unknown_frames') != 0):
                raise ValueError('transaction original installed worker report/source identity differs')
    first, replay, lost, unknown = (rows[k] for k in ('success','replay','lost_commit','unknown_replay'))
    before, after = first.get('before', {}), first.get('after', {})
    response = reports['success'].get('response', {})
    payload = 'native transaction installed worker — 雪'.encode()
    if (response.get('status') != 'completed' or reports['replay'].get('response') != response
            or before.get('request') is not None or after.get('request', {}).get('state') != 'completed'
            or json.loads(after['request'].get('response', 'null')) != response
            or any(type(x.get(k)) is not int for x in (before,after) for k in ('artifacts','costs'))
            or after['artifacts'] != before['artifacts'] + 1
            or response.get('result', {}).get('artifact', {}).get('sha256') != hashlib.sha256(payload).hexdigest()
            or response.get('result', {}).get('byte_length') != str(len(payload))
            or replay.get('state_unchanged') is not True or replay.get('native_transaction_still_checks_original_replay') is not True):
        raise ValueError('transaction normal durable publication or exact original replay differs')
    old, retained, resumed = lost.get('before', {}), lost.get('after', {}), unknown.get('after', {})
    rejected = reports['unknown_replay'].get('response', {})
    if (type(lost.get('worker_exit')) is not int or lost['worker_exit'] != 1
            or logs['lost_commit'][0] != b'' or b'actual durable COMMIT acknowledgement lost' not in logs['lost_commit'][1]
            or counts['lost_commit'].get('close_calls') != 0
            or type(counts['lost_commit'].get('unknown_frames')) is not int or counts['lost_commit']['unknown_frames'] <= 0
            or lost.get('close_refused_before_original_close') is not True
            or retained.get('request', {}).get('state') != 'running' or retained['request'].get('response') is not None
            or retained.get('artifacts') != old.get('artifacts') or retained.get('costs') != old.get('costs')
            or resumed.get('request') != retained['request'] or resumed.get('artifacts') != retained['artifacts']
            or type(resumed.get('costs')) is not int or type(retained.get('costs')) is not int
            or resumed['costs'] != retained['costs'] + 1
            or rejected.get('status') != 'rejected' or rejected.get('error', {}).get('code') != 'E_HIA_REQUEST_UNKNOWN'
            or unknown.get('original_running_request_not_replayed') is not True):
        raise ValueError('transaction unknown COMMIT was refunded, retried, completed or cleaned')
    for label in ('wheel','install'):
        release_bytes(at / (label + '.stdout'), pins);release_bytes(at / (label + '.stderr'), pins)
    return {'installed': installation, 'bundle_sha256': pin, 'actual_worker_counts': counts,
        'normal_replay_retains_original_transaction_checks': True, 'unknown_replay_original_cost_delta': 1,
        'raw_worker_stdin_and_removed_temporary_database_not_claimed_retained': True,
        'unserialized_success_exit_codes_owned_by_complete_full_test': True,
        'close_count_scope': 'actual retained close-dispatch body entry; not an independent SQLite syscall probe'}


def require_store_transaction_component(directory, root, cold_path, compiler, sources, pins):
    final_delivery_target_binding(root, pins)
    final_same_cold(cold_path, compiler, sources, pins)
    directory = Path(directory); manifest_path = directory / 'built/manifest.json'
    manifest = store_transaction_build_readback(manifest_path.parent, root, compiler, sources, pins, cold_path=cold_path)
    custody = release_json(directory / 'component-custody.json', pins)
    if (custody.get('schema') != 'hepta.hia.transaction-component-custody.v1'
            or custody.get('source_manifest_before') != sources or custody.get('source_manifest_after') != sources
            or custody.get('source_and_compiler_unchanged') is not True
            or custody.get('manifest') != str(manifest_path) or custody.get('compiler_sha256') != manifest['compiler_sha256']
            or custody.get('matching_cold_report') != str(cold_path) or custody.get('original_cases') != 521
            or custody.get('test_result_owned_by_outer_runner') is not True
            or any(custody.get(k) is not False for k in ('all_input_equivalence_proved','all_python_versions_tested','whole_native_delivery_qualified'))):
        raise ValueError('transaction complete same-cold component custody differs')
    histories = store_transaction_histories(directory, root, compiler, manifest_path, manifest, sources, 'MATCHING_SOURCE_COLD_COMPONENT', pins)
    controls = store_transaction_controls(directory, root, compiler, sources, manifest_path, pins, cold_path=cold_path)
    installed = store_transaction_installation(directory, root, manifest_path, manifest, sources, pins)
    return {'passed': True, 'scope': 'MATCHING_SOURCE_COLD_COMPONENT', 'manifest': str(manifest_path),
        'histories': histories, 'controls': controls, 'installed': installed,
        'test_bodies_rerun_by_readback': False, 'whole_native_stack_qualified': False}


def artifact_delivery_executables(public):
    """Admit the fixed public/private ELF pair without loading either image."""
    if type(public) is not bytes or len(public) < 352:
        raise ValueError('artifact delivery public executable is incomplete')
    header = struct.unpack_from('<HHIQQQIHHHHHH', public, 16)
    if (public[:16] != b'\x7fELF\x02\x01\x01' + bytes(9)
            or header != (2,62,1,0x400000 + 352,64,0,0,64,56,3,0,0,0)):
        raise ValueError('artifact delivery original public ELF entry differs')
    headers = ((1,5,0,0x400000,0x400000,len(public),len(public),4096),
               (0x6474e551,6,0,0,0,0,0,16), (4,4,232,0x400000+232,0x400000+232,120,120,4))
    if (any(struct.unpack_from('<II6Q', public, 64+56*i) != row for i,row in enumerate(headers))
            or struct.unpack_from('<III', public, 232) != (9,96,1) or public[244:256] != b'HIADELIV\0' + bytes(3)):
        raise ValueError('artifact delivery fixed ELF program/note headers differ')
    words = struct.unpack_from('<12Q', public, 256)
    if (words != (int.from_bytes(b'HIADCTL1','little'),1,0x400000+352,words[3],16,128,96,24,0,0,63,0)
            or not words[2] < words[3] < 0x400000+len(public)):
        raise ValueError('artifact delivery private capability descriptor differs')
    private = bytearray(public);struct.pack_into('<Q', private, 24, words[3])
    return bytes(private), {'public_entry':words[2],'private_entry':words[3], 'prefix_bytes':16, 'ack_bytes':128}


def artifact_delivery_ack(raw, nonce, returncode, stdout_bytes):
    if (type(raw) is not bytes or len(raw) != 128 or type(nonce) is not bytes or len(nonce) != 16
            or type(returncode) is not int or not 0 <= returncode <= 255
            or type(stdout_bytes) is not int or stdout_bytes < 0):
        raise ValueError('artifact delivery full ACK extent or observed status differs')
    w = struct.unpack('<16Q', raw)
    if (w[:2] != (int.from_bytes(b'HIAPDLV1','little'),1) or w[2:4] != struct.unpack('<2Q',nonce)
            or not 0 <= w[4] <= 6 or w[5] not in (1,2,3) or w[6] != returncode or w[7] > 63
            or w[9] != stdout_bytes or w[10] & ~32767 or w[11] > 63 or w[12] > 63
            or raw[104:120] != hashlib.sha256(raw[:104]).digest()[:16]
            or w[15] != int.from_bytes(b'HIAPEND1','little')
            or (w[5] == 1 and (returncode != 0 or w[4] == 0))
            or (w[5] == 2 and (returncode == 0 or stdout_bytes != 0))
            or (w[5] != 3 and not w[10] & (1<<14))):
        raise ValueError('artifact delivery complete ACK identity/checksum/disposition differs')
    return dict(zip(('operation','outcome','exit_code','phase','input_bytes','stdout_bytes','facts','failure_phase','cleanup_phase'),w[4:13]))


def artifact_delivery_build_readback(directory, root, compiler, sources, pins, *, cold_path=None, development=False, private_file=False):
    if type(development) is not bool or development == (cold_path is not None):
        raise ValueError('artifact build reader requires explicit DEV or actual matching cold')
    directory, root, compiler = Path(directory), Path(root), Path(compiler)
    constants = delivery_literal_values(root/'hepta/artifact_publication_native.py',
        ('NATIVE_PUBLICATION_SOURCES','NATIVE_PUBLICATION_OPERATIONS'),pins)
    names, operations = constants['NATIVE_PUBLICATION_SOURCES'],constants['NATIVE_PUBLICATION_OPERATIONS']
    if (type(names) is not tuple or len(names)!=6 or len(set(names))!=6
            or operations != ('publish','verify','withdraw','store-put','store-get','store-hash')):
        raise ValueError('artifact complete original source/operation inventory differs')
    inputs = {n:hashlib.sha256(release_bytes(root/n,pins)).hexdigest() for n in names}
    if any(sources.get(n)!=digest for n,digest in inputs.items()):
        raise ValueError('artifact source inputs are not current-cold bound')
    compiled = {label:final_compile_transport(directory,label,name,root,compiler,sources,pins)
                for label,name in zip(('policy','packer','sha256'),names[:3])}
    build = release_json(directory/'build.json',pins)
    public = release_bytes(directory/'hia-artifact',pins)
    private, descriptor = artifact_delivery_executables(public)
    if private_file and release_bytes(directory/'hia-artifact-private',pins)!=private:
        raise ValueError('artifact fixed private executable differs from the admitted public pair')
    frame = struct.pack('<3Q',int.from_bytes(b'HIAPUB01','little'),len(compiled['policy']['image']),
        len(compiled['sha256']['image']))+compiled['policy']['image']+compiled['sha256']['image']
    frame_sha, packer_sha = hashlib.sha256(frame).hexdigest(),compiled['packer']['image_sha256']
    receipt = release_json(directory/'publication-pack.receipt.json',pins)
    output = release_bytes(directory/'publication-pack.output.bin',pins)
    request = release_json(directory/'publication-pack.request.json',pins)
    if (request != {'capacity':1048576,'format':'flat-x86-64','image':compiled['packer']['image_path'],
                    'image_sha256':packer_sha,'output':str(directory/'publication-pack.output.bin'),
                    'source':str(directory/'publication-pack.input.bin'),'source_sha256':frame_sha,
                    'workspace_fill':0,'workspace_size':1048576}
            or release_bytes(directory/'publication-pack.input.bin',pins)!=frame
            or not 0<len(public)<=len(output)<=1048576 or output[:len(public)]!=public
            or receipt.get('status')!='returned' or receipt.get('format')!='flat-x86-64'
            or receipt.get('return_encoding')!='zero-extended-u32'
            or any(type(receipt.get(k)) is not int or receipt[k]!=v for k,v in (
                ('abi_status',0),('core_u32',len(public)),('result_u64',len(public)),('input_bytes',len(frame))))
            or any(receipt.get(k)!=v for k,v in (('artifact_sha256',packer_sha),('image_sha256',packer_sha),
                ('input_sha256',frame_sha),('source_sha256',frame_sha),('output_sha256',hashlib.sha256(output).hexdigest())))
            or receipt.get('source_unchanged') is not True or receipt.get('forbidden_compiler_modules_loaded')!=[]):
        raise ValueError('artifact actual packer request/full output/receipt is not source-bound')
    compiler_sha=hashlib.sha256(release_bytes(compiler,pins)).hexdigest()
    if (build.get('schema')!='hepta.hia.artifact-publication-build.v1'
            or build.get('status')!='NATIVE_ARTIFACT_PUBLICATION_BUILT'
            or build.get('profile')!=delivery_literal_values(root/'tools/hia_selfhost_contract.py',('PROFILE',),pins)['PROFILE']
            or build.get('source_manifest')!=sources or build.get('source_sha256')!=inputs
            or build.get('executable_path')!='hia-artifact' or build.get('operations')!=list(operations)
            or build.get('compiler_sha256')!=compiler_sha or build.get('native_packer_receipt')!=receipt
            or build.get('compile_receipts')!={k:v['receipt'] for k,v in compiled.items()}
            or build.get('executable_sha256')!=hashlib.sha256(public).hexdigest()
            or build.get('public_executable_sha256')!=hashlib.sha256(public).hexdigest()
            or build.get('private_executable_sha256')!=hashlib.sha256(private).hexdigest()):
        raise ValueError('artifact actual public/private build identity differs')
    if development:
        if (build.get('scope')!='DEVELOPMENT_COMPONENT' or build.get('matching_current_source_cold_qualified') is not False
                or build.get('cold_report_sha256') is not None):
            raise ValueError('artifact development build was relabelled as cold-qualified')
    else:
        inspection={'elf_type':'ET_EXEC','machine':'EM_X86_64','entry':descriptor['public_entry'],
            'program_headers':['PT_LOAD_RX','PT_GNU_STACK_RW','PT_NOTE_HIADELIV'],
            'interpreter':None,'dynamic_loader':False,'libc':False,'bytes':len(public),
            'sha256':hashlib.sha256(public).hexdigest(),'private_delivery_entry':descriptor['private_entry'],
            'private_delivery_ack_bytes':128,'private_delivery_prefix_bytes':16,
            'public_cli_unchanged':True,'argv_env_stdin_control_markers':False}
        if (build.get('cold_report_sha256')!=hashlib.sha256(release_bytes(cold_path,pins)).hexdigest()
                or build.get('image_sha256')!={k:v['image_sha256'] for k,v in compiled.items()}
                or build.get('frame_sha256')!=frame_sha or build.get('executable')!=inspection
                or build.get('artifact_payload_fixed_size_limit') is not None
                or build.get('Agent_artifact_file_limit_bytes')!=64<<20
                or any(build.get(k) is not False for k in ('SQLite_journal_replaced','runtime_Python_or_libc_or_child_required',
                    'full_Agent_persistence_replaced','default_changed','whole_native_delivery_qualified'))):
            raise ValueError('artifact cold/source/packed executable admission differs or widens original scope')
    if not (directory/'hia-artifact').stat().st_mode & stat.S_IXUSR:
        raise ValueError('artifact public executable lost its required executable mode')
    return {'manifest':build,'public':public,'private':private,'descriptor':descriptor,
        'public_sha256':hashlib.sha256(public).hexdigest(),'private_sha256':hashlib.sha256(private).hexdigest()}


def artifact_delivery_child(directory, kind, pins):
    folder = Path(directory) / kind
    value = release_json(folder / 'observations.json', pins)
    if (value.get('schema') != 'hepta.hia.artifact-delivery-child.v1'
            or value.get('status') != 'PASS' or value.get('kind') != kind
            or value.get('unknown_custody_not_cleared') is not True
            or value.get('whole_native_stack_qualified') is not False
            or type(value.get('observations')) is not dict
            or release_bytes(folder / 'stdout.log', pins) != ('D5 child ' + kind + ' PASS\n').encode()):
        raise ValueError('artifact delivery child is missing a complete original observation: ' + kind)
    release_bytes(folder / 'stderr.log', pins)
    return value['observations']


def artifact_delivery_actual_ack(row, pins=None):
    raw = bytes.fromhex(row['stderr_hex'])
    stdin = bytes.fromhex(row['input_hex'])
    stdout = bytes.fromhex(row['stdout_hex'])
    if len(stdin) < 16:
        raise ValueError('artifact actual private child input has no complete nonce')
    return artifact_delivery_ack(raw, stdin[:16], row['exit'], len(stdout))


def artifact_delivery_terminal_controls(directory, root, built, pins):
    value = artifact_delivery_child(directory, 'terminal', pins)
    raw = release_bytes(Path(root) / 'tests/fixtures/hia_artifact_delivery_terminal_cases.json', pins)
    expected = json.loads(raw)['cases']
    rows = value.get('cases')
    if (hashlib.sha256(raw).hexdigest() != 'c883ffba7947f88d64acd37967b6f710416de4a3156e8885f25321291485aee3'
            or type(rows) is not list or len(rows) != len(expected) or len(rows) != 44
            or value.get('input_sha256') != hashlib.sha256(raw).hexdigest()
            or value.get('policy_image_sha256') != hashlib.sha256(release_bytes(Path(directory) / 'artifact/policy.image.bin', pins)).hexdigest()
            or value.get('VM_steps_limit') != 2000000):
        raise ValueError('artifact complete original 44-case terminal inventory differs')
    lo, hi = struct.unpack('<2Q', bytes(range(16)))
    for case, row in zip(expected, rows):
        result = bytes(128) if case['policy_return'] == 16 else struct.pack('<16Q',
            int.from_bytes(b'HIAPDLV1', 'little'), 1, lo, hi, case['operation'], case['outcome'],
            case['exit_code'], case['phase'], case['input_bytes'], case['stdout_bytes'], case['facts'],
            case['failure_phase'], case['cleanup_phase'], 0, 0, int.from_bytes(b'HIAPEND1', 'little'))
        if row != {'name': case['name'], 'native_return': case['policy_return'], 'VM_return': case['policy_return'],
                   'expected_return': case['policy_return'], 'native_hex': result.hex(), 'VM_hex': result.hex(),
                   'expected_hex': result.hex(), 'canaries_unchanged': True}:
            raise ValueError('artifact native/VM complete terminal output differs: ' + case['name'])
    return {'complete_cases': 44, 'full_128_byte_outputs_equal': True, 'original_VM_limit': 2000000,
            'workspace_immutability_and_canaries_authority': 'complete retained test method plus observed canary flag'}


def artifact_delivery_operation_controls(directory, root, value, built, pins):
    record = release_json(Path(directory) / 'cli/operation-observations.json', pins)
    raw = release_bytes(Path(root) / 'tests/fixtures/hia_artifact_delivery_operation_cases.json', pins)
    cases = json.loads(raw)['cases']
    if (value != record or len(cases) != 5
            or hashlib.sha256(raw).hexdigest() != 'bfe2c946858572f1670503129e80d1ecc19d02db38a8609be91e83466f754159'
            or record.get('cases_sha256') != hashlib.sha256(raw).hexdigest()
            or record.get('public_image_sha256') != built['public_sha256']
            or record.get('private_image_sha256') != built['private_sha256']
            or record.get('candidate_full_current_admission') is not True
            or record.get('original_code_admission_explicit') is not True
            or len(record.get('original', [])) != 5 or len(record.get('selected', [])) != 5):
        raise ValueError('artifact separate operation-object original/current-image observation differs')
    for case, old, new in zip(cases, record['original'], record['selected']):
        if (old.get('name') != case['name'] or new.get('name') != case['name']
                or evaluation_json_bytes({k:v for k,v in old.items() if k!='calls'}) !=
                   evaluation_json_bytes({k:v for k,v in new.items() if k!='calls'})):
            raise ValueError('artifact original operation-object result/exception/effects differ')
        for selected, side in ((False, old), (True, new)):
            for call in side['calls']:
                expected_sha = built['private_sha256' if selected else 'public_sha256']
                if (call.get('sealed_sha256') != expected_sha or call.get('env') != {'PATH':''}
                        or len(call.get('argv', [])) != 4 or len(call.get('pass_fds', [])) != 1
                        or call['argv'][0] != '/proc/self/fd/' + str(call['pass_fds'][0])
                        or call.get('entry') != built['descriptor']['private_entry' if selected else 'public_entry']):
                    raise ValueError('artifact operation object sealed complete executable/ABI differs')
                if selected:
                    ack = artifact_delivery_actual_ack(call)
                    if call.get('ack') != ack:
                        raise ValueError('artifact operation object full ACK differs')
                elif call.get('stderr_hex') != '':
                    raise ValueError('original public operation unexpectedly returned private ACK bytes')
    old, new = record['original'][1], record['selected'][1]
    if (old['outcome'] != {'returned':True} or old['operation_comparisons'] != [['__ne__','withdraw','withdraw']]*2
            or new['calls'][0]['ack']['operation'] != 3 or new['calls'][0]['ack']['input_bytes'] != 0
            or new['calls'][0]['input_hex'] != (bytes(range(16))+b'abc').hex()):
        raise ValueError('artifact original withdraw subclass/input domain was narrowed')
    return {'complete_original_operation_cases':5, 'canonical_nontransport_results_equal':True,
            'old_public_code_admission_is_explicit':True, 'selected_sealed_private_bytes_verified':True}


def artifact_delivery_cli_controls(directory, root, built, pins):
    value = artifact_delivery_child(directory, 'cli', pins)
    rows = value.get('cases')
    if (type(rows) is not list or len(rows) != 43
            or value.get('actual_six_operations_public_and_private') is not True
            or value.get('public_control_marker_added') is not False):
        raise ValueError('artifact public/private complete CLI scope differs')
    nonce = bytes(range(16)); position = 0
    operations = ('publish','verify','withdraw','store-put','store-get','store-hash')
    for payload in (b'\0',bytes(range(256)),nonce+b'HIADCTL1\0private-looking-public-data'):
        for code, operation in enumerate(operations,1):
            for private in (False,True):
                row = rows[position]; position += 1
                data = b'' if operation in ('withdraw','store-get') else payload
                stdout = bytes.fromhex(row['stdout_hex'])
                argv = row.get('argv',[])
                if (row.get('operation') != operation or row.get('private') is not private
                        or type(row.get('exit')) is not int or row['exit'] != 0 or row.get('env') != {'PATH':''}
                        or row.get('stdin_hex') != ((nonce if private else b'')+data).hex()
                        or len(argv)!=4 or argv[0]!=str(Path(directory)/'artifact'/('hia-artifact-private' if private else 'hia-artifact'))
                        or argv[1]!=operation):
                    raise ValueError('artifact original four-argument CLI/data domain differs')
                if private:
                    ack = artifact_delivery_ack(bytes.fromhex(row['stderr_hex']),nonce,0,len(stdout))
                    if row.get('ack')!=ack or ack['operation']!=code or ack['outcome']!=1:
                        raise ValueError('artifact actual CLI complete private ACK differs')
                elif row.get('stderr_hex')!='':
                    raise ValueError('artifact public CLI leaked a private control channel')
                if operation=='store-get':
                    equal = stdout==payload
                else:
                    expected = {'withdrawn':True} if operation=='withdraw' else {'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
                    equal = evaluation_json_bytes(json.loads(stdout))==evaluation_json_bytes(expected)
                if not equal:
                    raise ValueError('artifact original CLI stdout bytes/document differ')
    for operation,row in zip(('_delivery','HIADCTL1','store-control'),rows[36:39]):
        if row!={'unknown_public_operation':operation,'exit':16,'stdin_hex':nonce.hex(),'stdout_hex':'','stderr_hex':''}:
            raise ValueError('artifact old public CLI operation refusal changed')
    for extent,row in zip((0,1,8,15),rows[39:]):
        raw = bytes.fromhex(row['stderr_hex'])
        ack = artifact_delivery_ack(raw,raw[16:32],16,0)
        if (row.get('short_private_prefix')!=extent or row.get('exit')!=16 or row.get('ack')!=ack
                or row.get('original_nonce_complete') is not False or ack['outcome']!=3 or ack['facts']&(1<<14)):
            raise ValueError('artifact truncated private prefix was falsely confirmed')
    operations = artifact_delivery_operation_controls(directory,root,value.get('operation_objects'),built,pins)
    return {'six_operations_both_entries':36,'public_unknown_operations':3,'short_private_prefixes':4,
            'separate_operation_objects':operations,'filesystem_effect_assertions_authority':'original complete CLI method'}


def artifact_delivery_loss_controls(directory, built, pins):
    value = artifact_delivery_child(directory,'loss',pins)
    modes = ('missing','truncated','extra','nonce','checksum','wrong-output',
             'OSError','ValueError','RuntimeError','MemoryError','KeyboardInterrupt','SystemExit')
    rows = value.get('cases')
    if (type(rows) is not list or [r.get('mode') for r in rows]!=list(modes)
            or value.get('retained_custody_not_cleared') is not True
            or value.get('source_Store_and_actual_provider_composition') is not True):
        raise ValueError('artifact complete actual loss matrix differs')
    for row in rows:
        calls = row.get('native',[])
        if ([c.get('operation') for c in calls]!=['store-hash','store-put']
                or row.get('retry_native_calls')!=0 or not row.get('close_error_type','').endswith('Unknown')
                or any(row.get(k) is not True for k in ('database_still_open','artifact_row_count_unchanged',
                    'same_object_reinitialization_refused','exact_Store_retained','unrelated_healthy_Store_closed'))):
            raise ValueError('artifact actual effect loss was retried/closed or lost exact Store custody')
        for code,call in zip((6,4),calls):
            ack=artifact_delivery_actual_ack(call)
            if call['exit']!=0 or ack['outcome']!=1 or ack['operation']!=code:
                raise ValueError('artifact loss matrix did not first execute the actual intended native effect')
        preserve=row['mode'] in ('RuntimeError','MemoryError','KeyboardInterrupt','SystemExit')
        if (row.get('injected_identity_preserved') is not preserve
                or (preserve and row.get('error_type')!=row['mode'])
                or (not preserve and not row.get('error_type','').endswith('Unknown'))):
            raise ValueError('artifact actual native loss identity/disposition differs')
    return {'complete_actual_loss_cases':12,'raw_confirmed_effect_ACKs_before_injection':24,
            'repeat_native_calls':0,'retained_Store_policy_forbidden_scope':'loss child only'}


def artifact_delivery_boundary_controls(directory, built, pins):
    negative=artifact_delivery_child(directory,'negative',pins)
    rows=negative.get('cases')
    if (type(rows) is not list or [r.get('fsync_position') for r in rows]!=[1,2]
            or negative.get('real_file_and_directory_fsync_refusals') is not True
            or negative.get('allowed_immutable_content_residue_preserved') is not True):
        raise ValueError('artifact original file/directory fsync refusal scope differs')
    for position,row in enumerate(rows,1):
        call=row['native'];ack=artifact_delivery_actual_ack(call)
        payload=b'actual HIA fsync refusal '+bytes([position]);digest=hashlib.sha256(payload).hexdigest()
        if (row.get('ack')!=ack or ack['outcome']!=2 or ack['exit_code']!=15
                or row.get('error_type')!='PublicationRejected' or 'E_PUBLISH_IO' not in row.get('error_message','')
                or row.get('residual_files')!=([] if position==1 else [digest])
                or row.get('resource_retirement_allowed') is not True
                or not ack['facts']&(1<<2) or (position==2 and not ack['facts']&(1<<8))):
            raise ValueError('artifact business refusal was confused with an unconfirmed native delivery')
        argv=call.get('argv',[]);trace=Path(directory)/'negative'/str(position)/'strace.log'
        if (len(argv)!=9 or argv[1:5]!=['-o',str(trace),'-e','inject=fsync:error=EIO:when='+str(position)]
                or argv[6]!='store-put' or bytes.fromhex(call['input_hex'])[16:]!=payload):
            raise ValueError('artifact actual fsync injection command differs')
        raw=release_bytes(trace,pins)
        if b'fsync(' not in raw or b'EIO' not in raw or b'INJECTED' not in raw:
            raise ValueError('artifact actual fsync injection raw trace absent')
        if position==2 and release_bytes(Path(directory)/'negative/2/store'/digest,pins)!=payload:
            raise ValueError('artifact permitted immutable residue bytes changed')
    boundaries=artifact_delivery_child(directory,'boundaries',pins)
    rows=boundaries.get('cases')
    expected=[(kind,position) for kind in ('OSError','ValueError','RuntimeError','MemoryError','KeyboardInterrupt','SystemExit','ArtifactDeliveryUnknown')
              for position in ('before-handoff','after-confirmed-terminal')]
    if (type(rows) is not list or len(rows)!=15
            or boundaries.get('exception_name_never_evidence_of_loss') is not True
            or boundaries.get('post_terminal_foreign_not_reclassified') is not True):
        raise ValueError('artifact ordinary foreign boundary scope differs')
    for (kind,position),row in zip(expected,rows[:14]):
        calls=row.get('native',[])
        if (row.get('family')!=kind or row.get('position')!=position
                or row.get('error_identity_preserved') is not True or row.get('resource_closed') is not True
                or len(calls)!=(0 if position=='before-handoff' else 1)):
            raise ValueError('artifact confirmed/preentry foreign exception lost original identity')
        if calls:
            raw=bytes.fromhex(calls[0]['stderr_hex'])
            ack=artifact_delivery_ack(raw,raw[16:32],calls[0]['exit'],struct.unpack_from('<Q',raw,72)[0])
            if calls[0].get('operation')!='store-hash' or ack['outcome']!=1:
                raise ValueError('artifact post-terminal foreign control lacks a confirmed actual effect')
    safe=rows[-1]
    if (safe.get('position')!='memfd-before-entry' or safe.get('original_cause_identity') is not True
            or safe.get('native_calls')!=0 or safe.get('resource_closed') is not True
            or 'E_PUBLISH_NATIVE_CUSTODY' not in safe.get('error','')):
        raise ValueError('artifact safe preentry preparation refusal differs')
    lifetimes=artifact_delivery_child(directory,'lifetimes',pins)
    flags=('healthy_weak_owner_released','cross_thread_no_invented_parent','explicit_resource_loss_observed_on_existing_record',
        'cross_context_deactivate_no_token_reset','stale_scope_inherits_no_resource','pre_reserved_resume_observation_error_identity',
        'failed_observation_custody_retained','normal_observation_retired','identity_only_resource_protocol')
    if set(lifetimes)!=set(flags)|{'cross_thread_native_calls'} or lifetimes.get('cross_thread_native_calls')!=1 or any(lifetimes[k] is not True for k in flags):
        raise ValueError('artifact actual resource/thread/context lifetime controls differ')
    reentrant=artifact_delivery_child(directory,'reentrant',pins);calls=reentrant.get('native',[])
    if (len(calls)!=2 or reentrant.get('root_lookups')!=['root.__fspath__']
            or reentrant.get('outer_receipt')!={'sha256':hashlib.sha256(b'outer').hexdigest(),'bytes':5}
            or any(reentrant.get(k) is not True for k in ('direct_helper_did_not_consume_outer_token','canonical_unarmed_refused_before_child','selector_token_restored'))):
        raise ValueError('artifact reentrant old direct helper/token boundary differs')
    for index,(operation,call) in enumerate(zip(('withdraw','store-hash'),calls)):
        if (call.get('operation')!=operation or call.get('exit')!=0
                or call.get('sealed_sha256')!=built['public_sha256' if index==0 else 'private_sha256']
                or call.get('fixed_admitted_sha256')!=built['private_sha256']):
            raise ValueError('artifact reentrant complete sealed bytes differ')
        if index==0:
            if call.get('stderr_hex')!='' or call.get('input_hex')!='' or json.loads(bytes.fromhex(call['stdout_hex']))!={'withdrawn':False}:
                raise ValueError('artifact original low-level public invocation consumed private control')
        elif artifact_delivery_actual_ack(call)['operation']!=6:
            raise ValueError('artifact actual outer reentrant ACK operation differs')
    return {'real_fsync_refusals':2,'foreign_boundaries':15,'lifetime_control_flags':len(flags),
        'reentrant_actual_children':2,'control_assertions_authority':'complete original Native methods; no control is rerun by this reader'}


def artifact_delivery_worker_counts(raw, root, built, pins):
    prefix=b'D5_COUNTS='
    rows=[line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    if len(rows)!=1:
        raise ValueError('artifact installed worker actual counter record absent/duplicated')
    value=json.loads(rows[0]);owners={'store','context','journal','provider'}
    for phase in ('startup','request','cleanup'):
        if set(value.get(phase,{}))!=owners:
            raise ValueError('artifact installed worker phase/owner inventory differs')
        final_positive_counts(value[phase])
    modules=('artifact_publication_native','hia_artifact_delivery','hia_native_delivery',
             'hia_store_artifact_profile_native','hia_service_context_native','hia_agent_journal_native')
    expected={'hepta.'+name:hashlib.sha256(release_bytes(Path(root)/'hepta'/(name+'.py'),pins)).hexdigest() for name in modules}
    if value.get('module_sha256')!=expected:
        raise ValueError('artifact installed child module bytes differ from the current source')
    natural=value.get('natural_admissions')
    if (type(natural) is not dict or set(natural)!={'startup','request','cleanup'}
            or value.get('observer_extra_admissions')!=0):
        raise ValueError('artifact observer added source admission calls or lost real admission counters')
    final_positive_counts(natural)
    for key in ('durable_puts','lost_ack','peer_losses','swallowed','close_attempts','actual_db_close',
                'lost_records','pending_native_records','Store_unknown_frames'):
        if type(value.get(key)) is not int or value[key]<0:
            raise ValueError('artifact installed resource/worker counter differs: '+key)
    operations=value.get('provider_operations')
    if type(operations) is not list or len(operations)!=value['request']['provider']:
        raise ValueError('artifact actual provider request calls do not match raw receipts')
    names=('publish','verify','withdraw','store-put','store-get','store-hash')
    for call in operations:
        raw_ack=bytes.fromhex(call['stderr_hex']);stdout=bytes.fromhex(call['stdout_hex'])
        ack=artifact_delivery_ack(raw_ack,raw_ack[16:32],call['exit'],len(stdout))
        if (call.get('operation') not in names or ack['operation']!=names.index(call['operation'])+1
                or ack['outcome']!=1 or call.get('sealed_sha256')!=built['private_sha256']
                or re.fullmatch('[0-9a-f]{64}',call.get('stdin_sha256','')) is None):
            raise ValueError('artifact installed actual sealed bytes/operation/complete ACK differ')
    return value


def artifact_delivery_scope_controls(directory, scope, root, manifests, capsule, pins):
    folder=Path(directory)/'installed'
    actual=release_json(folder/'scope-probe.stdout',pins)
    if scope!=actual or scope.get('schema')!='hepta.hia.artifact-delivery-scope-observations.v1' or scope.get('status')!='PASS':
        raise ValueError('artifact installed scope raw stdout differs')
    expected=['unselected_scope','v1_scope','wrong_factory','wrong_path','wrong_actual_thread',
        'wrong_actual_process','owner_after_scope','NativeWorkerBundleBinding_exact_registry_boundary',
        'NativeWorkerSchedulingBinding_exact_registry_boundary']
    for name in ('added_module','deleted_module','changed_module','build.json','hia-artifact'):
        expected.extend(name+suffix for suffix in ('_fresh_public_call','_cached_call_local_admission','_terminal_identity'))
    rows=scope.get('rows',[])
    if ([r.get('name') for r in rows]!=expected or scope.get('artifact_children')!=0
            or scope.get('source_restored') is not True or scope.get('selectors_restored') is not True
            or scope.get('old_v2_v3_scope')!='exact existing registry unit boundary; profiles not built in this control'):
        raise ValueError('artifact complete fresh inventory/manifest/image/scope negative matrix differs')
    for row in rows:
        if row['name']=='wrong_actual_process':
            if row!={'name':'wrong_actual_process','child_exit':0,'artifact_children':0}:
                raise ValueError('artifact actual fork owner control differs')
        elif (row.get('children')!=0 or not row.get('error')
              or ('error_type' in row and row['error_type'] not in ('ValueError','OSError','TypeError','RuntimeError','PublicationRejected'))):
            raise ValueError('artifact custody refusal reached an actual child or lacks original error')
    probe=folder/'scope-probe'
    for name in ('build.json','hia-artifact'):
        if release_bytes(probe/'artifact'/name,pins)!=release_bytes(Path(manifests['artifact']).parent/name,pins):
            raise ValueError('artifact scope probe failed to restore the full actual manifest/image')
    copied=dict(capsule);copied['artifact_manifest']=str(probe/'artifact/build.json')
    if release_json(probe/'capsule.json',pins)!=copied:
        raise ValueError('artifact scope probe did not bind the one deliberate copied artifact manifest')
    return {'negative_rows':len(expected),'artifact_children':0,'whole_inventory_added_deleted_changed_checks':True,
            'old_v2_v3_scope':'registry unit negatives only; their executable profiles were not constructed'}


def artifact_delivery_installation(directory, root, manifests, built, sources, pins):
    folder=Path(directory)/'installed'
    value=artifact_delivery_child(directory,'installed',pins)
    if value!=release_json(folder/'installed-observations.json',pins):
        raise ValueError('artifact installed aggregate differs from its retained child result')
    flags=('actual_original_worker','fresh_wheel_unique_RECORD_verified','retained_Store_context_journal_bodies_forbidden_in_child',
        'artifact_is_separate_private_ABI_not_six_argument_helper','every_public_call_and_normal_terminal_full_inventory_checks',
        'source_and_manifest_image_mutations_restored_in_finally')
    if (value.get('schema')!='hepta.hia.artifact-delivery-installed-observations.v1'
            or any(value.get(k) is not True for k in flags) or value.get('whole_native_stack_qualified') is not False):
        raise ValueError('artifact installed worker scope/identity differs')
    wheel=Path(value['wheel']);wheels=list((folder/'wheels').glob('*.whl'))
    if (len(wheels)!=1 or wheel.resolve(strict=True)!=wheels[0].resolve(strict=True)
            or value.get('wheel_sha256')!=hashlib.sha256(release_bytes(wheel,pins)).hexdigest()):
        raise ValueError('artifact installed wheel identity is not unique')
    files,dist,installation=final_wheel_installation(wheel,folder/'installed',root,sources,pins)
    records=release_json(folder/'wheel-records.json',pins)
    if (type(records) is not list or len(records)!=len(files)
            or {row.get('name'):row for row in records}!={n:{'name':n,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()} for n,b in files.items()}
            or value.get('wheel_records_sha256')!=hashlib.sha256(release_bytes(folder/'wheel-records.json',pins)).hexdigest()):
        raise ValueError('artifact wheel complete RECORD member observation differs')
    helpers=[('HEPTA_HIA_'+name.upper()+'_MANIFEST',manifests[name]) for name in ('store_artifact_profile','service_context','agent_journal')]
    bundle_sha=final_helper_bundle(folder/'helpers-v1.json',helpers,pins)
    capsule=release_json(folder/'artifact-v4.json',pins)
    expected={'schema':'hepta.hia.native-helpers.v4','target':'linux-x86_64-lp64','abi':'hia-worker-artifact-delivery-v1',
        'helpers_bundle':str(folder/'helpers-v1.json'),'helpers_bundle_sha256':bundle_sha,
        'artifact_manifest':manifests['artifact'],'artifact_manifest_sha256':hashlib.sha256(release_bytes(manifests['artifact'],pins)).hexdigest()}
    capsule_sha=hashlib.sha256(release_bytes(folder/'artifact-v4.json',pins)).hexdigest()
    if (capsule!=expected or value.get('v1_bundle_sha256')!=bundle_sha or value.get('v4_capsule_sha256')!=capsule_sha
            or value.get('source_bound_public_private_manifest_sha256')!=expected['artifact_manifest_sha256']):
        raise ValueError('artifact separate v4 capsule changed or was inserted as a six-argument helper')
    commands=release_json(folder/'commands.json',pins)
    labels=['wheel','install']+[label for mode in ('normal','ack','peer-swallow','peer-replace','exit') for label in (mode,mode+'-replay')]+['installed-source-drift','scope-probe']
    if (type(commands) is not list or len(commands)!=len(labels)
            or {row.get('label') for row in commands}!=set(labels)):
        raise ValueError('artifact installed original full command inventory was reduced')
    logs={}
    for row in commands:
        label=row['label'];stdout=release_bytes(folder/(label+'.stdout'),pins);stderr=release_bytes(folder/(label+'.stderr'),pins)
        if (row.get('stdout_sha256')!=hashlib.sha256(stdout).hexdigest() or row.get('stderr_sha256')!=hashlib.sha256(stderr).hexdigest()
                or type(row.get('exit_code')) is not int or type(row.get('elapsed_seconds')) not in (int,float)
                or not 0<=row['elapsed_seconds']<float('inf') or row.get('argv',[None,None])[1]!='-B'):
            raise ValueError('artifact installed raw command/status/unchanged 60s method transport differs')
        logs[label]=(stdout,stderr,row)
    worker_scripts=delivery_literal_values(Path(root)/'tests/hia_artifact_delivery_installed.py',('WORKER','SCOPE_PROBE'),pins)
    for label in labels[2:-1]:
        argv=logs[label][2]['argv'];mode='normal' if label.endswith('-replay') or label=='installed-source-drift' else label
        if (argv[2:7]!=['-I','-c',worker_scripts['WORKER'],str(folder/'installed'),mode]
                or len(argv)!=16 or argv[7]!='--state-root' or argv[9]!='--artifact-root'
                or argv[11:]!=['--request-json-stdin','--native-helpers-manifest',str(folder/'artifact-v4.json'),
                              '--expected-native-helpers-sha256',capsule_sha]
                or re.fullmatch('[0-9a-f]{64}',logs[label][2].get('stdin_sha256','')) is None):
            raise ValueError('artifact installed child is not the recorded original worker wrapper/ABI')
    rows=value.get('worker',{})
    if set(rows)!={'normal','ack','peer-swallow','peer-replace','exit','installed_source_drift'}:
        raise ValueError('artifact installed actual worker/replay branch set differs')
    baseline=artifact_delivery_closed_baseline(folder,value.get('closed_baseline'),capsule_sha,commands,pins)
    schedule=artifact_delivery_pair_schedule(folder,value.get('pair_schedule'),rows,commands,pins)
    if any(evaluation_json_bytes(rows[mode].get('before'))!=evaluation_json_bytes(rows['normal'].get('before'))
            for mode in ('ack','peer-swallow','peer-replace','exit')):
        raise ValueError('artifact byte-identical closed baseline copies disagree before worker execution')
    workers=artifact_delivery_installed_workers(rows,logs,root,built,sources,capsule_sha,pins,final_installed_worker_identity(files,root,pins))
    drift=rows['installed_source_drift'];original=files['hepta/_data/examples/hia_bootstrap/artifact_publication_policy.hepta']
    drift_counts=artifact_delivery_worker_counts(logs['installed-source-drift'][1],root,built,pins)
    if (drift.get('counts')!=drift_counts or drift.get('exit_code')!=logs['installed-source-drift'][2]['exit_code']
            or drift['exit_code']==0 or logs['installed-source-drift'][0]!=b''
            or any(v for phase in ('startup','request','cleanup') for v in drift_counts[phase].values())
            or drift_counts['close_attempts']!=0 or drift.get('request_database_unchanged') is not True
            or drift.get('original_sha256')!=hashlib.sha256(original).hexdigest()
            or drift.get('changed_sha256')!=hashlib.sha256(original+b'\n').hexdigest()
            or drift.get('restored_sha256')!=hashlib.sha256(original).hexdigest()
            or drift.get('exact_change')!='one appended LF in packaged artifact publication policy'):
        raise ValueError('artifact installed exact LF mutation did not fail before any effect and restore')
    scope=artifact_delivery_scope_controls(directory,value.get('scope'),root,manifests,capsule,pins)
    if logs['scope-probe'][2]['exit_code']!=0 or logs['wheel'][2]['exit_code']!=0 or logs['install'][2]['exit_code']!=0:
        raise ValueError('artifact installation/custody child did not return success')
    return {'wheel':str(wheel),'wheel_sha256':value['wheel_sha256'],'installation':installation,
        'worker':workers,'scope':scope,'v4_capsule_sha256':capsule_sha,
        'closed_baseline':baseline,'pair_schedule':schedule,
        'source_restored_to_wheel_bytes':True,'actual_db_close_counter_scope':'original close reference entry, not OS syscall probe',
        'raw_worker_request_stdin_and_removed_fixture_SQLite_files_retained':False,
        'no_false_zero_startup_claim':True,'whole_native_stack_qualified':False}


def artifact_delivery_installed_workers(rows, logs, root, built, sources, capsule_sha, pins, worker_identity):
    observed={}
    for mode,exit_code in (('normal',0),('ack',1),('peer-swallow',1),('peer-replace',1),('exit',73)):
        row=rows[mode];stdout,stderr,command=logs[mode]
        replay_stdout,replay_stderr,replay_command=logs[mode+'-replay']
        counts=artifact_delivery_worker_counts(stderr,root,built,pins)
        replay=artifact_delivery_worker_counts(replay_stderr,root,built,pins)
        if (row.get('worker_exit_code')!=exit_code or command['exit_code']!=exit_code
                or row.get('counts')!=counts or row.get('replay_counts')!=replay
                or row.get('replay_worker_exit_code')!=0 or replay_command['exit_code']!=0
                or counts['durable_puts']!=1 or any(counts['request'][k]<=0 for k in ('provider','store','context','journal'))
                or counts['startup']['store']<=0 or counts['close_attempts']!=(0 if mode=='exit' else 1)
                or counts['actual_db_close']!=(1 if mode=='normal' else 0)
                or counts['peer_losses']!=int(mode.startswith('peer-')) or counts['swallowed']!=int(mode.startswith('peer-'))
                or counts['lost_ack']!=int(mode=='ack')):
            raise ValueError('artifact actual worker effect/loss/close disposition differs: '+mode)
        before,after,last=(row.get(k) for k in ('before','after','replay_state'))
        for state in (before,after,last):
            if (type(state) is not dict or set(state)!={'request','artifacts','costs'}
                    or any(type(state[k]) is not int or state[k]<0 for k in ('artifacts','costs'))):
                raise ValueError('artifact installed durable state observation is incomplete')
        if before['request'] is not None or type(after['request']) is not dict or last['request']!=after['request']:
            raise ValueError('artifact original request intent/replay observation changed')
        replay_report=json.loads(replay_stdout)
        if evaluation_json_bytes(replay_report)!=evaluation_json_bytes(row.get('replay_report')):
            raise ValueError('artifact actual replay stdout differs from durable observations')
        reports=[replay_report]
        if mode=='normal':
            report=json.loads(stdout);reports.append(report)
            if (evaluation_json_bytes(report)!=evaluation_json_bytes(row.get('report'))
                    or report.get('response',{}).get('status')!='completed'
                    or replay_report.get('response')!=report.get('response')
                    or after['request'].get('state')!='completed' or last!=after
                    or after['artifacts']!=before['artifacts']+1 or after['costs']!=before['costs']+1
                    or counts['lost_records']!=0 or counts['Store_unknown_frames']!=0):
                raise ValueError('artifact original completed publication/exact replay differs')
        elif (stdout!=b'' or row.get('report') is not None or after['request'].get('state')!='running'
                or after['request'].get('response') is not None or after['artifacts']!=before['artifacts']
                or after['costs']!=before['costs'] or last['artifacts']!=after['artifacts'] or last['costs']!=after['costs']+1
                or replay_report.get('response',{}).get('status')!='rejected'
                or replay_report['response'].get('error',{}).get('code')!='E_HIA_REQUEST_UNKNOWN'
                or (mode=='exit' and counts['pending_native_records']<=0)
                or (mode!='exit' and (counts['lost_records']<=0 or counts['Store_unknown_frames']<=0))):
            raise ValueError('artifact actual unconfirmed effect was completed/refunded/retried')
        for report in reports:
            if (report.get('schema')!='hia-agent-worker-report-v1' or report.get('tool')!='hia_artifact'
                    or report.get('complete') is not True or report.get('profile_sha256')!='a'*64
                    or report.get('native_helpers_sha256')!=capsule_sha
                    or report.get('worker_sha256')!=worker_identity['worker_sha256']
                    or report.get('catalog_sha256')!=worker_identity['catalog_sha256']
                    or any(re.fullmatch('[0-9a-f]{64}',report.get(k,'')) is None for k in ('backend_sha256','catalog_sha256','request_sha256'))):
                raise ValueError('artifact original installed worker source/capsule report differs')
        if (any(replay['request'][k]!=0 for k in ('provider','store','context')) or replay['request']['journal']<=0
                or replay['startup']['store']<=0 or any(replay[k]!=0 for k in ('durable_puts','lost_records','Store_unknown_frames'))
                or replay['close_attempts']!=1 or replay['actual_db_close']!=1
                or row.get('request_provider_calls_on_replay')!=0 or row.get('startup_is_not_zero_native_calls') is not True
                or row.get('durable_content_sha256')!=hashlib.sha256(('actual private delivery — 雪 — '+mode).encode()).hexdigest()):
            raise ValueError('artifact exact replay performed another publication or hid startup observations')
        observed[mode]={'actual_exit_code':exit_code,'request_native_entries':dict(counts['request']),
            'replay_request_native_entries':dict(replay['request']),'complete_raw_native_receipts':len(counts['provider_operations']),
            'state_after_equals_replay':last==after,'unknown_replay_cost_delta':last['costs']-after['costs']}
    return observed


def artifact_delivery_component_custody(directory, root, compiler, sources, pins, *, cold_path=None, development=False):
    if type(development) is not bool or development == (cold_path is not None):
        raise ValueError('artifact component custody requires explicit DEV or this original matching cold')
    directory,root,compiler=Path(directory),Path(root),Path(compiler)
    inputs=final_source_inputs(root,sources,'tests/hia_artifact_delivery_fixture.py','INPUTS',pins)
    expected_sources={n:v for n,v in sources.items() if n!='docs/HIA_SELFHOST_CORE_SUPPORT.json'}
    expected_sources.update(inputs)
    custody=release_json(directory/'component-custody.json',pins)
    owners=('store_artifact_profile','service_context','store_lifecycle','agent_journal')
    manifests={'artifact':str(directory/'artifact/build.json'),**{n:str(directory/('build-'+n)/'manifest.json') for n in owners}}
    if (release_json(directory/'manifests.json',pins)!=manifests
            or custody.get('schema')!='hepta.hia.artifact-delivery-component-custody.v1'
            or custody.get('scope')!=('DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT')
            or custody.get('matching_cold_report')!=(None if development else str(cold_path))
            or custody.get('matching_cold_sha256')!=(None if development else hashlib.sha256(release_bytes(cold_path,pins)).hexdigest())
            or custody.get('compiler_sha256')!=hashlib.sha256(release_bytes(compiler,pins)).hexdigest()
            or custody.get('manifests')!=manifests or custody.get('source_before')!=expected_sources
            or custody.get('source_after')!=expected_sources or custody.get('inputs_stable') is not True
            or custody.get('original_132_and_Store_130_qualified_by_this_record') is not False
            or custody.get('whole_native_stack_qualified') is not False):
        raise ValueError('artifact complete component source/compiler/cold custody differs')
    built=artifact_delivery_build_readback(directory/'artifact',root,compiler,sources,pins,
        cold_path=cold_path,development=development,private_file=True)
    auxiliary={}
    for owner in owners:
        folder=directory/('build-'+owner)
        if owner=='agent_journal' and development:
            source='examples/hia_bootstrap/agent_journal.hepta'
            compiled=final_compile_transport(folder,'agent-journal',source,root,compiler,sources,pins)
            manifest=release_json(folder/'manifest.json',pins);build=release_json(folder/'development-build.json',pins)
            expected={'schema':'hepta.hia.agent-journal-native.v2','source_sha256':sources[source],
                'image_path':'agent-journal.image.bin','image_sha256':compiled['image_sha256'],'compiler_sha256':compiled['compiler_sha256']}
            if (manifest!=expected or build!={'scope':'DEVELOPMENT_COMPONENT','native_compile_receipt':compiled['receipt'],
                                             'matching_current_source_cold_qualified':False}):
                raise ValueError('artifact explicit development journal transport was mislabeled')
            auxiliary[owner]=manifest
        else:
            auxiliary[owner]=delivery_compile_readback(folder,owner,root,compiler,sources,pins,
                cold_path=cold_path,development=development)
    actual_files={str(p):hashlib.sha256(release_bytes(p,pins)).hexdigest()
        for folder in (directory/'artifact',*(directory/('build-'+n) for n in owners))
        for p in sorted(folder.rglob('*')) if p.is_file()}
    if custody.get('build_files')!=actual_files:
        raise ValueError('artifact component retained build inventory omitted/changed actual files')
    return custody,manifests,built,auxiliary


def require_artifact_delivery_component(directory, root, cold_path, compiler, sources, pins):
    final_delivery_target_binding(root,pins);final_same_cold(cold_path,compiler,sources,pins)
    custody,manifests,built,auxiliary=artifact_delivery_component_custody(directory,root,compiler,sources,pins,cold_path=cold_path)
    terminal=artifact_delivery_terminal_controls(directory,root,built,pins)
    cli=artifact_delivery_cli_controls(directory,root,built,pins)
    loss=artifact_delivery_loss_controls(directory,built,pins)
    boundaries=artifact_delivery_boundary_controls(directory,built,pins)
    installed=artifact_delivery_installation(directory,root,manifests,built,sources,pins)
    return {'passed':True,'manifest':str(Path(directory)/'artifact/build.json'),
        'scope':'MATCHING_SOURCE_COLD_COMPONENT','manifests':manifests,'custody':custody,'auxiliary_manifests':auxiliary,
        'public_sha256':built['public_sha256'],'fixed_private_sha256':built['private_sha256'],
        'terminal':terminal,'cli':cli,'loss':loss,'boundaries':boundaries,'installed':installed,
        'original_full_132_and_Store_130_are_separate_required_gates':True,'whole_native_stack_qualified':False}


def store_transaction_caller_inventory(root, sources, discovery, pins, *, separate=False):
    root=Path(root)
    name=('tests/fixtures/hia_store_transaction_separate_5bf.json' if separate else
          'tests/fixtures/hia_emission_original_73f1634/original-freeze.json')
    digest=('7c6ebe725943cb69f20e8c2fc2c9aa9d59059bceeb47be7e9d21e6f32c285db8' if separate else
            'dec08c099ea1d262f1a3d32dc34801c816484bda6724fac60f5a8a1d5d8c4048')
    raw=release_bytes(root/name,pins);original=json.loads(raw)
    if hashlib.sha256(raw).hexdigest()!=digest:
        raise ValueError('transaction complete original caller fixture changed')
    adjustments=[]
    if separate:
        modules=['tests.test_hia_agent_journal_native','tests.test_hia_execution_budget_native','tests.test_hia_slot_ledger_native']
        planned=original.get('ordered_ids');records=original.get('modules',[])
        if (original.get('base_commit')!='5bf69586b890706290c5fbfe93065ec0d3af40b1'
                or original.get('modules_in_requested_order')!=modules or original.get('test_count')!=61
                or [r.get('module') for r in records]!=modules or [r.get('test_count') for r in records]!=[21,25,15]):
            raise ValueError('transaction complete original 21/25/15 separate module inventory differs')
    else:
        modules=original.get('ordinary_modules',[]);planned=original.get('ordinary_ordered_ids');records=list(original.get('callers',{}).values())
        if (len(modules)!=9 or original.get('ordinary_count')!=112 or len(records)!=17
                or sum(len(r['recorded_ids']) for r in records)!=240 or original.get('separate_scope_count')!=128):
            raise ValueError('transaction original full 112 and separate 128 scopes differ')
    expected_count=61 if separate else 112
    if len(planned)!=expected_count or len(set(planned))!=expected_count:
        raise ValueError('transaction complete original ordered caller IDs differ')
    delivery_description_subset(discovery,planned)
    helper=delivery_literal_values(root/'hepta/hia_native_helpers.py',('HELPERS',),pins)['HELPERS']
    current_count=len(helper)
    for record in records:
        source=release_bytes(root/record['path'],pins);actual=hashlib.sha256(source).hexdigest()
        if sources.get(record['path'])!=actual:
            raise ValueError('transaction caller source is not in the actual cold source closure')
        if actual==record['sha256'] and ('bytes' not in record or len(source)==record['bytes']):
            continue
        old=b'        self.assertEqual(len(HELPERS), 37)\n';new=('        self.assertEqual(len(HELPERS), '+str(current_count)+')\n').encode()
        if (separate or record['path']!='tests/test_hia_worker_native_helpers.py' or current_count<37 or source.count(new)!=1
                or hashlib.sha256(source.replace(new,old,1)).hexdigest()!=record['sha256']):
            raise ValueError('transaction original complete caller source changed outside one registry decimal')
        adjustments.append({'path':record['path'],'original_sha256':record['sha256'],'current_sha256':actual,
            'original_helper_count':37,'current_helper_count':current_count,
            'sole_permitted_change':'one exact registry-count assertion decimal literal','all_other_source_bytes_unchanged':True})
    inputs=final_source_inputs(root,sources,'tools/build_hia_store_transaction.py','INPUTS',pins)
    extras=[name,*(r['path'] for r in records),
            'tools/qualify_hia_store_transaction.py' if separate else 'tools/qualify_hia_store_transaction_callers.py']
    if not separate:extras.append('tools/qualify_hia_emission_callers.py')
    current={n:v for n,v in sources.items() if n!='docs/HIA_SELFHOST_CORE_SUPPORT.json'}
    current.update(inputs);current.update({n:hashlib.sha256(release_bytes(root/n,pins)).hexdigest() for n in extras})
    return original,planned,current,adjustments


def store_transaction_caller_counts(report, planned, *, separate=False):
    frames=report.get('actual_transaction_frames') if separate else report.get('frames_by_original_test')
    events=report.get('actual_native_events') if separate else report.get('actual_native_event_counts')
    total=final_positive_counts(frames)
    if not set(frames)<=set(planned)|{'outside-test'}:
        raise ValueError('transaction actual frame was credited to an unplanned method')
    final_positive_counts(events)
    if not set(events)<=set('012345'):
        raise ValueError('transaction caller observed an undeclared native event')
    if not separate:
        per_test=report.get('native_event_counts_by_original_test',{})
        if (type(per_test) is not dict or not set(per_test)<=set(planned)|{'outside-test'}
                or type(report.get('actual_transaction_frames')) is not int or report['actual_transaction_frames']!=total):
            raise ValueError('transaction actual native per-method accounting differs')
        summed={}
        for value in per_test.values():
            final_positive_counts(value)
            if not set(value)<=set('012345'):raise ValueError('transaction per-method native event differs')
            for key,count in value.items():summed[key]=summed.get(key,0)+count
        if summed!=events:
            raise ValueError('transaction aggregate events do not equal original per-method observations')
    return total,events


def require_store_transaction_callers(directory, root, cold_path, compiler, sources, discovery, pins):
    directory=Path(directory)
    original,planned,expected_sources,adjustments=store_transaction_caller_inventory(root,sources,discovery,pins)
    report=release_json(directory/'report.json',pins)
    manifest=store_transaction_build_readback(directory/'qualified',root,compiler,sources,pins,cold_path=cold_path)
    actual_count=final_complete_ids(report.get('planned'),report.get('started'),report.get('stopped'),planned)
    if (report.get('schema')!='hepta.hia.transaction-nine-ordinary-callers.v1' or report.get('status')!='PASS'
            or report.get('scope')!='MATCHING_SOURCE_COLD_NINE_ORDINARY_TRANSACTION_CALLER_MODULES'
            or report.get('actual_tests')!=112 or actual_count!=112
            or report.get('original_baseline_commit')!=original['base_commit']
            or report.get('original_modules')!=original['ordinary_modules']
            or report.get('source_pins')!=expected_sources or report.get('source_and_bundle_unchanged') is not True
            or report.get('original_registry_count_assertion_adjustments')!=adjustments
            or report.get('native_image_sha256')!=manifest['image_sha256'] or report.get('reference_calls')!=[]
            or any(report.get(k)!=[] for k in ('errors','failures','skipped','expected_failures','unexpected_successes'))
            or report.get('retained_transaction_forbidden') is not True or report.get('all_nine_ordinary_modules_unfiltered') is not True
            or report.get('reference_poison_scope')!='test process; subprocesses inherit selector, not Python patches'
            or report.get('separate_original_administrator_scope_gates')!=original['separate_scope_modules']
            or report.get('separate_full_native_transaction_callers')!=['tests.test_hia_agent_journal_native',
                'tests.test_hia_execution_budget_native','tests.test_hia_slot_ledger_native']
            or any(report.get(k) is not False for k in ('original_test_budgets_changed',
                'original_130_artifact_provider_gate_replaced_by_112','whole_project_dynamic_caller_closure_claimed','whole_native_delivery_qualified'))):
        raise ValueError('transaction nine complete original caller report has a failure/missing test or false scope')
    actual_builds={str(p):hashlib.sha256(release_bytes(p,pins)).hexdigest()
                   for p in sorted((directory/'qualified').rglob('*')) if p.is_file()}
    if report.get('bundle_pins')!=actual_builds:
        raise ValueError('transaction actual retained caller build files differ')
    frames,events=store_transaction_caller_counts(report,planned)
    if frames<=0 or any(events.get(k,0)<=0 for k in ('0','1','2','4')):
        raise ValueError('transaction original callers did not observe the complete required native route')
    log=final_verbose_log(directory/'tests.log',planned,discovery,pins)
    return {'passed':True,'actual_tests':112,'original_modules':original['ordinary_modules'],
        'actual_transaction_frames':frames,'actual_native_event_counts':events,'raw_log':log,
        'source_and_compiler_image_bound':True,'retained_transaction_calls':0,
        'poison_scope':report['reference_poison_scope'],'whole_project_dynamic_caller_closure_claimed':False}


def final_cold_legacy_component(directory, owner, root, compiler, cold_path, sources, pins):
    directory=Path(directory);label=owner.replace('_','-');source='examples/hia_bootstrap/'+owner+'.hepta'
    compiled=final_compile_transport(directory,label,source,root,compiler,sources,pins)
    manifest=release_json(directory/'manifest.json',pins);build=release_json(directory/'build.json',pins)
    expected={'schema':'hepta.hia.'+owner.replace('_','-')+'-native.'+('v2' if owner=='agent_journal' else 'v1'),
        'source_sha256':sources[source],'image_path':label+'.image.bin',
        'image_sha256':compiled['image_sha256'],'compiler_sha256':compiled['compiler_sha256']}
    if (manifest!=expected or build.get('manifest')!=manifest or build.get('native_compile_receipt')!=compiled['receipt']
            or build.get('status')!='NATIVE_CANDIDATE_BUILT'
            or build.get('profile')!=delivery_literal_values(Path(root)/'tools/hia_selfhost_contract.py',('PROFILE',),pins)['PROFILE']
            or build.get('source_manifest')!=sources
            or build.get('cold_report_sha256')!=hashlib.sha256(release_bytes(cold_path,pins)).hexdigest()):
        raise ValueError('transaction separate original retained cold component differs: '+owner)
    return manifest


def require_store_transaction_separate_callers(directory, root, cold_path, compiler, sources, discovery, pins):
    directory,root=Path(directory),Path(root)
    original,planned,expected_sources,adjustments=store_transaction_caller_inventory(root,sources,discovery,pins,separate=True)
    report=release_json(directory/'report.json',pins)
    manifest=store_transaction_build_readback(directory/'transaction',root,compiler,sources,pins,cold_path=cold_path)
    if (report.get('schema')!='hepta.hia.transaction-three-complete-callers.v1' or report.get('status')!='PASS'
            or report.get('scope')!='MATCHING_SOURCE_COLD_THREE_COMPLETE_TRANSACTION_CALLER_MODULES'
            or report.get('original_inventory_sha256')!='7c6ebe725943cb69f20e8c2fc2c9aa9d59059bceeb47be7e9d21e6f32c285db8'
            or report.get('original_ordered_ids')!=planned or report.get('original_count')!=61
            or report.get('source_before')!=expected_sources or report.get('source_after')!=expected_sources
            or report.get('source_compiler_and_builds_unchanged') is not True or report.get('deadline_seconds')!=1800
            or report.get('compiler_sha256')!=hashlib.sha256(release_bytes(compiler,pins)).hexdigest()
            or report.get('positive_transaction_observations_required_for_aggregate_PASS') is not True
            or report.get('ordinary_112_and_artifact_130_are_separate_gates') is not True
            or any(report.get(k) is not False for k in ('original_inner_limits_changed','original_administrator_bundles_enlarged',
                                                       'whole_project_dynamic_caller_closure_claimed'))):
        raise ValueError('transaction complete original separate caller report/cold/source scope differs')
    build_files={str(p):hashlib.sha256(release_bytes(p,pins)).hexdigest() for p in sorted((directory/'transaction').rglob('*')) if p.is_file()}
    if report.get('build_pins')!=build_files:
        raise ValueError('transaction separate caller actual retained build identity differs')
    stages=report.get('stages',[]);modules=original['modules_in_requested_order']
    if len(stages)!=3 or [row.get('selector') for row in stages]!=modules:
        raise ValueError('transaction complete original 61-method subprocess stages were reduced')
    total_frames=0;total_events={};observations=[]
    for index,(module,stage) in enumerate(zip(modules,stages),1):
        stem=str(index)+'-'+module.rsplit('.',1)[-1];at=directory/(stem+'.json')
        raw=release_bytes(at,pins);value=json.loads(raw)
        expected=[name for name in planned if name.startswith(module+'.')]
        final_complete_ids(value.get('planned'),value.get('started'),value.get('stopped'),expected)
        command=stage.get('command',[])
        suffix=['-B',str(root/'tools/qualify_hia_store_transaction.py'),'--cold-report',str(cold_path),
            '--evidence',str(directory),'--execute-module',module,'--manifest',str(directory/'transaction/manifest.json'),
            '--stage-report',str(at)]
        if (stage.get('status')!='PASS' or type(stage.get('returncode')) is not int or stage['returncode']!=0 or len(command)!=len(suffix)+1 or command[1:]!=suffix
                or any(stage.get(k) is not False for k in ('timed_out','process_group_killed','cleanup_pipes_unconfirmed'))
                or stage.get('stage_report')!=str(at) or stage.get('stage_report_sha256')!=hashlib.sha256(raw).hexdigest()
                or value.get('schema')!='hepta.hia.transaction-separate-module.v1' or value.get('status')!='PASS'
                or value.get('selector')!=module or value.get('testsRun')!=len(expected)
                or value.get('outcomes')!=[[name,'ok'] for name in expected]
                or value.get('unstarted')!=[] or value.get('unterminated')!=[]
                or value.get('anomalies')!={k:[] for k in ('errors','failures','skipped','expectedFailures','unexpectedSuccesses')}
                or value.get('source_before')!=expected_sources or value.get('source_after')!=expected_sources
                or value.get('source_unchanged') is not True or value.get('reference_calls')!=[]
                or value.get('native_image_sha256')!=manifest['image_sha256']
                or value.get('original_methods_or_fixtures_or_deadlines_changed') is not False
                or value.get('parent_process_poison_is_not_inherited_by_subprocesses') is not True
                or value.get('every_original_test_claimed_to_enter_transaction') is not False):
            raise ValueError('transaction original separate subprocess was incomplete/nonpassing: '+module)
        release_bytes(directory/(stem+'.stdout'),pins)
        log=final_verbose_log(directory/(stem+'.stderr'),expected,discovery,pins)
        frames,events=store_transaction_caller_counts(value,expected,separate=True);total_frames+=frames
        for key,count in events.items():total_events[key]=total_events.get(key,0)+count
        observations.append({'module':module,'actual_tests':len(expected),'frames':frames,'events':events,'raw_log':log})
    if (report.get('actual_transaction_frames')!=total_frames or total_frames<=0
            or report.get('actual_native_events')!=total_events or any(total_events.get(k,0)<=0 for k in ('0','1','2','4'))):
        raise ValueError('transaction original 61-method aggregate lacks actual native delivery observations')
    return {'passed':True,'actual_tests':61,'stages':observations,'actual_transaction_frames':total_frames,
        'actual_native_event_counts':total_events,'deadline_seconds':1800,
        'retained_original_components':store_transaction_separate_components(directory,root,cold_path,compiler,sources,pins),
        'journal_21_original_temporary_build_receipt_retained':False,
        'journal_21_matching_cold_authority':'unchanged original setUpClass and complete source-bound subprocess gate',
        'original_administrator_bundles_enlarged':False}


def store_transaction_separate_components(directory, root, cold_path, compiler, sources, pins):
    directory=Path(directory)
    budget=directory/'2-test_hia_execution_budget_native-component/ExecutionBudgetNativeTests'
    slot=directory/'3-test_hia_slot_ledger_native-component/SlotLedgerNativeTests'
    paths={'execution_budget':budget/'qualified-execution-budget',
           'agent_journal':budget/'qualified-agent-journal','slot_ledger':slot/'qualified'}
    manifests={name:final_cold_legacy_component(path,name,root,compiler,cold_path,sources,pins) for name,path in paths.items()}
    qualified=release_json(budget/'qualified-build.json',pins)
    if qualified!={'mode':'MATCHING_CURRENT_SOURCE_COLD_BUILD','manifest_path':str(paths['execution_budget']/'manifest.json'),
                   'cold_report_sha256':hashlib.sha256(release_bytes(cold_path,pins)).hexdigest(),
                   'compiler_sha256':hashlib.sha256(release_bytes(compiler,pins)).hexdigest(),
                   'matching_current_source_cold_qualified':True}:
        raise ValueError('transaction separate original execution-budget fixture source binding differs')
    fixture=release_json(slot/'fixture.json',pins)
    if fixture!={'mode':'MATCHING_CURRENT_SOURCE_COLD_BUILD','manifest':manifests['slot_ledger'],
                 'native_compile_receipt':release_json(paths['slot_ledger']/'build.json',pins)['native_compile_receipt'],
                 'cold_report':str(cold_path),'matching_current_source_cold_qualified':True}:
        raise ValueError('transaction separate original slot fixture source binding differs')
    return manifests


def artifact_delivery_caller_inventory(root, sources, discovery, pins):
    root=Path(root);name='tests/fixtures/hia_artifact_delivery_callers_5bf69586.json'
    raw=release_bytes(root/name,pins);original=json.loads(raw)
    if (hashlib.sha256(raw).hexdigest()!='90c692ff69571913150d577761520f9b63d1a50fabd3d9c3a0ccf7baeb8f2754'
            or [original.get(k) for k in ('direct_count','additional_count','total_count')]!=[63,69,132]
            or len(original.get('modules',[]))!=7 or len(original.get('ordered_ids',[]))!=132):
        raise ValueError('artifact complete original seven-module caller inventory changed')
    direct_raw=release_bytes(root/original['direct_original_fixture'],pins)
    if (hashlib.sha256(direct_raw).hexdigest()!=original['direct_original_fixture_sha256']
            or json.loads(direct_raw).get('declared_original_test_ids')!=original['direct_ordered_ids']):
        raise ValueError('artifact independent original 63 caller fixture differs')
    for record in original['modules']:
        body=release_bytes(root/record['path'],pins)
        if (len(body)!=record['bytes'] or hashlib.sha256(body).hexdigest()!=record['sha256']
                or sources.get(record['path'])!=record['sha256']):
            raise ValueError('artifact original complete caller source changed: '+record['path'])
    groups=[{'name':'original-direct-63','modules':original['direct_modules'],
             'ordered_ids':original['direct_ordered_ids'],'count':63,'selector':None},*original['additional_groups']]
    planned=original['ordered_ids']
    if ([group['name'] for group in groups]!=['original-direct-63','additional-generic-37','additional-store-32']
            or [group['count'] for group in groups]!=[63,37,32]
            or [group['selector'] for group in groups]!=[None,'HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST','HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST']
            or sum((group['ordered_ids'] for group in groups),[])!=planned or len(set(planned))!=132):
        raise ValueError('artifact original full-module fixed routing or order differs')
    delivery_description_subset(discovery,planned)
    expected={n:v for n,v in sources.items() if n!='docs/HIA_SELFHOST_CORE_SUPPORT.json'}
    extras=[name,original['direct_original_fixture'],'tools/qualify_hia_artifact_delivery_callers.py',*(r['path'] for r in original['modules'])]
    expected.update({n:hashlib.sha256(release_bytes(root/n,pins)).hexdigest() for n in extras})
    return original,groups,planned,expected


def artifact_delivery_caller_counts(report, groups, planned):
    operations=('publish','verify','withdraw','store-put','store-get','store-hash')
    allowed={kind+':'+operation for kind in ('handoff','acknowledged','public-receipt') for operation in operations}
    counts=report.get('provider_observations');per_test=report.get('provider_observations_by_test')
    required=tuple(kind+':'+operation for kind in ('acknowledged','public-receipt') for operation in operations)
    final_positive_counts(counts,required=required)
    if (not set(counts)<=allowed or type(per_test) is not dict or not set(per_test)<=set(planned)|{'outside-test'}):
        raise ValueError('artifact actual provider counter inventory contains an unplanned observation')
    summed={}
    for row in per_test.values():
        final_positive_counts(row)
        if not set(row)<=allowed:raise ValueError('artifact per-test provider operation differs')
        for key,count in row.items():summed[key]=summed.get(key,0)+count
    if summed!=counts:
        raise ValueError('artifact aggregate provider counts differ from original per-test entries')
    rows=report.get('acknowledgements')
    if type(rows) is not list or not rows:
        raise ValueError('artifact actual complete raw ACK observations absent')
    ack_counts={};ack_by_test={};group_ids={g['name']:set(g['ordered_ids']) for g in groups}
    for row in rows:
        operation=row.get('operation');test=row.get('test');group=row.get('group')
        if (operation not in operations or group not in group_ids or test not in group_ids[group]|{'outside-test'}
                or type(row.get('stdout_bytes')) is not int or row['stdout_bytes']<0
                or row.get('stderr_bytes')!=128 or re.fullmatch('[0-9a-f]{64}',row.get('stdout_sha256','')) is None):
            raise ValueError('artifact raw ACK method/group/stream identity differs')
        raw=bytes.fromhex(row['stderr_hex']);nonce=bytes.fromhex(row['nonce_hex'])
        ack=artifact_delivery_ack(raw,nonce,row['returncode'],row['stdout_bytes'])
        if (row.get('outcome')!=ack['outcome'] or row.get('acknowledged_operation')!=ack['operation']
                or row.get('input_bytes')!=ack['input_bytes'] or ack['operation']!=operations.index(operation)+1):
            raise ValueError('artifact caller full ACK differs from independently decoded frame')
        key='acknowledged:'+operation;ack_counts[key]=ack_counts.get(key,0)+1
        observed=ack_by_test.setdefault(test,{});observed[key]=observed.get(key,0)+1
    if ack_counts!={k:v for k,v in counts.items() if k.startswith('acknowledged:')}:
        raise ValueError('artifact actual full raw receipt count differs from acknowledgement counters')
    for test,row in per_test.items():
        if {k:v for k,v in row.items() if k.startswith('acknowledged:')}!=ack_by_test.get(test,{}):
            raise ValueError('artifact actual per-test raw receipt accounting differs')
    for operation in operations:
        if not counts.get('handoff:'+operation,0)>=counts['acknowledged:'+operation]>=counts['public-receipt:'+operation]>0:
            raise ValueError('artifact public confirmations exceed actual handoff/ACK observations')
    return {'provider_observations':counts,'complete_raw_ACKs':len(rows),
        'stdout_scope':'original observer recorded length and digest; full inner stdout is not separately retained',
        'python_observer_scope':'parent process only; no claimed subprocess Python instrumentation'}


def require_artifact_delivery_callers(directory, root, cold_path, compiler, sources, discovery, pins):
    directory=Path(directory)
    original,groups,planned,expected_sources=artifact_delivery_caller_inventory(root,sources,discovery,pins)
    report=release_json(directory/'report.json',pins)
    final_complete_ids(report.get('planned'),report.get('started'),report.get('stopped'),planned)
    built=artifact_delivery_build_readback(directory/'additional-selected-build',root,compiler,sources,pins,cold_path=cold_path)
    manifest=directory/'additional-selected-build/build.json';executable=manifest.parent/'hia-artifact'
    cold=release_json(cold_path,pins);nested=Path(cold['nested_report'])
    expected_cold={'path':str(cold_path),'sha256':hashlib.sha256(release_bytes(cold_path,pins)).hexdigest(),
        'nested_path':str(nested),'nested_sha256':hashlib.sha256(release_bytes(nested,pins)).hexdigest()}
    expected_compiler={'path':str(compiler),'sha256':hashlib.sha256(release_bytes(compiler,pins)).hexdigest()}
    poison='Only direct _read_exact calls in original public code with captured nonempty selection. No global reference16 ban. Withdrawal retains the original sealed-descriptor/operation assertions.'
    observation='Parent-process provider handoff and validated ACK/public receipt calls. No claim that Python wrappers instrument subprocess interiors.'
    if (report.get('schema')!='hepta.hia.artifact-delivery-original-callers.v1' or report.get('status')!='PASS'
            or report.get('scope')!='MATCHING_SOURCE_COLD_ORIGINAL_ARTIFACT_63_PLUS_ADDITIONAL_69'
            or report.get('actual_tests')!=132 or report.get('modules')!=[r['module'] for r in original['modules']]
            or report.get('original_baseline_commit')!=original['base_commit']
            or report.get('original_fixture_baseline_commit')!=original['direct_original_fixture_base']
            or report.get('source_before')!=expected_sources or report.get('source_after')!=expected_sources
            or report.get('source_and_application_unchanged') is not True or report.get('all_seven_modules_unfiltered') is not True
            or report.get('additional_manifest')!=str(manifest) or report.get('additional_fixed_private_sha256')!=built['private_sha256']
            or report.get('additional_application_pins')!={str(p):hashlib.sha256(release_bytes(p,pins)).hexdigest() for p in (manifest,executable)}
            or report.get('cold_report')!=expected_cold or report.get('compiler')!=expected_compiler
            or report.get('reference_calls')!=[] or report.get('poison_scope')!=poison or report.get('observation_scope')!=observation
            or report.get('whole_module_selectors')!={'original-direct-63':'original fixtures only',
                'additional-generic-37':'HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST','additional-store-32':'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST'}
            or any(report.get(k) is not False for k in ('original_fixture_build_inputs_modified','original_fixture_temporary_builds_claimed_retained',
                'original_test_limits_deadlines_assertions_changed','new_aggregate_wall_limit_added',
                'whole_project_dynamic_caller_closure_claimed','installed_worker_qualified_by_this_gate','whole_native_delivery_qualified'))):
        raise ValueError('artifact complete original 132 caller source/cold/application scope differs')
    records=report.get('groups',[])
    if len(records)!=3:raise ValueError('artifact complete original caller group was omitted')
    logs=[]
    for expected,row in zip(groups,records):
        if (row.get('name')!=expected['name'] or row.get('modules')!=expected['modules']
                or row.get('planned')!=expected['ordered_ids'] or row.get('selector')!=expected['selector']
                or row.get('actual_tests')!=expected['count'] or row.get('was_successful') is not True
                or any(row.get(k)!=[] for k in ('errors','failures','skipped','expected_failures','unexpected_successes'))):
            raise ValueError('artifact complete original group has missing/error/skipped tests: '+expected['name'])
        logs.append(final_verbose_log(directory/(expected['name']+'-tests.log'),expected['ordered_ids'],discovery,pins))
    counts=artifact_delivery_caller_counts(report,groups,planned)
    return {'passed':True,'actual_tests':132,'group_sizes':[63,37,32],'raw_logs':logs,
        'actual_fixed_private_sha256':built['private_sha256'],'observations':counts,
        'all_original_methods_deadlines_and_reference16_scope_preserved':True,
        'temporary_original_fixture_build_receipts_claimed_retained':False,
        'installed_worker_qualified_by_this_gate':False,'whole_project_dynamic_caller_closure_claimed':False}


def require_final_delivery_caller(name, directory, root, cold_path, compiler, sources, discovery, pins):
    final_delivery_target_binding(root,pins)
    final_same_cold(cold_path,compiler,sources,pins)
    readers={'store-transaction-callers':require_store_transaction_callers,
        'store-transaction-separate-callers':require_store_transaction_separate_callers,
        'artifact-delivery-callers':require_artifact_delivery_callers}
    if name not in readers:raise ValueError('unknown final delivery complete caller gate')
    return readers[name](directory,root,cold_path,compiler,sources,discovery,pins)


def final_installed_worker_identity(files, root, pins):
    names=('DISCOVERY_FILES','NATIVE_SOURCE_FILES','SOURCE_BUILD_FILES','COMPILER_BUILD_FILES','PUBLICATION_BUILD_FILES',
        'BACKEND_BUILD_FILES','EMITTER_BUILD_FILES','BYTE_WRAPPER_BUILD_FILES','MACHINE_OBJECT_BUILD_FILES',
        'EXECUTION_OBSERVATION_BUILD_FILES','CONTINUATION_BUILD_FILES','VERSION')
    constants=delivery_literal_values(Path(root)/'hepta/hia_agent_contract.py',names,pins)
    entries={name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()
             if name.startswith('hepta/') and name.endswith('.py') and not name.startswith('hepta/_data/')}
    resources=['docs/'+name for name in constants['DISCOVERY_FILES']]
    for group in names[1:-1]:resources.extend(constants[group])
    for name in resources:
        entries[name]=hashlib.sha256(files['hepta/_data/'+name]).hexdigest()
    return {'worker_sha256':hashlib.sha256(evaluation_json_bytes(entries)).hexdigest(),
            'catalog_sha256':entries['docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json'],'contract_version':constants['VERSION']}




def artifact_delivery_tree_record(value, *, sqlite_state=False):
    if type(value) is not dict or not value or value.get('.',{}).get('kind')!='directory':
        raise ValueError('artifact closed baseline lacks its complete root tree record')
    for name,row in value.items():
        if (type(name) is not str or type(row) is not dict
                or (name!='.' and (not name or name.startswith('/') or any(p in ('','.', '..') for p in name.split('/'))))
                or type(row.get('mode')) is not int or not 0<=row['mode']<=0o7777
                or type(row.get('mtime_ns')) is not int):
            raise ValueError('artifact closed baseline path/mode/nanosecond observation differs')
        kind=row.get('kind');keys={'kind','mode','mtime_ns'}
        if kind=='file':
            keys|={'bytes','sha256'}
            if (type(row.get('bytes')) is not int or row['bytes']<0
                    or re.fullmatch('[0-9a-f]{64}',row.get('sha256','')) is None):
                raise ValueError('artifact closed baseline full file byte/hash record differs')
        elif kind!='directory':
            raise ValueError('artifact baseline contains an unobserved special file or symlink')
        if set(row)!=keys:
            raise ValueError('artifact closed baseline tree entry schema differs')
        if name!='.':
            parent=name.rpartition('/')[0] or '.'
            if value.get(parent,{}).get('kind')!='directory':
                raise ValueError('artifact closed baseline omits a parent directory')
    if sqlite_state and (value.get('state.sqlite3',{}).get('kind')!='file'
            or value.get('artifacts',{}).get('kind')!='directory'
            or any('state.sqlite3'+suffix in value for suffix in ('-wal','-shm','-journal'))):
        raise ValueError('artifact closed SQLite/CAS baseline or unresolved journal namespace differs')
    raw=json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()
    return hashlib.sha256(raw).hexdigest()


def artifact_delivery_closed_baseline(folder, value, capsule_sha, commands, pins):
    folder=Path(folder);record=release_json(folder/'closed-baseline.json',pins)
    if (evaluation_json_bytes(record)!=evaluation_json_bytes(value)
            or record.get('schema')!='hepta.hia.artifact-delivery-closed-baseline.v1'
            or type(record.get('real_selected_preparation_count')) is not int
            or record['real_selected_preparation_count']!=1
            or record.get('actual_SQLite_connection_closed') is not True
            or record.get('v4_capsule_sha256')!=capsule_sha
            or record.get('state_tree_unchanged') is not True
            or record.get('shared_files_root_unchanged') is not True):
        raise ValueError('artifact actual same-capsule closed-baseline observation differs')
    for key in ('state_root','files_root'):
        if type(record.get(key)) is not str or not Path(record[key]).is_absolute() or '..' in Path(record[key]).parts:
            raise ValueError('artifact baseline records a non-absolute state/files root')
    tree_sha=artifact_delivery_tree_record(record.get('state_tree'),sqlite_state=True)
    files_sha=artifact_delivery_tree_record(record.get('files_tree'))
    if (record.get('state_tree_sha256')!=tree_sha
            or evaluation_json_bytes(record.get('state_tree_after'))!=evaluation_json_bytes(record['state_tree'])
            or evaluation_json_bytes(record.get('files_tree_after'))!=evaluation_json_bytes(record['files_tree'])):
        raise ValueError('artifact closed baseline changed bytes/modes/nanosecond times after all workers')
    labels=['normal','ack','peer-swallow','peer-replace','exit','installed-source-drift']
    copies=record.get('copies')
    if type(copies) is not list or [row.get('label') for row in copies]!=labels:
        raise ValueError('artifact complete six pre-worker state copies were reduced')
    identities=[record.get('database_identity')];roots=[record['state_root']]
    by_label={row['label']:row for row in commands}
    for row in copies:
        state=row.get('state_root');label=row['label']
        if (type(state) is not str or not Path(state).is_absolute() or '..' in Path(state).parts
                or state in roots or row.get('files_root')!=record['files_root']
                or row.get('byte_identical_before_worker') is not True
                or row.get('independent_database_inode') is not True
                or row.get('state_tree_sha256')!=tree_sha
                or evaluation_json_bytes(row.get('state_tree'))!=evaluation_json_bytes(record['state_tree'])):
            raise ValueError('artifact copied complete SQLite/CAS state differs before worker entry')
        roots.append(state);identities.append(row.get('database_identity'))
        for command_label in ([label] if label=='installed-source-drift' else [label,label+'-replay']):
            argv=by_label[command_label].get('argv',[])
            if len(argv)!=16 or argv[8]!=state or argv[10]!=record['files_root']:
                raise ValueError('artifact worker/replay did not use its independent copy and shared files root')
    if (any(type(row) is not list or len(row)!=2 or any(type(v) is not int or v<0 for v in row) for row in identities)
            or len({tuple(row) for row in identities})!=7):
        raise ValueError('artifact live baseline plus six copies lack seven distinct observed DB identities')
    return {'record_sha256':hashlib.sha256(release_bytes(folder/'closed-baseline.json',pins)).hexdigest(),
        'actual_closed_preparation_count':1,'state_tree_sha256':tree_sha,'files_tree_sha256':files_sha,
        'complete_pre_worker_copies':6,'simultaneously_observed_distinct_DB_identities':7,
        'state_and_shared_files_tree_after_unchanged':True,
        'observation_scope':'retained exact tree, byte-identity, mode, nanosecond, closed-connection and inode observations from the complete original method',
        'removed_temporary_SQLite_and_CAS_bytes_independently_read_back':False}


def artifact_delivery_pair_schedule(folder, value, workers, commands, pins):
    folder=Path(folder);record=release_json(folder/'pair-schedule.json',pins)
    modes=['normal','ack','peer-swallow','peer-replace','exit']
    expected_codes={'normal':0,'ack':1,'peer-swallow':1,'peer-replace':1,'exit':73}
    if (evaluation_json_bytes(record)!=evaluation_json_bytes(value)
            or record.get('schema')!='hepta.hia.artifact-delivery-pair-schedule.v1'
            or type(record.get('maximum_workers')) is not int or record['maximum_workers']!=2
            or record.get('mode_order')!=modes or record.get('submission_order')!=modes
            or record.get('collection_order')!=modes
            or type(record.get('completion_order')) is not list
            or len(record['completion_order'])!=5 or set(record['completion_order'])!=set(modes)
            or record.get('all_pairs_joined') is not True or record.get('failed_modes')!=[]
            or type(record.get('active_pairs')) is not int or record['active_pairs']!=0
            or type(record.get('maximum_observed_active_pairs')) is not int
            or not 1<=record['maximum_observed_active_pairs']<=2
            or type(record.get('pairs')) is not dict or set(record['pairs'])!=set(modes)):
        raise ValueError('artifact five complete supervised pairs/max-two scheduling differs')
    def stamp(v): return type(v) is int and v>0
    submitted=record.get('all_pairs_submitted_monotonic_ns')
    joined=record.get('all_pairs_joined_monotonic_ns')
    mutations=record.get('mutations_started_monotonic_ns')
    if any(not stamp(v) for v in (submitted,joined,mutations)) or not submitted<=joined<=mutations:
        raise ValueError('artifact mutation began before all submitted pairs had joined')
    starts=release_json(folder/'command-starts.json',pins)
    labels=['wheel','install']+[label for mode in modes for label in (mode,mode+'-replay')]+['installed-source-drift','scope-probe']
    if (type(commands) is not list or len(commands)!=14 or {r.get('label') for r in commands}!=set(labels)
            or type(starts) is not list or len(starts)!=14 or {r.get('label') for r in starts}!=set(labels)):
        raise ValueError('artifact original fourteen command starts/completions differ')
    by={r['label']:r for r in commands};start_by={r['label']:r for r in starts}
    for label,row in by.items():
        start=start_by[label]
        if (set(start)!={'label','argv','started_monotonic_ns','thread_id'}
                or start.get('argv')!=row.get('argv')
                or start.get('started_monotonic_ns')!=row.get('started_monotonic_ns')
                or not stamp(start.get('thread_id'))
                or any(not stamp(row.get(k)) for k in ('started_monotonic_ns','finished_monotonic_ns'))
                or row['finished_monotonic_ns']<row['started_monotonic_ns']
                or row.get('timed_out',False) is not False
                or row.get('timeout_seconds',60)!=60):
            raise ValueError('artifact retained command start/finish, timeout or thread identity differs')
    if (by['wheel']['finished_monotonic_ns']>by['install']['started_monotonic_ns']
            or by['install']['finished_monotonic_ns']>min(by[m]['started_monotonic_ns'] for m in modes)
            or mutations>by['installed-source-drift']['started_monotonic_ns']
            or by['installed-source-drift']['finished_monotonic_ns']>by['scope-probe']['started_monotonic_ns']):
        raise ValueError('artifact wheel/install, all-pair completion, drift and scope order differs')
    intervals=[];threads=set()
    for mode in modes:
        pair=record['pairs'][mode];first=by[mode];replay=by[mode+'-replay']
        if (pair.get('status')!='passed' or pair.get('expected_first_exit_code')!=expected_codes[mode]
                or pair.get('observation_path')!=mode+'-observations.json'
                or any(not stamp(pair.get(k)) for k in ('submitted_monotonic_ns','started_monotonic_ns','finished_monotonic_ns','thread_id'))
                or pair['submitted_monotonic_ns']>submitted
                or not pair['submitted_monotonic_ns']<=pair['started_monotonic_ns']<=first['started_monotonic_ns']
                    <=first['finished_monotonic_ns']<=replay['started_monotonic_ns']
                    <=replay['finished_monotonic_ns']<=pair['finished_monotonic_ns']<=joined
                or any(start_by[label]['thread_id']!=pair['thread_id'] for label in (mode,mode+'-replay'))):
            raise ValueError('artifact pair did not retain original worker/state/replay order through join')
        raw=release_bytes(folder/(mode+'-observations.json'),pins)
        if (pair.get('observation_sha256')!=hashlib.sha256(raw).hexdigest()
                or evaluation_json_bytes(json.loads(raw))!=evaluation_json_bytes(workers.get(mode))):
            raise ValueError('artifact actual per-pair original observations differ from ordered aggregate')
        threads.add(pair['thread_id']);intervals.append((pair['started_monotonic_ns'],pair['finished_monotonic_ns']))
    if len(threads)>2:
        raise ValueError('artifact supervisor used more than its two original worker threads')
    finished=[record['pairs'][mode]['finished_monotonic_ns'] for mode in record['completion_order']]
    if finished!=sorted(finished):
        raise ValueError('artifact retained pair completion order contradicts its actual times')
    # Clock ties need not identify a cross-pair execution order. Strict overlap
    # still rejects an observed third simultaneously active pair.
    for start,end in intervals:
        active=sum(a<=start<b for a,b in intervals)
        if active>2 or active>record['maximum_observed_active_pairs']:
            raise ValueError('artifact observed pair intervals exceed declared max-two concurrency')
    return {'record_sha256':hashlib.sha256(release_bytes(folder/'pair-schedule.json',pins)).hexdigest(),
        'commands':14,'fresh_first_workers':5,'fresh_replay_workers':5,'maximum_workers':2,
        'maximum_observed_active_pairs':record['maximum_observed_active_pairs'],
        'all_five_pairs_submitted_collected_and_joined':True,
        'per_pair_worker_then_replay_order_checked':True,'cross_pair_fixed_command_order_required':False,
        'all_mutations_follow_complete_pair_join':True,'original_child_timeout_seconds':60}
# END FINAL DELIVERY INDEPENDENT READBACK

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
    native_build_dispatch = None
    emission = None
    store_artifact_profile = None
    native_delivery = store_native_delivery = None
    store_transaction = artifact_delivery = None
    final_binding = None
    sha_image_bound = False
    try:
        if read_pinned_json(args.target, pins) != target:
            raise ValueError("target.json changed before supplemental admission")
        before = source_admission(root, target)
        final_binding = final_delivery_target_binding(root, pins)
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
        native_build_dispatch = require_native_build_dispatch_component(retained / "native-build-dispatch", root,
                                                                        cold_path, compiler, sources, pins)
        added_components["native-build-dispatch"] = native_build_dispatch["manifest"]
        emission = require_emission_component(retained / "emission", root, cold_path, compiler, sources, pins)
        added_components["emission"] = emission["manifest"]
        store_artifact_profile = require_store_profile_component(retained / "store-artifact-profile", root,
                                                                 cold_path, compiler, sources, pins)
        added_components["store-artifact-profile"] = store_artifact_profile["manifest"]
        native_delivery = require_native_delivery_component(retained / "native-delivery", root, cold_path,
                                                            compiler, sources, pins)
        store_native_delivery = require_native_delivery_component(retained / "store-native-delivery", root, cold_path,
                                                                  compiler, sources, pins, store=True)
        store_transaction = require_store_transaction_component(retained / "store-transaction", root,
            cold_path, compiler, sources, pins)
        artifact_delivery = require_artifact_delivery_component(retained / "artifact-delivery", root,
            cold_path, compiler, sources, pins)
        added_components["store-transaction"] = store_transaction["manifest"]
        added_components["artifact-delivery"] = artifact_delivery["manifests"]
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
        emission_jobs = (
            ("emission-callers", ["tools/qualify_hia_emission_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "emission-callers")], {}),
        )
        store_artifact_profile_jobs = (
            ("store-artifact-profile-callers", ["tools/qualify_hia_store_artifact_profile_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "store-artifact-profile-callers")], {}),
        )
        native_delivery_jobs = (
            ("native-delivery-components", ["tools/qualify_hia_native_delivery.py", "--group", "components",
                "--cold-report", str(cold_path), "--evidence", str(output / "native-delivery-components")], {}),
            ("native-delivery-caller-groups", ["tools/qualify_hia_native_delivery.py", "--group", "callers",
                "--cold-report", str(cold_path), "--evidence", str(output / "native-delivery-caller-groups")], {}),
        )
        final_delivery_jobs = (
            ("store-transaction-callers", ["tools/qualify_hia_store_transaction_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "store-transaction-callers")], {}),
            ("store-transaction-separate-callers", ["tools/qualify_hia_store_transaction.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "store-transaction-separate-callers")], {}),
            ("artifact-delivery-callers", ["tools/qualify_hia_artifact_delivery_callers.py",
                "--cold-report", str(cold_path), "--evidence", str(output / "artifact-delivery-callers")], {}),
        )
        for name, arguments, selection in (*jobs, *service_context_jobs, *cost_ledger_jobs, *evaluation_jobs,
                                           *native_build_admission_jobs, *emission_jobs, *store_artifact_profile_jobs,
                                           *native_delivery_jobs, *final_delivery_jobs):
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
                if name in FINAL_DELIVERY_CALLER_JOBS:
                    observed = require_final_delivery_caller(name, output / name, root, cold_path,
                        compiler, sources, discovery, pins)
                    record["observed_complete_caller_readback"] = observed
                    record["actual_tests"] = observed["actual_tests"]
                    record["passed"] = bool(record["passed"] and observed["passed"])
                elif name.endswith("-callers") and name != "cli-discovery-callers":
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
                        "emission-callers": "MATCHING_SOURCE_COLD_NINE_ORDINARY_EMISSION_CALLER_MODULES",
                        "store-artifact-profile-callers": "MATCHING_SOURCE_COLD_TEN_ORIGINAL_STORE_ARTIFACT_PROFILE_CALLER_MODULES",
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
                    elif name == "emission-callers":
                        from tools.build_hia_emission import INPUTS, SOURCE_NAME
                        manifest_path = output / name / "qualified/manifest.json"
                        require_cold_component(manifest_path, SOURCE_NAME, cold_sha, compiler_sha, sources, pins)
                        require_release_compilation(manifest_path.parent, "emission", SOURCE_NAME,
                                                    INPUTS, root, compiler, sources, pins)
                        record["emission_original_observations"] = require_emission_callers(
                            output / name, root, sources, discovery, manifest_path, pins)
                    elif name == "store-artifact-profile-callers":
                        from tools.build_hia_store_artifact_profile import INPUTS, SOURCE_NAME
                        manifest_path = output / name / "qualified/manifest.json"
                        require_cold_component(manifest_path, SOURCE_NAME, cold_sha, compiler_sha, sources, pins)
                        require_release_compilation(manifest_path.parent, "store_artifact_profile", SOURCE_NAME,
                                                    INPUTS, root, compiler, sources, pins)
                        record["store_artifact_profile_original_observations"] = require_store_profile_callers(
                            output / name, root, sources, discovery, manifest_path, cold_path, pins)
                elif name in ("native-delivery-components", "native-delivery-caller-groups"):
                    group = "components" if name == "native-delivery-components" else "callers"
                    record["native_delivery_original_gate_readback"] = require_native_delivery_group(
                        output / name, group, root, cold_path, compiler, sources, discovery, pins,
                        native_delivery["manifests"])
                    record["passed"] = bool(record["passed"] and record["native_delivery_original_gate_readback"]["passed"])
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
                  and native_build_dispatch is not None and native_build_dispatch["passed"]
                  and emission is not None and emission["passed"]
                  and store_artifact_profile is not None and store_artifact_profile["passed"]
                  and native_delivery is not None and native_delivery["passed"]
                  and store_native_delivery is not None and store_native_delivery["passed"]
                  and store_transaction is not None and store_transaction["passed"]
                  and artifact_delivery is not None and artifact_delivery["passed"]
                  and final_binding is not None
                  and len(commands) == 21 and all(row["passed"] for row in commands))
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
        "native_build_dispatch_full_discovery_artifact_readback": native_build_dispatch,
        "emission_full_discovery_artifact_readback": emission,
        "store_artifact_profile_full_discovery_artifact_readback": store_artifact_profile,
        "native_delivery_full_discovery_artifact_readback": native_delivery,
        "store_native_delivery_full_discovery_artifact_readback": store_native_delivery,
        "store_transaction_full_discovery_artifact_readback": store_transaction,
        "artifact_delivery_full_discovery_artifact_readback": artifact_delivery,
        "final_delivery_target_and_composition_binding": final_binding,
        "original_18_supplemental_jobs_modified": False,
        "store_transaction_complete_112_job_19_added": True,
        "store_transaction_complete_61_job_20_added": True,
        "artifact_delivery_complete_132_job_21_added": True,
        "production_sha_image_matches_actual_executed_differential_image": sha_image_bound,
        "commands": commands, "captured_inputs": pins, "original_35_stages_modified": False,
        "original_component_test_suites_rerun": True,
        "original_component_rerun_scope": "complete eleven original modules / 152 methods in added delivery job 17",
        "new_focused_delivery_suites_rerun_by_supplement": False,
        "original_10_supplemental_jobs_modified": False,
        "service_context_job_11_modified": False,
        "cost_ledger_job_12_modified": False,
        "evaluation_job_13_modified": False,
        "native_build_admission_job_14_modified": False,
        "emission_job_15_added": True,
        "emission_job_15_modified": False,
        "store_artifact_profile_job_16_added": True,
        "store_artifact_profile_job_16_modified": False,
        "native_delivery_complete_original_152_job_17_added": True,
        "native_delivery_complete_six_caller_groups_job_18_added": True,
        "service_context_original_caller_gate_attempted": any(
            row["name"] == "service-context-callers" for row in commands),
        "cost_ledger_seven_ordinary_caller_gate_attempted": any(
            row["name"] == "cost-ledger-callers" for row in commands),
        "evaluation_seven_ordinary_caller_gate_attempted": any(
            row["name"] == "evaluation-callers" for row in commands),
        "native_build_admission_nine_ordinary_caller_gate_attempted": any(
            row["name"] == "native-build-admission-callers" for row in commands),
        "emission_nine_ordinary_caller_gate_attempted": any(
            row["name"] == "emission-callers" for row in commands),
        "store_artifact_profile_ten_complete_original_caller_gate_attempted": any(
            row["name"] == "store-artifact-profile-callers" for row in commands),
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


def audit_copy_tar_payload(stream, manifest, manifest_raw):
    """Verify every recorded member without extracting or rebuilding the tar."""
    files = manifest["files"]
    directories = manifest["original_evidence_directories"]
    expected_files = {"evidence/" + name: row for name, row in files.items()}
    embedded = "evidence/artifact-manifest.json"
    expected_files[embedded] = {"bytes": len(manifest_raw), "sha256": hashlib.sha256(manifest_raw).hexdigest()}
    expected_directories = {"evidence", *("evidence/" + name for name in directories)}
    for name in (*expected_files, *expected_directories):
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != name:
            raise ValueError("audit copy manifest contains a non-canonical archive path")
        expected_directories.update(parent.as_posix() for parent in path.parents if parent.as_posix() != ".")
    expected_names = set(expected_files) | expected_directories
    seen, ordered_members = set(), hashlib.sha256()
    with tarfile.open(fileobj=stream, mode="r|", bufsize=1024 * 1024) as archive:
        for member in archive:
            if (member.name in seen or member.name not in expected_names
                    or not (member.isfile() or member.isdir())
                    or "mtime" not in member.pax_headers):
                raise ValueError("audit copy has an unexpected, duplicate or unsupported original member")
            seen.add(member.name)
            mtime_ns = int(Decimal(member.pax_headers["mtime"]) * 1_000_000_000)
            member_digest = None
            if member.isfile():
                if member.name not in expected_files:
                    raise ValueError("audit copy replaced an original directory with a file")
                expected = expected_files[member.name]
                if member.size != expected["bytes"]:
                    raise ValueError("audit copy changed an original file size")
                with archive.extractfile(member) as body:
                    member_digest = hashlib.file_digest(body, "sha256").hexdigest()
                if member_digest != expected["sha256"]:
                    raise ValueError("audit copy changed original evidence bytes")
            else:
                if member.name not in expected_directories or member.size != 0:
                    raise ValueError("audit copy replaced an original file with a directory")
                # The staging root is not the original audit/evidence directory,
                # whose recorded member is evidence/evidence. Its actual metadata
                # still participates in both complete tar reads and ordered hash.
                expected = {} if member.name == "evidence" else directories.get(member.name.removeprefix("evidence/"), {})
            if ("mode_octal" in expected and member.mode != int(expected["mode_octal"], 8)
                    or "mtime_ns" in expected and mtime_ns != expected["mtime_ns"]):
                raise ValueError("audit copy changed recorded original modes or nanosecond timestamps")
            observed = {"name": member.name, "kind": "file" if member.isfile() else "directory",
                        "bytes": member.size, "sha256": member_digest, "mode": member.mode,
                        "mtime_ns": mtime_ns, "uid": member.uid, "gid": member.gid,
                        "uname": member.uname, "gname": member.gname, "pax_headers": member.pax_headers}
            ordered_members.update(evaluation_json_bytes(observed) + b"\n")
    if seen != expected_names:
        raise ValueError("audit copy omitted an original archive member")
    # tarfile may stop at the tar end marker. The remaining decoded bytes are
    # still part of the original payload and must enter the stream hash/copy.
    while stream.read(1024 * 1024):
        pass
    return {"verified_archive_member_count": len(seen), "verified_original_file_count": len(files),
            "ordered_member_observations_sha256": ordered_members.hexdigest()}


def audit_copy(args):
    """Create one verified complete XZ copy after the original upload has run.

    This command never changes qualification results or the original archive.
    It accepts only an archive collected by the current exact five-file harness.
    """
    import gzip
    import lzma

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt_path = output / "audit-copy-receipt.json"
    record = {"schema": "hepta.hia.full-retained-audit-lossless-copy.v1", "status": "HOLD",
              "scope": "COMPLETE_ORIGINAL_TAR_PAYLOAD_COPY_NOT_A_QUALIFICATION_RESULT",
              "qualification_result_changed": False, "original_collect_replaced": False,
              "original_archive_removed": False, "split_or_range_delivery_used": False,
              "upload_ready": False, "error": None}
    before = {}
    try:
        source = args.original.resolve(strict=True)
        original_paths = {name: source / name for name in (
            "original-evidence.tar.gz", "artifact-manifest.json", "collection-receipt.json")}
        for name, path in original_paths.items():
            observed = path.lstat()
            if not stat.S_ISREG(observed.st_mode):
                raise ValueError("original audit archive input is not a regular file")
            before[name] = {"bytes": observed.st_size, "sha256": sha(path),
                            "mode": stat.S_IMODE(observed.st_mode), "mtime_ns": observed.st_mtime_ns,
                            "device": observed.st_dev, "inode": observed.st_ino}
        record["original_inputs_before"] = before
        manifest_raw = original_paths["artifact-manifest.json"].read_bytes()
        collection_raw = original_paths["collection-receipt.json"].read_bytes()
        manifest, collection = json.loads(manifest_raw), json.loads(collection_raw)
        if (manifest.get("schema") != "hepta.hia.full-retained-audit-artifact.v1"
                or manifest.get("scope") != "ORIGINAL_SUCCESS_FAILURE_AND_PARTIAL_EVIDENCE_NOT_A_PASS_CLAIM"
                or type(manifest.get("files")) is not dict or type(manifest.get("original_evidence_directories")) is not dict
                or collection.get("archive") != "original-evidence.tar.gz"
                or type(collection.get("bytes")) is not int
                or collection["bytes"] != before["original-evidence.tar.gz"]["bytes"]
                or collection.get("sha256") != before["original-evidence.tar.gz"]["sha256"]
                or collection.get("artifact_manifest_sha256") != hashlib.sha256(manifest_raw).hexdigest()
                or type(collection.get("retained_file_count")) is not int
                or collection["retained_file_count"] != len(manifest["files"])
                or type(collection.get("verified_archive_member_count")) is not int
                or any(collection.get(key) is not True for key in (
                    "all_archived_bytes_hashes_types_modes_and_mtimes_read_back",
                    "original_modes_recorded_and_archived", "failure_or_interrupted_results_not_rewritten"))):
            raise ValueError("original complete collection receipt or manifest differs")
        harness = Path(__file__).resolve().parent
        harness_hashes = {}
        for relative, archived in HARNESS_FILES.items():
            digest = sha(harness / relative)
            if manifest["files"].get("harness/" + archived, {}).get("sha256") != digest:
                raise ValueError("archive was not collected by this exact current five-file harness")
            harness_hashes[relative] = digest
        if not lzma.is_check_supported(lzma.CHECK_SHA256):
            raise ValueError("the runtime lacks the required XZ SHA-256 integrity check")
        record["source_harness_files_sha256"] = harness_hashes
        parameters = {"format": "XZ", "preset": 9, "extreme": True, "integrity_check": "SHA256",
                      "implementation": "Python stdlib lzma.LZMACompressor", "parallel_streams": 1,
                      "python_version": sys.version, "bit_identical_compression_across_library_versions_claimed": False}
        compressor = lzma.LZMACompressor(format=lzma.FORMAT_XZ,
                                        preset=9 | lzma.PRESET_EXTREME, check=lzma.CHECK_SHA256)
        partial = output / "original-evidence.tar.xz.partial"

        class PayloadReader:
            def __init__(self, raw, write=None):
                self.raw, self.write = raw, write
                self.digest, self.bytes = hashlib.sha256(), 0

            def read(self, count=-1):
                data = self.raw.read(count)
                self.digest.update(data)
                self.bytes += len(data)
                if self.write is not None:
                    self.write(data)
                return data

        class StrictXZReader:
            def __init__(self, raw):
                self.raw = raw
                self.decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
                self.buffer, self.finished = bytearray(), False

            def read(self, count):
                if count < 0:
                    raise ValueError("audit copy requires bounded streaming reads")
                while len(self.buffer) < count and not self.finished:
                    incoming = self.raw.read(1024 * 1024) if self.decoder.needs_input else b""
                    if self.decoder.needs_input and not incoming:
                        raise ValueError("audit copy XZ stream ended before its checksum")
                    self.buffer.extend(self.decoder.decompress(incoming, max_length=max(count, 1024 * 1024)))
                    if self.decoder.eof:
                        if (self.decoder.check != lzma.CHECK_SHA256
                                or self.decoder.unused_data or self.raw.read(1)):
                            raise ValueError("audit copy XZ has a wrong checksum type or unverified trailing stream")
                        self.finished = True
                data = bytes(self.buffer[:count])
                del self.buffer[:count]
                return data

        with original_paths["original-evidence.tar.gz"].open("rb") as raw, \
                gzip.GzipFile(fileobj=raw, mode="rb") as decoded, partial.open("xb") as encoded:
            def encode(data):
                encoded.write(compressor.compress(data))
            original = PayloadReader(decoded, encode)
            original_members = audit_copy_tar_payload(original, manifest, manifest_raw)
            encoded.write(compressor.flush())
        del compressor
        if original_members["verified_archive_member_count"] != collection["verified_archive_member_count"]:
            raise ValueError("decoded original member count differs from its full collection receipt")
        compressed_sha = sha(partial)
        with partial.open("rb") as encoded:
            copied = PayloadReader(StrictXZReader(encoded))
            copied_members = audit_copy_tar_payload(copied, manifest, manifest_raw)
        if (original.bytes != copied.bytes or original.digest.digest() != copied.digest.digest()
                or original_members != copied_members or sha(partial) != compressed_sha):
            raise ValueError("complete XZ readback differs from the exact original tar stream")
        after = {}
        for name, path in original_paths.items():
            observed = path.lstat()
            if not stat.S_ISREG(observed.st_mode):
                raise ValueError("original audit archive input changed type during copy")
            after[name] = {"bytes": observed.st_size, "sha256": sha(path),
                           "mode": stat.S_IMODE(observed.st_mode), "mtime_ns": observed.st_mtime_ns,
                           "device": observed.st_dev, "inode": observed.st_ino}
        if after != before or any(sha(harness / name) != digest for name, digest in harness_hashes.items()):
            raise ValueError("original gzip, manifest, receipt or current harness changed during complete copy")
        record["original_inputs_after"] = after
        destination = output / "original-evidence.tar.xz"
        partial.rename(destination)
        (output / "artifact-manifest.json").write_bytes(manifest_raw)
        (output / "collection-receipt.json").write_bytes(collection_raw)
        # The service's later artifact metadata is authoritative for its outer
        # ZIP size. Reserve overhead; never split, truncate or range-download.
        limit, zip_reserve, receipt_reserve = 512 * 1024 * 1024, 1024 * 1024, 64 * 1024
        delivery_bytes = destination.stat().st_size + len(manifest_raw) + len(collection_raw)
        upload_ready = delivery_bytes + zip_reserve + receipt_reserve < limit
        record.update({"status": "VERIFIED_COMPLETE_COPY" if upload_ready else "HOLD",
            "upload_ready": upload_ready,
            "hold_reason": None if upload_ready else "complete copy exceeds conservative normal-artifact delivery budget",
            "original_gzip": before["original-evidence.tar.gz"],
            "original_artifact_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "original_collection_receipt_sha256": hashlib.sha256(collection_raw).hexdigest(),
            "exact_uncompressed_tar": {"bytes": original.bytes, "sha256": original.digest.hexdigest()},
            "complete_xz_readback_tar": {"bytes": copied.bytes, "sha256": copied.digest.hexdigest()},
            "compressed_copy": {"file": destination.name, "bytes": destination.stat().st_size,
                                "sha256": compressed_sha, "parameters": parameters},
            "member_readback": copied_members,
            "original_recorded_files_modes_and_nanosecond_times_verified": True,
            "all_original_tar_bytes_including_padding_preserved": True,
            "unrecorded_implicit_directory_metadata_preserved_by_exact_tar_identity": True,
            "original_gzip_manifest_receipt_and_harness_unchanged": True,
            "lossless_tar_payload_rebuilt_from_filesystem": False,
            "normal_artifact_size_limit_bytes": limit, "outer_zip_overhead_reserved_bytes": zip_reserve,
            "copy_receipt_reserved_bytes": receipt_reserve,
            "actual_outer_artifact_size_observed": False,
            "workflow_scheduling_scope": "separate post-collection and post-original-upload step; no benchmark execution"})
    except Exception as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
    write_json(receipt_path, record)
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write("upload_ready=" + ("true" if record["upload_ready"] else "false") + "\n")
            stream.write("delivery_status=" + record["status"] + "\n")
    print(json.dumps({"delivery_status": record["status"], "upload_ready": record["upload_ready"],
                      "receipt": str(receipt_path), "qualification_result_changed": False}))
    return 0 if record["upload_ready"] else 2


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
    copy_parser = commands.add_parser("audit-copy")
    copy_parser.add_argument("--original", type=Path, required=True)
    copy_parser.add_argument("--output", type=Path, required=True)
    copy_parser.add_argument("--github-output", type=Path)
    copy_parser.set_defaults(operation=audit_copy)
    args = parser.parse_args()
    return args.operation(args)


if __name__ == "__main__":
    raise SystemExit(main())
