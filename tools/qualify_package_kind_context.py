#!/usr/bin/env python3
"""Exact schema/version/context methods; no native compilation or execution."""
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.qualify_versioned_package_context import StrictResult, identities, verify_inputs

PLANNED = [
    "tests.test_package_kind_schema.PackageKindSchemaTests.test_array_kinds_have_package_diagnostics",
    "tests.test_package_kind_schema.PackageKindSchemaTests.test_cli_reports_one_json_diagnostic_instead_of_traceback",
    "tests.test_package_kind_schema.PackageKindSchemaTests.test_default_bin_and_lib_keep_default_entry_selection",
    "tests.test_package_kind_schema.PackageKindSchemaTests.test_invalid_dependency_kind_reports_the_dependency_manifest",
    "tests.test_package_kind_schema.PackageKindSchemaTests.test_invalid_kind_precedes_missing_entry_and_bad_dependencies",
    "tests.test_package_kind_schema.PackageKindSchemaTests.test_non_string_scalar_kinds_keep_the_same_diagnostic",
    "tests.test_package_kind_schema.PackageKindSchemaTests.test_prior_name_version_and_unknown_key_diagnostics_are_unchanged",
    "tests.test_package_kind_schema.PackageKindSchemaTests.test_table_kinds_have_package_diagnostics",
    "tests.test_package_kind_schema.PackageKindSchemaTests.test_unsupported_string_kinds_keep_the_same_diagnostic",
    "tests.test_package_kind_schema.PackageKindSchemaTests.test_valid_kinds_roundtrip_content_lock",
    "tests.test_versioned_package_kind.VersionedPackageKindTests.test_failed_lock_refresh_preserves_bytes_and_valid_recovery",
    "tests.test_versioned_package_kind.VersionedPackageKindTests.test_invalid_declared_candidates_reject_before_version_selection",
    "tests.test_versioned_package_kind.VersionedPackageKindTests.test_public_cli_rejects_unselected_kind_then_frontend_recovers",
    "tests.test_versioned_package_kind.VersionedPackageKindTests.test_schema_diagnostic_precedes_locked_context_conflict",
]


def main():
    if sys.flags.optimize:
        raise SystemExit("Python assertions must remain enabled")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONPATH"] = str(ROOT)
    os.chdir(ROOT)
    verify_inputs()
    before = identities()
    print("PACKAGE_KIND_CONTEXT_IDENTITY " + json.dumps({
        "python": sys.version, "source_sha256": before}, sort_keys=True), flush=True)
    suite = unittest.TestLoader().loadTestsFromNames(PLANNED)
    result = unittest.TextTestRunner(verbosity=2, resultclass=StrictResult).run(suite)
    report = {"planned": PLANNED, "started": result.started, "finished": result.finished,
              "passed": result.passed, "failures": len(result.failures), "errors": len(result.errors),
              "skips": len(result.skipped), "expected_failures": len(result.expectedFailures),
              "unexpected_successes": len(result.unexpectedSuccesses)}
    print("PACKAGE_KIND_CONTEXT_METHODS " + json.dumps(report, sort_keys=True), flush=True)
    if (not result.wasSuccessful() or result.started != PLANNED or result.finished != PLANNED
            or result.passed != PLANNED or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses):
        raise SystemExit("Exact package-kind context inventory failed")
    verify_inputs()
    if before != identities():
        raise SystemExit("Source changed during package-kind context checks")
    print("PACKAGE_KIND_CONTEXT_PASS " + json.dumps({
        "methods": 14, "source_unchanged": True, "native_execution": False}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
