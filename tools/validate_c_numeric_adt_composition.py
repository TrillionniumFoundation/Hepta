#!/usr/bin/env python3
"""Run an exact, no-skip inventory; native Rust is opt-in and explicit."""
from pathlib import Path
import hashlib
import json
import os
import platform
import sys
import unittest
import shutil
import subprocess
from verify_numeric_adt_sources import verify

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
MODULES = ["test_c_float_int_casts", "test_c_numeric_adt_composition", "test_c_unit_values", "test_c_results", "test_c_generic_structs", "test_c_generic_enums", "test_c_payload_enums", "test_c_fieldless_enums", "test_c_backend", "test_parser", "test_checker",
           "test_language.LanguageSyntax", "test_language.LanguageRejections",
           "test_cross_feature_audit.CIntegrationAudit.test_new_language_features_fail_before_c_codegen_or_artifact_replacement"]


NUMERIC = [
    "tests.test_c_float_casts.CFloatCastTests.test_all_twenty_float_integer_pairs_emit",
    "tests.test_c_float_casts.CFloatCastTests.test_integer_to_float_and_float_width_changes_emit",
    "tests.test_c_float_casts.CFloatCastTests.test_native_boundaries_and_seeded_bits_under_float_cast_sanitizer",
    "tests.test_c_float_casts.CFloatCastTests.test_effectful_cast_operand_runs_once_and_short_circuits",
    "tests.test_c_float_conversions.CFloatConversionTests.test_twenty_two_conversion_pairs_emit",
    "tests.test_c_float_conversions.CFloatConversionTests.test_native_exact_bits_all_rounding_modes_and_x86_flush_modes",
    "tests.test_c_float_conversions.CFloatConversionTests.test_oracle_known_ties_overflow_and_signed_zero",
    "tests.test_c_float_conversions.CFloatConversionTests.test_effectful_operands_execute_once_and_short_circuit",
    "tests.test_c_float_conversions.CFloatConversionTests.test_fast_math_and_unknown_representation_are_rejected",
]
RUST_ONLY = [
    "tests.test_c_float_casts.CFloatCastTests.test_actual_rust_casts_match_the_same_bit_pattern_oracle",
    "tests.test_c_float_conversions.CFloatConversionTests.test_native_rust_matches_exact_oracle",
]
RUST_REQUIRED = os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1"
MODULES += NUMERIC + (RUST_ONLY if RUST_REQUIRED else [])


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class TrackedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started, self.finished, self.passed = [], [], []

    def startTest(self, test):
        self.started.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.finished.append(test.id())
        super().stopTest(test)

    def addSuccess(self, test):
        self.passed.append(test.id())
        super().addSuccess(test)


def main():
    provenance = verify()
    if RUST_REQUIRED:
        rustc = shutil.which("rustc")
        selected = shutil.which(os.environ.get("RUSTC", "rustc"))
        if not rustc or not selected or Path(rustc).resolve() != Path(selected).resolve():
            raise SystemExit("Native Rust must exist and RUSTC must select the rustc on PATH")
        version = subprocess.run([rustc, "--version"], capture_output=True, text=True, timeout=10)
        if version.returncode or not version.stdout.startswith("rustc 1.90.0 "):
            raise SystemExit("Native Rust must match pinned version 1.90.0")
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in MODULES)
    planned = [test.id() for test in flatten(suite)]
    expected = json.loads((ROOT / ("tools/c_numeric_adt_rust_test_ids.json" if RUST_REQUIRED else "tools/c_numeric_adt_test_ids.json")).read_text())
    if planned != expected or len(set(planned)) != len(planned):
        raise SystemExit("Test inventory differs from frozen unique method IDs")
    inputs = [str(path.relative_to(ROOT)) for path in sorted((ROOT / "hepta").glob("*.py"))]
    inputs += sorted({"tests/" + name.removeprefix("tests.").split(".")[0] + ".py" for name in MODULES})
    inputs += ["examples/fieldless_enums.hepta", "examples/payload_enums.hepta", "tools/c_generic_struct_test_ids.json",
               "tools/validate_c_generic_structs.py", "tools/validate_c_generic_enums.py", "tools/c_generic_enum_test_ids.json", "tools/validate_c_payload_enums.py", "tools/c_payload_enum_test_ids.json", "tools/validate_c_fieldless_enums.py",
               "tools/c_fieldless_enum_test_ids.json", "tools/qualify_c_payload_enum_oracle.py", "tools/qualify_c_generic_enum_oracle.py", "examples/generic_enums.hepta", "toolchain-lock.json", "examples/generic_structs.hepta", "tools/qualify_c_generic_struct_oracle.py", "examples/c_results.hepta", "tools/c_result_test_ids.json", "tools/validate_c_results.py", "tools/qualify_c_result_oracle.py", "tests/test_c_unit_values.py", "examples/c_unit_values.hepta", "tools/c_unit_test_ids.json", "tools/validate_c_unit_values.py", "tools/qualify_c_unit_oracle.py", "tools/verify_numeric_adt_sources.py", "tools/numeric_adt_source_origins.json", "tools/validate_c_numeric_adt_composition.py", "tools/c_numeric_adt_test_ids.json", "tools/c_numeric_adt_rust_test_ids.json", "tools/qualify_c_float_int_oracle.py", "tools/qualify_c_numeric_adt_oracle.py", "examples/c_float_int_casts.hepta", "tests/__init__.py", "tests/test_c_float_casts.py", "tests/test_c_float_conversions.py", "docs/C_NUMERIC_ADT_COMPOSITION.md", "docs/C_FLOAT_CASTS.md", ".github/workflows/c-numeric-adt-composition.yml"]
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs}
    print(json.dumps({"python": sys.version, "host": platform.platform(), "source_transplants": provenance,
                      "inventory_mode": "native-c-and-rust" if RUST_REQUIRED else "native-c-only",
                      "unexecuted_rust_reference_methods": [] if RUST_REQUIRED else RUST_ONLY,
                      "rust_required": os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1",
                      "source_sha256": hashes, "planned": planned}), flush=True)
    result = unittest.TextTestRunner(verbosity=2, resultclass=TrackedResult).run(suite)
    ok = (result.wasSuccessful() and not result.skipped and not result.expectedFailures
          and not result.unexpectedSuccesses and planned == result.started == result.finished == result.passed
          and all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
                  for name, digest in hashes.items()))
    print(json.dumps({"tests_run": result.testsRun, "started": result.started,
                      "finished": result.finished, "passed": result.passed,
                      "complete_pass": ok}), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
