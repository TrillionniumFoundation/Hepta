"""v6 executable Owner Core -> independent VM -> native child differential.

A generated C object is a subprocess transport control, never claimed to be a
Hepta-built implementation. Standalone HIA/Hepta true native builds are scoped
separately and require the actual pinned Clang20 and, for source, Rust.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.hia_program_runtime import execute_program
from hepta.hia_source_bridge import lower_checked_owned_hia
from hepta.hia_native_differential import (HIADifferentialRejected,
    compare_verified_hia_program, qualify_executable_hia_program,
    qualify_checked_hia_source)
from hepta.parser import parse

CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")
_SOURCE = '''module differential_owned_hia;
export "C" fn drop_case() -> i32 effects {alloc,block,panic} {
    let bytes = buffer(4);
    drop(move bytes);
    return 7;
}
'''
_PROJECT = "f" * 64


def checked_core():
    program = parse(_SOURCE, "owned_core.hepta")
    typed = check(program)
    if not typed.ok:
        raise AssertionError([item.to_dict() for item in typed.diagnostics])
    return lower_checked_owned_hia(program, typed, project_sha256=_PROJECT).program


class ExistingV6CoreDifferentialTests(unittest.TestCase):
    def test_actual_owned_core_verification_and_vm_observe_drop(self):
        core = checked_core()
        result = execute_program(core, "drop_case", [])
        self.assertEqual(result["result"], 7)
        self.assertEqual(result["resources"]["allocations"], 1)
        self.assertEqual(result["resources"]["frees"], 1)
        self.assertEqual(result["resources"]["live_owners"], 0)

    @unittest.skipUnless(shutil.which("clang"), "Clang needed for subprocess transport")
    def test_real_clang_transport_with_existing_verified_owner_vm(self):
        core = checked_core()
        with tempfile.TemporaryDirectory(prefix="hia-v6-transport-") as temp:
            source, library = Path(temp) / "bridge.c", Path(temp) / "bridge.so"
            source.write_text('#include <stdint.h>\n'
                              'int32_t drop_case(void) { return 7; }\n')
            subprocess.run(["clang", "-shared", "-fPIC", str(source),
                            "-o", str(library)], check=True, timeout=30)
            report = compare_verified_hia_program(core, library, {"drop_case": [[]]})
            self.assertEqual(report["cases_executed"], 1)
            self.assertTrue(report["claims"]["executable_hia_program_reverified"])
            self.assertFalse(report["claims"]["native_compiled_from_program_verified"])
            self.assertFalse(report["claims"]["checked_hepta_source_replayed"])

    def test_wrong_hia_argument_count_refused_before_native_load(self):
        # Retain PR #221's independent Core-v6 native preflight regression.
        core = checked_core()
        for vectors in ([[99]], [[1, 2]], [[], [5]]):
            with self.subTest(args=vectors):
                with patch("hepta.hia_native_differential._observe_native") as runner:
                    with self.assertRaisesRegex(HIADifferentialRejected, "ABI argument arity"):
                        compare_verified_hia_program(core, "not_a_library.so",
                                                     {"drop_case": vectors})
                    runner.assert_not_called()

    def test_missing_native_export_cannot_count_as_full_qualification(self):
        core = checked_core()
        with patch("hepta.hia_native_differential._observe_native") as runner:
            with self.assertRaisesRegex(HIADifferentialRejected, "export inventory"):
                compare_verified_hia_program(core, "absent.so",
                                             {"wrong_export": [[]]})
            runner.assert_not_called()

    def test_core_abi_arity_rejects_before_native_child(self):
        # drop_case is a verified zero-argument C export. ctypes must never
        # call it with arbitrary caller-supplied words, even if the VM would
        # later reject those words on its own.
        from hepta.hia_native_differential import _require_exact_argument_arities
        core = checked_core()
        _require_exact_argument_arities({"drop_case": [[]]}, (("drop_case", 0),))
        for arguments in ([3], [3, 4], [True]):
            with self.subTest(arguments=arguments):
                with patch("hepta.hia_native_differential._observe_native") as child:
                    with self.assertRaisesRegex(HIADifferentialRejected, "arity"):
                        compare_verified_hia_program(
                            core, "not-a-real-binary.so",
                            {"drop_case": [arguments]})
                    child.assert_not_called()
        for signatures in ((("drop_case", True),), (("drop_case", 1.0),),
                           (("drop_case", -1),), (("drop_case", 0), ("drop_case", 0))):
            with self.subTest(signatures=signatures):
                with self.assertRaisesRegex(HIADifferentialRejected, "signature"):
                    _require_exact_argument_arities({"drop_case": [[]]}, signatures)

    @unittest.skipUnless(shutil.which(CLANG), "pinned Clang20 required")
    def test_actual_executable_hia_llvm_matches_owner_vm(self):
        core = checked_core()
        report = qualify_executable_hia_program(core, {"drop_case": [[]]}, clang=CLANG)
        self.assertTrue(report["claims"]["native_compiled_from_program_verified"])
        self.assertFalse(report["claims"]["checked_hepta_source_replayed"])
        self.assertEqual(report["cases_executed"], 1)

    def test_source_static_budget_receipt_is_replayed_before_native_child(self):
        # The native builder may return a complete, rehashed receipt with
        # understated heap bytes. No finite VM/native comparison may start.
        from copy import deepcopy
        from hashlib import sha256
        import json
        from types import SimpleNamespace
        from hepta.hia_static_budget import analyze_static_budget

        core = checked_core()
        limits = {"max_live_heap_bytes": 4}
        genuine = analyze_static_budget(core, **limits)
        self.assertGreater(genuine["functions"][0]["max_live_heap_bytes"], 0)
        fake = deepcopy(genuine)
        fake["functions"][0]["max_live_heap_bytes"] = 0
        unsealed = {k: v for k, v in fake.items() if k != "sha256"}
        fake["sha256"] = sha256(json.dumps(
            unsealed, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")).hexdigest()
        analyzed = SimpleNamespace(
            program=object(), checked=object(),
            project=SimpleNamespace(identity=_PROJECT, unchanged=lambda: True),
            report={"ok": True})
        fake_builder = {
            "ok": True,
            "claims": {"native_codegen_consumed_verified_hia_core": True},
            "static_resource_budget": fake,
        }
        with tempfile.TemporaryDirectory(prefix="hia-forged-budget-") as temp:
            source = Path(temp) / "original.hepta"
            source.write_text(_SOURCE, encoding="utf-8")
            with (
                patch("hepta.pipeline.analyze_project", return_value=analyzed),
                patch("hepta.hia_source_bridge.build_checked_hepta_hia_native",
                      return_value=fake_builder) as build,
                patch("hepta.hia_source_bridge.lower_checked_owned_hia",
                      return_value=SimpleNamespace(program=core)),
                patch("hepta.hia_native_differential._observe_native") as child,
            ):
                with self.assertRaisesRegex(HIADifferentialRejected, "budget replay"):
                    qualify_checked_hia_source(
                        source, {"drop_case": [[]]}, profile="owned",
                        static_resource_limits=limits)
                child.assert_not_called()
                build.assert_called_once()
                self.assertEqual(
                    build.call_args.kwargs["static_resource_limits"], limits)

    def test_rejected_source_builder_diagnostics_are_detached_and_never_authority(self):
        from copy import deepcopy
        report = {"ok": False, "status": "rejected",
                  "claims": {"native_codegen_consumed_verified_hia_core": True},
                  "diagnostics": [{"code": "E_HIA_HEPTA_BRIDGE", "message": "exact host receipt refused"}],
                  "rust_reference": {"diagnostics": [{"code": "E_RUSTC", "message": "nested detail"}]}}
        expected = deepcopy(report)
        with (patch("hepta.hia_native_differential.platform.system", return_value="Linux"),
              patch("hepta.hia_source_bridge.build_checked_hepta_hia_native", return_value=report),
              patch("hepta.hia_native_differential._observe_native") as child):
            with self.assertRaisesRegex(HIADifferentialRejected, "exact host receipt refused") as caught:
                qualify_checked_hia_source("rejected.hepta", {"drop_case": [[]]})
            child.assert_not_called()
        first = caught.exception.build_diagnostics
        self.assertTrue(first["diagnostic_only"])
        self.assertFalse(first["authorizes_execution"])
        self.assertEqual(first["snapshot_status"], "retained")
        self.assertEqual(first["builder_report"], expected)
        report["rust_reference"]["diagnostics"][0]["message"] = "caller mutation"
        first["builder_report"]["diagnostics"][0]["message"] = "returned view mutation"
        self.assertEqual(caught.exception.build_diagnostics["builder_report"], expected)

    def test_malformed_or_over_budget_build_diagnostics_keep_the_original_refusal(self):
        class Unprintable:
            def __repr__(self):
                raise AssertionError("diagnostic copying must not invoke object hooks")

        cyclic = []
        cyclic.append(cyclic)
        deep = None
        for _ in range(20):
            deep = [deep]
        for label, value in (("cycle", cyclic), ("depth", deep), ("items", [0] * 129),
                             ("text", "x" * 16385), ("huge_integer", 1 << 129),
                             ("nodes", [list(range(128)) for _ in range(9)]),
                             ("total_text", ["x" * 16000] * 3),
                             ("encoded_bytes", "\U0001f9e0" * 6000),
                             ("nonfinite", float("nan")), ("object", Unprintable())):
            with self.subTest(case=label):
                report = {"ok": False, "diagnostics": [], "details": value}
                with (patch("hepta.hia_native_differential.platform.system", return_value="Linux"),
                      patch("hepta.hia_source_bridge.build_checked_hepta_hia_native", return_value=report),
                      patch("hepta.hia_native_differential._observe_native") as child):
                    with self.assertRaisesRegex(HIADifferentialRejected, "qualification rejected") as caught:
                        qualify_checked_hia_source("rejected.hepta", {"drop_case": [[]]})
                    child.assert_not_called()
                self.assertEqual(caught.exception.build_diagnostics["snapshot_status"], "unavailable")
                self.assertIsNone(caught.exception.build_diagnostics["builder_report"])
                self.assertFalse(caught.exception.build_diagnostics["authorizes_execution"])

    def test_diagnostic_allocation_failure_cannot_replace_qualification_rejection(self):
        with (patch("hepta.hia_native_differential.platform.system", return_value="Linux"),
              patch("hepta.hia_source_bridge.build_checked_hepta_hia_native", return_value={"ok": False}),
              patch("hepta.hia_native_differential._bounded_build_diagnostics", side_effect=MemoryError),
              patch("hepta.hia_native_differential._observe_native") as child):
            with self.assertRaisesRegex(HIADifferentialRejected, "qualification rejected") as caught:
                qualify_checked_hia_source("rejected.hepta", {"drop_case": [[]]})
            child.assert_not_called()
        self.assertEqual(caught.exception.build_diagnostics["snapshot_status"], "unavailable")

    @unittest.skipUnless(shutil.which(CLANG) and
                         (os.environ.get("RUSTC") or shutil.which("rustc")),
                         "pinned Rust and Clang20 required")
    def test_pinned_hepta_owned_source_to_single_core_native(self):
        from hepta.hia_program_llvm import native_host_profile
        from hepta.hia_source_bridge import build_checked_hepta_hia_native
        observed_builds = []

        def retain_real_build(*args, **kwargs):
            report = build_checked_hepta_hia_native(*args, **kwargs)
            observed_builds.append(report)
            return report

        with tempfile.TemporaryDirectory(prefix="hia-v6-source-") as temp:
            src = Path(temp) / "owned.hepta"
            src.write_text(_SOURCE, encoding="utf-8")
            # Keep the real formerly failing builder/qualifier path. This
            # wrapper observes the unmodified producer receipt and never
            # changes a field to satisfy source-facing reinspection.
            with patch("hepta.hia_source_bridge.build_checked_hepta_hia_native", side_effect=retain_real_build):
                report = qualify_checked_hia_source(
                    src, {"drop_case": [[]]}, profile="owned",
                    clang=CLANG, rustc=os.environ.get("RUSTC"),
                    static_resource_limits={"max_live_heap_bytes": 4})
            self.assertEqual(len(observed_builds), 1)
            self.assertTrue(observed_builds[0]["ok"], observed_builds[0])
            self.assertEqual(observed_builds[0]["native_backend"]["build_host"], native_host_profile())
            self.assertIs(observed_builds[0]["native_backend"]["cross_target_compilation"], False)
            self.assertTrue(observed_builds[0]["claims"]["source_native_binary_abi_rechecked"])
            self.assertTrue(report["claims"]["source_static_resource_budget_replayed"])
            self.assertEqual(report["static_resource_limits"], {"max_live_heap_bytes": 4})
            self.assertTrue(report["claims"]["native_compiled_from_program_verified"])
            self.assertTrue(report["claims"]["checked_hepta_source_replayed"])
            self.assertEqual(report["cases_executed"], 1)


if __name__ == "__main__":
    unittest.main()
