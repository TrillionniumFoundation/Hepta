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
        core = checked_core()
        for vectors in ([[99]], [[1, 2]], [[] , [5]]):
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

    @unittest.skipUnless(shutil.which(CLANG), "pinned Clang20 required")
    def test_actual_executable_hia_llvm_matches_owner_vm(self):
        core = checked_core()
        report = qualify_executable_hia_program(core, {"drop_case": [[]]}, clang=CLANG)
        self.assertTrue(report["claims"]["native_compiled_from_program_verified"])
        self.assertFalse(report["claims"]["checked_hepta_source_replayed"])
        self.assertEqual(report["cases_executed"], 1)

    @unittest.skipUnless(shutil.which(CLANG) and
                         (os.environ.get("RUSTC") or shutil.which("rustc")),
                         "pinned Rust and Clang20 required")
    def test_pinned_hepta_owned_source_to_single_core_native(self):
        with tempfile.TemporaryDirectory(prefix="hia-v6-source-") as temp:
            src = Path(temp) / "owned.hepta"
            src.write_text(_SOURCE, encoding="utf-8")
            report = qualify_checked_hia_source(
                src, {"drop_case": [[]]}, profile="owned",
                clang=CLANG, rustc=os.environ.get("RUSTC"))
            self.assertTrue(report["claims"]["native_compiled_from_program_verified"])
            self.assertTrue(report["claims"]["checked_hepta_source_replayed"])
            self.assertEqual(report["cases_executed"], 1)


if __name__ == "__main__":
    unittest.main()
