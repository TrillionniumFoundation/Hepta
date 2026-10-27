"""Composition of nominal ownership and every v2-v6 byte instruction.

The native test executes the frozen observer on x86-64 and actual AArch64
machine code under QEMU; source inspection is never counted as execution.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_llvm import (PROFILE_V6, PROFILE_AARCH64_V6, TARGET_AARCH64,
                                    emit_program_llvm)
from hepta.hia_program_aarch64 import COMPOSITE_BULK_CASES, COMPOSITE_BULK_TRAPS
from tools.qualify_hia_composite_bulk import (byte_oracle, composite_bulk_program,
    expected_counts, qualify, validate_qualification, wrong_result_program)


def configured_tool(variable, default):
    selected = os.environ.get(variable, default)
    return shutil.which(selected) or selected


# The qualifier binds an explicit filesystem path, so resolve PATH aliases
# before calling it. An unavailable explicit selection stays unavailable.
CLANG = configured_tool("CLANG", "clang")
LINKER = configured_tool("HEPTA_LLD", "ld.lld")
QEMU = configured_tool("HEPTA_QEMU_AARCH64", "qemu-aarch64")


class CompositeBulkCoreTests(unittest.TestCase):
    def test_one_nominal_authority_normalizes_to_v6_and_keeps_helper_internal(self):
        original = verify_program(composite_bulk_program())
        normalized = verify_program(original.canonical_bytes)
        self.assertEqual(original.as_dict()["schema"], "hepta.hia.program.v6")
        self.assertEqual(original.scalar_entrypoints, frozenset({"aggregate_bulk"}))
        self.assertEqual(original.canonical_bytes, normalized.canonical_bytes)
        self.assertNotEqual(original.input_sha256, normalized.input_sha256)
        for candidate in (original, normalized):
            self.assertEqual(emit_program_llvm(candidate).profile, PROFILE_V6)
            self.assertEqual(emit_program_llvm(candidate, target=TARGET_AARCH64).profile, PROFILE_AARCH64_V6)
            self.assertEqual(emit_program_llvm(candidate).exports, ("aggregate_bulk",))
        self.assertEqual(emit_program_llvm(original).text, emit_program_llvm(normalized).text)

    def test_independent_bytes_and_cleanup_match_full_case_denominator(self):
        checked = verify_program(composite_bulk_program())
        for arguments, failure, expected in COMPOSITE_BULK_CASES:
            with self.subTest(arguments=arguments, failure=failure):
                self.assertEqual(byte_oracle(arguments, failure), expected)
                result = execute_program(checked, "aggregate_bulk", list(arguments), allocation_fail_at=failure)
                self.assertEqual(result["result"], expected)
                self.assertEqual(result["resources"]["live_owners"], 0)
                self.assertEqual(result["resources"]["live_local_loans"], 0)
                self.assertEqual(result["resources"]["allocations"], result["resources"]["frees"])

    def test_each_bounds_stage_traps_and_an_earlier_schema_cannot_accept_v6(self):
        core = verify_program(composite_bulk_program())
        for name, arguments in COMPOSITE_BULK_TRAPS.items():
            with self.subTest(name=name):
                with self.assertRaises(IndexError):
                    byte_oracle(arguments)
                with self.assertRaises(HIAProgramTrap) as caught:
                    execute_program(core, "aggregate_bulk", list(arguments))
                self.assertEqual(caught.exception.code, "bounds")
        for version in range(1, 6):
            older = core.as_dict()
            older["schema"] = "hepta.hia.program.v" + str(version)
            with self.subTest(version=version), self.assertRaises(HIAProgramRejected):
                verify_program(older)

    def test_live_aggregate_loan_cannot_be_bypassed_with_owner_drop(self):
        source = composite_bulk_program()
        work = source["functions"][0]["blocks"][2]
        unpack = next(index for index, instruction in enumerate(work["ops"])
                      if instruction["op"] == "record.unpack")
        work["ops"].insert(unpack + 1, {"op": "owner.drop", "args": ["work_source_owner"], "out": [], "attrs": {}})
        with self.assertRaises(HIAProgramRejected):
            verify_program(source)

    def test_wrong_result_is_a_valid_program_and_not_a_false_static_rejection(self):
        core = verify_program(wrong_result_program())
        self.assertEqual(execute_program(core, "aggregate_bulk", [5, 1, 3, 77, 0])["result"], 10)

    def test_target_artifact_regular_to_fifo_race_fails_without_blocking(self):
        code = r'''
import os
from pathlib import Path
from unittest.mock import patch
from hepta.hia_program_aarch64 import _read, HIAProgramAArch64Rejected
p=Path("artifact");p.write_bytes(b"ordinary bytes")
original=os.open
def race(path,flags,*args,**kwargs):
    if Path(path)==p:
        p.unlink();os.mkfifo(p)
    return original(path,flags,*args,**kwargs)
with patch("hepta.hia_program_aarch64.os.open",race):
    try:_read(p,1024)
    except HIAProgramAArch64Rejected:raise SystemExit(0)
    raise SystemExit(1)
'''
        import os
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory() as directory:
            observed = subprocess.run([sys.executable, "-c", code], cwd=directory, env=env,
                                      capture_output=True, text=True, timeout=3)
            self.assertEqual(observed.returncode, 0, observed.stderr)


@unittest.skipUnless(all(shutil.which(tool) for tool in (CLANG, LINKER, QEMU)),
                     "actual pinned LLVM/lld and AArch64 QEMU required")
class CompositeBulkNativeTests(unittest.TestCase):
    def test_full_native_oracles_and_strict_retained_receipts(self):
        with tempfile.TemporaryDirectory(prefix="hia-composite-bulk-tests-") as directory:
            report = qualify(directory=Path(directory) / "run", clang=CLANG, linker=LINKER, qemu=QEMU)
            self.assertTrue(report["ok"], json.dumps(report.get("error")))
            self.assertEqual(report["counts"], expected_counts())
            self.assertTrue(validate_qualification(report)["ok"])
            for change in ("wrong_count", "hidden_control", "wrong_result", "wrong_log"):
                forged = deepcopy(report)
                forged.pop("record_sha256")
                if change == "wrong_count":
                    forged["counts"]["actual_scalar_abi_calls"] += 1
                elif change == "hidden_control":
                    forged["negative_controls"].pop()
                elif change == "wrong_result":
                    forged["native"]["aarch64"]["composite"]["execution"]["returncode"] = 1
                else:
                    forged["processes"][0]["stdout_sha256"] = "0" * 64
                with self.subTest(change=change), self.assertRaises(ValueError):
                    validate_qualification(forged)


if __name__ == "__main__":
    unittest.main()
