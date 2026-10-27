"""Actual Rust byte-owner execution against canonical Python operations/ledgers.

This finite single-block shadow is not production admission or native LLVM
qualification. Every positive source passes the Python Core verifier first.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import (
    HIAProgramBudgetExceeded, HIAProgramTrap, execute_program,
)
from tests.test_hia_program import b, c, f, i, m, ret, resource_program, joined_loan_program

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"


def optional_pair():
    return m(f("pair", [("a", "usize"), ("b", "usize")],
               ["usize", "usize", "bool", "bool"], ["alloc"], [
        b("entry", [("a", "usize"), ("b", "usize")], [
            i("buffer.try_new", ["a"], [("first", "buffer"), ("first_ok", "bool")]),
            i("buffer.try_new", ["b"], [("second", "buffer"), ("second_ok", "bool")]),
            i("buffer.len", ["first"], [("first_len", "usize")]),
            i("buffer.len", ["second"], [("second_len", "usize")]),
            i("owner.drop", ["second"]), i("owner.drop", ["first"]),
        ], ret("first_len", "second_len", "first_ok", "second_ok"))]))


def reborrowed_bytes():
    params = [("size", "usize"), ("write_at", "usize"),
              ("read_at", "usize"), ("value", "u8")]
    return m(f("probe", params, ["u8", "usize"], ["alloc", "read", "write", "trap"], [
        b("entry", params, [
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("parent", "mutbuf")]),
            i("borrow.mut", ["parent"], [("writer", "mutbuf")]),
            i("buffer.store", ["writer", "write_at", "value"]),
            i("loan.end", ["writer"]),
            i("borrow.read", ["parent"], [("reader", "readbuf")]),
            i("buffer.load", ["reader", "read_at"], [("answer", "u8")]),
            # Length is an observation of the underlying owner; the Python
            # grammar allows it on a suspended parent without byte access.
            i("buffer.len", ["parent"], [("length", "usize")]),
            i("loan.end", ["reader"]), i("loan.end", ["parent"]),
            i("owner.move", ["owner"], [("moved", "buffer")]),
            i("owner.drop", ["moved"]),
        ], ret("answer", "length"))]))


@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable: Rust owned VM NOT qualified")
class RustByteOwnerVmParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        built = subprocess.run(
            ["cargo", "build", "--locked", "--offline", "--message-format=json",
             "--manifest-path", str(MANIFEST)],
            cwd=ROOT, capture_output=True, text=True, timeout=240, check=False)
        if built.returncode:
            raise AssertionError("Actual Rust owned VM build failed:\n" + built.stderr[-6000:])
        paths = [item["executable"] for line in built.stdout.splitlines()
                 if (item := json.loads(line)).get("reason") == "compiler-artifact"
                 and item.get("executable")
                 and "bin" in item.get("target", {}).get("kind", [])]
        if len(paths) != 1:
            raise AssertionError("Cargo did not identify exactly one Rust executable")
        cls.executable = paths[0]
        cls.parity_observations = 0

    @classmethod
    def tearDownClass(cls):
        print(f"Rust byte-owner/Python full-ledger parity observations: {cls.parity_observations}")

    def raw_run(self, raw, entry, arguments, *, steps=1000, heap=1024, fail=None,
                mode="--owned-run"):
        command = [self.executable, mode, entry, json.dumps(arguments, separators=(",", ":"))]
        command += ([str(steps)] if mode == "--scalar-run" else
                    [str(steps), str(heap), "none" if fail is None else str(fail)])
        return subprocess.run(command, input=raw, cwd=ROOT, capture_output=True,
                              timeout=15, check=False)

    def parity(self, document, entry, arguments, *, steps=1000, heap=1024, fail=None):
        canonical = verify_program(document)
        result = self.raw_run(canonical.canonical_bytes, entry, arguments,
                              steps=steps, heap=heap, fail=fail)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stderr, b"")
        rust = json.loads(result.stdout)
        try:
            python = execute_program(canonical, entry, arguments,
                                     max_steps=steps, max_heap_bytes=heap,
                                     allocation_fail_at=fail, max_call_depth=32)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
            python = stopped.report
        self.assertEqual(rust["schema"], "hepta.hia.rust-byte-owner-execution.v1")
        self.assertEqual(rust["program_sha256"], canonical.sha256)
        self.assertEqual(rust["status"], python["status"])
        self.assertEqual(rust["steps"], python["steps"])
        # Compare EVERY field and the exact inventory, not a digest/summary.
        self.assertEqual(rust["resources"], python["resources"])
        self.assertIs(rust["claims"]["production_admission_authorized"], False)
        self.assertIs(rust["claims"]["native_backend_refinement_proved"], False)
        if python["status"] == "returned":
            self.assertEqual(rust["values"], python["values"])
            self.assertEqual(rust["resources"]["live_owners"], 0)
            self.assertEqual(rust["resources"]["live_local_loans"], 0)
        else:
            self.assertEqual(rust["error"]["code"], python["error"]["code"])
            self.assertNotIn("values", rust)
        type(self).parity_observations += 1
        return rust

    def test_real_owner_move_drop_and_scalar_mode_stays_closed(self):
        for version in range(1, 8):
            source = resource_program()
            source["schema"] = f"hepta.hia.program.v{version}"
            for size, value in ((1, 0), (1, 255), (17, 93)):
                with self.subTest(version=version, size=size, value=value):
                    result = self.parity(source, "owned", [size, value])
                    self.assertEqual(result["values"], [value])
                    self.assertEqual(result["resources"]["allocations"], 1)
                    self.assertEqual(result["resources"]["frees"], 1)
                    self.assertEqual(result["resources"]["loans_started"], 2)
            scalar = self.raw_run(verify_program(source).canonical_bytes, "owned", [1, 2],
                                  mode="--scalar-run")
            self.assertNotEqual(scalar.returncode, 0)
            self.assertEqual(scalar.stdout, b"")

    def test_every_small_byte_offset_and_reborrow_resume(self):
        source = reborrowed_bytes()
        for size in (1, 2, 4):
            for write_at in range(size):
                for read_at in range(size):
                    for value in (0, 255):
                        with self.subTest(size=size, write=write_at, read=read_at, value=value):
                            result = self.parity(source, "probe", [size, write_at, read_at, value])
                            self.assertEqual(result["values"],
                                             [value if write_at == read_at else 0, size])
                            self.assertEqual(result["resources"]["loans_ended"], 3)

    def test_optional_allocations_fail_positions_and_zero_size(self):
        for sizes in ((0, 0), (0, 4), (4, 0), (3, 5)):
            for fail in (None, 1, 2, 3):
                with self.subTest(sizes=sizes, fail=fail):
                    report = self.parity(optional_pair(), "pair", list(sizes), fail=fail)
                    self.assertEqual(report["resources"]["owners_created"], 2)
                    self.assertEqual(report["resources"]["owners_dropped"], 2)
        oversized = self.parity(optional_pair(), "pair", [2**63, 2], fail=1)
        self.assertEqual(oversized["values"], [0, 0, False, False])
        self.assertEqual(oversized["resources"]["allocation_attempts"], 1)

    def test_live_peak_budget_precedes_allocator_failure(self):
        for heap in (0, 2, 3, 7, 8):
            for fail in (None, 1, 2):
                with self.subTest(heap=heap, fail=fail):
                    self.parity(optional_pair(), "pair", [3, 5], heap=heap, fail=fail)
        result = self.parity(optional_pair(), "pair", [3, 5], heap=7)
        self.assertEqual(result["error"]["code"], "heap")
        self.assertEqual(result["resources"]["allocation_attempts"], 1)
        self.assertEqual(result["resources"]["live_bytes"], 3)
        self.assertEqual(result["resources"]["frees"], 0)

    def test_every_step_boundary_preserves_stopped_resource_state(self):
        for steps in range(1, 15):
            with self.subTest(steps=steps):
                self.parity(resource_program(), "owned", [3, 72], steps=steps)

    def test_bounds_allocation_and_explicit_traps_do_not_invent_cleanup(self):
        for args in ([0, 0, 0, 7], [3, 3, 0, 7], [3, 0, 3, 7],
                     [3, 2**64 - 1, 0, 7], [3, 0, 2**64 - 1, 7]):
            with self.subTest(args=args):
                stopped = self.parity(reborrowed_bytes(), "probe", args)
                self.assertEqual(stopped["error"]["code"], "bounds")
                self.assertEqual(stopped["resources"]["frees"], 0)
        for size, fail in ((4, 1), (2**63, None), (2**64 - 1, None)):
            self.parity(resource_program(), "owned", [size, 9], fail=fail)
        for code in ("user", "bounds", "allocation", "overflow", "division_by_zero"):
            source = resource_program()
            source["functions"][0]["blocks"][0]["ops"] = source["functions"][0]["blocks"][0]["ops"][:2]
            source["functions"][0]["blocks"][0]["term"] = {"op": "trap", "code": code}
            stopped = self.parity(source, "owned", [2, 7])
            self.assertEqual(stopped["resources"]["live_owners"], 1)
            self.assertEqual(stopped["resources"]["live_local_loans"], 1)

    def test_scalar_trap_while_owner_live_keeps_the_ledger(self):
        source = resource_program()
        ops = source["functions"][0]["blocks"][0]["ops"]
        ops[1:1] = [c("large", "u8", 255), c("one", "u8", 1),
                    i("int.add.checked", ["large", "one"], [("overflowed", "u8")])]
        stopped = self.parity(source, "owned", [2, 9])
        self.assertEqual(stopped["error"]["code"], "overflow")
        self.assertEqual(stopped["resources"]["live_bytes"], 2)
        self.assertEqual(stopped["resources"]["owners_dropped"], 0)

    def test_unsupported_whole_program_refuses_before_any_execution(self):
        variants = []
        bulk = resource_program()
        bulk["schema"] = "hepta.hia.program.v2"
        bulk["functions"][0]["blocks"][0]["ops"].insert(
            2, i("buffer.fill", ["writer", "value"]))
        variants.append((bulk, "owned", [4, 7]))
        recursive = resource_program()
        recursive["functions"][0]["blocks"][0]["ops"].insert(
            1, i("call", ["n", "value"], [("recursive", "u8")], function="owned"))
        variants.append((recursive, "owned", [4, 7]))
        hidden = resource_program()
        hidden["exports"] = ["owned"]
        hidden["functions"].append(f("hidden", [], [], [], [b("hidden_entry", [], [], ret())]))
        variants.append((hidden, "owned", [4, 7]))
        variants.append((joined_loan_program(), "join", [True]))
        for source, entry, args in variants:
            raw = verify_program(source).canonical_bytes
            result = self.raw_run(raw, entry, args, fail=1)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(result.stderr.startswith(b"E_HIA_RUST_UNSUPPORTED:"), result.stderr)
            self.assertEqual(result.stdout, b"")
        chain = (ROOT / "examples/hia_recursive_chain/core_v7.json").read_bytes()
        nominal = (ROOT / "examples/hia_program/generic_owned_enum.hia").read_bytes()
        verify_program(nominal)
        # Primitive chain reaches the execution profile and is unsupported;
        # a raw nominal document is outside the existing strict Rust schema.
        for raw, entry, error in (
            (chain, "chain_probe", b"E_HIA_RUST_UNSUPPORTED:"),
            (nominal, "probe", b"E_HIA_FORMAT:"),
        ):
            result = self.raw_run(raw, entry, [])
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(result.stderr.startswith(error), result.stderr)
            self.assertEqual(result.stdout, b"")

    def test_wrong_types_exports_and_illegal_loans_cannot_enter_machine(self):
        raw = verify_program(resource_program()).canonical_bytes
        for args in ([True, 7], [1, 256], [1, "7"], [{"owner": 1}, 7]):
            result = self.raw_run(raw, "owned", args)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
        source = resource_program()
        source["exports"] = []
        result = self.raw_run(verify_program(source).canonical_bytes, "owned", [1, 2])
        self.assertNotEqual(result.returncode, 0)
        for mutation in ("drop_borrowed", "access_parent", "double_drop", "return_loan"):
            invalid = reborrowed_bytes()
            ops = invalid["functions"][0]["blocks"][0]["ops"]
            if mutation == "drop_borrowed": ops.insert(3, i("owner.drop", ["owner"]))
            elif mutation == "access_parent": ops[3]["args"][0] = "parent"
            elif mutation == "double_drop": ops.append(i("owner.drop", ["moved"]))
            else:
                invalid["functions"][0]["returns"] = ["readbuf"]
                invalid["functions"][0]["blocks"][0]["term"] = ret("reader")
            with self.assertRaises(HIAProgramRejected): verify_program(invalid)
            result = self.raw_run(json.dumps(invalid).encode(), "probe", [1, 0, 0, 7])
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")

    def test_policy_limits_fail_closed(self):
        raw = verify_program(resource_program()).canonical_bytes
        for policy in ({"steps": 0}, {"steps": 1_000_001},
                       {"heap": 16 * 1024 * 1024 + 1}, {"fail": 0}):
            result = self.raw_run(raw, "owned", [1, 7], **policy)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(result.stderr.startswith(b"E_HIA_BUDGET_POLICY:"), result.stderr)
            self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
