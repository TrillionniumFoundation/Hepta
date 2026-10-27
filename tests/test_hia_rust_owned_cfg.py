"""Executed Rust/Python resource CFG and call parity, including stopped ledgers.

All positive documents pass the canonical Python authority first. This finite
byte-owner runtime remains a development oracle, not production admission.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from tests.test_hia_program import b, c, f, i, m, ret, jump, branch, joined_loan_program
from tests.test_hia_rust_calls_shadow import call_owner, borrowed_call

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"


def loop_bytes():
    """Fallible construction, loop-carried owner/loan, writes and final cleanup."""
    fields = [("owner", "buffer"), ("view", "mutbuf"), ("size", "usize"),
              ("value", "u8"), ("index", "usize"), ("sum", "u8")]
    def parameters(prefix):
        return [(prefix + name, ty) for name, ty in fields]
    def names(prefix):
        return [prefix + name for name, _ in fields]
    return m(f("loop", [("n", "usize"), ("byte", "u8")], ["u8", "bool"],
               ["alloc", "read", "write", "trap"], [
        b("entry", [("n", "usize"), ("byte", "u8")], [
            i("buffer.try_new", ["n"], [("allocated", "buffer"), ("ok", "bool")]),
        ], branch("ok", ("ready", "allocated", "n", "byte"), ("failed", "allocated"))),
        b("failed", [("empty", "buffer")], [
            i("owner.drop", ["empty"]), c("failure_value", "u8", 0),
            c("failure_status", "bool", False),
        ], ret("failure_value", "failure_status")),
        b("ready", [("ready_owner", "buffer"), ("ready_n", "usize"), ("ready_byte", "u8")], [
            i("borrow.mut", ["ready_owner"], [("ready_view", "mutbuf")]),
            c("zero", "usize", 0), c("initial_sum", "u8", 0),
        ], jump("condition", "ready_owner", "ready_view", "ready_n", "ready_byte", "zero", "initial_sum")),
        b("condition", parameters("loop_"), [
            i("compare.lt", ["loop_index", "loop_size"], [("again", "bool")]),
        ], branch("again", ("body", *names("loop_")), ("done", "loop_owner", "loop_view", "loop_sum"))),
        b("body", parameters("body_"), [
            i("buffer.store", ["body_view", "body_index", "body_value"]),
            i("buffer.load", ["body_view", "body_index"], [("loaded", "u8")]),
            i("int.add.wrap", ["body_sum", "loaded"], [("sum_next", "u8")]),
            c("one", "usize", 1),
            i("int.add.checked", ["body_index", "one"], [("index_next", "usize")]),
        ], jump("condition", "body_owner", "body_view", "body_size", "body_value", "index_next", "sum_next")),
        b("done", [("done_owner", "buffer"), ("done_view", "mutbuf"), ("answer", "u8")], [
            i("loan.end", ["done_view"]), i("owner.drop", ["done_owner"]),
            c("success_status", "bool", True),
        ], ret("answer", "success_status")),
    ]))


def replace_owner():
    """A failed replacement returns the original owner; success destroys it."""
    replacement = f("replace", [("old", "buffer"), ("requested", "usize")],
                    ["buffer", "bool"], ["alloc"], [
        b("replace_entry", [("old", "buffer"), ("requested", "usize")], [
            i("buffer.try_new", ["requested"], [("new", "buffer"), ("ok", "bool")]),
        ], branch("ok", ("accepted", "old", "new"), ("recovered", "old", "new"))),
        b("accepted", [("old_good", "buffer"), ("new_good", "buffer")], [
            i("owner.drop", ["old_good"]), c("accepted_status", "bool", True),
        ], ret("new_good", "accepted_status")),
        b("recovered", [("old_back", "buffer"), ("empty", "buffer")], [
            i("owner.drop", ["empty"]), c("recovered_status", "bool", False),
        ], ret("old_back", "recovered_status")),
    ])
    caller = f("replace_probe", [("first_size", "usize"), ("next_size", "usize")],
               ["usize", "bool"], ["alloc", "trap"], [
        b("entry", [("first_size", "usize"), ("next_size", "usize")], [
            i("buffer.new", ["first_size"], [("first", "buffer")]),
            i("call", ["first", "next_size"], [("final", "buffer"), ("changed", "bool")], function="replace"),
            i("buffer.len", ["final"], [("length", "usize")]),
            i("owner.drop", ["final"]),
        ], ret("length", "changed")),
    ])
    return m(replacement, caller)


def recursive_owner():
    params = [("owned", "buffer"), ("remaining", "usize")]
    relay = f("relay", params, ["buffer"], ["trap"], [
        b("relay_entry", params, [
            c("zero", "usize", 0),
            i("compare.eq", ["remaining", "zero"], [("finished", "bool")]),
        ], branch("finished", ("returned", "owned"), ("recurse", "owned", "remaining"))),
        b("returned", [("returned_owner", "buffer")], [], ret("returned_owner")),
        b("recurse", [("recursive_owner", "buffer"), ("count", "usize")], [
            c("one", "usize", 1),
            i("int.sub.checked", ["count", "one"], [("next_count", "usize")]),
            i("call", ["recursive_owner", "next_count"], [("relayed", "buffer")], function="relay"),
        ], ret("relayed")),
    ])
    caller = f("recursion_probe", [("depth", "usize")], ["usize"], ["alloc", "trap"], [
        b("entry", [("depth", "usize")], [
            c("size", "usize", 3), i("buffer.new", ["size"], [("owner", "buffer")]),
            i("call", ["owner", "depth"], [("after", "buffer")], function="relay"),
            i("buffer.len", ["after"], [("length", "usize")]), i("owner.drop", ["after"]),
        ], ret("length")),
    ])
    return m(relay, caller)


def aliased_read_call():
    """Two shared formal loans may denote one caller loan, including a reborrow."""
    params = [("left", "readbuf"), ("right", "readbuf")]
    reader = f("read_twice", params, ["u8"], ["read", "trap"], [
        b("reader_entry", params, [
            i("borrow.read", ["left"], [("child", "readbuf")]),
            c("zero", "usize", 0),
            i("buffer.load", ["right", "zero"], [("a", "u8")]),
            i("buffer.load", ["child", "zero"], [("z", "u8")]),
            i("loan.end", ["child"]),
            i("int.add.wrap", ["a", "z"], [("sum", "u8")]),
        ], ret("sum")),
    ])
    caller = f("alias_probe", [("value", "u8")], ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", [("value", "u8")], [
            c("size", "usize", 1), c("index", "usize", 0),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("parent", "mutbuf")]),
            i("buffer.store", ["parent", "index", "value"]),
            i("call", ["parent", "parent"], [("answer", "u8")], function="read_twice"),
            i("loan.end", ["parent"]), i("owner.drop", ["owner"]),
        ], ret("answer")),
    ])
    return m(reader, caller)


@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable: resource CFG execution NOT qualified")
class RustByteOwnerCfgParity(unittest.TestCase):
    observations = []
    sources = {}

    @classmethod
    def setUpClass(cls):
        built = subprocess.run(["cargo", "build", "--locked", "--offline", "--message-format=json",
                                "--manifest-path", str(MANIFEST)],
                               cwd=ROOT, capture_output=True, text=True, timeout=240)
        if built.returncode:
            raise AssertionError("Rust build failed:\n" + built.stderr[-6000:])
        paths = [item["executable"] for line in built.stdout.splitlines()
                 if (item := json.loads(line)).get("reason") == "compiler-artifact"
                 and item.get("executable")
                 and "bin" in item.get("target", {}).get("kind", [])]
        if len(paths) != 1:
            raise AssertionError("Cargo did not identify exactly one Rust executable")
        cls.executable = paths[0]
        cls.observations = []
        cls.sources = {}

    @classmethod
    def tearDownClass(cls):
        print(f"Rust byte-owner CFG/Python full-ledger parity observations: {len(cls.observations)}")

    def raw_run(self, raw, entry, arguments, *, steps=1000, heap=1024, fail=None):
        return subprocess.run([self.executable, "--owned-run", entry,
                               json.dumps(arguments, separators=(",", ":")), str(steps), str(heap),
                               "none" if fail is None else str(fail)], input=raw, cwd=ROOT,
                              capture_output=True, timeout=15, check=False)

    def parity(self, document, entry, arguments, *, steps=1000, heap=1024, fail=None):
        canonical = verify_program(document)
        result = self.raw_run(canonical.canonical_bytes, entry, arguments, steps=steps, heap=heap, fail=fail)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stderr, b"")
        rust = json.loads(result.stdout)
        try:
            python = execute_program(canonical, entry, arguments, max_steps=steps,
                                     max_heap_bytes=heap, allocation_fail_at=fail, max_call_depth=32)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
            python = stopped.report
        self.assertEqual(rust["profile"], "bounded-cfg-byte-owner-v2")
        self.assertEqual(rust["program_sha256"], canonical.sha256)
        for field in ("status", "steps", "resources"):
            self.assertEqual(rust[field], python[field], field)
        self.assertIs(rust["claims"]["production_admission_authorized"], False)
        self.assertIs(rust["claims"]["native_backend_refinement_proved"], False)
        self.assertIs(rust["claims"]["general_resource_execution"], False)
        if python["status"] == "returned":
            self.assertEqual(rust["values"], python["values"])
            self.assertEqual(rust["resources"]["live_owners"], 0)
            self.assertEqual(rust["resources"]["live_local_loans"], 0)
        else:
            self.assertEqual(rust["error"]["code"], python["error"]["code"])
            self.assertNotIn("values", rust)
        type(self).sources[canonical.sha256] = canonical.as_dict()
        type(self).observations.append({"entry": entry, "arguments": arguments,
            "policy": {"max_steps": steps, "max_heap_bytes": heap, "allocation_fail_at": fail,
                       "max_call_depth": 32}, "rust": rust, "python": python})
        return rust

    def test_loop_carried_owner_loan_values_and_failure_branch(self):
        for version in range(1, 8):
            source = loop_bytes()
            source["schema"] = f"hepta.hia.program.v{version}"
            for size, value in ((0, 255), (1, 0), (3, 87), (7, 255)):
                for fail in (None, 1):
                    with self.subTest(version=version, size=size, value=value, fail=fail):
                        report = self.parity(source, "loop", [size, value], fail=fail)
                        success = fail is None or size == 0
                        self.assertEqual(report["values"], [(size * value) % 256 if success else 0, success])

    def test_branch_join_keeps_loan_root_and_empty_helpers_are_supported(self):
        for condition in (False, True):
            source = joined_loan_program()
            source["functions"].append(f("uncalled", [], [], [], [b("unused_entry", [], [], ret())]))
            self.parity(source, "join", [condition])
        for size in (0, 4, 2**63):
            for fail in (None, 1):
                self.parity(call_owner(), "use", [size], fail=fail)
        self.parity(borrowed_call(), "outer", [])

    def test_owner_consuming_call_returns_real_owner_after_failure_or_success(self):
        for sizes in ((0, 0), (0, 5), (3, 0), (3, 5), (3, 2**63)):
            for fail in (None, 1, 2, 3):
                with self.subTest(sizes=sizes, fail=fail):
                    self.parity(replace_owner(), "replace_probe", list(sizes), fail=fail)
        for heap in (0, 2, 3, 7, 8):
            for fail in (None, 1, 2):
                self.parity(replace_owner(), "replace_probe", [3, 5], heap=heap, fail=fail)

    def test_readonly_call_alias_and_nested_reborrow_resume(self):
        for value in (0, 1, 127, 128, 255):
            report = self.parity(aliased_read_call(), "alias_probe", [value])
            self.assertEqual(report["values"], [(2 * value) % 256])
            self.assertEqual(report["resources"]["loans_started"], 2)
            self.assertEqual(report["resources"]["loans_ended"], 2)

    def test_recursive_owner_return_and_exact_call_depth_stop(self):
        for depth in (0, 1, 5, 30, 31, 32, 200):
            report = self.parity(recursive_owner(), "recursion_probe", [depth])
            if depth <= 30:
                self.assertEqual(report["values"], [3])
                self.assertEqual(report["resources"]["frees"], 1)
            else:
                self.assertEqual(report["error"]["code"], "calls")
                self.assertEqual(report["resources"]["live_owners"], 1)
                self.assertEqual(report["resources"]["frees"], 0)

    def test_every_executed_step_cut_retains_actual_resource_state(self):
        for document, entry, args in ((loop_bytes(), "loop", [2, 93]),
                                      (replace_owner(), "replace_probe", [3, 5]),
                                      (aliased_read_call(), "alias_probe", [7])):
            success = self.parity(document, entry, args)
            for cut in range(1, success["steps"] + 1):
                with self.subTest(entry=entry, cut=cut):
                    self.parity(document, entry, args, steps=cut)

    def test_internal_traps_do_not_claim_owner_or_loan_cleanup(self):
        for code in ("user", "bounds", "allocation", "overflow", "division_by_zero"):
            source = aliased_read_call()
            reader = source["functions"][0]["blocks"][0]
            reader["ops"] = reader["ops"][:1]
            reader["term"] = {"op": "trap", "code": code}
            report = self.parity(source, "alias_probe", [42])
            self.assertEqual(report["error"]["code"], code)
            self.assertEqual(report["resources"]["live_local_loans"], 2)
            self.assertEqual(report["resources"]["owners_dropped"], 0)

    def test_hidden_bulk_or_chain_reject_before_entry_allocation_failure(self):
        for kind in ("bulk", "chain"):
            source = call_owner()
            source["schema"] = "hepta.hia.program.v7"
            source["exports"] = ["use"]
            helper = (f("hidden", [("loan", "mutbuf"), ("byte", "u8")], [], ["write"], [
                        b("hidden_entry", [("loan", "mutbuf"), ("byte", "u8")],
                          [i("buffer.fill", ["loan", "byte"])], ret())])
                      if kind == "bulk" else
                      f("hidden", [("list", "chain")], [], ["trap"], [
                          b("hidden_entry", [("list", "chain")], [], {"op": "trap", "code": "user"})]))
            source["functions"].append(helper)
            canonical = verify_program(source)
            result = self.raw_run(canonical.canonical_bytes, "use", [4], steps=1, fail=1)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertTrue(result.stderr.startswith(b"E_HIA_RUST_UNSUPPORTED:"), result.stderr)

    def test_resource_signatures_remain_internal_before_execution(self):
        source = call_owner()
        canonical = verify_program(source)
        result = self.raw_run(canonical.canonical_bytes, "maker", [4], steps=1, heap=0)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertTrue(result.stderr.startswith(b"E_HIA_INPUT:"), result.stderr)
        source["exports"] = ["use"]
        result = self.raw_run(verify_program(source).canonical_bytes, "maker", [4])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_double_transfer_bad_loan_join_and_mutable_call_alias_reject(self):
        invalid = []
        source = replace_owner()
        source["functions"][1]["blocks"][0]["ops"].append(i("owner.drop", ["first"]))
        invalid.append(source)
        source = joined_loan_program()
        source["functions"][0]["blocks"][0]["term"]["else"]["args"] = ["z", "a", "view"]
        invalid.append(source)
        source = aliased_read_call()
        reader = source["functions"][0]
        for param in reader["params"] + reader["blocks"][0]["params"]:
            param["type"] = "mutbuf"
        invalid.append(source)
        for source in invalid:
            with self.assertRaises(HIAProgramRejected):
                verify_program(source)
            result = self.raw_run(json.dumps(source).encode(), "not_run", [], steps=1)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
