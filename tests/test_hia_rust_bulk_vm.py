"""Actual Rust/Python bulk-memory execution with exact stopped/success ledgers."""
from copy import deepcopy
import json
import shutil
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from tests import test_hia_rust_owned_cfg as cfg
from tests.test_hia_program import b, c, f, i, m, ret
from tests.test_hia_bulk_memory import bulk_program
from tests.test_hia_overlap_move import move_program, empty_program
from tests.test_hia_swap_v4 import swap_program
from tests.test_hia_offset_copy_v5 import copy_program
from tests.test_hia_range_fill_v6 import fill_program


def copy_large():
    params = [("size", "usize"), ("dst", "usize"), ("src", "usize"),
              ("count", "usize"), ("probe", "usize")]
    source = m(f("large_copy", params, ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", params, [
            i("buffer.new", ["size"], [("destination", "buffer")]),
            i("buffer.new", ["size"], [("source", "buffer")]),
            i("borrow.mut", ["source"], [("source_writer", "mutbuf")]),
            c("byte", "u8", 57), i("buffer.fill", ["source_writer", "byte"]),
            i("loan.end", ["source_writer"]),
            i("borrow.read", ["source"], [("reader", "readbuf")]),
            i("borrow.mut", ["destination"], [("writer", "mutbuf")]),
            i("buffer.copy_range", ["writer", "reader", "dst", "src", "count"]),
            i("buffer.load", ["writer", "probe"], [("answer", "u8")]),
            i("loan.end", ["reader"]), i("loan.end", ["writer"]),
            i("owner.drop", ["source"]), i("owner.drop", ["destination"]),
        ], ret("answer"))]))
    source["schema"] = "hepta.hia.program.v5"
    return source


def through_borrowed_helpers(document):
    """Move each bulk instruction into a call-scoped direct mutable reborrow."""
    source = deepcopy(document)
    outer = source["functions"][0]
    types = {p["name"]: p["type"] for p in outer["params"]}
    for block in outer["blocks"]:
        for op in block["ops"]:
            types.update({p["name"]: p["type"] for p in op["out"]})
        for index, op in enumerate(block["ops"]):
            if op["op"] not in {"buffer.fill", "buffer.copy", "buffer.move_within", "buffer.swap",
                                "buffer.copy_range", "buffer.fill_range"}:
                continue
            name = "bulk_helper_" + str(len(source["functions"]))
            params = [("arg" + str(n), types[arg]) for n, arg in enumerate(op["args"])]
            args = [name for name, _ in params]
            helper = f(name, params, [], outer["effects"], [b("helper_entry", params, [
                i("borrow.mut", [args[0]], [("child", "mutbuf")]),
                i(op["op"], ["child", *args[1:]]), i("loan.end", ["child"]),
            ], ret())])
            source["functions"].append(helper)
            block["ops"][index] = i("call", op["args"], function=name)
    return source


@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable: Rust bulk execution NOT qualified")
class RustByteOwnerBulkParity(unittest.TestCase):
    setUpClass = classmethod(cfg.RustByteOwnerCfgParity.setUpClass.__func__)
    raw_run = cfg.RustByteOwnerCfgParity.raw_run
    parity = cfg.RustByteOwnerCfgParity.parity
    observations = []
    sources = {}

    @classmethod
    def tearDownClass(cls):
        print(f"Rust byte-owner bulk/Python full-ledger parity observations: {len(cls.observations)}")

    def test_fill_and_copy_obey_each_admitting_schema(self):
        for version in range(2, 8):
            source = bulk_program(f"hepta.hia.program.v{version}")
            for size, count, byte in ((1, 1, 255), (7, 3, 91), (7, 0, 91), (0, 0, 3)):
                report = self.parity(source, "bulk", [size, count, byte])
                if size:
                    self.assertEqual(report["values"], [byte if count else 0])
                else:
                    self.assertEqual(report["error"]["code"], "bounds")

    def test_overlap_moves_snapshot_the_source_in_both_directions(self):
        original = [11, 22, 33, 44, 55]
        for dst, src, count in ((1, 0, 4), (0, 1, 4), (0, 0, 5), (5, 5, 0)):
            expected = original.copy()
            expected[dst:dst + count] = original[src:src + count]
            for probe, answer in enumerate(expected):
                report = self.parity(move_program(), "move_bytes", [5, dst, src, count, probe])
                self.assertEqual(report["values"], [answer])
        self.assertEqual(self.parity(empty_program(), "empty", [0])["values"], [42])

    def test_swap_and_offset_copy_compare_every_observed_byte(self):
        original = [11, 22, 33, 44, 55]
        for left, right in ((0, 4), (4, 0), (2, 2)):
            expected = original.copy()
            expected[left], expected[right] = expected[right], expected[left]
            for probe, answer in enumerate(expected):
                self.assertEqual(self.parity(swap_program(), "swap_bytes", [5, left, right, probe])["values"], [answer])
        for dst, src, count in ((0, 0, 5), (1, 2, 2), (2, 1, 2), (5, 5, 0)):
            expected = [0] * 5
            expected[dst:dst + count] = original[src:src + count]
            for probe, answer in enumerate(expected):
                self.assertEqual(self.parity(copy_program(), "copy_offset", [5, dst, src, count, probe])["values"], [answer])

    def test_range_fill_accepts_exact_end_and_checks_empty_extents(self):
        for offset, count in ((0, 5), (1, 3), (5, 0)):
            for probe in range(5):
                report = self.parity(fill_program(), "fill_range", [5, offset, count, 177, probe])
                self.assertEqual(report["values"], [177 if offset <= probe < offset + count else 0])
        self.assertEqual(self.parity(fill_program(read=False), "fill_range", [0, 0, 0, 7, 0])["values"], [9])
        for args in ((0, 1, 0, 7, 0), (5, 6, 0, 7, 0), (5, 4, 2, 7, 0), (5, 2, 2**64-1, 7, 0)):
            self.assertEqual(self.parity(fill_program(read=False), "fill_range", list(args))["error"]["code"], "bounds")

    def test_cross_chunk_copy_and_allocation_failure_keep_exact_ledgers(self):
        source = copy_large()
        for dst, src, count in ((2, 1, 8200), (8204, 8204, 0)):
            for probe in (0, 1, 2, 4095, 4096, 4097, 8191, 8201, 8202, 8203):
                report = self.parity(source, "large_copy", [8204, dst, src, count, probe], heap=20000)
                self.assertEqual(report["values"], [57 if dst <= probe < dst + count else 0])
                self.assertEqual(report["resources"]["allocations"], 2)
                self.assertEqual(report["resources"]["frees"], 2)
                self.assertEqual(report["resources"]["peak_bytes"], 16408)
        for fail in (1, 2, 3):
            self.parity(source, "large_copy", [8204, 2, 1, 8200, 4096], heap=20000, fail=fail)
        for heap in (0, 8203, 8204, 16407, 16408):
            self.parity(source, "large_copy", [8204, 2, 1, 8200, 4096], heap=heap)

    def test_all_six_bulk_operations_compose_with_calls_and_reborrows(self):
        cases = ((bulk_program(), "bulk", [7, 7, 87]),
                 (move_program(), "move_bytes", [5, 1, 0, 4, 4]),
                 (swap_program(), "swap_bytes", [5, 0, 4, 0]),
                 (copy_program(), "copy_offset", [5, 1, 2, 2, 1]),
                 (fill_program(), "fill_range", [5, 1, 3, 77, 2]))
        for source, entry, args in cases:
            wrapped = through_borrowed_helpers(source)
            success = self.parity(wrapped, entry, args)
            for cut in range(1, success["steps"] + 1):
                self.parity(wrapped, entry, args, steps=cut)

    def test_bulk_in_loop_carried_loan_and_fallible_branch(self):
        source = cfg.loop_bytes()
        source["schema"] = "hepta.hia.program.v7"
        body = next(block for block in source["functions"][0]["blocks"] if block["id"] == "body")
        body["ops"][0] = i("buffer.fill", ["body_view", "body_value"])
        for size in (0, 1, 4):
            for fail in (None, 1):
                report = self.parity(source, "loop", [size, 73], fail=fail)
                ok = fail is None or size == 0
                self.assertEqual(report["values"], [(size * 73) % 256 if ok else 0, ok])

    def test_bounds_including_u64_max_preserve_stopped_resources(self):
        maximum = 2**64 - 1
        cases = [(bulk_program(), "bulk", [5, maximum, 7]),
                 (move_program(), "move_bytes", [5, maximum, 0, 0, 0]),
                 (move_program(), "move_bytes", [5, 0, maximum, 0, 0]),
                 (move_program(), "move_bytes", [5, 0, 0, maximum, 0]),
                 (swap_program(), "swap_bytes", [5, 0, maximum, 0]),
                 (swap_program(), "swap_bytes", [5, maximum, 0, 0]),
                 (copy_program(), "copy_offset", [5, maximum, 0, 0, 0]),
                 (copy_program(), "copy_offset", [5, 0, maximum, 0, 0]),
                 (copy_program(), "copy_offset", [5, 0, 0, maximum, 0]),
                 (fill_program(read=False), "fill_range", [5, maximum, 0, 7, 0])]
        for source, entry, args in cases:
            report = self.parity(source, entry, args)
            self.assertEqual(report["error"]["code"], "bounds")
            self.assertGreater(report["resources"]["live_owners"], 0)
            self.assertEqual(report["resources"]["frees"], 0)

    def test_version_types_effects_alias_and_future_schema_refuse_before_execution(self):
        old = [(bulk_program(), 1), (move_program(), 2), (swap_program(), 3),
               (copy_program(), 4), (fill_program(), 5)]
        for source, version in old:
            source["schema"] = f"hepta.hia.program.v{version}"
            with self.assertRaises(HIAProgramRejected):
                verify_program(source)
            result = self.raw_run(json.dumps(source).encode(), "not_entered", [], fail=1, steps=1)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
        invalid = []
        source = bulk_program(); source["functions"][0]["effects"].remove("write"); invalid.append(source)
        source = bulk_program(); source["functions"][0]["blocks"][0]["ops"][7]["args"] = ["target", "target", "count"]; invalid.append(source)
        source = fill_program(); source["functions"][0]["blocks"][0]["ops"][2]["args"][1] = "value"; invalid.append(source)
        for source in invalid:
            with self.assertRaises(HIAProgramRejected): verify_program(source)
            result = self.raw_run(json.dumps(source).encode(), "not_entered", [], steps=1)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
        source = bulk_program(); source["schema"] = "hepta.hia.program.v9"
        result = self.raw_run(json.dumps(source).encode(), "bulk", [1, 1, 7], steps=1, fail=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.startswith(b"E_HIA_SCHEMA:"), result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_uncalled_bulk_helper_is_admitted_without_execution(self):
        source = cfg.call_owner()
        source["schema"] = "hepta.hia.program.v2"
        source["functions"].append(f("unused_fill", [("loan", "mutbuf"), ("byte", "u8")], [], ["write"], [
            b("unused_entry", [("loan", "mutbuf"), ("byte", "u8")], [i("buffer.fill", ["loan", "byte"])], ret())]))
        report = self.parity(source, "use", [3])
        self.assertEqual(report["values"], [3, True])


if __name__ == "__main__":
    unittest.main()
