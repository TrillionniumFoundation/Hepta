"""Finite source/nominal -> canonical Core -> Python/actual Rust resource parity.

Only canonical v1-v7 operations are executed. Source projection-borrow helpers
are inlined by the existing frontend; primitive cross-call Loan returns remain
rejected. Full reports, original inputs and negative admissions are retained by
tools/qualify_hia_rust_owned_memory.py. This corpus grants no production authority.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from tests.test_hia_program import b, branch, c, f, i, m, ret
from tests.test_hia_bulk_memory import bulk_program
from tests.test_hia_offset_copy_v5 import copy_program
from tests.test_hia_overlap_move import move_program
from tests.test_hia_range_fill_v6 import fill_program
from tests.test_hia_swap_v4 import swap_program
from tests.test_hia_zero_length_bulk_native import zero_bulk_program
from tests.test_hia_program_composite import (
    stored_loan_program, enum_owner_program, task_program,
    scalar_task_program, owned_result_task_program,
)
from tests.test_hia_composite_v6_resources import composite_bulk_program, composite_range_task_program
from tests.test_hia_recursive_chain import one_function

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust/hia-core-shadow/Cargo.toml"
MAX_U64 = (1 << 64) - 1
EXTENDED = {"buffer.fill", "buffer.copy", "buffer.move_within", "buffer.fill_range",
            "buffer.copy_range", "buffer.swap", "chain.empty", "chain.try_push",
            "chain.pop", "chain.is_empty", "chain.head_read", "chain.head_mut"}


def chain_extent():
    document = m(f("extent", [("size", "usize")], ["usize"], ["alloc"], [
        b("entry", [("size", "usize")], [
            i("buffer.try_new", ["size"], [("payload", "buffer"), ("allocated", "bool")]),
            i("chain.empty", out=[("empty", "chain")]),
            i("chain.try_push", ["empty", "payload"],
              [("built", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
            i("owner.move", ["built"], [("moved", "chain")]),
            i("chain.pop", ["moved"], [("rest", "chain"), ("popped", "buffer"), ("present", "bool")]),
            i("buffer.len", ["popped"], [("popped_len", "usize")]),
            i("buffer.len", ["fallback"], [("fallback_len", "usize")]),
            i("int.add.wrap", ["popped_len", "fallback_len"], [("length", "usize")]),
            i("owner.drop", ["rest"]), i("owner.drop", ["popped"]), i("owner.drop", ["fallback"]),
        ], ret("length"))]))
    document["schema"] = "hepta.hia.program.v7"
    return document


def recursive_chain():
    params = [("owned", "chain"), ("remaining", "usize")]
    relay = f("relay", params, ["chain"], ["trap"], [
        b("entry", params, [c("zero", "usize", 0),
            i("compare.eq", ["remaining", "zero"], [("done", "bool")])],
          branch("done", ("returned", "owned"), ("recurse", "owned", "remaining"))),
        b("returned", [("final", "chain")], [], ret("final")),
        b("recurse", [("input", "chain"), ("depth", "usize")], [
            c("one", "usize", 1), i("int.sub.checked", ["depth", "one"], [("next", "usize")]),
            i("call", ["input", "next"], [("output", "chain")], function="relay"),
        ], ret("output")),
    ])
    main = f("chain_recursion", [("depth", "usize")], ["bool"], ["alloc", "trap"], [
        b("entry", [("depth", "usize")], [
            c("size", "usize", 1), i("buffer.new", ["size"], [("payload", "buffer")]),
            i("chain.empty", out=[("empty", "chain")]),
            i("chain.try_push", ["empty", "payload"],
              [("built", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["fallback"]),
            i("call", ["built", "depth"], [("relayed", "chain")], function="relay"),
            i("owner.drop", ["relayed"]),
        ], ret("ok"))])
    document = m(relay, main)
    document["schema"] = "hepta.hia.program.v7"
    return document


@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable: owned-memory execution NOT qualified")
class RustOwnedMemoryParity(unittest.TestCase):
    observations = []
    admissions = []
    programs = {}
    inputs = {}

    @classmethod
    def setUpClass(cls):
        cls.observations, cls.admissions, cls.programs, cls.inputs = [], [], {}, {}
        built = subprocess.run(["cargo", "build", "--locked", "--offline", "--message-format=json",
                                "--manifest-path", str(MANIFEST)], cwd=ROOT,
                               capture_output=True, text=True, timeout=240)
        cls.build = {"argv": built.args, "cwd": str(ROOT), "returncode": built.returncode,
                     "stdout": built.stdout, "stderr": built.stderr}
        if built.returncode:
            raise AssertionError("Actual Rust build failed:\n" + built.stderr)
        paths = [item["executable"] for line in built.stdout.splitlines()
                 if (item := json.loads(line)).get("reason") == "compiler-artifact"
                 and item.get("executable") and "bin" in item.get("target", {}).get("kind", [])]
        if len(paths) != 1:
            raise AssertionError("Cargo must identify exactly one actual executable")
        cls.executable = paths[0]

    @classmethod
    def tearDownClass(cls):
        print(f"Rust owned-memory/Python full-ledger observations: {len(cls.observations)}; "
              f"negative admissions: {len(cls.admissions)}")

    def remember(self, value, name, kind):
        raw = value.encode() if isinstance(value, str) else json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        key = hashlib.sha256(raw).hexdigest()
        # A raw-format rejection can reuse an input already normalized by
        # admit(). Keep that verified Core link while recording this use.
        item = type(self).inputs.setdefault(key, {})
        item.update({"kind": kind, "name": name, "utf8": raw.decode()})
        return key


    def raw_run(self, raw, entry, arguments, *, steps=10000, heap=32768, fail=None):
        argv = [self.executable, "--owned-run", entry, json.dumps(arguments, separators=(",", ":")),
                str(steps), str(heap), "none" if fail is None else str(fail)]
        result = subprocess.run(argv, input=raw, cwd=ROOT, capture_output=True, timeout=20)
        return {"argv": argv, "returncode": result.returncode,
                "stdout": result.stdout.decode(), "stderr": result.stderr.decode()}

    def parity(self, core, entry, arguments, *, steps=10000, heap=32768, fail=None):
        # Recheck the exact primitive bytes sent to Rust; nominal/source data
        # is never an execution fallback or an alternative semantic authority.
        checked = verify_program(core.canonical_bytes)
        raw = self.raw_run(checked.canonical_bytes, entry, arguments, steps=steps, heap=heap, fail=fail)
        try:
            python = execute_program(checked, entry, arguments, max_steps=steps,
                                     max_heap_bytes=heap, allocation_fail_at=fail, max_call_depth=32)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
            python = stopped.report
        row = {"program_sha256": checked.sha256, "entry": entry, "arguments": arguments,
               "policy": {"max_steps": steps, "max_heap_bytes": heap,
                          "allocation_fail_at": fail, "max_call_depth": 32},
               "rust_process": raw, "python": python}
        type(self).observations.append(row)  # Preserve failing observations, too.
        self.assertEqual(raw["returncode"], 0, raw["stderr"])
        self.assertEqual(raw["stderr"], "")
        rust = json.loads(raw["stdout"])
        row["rust"] = rust
        self.assertEqual(rust["program_sha256"], checked.sha256)
        document = checked.as_dict()
        chain = any("chain" in fn["returns"] or any(p["type"] == "chain" for p in fn["params"])
                    or any(p["type"] == "chain" for block in fn["blocks"] for p in block["params"])
                    or any(op["op"].startswith("chain.") or any(p["type"] == "chain" for p in op["out"])
                           for block in fn["blocks"] for op in block["ops"])
                    for fn in document["functions"])
        expected_profile = ("bounded-cfg-owned-memory-v5" if chain
                            else "bounded-cfg-byte-owner-loan-returns-v4"
                            if document["schema"] == "hepta.hia.program.v8"
                            else "bounded-cfg-byte-owner-bulk-v3")
        self.assertEqual(rust["profile"], expected_profile)
        for key in ("status", "steps", "resources"):
            self.assertEqual(rust[key], python[key], key)
        for claim in ("general_resource_execution", "production_admission_authorized",
                      "native_backend_refinement_proved"):
            self.assertIs(rust["claims"][claim], False)
        if python["status"] == "returned":
            self.assertEqual(rust["values"], python["values"])
            self.assertEqual(rust["resources"]["live_owners"], 0)
            self.assertEqual(rust["resources"]["live_local_loans"], 0)
            if "live_chain_nodes" in rust["resources"]:
                self.assertEqual(rust["resources"]["live_chain_nodes"], 0)
                self.assertEqual(rust["resources"]["live_chains"], 0)
        else:
            self.assertEqual(rust["error"]["code"], python["error"]["code"])
            self.assertNotIn("values", rust)
        row["matched"] = True
        return rust

    def reject(self, document, name, entry="entrypoint", arguments=()):
        key = self.remember(document, name, "primitive-negative")
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_program(document)
        row = {"input_sha256": key, "python_error": str(caught.exception), "rust_attempts": []}
        type(self).admissions.append(row)
        codes = []
        for steps, fail in ((10000, None), (1, 1)):
            raw = self.raw_run(json.dumps(document).encode(), entry, list(arguments), steps=steps, fail=fail)
            row["rust_attempts"].append(raw)
            self.assertNotEqual(raw["returncode"], 0)
            self.assertEqual(raw["stdout"], "")
            self.assertTrue(raw["stderr"].startswith("E_HIA_"), raw)
            codes.append(raw["stderr"].split(":", 1)[0])
        self.assertEqual(codes[0], codes[1])
        row["rejected"] = True

    def test_bulk_versions_full_ranges_failure_and_chunk_boundary(self):
        for version in range(2, 8):
            core = self.admit(bulk_program(f"hepta.hia.program.v{version}"), f"bulk-v{version}")
            self.parity(core, "bulk", [7, 7, 131])
        core = self.admit(bulk_program(), "bulk-ranges")
        for args in ([1, 1, 255], [17, 0, 7], [17, 17, 31], [4097, 4097, 173],
                     [8193, 8193, 255], [0, 0, 9], [3, 4, 7], [3, MAX_U64, 7]):
            report = self.parity(core, "bulk", args)
            if report["status"] == "returned":
                self.assertEqual(report["values"], [args[2] if args[1] else 0])
        for failure in (1, 2, 3):
            self.parity(core, "bulk", [17, 17, 31], fail=failure)

    def test_range_copy_move_fill_swap_compare_independent_bytes(self):
        initial = [11, 22, 33, 44, 55]
        pairs = [(0, 0, 5), (1, 0, 4), (0, 1, 4), (2, 1, 3), (1, 2, 3),
                 (5, 5, 0), (0, 5, 0), (4, 0, 1)]
        for document, entry, distinct in ((copy_program(), "copy_offset", True),
                                           (move_program(), "move_bytes", False)):
            core = self.admit(document, entry)
            for dst, src, count in pairs:
                expected = [0] * 5 if distinct else initial[:]
                expected[dst:dst + count] = initial[src:src + count]
                for probe in range(5):
                    report = self.parity(core, entry, [5, dst, src, count, probe])
                    self.assertEqual(report["values"], [expected[probe]])
            for dst, src, count in ((0, 5, 1), (5, 0, 1), (MAX_U64, 0, 0),
                                     (0, MAX_U64, 0), (1, 0, MAX_U64)):
                self.assertEqual(self.parity(core, entry, [5, dst, src, count, 0])["error"]["code"], "bounds")
        core = self.admit(fill_program(), "range-fill")
        for offset, count in ((0, 5), (1, 3), (5, 0), (2, 1)):
            for probe in range(5):
                expected = 91 if offset <= probe < offset + count else 0
                self.assertEqual(self.parity(core, "fill_range", [5, offset, count, 91, probe])["values"], [expected])
        for offset, count in ((5, 1), (MAX_U64, 0), (1, MAX_U64)):
            self.parity(core, "fill_range", [5, offset, count, 91, 0])
        core = self.admit(swap_program(), "swap")
        for left, right in ((0, 4), (4, 0), (2, 2)):
            expected = initial[:]
            expected[left], expected[right] = expected[right], expected[left]
            for probe in range(5):
                self.assertEqual(self.parity(core, "swap_bytes", [5, left, right, probe])["values"], [expected[probe]])
        for left, right in ((0, 5), (5, 0), (MAX_U64, 0), (0, MAX_U64)):
            self.parity(core, "swap_bytes", [5, left, right, 0])

    def test_zero_length_bulk_keeps_real_empty_owner_obligations(self):
        for kind in ("fill_and_copy", "move_within", "copy_range"):
            core = self.admit(zero_bulk_program(kind), "zero-" + kind)
            for size, dst, src in ((0, 0, 0), (7, 7, 7), (7, 0, 7)):
                for fail in (None, 1, 2):
                    self.parity(core, "zero_bulk", [size, dst, src, 0], fail=fail)
        core = self.admit(fill_program(read=False), "zero-range-fill")
        self.assertEqual(self.parity(core, "fill_range", [0, 0, 0, 255, 0], heap=0, fail=1)["values"], [9])
        self.assertEqual(self.parity(core, "fill_range", [0, 1, 0, 255, 0], heap=0)["error"]["code"], "bounds")



    def test_chain_consuming_recursion_stops_at_the_shared_call_limit(self):
        core = self.admit(recursive_chain(), "recursive-chain-transfer")
        for depth in (0, 1, 5, 30, 31, 32, 200):
            for fail in (None, 2):
                report = self.parity(core, "chain_recursion", [depth], fail=fail)
                if depth <= 30:
                    self.assertEqual(report["values"], [fail is None])
                else:
                    self.assertEqual(report["error"]["code"], "calls")
                    self.assertEqual(report["resources"]["live_chains"], 1)
                    self.assertEqual(report["resources"]["live_chain_nodes"], int(fail is None))
                    self.assertEqual(report["resources"]["live_owners"], 2 if fail is None else 0)




    def test_illegal_chain_and_bulk_lifecycles_reject_before_execution(self):
        for operation in (i("owner.drop", ["owned"]),
                          i("owner.move", ["owned"], [("moved", "chain")]),
                          i("chain.pop", ["owned"], [("tail", "chain"), ("item", "buffer"), ("ok", "bool")]),
                          i("chain.try_push", ["owned", "payload"], [("tail", "chain"), ("item", "buffer"), ("ok", "bool")])):
            source = one_function([i("chain.empty", out=[("owned", "chain")]), c("zero", "usize", 0),
                i("buffer.new", ["zero"], [("payload", "buffer")]),
                i("chain.head_read", ["owned"], [("reader", "readbuf")]), operation])
            self.reject(source, "borrowed-chain-" + operation["op"])
        for operation in (i("buffer.len", ["owned"], [("size", "usize")]),
                          i("borrow.read", ["owned"], [("reader", "readbuf")])):
            self.reject(one_function([i("chain.empty", out=[("owned", "chain")]), operation]),
                        "chain-is-not-buffer-" + operation["op"])
        for version in range(1, 7):
            source = chain_extent()
            source["schema"] = f"hepta.hia.program.v{version}"
            self.reject(source, f"chain-version-{version}", "extent", [7])
        for opcode in ("buffer.copy", "buffer.copy_range"):
            source = bulk_program("hepta.hia.program.v7") if opcode == "buffer.copy" else copy_program()
            for fn in source["functions"]:
                for block in fn["blocks"]:
                    for operation in block["ops"]:
                        if operation["op"] == opcode:
                            operation["args"][1] = operation["args"][0]
            self.reject(source, "mutable-copy-alias-" + opcode)




if __name__ == "__main__":
    unittest.main()
