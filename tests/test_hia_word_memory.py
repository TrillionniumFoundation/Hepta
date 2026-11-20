"""Real v9 admission, VM byte oracles, and bounded resource semantics."""
from copy import deepcopy
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, qualify_entry_live_heap_budget, qualify_finite_entry_live_heap_budget_v9)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import emit_program_llvm, _can_elide_zero_initialization
from hepta.hia_program_native import emit_program_machine
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget, qualify_vm_call_depth
from tools.hia_word_memory_cases import (
    ORDERS, WORD_OPS, acyclic_program, expected, owned_program)


class WordMemoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = owned_program()
        cls.checked = verify_program(cls.document)

    def test_exact_bytes_orders_alignment_and_full_u64_values(self):
        for order in ORDERS:
            for n in (8, 9, 17, 32):
                for offset in sorted({0, min(1, n - 8), n - 8}):
                    for value in (0, 0x0123456789ABCDEF, (1 << 64) - 1):
                        result = execute_program(self.checked, "load_" + order,
                                                 [n, offset, value, 0])
                        self.assertEqual(result["result"], expected("load", order, n, offset, value, 0))
                        probes = sorted({0, n - 1, offset, offset + 7,
                                         max(0, offset - 1), min(n - 1, offset + 8)})
                        for probe in probes:
                            result = execute_program(self.checked, "store_" + order,
                                                     [n, offset, value, probe])
                            self.assertEqual(result["result"],
                                             expected("store", order, n, offset, value, probe))
                            self.assertEqual(result["resources"]["live_owners"], 0)
                            self.assertEqual(result["resources"]["live_local_loans"], 0)

    def test_bounds_keep_all_offset_bits_and_trap_before_return(self):
        for mode in ("load", "store"):
            for order in ORDERS:
                for n, offset in [(n, 0) for n in range(8)] + [
                    (8, 1), (9, 2), (17, 10), (17, 17), (17, 18),
                    (32, 1 << 32), (32, (1 << 32) + 1),
                    (32, (1 << 63) + 1), (32, (1 << 64) - 1),
                ]:
                    with self.subTest(mode=mode, order=order, n=n, offset=offset):
                        with self.assertRaises(HIAProgramTrap) as caught:
                            execute_program(self.checked, mode + "_" + order, [n, offset, 91, 0])
                        self.assertEqual(caught.exception.code, "bounds")
                        self.assertEqual(caught.exception.report["status"], "trapped")

    def test_failing_vm_store_retains_every_byte_and_load_accepts_readonly(self):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from tools.hia_word_memory_cases import instruction
        for order in ORDERS:
            for n in range(24):
                for offset in {n, n + 1, max(0, n - 7), (1 << 32) + 1, (1 << 64) - 1}:
                    machine = _Machine(self.checked, 100, 100, None, 10)
                    owner = _Owner(1, bytearray([0xA5] * n))
                    view = _View(owner, True)
                    before = bytes(owner.data)
                    op = instruction("buffer.store.u64." + order, ["view", "offset", "value"])
                    with self.assertRaises(HIAProgramTrap):
                        machine.operation(op, {"view": view, "offset": offset,
                                               "value": 0x0123456789ABCDEF}, 0)
                    self.assertEqual(bytes(owner.data), before)
        source = acyclic_program()
        ops = source["functions"][0]["blocks"][0]["ops"]
        ops[6:7] = [
            instruction("loan.end", ["view"]),
            instruction("borrow.read", ["owner"], [("reader", "readbuf")]),
            instruction("buffer.load.u64.be", ["reader", "offset"], [("result", "u64")]),
        ]
        ops[9]["args"] = ["reader"]
        self.assertEqual(execute_program(source, "probe", [])["result"], 0x1032547698BADCFE)

    def test_version_types_effects_attributes_and_loan_guards(self):
        for version in range(1, 9):
            bad = deepcopy(self.document)
            bad["schema"] = f"hepta.hia.program.v{version}"
            with self.assertRaises(HIAProgramRejected):
                verify_program(bad)
        for opcode in WORD_OPS:
            for kind in ("missing_effect", "attributes", "offset_type", "loan_type"):
                bad = deepcopy(self.document)
                fn = next(f for f in bad["functions"] if any(
                    op["op"] == opcode for b in f["blocks"] for op in b["ops"]))
                op = next(op for b in fn["blocks"] for op in b["ops"] if op["op"] == opcode)
                if kind == "missing_effect":
                    fn["effects"].remove("read" if ".load." in opcode else "write")
                elif kind == "attributes":
                    op["attrs"] = {"unchecked": True}
                elif kind == "offset_type":
                    op["args"][1] = "rvalue"
                else:
                    op["args"][0] = "rowner"
                with self.subTest(opcode=opcode, kind=kind), self.assertRaises(HIAProgramRejected):
                    verify_program(bad)

    def test_assembly_roundtrip_both_native_lowerings_and_zero_initialization(self):
        rendered = render_assembly(self.checked)
        self.assertEqual(assemble_program(rendered).canonical_bytes, self.checked.canonical_bytes)
        machine = emit_program_machine(self.checked)
        self.assertEqual(set(machine.exports), set(self.document["exports"]))
        for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                       "riscv64-unknown-linux-gnu"):
            ir = emit_program_llvm(self.checked, target=target).text
            self.assertIn("call i64 @llvm.bswap.i64", ir)
            self.assertIn("icmp ule i64", ir)
            self.assertIn("icmp uge i64", ir)
            self.assertIn("load i64", ir)
            self.assertIn("align 1", ir)
        # A new memory reader cannot accidentally join the "unread" whitelist.
        for fn in self.document["functions"]:
            self.assertFalse(_can_elide_zero_initialization(fn))

    def test_word_access_has_one_tick_no_new_payload_or_frame(self):
        doc = acyclic_program()
        report = execute_program(doc, "probe", [])
        self.assertEqual(report["result"], 0x1032547698BADCFE)
        bounds = analyze_static_budget(doc)
        row = bounds["functions"][0]
        self.assertEqual(row["max_vm_ticks"], report["steps"])
        self.assertEqual(row["max_allocator_interactions"], 2)
        self.assertEqual(row["max_call_depth"], 1)
        self.assertEqual(qualify_vm_call_depth(doc, max_call_depth=1)["core_schema"], doc["schema"])
        for bound in (qualify_entry_live_heap_budget(doc, "probe", max_live_heap_bytes=17),
                      qualify_finite_entry_live_heap_budget_v9(doc, "probe", [], max_live_heap_bytes=17)):
            self.assertEqual(bound["peak_bound_bytes"], 17)
            self.assertFalse(bound["claims"]["fixed_width_memory_allocates_payload"])

    def test_loaded_word_does_not_authorize_an_allocation_bound(self):
        from tools.hia_word_memory_cases import instruction
        document = acyclic_program()
        ops = document["functions"][0]["blocks"][0]["ops"]
        ops[2]["attrs"]["value"] = 8
        ops[6]["op"] = "buffer.load.u64.le"
        ops[7:7] = [
            instruction("int.cast", ["result"], [("requested", "usize")], mode="wrap"),
            instruction("buffer.new", ["requested"], [("extra", "buffer")]),
            instruction("owner.drop", ["extra"]),
        ]
        # Execution may observe the stored eight. Static resource admission
        # cannot use that observation as proof of an allocation extent.
        self.assertEqual(execute_program(document, "probe", [])["result"], 8)
        for qualifier in (
                lambda: qualify_entry_live_heap_budget(document, "probe", max_live_heap_bytes=25),
                lambda: qualify_finite_entry_live_heap_budget_v9(
                    document, "probe", [], max_live_heap_bytes=25)):
            with self.assertRaises(HIAHeapBoundRejected):
                qualifier()


if __name__ == "__main__":
    unittest.main()
