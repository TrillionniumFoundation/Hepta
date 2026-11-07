"""Adversarial register-lifetime checks and independent real SysV observations."""
from __future__ import annotations

from copy import deepcopy
import ctypes
import json
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_contract import PLAN_SCHEMA, validate
from hepta.hia_machine_plan import (LAYOUT_V1, MACHINE_V2, MachinePlanRejected, VALUE_REGISTERS,
                                    register_assignment_witness, validate_plan)
from hepta.hia_program import MAX_BYTES, MAX_DEPTH, MAX_NODES, execute_program, verify_program
from hepta.hia_program_native import compile_program_machine, emit_program_machine
from tests.test_hia_program_native_review import _abi_program, _bounds_program, ABI_WITNESS, BOUNDS_OBSERVER
from tools.qualify_hia_machine_registers import (
    _block, _const, _function, _op, _ret, explicit_plan, fixture, qualify, workload,
)

NATIVE = platform.system() == "Linux" and platform.machine() == "x86_64" and shutil.which("ld")
CC = shutil.which("cc")


class ScalarRegisterValidationTests(unittest.TestCase):
    def setUp(self):
        document, self.placements = fixture()
        self.program = verify_program(document)

    def test_default_v3_preserves_canonical_bytes_and_needs_every_explicit_field(self):
        plan = explicit_plan(self.program)
        validate(plan, PLAN_SCHEMA)
        self.assertEqual(emit_program_machine(self.program).object_bytes,
                         emit_program_machine(self.program, machine_plan=plan).object_bytes)
        for field in ("value_registers", "instruction_selection", "scratch_registers"):
            bad = deepcopy(plan)
            del bad[field]
            with self.subTest(field=field), self.assertRaises(MachinePlanRejected):
                validate_plan(self.program, bad)
        bad = deepcopy(plan)
        del bad["instruction_selection"]["scalar_select"]
        with self.assertRaises(MachinePlanRejected):
            validate_plan(self.program, bad)

    def test_validated_assignments_are_immutable_and_sealed_in_native_images(self):
        plan = explicit_plan(self.program, self.placements)
        frozen = validate_plan(self.program, plan)
        image = emit_program_machine(self.program, machine_plan=plan)
        plan["value_registers"]["plus7"]["x"] = "r15"
        self.assertEqual(frozen["value_registers"]["plus7"]["x"], "r12")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "E_HIA_PROGRAM_ORIGIN"):
                compile_program_machine(image, program=self.program, output=Path(directory) / "wrong.o",
                                        kind="object", machine_plan=plan)

    def test_plan_snapshot_rejects_copy_and_equality_hooks_before_running_them(self):
        hooks = []

        class CopyHook(str):
            def __deepcopy__(self, memo):
                hooks.append("copy")
                plan["value_registers"]["plus7"]["x"] = "rax"
                return str(self)

        class EqualityHook(str):
            def __eq__(self, other):
                hooks.append("equality")
                return True

        for location in ("hash-copy", "hash-equality", "object-key"):
            plan = explicit_plan(self.program, {"plus7": {"x": "r12", "seven": "r13", "answer": "r14"}})
            if location == "hash-copy":
                plan["core_sha256"] = CopyHook(self.program.sha256)
            elif location == "hash-equality":
                plan["core_sha256"] = EqualityHook(self.program.sha256)
            else:
                plan[CopyHook("schema")] = plan.pop("schema")
            with self.subTest(location=location):
                with self.assertRaisesRegex(MachinePlanRejected, "bounded plain JSON"):
                    validate_plan(self.program, plan)
                with self.assertRaisesRegex(ValueError, "E_HIA_MACHINE_PLAN"):
                    emit_program_machine(self.program, machine_plan=plan)
                self.assertEqual(hooks, [])
                self.assertEqual(plan["value_registers"]["plus7"]["x"], "r12")

    def test_plan_snapshot_bounds_cycles_depth_fanout_and_bytes_before_semantic_checks(self):
        cycle = []
        cycle.append(cycle)
        deep = 0
        for _ in range(MAX_DEPTH + 1):
            deep = [deep]
        for name, value in (("cycle", cycle), ("depth", deep),
                            ("nodes", [0] * MAX_NODES), ("bytes", "x" * (MAX_BYTES + 1))):
            plan = explicit_plan(self.program)
            plan["value_registers"] = value
            with self.subTest(case=name), patch("hepta.hia_machine_plan.register_assignment_witness") as witness:
                with self.assertRaisesRegex(MachinePlanRejected, "bounded plain JSON"):
                    validate_plan(self.program, plan)
                witness.assert_not_called()

    def test_plain_json_v1_v2_v3_plans_keep_their_machine_bytes(self):
        v1 = {"schema": LAYOUT_V1, "core_sha256": self.program.sha256,
              "block_order": {"plus7": ["entry"]}}
        v2 = explicit_plan(self.program)
        v2["schema"] = MACHINE_V2
        del v2["value_registers"]
        del v2["instruction_selection"]["scalar_select"]
        canonical = emit_program_machine(self.program).object_bytes
        for plan in (v1, v2, explicit_plan(self.program)):
            source = json.loads(json.dumps(plan))
            frozen = validate_plan(self.program, source)
            self.assertEqual(frozen, plan)
            self.assertIsNot(frozen, source)
            source["block_order"]["plus7"] = ["invalid_after_capture"]
            self.assertEqual(emit_program_machine(self.program, machine_plan=frozen).object_bytes, canonical)

    def test_unreviewed_locations_types_and_unknown_values_fail_closed(self):
        invalid = [[], {"missing": {}}, {"plus7": []}, {"plus7": {"x": ["r12"]}},
                   {"plus7": {"x": "rax"}}, {"plus7": {"x": "rbp"}},
                   {"plus7": {"missing": "r12"}}, {"memory_calls": {"data": "r12"}},
                   {"memory_calls": {"view": "r12"}}]
        for mappings in invalid:
            plan = explicit_plan(self.program)
            plan["value_registers"] = mappings
            with self.subTest(mappings=mappings), self.assertRaises(MachinePlanRejected):
                validate_plan(self.program, plan)
        plan = explicit_plan(self.program)
        plan["instruction_selection"]["scalar_select"] = "load_speculative_pointer"
        with self.assertRaises(MachinePlanRejected):
            validate_plan(self.program, plan)

    def test_live_inputs_outputs_and_branch_condition_interfere(self):
        invalid = [
            {"plus7": {"x": "r12", "seven": "r12"}},
            {"plus7": {"x": "r12", "answer": "r12"}},
            {"pair_caller": {"left": "r12", "right": "r12"}},
            {"swap_loop": {"left": "r12", "more": "r12"}},
            {"across_calls": {"x": "r12", "first": "r12"}},
        ]
        for mappings in invalid:
            with self.subTest(mappings=mappings), self.assertRaisesRegex(MachinePlanRejected, "interfering values"):
                validate_plan(self.program, explicit_plan(self.program, mappings))

    def test_dead_parameter_and_dead_definition_writes_cannot_clobber_live_values(self):
        document, _ = fixture()
        document["functions"] = [document["functions"][0]]
        fn = document["functions"][0]
        fn["params"].append({"name": "unused_parameter", "type": "u64"})
        fn["blocks"][0]["params"].append({"name": "unused_parameter", "type": "u64"})
        fn["blocks"][0]["ops"].insert(0, _const("unused_definition", "u64", 77))
        program = verify_program(document)
        for dead in ("unused_parameter", "unused_definition"):
            with self.subTest(dead=dead), self.assertRaisesRegex(MachinePlanRejected, "interfering values"):
                validate_plan(program, explicit_plan(program, {"plus7": {"x": "r12", dead: "r12"}}))

    def test_disjoint_lifetimes_and_separate_blocks_have_independent_witnesses(self):
        witness = register_assignment_witness(self.program, self.placements)
        reuse = witness["functions"]["reuse"]
        intervals = {row["value"]: row for row in reuse["intervals"]}
        self.assertEqual(intervals["x"]["register"], intervals["eleven"]["register"])
        self.assertLess(intervals["x"]["last"], intervals["eleven"]["first"])
        loop = witness["functions"]["swap_loop"]
        self.assertEqual(loop["callee_saved_registers"], list(VALUE_REGISTERS))
        self.assertEqual({row["block"] for row in loop["intervals"]}, {"entry", "loop", "body", "done"})


@unittest.skipUnless(NATIVE, "native register plans require Linux x86-64 and GNU ld")
class ScalarRegisterExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        document, placements = fixture()
        cls.program = verify_program(document)
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-register-plan-")
        cls.directory = Path(cls.temporary.name)
        cls.variants = {"canonical": None, "registers": explicit_plan(cls.program, placements),
                        "cmov": explicit_plan(cls.program, select="cmov_scalar"),
                        "combined": explicit_plan(cls.program, placements, select="cmov_scalar", layout=True, compact=True)}
        cls.images, cls.libraries, cls.functions = {}, {}, {}
        for name, plan in cls.variants.items():
            image = cls.images[name] = emit_program_machine(cls.program, machine_plan=plan)
            output = cls.directory / (name + ".so")
            compile_program_machine(image, program=cls.program, output=output, linker="ld", machine_plan=plan)
            library = cls.libraries[name] = ctypes.CDLL(str(output))
            funcs = cls.functions[name] = {}
            for fn in cls.program.as_dict()["functions"]:
                if fn["name"] == "pair":
                    continue
                native = getattr(library, fn["name"])
                native.argtypes = [ctypes.c_bool if p["type"] == "bool" else ctypes.c_uint64 for p in fn["params"]]
                native.restype = ctypes.c_uint64
                funcs[fn["name"]] = native
        cls.cases = workload(cls.program)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def check_functions(self, symbols):
        count = 0
        for name, funcs in self.functions.items():
            for case in self.cases:
                if case["function"] in symbols:
                    self.assertEqual(funcs[case["function"]](*case["args"]), case["expected"], (name, case))
                    count += 1
        self.case_counts = {"native_outputs_checked": count}

    def test_assigned_scalars_and_disjoint_register_reuse(self):
        self.check_functions({"plus7", "reuse"})

    def test_caller_mutation_after_lifetime_check_cannot_change_emitted_registers(self):
        plan = explicit_plan(self.program, {"plus7": {"x": "r12", "seven": "r13", "answer": "r14"}})
        retained = json.loads(json.dumps(plan))

        def validate_then_mutate_caller(checked, assignments):
            result = register_assignment_witness(checked, assignments)
            plan["value_registers"]["plus7"]["x"] = "rax"
            return result

        # Deterministically exercise the old check/copy gap without relying on
        # scheduling a racing thread. Only the caller's original is changed.
        with patch("hepta.hia_machine_plan.register_assignment_witness", side_effect=validate_then_mutate_caller):
            image = emit_program_machine(self.program, machine_plan=plan)
        self.assertEqual(plan["value_registers"]["plus7"]["x"], "rax")
        self.assertEqual(image.object_bytes, emit_program_machine(self.program, machine_plan=retained).object_bytes)
        output = self.directory / "detached-plan.so"
        compile_program_machine(image, program=self.program, output=output, linker="ld", machine_plan=retained)
        library = ctypes.CDLL(str(output))
        function = library.plus7
        function.argtypes, function.restype = [ctypes.c_uint64], ctypes.c_uint64
        self.assertEqual(function(10), 17)  # The old accepted rax mapping produced 14.

    def test_register_values_survive_internal_calls_multiple_results_and_recursion(self):
        self.check_functions({"across_calls", "pair_caller", "recursive_sum"})

    def test_permuted_backedges_and_reordered_blocks_preserve_staged_inputs(self):
        self.check_functions({"swap_loop"})

    def test_register_values_survive_calloc_memset_and_free(self):
        self.check_functions({"memory_calls"})

    def test_cmov_selects_both_full_width_values_under_all_plans(self):
        self.check_functions({"choose"})
        self.assertNotEqual(self.images["cmov"].text_bytes, self.images["canonical"].text_bytes)
        self.assertNotEqual(self.images["registers"].text_bytes, self.images["canonical"].text_bytes)

    def test_changed_plans_preserve_requested_loaded_symbol_alignment(self):
        for fn in self.functions["combined"].values():
            self.assertEqual(ctypes.cast(fn, ctypes.c_void_p).value % 64, 0)

    def test_cmov_preserves_signed_unsigned_boolean_and_unit_value_representations(self):
        types = {**{f"{sign}{width}": getattr(ctypes, ("c_int" if sign == "i" else "c_uint") + str(width))
                   for sign in ("i", "u") for width in (8, 16, 32, 64)},
                 "isize": ctypes.c_int64, "usize": ctypes.c_uint64, "bool": ctypes.c_bool}
        funcs, assignments, cases = [], {}, []
        for typ in types:
            name = "select_" + typ
            params = [("condition", "bool"), ("yes", typ), ("no", typ)]
            funcs.append(_function(name, params, [typ], [_block("entry", params, [
                _op("select", ["condition", "yes", "no"], [("answer", typ)]),
            ], _ret("answer"))]))
            assignments[name] = {"condition": "rbx", "yes": "r12", "no": "r13", "answer": "r14"}
            if typ == "bool":
                pairs = [(False, True), (True, False), (False, False), (True, True)]
            else:
                bits = 64 if typ.endswith("size") else int(typ[1:])
                lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if typ[0] == "i" else (0, (1 << bits) - 1)
                pairs = [(lo, hi), (hi, lo), (0, 1), (hi, hi)]
            cases.extend((name, typ, [condition, yes, no]) for condition in (False, True) for yes, no in pairs)
        params = [("condition", "bool")]
        funcs.append(_function("select_unit", params, ["unit"], [_block("entry", params, [
            _const("yes", "unit", None), _const("no", "unit", None),
            _op("select", ["condition", "yes", "no"], [("answer", "unit")]),
        ], _ret("answer"))]))
        program = verify_program({"schema": "hepta.hia.program.v1", "module": "all_cmov_types", "functions": funcs})
        plan = explicit_plan(program, assignments, select="cmov_scalar", compact=True)
        image = emit_program_machine(program, machine_plan=plan)
        output = self.directory / "select-all-types.so"
        compile_program_machine(image, program=program, output=output, linker="ld", machine_plan=plan)
        library = ctypes.CDLL(str(output))
        for name, typ, args in cases:
            fn = getattr(library, name)
            fn.argtypes, fn.restype = [ctypes.c_bool, types[typ], types[typ]], types[typ]
            self.assertEqual(fn(*args), execute_program(program, name, args)["result"], (name, args))
        library.select_unit.argtypes, library.select_unit.restype = [ctypes.c_bool], None
        for condition in (False, True):
            self.assertIsNone(library.select_unit(condition))
        self.case_counts = {"native_outputs_checked": len(cases) + 2}

    @unittest.skipUnless(CC, "independent ABI and allocation observers need a native C test compiler")
    def test_independent_sysv_witness_preserves_all_callee_saved_registers_and_stack_arguments(self):
        program = verify_program(_abi_program())
        plan = explicit_plan(program, {"narrow_mix": {f"a{i}": reg for i, reg in enumerate(VALUE_REGISTERS)}},
                             select="cmov_scalar", compact=True)
        image = emit_program_machine(program, machine_plan=plan)
        root = self.directory
        obj, witness, driver, binary = (root / name for name in ("abi.o", "abi.S", "abi.c", "abi-observer"))
        receipt = compile_program_machine(image, program=program, output=obj, kind="object", machine_plan=plan)
        self.assertGreater(receipt["function_frames"]["narrow_mix"], 4096)
        witness.write_text(ABI_WITNESS)
        driver.write_text("#include <stdint.h>\n#include <stdio.h>\nuint64_t abi_witness(void);\n"
                          "int main(void){printf(\"%llu\\n\",(unsigned long long)abi_witness());return 0;}\n")
        child = subprocess.run([CC, "-O2", str(driver), str(witness), str(obj), "-o", str(binary)],
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        observed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)
        args = [-128, 250, -32767, 0xfeed, -2147483647, 0xdeadbeef,
                0x8123456789abcdef - (1 << 64), 0xfedcba9876543210, True, 0xa5]
        self.assertEqual(int(observed.stdout), execute_program(program, "narrow_mix", args)["result"])

    @unittest.skipUnless(CC, "independent pre-write bounds observer needs a native C test compiler")
    def test_assigned_indices_retain_trap_before_partial_memory_write(self):
        program = verify_program(_bounds_program())
        assignments = {fn["name"]: {"offset": "r12", "count": "r13", "four": "r14"}
                       for fn in program.as_dict()["functions"]}
        plan = explicit_plan(program, assignments, select="cmov_scalar", compact=True)
        image = emit_program_machine(program, machine_plan=plan)
        root = self.directory
        obj, driver, binary = (root / name for name in ("bounds.o", "bounds.c", "bounds-observer"))
        compile_program_machine(image, program=program, output=obj, kind="object", machine_plan=plan)
        driver.write_text(BOUNDS_OBSERVER)
        flags = ["-Wl,--wrap=" + name for name in ("calloc", "free", "memset", "memcpy", "memmove", "abort")]
        child = subprocess.run([CC, "-O0", "-fno-builtin", str(driver), str(obj), *flags, "-o", str(binary)],
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        cases = [("bad_swap", 4, 0), ("bad_swap", (1 << 64) - 1, 0)]
        cases += [(name, offset, count) for name in ("bad_fill", "bad_move", "bad_copy")
                  for offset, count in ((3, 2), ((1 << 64) - 1, 0), (0, (1 << 64) - 1))]
        for name, offset, count in cases:
            observed = subprocess.run([str(binary), name, str(offset), str(count)], capture_output=True, text=True, timeout=10)
            self.assertEqual(observed.returncode, 90, (name, offset, count, observed.stdout, observed.stderr))
        self.case_counts = {"traps_before_writes_checked": len(cases)}

    def test_assigned_arithmetic_retains_overflow_abort(self):
        params = [("a", "u64"), ("b", "u64")]
        program = verify_program({"schema": "hepta.hia.program.v1", "module": "allocated_trap", "functions": [
            _function("checked_add", params, ["u64"], [_block("entry", params, [
                _op("int.add.checked", ["a", "b"], [("answer", "u64")]),
            ], _ret("answer"))], ["trap"]) ]})
        plan = explicit_plan(program, {"checked_add": {"a": "r12", "b": "r13", "answer": "r14"}}, compact=True)
        image = emit_program_machine(program, machine_plan=plan)
        output = self.directory / "overflow.so"
        compile_program_machine(image, program=program, output=output, linker="ld", machine_plan=plan)
        script = ("import ctypes,resource,sys;resource.setrlimit(resource.RLIMIT_CORE,(0,0));"
                  "f=ctypes.CDLL(sys.argv[1]).checked_add;f.argtypes=[ctypes.c_uint64]*2;f.restype=ctypes.c_uint64;"
                  "f((1<<64)-1,1)")
        observed = subprocess.run([sys.executable, "-c", script, str(output)], capture_output=True, timeout=10)
        self.assertEqual(observed.returncode, -signal.SIGABRT)

    def test_failed_campaign_arm_retains_all_attempts_and_costs(self):
        original = emit_program_machine

        def fail_canonical(program, *, machine_plan=None, **kwargs):
            if machine_plan is None:
                raise ValueError("injected canonical emission failure")
            return original(program, machine_plan=machine_plan, **kwargs)

        path = self.directory / "failed-campaign"
        with patch("tools.qualify_hia_machine_registers.emit_program_machine", side_effect=fail_canonical):
            report = qualify(path)
        self.assertFalse(report["ok"])
        self.assertEqual(len(report["attempts"]), 8)
        first = report["attempts"][0]
        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["error"]["message"], "injected canonical emission failure")
        self.assertGreater(first["phases"]["emit"]["wall_ns"], 0)
        self.assertEqual([row["status"] for row in report["attempts"][-3:]], ["rejected"] * 3)
        self.assertEqual(json.loads((path / "result.json").read_text()), report)
        self.assertFalse(report["full_search_cost_complete"])


if __name__ == "__main__":
    unittest.main()
