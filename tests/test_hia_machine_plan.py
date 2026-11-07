"""Independent native observations for each explicit machine-plan choice."""
from __future__ import annotations

from copy import deepcopy
import ctypes
import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest

from hepta.hia_agent_contract import PLAN_SCHEMA, validate
from hepta.hia_machine_elf import write_elf_object
from hepta.hia_machine_plan import MACHINE_V2, MachinePlanRejected, validate_plan
from hepta.hia_machine_x64 import Code, MachineEncodingError
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_native import compile_program_machine, emit_program_machine
from tests.test_hia_program_native import minimal_document
from tools.qualify_hia_program import block, constant, function, operation, ret


def explicit_plan(program, **changes):
    plan = {"schema": MACHINE_V2, "core_sha256": program.sha256, "block_order": {},
            "function_order": [fn["name"] for fn in program.as_dict()["functions"]],
            "scratch_registers": {"r10": "r10", "r11": "r11"},
            "instruction_selection": {"move_immediate": "movabs", "alu_immediate": "imm32"},
            "function_alignment": 1}
    plan.update(changes)
    return plan


def call_document():
    doc = minimal_document()
    params = [("x", "u64")]
    doc["functions"].append(function("twice", params, ["u64"], [], [
        block("entry", params, [operation("call", ["x"], [("first", "u64")], function="answer"),
                               operation("call", ["first"], [("second", "u64")], function="answer")], ret("second"))]))
    return doc


class MachinePlanValidationTests(unittest.TestCase):
    def setUp(self):
        self.program = verify_program(call_document())
        self.plan = explicit_plan(self.program)

    def test_each_choice_is_explicit_and_core_bound(self):
        validate(self.plan, PLAN_SCHEMA)
        frozen = validate_plan(self.program, self.plan)
        self.plan["function_order"].reverse()
        self.assertNotEqual(frozen["function_order"], self.plan["function_order"])
        for update in ({"core_sha256": "0" * 64}, {"function_order": ["answer", "answer"]},
                       {"function_order": ["answer"]}, {"function_order": ["answer", "foreign"]},
                       {"function_alignment": True}, {"function_alignment": 4096},
                       {"block_order": {"answer": ["entry", "entry"]}},
                       {"scratch_registers": {"r10": "rax", "r11": "r10"}},
                       {"scratch_registers": {"r10": "r10", "r11": "r10"}},
                       {"instruction_selection": {"move_immediate": "zero_with_xor", "alu_immediate": "imm32"}},
                       {"instruction_selection": {"move_immediate": "movabs"}}, {"raw_bytes": "c3"}):
            with self.subTest(update=update), self.assertRaises(MachinePlanRejected):
                validate_plan(self.program, {**self.plan, **update})

    def test_default_plan_is_byte_identical_and_plan_changes_are_sealed(self):
        canonical = emit_program_machine(self.program)
        planned = emit_program_machine(self.program, machine_plan=self.plan)
        self.assertEqual(canonical.object_bytes, planned.object_bytes)
        self.assertEqual(canonical.function_frames, planned.function_frames)
        self.assertIsNone(canonical.machine_plan_sha256)
        self.assertIsNotNone(planned.machine_plan_sha256)
        with tempfile.TemporaryDirectory() as directory:
            changed = deepcopy(self.plan)
            changed["function_alignment"] = 16
            with self.assertRaisesRegex(ValueError, "E_HIA_PROGRAM_ORIGIN"):
                compile_program_machine(planned, program=self.program,
                    output=Path(directory) / "wrong.o", kind="object", machine_plan=changed)

    def test_encoder_rejects_unreviewed_registers_and_choices(self):
        for kwargs in ({"scratch_registers": {"r10": "rax", "r11": "rcx"}},
                       {"scratch_registers": {"r10": "r11", "r11": "r11"}},
                       {"move_immediate": "xor"}, {"alu_immediate": "truncate"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(MachineEncodingError):
                Code(**kwargs)


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64" and shutil.which("ld"),
                     "native machine-plan tests require Linux x86-64 and GNU ld")
class MachinePlanExecutionTests(unittest.TestCase):
    def test_requested_alignment_survives_elf_linking_and_loading(self):
        program = verify_program(call_document())
        with tempfile.TemporaryDirectory() as directory:
            for alignment in (16, 32, 64):
                plan = explicit_plan(program, function_alignment=alignment)
                image = emit_program_machine(program, machine_plan=plan)
                header = struct.unpack_from("<16sHHIQQQIHHHHHH", image.object_bytes)
                section = struct.unpack_from("<IIQQQQIIQQ", image.object_bytes, header[6] + 64)
                self.assertEqual(section[8], alignment)
                output = Path(directory) / (str(alignment) + ".so")
                compile_program_machine(image, program=program, output=output, linker="ld", machine_plan=plan)
                library = ctypes.CDLL(str(output))
                for name in ("answer", "twice"):
                    address = ctypes.cast(getattr(library, name), ctypes.c_void_p).value
                    self.assertEqual(address % alignment, 0, (name, alignment, address))

    def test_independent_scratch_selection_and_layout_observations(self):
        program = verify_program(call_document())
        variants = {
            "canonical": None,
            "registers": explicit_plan(program, scratch_registers={"r10": "r11", "r11": "r10"}),
            "selection": explicit_plan(program, instruction_selection={
                "move_immediate": "mov32_if_exact", "alu_immediate": "imm8_if_exact"}),
            "layout": explicit_plan(program, function_order=["twice", "answer"], function_alignment=32),
            "combined": explicit_plan(program, scratch_registers={"r10": "r11", "r11": "r10"},
                instruction_selection={"move_immediate": "mov32_if_exact", "alu_immediate": "imm8_if_exact"},
                function_order=["twice", "answer"], function_alignment=16),
        }
        images = {}
        with tempfile.TemporaryDirectory() as directory:
            for name, plan in variants.items():
                image = emit_program_machine(program, machine_plan=plan)
                images[name] = image
                output = Path(directory) / (name + ".so")
                compile_program_machine(image, program=program, output=output, linker="ld", machine_plan=plan)
                library = ctypes.CDLL(str(output))
                for symbol, delta in (("answer", 7), ("twice", 14)):
                    fn = getattr(library, symbol)
                    fn.argtypes, fn.restype = [ctypes.c_uint64], ctypes.c_uint64
                    for value in [*range(256), (1 << 32) - 1, (1 << 63), (1 << 64) - 1]:
                        self.assertEqual(fn(value), (value + delta) & ((1 << 64) - 1), (name, symbol, value))
            for name in ("registers", "selection", "layout", "combined"):
                self.assertNotEqual(images[name].text_bytes, images["canonical"].text_bytes, name)
            self.assertLess(len(images["selection"].text_bytes), len(images["canonical"].text_bytes))

    def test_immediate_boundaries_and_live_flags_on_real_machine(self):
        code = Code(scratch_registers={"r10": "r11", "r11": "r10"},
                    move_immediate="mov32_if_exact", alu_immediate="imm8_if_exact")
        symbols, expected = [], {}

        def begin():
            name = "case_" + str(len(symbols))
            symbols.append({"name": name, "offset": code.offset, "size": 0, "global": True})
            return name

        def end(name, value):
            code.ret()
            symbols[-1]["size"] = code.offset - symbols[-1]["offset"]
            expected[name] = value & ((1 << 64) - 1)

        for value in (0, 1, (1 << 31) - 1, 1 << 31, (1 << 32) - 1, 1 << 32, -1, -(1 << 63), (1 << 64) - 1):
            name = begin()
            code.mov_imm("r10", value)
            code.mov_rr("rax", "r10")
            end(name, value)
        for a in (-(1 << 63), -129, -128, -1, 0, 127, 128, (1 << 63) - 1):
            for b in (-129, -128, -127, 0, 127, 128):
                name = begin()
                code.mov_imm("r10", a)
                code.alu_imm("cmp", "r10", b)
                code.setcc("l", "r11")
                code.mov_rr("rax", "r11")
                end(name, int(a < b))
        raw, relocations = code.finalize()
        with tempfile.TemporaryDirectory() as directory:
            obj, shared = Path(directory) / "choices.o", Path(directory) / "choices.so"
            obj.write_bytes(write_elf_object(raw, symbols, relocations))
            subprocess.run(["ld", "-shared", "--no-undefined", "-z", "noexecstack", "-o", str(shared), str(obj)],
                           check=True, capture_output=True, timeout=30)
            library = ctypes.CDLL(str(shared))
            for name, value in expected.items():
                fn = getattr(library, name)
                fn.argtypes, fn.restype = [], ctypes.c_uint64
                self.assertEqual(fn(), value, name)


if __name__ == "__main__":
    unittest.main()
