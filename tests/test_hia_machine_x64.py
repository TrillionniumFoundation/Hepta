"""Independent executable/disassembly tests for the direct machine encoder."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest

from hepta.hia_machine_x64 import Code, MachineEncodingError
from hepta.hia_machine_elf import write_elf_object, MachineObjectError

_MASK = (1 << 64) - 1
_REGS = ("rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
_SAVED = ("rbx", "rbp", "r12", "r13", "r14", "r15")


class EncoderStructuralTests(unittest.TestCase):
    def test_relocation_and_local_branches_are_deterministic(self):
        code = Code()
        code.label("start")
        code.jmp("end")
        code.call("calloc")
        code.jcc("ne", "start")
        code.label("end")
        code.ret()
        machine, relocations = code.finalize()
        self.assertEqual(machine[:5], b"\xe9\x0b\0\0\0")
        self.assertEqual(machine[10:16], b"\x0f\x85\xf0\xff\xff\xff")
        self.assertEqual(relocations, [{"offset": 6, "symbol": "calloc", "type": 4, "addend": -4}])
        self.assertEqual(code.finalize(), (machine, relocations))
        relocations[0]["offset"] = 900
        self.assertEqual(code.finalize()[1][0]["offset"], 6)

    def test_invalid_registers_immediates_labels_and_relocations_reject(self):
        for invalid in ("xmm0", "eax", 1, None):
            with self.assertRaises(MachineEncodingError): Code().mov_rr("rax", invalid)
        for invalid in (True, -(1 << 63) - 1, 1 << 64):
            with self.assertRaises(MachineEncodingError): Code().mov_imm("rax", invalid)
        for invalid in (True, 1 << 31, -(1 << 31) - 1):
            with self.assertRaises(MachineEncodingError): Code().load("rax", "rbp", invalid)
        code = Code(); code.label("a")
        with self.assertRaises(MachineEncodingError): code.label("a")
        code.jmp("missing")
        with self.assertRaises(MachineEncodingError): code.finalize()
        with self.assertRaises(MachineEncodingError): Code().shift_imm("shl", "rax", 64)
        with self.assertRaises(MachineEncodingError): Code().jcc("unsupported", "x")
        with self.assertRaises(MachineEncodingError): Code().cmov("unsupported", "rax", "rcx")
        with self.assertRaises(MachineEncodingError): Code().cmov("e", "rax", "[rcx]")
        with self.assertRaises(MachineEncodingError): Code().call("puts;system")

    def test_elf_symbol_order_and_stack_flags(self):
        code = Code(); code.call("helper"); code.ret(); code.mov_imm("rax", 42); code.ret()
        raw, relocs = code.finalize()
        symbols = [{"name": "answer", "offset": 0, "size": 6, "global": True},
                   {"name": "helper", "offset": 6, "size": len(raw)-6, "global": False}]
        result = write_elf_object(raw, symbols, relocs)
        self.assertEqual(result, write_elf_object(raw, symbols[::-1], relocs))
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", result)
        self.assertEqual(header[1:4], (1, 62, 1))
        self.assertEqual(header[12:], (7, 5))
        stack = struct.unpack_from("<IIQQQQIIQQ", result, header[6] + 6 * 64)
        self.assertEqual(stack[1:3], (1, 0))
        for bad in ([dict(symbols[0], size=1000)], symbols + [dict(symbols[0])],
                    [dict(symbols[0], name="x\0y")]):
            with self.assertRaises(MachineObjectError): write_elf_object(raw, bad, relocs)
        for bad in ([dict(relocs[0], offset=0)], [dict(relocs[0], type=1)],
                    [dict(relocs[0], offset=True)], relocs * 2):
            with self.assertRaises(MachineObjectError): write_elf_object(raw, symbols, bad)


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64" and shutil.which("ld"),
                     "direct executable encoder validation needs Linux x86-64 and a linker")
class EncoderExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hia-machine-encoder-")
        cls.path = Path(cls.directory.name)
        cls.code, cls.symbols, cls.expected = Code(), [], {}
        cls.counter = 0
        cls._emit_all()
        machine, relocs = cls.code.finalize()
        cls.object_bytes = write_elf_object(machine, cls.symbols, relocs)
        cls.object = cls.path / "machine.o"
        cls.object.write_bytes(cls.object_bytes)
        cls.library_path = cls.path / "machine.so"
        # Only the system linker executes: the code is never passed to cc/as/LLVM.
        subprocess.run(["ld", "-shared", "--no-undefined", "-z", "noexecstack", "-o",
                        str(cls.library_path), str(cls.object)], check=True, capture_output=True)
        cls.library = ctypes.CDLL(str(cls.library_path))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    @classmethod
    def begin(cls, name=None, public=True):
        if name is None:
            name = "machine_case_" + str(cls.counter); cls.counter += 1
        cls.symbols.append({"name": name, "offset": cls.code.offset, "size": None, "global": public})
        return name

    @classmethod
    def end(cls):
        cls.symbols[-1]["size"] = cls.code.offset - cls.symbols[-1]["offset"]

    @classmethod
    def _emit_all(cls):
        c = cls.code
        for op in ("add", "sub", "and_", "or_", "xor", "imul"):
            for dst in _REGS:
                for src in _REGS:
                    if src == dst: continue
                    name = cls.begin()
                    for saved in _SAVED: c.push(saved)
                    a, b = 0xd731caef917a3421, 0x278c102347e9bcf1
                    c.mov_imm(dst, a); c.mov_imm(src, b)
                    getattr(c, op)(dst, src); c.mov_rr("rax", dst)
                    for saved in reversed(_SAVED): c.pop(saved)
                    c.ret(); cls.end()
                    result = {"add": a + b, "sub": a - b, "and_": a & b,
                              "or_": a | b, "xor": a ^ b, "imul": a * b}[op]
                    cls.expected[name] = result & _MASK
        for op in ("shl", "shr", "sar"):
            for dst in _REGS:
                for variable in (False, True):
                    if variable and dst == "rcx": continue
                    name = cls.begin()
                    for saved in _SAVED: c.push(saved)
                    value, count = 0xd731caef917a3421, 17
                    c.mov_imm(dst, value)
                    if variable:
                        c.mov_imm("rcx", count); c.shift_cl(op, dst)
                    else: c.shift_imm(op, dst, count)
                    c.mov_rr("rax", dst)
                    for saved in reversed(_SAVED): c.pop(saved)
                    c.ret(); cls.end()
                    signed = value - (1 << 64)
                    result = {"shl": value << count, "shr": value >> count, "sar": signed >> count}[op]
                    cls.expected[name] = result & _MASK
        for dst in _REGS:
            for cc, expected in (("l", 1), ("ge", 0), ("a", 1), ("b", 0), ("e", 0), ("ne", 1)):
                name = cls.begin()
                for saved in _SAVED: c.push(saved)
                c.mov_imm("rax", -7); c.mov_imm("rcx", 3); c.cmp("rax", "rcx")
                c.setcc(cc, dst); c.mov_rr("rax", dst)
                for saved in reversed(_SAVED): c.pop(saved)
                c.ret(); cls.end(); cls.expected[name] = expected
        for dst in _REGS:
            for src in _REGS:
                if dst == src:
                    continue
                for cc, choose in (("l", True), ("ge", False), ("a", True), ("b", False), ("e", False), ("ne", True)):
                    name = cls.begin()
                    for saved in _SAVED: c.push(saved)
                    c.mov_imm("rax", -7); c.mov_imm("rcx", 3); c.cmp("rax", "rcx")
                    before, selected = 0x87654321fedcba98, 0x1020304050607080
                    c.mov_imm(dst, before); c.mov_imm(src, selected); c.cmov(cc, dst, src)
                    c.mov_rr("rax", dst)
                    for saved in reversed(_SAVED): c.pop(saved)
                    c.ret(); cls.end(); cls.expected[name] = selected if choose else before
        name = cls.begin("cmov_preserves_flags")
        c.mov_imm("rax", 7); c.alu_imm("cmp", "rax", 7)
        c.mov_imm("r10", 99); c.cmov("e", "rax", "r10"); c.setcc("e", "rax"); c.ret(); cls.end()
        cls.expected[name] = 1
        for op, a, b, expected in (("div", (1 << 63)+7, 5, ((1 << 63)+7)//5),
                                    ("idiv", -37, 5, -7), ("mul", (1 << 63)+7, 5, (1 << 63)+35)):
            name = cls.begin()
            c.mov_imm("rax", a); c.mov_imm("r10", b)
            if op == "idiv": c.cqo()
            else: c.xor("rdx", "rdx")
            getattr(c, op)("r10"); c.ret(); cls.end(); cls.expected[name] = expected & _MASK
        for op in ("neg", "bitnot"):
            for dst in _REGS:
                name = cls.begin()
                for saved in _SAVED: c.push(saved)
                value = 0x7ffefffdfcfbfaf9
                c.mov_imm(dst, value); getattr(c, op)(dst); c.mov_rr("rax", dst)
                for saved in reversed(_SAVED): c.pop(saved)
                c.ret(); cls.end()
                cls.expected[name] = (-value if op == "neg" else ~value) & _MASK
        for op in ("add", "sub", "and", "or", "xor"):
            for dst in _REGS:
                name = cls.begin()
                for saved in _SAVED: c.push(saved)
                value, immediate = 0xd731caef917a3421, -17
                c.mov_imm(dst, value); c.alu_imm(op, dst, immediate); c.mov_rr("rax", dst)
                for saved in reversed(_SAVED): c.pop(saved)
                c.ret(); cls.end()
                result = {"add": value + immediate, "sub": value - immediate,
                          "and": value & immediate, "or": value | immediate,
                          "xor": value ^ immediate}[op]
                cls.expected[name] = result & _MASK
        name = cls.begin("memory_probe")
        c.push("rbp"); c.mov_rr("rbp", "rsp"); c.alu_imm("sub", "rsp", 32)
        c.mov_imm("r11", 0xfedcba9876543210); c.store("rsp", 8, "r11")
        c.lea("r10", "rsp", 8); c.load("rax", "r10")
        c.store_u8("r10", 0, "rsi"); c.load_u8("r9", "r10", 0)
        c.xor("rax", "r9"); c.leave(); c.ret(); cls.end()
        # Also check the extended SIB base r12 and full byte registers.
        name = cls.begin("memory_r12_probe")
        c.push("r12"); c.alu_imm("sub", "rsp", 16); c.mov_rr("r12", "rsp")
        c.mov_imm("r10", 0xffeeddccbbaa9988); c.store("r12", 0, "r10")
        c.load("rax", "r12", 0); c.alu_imm("add", "rsp", 16); c.pop("r12"); c.ret(); cls.end()
        cls.expected[name] = 0xffeeddccbbaa9988
        cls.begin("internal_leaf", public=False); c.mov_imm("rax", 73); c.ret(); cls.end()
        cls.begin("internal_caller"); c.alu_imm("sub", "rsp", 8); c.call("internal_leaf")
        c.alu_imm("add", "rsp", 8); c.ret(); cls.end(); cls.expected["internal_caller"] = 73
        cls.begin("branch_probe")
        c.mov_imm("rax", 0); c.mov_imm("r10", 4); c.label("loop")
        c.alu_imm("add", "rax", 7); c.alu_imm("sub", "r10", 1); c.jcc("ne", "loop")
        c.jmp("done"); c.ud2(); c.label("done"); c.ret(); cls.end(); cls.expected["branch_probe"] = 28

    def test_all_general_registers_rex_arithmetic_shifts_conditions_and_internal_calls(self):
        self.assertGreater(len(self.expected), 1400)
        for name, expected in self.expected.items():
            with self.subTest(symbol=name):
                function = getattr(self.library, name)
                function.argtypes = []; function.restype = ctypes.c_uint64
                self.assertEqual(function(), expected)

    def test_memory_sib_displacements_lea_and_low_byte_rex(self):
        function = self.library.memory_probe
        function.argtypes = [ctypes.c_uint64, ctypes.c_uint64]; function.restype = ctypes.c_uint64
        for byte in (0, 1, 127, 255, 0xabcde):
            self.assertEqual(function(0, byte), 0xfedcba9876543210 ^ (byte & 255))

    def test_external_allocator_relocations_resolve_with_only_ld(self):
        c = Code()
        c.push("rbx")
        c.mov_imm("rdi", 1); c.mov_imm("rsi", 16); c.call("calloc")
        c.test("rax", "rax"); c.jcc("e", "allocation_failed")
        c.load("rbx", "rax"); c.mov_rr("rdi", "rax"); c.call("free")
        c.mov_rr("rax", "rbx"); c.pop("rbx"); c.ret()
        c.label("allocation_failed"); c.mov_imm("rax", -1); c.pop("rbx"); c.ret()
        machine, relocs = c.finalize()
        obj = self.path / "allocator.o"; lib = self.path / "allocator.so"
        obj.write_bytes(write_elf_object(machine, [
            {"name": "allocator_probe", "offset": 0, "size": len(machine), "global": True}], relocs))
        subprocess.run(["ld", "-shared", "--no-undefined", "-z", "noexecstack", "-o",
                        str(lib), str(obj), "-lc"], check=True, capture_output=True)
        loaded = ctypes.CDLL(str(lib)); function = loaded.allocator_probe
        function.argtypes = []; function.restype = ctypes.c_uint64
        self.assertEqual(function(), 0)

    @unittest.skipUnless(shutil.which("readelf") and shutil.which("objdump"), "binutils inspection required")
    def test_independent_elf_and_isa_tools_accept_output(self):
        # ELF text assertions must not inherit the operator desktop locale.
        environment = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        elf = subprocess.run(["readelf", "-W", "-h", "-S", "-s", "-r", str(self.object)],
                             check=True, capture_output=True, text=True, env=environment).stdout
        self.assertIn("REL (Relocatable file)", elf)
        self.assertIn("R_X86_64_PLT32", elf)
        self.assertIn("LOCAL  HIDDEN", elf)
        disassembly = subprocess.run(["objdump", "-d", str(self.object)],
                                     check=True, capture_output=True, text=True, env=environment).stdout
        self.assertNotIn("(bad)", disassembly)
        self.assertIn("movz", disassembly)
        segments = subprocess.run(["readelf", "-W", "-l", str(self.library_path)],
                                  check=True, capture_output=True, text=True, env=environment).stdout
        stack = next(line for line in segments.splitlines() if "GNU_STACK" in line)
        self.assertNotIn("RWE", stack)
        self.assertNotIn("internal_leaf", [name for name in dir(self.library) if not name.startswith("_")])
        with self.assertRaises(AttributeError): getattr(self.library, "internal_leaf")


if __name__ == "__main__":
    unittest.main()
