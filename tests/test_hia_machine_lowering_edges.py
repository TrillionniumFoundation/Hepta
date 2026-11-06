"""Adversarial direct-backend ABI, integer, CFG and linker-byte witnesses.

Expected integer results are derived with Python mathematics rather than from
another machine backend. Trap invocations execute in isolated child processes.
The .text witness compares the linked bytes with the encoder's original bytes,
allowing changes only in each declared four-byte call relocation field.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import struct
import subprocess
import tempfile
import unittest

from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from hepta.hia_program_runtime import HIAProgramTrap

_TYPES = ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize")
_CTYPES = {"i8": ctypes.c_int8, "u8": ctypes.c_uint8, "i16": ctypes.c_int16,
           "u16": ctypes.c_uint16, "i32": ctypes.c_int32, "u32": ctypes.c_uint32,
           "i64": ctypes.c_int64, "u64": ctypes.c_uint64, "isize": ctypes.c_int64,
           "usize": ctypes.c_uint64, "bool": ctypes.c_bool, "unit": None}
_MASK = (1 << 64) - 1


def _width(typ):
    return 64 if typ in {"usize", "isize"} else int(typ[1:])


def _bounds(typ):
    bits = _width(typ)
    return (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if typ.startswith("i") else (0, (1 << bits) - 1)


def _wrap(value, typ):
    bits = _width(typ)
    result = value & ((1 << bits) - 1)
    return result - (1 << bits) if typ.startswith("i") and result >= (1 << (bits - 1)) else result


def _p(name, typ):
    return {"name": name, "type": typ}


def _op(op, args, out, **attrs):
    return {"op": op, "args": list(args), "out": [_p(*x) for x in out], "attrs": attrs}


def _const(name, typ, value):
    return _op("const", [], [(name, typ)], value=value)


def _block(name, params, ops, term):
    return {"id": name, "params": [_p(*x) for x in params], "ops": ops, "term": term}


def _ret(*values):
    return {"op": "ret", "values": list(values)}


def _jump(target, *args):
    return {"op": "jump", "target": target, "args": list(args)}


def _branch(condition, yes, yesargs, no, noargs):
    return {"op": "branch", "cond": condition,
            "then": {"target": yes, "args": list(yesargs)},
            "else": {"target": no, "args": list(noargs)}}


def _fn(name, params, returns, ops, effects=(), blocks=None):
    return {"name": name, "params": [_p(*x) for x in params], "returns": list(returns),
            "effects": list(effects), "entry": "entry", "blocks": blocks if blocks is not None else
            [_block("entry", params, ops, _ret("r"))]}


def _module(name, functions, exports=None):
    result = {"schema": "hepta.hia.program.v8", "module": name, "functions": functions}
    if exports is not None:
        result["exports"] = list(exports)
    return result


def _arithmetic_program():
    functions = []
    for typ in _TYPES:
        for action in ("add", "sub", "mul"):
            for mode in ("checked", "wrap"):
                name = action + "_" + mode + "_" + typ
                functions.append(_fn(name, [("a", typ), ("b", typ)], [typ], [
                    _op("int." + action + "." + mode, ["a", "b"], [("r", typ)])],
                    ["trap"] if mode == "checked" else []))
    return _module("arithmetic_edges", functions)


def _comparison_program():
    functions = []
    for typ in _TYPES:
        for action in ("div", "rem", "shl", "shr"):
            functions.append(_fn(action + "_" + typ, [("a", typ), ("b", typ)], [typ], [
                _op("int." + action + ".checked", ["a", "b"], [("r", typ)])], ["trap"]))
        functions.append(_fn("neg_" + typ, [("a", typ)], [typ], [
            _op("int.neg.checked", ["a"], [("r", typ)])], ["trap"]))
        for action in ("eq", "ne", "lt", "le", "gt", "ge"):
            functions.append(_fn(action + "_" + typ, [("a", typ), ("b", typ)], ["bool"], [
                _op("compare." + action, ["a", "b"], [("r", "bool")])]))
    return _module("division_shift_compare_edges", functions)


def _cast_program(mode):
    functions = []
    for src in _TYPES:
        for dst in _TYPES:
            name = "cast_" + src + "_" + dst
            functions.append(_fn(name, [("a", src)], [dst], [
                _op("int.cast", ["a"], [("r", dst)], mode=mode)], ["trap"] if mode == "checked" else []))
    return _module("cast_" + mode + "_edges", functions)


def _control_program():
    mix_types = ("i8", "u16", "i32", "u64", "bool", "u8", "i16", "u32",
                 "i64", "isize", "usize", "i8", "u16", "bool", "i32", "u64", "u8", "i16")
    params = [("p" + str(i), typ) for i, typ in enumerate(mix_types)]
    ops = [_const("zero", "u64", 0), _const("one", "u64", 1)]
    previous = "zero"
    for i, (name, typ) in enumerate(params):
        if typ == "bool":
            ops.append(_op("select", [name, "one", "zero"], [("v" + str(i), "u64")]))
        else:
            ops.append(_op("int.cast", [name], [("v" + str(i), "u64")], mode="wrap"))
        ops.extend([_const("weight" + str(i), "u64", 2 * i + 1),
                    _op("int.mul.wrap", ["v" + str(i), "weight" + str(i)], [("part" + str(i), "u64")]),
                    _op("int.add.wrap", [previous, "part" + str(i)], [("total" + str(i), "u64")])])
        previous = "total" + str(i)
    mix = _fn("mixed_18_arguments", params, ["u64"], [], blocks=[_block("entry", params, ops, _ret(previous))])
    params = [(x, "u64") for x in ("a", "b", "c", "d", "n")]
    values = [(x, "u64") for x in ("la", "lb", "lc", "ld", "ln")]
    done = [(x, "u64") for x in ("da", "db", "dc", "dd")]
    ops = [_const("hundred", "u64", 100), _const("ten_thousand", "u64", 10000),
           _const("million", "u64", 1000000),
           _op("int.mul.wrap", ["db", "hundred"], [("bterm", "u64")]),
           _op("int.mul.wrap", ["dc", "ten_thousand"], [("cterm", "u64")]),
           _op("int.mul.wrap", ["dd", "million"], [("dterm", "u64")]),
           _op("int.add.wrap", ["da", "bterm"], [("ab", "u64")]),
           _op("int.add.wrap", ["ab", "cterm"], [("abc", "u64")]),
           _op("int.add.wrap", ["abc", "dterm"], [("r", "u64")])]
    rotate = _fn("parallel_rotate", params, ["u64"], [], blocks=[
        _block("entry", params, [], _jump("loop", "a", "b", "c", "d", "n")),
        _block("loop", values, [_const("zero", "u64", 0), _const("one", "u64", 1),
            _op("compare.ne", ["ln", "zero"], [("more", "bool")]),
            _op("int.sub.wrap", ["ln", "one"], [("next_n", "u64")])],
            _branch("more", "loop", ["lb", "lc", "ld", "la", "next_n"], "done", ["la", "lb", "lc", "ld"])),
        _block("done", done, ops, _ret("r")),
    ])
    swap = _fn("swap_pair", [("a", "u64"), ("b", "u64")], ["u64", "u64"], [], blocks=[
        _block("entry", [("a", "u64"), ("b", "u64")], [], _ret("b", "a"))])
    invoke = _fn("invoke_pair", [("a", "u64"), ("b", "u64")], ["u64"], [
        _op("call", ["a", "b"], [("x", "u64"), ("y", "u64")], function="swap_pair"),
        _op("call", ["x", "y"], [("z", "u64"), ("w", "u64")], function="swap_pair"),
        _op("call", ["z", "w"], [("p", "u64"), ("q", "u64")], function="swap_pair"),
        _const("weight", "u64", 257),
        _op("int.mul.wrap", ["p", "weight"], [("weighted", "u64")]),
        _op("int.add.wrap", ["weighted", "q"], [("r", "u64")]),
    ])
    # Thousands of simultaneously assigned stack words force multiple probes.
    ops = [_const("c0", "u64", 0)]
    for i in range(1, 700):
        ops.append(_const("c" + str(i), "u64", i))
    previous = "c0"
    for i in range(1, 700):
        ops.append(_op("int.add.wrap", [previous, "c" + str(i)], [("sum" + str(i), "u64")]))
        previous = "sum" + str(i)
    large = _fn("large_frame", [], ["u64"], [], blocks=[_block("entry", [], ops, _ret(previous))])
    return _module("control_edges", [mix, rotate, swap, invoke, large],
                   ["mixed_18_arguments", "parallel_rotate", "invoke_pair", "large_frame"]), mix_types


def _sections(data):
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    shoff, shsize, count, names_index = header[6], header[11], header[12], header[13]
    records = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shsize) for i in range(count)]
    names = records[names_index]
    names_bytes = data[names[4]:names[4] + names[5]]
    result = {}
    for i, record in enumerate(records):
        name = names_bytes[record[0]:].split(b"\0", 1)[0].decode("ascii")
        result[name] = {"index": i, "type": record[1], "flags": record[2], "address": record[3],
                        "offset": record[4], "size": record[5], "link": record[6], "entry_size": record[9]}
    return result


def _symbols(data, sections):
    table = sections[".symtab"]
    strings = next(s for s in sections.values() if s["index"] == table["link"])
    strings_bytes = data[strings["offset"]:strings["offset"] + strings["size"]]
    result = []
    for offset in range(table["offset"], table["offset"] + table["size"], 24):
        name, info, other, section, value, size = struct.unpack_from("<IBBHQQ", data, offset)
        result.append({"name": strings_bytes[name:].split(b"\0", 1)[0].decode("ascii"),
                       "info": info, "other": other, "section": section, "value": value, "size": size})
    return result


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64"
                     and hasattr(os, "fork") and shutil.which("cc"),
                     "actual direct lowering needs Linux x86-64 and a native linker driver")
class MachineLoweringEdgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hia-machine-edges-")
        cls.path = Path(cls.directory.name)
        cls.programs, cls.images, cls.libraries, cls.functions = {}, {}, {}, {}
        control, cls.mix_types = _control_program()
        for key, document in (("arith", _arithmetic_program()), ("other", _comparison_program()),
                              ("cast_checked", _cast_program("checked")), ("cast_wrap", _cast_program("wrap")),
                              ("control", control)):
            program = verify_program(document)
            image = emit_program_machine(program)
            destination = cls.path / (key + ".so")
            compile_program_machine(image, program=program, output=destination)
            library = ctypes.CDLL(str(destination))
            cls.programs[key], cls.images[key], cls.libraries[key] = program, image, library
            for fn in document["functions"]:
                if fn["name"] not in image.exports:
                    continue
                f = getattr(library, fn["name"])
                f.argtypes = [_CTYPES[p["type"]] for p in fn["params"]]
                f.restype = _CTYPES[fn["returns"][0]]
                cls.functions[key, fn["name"]] = f

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        # Qualification captures these observed counts separately for every test.
        self.case_counts = {}

    def valid_cases(self, key, cases):
        """One isolated child executes success cases; diagnostics identify a crash."""
        cases = list(cases)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            try:
                for name, args, expected in cases:
                    description = json.dumps([key, name, args, expected])
                    os.write(write_fd, (description + "\n").encode())
                    result = self.functions[key, name](*args)
                    if result != expected:
                        os.write(write_fd, ("MISMATCH " + repr(result) + "\n").encode())
                        os._exit(2)
                    # Acknowledge only an actual native return with the expected value.
                    os.write(write_fd, b"PASS\n")
                os._exit(0)
            except BaseException as error:
                os.write(write_fd, ("ERROR " + repr(error) + "\n").encode())
                os._exit(3)
        os.close(write_fd)
        chunks = []
        while True:
            chunk = os.read(read_fd, 65536)
            if not chunk: break
            chunks.append(chunk)
        os.close(read_fd)
        _, status = os.waitpid(pid, 0)
        lines = b"".join(chunks).decode().splitlines()
        completed = lines.count("PASS")
        count_key = key + "_valid_cases"
        self.case_counts[count_key] = self.case_counts.get(count_key, 0) + completed
        self.assertEqual(status, 0, "native success batch failed: " + repr(lines[-2:]))
        self.assertEqual(completed, len(cases), "native success acknowledgement inventory differs")
        return completed

    def trap_cases(self, key, cases):
        cases = list(cases)
        completed = 0
        for name, args in cases:
            with self.subTest(module=key, function=name, args=args):
                pid = os.fork()
                if pid == 0:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                    null_fd = os.open(os.devnull, os.O_WRONLY)
                    os.dup2(null_fd, 2); os.close(null_fd)
                    try: self.functions[key, name](*args)
                    except BaseException: os._exit(3)
                    os._exit(0)
                _, status = os.waitpid(pid, 0)
                self.assertTrue(os.WIFSIGNALED(status), f"expected abort, status={status}")
                self.assertEqual(os.WTERMSIG(status), signal.SIGABRT)
                completed += 1
                count_key = key + "_trap_cases"
                self.case_counts[count_key] = self.case_counts.get(count_key, 0) + 1
        return completed

    def test_signed_unsigned_arithmetic_boundaries(self):
        valid, traps = [], []
        for typ in _TYPES:
            lo, hi = _bounds(typ)
            values = {lo, lo + 1, 0, 1, 2, hi - 1, hi, hi // 2}
            if lo < 0: values |= {-1, -2, lo // 2}
            # Cross-product includes carry/borrow and sign changes at every width.
            for a in sorted(values):
                for b in sorted(values):
                    for op, result in (("add", a + b), ("sub", a - b), ("mul", a * b)):
                        valid.append((op + "_wrap_" + typ, [a, b], _wrap(result, typ)))
                        name = op + "_checked_" + typ
                        (valid if lo <= result <= hi else traps).append(
                            (name, [a, b], result) if lo <= result <= hi else (name, [a, b]))
        self.assertGreater(self.valid_cases("arith", valid), 3000)
        self.assertGreater(self.trap_cases("arith", traps), 700)

    def test_division_remainder_shift_comparison_and_negation_boundaries(self):
        valid, traps = [], []
        for typ in _TYPES:
            lo, hi = _bounds(typ); bits = _width(typ)
            values = sorted({lo, lo + 1, 0, 1, 2, hi - 1, hi} | ({-1, -2} if lo < 0 else set()))
            for a in values:
                name = "neg_" + typ
                if lo <= -a <= hi: valid.append((name, [a], -a))
                else: traps.append((name, [a]))
                for b in values:
                    for action, result in (("eq", a == b), ("ne", a != b), ("lt", a < b),
                                           ("le", a <= b), ("gt", a > b), ("ge", a >= b)):
                        valid.append((action + "_" + typ, [a, b], result))
                    for action in ("div", "rem"):
                        name = action + "_" + typ
                        if b == 0 or (lo < 0 and a == lo and b == -1):
                            traps.append((name, [a, b]))
                        else:
                            q = abs(a) // abs(b)
                            if (a < 0) != (b < 0): q = -q
                            valid.append((name, [a, b], q if action == "div" else a - q * b))
                for count in (0, 1, bits - 1, bits, bits + 1, hi) + ((-1, lo) if lo < 0 else ()):
                    for action in ("shl", "shr"):
                        name = action + "_" + typ
                        if 0 <= count < bits:
                            value = _wrap(a << count, typ) if action == "shl" else a >> count
                            valid.append((name, [a, count], value))
                        else: traps.append((name, [a, count]))
        self.assertGreater(self.valid_cases("other", valid), 4000)
        self.assertGreater(self.trap_cases("other", traps), 500)

    def test_all_integer_cast_pairs_at_both_sides_of_each_destination_boundary(self):
        valid, traps, wrapped = [], [], []
        for src in _TYPES:
            lo, hi = _bounds(src)
            values = {lo, lo + 1, 0, 1, hi - 1, hi}
            if lo < 0: values.add(-1)
            for dst in _TYPES:
                dlow, dhigh = _bounds(dst)
                for boundary in (dlow, dhigh):
                    values.update(v for v in (boundary - 1, boundary, boundary + 1) if lo <= v <= hi)
            for dst in _TYPES:
                dlow, dhigh = _bounds(dst)
                name = "cast_" + src + "_" + dst
                for value in sorted(values):
                    wrapped.append((name, [value], _wrap(value, dst)))
                    if dlow <= value <= dhigh: valid.append((name, [value], value))
                    else: traps.append((name, [value]))
        self.assertGreater(self.valid_cases("cast_wrap", wrapped), 1500)
        self.assertGreater(self.valid_cases("cast_checked", valid), 900)
        self.assertGreater(self.trap_cases("cast_checked", traps), 500)

    def test_many_arguments_dirty_high_bits_parallel_edges_multiple_returns_and_large_frame(self):
        values = [-128, 65535, -(1 << 31), (1 << 64) - 1, True, 255, -32768, (1 << 32) - 1,
                  -(1 << 63), -17, (1 << 63) + 19, -1, 12345, False, (1 << 31) - 1, 73, 129, 32767]
        expected = sum((int(v) & _MASK) * (2 * i + 1) for i, v in enumerate(values)) & _MASK
        cases = [("mixed_18_arguments", values, expected)]
        for n in (0, 1, 2, 3, 4, 5, 17, 1001):
            v = [11, 23, 37, 49]; rotated = v[n % 4:] + v[:n % 4]
            cases.append(("parallel_rotate", v + [n], sum(x * 100 ** i for i, x in enumerate(rotated))))
        for a, b in ((0, 0), (1, 2), (73, 19), (_MASK, 2), (1 << 63, _MASK)):
            cases.append(("invoke_pair", [a, b], (b * 257 + a) & _MASK))
        cases.append(("large_frame", [], 699 * 700 // 2))
        self.assertEqual(self.valid_cases("control", cases), 15)
        self.assertGreater(dict(self.images["control"].function_frames)["large_frame"], 8192)
        # SysV gives the callee narrow low bits; high register/stack bits may be dirty.
        raw = ctypes.CFUNCTYPE(ctypes.c_uint64, *([ctypes.c_uint64] * len(values)))(
            ("mixed_18_arguments", self.libraries["control"]))
        words = []
        for i, (value, typ) in enumerate(zip(values, self.mix_types)):
            width = 8 if typ == "bool" else _width(typ)
            mask = (1 << width) - 1
            high = (0x9bceda7321f055aa + i * 0x10100101) & _MASK & ~mask
            words.append(high | (int(value) & mask))
        self.assertEqual(raw(*words), expected)

    def test_independent_vm_agrees_on_edge_semantics(self):
        examples = [("arith", "mul_wrap_i64", [-(1 << 63), -1]),
                    ("arith", "mul_checked_u64", [(1 << 32) - 1, (1 << 32) + 1]),
                    ("other", "shr_i64", [-(1 << 63), 63]),
                    ("other", "shl_u8", [255, 7]),
                    ("cast_wrap", "cast_i8_u64", [-1]),
                    ("cast_checked", "cast_u64_i64", [(1 << 63) - 1])]
        for key, name, args in examples:
            result = execute_program(self.programs[key], name, args)["result"]
            self.assertEqual(self.functions[key, name](*args), result)
        for key, name, args in (("other", "rem_i8", [-128, -1]),
                                ("other", "shl_i64", [1, -1]),
                                ("cast_checked", "cast_i64_u64", [-1]),
                                ("arith", "mul_checked_u64", [1 << 63, 2])):
            with self.assertRaises(HIAProgramTrap): execute_program(self.programs[key], name, args)
            self.trap_cases(key, [(name, args)])

    def test_linked_text_changes_only_declared_call_displacements(self):
        image = self.images["control"]
        obj = image.object_bytes; object_sections = _sections(obj)
        object_symbols = _symbols(obj, object_sections)
        linked = (self.path / "control.so").read_bytes(); linked_sections = _sections(linked)
        linked_symbols = {s["name"]: s for s in _symbols(linked, linked_sections)}
        first = linked_symbols["__hia_native_fn_0"]["value"]
        text = linked_sections[".text"]
        start = text["offset"] + first - text["address"]
        actual = linked[start:start + len(image.text_bytes)]
        self.assertEqual(len(actual), len(image.text_bytes))
        relocation_section = object_sections[".rela.text"]
        mutable = set(); relocations = []
        for offset in range(relocation_section["offset"], relocation_section["offset"] + relocation_section["size"], 24):
            site, info, addend = struct.unpack_from("<QQq", obj, offset)
            self.assertEqual((info & 0xffffffff, addend), (4, -4))
            mutable.update(range(site, site + 4))
            target = object_symbols[info >> 32]["name"]
            relocations.append((site, target))
            self.assertEqual(image.text_bytes[site-1], 0xe8)
            displacement = struct.unpack_from("<i", actual, site)[0]
            destination = first + site + 4 + displacement
            if target.startswith("__hia_native_fn_"):
                self.assertEqual(destination, linked_symbols[target]["value"])
            else:
                self.assertEqual(target, "abort")
                self.assertTrue(any(s["address"] <= destination < s["address"] + s["size"]
                                    for n, s in linked_sections.items() if n.startswith(".plt")))
        self.assertGreater(len(relocations), 10)
        self.assertGreater(len(image.text_bytes) - len(mutable), 30000)
        differences = {i for i, (before, after) in enumerate(zip(image.text_bytes, actual)) if before != after}
        self.assertTrue(differences <= mutable, "linker rewrote non-relocation machine instructions")
        # Every function extent maps to the exact emitted bytes in one contiguous image.
        for sym in object_symbols:
            if not sym["name"] or sym["section"] == 0: continue
            if sym["name"] in linked_symbols:
                self.assertEqual(linked_symbols[sym["name"]]["value"], first + sym["value"])
                self.assertEqual(linked_symbols[sym["name"]]["size"], sym["size"])
        self.assertNotIn(".llvm.lto", object_sections)
        self.assertFalse(any("lto" in name for name in object_sections))
        self.case_counts.update({
            "linked_machine_text_bytes": len(image.text_bytes),
            "linked_call_relocations": len(relocations),
            "linked_relocation_bytes": len(mutable),
            "linked_preserved_instruction_bytes": len(image.text_bytes) - len(mutable),
            "linked_non_relocation_byte_differences": len(differences - mutable),
        })


if __name__ == "__main__":
    unittest.main()
