"""Finite witnesses for the declared Selfhost-Core v20 output-format profiles.

The Python side constructs ordinary input assembly and independent mathematical/
Core-VM observations before B0. Native B3 and mutated M3 compile every native
fixture. A finite witness inventory is not a proof of all accepted inputs.

Persist all generations, inputs, outputs and raw child logs:
  python -B tests/test_hia_selfhost_language_coverage.py --output NEW_REPORT.json

unittest uses HIA_SELFHOST_LANGUAGE_EVIDENCE when set; otherwise a temporary
evidence directory is removed only after its tests finish.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

COVERAGE_PATH = "docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json"
SELF_PATH = "tests/test_hia_selfhost_language_coverage.py"
PROFILE = "selfhost-core-linux-x86_64-v20"
WIDTHS = {"u8": 8, "u16": 16, "u32": 32, "u64": 64, "usize": 64}
BINARY_INTEGER = ("int.add.wrap", "int.sub.wrap", "int.mul.wrap", "bit.and", "bit.or", "bit.xor")
CHECKED_BINARY = ("int.add.checked", "int.sub.checked", "int.mul.checked", "int.div.checked", "int.rem.checked")
CHECKED_ARITHMETIC = (*CHECKED_BINARY, "int.neg.checked")
UNARY_INTEGER = ("bit.not", "int.neg.checked")
NEW_INTEGER = ("bit.not", *CHECKED_ARITHMETIC)
SHIFTS = ("int.shl.checked", "int.shr.checked")
COMPARISONS = ("compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge")
INPUT_OPCODES = tuple(sorted(("const", *BINARY_INTEGER, *NEW_INTEGER, *SHIFTS, *COMPARISONS,
    "bool.and", "bool.or", "bool.not", "int.cast", "buffer.len", "buffer.load",
    "buffer.store", "buffer.swap", "buffer.fill", "buffer.fill_range", "buffer.copy",
    "buffer.copy_range", "buffer.move_within", "call", "select",
    "borrow.read", "borrow.mut", "loan.end")))
ELF_OWNED_OPCODES = ("buffer.new", "buffer.try_new", "owner.drop", "owner.move")
ELF_CHAIN_OPCODES = ("chain.empty", "chain.head_mut", "chain.head_read", "chain.is_empty", "chain.pop", "chain.try_push")
NATIVE = (platform.system() == "Linux"
          and platform.machine().lower() in {"x86_64", "amd64"}
          and bool(shutil.which("ld")))
HEADER = ("hia-asm.v1 hepta.hia.program.v8 selfhost\n"
    "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
    "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n")


def digest(data):
    return sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def scalar_cases():
    """Boundary witnesses are specified independently of the HIA encoder."""
    rows = []
    def add(group, typ, op, args, expected, result_type=None, mode=None):
        row = {"id": group + "-" + str(sum(x["group"] == group for x in rows)),
               "group": group, "operand_type": typ, "opcode": op,
               "arguments": args, "result_type": result_type or typ, "expected": expected}
        if mode is not None:
            row["mode"] = mode
        rows.append(row)
    for typ, width in WIDTHS.items():
        mask, high = (1 << width) - 1, 1 << (width - 1)
        for value in (0, 1, high - 1, high, mask):
            add("scalar-" + typ, typ, "const", [], value)
        alternating = int.from_bytes(bytes([0x55]) * (width // 8), "little")
        pairs = ((0, 0), (0, 1), (1, 0), (mask, 1), (mask, mask),
                 (high, 1), (high, high), (mask - 1, 2), (alternating, mask ^ alternating))
        for op in BINARY_INTEGER:
            for a, b in pairs:
                value = {"int.add.wrap": lambda: a + b, "int.sub.wrap": lambda: a - b,
                         "int.mul.wrap": lambda: a * b, "bit.and": lambda: a & b,
                         "bit.or": lambda: a | b, "bit.xor": lambda: a ^ b}[op]() & mask
                add("scalar-" + typ, typ, op, [a, b], value)
        for value in (0, 1, high - 1, high, mask, alternating):
            add("scalar-" + typ, typ, "bit.not", [value], mask ^ value)
        checked_pairs = {
            "int.add.checked": ((0, 0), (0, mask), (mask, 0), (1, mask - 1),
                (mask - 1, 1), (high - 1, 1), (high, high - 1),
                (alternating, mask ^ alternating)),
            "int.sub.checked": ((0, 0), (mask, 0), (mask, mask), (1, 1),
                (mask, 1), (high, 1), (high, high - 1), (mask, high), (alternating, 0)),
        }
        checked_pairs.update({
            "int.mul.checked": ((0, 0), (0, mask), (mask, 0), (mask, 1), (1, mask),
                (high, 1), (1, high), (high - 1, 2), (2, high - 1), (mask // 3, 3)),
            "int.div.checked": ((0, 1), (0, mask), (mask, 1), (mask, mask), (mask, 2),
                (high, 1), (high, 2), (mask, high), (high - 1, high), (mask, 3)),
            "int.rem.checked": ((0, 1), (0, mask), (mask, 1), (mask, mask), (mask, 2),
                (high, 1), (high, 2), (mask, high), (high - 1, high), (mask, 3)),
        })
        add("scalar-" + typ, typ, "int.neg.checked", [0], 0)
        for op, operands in checked_pairs.items():
            for a, b in operands:
                value = {"int.add.checked": lambda: a + b, "int.sub.checked": lambda: a - b,
                         "int.mul.checked": lambda: a * b, "int.div.checked": lambda: a // b,
                         "int.rem.checked": lambda: a % b}[op]()
                if not 0 <= value <= mask:
                    raise AssertionError("positive checked arithmetic oracle is out of range")
                add("scalar-" + typ, typ, op, [a, b], value)
        for op in SHIFTS:
            for a, b in ((0, 0), (1, 0), (1, width - 1), (high, width - 1),
                         (mask, 1), (mask, width - 1)):
                value = ((a << b) if op == "int.shl.checked" else (a >> b)) & mask
                add("scalar-" + typ, typ, op, [a, b], value)
        for op in COMPARISONS:
            for a, b in ((0, 0), (0, 1), (1, 0), (mask, mask), (high, 1),
                         (1, high), (high, high), (mask, mask - 1)):
                value = {"compare.eq": a == b, "compare.ne": a != b,
                         "compare.lt": a < b, "compare.le": a <= b,
                         "compare.gt": a > b, "compare.ge": a >= b}[op]
                add("scalar-" + typ, typ, op, [a, b], value, "bool")
    for typ, width in WIDTHS.items():
        mask, high = (1 << width) - 1, 1 << (width - 1)
        for condition in (False, True):
            for left, right in ((0, mask), (mask, 0), (high, high - 1), (1, mask - 1)):
                add("scalar-" + typ, typ, "select", [condition, left, right], left if condition else right)
    for condition in (False, True):
        for left in (False, True):
            for right in (False, True):
                add("boolean", "bool", "select", [condition, left, right], left if condition else right)
    for value in (False, True):
        add("boolean", "bool", "const", [], value)
        add("boolean", "bool", "bool.not", [value], not value)
    for op in ("bool.and", "bool.or", "compare.eq", "compare.ne"):
        for a in (False, True):
            for b in (False, True):
                value = {"bool.and": a and b, "bool.or": a or b,
                         "compare.eq": a == b, "compare.ne": a != b}[op]
                add("boolean", "bool", op, [a, b], value)
    for source, sw in WIDTHS.items():
        for target, tw in WIDTHS.items():
            for value in (0, 1, (1 << (sw - 1)) - 1, 1 << (sw - 1), (1 << sw) - 1):
                add("cast", source, "int.cast", [value], value & ((1 << tw) - 1), target, "wrap")
            width = min(sw, tw)
            for value in (0, 1, (1 << (width - 1)) - 1, 1 << (width - 1), (1 << width) - 1):
                add("checked-cast", source, "int.cast", [value], value, target, "checked")
    return rows


class Assembly:
    """A fixture writer, not a compiler or an alternate admission path."""
    def __init__(self, serial=3):
        self.lines = []
        self.serial = serial

    def emit(self, typ, op, args=(), attrs=None):
        name = "v" + str(self.serial)
        self.serial += 1
        suffix = " " + json.dumps(attrs, separators=(",", ":")) if attrs else ""
        self.lines.append("  " + name + ":" + typ + " = " + op + "(" + ",".join(args) + ")" + suffix)
        return name

    def const(self, typ, value):
        return self.emit(typ, "const", attrs={"value": value})

    def effect(self, op, args):
        self.lines.append("  _ = " + op + "(" + ",".join(args) + ")")

    def result(self, case):
        args = [self.const("bool" if case["opcode"] == "select" and i == 0 else case["operand_type"], value)
                for i, value in enumerate(case["arguments"])]
        if case["opcode"] == "const":
            return self.const(case["result_type"], case["expected"])
        attrs = {"mode": case["mode"]} if "mode" in case else None
        return self.emit(case["result_type"], case["opcode"], args, attrs)

    def text(self):
        return "\n".join(self.lines) + "\n"


def scalar_reference_source(case):
    a = Assembly(0)
    result = a.result(case)
    return ("hia-asm.v1 hepta.hia.program.v8 language_reference\n"
        "fn f0() -> (" + case["result_type"] + ") effects(read,write,trap) entry(b0)\n"
        "block b0()\n" + a.text() + "  ret(" + result + ")\nend\n").encode()


def scalar_fixture(group, rows, *, input_arguments=False):
    a = Assembly()
    input_bytes = bytearray()
    for index, case in enumerate(rows):
        if input_arguments:
            if case["opcode"] not in (*NEW_INTEGER, "int.cast") or case["operand_type"] != rows[0]["operand_type"]:
                raise ValueError("dynamic fixture needs one integer type and an integer operation or cast")
            args = []
            for value in case["arguments"]:
                offset = a.const("usize", len(input_bytes))
                args.append(a.emit(case["operand_type"], "call", ["v0", offset], {"function": "f3"}))
                input_bytes.extend(value.to_bytes(WIDTHS[case["operand_type"]] // 8, "little"))
            attrs = {"mode": case["mode"]} if "mode" in case else None
            result = a.emit(case["result_type"], case["opcode"], args, attrs)
        else:
            result = a.result(case)
        if case["result_type"] == "bool":
            word = a.emit("u64", "call", [result], {"function": "f1"})
        else:
            word = a.emit("u64", "int.cast", [result], {"mode": "wrap"})
        offset = a.const("usize", index * 8)
        a.emit("u32", "call", ["v1", offset, word], {"function": "f2"})
    size = a.const("u32", len(rows) * 8)
    bool_helper = ("fn f1(v0:bool) -> (u64) effects(read,write,trap) entry(b0)\n"
        "block b0(v0:bool)\n  branch v0 b1() b2()\n"
        'block b1()\n  v1:u64 = const() {"value":1}\n  ret(v1)\n'
        'block b2()\n  v2:u64 = const() {"value":0}\n  ret(v2)\nend\n')
    word = Assembly(3)
    for byte in range(8):
        amount = word.const("u64", byte * 8)
        shifted = word.emit("u64", "int.shr.checked", ["v2", amount])
        value = word.emit("u8", "int.cast", [shifted], {"mode": "wrap"})
        delta = word.const("usize", byte)
        offset = word.emit("usize", "int.add.wrap", ["v1", delta])
        word.effect("buffer.store", ["v0", offset, value])
    returned = word.const("u32", 0)
    word_helper = ("fn f2(v0:mutbuf,v1:usize,v2:u64) -> (u32) effects(read,write,trap) entry(b0)\n"
        "block b0(v0:mutbuf,v1:usize,v2:u64)\n" + word.text() + "  ret(" + returned + ")\nend\n")
    input_helper = ""
    if input_arguments:
        typ = rows[0]["operand_type"]
        reader = Assembly(2)
        combined = reader.const(typ, 0)
        for byte in range(WIDTHS[typ] // 8):
            delta = reader.const("usize", byte)
            offset = reader.emit("usize", "int.add.wrap", ["v1", delta])
            value = reader.emit("u8", "buffer.load", ["v0", offset])
            widened = reader.emit(typ, "int.cast", [value], {"mode": "wrap"})
            amount = reader.const(typ, byte * 8)
            shifted = reader.emit(typ, "int.shl.checked", [widened, amount])
            combined = reader.emit(typ, "bit.or", [combined, shifted])
        input_helper = ("fn f3(v0:readbuf,v1:usize) -> (" + typ + ") effects(read,write,trap) entry(b0)\n"
            "block b0(v0:readbuf,v1:usize)\n" + reader.text() + "  ret(" + combined + ")\nend\n")
    source = (HEADER + a.text() + "  ret(" + size + ")\nend\n" + bool_helper + word_helper + input_helper).encode()
    return {"id": group, "kind": "scalar", "source": source, "input": bytes(input_bytes),
            "input_arguments": input_arguments,
            "capacity": len(rows) * 8, "workspace_size": 0,
            "expected_result": len(rows) * 8,
            "expected_output": b"".join(struct.pack("<Q", int(row["expected"])) for row in rows),
            "case_ids": [row["id"] for row in rows]}


def boundary_fixture(label, source, expected=7):
    return {"id": label, "kind": "boundary", "source": source, "input": b"",
            "capacity": 8, "workspace_size": 0, "expected_result": expected,
            "expected_output": bytes([0xa5]) * 8, "case_ids": [label]}


def simple_source(value=7, variable=3):
    return (HEADER + f'  v{variable}:u32 = const() {{"value":{value}}}\n'
            f"  ret(v{variable})\nend\n").encode()


def block_source(counts):
    lines = []
    for fn, count in enumerate(counts):
        if fn == 0:
            lines.append(HEADER)
            serial = 3
        else:
            lines.append(f"fn f{fn}() -> (u32) effects(read,write,trap) entry(b0)\nblock b0()\n")
            serial = 0
        for block in range(count):
            if block:
                lines.append(f"block b{block}()\n")
            if block + 1 < count:
                lines.append(f"  jump b{block + 1}()\n")
            else:
                lines.append(f'  v{serial}:u32 = const() {{"value":7}}\n  ret(v{serial})\n')
        lines.append("end\n")
    return "".join(lines).encode()


def parameter_source(count):
    a = Assembly()
    args = [a.const("u8", i) for i in range(count)]
    result = a.emit("u32", "call", args, {"function": "f1"})
    params = ",".join("v" + str(i) + ":u8" for i in range(count))
    b = Assembly(count)
    current = "v0"
    for i in range(1, count):
        current = b.emit("u8", "int.add.wrap", [current, "v" + str(i)])
    returned = b.emit("u32", "int.cast", [current], {"mode": "wrap"})
    return (HEADER + a.text() + "  ret(" + result + ")\nend\n"
        + "fn f1(" + params + ") -> (u32) effects(read,write,trap) entry(b0)\n"
        + "block b0(" + params + ")\n" + b.text() + "  ret(" + returned + ")\nend\n").encode()


def buffer_fixture():
    a = Assembly()
    indices = [a.const("usize", i) for i in range(8)]
    for destination, resource in enumerate(("v0", "v1", "v2")):
        length = a.emit("usize", "buffer.len", [resource])
        byte = a.emit("u8", "int.cast", [length], {"mode": "wrap"})
        a.effect("buffer.store", ["v1", indices[destination], byte])
    first = a.emit("u8", "buffer.load", ["v0", indices[0]])
    last = a.emit("u8", "buffer.load", ["v0", indices[3]])
    a.effect("buffer.store", ["v1", indices[3], first])
    a.effect("buffer.store", ["v1", indices[4], last])
    observed = a.emit("u8", "buffer.load", ["v1", indices[4]])
    a.effect("buffer.store", ["v2", indices[0], observed])
    workspace = a.emit("u8", "buffer.load", ["v2", indices[0]])
    a.effect("buffer.store", ["v1", indices[5], workspace])
    a.effect("buffer.swap", ["v1", indices[3], indices[4]])
    result = a.const("u32", 8)
    source = (HEADER + a.text() + "  ret(" + result + ")\nend\n").encode()
    return {"id": "borrowed-buffer-operations", "kind": "buffer", "source": source,
            "input": bytes([0x12, 0x7f, 0x80, 0xfe]), "capacity": 8, "workspace_size": 5,
            "expected_result": 8, "expected_output": bytes([4, 8, 5, 0xfe, 0x12, 0xfe, 0xa5, 0xa5]),
            "case_ids": ["buffer.len-readbuf", "buffer.len-mutbuf", "buffer.load-readbuf",
                         "buffer.load-mutbuf", "buffer.store-mutbuf", "buffer.swap-mutbuf"]}


def buffer_reference_source(fixture):
    """Only a general-Core owner wrapper is added; native body bytes are kept."""
    a = Assembly(0)
    owners, loans = [], []
    for initial in (fixture["input"], bytes([0xa5]) * fixture["capacity"],
                    bytes(fixture["workspace_size"])):
        length = a.const("usize", len(initial))
        owner = a.emit("buffer", "buffer.new", [length])
        loan = a.emit("mutbuf", "borrow.mut", [owner])
        for i, value in enumerate(initial):
            index, byte = a.const("usize", i), a.const("u8", value)
            a.effect("buffer.store", [loan, index, byte])
        owners.append(owner)
        loans.append(loan)
    a.effect("loan.end", [loans[0]])
    loans[0] = a.emit("readbuf", "borrow.read", [owners[0]])
    a.emit("u32", "call", loans, {"function": "f0"})
    returned = []
    for i in range(fixture["capacity"]):
        index = a.const("usize", i)
        returned.append(a.emit("u8", "buffer.load", [loans[1], index]))
    for loan in loans:
        a.effect("loan.end", [loan])
    for owner in owners:
        a.effect("owner.drop", [owner])
    wrapper = ("hia-asm.v1 hepta.hia.program.v8 language_reference\n"
        "fn reference_entry() -> (" + ",".join(["u8"] * len(returned)) + ") effects(alloc,read,write,trap) entry(b0)\n"
        "block b0()\n" + a.text() + "  ret(" + ",".join(returned) + ")\nend\n")
    body = fixture["source"].decode().split("\n", 1)[1]
    return (wrapper + body).encode()


def select_input_fixtures():
    """Same native program per type, with both condition and values from input."""
    fixtures = []
    for typ, width in WIDTHS.items():
        a = Assembly()
        zero8 = a.const("u8", 0)
        flag = a.emit("u8", "buffer.load", ["v0", a.const("usize", 0)])
        condition = a.emit("bool", "compare.ne", [flag, zero8])
        operands = []
        for base in (1, 9):
            value = a.const("u64", 0)
            for index in range(8):
                byte = a.emit("u8", "buffer.load", ["v0", a.const("usize", base + index)])
                word = a.emit("u64", "int.cast", [byte], {"mode": "wrap"})
                shifted = a.emit("u64", "int.shl.checked", [word, a.const("u64", index * 8)])
                value = a.emit("u64", "bit.or", [value, shifted])
            operands.append(a.emit(typ, "int.cast", [value], {"mode": "wrap"}))
        selected = a.emit(typ, "select", [condition, *operands])
        word = a.emit("u64", "int.cast", [selected], {"mode": "wrap"})
        for index in range(8):
            shifted = a.emit("u64", "int.shr.checked", [word, a.const("u64", index * 8)])
            byte = a.emit("u8", "int.cast", [shifted], {"mode": "wrap"})
            a.effect("buffer.store", ["v1", a.const("usize", index), byte])
        result = a.emit("u32", "int.cast", [selected], {"mode": "wrap"})
        source = (HEADER + a.text() + "  ret(" + result + ")\nend\n").encode()
        mask, high = (1 << width) - 1, 1 << (width - 1)
        for i, (flag, left, right) in enumerate(((0, 0, mask), (1, mask, 0),
                (0, high, high - 1), (1, high, mask), (255, mask - 1, 1))):
            expected = left if flag else right
            fixtures.append({"id": "select-input-" + typ + "-" + str(i), "kind": "buffer",
                "source": source, "input": bytes([flag]) + struct.pack("<QQ", left, right),
                "capacity": 8, "workspace_size": 0, "expected_result": expected & 0xffffffff,
                "expected_output": struct.pack("<Q", expected), "case_ids": ["select-" + typ]})
    a = Assembly()
    zero = a.const("u8", 0)
    values = []
    for index in range(3):
        byte = a.emit("u8", "buffer.load", ["v0", a.const("usize", index)])
        values.append(a.emit("bool", "compare.ne", [byte, zero]))
    selected = a.emit("bool", "select", values)
    source = HEADER + a.text() + "  branch " + selected + " b1(v1) b2(v1)\n"
    for block, serial, value in ((1, 1000, 1), (2, 1010, 0)):
        a = Assembly(serial + 1)
        a.effect("buffer.store", ["v" + str(serial), a.const("usize", 0), a.const("u8", value)])
        result = a.const("u32", value)
        source += "block b" + str(block) + "(v" + str(serial) + ":mutbuf)\n" + a.text() + "  ret(" + result + ")\n"
    source = (source + "end\n").encode()
    for condition in (0, 1):
        for left in (0, 1):
            for right in (0, 1):
                expected = left if condition else right
                fixtures.append({"id": f"select-input-bool-{condition}{left}{right}", "kind": "buffer",
                    "source": source, "input": bytes([condition, left, right]), "capacity": 8,
                    "workspace_size": 0, "expected_result": expected,
                    "expected_output": bytes([expected]) + bytes([0xa5]) * 7, "case_ids": ["select-bool"]})
    return fixtures


def boolean_equality_input_fixtures():
    """Both equality operands change through input bytes in one program per op."""
    fixtures = []
    for opcode in ("compare.eq", "compare.ne"):
        a = Assembly()
        values = []
        for offset in (0, 1):
            index, zero = a.const("usize", offset), a.const("u8", 0)
            byte = a.emit("u8", "buffer.load", ["v0", index])
            values.append(a.emit("bool", "compare.ne", [byte, zero]))
        condition = a.emit("bool", opcode, values)
        one, zero = a.const("u32", 1), a.const("u32", 0)
        result = a.emit("u32", "select", [condition, one, zero])
        byte = a.emit("u8", "int.cast", [result], {"mode": "wrap"})
        index = a.const("usize", 0)
        a.effect("buffer.store", ["v1", index, byte])
        source = (HEADER + a.text() + "  ret(" + result + ")\nend\n").encode()
        for left in (False, True):
            for right in (False, True):
                expected = int((left == right) if opcode == "compare.eq" else (left != right))
                fixtures.append({"id": "bool-equality-input-" + opcode + "-"
                    + str(int(left)) + str(int(right)), "kind": "buffer", "source": source,
                    "input": bytes([int(left), int(right)]), "capacity": 8, "workspace_size": 0,
                    "expected_result": expected,
                    "expected_output": bytes([expected]) + bytes([0xa5]) * 7,
                    "case_ids": ["bool-" + opcode]})
    return fixtures


def positive_fixtures():
    rows = scalar_cases()
    groups = list(dict.fromkeys(row["group"] for row in rows))
    fixtures = [scalar_fixture(group, [row for row in rows if row["group"] == group])
                for group in groups]
    # The independent wrapper returns every observed byte. Keep each batch
    # within the shared 128-result budget rather than weakening that budget.
    for typ in WIDTHS:
        dynamic = [row for row in rows if row["operand_type"] == typ and row["opcode"] in NEW_INTEGER]
        fixtures += [scalar_fixture("dynamic-integer-" + typ + "-" + str(index // 16),
            dynamic[index:index + 16], input_arguments=True) for index in range(0, len(dynamic), 16)]
        for target in WIDTHS:
            casts = [row for row in rows if row["operand_type"] == typ
                     and row["result_type"] == target and row.get("mode") == "checked"]
            fixtures.append(scalar_fixture("dynamic-cast-" + typ + "-" + target,
                                           casts, input_arguments=True))
    fixtures += boolean_equality_input_fixtures()
    fixtures += select_input_fixtures()
    fixtures += u16_flow_fixtures()
    from tools.hia_selfhost_bulk import OPS, bulk_cases, fixture_source, oracle
    for op in OPS:
        case = dict(next(row for row in bulk_cases() if row['opcode'] == op))
        case['initial_hex'] = bytes([0xa5] * 8).hex()
        trap, expected = oracle(case)
        assert not trap
        fixtures.append({'id': 'bulk-' + op, 'kind': 'buffer',
            'source': fixture_source(case), 'input': bytes.fromhex(case['source_hex']),
            'capacity': 8, 'workspace_size': 0, 'expected_result': 0,
            'expected_output': expected, 'case_ids': [op]})
    from tools.hia_selfhost_loans import loan_cases
    loans = {case["id"]: case for case in loan_cases()}
    for name, expected in (("shared-depth-8", bytes([0xa5]) * 8),
                           ("exclusive-after-shared-close", bytes([201]) * 8),
                           ("loan-through-loop-backedge", bytes([0, 1, 2, 3]) + bytes([0xa5]) * 4),
                           ("incoming-from-later-source-block", bytes([77]) * 8)):
        case = loans[name]
        fixtures.append({"id": "loan-" + name, "kind": "buffer", "source": case["source"].encode(),
            "input": bytes.fromhex(case["source_hex"]), "capacity": 8, "workspace_size": 0,
            "expected_result": case["expected_result"], "expected_output": expected,
            "case_ids": ["borrow.read", "borrow.mut", "loan.end"]})
    fixtures += [buffer_fixture(), boundary_fixture("parameters-16", parameter_source(16), 120),
                 boundary_fixture("blocks-per-function-256", block_source([256])),
                 boundary_fixture("blocks-total-1536", block_source([256] * 6)),
                 boundary_fixture("ssa-index-2047", simple_source(variable=2047))]
    spaced = simple_source().replace(b",", b" , ").replace(b" = ", b"   =   ")
    spaced = spaced.replace(b'{"value":7}', b'{ "value" : 7 }')
    fixtures.append(boundary_fixture("optional-ascii-spaces", spaced))
    # Preserve the former valid-Core/profile refusal as an admitted witness.
    fixtures.append(boundary_fixture("effect-trap-unused",
        simple_source().replace(b"effects(read,write,trap)", b"effects(trap)")))
    # Distribute spaces across real lines: the independent assembly frontend
    # also has a 16 KiB per-line transport limit, separate from the 1 MiB source bound.
    lines = block_source([256] * 6).splitlines(keepends=True)
    remaining = (1 << 20) - sum(map(len, lines))
    per_line, extra = divmod(remaining, len(lines))
    padded = b"".join(b" " * (per_line + int(i < extra)) + line for i, line in enumerate(lines))
    fixtures.append(boundary_fixture("source-bytes-1048576", padded))
    return fixtures


def u16_flow_fixtures():
    """u16 is scalar even though its native type code follows owned types."""
    repeated = (HEADER +
        '  v3:u16 = const() {"value":65535}\n'
        '  v4:u16 = call(v3,v3) {"function":"f1"}\n'
        '  v5:u32 = int.cast(v4) {"mode":"wrap"}\n  ret(v5)\nend\n'
        'fn f1(v0:u16,v1:u16) -> (u16) effects(read,write,trap) entry(b0)\n'
        'block b0(v0:u16,v1:u16)\n  v2:bool = compare.eq(v0,v1)\n'
        '  branch v2 b1(v0,v0) b1(v0,v1)\n'
        'block b1(v3:u16,v4:u16)\n'
        '  v5:u16 = int.add.wrap(v3,v4)\n  ret(v5)\nend\n').encode()
    tail = (HEADER +
        '  v3:u16 = const() {"value":65535}\n'
        '  v4:u16 = const() {"value":32768}\n'
        '  v5:u16 = const() {"value":4}\n'
        '  v6:u16 = call(v3,v4,v5) {"function":"f1"}\n'
        '  v7:u32 = int.cast(v6) {"mode":"wrap"}\n  ret(v7)\nend\n'
        'fn f1(v0:u16,v1:u16,v2:u16) -> (u16) effects(read,write,trap) entry(b0)\n'
        'block b0(v0:u16,v1:u16,v2:u16)\n'
        '  v3:u16 = const() {"value":0}\n'
        '  v4:bool = compare.eq(v2,v3)\n'
        '  branch v4 b1(v0,v1) b2(v0,v1,v2)\n'
        'block b1(v5:u16,v6:u16)\n'
        '  v7:u16 = int.add.wrap(v5,v6)\n  ret(v7)\n'
        'block b2(v8:u16,v9:u16,v10:u16)\n'
        '  v11:u16 = const() {"value":1}\n'
        '  v12:u16 = int.sub.checked(v10,v11)\n'
        '  v13:u16 = int.add.wrap(v8,v9)\n'
        '  v14:u16 = call(v9,v13,v12) {"function":"f1"}\n'
        '  ret(v14)\nend\n').encode()
    return [boundary_fixture("u16-repeated-call-and-edge", repeated, 65534),
            boundary_fixture("u16-tail-call-swap-and-wrap", tail, 65531)]


def rejected_fixtures():
    """Invalid Core is distinct from valid Core outside the bounded profile."""
    from tools.qualify_hia_selfhost import SAMPLE, invalid_sources
    from tools.hia_selfhost_cases import (backward_chain_source, scalar_function,
                                         call_graph_invalid_sources, recursion_refusals)
    from tools.hia_selfhost_resources import swap_refusals
    from tools.hia_selfhost_tailcalls import tail_refusals
    rows = {}
    def add(name, source, boundary, general_core=None):
        rows[name] = {"id": name, "source": source, "boundary": boundary,
                      "general_core_expected": general_core}
    for name, source in invalid_sources(SAMPLE.read_bytes()).items():
        add("existing-" + name, source, "grammar, types, SSA, control and resource admission", "rejected")
    for name, source in call_graph_invalid_sources(SAMPLE.read_bytes()).items():
        add("call-" + name, source, "exact direct-call signature/target", "rejected")
    for name, source in recursion_refusals().items():
        add("recursion-" + name, source, "v6 checked tail-self-only recursion", "accepted")
    for name, source in swap_refusals().items():
        add("swap-" + name, source, "mutbuf, usize indices, zero results, exact arity", "rejected")
    from tools.hia_selfhost_bulk import bulk_refusals
    for name, source in bulk_refusals().items():
        add('bulk-' + name, source, 'exact borrowed bulk signature and zero results', 'rejected')
    from tools.hia_selfhost_loans import loan_refusals, loan_profile_refusals
    for name, source in loan_refusals().items():
        add('loan-' + name, source, 'exact active capability roots, parents and closed transfers', 'rejected')
    for name, source in loan_profile_refusals().items():
        add('loan-profile-' + name, source, 'resource result SSA index at most 2047', 'accepted')
    # Existing tail witnesses are independently classified by their own helper.
    for name, (source, general_core) in tail_refusals().items():
        add("tail-" + name, source, "immediate exact tail return and mutable arguments",
            "accepted" if general_core else "rejected")
    selection = (HEADER + '  v3:bool = const() {"value":true}\n'
        '  v4:u32 = const() {"value":1}\n  v5:u32 = const() {"value":2}\n'
        '  v6:u8 = const() {"value":3}\n  v7:bool = const() {"value":false}\n')
    invalid_selections = [("arity-" + str(n), "v8:u32", ",".join(["v3", "v4", "v5", "v4"][:n]))
                          for n in (0, 1, 2, 4)]
    invalid_selections += [("condition", "v8:u32", "v4,v4,v5"),
        ("unlike-values", "v8:u32", "v3,v4,v6"),
        ("unlike-values-reversed", "v8:u8", "v3,v6,v4"),
        ("result-type", "v8:u8", "v3,v4,v5"),
        ("bool-integer-mix", "v8:bool", "v3,v7,v4"),
        ("readonly-resource", "v8:readbuf", "v3,v0,v0"),
        ("mutable-resource", "v8:mutbuf", "v3,v1,v2"),
        ("void-result", "_", "v3,v4,v5"),
        ("undefined-third", "v8:u32", "v3,v4,v99")]
    for name, output, arguments in invalid_selections:
        source = (selection + f"  {output} = select({arguments})\n  ret(v4)\nend\n").encode()
        add("select-" + name, source, "bool condition, three operands, matching scalar values/result", "rejected")
    seed = simple_source()
    additions = (
        ("parameters-17", parameter_source(17), "16 parameters/arguments"),
        ("blocks-per-function-257", block_source([257]), "256 blocks per function"),
        ("blocks-total-1537", block_source([256] * 6 + [1]), "1536 total blocks"),
        ("functions-129", backward_chain_source() + scalar_function(128).encode(), "128 functions"),
        ("ssa-index-2048", simple_source(variable=2048), "maximum SSA index 2047"),
        ("noncontiguous-function", seed.replace(b"fn f0(", b"fn f1(", 1), "contiguous function numbers"),
        ("entry-signature-name", seed.replace(b"block b0(v0:", b"block b0(v3:", 1), "entry signature names/types"),
        ("non-u32-public-entry-i16", seed.replace(b"v3:u32", b"v3:i16").replace(b"-> (u32)", b"-> (i16)"), "public entry remains u32 despite internal signed scalar support"),
        ("unsupported-module-name", seed.replace(b"v8 selfhost", b"v8 arbitrary"), "fixed input module"),
        ("unsupported-arbitrary-function-name", seed.replace(b"f0(", b"named("), "numeric function identifiers"),
        ("tab-whitespace", seed.replace(b"  v3", b"\tv3"), "ASCII space and LF only"),
        ("crlf-whitespace", seed.replace(b"\n", b"\r\n"), "ASCII space and LF only"),
        ("unknown-cast-mode", parameter_source(1).replace(b'"mode":"wrap"', b'"mode":"truncate"'), "closed checked/wrap cast modes"),
        ("inbound-entry-edge", (HEADER + "  jump b0(v0,v1,v2)\nend\n").encode(), "no inbound entry edges"),
        ("bool-as-integer", (HEADER + '  v3:bool = const() {"value":true}\n'
            '  v4:bool = int.add.wrap(v3,v3)\n  v5:u32 = const() {"value":0}\n  ret(v5)\nend\n').encode(),
            "integer/boolean type distinction"),
        ("unsigned-comparison-type-mismatch", (HEADER +
            '  v3:u8 = const() {"value":1}\n  v4:u32 = const() {"value":1}\n'
            '  v5:bool = compare.eq(v3,v4)\n  v6:u32 = const() {"value":0}\n  ret(v6)\nend\n').encode(),
            "matching unsigned comparison operands"),
        ("integer-op-arity", (HEADER +
            '  v3:u32 = const() {"value":1}\n  v4:u32 = int.add.wrap(v3)\n  ret(v4)\nend\n').encode(),
            "exact operation arity"),
        ("integer-const-arity", seed.replace(b"const()", b"const(v0)"), "zero-argument const"),
        ("boolean-literal-not-integer", seed.replace(b'{"value":7}', b'{"value":true}'), "typed literals"),
        ("integer-literal-not-boolean", (HEADER +
            '  v3:bool = const() {"value":1}\n  v4:u32 = const() {"value":0}\n  ret(v4)\nend\n').encode(),
            "typed literals"),
    )
    for name, source, boundary in additions:
        add(name, source, boundary)
    equality = (HEADER + '  v3:bool = const() {"value":true}\n'
        '  v4:bool = const() {"value":false}\n  v5:bool = compare.eq(v3,v4)\n'
        '  v6:u32 = const() {"value":0}\n  ret(v6)\nend\n').encode()
    for opcode in ("compare.lt", "compare.le", "compare.gt", "compare.ge"):
        add("boolean-ordering-" + opcode, equality.replace(b"compare.eq", opcode.encode()),
            "booleans support equality but not integer ordering", "rejected")
    for label, source in {
        "left-integer": equality.replace(b'v3:bool = const() {"value":true}',
                                         b'v3:u8 = const() {"value":1}'),
        "right-integer": equality.replace(b'v4:bool = const() {"value":false}',
                                          b'v4:u8 = const() {"value":0}'),
        "resource-operands": equality.replace(b"compare.eq(v3,v4)", b"compare.eq(v0,v0)"),
        "integer-result": equality.replace(b"v5:bool =", b"v5:u8 ="),
    }.items():
        add("boolean-equality-" + label, source, "matching equality scalar types and bool result", "rejected")
    cast = (HEADER + '  v3:u32 = const() {"value":1}\n'
        '  v4:u8 = int.cast(v3) {"mode":"checked"}\n'
        '  v5:u32 = const() {"value":0}\n  ret(v5)\nend\n').encode()
    for label, source in {
        "boolean-input": cast.replace(b'v3:u32 = const() {"value":1}',
                                       b'v3:bool = const() {"value":true}'),
        "boolean-result": cast.replace(b"v4:u8 =", b"v4:bool ="),
        "resource-input": cast.replace(b"int.cast(v3)", b"int.cast(v0)"),
        "short-arity": cast.replace(b"int.cast(v3)", b"int.cast()"),
        "long-arity": cast.replace(b"int.cast(v3)", b"int.cast(v3,v3)"),
        "discarded-result": cast.replace(b"v4:u8 =", b"_ ="),
        "unquoted-mode": cast.replace(b'"checked"', b"checked"),
    }.items():
        add("checked-cast-" + label, source, "one integer operand/result and quoted checked mode", "rejected")
    scalar_resource_prefix = HEADER.replace("v8 selfhost\n", "v8 selfhost_elf\n").replace(
        "effects(read,write,trap)", "effects(alloc,read,write,trap)")
    for name, instruction in (
            ("owner-drop", "_ = owner.drop(v3)"),
            ("owner-move", "v4:u16 = owner.move(v3)"),
            ("loan-end", "_ = loan.end(v3)"),
            ("borrow-read", "v4:readbuf = borrow.read(v3)"),
            ("buffer-length", "v4:usize = buffer.len(v3)")):
        source = (scalar_resource_prefix + '  v3:u16 = const() {"value":65535}\n'
            + "  " + instruction + '\n  v5:u32 = const() {"value":0}\n  ret(v5)\nend\n').encode()
        add("u16-not-resource-" + name, source, "u16 is neither owner nor loan", "rejected")
    for op in NEW_INTEGER:
        arguments = "v3" if op in UNARY_INTEGER else "v3,v4"
        valid = (HEADER + '  v3:u32 = const() {"value":1}\n'
            '  v4:u32 = const() {"value":1}\n  v5:u32 = ' + op + '(' + arguments + ')\n'
            '  v6:u32 = const() {"value":0}\n  ret(v6)\nend\n').encode()
        token = op.encode() + b"(" + arguments.encode() + b")"
        bad_shapes = {
            "short-arity": valid.replace(token, op.encode() + b"(" + (b"" if op in UNARY_INTEGER else b"v3") + b")"),
            "long-arity": valid.replace(token, op.encode() + b"(" + arguments.encode() + b",v4)"),
            "result-type": valid.replace(b"v5:u32", b"v5:u8"),
            "missing-result": valid.replace(b"v5:u32 =", b"_ ="),
            "buffer-operand": valid.replace(token, op.encode() + b"(" + arguments.encode().replace(b"v3", b"v0") + b")"),
            "boolean-operand": valid.replace(b"v3:u32", b"v3:bool").replace(b"v4:u32", b"v4:bool")
                .replace(b"v5:u32", b"v5:bool").replace(b'{"value":1}', b'{"value":true}'),
            "unexpected-attribute": valid.replace(token, token + b' {"mode":"wrap"}'),
        }
        if op in CHECKED_BINARY:
            bad_shapes["operand-type-mismatch"] = valid.replace(b"v4:u32", b"v4:u8")
        for name, source in bad_shapes.items():
            add(op + "-" + name, source, "exact unsigned operation signature and empty attributes", "rejected")
        for typ, width in WIDTHS.items():
            source = valid.replace(b":u32 =", (":" + typ + " =").encode(), 3)
            source = source.replace(b'{"value":1}', ('{"value":' + str(1 << width) + '}').encode(), 1)
            add(op + "-" + typ + "-literal-overflow", source, "typed literal must fit the operand width", "rejected")
    return list(rows.values())


def shift_trap_cases():
    rows = []
    for typ, width in WIDTHS.items():
        for op in SHIFTS:
            for amount in (width, width + 1):
                a = Assembly()
                value, shift = a.const(typ, 1), a.const(typ, amount)
                result = a.emit(typ, op, [value, shift])
                result = a.emit("u32", "int.cast", [result], {"mode": "wrap"})
                source = (HEADER + a.text() + "  ret(" + result + ")\nend\n").encode()
                rows.append({"id": "shift-trap-" + typ + "-" + op.split(".")[1] + "-" + str(amount),
                             "kind": "shift", "operand_type": typ, "opcode": op, "amount": amount,
                             "expected_output": bytes([0xa5]) * 8, "source": source})
    return rows


def checked_arithmetic_trap_cases():
    """Overflow must abort before a later store; earlier stores are observable."""
    rows = []
    for typ, width in WIDTHS.items():
        mask, high = (1 << width) - 1, 1 << (width - 1)
        inputs = {
            "int.add.checked": ((mask, 1), (1, mask), (high, high), (mask, mask)),
            "int.sub.checked": ((0, 1), (0, mask), (mask - 1, mask), (high - 1, high)),
            "int.mul.checked": ((mask, 2), (2, mask), (high, 2), (mask, mask)),
            "int.div.checked": ((0, 0), (1, 0), (high, 0), (mask, 0)),
            "int.rem.checked": ((0, 0), (1, 0), (high, 0), (mask, 0)),
            "int.neg.checked": ((1, 0), (high - 1, 0), (high, 0), (mask, 0)),
        }
        for op, operands in inputs.items():
            for index, (left, right) in enumerate(operands):
                for prior_store in ((False, True) if index == 0 else (True,)):
                    a = Assembly()
                    first, second = a.const("usize", 0), a.const("usize", 1)
                    before, after = a.const("u8", 99), a.const("u8", 77)
                    if prior_store:
                        a.effect("buffer.store", ["v1", first, before])
                    values = [left] if op == "int.neg.checked" else [left, right]
                    operands = [a.const(typ, value) for value in values]
                    result = a.emit(typ, op, operands)
                    a.effect("buffer.store", ["v1", second, after])
                    result = a.emit("u32", "int.cast", [result], {"mode": "wrap"})
                    source = (HEADER + a.text() + "  ret(" + result + ")\nend\n").encode()
                    case = {"operand_type": typ, "opcode": op, "arguments": values,
                            "result_type": typ}
                    rows.append({**case, "id": "checked-trap-" + typ + "-" + op.split(".")[1]
                        + "-" + str(index) + ("-prior-store" if prior_store else "-no-prior-store"),
                        "kind": "checked_arithmetic", "prior_store": prior_store, "source": source,
                        "reference_source": scalar_reference_source(case),
                        "expected_output": bytes([99 if prior_store else 0xa5]) + bytes([0xa5]) * 7})
    return rows


def checked_cast_trap_cases():
    """Narrowing overflow depends on input bytes, with both visible write orders."""
    rows = []
    for source_type, source_width in WIDTHS.items():
        for target_type, target_width in WIDTHS.items():
            if source_width <= target_width:
                continue
            for index, value in enumerate((1 << target_width, (1 << source_width) - 1)):
                for prior_store in (False, True):
                    a = Assembly()
                    before, after = a.const("u8", 99), a.const("u8", 77)
                    first, second = a.const("usize", 0), a.const("usize", 1)
                    if prior_store:
                        a.effect("buffer.store", ["v1", first, before])
                    operand = a.const(source_type, 0)
                    for byte in range(source_width // 8):
                        offset = a.const("usize", byte)
                        part = a.emit("u8", "buffer.load", ["v0", offset])
                        part = a.emit(source_type, "int.cast", [part], {"mode": "wrap"})
                        amount = a.const(source_type, byte * 8)
                        part = a.emit(source_type, "int.shl.checked", [part, amount])
                        operand = a.emit(source_type, "bit.or", [operand, part])
                    result = a.emit(target_type, "int.cast", [operand], {"mode": "checked"})
                    a.effect("buffer.store", ["v1", second, after])
                    result = a.emit("u32", "int.cast", [result], {"mode": "wrap"})
                    source = (HEADER + a.text() + "  ret(" + result + ")\nend\n").encode()
                    case = {"operand_type": source_type, "result_type": target_type,
                            "opcode": "int.cast", "mode": "checked", "arguments": [value]}
                    rows.append({**case, "id": "checked-cast-trap-" + source_type + "-" + target_type
                        + "-" + str(index) + ("-prior-store" if prior_store else "-no-prior-store"),
                        "kind": "checked_cast", "prior_store": prior_store, "source": source,
                        "input": value.to_bytes(source_width // 8, "little"),
                        "reference_source": scalar_reference_source(case),
                        "expected_output": bytes([99 if prior_store else 0xa5]) + bytes([0xa5]) * 7})
    return rows


def independent_references():
    """Run Core VM before B0 and preserve its disagreement with any oracle."""
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    from hepta.hia_program_runtime import HIAProgramTrap
    scalar = []
    for case in scalar_cases():
        source = scalar_reference_source(case)
        checked = assemble_program(source)
        result = execute_program(checked, "f0", [])
        if result["status"] != "returned" or result["result"] != case["expected"]:
            raise AssertionError({"case": case["id"], "reference": result, "oracle": case["expected"]})
        scalar.append({**case, "reference_source": source.decode(), "core_sha256": checked.sha256,
                       "reference_result": result})
    positives = []
    for fixture in positive_fixtures():
        checked = assemble_program(fixture["source"])
        item = {key: value for key, value in fixture.items() if not isinstance(value, bytes)}
        item.update({"source_bytes": len(fixture["source"]), "source_sha256": digest(fixture["source"]),
                     "core_sha256": checked.sha256, "input_hex": fixture["input"].hex(),
                     "expected_output_hex": fixture["expected_output"].hex()})
        if fixture["kind"] == "boundary":
            scalar_doc = checked.as_dict()
            scalar_doc["functions"][0]["params"] = []
            scalar_doc["functions"][0]["blocks"][0]["params"] = []
            result = execute_program(scalar_doc, "f0", [])
            if result["status"] != "returned" or result["result"] != fixture["expected_result"]:
                raise AssertionError({"case": fixture["id"], "reference": result})
            item.update({"reference_result": result,
                         "reference_change": "remove unused borrowed entry parameters; preserve operations, calls and control flow"})
        elif fixture["kind"] == "buffer" or fixture.get("input_arguments"):
            source = buffer_reference_source(fixture)
            result = execute_program(assemble_program(source), "reference_entry", [])
            if result["status"] != "returned" or result["result"] != list(fixture["expected_output"]):
                raise AssertionError({"case": fixture["id"], "reference": result})
            item.update({"reference_source": source.decode(), "reference_result": result,
                         "reference_change": "add general-Core owned allocation wrapper around unchanged borrowed body"})
        positives.append(item)
    negatives = []
    for fixture in rejected_fixtures():
        try:
            checked = assemble_program(fixture["source"])
        except HIAProgramRejected as exc:
            result = {"status": "rejected", "code": exc.code, "message": str(exc)}
        else:
            result = {"status": "accepted", "core_sha256": checked.sha256}
        expected = fixture["general_core_expected"]
        if expected is not None and result["status"] != expected:
            raise AssertionError({"case": fixture["id"], "reference": result, "expected": expected})
        negatives.append({key: value for key, value in fixture.items() if key != "source"} |
                         {"source_sha256": digest(fixture["source"]), "source_bytes": len(fixture["source"]),
                          "reference_result": result})
    traps = []
    for fixture in shift_trap_cases() + checked_arithmetic_trap_cases() + checked_cast_trap_cases():
        checked = assemble_program(fixture["source"])
        if fixture["kind"] in {"checked_arithmetic", "checked_cast"}:
            scalar_doc = assemble_program(fixture["reference_source"]).as_dict()
        else:
            scalar_doc = checked.as_dict()
            scalar_doc["functions"][0]["params"] = []
            scalar_doc["functions"][0]["blocks"][0]["params"] = []
        try:
            result = execute_program(scalar_doc, "f0", [])
        except HIAProgramTrap as exc:
            result = {"status": "trapped", "trap": exc.code, "message": str(exc)}
        expected_trap = "division_by_zero" if fixture["opcode"] in {"int.div.checked", "int.rem.checked"} else "overflow"
        if result.get("status") != "trapped" or result.get("trap") != expected_trap:
            raise AssertionError({"case": fixture["id"], "reference": result})
        traps.append({key: value for key, value in fixture.items() if not isinstance(value, bytes)} |
                     {"core_sha256": checked.sha256, "source_sha256": digest(fixture["source"]),
                      "arithmetic_reference_source": fixture.get("reference_source", b"").decode(),
                      "runtime_input_hex": fixture.get("input", b"").hex(),
                      "expected_native_output_hex": fixture["expected_output"].hex(),
                      "memory_ordering_reference": "native shared output directly observes prior store and absence of later store",
                      "reference_result": result})
    return {"scalar": scalar, "positive": positives, "negative": negatives, "traps": traps}


def semantic_contract(contract):
    return {key: value for key, value in contract.items() if key != "source_identity"}


def coverage_manifest():
    from tools.generate_hia_selfhost import document, WORDS
    from tools.hia_selfhost_contract import support_contract
    from hepta.hia_agent_assembly import render_assembly
    from hepta.hia_opcodes import OPCODES
    contract = support_contract()
    doc, names = document()
    compiler = (ROOT / "examples/hia_bootstrap/selfhost.hiaasm").read_bytes()
    if render_assembly(doc).encode() != compiler:
        raise AssertionError("authoring map is not the checked-in HIA compiler")
    supported = sorted(word for word in WORDS if word in OPCODES)
    if supported != sorted(set(INPUT_OPCODES) | set(ELF_OWNED_OPCODES) | set(ELF_CHAIN_OPCODES)):
        raise AssertionError("coverage inventory differs from actual HIA keyword/opcode set")
    rules = {
        "scalar_types": (["read_type", "instruction", "normalize", "scalar_literal", "integer_width"], ["scalar-*", "boolean", "cast", "checked-cast"]),
        "resources": (["args", "edge", "operation", "bulk_buffer", "bulk_range_guard",
                       "loan_operation", "loan_access", "loan_incoming", "loan_transfer"],
                      ["borrowed-buffer-operations", "existing-readonly-*", "swap-*", "bulk-*", "loan-*"]),
        "integer_operations": (["instruction", "operation", "checked_integer", "signed_integer", "cast_integer", "select_scalar", "normalize"],
            ["scalar-*", "dynamic-integer-*", "boolean", "cast", "shift-trap-*", "checked-trap-*",
             "checked-cast*", "dynamic-cast-*", "bool-equality-input-*", "boolean-equality-*", "boolean-ordering-*",
             "bit.not-*", "int.add.checked-*", "int.sub.checked-*", "select-*"]),
        "control_flow": (["parse_block", "edge", "check_graph"], ["boolean", "blocks-*", "inbound-entry-edge", "existing-unreachable-block"]),
        "effects": (["parse_effects", "require_effects", "instruction_effects", "instruction"],
                    ["declaration-*", "call-*-missing-*", "*-missing-*", "malformed-*", "int.cast-*"]),
        "calls": (["instruction", "args", "check_calls", "copy_argument", "read_result_types", "return_results", "call_results"],
                  ["parameters-16", "parameters-17", "call-*", "pair-*", "triple-*"]),
        "recursion": (["instruction", "parse_block", "check_calls", "return_results"], ["recursion-*", "tail-*", "pair-tail-*"]),
        "owned_resources": (["read_type", "owned_read_outputs", "owned_instruction",
            "owned_define_outputs", "owner_free", "owner_produce", "owner_consume",
            "owner_call_consume", "loan_incoming", "loan_transfer", "owned_allocate_libc",
            "chain_instruction", "chain_store_transfer", "chain_drop_helper", "loan_borrow", "loan_produce"],
            ["new-*", "try-*", "move-*", "owned-*", "flow-*", "lifo-*", "iterative-drop-*", "empty-head-*", "parameter-*"]),
        "general_core_checker": (["compile", "read_type", "next_token", "instruction"], ["unsupported-*"]),
        "successor_output": (["wrapper", "operation", "relocation", "fix_all"], ["B1", "B2", "B3", "M1", "M2", "M3"]),
        "successor_object_output": (["elf_begin", "elf_finish", "elf_section", "align8",
            "owned_import", "owned_elf_relocations", "owned_elf_finish"], ["new-*", "try-*", "flow-*"]),
        "general_object_linking": (["compile", "elf_finish"], []),
    }
    existing = {
        "integer_operations": ["tools.hia_selfhost_select.qualify_select"],
        "resources": ["tools.hia_selfhost_resources.qualify_resources", "tools.hia_selfhost_bulk.qualify_bulk",
                      "tools.hia_selfhost_loans.qualify_loans",
                      "tests.test_hia_selfhost.SelfhostNativeTests.test_native_edges_reject_readonly_duplicates_but_calls_keep_legal_aliases"],
        "control_flow": ["tools.qualify_hia_selfhost.qualify"],
        "effects": ["tools.hia_selfhost_effects.qualify"],
        "calls": ["tools.hia_selfhost_cases.backward_chain_source", "tools.qualify_hia_selfhost.qualify", "tools.hia_selfhost_multi_results.qualify"],
        "recursion": ["tools.hia_selfhost_tailcalls.qualify_tailcalls"],
        "owned_resources": ["tools.qualify_hia_selfhost_owned_elf.qualify",
                            "tools.qualify_hia_selfhost_chain_elf.qualify",
                            "tools.qualify_hia_selfhost_chain_flow.qualify",
                            "tests.test_hia_selfhost_owned_flow.OwnedFlowSourceTests"],
        "successor_output": ["tools.qualify_hia_selfhost.qualify"],
        "successor_object_output": ["tools.qualify_hia_selfhost.qualify_elf_outputs",
                                    "tools.qualify_hia_selfhost_owned_elf.qualify"],
        "general_object_linking": [],
    }
    features = []
    for row in contract["support"]:
        functions, witnesses = rules[row["area"]]
        features.append({**row, "hia_functions": {name: names[name] for name in functions},
                         "new_witnesses": witnesses, "existing_evidence": existing.get(row["area"], [])})
    scalar_types = next(row["items"] for row in contract["support"] if row["area"] == "scalar_types")
    row_cases = scalar_cases()
    negative = rejected_fixtures()
    return {
        "schema": "hepta.hia.selfhost-language-coverage.v1", "profile": PROFILE,
        "claims": {"inventory_covers_declared_profile_features": True,
                   "finite_witnesses_are_all_input_correctness_proof": False,
                   "whole_HIA_language_self_hosted": False,
                   "compiler_correctness_formally_proved": False,
                   "this_inventory_is_execution_evidence": False},
        "source": {
            "compiler": {"path": "examples/hia_bootstrap/selfhost.hiaasm", "sha256": digest(compiler)},
            "authoring_map": {"path": "tools/generate_hia_selfhost.py",
                "sha256": digest((ROOT / "tools/generate_hia_selfhost.py").read_bytes())},
            "semantic_support_sha256": digest(canonical(semantic_contract(contract))),
            "support_projection_omits": ["source_identity"],
        },
        "input_opcodes": supported,
        "input_opcodes_by_output": {"selfhost": list(INPUT_OPCODES), "selfhost_elf": supported},
        "input_opcode_inventory_scope": "union of explicit output-format profiles; owned-buffer and chain operations require selfhost_elf; opcode-name coverage does not imply all Core types or result shapes",
        "general_core_opcode_count": len(OPCODES),
        "general_core_opcodes_outside_profile": sorted(set(OPCODES) - set(supported)),
        "input_types": [*scalar_types, "readbuf", "mutbuf", "buffer", "chain"],
        "input_types_by_output": {"selfhost": [*scalar_types, "readbuf", "mutbuf"],
                                  "selfhost_elf": [*scalar_types, "readbuf", "mutbuf", "buffer", "chain"]},
        "signed_and_unit_scope": {"types": ["i8", "i16", "i32", "i64", "isize", "unit"],
            "qualification": ["tools.hia_selfhost_signed_cases.qualify", "tools.hia_selfhost_scalar_casts.qualify"],
            "before_B0_independent_VM": True, "all_input_correctness_proved": False},
        "keyword_lookup_scope": {"representation": "four packed u64 words and exact byte/length equality",
            "hash_dispatch": False, "maximum_keyword_bytes": 32,
            "qualification": "tools.hia_selfhost_keywords.qualify on original B3 and mutated M3",
            "all_input_correctness_proved": False},
        "internal_scalar_result_scope": {
            "cardinality": [0, 1, 2, 3], "public_entry": "unchanged f0(readbuf,mutbuf,mutbuf)->u32",
            "types": scalar_types, "returned_resources_supported": False,
            "combinations": ["forward/backward direct calls", "branches", "loop-carried values",
                             "exact ordered self-tail returns", "borrowed parameters", "consumed owner parameters"],
            "qualification": "tools.hia_selfhost_multi_results.qualify on original B3 and mutated M3",
            "finite_witnesses_are_all_input_correctness_proof": False},
        "owned_buffer_scope": {
            "opcodes": list(ELF_OWNED_OPCODES), "output_module": "selfhost_elf",
            "allocation_effect": "alloc required for allocation, drop and calls to allocating functions",
            "runtime": "explicit calloc/free ELF imports under the existing Core allocator contract",
            "multi_result_operations": ["buffer.try_new returns buffer,bool"],
            "general_multi_result_call_return_abi_supported": False,
            "chain_operations_qualified_separately": True,
            "flat_owned_parameters_and_operations_supported": False,
            "qualification": "tools.qualify_hia_selfhost_owned_elf.qualify on original B3 and mutated M3",
            "reference": "independent Core VM, direct native backend, linked successor ELF and byte/result observations",
            "finite_witnesses_are_all_input_correctness_proof": False},
        "chain_scope": {"opcodes": list(ELF_CHAIN_OPCODES), "output_module": "selfhost_elf",
            "runtime": "dynamic 24-byte nodes under the same closed calloc/free contract",
            "multi_result_operations": ["chain.try_push returns chain,buffer,bool", "chain.pop returns chain,buffer,bool"],
            "ownership": "closed chain roots and nested head-loan graphs; consuming operations require no live descendant loans",
            "resource_parameter_boundaries": "v2047 block parameters accepted; function/block v2048, v8192 and UINT64_MAX refused before capability-table access",
            "destruction": "one shared iterative helper, constant frame independent of node count",
            "qualification": "tools.qualify_hia_selfhost_chain_elf.qualify on original B3 and mutated M3",
            "allocator_qualification": "tools.qualify_hia_selfhost_chain_flow.qualify; explicit ordinary allocator NULL inputs and native event conservation",
            "host_native_fixture_compilation_after_B0": True,
            "external_assembler_in_successor_compilation": False,
            "general_multi_result_call_return_abi_supported": False,
            "finite_witnesses_are_all_input_correctness_proof": False},
        "features": features,
        "syntax": {"contract": contract["syntax"],
                   "hia_functions": {name: names[name] for name in (
                       "compile", "parse_function", "parse_params", "parse_block", "define",
                       "variable", "next_token", "decimal", "adjacent", "separated", "expect")},
                   "new_positive": ["optional-ascii-spaces", "ssa-index-2047"],
                   "new_negative": [row["id"] for row in negative if row["id"].startswith(
                       ("existing-", "noncontiguous-", "entry-", "unsupported-", "tab-", "crlf-", "ssa-"))]},
        "limits": {"contract": contract["limits"],
                   "new_boundaries": ["parameters-16", "parameters-17", "blocks-per-function-256",
                                      "blocks-per-function-257", "blocks-total-1536", "blocks-total-1537",
                                      "functions-129", "ssa-index-2047", "ssa-index-2048",
                                      "source-bytes-1048576"],
                   "existing_evidence": ["tools.hia_selfhost_cases.backward_chain_source",
                       "tools.hia_selfhost_capacity.qualify_capacity",
                       "tools.hia_selfhost_tailcalls.qualify_tailcalls",
                       "tools.qualify_hia_selfhost.qualify"],
                   "unreachable_relocation_ceiling": {
                       "configured": contract["limits"]["relative_relocations"],
                       "derived_maximum_with_other_limits": contract["capacity_derivation"]["relative_relocations_upper_bound"]},
                   "transport_limit": "ordinary child rejects source/output sizes above 1 MiB before native entry; no larger native-call claim"},
        "scalar_witnesses": {
            "count": len(row_cases), "groups": {group: sum(row["group"] == group for row in row_cases)
                for group in dict.fromkeys(row["group"] for row in row_cases)},
            "unsigned_widths": WIDTHS, "wrap_cast_pairs": [[a, b] for a in WIDTHS for b in WIDTHS],
            "checked_cast_pairs": [[a, b] for a in WIDTHS for b in WIDTHS],
            "boolean_equality": ["compare.eq", "compare.ne"],
            "boolean_inputs": [[a, b] for a in (False, True) for b in (False, True)],
            "specification_sha256": digest(canonical(row_cases)),
            "observation": "eight little-endian output bytes per scalar result, including all 64 bits",
            "dynamic_integer_witnesses": "each new integer operation reads all operand bytes from the runtime source buffer",
            "reference": "independent general Core VM plus Python integer/boolean oracle, executed before B0"},
        "rejected_inputs": [{"id": row["id"], "boundary": row["boundary"],
                            "general_core_expected": row["general_core_expected"],
                            "source_sha256": digest(row["source"])} for row in negative],
        "checked_shift_traps": [{"id": row["id"], "type": row["operand_type"], "opcode": row["opcode"],
                                "amount": row["amount"]} for row in shift_trap_cases()],
        "checked_arithmetic_traps": [{"id": row["id"], "type": row["operand_type"], "opcode": row["opcode"],
            "arguments": row["arguments"], "prior_store": row["prior_store"],
            "expected_native_output_hex": row["expected_output"].hex(),
            "source_sha256": digest(row["source"])} for row in checked_arithmetic_trap_cases()],
        "checked_cast_traps": [{"id": row["id"], "source_type": row["operand_type"],
            "target_type": row["result_type"], "arguments": row["arguments"],
            "prior_store": row["prior_store"], "runtime_input_hex": row["input"].hex(),
            "expected_native_output_hex": row["expected_output"].hex(),
            "source_sha256": digest(row["source"])} for row in checked_cast_trap_cases()],
        "bootstrap": {"required": contract["required_replay"],
                      "dependency_closure": "support source_identity includes this test and this inventory; B0 receipt records actual loaded seed modules",
                      "successors": "stdlib-only disposable child; all input translation is executed HIA",
                      "cold_replay": "tools/replay_hia_selfhost_cold.py",
                      "cold_replay_boundary": "source/process/cache isolation; same host CPython, standard library, GNU ld, libc, kernel and hardware"},
        "run": {"command": "python -B tests/test_hia_selfhost_language_coverage.py --output <new-report.json>",
                "unittest_evidence_environment": "HIA_SELFHOST_LANGUAGE_EVIDENCE",
                "retained": ["B0 and B1/B2/B3", "M1/M2/M3", "exact compiler and fixture input bytes",
                             "reference observations", "native output bytes", "raw child stdout/stderr",
                             "native request and receipt JSON", "source closure and runtime identities"],
                "failure_report": "report is written with status FAIL and an error before raising"},
    }


def validate_inventory():
    actual = json.loads((ROOT / COVERAGE_PATH).read_text())
    expected = coverage_manifest()
    if actual != expected:
        raise AssertionError("language inventory is stale; regenerate from coverage_manifest after review")
    from tools.hia_selfhost_contract import SOURCE_FILES
    if SELF_PATH not in SOURCE_FILES or COVERAGE_PATH not in SOURCE_FILES:
        raise AssertionError("coverage evidence inputs are outside the pinned source closure")
    return actual


def qualify_language(output):
    from tools.hia_selfhost_contract import validate_contract
    from tools.qualify_hia_selfhost import (CAPACITY, INVALID, SOURCE, build_seed, compile_stage,
                                           invoke, mutate_compiler, source_manifest)
    if not NATIVE:
        raise RuntimeError("native language qualification requires Linux x86-64 and GNU ld")
    requested = Path(output)
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    if any(path.is_symlink() for path in (requested, *requested.parents)):
        raise ValueError("language qualification output cannot use symbolic links")
    if requested.exists():
        raise ValueError("language qualification requires a fresh report")
    output = requested.resolve()
    directory = output.with_suffix(".evidence")
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.selfhost-language-qualification.v1", "profile": PROFILE,
              "status": "FAIL", "checks": {}, "positive": [], "negative": [], "traps": [],
              "generations": [], "modified_generations": [],
              "claims": {"whole_HIA_language_self_hosted": False,
                         "compiler_correctness_formally_proved": False,
                         "finite_witnesses_prove_all_inputs": False}}
    try:
        contract = validate_contract()
        inventory = validate_inventory()
        before = source_manifest()
        report.update({"source_manifest": before,
                       "inventory_sha256": digest((ROOT / COVERAGE_PATH).read_bytes()),
                       "semantic_support_sha256": inventory["source"]["semantic_support_sha256"],
                       "runtime": {"python": sys.version, "executable": str(Path(sys.executable).resolve()),
                                   "executable_sha256": digest(Path(sys.executable).read_bytes()),
                                   "platform": platform.platform()}})
        reference = independent_references()
        write_json(directory / "independent-reference.json", reference)
        report["reference"] = {"path": str(directory / "independent-reference.json"),
            "sha256": digest((directory / "independent-reference.json").read_bytes()),
            "scalar_cases": len(reference["scalar"]), "before_B0": True}
        checks = report["checks"]
        checks["reference_vm_matches_all_scalar_oracles"] = True
        checks["inventory_matches_actual_compiler_source"] = True
        compiler_source = SOURCE.read_bytes()
        (directory / "compiler.hiaasm").write_bytes(compiler_source)
        seed, seed_receipt = build_seed(directory, compiler_source)
        report["seed"] = seed_receipt
        predecessor = seed
        for generation in ("B1", "B2", "B3"):
            predecessor, receipt = compile_stage(directory, generation, predecessor, compiler_source,
                image_format="seed-shared" if generation == "B1" else "flat-x86-64",
                workspace_fill=0x5a if generation == "B3" else 0)
            report["generations"].append(receipt)
        b3 = predecessor
        modified = mutate_compiler(compiler_source)
        (directory / "compiler-mutated.hiaasm").write_bytes(modified)
        for generation in ("M1", "M2", "M3"):
            predecessor, receipt = compile_stage(directory, generation, predecessor, modified)
            report["modified_generations"].append(receipt)
        m3 = predecessor
        original_hashes = [row["produced_sha256"] for row in report["generations"]]
        modified_hashes = [row["produced_sha256"] for row in report["modified_generations"]]
        checks["original_fixed_point"] = len(set(original_hashes)) == 1
        checks["modified_fixed_point"] = (modified_hashes[0] != modified_hashes[1]
            and modified_hashes[1] == modified_hashes[2] and modified_hashes[2] != original_hashes[2])
        checks["source_bound_before_execution"] = contract["profile"] == PROFILE
        positive = positive_fixtures()
        negative = rejected_fixtures()
        traps = shift_trap_cases() + checked_arithmetic_trap_cases() + checked_cast_trap_cases()
        for label, compiler in (("B3", b3), ("M3", m3)):
            for fixture in positive:
                name = label + "-" + fixture["id"]
                image, build = compile_stage(directory, name + "-build", compiler, fixture["source"])
                result, observed = invoke(directory, name, image, fixture["input"],
                    capacity=fixture["capacity"], workspace_size=fixture["workspace_size"])
                good = (result.get("status") == "returned" and result.get("abi_status") == 0
                    and result.get("core_u32") == fixture["expected_result"]
                    and result.get("source_unchanged") and not result.get("forbidden_compiler_modules_loaded")
                    and observed == fixture["expected_output"])
                checks[name] = bool(good)
                report["positive"].append({"compiler": label, "id": fixture["id"],
                    "case_ids": fixture["case_ids"], "build": build, "execution": result,
                    "expected_result": fixture["expected_result"],
                    "expected_output_sha256": digest(fixture["expected_output"]),
                    "observed_output_sha256": digest(observed)})
            for fixture in negative:
                name = label + "-reject-" + fixture["id"]
                result, observed = invoke(directory, name, compiler, fixture["source"], capacity=512)
                good = (result.get("status") == "returned" and result.get("abi_status") == 0
                    and result.get("core_u32") == INVALID and result.get("source_unchanged")
                    and result.get("output_unchanged") and observed == bytes([0xa5]) * 512
                    and not result.get("forbidden_compiler_modules_loaded"))
                checks[name] = bool(good)
                report["negative"].append({"compiler": label, "id": fixture["id"],
                                          "execution": result, "transactional_rejection": bool(good)})
            for fixture in traps:
                name = label + "-" + fixture["id"]
                image, build = compile_stage(directory, name + "-build", compiler, fixture["source"])
                result, observed = invoke(directory, name, image, fixture.get("input", b""), capacity=8, workspace_size=0,
                                           observe_trap_writes=True)
                good = (result.get("status") == "child_failed" and result.get("returncode") == -4
                    and result.get("shared_output_observation", {}).get("available")
                    and observed == fixture["expected_output"])
                checks[name] = bool(good)
                report["traps"].append({"compiler": label, "id": fixture["id"], "kind": fixture["kind"],
                                        "prior_store": fixture.get("prior_store", False),
                                        "operand_type": fixture["operand_type"],
                                        "result_type": fixture.get("result_type"),
                                        "runtime_input_hex": fixture.get("input", b"").hex(),
                                        "expected_output_hex": fixture["expected_output"].hex(),
                                        "observed_output_hex": observed.hex(),
                                        "build": build, "execution": result})
        checks["source_closure_unchanged"] = source_manifest() == before
        report["counts"] = {"scalar_witnesses": len(reference["scalar"]),
            "positive_programs_per_compiler": len(positive),
            "rejections_per_compiler": len(negative), "shift_traps_per_compiler": len(shift_trap_cases()),
            "checked_arithmetic_traps_per_compiler": len(checked_arithmetic_trap_cases()),
            "checked_cast_traps_per_compiler": len(checked_cast_trap_cases()),
            "traps_per_compiler": len(traps),
            "compilers": 2, "checks_total": len(checks), "checks_passed": sum(checks.values())}
        report["status"] = "SELFHOST_LANGUAGE_COVERAGE_PASS" if all(checks.values()) else "FAIL"
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        report["wall_elapsed_ns"] = time.monotonic_ns() - started
        write_json(output, report)
    return report


class SelfhostLanguageSourceTests(unittest.TestCase):
    def test_inventory_matches_supported_features_actual_hia_and_source_closure(self):
        manifest = validate_inventory()
        self.assertEqual(manifest["profile"], PROFILE)
        self.assertEqual(len(manifest["input_opcodes"]), 50)
        self.assertEqual(manifest["input_opcodes_by_output"]["selfhost"], list(INPUT_OPCODES))
        self.assertEqual(len(manifest["input_opcodes_by_output"]["selfhost"]), 40)
        self.assertEqual(set(manifest["input_opcodes_by_output"]["selfhost_elf"]),
                         set(INPUT_OPCODES) | set(ELF_OWNED_OPCODES) | set(ELF_CHAIN_OPCODES))
        self.assertNotIn("buffer", manifest["input_types_by_output"]["selfhost"])
        self.assertIn("buffer", manifest["input_types_by_output"]["selfhost_elf"])
        self.assertIn("select", manifest["input_opcodes"])
        self.assertEqual(manifest["general_core_opcode_count"], 50)
        self.assertFalse(manifest["claims"]["whole_HIA_language_self_hosted"])
        self.assertFalse(manifest["claims"]["compiler_correctness_formally_proved"])

    def test_every_supported_integer_opcode_and_width_has_independent_inputs(self):
        rows = scalar_cases()
        for typ in WIDTHS:
            observed = {row["opcode"] for row in rows if row["operand_type"] == typ}
            self.assertTrue(set(("const", *BINARY_INTEGER, *NEW_INTEGER, *SHIFTS, *COMPARISONS, "int.cast", "select")) <= observed)
        self.assertEqual({(row["operand_type"], row["result_type"]) for row in rows if row["opcode"] == "int.cast"},
                         {(a, b) for a in WIDTHS for b in WIDTHS})
        for op in ("bool.and", "bool.or"):
            self.assertEqual({tuple(row["arguments"]) for row in rows if row["opcode"] == op},
                             {(a, b) for a in (False, True) for b in (False, True)})

    def test_select_covers_each_scalar_type_and_changing_inputs(self):
        rows = [row for row in scalar_cases() if row["opcode"] == "select"]
        self.assertEqual(len(rows), 48)
        for typ in (*WIDTHS, "bool"):
            selected = [row for row in rows if row["operand_type"] == typ]
            self.assertEqual(len(selected), 8)
            self.assertEqual({row["arguments"][0] for row in selected}, {False, True})
        self.assertEqual({tuple(row["arguments"]) for row in rows if row["operand_type"] == "bool"},
                         {(c, a, b) for c in (False, True) for a in (False, True) for b in (False, True)})
        fixtures = select_input_fixtures()
        self.assertEqual(len(fixtures), 33)
        for typ in (*WIDTHS, "bool"):
            selected = [row for row in fixtures if row["id"].startswith("select-input-" + typ + "-")]
            self.assertEqual(len({row["source"] for row in selected}), 1)
            self.assertGreater(len({row["input"] for row in selected}), 1)
            self.assertGreater(len({row["expected_output"] for row in selected}), 1)

    def test_independent_core_vm_agrees_with_scalar_buffer_and_boundary_oracles(self):
        reference = independent_references()
        # Includes all unsigned scalar operations, full-width and zero divisors.
        self.assertEqual(len(reference["scalar"]), 1183)
        self.assertTrue(all(row["reference_result"]["status"] == "trapped" for row in reference["traps"]))
        self.assertTrue(any(row["reference_result"]["status"] == "accepted" for row in reference["negative"]))
        self.assertTrue(any(row["reference_result"]["status"] == "rejected" for row in reference["negative"]))

    def test_flat_native_fixtures_cover_all_flat_input_opcodes_and_observe_full_width(self):
        from hepta.hia_agent_assembly import assemble_program
        observed = set()
        fixtures = positive_fixtures()
        for fixture in fixtures:
            checked = assemble_program(fixture["source"])
            observed.update(op["op"] for fn in checked.as_dict()["functions"] for block in fn["blocks"] for op in block["ops"])
            if fixture["kind"] == "scalar":
                self.assertEqual(fixture["capacity"], len(fixture["case_ids"]) * 8)
        self.assertEqual(observed, set(INPUT_OPCODES))
        self.assertTrue(any(fixture["capacity"] > 128 for fixture in fixtures))

    def test_owned_fixtures_cover_only_the_explicit_elf_extension(self):
        from hepta.hia_agent_assembly import assemble_program
        from tools.hia_selfhost_owned_elf_cases import cases
        from tools.hia_selfhost_owned_flow_cases import cases as flow_cases
        observed = set()
        for case in [*cases(), *flow_cases()]:
            checked = assemble_program(case["source"])
            self.assertEqual(checked.as_dict()["module"], "selfhost_elf")
            observed.update(op["op"] for fn in checked.as_dict()["functions"]
                            for block in fn["blocks"] for op in block["ops"])
        self.assertEqual(observed - set(INPUT_OPCODES), set(ELF_OWNED_OPCODES))
        self.assertFalse(any(op.startswith("chain.") for op in observed))

    def test_chain_fixtures_cover_six_chain_opcodes_without_general_signature_claims(self):
        from hepta.hia_agent_assembly import assemble_program
        from tools.hia_selfhost_chain_cases import cases
        observed = set()
        for case in cases():
            checked = assemble_program(case["source"]).as_dict()
            self.assertEqual(checked["module"], "selfhost_elf")
            observed.update(op["op"] for fn in checked["functions"] for block in fn["blocks"] for op in block["ops"])
        self.assertEqual({op for op in observed if op.startswith("chain.")}, set(ELF_CHAIN_OPCODES))
        self.assertTrue(observed <= set(INPUT_OPCODES) | set(ELF_OWNED_OPCODES) | set(ELF_CHAIN_OPCODES))

    def test_rejections_retain_invalid_core_and_valid_outside_profile_distinction(self):
        reference = independent_references()
        rows = {row["id"]: row for row in reference["negative"]}
        for name in ("recursion-non-tail-direct-recursion", "recursion-mutual-recursion",
                     "recursion-unreachable-cycle", "unsupported-module-name"):
            self.assertEqual(rows[name]["reference_result"]["status"], "accepted")
        for name in ("integer-op-arity", "unsigned-comparison-type-mismatch", "swap-readonly"):
            self.assertEqual(rows[name]["reference_result"]["status"], "rejected")
        for op in NEW_INTEGER:
            self.assertTrue(all(row["reference_result"]["status"] == "rejected"
                for row in rows.values() if row["id"].startswith(op + "-")))

    def test_checked_arithmetic_covers_width_boundaries_and_both_write_orders(self):
        rows = checked_arithmetic_trap_cases()
        self.assertEqual(len(rows), 150)
        for typ, width in WIDTHS.items():
            for op in CHECKED_ARITHMETIC:
                cases = [row for row in rows if row["operand_type"] == typ and row["opcode"] == op]
                self.assertEqual(len(cases), 5)
                self.assertEqual({row["prior_store"] for row in cases}, {False, True})
                for row in cases:
                    args = row["arguments"]
                    if op in {"int.div.checked", "int.rem.checked"}:
                        self.assertEqual(args[1], 0)
                    else:
                        result = {"int.add.checked": lambda: args[0] + args[1],
                            "int.sub.checked": lambda: args[0] - args[1],
                            "int.mul.checked": lambda: args[0] * args[1],
                            "int.neg.checked": lambda: -args[0]}[op]()
                        self.assertFalse(0 <= result < (1 << width))
                    self.assertEqual(row["expected_output"][1:], bytes([0xa5]) * 7)

    def test_checked_casts_cover_all_pairs_and_narrowing_overflow_with_runtime_inputs(self):
        cases = [row for row in scalar_cases() if row.get("mode") == "checked"]
        self.assertEqual(len(cases), 125)
        self.assertEqual({(row["operand_type"], row["result_type"]) for row in cases},
                         {(source, target) for source in WIDTHS for target in WIDTHS})
        for source in WIDTHS:
            for target in WIDTHS:
                pair = [row for row in cases if (row["operand_type"], row["result_type"]) == (source, target)]
                self.assertEqual(max(row["expected"] for row in pair),
                                 (1 << min(WIDTHS[source], WIDTHS[target])) - 1)
        fixtures = [row for row in positive_fixtures() if row["id"].startswith("dynamic-cast-")]
        self.assertEqual(len(fixtures), 25)
        self.assertTrue(all(row["input_arguments"] and row["input"] for row in fixtures))
        traps = checked_cast_trap_cases()
        self.assertEqual(len(traps), 36)
        for row in traps:
            self.assertGreaterEqual(row["arguments"][0], 1 << WIDTHS[row["result_type"]])
            self.assertEqual(int.from_bytes(row["input"], "little"), row["arguments"][0])
        for source in WIDTHS:
            for target in WIDTHS:
                if WIDTHS[source] > WIDTHS[target]:
                    pair = [row for row in traps if (row["operand_type"], row["result_type"]) == (source, target)]
                    self.assertEqual(len(pair), 4)
                    self.assertEqual({row["prior_store"] for row in pair}, {False, True})
                    for prior in (False, True):
                        same_program = [row for row in pair if row["prior_store"] == prior]
                        self.assertEqual(len({row["source"] for row in same_program}), 1)
                        self.assertEqual(len({row["input"] for row in same_program}), 2)

    def test_boolean_equality_has_the_full_truth_table_and_input_dependent_programs(self):
        for opcode in ("compare.eq", "compare.ne"):
            rows = [row for row in scalar_cases() if row["operand_type"] == "bool" and row["opcode"] == opcode]
            self.assertEqual({tuple(row["arguments"]) for row in rows},
                             {(left, right) for left in (False, True) for right in (False, True)})
            fixtures = [row for row in boolean_equality_input_fixtures() if opcode in row["id"]]
            self.assertEqual(len(fixtures), 4)
            self.assertEqual(len({row["source"] for row in fixtures}), 1)
            self.assertEqual(len({row["input"] for row in fixtures}), 4)
            self.assertEqual({row["expected_result"] for row in fixtures}, {0, 1})

    def test_language_inventory_does_not_claim_unavailable_whole_v8_or_formal_proof(self):
        manifest = coverage_manifest()
        self.assertFalse(manifest["claims"]["finite_witnesses_are_all_input_correctness_proof"])
        self.assertFalse(manifest["claims"]["this_inventory_is_execution_evidence"])
        unsupported = {row["area"] for row in manifest["features"] if row["status"] == "not_implemented"}
        self.assertEqual(unsupported, {"general_core_checker", "general_object_linking"})
        owned = next(row for row in manifest["features"] if row["area"] == "owned_resources")
        self.assertEqual(owned["status"], "bounded_subset")
        self.assertFalse(manifest["owned_buffer_scope"]["flat_owned_parameters_and_operations_supported"])
        self.assertFalse(manifest["owned_buffer_scope"]["general_multi_result_call_return_abi_supported"])
        self.assertFalse(manifest["owned_buffer_scope"]["finite_witnesses_are_all_input_correctness_proof"])
        self.assertEqual(manifest["limits"]["unreachable_relocation_ceiling"],
                         {"configured": 12000, "derived_maximum_with_other_limits": 11267})


@unittest.skipUnless(NATIVE, "Linux x86-64 and GNU ld seed linker required")
class SelfhostLanguageNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retained = os.environ.get("HIA_SELFHOST_LANGUAGE_EVIDENCE")
        cls.temporary = None if retained else tempfile.TemporaryDirectory(prefix="hia-language-coverage-")
        cls.output = Path(retained) if retained else Path(cls.temporary.name) / "language.json"
        cls.report = qualify_language(cls.output)

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:
            cls.temporary.cleanup()

    def test_original_and_modified_compilers_are_real_fixed_points(self):
        self.assertTrue(self.report["checks"]["original_fixed_point"])
        self.assertTrue(self.report["checks"]["modified_fixed_point"])
        self.assertTrue(self.report["checks"]["source_closure_unchanged"])

    def test_every_positive_program_runs_under_both_hia_compilers(self):
        self.assertEqual(self.report["status"], "SELFHOST_LANGUAGE_COVERAGE_PASS", self.report["checks"])
        groups = {row["id"] for row in self.report["positive"]}
        for group in groups:
            self.assertEqual({row["compiler"] for row in self.report["positive"] if row["id"] == group}, {"B3", "M3"})
        self.assertEqual(self.report["reference"]["scalar_cases"], 1183)

    def test_negative_inputs_are_transactionally_rejected_by_both_compilers(self):
        self.assertTrue(self.report["negative"])
        self.assertTrue(all(row["transactional_rejection"] for row in self.report["negative"]))

    def test_invalid_checked_shifts_trap_with_native_output_preserved(self):
        rows = [row for row in self.report["traps"] if row["kind"] == "shift"]
        self.assertEqual(len(rows), 40)
        for row in rows:
            self.assertEqual(row["execution"]["returncode"], -4)
            self.assertTrue(row["execution"]["shared_output_observation"]["unchanged"])

    def test_checked_arithmetic_traps_before_later_writes_and_preserves_prior_writes(self):
        rows = [row for row in self.report["traps"] if row["kind"] == "checked_arithmetic"]
        self.assertEqual(len(rows), 300)
        for row in rows:
            self.assertEqual(row["execution"]["returncode"], -4)
            self.assertEqual(row["observed_output_hex"], row["expected_output_hex"])
            self.assertEqual(row["execution"]["shared_output_observation"]["unchanged"], not row["prior_store"])

    def test_new_integer_operations_use_runtime_input_under_both_compilers(self):
        for typ in WIDTHS:
            rows = [row for row in self.report["positive"] if row["id"].startswith("dynamic-integer-" + typ + "-")]
            self.assertEqual({row["compiler"] for row in rows}, {"B3", "M3"})
            for row in rows:
                self.assertGreater(row["execution"]["input_bytes"], 0)
                self.assertEqual(row["observed_output_sha256"], row["expected_output_sha256"])

    def test_select_uses_changing_inputs_and_full_width_output_under_both_compilers(self):
        for typ in (*WIDTHS, "bool"):
            rows = [row for row in self.report["positive"]
                    if row["id"].startswith("select-input-" + typ + "-")]
            for compiler in ("B3", "M3"):
                observed = [row for row in rows if row["compiler"] == compiler]
                self.assertEqual(len(observed), 8 if typ == "bool" else 5)
                for row in observed:
                    self.assertGreater(row["execution"]["input_bytes"], 0)
                    self.assertEqual(row["observed_output_sha256"], row["expected_output_sha256"])

    def test_checked_casts_read_runtime_values_and_preserve_trap_write_order(self):
        for compiler in ("B3", "M3"):
            rows = [row for row in self.report["positive"] if row["compiler"] == compiler
                    and row["id"].startswith("dynamic-cast-")]
            self.assertEqual(len(rows), 25)
            self.assertEqual({row["id"] for row in rows},
                             {"dynamic-cast-" + source + "-" + target for source in WIDTHS for target in WIDTHS})
            for row in rows:
                self.assertGreater(row["execution"]["input_bytes"], 0)
                self.assertEqual(row["observed_output_sha256"], row["expected_output_sha256"])
            traps = [row for row in self.report["traps"] if row["compiler"] == compiler and row["kind"] == "checked_cast"]
            self.assertEqual(len(traps), 36)
            self.assertEqual({row["prior_store"] for row in traps}, {False, True})
            for row in traps:
                self.assertTrue(row["runtime_input_hex"])
                self.assertEqual(row["execution"]["returncode"], -4)
                self.assertEqual(row["observed_output_hex"], row["expected_output_hex"])

    def test_boolean_equality_reads_all_truth_table_inputs(self):
        for compiler in ("B3", "M3"):
            for opcode in ("compare.eq", "compare.ne"):
                rows = [row for row in self.report["positive"] if row["compiler"] == compiler
                        and row["id"].startswith("bool-equality-input-" + opcode + "-")]
                self.assertEqual(len(rows), 4)
                for row in rows:
                    self.assertEqual(row["execution"]["input_bytes"], 2)
                    self.assertEqual(row["observed_output_sha256"], row["expected_output_sha256"])

    def test_all_generations_and_raw_evidence_are_retained(self):
        directory = self.output.with_suffix(".evidence")
        for generation in ("B1", "B2", "B3", "M1", "M2", "M3"):
            self.assertTrue((directory / (generation + ".image.bin")).is_file())
            self.assertTrue((directory / (generation + ".stdout.log")).is_file())
            self.assertTrue((directory / (generation + ".stderr.log")).is_file())
        self.assertTrue((directory / "B0.receipt.json").is_file())
        self.assertTrue((directory / "independent-reference.json").is_file())


def check_native_report_assertions(report, output):
    """Run native unittest assertions on this invocation's actual report.

    Reuse the complete native qualification just performed by the CLI, without
    omitting the existing assertions or building a second compiler chain.
    This does not admit external reports or add native observations.
    """
    class CurrentInvocationAssertions(SelfhostLanguageNativeTests):
        @classmethod
        def setUpClass(cls):
            cls.temporary = None
            cls.output = output
            cls.report = report

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CurrentInvocationAssertions)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    complete = (result.testsRun == 10 and result.wasSuccessful() and not result.skipped
                and not result.expectedFailures and not result.unexpectedSuccesses)
    write_json(output.with_suffix(".assertions.json"), {
        "schema": "hepta.hia.selfhost-language-native-assertions.v1",
        "report_sha256": digest(output.read_bytes()),
        "tests_run": result.testsRun,
        "passed": complete,
        "failures": [{"test": test.id(), "detail": detail} for test, detail in result.failures],
        "errors": [{"test": test.id(), "detail": detail} for test, detail in result.errors],
        "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "additional_native_execution": False,
    })
    return complete


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--generate-inventory", action="store_true",
                        help="write feature inventory only; does not regenerate the support source lock")
    args = parser.parse_args()
    if args.generate_inventory:
        write_json(ROOT / COVERAGE_PATH, coverage_manifest())
        print(json.dumps({"inventory": COVERAGE_PATH, "sha256": digest((ROOT / COVERAGE_PATH).read_bytes())}))
        return
    if args.output is None:
        parser.error("--output is required for retained native qualification")
    result = qualify_language(args.output)
    assertions_passed = (result["status"] == "SELFHOST_LANGUAGE_COVERAGE_PASS"
                         and check_native_report_assertions(result, args.output))
    print(json.dumps({"status": result["status"], "output": str(args.output),
                      "counts": result.get("counts"), "error": result.get("error")}, sort_keys=True))
    raise SystemExit(0 if assertions_passed else 1)


if __name__ == "__main__":
    main()
