"""Independent v9 word-memory witnesses for the complete language gate.

The byte oracle uses Python's integer byte encoding, before any native compiler
runs. The generated bodies use all three borrowed buffers without aliasing.
"""
from __future__ import annotations


WORD_OPCODES = ("buffer.load.u64.le", "buffer.load.u64.be",
                "buffer.store.u64.le", "buffer.store.u64.be")


def _header(header):
    assert "hepta.hia.program.v8 " in header
    return header.replace("hepta.hia.program.v8 ", "hepta.hia.program.v9 ", 1)


def positive_fixtures(assembly, header):
    fixtures = []
    values = (0, 1, 0x0102030405060708, 1 << 63, (1 << 64) - 1)
    for load_endian, read_order in (("le", "little"), ("be", "big")):
        for store_endian, write_order in (("le", "little"), ("be", "big")):
            for offset in (0, 1, 7, 8, 9):
                a = assembly()
                position = a.const("usize", offset)
                destination = (offset + 3) % 9
                at = a.const("usize", destination)
                value = a.emit("u64", "buffer.load.u64." + load_endian, ["v0", position])
                a.effect("buffer.store.u64." + store_endian, ["v1", at, value])
                reloaded = a.emit("u64", "buffer.load.u64." + store_endian, ["v1", at])
                workspace = a.const("usize", 3)
                a.effect("buffer.store.u64." + store_endian, ["v2", workspace, reloaded])
                observed = a.emit("u64", "buffer.load.u64." + load_endian, ["v2", workspace])
                last = a.const("usize", 24)
                a.effect("buffer.store.u64.le", ["v1", last, observed])
                result = a.const("u32", 32)
                source = (_header(header) + a.text() + "  ret(" + result + ")\nend\n").encode()
                for index, value in enumerate(values):
                    encoded = value.to_bytes(8, write_order)
                    expected = bytearray([0xa5] * 32)
                    expected[destination:destination + 8] = encoded
                    expected[24:32] = int.from_bytes(encoded, read_order).to_bytes(8, "little")
                    fixtures.append({"id": f"word-{load_endian}-{store_endian}-offset-{offset}-value-{index}",
                        "kind": "buffer", "source": source,
                        "input": bytes(range(offset)) + value.to_bytes(8, read_order) + b"\x5a\xc3",
                        "capacity": 32, "workspace_size": 24, "expected_result": 32,
                        "expected_output": bytes(expected), "case_ids": [
                            "word-v9", "word-unaligned", "word-readbuf", "word-mutbuf",
                            *sorted({"buffer.load.u64." + load_endian, "buffer.load.u64." + store_endian,
                                     "buffer.store.u64." + store_endian, "buffer.store.u64.le"})]})
    return fixtures


def single_source(assembly, header, opcode, *, offset=0, prior=False):
    a = assembly()
    if prior:
        a.effect("buffer.store", ["v1", a.const("usize", 0), a.const("u8", 0x71)])
    at = a.const("usize", offset)
    if opcode.startswith("buffer.load"):
        a.emit("u64", opcode, ["v0", at])
    else:
        a.effect(opcode, ["v1", at, a.const("u64", 0x0102030405060708)])
    a.effect("buffer.store", ["v1", a.const("usize", 7), a.const("u8", 0x99)])
    result = a.const("u32", 8)
    return (_header(header) + a.text() + "  ret(" + result + ")\nend\n").encode()


def rejected_fixtures(assembly, header):
    rows = []
    for opcode in WORD_OPCODES:
        source = single_source(assembly, header, opcode)
        cases = {
            "v8": source.replace(b"program.v9 ", b"program.v8 ", 1),
            "offset-type": source.replace(b":usize = const() {\"value\":0}", b":u8 = const() {\"value\":0}", 1),
            "missing-trap": source.replace(b"effects(read,write,trap)", b"effects(read,write)", 1),
        }
        # Attribute validation is observed on the word operation itself.
        lines = source.decode().splitlines()
        for i, line in enumerate(lines):
            if " = " + opcode + "(" in line:
                lines[i] = line + ' {"width":8}'
                break
        else:
            raise AssertionError(opcode)
        cases["attributes"] = ("\n".join(lines) + "\n").encode()
        if opcode.startswith("buffer.store"):
            cases["readonly"] = source.replace((opcode + "(v1,").encode(), (opcode + "(v0,").encode())
        for name, data in cases.items():
            rows.append({"id": "word-" + opcode + "-" + name, "source": data,
                         "boundary": "v9-only, exact u64/usize borrowed signature, effects and empty attributes",
                         "general_core_expected": "rejected"})
    return rows


def trap_cases(assembly, header):
    rows = []
    for opcode in WORD_OPCODES:
        positions = ((0, 0), (7, 0), (8, 1), (8, 1 << 32), (8, (1 << 64) - 1)) if opcode.startswith("buffer.load") else ((8, 1), (8, 1 << 32), (8, (1 << 64) - 1))
        for length, offset in positions:
            for prior in (False, True):
                expected = bytes([0x71 if prior else 0xa5]) + bytes([0xa5] * 7)
                rows.append({"id": f"word-trap-{opcode}-len-{length}-offset-{offset}-prior-{int(prior)}",
                    "kind": "word_memory", "opcode": opcode, "operand_type": "u64", "result_type": "u64",
                    "source": single_source(assembly, header, opcode, offset=offset, prior=prior),
                    "input": bytes(range(length)), "capacity": 8, "workspace_size": 0,
                    "prior_store": prior, "expected_output": expected})
    return rows
