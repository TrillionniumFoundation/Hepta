"""Original/unrolled actual native word helpers, all bytes and real SIGILL.

The 8-byte access order, partial writes, every final-byte boundary, unsigned
address wrap, complete u64 values and immutable source are compared.  This is
a separate local development gate, not a replacement for the full build gate.
"""
from pathlib import Path
import ast
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "original-r13"
REFERENCE = ROOT / "reference-kit-r13"
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / "authoring-dependencies"), str(REFERENCE), str(ORIGINAL / "tools"), str(ROOT)]
from self_rebuild_test_common import Gate, identity, digest
old_path = ROOT / "development/generate-self-rebuild-r2/clean_build_driver.authoring.py"
new_path = ROOT / "development/generate-self-rebuild-r4/clean_build_driver.authoring.py"
sources = [Path(__file__), ROOT / "self_rebuild_test_common.py", old_path, new_path,
           ROOT / "clean_build_self_rebuild_r4.py", ROOT / "B3-35ee.original.image.bin"]
sources += list(REFERENCE.rglob("*.py"))
gate = Gate(ROOT / "development/self-rebuild-word-pairs-r1", sources,
            "LOCAL_FIVE_EXACT_8_BYTE_HELPERS_COMPLETE_OUTPUT_AND_REAL_TRAP_PAIRING")

CONTROL = '''
def control(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def emit(o:mutbuf, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''

def fixture(kind, capacity, at, value, payload=bytes(range(17, 49))):
    wire = struct.pack("<2Q", at, value) + payload
    initial = bytes(((index * 73 + 19) & 255) for index in range(capacity))
    expected = bytearray(initial)
    offset = 4096 if kind in ("hget", "hput") else 0
    target = wire if kind == "uint" else initial
    trapped = False
    read = 0
    for index in range(8):
        address = (offset + at + index) & ((1 << 64) - 1)
        if address >= len(target):
            trapped = True
            break
        if kind in ("put", "hput"):
            expected[address] = (value >> (index * 8)) & 255
        else:
            read |= target[address] << (index * 8)
    if not trapped and kind in ("uint", "get", "hget"):
        assert capacity >= 8
        expected[:8] = struct.pack("<Q", read)
    return {"kind": kind, "capacity": capacity, "at": at, "value": value,
            "wire": wire, "initial": initial, "expected": bytes(expected), "trapped": trapped}

try:
    from build_authoring import document
    from hepta.hia_agent_assembly import render_assembly
    from tools.qualify_hia_selfhost import compile_stage, invoke
    old = old_path.read_text()
    new = new_path.read_text()
    edits = [row for row in json.loads((ROOT / "development/generate-self-rebuild-r4/exact-inverse-edits.json").read_bytes())
             if row["owner"] == "expanded-word-helper"]
    assert len(edits) == 5 and all(row["width"] == 8 for row in edits)
    inverse = new
    for row in reversed(edits):
        assert inverse.count(row["new"]) == 1
        inverse = inverse.replace(row["new"], row["old"], 1)
    assert inverse == old
    kinds = ("uint", "get", "put", "hget", "hput")
    images = {}
    for revision, text in (("old", old), ("new", new)):
        functions = {node.name: ast.get_source_segment(text, node) for node in ast.parse(text).body}
        for kind in kinds:
            probe = "def probe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    at = control(s, 0)\n"
            if kind in ("put", "hput"):
                probe += f"    value = control(s, 8)\n    {kind}(o, at, value)\n    return 0\n"
            else:
                owner = "s" if kind == "uint" else "o"
                probe += f"    value = {kind}({owner}, at)\n    emit(o, value)\n    return 0\n"
            body = probe + "\n" + functions[kind] + "\n" + CONTROL
            raw = render_assembly(document(body, "word_order_probe")).encode()
            image, receipt = compile_stage(gate.out, revision + "-" + kind, ROOT / "B3-35ee.original.image.bin", raw)
            images[revision, kind] = image
    cases = []
    # First input always contains the fixed 16-byte control plus 32 payload.
    for at in [*range(8), *range(40, 49), 49, (1 << 64) - 1, (1 << 64) - 7]:
        cases.append(fixture("uint", 8, at, 0xfedcba9876543210))
    for kind in ("get", "put"):
        for capacity in range(10):
            cases.append(fixture(kind, capacity, 0, 0xfedcba9876543210))
        for at in range(10):
            cases.append(fixture(kind, 16, at, 0x0123456789abcdef))
        for at in (16, 17, (1 << 64) - 1, (1 << 64) - 7):
            cases.append(fixture(kind, 16, at, (1 << 64) - 1))
    for kind in ("hget", "hput"):
        for size in range(10):
            cases.append(fixture(kind, 4096 + size, 0, 0xfedcba9876543210))
        for at in range(10):
            cases.append(fixture(kind, 4112, at, 0x0123456789abcdef))
        for at in ((1 << 64) - 4096, (1 << 64) - 4095, (1 << 64) - 4094, (1 << 64) - 4097):
            cases.append(fixture(kind, 16, at, (1 << 64) - 1))
    gate.write("predeclared-cases.json", [{k: (v.hex() if isinstance(v, bytes) else v) for k, v in row.items()} for row in cases])
    ledger = []
    for index, case in enumerate(cases):
        observed = []
        for revision in ("old", "new"):
            label = f"case-{index:03d}-{case['kind']}-{revision}"
            receipt, output = invoke(gate.out, label, images[revision, case["kind"]], case["wire"],
                                     capacity=case["capacity"], workspace_size=1,
                                     output_initial=case["initial"], observe_trap_writes=True)
            assert output == case["expected"], (label, receipt)
            if case["trapped"]:
                assert receipt["status"] == "child_failed" and receipt["returncode"] == -4, (label, receipt)
            else:
                assert receipt["status"] == "returned" and receipt["abi_status"] == 0 and receipt["core_u32"] == 0, (label, receipt)
                assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
            assert receipt["shared_output_observation"]["available"]
            observed.append({"status": receipt["status"], "returncode": receipt.get("returncode"),
                             "core_u32": receipt.get("core_u32"), "output_sha256": digest(output), "output_bytes": len(output)})
        assert observed[0] == observed[1]
        ledger.append({"case": index, "kind": case["kind"], "trapped": case["trapped"], "old": observed[0], "new": observed[1]})
        gate.write("completed-pairs.json", ledger)
    assert len(cases) == 116
    gate.summary.update(status="PASS", paired_cases=len(cases), actual_native_entries=len(cases) * 2,
                        actual_compiles=10, real_SIGILL_pairs=sum(row["trapped"] for row in cases),
                        full_original_body_inverse_equal=True, all_full_outputs_and_expected_partial_writes_equal=True)
except BaseException as exc:
    gate.fail(exc)
finally:
    gate.finish()
