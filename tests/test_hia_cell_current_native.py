"""Current native Cell controls; retain every old behavioral method unchanged.

The independent f33 suite remains in test_hia_cell_bridge.py in its entirety.
Only its old compiler-identity method is replaced here by current native custody.
"""
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
from unittest.mock import patch

from tests import test_hia_cell_bridge as original
from tools import build_hia_cell_bridge as build
from tools import generate_hia_cell_bridge_image_packer as pack
from hepta.hia_json_preflight_native import NativeHiaJsonImage

ROOT = Path(__file__).resolve().parents[1]


def _selected_build(root, output):
    cold = os.environ.get("HIA_CELL_NATIVE_COLD_REPORT")
    development = os.environ.get("HIA_CELL_NATIVE_DEVELOPMENT_COMPILER")
    if bool(cold) == bool(development):
        raise ValueError("select exactly one explicit Cell cold or development compiler")
    if cold:
        return build.build_native_bridge(
            root, output, cold_report=cold,
            generation_index=os.environ.get("HIA_CELL_NATIVE_GENERATION_INDEX"),
        )
    from tests.hia_cell_native_fixture import development_build
    return development_build(root, output, development)


class HiaCellCurrentNativeTests(original.HiaCellBridgeNativeTests):
    @classmethod
    def setUpClass(cls):
        # Original setup, fixture code, loader and every behavior body are kept.
        with patch.object(original, "build_native_bridge", _selected_build):
            super().setUpClass()
        cls.native_images = {}
        for role in ("image-packer", "shared-linker"):
            record = cls.build["native_artifacts"][role]
            raw = Path(record["path"]).read_bytes()
            if len(raw) != record["bytes"] or sha256(raw).hexdigest() != record["sha256"]:
                raise ValueError("Cell native packaging image changed")
            cls.native_images[role] = NativeHiaJsonImage(raw, record["sha256"])

    @classmethod
    def tearDownClass(cls):
        cls.native_images.clear()
        super().tearDownClass()

    def test_generated_source_is_exact_and_original_compiler_is_pinned(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_cell_bridge_continuation import document
        source = (ROOT / build.NATIVE_INPUTS[0]).read_bytes()
        self.assertEqual(render_assembly(document()).encode(), source)
        self.assertEqual(sha256(source).hexdigest(), self.build["source_sha256"])
        self.assertEqual(pack.generated_source(), (ROOT / pack.SOURCE_PATH).read_bytes())
        self.assertIs(self.build["claims"]["fallback_used"], False)
        self.assertIs(self.build["claims"]["native_compile_pack_link"], True)
        self.assertGreater(self.build["compile_wall_ns"], 0)
        for receipt in self.build["native_calls"].values():
            self.assertEqual(type(receipt["abi_status"]), int)
            self.assertEqual(receipt["abi_status"], 0)
            self.assertIs(receipt["source_unchanged"], True)
            self.assertEqual(receipt["forbidden_compiler_modules_loaded"], [])
        if os.environ.get("HIA_CELL_NATIVE_COLD_REPORT"):
            self.assertIs(self.build["claims"]["cold_compiler_admitted"], True)
            self.assertIs(self.build["claims"]["development_only"], False)
            self.assertEqual(self.build["generation_sha256"], [self.build["compiler_sha256"]] * 3)
            self.assertEqual(self.build["source_head"], self.build["input_custody"]["source_head"])
            self.assertEqual(self.build["compiler_commit"], self.build["source_head"])
        else:
            self.assertIs(self.build["claims"]["cold_compiler_admitted"], False)
            self.assertIs(self.build["claims"]["development_only"], True)
            self.assertIsNone(self.build["compiler_commit"])
        self.assertIs(self.build["claims"]["cell_execution_qualified"], False)
        self.assertIs(self.build["claims"]["whole_stack_qualified"], False)

    def call_packaging(self, role, data, capacity, workspace=128):
        source = ctypes.create_string_buffer(data, max(1, len(data)))
        output = ctypes.create_string_buffer(max(1, capacity))
        work = ctypes.create_string_buffer(max(1, workspace))
        ctypes.memset(output, 0xA5, capacity)
        original_input = source.raw
        result = int(self.native_images[role]._entry(
            source, len(data), output, capacity, work, workspace,
        ))
        self.assertEqual(source.raw, original_input)
        return result, output.raw[:capacity]

    def packet(self):
        flat = Path(self.build["native_artifacts"]["continuation"]["path"]).read_bytes()
        return struct.pack("<8s3Q", b"HCLPACK1", len(flat), original.MAX_EXTENT, 0) + flat

    def test_hia_object_matches_independent_layout_and_assembler_prefix(self):
        flat = self.packet()[32:]
        actual = Path(self.build["object"]["path"]).read_bytes()
        self.assertEqual(actual, pack.reference_object(flat))
        directory = Path(self.build["image_path"]).parent
        object_path = directory / "cell-entry-reference.o"
        result = subprocess.run(
            ["as", "--64", "--fatal-warnings", "-o", str(object_path),
             str(ROOT / "tools/hia_cell_bridge_entry.S")],
            capture_output=True, timeout=30,
        )
        (directory / "cell-entry-as.stdout").write_bytes(result.stdout)
        (directory / "cell-entry-as.stderr").write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = object_path.read_bytes()
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
        sections = [struct.unpack_from("<IIQQQQIIQQ", raw, header[6] + 64 * i)
                    for i in range(header[12])]
        strings_row = sections[header[13]]
        strings = raw[strings_row[4]:strings_row[4] + strings_row[5]]
        named = {strings[row[0]:strings.index(0, row[0])].decode(): row for row in sections}
        text = named[".text"]
        self.assertEqual(raw[text[4]:text[4] + text[5]], pack.BRIDGE)
        self.assertEqual(len(pack.BRIDGE), 201)
        self.assertFalse(any(row[1] == 4 and row[5] for row in sections))
        symbols_row = named[".symtab"]
        symbol_strings = sections[symbols_row[6]]
        names = raw[symbol_strings[4]:symbol_strings[4] + symbol_strings[5]]
        symbols = [struct.unpack_from("<IBBHQQ", raw, symbols_row[4] + i)
                   for i in range(0, symbols_row[5], 24)]
        exported = [row for row in symbols if names[row[0]:names.index(0, row[0])] == b"cell_bridge_step"]
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0][1:], (18, 0, sections.index(text), 0, 201))

    def test_native_packer_refusals_publish_no_output(self):
        packet = self.packet()
        variants = [("magic", b"BADMAGIC" + packet[8:]), ("short", packet[:31]),
                    ("tail", packet + b"\0"), ("truncated", packet[:-1])]
        for at, values in ((8, (0, pack.MAX_FLAT + 1, 2**64 - 1)),
                           (16, (0, original.MAX_EXTENT - 1, original.MAX_EXTENT + 1)),
                           (24, (1, 2**64 - 1))):
            for value in values:
                raw = bytearray(packet)
                struct.pack_into("<Q", raw, at, value)
                variants.append((f"word-{at}-{value}", bytes(raw)))
        extent = self.build["object"]["bytes"]
        for label, raw in variants:
            with self.subTest(label=label):
                code, output = self.call_packaging("image-packer", raw, extent)
                self.assertEqual(code, 0xFFFFFFFF)
                self.assertEqual(output, b"\xA5" * extent)

    def test_native_packer_capacity_refusals_publish_no_output(self):
        packet, extent = self.packet(), self.build["object"]["bytes"]
        for capacity, workspace in ((0, 128), (63, 128), (extent - 1, 128),
                                    (extent, 0), (extent, 127)):
            with self.subTest(capacity=capacity, workspace=workspace):
                code, output = self.call_packaging("image-packer", packet, capacity, workspace)
                self.assertEqual(code, 0xFFFFFFFE)
                self.assertEqual(output, b"\xA5" * capacity)

    def test_native_linker_malformed_objects_publish_no_output(self):
        original_object = Path(self.build["object"]["path"]).read_bytes()
        variants = [b"BAD!" + original_object[4:], original_object[:-1], original_object + b"\0"]
        for number, raw in enumerate(variants):
            with self.subTest(number=number):
                code, output = self.call_packaging("shared-linker", raw, 1 << 20, 1 << 20)
                self.assertGreaterEqual(code, 0xFFFFFFF0)
                self.assertEqual(output, b"\xA5" * (1 << 20))

    def test_current_native_abi_preserves_all_three_original_extent_limits(self):
        buffers = [ctypes.create_string_buffer(b"\x93" * 256, 256) for _ in range(3)]
        for index in range(3):
            with self.subTest(index=index):
                sizes = [256, 256, 256]
                sizes[index] = original.MAX_EXTENT + 1
                args = [value for pair in zip(buffers, sizes) for value in pair]
                code = int(self.bridge._entry(*args))
                self.assertEqual(code, 1 << 32)
                self.assertEqual([buffer.raw for buffer in buffers], [b"\x93" * 256] * 3)

    def test_native_packer_maximum_declared_length_is_exact(self):
        # Exercise the actual maximum admitted extent, without invoking its code.
        flat = b"\xC3" + bytes(pack.MAX_FLAT - 1)
        packet = struct.pack("<8s3Q", b"HCLPACK1", len(flat), original.MAX_EXTENT, 0) + flat
        expected = pack.reference_object(flat)
        code, output = self.call_packaging("image-packer", packet, len(expected))
        self.assertEqual(code, len(expected))
        self.assertEqual(output, expected)

    def test_current_native_abi_preserves_null_address_and_alias_priorities(self):
        observed = self.child_control("complete-native-byte-guards", '''import ctypes,json
from pathlib import Path
from tools import cell_bridge_native as n
d=json.load(__import__("sys").stdin)
record=json.loads((Path(d["fixtures"]["first"]["image"]).parent.parent/"native-build.json").read_text())
bridge=n.NativeCellBridge(Path(d["root"]),record["image_path"],record["image_sha256"],expected_source_sha256=record["source_sha256"])
rows=[]
def run(label,change,expected):
    buffers=[ctypes.create_string_buffer(b"\\x93"*1024,1024) for _ in range(3)]
    pointers=[ctypes.addressof(b)+256 for b in buffers]
    lengths=[256,256,256]
    change(pointers,lengths)
    args=[v for pair in zip(pointers,lengths) for v in pair]
    actual=int(bridge._entry(*args))
    assert actual==expected,(label,actual,expected)
    assert all(b.raw==b"\\x93"*1024 for b in buffers),label
    rows.append({"case":label,"native_return":actual,"bytes_unchanged":True})
for index in range(3):
    run("null-"+str(index),lambda p,l,i=index:p.__setitem__(i,0),2<<32)
    run("overflow-"+str(index),lambda p,l,i=index:p.__setitem__(i,(1<<64)-128),3<<32)
for left,right in ((0,1),(0,2),(1,2)):
    for offset in (0,-128,128):
        run("alias-"+str(left)+"-"+str(right)+"-"+str(offset),
            lambda p,l,a=left,b=right,o=offset:p.__setitem__(b,p[a]+o),4<<32)
def empty(p,l):
    p[0]=p[1]+128;l[0]=0
run("empty-inside-live-range",empty,1)
def source_null_before_later_extent(p,l):
    p[0]=0;l[1]=65793
run("per-range-null-precedes-later-extent",source_null_before_later_extent,2<<32)
def source_address_before_later_extent(p,l):
    p[0]=(1<<64)-128;l[2]=65793
run("per-range-address-precedes-later-extent",source_address_before_later_extent,3<<32)
bridge.close()
print(json.dumps({"cases":rows,"completed":len(rows)}))
''')
        self.assertEqual(observed["completed"], 18)
        self.assertTrue(all(row["bytes_unchanged"] is True for row in observed["cases"]))

    def test_native_pipeline_rejects_late_artifact_replacement(self):
        from tests.hia_cell_native_fixture import development_build

        pipeline = build._compile_pipeline
        compiler = Path(self.build["image_path"]).parent / "captured-compiler.flat"
        rows = []
        for role in ("compiler", "continuation", "image-packer", "shared-linker", "object", "image"):
            directory = Path(self.build["image_path"]).parent / ("late-artifact-" + role)

            def changed(*args, **kwargs):
                report, expected = pipeline(*args, **kwargs)
                if role == "compiler":
                    target = directory / "captured-compiler.flat"
                elif role == "object":
                    target = Path(report["object"]["path"])
                elif role == "image":
                    target = Path(report["image_path"])
                else:
                    target = Path(report["native_artifacts"][role]["path"])
                raw = target.read_bytes()
                self.assertEqual(raw, expected[target])
                self.assertEqual(len(report["native_calls"]), 5)
                altered = bytes([raw[0] ^ 1]) + raw[1:]
                mode = target.stat().st_mode & 0o777
                target.chmod(mode | 0o200)
                try:
                    target.write_bytes(altered)
                finally:
                    target.chmod(mode)
                rows.append({"role": role, "bytes": len(raw),
                             "original_sha256": sha256(raw).hexdigest(),
                             "altered_sha256": sha256(altered).hexdigest(),
                             "actual_native_calls_before_mutation": 5})
                return report, expected

            with self.subTest(role=role), patch.object(build, "_compile_pipeline", changed):
                with self.assertRaisesRegex(ValueError, "compiler or produced artifact changed"):
                    development_build(ROOT, directory, compiler)
        self.assertEqual(len(rows), 6)
        (Path(self.build["image_path"]).parent / "late-artifact-controls.json").write_text(
            json.dumps({"scope": "actual development pipeline publication refusals",
                        "native_cold_qualification_claimed": False, "cases": rows},
                       indent=2, sort_keys=True) + "\n"
        )
