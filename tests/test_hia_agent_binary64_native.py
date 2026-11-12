"""Actual HIA decimal rounding, independent VM and exact midpoint witnesses."""
from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_binary64_native import SOURCE, SCHEMA, SELECTOR, NativeAgentBinary64
from tools.generate_hia_agent_binary64 import document

ROOT = Path(__file__).resolve().parents[1]


def vm_bits(wire, checked=None):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = assemble_program(SOURCE.read_bytes()) if checked is None else checked
    owners = [_Owner(-1, bytearray(wire)), _Owner(-2, bytearray(b'\xa5' * 8)),
              _Owner(-3, bytearray(b'\x93' * 4096))]
    machine = _Machine(checked, 50000000, 16 << 20, None, 128)
    entry = next(fn for fn in checked.as_dict()['functions'] if fn['name'] == 'f0')
    result = machine.invoke(entry, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
    return result, bytes(owners[1].data)


def midpoint_cases():
    # Exact rational reference, not host decimal-to-binary conversion. One
    # decimal unit at place1600 lies past the800 retained significant digits.
    for lower in (0, 1, 2, (1 << 52) - 1, 1 << 52, (1 << 52) + 1,
                  0x3fefffffffffffff, 0x3ff0000000000000, 0x3ff0000000000001,
                  0x7feffffffffffffe, 0x7fefffffffffffff):
        low = Fraction.from_float(struct.unpack('<d', struct.pack('<Q', lower))[0])
        high = (Fraction(1 << 1024) if lower == 0x7fefffffffffffff else
                Fraction.from_float(struct.unpack('<d', struct.pack('<Q', lower + 1))[0]))
        mid = (low + high) / 2
        scale = 10 ** 1600
        assert (mid.numerator * scale) % mid.denominator == 0
        coefficient = mid.numerator * scale // mid.denominator
        for adjustment in (-1, 0, 1):
            digits = str(coefficient + adjustment).rjust(1601, '0')
            text = digits[:-1600] + '.' + digits[-1600:]
            expected = lower if adjustment < 0 else lower + 1
            if adjustment == 0:
                expected = lower + (lower & 1)
            yield text.encode(), expected
            yield ('-' + text).encode(), expected | (1 << 63)


class AgentBinary64SourceTests(unittest.TestCase):
    def test_generated_actual_source(self):
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(len(assemble_program(SOURCE.read_bytes()).as_dict()['functions']), 12)

    def test_independent_Core_VM_before_any_native_seed(self):
        from hepta.hia_agent_assembly import assemble_program
        checked = assemble_program(SOURCE.read_bytes())
        for wire, bits in ((b'0', 0), (b'-0.0', 1 << 63), (b'1.25', 0x3ff4000000000000)):
            self.assertEqual(vm_bits(wire, checked), (8, struct.pack('<Q', bits)))
        for wire in (b'01', b'1e+', b'1.', b'NaN'):
            self.assertEqual(vm_bits(wire, checked), (0xffffffff, b'\xa5' * 8))

    def test_unqualified_builder_refuses_before_output_creation(self):
        from tools.build_hia_agent_binary64 import build
        with tempfile.TemporaryDirectory() as d:
            r = Path(d); (r / 'compiler').write_bytes(b'notqualified'); (r / 'cold').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'completed matching-source cold'):
                build(r / 'output', r / 'compiler', r / 'cold')
            self.assertFalse((r / 'output').exists())


class AgentBinary64NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Independent HIA VM witness precedes any native seed/image compilation.
        assert vm_bits(b'1.25') == (8, struct.pack('<Q', 0x3ff4000000000000))
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        selected = os.environ.get('HEPTA_HIA_AGENT_BINARY64_EVIDENCE')
        cls.temporary = None
        if selected:
            cls.folder = Path(selected); cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-agent-binary64-')
            cls.folder = Path(cls.temporary.name)
        seed, _ = build_seed(cls.folder)
        compiler_source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first, _ = compile_stage(cls.folder, 'B1', seed, compiler_source, image_format='seed-shared')
        second, _ = compile_stage(cls.folder, 'B2', first, compiler_source)
        assert first.read_bytes() == second.read_bytes()
        image, receipt = compile_stage(cls.folder, 'agent-binary64', second, SOURCE.read_bytes())
        raw = image.read_bytes(); cls.native = NativeAgentBinary64(raw, sha256(raw).hexdigest())
        cls.manifest = cls.folder / 'binary64-manifest.json'
        cls.manifest.write_text(json.dumps(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
            image_path=image.name, image_sha256=sha256(raw).hexdigest(), compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        from hepta.hia_agent_data_json_native import SOURCE as DATA_SOURCE, SCHEMA as DATA_SCHEMA
        image, data_receipt = compile_stage(cls.folder, 'agent-data-json', second, DATA_SOURCE.read_bytes())
        cls.data_manifest = cls.folder / 'data-manifest.json'
        cls.data_manifest.write_text(json.dumps(dict(schema=DATA_SCHEMA, source_sha256=sha256(DATA_SOURCE.read_bytes()).hexdigest(),
            image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(), compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        (cls.folder / 'development-build.json').write_text(json.dumps(dict(status='DEVELOPMENT_NOT_COLD_QUALIFICATION',
            native_compile_receipt=receipt, data_compile_receipt=data_receipt, foreign_float_boxing=True)))

    @classmethod
    def tearDownClass(cls):
        if cls.temporary: cls.temporary.cleanup()

    def test_native_exact_midpoints_sticky_tails_and_negative_zero(self):
        observations = []
        for wire, expected in midpoint_cases():
            with self.subTest(wire=wire[:40], expected=expected):
                if expected & 0x7fffffffffffffff == 0x7ff0000000000000:
                    with self.assertRaisesRegex(ValueError, 'nonfinite'): self.native.bits(wire)
                    observations.append({'input_sha256': sha256(wire).hexdigest(), 'nonfinite_refused': True})
                else:
                    actual = self.native.bits(wire)
                    self.assertEqual(actual, struct.pack('<Q', expected))
                    observations.append({'input_sha256': sha256(wire).hexdigest(), 'expected_bits': expected, 'actual_hex': actual.hex()})
        (self.folder / 'exact-midpoint-observations.json').write_text(json.dumps(observations, indent=2))

    def test_native_large_numeric_corpus_matches_binary64_bits(self):
        values = ['0', '-0', '0.0', '-0.0', '0e999999999', '-0e-999999999',
                  '1e400', '-1e400', '1e-99999', '-1e-99999', '5e-324',
                  '2.2250738585072014e-308', '1.7976931348623157e308', '1.7976931348623159e308']
        rng = random.Random(601110)
        for _ in range(512):
            size = rng.randrange(1, 1300)
            digits = str(rng.randrange(1, 10)) + ''.join(str(rng.randrange(10)) for _ in range(size - 1))
            values.append(('-' if rng.getrandbits(1) else '') + digits + 'e' + str(rng.randrange(-size - 330, 310 - size)))
        for text in values:
            reference = float(text)
            with self.subTest(text=text[:40]):
                if not math.isfinite(reference):
                    with self.assertRaises(ValueError): self.native.bits(text.encode())
                else:
                    self.assertEqual(self.native.bits(text.encode()), struct.pack('<d', reference))

    def test_actual_selected_Agent_data_has_no_host_decimal_or_JSON_parser(self):
        from hepta import hia_agent_store as store, hia_agent_data_json_native as data
        selection = {SELECTOR: str(self.manifest), data.SELECTOR: str(self.data_manifest)}
        with patch.dict(os.environ, selection), patch('json.loads', side_effect=AssertionError('foreign JSON parser')), \
                patch.object(store.re, 'compile', side_effect=AssertionError('foreign numeric tokenizer')), \
                patch.object(store, 'float', side_effect=AssertionError('foreign decimal conversion'), create=True), \
                patch.object(data, 'float', side_effect=AssertionError('foreign decimal conversion'), create=True):
            value = store.decode_data(b'{"ratio":1.25,"z":-0.0,"tiny":5e-324,"integer":123456789012345678901234567890}')
            self.assertEqual(struct.pack('<d', value['ratio']), struct.pack('<Q', 0x3ff4000000000000))
            self.assertEqual(struct.pack('<d', value['z']), struct.pack('<Q', 1 << 63))
            self.assertEqual(struct.pack('<d', value['tiny']), struct.pack('<Q', 1))
            self.assertEqual(value['integer'], 123456789012345678901234567890)
            with self.assertRaises(store.AgentRejected) as caught: store.decode_data(b'1e400')
            self.assertEqual(caught.exception.code, 'E_HIA_JSON')
        bad = self.folder / 'invalid-binary64-manifest.json'; bad.write_text('{}')
        with patch.dict(os.environ, {SELECTOR: str(bad)}), \
                patch.object(store, 'float', side_effect=AssertionError('fallback'), create=True):
            with self.assertRaises(ValueError): store.decode_data(b'1.0')

    def test_full_byte_ceiling_saturated_exponents_and_private_concurrent_workspaces(self):
        wire = b'-0e' + b'9' * ((8 << 20) - 3)
        self.assertEqual(self.native.bits(wire), struct.pack('<Q', 1 << 63))
        with self.assertRaises(ValueError): self.native.bits(wire + b'9')
        self.assertEqual(self.native.bits(b'0.' + b'0' * 32768 + b'1e32769'), struct.pack('<d', 1.0))
        for wire in (b'', b'01', b'+1', b'1.', b'.1', b'1e', b'1e+', b'1.0 ', b'NaN', b'Infinity', b'\xff'):
            with self.subTest(wire=wire), self.assertRaises(ValueError): self.native.bits(wire)
        inputs = [b'-0.0', b'1.25', b'5e-324', b'2.2250738585072014e-308'] * 12
        with ThreadPoolExecutor(max_workers=8) as pool:
            actual = list(pool.map(self.native.bits, inputs))
        self.assertEqual(actual, [struct.pack('<d', float(wire)) for wire in inputs])

    def test_actual_native_ABI_refuses_before_output_and_never_writes_past_capacities(self):
        import ctypes
        for wire, out_size, work_size, expected in (
                (b'1.25', 7, 4096, 0xfffffffd), (b'1.25', 8, 4095, 0xfffffffd),
                (b'1e+', 8, 4096, 0xffffffff), (b'1e400', 8, 4096, 0xfffffffc),
                (b'1.25', 8, 4096, 8)):
            source = ctypes.create_string_buffer(wire)
            output = ctypes.create_string_buffer(b'\xa5' * 40, 40)
            workspace = ctypes.create_string_buffer(b'\x93' * 4128, 4128)
            status = self.native._entry(source, len(wire), ctypes.byref(output, 16), out_size,
                                       ctypes.byref(workspace, 16), work_size)
            self.assertEqual(status, expected)
            self.assertEqual(output.raw[:16] + output.raw[24:], b'\xa5' * 32)
            self.assertEqual(workspace.raw[:16] + workspace.raw[4112:], b'\x93' * 32)
            if expected != 8:
                self.assertEqual(output.raw, b'\xa5' * 40)

    def test_actual_selected_full_Agent_node_ceiling_under_retained_child_limits(self):
        code = r'''
import os,resource,sys
sys.path.insert(0,sys.argv[1])
from hepta import hia_agent_store as store
os.environ['HEPTA_HIA_AGENT_DATA_JSON_MANIFEST']=sys.argv[2]
os.environ['HEPTA_HIA_AGENT_BINARY64_MANIFEST']=sys.argv[3]
def absent(*a,**k):raise AssertionError('foreign decimal converter')
store.float=absent
resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
resource.setrlimit(resource.RLIMIT_CPU,(10,10))
wire=b'['+b'0.0,'*262142+b'0.0]'
value=store.decode_data(wire)
assert len(value)==262143 and all(v.hex()=='0x0.0p+0' for v in value)
print('262144nodes/selectedgrammar+nativefloat/nohostfloat/256MiB/10CPU')
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code, str(ROOT),
                                 str(self.data_manifest), str(self.manifest)], capture_output=True,
                                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C'}, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b'262144nodes/selectedgrammar+nativefloat', result.stdout)


if __name__ == '__main__': unittest.main()
