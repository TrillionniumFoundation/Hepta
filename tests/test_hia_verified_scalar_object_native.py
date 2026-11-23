"""Exercise the source-owned register allocator and object writer at the HIA ABI."""
import os
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_verified_scalar import emit_verified_scalar, VerifiedScalarRejected
from tests.test_hia_program import arithmetic, b, c, f, i, m, ret
from tests.test_hia_verified_scalar_division import live_division
from tests.test_hia_verified_scalar_shifts import live_shift
from tools.generate_hia_verified_scalar_object import program, subject_program
from tools.qualify_hia_selfhost import compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]
BOOT = ROOT / 'examples/hia_bootstrap'
COMPILER = os.environ.get('HEPTA_HIA_SELFHOST_TEST_COMPILER')


def full_pressure_mul(left, right):
    """At MUL RAX is free, every other register lives, and two SSA names die."""
    params = [(name, 'u32') for name in (left, 'p', right, 'q', 'r', 's')]
    ops = [c('dead', 'u32', 2), c('t', 'u32', 3), c('u', 'u32', 4),
           i('int.add.wrap', ['dead', 'dead'], [('unused', 'u32')]),
           i('int.mul.checked', [left, right], [('product', 'u32')])]
    previous = 'product'
    for index, name in enumerate(('p', 'q', 'r', 's', 't', 'u')):
        target = 'sum' + str(index)
        ops.append(i('int.add.wrap', [previous, name], [(target, 'u32')]))
        previous = target
    return m(f('calculate', params, ['u32'], ['trap'], [b('entry', params, ops, ret(previous))]))


class RegisterLeafSourceTests(unittest.TestCase):
    def test_generated_subject_and_object_are_exact(self):
        for name, doc in [('verified_scalar_subject', subject_program()), ('verified_scalar_object', program())]:
            self.assertEqual((BOOT / (name + '.hepta')).read_text(), render_assembly(doc))


@unittest.skipUnless(COMPILER, 'requires the cold HIA compiler')
class RegisterLeafObjectTests(unittest.TestCase):
    def test_physical_subject_liveness_and_machine_objects(self):
        import json

        with TemporaryDirectory() as temporary:
            work = Path(temporary)
            def compile_image(name):
                return compile_stage(work, name, Path(COMPILER), (BOOT / (name + '.hepta')).read_bytes())[0]
            selector = compile_image('verified_scalar_subject')
            emitter = compile_image('verified_scalar_object')

            def execute(label, image, data, capacity, workspace):
                result, raw = invoke(work, label, image, data, capacity=capacity, workspace_size=workspace)
                self.assertEqual(result['status'], 'returned')
                self.assertEqual(result['source_unchanged'], True)
                self.assertLessEqual(result['core_u32'], capacity)
                return raw[:result['core_u32']]

            cases = [('scalar-add', json.loads((ROOT / 'examples/hia_safe_core/scalar_add.core.hepta').read_bytes())),
                     ('rank-rdx', full_pressure_mul('z', 'a')), ('rank-rdi', full_pressure_mul('a', 'z')),
                     ('cl-relocation', live_shift()), ('rdx-relocation', live_division('int.rem.checked'))]
            cases.extend((typ + '-' + op, arithmetic('int.' + op + '.checked', typ))
                         for typ in ('u8', 'u32', 'i16', 'i64') for op in ('add', 'mul', 'shl', 'div'))
            for label, doc in cases:
                with self.subTest(case=label):
                    source = json.dumps(doc).encode()
                    subject = execute(label + '-subject', selector, source, 65536, 1 << 20)
                    self.assertEqual(subject[:8], b'HIASLE01')
                    offered = execute(label + '-object', emitter, subject, 16384, 8192)
                    self.assertEqual(offered, emit_verified_scalar(doc).object_bytes)

            refused = live_shift(pressure=True)
            with self.assertRaises(VerifiedScalarRejected):
                emit_verified_scalar(refused)
            subject = execute('exhausted-subject', selector, json.dumps(refused).encode(), 65536, 1 << 20)
            self.assertEqual(execute('exhausted-object', emitter, subject, 16384, 8192), b'')
            rank_count = struct.unpack_from('<Q', subject, 48)[0]
            self.assertGreater(rank_count, 1)
            malformed = subject[:-rank_count] + bytes(rank_count)
            self.assertEqual(execute('duplicate-ranks', emitter, malformed, 16384, 8192), b'')
