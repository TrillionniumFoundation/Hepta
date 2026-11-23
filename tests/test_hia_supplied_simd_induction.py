"""Check the public supplied SIMD proof against a freshly linked, source-matched ELF."""
from hashlib import sha256
import os
from pathlib import Path
import shutil
import struct
import subprocess
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_scalar_reference_native import sealed_reference_bytes
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program


PROVER = os.environ.get('HEPTA_HIA_TEST_SUPPLIED_SIMD_PROVER')


@unittest.skipUnless(PROVER and shutil.which('ld'), 'requires a physical supplied HIA verifier and GNU ld')
class SuppliedSIMDInductionTests(unittest.TestCase):
    def test_full_sse2_sum_queries_and_counterfeit_instruction_refusals(self):
        core = simd_kernel_program('sum_u8')
        doc = core.canonical_bytes
        obj = emit_verified_simd(core, isa='sse2').object_bytes
        with TemporaryDirectory() as tmp:
            objpath = Path(tmp) / 'kernel.o'
            sopath = objpath.with_suffix('.so')
            objpath.write_bytes(obj)
            subprocess.run(['ld', '-shared', '-z', 'noexecstack', '-z', 'relro', '-z', 'now',
                            '--hash-style=both', '--build-id=none', str(objpath), '-lc', '-o', str(sopath)],
                           capture_output=True, check=True)
            final = sopath.read_bytes()

        def verify(magic, object_bytes, final_bytes):
            header = struct.pack('<8s5Q', magic, 1, 30000, len(doc), len(object_bytes), len(final_bytes))
            with sealed_reference_bytes(header, doc, object_bytes, final_bytes) as request:
                os.lseek(request, 0, os.SEEK_SET)
                return subprocess.run([PROVER], stdin=request, capture_output=True, timeout=35, env={'PATH': ''})

        legacy = verify(b'HIASP001', obj, final)
        self.assertEqual((legacy.returncode, legacy.stdout[:8], len(legacy.stdout)), (0, b'HIASIMR1', 464))
        complete = verify(b'HIASP002', obj, final)
        self.assertEqual((complete.returncode, complete.stdout[:8]), (0, b'HIASIMR2'))
        receipt = complete.stdout
        self.assertEqual(receipt[8:72], legacy.stdout[8:72])
        self.assertEqual(receipt[80:464], legacy.stdout[80:464])
        self.assertEqual(receipt[80:176], b''.join(sha256(raw).digest() for raw in (doc, obj, final)))
        count, = struct.unpack_from('<Q', receipt, 72)
        self.assertEqual(count, 12)
        cursor = 464
        outcomes = {}
        for _ in range(count):
            role, extent = struct.unpack_from('<2Q', receipt, cursor)
            self.assertNotIn(role, outcomes)
            cursor += 16
            self.assertEqual(receipt[cursor:cursor + 8], b'HIAPROR1')
            projected, verdict, steps, variables, clauses, formula, witness, table, _ = struct.unpack_from(
                '<9Q', receipt, cursor + 8)
            self.assertEqual(projected, 3)
            self.assertGreater(min(steps, variables, clauses), 0)
            self.assertEqual(extent, 80 + formula + witness + table)
            self.assertEqual(receipt[cursor + 80:cursor + 88], b'HIACNX02')
            outcomes[role] = verdict
            cursor += extent
        self.assertEqual(cursor, len(receipt))
        self.assertEqual({role for role, verdict in outcomes.items() if verdict == 1}, {1})
        self.assertEqual({role for role, verdict in outcomes.items() if verdict == 2},
                         {2, 3, 4, 5, 6, 31, 32, 42, 43, 47, 52})
        sequence = bytes.fromhex('4883ec08e8')
        self.assertEqual(obj.count(sequence), 1)
        self.assertEqual(final.count(sequence), 1)
        altered = bytes.fromhex('4883ec07e8')
        bad = verify(b'HIASP002', obj.replace(sequence, altered), final.replace(sequence, altered))
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, b'')
        # The vector body retains its valid encoding and changes one operand.
        # Replace only the vector loop following its comparison, since the
        # same packed add also appears in the bulk loop.
        vector = bytes.fromhex('f30f6f0f660ff6ca660fd4c1')
        pos = obj.rindex(vector)
        final_pos = final.rindex(vector)
        changed_obj, changed_final = bytearray(obj), bytearray(final)
        changed_obj[pos + len(vector) - 1] = 192
        changed_final[final_pos + len(vector) - 1] = 192
        bad = verify(b'HIASP002', bytes(changed_obj), bytes(changed_final))
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, b'')
