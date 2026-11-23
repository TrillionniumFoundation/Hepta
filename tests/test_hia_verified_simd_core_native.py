"""Check the real self-hosted SIMD Core recognizer against the established verifier."""
from copy import deepcopy
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_verified_simd import simd_kernel_program
from hepta.hia_verified_simd_check import recognize_simd_core, VerifiedSIMDRejected
from tools.generate_hia_verified_simd_core import KINDS, MODULE, program
from tools.qualify_hia_selfhost import compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap' / (MODULE + '.hepta')
COMPILER = os.environ.get('HEPTA_HIA_SELFHOST_TEST_COMPILER')


class VerifiedSIMDCoreTests(unittest.TestCase):
    def test_checked_in_policy(self):
        self.assertEqual(SOURCE.read_text(), render_assembly(program()))

    @unittest.skipUnless(COMPILER, 'requires a self-hosted HIA compiler image')
    def test_actual_image_accepts_bijections_and_refuses_changed_recurrences(self):
        with TemporaryDirectory() as temp:
            path = Path(temp)
            image, _ = compile_stage(path, 'matcher', Path(COMPILER), SOURCE.read_bytes())
            for index, kind in enumerate(KINDS, 1):
                doc = simd_kernel_program(kind, 'external_name').as_dict()
                f = doc['functions'][0]
                ids = {b['id'] for b in f['blocks']}
                ids.update(p['name'] for b in f['blocks'] for p in b['params'])
                ids.update(p['name'] for b in f['blocks'] for op in b['ops'] for p in op['out'])

                def rename(value):
                    if isinstance(value, str):
                        return ('new_' + value) if value in ids else value
                    if isinstance(value, list):
                        return list(map(rename, value))
                    if isinstance(value, dict):
                        return {k: (v if k == 'op' else rename(v)) for k, v in value.items()}
                    return value

                alpha = rename(doc)
                alpha['functions'][0]['blocks'].reverse()
                empty_exports = dict(alpha, exports=[])
                stride = deepcopy(doc)
                stride['functions'][0]['blocks'][2]['ops'][-2]['attrs']['value'] = 2
                edge = deepcopy(doc)
                back = edge['functions'][0]['blocks'][2]['term']['args']
                back[-1] = edge['functions'][0]['blocks'][2]['params'][-1]['name']
                cases = [doc, alpha, empty_exports, stride, edge]
                for number, case in enumerate(cases):
                    raw = json.dumps(case).encode()
                    with self.subTest(kernel=kind, case=number):
                        result, reply = invoke(path, f'{kind}-{number}', image, raw,
                                               capacity=65536, workspace_size=131072)
                        self.assertEqual(result['status'], 'returned')
                        if number < 3:
                            self.assertEqual(recognize_simd_core(case), (kind, 'external_name'))
                            self.assertEqual(result['core_u32'], 37)
                            self.assertEqual(reply[:8], b'HIASIMC1')
                            self.assertEqual(int.from_bytes(reply[8:16], 'little'), index)
                            self.assertEqual(int.from_bytes(reply[16:24], 'little'), 13)
                            self.assertEqual(reply[24:37], b'external_name')
                        else:
                            with self.assertRaises(VerifiedSIMDRejected):
                                recognize_simd_core(case)
                            self.assertEqual(result['core_u32'], 0)
