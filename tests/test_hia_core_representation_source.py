"""Source qualification of the independent byte representation components.

These finite interpreter controls establish no native, installed or cold claim.
All old public Core and renderer tests remain independently registered.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import _Machine, _Owner, _View

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = 1 << 20

# Original R7 native full frames, including its output key-table scratch.
# Image SHA-256: 35c4661a18b8464e579c852193e7d61a0f455470779955b41c884e34c753f902.
_FROZEN_ARENA_FRAMES = json.loads(zlib.decompress(base64.b64decode(
    'eNrt2sFO4lAUBuA9T9F07YL23raMb4NVNy4gCnFhfPfBEBcczRAznGQyfP8XE0pnuFruPwfTeVs0TVtWpW9vm7fD48PRZr/b7neH43YpIiIiV5f1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABftTeL5pD2ZbN/nh/a26Yd7sqyn6/3a7j/vCavm+enl+36eFlW3fIk8xyeuETqtw+PxwnL/Shx/eHMeRERERERERERERERERGRfyTtomneP24Et2VVSnvbvB1vCm/2u+1+50b5x43ycMnCHeFqE4mIyH8Y/3kQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgO+0N4vmkPZls3+eH9rbph3uyrKfr/druP+8Jq+b56eX7fp4Weqq/qpdLXU9LMuydKtueZJ5Pn0inq/h+Pjktw+PiX9+OD18PJP49+vyhylnzvdnvt/uwuuVM8eXXq/++fpffL34+lPyemM4/pW8Xvx57pLXW4Xj++T14vV7TF5vHV4+u3/h/eqy+zeHl8/uX9gfXXb/HsLLZ/cv7McuuX9ftmNy/+L+75L714X51yf3L/atT+5fF+Zfn9y/2O8+uX9dmH99cv/ivyd9dv/C/Ouz+xeuX5/dvzD/Snb/wvtVsvsX5l/J7l/YHyW7f2H+lez+hf1YkvsXfz0qyf2L86ck96/vz/x+e+n1wvma3L8+zL+a3L84X2ty//ow/2py/+I8r9n9C/OvZvcvXL+a3b8w/4bs/oX3a8juX5h/Q3b/wv4YsvsX5t+Q3b+wH4fk/sXTQ3L/4ue/Ibl/Jcy/Mbl/8fPmmNy/EubfmNy/+Pl2TO5fCfNvTO5f/Dw9ZvcvzL8xu3/h+o3Z/Qvzb8ruX3i/puz+hfk3Zfcv7I8pu39h/k3Z/Qv7cUruX7x9NCX3L97/m/62f1efdtE074v3xW/tx1rQ'
)))


class CoreRepresentationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.generate_hia_assembly_reparse import document as reparse
        from tools.generate_hia_core_representation_internal import document as representation
        from tools.generate_hia_core_representation_private import document as private
        cls.documents = {'assembly_reparse': reparse(), 'core_representation_internal': representation()[0],
                         'core_representation_private': private()[0]}
        cls.programs = {name: assemble_program((ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes())
                        for name in cls.documents}
        selected = os.environ.get('HEPTA_HIA_REPRESENTATION_SOURCE_EVIDENCE')
        cls.temporary = None if selected else tempfile.TemporaryDirectory(prefix='hia-representation-source-')
        cls.evidence = Path(selected or cls.temporary.name)
        cls.evidence.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def invoke(self, label, component, raw, output_size, workspace, expected=None):
        folder = self.evidence / label
        folder.mkdir()
        initial = (raw, b'\xa5' * output_size, workspace)
        owners = tuple(_Owner(-(i + 1), bytearray(value)) for i, value in enumerate(initial))
        machine = _Machine(self.programs[component], 10000000, CAPACITY, None, 128)
        record = {'schema': 'hia.representation.source-vm.v1', 'status': 'IN_PROGRESS',
                  'native_execution': False, 'whole_native': False, 'step_limit': 10000000}
        for name, value in zip(('source', 'output', 'workspace'), initial):
            (folder / ('initial-' + name + '.bin')).write_bytes(value)
        try:
            values = machine.invoke(machine.functions['f0'], [_View(owners[0], False),
                _View(owners[1], True), _View(owners[2], True)])
            record.update(status='returned', report=machine.report('f0', 'returned', values, external_roots=owners))
            self.assertEqual(bytes(owners[0].data), raw)
            self.assertEqual(tuple(len(owner.data) for owner in owners), tuple(map(len, initial)))
            self.assertEqual(len(values), 1)
            if expected is not None:
                for name, owner, wanted in zip(('source', 'output', 'workspace'), owners, expected):
                    with self.subTest(complete_buffer=name):
                        self.assertEqual(bytes(owner.data), wanted)
            return values[0], bytes(owners[1].data)
        except BaseException as exc:
            record.update(status='exception', error_type=type(exc).__name__, error=str(exc))
            raise
        finally:
            record['steps'] = machine.steps
            for name, owner in zip(('source', 'output', 'workspace'), owners):
                (folder / (name + '.bin')).write_bytes(bytes(owner.data))
            (folder / 'RESULT.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')

    def test_generated_assets_are_reproducible_and_independently_verified(self):
        for name, document in self.documents.items():
            with self.subTest(component=name):
                raw = (ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes()
                self.assertEqual(render_assembly(document).encode(), raw)
                self.assertEqual(verify_program(document).canonical_bytes, self.programs[name].canonical_bytes)
                self.assertLessEqual(len(document['functions']), 128)
                self.assertLessEqual(sum(len(f['blocks']) for f in document['functions']), 1536)
                self.assertLessEqual(sum(len(b['ops']) for f in document['functions'] for b in f['blocks']), 8192)

    def test_private_actual_arena_accepts_exact_boundary_and_refuses_one_less(self):
        from hepta.hia_core_json_bytes_native import BAD_ABI
        raw = b'[' + b','.join([b'0'] * 64) + b']'
        exact = 64 + 56 * 65 + len(raw)
        self.assertEqual(exact, 3833)
        for amount in (exact - 1, exact):
            workspace = bytearray(amount)
            workspace[:8] = b'HIACIR01'
            struct.pack_into('<Q', workspace, 8, 4300)
            expected = tuple(bytes.fromhex(_FROZEN_ARENA_FRAMES[str(amount)][name])
                             for name in ('source', 'output', 'workspace'))
            code, output = self.invoke('actual-arena-' + str(amount), 'core_representation_internal',
                                       raw, 32768, bytes(workspace), expected=expected)
            if amount < exact:
                self.assertEqual(code, BAD_ABI)
            else:
                self.assertEqual(code, len(raw))
                self.assertEqual(output[:code], raw)
                self.assertEqual(output[code:], expected[1][code:])

    def test_independent_reparser_restores_real_formatter_core_identity(self):
        from tools.generate_hia_assembly_reparse import WORKSPACE_BYTES
        document = {'schema': 'hepta.hia.program.v8', 'module': 'representation_control', 'exports': [],
            'functions': [{'name': 'main', 'params': [], 'returns': ['u32'], 'effects': [], 'entry': 'b0',
                'blocks': [{'id': 'b0', 'params': [], 'ops': [{'op': 'const', 'args': [],
                    'out': [{'name': 'answer', 'type': 'u32'}], 'attrs': {'value': 42}}],
                    'term': {'op': 'ret', 'values': ['answer']}}]}]}
        checked = verify_program(document)
        raw = render_assembly(checked).encode()
        code, output = self.invoke('independent-reparse', 'assembly_reparse', raw, 32768, bytes(WORKSPACE_BYTES))
        self.assertLessEqual(code, len(output))
        self.assertEqual(verify_program(output[:code]).canonical_bytes, checked.canonical_bytes)
        self.assertEqual(output[code:], b'\xa5' * (len(output) - code))


    def test_private_resident_refuses_both_public_requests_with_all_buffers_unchanged(self):
        from hepta.hia_core_json_bytes_native import BAD_ABI
        raw = b'null'
        for magic in (b'HIACJQ01', b'HIACJDQ1'):
            workspace = bytearray(32768)
            workspace[:8] = magic
            struct.pack_into('<Q', workspace, 8, 4300)
            expected = (raw, b'\xa5' * 32768, bytes(workspace))
            code, output = self.invoke('private-refusal-' + magic.decode('ascii'),
                'core_representation_private', raw, 32768, bytes(workspace), expected=expected)
            self.assertEqual(code, BAD_ABI)
            self.assertEqual(output, expected[1])



if __name__ == '__main__':
    unittest.main()
