"""Public Base64 package consumers, checked against Python's standard library.

HEPTA_BASE64_BACKEND=c (default) or rust requires the selected native toolchain;
missing tools fail rather than skip. Supplemental ctypes checks are separate.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.packages import load_package, verify_lock, write_lock
from hepta.pipeline import analyze_project

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / 'stdlib/base64'
BACKEND = os.environ.get('HEPTA_BASE64_BACKEND', 'c')
CONTRACT = ('resources { heap_allocations = 0; may_block = false; '
            'may_suspend = false; may_spawn = false; }')
MAX = (1 << 64) - 1


def canonical_decode(data):
    try:
        decoded = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error):
        return None
    # Python accepts nonzero unused bits and some excessive padding. RFC4648
    # canonical form additionally requires the unique standard padded encoding.
    return decoded if base64.b64encode(decoded) == data else None


class Base64Tests(unittest.TestCase):
    def setUp(self):
        self.assertIn(BACKEND, {'c', 'rust'})
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-stdlib-base64-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(LIBRARY, self.root / 'base64')
        self.app = self.root / 'app'
        (self.app / 'src').mkdir(parents=True)
        (self.app / 'hepta.toml').write_text(
            '[package]\nname = "base64_test"\nversion = "0.1.0"\nkind = "bin"\n'
            '[dependencies]\nbase64 = { path = "../base64" }\n', encoding='utf-8')

    def source(self, body, effects='panic, write'):
        entry = self.app / 'src/main.hepta'
        entry.write_text('import base64;\nfn main() -> Unit effects { ' + effects + ' }\n'
                         + CONTRACT + '\n{\n' + body + '\n}\n', encoding='utf-8')
        write_lock(self.app)
        return entry

    def execute(self, body):
        self.source(body)
        analysis = analyze_project(self.app, backend=BACKEND, crate_type='bin', locked=True)
        self.assertTrue(analysis.report['ok'], analysis.report)
        self.assertEqual(len(analysis.project.modules), 2)
        self.assertTrue(analysis.report['project']['locked'])
        for optimize in (False, True):
            artifact = self.root / ('optimized' if optimize else 'unoptimized')
            if BACKEND == 'c':
                native = compile_c(analysis.c, output=artifact, optimize=optimize, sanitize=True)
                self.assertFalse(native['rustc_used'])
                self.assertIn('-fsanitize=undefined', native['flags'])
                self.assertIn('-fno-sanitize-recover=all', native['flags'])
            else:
                native = compile_rust(analysis.rust, output=artifact, crate_type='bin', optimize=optimize)
            self.assertTrue(native['ok'], native)
            self.assertGreater(native['artifact_bytes'], 0)
            result = subprocess.run([str(artifact)], capture_output=True, text=True, timeout=15)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))

    def cases(self, cases):
        batches, batch, byte_checks = [], [], 0
        for case in cases:
            cost = len(case[1]) + len(case[4])
            if batch and (len(batch) >= 20 or byte_checks + cost > 256):
                batches.append(batch)
                batch, byte_checks = [], 0
            batch.append(case)
            byte_checks += cost
        if batch:
            batches.append(batch)
        for batch in batches:
            lines = []
            for n, (mode, data, start, end, output, offset) in enumerate(batch):
                # The public shared C subset uses nonempty backing arrays.
                data, output = bytes(data), bytes(output)
                self.assertTrue(data and output)
                expected = None
                if 0 <= start <= end <= len(data):
                    segment = data[start:end]
                    expected = base64.b64encode(segment) if mode == 'encode' else canonical_decode(segment)
                length_ok = expected is not None
                size = len(expected) if length_ok else 0
                ok = length_ok and offset <= len(output) and size <= len(output) - offset
                wanted = bytearray(output)
                if ok:
                    wanted[offset:offset + size] = expected
                lines += [f'let input{n}: [u8; {len(data)}] = [{", ".join(map(str, data))}];',
                          f'let mut output{n}: [u8; {len(output)}] = [{", ".join(map(str, output))}];',
                          f'let result{n} = base64::{mode}(read input{n}, {start}, {end}, mut output{n}, {offset});',
                          f'assert(result{n}.ok == {str(ok).lower()});',
                          f'assert(result{n}.bytes == {size if ok else 0});']
                if mode == 'decode':
                    lines += [f'let length{n} = base64::decoded_length(read input{n}, {start}, {end});',
                              f'assert(length{n}.ok == {str(length_ok).lower()});',
                              f'assert(length{n}.bytes == {size});']
                lines += [f'assert(input{n}[{i}] == {value});' for i, value in enumerate(data)]
                lines += [f'assert(output{n}[{i}] == {value});' for i, value in enumerate(wanted)]
            self.execute('\n'.join(lines))

    def test_rfc4648_vectors(self):
        cases = []
        for raw, encoded in [(b'', b''), (b'f', b'Zg=='), (b'fo', b'Zm8='),
                             (b'foo', b'Zm9v'), (b'foob', b'Zm9vYg=='),
                             (b'fooba', b'Zm9vYmE='), (b'foobar', b'Zm9vYmFy')]:
            self.assertEqual(base64.b64encode(raw), encoded)
            for mode, data in [('encode', raw), ('decode', encoded)]:
                framed = b'\xff' + data + b'\xff'
                cases.append((mode, framed, 1, len(framed) - 1, b'\xa5' * 13, 2))
        self.cases(cases)

    def test_all_single_byte_encodings(self):
        cases = []
        for value in range(256):
            raw = bytes([value])
            cases += [('encode', raw, 0, 1, b'\xa5' * 6, 1),
                      ('decode', base64.b64encode(raw), 0, 4, b'\xa5' * 3, 1)]
        self.cases(cases)

    def test_seeded_multiquartet_inputs(self):
        rng = random.Random(20261105)
        cases = []
        for length in range(1, 41):
            data = bytes(rng.randrange(256) for _ in range(length))
            encoded = base64.b64encode(data)
            cases += [('encode', b'\xff' + data + b'\xff', 1, length + 1, b'\xa5' * (len(encoded) + 3), 2),
                      ('decode', b'\xff' + encoded + b'\xff', 1, len(encoded) + 1, b'\xa5' * (length + 3), 1)]
        self.cases(cases)

    def test_noncanonical_and_malformed_inputs_are_unchanged(self):
        invalid = [b'A', b'AA', b'AAA', b'AAAAA', b'=', b'====', b'=AAA', b'A=AA',
                   b'AA=A', b'AA==AAAA', b'AAA=AAAA', b'AAAA====', b'AAAA=',
                   b'Zg', b'Zg=', b'Zg===', b'Zh==', b'Zm9=', b' Zg==',
                   b'Zg==\n', b'AA-_', b'AA\x00A', b'AA\xffA']
        # Late-invalid suffix must not leave a decoded valid prefix in output.
        invalid += [b'Zm9v' + suffix for suffix in invalid]
        for char in (0, 9, 10, 13, 32, 33, 45, 95, 127, 128, 255):
            for position in range(4):
                data = bytearray(b'AAAA')
                data[position] = char
                invalid.append(bytes(data))
        self.assertTrue(all(canonical_decode(data) is None for data in invalid))
        self.cases([('decode', data, 0, len(data), b'\xa5' * 12, 1) for data in invalid])

    def test_ranges_capacity_and_maximum_offsets(self):
        cases = []
        for mode, data in [('encode', b'\x00\x01\x02\x03\xff'), ('decode', b'Zm9vYg==')]:
            for start in range(len(data) + 1):
                for end in range(start, len(data) + 1):
                    for capacity, offset in [(1, 0), (6, 1), (12, 2)]:
                        cases.append((mode, data, start, end, b'\xa5' * capacity, offset))
            for start, end in [(2, 1), (0, len(data) + 1), (MAX, MAX), (0, MAX), (MAX, 0)]:
                cases.append((mode, data, start, end, b'\xa5' * 12, 0))
            for offset in (12, 13, MAX):
                cases.append((mode, data, 0, len(data), b'\xa5' * 12, offset))
                cases.append((mode, data, 0, 0, b'\xa5' * 12, offset))
        self.cases(cases)

    def test_encoded_length_overflow_boundaries(self):
        threshold = (MAX // 4) * 3
        lengths = list(range(129)) + list(range(threshold - 3, threshold + 4)) + [MAX - 2, MAX - 1, MAX]
        lines = []
        for n, length in enumerate(lengths):
            size = ((length + 2) // 3) * 4
            ok = size <= MAX
            lines += [f'let size{n} = base64::encoded_length({length});',
                      f'assert(size{n}.ok == {str(ok).lower()});',
                      f'assert(size{n}.bytes == {size if ok else 0});']
        self.execute('\n'.join(lines))

    def test_resource_contracts_and_both_frontends(self):
        self.source('let size = base64::encoded_length(6); assert(size.ok);')
        for backend in ('c', 'rust'):
            analysis = analyze_project(self.app, backend=backend, native=False)
            self.assertTrue(analysis.report['ok'], analysis.report)
            self.assertEqual(analysis.report['status'], 'frontend_only')
            self.assertEqual(len(analysis.program.functions), 7)
            for effects in analysis.report['effects'].values():
                self.assertLessEqual(set(effects), {'panic', 'write'})
            for function in analysis.program.functions:
                self.assertEqual(function.resources, {'heap_allocations': 0, 'may_block': False,
                                                      'may_suspend': False, 'may_spawn': False})
        no_std = analyze_project(self.root / 'base64', backend='rust', crate_type='obj', no_std=True, native=False)
        self.assertTrue(no_std.report['ok'], no_std.report)
        self.assertIn('#![no_std]', no_std.rust)
        if BACKEND == 'rust':
            native = compile_rust(no_std.rust, crate_type='obj', output=self.root / 'base64.o')
            self.assertTrue(native['ok'], native)
            self.assertGreater(native['artifact_bytes'], 0)

    def test_invalid_consumers_reject(self):
        invalid = [
            ('let data: [u16; 4] = [65,65,65,65]; let r = base64::decoded_length(read data, 0, 4);', 'E_TYPE'),
            ('let data: [u8; 4] = [65,65,65,65]; let r = base64::decoded_length(data, 0, 4);', 'E_BORROW_MODE'),
            ('let data: [u8; 1] = [0]; let out: [u8; 4] = [0,0,0,0]; let r = base64::encode(read data, 0, 1, mut out, 0);', 'E_IMMUTABLE'),
        ]
        for backend in ('c', 'rust'):
            for body, code in invalid:
                with self.subTest(backend=backend, code=code):
                    self.source(body)
                    report = analyze_project(self.app, backend=backend, native=False).report
                    self.assertFalse(report['ok'], report)
                    self.assertIn(code, [d['code'] for d in report['diagnostics']])
            self.source('let size = base64::encoded_length(1);', effects='')
            report = analyze_project(self.app, backend=backend, native=False).report
            self.assertFalse(report['ok'], report)
            self.assertIn('E_EFFECT', [d['code'] for d in report['diagnostics']])

    def test_repeated_calls_and_borrow_alias_refusal(self):
        self.execute('''let input: [u8; 1] = [102];
        let mut data: [u8; 5] = [7,7,7,7,7];
        let first = base64::encode(read input, 0, 1, mut data, 1);
        let second = base64::encode(read input, 0, 1, mut data, 1);
        assert(first.ok && second.ok && data[0] == 7 && data[1] == 90 && data[4] == 61);
        let mut restored: [u8; 2] = [9,9];
        let decoded = base64::decode(read data, 1, 5, mut restored, 1);
        assert(decoded.ok && restored[0] == 9 && restored[1] == 102);''')
        self.source('let mut data: [u8; 4] = [0,0,0,0]; let r = base64::encode(read data, 0, 1, mut data, 0);')
        analysis = analyze_project(self.app, backend='c', native=False)
        self.assertFalse(analysis.report['ok'], analysis.report)
        self.assertIn('E_C_BORROW', [d['code'] for d in analysis.report['diagnostics']])

    def test_package_lock_relocation_and_staleness(self):
        self.source('let size = base64::encoded_length(1);')
        relocated = self.root / 'relocated'
        shutil.copytree(self.root / 'base64', relocated / 'base64')
        shutil.copytree(self.app, relocated / 'app')
        verify_lock(load_package(relocated / 'app'))
        changed = relocated / 'base64/src/lib.hepta'
        changed.write_text(changed.read_text(encoding='utf-8') + '\n// changed bytes\n', encoding='utf-8')
        with self.assertRaises(HeptaError) as rejected:
            verify_lock(load_package(relocated / 'app'))
        self.assertEqual(rejected.exception.diagnostic.code, 'E_LOCK_STALE')

    def test_checked_in_example_public_cli(self):
        result = subprocess.run([sys.executable, '-m', 'hepta', 'run',
                                 str(ROOT / 'examples/packages/base64_packet'), '--locked',
                                 '--backend', BACKEND, '--json'], cwd=ROOT,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['ok'], report)
        self.assertEqual((report['returncode'], report['stdout'], report['stderr']), (0, '', ''))


if __name__ == '__main__':
    unittest.main()
