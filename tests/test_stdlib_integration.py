"""Public multi-library packet consumer, independently modeled with Python stdlib."""
from __future__ import annotations
import base64
import binascii
import bisect
import hashlib
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
EXAMPLE = ROOT / 'examples/packages/indexed_text'
BACKEND = os.environ.get('HEPTA_INTEGRATION_BACKEND', 'c')
MAX = (1 << 64) - 1
CONTRACT = 'resources { heap_allocations = 0; may_block = false; may_suspend = false; may_spawn = false; }'
SENTINEL = 0xFFEEDDCCBBAA9988


def packet(text):
    raw = text.encode('utf-8')
    return base64.b64encode(len(raw).to_bytes(2, 'big') + raw)


def expected(wire, start, end, scratch_size, scalar_size, query):
    """No Hepta library, generated code, or paired encoder supplies expectations."""
    scratch, scalars = [165] * scratch_size, [SENTINEL] * scalar_size
    failure = lambda stage: ((stage, 0, 0, 0), scratch, scalars)
    if not 0 <= start <= end <= len(wire):
        return failure(1)
    try:
        segment = wire[start:end]
        raw = base64.b64decode(segment, validate=True)
        if base64.b64encode(raw) != segment:
            return failure(1)
    except (ValueError, binascii.Error):
        return failure(1)
    if scratch_size < 1 or len(raw) > scratch_size - 1:
        return failure(1)
    scratch[1:1 + len(raw)] = raw
    if len(raw) < 2:
        return failure(2)
    if int.from_bytes(raw[:2], 'big') != len(raw) - 2:
        return failure(3)
    try:
        text = raw[2:].decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return failure(4)
    if scalar_size < 1 or len(text) > scalar_size - 1:
        return failure(5)
    values = sorted(map(ord, text))
    scalars[1:1 + len(values)] = values
    return ((0, len(values), 1 + bisect.bisect_left(values, query),
             1 + bisect.bisect_right(values, query)), scratch, scalars)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.assertIn(BACKEND, {'c', 'rust'})
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-stdlib-integration-case-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / 'stdlib', self.root / 'stdlib')
        self.app = self.root / 'examples/packages/indexed_text'
        shutil.copytree(EXAMPLE, self.app)

    def source(self, body, effects='panic, write'):
        entry = self.app / 'src/main.hepta'
        entry.write_text('import packet;\nfn main() -> Unit effects { ' + effects + ' }\n'
                         + CONTRACT + '\n{\n' + body + '\n}\n', encoding='utf-8')
        write_lock(self.app)

    def execute(self, body):
        self.source(body)
        analysis = analyze_project(self.app, backend=BACKEND, locked=True, crate_type='bin')
        self.assertTrue(analysis.report['ok'], analysis.report)
        self.assertEqual(len(analysis.project.modules), 6)
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
            result = subprocess.run([str(artifact)], capture_output=True, text=True, timeout=20)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))

    def cases(self, cases):
        # Bound translation-unit size without omitting any vector/assertion.
        batches, batch, cost = [], [], 0
        for case in cases:
            n = len(case[0]) + case[3] + case[4]
            if batch and (len(batch) >= 12 or cost + n > 350):
                batches.append(batch)
                batch, cost = [], 0
            batch.append(case)
            cost += n
        if batch:
            batches.append(batch)
        for batch in batches:
            lines = []
            for n, (wire, start, end, scratch_size, scalar_size, query) in enumerate(batch):
                self.assertTrue(wire and scratch_size and scalar_size)
                result, scratch, scalars = expected(wire, start, end, scratch_size, scalar_size, query)
                arr = lambda values: '[' + ','.join(map(str, values)) + ']'
                lines += [f'let input{n}: [u8; {len(wire)}] = {arr(wire)};',
                          f'let mut scratch{n}: [u8; {scratch_size}] = {arr([165] * scratch_size)};',
                          f'let mut scalars{n}: [u64; {scalar_size}] = {arr([SENTINEL] * scalar_size)};',
                          f'let result{n} = packet::index_packet(read input{n}, {start}, {end}, mut scratch{n}, mut scalars{n}, {query});']
                for field, value in zip(('stage', 'scalars', 'lower', 'upper'), result):
                    lines.append(f'assert(result{n}.{field} == {value});')
                for name, values in [('input', wire), ('scratch', scratch), ('scalars', scalars)]:
                    lines += [f'assert({name}{n}[{i}] == {v});' for i, v in enumerate(values)]
            self.execute('\n'.join(lines))

    @staticmethod
    def valid_case(text, query, padding=2):
        wire = b'\xff' + packet(text) + b'\xff'
        return wire, 1, len(wire) - 1, len(text.encode('utf-8')) + 3 + padding, len(text) + 1 + padding, query

    def test_unicode_boundaries_and_duplicate_queries(self):
        texts = ['', '\0', 'a', 'zzé😀é\0', '\x7f\u0080\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff',
                 '\ufeff\ufdd0\ufffe', 'é' * 9, 'zyxwvu']
        self.cases([self.valid_case(s, q) for s in texts for q in (0, 97, 233, 0x1F600, MAX)])

    def test_all_single_byte_payloads(self):
        cases = []
        for value in range(256):
            wire = base64.b64encode(b'\0\1' + bytes([value]))
            cases.append((wire, 0, len(wire), 6, 4, value))
        self.cases(cases)

    def test_seeded_unicode_packets(self):
        rng = random.Random(20261105)
        cases = []
        pool = [0, 1, 127, 128, 2047, 2048, 0xD7FF, 0xE000, 0xFFFF, 0x10000, 0x10FFFF]
        for i in range(48):
            values = [rng.choice(pool) for _ in range(i % 15)]
            text = ''.join(map(chr, values))
            query = rng.choice(values + [MAX, 0])
            cases.append(self.valid_case(text, query, padding=i % 3))
        self.cases(cases)

    def test_malformed_wire_header_and_utf8(self):
        malformed = [b'A', b'AA', b'AAA', b'AA-_', b'AA==AAAA', b'Zh==', b'Zm9=',
                     b'AA==\n', b'AAAA====', b'A\xffAA']
        raw = [b'', b'\0', b'\0\1', b'\0\0x', b'\xff\xffx']
        invalid_utf8 = [b'\x80', b'\xc0\x80', b'\xe0\x80\x80', b'\xed\xa0\x80',
                        b'\xf4\x90\x80\x80', b'\xf5\x80\x80\x80', b'\xe2\x82']
        for value in invalid_utf8:
            for prefix in (b'', b'valid'):
                text = prefix + value
                raw.append(len(text).to_bytes(2, 'big') + text)
        malformed += [base64.b64encode(value) for value in raw]
        self.cases([(b'\xff' + w + b'\xff', 1, len(w) + 1, 30, 20, 0) for w in malformed])

    def test_range_and_capacity_boundaries(self):
        wire = packet('éa')
        cases = [(wire, s, e, 10, 5, 97) for s in range(len(wire) + 1) for e in range(s, len(wire) + 1)]
        cases += [(wire, s, e, 10, 5, 97) for s, e in [(2, 1), (0, len(wire) + 1), (MAX, MAX), (MAX, 0), (0, MAX)]]
        for text in ('', 'a', 'éa😀'):
            encoded = packet(text)
            for scratch in range(1, len(text.encode()) + 6):
                for scalar in range(1, len(text) + 3):
                    cases.append((encoded, 0, len(encoded), scratch, scalar, 97))
        self.cases(cases)

    def test_seeded_arbitrary_payloads(self):
        rng = random.Random(697692)
        cases = []
        for n in range(32):
            raw = bytes(rng.randrange(256) for _ in range(n % 9))
            wire = base64.b64encode(len(raw).to_bytes(2, 'big') + raw)
            cases.append((wire, 0, len(wire), 15, 12, 128))
        self.cases(cases)

    def test_repeated_calls_replace_only_result_range(self):
        body = '''let input: [u8; 8] = [65,65,78,104,89,109,69,61];
        let mut scratch: [u8; 8] = [165,165,165,165,165,165,165,165];
        let mut scalars: [u64; 5] = [999,999,999,999,999];
        let first = packet::index_packet(read input, 0, 8, mut scratch, mut scalars, 97);
        let second = packet::index_packet(read input, 0, 8, mut scratch, mut scalars, 98);
        assert(first.stage == 0 && second.stage == 0);
        assert(first.lower == 1 && first.upper == 3 && second.lower == 3 && second.upper == 4);
        assert(scalars[0] == 999 && scalars[1] == 97 && scalars[2] == 97 && scalars[3] == 98 && scalars[4] == 999);
        assert(scratch[0] == 165 && scratch[6] == 165 && scratch[7] == 165);'''
        self.execute(body)

    def test_both_frontends_resources_and_no_std(self):
        for backend in ('c', 'rust'):
            analysis = analyze_project(self.app, backend=backend, native=False, locked=True, crate_type='bin')
            self.assertTrue(analysis.report['ok'], analysis.report)
            self.assertEqual(analysis.report['status'], 'frontend_only')
            self.assertEqual(len(analysis.project.modules), 6)
            for effects in analysis.report['effects'].values():
                self.assertLessEqual(set(effects), {'panic', 'write'})
            for function in analysis.program.functions:
                self.assertEqual(function.resources, {'heap_allocations': 0, 'may_block': False,
                                                      'may_suspend': False, 'may_spawn': False})
        # Actual composed library object excludes the application's main entry.
        manifest = self.app / 'hepta.toml'
        manifest.write_text(manifest.read_text().replace('kind = "bin"', 'kind = "lib"\nentry = "src/packet.hepta"'), encoding='utf-8')
        write_lock(self.app)
        analysis = analyze_project(self.app, backend='rust', native=False, locked=True, no_std=True, crate_type='obj')
        self.assertTrue(analysis.report['ok'], analysis.report)
        self.assertIn('#![no_std]', analysis.rust)
        if BACKEND == 'rust':
            native = compile_rust(analysis.rust, output=self.root / 'composed.o', crate_type='obj')
            self.assertTrue(native['ok'], native)
            self.assertGreater(native['artifact_bytes'], 0)

    def test_type_mutability_and_effect_refusals(self):
        for backend in ('c', 'rust'):
            for data_type, mutable, effects, code in [('u16', 'mut ', 'panic, write', 'E_TYPE'),
                                                    ('u8', '', 'panic, write', 'E_IMMUTABLE'),
                                                    ('u8', 'mut ', '', 'E_EFFECT')]:
                body = f'let input: [{data_type}; 1] = [0]; let {mutable}scratch: [u8; 1] = [0]; let mut scalars: [u64; 1] = [0]; let result = packet::index_packet(read input, 0, 1, mut scratch, mut scalars, 0);'
                self.source(body, effects)
                analysis = analyze_project(self.app, backend=backend, native=False, crate_type='bin')
                self.assertFalse(analysis.report['ok'], analysis.report)
                self.assertIn(code, [d['code'] for d in analysis.report['diagnostics']])

    def test_combined_lock_relocation_and_each_component_staleness(self):
        verify_lock(load_package(self.app))
        for name in ('bytes', 'base64', 'utf8', 'ordering'):
            source = self.root / 'stdlib' / name / 'src/lib.hepta'
            original = source.read_bytes()
            try:
                source.write_bytes(original + b'\n// integration lock mutation\n')
                with self.assertRaises(HeptaError) as rejected:
                    verify_lock(load_package(self.app))
                self.assertEqual(rejected.exception.diagnostic.code, 'E_LOCK_STALE')
            finally:
                source.write_bytes(original)
            verify_lock(load_package(self.app))

    def test_checked_in_example_public_cli(self):
        result = subprocess.run([sys.executable, '-m', 'hepta', 'run', str(self.app), '--locked',
                                 '--backend', BACKEND, '--json'], cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['ok'], report)
        self.assertEqual((report['returncode'], report['stdout'], report['stderr']), (0, '', ''))

    def test_frozen_component_and_compiler_bytes(self):
        manifest = json.loads((ROOT / 'tools/stdlib_integration_components.json').read_text())
        self.assertEqual([c['pr'] for c in manifest['components']], [692, 693, 696, 697])
        self.assertEqual(sum(len(c['files']) for c in manifest['components']), 39)
        for group in [manifest['compiler'], *manifest['components']]:
            for entry in group['files']:
                data = (ROOT / entry['path']).read_bytes()
                self.assertEqual(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(), entry['git_blob'], entry['path'])


if __name__ == '__main__':
    unittest.main()
