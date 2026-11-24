"""Independent original Rust captures and public contracts for the HIA owner.

HEPTA_HIA_NDU_SCALAR selects a built ELF; no test builds a Python substitute.
HEPTA_HIA_NDU_BUILD selects an actual matching-source cold build for admission.
Missing prerequisites remain explicit skips rather than qualification evidence.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BINARY = os.environ.get('HEPTA_HIA_NDU_SCALAR')
BUILD = os.environ.get('HEPTA_HIA_NDU_BUILD')
PIN = 'd3c2d760eca5065fc966820379c35c6e8d56e855'


def original_pairs():
    archive_path = ROOT / 'review-evidence/hia-ndu-persistent-20261108-5e6c/originals.tar.xz'
    seen = set()
    with tarfile.open(archive_path) as archive:
        for member in archive:
            if not member.name.endswith('prepared_ndu-originals.jsonl'):
                continue
            for line in archive.extractfile(member):
                record = json.loads(line)
                observed = record.get('observation', {})
                pump = observed.get('pump') or {}
                supplied, expected = observed.get('stdin'), pump.get('stdout')
                if not supplied or not expected or pump.get('returncode') != 0:
                    continue
                raw, answer = base64.b64decode(supplied['data']), base64.b64decode(expected['data'])
                if sha256(raw).hexdigest() != supplied['sha256'] or sha256(answer).hexdigest() != expected['sha256']:
                    raise AssertionError('original Rust capture differs from its retained digest')
                key = supplied['sha256'], expected['sha256']
                if key not in seen:
                    seen.add(key)
                    yield raw, answer


def frame(sequence, body, session='1' * 64):
    payload = sequence.to_bytes(4, 'big') + session.encode('ascii') + body
    return len(payload).to_bytes(4, 'big') + payload


def frames(raw):
    result = []
    while raw:
        if len(raw) < 4:
            raise AssertionError('partial output frame header')
        size = int.from_bytes(raw[:4], 'big')
        if size < 69 or len(raw) < size + 4:
            raise AssertionError('partial output frame body')
        result.append((int.from_bytes(raw[4:8], 'big'), raw[8:72], raw[72:size + 4]))
        raw = raw[size + 4:]
    return result


@unittest.skipUnless(BINARY and Path(BINARY).is_file(), 'actual HIA NDU ELF required; NOT qualified')
class NativeScalarNduTests(unittest.TestCase):
    def invoke(self, raw, *args, timeout=15):
        return subprocess.run([BINARY, *args], input=raw, capture_output=True,
                              env={'PATH': ''}, timeout=timeout, check=False)

    def test_original_fourteen_public_contract_tests(self):
        with patch.dict(os.environ, {'HEPTA_NDU_BRIDGE': BINARY}):
            spec = importlib.util.spec_from_file_location('ndu_original_contract', ROOT / 'tests/test_hia_ndu_bridge.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.NativeNDUBridgeTests)
        result = unittest.TestResult()
        suite.run(result)
        self.assertEqual(result.testsRun, 14)
        self.assertEqual(result.skipped, [])
        self.assertEqual(result.errors + result.failures, [])

    def test_original_rust_complete_stdout_and_digests(self):
        pairs = list(original_pairs())
        self.assertGreaterEqual(len(pairs), 64)
        for raw, expected in pairs:
            with self.subTest(request=sha256(raw).hexdigest()):
                actual = self.invoke(raw)
                self.assertEqual((actual.returncode, actual.stderr), (0, b''))
                self.assertEqual(actual.stdout, expected)

    def test_stream_replays_fresh_original_results_and_exact_hello(self):
        pairs = list(original_pairs())[:4]
        actual = self.invoke(b''.join(frame(i, raw) for i, (raw, _) in enumerate(pairs, 1)),
                             '--stream-v1', '1' * 64, '4')
        self.assertEqual((actual.returncode, actual.stderr), (0, b''))
        decoded = frames(actual.stdout)
        self.assertEqual([row[0] for row in decoded], list(range(5)))
        self.assertTrue(all(row[1] == b'1' * 64 for row in decoded))
        expected_hello = {
            'schema': 'hepta.hia.ndu-stream-hello.v1',
            'transport_profile': 'hepta.hia.ndu-ranking-persistent-framed.v1',
            'upstream_commit': PIN, 'entry_point': 'codex_hepta_ndu::evaluate_candidates_with_policy',
            'max_requests': 4, 'max_frame_json_bytes': 1048576, 'max_session_bytes': 8388608,
            'authority': 'ADVISORY_ONLY', 'result_cache': False, 'evaluates_each_request': True,
        }
        self.assertEqual(decoded[0][2], json.dumps(expected_hello, sort_keys=True, separators=(',', ':')).encode())
        self.assertEqual([row[2] for row in decoded[1:]], [expected for _, expected in pairs])

    def test_stream_refuses_replay_mismatched_session_and_partial_frames(self):
        raw, _ = next(original_pairs())
        invalid = (frame(0, raw), frame(2, raw), frame(1, raw, '2' * 64),
                   b'\xff' * 4, b'\0', b'\0\0\0E' + b'x' * 10)
        for payload in invalid:
            with self.subTest(payload=payload[:8]):
                actual = self.invoke(payload, '--stream-v1', '1' * 64, '2')
                self.assertEqual(actual.returncode, 2)
                self.assertEqual([row[0] for row in frames(actual.stdout)], [0])
                self.assertEqual(json.loads(actual.stderr)['schema'], 'hepta.hia.ndu-stream-error.v1')

    def test_stream_boundary_eof_and_round_limit(self):
        raw, expected = next(original_pairs())
        actual = self.invoke(b'', '--stream-v1', '1' * 64, '256')
        self.assertEqual((actual.returncode, actual.stderr), (0, b''))
        self.assertEqual([row[0] for row in frames(actual.stdout)], [0])
        actual = self.invoke(frame(1, raw) + frame(1, raw), '--stream-v1', '1' * 64, '1')
        self.assertEqual((actual.returncode, actual.stderr), (0, b''))
        self.assertEqual([row[0] for row in frames(actual.stdout)], [0, 1])
        self.assertEqual(frames(actual.stdout)[1][2], expected)

    def test_stream_combined_byte_budget_is_not_renewed(self):
        raw, _ = next(original_pairs())
        large = b' ' * (1048576 - len(raw)) + raw
        actual = self.invoke(b''.join(frame(i, large) for i in range(1, 9)),
                             '--stream-v1', '1' * 64, '8', timeout=60)
        self.assertEqual(actual.returncode, 2)
        self.assertEqual([row[0] for row in frames(actual.stdout)], list(range(8)))
        self.assertIn('session byte allowance exhausted', json.loads(actual.stderr)['error'])

    def test_escaped_ascii_names_and_exact_unsigned_generation(self):
        raw, expected = next(original_pairs())
        escaped = raw.replace(b'"id"', b'"\\u0069d"').replace(b'"schema"', b'"\\u0073chema"')
        actual = self.invoke(escaped)
        self.assertEqual((actual.returncode, actual.stderr), (0, b''))
        value = json.loads(expected)
        value['request_sha256'] = sha256(escaped).hexdigest()
        self.assertEqual(json.loads(actual.stdout), value)
        value = json.loads(raw)
        value['generation'] = (1 << 64) - 1
        actual = self.invoke(json.dumps(value, separators=(',', ':')).encode())
        self.assertEqual((actual.returncode, actual.stderr), (0, b''))
        self.assertEqual(json.loads(actual.stdout)['generation'], (1 << 64) - 1)
        value['generation'] = 1 << 64
        actual = self.invoke(json.dumps(value, separators=(',', ':')).encode())
        self.assertEqual(actual.returncode, 2)
        self.assertEqual(actual.stdout, b'')

    def test_rust_stable_id_domain_and_startup_decimal_spelling(self):
        raw, _ = next(original_pairs())
        value = json.loads(raw)
        value['candidates'][1]['id'] = '9' * 128
        actual = self.invoke(json.dumps(value, separators=(',', ':')).encode())
        self.assertEqual((actual.returncode, actual.stderr), (0, b''))
        value['candidates'][1]['id'] += '9'
        actual = self.invoke(json.dumps(value, separators=(',', ':')).encode())
        self.assertEqual(actual.returncode, 2)
        actual = self.invoke(b'', '--stream-v1', '0' * 64, '+' + '0' * 5000 + '1')
        self.assertEqual((actual.returncode, actual.stderr), (0, b''))
        self.assertEqual(json.loads(frames(actual.stdout)[0][2])['max_requests'], 1)

    def test_elf_has_no_interpreter_or_dynamic_loader(self):
        binary = Path(BINARY).read_bytes()
        self.assertEqual(binary[:7], b'\x7fELF\x02\x01\x01')
        offset = struct.unpack_from('<Q', binary, 32)[0]
        size, count = struct.unpack_from('<HH', binary, 54)
        kinds = [struct.unpack_from('<I', binary, offset + i * size)[0] for i in range(count)]
        self.assertNotIn(2, kinds)  # PT_DYNAMIC
        self.assertNotIn(3, kinds)  # PT_INTERP


@unittest.skipUnless(BINARY and BUILD, 'actual matching-source HIA build required; NOT qualified')
class MatchingColdNduTests(unittest.TestCase):
    def bridge(self):
        return {'binary': BINARY, 'build_receipt': str(Path(BUILD) / 'build-receipt.json')}

    def test_existing_prepared_and_persistent_consumers_use_hia(self):
        from hepta.hia_ndu_optimizer import _native_rank
        from hepta.hia_ndu_prepared_ranker import PreparedNduRanker
        from hepta.hia_ndu_persistent_ranker import PersistentNduRanker
        raw, expected = next(original_pairs())
        request, expected = json.loads(raw), json.loads(expected)
        result, identity = _native_rank(self.bridge(), request, timeout_s=10)
        self.assertEqual(result, expected)
        self.assertEqual(identity['implementation'], 'HIA')
        with PreparedNduRanker(self.bridge(), max_requests=2) as prepared:
            self.assertEqual(prepared.rank(request)[0], expected)
        with PersistentNduRanker(self.bridge(), max_requests=2) as persistent:
            self.assertEqual(persistent.rank(request)[0], expected)
            self.assertEqual(persistent.rank(request)[0], expected)

    def test_implicit_selection_uses_the_real_hia_image(self):
        from hepta.hia_ndu_optimizer import _native_rank
        from hepta.hia_ndu_prepared_ranker import PreparedNduRanker
        from hepta.hia_ndu_persistent_ranker import PersistentNduRanker
        raw, expected = next(original_pairs())
        request, expected = json.loads(raw), json.loads(expected)
        with patch('hepta.hia_ndu_native.default_ndu_bridge', return_value=self.bridge()):
            result, identity = _native_rank(None, request, timeout_s=10)
            self.assertEqual((result, identity['implementation']), (expected, 'HIA'))
            with PreparedNduRanker(max_requests=1) as owner:
                self.assertEqual(owner.rank(request)[0], expected)
            with PersistentNduRanker(max_requests=1) as owner:
                self.assertEqual(owner.rank(request)[0], expected)

    def test_development_foreign_and_changed_custody_cannot_launch(self):
        from hepta.hia_ndu_optimizer import OptimizationRejected, _native_rank
        request = json.loads(next(original_pairs())[0])
        actual = json.loads(Path(self.bridge()['build_receipt']).read_bytes())
        variants = []
        for key, value in (('schema', 'hepta.hia.ndu-build.v1'),
                           ('schema', 'hepta.test.ndu-transport-fixture.v1'),
                           ('scope', 'DEVELOPMENT_COMPONENT'),
                           ('implementation', 'Rust'),
                           ('source_sha256', {}),
                           ('executable_sha256', '0' * 64)):
            variants.append({**actual, key: value})
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / 'rejected-receipt.json'
            for value in variants:
                receipt.write_text(json.dumps(value))
                with self.subTest(value=value), patch('subprocess.Popen') as launch:
                    with self.assertRaises(OptimizationRejected):
                        _native_rank({**self.bridge(), 'build_receipt': str(receipt)}, request, timeout_s=10)
                    launch.assert_not_called()


class RetiredScalarReferenceTests(unittest.TestCase):
    def test_archived_oracle_retains_exact_independent_source(self):
        from tools.hia_ndu_reference import FILES, materialize_reference, reference_files
        files = reference_files()
        self.assertEqual({name: sha256(raw).hexdigest() for name, raw in files.items()}, FILES)
        with tempfile.TemporaryDirectory() as temporary:
            directory = materialize_reference(Path(temporary) / 'oracle')
            self.assertEqual({str(path.relative_to(directory)): path.read_bytes()
                              for path in directory.rglob('*') if path.is_file()}, files)

    def test_shared_rust_builder_has_no_implicit_scalar_production_adapter(self):
        from tools.build_hia_ndu_bridge import build
        with tempfile.TemporaryDirectory() as temporary, patch('subprocess.check_output') as command:
            with self.assertRaisesRegex(ValueError, 'retired'):
                build(temporary, Path(temporary) / 'uncreated')
            command.assert_not_called()
            self.assertFalse((Path(temporary) / 'uncreated').exists())


if __name__ == '__main__':
    unittest.main()
