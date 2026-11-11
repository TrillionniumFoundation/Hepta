"""Real constructor ingress only; no complete initializer/normalizer claim."""
from __future__ import annotations
import ctypes
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_nominal_json_native import SOURCE, MAX_BYTES, MAX_NODES
from hepta.hia_composite_constructor_native import SOURCES, CTOR_MAGIC, MAGIC, WORKSPACE_BYTES, OUTPUT_BYTES
from hepta.hia_composite_function_tokens import ObjectTokenDecoder, detached_packet_index
from tools.build_hia_nominal_json import admit_compile_receipt
from tests import test_hia_nominal_json_native as support

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIRECTORY = 'HEPTA_HIA_NOMINAL_JSON_INGRESS_EVIDENCE'
ABI = 0xfffffff1


class NominalJSONConstructorIngressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the actual VM-first fresh/cold fixture implementation, with an
        # independent owner and evidence directory. No inherited tests are run.
        class Fixture:
            pass
        cls.fixture = Fixture
        with patch.object(support, 'EVIDENCE_DIRECTORY', EVIDENCE_DIRECTORY):
            support.NominalJSONNativeTests.setUpClass.__func__(Fixture)
        cls.folder, cls.native = Fixture.folder, Fixture.native
        cls.cold_inputs = None
        cold = os.environ.get(support.COLD_REPORT)
        if cold:
            from tools.build_hia_json_preflight import admit_cold_build
            path = Path(cold)
            raw = path.read_bytes()
            cls.cold_inputs = (path, raw, admit_cold_build(Fixture.compiler_bytes, raw))
        from tools.qualify_hia_selfhost import compile_stage
        cls.images, cls.receipts, cls.sources = {}, {}, {}
        for name, path in SOURCES.items():
            source = path.read_bytes()
            if cls.cold_inputs is not None:
                assert cls.cold_inputs[2][path.relative_to(ROOT).as_posix()] == sha256(source).hexdigest()
            image, receipt = compile_stage(cls.folder, 'constructor-' + name, Fixture.compiler, source)
            produced = image.read_bytes()
            admit_compile_receipt(receipt, compiler_bytes=Fixture.compiler_bytes,
                source_bytes=source, image_bytes=produced)
            cls.images[name] = NativeHiaJsonImage(produced, sha256(produced).hexdigest())
            cls.receipts[name] = receipt
            cls.sources[name] = (path, source, image, produced)
        cls.observations = []

    @classmethod
    def tearDownClass(cls):
        fixture = cls.fixture
        assert fixture.compiler.read_bytes() == fixture.compiler_bytes
        assert SOURCE.read_bytes() == fixture.source_bytes
        assert fixture.image_path.read_bytes() == fixture.image
        for path, source, image, produced in cls.sources.values():
            assert path.read_bytes() == source and image.read_bytes() == produced
        if cls.cold_inputs is not None:
            from tools.build_hia_json_preflight import current_sources
            path, raw, source_map = cls.cold_inputs
            assert path.read_bytes() == raw and current_sources() == source_map
        report = {'schema': 'hepta.hia.nominal-json-constructor-ingress.v1',
                  'status': 'OBSERVATIONS_RECORDED_SEE_TEST_RUNNER_RESULT',
                  'scope': fixture.scope, 'observations': cls.observations,
                  'receipts': cls.receipts, 'codec_pins': fixture.pins,
                  'probe_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
                  'complete_constructor_initialization_tested': False,
                  'complete_normalizer_tested': False, 'host_payload_callbacks_removed': False}
        (cls.folder / 'ingress-observations.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        if fixture.temporary:
            fixture.temporary.cleanup()

    def consume(self, wire, *, render_request=False):
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
        with mmap.mmap(-1, WORKSPACE_BYTES, flags=flags) as workspace, mmap.mmap(-1, OUTPUT_BYTES, flags=flags) as output:
            wptr = ctypes.addressof(ctypes.c_char.from_buffer(workspace))
            optr = ctypes.addressof(ctypes.c_char.from_buffer(output))
            result = self.images['owner']._entry(source, len(wire), optr, OUTPUT_BYTES, wptr, WORKSPACE_BYTES)
            self.assertEqual(source.raw[:len(wire)], wire)
            frame = struct.unpack_from('<8Q', output) if result == 64 else None
            fatal = struct.unpack_from('<Q', workspace, 4096 + 96)[0]
            command = None
            if render_request:
                self.assertEqual(result, 64)
                self.assertEqual((frame[0], frame[1], frame[2], frame[3], frame[7]), (CTOR_MAGIC, 2, 0, 10, 1))
                _, index = detached_packet_index(wire)
                decoder = ObjectTokenDecoder(index)
                empty = ctypes.create_string_buffer(1)
                sequence = 0
                while not decoder.complete:
                    size = self.images['render']._entry(empty, 0, optr, OUTPUT_BYTES, wptr, WORKSPACE_BYTES)
                    self.assertTrue(64 <= size <= OUTPUT_BYTES)
                    streamed = struct.unpack_from('<8Q', output)
                    self.assertEqual(streamed[:3], (MAGIC, 1, sequence))
                    self.assertIn(streamed[3], (0, 1))
                    self.assertEqual(streamed[4:7], (0, 0, frame[6]))
                    self.assertEqual(streamed[7], size - 64)
                    decoder.feed(output[64:size], final=bool(streamed[3]))
                    sequence += 1
                command = decoder.root
            return result, frame, fatal, command

    def compare_ingress(self, raw, *, legacy=False, render_request=False):
        status, previous, count = support.reference(raw, wrapper=True, legacy=legacy)
        self.assertEqual(status, 0)
        converted = self.native.encode(raw, constructor_wrapper=True, legacy=legacy)
        self.assertEqual(converted.wire, previous)
        result = self.consume(converted.wire, render_request=render_request)
        self.assertEqual(result, self.consume(previous, render_request=render_request))
        self.observations.append({'input_sha256': sha256(raw).hexdigest(),
            'input_bytes': len(raw), 'packet_bytes': len(previous), 'source_nodes': count,
            'result': result[0], 'frame': result[1], 'fatal': result[2], 'first_command': result[3]})
        return result, converted

    def test_all_composite_profiles_and_legacy_reach_the_real_first_type_request(self):
        for profile in (1, 2, 3, 4):
            document = {'schema': 'hepta.hia.composite.v' + str(profile), 'module': 'm', 'types': [],
                'functions': [{'name': 'f', 'params': [], 'returns': [], 'effects': [],
                    'entry': 'b', 'blocks': [{'id': 'b', 'params': [], 'ops': [],
                                            'term': {'op': 'ret', 'values': []}}]}]}
            for legacy in ((False, True) if profile == 1 else (False,)):
                result, _ = self.compare_ingress(json.dumps(document).encode(),
                                                legacy=legacy, render_request=True)
                self.assertEqual(result[1], (CTOR_MAGIC, 2, 0, 10, 1, profile, 1, 1))
                self.assertEqual(result[3], [1, [], profile != 1, profile >= 3])

    def test_public_core64_and_raw128_are_distinct_depth_gates(self):
        from hepta.hia_program import _decode, HIAProgramRejected
        # Last empty array at depth 64 gives 65 raw containers, 66 with wrapper.
        cases = [(64, False, True, True), (65, True, True, True),
                 (65, False, False, True), (127, False, False, True),
                 (128, False, False, False), (129, True, False, False)]
        for containers, empty, public_ok, ingress_ok in cases:
            raw = b'[' * containers + (b'' if empty else b'0') + b']' * containers
            with self.subTest(containers=containers, empty=empty):
                with patch.dict(os.environ, {'HEPTA_HIA_JSON_PREFLIGHT_MANIFEST': '',
                        'HEPTA_HIA_JSON_DECODE_MANIFEST': '', 'HEPTA_HIA_JSON_CANONICAL_MANIFEST': ''}):
                    if public_ok:
                        _decode(raw)
                    else:
                        with self.assertRaises(HIAProgramRejected) as caught:
                            _decode(raw)
                        self.assertEqual(caught.exception.code, 'E_HIA_LIMIT')
                result, _ = self.compare_ingress(raw)
                if ingress_ok:
                    self.assertEqual(result[0], 64)
                    self.assertEqual((result[1][0], result[1][2], result[1][3]), (CTOR_MAGIC, 1, 2000))
                    self.assertEqual(result[2], 0)
                else:
                    self.assertEqual(result, (ABI, None, 1, None))

    def test_full_raw_node_budget_including_all_object_keys_and_wrapper(self):
        rows = [b'[' + b','.join([b'0'] * (MAX_NODES - 1)) + b']',
                b'{' + b','.join(('"k%06d":null' % i).encode() for i in range(MAX_NODES - 1)) + b'}']
        for raw in rows:
            result, packet = self.compare_ingress(raw)
            self.assertEqual(packet.source_nodes, MAX_NODES)
            _, index = detached_packet_index(packet.wire)
            expected = MAX_NODES + 2 if raw[:1] == b'[' else MAX_NODES * 2 + 1
            self.assertEqual(len(index), expected)
            self.assertLess(expected, 1048576)
            self.assertEqual(result[0], 64)
            self.assertEqual((result[1][2], result[1][3], result[2]), (1, 2000, 0))
            self.assertLess(len(packet.wire), 64 << 20)

    def test_full_raw_byte_budget_reaches_existing_semantic_shape_refusal(self):
        raw = b'"' + b'a' * (MAX_BYTES - 2) + b'"'
        result, packet = self.compare_ingress(raw)
        self.assertEqual(len(packet.wire), len(raw) + 55)
        self.assertEqual(result[0], 64)
        self.assertEqual((result[1][2], result[1][3], result[2]), (1, 2000, 0))


if __name__ == '__main__':
    unittest.main()
