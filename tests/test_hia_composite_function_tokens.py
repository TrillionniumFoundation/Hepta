"""Reconstructed generic codec and actual complete-kernel stream controls.

No historical renderer-fixture image or test result is fabricated here. The
native checks use the restored five-image owner and an ordinary source function.
"""
from copy import deepcopy
import ctypes
import json
import os
import struct
import unittest
from unittest.mock import patch

from hepta.hia_composite_function_tokens import ObjectTokenDecoder, TokenProtocolError, detached_packet_index
from hepta.hia_instruction_policy_native import transport


class TokenCodecTests(unittest.TestCase):
    def test_exact_detached_tree_and_source_node_identity(self):
        source = {'a': [None, True, False, -5, 2**63, '汉字'], 'b': {'x': [1, 2]}}
        expected = deepcopy(source)
        detached, index = detached_packet_index(transport(source))
        source['a'].clear(); source['b']['x'][0] = 99
        decoder = ObjectTokenDecoder(index)
        self.assertEqual(decoder.feed(struct.pack('<2Q', 0, 0), final=True), expected)
        self.assertEqual(detached, expected)
        self.assertIsNot(detached, source)
        self.assertIsNot(detached['b']['x'], source['b']['x'])

    def test_chunked_containers_and_repeated_strings(self):
        text = 'h2internal_8192'.encode()
        word = struct.pack('<2Q', 1, len(text)) + text
        decoder = ObjectTokenDecoder({})
        self.assertIsNone(decoder.feed(struct.pack('<2Q', 5, 4) + word))
        result = decoder.feed(word + struct.pack('<4Q', 3, 1, 4, 0), final=True)
        self.assertEqual(result, ['h2internal_8192', 'h2internal_8192', True, None])
        self.assertIs(result[0], result[1])
        with self.assertRaises(TokenProtocolError):
            decoder.feed(b'', final=True)

    def test_malformed_packet_or_first_token_error_fails_closed(self):
        for wire in (b'', b'x', struct.pack('<2Q', 0, 1),
                     struct.pack('<3Q', 5, 8, 1), struct.pack('<2Q', 7, 0)):
            with self.subTest(wire=wire), self.assertRaises(TokenProtocolError):
                detached_packet_index(wire)
        for wire in (b'x', struct.pack('<2Q', 7, 0), struct.pack('<2Q', 3, 2),
                     struct.pack('<2Q', 5, 1), struct.pack('<2Q', 0, 1)):
            with self.subTest(wire=wire):
                decoder = ObjectTokenDecoder({})
                with self.assertRaises(TokenProtocolError):
                    decoder.feed(wire, final=True)
                with self.assertRaises(TokenProtocolError):
                    decoder.feed(struct.pack('<2Q', 4, 0), final=True)


@unittest.skipUnless(all(os.environ.get(name) for name in (
    'HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST',
    'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST',
    'HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST')), 'explicit exact native bundle/dependencies required')
class NativeStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.hia_composite_functions_native import SELECTOR
        from hepta.hia_composite_types_native import SELECTOR as TYPE_SELECTOR
        from hepta.hia_task_helpers_native import SELECTOR as HELPER_SELECTOR
        cls.environment = {
            SELECTOR: os.environ['HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST'],
            TYPE_SELECTOR: os.environ['HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST'],
            HELPER_SELECTOR: os.environ['HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST']}
        cls.reference_environment = dict.fromkeys(cls.environment, '')

    def test_actual_complete_function_stream_exceeds_public_output_limits(self):
        from hepta import hia_program_composite as composite
        from tests.test_hia_program import b, f, ret
        from tests.test_hia_program_composite import record
        from tests.test_hia_composite_returned_loans import v4
        definitions = [record('A', [('p' + str(n), 'u8') for n in range(64)]),
                       record('R', [('part' + str(n), 'A') for n in range(8)])]
        params = [('input', 'R')]
        document = v4(definitions,
            f('large', params, ['R'] * 1000, [], [b('entry', params, [], ret(*(['input'] * 1000))) ]))
        with patch.dict(os.environ, self.reference_environment):
            reference = composite._Elaborator(deepcopy(document))
            expected = reference.function(reference.document['functions'][0])
        with patch.dict(os.environ, self.environment):
            owner = composite._Elaborator(document)
        session = owner._native_function_session
        image = session.images['render']
        entry = image._entry
        chunks = []

        def observed(source, size, output, capacity, workspace, workspace_size):
            extent = entry(source, size, output, capacity, workspace, workspace_size)
            if extent >= 64 and extent <= capacity:
                frame = struct.unpack('<8Q', ctypes.string_at(output, 64))
                if frame[1] == 0:
                    chunks.append((extent, frame))
            return extent

        image._entry = observed
        try:
            actual = owner.function(document['functions'][0])
            self.assertEqual(actual, expected)
            self.assertGreater(len(json.dumps(actual, separators=(',', ':')).encode()), 8 << 20)
            self.assertEqual(len(actual['returns']), 512000)
            values = actual['blocks'][0]['term']['values']
            self.assertEqual(len(values), 512000)
            self.assertIs(values[0], values[512])
            self.assertGreater(len(chunks), 1)
            self.assertEqual([frame[2] for _, frame in chunks], list(range(len(chunks))))
            self.assertTrue(all(64 <= extent <= 65536 for extent, _ in chunks))
            self.assertEqual(chunks[-1][1][3], 1)
        finally:
            image._entry = entry
            session.close(); owner.types.close()

    def test_actual_render_rejects_short_output_or_workspace(self):
        from hepta.hia_composite_functions_native import installed_composite_functions, WORKSPACE_BYTES
        manifest = os.environ['HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST']
        image = installed_composite_functions(manifest).images['render']
        source = ctypes.create_string_buffer(1)
        output = ctypes.create_string_buffer(65536)
        workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        self.assertEqual(image._entry(source, 0, output, 65536, workspace, 1), 0xfffffff1)
        self.assertEqual(image._entry(source, 0, output, 1, workspace, WORKSPACE_BYTES), 0xfffffff1)
        self.assertEqual(struct.unpack_from('<Q', workspace, 4096 + 96)[0], 1)


if __name__ == '__main__':
    unittest.main()
