"""Original Agent artifact paging and its explicitly admitted HIA replacement."""
import argparse
import ctypes
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_read_page_native import REQUEST, SOURCE, installed_agent_read_page
from hepta.hia_agent_service import HIAAgentService


SELECTOR = 'HEPTA_HIA_AGENT_READ_PAGE_MANIFEST'


class AgentReadPageSourceTests(unittest.TestCase):
    def test_source_matches_authoring(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_agent_read_page import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))


class AgentReadPageNativeTests(unittest.TestCase):
    manifest = None
    test_root = None

    def setUp(self):
        if self.manifest is None:
            self.skipTest('run with the current cold-built artifact page image')
        self.native = installed_agent_read_page(str(self.manifest))

    def test_utf8_and_binary_compare_to_original_page_logic(self):
        rng = random.Random(76291)
        text = ''.join(chr(point) for point in
                       (0, 7, 8, 9, 10, 11, 12, 13, 31, 32, 34, 92, 127,
                        128, 2047, 2048, 0xD7FF, 0xE000, 0x2028, 0xFFFF, 0x10000, 0x10FFFF))
        cases = [b'', b'a', (text * 13000).encode(), b'\0' * 70000, b'"' * 70000,
                 b'\\' * 70000, b'\n' * 70000, ('𐀀' * 20000).encode(),
                 b'\xc0\x80', b'\xe0\x9f\xbf', b'\xed\xa0\x80',
                 b'\xf0\x8f\xbf\xbf', b'\xf4\x90\x80\x80',
                 b'\xf5\x80\x80\x80', b'\xe2\x80',
                 b'valid-first-page' * 5000 + b'\xff', rng.randbytes(70001)]
        for artifact in cases:
            for offset in (0, 1, 3, 511, len(artifact), len(artifact) + 1):
                for limit in (1, 3, 512, 4097, 65536):
                    with self.subTest(size=len(artifact), offset=offset, limit=limit):
                        reference = HIAAgentService._reference_read_page(artifact, offset, limit)
                        self.assertEqual(self.native.read_page(artifact, offset, limit), reference)
        self.assertEqual(self.native.read_page(b'\0' * 70000, 0, 65536),
                         ('utf8', '\0' * 16384, 16384))
        self.assertEqual(self.native.read_page(b'xy\xff', 0, 2), ('base64', 'eHk=', 2))

    def test_malformed_and_small_output_leave_bytes_untouched(self):
        good = REQUEST.pack(b'HIAARP01', 0, 512) + b'a page'
        cases = ((good[:20], 64, 0xffffffff),
                 (b'HIABAD01' + good[8:], 64, 0xffffffff),
                 (REQUEST.pack(b'HIAARP01', 0, 65537), 64, 0xffffffff),
                 (good, 45, 0xfffffffe))
        for wire, capacity, expected in cases:
            source = ctypes.create_string_buffer(wire, len(wire))
            before = b'\xa7' * capacity
            output = ctypes.create_string_buffer(before, len(before))
            code = self.native._entry(source, len(wire), output, capacity, None, 0)
            self.assertEqual((code, output.raw, source.raw), (expected, before, wire))

    def test_tool_resource_alias_and_restart_reuse_exact_cursor(self):
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            directory = Path(temporary) / 'state'
            service = HIAAgentService(directory)
            try:
                artifact = service.store.put(b'\0' * 65534 + '你'.encode() + b'tail', 'input')
                query = {'artifact': artifact, 'catalog_sha256': service.catalog_sha256}
                with patch.dict('os.environ', {SELECTOR: ''}):
                    first = service.call('hia_read', query)
                    self.assertEqual(first['status'], 'completed')
                    cursor = first['result']['next_cursor']
                    self.assertTrue(cursor.startswith('page-'))
                    later = service.call('hia_read', {**query, 'cursor': cursor, 'max_bytes': 512})
                    alias = service.call('hia_resource_read', {'uri': artifact['uri']})
            finally:
                service.close()
            service = HIAAgentService(directory)
            try:
                with (patch.dict('os.environ', {SELECTOR: str(self.manifest)}),
                      patch.object(HIAAgentService, '_reference_read_page',
                                   side_effect=AssertionError('reference paging selected'))):
                    self.assertEqual(service.call('hia_read', query), first)
                    self.assertEqual(service.call('hia_read', {**query, 'cursor': cursor,
                                                               'max_bytes': 512}), later)
                    self.assertEqual(service.call('hia_resource_read', {'uri': artifact['uri']}), alias)
                with patch.dict('os.environ', {SELECTOR: str(directory / 'missing.json')}):
                    self.assertEqual(service.call('hia_read', query)['status'], 'rejected')
            finally:
                service.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--test-root', type=Path, required=True)
    args = parser.parse_args()
    AgentReadPageNativeTests.manifest = args.manifest.resolve()
    AgentReadPageNativeTests.test_root = args.test_root.resolve()
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(tests)
                              for tests in (AgentReadPageSourceTests, AgentReadPageNativeTests))
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
