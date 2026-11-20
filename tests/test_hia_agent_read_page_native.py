"""Original Agent artifact paging and its explicitly admitted HIA replacement."""
import argparse
from base64 import b64encode
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_read_page_native import CURSOR_REQUEST, REQUEST, SOURCE, installed_agent_read_page
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
    native_release = None
    executable = None

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

    def test_issued_cursor_matches_canonical_reference_and_exact_next_offset(self):
        ref = {'uri': 'hia://artifacts/' + 'a' * 192, 'sha256': 'b' * 64, 'id': 'c' * 192}
        data = b'a' * 2200 + b'\xff'
        for start, limit in ((0, 1), (66, 34), (902, 231), (2099, 194), (len(data), 10)):
            encoding, content, next_offset = HIAAgentService._reference_read_page(data, start, limit)
            cursor = None
            if next_offset is not None:
                canonical = json.dumps({'artifact': ref, 'offset': next_offset},
                                       sort_keys=True, separators=(',', ':')).encode()
                cursor = 'page-' + sha256(canonical).hexdigest()
            self.assertEqual(self.native.read_issued_page(data, start, limit, ref),
                             (encoding, content, next_offset, cursor))
        raw = CURSOR_REQUEST.pack(b'HIAARC01', 0, 1, 2) + b'{}' + b'abc'
        source = ctypes.create_string_buffer(raw)
        capacity = 108
        before = b'\xa7' * capacity
        output = ctypes.create_string_buffer(before, len(before))
        scratch = ctypes.create_string_buffer(4130)
        code = self.native._entry(source, len(raw), output, capacity, scratch, len(scratch))
        self.assertEqual((code, output.raw), (0xfffffffe, before))
        code = self.native._entry(source, len(raw), output, capacity, scratch, len(scratch) - 1)
        self.assertEqual((code, output.raw), (0xffffffff, before))

    def test_standalone_page_rejects_open_input_and_preserves_issued_cursor(self):
        if self.executable is None:
            self.skipTest('run with the matching standalone artifact pager')
        image = self.executable.read_bytes()
        self.assertTrue(self.native.matches_standalone(image))
        ref = {'uri': 'hia://artifacts/abc', 'sha256': 'b' * 64, 'id': 'a-12'}
        cases = ((b'', 0, 1), ('甲乙'.encode(), 0, 5), (b'a\xff', 0, 1),
                 (b'\0' * 70000, 0, 65536), (b'abc', 3, 1))
        expected = [self.native.read_issued_page(data, offset, limit, ref)
                    for data, offset, limit in cases]
        with (patch('hepta.hia_native_helpers.pinned_agent_read_page_executable', return_value=image),
              patch.object(self.native, '_entry', side_effect=AssertionError('mapped page invoked'))):
            actual = [self.native.read_issued_page(data, offset, limit, ref)
                      for data, offset, limit in cases]
        self.assertEqual(actual, expected)
        wire = REQUEST.pack(b'HIAARP01', 0, 3) + b'abc'
        unsealed = subprocess.run([self.executable], input=wire, capture_output=True,
                                  timeout=5, env={'PATH': ''})
        self.assertEqual((unsealed.returncode, unsealed.stdout, unsealed.stderr), (2, b'', b''))
        from hepta.hia_scalar_reference_native import sealed_reference_bytes

        with sealed_reference_bytes(b'badframe' + wire[8:]) as fd:
            invalid = subprocess.run([self.executable], stdin=fd, capture_output=True,
                                     timeout=5, env={'PATH': ''})
        self.assertEqual((invalid.returncode, invalid.stdout, invalid.stderr), (2, b'', b''))

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
                    with patch('hepta.hia_agent_service.digest',
                               side_effect=AssertionError('hosted cursor digest selected')):
                        self.assertEqual(service._hia_read(query), first['result'])
                    second = service.store.put(b'another artifact', 'input')
                    mismatched = service.call('hia_read', {**query, 'artifact': second, 'cursor': cursor})
                    self.assertEqual(mismatched['error']['code'], 'E_HIA_CURSOR')
                with patch.dict('os.environ', {SELECTOR: str(directory / 'missing.json')}):
                    self.assertEqual(service.call('hia_read', query)['status'], 'rejected')
            finally:
                service.close()

    def test_installed_store_reopens_native_cursor_without_sqlite(self):
        release = self.native_release
        if release is None:
            self.skipTest('provide the installed native Store to exercise persistent cursors')
        names = ('hia-agent-store', 'hia-artifact', 'hia-agent-artifact-capture')
        store = (release, *(sha256((release / name).read_bytes()).hexdigest() for name in names))
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            directory = Path(temporary)
            subprocess.run([release / 'hia-agent-store-init', directory, 'store'],
                           input=b'', capture_output=True, check=True, timeout=10, env={'PATH': ''})
            with (ExitStack() as invocation,
                  patch.dict('os.environ', {SELECTOR: str(self.manifest)}),
                  patch('sqlite3.connect', side_effect=AssertionError('hosted SQLite selected')),
                  patch('hepta.hia_agent_store.stable_read',
                        side_effect=AssertionError('hosted artifact bytes selected'))):
                if self.executable is not None:
                    invocation.enter_context(patch('hepta.hia_native_helpers.pinned_agent_read_page_executable',
                                                   return_value=self.executable.read_bytes()))
                    invocation.enter_context(patch.object(self.native, '_entry',
                                                          side_effect=AssertionError('mapped pager selected')))
                    invocation.enter_context(patch.object(self.native, 'read_issued_page',
                                                          side_effect=AssertionError('hosted artifact transfer')))
                service = HIAAgentService(directory, native_store=store)
                try:
                    first_page, second_page = b'a' * 512, b'b' * 512
                    ref = service.store.put(first_page + second_page + b'\xff', 'input')
                    args = {'artifact': ref, 'catalog_sha256': service.catalog_sha256, 'max_bytes': 512}
                    with ExitStack() as page:
                        if self.executable is not None:
                            page.enter_context(patch.object(
                                service.store, 'get', side_effect=AssertionError('hosted Store payload read')))
                        first = service.call('hia_read', args)
                        alias = service.call('hia_resource_read', {'uri': ref['uri'], 'max_bytes': 512})
                    self.assertEqual(first['status'], 'completed', first)
                    self.assertEqual(alias['result'], first['result'])
                    self.assertEqual(first['result']['content'], b64encode(first_page).decode())
                    cursor = first['result']['next_cursor']
                    self.assertIsNotNone(cursor)
                finally:
                    service.close()
                service = HIAAgentService(directory, native_store=store)
                try:
                    with ExitStack() as paging:
                        if self.executable is not None:
                            paging.enter_context(patch.object(
                                service.store, 'cursor_lookup', side_effect=AssertionError('host decoded cursor')))
                            paging.enter_context(patch.object(
                                HIAAgentService, '_read_window', side_effect=AssertionError('host chose page window')))
                        second = service.call('hia_read', {**args, 'cursor': cursor})
                        missing = service.call('hia_read', {**args, 'cursor': '你' * 512})
                        self.assertEqual(missing['error']['code'], 'E_HIA_CURSOR')
                        other = service.store.put(b'other bytes', 'input')
                        wrong = service.call('hia_read', {**args, 'artifact': other, 'cursor': cursor})
                        self.assertEqual(wrong['error']['code'], 'E_HIA_CURSOR')
                    self.assertEqual(second['status'], 'completed', second)
                    self.assertEqual(second['result']['content'], b64encode(second_page).decode())
                    end = service.call('hia_read', {**args, 'cursor': second['result']['next_cursor']})
                    self.assertEqual(end['status'], 'completed', end)
                    self.assertEqual((end['result']['content'], end['result']['next_cursor']), ('/w==', None))
                finally:
                    service.close()
            self.assertFalse(list(directory.glob('state.sqlite3*')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--test-root', type=Path, required=True)
    parser.add_argument('--native-release', type=Path)
    parser.add_argument('--executable', type=Path)
    args = parser.parse_args()
    AgentReadPageNativeTests.manifest = args.manifest.resolve()
    AgentReadPageNativeTests.test_root = args.test_root.resolve()
    AgentReadPageNativeTests.native_release = args.native_release.resolve() if args.native_release else None
    AgentReadPageNativeTests.executable = args.executable.resolve() if args.executable else None
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(tests)
                              for tests in (AgentReadPageSourceTests, AgentReadPageNativeTests))
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
