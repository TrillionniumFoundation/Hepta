"""Exercise installed native capture against ordinary Linux files and roots."""
import argparse
from hashlib import sha256
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_artifact_capture_native import SELECTOR
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentRejected, capture_path


class CaptureRuntimeTests(unittest.TestCase):
    executable = None
    test_root = None

    def setUp(self):
        if self.executable is None:
            self.skipTest('run with the installed native Agent artifact capture executable')
        folder = tempfile.TemporaryDirectory(prefix='hia-capture-', dir=self.test_root)
        self.addCleanup(folder.cleanup)
        self.base = Path(folder.name)
        self.authorized = self.base / 'approved'
        self.authorized.mkdir()

    def invoke(self, root, path, limit):
        return subprocess.run([self.executable, root, path, str(limit)],
                              stdin=subprocess.DEVNULL, capture_output=True,
                              env={'PATH': ''}, timeout=3, check=False)

    def positive(self, path, expected, limit, root=None):
        root = self.authorized if root is None else root
        self.assertEqual(capture_path(os.fsdecode(path), [Path(root)], limit), expected)
        result = self.invoke(root, path, limit)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))

    def negative(self, path, status, code, message, root=None):
        root = self.authorized if root is None else root
        with self.assertRaises(AgentRejected) as raised:
            capture_path(os.fspath(path), [Path(root)] if root else [], 1024)
        self.assertEqual((raised.exception.code, str(raised.exception)), (code, message))
        result = self.invoke(root, path, 1024)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (status, b'', b''))

    def test_static_native_elf_has_no_interpreter_or_dynamic_segment(self):
        data = self.executable.read_bytes()
        self.assertEqual(data[:7], b'\x7fELF\x02\x01\x01')
        self.assertEqual(struct.unpack_from('<HH', data, 16), (2, 62))
        table = struct.unpack_from('<Q', data, 32)[0]
        width, count = struct.unpack_from('<HH', data, 54)
        kinds = {struct.unpack_from('<I', data, table + offset * width)[0]
                 for offset in range(count)}
        self.assertIn(1, kinds)
        self.assertTrue(kinds.isdisjoint({2, 3}))

    def test_ordinary_paths_and_exact_capture(self):
        nested = self.authorized / '目录'
        nested.mkdir()
        entry = nested / '数据.hepta'
        entry.write_bytes(b'\x00\xffHIA\r\n')
        self.positive(str(nested) + '//./数据.hepta///', entry.read_bytes(), 7)
        raw = os.fsdecode(os.fsencode(nested) + b'/\xff.hepta')
        Path(raw).write_bytes(b'')
        self.positive(raw, b'', 1)
        alternate_root = '/' + str(self.authorized)
        self.positive('/' + str(entry), entry.read_bytes(), 7, alternate_root)

    def test_maximum_extent_and_oversized_file(self):
        entry = self.authorized / 'maximum'
        payload = bytes(range(256)) * (1 << 15)
        entry.write_bytes(payload)
        self.positive(entry, payload, len(payload))
        with entry.open('ab') as stream:
            stream.write(b'x')
        result = self.invoke(self.authorized, entry, len(payload))
        self.assertEqual((result.returncode, result.stdout, result.stderr), (67, b'', b''))

    def test_relative_traversal_and_outside_roots(self):
        self.negative('root/file', 65, 'E_HIA_PATH', 'artifact paths must be absolute')
        self.negative(str(self.authorized) + '/child/../file', 69, 'E_HIA_PATH',
                      'artifact traversal is not permitted')
        for path in (self.authorized, self.base / 'approved-neighbor' / 'file'):
            self.negative(path, 66, 'E_HIA_PATH_AUTHORITY',
                          'artifact path is outside configured roots')
        self.negative(self.authorized / 'file', 66, 'E_HIA_PATH_AUTHORITY',
                      'artifact path is outside configured roots', '')

    def test_no_symlink_traversal_and_no_read_from_special_files(self):
        external = self.base / 'external'
        external.mkdir()
        (external / 'secret').write_bytes(b'MUST NOT BE READ')
        (self.authorized / 'link').symlink_to(external, target_is_directory=True)
        (self.authorized / 'leaf').symlink_to(external / 'secret')
        os.mkfifo(self.authorized / 'fifo')
        self.negative(self.authorized / 'link' / 'secret', 70, 'E_HIA_PATH',
                      'artifact path contains an unavailable or unsafe component')
        for name in ('leaf', 'missing'):
            self.negative(self.authorized / name, 71, 'E_HIA_ARTIFACT_FILE',
                          'cannot read authorized ordinary artifact')
        self.negative(self.authorized / 'fifo', 67, 'E_HIA_ARTIFACT_FILE',
                      'artifact is not a bounded ordinary file')
        alias = self.base / 'root-link'
        alias.symlink_to(external, target_is_directory=True)
        result = self.invoke(str(alias) + '/', alias / 'secret', 1024)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (70, b'', b''))


class PublicCaptureTests(unittest.TestCase):
    manifest = None
    test_root = None

    def test_hia_artifact_requires_native_capture_and_persists_exact_bytes(self):
        if self.manifest is None:
            self.skipTest('run with a current cold-built capture manifest')
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            base = Path(temporary)
            approved = base / 'approved'
            approved.mkdir()
            unrelated = base / 'other-approved'
            unrelated.mkdir()
            entry = approved / '数据.hepta'
            payload = b'\x00HIA\xff\r\n'
            entry.write_bytes(payload)
            service = HIAAgentService(base / 'state', artifact_roots=(unrelated, approved))
            self.addCleanup(service.close)
            arguments = {
                'catalog_sha256': service.catalog_sha256,
                'artifact_profile': service.profiles['artifact'],
                'source': {'kind': 'path', 'path': str(entry), 'max_bytes': len(payload),
                           'expected_sha256': sha256(payload).hexdigest()},
            }
            with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
                  patch('hepta.hia_agent_store._reference_capture_path',
                        side_effect=AssertionError('native capture fell back to Python'))):
                completed = service.call('hia_artifact', {**arguments, 'request_key': 'capture-1'})
                self.assertEqual(completed['status'], 'completed', completed)
                self.assertEqual(completed['result']['byte_length'], str(len(payload)))
                self.assertEqual(service.store.get(completed['result']['artifact']), (payload, {}))
                for name, updates, code in (
                    ('digest', {'expected_sha256': '0' * 64}, 'E_HIA_ARTIFACT_CHANGED'),
                    ('limit', {'max_bytes': 1}, 'E_HIA_ARTIFACT_FILE'),
                    ('outside', {'path': str(base / 'not-authorized')}, 'E_HIA_PATH_AUTHORITY'),
                    ('nul', {'path': str(entry) + '\x00'}, 'E_HIA_PATH'),
                ):
                    response = service.call('hia_artifact', {
                        **arguments, 'request_key': name, 'source': {**arguments['source'], **updates},
                    })
                    self.assertEqual(response.get('error', {}).get('code'), code, response)
                with patch.dict(os.environ, {SELECTOR: str(base / 'missing.json')}):
                    refused = service.call('hia_artifact', {**arguments, 'request_key': 'missing-pin'})
                    self.assertEqual(refused.get('error', {}).get('code'),
                                     'E_HIA_ARTIFACT_NATIVE_CUSTODY', refused)
                self.assertEqual(service.call('hia_artifact', {**arguments, 'request_key': 'capture-1'}),
                                 completed)
            rows = service.store.db.execute("SELECT sha256 FROM artifacts WHERE kind='input'").fetchall()
            self.assertEqual([row['sha256'] for row in rows], [sha256(payload).hexdigest()])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--test-root', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    CaptureRuntimeTests.executable = args.executable.resolve(strict=True)
    CaptureRuntimeTests.test_root = args.test_root
    PublicCaptureTests.manifest = args.manifest.resolve(strict=True)
    PublicCaptureTests.test_root = args.test_root
    unittest.main(argv=[sys.argv[0], '-v'])
