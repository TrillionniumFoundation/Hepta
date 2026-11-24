"""Directory capabilities preserve native package admission and caller offsets."""
from __future__ import annotations
from hashlib import sha256
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from tests.test_hia_release_install import DIRECTORY_POLICY, fields, observe, reference_unpack
from tools.generate_hia_release_install import MAGIC
ROOT = Path(__file__).resolve().parents[1]

class DirectoryCapabilitySourceTests(unittest.TestCase):
    def test_descriptor_is_parsed_by_hia_without_path_dereference(self):
        for raw, value in ((b'fd:3', 3), (b'fd:2147483647', 2147483647)):
            rc, data = observe(raw, fields(p0=0), policy=DIRECTORY_POLICY,
                               workspace_offsets=range(3104, 3112))
            self.assertEqual((rc, struct.unpack('<Q', data)[0]), (0, value))

    def test_descriptor_syntax_is_closed_before_transport(self):
        for raw in (b'fd:', b'fd:0', b'fd:2', b'fd:03', b'fd:+3', b'fd:3/',
                    b'fd:3\x00', b'fd:2147483648', b'fd:999999999999'):
            with self.subTest(raw=raw):
                self.assertEqual(observe(raw, fields(p0=0), policy=DIRECTORY_POLICY)[0], 16)

class DirectoryCapabilityKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-directory-capability-')
        cls.folder = Path(cls.temporary.name)
        seed, _ = build_seed(cls.folder)
        selfhost = (ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first, _ = compile_stage(cls.folder, 'B1', seed, selfhost, image_format='seed-shared')
        second, _ = compile_stage(cls.folder, 'B2', first, selfhost)
        if first.read_bytes() != second.read_bytes():
            raise AssertionError('self-hosted compiler did not close')
        images = {}
        for name in ('release_directory_policy', 'release_directory_packer', 'sha256_stream'):
            images[name], _ = compile_stage(
                cls.folder, name, second,
                (ROOT/'examples/hia_bootstrap'/f'{name}.hepta').read_bytes())
        policy = images['release_directory_policy'].read_bytes()
        digest = images['sha256_stream'].read_bytes()
        result, packed = invoke(cls.folder, 'pack', images['release_directory_packer'],
                                struct.pack('<3Q', MAGIC, len(policy), len(digest))+policy+digest)
        if result['status'] != 'returned' or not 0 < result['core_u32'] <= len(packed):
            raise AssertionError(result)
        cls.app = cls.folder/'hia-directory-package-build'
        cls.app.write_bytes(packed[:result['core_u32']])
        cls.app.chmod(0o500)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix='case-', dir=self.folder))
        self.stage = self.case/'stage'
        self.stage.mkdir(mode=0o700)
        self.expected = {'one.txt': (0o400, b'first native member\n'),
                         'two.bin': (0o500, bytes(range(256))*17)}
        for name, (mode, data) in self.expected.items():
            member = self.stage/name
            member.write_bytes(data)
            member.chmod(mode)
        self.fd = os.open(self.stage, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)

    def tearDown(self):
        os.close(self.fd)

    def run_native(self, argument, fds=None):
        return subprocess.run([str(self.app), argument], capture_output=True, timeout=30,
                              env={'PATH': ''}, pass_fds=(self.fd,) if fds is None else fds)

    def test_capability_and_absolute_path_have_identical_content(self):
        normal = self.run_native(str(self.stage))
        self.assertEqual(normal.returncode, 0, normal.stderr)
        self.assertEqual(reference_unpack(normal.stdout),
                         {name.encode(): value for name, value in self.expected.items()})
        self.assertEqual(normal.stderr, sha256(normal.stdout).hexdigest().encode()+b'\n')
        original_offset = os.lseek(self.fd, 0, os.SEEK_CUR)
        for _ in range(2):
            actual = self.run_native(f'fd:{self.fd}')
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr),
                             (0, normal.stdout, normal.stderr))
            self.assertEqual(os.lseek(self.fd, 0, os.SEEK_CUR), original_offset)

    def test_kernel_capabilities_retain_original_refusals(self):
        for text in ('fd:', 'fd:0', 'fd:2', f'fd:0{self.fd}', f'fd:+{self.fd}',
                     f'fd:{self.fd}/x', 'fd:2147483648', 'fd:999999999999',
                     'fd:2147483647'):
            with self.subTest(text=text):
                result = self.run_native(text)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
        regular = os.open(self.stage/'one.txt', os.O_RDONLY)
        try:
            result = self.run_native(f'fd:{regular}', (regular,))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
        finally:
            os.close(regular)
        for kind in ('symlink', 'hardlink'):
            member = self.stage/'alias'
            if kind == 'symlink':
                os.symlink(self.stage/'one.txt', member)
            else:
                os.link(self.stage/'one.txt', member)
            try:
                result = self.run_native(f'fd:{self.fd}')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
            finally:
                member.unlink()

if __name__ == '__main__':
    unittest.main()
