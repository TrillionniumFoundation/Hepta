"""Directory-capability admission and real installer/attester filesystem effects."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
from tempfile import TemporaryDirectory
import unittest

from tests.test_hia_release_install import bundle, fields, observe, reference_unpack
from tools.build_hia_native_store_release import _source_inventory_packet


class ReleaseRootCapabilityPolicyTests(unittest.TestCase):
    def arguments(self, root, *, workspace=None):
        args = (b'install', root, b'01' * 32)
        wire = struct.pack('<3Q', *map(len, args)) + b''.join(args)
        return observe(wire, fields() if workspace is None else workspace,
                       offsets=(0,), workspace_offsets=range(160, 176))

    def test_canonical_descriptor_bounds_are_decided_by_hia(self):
        for number in (3, 9, 10, 999, 2147483647):
            with self.subTest(number=number):
                result, actual = self.arguments(f'fd:{number}'.encode())
                self.assertEqual(result, 1)
                self.assertEqual(actual[0], 0)
                self.assertEqual(struct.unpack('<2Q', actual[1:]), (1, number))

    def test_bad_descriptor_grammar_is_rejected_before_syscalls(self):
        for root in (b'fd:', b'fd:0', b'fd:1', b'fd:2', b'fd:03', b'fd:+3',
                     b'fd:-3', b'fd: 3', b'fd:3 ', b'fd:3/child', b'fd:3\0',
                     b'fd:2147483648', b'fd:99999999999', b'FD:3', b'fd:3x'):
            with self.subTest(root=root):
                self.assertEqual(self.arguments(root)[0], 16)

    def test_ordinary_path_clears_capability_fields(self):
        result, actual = self.arguments(b'/var/tmp/releases',
                                       workspace=fields(p160=1, p168=99))
        self.assertEqual(result, 1)
        self.assertEqual(actual, bytes(17))


@unittest.skipUnless(os.environ.get('HIA_TEST_RELEASE_INSTALL_FD'),
                     'requires an actual source-compiled hia-release ELF')
class ReleaseRootCapabilityKernelTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory(prefix='hia-release-fd-')
        self.base = Path(self.temporary.name)
        self.app = Path(os.environ['HIA_TEST_RELEASE_INSTALL_FD']).resolve()
        self.wire = bundle([('app', 0o500, b'\x00native\xff\n' * 17),
                            ('source.hepta', 0o400, b'')])
        self.digest = sha256(self.wire).hexdigest()
        self.members = {name.decode(): sha256(raw).hexdigest()
                        for name, (_, raw) in reference_unpack(self.wire).items()}
        self.attestation = _source_inventory_packet(self.wire, self.members)

    def tearDown(self):
        # These are exclusively test-owned sealed directories. The product
        # itself never chmods a published release back to a mutable mode.
        for path, directories, _ in os.walk(self.base, topdown=True, followlinks=False):
            os.chmod(path, os.stat(path).st_mode | 0o700)
            for name in directories:
                child = Path(path) / name
                if not child.is_symlink():
                    child.chmod(child.stat().st_mode | 0o700)
        self.temporary.cleanup()

    def depot(self, name):
        path = self.base / name
        path.mkdir(mode=0o700)
        return path

    def run_app(self, operation, root, *, descriptors=(), wire=None, code=0):
        if wire is None:
            wire = self.attestation if operation == 'attest' else self.wire
        p = subprocess.run([str(self.app), operation, str(root), self.digest],
                           input=wire, capture_output=True, pass_fds=descriptors,
                           env={'PATH': ''}, timeout=30)
        self.assertEqual(p.returncode, code, (operation, root, p.stdout, p.stderr))
        self.assertEqual(p.stderr, b'')
        if code:
            self.assertEqual(p.stdout, b'')
        return p.stdout

    def installed(self, depot):
        release = depot / self.digest
        self.assertEqual(sorted(p.name for p in depot.iterdir()), [self.digest])
        self.assertEqual(stat.S_IMODE(release.stat().st_mode), 0o500)
        return {path.name: (stat.S_IMODE(path.stat().st_mode), path.read_bytes())
                for path in release.iterdir()}

    def test_install_verify_attest_match_path_with_readonly_and_path_capabilities(self):
        absolute = self.depot('absolute')
        expected = {operation: self.run_app(operation, absolute)
                    for operation in ('install', 'verify', 'attest')}
        self.assertTrue(json.loads(expected['attest'])['source_attested'])
        reference = self.installed(absolute)
        for kind, flags in (('readonly', os.O_RDONLY), ('path', os.O_PATH)):
            with self.subTest(kind=kind):
                depot = self.depot(kind)
                fd = os.open(depot, flags | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    before = os.fstat(fd)
                    if kind == 'readonly':
                        os.lseek(fd, 0, os.SEEK_SET)
                    for operation in ('install', 'verify', 'attest'):
                        actual = self.run_app(operation, f'fd:{fd}', descriptors=(fd,))
                        self.assertEqual(actual, expected[operation])
                        after = os.fstat(fd)
                        self.assertEqual((after.st_dev, after.st_ino),
                                         (before.st_dev, before.st_ino))
                    if kind == 'readonly':
                        self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 0)
                    self.assertEqual(self.installed(depot), reference)
                finally:
                    os.close(fd)

    def test_held_capability_survives_path_rename_and_does_not_follow_replacement(self):
        original = self.depot('original')
        replacement = self.depot('replacement')
        held = self.base / 'held'
        fd = os.open(original, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            original.rename(held)
            original.symlink_to(replacement, target_is_directory=True)
            self.run_app('install', f'fd:{fd}', descriptors=(fd,))
            self.run_app('attest', f'fd:{fd}', descriptors=(fd,))
            self.assertTrue(self.installed(held))
            self.assertEqual(list(replacement.iterdir()), [])
            self.run_app('verify', original, code=10)
        finally:
            os.close(fd)

    def test_closed_regular_and_symlink_descriptors_publish_nothing(self):
        depot = self.depot('depot')
        closed = os.open(depot, os.O_RDONLY | os.O_DIRECTORY)
        os.close(closed)
        self.run_app('install', f'fd:{closed}', code=10)
        regular = self.base / 'regular'
        regular.write_bytes(b'unchanged')
        symlink = self.base / 'symlink'
        symlink.symlink_to(depot, target_is_directory=True)
        for path, flags in ((regular, os.O_RDONLY), (symlink, os.O_PATH | os.O_NOFOLLOW)):
            fd = os.open(path, flags | os.O_CLOEXEC)
            try:
                for operation in ('install', 'verify', 'attest'):
                    with self.subTest(path=path.name, operation=operation):
                        self.run_app(operation, f'fd:{fd}', descriptors=(fd,), code=10)
                        os.fstat(fd)
            finally:
                os.close(fd)
        self.assertEqual(list(depot.iterdir()), [])
        self.assertEqual(regular.read_bytes(), b'unchanged')

    def test_bad_argv_descriptor_forms_publish_nothing(self):
        depot = self.depot('depot')
        fd = os.open(depot, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for argument in ('fd:', 'fd:0', 'fd:1', 'fd:2', f'fd:0{fd}',
                             f'fd:+{fd}', f'fd:-{fd}', f'fd:{fd}/child',
                             'fd:2147483648', 'fd:99999999999', 'FD:3'):
                with self.subTest(argument=argument):
                    self.run_app('install', argument, descriptors=(fd,), code=16)
            self.assertEqual(list(depot.iterdir()), [])
        finally:
            os.close(fd)

    def test_original_directory_permission_gate_applies_to_capabilities(self):
        depot = self.depot('unsafe')
        depot.chmod(0o770)
        fd = os.open(depot, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.run_app('install', depot, code=10)
            self.run_app('install', f'fd:{fd}', descriptors=(fd,), code=10)
            self.assertEqual(list(depot.iterdir()), [])
        finally:
            os.close(fd)

    def test_attestation_content_and_inventory_gates_remain_exact(self):
        depot = self.depot('attest')
        fd = os.open(depot, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.run_app('install', f'fd:{fd}', descriptors=(fd,))
            changed = dict(self.members, app='0' * 64)
            bad = _source_inventory_packet(self.wire, changed)
            for root, descriptors in ((depot, ()), (f'fd:{fd}', (fd,))):
                self.run_app('attest', root, descriptors=descriptors, wire=bad, code=11)
                self.run_app('attest', root, descriptors=descriptors,
                             wire=self.attestation[:-1], code=16)
            app = depot / self.digest / 'app'
            app.chmod(0o700)
            app.write_bytes(bytes(len(app.read_bytes())))
            app.chmod(0o500)
            for root, descriptors in ((depot, ()), (f'fd:{fd}', (fd,))):
                self.run_app('verify', root, descriptors=descriptors, code=11)
                self.run_app('attest', root, descriptors=descriptors, code=11)
        finally:
            os.close(fd)

    @unittest.skipUnless(os.environ.get('HIA_TEST_RELEASE_SELECTION_FD'),
                         'requires the regenerated native selection ELF')
    def test_shared_selection_root_code_matches_path_and_descriptor(self):
        select = str(Path(os.environ['HIA_TEST_RELEASE_SELECTION_FD']).resolve())
        depot = self.depot('selection')
        fd = os.open(depot, os.O_RDONLY | os.O_DIRECTORY)
        try:
            results = [subprocess.run([select, 'status', str(root)],
                       capture_output=True, pass_fds=descriptors,
                       env={'PATH': ''}, timeout=30)
                       for root, descriptors in ((depot, ()), (f'fd:{fd}', (fd,)))]
            for result in results:
                self.assertEqual((result.returncode, result.stderr), (0, b''))
            self.assertEqual(results[0].stdout, results[1].stdout)
            os.fstat(fd)
        finally:
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
