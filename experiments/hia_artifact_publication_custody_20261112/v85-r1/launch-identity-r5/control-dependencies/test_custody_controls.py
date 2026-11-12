"""Real temporary-file/process controls; never imports or executes Hepta native code."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parent / 'source'
sys.path.insert(0, str(SOURCE))
from tools import hia_artifact_publication_custody as custody
from tools import qualify_hia_artifact_publication_tests as runner


class CustodyControls(unittest.TestCase):
    def setUp(self):
        retained = os.environ.get('HIA_CUSTODY_CONTROL_RETAIN')
        if retained:
            self.root = Path(tempfile.mkdtemp(prefix=self._testMethodName + '-', dir=retained))
        else:
            self.temp = tempfile.TemporaryDirectory(prefix='publication-custody-controls-')
            self.addCleanup(self.temp.cleanup)
            self.root = Path(self.temp.name)

    def script(self, body):
        path = self.root / 'native-operation-shaped-synthetic-child'
        path.write_text('#!' + sys.executable + '\n' + body)
        path.chmod(0o700)
        return path

    def session(self):
        session = custody.Session(self.root / 'evidence')
        session.install()
        self.addCleanup(lambda: session.restore() if custody._ACTIVE is session else None)
        return session

    def finish(self, session):
        session.restore()
        return session.finish(unittest.TestResult())

    def closed_fixture(self):
        root = self.root / 'closed'
        root.mkdir(mode=0o700)
        (root / 'calls').mkdir(mode=0o700)
        (root / 'data').write_bytes(b'exact\0regular\xff')
        os.link(root / 'data', root / 'same-inode')
        (root / 'dangling').symlink_to('/unread/outside')
        os.mkfifo(root / 'fifo')
        # A real terminated process identity, not the live test process.
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(.05)'])
        pid = custody.process_identity(child.pid)
        child.wait(timeout=2)
        custody.write_json(root / 'RUN.json', {'runner': pid, 'calls': []})
        return root

    def external_fixture(self):
        """A real exited recorder owns its original-system-temp fixture."""
        root = self.root / 'external-records'
        program = '''import sys, pathlib, unittest, os
sys.path.insert(0, sys.argv[1])
from tools import hia_artifact_publication_custody as custody
session = custody.Session(pathlib.Path(sys.argv[2]))
session.install()
directory = custody.temporary_directory(prefix='publication-custody-original-fs-')
fixture = pathlib.Path(directory.name)
(fixture / 'full-bytes').write_bytes(b'external\\x00fixture\\xff')
os.link(fixture / 'full-bytes', fixture / 'hardlink')
os.mkfifo(fixture / 'fifo')
(fixture / 'symlink').symlink_to('/not-read-outside-fixture')
directory.cleanup()
session.restore()
session.finish(unittest.TestResult())
'''
        (self.root / 'external-fixture-child.py').write_text(program)
        result = subprocess.run([sys.executable, '-B', str(self.root / 'external-fixture-child.py'),
                                 str(SOURCE), str(root)], capture_output=True, timeout=5)
        (self.root / 'external-fixture.stdout').write_bytes(result.stdout)
        (self.root / 'external-fixture.stderr').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads((root / 'RUN.json').read_bytes())
        self.assertEqual(len(record['fixtures']), 1)
        fixture = Path(record['fixtures'][0]['path'])
        self.assertEqual(fixture.parent, Path(tempfile.gettempdir()))
        self.assertFalse(runner.live_identity(record['runner']))
        return root, fixture

    def test_default_temporary_directory_still_removes(self):
        with custody.temporary_directory(prefix='publication-original-default-') as name:
            path = Path(name); (path / 'raw').write_bytes(b'original')
        self.assertFalse(path.exists())

    def test_explicit_temporary_directory_retains_after_cleanup(self):
        session = self.session()
        directory = custody.temporary_directory(prefix='publication-retained-')
        path = Path(directory.name)
        self.assertEqual(path.parent, Path(tempfile.gettempdir()))
        with directory as name:
            self.assertEqual(Path(name), path)
            (path / 'raw').write_bytes(b'exact')
        directory.cleanup()
        self.assertEqual((path / 'raw').read_bytes(), b'exact')
        self.finish(session)

    def test_real_run_bytes_and_original_timeout_argument(self):
        program = self.script('import sys\ndata=sys.stdin.buffer.read()\nsys.stdout.buffer.write(data)\nsys.stderr.buffer.write(b"stderr\\x00")\n')
        session = self.session()
        payload = b'full offered bytes\x00\xff'
        result = subprocess.run([str(program), 'store-put', '/unused', '-'], input=payload,
                                capture_output=True, env={'PATH': ''}, timeout=2)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, payload, b'stderr\0'))
        body = self.finish(session)
        self.assertTrue(body['known_direct_children_reaped'])
        request = json.loads((session.calls[0].root / 'request.json').read_bytes())
        self.assertEqual(request['timeout'], 2)
        self.assertEqual(request['env'], {'PATH': ''})
        self.assertEqual((session.calls[0].root / 'stdin.offered.bin').read_bytes(), payload)
        output = next(row['stdout'] for row in session.calls[0].events if row['kind'] == 'COMMUNICATE_RETURN')
        self.assertEqual(Path(output['path']).read_bytes(), payload)
        self.assertEqual(Path(request['executable']['path']).read_bytes(), program.read_bytes())

    def test_real_timeout_keeps_original_kill_wait_and_partial_output(self):
        program = self.script('import sys,time\nsys.stdout.buffer.write(b"partial");sys.stdout.buffer.flush()\ntime.sleep(5)\n')
        session = self.session()
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            subprocess.run([str(program), 'store-put', '/unused', '-'], input=b'input',
                           capture_output=True, env={'PATH': ''}, timeout=.05)
        self.assertEqual(raised.exception.timeout, .05)
        body = self.finish(session)
        call = body['calls'][0]
        self.assertTrue(call['direct_child_reaped_observed'])
        self.assertIsNotNone(call['returncode'])
        self.assertIsNone(custody.process_identity(call['process']['pid']))
        events = session.calls[0].events
        self.assertEqual(sum(row['kind'] == 'ORIGINAL_CALLER_KILL_REQUEST' for row in events), 1)
        self.assertEqual(next(row['exception_type'] for row in events if row['kind'] == 'RUN_EXCEPTION'), 'TimeoutExpired')
        self.assertTrue(any(row['kind'] == 'COMMUNICATE_EXCEPTION' and row['output_may_be_partial'] for row in events))

    def test_direct_popen_manual_stdin_and_communicate_timeout_preserved(self):
        program = self.script('import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n')
        session = self.session()
        payload = b'manual stdin'
        process = custody.observed_popen([str(program), 'publish', '/unused/a', '/unused/b'],
                    offered_input=payload, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, env={'PATH': ''})
        process.stdin.write(payload); process.stdin.close(); process.stdin = None
        self.assertEqual(process.communicate(timeout=2), (payload, b''))
        self.finish(session)
        events = session.calls[0].events
        self.assertEqual(next(row['timeout'] for row in events if row['kind'] == 'COMMUNICATE_BEGIN'), 2)

    def test_sealed_memfd_original_bytes_survive_route_delegation(self):
        import fcntl
        source = ('#!' + sys.executable + '\nimport sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n').encode()
        fd = os.memfd_create('synthetic-custody-control', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        self.addCleanup(os.close, fd); os.write(fd, source)
        # This local Python build omits the names.  These exact Linux UAPI
        # definitions were read from /usr/include/linux/fcntl.h (40, 46-49)
        # and asm-generic/fcntl.h (192); this changes only this synthetic test.
        fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1024 + 9), 0x0001 | 0x0002 | 0x0004 | 0x0008)
        session = self.session(); delegated = subprocess.run
        def route(argv, **kwargs):
            self.assertEqual(argv[1], 'store-hash')
            return delegated(argv, **kwargs)
        with patch.object(subprocess, 'run', side_effect=route):
            result = subprocess.run(['/proc/self/fd/' + str(fd), 'store-hash', '/unused', '-'],
                     input=b'memfd', capture_output=True, pass_fds=(fd,), env={'PATH': ''}, timeout=2)
        self.assertEqual(result.stdout, b'memfd')
        self.finish(session)
        self.assertEqual((session.calls[0].root / 'executable.bin').read_bytes(), source)

    def test_reader_rejects_symlink_parent_leaf_and_fifo_without_blocking(self):
        plain = self.root / 'plain'; plain.mkdir(); (plain / 'file').write_bytes(b'raw')
        (self.root / 'alias').symlink_to(plain, target_is_directory=True)
        (plain / 'link').symlink_to(plain / 'file'); os.mkfifo(plain / 'fifo')
        for path in (self.root / 'alias' / 'file', plain / 'link', plain / 'fifo'):
            with self.subTest(path=str(path)), self.assertRaises((OSError, ValueError)):
                custody.read_file(path)

    def test_create_only_output_refuses_existing_and_parent_alias(self):
        path = self.root / 'raw'; custody.write_new(path, b'first')
        with self.assertRaises(FileExistsError):custody.write_new(path, b'second')
        self.assertEqual(path.read_bytes(), b'first')
        parent = self.root / 'directory'; parent.mkdir()
        (self.root / 'linkdir').symlink_to(parent, target_is_directory=True)
        with self.assertRaises(OSError):custody.write_new(self.root / 'linkdir' / 'new', b'never')
        self.assertFalse((parent / 'new').exists())

    def test_typed_archive_reads_every_regular_byte_and_never_opens_fifo(self):
        root = self.closed_fixture(); before = runner.typed_inventory(root)
        output = self.root / 'archive'
        self.assertEqual(runner.archive_evidence(root, output), 0)
        self.assertEqual(runner.typed_inventory(root), before)
        rows = json.loads((output / 'TYPED-MANIFEST.json').read_bytes())
        by_name = {row['path']: row for row in rows}
        self.assertEqual(by_name['records/fifo']['kind'], 'fifo')
        self.assertEqual(by_name['records/dangling']['link_target'], '/unread/outside')
        self.assertEqual(by_name['records/data']['identity']['ino'], by_name['records/same-inode']['identity']['ino'])
        with tarfile.open(output / 'publication-originals.tar.gz') as archive:
            self.assertEqual(archive.extractfile('regular/records/data').read(), b'exact\0regular\xff')
            self.assertEqual(archive.extractfile('regular/records/same-inode').read(), b'exact\0regular\xff')
            self.assertFalse(any(member.issym() or member.isfifo() or member.islnk() for member in archive))

    def test_registered_original_temp_fixture_archives_after_real_recorder_exit(self):
        root, fixture = self.external_fixture()
        output = self.root / 'archive'
        self.assertEqual(runner.archive_evidence(root, output), 0)
        rows = json.loads((output / 'TYPED-MANIFEST.json').read_bytes())
        by_name = {row['path']: row for row in rows}
        self.assertEqual(by_name['fixture-000/full-bytes']['original_path'], str(fixture / 'full-bytes'))
        self.assertEqual(by_name['fixture-000/fifo']['kind'], 'fifo')
        self.assertEqual(by_name['fixture-000/symlink']['link_target'], '/not-read-outside-fixture')
        self.assertEqual(by_name['fixture-000/full-bytes']['identity']['ino'],
                         by_name['fixture-000/hardlink']['identity']['ino'])
        with tarfile.open(output / 'publication-originals.tar.gz') as archive:
            self.assertEqual(archive.extractfile('regular/fixture-000/full-bytes').read(),
                             b'external\x00fixture\xff')
            self.assertEqual(archive.extractfile('regular/fixture-000/hardlink').read(),
                             b'external\x00fixture\xff')
            self.assertFalse(any(member.issym() or member.isfifo() or member.islnk() for member in archive))

    def test_registered_original_temp_root_replacement_is_rejected(self):
        root, fixture = self.external_fixture()
        original = fixture.with_name(fixture.name + '-original-preserved')
        fixture.rename(original)
        fixture.mkdir(mode=0o700)
        (fixture / 'substitute').write_bytes(b'must not read replacement')
        (self.root / 'replaced-root-locations.json').write_text(json.dumps({
            'recorded': str(fixture), 'original_preserved': str(original)}, indent=2) + '\n')
        output = self.root / 'archive'
        self.assertEqual(runner.archive_evidence(root, output), 1)
        report = json.loads((output / 'ARCHIVE.json').read_bytes())
        self.assertEqual(report['status'], 'HOLD')
        self.assertEqual(report['failure']['message'], 'retained original temporary root changed')
        self.assertFalse((output / 'publication-originals.tar.gz').exists())

    def test_live_runner_only_fixed_metadata_is_retained(self):
        root = self.closed_fixture()
        record = {'runner': custody.process_identity(os.getpid()), 'calls': []}
        (root / 'RUN.json').write_text(json.dumps(record))
        output = self.root / 'archive'
        with patch.object(runner, 'typed_inventory', side_effect=AssertionError('must not traverse live fixtures')):
            self.assertEqual(runner.archive_evidence(root, output), 1)
        self.assertFalse((output / 'publication-originals.tar.gz').exists())
        self.assertEqual(json.loads((output / 'RUN.json').read_bytes()), record)

    def test_regular_change_during_archive_is_hold_and_partial_archive_is_kept(self):
        root = self.closed_fixture(); output = self.root / 'archive'
        original = runner.HashingReader.read; mutated = []
        def changing(reader, size=-1):
            raw = original(reader, size)
            if not mutated:
                (root / 'data').write_bytes(b'changed size')
                mutated.append(True)
            return raw
        with patch.object(runner.HashingReader, 'read', changing):
            self.assertEqual(runner.archive_evidence(root, output), 1)
        self.assertTrue((output / 'publication-originals.tar.gz').exists())
        self.assertEqual(json.loads((output / 'ARCHIVE.json').read_bytes())['status'], 'HOLD')

    def test_declared_source_mismatch_is_not_accepted(self):
        root = self.root / 'source'; (root / 'docs').mkdir(parents=True); (root / 'x.py').write_bytes(b'x=1\n')
        contract = {'profile': 'synthetic-control', 'source_identity': {'files': {'x.py': sha256(b'x=1\n').hexdigest()}}}
        (root / 'docs/HIA_SELFHOST_CORE_SUPPORT.json').write_text(json.dumps(contract))
        with patch.object(runner, 'ROOT', root):
            self.assertEqual(runner.source_snapshot()['files']['x.py']['bytes'], 4)
            (root / 'x.py').write_bytes(b'x=2\n')
            with self.assertRaisesRegex(ValueError, 'declared source bytes differ'):runner.source_snapshot()


if __name__ == '__main__':
    unittest.main(verbosity=2)
