"""Refuse incomplete guest evidence and preserve real process failures."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from tools import qualify_hia_linux_baseline as baseline


RUN_ID = 'abcd1234abcd1234abcd1234'


def serial(*, missing=None, failed=None, duplicate=None, run_id=RUN_ID):
    events = [{'event': 'begin', 'pid': 1, 'run_id': run_id}]
    for key in baseline.CHECK_IDS:
        if key == missing:
            continue
        event = {'event': 'check', 'run_id': run_id, 'id': key, 'passed': key != failed, 'errno': 0}
        events.append(event)
        if key == duplicate:
            events.append(event.copy())
    events += [{'event': 'complete', 'run_id': run_id, 'total': len(baseline.CHECK_IDS),
                'passed': len(baseline.CHECK_IDS)-(failed is not None), 'failed': int(failed is not None)},
               {'event': 'shutdown', 'run_id': run_id, 'operation': 'poweroff'}]
    return '\n'.join(baseline.PREFIX + json.dumps(e) for e in events) + '\n[0.4] reboot: Power down\n'


class GuestEvidence(unittest.TestCase):
    def test_complete_inventory_requires_clean_exit_and_actual_powerdown(self):
        text = serial()
        self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, 0, False)['status'], 'PASS')
        for code, timed_out in [(1, False), (-15, False), (0, True)]:
            self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, code, timed_out)['status'], 'FAIL')
        self.assertEqual(baseline.parse_guest_serial(text.replace('reboot: Power down', ''), RUN_ID, 0, False)['status'], 'FAIL')

    def test_missing_check_keeps_not_run(self):
        verdict = baseline.parse_guest_serial(serial(missing='mmap_pages'), RUN_ID, 0, False)
        self.assertEqual(verdict['status'], 'FAIL')
        self.assertEqual(verdict['guest_tests']['not_run'], 1)
        self.assertEqual(verdict['guest_tests']['skipped'], 0)

    def test_one_actual_failed_check_is_retained(self):
        verdict = baseline.parse_guest_serial(serial(failed='file_lifecycle'), RUN_ID, 0, False)
        self.assertEqual(verdict['guest_tests']['failed'], 1)
        self.assertEqual(verdict['guest_tests']['passed'], 13)
        self.assertEqual(verdict['status'], 'FAIL')

    def test_duplicate_check_and_stale_nonce_rejected(self):
        for text in (serial(duplicate='pipe_roundtrip'), serial(run_id='0' * 24)):
            self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, 0, False)['status'], 'FAIL')

    def test_malformed_or_nonboolean_protocol_is_not_ignored(self):
        for text in (serial() + baseline.PREFIX + '{bad}\n',
                     serial().replace('"passed": true', '"passed": 1', 1)):
            self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, 0, False)['status'], 'FAIL')

    def test_empty_serial_and_completed_without_shutdown_rejected(self):
        for text in ('', '\n'.join(x for x in serial().splitlines() if 'shutdown' not in x)):
            self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, 0, False)['status'], 'FAIL')

    def test_boolean_complete_count_is_not_an_integer_receipt(self):
        text = serial().replace('"failed": 0', '"failed": false')
        self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, 0, False)['status'], 'FAIL')


class InputsAndProcesses(unittest.TestCase):
    def test_module_directory_is_explicit_and_never_inherited_from_ambient_environment(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {'QEMU_MODULE_DIR': '/ambient/untrusted'}):
            root = Path(directory)
            env = baseline.build_environment(root/'llvm/bin', root/'sysroot')
            self.assertEqual(env['QEMU_MODULE_DIR'], str(root/'sysroot/usr/lib/x86_64-linux-gnu/qemu'))
            self.assertNotIn('QEMU_MODULE_DIR', baseline.build_environment(root/'llvm/bin'))
            with self.assertRaisesRegex(ValueError, 'runtime module is missing'):
                baseline.qemu_runtime_modules(env)
            modules = Path(env['QEMU_MODULE_DIR']); modules.mkdir(parents=True)
            target = modules/'accel-tcg-x86_64.so'; target.write_bytes(b'first module bytes')
            before = baseline.qemu_runtime_modules(env)
            target.write_bytes(b'different module bytes')
            self.assertNotEqual(baseline.qemu_runtime_modules(env), before)

    def test_preflight_keeps_cpu_paused_and_has_no_kernel_or_network(self):
        command = baseline.qemu_machine_command('qemu', 'data', 'bios', paused=True)
        self.assertIn('-S', command)
        self.assertEqual(command[command.index('-monitor')+1], 'stdio')
        self.assertEqual(command[command.index('-serial')+1], 'none')
        self.assertEqual(command[command.index('-nic')+1], 'none')
        self.assertNotIn('-kernel', command)
        self.assertNotIn('-initrd', command)

    def test_bounded_real_process_input_is_preserved_and_not_interactive(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = baseline.CommandRunner(directory, {'PATH': os.environ['PATH']})
            record = runner.run('quit-input', [sys.executable, '-c',
                'import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.exit(0 if data==b"quit\\n" else 7)'],
                stdin_bytes=b'quit\n')
            self.assertEqual(Path(record['stdin']['path']).read_bytes(), b'quit\n')
            self.assertEqual(record['stdin']['sha256'], hashlib.sha256(b'quit\n').hexdigest())
            self.assertEqual(Path(record['stdout']['path']).read_bytes(), b'quit\n')
            with self.assertRaisesRegex(ValueError, 'bounded bytes'):
                runner.run('too-large', [sys.executable], stdin_bytes=b'x'*4097)

    def test_newc_preserves_executable_bytes_and_console_device(self):
        body = b'ELF fixture bytes\x00\xff'
        archive = baseline.newc([('init', stat.S_IFREG | 0o755, body, 0, 0),
                                 ('dev/console', stat.S_IFCHR | 0o600, b'', 5, 1)])
        offset, members = 0, {}
        while True:
            self.assertEqual(archive[offset:offset+6], b'070701')
            fields = [int(archive[offset+6+8*i:offset+14+8*i], 16) for i in range(13)]
            name = archive[offset+110:offset+110+fields[11]-1].decode()
            offset = (offset+110+fields[11]+3)//4*4
            data = archive[offset:offset+fields[6]]
            offset = (offset+fields[6]+3)//4*4
            if name == 'TRAILER!!!':
                break
            members[name] = (fields, data)
        self.assertEqual(members['init'][1], body)
        self.assertEqual(members['init'][0][1], stat.S_IFREG | 0o755)
        self.assertEqual(members['dev/console'][0][9:11], [5, 1])
        with self.assertRaises(ValueError):
            baseline.newc([('../escape', stat.S_IFREG, b'', 0, 0)])

    def test_initramfs_is_reproducible_and_not_host_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'init').write_bytes(b'not executed')
            baseline.create_initramfs(root/'init', root/'one.gz')
            baseline.create_initramfs(root/'init', root/'two.gz')
            self.assertEqual((root/'one.gz').read_bytes(), (root/'two.gz').read_bytes())
            self.assertIn(b'not executed', gzip.decompress((root/'one.gz').read_bytes()))

    def test_pristine_archive_checks_changed_added_and_symlink_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'source'; source.mkdir()
            (source/'unit.c').write_bytes(b'int unit;\n')
            (source/'link').symlink_to('unit.c')
            archive = root/'source.tar.xz'
            with tarfile.open(archive, 'w:xz') as stream:
                stream.add(source, arcname='linux-test', recursive=True)
            expected = baseline.sha(archive)
            self.assertEqual(len(baseline.verify_kernel_source(source, archive, expected)), 2)
            (source/'unit.c').write_bytes(b'int changed;\n')
            with self.assertRaisesRegex(ValueError, 'differs'):
                baseline.verify_kernel_source(source, archive, expected)
            (source/'unit.c').write_bytes(b'int unit;\n')
            (source/'extra').write_bytes(b'extra')
            with self.assertRaisesRegex(ValueError, 'differs'):
                baseline.verify_kernel_source(source, archive, expected)

    def test_config_parser_rejects_duplicate_and_retains_disabled_symbols(self):
        parsed = baseline.parse_config('CONFIG_SMP=y\n# CONFIG_UNSAFE is not set\n')
        self.assertEqual(parsed['CONFIG_UNSAFE'], 'n')
        with self.assertRaises(ValueError):
            baseline.parse_config('CONFIG_SMP=y\nCONFIG_SMP=n\n')

    def test_qemu_is_tcg_bounded_and_has_no_external_network(self):
        command = baseline.qemu_command('qemu', 'data', 'bios', 'bzImage', 'initrd', RUN_ID, '6.18.60')
        self.assertEqual(command[command.index('-accel')+1], 'tcg,thread=multi')
        self.assertEqual(command[command.index('-cpu')+1], 'qemu64,-popcnt')
        self.assertEqual(command[command.index('-nic')+1], 'none')
        self.assertIn('hia_run_id=' + RUN_ID, command[-1])
        with self.assertRaises(ValueError):
            baseline.qemu_command('qemu', 'data', 'bios', 'kernel', 'initrd', 'unsafe value', '6.18.60')

    def test_real_process_failure_and_timeout_keep_original_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = baseline.CommandRunner(directory, {'PATH': os.environ['PATH']})
            record = runner.run('exit-seven', [sys.executable, '-c',
                'import sys; print("retained-out"); print("retained-err",file=sys.stderr);sys.exit(7)'], check=False)
            self.assertEqual(record['exit_code'], 7)
            self.assertEqual(Path(record['stdout']['path']).read_text(), 'retained-out\n')
            self.assertEqual(Path(record['stderr']['path']).read_text(), 'retained-err\n')
            timed = runner.run('real-timeout', [sys.executable, '-c', 'import time;time.sleep(5)'], timeout=0.05, check=False)
            self.assertTrue(timed['timed_out'])
            self.assertNotEqual(timed['exit_code'], 0)
            self.assertEqual(len(list((Path(directory)/'commands').glob('*.started.json'))), 2)

    def test_missing_executable_has_a_failed_command_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = baseline.CommandRunner(directory, {'PATH': os.environ['PATH']})
            record = runner.run('missing', ['/this-executable-does-not-exist'], check=False)
            self.assertEqual(record['exit_code'], 127)
            self.assertIn('spawn_error', record)
            self.assertTrue(list((Path(directory)/'commands').glob('*-missing.json')))


if __name__ == '__main__':
    unittest.main()
