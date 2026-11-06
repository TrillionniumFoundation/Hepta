#!/usr/bin/env python3
"""Build a frozen stock Linux configuration and boot its finite PID1 smoke in TCG.

This command does not install a host kernel, load a host module, change a sysctl,
or run the guest administration program on the host. All build outputs live in a
new O= directory. A stock PASS is not HIA translation or whole-Linux qualification.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time


ROOT = Path(__file__).resolve().parents[1]
KERNEL_VERSION = '6.18.60'
UPSTREAM_COMMIT = 'f45ed76d6791cf72ff1265ee93511175bbbc2f18'
ARCHIVE_SHA256 = '3c2f44ef6acc021a7ad444d9a2e6ec1ef488ff09368793d0004a6080f69d621e'
CHECK_IDS = (
    'pid1', 'mount_proc', 'mount_sysfs', 'mount_devtmpfs', 'mount_tmpfs',
    'kernel_identity', 'cpu_count', 'fork_exec_wait', 'pipe_roundtrip',
    'mmap_pages', 'mprotect_fault', 'file_lifecycle', 'unix_socketpair', 'loopback_tcp',
)
PREFIX = 'HIA_LINUX_SMOKE '
BOOT_OVERLAY = {key: 'y' for key in (
    'CONFIG_BLK_DEV_INITRD', 'CONFIG_RD_GZIP', 'CONFIG_PRINTK', 'CONFIG_PRINTK_TIME',
    'CONFIG_TTY', 'CONFIG_SERIAL_8250', 'CONFIG_SERIAL_8250_CONSOLE', 'CONFIG_SMP',
    'CONFIG_BINFMT_ELF', 'CONFIG_PROC_FS', 'CONFIG_SYSFS', 'CONFIG_DEVTMPFS',
    'CONFIG_TMPFS', 'CONFIG_SHMEM', 'CONFIG_NET', 'CONFIG_INET', 'CONFIG_UNIX',
)}
BOOT_OVERLAY['CONFIG_INITRAMFS_SOURCE'] = '""'
LLVM_TOOLS = ('clang', 'ld.lld', 'llvm-ar', 'llvm-nm', 'llvm-objcopy',
              'llvm-objdump', 'llvm-readelf', 'llvm-strip')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(path):
    path = Path(path)
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def write_gzip_json(path, value):
    data = canonical(value)
    with Path(path).open('xb') as stream:
        stream.write(gzip.compress(data, mtime=0))
    return {**identity(path), 'uncompressed_sha256': hashlib.sha256(data).hexdigest()}


def source_identity(expected_head):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()
    actual = git('rev-parse', 'HEAD')
    require(actual == expected_head, 'execution wrapper HEAD differs from --expected-head')
    require(not git('status', '--porcelain', '--untracked-files=all'), 'execution wrapper source is dirty')
    return {'commit': actual, 'tree': git('rev-parse', 'HEAD^{tree}'), 'clean': True,
            'wrapper': identity(__file__),
            'guest_source': identity(ROOT / 'experiments/hia_linux_kernel_20261106/guest_init.c')}


def inventory_tree(root):
    root = Path(root)
    entries = []
    for current, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                entries.append({'path': relative, 'type': 'symlink', 'target': target,
                                'bytes': len(os.fsencode(target)),
                                'sha256': hashlib.sha256(b'symlink\0' + os.fsencode(target)).hexdigest()})
            elif stat.S_ISREG(info.st_mode):
                entries.append({'path': relative, 'type': 'file', 'bytes': info.st_size, 'sha256': sha(path)})
            else:
                require(stat.S_ISDIR(info.st_mode), 'nonregular source member: ' + relative)
    entries.sort(key=lambda item: item['path'])
    return entries


def verify_kernel_source(source, archive, expected_sha=ARCHIVE_SHA256):
    require(sha(archive) == expected_sha, 'official source archive SHA-256 mismatch')
    expected = {}
    root_name = None
    with tarfile.open(archive, 'r:xz') as stream:
        for member in stream:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and name.parts, 'unsafe archive path')
            root_name = root_name or name.parts[0]
            require(name.parts[0] == root_name, 'archive has multiple roots')
            if member.isdir():
                continue
            relative = PurePosixPath(*name.parts[1:]).as_posix()
            require(relative != '.' and relative not in expected, 'duplicate/empty archive file')
            if member.isfile():
                body = stream.extractfile(member)
                require(body is not None, 'unreadable archive member')
                expected[relative] = {'path': relative, 'type': 'file', 'bytes': member.size,
                                      'sha256': hashlib.file_digest(body, 'sha256').hexdigest()}
            elif member.issym():
                target = member.linkname
                expected[relative] = {'path': relative, 'type': 'symlink', 'target': target,
                                      'bytes': len(os.fsencode(target)),
                                      'sha256': hashlib.sha256(b'symlink\0' + os.fsencode(target)).hexdigest()}
            else:
                raise ValueError('unsupported archive member type: ' + member.name)
    actual = inventory_tree(source)
    require(actual == sorted(expected.values(), key=lambda item: item['path']),
            'kernel directory differs from the exact official archive')
    return actual


def build_environment(llvm_bin, sysroot=None):
    llvm_bin = Path(llvm_bin).resolve()
    # Preserve no ambient compiler flags, Kbuild variables, credentials or preload.
    env = {'PATH': str(llvm_bin) + ':/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
           'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1',
           'KBUILD_BUILD_USER': 'hia-research', 'KBUILD_BUILD_HOST': 'isolated-tcg',
           'KBUILD_BUILD_VERSION': '1', 'KBUILD_BUILD_TIMESTAMP': '1970-01-01 00:00:00 UTC',
           'SOURCE_DATE_EPOCH': '0'}
    libraries = [llvm_bin.parent.parent / 'x86_64-linux-gnu', llvm_bin.parent / 'lib']
    if sysroot:
        sysroot = Path(sysroot).resolve()
        env['PATH'] = str(sysroot / 'usr/bin') + ':' + env['PATH']
        libraries += [sysroot / 'usr/lib/x86_64-linux-gnu', sysroot / 'lib/x86_64-linux-gnu']
        env['BISON_PKGDATADIR'] = str(sysroot / 'usr/share/bison')
        env['M4'] = str(sysroot / 'usr/bin/m4')
        env['PKG_CONFIG_SYSROOT_DIR'] = str(sysroot)
        env['PKG_CONFIG_LIBDIR'] = ':'.join(map(str, [
            sysroot / 'usr/lib/x86_64-linux-gnu/pkgconfig',
            Path('/usr/lib/x86_64-linux-gnu/pkgconfig'), Path('/usr/share/pkgconfig')]))
    env['LD_LIBRARY_PATH'] = ':'.join(str(path) for path in libraries if path.is_dir())
    return env


class CommandRunner:
    def __init__(self, output, env):
        self.output, self.env, self.records = Path(output), env, []
        (self.output / 'commands').mkdir()

    def run(self, name, argv, *, cwd=None, timeout=120, check=True):
        require(re.fullmatch(r'[a-zA-Z0-9_-]+', name), 'invalid command label')
        number = len(self.records)
        stem = self.output / 'commands' / f'{number:03d}-{name}'
        record = {'name': name, 'argv': list(map(str, argv)), 'cwd': str(cwd or ROOT),
                  'started_at_utc': utc(), 'timeout_seconds': timeout, 'timed_out': False}
        write_json(str(stem) + '.started.json', record)
        print(json.dumps({'stage': name, 'status': 'RUNNING', 'started_at_utc': record['started_at_utc']}), flush=True)
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        start = time.monotonic_ns()
        with open(str(stem) + '.stdout', 'xb') as stdout, open(str(stem) + '.stderr', 'xb') as stderr:
            try:
                process = subprocess.Popen(record['argv'], cwd=cwd or ROOT, env=self.env,
                                           stdout=stdout, stderr=stderr, start_new_session=True)
            except OSError as error:
                code = 127
                record['spawn_error'] = str(error)
            else:
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    record['timed_out'] = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        code = process.wait()
                except BaseException:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
                    raise
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        record.update(exit_code=code, elapsed_ns=time.monotonic_ns() - start, completed_at_utc=utc(),
                      child_user_seconds=after.ru_utime-before.ru_utime,
                      child_system_seconds=after.ru_stime-before.ru_stime,
                      stdout=identity(str(stem) + '.stdout'), stderr=identity(str(stem) + '.stderr'))
        write_json(str(stem) + '.json', record)
        self.records.append(record)
        print(json.dumps({'stage': name, 'status': 'PASS' if code == 0 and not record['timed_out'] else 'FAIL',
                          'exit_code': code, 'elapsed_ns': record['elapsed_ns']}), flush=True)
        require(not check or (code == 0 and not record['timed_out']),
                'command failed: ' + name + '; inspect ' + str(stem) + '.json')
        return record


def parse_config(text):
    values = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
            require(key not in values, 'duplicate config symbol: ' + key)
            values[key] = value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            key = line[2:-11]
            require(key not in values, 'duplicate config symbol: ' + key)
            values[key] = 'n'
    return values


def newc(entries):
    output = bytearray()
    for index, (name, mode, body, major, minor) in enumerate(entries + [('TRAILER!!!', 0, b'', 0, 0)], 1):
        require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
                'unsafe initramfs member')
        encoded = name.encode() + b'\0'
        fields = [index, mode, 0, 0, 1, 0, len(body), 0, 0, major, minor, len(encoded), 0]
        output += b'070701' + ''.join(f'{value:08x}' for value in fields).encode() + encoded
        output += b'\0' * (-len(output) % 4)
        output += body
        output += b'\0' * (-len(output) % 4)
    return bytes(output)


def create_initramfs(init, path):
    entries = [(name, stat.S_IFDIR | 0o755, b'', 0, 0) for name in ('dev', 'proc', 'sys', 'tmp')]
    entries += [('dev/console', stat.S_IFCHR | 0o600, b'', 5, 1),
                ('dev/null', stat.S_IFCHR | 0o666, b'', 1, 3),
                ('init', stat.S_IFREG | 0o755, Path(init).read_bytes(), 0, 0)]
    with Path(path).open('xb') as stream:
        stream.write(gzip.compress(newc(entries), mtime=0))


def parse_guest_serial(text, run_id, exit_code, timed_out):
    rows = {key: {'id': key, 'status': 'NOT_RUN'} for key in CHECK_IDS}
    events, errors = [], []
    state = 'not_started'
    for line in text.splitlines():
        if not line.startswith(PREFIX):
            continue
        try:
            event = json.loads(line[len(PREFIX):])
            require(isinstance(event, dict) and event.get('run_id') == run_id, 'guest run identity mismatch')
            kind = event.get('event')
            if kind == 'begin':
                require(state == 'not_started' and event.get('pid') == 1, 'duplicate/invalid begin')
                state = 'checking'
            elif kind == 'check':
                key = event.get('id')
                require(state == 'checking' and key in rows and rows[key]['status'] == 'NOT_RUN', 'unexpected/duplicate check')
                require(type(event.get('passed')) is bool, 'nonboolean guest verdict')
                rows[key] = {**event, 'status': 'PASS' if event['passed'] else 'FAIL'}
            elif kind == 'complete':
                require(state == 'checking' and all(row['status'] != 'NOT_RUN' for row in rows.values()), 'incomplete check inventory')
                passed = sum(row['status'] == 'PASS' for row in rows.values())
                require(all(type(event.get(key)) is int for key in ('total', 'passed', 'failed'))
                        and event['total'] == len(CHECK_IDS)
                        and event.get('passed') == passed and event.get('failed') == len(CHECK_IDS)-passed,
                        'guest totals mismatch')
                state = 'complete'
            elif kind == 'shutdown':
                require(state == 'complete' and event.get('operation') == 'poweroff', 'invalid shutdown ordering')
                state = 'shutdown'
            else:
                raise ValueError('unexpected guest event: ' + str(kind))
            events.append(event)
        except (ValueError, TypeError) as error:
            errors.append(str(error))
    totals = {'total': len(CHECK_IDS), 'passed': sum(r['status'] == 'PASS' for r in rows.values()),
              'failed': sum(r['status'] == 'FAIL' for r in rows.values()), 'skipped': 0,
              'not_run': sum(r['status'] == 'NOT_RUN' for r in rows.values())}
    powered_down = 'reboot: Power down' in text
    passed = (not errors and state == 'shutdown' and exit_code == 0 and not timed_out
              and powered_down and totals['passed'] == len(CHECK_IDS))
    return {'status': 'PASS' if passed else 'FAIL', 'expected_check_ids': list(CHECK_IDS),
            'checks': list(rows.values()), 'guest_tests': totals, 'events': events,
            'protocol_errors': errors, 'terminal_state': state,
            'kernel_power_down_observed': powered_down, 'qemu_exit_code': exit_code,
            'timed_out': timed_out, 'scope': 'finite_pid1_os_smoke_not_linux_selftests'}


def collect_build_inventory(source, build, output, database):
    classified = []
    for index, entry in enumerate(database):
        args = entry.get('arguments') or shlex.split(entry['command'])
        file = Path(entry['file'])
        if not file.is_absolute():
            file = Path(entry['directory']) / file
        file = file.resolve()
        target_c = file.suffix == '.c' and '-D__KERNEL__' in args
        role = 'kernel_target_c' if target_c else 'host_or_unknown_compile_command'
        classified.append({'index': index, 'role': role, 'file': str(file),
                           'source_kind': 'original' if file.is_relative_to(source) else 'generated_or_external',
                           'source': identity(file) if file.is_file() else None})
    objects = [{**identity(p), 'relative_path': p.relative_to(build).as_posix(),
                'role': 'object_or_aggregate_role_not_inferred_from_suffix'}
               for p in sorted(build.rglob('*.o')) if p.is_file()]
    commands = sorted(path for path in build.rglob('*.cmd') if path.is_file())
    command_records = [{'path': path.relative_to(build).as_posix(), 'bytes': path.stat().st_size,
                        'sha256': sha(path)} for path in commands]
    archive = output / 'kbuild-commands.tar.gz'
    with archive.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as tar:
            for path in commands:
                data = path.read_bytes()
                member = tarfile.TarInfo(path.relative_to(build).as_posix())
                member.size, member.mode, member.mtime = len(data), 0o644, 0
                tar.addfile(member, io.BytesIO(data))
    record = {'schema': 'hepta.hia.linux.kbuild-inventory.v1',
              'compile_commands': classified, 'objects': objects, 'kbuild_commands': command_records,
              'kbuild_command_archive': identity(archive),
              'active_kernel_target_c_compile_commands': sum(x['role'] == 'kernel_target_c' for x in classified),
              'host_or_unknown_compile_commands': sum(x['role'] != 'kernel_target_c' for x in classified),
              'all_objects_have_hashes': True,
              'c_database_is_not_a_complete_assembly_rust_generated_or_linked_object_denominator': True,
              'runtime_coverage_not_inferred_from_build_or_symbols': True}
    return write_gzip_json(output / 'build-inventory.json.gz', record), record


def qemu_command(qemu, data, bios, kernel, initramfs, run_id, release):
    require(re.fullmatch(r'[a-f0-9]{24}', run_id) is not None, 'invalid run id')
    require(re.fullmatch(r'[a-zA-Z0-9._+-]+', release) is not None, 'invalid kernel release')
    cmdline = ('console=ttyS0,115200 rdinit=/init panic=-1 nokaslr '
               f'hia_run_id={run_id} hia_kernel_release={release}')
    return [str(qemu), '-machine', 'pc-i440fx-8.2', '-accel', 'tcg,thread=multi',
            '-cpu', 'qemu64,-popcnt', '-smp', '2', '-m', '1024', '-nodefaults',
            '-no-user-config', '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
            '-nic', 'none', '-no-reboot', '-L', str(data), '-bios', str(bios),
            '-kernel', str(kernel), '-initrd', str(initramfs), '-append', cmdline]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-source', type=Path, required=True)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--tool-sysroot', type=Path)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--qemu-data', type=Path, required=True)
    parser.add_argument('--bios', type=Path, required=True)
    parser.add_argument('--dependency-receipt', type=Path)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--build-timeout', type=int, default=7200)
    parser.add_argument('--boot-timeout', type=int, default=180)
    args = parser.parse_args(argv)
    require(re.fullmatch(r'[a-f0-9]{40}', args.expected_head) is not None, 'exact 40-hex source HEAD required')
    require(1 <= args.jobs <= 64 and args.build_timeout > 0 and args.boot_timeout > 0, 'invalid finite budget')
    source, output, llvm = args.kernel_source.resolve(), args.output.resolve(), args.llvm_bin.resolve()
    for protected in (ROOT, source, llvm, args.source_archive.resolve().parent):
        require(not output.is_relative_to(protected) and not protected.is_relative_to(output), 'output overlaps immutable inputs')
    output.mkdir(parents=True, exist_ok=False)
    start = time.monotonic_ns()
    result = {'schema': 'hepta.hia.linux.stock-baseline.v1', 'started_at_utc': utc(),
              'status': 'FAIL', 'build_status': 'NOT_RUN', 'boot_status': 'NOT_RUN',
              'image_kind': 'stock_linux', 'kernel_version': KERNEL_VERSION,
              'source_archive_sha256': ARCHIVE_SHA256, 'upstream_commit': UPSTREAM_COMMIT,
              'source_commit': args.expected_head, 'scope': 'stock_x86_64_qemu_boot_smoke',
              'active_compile_units': None, 'fallback_c_units': None, 'hia_compiled_units': 0,
              'ndu_calls': 0, 'whole_kernel_rewrite': False, 'ndu_gain_established': False,
              'guest_tests': {'total': len(CHECK_IDS), 'passed': 0, 'failed': 0, 'skipped': 0, 'not_run': len(CHECK_IDS)},
              'guest_check_ids': list(CHECK_IDS),
              'production_activation': False, 'global_linux_qualification': False,
              'dependency_preparation_cost_is_separate_from_this_run': True,
              'unmeasured': ['disk persistence', 'reboot persistence', 'external network/devices',
                             'SMP race correctness', 'full KUnit/kselftest/LTP', 'production performance']}
    runner, before, code_before = None, None, None
    try:
        code_before = source_identity(args.expected_head)
        result['source_before'] = code_before
        result['source_archive'] = identity(args.source_archive)
        print(json.dumps({'stage': 'verify-official-source', 'status': 'RUNNING'}), flush=True)
        before = verify_kernel_source(source, args.source_archive)
        result['linux_source_inventory'] = write_gzip_json(output / 'source-before.json.gz', before)
        result['linux_source_denominators'] = {
            'entries': len(before), 'regular_files': sum(x['type'] == 'file' for x in before),
            'symlinks': sum(x['type'] == 'symlink' for x in before),
            'c_sources': sum(x['path'].endswith('.c') for x in before),
            'headers': sum(x['path'].endswith('.h') for x in before),
            'assembly_sources': sum(x['path'].endswith(('.S', '.s')) for x in before),
            'rust_sources': sum(x['path'].endswith('.rs') for x in before)}
        env = build_environment(llvm, args.tool_sysroot)
        write_json(output / 'build-environment.json', env)
        runner = CommandRunner(output, env)
        tools = {}
        for name in LLVM_TOOLS:
            path = llvm / name
            require(path.is_file() and os.access(path, os.X_OK), 'missing LLVM tool: ' + name)
            rec = runner.run('version-' + name.replace('.', '-'), [path, '--version'])
            tools[name] = {**identity(path), 'version': Path(rec['stdout']['path']).read_text().splitlines()[0]}
        require('20.1.8' in tools['clang']['version'] and '20.1.8' in tools['ld.lld']['version'], 'declared LLVM 20.1.8 required')
        result['compiler'] = tools['clang']
        result['llvm_tools'] = tools
        rec = runner.run('version-qemu', [args.qemu, '--version'])
        result['qemu'] = {**identity(args.qemu), 'version': Path(rec['stdout']['path']).read_text().splitlines()[0],
                          'bios': identity(args.bios), 'machine': 'pc-i440fx-8.2', 'cpu': 'qemu64,-popcnt', 'acceleration': 'tcg'}
        if args.dependency_receipt:
            shutil.copyfile(args.dependency_receipt, output / 'dependency-receipt.json')
            result['dependency_receipt'] = identity(output / 'dependency-receipt.json')
        build = output / 'build'
        make = ['make', '-C', str(source), 'O=' + str(build), 'ARCH=x86_64', 'LLVM=' + str(llvm) + '/', 'V=1']
        runner.run('x86_64_defconfig', [*make, 'x86_64_defconfig'])
        shutil.copyfile(build / '.config', output / 'defconfig.generated.config')
        overlay = ['bash', source / 'scripts/config', '--file', build / '.config']
        for key, value in BOOT_OVERLAY.items():
            overlay += ['--enable', key[7:]] if value == 'y' else ['--set-str', key[7:], json.loads(value)]
        runner.run('apply-boot-overlay', overlay)
        runner.run('olddefconfig', [*make, 'olddefconfig'])
        config = (build / '.config').read_text()
        values = parse_config(config)
        require(all(values.get(k) == v for k, v in BOOT_OVERLAY.items()), 'a required boot config was not admitted')
        require(values.get('CONFIG_CC_IS_CLANG') == 'y' and values.get('CONFIG_LD_IS_LLD') == 'y', 'kernel compiler/linker config mismatch')
        shutil.copyfile(build / '.config', output / 'exact.config')
        write_json(output / 'boot-overlay.json', BOOT_OVERLAY)
        result['config_sha256'] = sha(output / 'exact.config')
        result['config'] = identity(output / 'exact.config')
        result['build_status'] = 'FAIL'
        runner.run('full-kbuild', [*make, '-j' + str(args.jobs), 'vmlinux', 'bzImage', 'modules'], timeout=args.build_timeout)
        require(sha(build / '.config') == result['config_sha256'], 'Kbuild changed the frozen config')
        result['kbuild_command_status'] = 'PASS'
        result['kernel_image'] = identity(build / 'arch/x86/boot/bzImage')
        result['vmlinux'] = identity(build / 'vmlinux')
        database_path = output / 'compile_commands.json'
        runner.run('compile-database', [sys.executable, '-B', source / 'scripts/clang-tools/gen_compile_commands.py',
                                       '-d', build, '-o', database_path, '-a', llvm / 'llvm-ar'])
        database = json.loads(database_path.read_bytes())
        require(isinstance(database, list) and database, 'actual Clang compilation database is empty')
        result['original_compile_commands_sha256'] = sha(database_path)
        result['original_compile_commands'] = identity(database_path)
        metadata, coverage = collect_build_inventory(source, build, output, database)
        result['build_inventory'] = metadata
        target_database = [database[row['index']] for row in coverage['compile_commands']
                           if row['role'] == 'kernel_target_c']
        result['target_compile_indices'] = [row['index'] for row in coverage['compile_commands']
                                           if row['role'] == 'kernel_target_c']
        require(target_database, 'kernel-target C compilation database is empty')
        target_database_path = output / 'target-compile_commands.json'
        write_json(target_database_path, target_database)
        result['compile_commands'] = identity(target_database_path)
        result['compile_commands_sha256'] = sha(target_database_path)
        result['active_compile_units'] = coverage['active_kernel_target_c_compile_commands']
        require(result['active_compile_units'] == len(target_database), 'target database denominator mismatch')
        result['fallback_c_units'] = result['active_compile_units']
        result['active_compile_units_scope'] = 'kernel-target C compile commands only; assembly/host/aggregate objects remain separately inventoried'
        runner.run('linked-symbols', [llvm / 'llvm-nm', '--defined-only', '--extern-only', build / 'vmlinux'])
        result['build_status'] = 'PASS'
        guest = output / 'guest'
        guest.mkdir()
        init = guest / 'init'
        runner.run('compile-static-guest', [llvm / 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                                          '-static', '-fno-pie', '--ld-path=' + str(llvm / 'ld.lld'),
                                          ROOT / 'experiments/hia_linux_kernel_20261106/guest_init.c', '-o', init])
        runner.run('inspect-static-guest', [llvm / 'llvm-readelf', '-h', '-l', init])
        initramfs = guest / 'initramfs.cpio.gz'
        create_initramfs(init, initramfs)
        result['guest_init'], result['initramfs'] = identity(init), identity(initramfs)
        run_id = hashlib.sha256((str(output) + utc()).encode()).hexdigest()[:24]
        result['run_id'] = run_id
        release = (build / 'include/config/kernel.release').read_text().strip()
        require(release == KERNEL_VERSION, 'built kernel release differs from frozen version')
        command = qemu_command(args.qemu, args.qemu_data, args.bios,
                               result['kernel_image']['path'], initramfs, run_id, release)
        rec = runner.run('boot-stock-kernel-tcg', command, timeout=args.boot_timeout, check=False)
        serial = Path(rec['stdout']['path']).read_text(errors='replace')
        verdict = parse_guest_serial(serial, run_id, rec['exit_code'], rec['timed_out'])
        write_json(output / 'guest-verdict.json', verdict)
        result['boot'] = {**verdict, 'command_receipt': rec}
        result['guest_tests'] = verdict['guest_tests']
        result['boot_status'] = verdict['status']
        require(verdict['status'] == 'PASS', 'finite guest smoke failed; original serial and verdict retained')
        result['status'] = 'PASS'
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
        result['status'] = 'FAIL'
    finally:
        if before is not None:
            try:
                after = inventory_tree(source)
                result['linux_source_after_inventory'] = write_gzip_json(output / 'source-after.json.gz', after)
                result['linux_source_unchanged'] = before == after
                if before != after:
                    result['status'] = 'FAIL'
                    result['source_error'] = 'upstream source changed during build or boot'
            except Exception as error:
                result['status'] = 'FAIL'
                result['source_after_error'] = str(error)
        if code_before is not None:
            try:
                result['source_after'] = source_identity(args.expected_head)
                require(result['source_after'] == code_before, 'wrapper source changed during execution')
            except Exception as error:
                result['status'] = 'FAIL'
                result['wrapper_source_after_error'] = str(error)
        result['commands'] = runner.records if runner else []
        result['completed_at_utc'] = utc()
        result['elapsed_ns'] = time.monotonic_ns() - start
        write_json(output / 'RESULT.json', result)
        print(json.dumps({'result': str(output / 'RESULT.json'), 'status': result['status'],
                          'build_status': result['build_status'], 'boot_status': result['boot_status'],
                          'image_kind': result['image_kind'], 'whole_kernel_rewrite': False}), flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
