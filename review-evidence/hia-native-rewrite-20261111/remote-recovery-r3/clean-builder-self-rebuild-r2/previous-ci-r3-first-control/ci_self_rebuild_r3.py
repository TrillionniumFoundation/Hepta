"""Fresh Ubuntu qualification of the inactive, source-rebuilding HIA builder.

The original R13 reader is run unchanged under its own 90/180 limit.  Every
new development gate then runs afresh under aggregate 90 CPU / 150 wall / 1 GiB.
The original compiler and packer continue to use their 10/20/256 MiB children.
No old target test is imported or replayed and no local result is inherited.
"""
from __future__ import annotations

import argparse
import ast
import ctypes
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import resource
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time
import traceback

INDEX_SHA256 = '2fda495e899352c5a3ee81011b4f20b7bcf5e01cf6ce3c124288f108175b2cd8'
INDEX_GITSHA = 'b9b54267541ea4a02643caafe041ddab4977b75c'
AS_LIMIT = 1 << 30
MAX_WALL_SECONDS = 2700
CHUNK = 1 << 20


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def gitsha(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()


def relative(name):
    pure = PurePosixPath(name)
    assert isinstance(name, str) and name and '\0' not in name
    assert not pure.is_absolute() and pure.as_posix() == name
    assert all(x not in ('', '.', '..') for x in pure.parts)
    return pure


def record(path):
    path = Path(path)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode), str(path)
    sh = hashlib.sha256()
    gh = hashlib.sha1(b'blob ' + str(before.st_size).encode('ascii') + b'\0')
    n = 0
    with path.open('rb') as stream:
        while raw := stream.read(CHUNK):
            sh.update(raw)
            gh.update(raw)
            n += len(raw)
    after = path.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mode) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mode)
    assert n == before.st_size
    return {'bytes': n, 'sha256': sh.hexdigest(), 'gitsha': gh.hexdigest(),
            'mode': stat.S_IMODE(before.st_mode)}


def require(actual, expected):
    for key in ('bytes', 'sha256', 'gitsha', 'mode'):
        if key in expected:
            assert actual[key] == expected[key], (key, actual, expected)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    path.write_bytes(raw)
    assert path.read_bytes() == raw


def self_cpu():
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def prepare_reference(original, project):
    """Copy only exact original kit bytes; no project import or target here."""
    packet = (original / 'development/gate-actual-r1/input.hiabuild').read_bytes()
    assert packet[:8] == b'HIABIN01' and packet[16:48] == hashlib.sha256(packet[64:]).digest()
    raw = packet[64:]
    assert len(raw) == 17209634 and sha(raw) == 'c7434fb3bea1782bfecf00d763233d087bd4b451ca103b1bcd15f81cbb8842ff'
    fields = struct.unpack_from('<8Q', raw)
    assert fields == (int.from_bytes(b'HIABKT01', 'little'), 1, 0, 644, 669556, 77245, 0, 0)
    compiler = raw[64:64 + fields[4]]
    assert sha(compiler) == '35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b'
    (project / 'B3-35ee.original.image.bin').write_bytes(compiler)
    at = 64 + fields[4]
    cold_raw = raw[at:at + fields[5]]
    at += fields[5]
    cold = json.loads(cold_raw)
    manifest = cold['source_manifest']
    assert isinstance(manifest, dict) and len(manifest) == 644 and cold['status'] == 'COLD_SELFHOST_REPLAY_PASS'
    (project / 'original-matching-cold.json').write_bytes(cold_raw)
    reference = project / 'reference-kit-r13'
    reference.mkdir()
    seen = set()
    rows = []
    for _ in range(644):
        assert at <= len(raw) - 32
        n, size, a, b = struct.unpack_from('<4Q', raw, at)
        at += 32
        assert a == b == 0 and n <= len(raw) - at
        name = raw[at:at + n].decode('ascii')
        at += n
        assert name not in seen and name in manifest and size <= len(raw) - at
        seen.add(name)
        source = raw[at:at + size]
        at += size
        assert sha(source) == manifest[name]
        destination = reference / relative(name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source)
        destination.chmod(0o644)
        pin = record(destination)
        assert pin['sha256'] == manifest[name]
        rows.append({'path': name, **pin})
    assert at == len(raw) and seen == set(manifest)
    write_json(project / 'reference-kit-r13-manifest.json', {
        'schema': 'hia-r13-exact-kit-source-materialization-ci-r1', 'source_rows': rows,
        'source_count': 644, 'compiler': record(project / 'B3-35ee.original.image.bin'),
        'cold': record(project / 'original-matching-cold.json'),
        'not_an_assumed_git_checkout': True})
    return rows



def become_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    actual = ctypes.c_int(0)
    assert libc.prctl(37, ctypes.addressof(actual), 0, 0, 0) == 0 and actual.value == 1
    assert hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal')
    return {'PR_SET_CHILD_SUBREAPER': 36, 'PR_GET_CHILD_SUBREAPER': 37, 'observed': actual.value}


class Qualification:
    def __init__(self, repo, out, index_path):
        self.repo, self.out, self.index_path = repo, out, index_path
        self.started = time.monotonic_ns()
        self.primary = None
        self.secondary = []
        self.live = {}
        self.inputs = {}
        self.project_sources = {}
        self.stages = []
        self.archive_complete = False
        self.result = {'schema': 'hia-clean-builder-true-self-rebuild-qualification-r1',
                       'status': 'INCOMPLETE', 'scope': 'FRESH_UBUNTU24_INACTIVE_SELF_REBUILD',
                       'activation': False, 'old_target_tests_executed': 0,
                       'inherited_local_cases': 0, 'new_source_cold_qualification': False,
                       'whole_worker_or_15_action_cli_qualification': False,
                       'original_R13_120_CPU_150_wall_test_source_unchanged': True}
        self.parent_pid = os.getpid()

    def failed(self, phase, exc):
        item = {'phase': phase, 'class': type(exc).__name__, 'message': str(exc),
                'traceback': ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))}
        if self.primary is None:
            self.primary = item
        else:
            self.secondary.append(item)
        self.result['status'] = 'FAIL'

    def attempt(self, phase, fn):
        try:
            return fn()
        except BaseException as exc:
            self.failed(phase, exc)
            return None

    def outer_budget(self):
        elapsed = time.monotonic_ns() - self.started
        assert elapsed < MAX_WALL_SECONDS * 1000000000, elapsed
        return elapsed

    def bound_input(self, path, expected):
        self.inputs[str(path)] = dict(expected)
        actual = record(path)
        require(actual, expected)
        self.inputs[str(path)] = actual
        return actual

    def reap_residual(self, pgid):
        """Always retire the stage group and every actual adopted child."""
        rows = []
        requested = set()
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic_ns() + 3000000000
        children_path = Path('/proc/self/task') / str(os.getpid()) / 'children'
        while True:
            while True:
                try:
                    pid, status, usage = os.wait4(-1, os.WNOHANG)
                except ChildProcessError:
                    pid = 0
                if pid == 0:
                    break
                rows.append({'pid': pid, 'wait4_status': status, 'returncode': os.waitstatus_to_exitcode(status),
                             'cpu_seconds': usage.ru_utime + usage.ru_stime,
                             'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
                             'maxrss_kib': usage.ru_maxrss, 'pidfd_kill_requested': pid in requested})
            children = [int(x) for x in children_path.read_text().split()]
            if not children:
                break
            for pid in children:
                try:
                    fd = os.pidfd_open(pid, 0)
                except ProcessLookupError:
                    continue
                try:
                    try:
                        text = Path('/proc', str(pid), 'stat').read_text()
                    except FileNotFoundError:
                        continue
                    fields = text[text.rfind(')') + 2:].split()
                    # The pidfd pins this exact process.  Only our actual child
                    # may be signalled, including adopted native descendants.
                    assert int(fields[1]) == os.getpid(), (pid, fields[1])
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
                        requested.add(pid)
                    except ProcessLookupError:
                        pass
                finally:
                    os.close(fd)
            assert time.monotonic_ns() < deadline, ('unreaped-owned-children', children)
            time.sleep(0.01)
        return rows

    def run(self, label, script, args=(), *, cpu=90, wall=150):
        """Whole process tree, all stdout/stderr bytes, then strict accounting."""
        self.outer_budget()
        folder = self.out / 'processes' / label
        folder.mkdir(parents=True, exist_ok=False)
        start = time.monotonic_ns()
        parent0 = self_cpu()
        source_before = record(script)
        env = os.environ.copy()
        env.pop('PYTHONPATH', None)
        env.pop('PYTHONHOME', None)
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        argv = [sys.executable, '-B', str(script), *map(str, args)]
        write_json(folder / 'request.json', {'argv': argv, 'script': source_before,
                   'cpu_seconds_strict': cpu, 'wall_seconds_strict': wall,
                   'address_bytes': AS_LIMIT, 'original_native_compiler_limits': [10, 20, 268435456]})
        proc = None
        primary = None
        observed = None
        row = {'label': label, 'status': 'INCOMPLETE', 'cpu_seconds_strict': cpu,
               'wall_seconds_strict': wall, 'address_bytes': AS_LIMIT}

        def setup():
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            resource.setrlimit(resource.RLIMIT_AS, (AS_LIMIT, AS_LIMIT))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            libc = ctypes.CDLL(None, use_errno=True)
            assert libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0
            assert os.getppid() == self.parent_pid
            assert libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0

        try:
            with (folder / 'stdout.raw').open('xb') as stdout, (folder / 'stderr.raw').open('xb') as stderr:
                proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                        cwd=script.parent, env=env, start_new_session=True, preexec_fn=setup)
                self.live[proc.pid] = proc
                while True:
                    pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
                    if pid:
                        observed = usage
                        proc.returncode = os.waitstatus_to_exitcode(status)
                        self.live.pop(proc.pid)
                        row.update(returncode=proc.returncode, wait4_status=status)
                        break
                    if time.monotonic_ns() - start >= wall * 1000000000:
                        raise TimeoutError('unchanged full stage wall limit: ' + label)
                    time.sleep(0.01)
            assert proc.returncode == 0, (label, proc.returncode)
        except BaseException as exc:
            primary = exc
            row.update(status='FAIL', error_class=type(exc).__name__, error=str(exc))
        finally:
            if proc is not None and proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    _, status, observed = os.wait4(proc.pid, 0)
                    proc.returncode = os.waitstatus_to_exitcode(status)
                    self.live.pop(proc.pid, None)
                    row['termination_returncode'] = proc.returncode
                except BaseException as exc:
                    if primary is None:
                        primary = exc
                    else:
                        primary.add_note('cleanup: ' + repr(exc))
            try:
                row['residual_descendants'] = self.reap_residual(proc.pid if proc is not None else None)
                assert not row['residual_descendants'], row['residual_descendants']
            except BaseException as exc:
                if primary is None:
                    primary = exc
                else:
                    primary.add_note('all-terminal process-tree cleanup: ' + repr(exc))
            for name in ('stdout', 'stderr'):
                try:
                    row[name] = record(folder / (name + '.raw'))
                except BaseException as exc:
                    if primary is None:
                        primary = exc
                    else:
                        primary.add_note(name + ': ' + repr(exc))
            try:
                assert record(script) == source_before
            except BaseException as exc:
                if primary is None:
                    primary = exc
                else:
                    primary.add_note('script after-check: ' + repr(exc))
            if observed is not None:
                row.update(child_cpu_seconds=observed.ru_utime + observed.ru_stime,
                           child_user_seconds=observed.ru_utime, child_system_seconds=observed.ru_stime,
                           child_maxrss_kib=observed.ru_maxrss)
            row['adopted_cpu_seconds'] = sum(x['cpu_seconds'] for x in row.get('residual_descendants', []))
            row['child_cpu_seconds'] = row.get('child_cpu_seconds', 0) + row['adopted_cpu_seconds']
            row['parent_observation_cpu_seconds'] = self_cpu() - parent0
            row['aggregate_cpu_seconds'] = row.get('child_cpu_seconds', 0) + row['parent_observation_cpu_seconds']
            row['elapsed_ns'] = time.monotonic_ns() - start
            try:
                assert observed is not None
                assert 0 <= row['aggregate_cpu_seconds'] < cpu, row
                assert 0 <= row['elapsed_ns'] < wall * 1000000000, row
            except BaseException as exc:
                if primary is None:
                    primary = exc
                else:
                    primary.add_note('stage final budget: ' + repr(exc))
            row['status'] = 'PASS' if primary is None else 'FAIL'
            self.stages.append(row)
            try:
                write_json(folder / 'process.json', row)
                print('HIA_SELF_REBUILD_STAGE ' + json.dumps(row, sort_keys=True), flush=True)
                assert time.monotonic_ns() - start < wall * 1000000000
                assert row.get('child_cpu_seconds', 0) + self_cpu() - parent0 < cpu
            except BaseException as exc:
                if primary is None:
                    primary = exc
                else:
                    primary.add_note('process receipt: ' + repr(exc))
            if primary is not None:
                row['status'] = 'FAIL'
                row['primary'] = {'class': type(primary).__name__, 'message': str(primary)}
                try:
                    write_json(folder / 'process.json', row)
                except BaseException as exc:
                    primary.add_note('failed-process-receipt: ' + repr(exc))
        if primary is not None:
            raise primary
        return row

    def materialize(self):
        self.bound_input(Path(__file__).resolve(), {})
        self.bound_input(self.index_path, {'sha256': INDEX_SHA256, 'gitsha': INDEX_GITSHA})
        index = json.loads(self.index_path.read_bytes())
        assert index['schema'] == 'hia-clean-builder-self-rebuild-ci-source-index-r2'
        assert len(index['source_files']) == 17
        self.index = index
        self.project = self.out / 'project'
        self.project.mkdir()
        names = set()
        for row in index['source_files']:
            source = self.repo / relative(row['repository_path'])
            self.bound_input(source, row)
            name = relative(row['destination'])
            assert str(name) not in names
            names.add(str(name))
            destination = self.project / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            destination.chmod(row['mode'])
            require(record(destination), row)
            self.project_sources[str(destination)] = record(destination)
            if destination.suffix == '.py':
                ast.parse(destination.read_bytes(), filename=str(destination))
        write_json(self.out / 'source-before.json', self.inputs)

    def restore_originals(self):
        reader = self.project / 'readonly-source/read_clean_builder_r13_originals.py'
        config = reader.with_name('original-inputs.json')
        recovered = self.out / 'r13-original-readback'
        self.run('read-complete-r13-originals', reader,
                 ['--repo', self.repo, '--out', recovered, '--inputs', config], cpu=90, wall=180)
        report = json.loads((recovered / 'summary.json').read_bytes())
        assert report['status'] == 'PASS' and report['primary_error'] is None and report['secondary_errors'] == []
        assert report['complete_original_archive_and_814_members_retained_and_afterchecked'] is True
        assert report['observed_members'] == 814 and report['observed_files'] == 661
        assert report['observed_raw_file_bytes'] == 171212656
        assert report['usage_after_output']['aggregate_cpu_seconds'] < 90
        assert report['usage_after_output']['elapsed_ns'] < 180000000000
        archive = recovered / 'originals/hia-native-clean-build-r1-development.tar.xz'
        require(record(archive), self.index['prior_original_archive'])
        custody = json.loads((recovered / 'originals/custody.json').read_bytes())
        originals = self.project / 'original-r13'
        shutil.copytree(recovered / 'restored', originals, copy_function=shutil.copy2)
        observed = 0
        for row in custody['members']:
            source = originals / relative(row['path'])
            if row['kind'] == 'directory':
                assert source.is_dir() and not source.is_symlink()
                assert stat.S_IMODE(source.lstat().st_mode) == row['mode']
            else:
                require(record(source), row)
                self.project_sources[str(source)] = record(source)
            observed += 1
        assert observed == 814
        self.result['complete_original_readback'] = {'members': 814, 'files': 661, 'bytes': 171212656}
        prepare_reference(originals, self.project)
        require(record(self.project / 'B3-35ee.original.image.bin'), self.index['cold_compiler'])
        for source in (self.project / 'reference-kit-r13').rglob('*'):
            if source.is_file():
                self.project_sources[str(source)] = record(source)
        for name in ('B3-35ee.original.image.bin', 'original-matching-cold.json', 'reference-kit-r13-manifest.json'):
            self.project_sources[str(self.project / name)] = record(self.project / name)
        write_json(self.out / 'all-project-source-before.json', self.project_sources)

    def fresh_gates(self):
        stages = [
            ('baseline-source', 'baseline_regenerate_r1.py', [], 'baseline-regenerate-r1'),
            ('original-self-rebuild-body', 'generate_self_rebuild_r2.py', [], 'generate-self-rebuild-r2'),
            ('optimized-self-rebuild-body', 'generate_self_rebuild_r4.py', [], 'generate-self-rebuild-r4'),
            ('word-pairs-116', 'test_self_rebuild_words_r1.py', [], 'self-rebuild-word-pairs-r1'),
            ('compile-three-and-pack', 'build_self_rebuild_r2.py', [], 'build-self-rebuild-r2'),
            ('prepare-exact-v2-kit', 'prepare_self_rebuild_kit_r2.py', [], None),
            ('complete-native-generation1', 'test_self_rebuild_generation_r2.py', [], 'self-rebuild-generation1-r2'),
            ('full-installed-group', 'test_self_rebuild_installed_r2.py', [], 'self-rebuild-installed-generation2-r2'),
            ('changed-source-native-reference', 'prepare_self_rebuild_mutation_r2.py', [], 'self-rebuild-mutation-r2/evidence'),
            ('changed-source-generation1', 'test_self_rebuild_mutation_generations_r1.py', ['--generation', 'first'], 'self-rebuild-mutation-generation1-r1'),
            ('changed-source-generation2', 'test_self_rebuild_mutation_generations_r1.py', ['--generation', 'second'], 'self-rebuild-mutation-generation2-r1'),
            ('changed-source-real-rejection', 'test_self_rebuild_mutation_rejection_r1.py', [], 'self-rebuild-mutation-rejection-r1'),
        ]
        reports = {}
        for label, name, args, result_dir in stages:
            self.run(label, self.project / name, args)
            if result_dir is None:
                manifest = json.loads((self.project / 'development/self-rebuild-kit-r2/manifest.json').read_bytes())
                assert manifest['old_base_count'] == 644 and manifest['own_source_count'] == 13
                continue
            directory = self.project / 'development' / result_dir
            value = json.loads((directory / 'summary.json').read_bytes())
            assert value['status'] == 'PASS'
            if (directory / 'post-output-budget.json').is_file():
                post = json.loads((directory / 'post-output-budget.json').read_bytes())
                assert post['status'] == 'PASS'
                assert 0 <= post['usage']['aggregate_cpu_seconds'] < 90
                assert 0 <= post['usage']['elapsed_ns'] < 150000000000
            reports[label] = value
        self.result['fresh_reports'] = reports
        words = reports['word-pairs-116']
        assert (words['paired_cases'], words['actual_native_entries'], words['actual_compiles'], words['real_SIGILL_pairs']) == (116, 232, 10, 57)
        assert words['all_full_outputs_and_expected_partial_writes_equal'] is True
        assert reports['baseline-source']['complete_hia_bytes_equal'] is True
        require(record(self.project / 'development/baseline-regenerate-r1/generated.hiaasm'), self.index['expected_original_hia'])
        require(record(self.project / 'development/generate-self-rebuild-r4/clean_build_driver.hiaasm'), self.index['expected_new_hia'])
        require(record(self.project / 'development/build-self-rebuild-r2/hia-build-self-rebuilding'), self.index['expected_native_builder'])
        require(record(self.project / 'development/self-rebuild-mutation-generation1-r1/package-files/hia-build'), self.index['expected_changed_builder'])
        for label in ('complete-native-generation1', 'full-installed-group'):
            assert reports[label]['package_bytes'] == self.index['expected_packages']['bytes']
            assert reports[label]['package_sha256'] == self.index['expected_packages']['normal_sha256']
        installed = reports['full-installed-group']
        assert installed['actual_install_no_replace_and_verify_calls'] == 3 and installed['fresh_complete_stdio_cases'] == 11
        assert len(installed['calls']) == 15 and installed['installed_complete_second_generation_package_equal'] is True
        for label in ('changed-source-generation1', 'changed-source-generation2'):
            assert reports[label]['package_bytes'] == self.index['expected_packages']['bytes']
            assert reports[label]['package_sha256'] == self.index['expected_packages']['changed_sha256']
            assert reports[label]['full_13_row_receipt_equal'] is True
        assert reports['changed-source-generation1']['first_builder_was_not_copied'] is True
        assert reports['changed-source-generation2']['complete_second_generation_fixed_point'] is True
        refusal = reports['changed-source-real-rejection']
        assert refusal['actual_native_reasons'] == [130, 137]
        assert refusal['actual_native_entries'] == 18 and refusal['actual_decoders'] == 4
        assert refusal['actual_fixed_elf_refusals'] == 2 and refusal['actual_poison_reentries'] == 2
        assert refusal['complete_original_base_inventory_cold_and_contract_gates_executed'] is True
        self.result['fresh_stages'] = len(stages)
        self.result['native_recipe_receipts_checked_per_complete_build'] = 13
        receipt_rows = []
        roots = [('words', 'self-rebuild-word-pairs-r1'), ('builder', 'build-self-rebuild-r2'),
                 ('mutation', 'self-rebuild-mutation-r2')]
        counts = {name: 0 for name, _ in roots}
        packers = []
        compiler_sha = self.index['cold_compiler']['sha256']
        for label, directory in roots:
            for path in sorted((self.project / 'development' / directory).glob('*.receipt.json')):
                value = json.loads(path.read_bytes())
                if value.get('artifact_sha256') == compiler_sha:
                    assert value['status'] == 'returned' and value['abi_status'] == 0
                    assert value['source_unchanged'] is True and value['forbidden_compiler_modules_loaded'] == []
                    assert value['limits']['cpu_seconds'] == 10 and value['limits']['address_bytes'] == 268435456
                    assert value['wall_elapsed_ns'] < 20000000000
                    assert value['produced_bytes'] > 0
                    counts[label] += 1
                    receipt_rows.append({'group': label, 'receipt_path': str(path), **record(path)})
                elif label != 'words' and value.get('artifact_sha256') == '87bb61f172a6197cbf6abdeba397178cc6a426069accde1d39479a29c0bc229a':
                    assert value['status'] == 'returned' and value['abi_status'] == 0
                    assert value['limits']['cpu_seconds'] == 10 and value['limits']['address_bytes'] == 268435456
                    assert value['wall_elapsed_ns'] < 20000000000
                    packers.append({'group': label, 'receipt_path': str(path), **record(path)})
        assert counts == {'words': 10, 'builder': 3, 'mutation': 1}, counts
        assert len(packers) == 2
        write_json(self.out / 'actual-external-compile-receipts.json', {'compilers': receipt_rows, 'packers': packers, 'counts': counts})
        self.result['fresh_external_B3_calls'] = sum(counts.values())
        self.result['fresh_external_HIA_packer_calls'] = len(packers)
        self.result['complete_native_build_invocations'] = 4
        self.result['status'] = 'PASS'

    def after(self):
        for path, expected in self.inputs.items():
            self.attempt('checkout-source-after:' + path, lambda p=path, v=expected: require(record(p), v))
        for path, expected in self.project_sources.items():
            self.attempt('project-source-after:' + path, lambda p=path, v=expected: require(record(p), v))

    def seal(self):
        self.run('full-original-seal', self.project / 'ci_self_rebuild_seal_r1.py',
                 ['--root', self.out], cpu=90, wall=180)
        custody = json.loads((self.out / 'custody.json').read_bytes())
        assert custody['status'] == 'PASS' and custody['primary'] is None and custody['secondary'] == []
        assert custody['complete_member_bytes_sha_mode_and_after_checked'] is True
        require(record(self.out / 'evidence.tar.xz'), custody['archive'])
        require(record(self.out / 'evidence-members.json'), custody['member_index'])
        post = json.loads((self.out / 'seal-post-output-budget.json').read_bytes())
        assert post['status'] == 'PASS'
        assert 0 <= post['usage']['aggregate_cpu_seconds'] < 90
        assert 0 <= post['usage']['elapsed_ns'] < 180000000000
        self.custody = custody
        self.archive_complete = True

    def finish(self):
        for pid, proc in list(self.live.items()):
            def kill(pid=pid, proc=proc):
                os.killpg(pid, signal.SIGKILL)
                _, status, _ = os.wait4(pid, 0)
                proc.returncode = os.waitstatus_to_exitcode(status)
                self.live.pop(pid, None)
            self.attempt('final-child-cleanup', kill)
        final_residual = self.attempt('final-owned-child-reap', lambda: self.reap_residual(None))
        if final_residual:
            self.failed('unreaped-descendants-at-finalization', RuntimeError(repr(final_residual)))
        self.after()
        self.result.update(primary=self.primary, secondary=self.secondary, stages=self.stages)
        if self.primary is not None:
            self.result['status'] = 'FAIL'
        self.attempt('frozen-run-result', lambda: write_json(self.out / 'run-result.json', self.result))
        self.attempt('full-original-seal', self.seal)
        self.after()
        elapsed = self.attempt('whole-driver-outer-wall', self.outer_budget)
        summary = {'schema': 'hia-self-rebuild-fresh-ci-final-r1',
                   'status': 'PASS' if self.primary is None and self.result['status'] == 'PASS' and self.archive_complete else 'FAIL',
                   'scope': self.result['scope'], 'primary': self.primary, 'secondary': self.secondary,
                   'complete_fresh_archive_afterchecked': self.archive_complete,
                   'fresh_runtime_and_source_stages': self.result.get('fresh_stages', 0),
                   'completed_process_stages': len(self.stages), 'elapsed_ns': elapsed,
                   'old_cases_inherited': 0, 'activation': False, 'current_source_cold_qualification': False}
        self.attempt('final-summary', lambda: write_json(self.out / 'summary.json', summary))
        if self.primary is not None:
            summary.update(status='FAIL', primary=self.primary, secondary=self.secondary)
        self.attempt('compact-final-stdout', lambda: print('HIA_TRUE_SELF_REBUILD_CI ' + json.dumps(summary, sort_keys=True), flush=True))
        self.attempt('strict-after-output-wall', self.outer_budget)
        if self.primary is not None:
            summary.update(status='FAIL', primary=self.primary, secondary=self.secondary)
            self.attempt('failed-summary-rewrite', lambda: write_json(self.out / 'summary.json', summary))
            return 1
        assert summary['status'] == 'PASS'
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--index', type=Path, default=Path(__file__).with_name('source-index-r2.json'))
    args = parser.parse_args()
    repo, out = args.repo.resolve(), args.out.resolve()
    assert out != repo and not out.is_relative_to(repo)
    out.mkdir(parents=True, exist_ok=False)
    state = Qualification(repo, out, args.index.resolve())
    try:
        assert sys.version_info[:3] == (3, 12, 14), sys.version
        assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
        release = platform.freedesktop_os_release()
        assert release['ID'] == 'ubuntu' and release['VERSION_ID'] == '24.04', release
        resource.setrlimit(resource.RLIMIT_AS, (AS_LIMIT, AS_LIMIT))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        affinity = sorted(os.sched_getaffinity(0))
        assert affinity
        os.sched_setaffinity(0, {affinity[0]})
        state.result['environment'] = {'python': sys.version, 'platform': platform.platform(),
                                       'os_release': release, 'selected_cpu': affinity[0], 'address_bytes': AS_LIMIT}
        state.result['process_tree_owner'] = become_subreaper()
        state.materialize()
        state.restore_originals()
        state.fresh_gates()
    except BaseException as exc:
        state.failed('qualification', exc)
    return state.finish()


if __name__ == '__main__':
    raise SystemExit(main())
