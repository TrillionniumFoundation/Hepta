"""Original-first finite source -> native package -> install/verify/exec evidence.

No Python path constructs candidate HIAREL01 bytes or candidate machine code.
All actual candidate work is performed by captured HIA-native executables.
This hosted harness freezes original values first and preserves every raw child
input, output, error stream and the original subreaper-owner receipt.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tests.hia_exec_release_controls import (GROUPS, VALID_CASES, REFUSAL_CASES,
    KERNEL_CASES, PROGRAM_INPUTS, exact_bundle, request_cases)
from tools.hia_selfhost_process_owner import run_owned
from tools.build_hia_json_preflight import current_sources
from tools.build_hia_exec_release import build, SOURCES
from tools.build_hia_source_build import _check_compile_receipt, _check_pack_output
from tools.qualify_hia_selfhost_cli import inspect_executable

CHILD = ROOT / 'tools/hia_exec_release_child.py'
ORIGINAL = ROOT / 'tests/hia_exec_release_controls.py'
OWNER = ROOT / 'tools/hia_selfhost_process_owner.py'
SECONDS = 120
CLEANUP_SECONDS = 3


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def put(path, raw):
    path = Path(path)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('short evidence write')
    return path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def expected_plan():
    rows = [('original-first', 'original'), ('original-second', 'original')]
    for case in VALID_CASES:
        rows += [(case + '-' + step, 'source-to-installed-exec')
                 for step in ('build', 'install', 'verify', *('exec-' + x for x in PROGRAM_INPUTS))]
    rows += [('refusal-' + name, 'refusals') for name in REFUSAL_CASES]
    rows += [('kernel-' + name, 'kernel-errors') for name in KERNEL_CASES]
    rows += [(name, 'no-replace-and-corruption') for name in
             ('existing-install', 'existing-verify', 'corrupt-verify', 'restored-verify')]
    rows += [(name, 'copied-native-runtime') for name in
             ('copied-build', 'copied-install', 'copied-verify', *('copied-exec-' + x for x in PROGRAM_INPUTS))]
    return [{'id': identity, 'group': group} for identity, group in rows]


class Run:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.commands, self.errors, self.captured = [], [], {}
        self.groups = {name: [] for name in GROUPS}

    def capture(self, path):
        path = Path(path).resolve(strict=True)
        raw = path.read_bytes()
        previous = self.captured.setdefault(path, raw)
        require(previous == raw, 'previously captured file changed: ' + str(path))
        return raw

    def remember(self, path, raw):
        put(path, raw)
        require(self.capture(path) == raw, 'evidence publication differs')
        return path

    def environment(self, folder):
        result = {'PATH': '/usr/bin:/bin', 'HOME': str(folder), 'LANG': 'C.UTF-8',
                  'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}
        if os.environ.get('LD_LIBRARY_PATH'):
            result['LD_LIBRARY_PATH'] = os.environ['LD_LIBRARY_PATH']
        return result

    def owned(self, identity, group, command, folder):
        started = time.monotonic_ns()
        result = run_owned(command, cwd=str(folder), env=self.environment(folder),
            stdout_path=folder / 'stdout.raw', stderr_path=folder / 'stderr.raw',
            receipt_path=folder / 'owner.json', qualification_seconds=SECONDS,
            cleanup_seconds=CLEANUP_SECONDS)
        stopped = time.monotonic_ns()
        row = {'id': identity, 'group': group, 'started_ns': started, 'stopped_ns': stopped,
            'command': command, 'directory': str(folder), 'observed_owner': result,
            'source_pins': {str(path): pin(self.capture(path)) for path in (OWNER, CHILD, ORIGINAL)}}
        for name in ('stdout.raw', 'stderr.raw', 'owner.json', 'owner.json.request.json',
                     'owner.json.stdout.log', 'owner.json.stderr.log'):
            path = folder / name
            if path.is_file():
                row[name] = {'path': str(path), **pin(self.capture(path))}
        self.commands.append(row)
        return row

    def original(self, identity):
        folder = self.directory / identity
        folder.mkdir(mode=0o700)
        target = folder / 'original.json'
        command = [sys.executable, '-I', '-S', '-B', str(ORIGINAL), '--originals', str(target)]
        row = self.owned(identity, 'original', command, folder)
        self.success_owner(row, 0)
        require(self.capture(folder / 'stderr.raw') == b'', 'original child stderr is not empty')
        raw = self.capture(target)
        row['original'] = {'path': str(target), **pin(raw)}
        return raw

    def execute(self, identity, group, image, data, arguments=(), mode='ordinary'):
        folder = self.directory / identity
        folder.mkdir(mode=0o700)
        image = Path(image).resolve(strict=True)
        image_raw = self.capture(image)
        input_path = self.remember(folder / 'stdin.raw', data)
        request = {'schema': 'hepta.hia.exec-release-exec-request.v1',
            'image': str(image), 'image_sha256': sha256(image_raw).hexdigest(),
            'input': str(input_path), 'input_sha256': sha256(data).hexdigest(),
            'arguments': list(arguments), 'mode': mode}
        request_raw = wire(request)
        request_path = self.remember(folder / 'request.json', request_raw)
        command = [sys.executable, '-I', '-S', '-B', str(CHILD),
                   '--request', str(request_path), '--sha256', sha256(request_raw).hexdigest()]
        row = self.owned(identity, group, command, folder)
        row.update(request={'path': str(request_path), **pin(request_raw)},
                   input={'path': str(input_path), **pin(data)},
                   image={'path': str(image), **pin(image_raw)})
        return row, self.capture(folder / 'stdout.raw'), self.capture(folder / 'stderr.raw')

    def success_owner(self, row, returncode):
        actual = row['observed_owner']
        cleanup = actual.get('cleanup', {})
        require(actual.get('status') == ('OWNED_PROCESS_COMPLETED' if returncode == 0 else 'QUALIFICATION_FAILED')
            and type(actual.get('returncode')) is int and actual['returncode'] == returncode
            and actual.get('qualification_seconds') == SECONDS
            and actual.get('cleanup_seconds') == CLEANUP_SECONDS
            and actual.get('timed_out') is False and actual.get('exit_observed_before_deadline') is True
            and cleanup.get('complete') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('observed_echild') is True and cleanup.get('errors') == [],
            {'id': row['id'], 'owner': actual, 'expected_returncode': returncode})

    def check(self, group, label, callback):
        try:
            callback()
        except Exception:
            self.groups[group].append({'id': label, 'status': 'HOLD',
                'exception': traceback.format_exc()})
        else:
            self.groups[group].append({'id': label, 'status': 'PASS'})

    def stable(self):
        for path, raw in self.captured.items():
            require(path.read_bytes() == raw, 'captured raw changed at terminal: ' + str(path))


def installer(run, compiler, cold, development):
    from tools.qualify_hia_selfhost import compile_stage, invoke
    from tools.generate_hia_release_install import MAGIC
    directory = run.directory / 'installer-build'
    if not development:
        from tools.build_hia_release_install import build as build_installer
        executable = build_installer(directory, compiler, cold)
        run.capture(directory / 'build.json')
        run.capture(executable)
        return executable
    # Explicit DEV-only bootstrap of the unchanged installer HIA. No cold
    # refusal can enter this branch and no source-policy/package Python fallback
    # is used. Its receipts remain separate from current-cold qualification.
    directory.mkdir(mode=0o700)
    compiler_raw = run.capture(compiler)
    images, receipts, sources = {}, {}, {}
    for label in ('release_install_policy', 'release_install_packer', 'sha256_stream'):
        path = ROOT / 'examples/hia_bootstrap' / (label + '.hepta')
        source = run.capture(path)
        sources[str(path.relative_to(ROOT))] = pin(source)
        image, receipt = compile_stage(directory, label, compiler, source)
        raw = run.capture(image)
        _check_compile_receipt(receipt, compiler=compiler_raw, source=source, produced=raw)
        require(type(receipt.get('result_u64')) is int and receipt['result_u64'] == len(raw),
                'DEV installer full compile return differs')
        images[label] = (image, raw)
        receipts[label] = receipt
        run.capture(directory / (label + '.receipt.json'))
    policy, digest = images['release_install_policy'][1], images['sha256_stream'][1]
    frame = struct.pack('<3Q', MAGIC, len(policy), len(digest)) + policy + digest
    receipt, output = invoke(directory, 'installer-pack', images['release_install_packer'][0], frame)
    executable_raw = _check_pack_output(receipt, output,
        artifact=images['release_install_packer'][1], source=frame)
    inspect_executable(executable_raw)
    executable = run.remember(directory / 'hia-release', executable_raw)
    executable.chmod(0o500)
    run.capture(directory / 'installer-pack.receipt.json')
    report = {'schema': 'hepta.hia.exec-release-dev-installer.v1', 'development_only': True,
        'source_sha256': sources, 'compiler_sha256': sha256(compiler_raw).hexdigest(),
        'compile_receipts': receipts, 'pack_receipt': receipt,
        'executable': {'path': str(executable), **pin(executable_raw)}}
    run.remember(directory / 'build.json', wire(report))
    return executable


def qualify(directory, compiler, cold_report, *, development=False, expected_compiler_sha256=None):
    run = Run(directory)
    planned = expected_plan()
    run.remember(run.directory / 'planned.json', wire(planned))
    sources_before = current_sources()
    completed = False
    frozen = None
    app = release = None
    results = {}
    try:
        # Neither candidate graph nor new executable has run in this qualifier
        # until these full fresh-child records are identical and frozen.
        first = run.original('original-first')
        second = run.original('original-second')
        require(first == second, 'two complete fresh originals differ')
        reference = json.loads(first)
        require(tuple(row['id'] for row in reference['cases']) == VALID_CASES,
                'original case order differs')
        inputs = []
        for row in reference['cases']:
            source = bytes.fromhex(row['source_hex'])
            path = run.remember(run.directory / (row['id'] + '.source'), source)
            inputs.append({'id': row['id'], 'path': str(path), **pin(source)})
        refusals = request_cases(reference)
        for row in refusals:
            path = run.remember(run.directory / ('refusal-' + row['id'] + '.source'), row['source'])
            inputs.append({'id': 'refusal-' + row['id'], 'path': str(path),
                **pin(row['source']), 'arguments': list(row['arguments']),
                'expected_returncode': row['expected_returncode']})
        frozen = {'schema': 'hepta.hia.exec-release-expectations.v1',
            'originals': [run.commands[0]['original'], run.commands[1]['original']],
            'inputs': inputs, 'source_manifest': sources_before,
            'planned': planned, 'frozen_ns': time.monotonic_ns(),
            'candidate_started': False, 'whole_native_delivery_qualified': False}
        run.remember(run.directory / 'expectations.json', wire(frozen))
        app = build(run.directory / 'builder', compiler, cold_report,
            development=development, expected_compiler_sha256=expected_compiler_sha256)
        build_raw = run.capture(app.parent / 'build.json')
        metadata = json.loads(build_raw)
        require(metadata['source_manifest'] == sources_before, 'builder source map changed')
        release = installer(run, app.parent / 'captured-compiler.image.bin',
            None if development else app.parent / 'captured-cold.json', development)
        package_root = run.directory / 'releases'
        package_root.mkdir(mode=0o700)

        for case in reference['cases']:
            def valid(case=case):
                identity, data = case['id'], bytes.fromhex(case['source_hex'])
                row, output, error = run.execute(identity + '-build', GROUPS[0], app, data,
                    (case['syntax'], sha256(data).hexdigest()))
                run.success_owner(row, 0)
                receipt = json.loads(error)
                members = exact_bundle(output)
                require(members[0][2] == data, 'package source is not the entire original input')
                require(receipt == {
                    'schema': 'hepta.hia.exec-release.v1', 'status': 'PACKAGE_BUILT',
                    'syntax': case['syntax'], 'profile': 'selfhost-exec-linux-x86_64.v1',
                    'source_sha256': sha256(data).hexdigest(),
                    'image_sha256': sha256(members[1][2]).hexdigest(),
                    'package_sha256': sha256(output).hexdigest(),
                    'source_bytes': len(data), 'image_bytes': len(members[1][2]),
                    'package_bytes': len(output), 'members': 2, 'runtime_python': False,
                    'generated_program_executed': False, 'installed': False, 'published': False},
                    'complete native package receipt differs')
                inspect_executable(members[1][2])
                digest = sha256(output).hexdigest()
                roots = package_root / identity
                roots.mkdir(mode=0o700)
                installed = roots / digest
                for operation in ('install', 'verify'):
                    record, out, err = run.execute(identity + '-' + operation, GROUPS[0], release, output,
                        (operation, str(roots), digest))
                    run.success_owner(record, 0)
                    require(err == b'' and json.loads(out) == {
                        'schema': 'hepta.hia.release-install.v1', 'sha256': digest,
                        'files': 2, 'bytes': len(output), 'published': operation == 'install'},
                        'original native installer/verify receipt differs')
                for name, mode, raw in members:
                    path = installed / name.decode('ascii')
                    require(run.capture(path) == raw and path.stat().st_mode & 0o7777 == mode,
                            'actual installed member bytes/mode differs')
                require(installed.stat().st_mode & 0o7777 == 0o500
                        and sorted(p.name for p in installed.iterdir()) == ['program', 'source.hepta'],
                        'actual installed inventory/mode differs')
                for expected in case['executions']:
                    record, out, err = run.execute(identity + '-exec-' + expected['input_hex'], GROUPS[0],
                        installed / 'program', bytes.fromhex(expected['input_hex']))
                    run.success_owner(record, 0)
                    require(out.hex() == expected['stdout_hex'] and err == b'',
                            'actual ET_EXEC differs from complete frozen original VM result')
                results[identity] = {'package': output, 'members': members,
                                     'root': roots, 'installed': installed, 'case': case}
            run.check(GROUPS[0], case['id'], valid)

        for case in refusals:
            def refused(case=case):
                row, out, err = run.execute('refusal-' + case['id'], GROUPS[1], app,
                    case['source'], case['arguments'])
                run.success_owner(row, case['expected_returncode'])
                require(out == b'' and json.loads(err) == {
                    'schema': 'hepta.hia.exec-release.v1', 'status': 'rejected',
                    'code': case['expected_returncode'], 'observed_stdout_bytes': 0,
                    'installed': False, 'published': False}, 'new CLI refusal receipt differs')
            run.check(GROUPS[1], case['id'], refused)

        echo = bytes.fromhex(reference['cases'][0]['source_hex'])
        for mode in KERNEL_CASES:
            def failed(mode=mode):
                row, out, err = run.execute('kernel-' + mode, GROUPS[2], app, echo,
                    ('assembly', sha256(echo).hexdigest()), mode)
                run.success_owner(row, 4)
                require(out == b'' and json.loads(err) == {
                    'schema': 'hepta.hia.exec-release.v1', 'status': 'rejected',
                    'code': 4, 'observed_stdout_bytes': 0, 'installed': False, 'published': False},
                    'actual OS failure was not classified by HIA')
            run.check(GROUPS[2], mode, failed)

        def no_replace():
            base = results['assembly-echo']
            package, installed, root = base['package'], base['installed'], base['root']
            digest = sha256(package).hexdigest()
            inode = installed.stat().st_ino
            record, out, err = run.execute('existing-install', GROUPS[3], release, package,
                ('install', str(root), digest))
            run.success_owner(record, 14)
            require(out == b'' and installed.stat().st_ino == inode, 'existing release was replaced')
            record, out, err = run.execute('existing-verify', GROUPS[3], release, package,
                ('verify', str(root), digest))
            run.success_owner(record, 0)
            require(json.loads(out)['published'] is False and err == b'', 'read-only resolution differs')
            # This is an explicit test-owned corruption, not product cleanup.
            # Save the complete preimage; never clear product state or rewrite
            # expected observations. Restore only this known test-owned inode.
            target = installed / 'source.hepta'
            original = target.read_bytes()
            before_stat = target.stat()
            run.remember(run.directory / 'corruption-before.raw', original)
            target.chmod(0o600)
            try:
                target.write_bytes(original + b'\n')
                target.chmod(0o400)
                changed_raw = target.read_bytes()
                changed_stat = target.stat()
                require(changed_raw == original + b'\n' and changed_stat.st_ino == before_stat.st_ino,
                        'test-owned corruption did not reach the original inode')
                run.remember(run.directory / 'corruption-during.raw', changed_raw)
                record, out, err = run.execute('corrupt-verify', GROUPS[3], release, package,
                    ('verify', str(root), digest))
                run.success_owner(record, 11)
                require(out == b'', 'actual changed installed source was accepted')
            finally:
                target.chmod(0o600)
                target.write_bytes(original)
                target.chmod(0o400)
            run.remember(run.directory / 'corruption-restored.raw', target.read_bytes())
            run.remember(run.directory / 'corruption.json', wire({
                'path': str(target), 'inode_before': before_stat.st_ino,
                'inode_during': changed_stat.st_ino, 'inode_restored': target.stat().st_ino,
                'source_before': pin(original), 'source_during': pin(changed_raw),
                'source_restored': pin(target.read_bytes()), 'test_owned_control': True}))
            record, out, err = run.execute('restored-verify', GROUPS[3], release, package,
                ('verify', str(root), digest))
            run.success_owner(record, 0)
            require(json.loads(out)['published'] is False and err == b'' and target.read_bytes() == original,
                    'restored original release failed read-only verification')
        run.check(GROUPS[3], 'complete-no-replace-corruption', no_replace)

        def copied():
            copied = run.directory / 'copied'
            copied.mkdir(mode=0o700)
            new_app = run.remember(copied / 'builder', run.capture(app))
            new_release = run.remember(copied / 'installer', run.capture(release))
            new_app.chmod(0o500); new_release.chmod(0o500)
            record, out, err = run.execute('copied-build', GROUPS[4], new_app, echo,
                ('assembly', sha256(echo).hexdigest()))
            run.success_owner(record, 0)
            require(out == results['assembly-echo']['package'], 'copied native executable differs')
            digest = sha256(out).hexdigest()
            root = copied / 'releases'; root.mkdir(mode=0o700)
            for op in ('install', 'verify'):
                record, receipt, error = run.execute('copied-' + op, GROUPS[4], new_release, out,
                    (op, str(root), digest))
                run.success_owner(record, 0)
                require(error == b'' and json.loads(receipt)['published'] is (op == 'install'),
                        'copied native installer differs')
            for expected in reference['cases'][0]['executions']:
                record, output, error = run.execute('copied-exec-' + expected['input_hex'], GROUPS[4],
                    root / digest / 'program', bytes.fromhex(expected['input_hex']))
                run.success_owner(record, 0)
                require(error == b'' and output.hex() == expected['stdout_hex'],
                        'copied installed program differs under empty PATH')
        run.check(GROUPS[4], 'complete-copied-runtime', copied)
        completed = True
    except Exception:
        run.errors.append(traceback.format_exc())
    finally:
        try:
            run.stable()
            require(current_sources() == sources_before, 'current complete source map changed')
        except Exception:
            run.errors.append(traceback.format_exc())
        actual_ids = [row['id'] for row in run.commands]
        planned_ids = [row['id'] for row in planned]
        full = completed and actual_ids == planned_ids and not run.errors and all(
            rows and all(row['status'] == 'PASS' for row in rows) for rows in run.groups.values())
        report = {'schema': 'hepta.hia.exec-release-qualification.v1',
            'status': ('PASS_EXPLICIT_DEVELOPMENT_FINITE_ONLY' if development else
                       'PASS_CURRENT_SOURCE_NATIVE_EXEC_RELEASE_FINITE') if full else 'HOLD',
            'development_only': development, 'planned': planned, 'commands': run.commands,
            'groups': run.groups, 'errors': run.errors,
            'missing_commands': [name for name in planned_ids if name not in actual_ids],
            'source_manifest': sources_before,
            'expectations': None if frozen is None else {
                'path': str(run.directory / 'expectations.json'),
                **pin(run.capture(run.directory / 'expectations.json'))},
            'builder_report': None if app is None else {
                'path': str(app.parent / 'build.json'), **pin(run.capture(app.parent / 'build.json'))},
            'installer_report': None if release is None else {
                'path': str(release.parent / 'build.json'), **pin(run.capture(release.parent / 'build.json'))},
            'all_input_equivalence_proved': False, 'ordinary_cli_default_changed': False,
            'public_vm_replaced': False, 'whole_native_delivery_qualified': False,
            'cold_or_gc_or_existing_resource_holds_resolved': False}
        ledger = [{'path': str(path), **pin(raw)} for path, raw in sorted(run.captured.items(), key=lambda item: str(item[0]))]
        ledger_raw = wire(ledger)
        put(run.directory / 'consumed-files.json', ledger_raw)
        report['consumed_files'] = {'path': str(run.directory / 'consumed-files.json'), **pin(ledger_raw)}
        put(run.directory / 'report.json', wire(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--cold-report', type=Path)
    parser.add_argument('--development', action='store_true')
    parser.add_argument('--compiler-sha256')
    args = parser.parse_args()
    result = qualify(args.output.resolve(), args.compiler.resolve(),
        None if args.cold_report is None else args.cold_report.resolve(),
        development=args.development, expected_compiler_sha256=args.compiler_sha256)
    print(json.dumps({'status': result['status'], 'output': str(args.output.resolve())}))
    return 0 if result['status'].startswith('PASS_') else 1


if __name__ == '__main__':
    raise SystemExit(main())
