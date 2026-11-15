"""Strict read-only admission-control evidence reader; no product imports."""
from __future__ import annotations
import argparse
from io import BytesIO
from hashlib import sha256
import json
from pathlib import Path
import zipfile

COUNTS = {'paths': 38, 'regular': 8, 'io-failures': 40, 'resolver-failures': 24,
          'cold-source': 1, 'admission': 8, 'cold-public': 16, 'pinned': 2, 'installed': 4}
SOURCE = ('paths', 'regular', 'io-failures', 'resolver-failures', 'cold-source')
NATIVE = ('admission', 'cold-public', 'pinned', 'installed')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _object(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate evidence object field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def _relative(name):
    require(type(name) is str and bool(name), 'unsafe evidence path type')
    path = Path(name)
    require(not path.is_absolute()
            and '..' not in path.parts and str(path) == name, 'unsafe evidence path')
    return path


def child(root, action, *, repository):
    root, repository = Path(root), Path(repository)
    require(action in COUNTS, 'unknown control action')
    snapshots = {}
    def consume(path):
        path = Path(path)
        raw = path.read_bytes()
        if path in snapshots:
            require(snapshots[path] == raw, 'evidence changed between reads: ' + str(path))
        snapshots[path] = raw
        return raw
    report_path = root / action / 'report.json'
    report_raw = consume(report_path);report = _object(report_raw)
    result_raw = consume(root / (action + '.result.json'));result = _object(result_raw)
    start = _object(consume(root / (action + '.start.json')))
    require(report['schema'] == 'hepta.hia.native-admission-io-control.v1'
            and report['action'] == action and report['status'] == 'PASS'
            and report['source_unchanged'] is True
            and report['source_before'] == report['source_after']
            and report['qualified_whole_native_stack'] is False
            and report['native_Capture_inputs_replaced'] is False, 'control report scope differs')
    require(type(report['observations']['count']) is int
            and report['observations']['count'] == COUNTS[action], 'control count differs')
    timeout = 600 if action == 'installed' else 60
    require(type(result['timeout_seconds']) is int and result['timeout_seconds'] == timeout
            and type(result['cleanup_seconds']) is int and result['cleanup_seconds'] == 3
            and result['timeout'] is False and result['cleanup_error'] is None
            and type(result['returncode']) is int and result['returncode'] == 0
            and type(result['expected_returncode']) is int and result['expected_returncode'] == 0,
            'owned command did not finish under its original declared budget')
    require(result['cleanup'] is not None and result['cleanup']['after'] == [],
            'owned command left descendants')
    for name in ('pid', 'pgid'):
        require(type(report[name]) is int and type(result[name]) is int
                and type(start[name]) is int and report[name] == result[name] == start[name],
                'report is not bound to actual owned process')
    invocation = _object(consume(root / 'invocation.json'))
    require(invocation['schema'] == 'hepta.hia.native-admission-invocation.v1'
            and invocation['phase'] == ('source' if action in SOURCE else 'native')
            and invocation['original_Capture_gates_replaced'] is False
            and invocation['retained_diagnostics'] == str(root)
            and type(invocation['pid']) is int and type(report['ppid']) is int
            and invocation['pid'] == report['ppid'],
            'child does not belong to its actual parent invocation')
    command = result['command']
    require(command == start['command'] and type(command) is list and len(command) in (8, 10)
            and command[1:3] == ['-I', '-B']
            and Path(command[3]) == repository / 'tests/hia_native_admission_io_controls.py'
            and command[4:6] == ['--action', action]
            and command[6:8] == ['--output', str(root / action)],
            'owned command route/arguments differ')
    require(result['cwd'] == start['cwd'] == str(repository), 'owned cwd differs')
    if action in NATIVE:
        require(len(command) == 10 and command[8] == '--manifest'
                and report['manifest']['path'] == command[9], 'native manifest is not explicit')
        require(sha256(consume(command[9])).hexdigest() == report['manifest']['sha256'],
                'actual native manifest changed')
    else:
        require(len(command) == 8, 'Source control acquired a native manifest')
    for stream in ('stdout', 'stderr'):
        raw = consume(root / (action + '.' + stream + '.log'))
        require(sha256(raw).hexdigest() == result[stream + '_sha256'], 'raw command stream differs')
    for name, pin in report['source_before'].items():
        raw = consume(repository / _relative(name))
        require(type(pin['bytes']) is int and _pin(raw) == pin, 'actual source pin differs: ' + name)
    files = report['files']
    require(type(files) is dict and 'source-before.json' in files, 'owned raw files missing')
    for name, pin in files.items():
        raw = consume(root / action / _relative(name))
        require(type(pin['bytes']) is int and _pin(raw) == pin, 'consumed raw evidence differs: ' + name)
    def evidence(name):
        require(name in files, 'required owned evidence is unsigned: ' + name)
        raw = consume(root / action / _relative(name))
        require(_pin(raw) == files[name], 'required consumed raw pin differs: ' + name)
        return raw
    require(_object(evidence('source-before.json')) == report['source_before'],
            'actual source snapshot is not the reported snapshot')
    if action in ('paths', 'regular'):
        require(evidence('expected.json') == evidence('actual.json')
                and _object(evidence('differences.json')) == [],
                'full independent expected/actual stream differs')
    if action == 'io-failures':
        rows = _object(evidence('io-failures.json'))
        require(len(rows) == 40 and len({row['id'] for row in rows}) == 40
                and all(row['same_error'] is True and row['capsule_retried_close'] is False
                        for row in rows), 'complete descriptor failure table differs')
    if action == 'resolver-failures':
        rows = _object(evidence('resolver-failures.json'))
        require(len(rows) == 24 and len({row['id'] for row in rows}) == 24
                and all(type(row['calls']) is int
                        and type(row['capability_cutpoint_reachable_in_this_runtime']) is bool
                        and row['calls'] == int(row['capability_cutpoint_reachable_in_this_runtime'])
                        for row in rows),
                'complete resolver fault table differs')
    if action == 'cold-source':
        require(report['observations']['cold_before_import'] is True
                and report['observations']['business_os_calls'] == [], 'cold isolation not observed')
    if action == 'cold-public':
        row = _object(evidence('cold-public.json'))
        require(row['business_fstat_calls'] == ['fstat', 'fstat']
                and row['expected_hex'] == row['actual_hex']
                and report['observations']['original_OS_cases'] == 12
                and report['observations']['original_race_cases'] == 3,
                'cold public/complete old race domain differs')
        real = _object(evidence('real-os.json'))
        require(real['raw_syscall_primitive_substituted'] is False
                and [row['id'] for row in real['observations']] == [
                    'ordinary', 'empty', 'outside', 'file_symlink', 'directory_symlink',
                    'fifo', 'directory', 'extent', 'relative', 'no_root', 'root_itself', 'traversal']
                and all(row['original'] == row['actual'] for row in real['observations']),
                'complete unchanged original OS controls differ')
        races = _object(evidence('real-os-races.json'))
        require(races['complete_original_and_actual_public_route'] is True
                and races['opaque_os_provider_replaced_by_raw_primitive'] is False
                and [row['id'] for row in races['rows']] == [
                    'directory-renamed-after-open', 'file-replaced-by-fifo', 'same-size-identity-change']
                and all(row['original'] == row['actual'] for row in races['rows']),
                'complete unchanged original race controls differ')
    if action == 'installed':
        installed = _object(evidence('installed/installed.json'))
        require(installed['schema'] == 'hepta.hia.store-file-capture-installed-worker.v1'
                and installed['runtime_authoring_imports_forbidden'] is True
                and installed['every_request_has_all_three_expected_identity_flags'] is True
                and installed['whole_native_stack_qualified'] is False,
                'original installed scope differs')
        labels = ('wheel', 'install', 'identity', 'normal', 'replay', 'source-plus-LF', 'extra-module')
        require(type(installed['commands']) is list and len(installed['commands']) == len(labels),
                'original installed command sequence differs')
        streams = {}
        for label, recorded in zip(labels, installed['commands']):
            prefix = 'installed/' + label
            receipt = _object(evidence(prefix + '.result.json'))
            begun = _object(evidence(prefix + '.start.json'))
            require(receipt == recorded and receipt['command'] == begun['command']
                    and receipt['cwd'] == begun['cwd'] == str(repository),
                    'installed actual command is not the reported command')
            require(type(receipt['timeout_seconds']) is int and receipt['timeout_seconds'] == 60
                    and type(receipt['cleanup_seconds']) is int and receipt['cleanup_seconds'] == 3
                    and receipt['timeout'] is False and receipt['cleanup_error'] is None
                    and receipt['cleanup'] is not None and receipt['cleanup']['after'] == [],
                    'installed original command budget/ownership differs')
            expected_code = 2 if label in ('source-plus-LF', 'extra-module') else 0
            require(type(receipt['returncode']) is int and receipt['returncode'] == expected_code
                    and type(receipt['expected_returncode']) is int
                    and receipt['expected_returncode'] == expected_code,
                    'installed original exit code differs')
            require(receipt['command'][1:3] == ['-I', '-B']
                    and all(type(receipt[name]) is int and type(begun[name]) is int
                            and receipt[name] == begun[name] for name in ('pid', 'pgid')),
                    'installed original interpreter/process binding differs')
            stream = {}
            for channel in ('stdout', 'stderr'):
                raw = evidence(prefix + '.' + channel + '.log')
                require(sha256(raw).hexdigest() == receipt[channel + '_sha256'],
                        'installed actual stream digest differs')
                stream[channel] = raw
            if label not in ('wheel', 'install'):
                lines = [line[len(b'CAPTURE_COUNTS='):] for line in stream['stderr'].splitlines()
                         if line.startswith(b'CAPTURE_COUNTS=')]
                require(len(lines) == 1, 'installed worker lacks one actual entry-count record')
                stream['counts'] = _object(lines[0])
                require(set(stream['counts']) == {'startup', 'request'}
                        and all(type(value) is int and value >= 0
                                for value in stream['counts'].values()),
                        'installed actual entry counts are not nonnegative integers')
            streams[label] = stream
        require(streams['identity']['counts'] == {'startup': 0, 'request': 0}
                and _object(streams['identity']['stdout']) == installed['identity'],
                'installed identity query acquired an execution or different identity')
        require(streams['normal']['counts']['request'] > 0
                and streams['replay']['counts']['request'] == 0
                and _object(streams['normal']['stdout']) == installed['observations']['normal']
                and _object(streams['replay']['stdout']) == installed['observations']['replay']
                and streams['normal']['counts'] == installed['observations']['normal_counts']
                and streams['replay']['counts'] == installed['observations']['replay_counts']
                and installed['observations']['normal']['response']['status'] == 'completed'
                and installed['observations']['normal']['response']
                    == installed['observations']['replay']['response'],
                'installed selected/replay observations differ from raw commands')
        for label in ('source-plus-LF', 'extra-module'):
            require(streams[label]['stdout'] == b'' and streams[label]['counts']['request'] == 0,
                    'installed drift command reached request execution')
        bundle_raw = evidence('installed/bundle.json')
        require(sha256(bundle_raw).hexdigest() == installed['bundle_sha256']
                == installed['identity']['native_helpers_sha256'],
                'installed actual bundle identity differs')
        capsule_name = 'hepta/hia_native_admission_io.py'
        capsule = consume(repository / capsule_name)
        require(sha256(capsule).hexdigest() == installed['wheel_files_checked_against_installed'][capsule_name],
                'installed wheel capsule source pin differs')
        installed_path, wheel_path = Path(installed['installed']), Path(installed['wheel'])
        require(installed_path.is_relative_to(root / action)
                and wheel_path.is_relative_to(root / action), 'installed artifacts escaped owned evidence')
        actual_capsule = evidence(str((installed_path / capsule_name).relative_to(root / action)))
        wheel_raw = evidence(str(wheel_path.relative_to(root / action)))
        require(actual_capsule == capsule and sha256(wheel_raw).hexdigest() == installed['wheel_sha256'],
                'actual installed capsule or wheel differs')
        with zipfile.ZipFile(BytesIO(wheel_raw)) as archive:
            require(archive.namelist().count(capsule_name) == 1
                    and archive.read(capsule_name) == capsule,
                    'actual wheel did not package the exact capsule')
    for path, raw in snapshots.items():
        require(path.read_bytes() == raw, 'consumed evidence changed at terminal reread: ' + str(path))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--phase', choices=('source', 'native'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    actions = SOURCE if args.phase == 'source' else NATIVE
    reports = [child(args.evidence, action, repository=args.repository) for action in actions]
    custody_path = args.evidence / ('source-custody.json' if args.phase == 'source'
                                    else 'component-custody.json')
    custody_raw = custody_path.read_bytes();custody = _object(custody_raw)
    require(custody['unchanged'] is True and custody['source_before'] == custody['source_after'],
            'complete parent class source/cold/compiler custody differs')
    if args.phase == 'source':
        require(all(report['source_before'] == custody['source_before'] for report in reports),
                'parent and actual Source children used different source bytes')
    else:
        require(custody['scope'] in ('DEVELOPMENT_COMPONENT', 'MATCHING_SOURCE_COLD_COMPONENT')
                and all(report['manifest']['path'] == custody['manifest']
                        and report['manifest']['sha256'] == custody['manifest_sha256']
                        for report in reports),
                'native class manifest/build scope differs')
        manifest_raw = Path(custody['manifest']).read_bytes()
        require(sha256(manifest_raw).hexdigest() == custody['manifest_sha256']
                and _object(manifest_raw)['compiler_sha256'] == custody['compiler_sha256'],
                'native class manifest does not bind the actual compiler digest')
    require(custody_path.read_bytes() == custody_raw, 'parent custody changed at terminal reread')
    result = {'schema': 'hepta.hia.native-admission-control-readback.v1', 'status': 'PASS',
              'phase': args.phase, 'actions': list(actions),
              'counts': [report['observations']['count'] for report in reports],
              'original_Capture_gates_still_required': True, 'whole_native_stack_qualified': False}
    with args.output.open('x') as stream:
        json.dump(result, stream, ensure_ascii=True, sort_keys=True, indent=2);stream.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
