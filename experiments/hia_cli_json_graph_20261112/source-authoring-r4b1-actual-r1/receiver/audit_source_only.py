"""Read the one frozen r4b1 source-only operation after proven owned closure.

No source import, generation, compiler, native image, process or old operation
is invoked. Original artifacts are never rewritten. A new audit is derivative
evidence; any original HOLD stays HOLD. A closed failed operation is still
inventoried before its failed classification is reported.
"""
from __future__ import annotations
import argparse
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1/source-authoring-r4b1')
LAUNCH_ROOT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-r4b1-source-actual-r1')
CANONICAL = '1cacd301013725b42380da34963ba4d9283fe927'
CANONICAL_TREE = '5bd0af76404d00148e7356690787aed7ab4c0da0'
REQUEST_SHA = '78b42eae2a35c0f2f1d579ec71fc044923d2edec99430279c3f528c512067bc7'
ROOT_PINS = {
    'INVOCATION-INTENT.json': '66d2250ba5c5ccfba9c5b2e40e15c86fe96cabec8769573986b7ac7c31207a3c',
    'INVOCATION-RETURN.json': '923b293d29a6150291505a8c16660facb250c3245f88a7cc3dc42e297d7be188',
    'PRETRIGGER.json': '84f25ff42396eebffa4c2dd657ccf1e644481159b9322f15f2c350061b349d55',
    'launcher.stdout.log': '190777457e8d218762f75d917fdfa445d3c28ca0ac319634da55ae068be91a15',
    'launcher.stderr.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
}
PYTHON = '/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3.12'
PYTHON_BYTES = 30894944
COMPONENTS = [('scalar', 'tools.generate_hia_cli_json_scalar'),
              ('py312_chunks', 'tools.generate_hia_cli_json_py312_chunks')]
LIMITS = {'source_bytes': 1 << 20, 'functions': 128, 'blocks_per_function': 256,
          'blocks_total': 1536, 'parameters_or_arguments': 16,
          'ssa_names_per_function': 2048, 'instruction_results': 3,
          'function_results': 3, 'instructions': 8192}


def identity(item):
    return [item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns]


def original(path, maximum=16 << 20):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute physical original path required')
    directories, links = [], []
    leaf = None
    try:
        directories.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for name in path.parts[1:-1]:
            parent = directories[-1]
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError('non-directory original parent')
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            directories.append(child)
            if identity(os.fstat(child)) != identity(before):
                raise ValueError('original parent changed')
            links.append((parent, name, child, identity(before)))
        parent = directories[-1]
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > maximum):
            raise ValueError('original must be bounded regular and single linked: ' + str(path))
        leaf = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        if identity(os.fstat(leaf)) != identity(before):
            raise ValueError('original descriptor differs')
        chunks, remaining = [], before.st_size
        while remaining:
            part = os.read(leaf, min(remaining, 1 << 16))
            if not part:
                raise ValueError('original ended before its extent')
            chunks.append(part)
            remaining -= len(part)
        if os.read(leaf, 1):
            raise ValueError('original grew')
        if (identity(os.fstat(leaf)) != identity(before)
                or identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != identity(before)):
            raise ValueError('original identity changed')
        for parent_fd, name, descriptor, pin in links:
            if (identity(os.fstat(descriptor)) != pin
                    or identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != pin):
                raise ValueError('original physical parent changed')
        raw = b''.join(chunks)
        return raw, {'path': str(path), 'bytes': len(raw),
                     'sha256': sha256(raw).hexdigest(), 'identity': identity(before)}
    finally:
        if leaf is not None:
            os.close(leaf)
        for descriptor in reversed(directories):
            os.close(descriptor)


def strict_json(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            if key in value:
                raise ValueError('duplicate original JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite original JSON')))


def namespace(root):
    result = {}
    def visit(path):
        for child in sorted(path.iterdir()):
            item = child.lstat()
            name = child.relative_to(root).as_posix()
            if stat.S_ISDIR(item.st_mode):
                visit(child)
            elif stat.S_ISREG(item.st_mode):
                result[name] = original(child)
            else:
                raise ValueError('unexpected original physical member: ' + name)
    visit(root)
    return result


def measurements(document, assembly):
    rows = []
    for function in document['functions']:
        names = {x['name'] for x in function['params']}
        params, args, results, instructions = len(function['params']), 0, 0, 0
        for block in function['blocks']:
            names.update(x['name'] for x in block['params'])
            params = max(params, len(block['params']))
            for instruction in block['ops']:
                names.update(x['name'] for x in instruction['out'])
                args = max(args, len(instruction['args']))
                results = max(results, len(instruction['out']))
                instructions += 1
            end = block['term']
            if end['op'] == 'branch':
                args = max(args, len(end['then']['args']), len(end['else']['args']))
            elif end['op'] == 'jump':
                args = max(args, len(end['args']))
            elif end['op'] == 'ret':
                args = max(args, len(end['values']))
        rows.append({'name': function['name'], 'blocks': len(function['blocks']),
                     'operations': instructions, 'ssa_names': len(names), 'parameters': params,
                     'arguments': args, 'instruction_results': results,
                     'function_results': len(function['returns'])})
    observed = {'source_bytes': len(assembly), 'functions': len(rows),
                'blocks_per_function': max(x['blocks'] for x in rows),
                'blocks_total': sum(x['blocks'] for x in rows),
                'parameters_or_arguments': max(max(x['parameters'], x['arguments']) for x in rows),
                'ssa_names_per_function': max(x['ssa_names'] for x in rows),
                'instruction_results': max(x['instruction_results'] for x in rows),
                'function_results': max(x['function_results'] for x in rows),
                'instructions': sum(x['operations'] for x in rows)}
    return {'actual': observed, 'functions': rows, 'limits': LIMITS,
            'source_lines_diagnostic': len(assembly.splitlines()),
            'compiler_line_gate_executed': False,
            'within_limits': all(value <= LIMITS[key] for key, value in observed.items())}


def audit():
    result = {'schema': 'hia.cli-json.r4b1.source-only.readonly-audit.v1', 'status': 'HOLD',
              'checks': [], 'errors': [], 'originals': {}, 'component_metrics': [],
              'original_failures': [],
              'source_only': True, 'source_imported_or_generated': False, 'native_executed': False,
              'original_17_executed': 0, 'trace_46_executed': 0, 'compiler_line_gate_executed': False,
              'original_status_reclassified': False, 'child_outputs_read': False}
    def check(value, label):
        result['checks'].append({'name': label, 'passed': bool(value)})
        if not value:
            result['errors'].append(label)
    def read(path, maximum=16 << 20):
        raw, record = original(path, maximum)
        result['originals'][str(path)] = record
        return raw
    try:
        request_raw = read(ROOT / 'guardian/REQUEST.json')
        check(sha256(request_raw).hexdigest() == REQUEST_SHA, 'frozen original request SHA')
        request = strict_json(request_raw)
        guard = strict_json(read(ROOT / 'guardian/guardian.json'))
        check(guard['schema'] == 'hepta.hia.external-qualification-guardian.v1', 'guardian schema')
        check(guard['command'] == request['command'] and guard['cwd'] == request['cwd'], 'guardian original command and cwd')
        check(guard['external_controller_seconds'] == request['controller_seconds'] == 180, 'unchanged 180 owner')
        life = guard['lifecycle']
        cleanup = life['cleanup']
        closed = (cleanup.get('complete') is True and cleanup.get('observed_echild') is True
                  and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
                  and cleanup.get('errors') == [] and life.get('cleanup_seconds') == 3)
        check(closed, 'closed ECHILD before any worker output read')
        if not closed or result['errors']:
            return result
        originals = namespace(ROOT / 'actual')
        result['child_outputs_read'] = True
        result['actual_namespace'] = {name: record for name, (_, record) in originals.items()}
        expected_names = {'REPORT.json', 'source.before.json', 'source.after.json'}
        expected_names.update(name + suffix for name, _ in COMPONENTS
                              for suffix in ('.authoring.py.txt', '.document.json', '.hiaasm',
                                             '.verified.json', '.caps.json'))
        check(set(originals) == expected_names and len(originals) == 13,
              'all thirteen exact successful worker originals')
        check(set(namespace(ROOT / 'guardian')) ==
              {'REQUEST.json', 'guardian.json', 'child.stdout.log', 'child.stderr.log'},
              'four exact original guardian and request files')
        check(len(request['source_identities']) == 174, 'complete fixed input denominator 174')
        for path, expected in request['source_identities'].items():
            maximum = PYTHON_BYTES if path == PYTHON else 16 << 20
            check(sha256(read(Path(path), maximum)).hexdigest() == expected, 'fixed input ' + path)
        check(guard['input_identity_preserved'] is True
              and guard['source_identities_before'] == guard['source_identities_after'] == request['source_identities'],
              'guardian complete before/after fixed inputs')
        for name in ('child.stdout.log', 'child.stderr.log'):
            path = ROOT / 'guardian' / name
            raw = read(path)
            check(guard['logs'][str(path)] == sha256(raw).hexdigest(), 'guardian original ' + name)
        config_raw = read(ROOT / 'control/CONFIG.json')
        config = strict_json(config_raw)
        check(config['components'] == [list(x) for x in COMPONENTS] and config['limits'] == LIMITS,
              'exact two components and nine original caps')
        check(len(config['source_pins']) == 167
              and sum(x['bytes'] for x in config['source_pins'].values()) == 2632579, 'full source denominator')
        report = strict_json(originals['REPORT.json'][0])
        result['observed_worker_status'] = report.get('status')
        result['observed_guardian_status'] = guard.get('status')
        check(report['schema'] == 'hia.cli-json.source-authoring.r4b.v1', 'worker schema')
        check(report['configuration']['sha256'] == sha256(config_raw).hexdigest()
              and report['configuration']['bytes'] == len(config_raw)
              and report['configuration']['path'] == str(ROOT / 'control/CONFIG.json'), 'actual configuration binding')
        check(report['native_executed'] is False and report['product_callers_executed'] is False
              and report['counts_are_plan_only'] is True, 'no product or caller execution')
        check(report['original_cli_ids'] == config['original_cli_ids'] and len(report['original_cli_ids']) == 17
              and report['trace_plan_ids'] == config['trace_plan_ids'] and len(report['trace_plan_ids']) == 46,
              '17 original callers and 46 traces preserved as plan only')
        before = strict_json(originals['source.before.json'][0])
        after = strict_json(originals['source.after.json'][0])
        check(before == after and set(before) == set(config['source_pins']), 'full original source identity before/after')
        source = namespace(ROOT / 'source')
        check(set(source) == set(config['source_pins']), 'physical source member set')
        for name, expected in config['source_pins'].items():
            raw, record = source[name]
            check(record['bytes'] == expected['bytes'] and record['sha256'] == expected['sha256']
                  and record == before[name], 'source physical byte and identity ' + name)
        for name in ('source_before', 'source_after'):
            record = report[name]
            actual = originals['source.' + name.split('_')[1] + '.json'][1]
            check(actual == record, 'worker ' + name + ' actual record')
        check(all(path in config['source_pins'] for path in report['actual_repository_modules'].values()),
              'every actual repository import pinned')
        check([(row['name'], row['module']) for row in report['components']] == COMPONENTS,
              'exact ordered two attempted components')
        for row in report['components']:
            label = row['name']
            if row['status'] != 'SOURCE_CORE_AND_CAPS_PASS_NOT_NATIVE':
                result['original_failures'].append({'component': label, 'status': row['status'],
                                                    'error': row.get('error')})
                check(row['status'] == 'HOLD' and row['error'] is not None,
                      label + ' original failure classification')
                for field, suffix in [('authoring_source', '.authoring.py.txt'), ('traceback', '.error.txt')]:
                    check(row[field] == originals[label + suffix][1], label + ' failed actual ' + field)
                continue
            check(row['error'] is None, label + ' original successful component')
            for field, suffix in [('authoring_source', '.authoring.py.txt'), ('document', '.document.json'),
                                  ('assembly', '.hiaasm'), ('verified_document', '.verified.json'), ('caps', '.caps.json')]:
                check(row[field] == originals[label + suffix][1], label + ' actual ' + field)
            document = strict_json(originals[label + '.verified.json'][0])
            measure = measurements(document, originals[label + '.hiaasm'][0])
            check(measure == strict_json(originals[label + '.caps.json'][0]) and measure['within_limits'] is True,
                  label + ' independently recomputed nine caps')
            check(document == strict_json(originals[label + '.document.json'][0]), label + ' full original and verified documents')
            result['component_metrics'].append({'name': label, **measure['actual'],
                                                'source_lines_diagnostic': measure['source_lines_diagnostic']})
        events = life['events']
        expected_kinds = ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped']
        check([x['kind'] for x in events] == expected_kinds and events[2]['si_status'] == life['returncode']
              and events[3]['returncode'] == life['returncode'] and all(x['pid'] == life['qualification_pid'] for x in events),
              'natural four events and same leader')
        check(type(life['returncode']) is int and life['returncode'] in (0, 1)
              and life['status'] == ('OWNED_PROCESS_COMPLETED' if life['returncode'] == 0 else 'QUALIFICATION_FAILED')
              and life['exit_observed_before_deadline'] is True
              and life['timed_out'] is False and life['interrupted_signals'] == []
              and life.get('owner_error') is None and life['event_overflow'] is False,
              'owner natural terminal result')
        check(life['qualification_seconds'] == 180 and life['qualification_started'] is True
              and life['subreaper_enabled'] is True and cleanup['deadline_exceeded'] is False
              and cleanup['elapsed_ns'] < 3000000000, 'actual owner and cleanup fixed budgets')
        check(guard['lifecycle_implementation_sha256'] == request['source_identities'][
                  str(ROOT / 'control/process_owner_impl.py')]
              and guard['qualification'] is None and guard['whole_native_delivery_qualified'] is False
              and guard['cold_180_second_gate_modified'] is False,
              'original owner implementation and source-only qualification scope')
        result['worker_elapsed_ns'] = report['elapsed_ns']
        result['owner_event_elapsed_ns'] = events[2]['monotonic_ns'] - events[0]['monotonic_ns']
        check(report['elapsed_ns'] < 180000000000 and result['owner_event_elapsed_ns'] < 180000000000,
              'actual source and owner within fixed deadline')
        outcome_pass = (report['status'] == 'TWO_NEW_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN'
                        and report['errors'] == [] and guard['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
                        and life['returncode'] == 0 and not result['original_failures'])
        result['both_original_result_layers_passed'] = outcome_pass
        if not outcome_pass:
            check(report['status'] == 'HOLD' and guard['status'] == 'HOLD' and life['returncode'] == 1,
                  'unchanged original HOLD classification')
        check(sha256(originals['REPORT.json'][0]).hexdigest() ==
              'bf12e2a33d694b66e10d75bd02a3ac3c2591cf9f00f764fd98894bcf329e59d9',
              'actual root reported worker bytes')
        check(result['originals'][str(ROOT / 'guardian/guardian.json')]['sha256'] ==
              '2465199803032cf95610933b158ddcaedbdb6b836746682356ec0b7a3b31878b',
              'actual root reported guardian bytes')
        root_originals = namespace(LAUNCH_ROOT)
        result['root_launch_namespace'] = {name: record for name, (_, record) in root_originals.items()}
        check(set(root_originals) == set(ROOT_PINS) and len(root_originals) == 5,
              'all five exact root launch originals')
        for name, digest in ROOT_PINS.items():
            raw, record = root_originals[name]
            result['originals'][record['path']] = record
            check(sha256(raw).hexdigest() == digest, 'root original pin ' + name)
        intent = strict_json(root_originals['INVOCATION-INTENT.json'][0])
        returned = strict_json(root_originals['INVOCATION-RETURN.json'][0])
        pretrigger = strict_json(root_originals['PRETRIGGER.json'][0])
        preexec_raw = read(ROOT / 'PREEXEC.json')
        preexec = strict_json(preexec_raw)
        check(intent['unique_invocation'] is True and intent['request_sha256'] == REQUEST_SHA
              and intent['command'] == preexec['command']
              and intent['cwd'] == preexec['cwd'] == request['cwd']
              and intent['environment'] == preexec['environment'] ==
              {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '/usr/bin:/bin'},
              'original single root invocation matches frozen launch')
        check(returned['returncode'] == life['returncode'] == 0
              and type(returned['returncode']) is int
              and returned['time_ns'] > intent['time_ns'], 'actual normal root return receipt')
        for name, field in [('launcher.stdout.log', 'launcher_stdout'),
                            ('launcher.stderr.log', 'launcher_stderr')]:
            raw, record = root_originals[name]
            actual = {**record, 'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
            check(actual == returned[field], 'root returned actual log ' + name)
        check(root_originals['launcher.stderr.log'][0] == b'', 'root stderr remains empty')
        launcher_lines = [strict_json(line) for line in root_originals['launcher.stdout.log'][0].splitlines()]
        check(launcher_lines == [
            {'stage': 'external_guardian_starting', 'supervisor_pid': life['supervisor_pid'],
             'controller_seconds': 180, 'child_stdout': str(ROOT / 'guardian/child.stdout.log'),
             'receipt': str(ROOT / 'guardian/guardian.json')},
            {'stage': 'external_guardian_finished', 'status': guard['status'],
             'lifecycle_status': life['status'], 'cleanup_complete': True,
             'observed_echild': True, 'receipt': str(ROOT / 'guardian/guardian.json')},
        ], 'both complete original launcher records match actual owner')
        child_line = strict_json(read(ROOT / 'guardian/child.stdout.log'))
        check(child_line == {'output': str(ROOT / 'actual'), 'schema': report['schema'],
                             'status': report['status']}, 'complete original child stdout binds actual report')
        check(pretrigger['schema'] == 'hia.root.cli-r4b1.source-pretrigger.v1'
              and pretrigger['status'] == 'PASS_FOR_TWO_NEW_SOURCE_COMPONENTS_ONLY'
              and pretrigger['canonical_commit'] == CANONICAL
              and pretrigger['canonical_tree'] == CANONICAL_TREE
              and pretrigger['owner_seconds'] == 180 and pretrigger['cleanup_seconds'] == 3
              and pretrigger['components'] == config['components'] and pretrigger['limits'] == LIMITS
              and pretrigger['native_executed'] is False
              and pretrigger['old_four_regenerated'] is False
              and pretrigger['whole_rewrite_closed'] is False, 'root pretrigger scope and canonical identities')
        check(len(pretrigger['inputs']) == 174
              and len({x['path'] for x in pretrigger['inputs']}) == 174
              and {x['path'] for x in pretrigger['inputs']} == set(request['source_identities']),
              'root pretrigger exact 174 input set')
        for expected in pretrigger['inputs']:
            path = Path(expected['path'])
            raw, record = original(path, PYTHON_BYTES if str(path) == PYTHON else 16 << 20)
            actual = {**record, 'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
            check(actual == expected, 'root input complete bytes and identity ' + str(path))
        for label, raw in [('request', request_raw), ('preexec', preexec_raw)]:
            path = str(ROOT / ('guardian/REQUEST.json' if label == 'request' else 'PREEXEC.json'))
            actual = {**result['originals'][path],
                      'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
            check(actual == pretrigger[label], 'root pretrigger original ' + label)
        check(len(pretrigger['canonical_leaves_verified']) == 195
              and len({x['path'] for x in pretrigger['canonical_leaves_verified']}) == 195,
              'root complete 195 canonical new leaves recorded')
        for expected in pretrigger['canonical_leaves_verified']:
            raw, record = original(Path(expected['path']))
            actual = {**record, 'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
            check(actual == expected, 'root canonical leaf complete bytes and identity ' + expected['path'])
        final_actual = namespace(ROOT / 'actual')
        final_guardian = namespace(ROOT / 'guardian')
        final_launch = namespace(LAUNCH_ROOT)
        check(final_actual == originals, 'all thirteen actual original bytes and identities still stable')
        check(all(record == result['originals'][str(ROOT / 'guardian' / name)]
                  for name, (_, record) in final_guardian.items()), 'all four guardian originals still stable')
        check(final_launch == root_originals, 'all five root originals still stable')
        result['launcher_return_record_existed'] = True
        result['launcher_original_subprocess_returncode_serialized'] = returned['returncode']
        result['previous_failed_operation_preserved'] = '60e30e1bd5ad5a7434ea0019767e5c9210e32be7'
        result['canonical_source_request'] = {'commit': CANONICAL, 'tree': CANONICAL_TREE}
        if not result['errors']:
            result['status'] = ('READONLY_TWO_NEW_SOURCE_COMPONENTS_PASS' if outcome_pass
                                else 'CLOSED_SOURCE_FAILURE_ORIGINALS_VERIFIED')
    except BaseException as error:
        result['errors'].append({'type': type(error).__name__, 'message': str(error)})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.exists():
        raise ValueError('fresh absolute derivative audit directory required')
    result = audit()
    os.mkdir(args.output, 0o700)
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    path = args.output / 'AUDIT.json'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError('short audit write')
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    actual, record = original(path)
    if actual != raw:
        raise ValueError('derivative audit readback differs')
    print(json.dumps({'status': result['status'], 'checks': len(result['checks']),
                      'errors': result['errors'], 'audit': record}, sort_keys=True))
    return 0 if result['status'] in ('READONLY_TWO_NEW_SOURCE_COMPONENTS_PASS',
                                     'CLOSED_SOURCE_FAILURE_ORIGINALS_VERIFIED') else 1


if __name__ == '__main__':
    raise SystemExit(main())
