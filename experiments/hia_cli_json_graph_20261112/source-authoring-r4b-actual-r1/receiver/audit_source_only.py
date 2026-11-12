"""Read the one frozen r4b source-only operation after proven owned closure.

No source import, generation, compiler, native image, process or old operation
is invoked. Original artifacts are never rewritten. A new audit is derivative
evidence; any original HOLD stays HOLD. A closed failed operation is still
inventoried before its failed classification is reported.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1/source-authoring-r4b')
REQUEST_SHA = 'c9bd5dc9820d1d1774314446b3b1dd4c2c7e584d2bc64a26d2cd7342fee10cbb'
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
    result = {'schema': 'hia.cli-json.r4b.source-only.readonly-audit.v1', 'status': 'HOLD',
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
              and sum(x['bytes'] for x in config['source_pins'].values()) == 2631235, 'full source denominator')
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
        reconciliation_path = Path('/workspace/scratch/e26ed3e2edcf/root/cli-r4b-source-actual-r1/RECONCILIATION.json')
        reconciliation_raw = read(reconciliation_path)
        check(sha256(reconciliation_raw).hexdigest() == '44b924e7af315a8cdfbd2fbc539c8cb2f3d3d28c80a9d8fc10d156e1e905762f',
              'root original launcher reconciliation pin')
        reconciliation = strict_json(reconciliation_raw)
        check(reconciliation['invocation_repeated'] is False
              and reconciliation['original_owner_returncode'] == life['returncode']
              and reconciliation['guardian']['sha256'] == result['originals'][str(ROOT / 'guardian/guardian.json')]['sha256']
              and reconciliation['worker']['sha256'] == originals['REPORT.json'][1]['sha256'],
              'root reconciliation binds same original failed operation')
        result['launcher_reporting_bug'] = reconciliation['wrapper_reporting_bug']
        result['launcher_return_record_existed'] = reconciliation['wrapper_return_record_existed']
        result['launcher_original_subprocess_returncode_serialized'] = reconciliation['external_guardian_subprocess_returncode_serialized_by_wrapper']
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
