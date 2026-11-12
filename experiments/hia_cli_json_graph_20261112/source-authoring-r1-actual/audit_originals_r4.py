"""Read and preserve the closed, failed source-only request; no product imports."""
from __future__ import annotations

import io
import json
import os
from hashlib import sha1, sha256
from pathlib import Path
import stat
import tarfile

HERE = Path(__file__).absolute().parent
RUN = HERE.parent / 'source-authoring-r1'
PREFIX = 'experiments/hia_cli_json_graph_20261112/source-authoring-r1-actual'
checks = []


def wire(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + '\n').encode()


def require(condition, label):
    checks.append({'check': label, 'pass': bool(condition)})
    if not condition:
        raise ValueError(label)


def identity(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read(path, *, caller_owned=True):
    named = path.lstat()
    require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and (named.st_uid == os.getuid() if caller_owned else not (named.st_mode & 0o022)),
            ('regular owned single-link: ' if caller_owned else 'fixed runtime regular single-link without group/world write: ') + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(identity(before) == identity(named), 'opened identity: ' + str(path))
        parts = []
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            parts.append(chunk)
        raw = b''.join(parts)
        require(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()) and len(raw) == before.st_size,
                'complete stable read: ' + str(path))
    finally:
        os.close(fd)
    return {'path': str(path), 'identity': identity(before), **pin(raw)}, raw


def create(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)
    record, actual = read(path)
    require(actual == raw, 'copy readback: ' + str(path))
    return record


def measured(document, assembly):
    rows = []
    for fn in document['functions']:
        names = {v['name'] for v in fn['params']}
        params, arguments, outputs, operations = len(fn['params']), 0, 0, 0
        for block in fn['blocks']:
            names.update(v['name'] for v in block['params'])
            params = max(params, len(block['params']))
            for op in block['ops']:
                names.update(v['name'] for v in op['out'])
                arguments, outputs = max(arguments, len(op['args'])), max(outputs, len(op['out']))
                operations += 1
            term = block['term']
            groups = ([term['args']] if term['op'] == 'jump' else
                      [term['then']['args'], term['else']['args']] if term['op'] == 'branch' else
                      [term['values']] if term['op'] == 'ret' else [])
            arguments = max([arguments] + [len(group) for group in groups])
        rows.append({'name': fn['name'], 'blocks': len(fn['blocks']), 'operations': operations,
                     'ssa_names': len(names), 'parameters': params, 'arguments': arguments,
                     'instruction_results': outputs, 'function_results': len(fn['returns'])})
    actual = {'source_bytes': len(assembly), 'functions': len(rows),
              'blocks_per_function': max(row['blocks'] for row in rows),
              'blocks_total': sum(row['blocks'] for row in rows),
              'parameters_or_arguments': max(max(row['parameters'], row['arguments']) for row in rows),
              'ssa_names_per_function': max(row['ssa_names'] for row in rows),
              'instruction_results': max(row['instruction_results'] for row in rows),
              'function_results': max(row['function_results'] for row in rows),
              'instructions': sum(row['operations'] for row in rows)}
    return actual, rows


def main():
    originals = {}
    paths = sorted((RUN / 'actual-r1').iterdir()) + [RUN / 'guardian-r1' / name for name in
             ['REQUEST.json', 'child.stderr.log', 'child.stdout.log', 'guardian.json']]
    require(len(paths) == 25, 'complete original physical 25-member set')
    records = {}
    for path in paths:
        name = path.relative_to(RUN).as_posix()
        record, raw = read(path)
        records[name] = record
        originals[name] = raw
    report = json.loads(originals['actual-r1/REPORT.json'])
    guard = json.loads(originals['guardian-r1/guardian.json'])
    request = json.loads(originals['guardian-r1/REQUEST.json'])
    config_record, config_raw = read(RUN / 'control/CONFIG.json')
    config = json.loads(config_raw)
    preexec_record, preexec_raw = read(RUN / 'PREEXEC.json')
    preexec = json.loads(preexec_raw)
    require(report['status'] == guard['status'] == 'HOLD', 'original whole-request HOLD remains HOLD')
    require(report['native_executed'] is False and report['product_callers_executed'] is False and
            report['counts_are_plan_only'] is True, 'no native or original caller execution')
    require(all(report['configuration'][key] == config_record[key] for key in ('path', 'bytes', 'sha256', 'identity')), 'report joins actual configuration bytes and identity')
    require(request['command'] == guard['command'] and request['cwd'] == guard['cwd'], 'guardian actual command and cwd')
    require(preexec['request']['sha256'] == records['guardian-r1/REQUEST.json']['sha256'], 'exact frozen request SHA')
    require(request['controller_seconds'] == guard['external_controller_seconds'] == 180, 'original source-only 180 seconds')
    life = guard['lifecycle']
    cleanup = life['cleanup']
    require(life['returncode'] == 1 and life['status'] == 'QUALIFICATION_FAILED', 'actual child exit one')
    require(life['qualification_started'] is True and life['timed_out'] is False and
            life['exit_observed_before_deadline'] is True and life['interrupted_signals'] == [] and
            life['event_overflow'] is False, 'natural failed child without timeout or interrupt')
    require(cleanup['complete'] is True and cleanup['observed_echild'] is True and
            cleanup['leader_reaped'] is True and cleanup['remaining_direct_children'] == [] and
            cleanup['errors'] == [] and cleanup['deadline_exceeded'] is False and life['cleanup_seconds'] == 3,
            'complete original three-second cleanup with ECHILD')
    events = life['events']
    require([row['kind'] for row in events] == ['qualification_started', 'owned_child_observed',
            'qualification_exit_observed', 'owned_child_reaped'], 'four natural events, no signal cleanup')
    require(guard['input_identity_preserved'] is True and
            guard['source_identities_before'] == guard['source_identities_after'] == request['source_identities'],
            'all original fixed input hashes preserved')
    for path, digest in request['source_identities'].items():
        record, _ = read(Path(path), caller_owned=(path != preexec['python']['path']))
        require(record['sha256'] == digest, 'current exact request input: ' + path)
    require(len(request['source_identities']) == 165 and len(config['source_pins']) == 160,
            'complete 165 fixed inputs and 160 source leaves')
    for path, digest in guard['logs'].items():
        require(records[Path(path).relative_to(RUN).as_posix()]['sha256'] == digest, 'guardian raw log binding: ' + path)
    before = json.loads(originals['actual-r1/source.before.json'])
    after = json.loads(originals['actual-r1/source.after.json'])
    require(before == after and sorted(before) == sorted(config['source_pins']), 'full source namespace and identity stable')
    for name, expected in config['source_pins'].items():
        require(all(before[name][key] == expected[key] for key in ('bytes', 'sha256')), 'source snapshot pin: ' + name)
    require(report['original_cli_ids'] == config['original_cli_ids'] == preexec['preserved_not_run']['original_cli_ids'] and
            len(report['original_cli_ids']) == len(set(report['original_cli_ids'])) == 17, 'original 17 IDs retained, not run')
    require(report['trace_plan_ids'] == config['trace_plan_ids'] == preexec['preserved_not_run']['trace_plan_ids'] and
            len(report['trace_plan_ids']) == len(set(report['trace_plan_ids'])) == 46, 'planned 46 traces retained, not run')
    require([row['name'] for row in report['components']] == ['text', 'sort', 'note', 'cgraph'],
            'all four components attempted in frozen order')
    summaries = []
    for row in report['components']:
        for key, value in row.items():
            if isinstance(value, dict) and {'path', 'bytes', 'sha256', 'identity'} <= value.keys():
                relative = Path(value['path']).relative_to(RUN).as_posix()
                require(all(records[relative][k] == value[k] for k in ('path', 'bytes', 'sha256', 'identity')),
                        row['name'] + ' original ' + key + ' full binding')
        summary = {'name': row['name'], 'actual_status': row['status'], 'elapsed_ns': row['elapsed_ns'],
                   'error': row.get('error')}
        if row['name'] == 'sort':
            require(row['status'] == 'HOLD' and row['error']['type'] == 'HIAProgramRejected' and
                    row['error']['message'] == "E_HIA_TYPE: buffer.copy_range: operand types must match ('mutbuf', 'readbuf', 'usize', 'usize', 'usize')",
                    'exact real sort type rejection retained')
            require(all('actual-r1/sort.' + suffix not in originals for suffix in
                        ('document.json', 'verified.json', 'hiaasm', 'caps.json')), 'no fabricated missing sort generated files')
        else:
            require(row['status'] == 'SOURCE_CORE_AND_CAPS_PASS_NOT_NATIVE' and row['error'] is None,
                    row['name'] + ' local source-only status')
            base = 'actual-r1/' + row['name']
            require(originals[base + '.document.json'] == originals[base + '.verified.json'],
                    row['name'] + ' full round-trip bytes equal')
            caps = json.loads(originals[base + '.caps.json'])
            actual, functions = measured(json.loads(originals[base + '.document.json']), originals[base + '.hiaasm'])
            require(caps['actual'] == actual and caps['functions'] == functions and caps['limits'] == config['limits'] and
                    caps['within_limits'] is True and all(actual[k] <= config['limits'][k] for k in actual),
                    row['name'] + ' nine recorded structural caps independently recounted')
            summary.update(assembly=pin(originals[base + '.hiaasm']), caps=actual,
                           assembly_lines_diagnostic_only=len(originals[base + '.hiaasm'].splitlines()))
        summaries.append(summary)
    sdk_records = {}
    for name in ('EXEC.original.sdk.json', 'TERMINAL.original.sdk.json'):
        record, raw = read(HERE / name)
        sdk_records[name] = record
        originals['sdk/' + name] = raw
    terminal = json.loads(originals['sdk/TERMINAL.original.sdk.json'])
    require(terminal['exit_code'] == 1, 'original terminal tool SDK exit code')
    archive_path = HERE / 'ORIGINALS.tar.xz'
    with archive_path.open('xb') as stream:
        with tarfile.open(fileobj=stream, mode='w:xz', preset=1, format=tarfile.PAX_FORMAT) as archive:
            for name, raw in sorted(originals.items()):
                item = tarfile.TarInfo(name)
                item.mode, item.mtime, item.uid, item.gid, item.size = 0o600, 0, 0, 0, len(raw)
                archive.addfile(item, io.BytesIO(raw))
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(archive_path, 0o600)
    archive_record, _ = read(archive_path)
    with tarfile.open(archive_path, 'r:xz') as archive:
        members = archive.getmembers()
        require([m.name for m in members] == sorted(originals), 'archive complete unique 27-member set')
        for member in members:
            require(member.isfile() and archive.extractfile(member).read() == originals[member.name],
                    'full archive member readback: ' + member.name)
    # Keep useful original text directly readable in Git; every larger document is
    # preserved without loss in ORIGINALS.tar.xz, with its original hash above.
    raw_records = {}
    for name, raw in originals.items():
        if name.startswith('sdk/') or name.endswith(('.document.json', '.verified.json')):
            continue
        raw_records[name] = create(HERE / 'raw' / name, raw)
    index = {'schema': 'hia.cli-json.source-authoring.actual-original-index.v1',
             'original_run_members': records, 'tool_sdk_originals': sdk_records,
             'complete_archive': archive_record, 'raw_readable_copies': raw_records,
             'archive_members': {name: pin(raw) for name, raw in sorted(originals.items())}}
    index_record = create(HERE / 'ORIGINALS.json', wire(index))
    audit = {'schema': 'hia.cli-json.source-authoring.actual-readback.v1',
             'status': 'READBACK_COMPLETE_ORIGINAL_SOURCE_ONLY_HOLD',
             'frozen_commit': '2620fc07a169b3e15cf6a9615b20d27fb9d59db8',
             'root_authorization': '0b04f68e9d91592ccd59aab898573b615e76ecf3',
             'original_status': 'HOLD', 'original_component_count': 4, 'component_observations': summaries,
             'native_executed': False, 'original_cli_executed': 0, 'planned_trace_cases_executed': 0,
             'original_cli_ids': report['original_cli_ids'], 'trace_plan_ids': report['trace_plan_ids'],
             'worker_elapsed_ns': report['elapsed_ns'],
             'owner_start_to_exit_observed_ns': events[2]['monotonic_ns'] - events[0]['monotonic_ns'],
             'natural_cleanup': {'complete': True, 'observed_echild': True, 'leader_reaped': True,
                                 'events': [e['kind'] for e in events], 'kill_events': []},
             'caps_scope': 'Only the nine listed structural metrics; 16384-line gate, native compilation and full compiler admission were not executed.',
             'scope_exclusions': ['No sorting equivalence', 'No complete graph equivalence', 'No installation or public selection',
                                  'No old UNKNOWN operation queried or replayed'],
             'index': index_record, 'preexec': preexec_record, 'checks': checks}
    audit_record = create(HERE / 'AUDIT.json', wire(audit))
    handoff = {'schema': 'hia.cli-json.source-authoring.hold-handoff.v1', 'status': audit['status'],
               'prefix': PREFIX, 'audit': audit_record, 'originals_index': index_record,
               'archive': archive_record, 'runtime_files': len(records),
               'runtime_bytes': sum(r['bytes'] for r in records.values()),
               'archive_members': len(originals), 'archive_member_bytes': sum(map(len, originals.values())),
               'root_next_step': 'Review a new isolated cross-buffer borrow.read/copy_range/loan.end source revision; original four-component HOLD remains unchanged.'}
    create(HERE / 'HANDOFF.json', wire(handoff))
    print(json.dumps({'status': audit['status'], 'checks': len(checks), 'archive': pin(archive_path.read_bytes()),
                      'runtime_files': len(records), 'runtime_bytes': handoff['runtime_bytes'],
                      'component_statuses': [[r['name'], r['actual_status']] for r in summaries]}, sort_keys=True))


if __name__ == '__main__':
    main()
