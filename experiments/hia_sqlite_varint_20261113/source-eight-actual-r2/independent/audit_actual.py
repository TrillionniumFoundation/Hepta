"""Read the one closed SQLite source8 r2 result; execute no project code."""
from __future__ import annotations
from collections import Counter
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import re
import stat
import traceback

HERE = Path(__file__).resolve().parent
REQUEST_ROOT = Path('/home/agent/hia-sqlite-source8-r2-recovery-20261113-e26e')
ACTUAL = Path('/home/agent/hia-sqlite-varint-source-eight-actual-r2-20261113-e26e')
ROOT_INVOCATION = Path('/workspace/scratch/e26ed3e2edcf/root/sqlite-varint-source8-r2-invocation')
ROOT_REVIEW = Path('/workspace/scratch/e26ed3e2edcf/root/sqlite-varint-source8-r2-review')
REQUEST_SHA = '7edf8b146dec5aa0acdfe75fa3dbd69aaae4916436de40736c237d2817fffcb7'
EXPECTED_FILES = {
    'CAPACITY-BEFORE.json', 'FINAL.json', 'INPUTS-AFTER.json', 'INPUTS-BEFORE.json',
    'ORIGINAL-CATALOG.json', 'OWNER-RETURN.json', 'REQUEST.original.json',
    'SOURCE-AFTER.json', 'SOURCE-BEFORE.json', 'lifecycle.json',
    'lifecycle.json.request.json', 'lifecycle.json.stderr.log',
    'lifecycle.json.stdout.log', 'stderr.log', 'stdout.log', 'tests/CORE.json',
    'tests/REPORT.json', 'tests/SOURCE-AFTER.json', 'tests/SOURCE-BEFORE.json',
    'tests/VM-RAW.json', 'tests/sqlite_varint.hiaasm', 'tests/unittest.log'}


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def read(path, maximum=64 << 20):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        check(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
              and 0 <= before.st_size <= maximum, 'regular bounded single-link: ' + str(path))
        body = stream.read(maximum + 1)
        check(len(body) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
              == identity(path.lstat()), 'identity changed: ' + str(path))
    return {'path': str(path), 'bytes': len(body), 'sha256': sha256(body).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest(),
            'identity': identity(before)}, body


def same_bytes(actual, expected):
    return all(actual[k] == expected[k] for k in ('bytes', 'sha256', 'git_blob'))


def dump(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    pin, checked = read(path)
    check(checked == raw, 'report readback')
    return pin


def independent_codec(source, before, command):
    """Closed-form base-128/base-256 arithmetic, not an imported implementation."""
    protocol, truncated, capacity = 0xfffffffd, 0xfffffffe, 0xfffffffc
    if len(command) != 16 or command[:8] != b'HIASVR01':
        return protocol, before
    operation = int.from_bytes(command[8:], 'little')
    if operation == 1:
        if len(source) > 9 or len(before) != 8:
            return protocol, before
        ending = next((i + 1 for i, b in enumerate(source[:8]) if b < 128), None)
        if ending is None:
            if len(source) < 9:
                return truncated, before
            value = sum((source[i] & 127) * (1 << (8 + 7 * (7-i))) for i in range(8)) + source[8]
            ending = 9
        else:
            value = sum((b & 127) * (1 << (7 * (ending-1-i))) for i, b in enumerate(source[:ending]))
        return ending, value.to_bytes(8, 'little')
    if operation == 2:
        if len(source) != 8 or len(before) > 9:
            return protocol, before
        value = int.from_bytes(source, 'little')
        if value >= 1 << 56:
            encoded = bytes(128 | ((value >> (8 + 7 * (7-i))) & 127) for i in range(8)) + bytes([value & 255])
        else:
            length = max(1, (value.bit_length() + 6) // 7)
            encoded = bytes(((value >> (7 * (length-1-i))) & 127) | (128 if i+1 < length else 0)
                            for i in range(length))
        if len(before) < len(encoded):
            return capacity, before
        return len(encoded), encoded + before[len(encoded):]
    return protocol, before


def main():
    result = {'schema': 'hia.sqlite-source8.independent-actual-audit.v1', 'status': 'HOLD',
              'request_commit': '045f1ae1e88f9be6680f618bf220857c42a4cbbb',
              'source_commit': '0504beb11c0dae875d8590660c42488b7bc634fb',
              'source_tree': '596ab07e8813e4811a8dca51800cd51eb397aeb2',
              'project_imported_or_executed_by_auditor': False,
              'native_C_SQL_network_or_product_replayed': False,
              'old_R4_owner': 'UNKNOWN_NOT_RECLASSIFIED', 'old_48_publication': 'UNKNOWN_NOT_REPLAYED',
              'errors': [], 'checks': []}
    try:
        request_pin, request_raw = read(REQUEST_ROOT / 'REQUEST.json')
        request = json.loads(request_raw)
        check(request_pin['sha256'] == REQUEST_SHA, 'canonical request SHA')
        check(request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3, 'original owner limits')
        # The bound original raw owner must close before the first child read.
        life_pin, life_raw = read(ACTUAL / 'lifecycle.json')
        life = json.loads(life_raw)
        owner_request_pin, owner_request_raw = read(ACTUAL / 'lifecycle.json.request.json')
        owner_request = json.loads(owner_request_raw)
        return_pin, return_raw = read(ACTUAL / 'OWNER-RETURN.json')
        returned = json.loads(return_raw)
        projected = dict(returned)
        supervisor = projected.pop('supervisor_returncode')
        digest = projected.pop('receipt_sha256')
        check(projected == life and type(supervisor) is int and supervisor == 0
              and digest == life_pin['sha256'], 'actual original owner/return full projection')
        check(owner_request['command'] == request['command'] and owner_request['cwd'] == str(REQUEST_ROOT)
              and owner_request['env'] == request['environment']
              and owner_request['qualification_seconds'] == 180 and owner_request['cleanup_seconds'] == 3
              and owner_request['receipt_path'] == str(ACTUAL / 'lifecycle.json')
              and owner_request['stdout_path'] == str(ACTUAL / 'stdout.log')
              and owner_request['stderr_path'] == str(ACTUAL / 'stderr.log')
              and owner_request['deadline_ns'] - owner_request['started_ns'] == 180_000_000_000,
              'raw owner request binds command/environment/cwd/paths/deadline')
        check(life['request_sha256'] == owner_request_pin['sha256']
              and life['implementation_sha256'] == request['inputs']['control/process_owner_impl.py']['sha256']
              == owner_request['implementation_sha256'] and life['schema'] == 'hepta.hia.selfhost-process-owner.v1'
              and life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3
              and life['subreaper_enabled'] is True and life['qualification_started'] is True
              and life['event_overflow'] is False and life['returncode'] == 0
              and life['status'] == 'OWNED_PROCESS_COMPLETED' and life['timed_out'] is False
              and life['exit_observed_before_deadline'] is True and life.get('owner_error') is None
              and life['interrupted_signals'] == [], 'natural current owner')
        cleanup = life['cleanup']
        check(all(cleanup[k] is True for k in ('attempted','complete','observed_echild','leader_reaped'))
              and cleanup['deadline_exceeded'] is False and cleanup['errors'] == []
              and cleanup['remaining_direct_children'] == [], 'bound ECHILD before child original reads')
        events = life['events']
        check([e['kind'] for e in events] == ['qualification_started','owned_child_observed',
              'qualification_exit_observed','owned_child_reaped']
              and all(e['pid'] == life['qualification_pid'] for e in events)
              and all(events[i]['monotonic_ns'] <= events[i+1]['monotonic_ns'] for i in range(3))
              and events[2]['monotonic_ns'] <= owner_request['deadline_ns'], 'four natural PID-bound events')
        result['checks'].append('CURRENT_OWNER_FULL_REQUEST_NATURAL_ZERO_AND_ECHILD')
        result['owner'] = {'receipt': life_pin, 'request': owner_request_pin, 'returned': return_pin,
                           'qualification_seconds':180, 'cleanup_seconds':3, 'events': events}

        observed = {}
        bodies = {}
        for path in sorted(ACTUAL.rglob('*')):
            item = path.lstat()
            check(not stat.S_ISLNK(item.st_mode), 'actual namespace symlink')
            if stat.S_ISDIR(item.st_mode):
                check(path == ACTUAL / 'tests', 'unexpected actual directory')
                continue
            name = str(path.relative_to(ACTUAL))
            observed[name], bodies[name] = read(path, 16 << 20)
        check(set(observed) == EXPECTED_FILES and len(observed) == 22
              and sum(p['bytes'] for p in observed.values()) == 4426961, 'whole actual22 namespace/bytes')
        check(bodies['REQUEST.original.json'] == request_raw, 'original request unchanged bytes')
        result['actual_files'] = observed
        result['actual_files_count'] = len(observed)
        result['actual_bytes'] = sum(p['bytes'] for p in observed.values())
        final = json.loads(bodies['FINAL.json'])
        report = json.loads(bodies['tests/REPORT.json'])
        catalog = json.loads(bodies['ORIGINAL-CATALOG.json'])
        check(catalog['after_current_ECHILD'] is True and catalog['complete_observed_namespace'] is True,
              'original catalog closure')
        catalog_rows = catalog['records']
        check(len(catalog_rows) == 18 and len({p['path'] for p in catalog_rows}) == 18,
              'original pre-final catalog has18 unique raw files')
        check(sum(p['bytes'] for p in catalog_rows) == catalog['regular_bytes'] == 3555614,
              'original catalog byte total')
        for pin in catalog_rows:
            name = str(Path(pin['path']).relative_to(ACTUAL))
            check(observed[name] == pin, 'full original catalog identity: ' + name)
        check({str(Path(p['path']).relative_to(ACTUAL)) for p in catalog_rows}
              == EXPECTED_FILES - {'ORIGINAL-CATALOG.json','FINAL.json','INPUTS-AFTER.json','SOURCE-AFTER.json'},
              'four later parent observations precisely distinguish final22')
        capacity = json.loads(bodies['CAPACITY-BEFORE.json'])
        check(capacity['free_bytes'] >= request['minimum_free_bytes'] == 256 << 20
              and capacity['free_inodes'] >= request['minimum_free_inodes'] == 4096,
              'actual original capacity admission')
        before = json.loads(bodies['INPUTS-BEFORE.json'])
        check(bodies['INPUTS-BEFORE.json'] == bodies['INPUTS-AFTER.json']
              and before == report['inputs_before'] == report['inputs_after']
              and set(before) == set(request['inputs']) and len(before) == 46, 'all46 frozen input observations')
        fresh_inputs = {}
        for name, expected in request['inputs'].items():
            pin, _ = read(REQUEST_ROOT / name)
            check(same_bytes(pin, expected) and pin == before[name], 'frozen input exact current identity: ' + name)
            fresh_inputs[name] = pin
        result['input_files_freshly_read'] = len(fresh_inputs)
        check(report['request'] == final['request'] == request_pin, 'worker/parent request identity')
        runtime_pin, _ = read(request['runtime']['path'])
        check(runtime_pin == request['runtime'] == report['runtime']
              and report['local_development_runtime'] == request['runtime_version'] == [3,12,14], 'runtime exact current identity')
        result['runtime'] = runtime_pin

        source_names = ('SOURCE-BEFORE.json','SOURCE-AFTER.json','tests/SOURCE-BEFORE.json','tests/SOURCE-AFTER.json')
        check(all(bodies[n] == bodies[source_names[0]] for n in source_names), 'four whole source observations equal')
        source_rows = json.loads(bodies[source_names[0]])
        source_map = json.loads(read(REQUEST_ROOT / request['source_map'])[1])
        source_expected = {p['path']:p for p in source_map['files']}
        check(len(source_map['files']) == len(source_expected) == len(source_rows) == 1686
              and set(source_expected) == set(source_rows), 'whole1686 exact source namespace')
        source_root = Path(request['source_root'])
        check({str(p.relative_to(source_root)) for p in source_root.rglob('*') if not p.is_dir()}
              == set(source_expected), 'physical source has no extra leaf')
        fresh_sources = {}
        for name, expected in source_expected.items():
            pin, _ = read(source_root / name)
            mode = '100755' if pin['identity'][2] & 0o111 else '100644'
            check(same_bytes(pin, expected) and mode == expected['mode'] and pin == source_rows[name],
                  'source actual/frozen/current bytes/mode/full identity: ' + name)
            fresh_sources[name] = pin
        check(sum(p['bytes'] for p in fresh_sources.values()) == request['source_total_bytes'] == 40890650,
              'source total bytes')
        check(source_map['commit'] == request['source_commit'] == result['source_commit']
              and source_map['tree'] == request['source_tree'] == result['source_tree'], 'current pure0504 source binding')
        check(report['source_before'] == observed['tests/SOURCE-BEFORE.json']
              and report['source_after'] == observed['tests/SOURCE-AFTER.json'], 'worker source original pins')
        result['source_fresh_read'] = {'files':len(fresh_sources),'bytes':sum(p['bytes'] for p in fresh_sources.values()),
                                       'manifest_pin':observed['SOURCE-BEFORE.json'],'records':fresh_sources}
        result['checks'].append('ALL22_OUTPUTS_46_INPUTS_AND1686_SOURCE_FULL_BYTES_MODE_IDENTITY')

        ids = request['expected_ids']
        check(len(ids) == len(set(ids)) == 8 and request['expected_methods'] == report['tests_run'] == 8,
              'source8 original denominator')
        for key in ('expected_ids','loaded_ids','actual_ids','success_ids'):
            check(report[key] == ids, 'ordered original method list: '+key)
        for key in ('errors','failures','skipped','expected_failures','unexpected_successes','denied_effects','secondary_errors'):
            check(report[key] == [], 'source anomalies: '+key)
        check(report['exception'] is None and report['status'] == 'SQLITE_VARINT_SOURCE_EIGHT_VM_PASS_ONLY',
              'worker semantic pass')
        for key in ('C_oracle_compiled','database_opened','native_compiler_executed','native_executed','network_used',
                    'old_source8_request_replayed','product_qualification_executed'):
            check(report[key] is False and final[key] is False, 'scope flag '+key)
        check(report['original_test_body_sha256'] == request['inputs']['candidate/inputs/tests/test_hia_sqlite_varint_source.py']['sha256']
              == '4101654ceaa24f564fbbb7f78e466bd340cde5d21fded2e206ee521c8e451af4', 'original8 bodies retained')
        import_pins = {p['path']:p for p in (*fresh_inputs.values(),*fresh_sources.values())}
        module_names = []
        for row in report['imports']:
            module_names.append(row['module'])
            if row.get('namespace_only') is True:
                check(row == {'module':'tools','namespace_only':True}, 'only original tools namespace is bodyless')
            else:
                check(row['source'] == import_pins[row['source']['path']], 'actually imported whole source pin')
        check(len(module_names) == len(set(module_names)) == 39 and request['test_module'] in module_names,
              '39 actual imports,38 source bodies plus original namespace')

        vm = json.loads(bodies['tests/VM-RAW.json'])
        check(vm['schema'] == 'hia.sqlite-varint.source-vm-raw.v1' and vm['native_executed'] is False
              and vm['compiler_executed'] is False and len(vm['calls']) == request['expected_vm_returns'] == 1618,
              'all1618 actual VM returns')
        counts = {name:0 for name in ids}
        statuses = Counter()
        sequence = []
        vm_fields = {'actual_returned','case','status','source_before_hex','source_after_hex',
                     'output_before_hex','output_after_hex','workspace_before_hex','workspace_after_hex'}
        for index, row in enumerate(vm['calls']):
            check(type(row) is dict and set(row) == vm_fields and row['actual_returned'] is True
                  and type(row['status']) is int and row['case'] in counts, 'actual VM row shape '+str(index))
            buffers = {}
            for key in vm_fields - {'actual_returned','case','status'}:
                raw = bytes.fromhex(row[key]);check(raw.hex() == row[key], 'canonical complete buffer hex')
                buffers[key] = raw
            source, before, command = (buffers[k] for k in ('source_before_hex','output_before_hex','workspace_before_hex'))
            check(source == buffers['source_after_hex'] and command == buffers['workspace_after_hex']
                  and len(before) == len(buffers['output_after_hex']), 'whole input/control/output extents')
            status, expected_output = independent_codec(source,before,command)
            check(status == row['status'] and expected_output == buffers['output_after_hex'],
                  'independent whole status/result/tail or refusal mismatch '+str(index))
            counts[row['case']] += 1; sequence.append(row['case']); statuses[str(status)] += 1
        expected_sequence = [name for name in ids for _ in range(request['expected_vm_by_id'][name])]
        check(counts == request['expected_vm_by_id'] and sequence == expected_sequence,
              'complete ordered per-method VM denominator')
        check(report['vm'] == final['vm'] and report['vm']['by_id'] == counts
              and report['vm']['actual_return_count'] == 1618 and report['vm']['pin'] == observed['tests/VM-RAW.json'],
              'independent VM result joins both original reports')
        result['vm'] = {'returns':1618,'by_id':counts,'status_counts':dict(statuses),
                        'all_whole_buffers_and_arithmetic_independently_recomputed':True,
                        'original':observed['tests/VM-RAW.json']}
        result['checks'].append('EIGHT_METHODS_39_IMPORTS_AND1618_COMPLETE_ARITHMETIC_BUFFER_JOINS')

        core = json.loads(bodies['tests/CORE.json'])
        functions = core['functions']; blocks = [b for f in functions for b in f['blocks']]
        operations = sum(len(b['ops']) for b in blocks)
        ssa = []
        def walk(v):
            if type(v) is dict:
                for k,x in v.items():
                    if k in ('args','params') and type(x) is list:check(len(x) <= 16, 'original16 args/edge/parameter limit')
                    walk(x)
            elif type(v) is list:
                for x in v:walk(x)
            elif type(v) is str and re.fullmatch('v[0-9]+',v):ssa.append(int(v[1:]))
        walk(core)
        lines = len(bodies['tests/sqlite_varint.hiaasm'].decode().split('\n'))
        check(core['schema'] == 'hepta.hia.program.v8' and core['module'] == 'sqlite_varint'
              and len(functions) == 6 <= 128 and len(blocks) == 54 <= 1536 and operations == 181 <= 8192
              and lines == 303 <= 16384 and len(bodies['tests/sqlite_varint.hiaasm']) <= 1 << 20
              and max(ssa) == 128 < 2048, 'complete Core/assembly original caps')
        for f in functions:
            check(len(f['blocks']) <= 256 and len(f['returns']) <= 3, 'function block/result caps')
            for b in f['blocks']:
                for op in b['ops']:check(len(op.get('out',[])) <= 3, 'multiple results cap')
        result['generated'] = {'assembly':observed['tests/sqlite_varint.hiaasm'], 'core':observed['tests/CORE.json'],
                               'lines':lines,'functions':len(functions),'blocks':len(blocks),'operations':operations,
                               'maximum_ssa_index':max(ssa),'original_caps_preserved':True}
        check(final['status'] == 'SQLITE_VARINT_SOURCE_EIGHT_VM_PASS_ONLY' and final['errors'] == []
              and all(final[k] is True for k in ('closed_owner','natural_owner','complete_output_custody','source_eight_pass'))
              and final['catalog'] == observed['ORIGINAL-CATALOG.json']
              and final['report'] == observed['tests/REPORT.json'], 'whole final acceptance conjunction')
        root_audit_pin, root_audit_raw = read(ROOT_INVOCATION / 'READBACK.json')
        root_audit = json.loads(root_audit_raw)
        check(root_audit_pin['sha256'] == 'e295d7800c7e648354ae6a550fd8c269dfa78ddd52b1cbedb3baf4eb8d47584b'
              and root_audit['actual_files'] == observed and root_audit['actual_VM_by_ID'] == counts,
              'Root independent original whole-byte catalogue and per-ID joins agree')
        result['root_independent_readback'] = root_audit_pin
        result['worker_elapsed_seconds'] = report['elapsed_seconds']
        result['tests_expected_loaded_actual_success'] = 8
        result['status'] = 'INDEPENDENT_SOURCE8_AND1618_COMPLETE_VM_READBACK_PASS_ONLY'
    except BaseException as error:
        result['status'] = 'HOLD'
        result['errors'].append({'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()})
    pin = dump(HERE / 'AUDIT.json',result)
    print(json.dumps({'status':result['status'],'audit':pin,'checks':len(result['checks'])},sort_keys=True))
    return 0 if result['status'] == 'INDEPENDENT_SOURCE8_AND1618_COMPLETE_VM_READBACK_PASS_ONLY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
