"""Independent exact r3 metadata diagnostic decoder; no product imports."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import re
import stat
from decode_small import loads, pin, require, wire

PREFIX = 'HIA_CORE_EMITTER_RUNTIME_METADATA_'
OPERATION = {
    'repository': 'TrillionniumFoundation/Hepta',
    'control_commit': '4b17b155ecd72c27e8300ffd778b837ce491cfdb',
    'workflow_commit': '6c0cf12e0c59a75cf4c1df84287a23840e38548f',
    'policy_sha256': '8a76ca513d306c09587b215393abe62438b0fef8b328f7db282564e65400bc8c',
    'run_id': 0, 'run_attempt': 1,
    'trigger_branch': 'codex/hia-core-emitter-native-development-run-r3-20261112-e26e',
}
PACKAGES = {'setuptools': '78.1.1', 'wheel': '0.46.3',
            'z3-solver': '4.15.4.0', 'jsonschema': '4.26.0'}
FIELDS = ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')
FIXED_METADATA_FILES = {'setuptools': ('setuptools/_vendor/autocommand-2.2.2.dist-info/METADATA',
                'setuptools/_vendor/autocommand-2.2.2.dist-info/RECORD',
                'setuptools/_vendor/backports.tarfile-1.2.0.dist-info/METADATA',
                'setuptools/_vendor/backports.tarfile-1.2.0.dist-info/RECORD',
                'setuptools/_vendor/importlib_metadata-8.0.0.dist-info/METADATA',
                'setuptools/_vendor/importlib_metadata-8.0.0.dist-info/RECORD',
                'setuptools/_vendor/inflect-7.3.1.dist-info/METADATA',
                'setuptools/_vendor/inflect-7.3.1.dist-info/RECORD',
                'setuptools/_vendor/jaraco.collections-5.1.0.dist-info/METADATA',
                'setuptools/_vendor/jaraco.collections-5.1.0.dist-info/RECORD',
                'setuptools/_vendor/jaraco.context-5.3.0.dist-info/METADATA',
                'setuptools/_vendor/jaraco.context-5.3.0.dist-info/RECORD',
                'setuptools/_vendor/jaraco.functools-4.0.1.dist-info/METADATA',
                'setuptools/_vendor/jaraco.functools-4.0.1.dist-info/RECORD',
                'setuptools/_vendor/jaraco.text-3.12.1.dist-info/METADATA',
                'setuptools/_vendor/jaraco.text-3.12.1.dist-info/RECORD',
                'setuptools/_vendor/more_itertools-10.3.0.dist-info/METADATA',
                'setuptools/_vendor/more_itertools-10.3.0.dist-info/RECORD',
                'setuptools/_vendor/packaging-24.2.dist-info/METADATA',
                'setuptools/_vendor/packaging-24.2.dist-info/RECORD',
                'setuptools/_vendor/platformdirs-4.2.2.dist-info/METADATA',
                'setuptools/_vendor/platformdirs-4.2.2.dist-info/RECORD',
                'setuptools/_vendor/tomli-2.0.1.dist-info/METADATA',
                'setuptools/_vendor/tomli-2.0.1.dist-info/RECORD',
                'setuptools/_vendor/typeguard-4.3.0.dist-info/METADATA',
                'setuptools/_vendor/typeguard-4.3.0.dist-info/RECORD',
                'setuptools/_vendor/typing_extensions-4.12.2.dist-info/METADATA',
                'setuptools/_vendor/typing_extensions-4.12.2.dist-info/RECORD',
                'setuptools/_vendor/wheel-0.45.1.dist-info/METADATA',
                'setuptools/_vendor/wheel-0.45.1.dist-info/RECORD',
                'setuptools/_vendor/zipp-3.19.2.dist-info/METADATA',
                'setuptools/_vendor/zipp-3.19.2.dist-info/RECORD',
                'setuptools-78.1.1.dist-info/METADATA',
                'setuptools-78.1.1.dist-info/RECORD'),
 'wheel': ('wheel-0.46.3.dist-info/METADATA', 'wheel-0.46.3.dist-info/RECORD'),
 'z3-solver': ('z3_solver-4.15.4.0.dist-info/METADATA', 'z3_solver-4.15.4.0.dist-info/RECORD'),
 'jsonschema': ('jsonschema-4.26.0.dist-info/METADATA', 'jsonschema-4.26.0.dist-info/RECORD')}
OWN_DIST_INFO = {'setuptools': 'setuptools-78.1.1.dist-info',
 'wheel': 'wheel-0.46.3.dist-info',
 'z3-solver': 'z3_solver-4.15.4.0.dist-info',
 'jsonschema': 'jsonschema-4.26.0.dist-info'}


def expand_report(report):
    require(report.get('lstat_chain_encoding') == 'exact-observation-record-indices.v1'
            and report.get('equal_field_encoding') == 'same-dict-resolved-path-and-original.v1',
            'unknown metadata observation encoding')
    records = report.get('lstat_observation_records')
    require(type(records) is list and 0 <= len(records) <= 4096, 'chain dictionary shape differs')
    used = set()
    for record in records:
        require(type(record) is dict and set(record) in (
                {'path', 'identity', 'kind'}, {'path', 'identity', 'kind', 'link_target'})
                and type(record['path']) is str and record['path'].startswith('/')
                and record['kind'] in ('directory', 'regular', 'symlink', 'other')
                and type(record['identity']) is list and len(record['identity']) == 9
                and all(type(x) is int for x in record['identity']), 'chain record differs')
    def visit(value):
        if type(value) is list:
            return [visit(item) for item in value]
        if type(value) is not dict:
            return value
        result = {}
        for name, item in value.items():
            if name in ('lstat_observation_records', 'lstat_chain_encoding', 'equal_field_encoding'):
                continue
            if name in ('lexical_lstat_chain', 'lexical_lstat_chain_after', 'lstat_chain'):
                require(type(item) is dict and set(item) == {'record_indices'}
                        and type(item['record_indices']) is list and 0 < len(item['record_indices']) <= 256,
                        'chain reference differs')
                chosen = []
                for index in item['record_indices']:
                    require(type(index) is int and 0 <= index < len(records), 'chain index outside dictionary')
                    used.add(index)
                    chosen.append(records[index])
                result[name] = chosen
            elif name == 'lexical_path' and item == {'same_as_resolved_path': True}:
                require(type(value.get('resolved_path')) is str, 'path equality reference missing')
                result[name] = value['resolved_path']
            elif name == 'after_original' and item == {'same_as_original': True}:
                require(type(value.get('original')) is dict and set(value['original']) ==
                        {'bytes', 'sha256', 'git_blob_sha1'}, 'original equality reference missing')
                result[name] = value['original']
            else:
                require(item not in ({'same_as_resolved_path': True}, {'same_as_original': True}),
                        'equality reference outside fixed field')
                result[name] = visit(item)
        return result
    result = visit(report)
    require(used == set(range(len(records))), 'unused observation dictionary record')
    return result

def evaluate(info, uid):
    require(type(info) is dict and info['identity'] == [info[x] for x in FIELDS]
            and all(type(info[x]) is int for x in FIELDS), 'metadata stat/identity differs')
    require(info['regular'] == stat.S_ISREG(info['mode'])
            and info['directory'] == stat.S_ISDIR(info['mode'])
            and info['symlink'] == stat.S_ISLNK(info['mode'])
            and info['posix_mode'] == stat.S_IMODE(info['mode']), 'mode projections differ')
    fields = {'uid_in_root_or_current': info['uid'] in (0, uid),
              'link_count_at_least_one': info['nlink'] >= 1,
              'no_group_or_other_write': not bool(info['posix_mode'] & 0o022)}
    return {**fields, 'all': all(fields.values())}

def verify_observation(row, uid, stage):
    require(row['predicate_before'] == evaluate(row['before'], uid)
            and row['predicate_after'] == evaluate(row['after'], uid), 'predicate fields differ')
    require(row['original'] == row['after_original']
            and row['original']['bytes'] == row['before']['size'] == row['after']['size']
            and row['bytes_and_nonmode_identity_unchanged'] is True, 'file byte accounting differs')
    changed = row['mode_change_attempted']
    require(type(changed) is bool, 'invalid mode action type')
    if changed:
        require(stage == 'admit' and row['lexical_path'] == row['resolved_path']
                and row['before']['uid'] == uid and row['before']['nlink'] == 1
                and row['before']['regular'] and row['before']['posix_mode'] & 0o022
                and row['after']['mode'] == row['before']['mode'] & ~0o022,
                'mode change outside admitted narrow scope')
        for field in FIELDS:
            if field not in ('mode', 'ctime_ns'):
                require(row['before'][field] == row['after'][field], 'nonmode identity changed')
    else:
        require(row['before'] == row['after'], 'unchanged file identity drifted')
    for key in ('lexical_lstat_chain', 'lexical_lstat_chain_after'):
        chain = row[key]
        require(type(chain) is list and chain and chain[0]['path'] == '/'
                and chain[-1]['path'] == row['lexical_path'], 'missing exact lstat chain')
        for link in chain:
            require(len(link['identity']) == len(FIELDS)
                    and all(type(value) is int for value in link['identity']), 'chain identity fields')

def decode(raw):
    require(type(OPERATION['run_id']) is int and OPERATION['run_id'] > 0, 'actual provider run identity not frozen')
    records = []
    for line in raw.decode('utf-8', errors='strict').splitlines(keepends=True):
        match = re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.]\d{1,9}Z (.*)\n', line)
        if match and match[1].startswith(PREFIX):
            kind, body = match[1][len(PREFIX):].split(' ', 1)
            value = loads(body)
            require(type(value) is dict and body == json.dumps(value, sort_keys=True), 'noncanonical runtime frame')
            records.append((kind, value, (match[1] + '\n').encode()))
    cursor = 0
    outputs, reports = {}, {}
    def take(kind):
        nonlocal cursor
        require(cursor < len(records) and records[cursor][0] == kind, 'runtime frame order differs')
        item = records[cursor]
        cursor += 1
        return item
    for stage in ('before', 'after', 'admit'):
        if cursor == len(records):
            break
        first = cursor
        _, start, _ = take('BEGIN')
        require(start['stage'] == stage and start['operation'] == OPERATION
                and type(start['bytes']) is int and 0 <= start['bytes'] <= 131072
                and start['frame_bytes'] == 8192
                and start['frame_count'] == (start['bytes'] + 8191) // 8192, 'runtime BEGIN differs')
        chunks = []
        offset = 0
        for index in range(start['frame_count']):
            _, frame, _ = take('FRAME')
            require(set(frame) == {'index', 'offset', 'bytes', 'sha256', 'base64'}
                    and type(frame['index']) is int and frame['index'] == index
                    and type(frame['offset']) is int and frame['offset'] == offset
                    and type(frame['bytes']) is int and frame['bytes'] == min(8192, start['bytes'] - offset),
                    'runtime frame coordinates differ')
            chunk = base64.b64decode(frame['base64'], validate=True)
            require(base64.b64encode(chunk).decode() == frame['base64']
                    and pin(chunk)['sha256'] == frame['sha256'] and len(chunk) == frame['bytes'],
                    'runtime frame byte/hash differs')
            chunks.append(chunk)
            offset += len(chunk)
        body = b''.join(chunks)
        wanted = {key: start[key] for key in ('bytes', 'sha256', 'git_blob_sha1')}
        require(pin(body) == wanted, 'whole runtime original pin differs')
        report = expand_report(loads(body))
        _, end, _ = take('END')
        require(end == {'stage': stage, **wanted, 'status': report['status']}, 'runtime END differs')
        require(sum(len(x[2]) for x in records[first:cursor]) <= 196608, 'runtime stdout cap differs')
        require(report['schema'] == 'hia.core-emitter-runtime-metadata-provisioning.v2'
                and report['stage'] == stage and report['operation'] == OPERATION
                and report['fixed_packages'] == PACKAGES
                and report['lstat_identity_field_order'] == list(FIELDS)
                and report['old_run_exact_failing_stat_unknown'] is True
                and report['system_runtime_predicate_unchanged'] is True
                and report['project_or_system_binary_modified'] is False
                and report['phase_owner_or_product_executed'] is False, 'runtime report scope differs')
        uid = report['current_euid']
        require(type(uid) is int, 'runtime uid differs')
        require(report['fixed_metadata_files'] == {name:list(paths) for name,paths in FIXED_METADATA_FILES.items()}
                and report['own_dist_info'] == OWN_DIST_INFO
                and report['expected_metadata_original_count'] == 40,
                'fixed full controller inventory declaration differs')
        expected_names = [(package, entry) for package, entries in FIXED_METADATA_FILES.items() for entry in entries]
        names = [(row['package'], row['distribution_entry']) for row in report['rows']]
        require(len(names) == len(set(names)) <= 40 and set(names) <= set(expected_names)
                and names == [item for item in expected_names if item in names],
                'complete controller metadata inventory/order differs')
        for row in report['rows']:
            require(row['expected_version'] == PACKAGES[row['package']]
                    and row['metadata_name'] == Path(row['distribution_entry']).name
                    and row['own_distribution_metadata'] is
                        (Path(row['distribution_entry']).parent.as_posix() == OWN_DIST_INFO[row['package']]),
                    'fixed version or own/vendor classification changed')
            if row.get('status') == 'OBSERVED':
                verify_observation(row, uid, stage)
                require(stage == 'before' or row['actual_version'] == row['expected_version'],
                        'fresh distribution version mismatch')
        complete = len(report['rows']) == 40 and not report['errors'] and all(
            row.get('status') == 'OBSERVED' for row in report['rows'])
        if 'complete_controller_metadata_originals' in report:
            require(report['complete_controller_metadata_originals'] is complete, 'complete metadata count mismatch')
            own = sum(row['own_distribution_metadata'] for row in report['rows'])
            require(report['own_metadata_original_count'] == own
                    and report['vendored_metadata_original_count'] == len(report['rows']) - own,
                    'own/vendor actual count mismatch')
            passes = complete and all(row['predicate_after']['all'] for row in report['rows'])
            require(report['original_metadata_predicate_passes'] is passes, 'metadata pass conjunction differs')
        if report.get('python') and 'predicate_after' in report['python']:
            verify_observation(report['python'], uid, 'before')
        if report['status'] == 'FIXED_METADATA_READY_FOR_UNCHANGED_CONTROLLER':
            require(stage == 'admit' and complete and passes
                    and report['python']['predicate_after']['all']
                    and 'after' in outputs, 'READY without complete new observation')
            source_pin = report['post_install_report_original']
            require({key: source_pin[key] for key in pin(outputs['after'])} == pin(outputs['after']),
                    'admission does not bind actual after-install original')
            old = {(row['package'], row['distribution_entry']): row for row in reports['after']['rows']}
            for row in report['rows']:
                previous = old[row['package'], row['distribution_entry']]
                require(previous['after']['identity'] == row['before']['identity']
                        and previous['original'] == row['original']
                        and previous['resolved_path'] == row['resolved_path'], 'metadata admission source drift')
        outputs[stage] = body
        reports[stage] = report
    require(cursor == len(records), 'extra runtime diagnostic records')
    return outputs, reports

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    raw = args.log.read_bytes()
    originals, reports = decode(raw)
    args.output.mkdir(mode=0o700, exist_ok=False)
    for stage, body in originals.items():
        with (args.output / (stage + '.json')).open('xb') as handle:
            handle.write(body)
    audit = {'schema': 'hia.core-emitter-runtime-metadata-independent-readback.v2',
             'operation': OPERATION, 'log_original': pin(raw),
             'stages': {stage: {'original': pin(originals[stage]), 'status': report['status'],
                'row_count': len(report['rows']),
                'mode_change_attempts': sum(bool(row.get('mode_change_attempted')) for row in report['rows'])}
                for stage, report in reports.items()},
             'new_metadata_admission_ready': reports.get('admit', {}).get('status') ==
                'FIXED_METADATA_READY_FOR_UNCHANGED_CONTROLLER',
             'old_run_exact_stat_cause_still_unknown': True,
             'product_or_cold_qualification_claimed': False}
    with (args.output / 'AUDIT.json').open('xb') as handle:
        handle.write(wire(audit))
    print(json.dumps(audit, sort_keys=True))

if __name__ == '__main__':
    main()
