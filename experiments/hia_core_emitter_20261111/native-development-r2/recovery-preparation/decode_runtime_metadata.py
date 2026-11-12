"""Independent exact r2 metadata diagnostic decoder; no product imports."""
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
    'control_commit': '07969d04cb9bb4674c92c5ffd4bf8dbafb3733c2',
    'workflow_commit': '336664b5c310a8efb7d506c99ba54cb846dfcc75',
    'policy_sha256': '3b20ce87f4cdd8e85bbdd10812b72a091471bcb41dc343938fe387f8e99ed08d',
    'run_id': 43170054958, 'run_attempt': 1,
    'trigger_branch': 'codex/hia-core-emitter-native-development-run-r2-20261112-e26e',
}
PACKAGES = {'setuptools': '78.1.1', 'wheel': '0.46.3',
            'z3-solver': '4.15.4.0', 'jsonschema': '4.26.0'}
FIELDS = ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')

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
        report = loads(body)
        _, end, _ = take('END')
        require(end == {'stage': stage, **wanted, 'status': report['status']}, 'runtime END differs')
        require(sum(len(x[2]) for x in records[first:cursor]) <= 196608, 'runtime stdout cap differs')
        require(report['schema'] == 'hia.core-emitter-runtime-metadata-provisioning.v1'
                and report['stage'] == stage and report['operation'] == OPERATION
                and report['fixed_packages'] == PACKAGES
                and report['lstat_identity_field_order'] == list(FIELDS)
                and report['old_run_exact_failing_stat_unknown'] is True
                and report['system_runtime_predicate_unchanged'] is True
                and report['project_or_system_binary_modified'] is False
                and report['phase_owner_or_product_executed'] is False, 'runtime report scope differs')
        uid = report['current_euid']
        require(type(uid) is int, 'runtime uid differs')
        names = [(row['package'], row['metadata_name']) for row in report['rows']]
        require(len(names) == len(set(names)) <= 8
                and set(names) <= {(p, n) for p in PACKAGES for n in ('METADATA', 'RECORD')},
                'metadata pair inventory differs')
        for row in report['rows']:
            require(row['expected_version'] == PACKAGES[row['package']], 'fixed version changed')
            if row.get('status') == 'OBSERVED':
                verify_observation(row, uid, stage)
                require(stage == 'before' or row['actual_version'] == row['expected_version'],
                        'fresh distribution version mismatch')
        complete = len(report['rows']) == 8 and not report['errors'] and all(
            row.get('status') == 'OBSERVED' for row in report['rows'])
        if 'complete_eight_originals' in report:
            require(report['complete_eight_originals'] is complete, 'complete metadata count mismatch')
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
            old = {(row['package'], row['metadata_name']): row for row in reports['after']['rows']}
            for row in report['rows']:
                previous = old[row['package'], row['metadata_name']]
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
    audit = {'schema': 'hia.core-emitter-runtime-metadata-independent-readback.v1',
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
