"""Fixed small failure channel for the integer source-only request.

The original four controls and tests remain unchanged. This always step reads
completed parent diagnostics, and reads child originals only after independently
checking the original bound ECHILD receipt. Error projections contain every
failure field and are explicitly derived JSON, never called original files.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'control'))
from common import create, parent_fd, physical_files, pin, read_file, require, wire
import protocol as p

SCHEMA = 'hepta.hia.core-integer-source-small-diagnostics.v1'
RAW_LIMIT = 512 << 10
STDOUT_LIMIT = 1 << 20
REPORT_READ_LIMIT = 8 << 20
PROJECTION_KEYS = {
    'prepare': ('schema', 'status', 'errors'),
    'final': ('schema', 'status', 'qualification', 'source_stage_pass', 'closed_owner',
              'natural_owner', 'owner_status', 'owner_returncode', 'errors',
              'omitted_or_failed_originals', 'deferred_owned_paths', 'unconfirmed_boundary'),
    'worker': ('schema', 'status', 'loaded_ids', 'executed_ids', 'stopped_ids',
               'loader_errors', 'failures', 'errors', 'skipped', 'expected_failures',
               'unexpected_successes', 'preservation_errors', 'forbidden_events',
               'all_inputs_stable', 'elapsed_ns', 'diagnostic_observer'),
}


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate diagnostic JSON key')
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError('nonfinite diagnostic JSON value')))


def new_directory(path):
    with parent_fd(path) as (parent, name):
        os.mkdir(name, 0o700, dir_fd=parent)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'new private diagnostic directory differs')


def failure(error):
    return {'type': type(error).__name__, 'message': str(error),
            'traceback': traceback.format_exc()}


def projection(role, value, original):
    require(type(value) is dict and role in PROJECTION_KEYS, 'fixed report object required')
    return wire({'schema': SCHEMA + '.error-fields',
                 'representation': 'DERIVED_COMPLETE_FAILURE_FIELDS_NOT_ORIGINAL_FILE',
                 'source_role': role, 'source_original': original,
                 'all_listed_field_values_preserved_without_truncation': True,
                 'field_domain': list(PROJECTION_KEYS[role]),
                 'present_fields': {key: value[key] for key in PROJECTION_KEYS[role] if key in value},
                 'absent_fields': [key for key in PROJECTION_KEYS[role] if key not in value]})


def build_channel(candidates, observation, directory, remaining_public_bytes):
    """Mandatory failure fields precede optional whole-file observations."""
    ordered = sorted(enumerate(candidates), key=lambda pair: (not pair[1]['mandatory'], pair[0]))
    selected, omitted = [], []
    used = 0
    for _, row in ordered:
        raw = row['raw']
        if used + len(raw) > RAW_LIMIT:
            omitted.append({key: value for key, value in row.items() if key != 'raw'})
            omitted[-1].update(reason='OMITTED_WHOLE_FILE_BUDGET', bytes=len(raw),
                               sha256=sha256(raw).hexdigest())
            continue
        selected.append(row)
        used += len(raw)
    require(not any(row['mandatory'] for row in omitted),
            'a complete mandatory failure original/projection exceeds the fixed small channel')
    index = {'schema': SCHEMA + '.index', 'source_status': observation['source_status'],
             'closed_owner_independently_observed': observation['closed_owner'],
             'source_qualification_granted_by_this_channel': False,
             'raw_limit': RAW_LIMIT, 'stdout_limit': STDOUT_LIMIT,
             'selected_raw_bytes': used, 'omitted_whole_files': omitted,
             'files': [{'ordinal': number, 'name': row['name'], 'bytes': len(row['raw']),
                        'sha256': sha256(row['raw']).hexdigest(),
                        'representation': row['representation'], 'original': row.get('original')}
                       for number, row in enumerate(selected)]}
    index_raw = wire(index)
    require(len(index_raw) <= 64 << 10, 'diagnostic index exceeds its fixed byte cap')
    lines = ['HIA_INTEGER_DIAGNOSTIC_INDEX ' + base64.b64encode(index_raw).decode() + '\n']
    for number, row in enumerate(selected):
        for offset in range(0, len(row['raw']), 8192):
            block = row['raw'][offset:offset + 8192]
            frame = {'file': number, 'offset': offset, 'bytes': len(block),
                     'sha256': sha256(block).hexdigest(), 'base64': base64.b64encode(block).decode()}
            lines.append('HIA_INTEGER_DIAGNOSTIC_FRAME ' + json.dumps(
                frame, sort_keys=True, separators=(',', ':')) + '\n')
    prefix = ''.join(lines).encode()
    end = {'schema': SCHEMA + '.end', 'status': 'COMPLETE_BOUNDED_DIAGNOSTIC_CHANNEL',
           'source_status': observation['source_status'], 'index_sha256': sha256(index_raw).hexdigest(),
           'prefix_sha256': sha256(prefix).hexdigest(), 'prefix_bytes': len(prefix),
           'files': len(selected), 'raw_bytes': used,
           'source_qualification_granted_by_this_channel': False}
    output = prefix + ('HIA_INTEGER_DIAGNOSTIC_END ' + json.dumps(
        end, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(output) <= STDOUT_LIMIT, 'diagnostic stdout including END exceeds the fixed cap')
    result = {'schema': SCHEMA + '.result', 'status': 'COMPLETE_BOUNDED_DIAGNOSTIC_CHANNEL',
              'index_sha256': sha256(index_raw).hexdigest(), 'stream_bytes': len(output),
              'stream_sha256': sha256(output).hexdigest(), 'end': end}
    result_raw = wire(result)
    require(used + len(index_raw) + len(result_raw) + len(output) <= remaining_public_bytes,
            'complete diagnostic files would exceed the original public custody cap')
    # Publish complete copies and stream bytes before exposing any END.
    for number, row in enumerate(selected):
        create(directory / ('%03d.raw' % number), row['raw'])
    create(directory / 'INDEX.json', index_raw)
    create(directory / 'RESULT.json', result_raw)
    create(directory / 'frames.txt', output)
    checked, _ = read_file(directory / 'frames.txt', STDOUT_LIMIT)
    require(checked == output, 'complete diagnostic stream readback differs')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capsule', type=Path, required=True)
    parser.add_argument('--operation', type=Path, required=True)
    parser.add_argument('--controller-logs', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    parser.add_argument('--control-tree', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    capsule = p.absolute(args.capsule)
    operation = p.absolute(args.operation)
    logs = p.absolute(args.controller_logs)
    temp = p.absolute(Path(os.environ['RUNNER_TEMP']))
    require(operation == temp / p.OPERATION
            and logs == temp / 'hia-integer-source-controller-logs', 'fixed diagnostic roots differ')
    policy, policy_raw, policy_record = p.load_policy(capsule, args.policy_sha256)
    require(Path(__file__).resolve() == capsule / 'diagnostics/failure_channel.py',
            'actual diagnostic script path differs')
    for row in policy['control_files']:
        p.file_matches(capsule / row['path'], row)
    public = operation.with_name(operation.name + '-public')
    if not public.exists():
        new_directory(public)
    directory = public / 'small-diagnostics'
    new_directory(directory)
    observation = {'schema': SCHEMA + '.observation', 'source_status': 'HOLD_OR_UNOBSERVED',
                   'closed_owner': False, 'reads': [], 'missing': [], 'read_errors': [],
                   'boundary_error': None, 'deferred_child_paths': ['work/', 'owned/'],
                   'policy_sha256': args.policy_sha256, 'control_commit': args.control_commit,
                   'control_tree': args.control_tree, 'native_execution': False}
    candidates = []

    def observed(path, role, maximum=REPORT_READ_LIMIT):
        try:
            raw, record = read_file(path, maximum)
            observation['reads'].append({'role': role, **record})
            return raw, record
        except FileNotFoundError:
            observation['missing'].append({'role': role, 'path': str(path)})
        except BaseException as error:
            observation['read_errors'].append({'role': role, 'path': str(path), **failure(error)})
        return None, None

    def original(name, raw, record, mandatory=False):
        if raw is not None:
            candidates.append({'name': name, 'raw': raw, 'original': record,
                               'mandatory': mandatory, 'representation': 'COMPLETE_ORIGINAL_FILE'})

    def report(path, role):
        raw, record = observed(path, role)
        if raw is None:
            return None, None
        try:
            value = parse(raw)
            candidates.append({'name': role + '-failure-fields.derived.json',
                               'raw': projection(role, value, record), 'original': record,
                               'mandatory': True,
                               'representation': 'DERIVED_COMPLETE_FAILURE_FIELDS_NOT_ORIGINAL_FILE'})
            original(role + '.original.json', raw, record)
            return value, record
        except BaseException as error:
            observation['read_errors'].append({'role': role, 'path': str(path), **failure(error)})
            original(role + '.unparsed.original', raw, record, mandatory=True)
            return None, record

    # Parent outputs belong to completed preparation/finalization steps.
    prepared, _ = report(public / 'PREPARE.json', 'prepare')
    final, _ = report(public / 'FINAL.json', 'final')
    if final is not None:
        observation['source_status'] = final.get('status', 'HOLD_OR_UNOBSERVED')
    for phase in ('prepare', 'run', 'finalize'):
        for stream in ('stderr', 'stdout'):
            path = logs / (phase + '.' + stream + '.log')
            raw, record = observed(path, 'parent-' + phase + '-' + stream, 4 << 20)
            original('parent-' + phase + '.' + stream + '.original.log', raw, record,
                     mandatory=(stream == 'stderr' and bool(raw)))

    # Only the original small request/lifecycle boundary is read before ECHILD.
    try:
        require(type(prepared) is dict and type(prepared.get('request')) is dict,
                'no completed preparation request is available')
        request, request_raw, request_record = p.read_request(
            operation / 'REQUEST.original.json', prepared['request']['sha256'])
        require(request_record == prepared['request']
                and request['control_commit'] == args.control_commit
                and request['control_tree'] == args.control_tree
                and request['policy_sha256'] == args.policy_sha256
                and request['capsule'] == str(capsule)
                and request['operation_root'] == str(operation)
                and request['public_root'] == str(public)
                and request['github_context']['GITHUB_RUN_ID'] == os.environ.get('GITHUB_RUN_ID')
                and request['github_context']['GITHUB_SHA'] == os.environ.get('GITHUB_SHA'),
                'current diagnostic request binding differs')
        observation['request_record'] = request_record
        original('REQUEST.original.json', request_raw, request_record, mandatory=True)
        life_raw, life_record = observed(operation / 'owned/lifecycle.json', 'owner-lifecycle', 4 << 20)
        request_owner_raw, request_owner_record = observed(
            operation / 'owned/lifecycle.json.request.json', 'owner-request', 262144)
        original('owner-lifecycle.original.json', life_raw, life_record, mandatory=True)
        original('owner-request.original.json', request_owner_raw, request_owner_record)
        require(life_raw is not None and request_owner_raw is not None, 'owner boundary originals missing')
        life = p.closed_owner(request, request_record, life_raw, request_owner_raw)
        observation['closed_owner'] = True
        observation['owner_status'] = life['status']
        observation['owner_returncode'] = life['returncode']
        observation['deferred_child_paths'] = []
    except BaseException as error:
        observation['boundary_error'] = failure(error)

    if observation['closed_owner']:
        worker, _ = report(operation / 'work/WORKER-REPORT.json', 'worker')
        for relative in ('owned/stderr.log', 'work/unittest.log', 'owned/stdout.log'):
            raw, record = observed(operation / relative, relative, 4 << 20)
            critical = bool(raw) and (relative == 'owned/stderr.log'
                                      or (relative == 'work/unittest.log' and worker is None))
            original(relative.replace('/', '-') + '.original', raw, record, mandatory=critical)
    # Full failure values are always separate from large buffer/source inventories.
    # Missing or unreadable originals are explicit; they never change source HOLD.
    for row in observation['reads']:
        _, checked = read_file(Path(row['path']), REPORT_READ_LIMIT)
        require(checked == {key: value for key, value in row.items() if key != 'role'},
                'a diagnostic input changed during the read transaction')
    observation_raw = wire(observation)
    own_raw, own_record = read_file(Path(__file__).resolve(), 64 << 10)
    names, _ = physical_files(public)
    used_public_bytes = sum((public / name).lstat().st_size for name in names)
    require(used_public_bytes + len(observation_raw) + len(own_raw) <= policy['public_max_bytes'],
            'diagnostic observation would exceed the original public custody cap')
    create(directory / 'DIAGNOSTICS.original.py', own_raw)
    create(directory / 'OBSERVATION.json', observation_raw)
    candidates.insert(0, {'name': 'OBSERVATION.json', 'raw': observation_raw,
                          'mandatory': True, 'representation': 'CURRENT_DIAGNOSTIC_OBSERVATION'})
    output = build_channel(candidates, observation, directory,
                           policy['public_max_bytes'] - used_public_bytes
                           - len(observation_raw) - len(own_raw))
    names, _ = physical_files(public)
    require(sum((public / name).lstat().st_size for name in names) <= policy['public_max_bytes'],
            'new small channel would exceed the original public custody cap')
    at = 0
    while at < len(output):
        written = os.write(1, output[at:])
        require(written > 0, 'diagnostic stdout write was short')
        at += written
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
