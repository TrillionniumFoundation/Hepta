#!/usr/bin/env python3
"""Bounded offline bytes/Git/finite-observation audit; never extract or run targets."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time

ARCHIVE_SHA = 'ae46861484a159341143aaf0ee4dfab2696e280d46dbea7c397c86ebd492b4f2'
MANIFEST_SHA = 'd15048f2f5c7dc0260f25752570fbdf925903f88139e138bc0ce28bc984f4cfa'
HEAD = '44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304'
TREE = '835555fb35dbdcf867724ef7a0bb1a6616270217'
MAX_MEMBER = 8 * 1024**2
MAX_TAR = 128 * 1024**2
MAX_MEMBERS = 4096
FUNCTIONS = ('stb_div_trunc', 'stb_div_floor', 'stb_div_eucl', 'stb_mod_trunc', 'stb_mod_floor', 'stb_mod_eucl')
MIN, MAX = -(1 << 31), (1 << 31) - 1
RESOURCES = {'allocation_attempts', 'allocations', 'frees', 'live_bytes', 'live_local_loans',
             'live_owners', 'loans_ended', 'loans_started', 'owners_created', 'owners_dropped', 'peak_bytes'}
COUNTS = {'common_inputs': 119, 'functions_per_version': 6, 'common_native_function_observations': 2856,
          'common_vm_function_observations': 1428, 'old_ubsan_failure_processes': 4,
          'old_hia_overflow_processes': 4, 'successor_only_native_function_observations': 48,
          'successor_probe_return_processes': 4, 'successor_only_vm_function_observations': 24,
          'witness_vm_observations': 8, 'hia_invalid_target_processes': 24,
          'hia_invalid_vm_observations': 24, 'failed_native_negative_controls': 2}
WITNESSES = [('stb_div_floor', [MAX, -2]), ('stb_div_floor', [MIN + 1, 2]),
             ('stb_mod_eucl', [-7, MIN]), ('stb_mod_eucl', [-1, MIN])]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def parse(data):
    require(len(data) <= MAX_MEMBER, 'JSON byte bound')
    return json.loads(data, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, 'input file type/size')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(fields(before) == fields(after) and len(data) == before.st_size, 'input changed or exceeds bound')
    return data


def safe(name):
    require(type(name) is str and 0 < len(name) < 512 and '\\' not in name and ':' not in name
            and str(PurePosixPath(name)) == name and not name.startswith('/')
            and all(part not in ('', '.', '..') for part in name.split('/'))
            and all(ord(c) >= 32 for c in name), 'unsafe member name')


def match(data, identity):
    require(type(identity['bytes']) is int and len(data) == identity['bytes'] and sha(data) == identity['sha256'],
            'recorded byte identity differs')


def load(archive, manifest_path, summary_path):
    # Read each external input once, within a size bound, then hash those exact
    # bytes before any decompression. No path is reopened after its hash check.
    compressed = regular_bytes(archive, 16 * 1024**2)
    manifest_bytes = regular_bytes(manifest_path, 2 * 1024**2)
    require(sha(compressed) == ARCHIVE_SHA and sha(manifest_bytes) == MANIFEST_SHA, 'external immutable SHA pin differs')
    manifest = parse(manifest_bytes)
    require(manifest['schema'] == 'hepta.hia.p3-p6.evidence-archive.v1' and manifest['source_head'] == HEAD
            and manifest['source_tree'] == TREE, 'manifest schema/source differs')
    match(compressed, manifest['archive'])
    summary_bytes = regular_bytes(summary_path, 256 * 1024)
    match(summary_bytes, manifest['summary'])
    summary = parse(summary_bytes)
    rows = manifest['members']
    require(type(rows) is list and 0 < len(rows) <= MAX_MEMBERS, 'member count bound')
    expected = {}
    for row in rows:
        safe(row['path'])
        require(row['path'] not in expected and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_MEMBER,
                'duplicate or oversized member')
        require(re.fullmatch('[0-9a-f]{64}', row['sha256']) and type(row['mode']) is int and 0 <= row['mode'] <= 0o7777,
                'invalid member identity')
        expected[row['path']] = row
    require(sum(row['bytes'] for row in rows) == manifest['payload_bytes'] <= MAX_TAR
            and len(rows) == manifest['member_count'], 'manifest denominator differs')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024**2)
    expanded = decoder.decompress(compressed, max_length=MAX_TAR + 1)
    require(len(expanded) <= MAX_TAR and decoder.eof and not decoder.unused_data,
            'expanded tar bound, truncated XZ or trailing compressed stream')
    raw = {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r|') as archive_stream:
        for member in archive_stream:
            safe(member.name)
            require(member.isfile() and not member.issparse() and not member.issym() and not member.islnk()
                    and member.name in expected and member.name not in raw, 'linked/special/sparse/unknown/duplicate member')
            require(member.size == expected[member.name]['bytes'] <= MAX_MEMBER
                    and member.mode == expected[member.name]['mode'], 'member size/mode differs')
            data = archive_stream.extractfile(member).read(MAX_MEMBER + 1)  # Bytes only; no extraction to disk.
            match(data, expected[member.name])
            raw[member.name] = data
            require(len(raw) <= MAX_MEMBERS, 'member count exceeded')
    require(set(raw) == set(expected), 'complete member set differs')
    for directory in manifest['historical_directories']:
        files = [data for name, data in raw.items() if name.startswith(directory['prefix'] + '/')]
        require(len(files) == directory['members'] and sum(map(len, files)) == directory['bytes'], 'historical raw records missing')
    return manifest, summary, raw


def tree_entries(data):
    entries, offset = {}, 0
    while offset < len(data):
        space = data.index(b' ', offset)
        end = data.index(b'\0', space + 1)
        mode, name = data[offset:space].decode('ascii'), data[space + 1:end].decode('utf-8')
        require('/' not in name and name not in ('', '.', '..') and name not in entries and end + 21 <= len(data),
                'malformed Git tree member')
        entries[name] = (mode, data[end + 1:end + 21].hex())
        offset = end + 21
    return entries


def verify_sources(manifest, raw):
    objects = manifest['raw_git_objects']
    for oid, record in objects.items():
        data = raw[record['archive_member']]
        require(record['type'] in ('commit', 'tree') and hashlib.sha1(
            record['type'].encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest() == oid, 'raw Git object differs')
    counts = {}
    for label, snapshot in manifest['source_snapshots'].items():
        commit = raw[objects[snapshot['head']]['archive_member']]
        require(objects[snapshot['head']]['type'] == 'commit'
                and commit.split(b'\n', 1)[0] == b'tree ' + snapshot['tree'].encode(), 'commit/root tree binding differs')
        for name, record in snapshot['files'].items():
            safe(name)
            tree = snapshot['tree']
            parts = name.split('/')
            for index, part in enumerate(parts):
                require(objects[tree]['type'] == 'tree', 'source ancestor is not a Git tree')
                mode, oid = tree_entries(raw[objects[tree]['archive_member']])[part]
                if index == len(parts) - 1:
                    data = raw[record['archive_member']]
                    require(mode == record['mode'] and mode in ('100644', '100755') and oid == record['git_blob']
                            and hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == oid,
                            'selected source bytes/mode differ from immutable commit')
                else:
                    require(mode == '40000', 'source ancestor mode differs')
                    tree = oid
        counts[label] = len(snapshot['files'])
    return counts


def math_values(a, b):
    require(type(a) is int and type(b) is int and MIN <= a <= MAX and MIN <= b <= MAX
            and b != 0 and (a, b) != (MIN, -1), 'outside finite signed division domain')
    trunc = (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
    floor = a // b
    remainder = a % abs(b)
    euclidean = (a - remainder) // b
    return [trunc, floor, euclidean, a - trunc * b, a - floor * b, remainder]


def common_domain(a, b):
    return (b != 0 and (a, b) != (MIN, -1)
            and not (a >= 0 and b < 0 and -a + b < MIN)
            and not (MIN < a < 0 and b > 0 and a - b < MIN)
            and not (b == MIN and MIN < a < 0))


def vm(row, core, function, expected=None, code=None):
    status = 'returned' if code is None else 'trapped'
    require(type(row['wall_ns']) is int and row['wall_ns'] >= 0 and row['status'] == status, 'VM envelope/cost')
    observation = row['observation']
    require(observation['schema'] == 'hepta.hia.program-execution.v1' and observation['source_used'] is False
            and type(observation['word_bits']) is int and observation['word_bits'] == 64
            and observation['function'] == function and observation['program_sha256'] == observation['input_sha256'] == core
            and observation['status'] == status and type(observation['steps']) is int and 0 < observation['steps'] <= 1000000,
            'VM identity, status or step count')
    require(canonical(observation['claims']) == canonical({'backend_refinement_proved': False,
        'finite_core_execution': True, 'whole_language_soundness_proved': False}), 'VM claims changed')
    require(set(observation['resources']) == RESOURCES
            and all(type(value) is int and value == 0 for value in observation['resources'].values()), 'VM scalar resource ledger changed')
    if code is None:
        require(type(observation['result']) is int and observation['result'] == expected
                and canonical(observation['values']) == canonical([expected]) and 'error' not in observation,
                'VM value/type differs from independent arithmetic')
    else:
        require(row['code'] == observation['error']['code'] == code and set(observation['error']) == {'code', 'message'}
                and type(observation['error']['message']) is str and 'values' not in observation and 'result' not in observation,
                'VM trap code or contradictory return payload')


def verify_p3(prefix, head, snapshot, raw):
    report = parse(raw[prefix + '/qualification.json'])
    require(report['ok'] is True and report['status'] == 'passed_finite_changed_body_update'
            and report['qualified_implementation_commit'] is True and report['development_only'] is False
            and report['expected_source_head'] == head and report['source_before'] == report['source_after']
            and report['source_before']['head'] == head and report['source_before']['tree'] == snapshot['tree']
            and report['source_before']['status'] == '' and report['tools_before'] == report['tools_after'], 'P3 formal source/tool/result binding')
    for name, identity in report['source_before']['files'].items():
        match(raw[snapshot['files'][name]['archive_member']], identity)
    files = report['retained_files']
    require({name[len(prefix) + 1:] for name in raw if name.startswith(prefix + '/')}
            == set(files) | {'qualification.json'}, 'P3 retained inventory differs')
    for name, identity in files.items():
        safe(name); match(raw[prefix + '/' + name], identity)
    require(canonical(report['counts']) == canonical(COUNTS)
            and report['protocol']['functions'] == list(FUNCTIONS)
            and report['protocol']['flags'] == ['-std=c11', '-O2', '-DC_INTEGER_DIVISION_TRUNCATES']
            and report['protocol']['other_macro_configurations_qualified'] is False
            and report['protocol']['old_undefined_inputs_are_equivalence_successes'] is False,
            'P3 denominator/configuration changed')
    for name in ('all_input_source_or_backend_refinement_proved', 'arbitrary_c_cpp_maintenance_qualified',
                 'complete_environment_attested', 'foreign_noexcept_recovery_qualified', 'human_effort_measured',
                 'native_allocator_counters_measured', 'original_c_linked_into_hia_target', 'performance_advantage_measured', 'rust_codegen_used'):
        require(report['claims'][name] is False, 'P3 unsupported claim promoted')
    processes = report['processes']
    require(len(processes) == 49, 'P3 explicit process ledger denominator')
    for index, process in enumerate(processes):
        require(process['index'] == index and process['status'] == 'completed' and 'error' not in process
                and type(process['wall_ns']) is int and process['wall_ns'] > 0, 'P3 missing process completion/cost')
        for stream in ('stdout', 'stderr'):
            data = raw[prefix + '/' + process[stream + '_file']]
            match(data, process[stream + '_identity'])
            require(data.decode() == process[stream], 'P3 process raw stream differs')
    common = parse(raw[prefix + '/common-cases.json'])
    require(len(common) == 119 and len({(row['a'], row['b']) for row in common}) == 119, 'common input denominator')
    for index, case in enumerate(common):
        require(case['case'] == index and common_domain(case['a'], case['b'])
                and canonical(case['expected']) == canonical(math_values(case['a'], case['b'])), 'common input/independent arithmetic')
    versions = report['versions']
    require([version['version'] for version in versions] == ['0.93', '0.94'], 'version denominator')
    changed = sorted(name for name in FUNCTIONS if versions[0]['active_body_sha256'][name] != versions[1]['active_body_sha256'][name])
    require(changed == ['stb_div_floor', 'stb_mod_eucl'] and report['changed_active_functions'] == changed, 'actual changed-body identity')
    for version in versions:
        label = version['version']; folder = prefix + '/' + label
        core = version['core_sha256']
        require(sha(raw[folder + '/program.hia.json']) == core and sha(raw[folder + '/hia.so']) == version['hia_artifact']['sha256'], 'Core/native byte identity')
        header = raw[folder + '/stb_divide.h']; pin = report['upstream_pins'][label]
        match(header, pin)
        require(hashlib.sha1(b'blob ' + str(len(header)).encode() + b'\0' + header).hexdigest() == pin['git_blob'], 'full upstream header blob')
        def matrix(kind, planned):
            meta = version[kind + '_native']
            require(processes[meta['process']]['returncode'] == 0 and meta['summary']['cases'] == len(planned)
                    and meta['summary']['native_function_observations'] == 12 * len(planned), 'native finite matrix denominator')
            lines = raw[prefix + '/' + meta['observations']].decode().splitlines()
            require(len(lines) == len(planned), 'native observation row denominator')
            for line, case in zip(lines, planned):
                values = [int(x) for x in line.split('\t')]
                expected = math_values(case['a'], case['b'])
                require(values == [case['a'], case['b'], *expected, *expected, *expected], 'C/HIA/independent values differ')
            vm_lines = raw[folder + '/' + ('common' if kind == 'common' else 'successor-only') + '-vm.jsonl'].splitlines()
            require(len(vm_lines) == 6 * len(planned), 'VM finite matrix denominator')
            for index, data in enumerate(vm_lines):
                row, case = parse(data), planned[index // 6]
                function = FUNCTIONS[index % 6]; expected = math_values(case['a'], case['b'])[index % 6]
                require(canonical(row['arguments']) == canonical([case['a'], case['b']]) and row['case'] == case['case']
                        and row['function'] == function and type(row['expected']) is int and row['expected'] == expected,
                        'VM frozen outer arguments/function')
                vm(row, core, function, expected=expected)
        matrix('common', common)
        require(len(version['witnesses']) == 4 and len(version['invalid_target_inputs']) == 12, 'failure control denominator')
        for item, (function, arguments) in zip(version['witnesses'], WITNESSES):
            expected = math_values(*arguments)[FUNCTIONS.index(function)]
            require(item['function'] == function and item['arguments'] == arguments
                    and item['common_domain_equivalence_claimed'] is False and item['expected_successor_value'] == expected,
                    'UB witness category changed')
            original = processes[item['original_c_process']]
            require(original['stdout'].startswith('ENTERED_ORIGINAL_C\n'), 'original C witness not entered')
            if label == '0.93':
                require(original['returncode'] != 0 and 'runtime error:' in original['stderr']
                        and processes[item['hia_native_process']]['returncode'] == -6, 'old UB/overflow failure lost')
                vm(item['vm'], core, function, code='overflow')
            else:
                require(original['returncode'] == 0 and parse(original['stdout'].split('\n')[1]) == {'value': expected}, 'successor C witness differs')
                vm(item['vm'], core, function, expected=expected)
        for index, item in enumerate(version['invalid_target_inputs']):
            arguments = [7, 0] if index % 2 == 0 else [MIN, -1]
            function = FUNCTIONS[index // 2]
            require(item['function'] == function and item['arguments'] == arguments and item['original_c_called'] is False
                    and processes[item['process']]['returncode'] == -6, 'invalid-input native rejection changed')
            vm(item['vm'], core, function, code='division_by_zero' if index % 2 == 0 else 'overflow')
        if label == '0.94':
            planned = [{'case': index, 'a': args[0], 'b': args[1]} for index, (_, args) in enumerate(WITNESSES)]
            matrix('successor_only', planned)
    controls = report['negative_controls']
    require(controls['old_undefined_behavior_reclassified_as_success'] is False
            and processes[controls['stale_target_process']]['returncode'] == -6
            and processes[controls['wrong_target_process']]['returncode'] == 2
            and 'functional mismatch' in processes[controls['wrong_target_process']]['stderr'], 'actual negative target controls lost')
    return {'head': head, 'retained_files': len(files), 'counts': COUNTS,
            'collector_wall_ns': report['collected_work_wall_ns'], 'current_qualification': head == HEAD}


def verify(archive, manifest_path, summary_path):
    started = time.monotonic_ns()
    manifest, summary, raw = load(archive, manifest_path, summary_path)
    source_counts = verify_sources(manifest, raw)
    receipt = parse(raw['current/run/RECEIPT.json']); plan = parse(raw['current/PLAN.json'])
    match(raw['current/PLAN.json'], receipt['plan']); match(raw['current/launch.py'], receipt['launcher'])
    require(receipt['status'] == 'completed' and receipt['errors'] == []
            and all(receipt[key + '_unchanged'] is True for key in ('source', 'tools', 'plan', 'launcher'))
            and receipt['expected_source_head'] == plan['source_head'] == HEAD
            and receipt['expected_source_tree'] == plan['source_tree'] == TREE, 'outer identity/state differs')
    before, after = parse(raw['current/run/source-before.json']), parse(raw['current/run/source-after.json'])
    require(before == after and before['head'] == HEAD and before['tree'] == TREE and before['status'] == '', 'full recorded source ledger drift')
    for name, source in manifest['source_snapshots']['current-44e34b7a']['files'].items():
        require(sha(raw[source['archive_member']]) == before['files'][name], 'selected source differs from full run ledger')
    for name, identity in receipt['retained_files'].items():
        safe(name); match(raw['current/run/' + name], identity)
    require({name[len('current/run/'):] for name in raw if name.startswith('current/run/')}
            == set(receipt['retained_files']) | {'RECEIPT.json'}, 'outer retained inventory differs')
    require(receipt['tools_before'] == receipt['tools_after'] and raw['current/outer.stderr'] == b'', 'tool drift or outer diagnostic')
    require([stage['id'] for stage in receipt['stages']] == ['p3', 'p6'], 'stage denominator')
    for stage, planned in zip(receipt['stages'], plan['stages']):
        require(stage == parse(raw['current/run/' + stage['id'] + '/execution.json']) and stage['argv'] == planned['argv']
                and stage['status'] == 'completed' and stage['returncode'] == 0 and stage['qualified'] is True
                and stage['raw_capture_complete'] is True and stage['raw_streams_persisted_complete'] is True
                and stage['persistence_errors'] == [] and stage['source_unchanged'] is True, 'stage/capture qualification differs')
        require(before == parse(raw['current/run/' + stage['id'] + '/source-after.json']), 'per-stage source drift')
    p6 = receipt['stages'][1]
    log = raw['current/run/p6/stderr'].decode()
    methods = sorted(re.findall(r'(?m)^test\w+ \((tests\.[^\s)]+)\) \.\.\. ok$', log))
    require(re.search(r'Ran 46 tests in [0-9.]+s\s+OK\s*\Z', log) and len(methods) == 46
            and methods == plan['stages'][1]['expected_methods'] == p6['observed_successful_methods']
            and p6['outcome'] == {'tests_run': 46, 'passed': True, 'failures': 0, 'errors': 0, 'skipped': 0}, 'P6 complete footer/method denominator')
    p3 = verify_p3('current/run/p3/qualification', HEAD, manifest['source_snapshots']['current-44e34b7a'], raw)
    old_prefix = 'historical/p3-stb-exact-ffe4a127/qualification'
    require(sha(raw[old_prefix + '/qualification.json']) == '1739deaae7229d6494732a495dac38e195ccef0fbd7586f08b725ebcd51a6f4c', 'original ffe result changed')
    historical = verify_p3(old_prefix, 'ffe4a1271098973692a049e3a58de9246a008680',
                           manifest['source_snapshots']['original-p3-ffe4a127'], raw)
    cpp = parse(raw['historical-cpp-package-reference/SUMMARY.json'])
    require(sha(raw['historical-cpp-package-reference/SUMMARY.json']) == '66f0a1eb737e89e45b2df8b97c1c79efefb5cfa80ffdcfd2655389dd7b5166e0'
            and cpp['cpp']['foreign_noexcept_terminations'] == 6
            and cpp['cpp']['all_allocation_failure_paths_recovered'] is False, 'historical C++ failures lost')
    require(summary['source_head'] == HEAD and summary['source_tree'] == TREE and summary['p3']['counts'] == COUNTS
            and summary['p6']['outcome'] == p6['outcome'] and summary['complete_human_development_cost_ns'] is None
            and summary['remaining_cpp_boundary']['foreign_noexcept_terminations'] == 6
            and summary['runtime_performance_advantage_measured'] is False, 'summary scope/count changed')
    require(receipt['outer_wall_ns'] == summary['outer_wall_ns'] >= sum(stage['wall_ns'] for stage in receipt['stages']), 'nested wall cost differs')
    return {'schema': 'hepta.hia.p3-p6.offline-verification.v1', 'verified': True,
            'archive_sha256': ARCHIVE_SHA, 'manifest_sha256': MANIFEST_SHA,
            'members_verified': len(raw), 'payload_bytes_verified': manifest['payload_bytes'],
            'source_head': HEAD, 'source_tree': TREE, 'source_snapshots_verified': source_counts,
            'current_p3': p3, 'historical_ffe_p3': historical, 'p6_methods': len(methods),
            'p6_failures': 0, 'p6_errors': 0, 'p6_skips': 0, 'old_cpp_unrecovered_sigabrt': 6,
            'historical_runs_promoted_to_current': False, 'archive_code_executed': False,
            'archive_files_extracted': False, 'SMT_or_native_reexecuted': False,
            'whole_environment_or_language_proved': False,
            'verification_wall_ns_before_encoding': time.monotonic_ns() - started}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.directory / 'executions.tar.xz', args.directory / 'MANIFEST.json', args.directory / 'SUMMARY.json')
    if args.output:
        with args.output.open('x') as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write('\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
