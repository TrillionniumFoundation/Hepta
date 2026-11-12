"""Read one already-closed SOURCE129 operation; never import or execute Hepta.

This is an independent stdlib reader. Its command line requires the parent's
explicit closure acknowledgement. It does not retry an owner or a child.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import traceback


REQUEST = Path('/tmp/hia-core-integer-native-integration-v92-r1-20261112-e26e/REQUEST.json')
REQUEST_SHA256 = '146f35ae20bfdeae71cd435aa2f0203ba448b38226475c8bb330b62cf897393a'
PUBLISHED_REQUEST_COMMIT = 'e142d8ff62e1db504c9dee71fe5a50b10e7fb139'
ACTUAL = Path('/tmp/hia-integer-wire-source129-v92-r1-20261112-e26e')
PIN_FIELDS = ('path', 'size', 'sha256', 'git_blob_sha1', 'mode', 'uid', 'gid',
              'nlink', 'device', 'inode', 'mtime_ns', 'ctime_ns')
CONTENT_FIELDS = ('relative_path', 'size', 'sha256', 'git_blob_sha1', 'mode')
ANOMALIES = ('loader_errors', 'errors', 'failures', 'skipped',
             'expectedFailures', 'unexpectedSuccesses')
FLAGS = ('native_executed', 'complete18_executed', 'complete116_executed',
         'cold_executed', 'installed_executed')
checks = []
cache = {}
joins = 0


def check(value, name, *, kind='integrity', details=None):
    row = {'name': name, 'kind': kind, 'pass': bool(value)}
    if details is not None:
        row['details'] = details
    checks.append(row)
    return bool(value)


def must(value, name):
    if not check(value, name):
        raise ValueError(name)


def exact_int(value):
    return type(value) is int


def identity(value):
    return {'size': value.st_size, 'mode': stat.S_IMODE(value.st_mode),
            'uid': value.st_uid, 'gid': value.st_gid, 'nlink': value.st_nlink,
            'device': value.st_dev, 'inode': value.st_ino,
            'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns}


def directory_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def read_file(path):
    """Hold every directory descriptor; reject leaf/ancestor links and changes."""
    path = Path(path)
    if not path.is_absolute() or any(x in ('.', '..') for x in path.parts[1:]):
        raise ValueError('noncanonical absolute path: ' + str(path))
    parents = []
    fd = None
    try:
        root_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parents.append((root_fd, None, None, os.fstat(root_fd)))
        for component in path.parts[1:-1]:
            parent = parents[-1][0]
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            parents.append((child, parent, component, os.fstat(child)))
        parent = parents[-1][0]
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('nonregular original: ' + str(path))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        held = os.fstat(fd)
        if identity(held) != identity(before):
            raise ValueError('leaf changed before read: ' + str(path))
        chunks, remaining = [], held.st_size
        while remaining:
            block = os.read(fd, min(remaining, 1024 * 1024))
            if not block:
                raise ValueError('short original: ' + str(path))
            chunks.append(block)
            remaining -= len(block)
        if os.read(fd, 1):
            raise ValueError('original grew: ' + str(path))
        data = b''.join(chunks)
        after = os.fstat(fd)
        linked = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if identity(before) != identity(after) or identity(after) != identity(linked):
            raise ValueError('original changed during read: ' + str(path))
        for directory, parent_fd, name, frozen in parents:
            if directory_identity(os.fstat(directory)) != directory_identity(frozen):
                raise ValueError('held directory changed: ' + str(path))
            if parent_fd is not None:
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if directory_identity(current) != directory_identity(frozen):
                    raise ValueError('directory link changed: ' + str(path))
        observed = {'path': str(path), **identity(after),
                    'sha256': hashlib.sha256(data).hexdigest(),
                    'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}
        return data, observed
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(parents):
            os.close(item[0])


def raw(path):
    key = str(path)
    if key not in cache:
        cache[key] = read_file(path)
    return cache[key][0]


def pin(path):
    raw(path)
    return cache[str(path)][1]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def document(path):
    return json.loads(raw(path), object_pairs_hook=unique_object,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('nonfinite JSON: ' + x)))


def bind(expected, *, label, path=None):
    global joins
    if not isinstance(expected, dict) or not all(key in expected for key in PIN_FIELDS):
        return check(False, label + ': complete raw pin')
    current_path = Path(expected['path']) if path is None else Path(path)
    must(str(current_path) == expected['path'], label + ': expected path')
    observed = pin(current_path)
    joins += 1
    return check({key: expected[key] for key in PIN_FIELDS} == observed,
                 label + ': bytes and complete physical identity',
                 details=None if all(expected[key] == observed[key] for key in PIN_FIELDS)
                 else {'expected': expected, 'observed': observed})


def content(rows):
    return [{key: row[key] for key in CONTENT_FIELDS} for row in rows]


def collect(root):
    files, directories = [], []
    for parent, names, leaves in os.walk(root, followlinks=False):
        p = Path(parent)
        status = p.lstat()
        must(stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode),
             'actual directory is ordinary: ' + str(p))
        directories.append({'relative_path': p.relative_to(root).as_posix(), **identity(status)})
        for name in names:
            status = (p / name).lstat()
            must(stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode),
                 'actual child directory is ordinary: ' + str(p / name))
        for name in leaves:
            q = p / name
            observed = pin(q)
            must(observed['uid'] == os.geteuid() and observed['nlink'] == 1
                 and observed['mode'] & 0o022 == 0, 'owned stable actual leaf: ' + str(q))
            files.append({'relative_path': q.relative_to(root).as_posix(), **observed})
    return sorted(files, key=lambda x: x['relative_path']), sorted(directories, key=lambda x: x['relative_path'])


def indexed_originals(rows, expected_paths, label):
    paths = [row['path'] for row in rows]
    check(len(paths) == len(set(paths)), label + ': no duplicate paths')
    check(paths == sorted(paths), label + ': frozen ordering')
    check(set(paths) == set(expected_paths), label + ': complete actual set',
          details={'missing': sorted(set(expected_paths) - set(paths)),
                   'extra': sorted(set(paths) - set(expected_paths))})
    for number, row in enumerate(rows):
        must(row['path'] in expected_paths, label + ': bounded target ' + str(number))
        bind(row, label=label + ':' + str(number))


def audit_closed_owner(policy):
    # Only these four fixed control originals may be read before bound closure.
    final = document(ACTUAL / 'FINAL.json')
    wrapped = document(ACTUAL / 'wrapper.json')
    life = document(ACTUAL / 'lifecycle.json')
    owner_request = document(ACTUAL / 'lifecycle.json.request.json')
    wrapper_projection = {key: value for key, value in wrapped.items()
                          if key not in {'receipt_sha256', 'supervisor_returncode'}}
    must(wrapped.get('receipt_sha256') == pin(ACTUAL / 'lifecycle.json')['sha256']
         and wrapper_projection == life, 'wrapper binds complete raw lifecycle')
    must(life.get('request_sha256') == pin(ACTUAL / 'lifecycle.json.request.json')['sha256'],
         'lifecycle binds complete raw owner request')
    expected_command = [policy['runtime']['path'], '-I', '-S', '-B', str(REQUEST.parent / 'control/worker.py')]
    must(owner_request['schema'] == life['schema'] == 'hepta.hia.selfhost-process-owner.v1'
         and owner_request['command'] == expected_command and final['command'] == expected_command
         and owner_request['cwd'] == str(REQUEST.parent)
         and owner_request['stdout_path'] == str(ACTUAL / 'child.stdout.log')
         and owner_request['stderr_path'] == str(ACTUAL / 'child.stderr.log')
         and owner_request['receipt_path'] == str(ACTUAL / 'lifecycle.json')
         and owner_request['implementation_sha256'] == life['implementation_sha256'] == policy['process_owner']['sha256'],
         'current owner command, cwd, outputs, implementation')
    must(owner_request['qualification_seconds'] == life['qualification_seconds'] == policy['qualification_seconds'] == 180
         and owner_request['cleanup_seconds'] == life['cleanup_seconds'] == policy['cleanup_seconds'] == 3
         and exact_int(owner_request['started_ns']) and exact_int(owner_request['deadline_ns'])
         and owner_request['deadline_ns'] - owner_request['started_ns'] == 180_000_000_000,
         'original exact owner budgets and deadline')
    environment = owner_request['env']
    must(set(environment) <= {'PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TZ',
                             'PYTHONDONTWRITEBYTECODE', 'PYTHONPYCACHEPREFIX'}
         and environment['PYTHONDONTWRITEBYTECODE'] == '1'
         and environment['PYTHONPYCACHEPREFIX'] == str(ACTUAL / 'unused-pycache'),
         'owner environment exact permitted key set and fixed Python values')
    cleanup = life['cleanup']
    must(exact_int(wrapped['supervisor_returncode']) and life['subreaper_enabled'] is True
         and cleanup['attempted'] is True and cleanup['complete'] is True
         and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
         and cleanup['deadline_exceeded'] is False and cleanup['errors'] == []
         and cleanup['remaining_direct_children'] == [], 'bound closed ECHILD before any child-body traversal')
    check(final['closed_owner_confirmed'] is True and final['child_originals_read'] is True,
          'finalizer records bound closed owner')
    natural = (wrapped['supervisor_returncode'] == 0 and life['status'] == 'OWNED_PROCESS_COMPLETED'
               and exact_int(life['returncode']) and life['returncode'] == 0
               and life['qualification_started'] is True and life['exit_observed_before_deadline'] is True
               and life['event_overflow'] is False and life['interrupted_signals'] == []
               and life.get('owner_error') is None and life.get('timed_out') is False
               and [row['kind'] for row in life['events']] == ['qualification_started', 'owned_child_observed',
                     'qualification_exit_observed', 'owned_child_reaped'])
    check(natural, 'natural zero original four-event lifecycle', kind='qualification')
    bind(final['request'], label='FINAL frozen REQUEST', path=REQUEST)
    observation = final['bound_owner_observation']
    bind(observation['lifecycle'], label='FINAL bound lifecycle', path=ACTUAL / 'lifecycle.json')
    bind(observation['request'], label='FINAL bound owner request', path=ACTUAL / 'lifecycle.json.request.json')
    check(observation['status'] == life['status'] and observation['returncode'] == life['returncode']
          and observation['supervisor_returncode'] == wrapped['supervisor_returncode'], 'FINAL owner observation exact')
    return final, life, owner_request


def expected_commands(policy):
    child = [policy['runtime']['path'], '-I', '-S', '-B', str(REQUEST.parent / 'control/child.py')]
    result = [('generator-' + format(index, '02d') + '-' + name,
               child + ['module', 'tools.generate_hia_' + name])
              for index, name in enumerate(policy['generator_names'], 1)]
    for stage in ('derive', 'idempotence'):
        result += [(stage + '-' + str(index), child + ['script', script, *args])
                   for index, (script, args) in enumerate(policy['derivations'], 1)]
    return result + [('source-tests', child + ['tests'])]


def audit_negative(policy, tests, source_by_name):
    allowed = policy['source_child_process_policy']
    rows = tests.get('allowed_negative_process_records', [])
    check(len(rows) == 4 and [row.get('index') for row in rows] == [1, 2, 3, 4],
          'four ordered actual negative process records', kind='qualification')
    output = []
    request_keys = ('schema', 'index', 'case', 'test_id', 'command', 'cwd', 'environment',
                    'timeout_seconds', 'runtime_before', 'binding_sources_before', 'temporary_parent',
                    'directory_before', 'cold_before', 'input_original', 'started_monotonic_ns')
    for number, row in enumerate(rows, 1):
        must(number <= 4, 'negative process index bounded')
        label = 'negative-admission-' + str(number)
        case = allowed['cases'][number - 1]
        root = Path(row['cwd'])
        command = [policy['runtime']['path'], *allowed['python_flags'],
                   str(Path(policy['source_root']) / allowed['script']), 'component', '--owner', case['owner'],
                   '--cold-report', str(root / 'cold.json'), '--output', str(root / 'report.json'),
                   '--evidence-dir', str(root / 'evidence')]
        env = dict(allowed['environment'])
        if case['development']:
            env[allowed['prefixes'][case['owner']] + '_DEVELOPMENT_MANIFEST'] = allowed['development_value']
        check(row['schema'] == 'hepta.source83-negative-admission-process.v1'
              and exact_int(row['index']) and row['index'] == number and row['case'] == case
              and row['test_id'] == allowed['target_test_id'] and row['command'] == command
              and row['environment'] == env and exact_int(row['timeout_seconds'])
              and row['timeout_seconds'] == allowed['timeout_seconds'] == 10,
              label + ': original exact command, environment, test, and budget')
        check(root.parent == Path(row['temporary_parent']) and root.name.startswith('tmp')
              and row['directory_before'] == row['directory_after']
              and row['directory_before']['mode'] == 0o700
              and row['directory_before']['uid'] == os.geteuid(), label + ': private original temporary directory')
        for field, suffix in (('input_original', 'input.bin'), ('request_original', 'request.json'),
                              ('receipt_original', 'receipt.json'), ('stdout', 'stdout.bin'), ('stderr', 'stderr.bin')):
            bind(row[field], label=label + ':' + field, path=ACTUAL / 'evidence' / (label + '.' + suffix))
        receipt = document(ACTUAL / 'evidence' / (label + '.receipt.json'))
        check(receipt == {key: value for key, value in row.items() if key != 'receipt_original'},
              label + ': complete raw receipt exactly equals final report projection')
        request_doc = document(ACTUAL / 'evidence' / (label + '.request.json'))
        check(request_doc == {key: row[key] for key in request_keys}, label + ': complete raw negative request')
        input_raw = raw(ACTUAL / 'evidence' / (label + '.input.bin'))
        check(input_raw == allowed['input_bytes_utf8'].encode() == b'{}', label + ': original invalid cold input')
        check(row['cold_before'] == row['cold_after'] and row['cold_before']['path'] == str(root / 'cold.json')
              and row['cold_before']['size'] == len(input_raw)
              and row['cold_before']['sha256'] == hashlib.sha256(input_raw).hexdigest()
              and row['cold_before']['git_blob_sha1'] == pin(ACTUAL / 'evidence' / (label + '.input.bin'))['git_blob_sha1'],
              label + ': removed temporary input remains exactly preserved')
        check(row['runtime_before'] == row['runtime_after'] == policy['runtime'], label + ': exact runtime unchanged')
        binding = [source_by_name[name] for name in allowed['binding_sources']]
        expected_binding = [{key: item[key] for key in PIN_FIELDS} for item in binding]
        check(row['binding_sources_before'] == row['binding_sources_after'] == expected_binding,
              label + ': four actual source identities unchanged')
        true_flags = ('popen_permission_consumed', 'process_started', 'original_run_called', 'original_run_returned',
                      'original_process_context_closed', 'output_absent', 'evidence_absent')
        check(all(row.get(key) is True for key in true_flags)
              and exact_int(row['pid']) and row['pid'] > 0 and exact_int(row['returncode'])
              and row['returncode'] != 0 and row['returncode_after_original_run'] == row['returncode']
              and row.get('error') is None and row.get('preservation_errors', []) == []
              and row['status'] == 'NEGATIVE_ADMISSION_RETURNED_AND_CLOSED',
              label + ': one real original negative process naturally returns nonzero and closes', kind='qualification')
        needle = b'development selection' if case['development'] else b'nested_report'
        check(needle in raw(ACTUAL / 'evidence' / (label + '.stderr.bin')),
              label + ': actual expected original admission refusal', kind='qualification')
        check(exact_int(row['started_monotonic_ns']) and exact_int(row['ended_monotonic_ns'])
              and row['ended_monotonic_ns'] >= row['started_monotonic_ns'], label + ': recorded real timing')
        output.append({'index': number, 'case': case, 'pid': row['pid'], 'returncode': row['returncode'],
                       'elapsed_ns': row['ended_monotonic_ns'] - row['started_monotonic_ns'],
                       'command': command, 'stdout': row['stdout'], 'stderr': row['stderr']})
    return output


def audit(output):
    started = time.monotonic()
    must(pin(REQUEST)['sha256'] == REQUEST_SHA256, 'exact canonical SOURCE129 request SHA')
    policy = document(REQUEST)
    must(policy['evidence_root'] == str(ACTUAL) and policy['expected_methods'] == 129
         and len(policy['expected_ids']) == len(set(policy['expected_ids'])) == 129
         and len(policy['generator_names']) == 63 and len(policy['derivations']) == 4
         and policy['base_commit'] == 'a06112e0b5de9ff70cf3546b29cc7bf5498d6697'
         and policy['base_tree'] == 'bada9276d3ee60376bcf98748052fce55bd7f605'
         and policy['physical_source_count'] == 1686, 'frozen SOURCE129 operation and complete denominators')
    final, life, owner_request = audit_closed_owner(policy)
    output['closed_owner_confirmed'] = True
    output['owner'] = {'lifecycle': pin(ACTUAL / 'lifecycle.json'), 'status': life['status'],
                       'returncode': life['returncode'], 'events': life['events'], 'cleanup': life['cleanup']}
    all_files, directories = collect(ACTUAL)
    output['actual_files'] = all_files
    output['actual_directories'] = directories
    paths = [row['path'] for row in all_files]
    indexed_originals(final['actual_originals'], [name for name in paths if name != str(ACTUAL / 'FINAL.json')],
                      'FINAL.actual_originals')
    originals_path = ACTUAL / 'evidence/ORIGINALS.json'
    if str(originals_path) in paths:
        indexed_originals(document(originals_path),
                          [name for name in paths if str(Path(name).parent).startswith(str(ACTUAL / 'evidence'))
                           and name != str(originals_path)], 'worker ORIGINALS')
    else:
        check(False, 'worker ORIGINALS complete index exists', kind='qualification')
    resource = document(ACTUAL / 'RESOURCE-OBSERVATION.json')
    check(exact_int(resource['available_bytes']) and resource['available_bytes'] >= policy['minimum_available_bytes'] == 512 * 1024 * 1024
          and exact_int(resource['free_inodes']) and resource['free_inodes'] >= policy['minimum_available_inodes'] == 4096
          and resource['native_trace_allocation'] is False, 'actual fresh resource precondition')
    for index, expected in enumerate(policy['control_inputs']):
        bind(expected, label='frozen control ' + str(index))
    bind(policy['process_owner'], label='original process owner')
    bind(policy['runtime'], label='exact runtime executable')
    bind(policy['peer_review_input'], label='current frozen peer review')
    before = document(ACTUAL / 'evidence/source-before.json')
    must(len(before) == 1686 and len({row['relative_path'] for row in before}) == 1686,
         'original source-before has 1686 unique paths')
    check(content(before) == policy['source_files'], 'source-before complete content equals frozen request')
    by_name = {row['relative_path']: row for row in before}
    source_root = Path(policy['source_root'])
    check(all(row['path'] == str(source_root / row['relative_path']) for row in before),
          'source-before full paths bind exact source root')
    snapshots = {}
    for name in ('source-after-generators', 'source-derived', 'source-after'):
        path = ACTUAL / 'evidence' / (name + '.json')
        if str(path) not in paths:
            check(False, name + ' actual exists', kind='qualification')
            continue
        rows = document(path)
        snapshots[name] = rows
        check(len(rows) == 1686 and [row['relative_path'] for row in rows] == [row['relative_path'] for row in before],
              name + ': complete fixed physical source set')
        check(all(row['path'] == str(source_root / row['relative_path']) for row in rows), name + ': exact source paths')
    if 'source-after-generators' in snapshots:
        check(content(snapshots['source-after-generators']) == content(before),
              'all 63 original generators preserve every source byte and mode', kind='qualification')
    derived_changes = []
    if 'source-derived' in snapshots:
        derived_changes = [row['relative_path'] for row in snapshots['source-derived']
                           if {key: row[key] for key in CONTENT_FIELDS} !=
                           {key: by_name[row['relative_path']][key] for key in CONTENT_FIELDS}]
        check(set(derived_changes) <= set(policy['allowed_derived_changes']), 'only allowed two derivation documents changed')
        for name in policy['allowed_derived_changes']:
            preserved = ACTUAL / 'evidence' / ('derived-' + Path(name).name)
            derived_pin = next(row for row in snapshots['source-derived'] if row['relative_path'] == name)
            check(pin(preserved)['size'] == derived_pin['size'] and pin(preserved)['sha256'] == derived_pin['sha256']
                  and pin(preserved)['git_blob_sha1'] == derived_pin['git_blob_sha1'],
                  'preserved complete actual derived bytes: ' + name)
        if 'source-after' in snapshots:
            check(content(snapshots['source-after']) == content(snapshots['source-derived']),
                  'four idempotence commands and complete tests preserve derived source', kind='qualification')
    if 'source-after' in snapshots:
        actual_source_files, _ = collect(source_root)
        check([row['relative_path'] for row in actual_source_files] == [row['relative_path'] for row in before],
              'final actual source physical set still exact')
        for row in snapshots['source-after']:
            bind(row, label='final source ' + row['relative_path'])
    report_path = ACTUAL / 'evidence/report.json'
    if str(report_path) not in paths:
        check(False, 'complete worker report exists', kind='qualification')
        return
    report = document(report_path)
    output['worker'] = {'pin': pin(report_path), 'status': report['status'], 'seconds': report.get('seconds'),
                        'error': report.get('error'), 'preservation_error': report.get('preservation_error')}
    check(report['schema'] == 'hepta.hia.core-integer-integration-source-run.v1'
          and report['base_commit'] == policy['base_commit'] and report['base_tree'] == policy['base_tree']
          and report['runtime'] == policy['runtime'] and report['generator_count'] == 63
          and report['original61_prefix'] == policy['generator_names'][:61]
          and report['original62_prefix'] == policy['generator_names'][:62]
          and report['expected_ids'] == policy['expected_ids'] and report['actual_git_HEAD_claimed'] is False,
          'worker current source, runtime, generator prefixes and 129 exact IDs')
    for holder, name in ((report, 'worker'), (final, 'FINAL')):
        check(all(holder[key] is False for key in FLAGS), name + ': no native/Core18/Core116/cold/installed claim')
        check(holder['zero_process_scope_claimed'] is False
              and holder['source_child_process_policy'] == policy['source_child_process_policy'], name + ': exact four-process exception scope')
    check(report['remote_triggered'] is False, 'no remote execution claim')
    check(report['status'] == final['status'] == 'SOURCE_INTEGRATION_PASS'
          and report.get('error') is None and report.get('preservation_error') is None and final.get('error') is None,
          'original source and parent statuses pass without errors', kind='qualification')
    check(report.get('actual_derived_changes') == derived_changes, 'worker actual derived changes rederived')
    if 'source-after' in snapshots:
        check(report['final_source_content'] == content(snapshots['source-after']), 'worker final source equals raw original')
        check(report['source_preserved_after_derivation'] is True, 'worker retained complete derivation stability', kind='qualification')
    wanted = expected_commands(policy)
    commands = report['commands']
    check(len(wanted) == len(commands) == 72, '63+4+4+1 complete 72 commands', kind='qualification')
    must(len(commands) <= 72, 'bounded source command sequence')
    summaries = []
    previous_end = None
    for index, row in enumerate(commands):
        label, command = wanted[index]
        check(row['label'] == label and row['command'] == command, 'command ' + str(index + 1) + ': exact ordered argv')
        check(exact_int(row['returncode']) and row['returncode'] == 0, label + ': actual zero return', kind='qualification')
        check(exact_int(row['started_monotonic_ns']) and exact_int(row['ended_monotonic_ns'])
              and row['started_monotonic_ns'] <= row['ended_monotonic_ns']
              and (previous_end is None or previous_end <= row['started_monotonic_ns']), label + ': ordered actual timestamps')
        previous_end = row['ended_monotonic_ns']
        report_name = 'source-tests.json' if label == 'source-tests' else label + '.report.json'
        for field, filename in (('stdout', label + '.stdout.log'), ('stderr', label + '.stderr.log'), ('report', report_name)):
            bind(row[field], label=label + ':' + field, path=ACTUAL / 'evidence' / filename)
        child = document(ACTUAL / 'evidence' / report_name)
        check(child['schema'] == 'hepta.hia.core-integer-integration-source-child.v1'
              and child['operation'] == command[5] and child['runtime_identity'] == policy['runtime']
              and child['runtime'].startswith('3.12.14 '), label + ': exact child operation and runtime')
        check(child['status'] == 'SOURCE_CHILD_PASS' and child.get('error') is None,
              label + ': child status', kind='qualification')
        check(child['native_or_compiler_or_process_attempts'] == [] and child['forbidden_attempts'] == []
              and child['forbidden_attempt_count'] == 0 and child['negative_permission_refusals'] == []
              and child['source_child_process_policy'] == policy['source_child_process_policy']
              and child['zero_process_scope_claimed'] is False, label + ': original poison and explicit four-command policy')
        check(all(child.get(key) is False for key in FLAGS if key != 'installed_executed'), label + ': original nonnative scope')
        if label != 'source-tests':
            check(child['allowed_negative_process_records'] == [] and child['allowed_negative_processes'] == 0
                  and child['expected_ids'] == child['loaded_ids'] == child['executed_ids'] == [],
                  label + ': no process permission outside source tests')
        summaries.append({'index': index + 1, 'label': label, 'returncode': row['returncode'],
                          'seconds': (row['ended_monotonic_ns'] - row['started_monotonic_ns']) / 1e9,
                          'child_seconds': child.get('seconds'), 'report': row['report'],
                          'stdout': row['stdout'], 'stderr': row['stderr']})
    output['commands'] = summaries
    test_path = ACTUAL / 'evidence/source-tests.json'
    if str(test_path) not in paths:
        check(False, 'complete original source test report exists', kind='qualification')
    else:
        tests = document(test_path)
        check(report.get('tests') == tests, 'worker embeds exact complete original test report', kind='qualification')
        if report.get('actual_source_test_report') is not None:
            bind(report['actual_source_test_report'], label='worker test report raw binding', path=test_path)
        check(tests['expected_ids'] == tests['loaded_ids'] == tests['executed_ids'] == policy['expected_ids']
              and exact_int(tests['tests_run']) and tests['tests_run'] == 129,
              'all 129 expected, loaded and executed original methods exact ordered equality', kind='qualification')
        check(all(tests[key] == [] for key in ANOMALIES), 'all six source-test anomalies empty', kind='qualification')
        check(exact_int(tests['allowed_negative_processes']) and tests['allowed_negative_processes']
              == report['allowed_negative_processes'] == final['allowed_negative_processes'] == 4
              and tests['forbidden_attempts'] == report['forbidden_attempts'] == final['forbidden_attempts'] == [],
              'exact four allowed original processes and zero forbidden attempts', kind='qualification')
        output['negative_processes'] = audit_negative(policy, tests, by_name)
        output['tests'] = {'pin': pin(test_path), 'expected': len(tests['expected_ids']),
                           'loaded': len(tests['loaded_ids']), 'executed': len(tests['executed_ids']),
                           'tests_run': tests['tests_run'], 'anomalies': {key: tests[key] for key in ANOMALIES},
                           'all_ids': tests['executed_ids']}
    # A second physical read prevents relying only on cached prior pin comparisons.
    for row in all_files:
        _, reread = read_file(row['path'])
        check(reread == {key: row[key] for key in PIN_FIELDS}, 'actual terminal reread stable: ' + row['relative_path'])
    output['actual_derived_changes'] = derived_changes
    output['raw_file_count'] = len(all_files)
    output['raw_bytes'] = sum(row['size'] for row in all_files)
    output['raw_directory_count'] = len(directories)
    output['reader_seconds'] = time.monotonic() - started


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--closed-ack', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.closed_ack or args.output.exists() or args.output.is_relative_to(ACTUAL):
        raise SystemExit('explicit closure acknowledgement and fresh external audit output required')
    output = {'schema': 'hepta.hia.v92-source129-independent-actual-audit.v1',
              'status': 'HOLD', 'request_commit': PUBLISHED_REQUEST_COMMIT,
              'request_path': str(REQUEST), 'request_sha256': REQUEST_SHA256,
              'actual_root': str(ACTUAL), 'parent_closure_acknowledgement': args.closed_ack,
              'closed_owner_confirmed': False, 'product_rerun': False, 'source_imported': False,
              'native_executed': False, 'qualification_scope': 'LOCAL_PYTHON_3_12_14_SOURCE129_ONLY',
              'native_Core39_Core18_Core116_cold_installed_qualified': False}
    try:
        audit(output)
    except BaseException:
        output['reader_error'] = traceback.format_exc()
    output['checks'] = checks
    output['check_count'] = len(checks)
    output['failed_checks'] = [row for row in checks if not row['pass']]
    output['raw_pin_join_count'] = joins
    integrity = not any(not row['pass'] and row['kind'] == 'integrity' for row in checks)
    qualified = not any(not row['pass'] and row['kind'] == 'qualification' for row in checks)
    output['custody_pass'] = integrity and output['closed_owner_confirmed'] and 'reader_error' not in output
    output['source129_qualification_pass'] = output['custody_pass'] and qualified
    output['status'] = ('CUSTODY_AND_SOURCE129_QUALIFICATION_PASS' if output['source129_qualification_pass'] else
                        'CUSTODY_PASS_SOURCE129_HOLD' if output['custody_pass'] else 'HOLD')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as stream:
        stream.write((json.dumps(output, sort_keys=True, indent=2) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({key: output.get(key) for key in ('status', 'check_count', 'raw_pin_join_count',
          'raw_file_count', 'raw_bytes', 'reader_seconds', 'reader_error')}))
    return 0 if output['custody_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
