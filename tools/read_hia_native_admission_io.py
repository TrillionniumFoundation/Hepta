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


def child(root, action, *, repository, _raw_snapshot=None):
    root, repository = Path(root), Path(repository)
    require(action in COUNTS, 'unknown control action')
    snapshots = {}
    def consume(path):
        path = Path(path)
        # v2 aggregation validates its one captured byte version. The default
        # v1 path still performs the original fresh read here.
        raw = path.read_bytes() if _raw_snapshot is None else _raw_snapshot[path]
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



MATCHED_STATUS = 'PASS_MATCHED_FINITE_OBSERVER'
MATCHED_LANES = ('original-a', 'original-b', 'candidate')
MATCHED_CASES = (('small', 4096), ('large', 100000), ('small', 2), ('empty', 4096),
                 ('directory', 4096), ('link', 4096), ('fifo', 4096), ('missing', 4096))
MATCHED_STAT_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                       'st_rdev', 'st_size', 'st_atime_ns', 'st_mtime_ns', 'st_ctime_ns')
MATCHED_SOURCES = (
    'hepta/hia_native_admission_io.py', 'hepta/hia_json_preflight_native.py',
    'hepta/hia_native_helpers.py', 'hepta/hia_store_file_capture_native.py',
    'tools/build_hia_store_file_capture.py',
    'tests/test_hia_native_admission_io.py', 'tests/hia_native_admission_io_controls.py',
    'tools/read_hia_native_admission_io.py',
    'tests/fixtures/hia_native_admission_io/regular_bytes.py.txt',
    'tests/fixtures/hia_native_admission_io/source_resource_path.py.txt',
    'tests/fixtures/hia_native_admission_io/source-identity.json',
    'tests/test_hia_store_file_capture_native.py',
    'tests/hia_store_file_capture_controls.py',
    'tests/hia_store_file_capture_installed.py',
    'examples/hia_bootstrap/store_file_capture.hepta',
)


def _matched_canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _matched_error(row, number):
    require(set(row) == {'status', 'error'}
            and row['status'] == 'raised' and type(row['error']['errno']) is int
            and row['error']['errno'] == number, 'actual FD probe error differs')
    require(set(row['error']) == {'type', 'text', 'args', 'errno', 'filename',
                                 'filename2', 'name', 'obj'}, 'raw error fields missing')


def _matched_fd_table(snapshot, *, initial=False):
    require(snapshot['atomic_snapshot_claimed'] is False
            and snapshot['fd_cleanup_performed'] is False, 'FD snapshot scope widened')
    names, rows = snapshot['enumerated'], snapshot['rows']
    require(type(names) is list and all(type(x) is str and x.isdecimal()
            and str(int(x)) == x for x in names)
            and names == sorted(set(names), key=int)
            and [row['fd'] for row in rows] == [int(x) for x in names],
            'FD enumeration/probes are incomplete or unordered')
    live, absent = [], []
    for row in rows:
        require(set(row) == {'fd', 'readlink', 'fstat', 'getfd', 'getfl', 'position'}
                and type(row['fd']) is int and row['fd'] >= 0, 'raw FD probe fields differ')
        if row['fstat']['status'] == 'returned':
            live.append(row['fd'])
            value = row['fstat']['value']
            require(set(row['fstat']) == {'status', 'value'}
                    and set(value) == set(MATCHED_STAT_FIELDS)
                    and all(type(value[x]) is int for x in MATCHED_STAT_FIELDS),
                    'actual descriptor stat is incomplete')
            require(row['readlink']['status'] == 'returned'
                    and type(row['readlink']['value']) is str
                    and all(row[key]['status'] == 'returned'
                            and type(row[key]['value']) is int for key in ('getfd', 'getfl')),
                    'live descriptor changed during its probes')
            if row['position']['status'] == 'returned':
                require(type(row['position']['value']) is int, 'noninteger descriptor position')
            else:
                _matched_error(row['position'], 29)  # actual ESPIPE, not a fabricated position
        else:
            absent.append(row['fd'])
            _matched_error(row['readlink'], 2)
            for key in ('fstat', 'getfd', 'getfl', 'position'):
                _matched_error(row[key], 9)
    first_free = 0
    while first_free in live:
        first_free += 1
    require(absent == [first_free] and len(rows) == len(live) + 1,
            'FD snapshot contains unexplained missing or extra descriptors')
    if initial:
        require(live == [0, 1, 2] and names == ['0', '1', '2', '3'],
                'initial process has an extra or missing live descriptor')
    return live


def _matched_version(observer):
    require(type(observer) is str and observer in ('matched-v2', 'matched-v3'),
            'unknown matched regular observer version')
    return '3' if observer == 'matched-v3' else '2'


def matched_input_preparation(plan, preparation):
    """Validate the recorded v3 setup; preserve both complete stat observations."""
    monotonic = (
        'started_monotonic_ns', 'before_snapshot_started_monotonic_ns',
        'before_snapshot_ended_monotonic_ns', 'delay_started_monotonic_ns',
        'delay_ended_monotonic_ns', 'after_snapshot_started_monotonic_ns',
        'after_snapshot_ended_monotonic_ns', 'ended_monotonic_ns')
    wall = ('started_time_ns', 'delay_started_time_ns',
            'delay_ended_time_ns', 'ended_time_ns')
    fields = {
        'schema', 'status', 'input_root', 'owner_pid', 'owner_pgid', 'source_before',
        'requested_delay_ns', 'delay_calls', 'snapshot_calls', 'provider_calls',
        'fd_cleanup_performed', 'timestamp_override_performed', 'retry_performed',
        'candidate_derived_expectation', 'whole_admission_qualification',
        'all_input_equivalence', 'error', 'before_inputs', 'after_inputs',
    } | set(monotonic) | set(wall)
    require(type(preparation) is dict and set(preparation) == fields
            and preparation['schema'] == 'hepta.hia.native-admission-regular-input-preparation.v3'
            and preparation['status'] == 'PREPARED_FIXED_HISTORY'
            and preparation['error'] is None
            and preparation['input_root'] == plan['input_root']
            and preparation['source_before'] == plan['source_before']
            and type(preparation['owner_pid']) is int
            and type(preparation['owner_pgid']) is int
            and preparation['owner_pid'] == plan['owner_pid']
            and preparation['owner_pgid'] == plan['owner_pgid'],
            'fixed input preparation identity or complete record differs')
    require(type(plan['input_preparation']) is dict
            and set(plan['input_preparation']) == {'path', 'bytes', 'sha256'}
            and Path(plan['input_preparation']['path']).is_absolute()
            and Path(plan['input_preparation']['path']).name == 'input-preparation.json'
            and type(plan['input_preparation']['bytes']) is int
            and _pin(_matched_canonical(preparation)) == {
                'bytes': plan['input_preparation']['bytes'],
                'sha256': plan['input_preparation']['sha256']},
            'fixed input preparation is not bound to the exact plan bytes')
    require(type(preparation['requested_delay_ns']) is int
            and preparation['requested_delay_ns'] == 1000000000
            and type(preparation['delay_calls']) is int and preparation['delay_calls'] == 1
            and type(preparation['snapshot_calls']) is int and preparation['snapshot_calls'] == 2
            and type(preparation['provider_calls']) is int and preparation['provider_calls'] == 0
            and preparation['fd_cleanup_performed'] is False
            and preparation['timestamp_override_performed'] is False
            and preparation['retry_performed'] is False
            and preparation['candidate_derived_expectation'] is False
            and preparation['whole_admission_qualification'] == 'HOLD'
            and preparation['all_input_equivalence'] is False,
            'fixed input preparation changed its declared operations or scope')
    moments = [preparation[name] for name in monotonic]
    require(all(type(value) is int and value >= 0 for value in moments)
            and moments == sorted(moments)
            and preparation['delay_ended_monotonic_ns']
                - preparation['delay_started_monotonic_ns'] >= 1000000000
            and all(type(preparation[name]) is int for name in wall),
            'fixed input preparation clock interval or order differs')
    before, after = preparation['before_inputs'], preparation['after_inputs']
    require(type(before) is dict and type(after) is dict
            and set(before) == set(after) == {
                'small', 'large', 'empty', 'directory', 'link', 'fifo', 'missing'}
            and after == plan['input_before'],
            'fixed preparation did not supply the complete real plan input snapshot')
    # Both raw snapshots retain every original stat field. Their recorded
    # atime changes are setup facts, not values copied into or removed from
    # the later exact plan/lane/final comparisons.
    for name in before:
        first, second = before[name], after[name]
        require(type(first) is dict and type(second) is dict
                and set(first) == set(second)
                and first['path'] == second['path'] == str(Path(plan['input_root']) / name),
                'fixed preparation input paths or fields differ')
        for key in first:
            if key != 'lstat':
                require(first[key] == second[key], 'fixed preparation changed original input bytes or target')
        if name == 'missing':
            require(first['lstat'] == second['lstat'], 'fixed preparation changed original missing input')
            _matched_error(first['lstat'], 2)
            continue
        require(set(first['lstat']) == set(second['lstat']) == {'status', 'value'}
                and first['lstat']['status'] == second['lstat']['status'] == 'returned',
                'fixed preparation input stat did not return')
        left, right = first['lstat']['value'], second['lstat']['value']
        require(type(left) is dict and type(right) is dict
                and set(left) == set(right) == set(MATCHED_STAT_FIELDS)
                and all(type(left[field]) is int and type(right[field]) is int
                        for field in MATCHED_STAT_FIELDS),
                'fixed preparation dropped or changed a stat field type')
        changed = [field for field in MATCHED_STAT_FIELDS if left[field] != right[field]]
        require(all(field == 'st_atime_ns' for field in changed),
                'fixed read-only preparation changed an input identity or non-access timestamp')
    return preparation['ended_monotonic_ns']


def matched_preconditions(plan, reports, input_after, *, observer='matched-v2', preparation=None):
    # Shared pure-data predicate: the external reader runs it again over its
    # own complete pinned reads. No product import or candidate oracle here.
    version = _matched_version(observer)
    cases = [{'index': i, 'id': name, 'limit': limit}
             for i, (name, limit) in enumerate(MATCHED_CASES)]
    require(plan['schema'] == 'hepta.hia.native-admission-regular-plan.v' + version
            and plan['lanes'] == list(MATCHED_LANES) and plan['cases'] == cases
            and set(plan['source_before']) == set(MATCHED_SOURCES)
            and plan['owner_budget_seconds'] == 60 and type(plan['owner_budget_seconds']) is int
            and plan['owner_cleanup_seconds'] == 3 and type(plan['owner_cleanup_seconds']) is int
            and type(plan['owner_pid']) is int and plan['owner_pid'] > 0
            and type(plan['owner_pgid']) is int and plan['owner_pgid'] == plan['owner_pid']
            and plan['additional_lane_budget'] is None
            and plan['launch'] == {'close_fds': True, 'start_new_session': False,
                                  'stdin': 'INHERIT', 'stdout': 'INHERIT', 'stderr': 'INHERIT'}
            and plan['whole_admission_qualification'] == 'HOLD'
            and plan['all_input_equivalence'] is False, 'matched plan scope differs')
    require(len(reports) == 3 and [row['lane'] for row in reports] == list(MATCHED_LANES)
            and len({row['pid'] for row in reports}) == 3, 'three independent lanes missing')
    expected_inputs = plan['input_before']
    require(set(expected_inputs) == {'small', 'large', 'empty', 'directory', 'link', 'fifo', 'missing'}
            and input_after == expected_inputs, 'shared input bytes/identities changed')
    expected_bytes = {'small': b'bounded\0bytes\n', 'large': bytes(range(256)) * 300, 'empty': b''}
    for name, row in expected_inputs.items():
        require(row['path'] == str(Path(plan['input_root']) / name), 'input path differs')
        if name in expected_bytes:
            require(row['content'] == _pin(expected_bytes[name]), 'original input bytes differ')
        if name == 'link':
            require(row['target'] == 'small', 'original link target differs')
        if name == 'missing':
            _matched_error(row['lstat'], 2)
        else:
            require(row['lstat']['status'] == 'returned'
                    and set(row['lstat']['value']) == set(MATCHED_STAT_FIELDS),
                    'actual input identity missing')
            mode = row['lstat']['value']['st_mode'] & 0o170000
            require(mode == (0o040000 if name == 'directory' else 0o120000 if name == 'link'
                             else 0o010000 if name == 'fifo' else 0o100000),
                    'original input kind differs')
    common = reports[0]['initial']['common']
    for lane, row in zip(MATCHED_LANES, reports):
        require(row['schema'] == 'hepta.hia.native-admission-regular-lane.v' + version
                and row['status'] == 'LANE_RECORDED'
                and type(row['pid']) is int and row['pid'] > 0
                and type(row['ppid']) is int and type(row['pgid']) is int
                and row['ppid'] == plan['owner_pid'] and row['pgid'] == plan['owner_pgid']
                and row['source_before'] == row['source_after'] == plan['source_before']
                and row['source_unchanged'] is True and row['plan_unchanged'] is True
                and row['plan_sha256'] == sha256(_matched_canonical(plan)).hexdigest()
                and row['ordered_cases'] == cases
                and row['provider_replaced'] is False and row['fd_cleanup_performed'] is False
                and row['whole_admission_qualification'] == 'HOLD'
                and row['all_input_equivalence'] is False, 'lane/source/case custody differs')
        initial = row['initial']
        require(initial['full_process_or_heap_equivalence_claimed'] is False
                and initial['task_ids'] == [row['pid']]
                and initial['common'] == common
                and common['environment_sha256'] == plan['environment_sha256']
                and common['inputs'] == row['inputs_after'] == expected_inputs,
                'initial runtime/process/FD/input preconditions do not match')
        _matched_fd_table(common['fds'], initial=True)
        _matched_fd_table(row['final_fds'])
        probe = row['directory_fd_after_all_eight']
        require(type(row['directory_filename']) is int
                and probe['fd'] == row['directory_filename'],
                'directory probe does not use the actual raw filename number')
        matching = [fd for fd in row['final_fds']['rows'] if fd['fd'] == probe['fd']]
        require(len(matching) == 1 and matching[0] == probe,
                'directory FD changed between final actual probes')
        if probe['fstat']['status'] == 'returned':
            value = probe['fstat']['value']
            directory = expected_inputs['directory']['lstat']['value']
            require(all(value[key] == directory[key] for key in ('st_dev', 'st_ino', 'st_mode')),
                    'retained actual filename does not identify the private directory')
    if observer == 'matched-v3':
        setup_end = matched_input_preparation(plan, preparation)
        require(all(type(row['started_monotonic_ns']) is int
                    and setup_end <= row['started_monotonic_ns'] for row in reports),
                'fixed input preparation did not finish before every actual lane')
    else:
        require(preparation is None, 'matched-v2 cannot consume a v3 preparation record')


def matched_child(root, *, repository, _raw_snapshot=None, observer='matched-v2'):
    version = _matched_version(observer)
    root, repository = Path(root), Path(repository)
    output = root / 'regular'
    captured = {}
    def consume(path):
        path = Path(path)
        # This is the same raw version reported by the v2 aggregate ledger.
        raw = path.read_bytes() if _raw_snapshot is None else _raw_snapshot[path]
        require(path not in captured or captured[path] == raw, 'matched evidence changed between reads')
        captured[path] = raw
        return raw
    report = _object(consume(output / 'report.json'))
    result = _object(consume(root / 'regular.result.json'))
    start = _object(consume(root / 'regular.start.json'))
    invocation = _object(consume(root / 'invocation.json'))
    require(report['schema'] == 'hepta.hia.native-admission-regular-matched-control.v' + version
            and report['status'] == MATCHED_STATUS and report['observer'] == observer
            and report['action'] == 'regular' and report['source_unchanged'] is True
            and report['source_before'] == report['source_after']
            and set(report['source_before']) == set(MATCHED_SOURCES)
            and report['qualified_whole_native_stack'] is False
            and report['native_Capture_inputs_replaced'] is False
            and report['whole_admission_qualification'] == 'HOLD'
            and report['all_input_equivalence'] is False
            and report['legacy_v1_failure_reclassified'] is False, 'matched report is not scoped v' + version)
    command = result['command']
    require(command == start['command']
            and command == [report['runtime']['executable'], '-I', '-B',
                str(repository / 'tests/hia_native_admission_io_controls.py'),
                '--action', 'regular', '--output', str(output),
                '--regular-observer', observer]
            and result['cwd'] == start['cwd'] == str(repository)
            and type(result['timeout_seconds']) is int and result['timeout_seconds'] == 60
            and type(result['cleanup_seconds']) is int and result['cleanup_seconds'] == 3
            and result['timeout'] is False and result['cleanup_error'] is None
            and type(result['returncode']) is int and result['returncode'] == 0
            and type(result['expected_returncode']) is int and result['expected_returncode'] == 0
            and result['cleanup']['before'] == [] and result['cleanup']['after'] == []
            and result['cleanup']['reaped'] is True,
            'matched observer exceeded or replaced the original owned 60+3 boundary')
    require(start['timeout_seconds'] == 60 and start['cleanup_seconds'] == 3
            and start['started_time_ns'] == result['started_time_ns'],
            'matched original start receipt differs')
    for field in ('pid', 'pgid'):
        require(type(report[field]) is int and report[field] > 0
                and report[field] == start[field] == result[field], 'actual owner identity differs')
    require(type(report['ppid']) is int and report['pid'] == report['pgid']
            and invocation['schema'] == 'hepta.hia.native-admission-invocation.v1'
            and invocation['phase'] == 'source'
            and invocation['original_Capture_gates_replaced'] is False
            and invocation['retained_diagnostics'] == str(root)
            and type(invocation['pid']) is int and invocation['pid'] == report['ppid'], 'matched actual parent invocation differs')
    for stream in ('stdout', 'stderr'):
        raw = consume(root / ('regular.' + stream + '.log'))
        require(sha256(raw).hexdigest() == result[stream + '_sha256'],
                'actual inherited stdout/stderr bytes changed')
    for name, pin in report['source_before'].items():
        require(_pin(consume(repository / _relative(name))) == pin, 'matched current source differs')
    files = report['files']
    expected_files = {'source-before.json', 'matched-plan.json', 'input-after.json',
                      'expected.json', 'repeat-original.json', 'actual.json', 'differences.json',
                      'fd-lifecycle.json', 'healthy-descriptor.json'}
    if observer == 'matched-v3':
        expected_files.add('input-preparation.json')
    for lane in MATCHED_LANES:
        expected_files.update({lane + '.start.json', lane + '.result.json',
                               lane + '/source-before.json', lane + '/observations.json',
                               lane + '/report.json'})
    require(set(files) == expected_files
            and {str(path.relative_to(output)) for path in output.rglob('*') if path.is_file()}
                == expected_files | {'report.json'}, 'matched evidence file closure differs')
    def evidence(name):
        require(name in files, 'required matched evidence is unsigned')
        raw = consume(output / _relative(name))
        require(_pin(raw) == files[name], 'matched evidence pin differs')
        return raw
    for name in sorted(files):
        evidence(name)
    require(_object(evidence('source-before.json')) == report['source_before'],
            'matched source snapshot changed')
    plan = _object(evidence('matched-plan.json'))
    require(plan['owner_pid'] == report['pid'] and plan['owner_pgid'] == report['pgid']
            and plan['source_before'] == report['source_before'], 'plan is not owned by actual observer')
    lane_reports = [_object(evidence(lane + '/report.json')) for lane in MATCHED_LANES]
    preparation = None
    if observer == 'matched-v3':
        preparation_raw = evidence('input-preparation.json')
        require(plan['input_preparation'] == {
                    'path': str(output / 'input-preparation.json'), **_pin(preparation_raw)},
                'fixed preparation path/raw pin is detached from the actual evidence')
        preparation = _object(preparation_raw)
    matched_preconditions(plan, lane_reports, _object(evidence('input-after.json')),
                          observer=observer, preparation=preparation)
    if observer == 'matched-v3':
        require(type(report['started_monotonic_ns']) is int
                and report['started_monotonic_ns'] <= preparation['started_monotonic_ns'],
                'fixed input preparation predates its actual owner')
    require(all(row['initial']['common']['runtime']['executable'] == command[0]
                and row['initial']['common']['runtime']['version'] == report['runtime']['version']
                and row['initial']['common']['runtime']['implementation'] == report['runtime']['implementation']
                and row['initial']['common']['cwd'] == str(repository) for row in lane_reports),
            'lane runtime differs from its actual owner interpreter/cwd')
    previous_end = (report['started_monotonic_ns'] if observer == 'matched-v2'
                    else preparation['ended_monotonic_ns'])
    observations = []
    for lane, lane_report in zip(MATCHED_LANES, lane_reports):
        receipt = _object(evidence(lane + '.result.json'))
        begin = _object(evidence(lane + '.start.json'))
        lane_command = [command[0], '-I', '-B', command[3],
                        '--action', 'regular', '--output', str(output / lane),
                        '--regular-observer', observer, '--regular-lane', lane,
                        '--regular-base', plan['input_root'],
                        '--regular-plan', str(output / 'matched-plan.json')]
        require(receipt['schema'] == 'hepta.hia.native-admission-regular-lane-owner.v' + version
                and receipt['lane'] == lane and receipt['command'] == lane_command
                and receipt['cwd'] == lane_report['cwd'] == str(repository)
                and lane_report['argv'] == lane_command[3:]
                and receipt['owner_pid'] == lane_report['ppid'] == report['pid']
                and receipt['owner_pgid'] == lane_report['pgid'] == report['pgid']
                and receipt['pid'] == lane_report['pid']
                and receipt['launch'] == plan['launch']
                and receipt['environment_sha256'] == plan['environment_sha256']
                and receipt['additional_lane_budget'] is None
                and type(receipt['returncode']) is int and receipt['returncode'] == 0
                and receipt['leader_reaped'] is True,
                'actual fresh lane launch/terminal differs')
        require(set(receipt) == set(begin) | {'returncode', 'leader_reaped', 'ended_monotonic_ns'}
                and all(receipt[key] == value for key, value in begin.items()),
                'lane terminal does not extend its exact actual start')
        moments = [previous_end, receipt['started_monotonic_ns'],
                   lane_report['started_monotonic_ns'], lane_report['ended_monotonic_ns'],
                   receipt['ended_monotonic_ns'], report['ended_monotonic_ns']]
        require(all(type(x) is int for x in moments) and moments == sorted(moments),
                'three full lanes did not run in declared sequential owner order')
        previous_end = receipt['ended_monotonic_ns']
        require(_object(evidence(lane + '/source-before.json')) == report['source_before'],
                'lane source-before raw file differs')
        raw = evidence(lane + '/observations.json');rows = _object(raw)
        require(type(rows) is list and len(rows) == 8
                and [row['id'] for row in rows] == [name for name, limit in MATCHED_CASES]
                and all(set(row) == {'id', 'outcome'} for row in rows)
                and _pin(raw) == lane_report['observation_pin']
                and raw == _matched_canonical(rows), 'full original eight raw observations differ')
        require(rows[4]['outcome']['status'] == 'raised'
                and rows[4]['outcome']['error']['filename']
                    == {'type': 'int', 'value': lane_report['directory_filename']},
                'directory FD probe is detached from original raw error')
        for row in rows:
            value = row['outcome']
            require(value['status'] in ('raised', 'returned'), 'unknown actual outcome status')
            if value['status'] == 'raised':
                require(set(value) == {'status', 'error'}
                        and set(value['error']) == {'type', 'text', 'args', 'errno', 'filename',
                                                   'filename2', 'name', 'obj'},
                        'original exception field was dropped')
            elif value['type'] == 'bytes':
                require(set(value) == {'status', 'type', 'hex'}
                        and bytes.fromhex(value['hex']).hex() == value['hex'],
                        'original returned bytes were altered')
            else:
                require(set(value) == {'status', 'type', 'value'}, 'original outcome field was dropped')
        observations.append(raw)
    # The strict preconditions and actual terminals above precede value comparison.
    require(observations[0] == observations[1] == observations[2]
            and evidence('expected.json') == observations[0]
            and evidence('repeat-original.json') == observations[1]
            and evidence('actual.json') == observations[2]
            and _object(evidence('differences.json')) == [], 'full matched raw value/error streams differ')
    final_a, final_b, final_c = [row['final_fds'] for row in lane_reports]
    lifecycle = _object(evidence('fd-lifecycle.json'))
    fd_status = ('FD_STATES_EQUAL_IN_OBSERVED_DOMAIN' if final_a == final_c
                 else 'FD_SEMANTICS_DIFFERENT')
    require(final_a == final_b
            and lifecycle == {
                'schema': 'hepta.hia.native-admission-regular-fd-lifecycle.v' + version,
                'status': fd_status, 'original_repeat_equal': True,
                'candidate_end_state_equal': final_a == final_c,
                'cutpoint': 'AFTER_ALL_EIGHT_BEFORE_TERMINAL_REPORT_FILES',
                'close_call_or_count_claimed': False, 'fd_cleanup_performed': False,
                'directory_probes': [row['directory_fd_after_all_eight'] for row in lane_reports],
                'whole_admission_qualification': 'HOLD', 'all_input_equivalence': False},
            'raw FD lifecycle difference was omitted or reclassified')
    healthy = _object(evidence('healthy-descriptor.json'))
    require(type(healthy['opened']) is list and len(healthy['opened']) == 1
            and type(healthy['opened'][0]) is int and healthy['opened'][0] >= 0
            and healthy['inheritable'] == [False] and healthy['one_descriptor_closed'] is True,
            'original healthy/CLOEXEC control missing')
    require(report['observations'] == {
                'count': 8, 'lanes': list(MATCHED_LANES), 'actual_outcome_calls': 24,
                'differences': 0, 'one_descriptor_closed': True, 'fd_lifecycle_status': fd_status,
                'qualification_scope': 'MATCHED_INITIAL_FD_FINITE_VALUE_ERROR_OBSERVER_ONLY',
                'whole_admission_qualification': 'HOLD', 'all_input_equivalence': False,
                'legacy_v1_failure_reclassified': False}, 'matched summary widened its actual scope')
    for path, raw in captured.items():
        require(path.read_bytes() == raw, 'matched evidence/source changed at final full reread')
    return report


def matched_source_readback(args):
    observer = getattr(args, 'regular_observer', 'matched-v2')
    version = _matched_version(observer)
    require(args.phase == 'source', 'matched regular successor is not a Native qualification mode')
    require(not args.output.exists(), 'matched readback output must be create-only')
    snapshots = {}
    initial_names = {str(path.relative_to(args.evidence)) for path in args.evidence.rglob('*')
                     if path.is_file()}
    for name in sorted(initial_names):
        path = args.evidence / _relative(name);snapshots[path] = path.read_bytes()
    for name in MATCHED_SOURCES:
        path = args.repository / _relative(name);snapshots[path] = path.read_bytes()
    reports = [matched_child(args.evidence, repository=args.repository, _raw_snapshot=snapshots,
                             observer=observer)
               if action == 'regular' else child(args.evidence, action,
                   repository=args.repository, _raw_snapshot=snapshots) for action in SOURCE]
    custody_path = args.evidence / 'source-custody.json'
    custody = _object(snapshots[custody_path])
    require(custody['unchanged'] is True
            and custody['source_before'] == custody['source_after']
            and all(row['source_before'] == custody['source_before'] for row in reports)
            and custody['whole_admission_qualification'] == 'HOLD'
            and custody['all_input_equivalence'] is False
            and custody['legacy_v1_failure_reclassified'] is False
            and custody['regular_observer_scope'] == reports[1]['observations']
            and custody['regular_observer_status'] == MATCHED_STATUS,
            'Source class custody does not explicitly retain the finite/HOLD distinction')
    require({str(path.relative_to(args.evidence)) for path in args.evidence.rglob('*') if path.is_file()}
            == initial_names, 'full Source evidence closure changed while read')
    for path, raw in snapshots.items():
        require(path.read_bytes() == raw, 'full Source v' + version + ' evidence/source changed at terminal reread')
    result = {'schema': 'hepta.hia.native-admission-control-readback.v' + version,
              'status': MATCHED_STATUS, 'phase': 'source', 'actions': list(SOURCE),
              'counts': [row['observations']['count'] for row in reports],
              'action_statuses': [row['status'] for row in reports],
              'regular_observer': observer,
              'fd_lifecycle_status': reports[1]['observations']['fd_lifecycle_status'],
              'whole_admission_qualification': 'HOLD', 'all_input_equivalence': False,
              'legacy_v1_failure_reclassified': False, 'original_Capture_gates_still_required': True,
              'whole_native_stack_qualified': False,
              'actual_inputs': [{'path': str(path), **_pin(raw)} for path, raw in snapshots.items()]}
    with args.output.open('x') as stream:
        json.dump(result, stream, ensure_ascii=True, sort_keys=True, indent=2);stream.write('\n')
    print(json.dumps({key: result[key] for key in ('schema', 'status', 'fd_lifecycle_status',
                     'whole_admission_qualification', 'all_input_equivalence')}, sort_keys=True))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--phase', choices=('source', 'native'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--regular-observer', choices=('legacy-v1', 'matched-v2', 'matched-v3'), default='legacy-v1')
    args = parser.parse_args()
    if args.regular_observer in ('matched-v2', 'matched-v3'):
        return matched_source_readback(args)
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
