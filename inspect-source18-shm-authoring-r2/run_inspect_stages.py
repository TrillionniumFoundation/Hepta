"""Explicit stages on the actual, privately generated inspect source.

The first reviewed plan enables only Source10 and the separate synthetic
Source8 group. The same runner has the retained build/Native17/VM12 path, but
that path requires a later plan pinned to the actual successful Source18
result and all its retained evidence. No generation or source preparation is
performed here, and no historical result is promoted to the new source.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import stat
import sys
import time
import traceback
from types import SimpleNamespace

HERE = Path(__file__).absolute().parent
SCOPE = Path('/workspace/scratch/dda74a4fae35/v132-inspect-machine-entry-r1/successor-r2')
PRIOR_STAGE = SCOPE / 'execution-stage-r1'
EVIDENCE_SCOPE = Path('/dev/shm/hia-inspect-stages-dda7')
EVIDENCE_AUTHORITY = {'schema': 'hepta.hia.inspect-fixed-evidence-filesystem.v1', 'path': '/dev/shm/hia-inspect-stages-dda7', 'device': 38, 'inode': 2, 'mode': 448, 'uid': 1000, 'gid': 1000}
GEN = SCOPE / 'generation-attempt-r1'
GEN_STAGE = SCOPE / 'generation-stage-r1'
SOURCE = SCOPE / 'materialization-attempt-r1/source'
BASE = Path('/workspace/scratch/dda74a4fae35/v119-inspect-generation-only-r1/attempt-r1/source')
KIT = Path('/workspace/scratch/dda74a4fae35/v119-inspect-policy-execution-r1')
OLD_SOURCE = Path('/workspace/scratch/dda74a4fae35/v119-inspect-source10-r1')
SCHEMA = 'hepta.hia.inspect-private-shared-stages.v1'
SOURCE_TREE = '741fa64dadb37f98ab9b195f1ee7b67fe683fc70'
SOURCE_GROUPS = ('source10', 'source8-physical-lease')
SECONDS, CLEANUP, MIB, MINIMUM_FREE = 180, 3, 1048576, 1073741824
_ATTEMPT = None


def require(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw):
    return {'bytes': len(raw), 'mode': '100644', 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def capture_bytes(path, maximum):
    """Small pre-bootstrap reader; all complete artifact pins remain required."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute fixed path required')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        def same(value):
            return (value.st_dev, value.st_ino, value.st_nlink, value.st_mode,
                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum
                and same(before) == same(path.lstat()), 'bounded held ordinary input required')
        chunks, left = [], before.st_size + 1
        while left:
            value = os.read(fd, min(left, MIB))
            if not value:
                break
            chunks.append(value)
            left -= len(value)
        raw = b''.join(chunks)
        require(len(raw) == before.st_size
                and same(before) == same(os.fstat(fd)) == same(path.lstat()),
                'input changed during full capture')
        return raw, stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)


def evidence_authority(plan):
    require(plan['evidence_authority'] == EVIDENCE_AUTHORITY,
            'only the explicitly reviewed evidence filesystem is admitted')
    require(EVIDENCE_SCOPE.resolve(strict=True) == EVIDENCE_SCOPE,
            'fixed evidence root traverses a symlink')
    fd = os.open(EVIDENCE_SCOPE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        held, named = os.fstat(fd), EVIDENCE_SCOPE.lstat()
        def observed(value):
            return {'schema': EVIDENCE_AUTHORITY['schema'], 'path': str(EVIDENCE_SCOPE),
                    'device': value.st_dev, 'inode': value.st_ino,
                    'mode': stat.S_IMODE(value.st_mode), 'uid': value.st_uid, 'gid': value.st_gid}
        require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(named.st_mode)
                and observed(held) == observed(named) == EVIDENCE_AUTHORITY,
                'fixed named/held evidence directory identity differs')
        space = os.fstatvfs(fd)
        require(not (space.f_flag & os.ST_NOEXEC), 'reviewed evidence filesystem became noexec')
        return {**EVIDENCE_AUTHORITY, 'available_bytes': space.f_bavail * space.f_frsize,
                'available_inodes': space.f_favail, 'mount_flags': space.f_flag,
                'observed_ns': time.time_ns()}
    finally:
        os.close(fd)


def bootstrap(plan_path, plan_sha256):
    path = Path(plan_path).absolute()
    require(path.parent == HERE and path.name in ('SOURCE-PLAN.json', 'NATIVE-PLAN.json'),
            'only the explicit reviewed stage plans are admitted')
    raw, mode = capture_bytes(path, MIB)
    require(mode == 0o644 and type(plan_sha256) is str
            and hashlib.sha256(raw).hexdigest() == plan_sha256, 'reviewed full plan differs')
    plan = json.loads(raw)
    require(plan['schema'] == SCHEMA + '.plan' and plan['status'] == 'AUTHORED_NOT_EXECUTED'
            and plan['source'] == {'path': str(SOURCE), 'files': 3188, 'tree': SOURCE_TREE}
            and plan['base'] == {'path': str(BASE), 'files': 3187,
                                 'tree': '7df49dd24bbba4ba3210168e639d6ea35a76a475'}
            and plan['limits'] == {'qualification_seconds': SECONDS, 'cleanup_seconds': CLEANUP,
                                   'minimum_free_bytes': MINIMUM_FREE}
            and plan['source_group_order'] == list(SOURCE_GROUPS)
            and plan['active_phase'] in ('source-controls', 'native-vm'),
            'fixed stage contract differs')
    runner, mode = capture_bytes(Path(__file__).absolute(), MIB)
    require(mode == 0o644 and pin(runner) == plan['runner'], 'reviewed complete runner differs')
    evidence_authority(plan)
    descriptor = plan['generation_runner']
    require(descriptor['path'] == str(GEN_STAGE / 'run_generation.py')
            and descriptor['posix_mode'] == 0o644, 'frozen generation guard location differs')
    code, mode = capture_bytes(Path(descriptor['path']), MIB)
    require(pin(code) == descriptor['pin'] and mode == descriptor['posix_mode'],
            'frozen generation guard bytes/mode differ')
    namespace = {'__name__': 'inspect_private_generation_authority', '__file__': descriptor['path']}
    # Execute only the already-reviewed stdlib guard definitions from the exact
    # captured bytes. Its main guard is false; no generator/product is invoked.
    exec(compile(code, descriptor['path'], 'exec'), namespace)
    guard = SimpleNamespace(**namespace)
    guard.load_plan(GEN_STAGE / 'PLAN.json', plan['generation_plan_sha256'])
    support = guard.helpers()
    captures = {name: guard.decode(guard.fixed_file(row)) for name, row in plan['inputs'].items()}
    require(set(captures) == {'generation_result', 'generation_runtime', 'generation_outer',
                             'source_map', 'source_final', 'base_final', 'installation',
                             'design', 'old_source10_plan', 'kit_spec'},
            'complete immutable predecessor inventory differs')
    guard.fixed_file(plan['old_source10_runner'])
    guard.fixed_file(plan['contract'])
    for row in plan['generation_evidence']:
        guard.fixed_file(row)
    result = captures['generation_result']
    require(result['status'] == 'GENERATION_ONLY_PASS'
            and result['source'] == str(SOURCE) and result['source_files'] == 3188
            and result['source_final_tree'] == SOURCE_TREE
            and result['owner_launch_attempts'] == 3 and result['generation_invocations'] == 2
            and result['check_invocations'] == 1 and result['generated_metadata_current'] is True
            and result['product_tests'] == result['native_compilations'] == result['vm_frames'] == 0
            and result['original_base_bytes_modes_seven_stat_fields_unchanged'] is True
            and result['nongenerated_private_bytes_modes_seven_stat_fields_unchanged'] is True
            and captures['generation_outer']['returncode'] == 0,
            'actual generation did not complete under the frozen original boundary')
    require(result['final_source_capture'] == {k: plan['inputs']['source_final'][k] for k in ('path', 'pin')}
            and result['final_base_capture'] == {k: plan['inputs']['base_final'][k] for k in ('path', 'pin')}
            and captures['source_final']['files'] == captures['source_map']
            and not captures['source_final']['errors'] and not captures['base_final']['errors']
            and support.tree_digest(captures['source_map']) == SOURCE_TREE
            and len(captures['source_map']) == 3188 and len(captures['base_final']['files']) == 3187,
            'actual post-generation source identity differs')
    installation = captures['installation']
    require(installation['source_tree'] == SOURCE_TREE and installation['source_files'] == 3188
            and installation['complete_map'] == {k: plan['inputs']['source_map'][k] for k in ('path', 'pin')},
            'actual installed output map differs')
    require([row['label'] for row in result['stages']] == ['generation-1', 'generation-2', 'generation-check'],
            'actual predecessor stage order differs')
    for row in result['stages']:
        directory = Path(row['directory'])
        require(directory.parent == GEN and row['status'] == 'PASS' and row['source_guard_pass'] is True,
                'predecessor stage status or directory differs')
        support.complete_receipt(row['owner_returned'], directory / 'OWNER.json')
        actual = guard.decode(capture_bytes(directory / 'OWNER-RETURNED.json', MIB)[0])
        require(actual == row['owner_returned'], 'generation actual returned owner differs')
        child_raw, _ = capture_bytes(directory / 'CHILD-RESULT.json', MIB)
        require(pin(child_raw) == row['child_result_pin'], 'generation complete child result differs')
    original = captures['kit_spec']
    require(plan['groups']['source10']['ids'] == original['groups']['source10']
            == captures['old_source10_plan']['ids']
            and plan['groups']['source10']['subtest_method_projection']
                == captures['old_source10_plan']['subtest_method_projection'],
            'original Source10 IDs or complete subtest projection differ')
    design = {row['name']: row for row in captures['design']['stages']}
    require(plan['groups']['source8-physical-lease']['ids'] == design['source8-physical-lease']['ids']
            and len(plan['groups']['source8-physical-lease']['ids']) == 8
            and plan['native_group_order'] == original['native_group_order']
            and plan['vm_group_order'] == original['vm_group_order'],
            'original independent group projections differ')
    for name in plan['native_group_order'] + plan['vm_group_order']:
        require(plan['groups'][name]['ids'] == original['groups'][name], 'fixed Native/VM IDs differ')
    for name, row in plan['test_source_pins'].items():
        require(captures['source_map'][name] == row, 'source test full-file pin differs')
    require(plan['compiler'] == original['compiler'] and plan['product_limits'] == original['limits'],
            'original compiler and execution budgets differ')
    return plan, guard, support, captures


def full_guard(output, label, plan, guard, support, captures):
    current_base = guard.capture(BASE, captures['base_final']['files'])
    current_source = guard.capture(SOURCE, captures['source_map'])
    record = {'label': label, 'base': guard.cas(output, current_base),
              'source': guard.cas(output, current_source), 'all_bytes_and_seven_stat_fields': True}
    guard.publish(output / ('GUARD-' + label + '.json'), record)
    guard.assert_capture(current_base, captures['base_final']['files'], stable=captures['base_final']['stat'])
    guard.assert_capture(current_source, captures['source_map'], stable=captures['source_final']['stat'])
    guard.independent(current_base, current_source)
    support.compiler_bytes()  # Full frozen B3 identity only; never invokes it.
    return record


def protected_source_fence(protected_inodes, plan):
    """Cooperative Source write fence; it is not a hostile-code sandbox."""
    roots = (BASE, SOURCE, KIT, GEN, GEN_STAGE, PRIOR_STAGE, HERE, OLD_SOURCE)
    exact = tuple(Path(row['path']) for row in plan['inputs'].values())
    exact += (Path(plan['compiler']['path']),)

    def check(path, directory_fd=None):
        if type(path) is int:
            current = os.fstat(path)
            require((current.st_dev, current.st_ino) not in protected_inodes,
                    'write to shared/frozen source descriptor refused')
            return
        require(type(path) in (str, bytes), 'exact filesystem argument required')
        named = Path(os.fsdecode(path))
        if named.is_absolute() or directory_fd in (None, -1, -100):
            value = Path(os.path.abspath(named))
        else:
            require(type(directory_fd) is int, 'exact directory descriptor required')
            held = os.fstat(directory_fd)
            require(stat.S_ISDIR(held.st_mode), 'directory descriptor is not a directory')
            directory = os.readlink('/proc/self/fd/' + str(directory_fd))
            require(directory.startswith('/') and not directory.endswith(' (deleted)'),
                    'held directory pathname is unavailable')
            bound = Path(directory)
            named_directory = bound.stat()
            require((named_directory.st_dev, named_directory.st_ino) == (held.st_dev, held.st_ino),
                    'held directory and named directory differ')
            value = Path(os.path.abspath(bound / named))
        resolved = value.resolve(strict=False)
        require(value not in exact and resolved not in exact
                and not any(value.is_relative_to(root) or resolved.is_relative_to(root) for root in roots),
                'write or mutation of a frozen source/evidence path refused')
        try:
            current = value.stat()
        except FileNotFoundError:
            return
        require((current.st_dev, current.st_ino) not in protected_inodes,
                'write through an alias of a frozen source inode refused')

    def audit(event, arguments):
        if event == 'open':
            path, mode, flags = arguments
            if (type(flags) is int and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)) or (
                    type(mode) is str and any(c in mode for c in 'wax+')):
                check(path)
        elif event in ('os.remove','os.rmdir'):
            check(arguments[0],arguments[1])
        elif event in ('os.mkdir','os.chmod'):
            check(arguments[0],arguments[2])
        elif event in ('os.chown','os.utime'):
            check(arguments[0],arguments[3])
        elif event == 'os.truncate':
            check(arguments[0])
        elif event in ('os.rename','os.link'):
            check(arguments[0],arguments[2]); check(arguments[1],arguments[3])
        elif event == 'os.symlink':
            check(arguments[1],arguments[2])
        elif event == 'subprocess.Popen' or event in ('os.system','os.exec','os.posix_spawn','os.fork','os.forkpty'):
            raise AssertionError('Source controls cannot start another product process')
    sys.addaudithook(audit)


def pure_parameter(value):
    # The fixed two Source subTest loops contain only exact built-in values.
    # Do not add repr/equality/attribute calls on arbitrary provider objects.
    if value is None or type(value) in (bool,int,str):
        return value
    if type(value) in (list,tuple):
        return [pure_parameter(item) for item in value]
    require(type(value) is dict and all(type(key) is str for key in value),
            'unexpected foreign subtest parameter protocol')
    return {key:pure_parameter(item) for key,item in dict.items(value)}


def admit_subtests(value, group):
    rows = value['actual_subtests']
    require([row['method_id'] for row in rows] == group['subtest_method_projection']
            and [row['ordinal'] for row in rows] == list(range(1, len(rows) + 1))
            and all(row['success'] is True and row['exception_type'] is None for row in rows),
            'complete successful subtest observations differ')
    if 'subtest_parameters' in group:
        require([row['parameters'] for row in rows] == group['subtest_parameters'],
                'all seven entry routes and two retirement branches must be observed')


def run_source_methods(group, output, support):
    import unittest
    original_result = unittest.TextTestResult
    rows = []
    class SubtestJournal(original_result):
        def addSubTest(self, test, subtest, error):
            parameters = {key:pure_parameter(value) for key,value in subtest.params.items()}
            rows.append({'ordinal':len(rows)+1, 'method_id':test.id(), 'parameters':parameters,
                         'success':error is None,
                         'exception_type':None if error is None else error[0].__module__+'.'+error[0].__qualname__})
            return super().addSubTest(test, subtest, error)
    unittest.TextTestResult = SubtestJournal
    try:
        result = support.run_exact_tests(group['ids'], output / 'TESTS.json')
        admit_subtests({'actual_subtests': rows}, group)
        return result
    finally:
        unittest.TextTestResult = original_result
        support.publish(output / 'SUBTESTS.json', {'schema':SCHEMA+'.subtests',
            'actual_subtests':rows,'declared_method_projection':group['subtest_method_projection'],
            'no_foreign_repr_added':True,'ordinary_TextTestResult_restored':True})


def admit_tests(tests, group):
    ids = group['ids']
    require(tests['status'] == 'PASS'
            and tests['declared_ids'] == tests['loaded_ids'] == tests['started_ids'] == tests['stopped_ids'] == ids
            and type(tests['tests_run']) is int and tests['tests_run'] == len(ids)
            and tests['events'] == [event for name in ids for event in (['start', name], ['stop', name])]
            and not any(tests[key] for key in ('loader_errors', 'failures', 'errors', 'skipped',
                                             'expected_failures', 'unexpected_successes')),
            'complete fixed executed ID/event observation differs')


def child(request_path, request_sha256):
    raw, _ = capture_bytes(Path(request_path).absolute(), MIB)
    require(hashlib.sha256(raw).hexdigest() == request_sha256, 'Source child request differs')
    request = json.loads(raw)
    plan, guard, support, captures = bootstrap(request['plan'], request['plan_sha256'])
    require(set(request) == {'schema', 'plan', 'plan_sha256', 'group', 'ids', 'runtime_context', 'output'}
            and request['schema'] == SCHEMA+'.request' and plan['active_phase'] == 'source-controls'
            and request['group'] in SOURCE_GROUPS
            and request['ids'] == plan['groups'][request['group']]['ids']
            and request['runtime_context'] == captures['generation_runtime'],
            'only an exact declared Source group is admitted')
    output = Path(request['output']).absolute()
    require(output == Path(request_path).parent / 'child' and not output.exists(),
            'fresh Source child evidence directory required')
    output.mkdir(mode=0o700); (output/'maps').mkdir(mode=0o700)
    result = {'schema':SCHEMA+'.child','status':'FAIL','request_pin':pin(raw),
              'group':request['group'], 'scope':'SOURCE_CONTROLS_ONLY',
              'matching_current_cold':False, 'Native_compilation':0,'VM_group_execution':0,
              'old3_or_CLI43_executed':False, 'synthetic_Source8_is_not_Native17':True}
    sys.path.insert(0,str(SOURCE))
    from tools.hia_linux_file_roundtrip_cold import guard_runtime_context
    try:
        require(sys.flags.ignore_environment == 1, 'Source child keeps its original -I mode')
        guard_runtime_context(request['runtime_context'])
        full_guard(output,'before',plan,guard,support,captures)
        protected = {(row['device'],row['inode']) for key in ('base_final','source_final')
                     for row in captures[key]['stat'].values()}
        protected_source_fence(protected, plan)
        result['tests'] = run_source_methods(plan['groups'][request['group']],output,support)
        admit_tests(result['tests'], plan['groups'][request['group']])
        guard_runtime_context(request['runtime_context'])
        result['status'] = 'PASS'
    except BaseException:
        result['traceback'] = traceback.format_exc()
    finally:
        try:
            full_guard(output,'after',plan,guard,support,captures)
            result['all_original_and_generated_source_bytes_modes_stats_unchanged'] = True
        except BaseException:
            result['source_guard_error'] = traceback.format_exc(); result['status']='FAIL'
        support.publish(output/'RESULT.json',result)
    return 0 if result['status']=='PASS' else 1


def evidence_rows(directory, guard):
    rows = []
    for path in sorted(Path(directory).rglob('*')):
        require(not path.is_symlink(), 'stage evidence symlink refused')
        if path.is_dir():
            continue
        raw, observed = guard.read_exact(path, maximum=max(MIB, path.lstat().st_size))
        rows.append({'path':str(path),'pin':pin(raw),'posix_mode':observed['mode']})
    return rows


def admit_source_predecessor(plan, guard, support, captures):
    descriptor = plan['source_predecessor']
    require(type(descriptor) is dict, 'actual complete Source18 predecessor is required')
    result = guard.decode(guard.fixed_file(descriptor))
    require(result['schema'] == SCHEMA+'.result' and result['status'] == 'SOURCE_CONTROLS_PASS'
            and result['phase'] == 'source-controls' and result['source_tree'] == SOURCE_TREE
            and result['source_files'] == 3188 and result['owner_launch_attempts'] == 2
            and result['complete_source_guard_pass'] is True
            and result['generation_result_pin'] == plan['inputs']['generation_result']['pin']
            and [row['label'] for row in result['stages']] == list(SOURCE_GROUPS),
            'actual Source18 predecessor is not complete for this source')
    for row in result['evidence']:
        guard.fixed_file(row)
    for row in result['stages']:
        require(row['status'] == 'PASS', 'a predecessor Source group failed')
        directory = Path(row['directory'])
        support.complete_receipt(row['owner_returned'], directory/'OWNER.json')
        actual = guard.decode(capture_bytes(directory/'child/TESTS.json', 8*MIB)[0])
        admit_tests(actual, plan['groups'][row['label']])
        admit_subtests(guard.decode(capture_bytes(directory/'child/SUBTESTS.json', MIB)[0]),
                       plan['groups'][row['label']])
    require(result['runtime'] == captures['generation_runtime'], 'Source predecessor runtime differs')
    return result


def execute(plan_path, plan_sha256, attempt, phase):
    global _ATTEMPT
    plan, guard, support, captures = bootstrap(plan_path, plan_sha256)
    require(phase == plan['active_phase'], 'this reviewed plan does not authorize the selected phase')
    attempt = Path(attempt).absolute()
    require(str(attempt) == plan['attempt'] and attempt.parent == EVIDENCE_SCOPE and not attempt.exists(),
            'fresh exact reviewed stage attempt required')
    require(guard.storage(EVIDENCE_SCOPE)['available_bytes'] >= MINIMUM_FREE, 'original 1GiB entry floor required')
    require((phase == 'source-controls' and plan['source_predecessor'] is None)
            or (phase == 'native-vm' and type(plan['source_predecessor']) is dict),
            'a later actual predecessor must be explicitly reviewed before Native/VM')
    attempt.mkdir(mode=0o700); _ATTEMPT = attempt
    (attempt/'maps').mkdir(mode=0o700); (attempt/'tmp').mkdir(mode=0o700)
    support.publish(attempt/'PLAN-USED.json', plan)
    report = {'schema':SCHEMA+'.result','status':'FAIL','phase':phase,
              'plan_pin':pin(Path(plan_path).read_bytes()), 'started_ns':time.monotonic_ns(),
              'stages':[], 'owner_launch_attempts':0, 'source_tree':SOURCE_TREE,'source_files':3188,
              'scope':'SOURCE_CONTROLS_ONLY' if phase=='source-controls' else 'DEVELOPMENT_NATIVE_VM_ONLY',
              'source_phase_has_no_compiler_Native_or_VM_invocation':phase=='source-controls',
              'generation_result_pin':plan['inputs']['generation_result']['pin'],
              'matching_current_cold':False,'whole_cli_native':False,'CLI_op10_connected':False,
              'original3_or_CLI43_executed':False, 'historical_results_not_inherited':True}
    sys.path.insert(0,str(SOURCE))
    from tools.hia_selfhost_process_owner import run_owned
    from tools.hia_linux_file_roundtrip_cold import (
        capture_runtime_context,guard_runtime_context,runtime_child_environment)
    runtime = None
    try:
        report['evidence_filesystem'] = evidence_authority(plan)
        full_guard(attempt,'before',plan,guard,support,captures)
        runtime = capture_runtime_context()
        require(runtime == captures['generation_runtime'], 'actual fixed runtime changed since generation')
        report['runtime'] = runtime
        support.publish(attempt/'RUNTIME.json', runtime)
        environment = runtime_child_environment({'PATH':'/usr/local/bin:/usr/bin:/bin',
            'HOME':str(attempt),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1',
            'TMPDIR':str(attempt/'tmp')}, runtime)
        if phase == 'native-vm':
            report['actual_source_predecessor'] = admit_source_predecessor(plan,guard,support,captures)
        inspect_manifest = None
        native_directories = []
        catalog = None
        order = list(SOURCE_GROUPS) if phase == 'source-controls' else (
            ['build-inspect'] + plan['native_group_order'] + plan['vm_group_order'])
        for index, label in enumerate(order):
            guard.storage_gate(attempt, label, MINIMUM_FREE)
            bootstrap(plan_path,plan_sha256)
            guard_runtime_context(runtime)
            full_guard(attempt, label+'-before',plan,guard,support,captures)
            directory = attempt / ('%02d-%s' % (index+1,label)); directory.mkdir(mode=0o700)
            source_group = label in SOURCE_GROUPS
            if source_group:
                request = {'schema':SCHEMA+'.request','plan':str(Path(plan_path).absolute()),
                    'plan_sha256':plan_sha256,'group':label,'ids':plan['groups'][label]['ids'],
                    'runtime_context':runtime,'output':str(directory/'child')}
                child_script = Path(__file__).absolute()
            else:
                kind = 'build-inspect' if label == 'build-inspect' else 'tests'
                request = {'schema':'hepta.hia.inspect-development-child-request.v1',
                    'kind':kind,'group':label,'ids':[] if kind=='build-inspect' else plan['groups'][label]['ids'],
                    'source':str(SOURCE),'source_map':plan['inputs']['source_map']['path'],
                    'source_map_pin':plan['inputs']['source_map']['pin'],
                    'kit_index_pin':pin((KIT/'KIT-PINS.json').read_bytes()),
                    'runtime_context':runtime,'output':str(directory/'RESULT.json')}
                child_script = KIT/'run_inspect_development.py'
                if kind == 'build-inspect':
                    request['build_output'] = str(attempt/'inspect-build')
                elif label in plan['native_group_order']:
                    require(inspect_manifest is not None, 'actual inspect build required')
                    request.update(inspect_manifest=inspect_manifest,controls_output=str(directory/'controls'))
                else:
                    if catalog is None:
                        require(len(native_directories) == len(plan['native_group_order']),
                                'all original Native groups must finish before making VM catalog')
                        from inspect_exec_vm import make_catalog
                        catalog = attempt/'NATIVE-VM-CATALOG.json'
                        manifest = guard.decode(capture_bytes(Path(inspect_manifest),MIB)[0])
                        make_catalog(native_directories,catalog,manifest['image_sha256'])
                    request.update(frame_catalog=str(catalog),frame_catalog_pin=pin(catalog.read_bytes()),
                                   controls_output=str(directory/'controls'))
            request_path = directory/'REQUEST.json'; support.publish(request_path,request)
            command = [sys.executable,'-I','-B',str(child_script),'--child',str(request_path),
                       '--request-sha256',pin(support.encoded(request))['sha256']]
            support.publish(directory/'COMMAND.json',{'argv':command,'cwd':str(SOURCE),
                'environment':environment,'supervisor_environment':environment,
                'qualification_seconds':SECONDS,'cleanup_seconds':CLEANUP})
            row = {'label':label,'directory':str(directory),'status':'FAIL','started_ns':time.monotonic_ns()}
            report['stages'].append(row)
            returned = None
            try:
                report['owner_launch_attempts'] += 1
                returned = run_owned(command,cwd=SOURCE,env=environment,supervisor_env=environment,
                    stdout_path=directory/'stdout.raw',stderr_path=directory/'stderr.raw',
                    receipt_path=directory/'OWNER.json',qualification_seconds=SECONDS,cleanup_seconds=CLEANUP)
                support.publish(directory/'OWNER-RETURNED.json',returned)
                support.complete_receipt(returned,directory/'OWNER.json')
                child_path = directory/'child/RESULT.json' if source_group else directory/'RESULT.json'
                child_raw, _ = capture_bytes(child_path,8*MIB)
                actual = guard.decode(child_raw)
                require(actual['status']=='PASS' and actual['request_pin']==pin(support.encoded(request)),
                        'actual group failed or is not bound to the full current request')
                if source_group:
                    require(actual['all_original_and_generated_source_bytes_modes_stats_unchanged'] is True,
                            'Source child did not keep its complete source')
                    tests = guard.decode(capture_bytes(directory/'child/TESTS.json',8*MIB)[0])
                    require(tests == actual['tests'], 'Source result and raw tests differ')
                    admit_tests(tests,plan['groups'][label])
                    subtests = guard.decode(capture_bytes(directory/'child/SUBTESTS.json',MIB)[0])
                    admit_subtests(subtests,plan['groups'][label])
                    row.update(tests=tests,subtests=subtests)
                elif label == 'build-inspect':
                    require(actual['source_unchanged'] is True and actual['compiler_unchanged'] is True,
                            'original build child source/compiler drift')
                    build = actual['build']
                    require(build['status']=='BUILT_AND_READ_BACK' and build['matching_current_cold'] is False
                            and build['compile_seconds']==20 and build['capacity']==MIB
                            and build['complete_source_map_pin']==plan['inputs']['source_map']['pin'],
                            'actual original build contract differs')
                    import run_inspect_development as original
                    require(Path(original.__file__).absolute()==KIT/'run_inspect_development.py',
                            'frozen build helper came from another directory')
                    original._check_rows(build['observation_bindings'])
                    require(original._bound(Path(build['manifest']))==build['manifest_binding'],
                            'actual complete inspect manifest binding differs')
                    inspect_manifest=build['manifest'];row['build']=build
                else:
                    require(actual['source_unchanged'] is True and actual['compiler_unchanged'] is True,
                            'original Native/VM child source/compiler drift')
                    tests=guard.decode(capture_bytes(directory/'TESTS.json',8*MIB)[0])
                    require(tests==actual['tests'],'original test result differs from raw')
                    admit_tests(tests,plan['groups'][label]);row['tests']=tests
                    if label in plan['native_group_order']:
                        native_directories.append(str(directory/'controls'))
                guard_runtime_context(runtime)
                row.update(status='PASS',child_result_pin=pin(child_raw))
            except BaseException:
                row['traceback']=traceback.format_exc()
                report['halted_after_first_failed_group']=True
                raise
            finally:
                row['owner_returned']=returned;row['finished_ns']=time.monotonic_ns()
                try:
                    full_guard(attempt,label+'-after',plan,guard,support,captures)
                    row['source_guard_pass']=True
                except BaseException:
                    row['source_guard_error']=traceback.format_exc();row['status']='FAIL'
                    report['halted_after_first_failed_group']=True
                support.publish(directory/'STAGE.json',row)
            require(row['status']=='PASS','stage source guard failed; no following owner is allowed')
        bootstrap(plan_path,plan_sha256);guard_runtime_context(runtime)
        report['status']='SOURCE_CONTROLS_PASS' if phase=='source-controls' else 'DEVELOPMENT_NATIVE_VM_PASS'
    except BaseException:
        report['traceback']=traceback.format_exc();report['halted_after_first_failed_group']=True
    finally:
        try:
            full_guard(attempt,'after',plan,guard,support,captures)
            report['complete_source_guard_pass']=True
        except BaseException:
            report['source_guard_error']=traceback.format_exc();report['status']='FAIL'
        report['finished_ns']=time.monotonic_ns()
        try:
            report['evidence']=evidence_rows(attempt,guard)
        except BaseException:
            report['evidence_capture_error']=traceback.format_exc();report['status']='FAIL'
        support.publish(attempt/'RESULT.json',report)
    return 0 if report['status'] in ('SOURCE_CONTROLS_PASS','DEVELOPMENT_NATIVE_VM_PASS') else 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-stage',choices=('source-controls','native-vm'))
    parser.add_argument('--plan',type=Path);parser.add_argument('--plan-sha256')
    parser.add_argument('--attempt',type=Path);parser.add_argument('--child',type=Path)
    parser.add_argument('--request-sha256')
    args=parser.parse_args(argv)
    if args.child is not None:
        require(args.execute_stage is None and args.plan is None and args.plan_sha256 is None
                and args.attempt is None and args.request_sha256,'mixed Source child/parent invocation')
        return child(args.child,args.request_sha256)
    require(args.execute_stage is not None and args.plan is not None and args.plan_sha256
            and args.attempt is not None and args.request_sha256 is None,
            'explicit reviewed stage invocation required')
    try:
        return execute(args.plan,args.plan_sha256,args.attempt,args.execute_stage)
    except BaseException:
        error=traceback.format_exc();sys.stderr.write(error)
        if _ATTEMPT is not None and not (_ATTEMPT/'RESULT.json').exists():
            with (_ATTEMPT/'ENTRY-FAILURE.json').open('x') as stream:
                json.dump({'status':'FAIL','traceback':error,'matching_current_cold':False},stream)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
