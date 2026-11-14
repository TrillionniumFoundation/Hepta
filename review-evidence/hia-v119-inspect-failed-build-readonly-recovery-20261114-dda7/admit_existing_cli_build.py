"""Separate read-only admission; preserve the real failed parent unchanged.

No compiler, Native entry, VM, test, or subprocess is launched. Only a distinct
admission result can be published. The old FAIL is an input and remains FAIL.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys
import time
import traceback

HERE = Path(__file__).absolute().parent
ROOT = HERE.parent
FIRST = ROOT / 'v119-inspect-retained-regressions-r1'
BUILD = FIRST / 'build-cli-attempt-r1/retained-cli-build'
SOURCE = ROOT / 'v119-inspect-generation-only-r1/attempt-r1/source'
TREE = '7df49dd24bbba4ba3210168e639d6ea35a76a475'
MIB = 1048576
SCHEMA = 'hepta.hia.inspect-existing-cli-build-admission.v1'
BUILD_FILES = ('INSPECT-RETAINED-BUILD.json', 'build.json', 'manifest.json', *(
    name + '/' + relative for name in ('control', 'format') for relative in (
        'cli-' + name + '.image.bin', 'cli-' + name + '.input.bin',
        'cli-' + name + '.output.bin', 'cli-' + name + '.receipt.json',
        'cli-' + name + '.request.json', 'cli-' + name + '.stderr.log',
        'cli-' + name + '.stdout.log', 'manifest.json')))


def require(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw):
    return {'bytes': len(raw), 'mode': '100644', 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def bootstrap(plan_path, plan_sha256):
    plan_path = Path(plan_path).absolute()
    require(plan_path == HERE / 'ADMISSION-PLAN.json', 'wrong reviewed admission plan')
    raw = plan_path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == plan_sha256, 'admission plan changed')
    plan = json.loads(raw)
    require(plan['schema'] == SCHEMA + '.plan' and plan['status'] == 'AUTHORED_NOT_EXECUTED'
            and plan['runner'] == pin(Path(__file__).read_bytes())
            and plan['source'] == {'path': str(SOURCE), 'tree': TREE, 'files': 3187},
            'reviewed admission identity differs')
    require(pin((HERE / 'RECOVERY-CONTRACT.md').read_bytes()) == plan['contract'], 'contract changed')
    require(pin((FIRST / 'run_retained_regressions.py').read_bytes()) == plan['original_runner']
            and pin((FIRST / 'PLAN.json').read_bytes()) == plan['original_plan'],
            'original failed runner/plan changed')
    sys.path.insert(0, str(FIRST))
    import run_retained_regressions as original
    require(Path(original.__file__).absolute() == FIRST / 'run_retained_regressions.py',
            'wrong original guard module')
    context = original.bootstrap(FIRST / 'PLAN.json', plan['original_plan']['sha256'])
    guard = context[3]
    index_raw, _ = guard.read_exact(HERE / 'FAILED-PARENT-RAW-INDEX.json',
        maximum=MIB, expected=plan['failed_raw_index'])
    index = json.loads(index_raw)
    require(index['status'] == 'POST_TERMINAL_RAW_CAPTURE_ONLY'
            and index['parent_status_unchanged'] == 'FAIL'
            and index['logical_files'] == 53 and index['logical_bytes'] == 13011219,
            'wrong fixed failed-parent raw inventory')
    return plan, original, context, index


def original_raw(index, guard):
    roots = {'attempt': FIRST / 'build-cli-attempt-r1',
             'outer': FIRST / 'build-cli-outer-execution-r1'}
    observed = set()
    for label, root in roots.items():
        for directory, folders, files in os.walk(root, followlinks=False):
            folders.sort(); files.sort()
            for name in folders:
                path = Path(directory) / name
                require(path.is_dir() and not path.is_symlink(), 'original evidence directory changed')
            for name in files:
                observed.add(label + '/' + (Path(directory) / name).relative_to(root).as_posix())
    require(observed == set(index['rows']), 'original complete raw inventory changed')
    values = {}
    for key, row in index['rows'].items():
        label, relative = key.split('/', 1)
        path = roots[label] / relative
        require(str(path) == row['path'] and '..' not in Path(relative).parts,
                'original evidence path escaped')
        expected = {name: row[name] for name in ('bytes', 'sha256', 'git_blob')}
        raw, actual = guard.read_exact(path, maximum=max(MIB, row['bytes']))
        require({name: pin(raw)[name] for name in expected} == expected
                and actual == row['observed_stat'], 'fixed original raw bytes/mode/inode changed: ' + key)
        values[key] = raw
    return values


def capture_build(index, guard):
    rows = {key.removeprefix('attempt/retained-cli-build/'): row
            for key, row in index['rows'].items() if key.startswith('attempt/retained-cli-build/')}
    require(set(rows) == set(BUILD_FILES), 'exact original nineteen build files required')
    expected = {name: {**{key: row[key] for key in ('bytes', 'sha256', 'git_blob')}, 'mode': '100644'}
                for name, row in rows.items()}
    actual = guard.capture(BUILD, expected)
    require(not actual['errors'] and actual['files'] == expected, 'complete actual build bytes/Git modes differ')
    modes = {name: (0o600 if name == 'INSPECT-RETAINED-BUILD.json' else 0o644) for name in BUILD_FILES}
    require({name: value['mode'] for name, value in actual['stat'].items()} == modes,
            'exact original build POSIX permissions differ')
    require(actual['stat'] == {name: row['observed_stat'] for name, row in rows.items()},
            'actual build inode/metadata changed after the post-terminal capture')
    return actual


def evaluate(loaded):
    """Fresh file admission only; no machine or original test is entered."""
    plan, original, context, index = loaded
    _, _, _, guard, support, _, frozen = context
    values = original_raw(index, guard)
    get = lambda key: support.json_bytes(values[key])
    parent = get('attempt/RESULT.json')
    stage = get('attempt/00-build-cli/STAGE.json')
    wrapper = get('attempt/00-build-cli/wrapper/RESULT.json')
    child = get('attempt/00-build-cli/FROZEN-RESULT.json')
    request_raw = values['attempt/00-build-cli/FROZEN-REQUEST.json']
    request = support.json_bytes(request_raw)
    require(parent['status'] == 'FAIL' and parent['owner_launch_attempts'] == 1
            and parent['group_counts'] == {} and parent['complete_source_guard_pass'] is True
            and parent['source_tree'] == TREE and parent['source_files'] == 3187
            and parent['stages'] == [stage] and parent['matching_current_cold'] is False,
            'original parent is not the one retained failed build-only attempt')
    require(stage['status'] == wrapper['status'] == child['status'] == 'PASS'
            and stage['source_guard_pass'] is True
            and wrapper['all_source_bytes_modes_stats_unchanged'] is True
            and child['source_unchanged'] is True and child['compiler_unchanged'] is True
            and child['request_pin'] == pin(request_raw)
            and child['kind'] == child['group'] == 'build-cli'
            and request['source'] == str(SOURCE) and request['ids'] == [],
            'original actual child, request, or source guard differs')
    returned = get('attempt/00-build-cli/OWNER-RETURNED.json')
    support.complete_receipt(returned, FIRST / 'build-cli-attempt-r1/00-build-cli/OWNER.json')
    require(returned == stage['owner_returned'], 'original raw/returned/stage owner differs')
    build = child['build']
    require(build == get('attempt/retained-cli-build/INSPECT-RETAINED-BUILD.json')
            and build['status'] == 'BUILT_AND_READ_BACK' and build['scope'] == frozen.DEVELOPMENT_SCOPE
            and build['matching_current_cold'] is False
            and build['manifest'] == str(BUILD / 'manifest.json'), 'original actual build result differs')
    frozen._check_rows(build['observation_bindings'])
    require(frozen._bound(BUILD / 'manifest.json') == build['manifest_binding']
            and frozen._bound(BUILD / 'build.json') == build['original_build_binding'],
            'original actual manifest/build changed')
    sys.path.insert(0, str(SOURCE))
    from tools import build_hia_cli_native as builder
    from tools.hia_cli_discovery_custody import admit_compilation
    from tools.hia_linux_file_roundtrip_cold import guard_runtime_context
    guard_runtime_context(context[5]['generation_runtime'])
    require(tuple(builder.SOURCES) == ('control', 'format'), 'original CLI pair inventory changed')
    observations = []
    for name, relative in builder.SOURCES.items():
        directory = BUILD / name
        label = 'cli-' + name
        source = (SOURCE / relative).read_bytes()
        image = directory / (label + '.image.bin')
        receipt, bindings = admit_compilation(directory, label, Path(support.B3['path']), source, image)
        require(build['children'][name] == {'actual_compile_receipt': receipt,
                'source': pin(source), 'image': pin(image.read_bytes())},
                'original complete compilation source/image/receipt chain differs')
        observations.extend(bindings)
    require(observations == build['observation_bindings'], 'original ordered full observation binding differs')
    old_build = get('attempt/retained-cli-build/build.json')
    require(old_build['owner_sources_before'] == old_build['owner_sources_after'] == builder.owner_sources()
            and old_build['source_manifest'] is None and old_build['cold_report_sha256'] is None,
            'original build owner/source/development boundary changed')
    captured = capture_build(index, guard)
    require(original_raw(index, guard) == values, 'original evidence changed during fresh admission')
    return {'original_parent': {'path': str(FIRST / 'build-cli-attempt-r1/RESULT.json'),
                               'pin': pin(values['attempt/RESULT.json']), 'status': 'FAIL'},
            'original_owner': {'raw': pin(values['attempt/00-build-cli/OWNER.json']),
                               'returned': pin(values['attempt/00-build-cli/OWNER-RETURNED.json'])},
            'original_child': pin(values['attempt/00-build-cli/FROZEN-RESULT.json']),
            'manifest': build['manifest'], 'manifest_binding': build['manifest_binding'],
            'output': str(BUILD), 'observation_bindings': observations,
            'capture': captured, 'compiler': support.B3,
            'matching_current_cold': False, 'whole_cli_native': False}


def verified_result(path, sha256, loaded):
    plan, original, context, index = loaded
    guard = context[3]
    path = Path(path).absolute()
    require(path == HERE / 'admission-attempt-r1/RESULT.json', 'wrong actual admission result path')
    raw, metadata = guard.read_exact(path, maximum=MIB)
    require(hashlib.sha256(raw).hexdigest() == sha256 and metadata['mode'] == 0o600,
            'actual admission result bytes/permissions changed')
    report = context[4].json_bytes(raw)
    require(report['status'] == 'READ_ONLY_BUILD_ADMISSION_PASS'
            and report['original_parent_status_unchanged'] == 'FAIL'
            and report['plan_pin'] == pin((HERE / 'ADMISSION-PLAN.json').read_bytes())
            and report['complete_source_guard_pass'] is True
            and report['new_compiles'] == report['new_native_entries'] == report['new_VM_runs']
                == report['new_tests'] == report['new_subprocesses'] == 0,
            'incomplete separate read-only admission')
    actual = evaluate(loaded)
    require(report['binding'] == actual, 'original build changed since separate admission')
    return {'result': str(path), 'result_pin': pin(raw), 'manifest': actual['manifest'],
            'output': actual['output'], 'capture': actual['capture']}


def no_process(event, args):
    require(event not in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'),
            'read-only admission may not start another process')


def execute(plan_path, plan_sha256, attempt):
    loaded = bootstrap(plan_path, plan_sha256)
    plan, original, context, index = loaded
    attempt = Path(attempt).absolute()
    require(attempt == HERE / 'admission-attempt-r1' and not attempt.exists(),
            'exclusive one-time admission evidence path required')
    attempt.mkdir(mode=0o700); (attempt / 'maps').mkdir(mode=0o700)
    guard, support = context[3], context[4]
    result = {'schema': SCHEMA + '.result', 'status': 'FAIL',
              'plan_pin': pin(Path(plan_path).read_bytes()), 'source_tree': TREE, 'source_files': 3187,
              'original_parent_status_unchanged': 'FAIL', 'new_compiles': 0, 'new_native_entries': 0,
              'new_VM_runs': 0, 'new_tests': 0, 'new_subprocesses': 0,
              'matching_current_cold': False, 'whole_cli_native': False,
              'started_ns': time.monotonic_ns()}
    try:
        original.full_guard(attempt, 'before', context)
        protected = {(value['device'], value['inode']) for key in ('base_final', 'source_final')
                     for value in context[5][key]['stat'].values()}
        protected.update((row['observed_stat']['device'], row['observed_stat']['inode'])
                         for row in index['rows'].values())
        original.write_fence(protected, (FIRST / 'build-cli-attempt-r1', FIRST / 'build-cli-outer-execution-r1'))
        sys.addaudithook(no_process)
        result['binding'] = evaluate(loaded)
        result['status'] = 'READ_ONLY_BUILD_ADMISSION_PASS'
    except BaseException:
        result['traceback'] = traceback.format_exc()
    finally:
        try:
            original.full_guard(attempt, 'after', context)
            original_raw(index, guard)
            result['complete_source_guard_pass'] = True
        except BaseException:
            result['final_guard_error'] = traceback.format_exc(); result['status'] = 'FAIL'
        result['finished_ns'] = time.monotonic_ns()
        support.publish(attempt / 'RESULT.json', result)
    return 0 if result['status'] == 'READ_ONLY_BUILD_ADMISSION_PASS' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admit-existing', action='store_true')
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--attempt', required=True, type=Path)
    args = parser.parse_args(argv)
    require(args.admit_existing, 'explicit reviewed admission required')
    return execute(args.plan, args.plan_sha256, args.attempt)


if __name__ == '__main__':
    raise SystemExit(main())
