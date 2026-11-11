"""Independent exact-leaf development copy and one source-only authoring run.

The 3932-file source was frozen by the earlier completed f74 task. This copies
its file bytes and modes, not its Git object database. It cannot establish
formal source-consumer or clone qualification and inherits no product result.
"""
from hashlib import sha1, sha256
import ast
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import traceback

from common import (
    ROOT, SOURCE, PYTHON, PYTHON_SHA, COMPILER, COMPILER_SHA, KEY, GENERATED,
    PREVIOUS_REPORT, PREVIOUS_REPORT_SHA, PREVIOUS_GUARD, PREVIOUS_GUARD_SHA,
    PREVIOUS_SNAPSHOT, PREVIOUS_SNAPSHOT_SHA, SOURCE_COUNT, NEW_COUNT,
    PREVIOUS_PREPARATION, PREVIOUS_PREPARATION_SHA, PREVIOUS_CANDIDATE, PREVIOUS_CANDIDATE_SHA,
    FAILED_AUTHORING_REPORT, FAILED_AUTHORING_REPORT_SHA, FAILED_AUTHORING_GUARD, FAILED_AUTHORING_GUARD_SHA,
    OVERLAYS, NEW_PATHS, LIMITS, ORACLE_SHA, checked_config, checked_relative,
    create, environment, identity, natural_guardian, read_json, require,
    stable_file, sync_directory, wire,
)

report = {
    'schema': 'hepta.hia.machine-elf.sort-authoring-development.v1',
    'status': 'HOLD', 'scope': 'COMPLETE_PHYSICAL_SOURCE_LEAF_COPY_AND_AUTHORING_ONLY',
    'key': KEY, 'root': str(ROOT), 'source': str(SOURCE),
    'candidate_source': str(ROOT / 'source'),
    'native_compilation_executed': False, 'product_tests_executed': False,
    'full_git_object_closure_verified': False, 'formal_source_consumer_executed': False,
    'prior_product_results_inherited': False, 'matching_current_cold': False,
    'whole_writer_qualified': False, 'whole_native_delivery_qualified': False,
    'commands': [], 'checks': {}, 'source_count': SOURCE_COUNT,
    'candidate_count': NEW_COUNT, 'python': sys.version, 'executable': sys.executable,
}
config = None
old_inputs = None
baseline = None
old_before = None
copy_before = None
expected = None
generation = None
controls_before = None
started = time.monotonic()


def save():
    number = 0
    while os.path.lexists(ROOT / ('report.tmp.' + str(number))):
        number += 1
    temporary = ROOT / ('report.tmp.' + str(number))
    create(temporary, wire(report))
    os.replace(temporary, ROOT / 'report.json')
    sync_directory(ROOT)


def runtime_inputs():
    return {
        'python': stable_file(PYTHON, PYTHON_SHA, resolve=True, executable=True)[0],
        'compiler': stable_file(COMPILER, COMPILER_SHA)[0],
        'previous_report': stable_file(PREVIOUS_REPORT, PREVIOUS_REPORT_SHA)[0],
        'previous_guardian': stable_file(PREVIOUS_GUARD, PREVIOUS_GUARD_SHA)[0],
        'previous_source_snapshot': stable_file(PREVIOUS_SNAPSHOT, PREVIOUS_SNAPSHOT_SHA)[0],
        'previous_preparation': stable_file(PREVIOUS_PREPARATION, PREVIOUS_PREPARATION_SHA)[0],
        'previous_candidate_before': stable_file(PREVIOUS_CANDIDATE, PREVIOUS_CANDIDATE_SHA)[0],
        'failed_authoring_report': stable_file(FAILED_AUTHORING_REPORT, FAILED_AUTHORING_REPORT_SHA)[0],
        'failed_authoring_guardian': stable_file(FAILED_AUTHORING_GUARD, FAILED_AUTHORING_GUARD_SHA)[0],
    }


def control_snapshot():
    names = [*config['files'], 'config.json', 'stdin-original.json', 'bootstrap-original.py']
    return {name: stable_file(ROOT / 'control' / name)[0] for name in sorted(names)}


def members(root, allow_git):
    require(root.is_absolute() and stat.S_ISDIR(root.lstat().st_mode)
            and not any(p.is_symlink() for p in (root, *root.parents)),
            'ordinary private source root required')
    result = set()
    for current, directories, files in os.walk(root, followlinks=False):
        parent = Path(current)
        if parent == root and '.git' in directories:
            require(allow_git, 'candidate must not contain a Git object directory')
            git = root / '.git'
            require(stat.S_ISDIR(git.lstat().st_mode), 'old Git directory is not ordinary')
            directories.remove('.git')
        for name in directories:
            path = parent / name
            relative = checked_relative(path.relative_to(root).as_posix())
            require(stat.S_ISDIR(path.lstat().st_mode)
                    and path.lstat().st_uid == os.geteuid(),
                    'ordinary owned source directory required: ' + relative)
        for name in files:
            result.add(checked_relative((parent / name).relative_to(root).as_posix()))
    return result


def snapshot(root, pins, name, allow_git=False):
    require(members(root, allow_git) == set(pins), 'source physical leaf denominator differs')
    files = {}
    for relative in sorted(pins):
        pin = pins[relative]
        info, _ = stable_file(root / relative, pin['sha256'])
        mode = '100755' if info['identity'][2] & stat.S_IXUSR else '100644'
        size = pin.get('bytes', pin.get('size'))
        require(info['bytes'] == size and mode == pin['mode'],
                'source file size or canonical mode differs: ' + relative)
        files[relative] = dict(info, mode=mode)
    value = {
        'schema': 'hepta.hia.machine-elf.sort-source-observation.v1',
        'root': str(root), 'files': files,
        'git_object_database_copied': False,
        'formal_source_qualification': False,
    }
    report.setdefault('source_records', {})[name] = create(ROOT / name, wire(value))
    return value


def copy_one(relative, old):
    target = ROOT / 'source' / relative
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(path.is_symlink() for path in (target.parent, *target.parent.parents)),
            'private destination parent is not ordinary')
    fd = os.open(SOURCE / relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    digest, count = sha256(), 0
    mode = 0o755 if old['mode'] == '100755' else 0o644
    with os.fdopen(fd, 'rb') as incoming:
        before = os.fstat(incoming.fileno())
        require(list(identity(before)) == old['identity'], 'old source changed before copy')
        outfd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        with os.fdopen(outfd, 'wb') as outgoing:
            os.fchmod(outgoing.fileno(), mode)
            for chunk in iter(lambda: incoming.read(1 << 20), b''):
                count += len(chunk)
                require(count <= old['bytes'], 'source grew during copy')
                digest.update(chunk)
                outgoing.write(chunk)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        require(identity(before) == identity(os.fstat(incoming.fileno()))
                == identity((SOURCE / relative).lstat()), 'old source changed during copy')
    require(count == old['bytes'] and digest.hexdigest() == old['sha256'],
            'copied source bytes differ')
    copied, _ = stable_file(target, old['sha256'])
    require(copied['bytes'] == count and copied['identity'][:2] != old['identity'][:2],
            'independent source bytes were not copied')
    return copied


def run_source_generation():
    label = 'source-generation'
    stdout, stderr = ROOT / (label + '.stdout'), ROOT / (label + '.stderr')
    command = [str(PYTHON), '-B', str(ROOT / 'control' / 'source_worker.py')]
    record = {'label': label, 'argv': command, 'cwd': str(ROOT / 'source'),
              'timeout_seconds': 60, 'returncode': None, 'timed_out': False}
    at = time.monotonic()
    try:
        with stdout.open('xb') as out, stderr.open('xb') as err:
            value = subprocess.run(command, cwd=ROOT / 'source', env=environment(),
                stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=60)
        record['returncode'] = value.returncode
    except subprocess.TimeoutExpired:
        record['timed_out'] = True
        raise
    finally:
        record['seconds'] = time.monotonic() - at
        record['stdout'] = stable_file(stdout)[0]
        record['stderr'] = stable_file(stderr)[0]
        report['commands'].append(record)
        save()
    require(record['returncode'] == 0, 'source generation or Core/cap check failed')


try:
    config = checked_config()
    controls_before = control_snapshot()
    report['control_inputs_before'] = controls_before
    old_inputs = runtime_inputs()
    report['old_inputs_before'] = old_inputs
    prior, prior_pin = read_json(PREVIOUS_REPORT, PREVIOUS_REPORT_SHA)
    prior_guard, guard_pin = read_json(PREVIOUS_GUARD, PREVIOUS_GUARD_SHA)
    require(prior.get('status') == 'ELF_INTEGRATION_DEVELOPMENT_PASS_PENDING_EXTERNAL_GUARDIAN'
            and prior.get('product_commit') == '66f00357a9a847c816609238a5d433e5f435023c'
            and prior.get('source_stable') is True
            and prior.get('readonly_inputs_stable') is True
            and natural_guardian(prior_guard), 'old completed source custody differs')
    preparation, preparation_pin = read_json(PREVIOUS_PREPARATION, PREVIOUS_PREPARATION_SHA)
    prepared, prepared_pin = read_json(PREVIOUS_CANDIDATE, PREVIOUS_CANDIDATE_SHA)
    baseline, snapshot_pin = read_json(PREVIOUS_SNAPSHOT, PREVIOUS_SNAPSHOT_SHA)
    require(preparation_pin['bytes'] == 8698 and prepared_pin['bytes'] == 2479941
            and snapshot_pin['bytes'] == 2479764, 'actual prior receipt sizes differ')
    require(prior['checks']['fresh_independent_source_preparation']['pass'] is True
            and prior['checks']['fresh_independent_source_preparation']['report'] == preparation_pin,
            'completed report does not bind the actual original preparation receipt')
    require(preparation.get('schema') == 'hepta.hia.machine-elf.integration-source-preparation.v1'
            and preparation.get('status') == 'DEVELOPMENT_SOURCE_PREPARED_NO_PRODUCT_EXECUTED'
            and preparation.get('scope') == 'SOURCE_PREPARATION_ONLY_NOT_QUALIFICATION'
            and preparation.get('base_commit') == '608157e52b0b94e0d294f6b99c4e809869f183aa'
            and preparation.get('base_tree') == 'e7c29a60796a1a78946a2c667aa80df86529e532'
            and preparation.get('product_commit') == '66f00357a9a847c816609238a5d433e5f435023c'
            and preparation.get('complete_independent_clone_checked') is True
            and preparation.get('original_source_state_stable') is True
            and preparation.get('original_source_metadata_stable') is True
            and preparation.get('native_executed') is False, 'actual historical source identity differs')
    require(preparation['candidate_source'] == prepared_pin
            and preparation['source_metadata']['candidate-source-before.json'] == prepared_pin,
            'original preparation does not bind the actual complete candidate observation')
    require(set(prepared) == {'schema', 'root', 'head', 'tree', 'files'}
            and prepared.get('schema') == 'hepta.hia.machine-elf.authoring-source-observation.v1'
            and prepared.get('root') == str(SOURCE)
            and prepared.get('head') == preparation['base_commit']
            and prepared.get('tree') == preparation['base_tree']
            and type(prepared.get('files')) is dict
            and len(prepared['files']) == SOURCE_COUNT, 'actual initial source observation differs')
    require(set(baseline) == {'root', 'files'} and baseline.get('root') == str(SOURCE)
            and type(baseline.get('files')) is dict
            and len(baseline['files']) == SOURCE_COUNT
            and baseline['files'] == prepared['files'],
            'complete before/after 3932-file source mappings differ')
    require(prior['source_after'] == snapshot_pin
            and prior['source_before']['sha256'] == PREVIOUS_SNAPSHOT_SHA
            and prior['source_before']['bytes'] == snapshot_pin['bytes'],
            'prior source report does not bind this complete file snapshot')
    require(type(preparation.get('products_installed')) is dict
            and len(preparation['products_installed']) == 12, 'original overlay denominator differs')
    for relative, pin in preparation['products_installed'].items():
        require(relative in prepared['files']
                and all(prepared['files'][relative][field] == pin[field]
                        for field in ('bytes', 'sha256')),
                'original product delta does not match the complete source observation')
    for relative, pin in baseline['files'].items():
        checked_relative(relative)
        require(pin['path'] == str(SOURCE / relative)
                and pin['resolved'] == pin['path']
                and pin['mode'] in ('100644', '100755')
                and type(pin['bytes']) is int and pin['bytes'] >= 0,
                'invalid previous physical source member')
    report['prior_completed_source_custody'] = {
        'report': prior_pin, 'guardian': guard_pin, 'snapshot': snapshot_pin,
        'preparation': preparation_pin, 'candidate_before': prepared_pin,
        'complete_before_after_files_mapping_equal': True, 'source_members': SOURCE_COUNT,
        'actual_post_snapshot_has_no_git_headers': True,
        'product_results_inherited': False,
    }
    for path, digest, name in (
        (PREVIOUS_REPORT, PREVIOUS_REPORT_SHA, 'prior-report-original.json'),
        (PREVIOUS_GUARD, PREVIOUS_GUARD_SHA, 'prior-guardian-original.json'),
        (PREVIOUS_SNAPSHOT, PREVIOUS_SNAPSHOT_SHA, 'prior-source-snapshot-original.json'),
        (PREVIOUS_PREPARATION, PREVIOUS_PREPARATION_SHA, 'prior-source-preparation-original.json'),
        (PREVIOUS_CANDIDATE, PREVIOUS_CANDIDATE_SHA, 'prior-candidate-before-original.json'),
        (FAILED_AUTHORING_REPORT, FAILED_AUTHORING_REPORT_SHA, 'failed-authoring-r2-report-original.json'),
        (FAILED_AUTHORING_GUARD, FAILED_AUTHORING_GUARD_SHA, 'failed-authoring-r2-guardian-original.json'),
    ):
        info, raw = stable_file(path, digest, collect=True)
        create(ROOT / 'inputs' / name, raw)
    space = os.statvfs(ROOT)
    report['storage_before'] = {'device': ROOT.stat().st_dev,
        'available_bytes': space.f_bavail * space.f_frsize, 'available_inodes': space.f_favail}
    require(space.f_bavail * space.f_frsize >= 8 << 30 and space.f_favail >= 100000,
            'original private storage capacity gate not met')
    old_before = snapshot(SOURCE, baseline['files'], 'old-source-before.json', True)
    require(old_before['files'] == baseline['files'],
            'current old source differs from its actual frozen f74 observation')
    (ROOT / 'source').mkdir(mode=0o700)
    for relative in sorted(baseline['files']):
        copy_one(relative, baseline['files'][relative])
    copy_before = snapshot(ROOT / 'source', baseline['files'], 'copy-before.json')
    report['checks']['complete_independent_physical_leaf_copy'] = True
    oracle_info, oracle = stable_file(ROOT / 'control' / 'oracle-608.py.txt',
                                     ORACLE_SHA, collect=True)
    require((ROOT / 'source' / 'hepta/hia_machine_elf.py').read_bytes().startswith(oracle),
            'complete original writer prefix was not retained')
    report['checks']['whole_original_oracle_prefix'] = True
    expected = dict(baseline['files'])
    require(not (set(expected) & NEW_PATHS), 'new helper path already exists in frozen source')
    for relative in OVERLAYS:
        pin = config['overlays'][relative]
        info, raw = stable_file(ROOT / 'control' / pin['file'], pin['sha256'], collect=True)
        require(info['bytes'] == pin['size'], 'exact staged source size differs')
        ast.parse(raw, filename=relative)
        target = ROOT / 'source' / relative
        if relative in NEW_PATHS:
            create(target, raw, 0o644)
        else:
            require(relative in copy_before['files'], 'existing overlay is outside source')
            temporary = target.with_name(target.name + '.timsort-overlay-new')
            create(temporary, raw, 0o644)
            os.replace(temporary, target)
        expected[relative] = {'sha256': pin['sha256'], 'size': pin['size'], 'mode': '100644'}
    before_generation = snapshot(ROOT / 'source', expected, 'candidate-before-generation.json')
    require(len(before_generation['files']) == NEW_COUNT, 'candidate file denominator differs')
    report['checks']['exact_nine_authoring_inputs'] = True
    _, compiler_bytes = stable_file(COMPILER, COMPILER_SHA, collect=True)
    require(len(compiler_bytes) == 668608, 'fixed development compiler length differs')
    create(ROOT / 'inputs' / 'B3.image.bin', compiler_bytes)
    report['development_compiler_input'] = {
        'original_path': str(COMPILER), 'bytes': len(compiler_bytes),
        'sha256': COMPILER_SHA, 'copied_path': str(ROOT / 'inputs' / 'B3.image.bin'),
        'executed': False, 'matching_current_cold': False,
    }
    save()
    run_source_generation()
    generation, pin = read_json(ROOT / 'source-generation-report.json')
    report['source_generation'] = pin
    require(generation.get('status') == 'SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED'
            and generation.get('roundtrip') is True
            and generation.get('original_limits') == LIMITS
            and generation.get('native_compilation_executed') is False
            and generation.get('product_tests_executed') is False
            and generation.get('comparison_input_count') == 122
            and generation.get('comparison_inputs_executed') is False,
            'source-only generation conjunction failed')
    generated, _ = stable_file(ROOT / 'source' / GENERATED, generation['generated_source']['sha256'])
    expected[GENERATED] = {'sha256': generated['sha256'], 'size': generated['bytes'], 'mode': '100644'}
    candidate_after = snapshot(ROOT / 'source', expected, 'candidate-source-after.json')
    for relative, old in copy_before['files'].items():
        if relative not in set(OVERLAYS) | {GENERATED}:
            require(candidate_after['files'][relative] == old,
                    'unapproved candidate source identity changed: ' + relative)
    require(len(candidate_after['files']) == NEW_COUNT, 'final candidate denominator differs')
    report['checks'].update(source_syntax=True, core_roundtrip=True, original_caps=True,
                            exact_ten_allowed_source_deltas=True)
    report['status'] = 'SORT_SOURCE_AUTHORING_PASS_PENDING_EXTERNAL_GUARDIAN'
except BaseException:
    report['error'] = traceback.format_exc()
finally:
    report['preserved_authoring_outputs'] = {}
    for name in ('generated-document.json', 'generated-machine-elf.hiaasm',
                 'source-generation-report.json'):
        path = ROOT / name
        if os.path.lexists(path):
            try:
                report['preserved_authoring_outputs'][name] = stable_file(path)[0]
            except BaseException:
                report.setdefault('output_observation_errors', {})[name] = traceback.format_exc()
                report['status'] = 'HOLD'
    try:
        if baseline is not None and old_before is not None:
            after = snapshot(SOURCE, baseline['files'], 'old-source-after.json', True)
            report['old_source_preserved'] = after == old_before
            require(report['old_source_preserved'], 'old completed source changed')
        if old_inputs is not None:
            report['old_inputs_after'] = runtime_inputs()
            report['old_inputs_preserved'] = old_inputs == report['old_inputs_after']
            require(report['old_inputs_preserved'], 'prior source custody/runtime/compiler changed')
        if config is not None:
            checked_config()
            report['control_inputs_after'] = control_snapshot()
            report['control_inputs_preserved'] = controls_before == report['control_inputs_after']
            require(report['control_inputs_preserved'], 'control byte or file identity changed')
    except BaseException:
        report['after_observation_error'] = traceback.format_exc()
        report['status'] = 'HOLD'
    report['seconds'] = time.monotonic() - started
    save()
    print(json.dumps({name: report.get(name) for name in (
        'status', 'scope', 'seconds', 'checks', 'error', 'after_observation_error',
        'old_source_preserved', 'old_inputs_preserved', 'control_inputs_preserved')},
        sort_keys=True), flush=True)
raise SystemExit(0 if report['status'] == 'SORT_SOURCE_AUTHORING_PASS_PENDING_EXTERNAL_GUARDIAN' else 1)
