"""One fresh ELF integration development attempt; original child gates retained."""
from pathlib import Path
import json
import os
import stat
import sys
import time
import traceback
from common import (ROOT, SOURCE, ORIGINAL, COMPILER, PYTHON, HIA_SHA, IMAGE_SHA,
    COMPILER_SHA, PRODUCT_COMMIT, BUDGETS, WORKFLOW_SHA, checked_config, create,
    environment, load_exact, natural_guardian, read_json, stable_file, wire, require)
config = checked_config(ROOT / 'control/config.json')
workflow = load_exact('elf_integration_workflow', ROOT / 'control/workflow_process.py',
                      WORKFLOW_SHA)
env = environment()
build_dir = ROOT / 'native-build'
manifest = build_dir / 'manifest.json'
report = {'schema': 'hepta.hia.machine-elf.integration-development.v1', 'status': 'HOLD',
    'scope': 'NEW_COMPONENT_DEVELOPMENT_NOT_FULL_QUALIFICATION',
    'product_commit': PRODUCT_COMMIT, 'root': str(ROOT), 'commands': [], 'checks': {},
    'budgets': BUDGETS, 'original_compile_limits': {'wall_seconds': 20, 'cpu_seconds': 10,
        'address_space_bytes': 256 << 20, 'stack_bytes': 8 << 20},
    'original_51_seconds': 180, 'cold_qualification_executed': False,
    'whole_native_delivery_qualified': False, 'whole_writer_qualified': False,
    'foreign_timsort_schedule_closed': False, 'old_55_51_results_inherited': False}
started = time.monotonic()
save_number = 0
readonly_before = None
source_before = None
build_before = None
failure = None

def save():
    global save_number
    save_number += 1
    path = ROOT / ('report-update-' + str(save_number) + '.json')
    create(path, wire(report))
    os.replace(path, ROOT / 'report.json')

def observed_inputs():
    return {path: stable_file(path, pin['sha256'], resolve=pin.get('resolve', False),
        executable=pin.get('executable', False))[0]
        for path, pin in config['readonly_inputs'].items()}

def source_snapshot(label):
    original, _ = read_json(ROOT / 'candidate-source-before.json')
    require(original['root'] == str(SOURCE) and len(original['files']) == 3932,
            'complete prepared source inventory differs')
    expected = original['files']
    actual = set()
    for current, directories, files in os.walk(SOURCE, followlinks=False):
        if Path(current) == SOURCE:
            require('.git' in directories, 'independent Git source missing')
            directories.remove('.git')
        for directory in directories:
            require(stat.S_ISDIR((Path(current) / directory).lstat().st_mode),
                    'source directory link or special file')
        actual.update((Path(current) / name).relative_to(SOURCE).as_posix() for name in files)
    require(actual == set(expected), 'complete source file denominator changed')
    result = {}
    for relative, old in sorted(expected.items()):
        info, _ = stable_file(SOURCE / relative, old['sha256'])
        mode = '100755' if (SOURCE / relative).stat().st_mode & stat.S_IXUSR else '100644'
        info = {**info, 'mode': mode}
        require(info == old, 'source bytes, mode or identity changed: ' + relative)
        result[relative] = info
    return result, create(ROOT / label, wire({'root': str(SOURCE), 'files': result}))

def step(label, argv, seconds, cwd=None):
    value = workflow.run_workflow_step([str(PYTHON), '-B', *map(str, argv)],
        cwd=SOURCE if cwd is None else cwd, env=env,
        stdout_path=ROOT / (label + '.stdout'), stderr_path=ROOT / (label + '.stderr'),
        receipt_path=ROOT / (label + '.process.json'), seconds=seconds)
    report['commands'].append(value)
    save()
    require(value['status'] == 'WORKFLOW_STEP_COMPLETED' and value['returncode'] == 0
        and value['timed_out'] is False and value['cleanup']['complete'] is True
        and value['cleanup']['signalled'] == [] and value['cleanup']['errors'] == [],
        label + ' did not complete naturally')

def build_snapshot():
    value, receipt = read_json(build_dir / 'build.json')
    doc, manifest_pin = read_json(manifest)
    require(Path(doc['image_path']).name == doc['image_path'], 'unsafe image basename')
    image_pin, _ = stable_file(build_dir / doc['image_path'], IMAGE_SHA)
    require(image_pin['bytes'] == 269358, 'actual image file identity differs')
    require(value['status'] == 'NATIVE_CANDIDATE_BUILT'
        and value['scope'] == 'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD'
        and value['build_inputs_stable'] is True and value['manifest'] == doc
        and value['compiler_sha256'] == COMPILER_SHA
        and value['native_compile_receipt']['input_sha256'] == HIA_SHA
        and value['native_compile_receipt']['produced_sha256'] == IMAGE_SHA
        and value['native_compile_receipt']['artifact_sha256'] == COMPILER_SHA
        and doc['source_sha256'] == HIA_SHA and doc['image_sha256'] == IMAGE_SHA,
        'actual builder/source/image/receipt conjunction failed')
    return {'report': receipt, 'manifest': manifest_pin, 'image': image_pin}

def methods(group):
    output = ROOT / ('methods-' + group)
    args = [ROOT / 'control/suite.py', '--group', group, '--output', output]
    if group != 'source':
        args += ['--manifest', manifest]
    step('methods-' + group, args, BUDGETS[group + '_methods'])
    value, pin = read_json(output / 'report.json')
    expected = config['method_ids'][group]
    require(value['status'] == 'PASS' and value['expected_test_ids'] == expected
        and value['loaded_test_ids'] == expected and value['executed_test_ids'] == expected
        and value['tests_run'] == len(expected) and value['loader_errors'] == []
        and all(number == 0 for number in value['anomaly_counts'].values()),
        'complete ' + group + ' method conjunction failed')
    if group != 'source':
        require(value['native_operation_counts'] and value['image_sha256'] == IMAGE_SHA
            and value['admitted_source_sha256'] == HIA_SHA, 'actual native group identity differs')
    report['checks'][group + '_complete_methods'] = {'pass': True, 'count': len(expected),
                                                  'report': pin}
    save()

try:
    require(sys.version_info[:3] == (3, 14, 4), 'fixed Python version differs')
    readonly_before = observed_inputs()
    report['readonly_inputs_before'] = readonly_before
    old, _ = read_json(config['baseline_guard']['report_path'],
                      config['baseline_guard']['report_sha256'])
    guard, _ = read_json(config['baseline_guard']['guardian_path'],
                        config['baseline_guard']['guardian_sha256'])
    require(old['status'] == 'COMPONENT_DEVELOPMENT_PASS_PENDING_EXTERNAL_GUARDIAN'
        and len(old['checks']) == 5 and all(old['checks'].values()) and natural_guardian(guard),
        'actual prior finite native evidence did not admit baseline')
    step('source-prepare', [ROOT / 'control/prepare.py'], BUDGETS['source_prepare'], ROOT)
    prepared, pin = read_json(ROOT / 'source-preparation.json')
    require(prepared['status'] == 'DEVELOPMENT_SOURCE_PREPARED_NO_PRODUCT_EXECUTED'
        and prepared['complete_independent_clone_checked'] is True
        and prepared['original_source_state_stable'] is True
        and prepared['original_source_metadata_stable'] is True
        and len(prepared['products_installed']) == 12, 'fresh source preparation refused')
    report['checks']['fresh_independent_source_preparation'] = {'pass': True, 'report': pin}
    source_before, pin = source_snapshot('source-before-products.json')
    report['source_before'] = pin
    methods('source')
    step('native-build', ['-m', 'tools.build_hia_machine_elf',
        '--compiler', ROOT / 'inputs/B3.image.bin', '--output', build_dir, '--development'],
        BUDGETS['native_build'])
    build_before = build_snapshot()
    report['build_before'] = build_before
    report['checks']['fresh_development_native_build'] = {'pass': True}
    step('private-permission', [ROOT / 'control/permission.py', '--manifest', manifest,
        '--output', ROOT / 'private-permission.json'], BUDGETS['private_guard_comparison'])
    value, pin = read_json(ROOT / 'private-permission.json')
    require(value['status'] == 'PASS' and value['loaded'] == value['executed'] == 1
        and value['loaded_case_ids'] == value['executed_case_ids']
        and value['candidate']['effect_ledger_delta'] == []
        and value['baseline']['effect_ledger_delta'], 'old/new real permission comparison failed')
    report['checks']['old_new_actual_native_permission'] = {'pass': True, 'report': pin}
    methods('native')
    methods('boundary')
    output = ROOT / 'original-51'
    step('original-51', ['-m', 'tools.qualify_hia_machine_elf',
        '--development-manifest', manifest, '--output', output], BUDGETS['original_51'])
    value, pin = read_json(output / 'report.json')
    expected = config['original_51_ids']
    require(value['status'] == 'SELECTED_NATIVE_ELF_CALLERS_PASS'
        and value['loaded_test_ids'] == expected and value['executed_test_ids'] == expected
        and len(expected) == value['tests_run'] == 51 and value['loader_errors'] == []
        and all(number == 0 for number in value['anomaly_counts'].values())
        and value['retained_writer_calls'] == [] and value['native_operation_counts']
        and value['bundle_stable'] is True and value['source_stable'] is True,
        'strict original 51 caller conjunction failed')
    report['checks']['original_51_strict_selected_callers'] = {'pass': True, 'report': pin}
    require(len(report['checks']) == 7 and all(x['pass'] for x in report['checks'].values()),
            'complete seven-gate development denominator differs')
    report['status'] = 'ELF_INTEGRATION_DEVELOPMENT_PASS_PENDING_EXTERNAL_GUARDIAN'
except BaseException as exc:
    failure = exc
    report['failure'] = {'type': type(exc).__name__, 'text': str(exc),
                         'traceback': traceback.format_exc()}
finally:
    try:
        if build_before is not None:
            after = build_snapshot()
            report['build_after'] = after
            require(after == build_before, 'actual bundle changed')
            report['build_stable'] = True
        if source_before is not None:
            after, pin = source_snapshot('source-after-products.json')
            report['source_after'] = pin
            require(after == source_before, 'full candidate source changed')
            report['source_stable'] = True
        checked_config(ROOT / 'control/config.json')
        report['controls_preserved'] = True
        if readonly_before is not None:
            after = observed_inputs()
            report['readonly_inputs_after'] = after
            require(after == readonly_before, 'original readonly inputs changed')
            report['readonly_inputs_stable'] = True
        if (ROOT / 'original-source-before.json').exists():
            observation, _ = read_json(ROOT / 'original-source-before.json')
            old_map = observation['files']
            actual_paths = set()
            for current, directories, filenames in os.walk(ORIGINAL, followlinks=False):
                if Path(current) == ORIGINAL:
                    require('.git' in directories, 'old complete Git source disappeared')
                    directories.remove('.git')
                for directory in directories:
                    require(stat.S_ISDIR((Path(current) / directory).lstat().st_mode),
                            'old source directory became nonordinary')
                actual_paths.update((Path(current) / name).relative_to(ORIGINAL).as_posix()
                                    for name in filenames)
            require(actual_paths == set(old_map), 'old full source denominator changed')
            new_map = {}
            for relative, old in old_map.items():
                info, _ = stable_file(ORIGINAL / relative, old['sha256'])
                mode = '100755' if (ORIGINAL / relative).stat().st_mode & stat.S_IXUSR else '100644'
                new_map[relative] = {**info, 'mode': mode}
            require(new_map == old_map, 'original full source metadata changed during products')
            report['original_source_after_products'] = create(
                ROOT / 'original-source-after-products.json',
                wire({'root': str(ORIGINAL), 'files': new_map}))
            report['original_source_stable'] = True
    except BaseException as exc:
        report['final_capture_failure'] = {'type': type(exc).__name__, 'text': str(exc),
                                         'traceback': traceback.format_exc()}
        if failure is None:
            failure = exc
    report['seconds'] = time.monotonic() - started
    if failure is not None:
        report['status'] = 'HOLD'
    save()
    print(json.dumps({'status': report['status'], 'checks': report['checks'],
                      'seconds': report['seconds']}), flush=True)
if failure is not None:
    raise failure
