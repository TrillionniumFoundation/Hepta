"""Read actual retained CLI and instruction-byte receipts for the v8 guardian.

These hosted checks admit no development build as current-source qualification.
They execute no compiler, image, product operation or replacement test suite.
"""
from hashlib import sha256
import json
from pathlib import Path
import re
import stat
import zipfile


COLD_CHECKS = {
    'export_manifest_matches_qualification', 'isolated_python_without_site',
    'nested_full_qualification_pass', 'nested_process_exit_zero',
    'no_ancestor_git_identity', 'no_bytecode_cache_created',
    'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
    'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed',
    'source_export_hashes_preserved',
}
ENCODING_MODULES = (
    'tests.test_hia_machine_x64', 'tests.test_hia_machine_plan',
    'tests.test_hia_machine_registers', 'tests.test_hia_machine_leaf_registers',
    'tests.test_hia_agent_native_machine_choices',
)
ENCODING_COMMANDS = {
    'align', 'mov_rr', 'mov_imm', 'load', 'store', 'lea', 'load_u8', 'store_u8',
    'add', 'sub', 'and_', 'or_', 'xor', 'cmp', 'test', 'alu_imm', 'shift',
    'imul', 'mul', 'imul_full', 'div', 'idiv', 'neg', 'bitnot', 'cqo',
    'set_byte', 'cmov', 'push', 'pop', 'ret', 'leave', 'ud2',
    'jmp_prefix', 'jcc_prefix', 'call_prefix', 'zero_rel32', 'rel32',
}
CLI_SOURCES = {
    'control': 'examples/hia_bootstrap/cli_control.hiaasm',
    'format': 'examples/hia_bootstrap/cli_format.hiaasm',
}
CLI_OWNER_FILES = (
    'hepta/cli.py', 'hepta/hia_cli_native.py', 'tools/build_hia_cli_native.py',
    'tools/generate_hia_cli_control.py', 'tools/hia_cli_control_phases.py',
    'tools/generate_hia_cli_format.py', 'tools/hia_cli_unicode_tables.json',
    *CLI_SOURCES.values(),
)
CLI_ACTIONS = {
    'capabilities', 'catalog', 'import-assembly', 'render-assembly',
    'check-assembly', 'verify', 'inspect', 'normalize', 'build', 'patch',
    'impact', 'edit-query', 'edit-apply', 'edit-batch-query', 'edit-batch-apply',
}
CLI_INSTALLED_REFUSALS = {
    'changed-installed-control', 'missing-installed-control',
    'changed-installed-format', 'missing-installed-format',
    'bundle-schema', 'bundle-child-traversal', 'bundle-child-hash',
    'missing-selected-bundle', 'empty-selected-bundle',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def raw_file(path):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode), 'retained evidence is not a regular file: ' + str(path))
    return path.read_bytes()


def json_file(path):
    value = json.loads(raw_file(path))
    require(type(value) is dict, 'retained JSON must be an object: ' + str(path))
    return value


def record(path):
    raw = raw_file(path)
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def cold_identity(raw, sources, profile):
    value = json.loads(raw)
    require(type(value) is dict
            and value.get('schema') == 'hepta.hia.selfhost-cold-replay.v1'
            and value.get('profile') == profile
            and value.get('status') == 'COLD_SELFHOST_REPLAY_PASS'
            and type(value.get('returncode')) is int and value['returncode'] == 0
            and type(value.get('checks')) is dict and set(value['checks']) == COLD_CHECKS
            and all(flag is True for flag in value['checks'].values())
            and type(sources) is dict and bool(sources)
            and value.get('source_manifest') == sources,
            'complete current-source cold identity is required')
    pins = value.get('generation_sha256')
    require(type(pins) is list and len(pins) == 3
            and all(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin) for pin in pins)
            and pins[0] == pins[1] == pins[2], 'cold compiler generations differ')
    return pins[0]


def compiled_child(directory, manifest, native, source_pin, compiler, schema):
    require(type(manifest) is dict
            and set(manifest) == {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            and manifest['schema'] == schema
            and all(type(manifest[key]) is str and re.fullmatch('[0-9a-f]{64}', manifest[key])
                    for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))
            and manifest['source_sha256'] == source_pin and manifest['compiler_sha256'] == compiler,
            'child source, image or compiler manifest differs')
    name = manifest['image_path']
    require(type(name) is str and name not in ('', '.', '..')
            and Path(name).name == name and '/' not in name and '\\' not in name,
            'child image must use its retained basename')
    image = Path(directory) / name
    payload = raw_file(image)
    require(sha256(payload).hexdigest() == manifest['image_sha256'], 'retained image bytes differ')
    require(type(native) is dict and native.get('status') == 'returned'
            and type(native.get('abi_status')) is int and native['abi_status'] == 0
            and native.get('source_unchanged') is True
            and native.get('produced_sha256') == manifest['image_sha256']
            and type(native.get('produced_bytes')) is int and native['produced_bytes'] == len(payload)
            and native.get('input_sha256') == source_pin
            and native.get('artifact_sha256') == compiler
            and native.get('forbidden_compiler_modules_loaded') == [],
            'retained native compilation receipt differs')
    return record(image)


def exact_suite(value, count, modules, *, style='ordinary'):
    if style == 'encoding':
        loaded, executed = value.get('loaded_ids'), value.get('executed_ids')
        anomalies = ('loader_errors', 'failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')
        require(value.get('modules') == list(modules) and value.get('strict_pass') is True,
                'instruction-byte module selection differs')
    else:
        loaded, executed = value.get('loaded_test_ids'), value.get('executed_test_ids')
        anomalies = ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')
    require(type(loaded) is list and len(loaded) == count
            and all(type(name) is str for name in loaded)
            and len(set(loaded)) == count and loaded == executed
            and type(value.get('tests_run')) is int and value['tests_run'] == count
            and all(value.get(key) == [] for key in anomalies)
            and all(any(name.startswith(module + '.') for module in modules) for name in loaded)
            and all(any(name.startswith(module + '.') for name in loaded) for module in modules),
            'complete original test denominator or zero-anomaly result is missing')


def encoding_callers(evidence, cold_raw, cold_sources, profile):
    evidence = Path(evidence)
    compiler = cold_identity(cold_raw, cold_sources, profile)
    value = json_file(evidence / 'report.json')
    require(value.get('schema') == 'hepta.hia.machine-encoding-selected-callers.v1'
            and value.get('status') == 'PASS'
            and value.get('scope') == 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
            and value.get('source_before') == cold_sources and value.get('source_after') == cold_sources
            and value.get('source_stable') is True and value.get('manifest_image_stable') is True
            and value.get('retained_encoding_entries') == []
            and value.get('default_or_whole_stack_claimed') is False,
            'instruction-byte callers lack current cold source binding')
    groups = value.get('groups')
    require(type(groups) is list and len(groups) == 2
            and all(type(group) is dict for group in groups)
            and [group.get('label') for group in groups] == ['component', 'original-callers'],
            'complete instruction-byte groups are missing')
    exact_suite(groups[0], 9, ('tests.test_hia_machine_encoding_native',), style='encoding')
    exact_suite(groups[1], 51, ENCODING_MODULES, style='encoding')
    entries = value.get('native_entries')
    require(type(entries) is dict and set(entries) == ENCODING_COMMANDS
            and all(type(count) is int and count > 0 for count in entries.values()),
            'all 37 native instruction commands must actually execute')
    directory = evidence / 'build'
    manifest = json_file(directory / 'manifest.json')
    build = json_file(directory / 'build.json')
    require(manifest == value.get('manifest')
            and value.get('manifest_sha256') == record(directory / 'manifest.json')['sha256']
            and value.get('native_image_sha256') == manifest.get('image_sha256')
            and build.get('schema') == 'hepta.hia.machine-encoding-build.v1'
            and build.get('status') == 'NATIVE_CANDIDATE_BUILT' and build.get('profile') == profile
            and build.get('manifest') == manifest and build.get('source_manifest') == cold_sources
            and build.get('cold_report_sha256') == sha256(cold_raw).hexdigest(),
            'instruction-byte retained cold build differs')
    image = compiled_child(directory, manifest, build.get('native_compile_receipt'),
                           cold_sources['examples/hia_bootstrap/machine_encoding.hiaasm'], compiler,
                           'hepta.hia.machine-encoding-native.v2')
    return {'tests_run': 60, 'component_tests': 9, 'original_caller_tests': 51,
            'result': record(evidence / 'report.json'), 'build': record(directory / 'build.json'),
            'manifest': record(directory / 'manifest.json'), 'image': image,
            'native_entries': entries, 'actual_cold_build_retained': True}


def installed_cli_fixture(evidence, source_files, bundle, children, compiler):
    case = Path(evidence) / 'installed-control'
    value = json_file(case / 'report.json')
    expected_sources = {name: source_files[path] for name, path in CLI_SOURCES.items()}
    original_keys = set(value) & {'original_manifest', 'original_development_manifest'}
    require(value.get('schema') == 'hepta.hia.cli-installed-control.v1'
            and value.get('status') == 'PASS_INSTALLED_NATIVE_CLI_CONTROL'
            and value.get('scope') == 'MATCHING_SOURCE_COLD_BUILD'
            and value.get('whole_native_delivery_qualified') is False
            and value.get('packaging_uses_declared_resources_only') is True
            and value.get('original_sources_preserved') is True
            and value.get('source_sha256_before') == value.get('source_sha256_after') == expected_sources
            and len(original_keys) == 1
            and value[next(iter(original_keys))] == str((Path(evidence) / 'qualified/manifest.json').resolve())
            and value.get('manifest') == str((case / 'bundle/manifest.json').resolve()),
            'installed CLI lacks current cold fixture and source binding')
    require(json_file(case / 'bundle/manifest.json') == bundle, 'installed CLI copied a different bundle')
    for name, source in CLI_SOURCES.items():
        manifest = json_file(case / 'bundle' / name / 'manifest.json')
        require(manifest == children[name]['manifest'], 'installed CLI companion manifest differs')
        compiled_child(case / 'bundle' / name, manifest, children[name]['native_compile_receipt'],
                       source_files[source], compiler, 'hepta.hia.cli-' + name + '-native.v1')
    wheel = value.get('wheel')
    require(type(wheel) is dict and type(wheel.get('path')) is str, 'installed CLI wheel is missing')
    path = Path(wheel['path'])
    require(path.parent == case / 'wheels' and path.suffix == '.whl', 'wheel is outside retained case')
    actual_wheel = record(path)
    require(type(wheel.get('bytes')) is int and wheel['bytes'] == actual_wheel['bytes']
            and wheel.get('sha256') == actual_wheel['sha256'], 'retained wheel bytes differ')
    installed_paths = {name: case / 'installed/hepta/_data' / source for name, source in CLI_SOURCES.items()}
    python_files = {name: pin for name, pin in source_files.items()
                    if name.startswith('hepta/') and name.endswith('.py')}
    require(bool(python_files), 'complete installed Python custody input is missing')
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        for name, source in CLI_SOURCES.items():
            member = 'hepta/_data/' + source
            require(names.count(member) == 1
                    and sha256(archive.read(member)).hexdigest() == expected_sources[name]
                    and record(installed_paths[name])['sha256'] == expected_sources[name],
                    'wheel or installed CLI resource differs')
        for name, pin in python_files.items():
            require(names.count(name) == 1 and sha256(archive.read(name)).hexdigest() == pin
                    and record(case / 'installed' / name)['sha256'] == pin,
                    'wheel or installed hosted custody source differs: ' + name)
    observed = value.get('installed_execution')
    require(type(observed) is dict
            and observed == json_file(case / 'installed-execution.json')
            and observed == json.loads(raw_file(case / 'installed-execution.stdout'))
            and observed.get('schema') == 'hepta.hia.cli-installed-execution.v1'
            and observed.get('status') == 'PASS_INSTALLED_NATIVE_CLI_CONTROL'
            and observed.get('whole_native_delivery_qualified') is False
            and observed.get('source_sha256') == expected_sources
            and observed.get('installed_source_paths') == {name: str(path) for name, path in installed_paths.items()}
            and observed.get('bundle_sha256') == record(case / 'bundle/manifest.json')['sha256']
            and observed.get('console_entry_point') == 'hepta.cli:hia_main'
            and observed.get('isolated_without_site') is True and observed.get('empty_PATH') is True
            and observed.get('sources_and_bundle_restored') is True
            and observed.get('forbidden_entries') == {'tools': [], 'retained_cli': [], 'retained_parser': []},
            'actual isolated CLI stdout or installed execution facts differ')
    returns = observed.get('native_returns')
    require(type(returns) is dict and set(returns) == {'control', 'format'}
            and all(type(values) is list and bool(values) and all(type(code) is int for code in values)
                    for values in returns.values()), 'both actual installed HIA images must execute')
    refusals = observed.get('refusals')
    require(type(refusals) is list and len(refusals) == 9
            and all(type(row) is dict and type(row.get('case')) is str for row in refusals)
            and {row['case'] for row in refusals} == CLI_INSTALLED_REFUSALS,
            'installed resource and bundle refusals are incomplete')
    calls = observed.get('calls')
    require(type(calls) is list and len(calls) == 8
            and all(type(row) is dict and type(row.get('argv')) is list and row['argv'] for row in calls)
            and [row['argv'][0] for row in calls] == [
                '--version', '--help', 'verify', 'capabilities', 'verify', 'verify', '--version', '--version']
            and [row.get('code') for row in calls] == [0, 0, 0, 0, 2, 2, 0, 0],
            'complete installed CLI success, refusal and restoration calls are missing')
    processes = value.get('processes')
    require(type(processes) is list and len(processes) == 3
            and all(type(row) is dict for row in processes)
            and [row.get('label') for row in processes] == ['wheel-build', 'wheel-install', 'installed-execution'],
            'actual wheel build, install and execution processes are missing')
    for row in processes:
        require(type(row.get('returncode')) is int and row['returncode'] == 0
                and type(row.get('argv')) is list and bool(row['argv'])
                and row.get('stdout_sha256') == record(case / (row['label'] + '.stdout'))['sha256']
                and row.get('stderr_sha256') == record(case / (row['label'] + '.stderr'))['sha256'],
                'installed CLI process outcome or retained logs differ')
    arguments = processes[-1]['argv']
    require(arguments[1:4] == ['-I', '-S', '-B']
            and arguments[4:] == [str(case / 'installed-control.py'), str(case / 'installed'),
                                  str(case / 'bundle/manifest.json'), str(case / 'input.hia')],
            'installed execution did not use the isolated retained command')
    return {'report': record(case / 'report.json'), 'wheel': actual_wheel,
            'execution': record(case / 'installed-execution.json'), 'native_returns': returns,
            'installed_python_files_verified': len(python_files), 'refusal_cases': sorted(CLI_INSTALLED_REFUSALS)}


def cli_fixture(evidence, cold_raw, cold_sources, source_files, profile):
    evidence = Path(evidence)
    compiler = cold_identity(cold_raw, cold_sources, profile)
    directory = evidence / 'qualified'
    bundle = json_file(directory / 'manifest.json')
    build = json_file(directory / 'build.json')
    expected_sources = {name: source_files[name] for name in CLI_OWNER_FILES}
    require(all(cold_sources.get(name) == pin for name, pin in expected_sources.items()),
            'CLI owner files lie outside the cold source closure')
    require(set(bundle) == {'schema', 'control_manifest', 'control_manifest_sha256',
                            'format_manifest', 'format_manifest_sha256'}
            and bundle['schema'] == 'hepta.hia.cli-native-bundle.v1'
            and build.get('schema') == 'hepta.hia.cli-native-build.v1'
            and build.get('scope') == 'MATCHING_SOURCE_COLD_BUILD'
            and build.get('source_manifest') == cold_sources and build.get('bundle') == bundle
            and build.get('cold_report_sha256') == sha256(cold_raw).hexdigest()
            and build.get('compiler_sha256') == compiler
            and build.get('owner_sources_before') == build.get('owner_sources_after') == expected_sources
            and build.get('native_compiler_profile_expanded') is False
            and build.get('whole_cli_native') is False and build.get('production_activated') is False
            and build.get('whole_native_delivery_qualified') is False,
            'CLI bundle lacks current-source cold provenance')
    children = build.get('children')
    require(type(children) is dict and set(children) == set(CLI_SOURCES), 'CLI companion build is incomplete')
    images = {}
    for name, source in CLI_SOURCES.items():
        require(bundle[name + '_manifest'] == name + '/manifest.json', 'CLI companion path differs')
        path = directory / name / 'manifest.json'
        manifest = json_file(path)
        require(bundle[name + '_manifest_sha256'] == record(path)['sha256']
                and type(children[name]) is dict and children[name].get('manifest') == manifest,
                'CLI companion manifest bytes differ')
        images[name] = compiled_child(path.parent, manifest, children[name].get('native_compile_receipt'),
                                      cold_sources[source], compiler, 'hepta.hia.cli-' + name + '-native.v1')
    observations = json_file(evidence / 'observations.json')
    require(observations.get('schema') == 'hia.cli.native-test-observations.v1'
            and observations.get('scope') == 'MATCHING_SOURCE_COLD_BUILD'
            and observations.get('manifest') == str((directory / 'manifest.json').resolve())
            and observations.get('whole_native_delivery_qualified') is False
            and type(observations.get('observations')) is list, 'CLI actual fixture observations are missing')
    actions = [row for row in observations['observations'] if type(row) is dict and 'all_actions' in row]
    require(len(actions) == 1 and type(actions[0].get('all_actions')) is list
            and len(actions[0]['all_actions']) == 15 and set(actions[0]['all_actions']) == CLI_ACTIONS,
            'all fifteen CLI actions must execute')
    cases = actions[0].get('cases')
    require(type(cases) is list and len(cases) == 23
            and all(type(row) is dict and row.get('equal') is True
                    and row.get('actual') == row.get('expected') for row in cases),
            'complete CLI action and publication comparisons are missing')
    original = json_file(evidence / 'original-agent-entry/report.json')
    require(original.get('schema') == 'hia.cli.original-agent-entry-native-selection.v1'
            and original.get('status') == 'PASS'
            and type(original.get('selected_child_argv')) is list and bool(original['selected_child_argv']),
            'ordinary CLI child selection is missing')
    exact_suite(original, 6, ('tests.test_hia_agent_entry',))
    installed = installed_cli_fixture(evidence, source_files, bundle, children, compiler)
    return {'images': images, 'bundle': record(directory / 'manifest.json'),
            'build': record(directory / 'build.json'), 'observations': record(evidence / 'observations.json'),
            'original_callers': record(evidence / 'original-agent-entry/report.json'),
            'actions': 15, 'action_cases': 23, 'original_caller_tests': 6,
            'installed': installed,
            'actual_cold_build_retained': True}
