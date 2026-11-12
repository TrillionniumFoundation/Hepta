"""Read current-cold compiler-owner evidence without running a native product.

The original Store/page 21-gate reader remains an exact sub-conjunction.
Selected-call attempts and successful native returns are distinct observations.
Development builds and historical PASS records cannot qualify these gates.
"""
from __future__ import annotations

import ast
import gzip
from hashlib import sha256
import importlib
import json
from pathlib import Path
import stat
import sys
import unittest
import zipfile

from tools import hia_store_page_gates as previous

ROOT = Path(__file__).resolve().parents[1]
LEGACY_SOURCE_GENERATORS = (
    'core_workspace_pipeline',
    'core_workspace_facts',
    'core_workspace_facts_cli',
    'core_workspace_materialize',
    'core_workspace_cli',
    'capability_renaming',
    'core_module_graph',
    'core_workspace_json',
    'core_workspace_json_cli',
    'agent_identity',
    'agent_slice',
    'elf_linker',
    'native_filter',
    'core_json_cli',
    'agent_stdio',
    'agent_snapshot',
    'agent_snapshot_json',
    'agent_snapshot_json_cli',
    'sha256_stream',
    'native_observer',
    'sha256',
    'json_preflight',
    'json_decode',
    'json_canonical',
    'core_json_frontend',
    'selfhost',
    'agent_binary64',
    'agent_data_json',
    'instruction_policy',
    'program_shape',
    'function_shape',
    'artifact_publication',
    'core_admission_cli',
    'core_admission',
    'agent_binary64_format',
    'core_patch',
    'core_patch_cli',
    'core_patch_result_cli',
    'composite_types',
    'task_helpers',
    'composite_functions',
    'composite_constructor',
    'composite_outer',
    'worker_request',
    'release_install',
    'agent_journal',
    'json_wire',
    'worker_report',
    'machine_plan',
    'linked_observer',
    'machine_encoding',
    'cli_control',
    'cli_format',
    'agent_store_authority',
    'artifact_page',
    'machine_state',
    'machine_instructions',
    'machine_elf',
    'core_lowering',
)
SOURCE_GENERATORS = LEGACY_SOURCE_GENERATORS + ('bounded_read', 'core_unpack')
require = previous.require
json_file = previous.json_file
child_path = previous.child_path
cold_inputs = previous.cold_inputs
COMPILER_GATES = (
    'machine_state_complete_component',
    'machine_state_selected_original_callers',
    'machine_instructions_complete_component',
    'machine_instructions_selected_original_callers',
    'core_lowering_complete_component',
    'core_lowering_selected_original_machine_callers',
    'core_lowering_selected_original_core_callers',
    'machine_elf_complete_module',
    'machine_elf_selected_original_callers',
)
SUCCESSOR_GATES = previous.SUCCESSOR_GATES + COMPILER_GATES
OWNERS = {
    'state': {
        'module': 'tests.test_hia_machine_state_native', 'component_count': 12,
        'prefix': 'HEPTA_HIA_MACHINE_STATE', 'development_suffix': '_DEVELOPMENT_BUNDLE',
        'qualifier': 'tools.qualify_hia_machine_state_callers',
        'caller_schema': 'hepta.hia.machine-state-selected-callers.v1',
        'kinds': ('state', 'encoding'), 'gates': COMPILER_GATES[0:2],
    },
    'instructions': {
        'module': 'tests.test_hia_machine_instructions_native', 'component_count': 12,
        'prefix': 'HEPTA_HIA_MACHINE_INSTRUCTIONS', 'development_suffix': '_DEVELOPMENT_BUNDLE',
        'qualifier': 'tools.qualify_hia_machine_instructions_callers',
        'caller_schema': 'hepta.hia.machine-instructions-selected-callers.v1',
        'kinds': ('instructions', 'state', 'encoding'), 'gates': COMPILER_GATES[2:4],
    },
    'core': {
        'module': 'tests.test_hia_core_lowering_native', 'component_count': 15,
        'prefix': 'HEPTA_HIA_CORE_LOWERING', 'development_suffix': '_DEVELOPMENT_MANIFEST',
        'qualifier': 'tools.qualify_hia_core_lowering_callers',
        'caller_schema': 'hepta.hia.core-lowering-selected-callers.v2',
        'gates': COMPILER_GATES[4:7],
    },
    'elf': {
        'module': 'tests.test_hia_machine_elf_native', 'component_count': 20,
        'prefix': 'HEPTA_HIA_MACHINE_ELF', 'development_suffix': '_DEVELOPMENT_MANIFEST',
        'qualifier': 'tools.qualify_hia_machine_elf',
        'caller_schema': 'hepta.hia.machine-elf-callers.v1',
        'gates': COMPILER_GATES[7:9],
    },
}
SINGLE = {
    'state': ('machine_state', 'machine-state', 1),
    'instructions': ('machine_instructions', 'machine-instructions', 1),
    'encoding': ('machine_encoding', 'machine-encoding', 2),
    'elf': ('machine_elf', 'machine-elf', 1),
}
GROUP_ANOMALIES = ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')


def file_record(path):
    """Stream every retained byte, including complete boundary archives."""
    path = Path(path).resolve(strict=True)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode), 'ordinary retained file required')
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                              value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    digest, count = sha256(), 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
            count += len(block)
    require(count == before.st_size and identity(path.stat()) == identity(before),
            'retained file changed while hashing')
    return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest()}


def source_now(context):
    from tools.build_hia_json_preflight import current_sources
    actual = current_sources()
    require(actual == context['source_manifest'], 'current full source differs from cold')
    return actual


def source_record(name, context):
    require(type(name) is str and name in context['source_manifest'],
            'gate dependency is outside current cold source closure: ' + str(name))
    row = file_record(ROOT / name)
    require(row['sha256'] == context['source_manifest'][name],
            'current source byte identity differs: ' + name)
    return row


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def loaded_ids(modules, count):
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(modules)
    ids = [test.id() for test in flatten(suite)]
    require(not loader.errors and len(ids) == count and len(set(ids)) == count,
            'complete current test module discovery differs')
    return ids


def expected_groups(owner):
    config = OWNERS[owner]
    component = {'label': 'component', 'modules': [config['module']],
                 'count': config['component_count']}
    component['ids'] = loaded_ids(component['modules'], component['count'])
    qualifier = importlib.import_module(config['qualifier'])
    if owner in ('state', 'instructions'):
        modules = list(qualifier.ORIGINAL_MODULES)
        return [component, {'label': 'original-callers', 'modules': modules,
                            'count': 51, 'ids': loaded_ids(modules, 51)}]
    if owner == 'core':
        result = [component]
        for label, modules, ids, count in (
                ('original-machine', qualifier.ORIGINAL_MODULES, qualifier.ORIGINAL_IDS, 51),
                ('original-core', qualifier.CORE_MODULES, qualifier.CORE_IDS, 50)):
            actual = loaded_ids(modules, count)
            require(actual == list(ids), 'frozen original Core caller IDs differ')
            result.append({'label': label, 'modules': list(modules), 'count': count, 'ids': actual})
        return result
    modules = list(qualifier.MODULES)
    actual = loaded_ids(modules, 51)
    require(actual == list(qualifier.EXPECTED_IDS), 'frozen original ELF caller IDs differ')
    return [component, {'label': 'original-callers', 'modules': modules, 'count': 51, 'ids': actual}]


def validate_groups(actual, expected):
    require(type(actual) is list and len(actual) == len(expected), 'complete test groups missing')
    for row, wanted in zip(actual, expected):
        require(row.get('label') == wanted['label'] and row.get('modules') == wanted['modules'],
                'test group/module order differs')
        require(row.get('expected_methods') == wanted['count'] and row.get('tests_run') == wanted['count']
                and type(row.get('tests_run')) is int, 'test group denominator differs')
        require(row.get('loaded_ids') == wanted['ids'] == row.get('executed_ids')
                and row.get('loader_errors') == [], 'test group IDs incomplete or reordered')
        require(row.get('strict_pass') is True
                and all(row.get(key) == [] for key in GROUP_ANOMALIES),
                'test group has skips, failures, errors or expected/unexpected successes')


def positive_counts(value, expected=None):
    require(type(value) is dict and value and all(type(v) is int and v > 0 for v in value.values()),
            'actual native counter is absent or nonpositive')
    if expected is not None:
        require(set(value) == set(expected), 'actual native operation denominator differs')
    return value


def single_build(kind, folder, context):
    stem, protocol, version = SINGLE[kind]
    folder = Path(folder).resolve(strict=True)
    manifest_path, build_path = folder / 'manifest.json', folder / 'build.json'
    manifest, image = previous.manifest_image(
        manifest_path, 'hepta.hia.' + protocol + '-native.v' + str(version),
        'examples/hia_bootstrap/' + stem + '.hiaasm', context)
    require(set(manifest) == {'schema', 'source_sha256', 'image_path',
                             'image_sha256', 'compiler_sha256'},
            'single native manifest fields differ')
    require(Path(manifest['image_path']).name == manifest['image_path']
            and image.parent == folder, 'single native image escaped its build')
    build = json_file(build_path)
    require(build.get('schema') == 'hepta.hia.' + protocol + '-build.v1'
            and build.get('status') == 'NATIVE_CANDIDATE_BUILT'
            and build.get('source_manifest') == context['source_manifest']
            and build.get('cold_report_sha256') == context['cold_sha256']
            and build.get('manifest') == manifest and build.get('production_activated') is False,
            'actual current-cold single-image build differs')
    # State/instructions/encoding build v1 has no scope/top-level compiler field.
    if kind == 'elf':
        previous.build_context(build, context)
        from tools.build_hia_machine_elf import OWNED_SOURCE_FILES
        require(build.get('compiler_sha256') == context['compiler_sha256']
                and build.get('build_inputs_stable') is True
                and build.get('owned_source_sha256') == {
                    name: context['source_manifest'][name] for name in OWNED_SOURCE_FILES},
                'ELF builder input identity differs')
        require(build.get('manifest_sha256') == file_record(manifest_path)['sha256'],
                'ELF build manifest bytes differ')
    previous.compile_receipt(build.get('native_compile_receipt'), manifest, image, context)
    return {'manifest': manifest,
            'files': [file_record(p) for p in (manifest_path, image, build_path)]}


def code_group_builds(owner, evidence, context):
    """Read distinct component/caller directories, even when their image SHA agrees."""
    config = OWNERS[owner]
    result = {}
    for label, folder in (('component', Path(evidence) / 'component-fixture'),
                          ('original-callers', Path(evidence))):
        owners = {kind: single_build(kind, folder / kind, context) for kind in config['kinds']}
        result[label] = {'owners': owners,
            'source_manifest_sha256': sha256(json.dumps(
                context['source_manifest'], sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'admission': 'INDEPENDENT_MATCHING_COLD_BUILD_READBACK'}
    return result


def code_operations(owner):
    from hepta.hia_machine_state_native import MODES
    from hepta.hia_machine_encoding_native import COMMANDS
    require(len(MODES) == 6 and len(COMMANDS) == 37, 'original state/byte operation inventory differs')
    result = {'state': tuple(MODES), 'encoding': tuple(COMMANDS)}
    if owner == 'instructions':
        from hepta.hia_machine_instructions_native import MODES as INSTRUCTIONS
        require(len(INSTRUCTIONS) == 41, 'original instruction operation inventory differs')
        result = {'instructions': tuple(INSTRUCTIONS), **result}
    return result


def validate_code_returns(owner, report, bindings):
    requirements = code_operations(owner)
    semantics = {
        'existing_native_entries': 'selected-call attempts before the original method',
        'normal_returns_by_group_image_operation': 'original selected method returned normally',
        'exceptional_calls_removed_from_attempt_ledger': False,
        'component_counts_relabelled_as_caller_counts': False,
    }
    require(report.get('native_counter_semantics') == semantics
            and report.get('normal_return_image_identity_changes') == [],
            'native return/attempt meaning or identity changed')
    captured = report.get('native_group_bindings')
    require(type(captured) is dict and set(captured) == set(bindings), 'actual group build capture missing')
    for label, expected in bindings.items():
        row = captured[label]
        require(row.get('before') == expected == row.get('after')
                and row.get('all_actual_file_bytes_stable') is True and row.get('binding_stable') is True,
                'actual component/caller build differs from its before/after capture')
    returns = report.get('normal_native_returns_by_group_image_operation')
    require(type(returns) is dict and set(returns) == set(bindings), 'complete return groups missing')
    coverage = {kind: set() for kind in requirements}
    totals = {kind: {} for kind in requirements}
    for label, binding in bindings.items():
        require(type(returns[label]) is dict and set(returns[label]) == set(requirements),
                'native return owner group differs')
        for kind, names in requirements.items():
            image = binding['owners'][kind]['manifest']['image_sha256']
            images = returns[label][kind]
            require(type(images) is dict and set(images) == {image},
                    'native returns refer to another group image')
            counters = positive_counts(images[image])
            require(set(counters) <= set(names), 'native return operation is outside the admitted owner')
            coverage[kind].update(counters)
            for operation, count in counters.items():
                totals[kind][operation] = totals[kind].get(operation, 0) + count
    require(all(coverage[kind] == set(names) for kind, names in requirements.items()),
            'complete normally returned operation coverage missing')
    require(report.get('normal_return_coverage_complete') is True
            and report.get('normal_return_coverage') == {kind: sorted(names) for kind, names in coverage.items()},
            'claimed coverage differs from actual admitted return ledger')
    attempt_fields = ({'state': 'native_state_entries', 'encoding': 'native_instruction_entries'}
        if owner == 'state' else {'state': 'native_state_entries',
        'encoding': 'native_byte_command_entries', 'instructions': 'native_instruction_control_entries'})
    for kind, field in attempt_fields.items():
        attempts = positive_counts(report.get(field), requirements[kind])
        require(all(attempts[name] >= count for name, count in totals[kind].items()),
                'normal returns exceed retained call attempts')
    return {'semantics': semantics, 'returns': returns,
            'coverage_union': {kind: sorted(names) for kind, names in coverage.items()},
            'each_group_claimed_to_cover_every_operation': False}


def literal_script(module, method=None, name=None):
    path = ROOT / (module.replace('.', '/') + '.py')
    tree = ast.parse(path.read_bytes())
    if method is not None:
        candidates = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == method]
        require(len(candidates) == 1, 'installed control method is ambiguous')
        tree = candidates[0]
        name = 'child'
    values = [node.value.value for node in ast.walk(tree)
              if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
              and isinstance(node.value, ast.Constant) and type(node.value.value) is str]
    require(len(values) == 1, 'installed control source literal differs')
    return values[0].encode()


def installed_package(case, context, resources, script_name, script_raw, labels, script_arguments):
    case = Path(case).resolve(strict=True)
    script = case / script_name
    require(script.read_bytes() == script_raw, 'retained installed child differs from its current test source')
    processes = json_file(case / 'processes.json')
    require(type(processes) is list and len(processes) == 3, 'complete wheel process denominator differs')
    wheels = sorted((case / 'wheels').glob('*.whl'))
    require(len(wheels) == 1, 'exactly one actual retained wheel required')
    wheel = wheels[0].resolve(strict=True)
    site = (case / 'installed').resolve(strict=True)
    expected_tail = [
        ['-B', '-m', 'pip', 'wheel', '--no-cache-dir', '--no-deps', '--no-index',
         '--no-build-isolation', '--wheel-dir', str(case / 'wheels'), str(case / 'source')],
        ['-B', '-m', 'pip', 'install', '--no-cache-dir', '--no-deps', '--no-index',
         '--target', str(site), str(wheel)],
        ['-I', '-S', '-B', str(script), str(site), *map(str, script_arguments)],
    ]
    files = [file_record(script), file_record(wheel), file_record(case / 'processes.json')]
    for row, label, arguments in zip(processes, labels, expected_tail):
        argv = row.get('argv')
        require(type(argv) is list and len(argv) == len(arguments) + 1
                and argv[1:] == arguments and row.get('returncode') == 0
                and type(row.get('returncode')) is int, 'installed process argv/status differs')
        for stream in ('stdout', 'stderr'):
            pin = file_record(case / (label + '.' + stream))
            require(row.get(stream + '_sha256') == pin['sha256'], 'installed original process log differs')
            files.append(pin)
        per_process = case / (label + '.process.json')
        if per_process.exists():
            require(json_file(per_process) == row, 'installed per-process record differs')
            files.append(file_record(per_process))
    py = {name: digest for name, digest in context['source_manifest'].items()
          if name.startswith('hepta/') and name.endswith('.py') and '_data' not in Path(name).parts}
    actual_py = {path.relative_to(site).as_posix() for path in (site / 'hepta').rglob('*.py')
                 if '_data' not in path.relative_to(site).parts}
    require(py and actual_py == set(py), 'actual installed Python package inventory differs')
    required = {**py, **{'hepta/_data/' + name: context['source_manifest'][name] for name in resources}}
    installed_files = []
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'wheel contains duplicate member paths')
        for name, digest in sorted(required.items()):
            path = child_path(site, name)
            pin = file_record(path)
            require(pin['sha256'] == digest and sha256(archive.read(name)).hexdigest() == digest,
                    'wheel/installed source bytes differ: ' + name)
            installed_files.append(pin)
    return {'files': files, 'installed_source_files': installed_files,
            'processes': processes, 'wheel': file_record(wheel)}


def comparisons(path, *, count=None, ids=None):
    rows = json_file(path)
    require(type(rows) is list and rows
            and len({row.get('id') for row in rows}) == len(rows)
            and all(row.get('expected') == row.get('actual') for row in rows),
            'actual retained comparison outcomes differ')
    if count is not None:
        require(len(rows) == count, 'retained comparison denominator differs')
    if ids is not None:
        require([row.get('id') for row in rows] == ids, 'retained comparison IDs differ')
    return file_record(path)


def inspect_code_observations(owner, evidence, context, bindings):
    fixture = Path(evidence) / 'component-fixture'
    from tests.test_hia_machine_encoding_native import cases
    ids = [row['id'] for row in cases()]
    require(len(ids) == 159 and len(set(ids)) == 159, 'original 159 instruction cases differ')
    files = [comparisons(fixture / 'original-instruction-observations.json', count=159, ids=ids)]
    if owner == 'state':
        files.append(comparisons(fixture / 'mutable-observations.json', count=14))
        meta = json_file(fixture / 'metaclass-observations.json')
        require(meta.get('expected') == meta.get('actual') and set(meta) == {'expected', 'actual'},
                'foreign metaclass outcomes differ')
        files.append(file_record(fixture / 'metaclass-observations.json'))
        method = 'test_actual_installed_wheel_uses_HIA_state_without_authoring_or_old_state'
        status = 'INSTALLED_NATIVE_MACHINE_STATE_PASS'
        flags = ('authoring_forbidden', 'retained_state_forbidden')
    else:
        files.append(comparisons(fixture / 'foreign-instruction-observations.json', count=15))
        files.append(comparisons(fixture / 'operand-boundary-observations.json'))
        method = 'test_actual_installed_wheel_uses_three_HIA_owners_without_authoring'
        status = 'INSTALLED_NATIVE_MACHINE_INSTRUCTIONS_PASS'
        flags = ('authoring_forbidden', 'retained_owners_forbidden')
    kinds = OWNERS[owner]['kinds']
    component = bindings['component']['owners']
    order = ('encoding', 'state') if owner == 'state' else ('encoding', 'state', 'instructions')
    arguments = [component[kind]['files'][0]['path'] for kind in order]
    package = installed_package(fixture / 'installed-control', context,
        ['examples/hia_bootstrap/' + SINGLE[kind][0] + '.hiaasm' for kind in kinds],
        'installed-control.py', literal_script(OWNERS[owner]['module'], method=method),
        ('wheel-build', 'wheel-install', 'installed-execution'), arguments)
    actual = json_file(fixture / 'installed-control' / 'installed-execution.stdout')
    require(actual == json_file(fixture / 'installed-control-report.json')
            and actual.get('status') == status and actual.get('isolated_without_site') is True
            and actual.get('empty_PATH') is True and all(actual.get(key) is True for key in flags),
            'installed owner observation differs')
    expected_resource = (fixture / 'installed-control' / 'installed' / 'hepta/_data/examples/hia_bootstrap'
                         / (SINGLE[owner][0] + '.hiaasm')).resolve(strict=True)
    require(Path(actual.get('source', '')).resolve(strict=True) == expected_resource
            and actual.get('image_sha256') == component[owner]['manifest']['image_sha256'],
            'installed selected source/image identity differs')
    states = code_operations(owner)['state']
    positive_counts(actual.get('native_calls' if owner == 'state' else 'native_state'), states)
    if owner == 'instructions':
        counters = positive_counts(actual.get('native_instructions'))
        require({'jmp', 'mov_imm', 'ret'} <= set(counters), 'installed instructions were not observed')
    window_path = fixture / 'source-admission-window.json'
    windows = json_file(window_path)
    window_kinds = ('encoding', 'state') if owner == 'state' else ('encoding', 'state', 'instructions')
    require(type(windows) is list and len(windows) == len(window_kinds),
            'complete post-selection source admission window observations missing')
    for row, kind in zip(windows, window_kinds):
        source = 'examples/hia_bootstrap/' + SINGLE[kind][0] + '.hiaasm'
        require(row.get('owner') == 'hepta.hia_' + SINGLE[kind][0] + '_native'
                and row.get('admitted_source_sha256') == context['source_manifest'][source]
                and row.get('changed_source_sha256') == sha256((ROOT / source).read_bytes() + b'\n').hexdigest()
                and row.get('ordinary_emit_entries') == 1 and row.get('emitter_entries') == 0
                and type(row.get('refusal')) is str and 'source identity mismatch' in row['refusal'],
                'post-selection source drift reached an unadmitted emission')
    files.extend((file_record(window_path), file_record(fixture / 'installed-control-report.json')))
    return {'files': files, 'installed': package,
            'actual_64MiB_and_protocol_assertions_bound_to_complete_method_ids': True,
            'standalone_boundary_receipt_invented': False}


def inspect_code_callers(owner, evidence, context, expected):
    evidence = Path(evidence).resolve(strict=True)
    report = json_file(evidence / 'report.json')
    require(report.get('schema') == OWNERS[owner]['caller_schema'] and report.get('status') == 'PASS'
            and report.get('scope') == 'MATCHING_SOURCE_COLD_SELECTED_CALLERS',
            'selected Code caller status/scope differs')
    validate_groups(report.get('groups'), expected)
    require(report.get('retained_owner_entries') == []
            and report.get('source_before') == context['source_manifest'] == report.get('source_after')
            and report.get('source_stable') is True and report.get('manifest_images_bundle_stable') is True,
            'selected Code source/bundle/old-owner boundary differs')
    require(report.get('component_denominator') == 12
            and report.get('guarded_original_caller_denominator') == 51
            and report.get('all_original_methods_unchanged') is True,
            'selected Code complete denominator claim differs')
    cold = {key: context[key] for key in ('source_manifest', 'cold_sha256', 'compiler_sha256')}
    cold['files'] = context['identities']
    require(report.get('cold_input_binding_before') == cold == report.get('cold_input_binding_after')
            and report.get('cold_input_binding_stable') is True, 'selected Code cold bytes changed')
    builds = code_group_builds(owner, evidence, context)
    counters = validate_code_returns(owner, report, builds)
    caller = builds['original-callers']['owners']
    bundle = json_file(evidence / 'bundle.json')
    require(bundle == {kind + '_manifest': caller[kind]['files'][0]['path'] for kind in OWNERS[owner]['kinds']},
            'actual caller selection bundle differs')
    inputs = []
    for kind in OWNERS[owner]['kinds']:
        inputs.extend(caller[kind]['files'][:2])
        require(report.get(kind + '_manifest') == caller[kind]['files'][0]['path']
                and report.get(kind + '_image_sha256') == caller[kind]['manifest']['image_sha256'],
                'caller mapped owner differs')
    inputs.append(file_record(evidence / 'bundle.json'))
    require(report.get('input_bindings') == inputs, 'original caller input bytes differ')
    runtime = inspect_code_observations(owner, evidence, context, builds)
    logs = [file_record(evidence / (row['label'] + '.unittest.log')) for row in expected]
    return {'owner': owner, 'gates': {name: True for name in OWNERS[owner]['gates']},
            'producer_report': file_record(evidence / 'report.json'), 'groups': expected,
            'actual_builds': builds, 'native_observations': counters,
            'component_runtime': runtime, 'unittest_logs': logs}


def core_build(folder, context):
    from hepta.hia_core_lowering_selection import ABI_SOURCE, checked_abi
    folder = Path(folder).resolve(strict=True)
    abi_raw = (ROOT / ABI_SOURCE).read_bytes()
    source_record(ABI_SOURCE, context)
    abi = checked_abi(abi_raw)
    names = ('core_lowering_pool', *abi['units'])
    require(len(names) == 39 and len(set(names)) == 39, 'complete Core 39-unit denominator differs')
    bundle = json_file(folder / 'manifest.json')
    expected_paths = {name: name + '/manifest.json' for name in names}
    require(set(bundle) == {'schema', 'abi_sha256', 'compiler_sha256', 'unit_manifests'}
            and bundle['schema'] == 'hepta.hia.core-lowering-native.v2'
            and bundle['abi_sha256'] == sha256(abi_raw).hexdigest()
            and bundle['compiler_sha256'] == context['compiler_sha256']
            and bundle['unit_manifests'] == expected_paths, 'complete Core bundle identity differs')
    build = json_file(folder / 'build.json')
    require(build.get('schema') == 'hepta.hia.core-lowering-build.v2'
            and build.get('status') == 'NATIVE_CANDIDATE_BUILT'
            and build.get('source_manifest') == context['source_manifest']
            and build.get('cold_report_sha256') == context['cold_sha256']
            and build.get('compiler_sha256') == context['compiler_sha256']
            and build.get('bundle') == bundle and build.get('abi_sha256') == bundle['abi_sha256']
            and build.get('production_activated') is False
            and build.get('complete_Function_methods') == 22
            and build.get('complete_Emitter_methods') == 6
            and build.get('complete_shared_helpers') == 5
            and build.get('hosted_object_primitive_kinds') == 19
            and build.get('ordinary_entry_requires_explicit_selector') is True
            and build.get('Emitter_control_owned_by_HIA') is True
            and build.get('native_object_runtime_and_byte_wrapper_policy_still_hosted') is True
            and build.get('native_persistence_or_linking_claimed') is False
            and build.get('whole_stack_rewritten_in_hia') is False
            and build.get('expected_unit_count') == 39 == build.get('actual_unit_count'),
            'actual complete Core current-cold build differs')
    receipts = build.get('units')
    require(type(receipts) is list and [row.get('name') for row in receipts] == list(names),
            'Core actual compile unit order differs')
    units = {}
    for name, row in zip(names, receipts):
        source = 'examples/hia_bootstrap/' + name + '.hiaasm'
        path = child_path(folder, expected_paths[name])
        manifest, image = previous.manifest_image(
            path, 'hepta.hia.core-lowering-unit-native.v2', source, context)
        require(set(manifest) == {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
                and Path(manifest['image_path']).name == manifest['image_path']
                and image.parent == path.parent and row.get('source') == source
                and row.get('manifest') == manifest, 'Core unit retained manifest differs')
        previous.compile_receipt(row.get('native_compile_receipt'), manifest, image, context)
        units[name] = {'manifest': manifest, 'files': [file_record(path), file_record(image)]}
    # The producer's bundle_files walks the actual serialized mapping order.
    input_files = [file_record(folder / 'manifest.json')]
    for name in bundle['unit_manifests']:
        input_files.extend(units[name]['files'])
    return {'bundle': bundle, 'units': units, 'unit_order': list(names),
            'bundle_files': input_files, 'build_file': file_record(folder / 'build.json'),
            'abi_file': source_record(ABI_SOURCE, context)}


def inspect_core_observations(evidence, context, component):
    fixture = Path(evidence) / 'component-fixture'
    case = fixture / 'installed-control'
    expected = json_file(case / 'expected.json')
    from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
    resources = tuple('docs/' + name for name in DISCOVERY_FILES) + tuple(NATIVE_SOURCE_FILES) + tuple(PUBLICATION_BUILD_FILES)
    py = {name: digest for name, digest in context['source_manifest'].items()
          if name.startswith('hepta/') and name.endswith('.py') and '_data' not in Path(name).parts}
    require(expected.get('python') == py
            and expected.get('resources') == {name: context['source_manifest'][name] for name in resources}
            and type(expected.get('document')) is dict, 'installed Core input inventory differs')
    package = installed_package(case, context, resources, 'installed-child.py',
        literal_script(OWNERS['core']['module'], name='INSTALLED_CHILD'),
        ('wheel-build', 'wheel-install', 'installed-execution'),
        [component['bundle_files'][0]['path'], case / 'expected.json'])
    observed = json_file(case / 'report.json')
    require(observed == json_file(case / 'installed-execution.stdout')
            and observed.get('status') == 'INSTALLED_CORE_LOWERING_PASS'
            and observed.get('units') == 39 and type(observed.get('units')) is int,
            'installed complete Core report differs')
    for flag in ('retained_lowering_forbidden', 'authoring_forbidden', 'isolated_without_site', 'empty_PATH'):
        require(observed.get(flag) is True, 'installed Core boundary missing: ' + flag)
    names = component['unit_order']
    require(observed.get('source_sha256') == {
                name: component['units'][name]['manifest']['source_sha256'] for name in names}
            and observed.get('abi_sha256') == component['bundle']['abi_sha256']
            and observed.get('image_sha256') == [
                component['units'][name]['manifest']['image_sha256'] for name in names],
            'installed Core actual images/ABI/sources differ')
    require(observed.get('python_files') == len(py) and observed.get('resource_files') == len(set(resources))
            and type(observed.get('actual_native_steps')) is int and observed['actual_native_steps'] > 0
            and type(observed.get('object_sha256')) is str and len(observed['object_sha256']) == 64,
            'installed Core execution/counts missing')
    return {'installed': package, 'files': [file_record(case / 'expected.json'), file_record(case / 'report.json')],
            'source_ABI_refusal_assertions_bound_to_complete_installed_method': True,
            'standalone_refusal_ledger_invented': False}


ELF_BOUNDARIES = (
    ('object-exact-64mib', 67108208, 1, 0, 16, None),
    ('object-over-64mib', 67108209, 1, 0, 16, 'ELF object exceeds byte budget'),
    ('code-exact-64mib', 67108864, 1, 0, 16, 'ELF object exceeds byte budget'),
    ('code-over-64mib', 67108865, 1, 0, 16, 'nonempty bounded immutable machine bytes required'),
    ('symbol-table-exact-65536', 65534, 65534, 0, 16, None),
    ('symbol-table-over-65536', 65535, 65535, 0, 16, 'ELF symbol inventory exceeds limit'),
    ('import-table-exact-65536', 65538, 65533, 1, 16, None),
    ('import-table-over-65536', 65539, 65534, 1, 16, 'ELF symbol inventory exceeds limit'),
    ('names-192-alignment-16', 11, 1, 2, 16, None),
    ('names-192-alignment-32', 11, 1, 2, 32, None),
    ('names-192-alignment-64', 11, 1, 2, 64, None),
)


def compare_gzip_pair(folder, row):
    """Read both full decoded ELF objects, bounded one-MiB blocks at a time."""
    paths, before = [], []
    for key in ('original', 'native'):
        observation = row[key]
        name = row['case'] + '-' + key + '.elf.gz'
        require(observation.get('archive') == name and observation.get('kind') == 'bytes',
                'boundary archive name/kind differs')
        path = child_path(Path(folder), name)
        pin = file_record(path)
        require(pin['sha256'] == observation.get('archive_sha256'), 'boundary archive original bytes differ')
        paths.append(path)
        before.append(pin)
    count, digest = 0, sha256()
    with gzip.open(paths[0], 'rb') as left, gzip.open(paths[1], 'rb') as right:
        while True:
            a, b = left.read(1 << 20), right.read(1 << 20)
            require(a == b, 'complete original/native boundary bytes differ')
            if not a:
                break
            count += len(a)
            require(count <= 67108864, 'decoded ELF exceeds unchanged object cap')
            digest.update(a)
    actual_sha = digest.hexdigest()
    for key in ('original', 'native'):
        require(row[key].get('bytes') == count and row[key].get('sha256') == actual_sha
                and count > 0, 'decoded boundary length/hash differs')
    if row['case'] == 'object-exact-64mib':
        require(count == 67108864, 'actual exact-64-MiB object is missing')
    require([file_record(p) for p in paths] == before, 'boundary archives changed during independent replay')
    return {'files': before, 'decoded_bytes_each': count, 'decoded_sha256': actual_sha,
            'independently_read_both_complete_decoded_objects': True}


def inspect_elf_boundaries(folder):
    folder = Path(folder)
    results = []
    for name, size, symbols, relocations, alignment, error in ELF_BOUNDARIES:
        path = folder / (name + '.json')
        row = json_file(path)
        require([row.get(k) for k in ('case', 'code_bytes', 'symbols', 'relocations', 'alignment')]
                == [name, size, symbols, relocations, alignment]
                and row.get('equal') is True, 'complete ELF boundary case/extent differs')
        positive_counts(row.get('native_operation_counts'))
        require(type(row.get('original')) is dict and type(row.get('native')) is dict,
                'ELF boundary observations missing')
        if error is not None:
            wanted = {'kind': 'exception', 'type': 'MachineObjectError', 'args': [error]}
            # The original writer's concrete exception class is admitted from the
            # unchanged public module; no invented native-only diagnostic.
            from hepta.hia_machine_elf import MachineObjectError
            wanted['type'] = MachineObjectError.__qualname__
            require(row['original'] == wanted == row['native'], 'original ELF exception type/args differ')
            replay = None
        else:
            replay = compare_gzip_pair(folder, row)
        results.append({'observation': file_record(path), 'archive_replay': replay})
    require(sum(item['archive_replay'] is not None for item in results) == 6,
            'complete twelve-archive boundary denominator differs')
    return results


def check_hex_record(value):
    require(type(value) is dict and set(value) == {'bytes', 'sha256', 'hex'},
            'complete ELF object hex record differs')
    raw = bytes.fromhex(value['hex'])
    require(type(value['bytes']) is int and value['bytes'] == len(raw)
            and sha256(raw).hexdigest() == value['sha256'], 'full ELF object bytes differ')
    return raw


def inspect_elf_observations(evidence, context, bindings):
    fixture = Path(evidence) / 'fixture'
    native_folder = fixture / 'MachineElfNativeTests'
    boundary_folder = fixture / 'MachineElfBoundaryTests'
    definitions_path = ROOT / 'tests/hia_machine_elf_cases.json'
    source_record('tests/hia_machine_elf_cases.json', context)
    definitions = json_file(definitions_path)
    observed = json_file(native_folder / 'complete-55.json')
    cases = observed.get('cases')
    require(observed.get('revision') == definitions.get('revision')
            == 'RECONSTRUCTED_NEW_55_NOT_RECOVERED_OLD_CONTROL'
            and observed.get('loaded') == 55 == observed.get('executed')
            and type(cases) is list and len(cases) == 55
            and [row.get('id') for row in cases] == [row['id'] for row in definitions['cases']]
            and len({row.get('id') for row in cases}) == 55,
            'complete reconstructed ELF 55-case denominator differs')
    positive_counts(observed.get('native_operation_counts'))
    for row, definition in zip(cases, definitions['cases']):
        require(row.get('equal') is True and row.get('original') == row.get('native')
                and type(row.get('original')) is list and row['original']
                and row['original'][0] == definition['expected_kind'], 'ELF 55-case full outcome differs')
        if row['original'][0] == 'bytes':
            check_hex_record(row['original'][1])
    returned = json_file(native_folder / 'complete-return-object.json')
    require(type(returned.get('selected')) is dict and returned['selected']
            and returned['selected'] == returned.get('same_identity_oracle') == returned.get('frozen')
            and returned.get('original', {}).get('object_bytes') == returned['selected'].get('object_bytes'),
            'ELF complete dataclass/identity oracle differs')
    check_hex_record(returned['selected']['object_bytes'])
    require(returned['original'].get('implementation_sha256') != returned['selected'].get('implementation_sha256'),
            'selected and unselected implementation identities unexpectedly agree')
    binding = bindings['MachineElfNativeTests']
    case = native_folder / 'installed-wheel'
    manifest = binding['files'][0]['path']
    package = installed_package(case, context, ['examples/hia_bootstrap/machine_elf.hiaasm'],
        'installed.py', literal_script(OWNERS['elf']['module'], name='INSTALLED_CONTROL'),
        ('build', 'install', 'execution'), [manifest, case / 'inputs.json'])
    installed = json_file(case / 'execution.stdout')
    require(installed.get('status') == 'INSTALLED_NATIVE_ELF_PASS'
            and installed.get('full_return_object_equal') is True
            and installed.get('isolated_without_site') is True and installed.get('empty_PATH') is True
            and installed.get('actual') == json_file(case / 'inputs.json').get('expected'),
            'installed ELF full return object differs')
    require(installed.get('source_sha256') == binding['manifest']['source_sha256']
            and installed.get('image_sha256') == binding['manifest']['image_sha256'],
            'installed ELF actual source/image differs')
    positive_counts(installed.get('native_operation_counts'))
    boundaries = inspect_elf_boundaries(boundary_folder)
    return {'files': [file_record(native_folder / 'complete-55.json'),
                      file_record(native_folder / 'complete-return-object.json'),
                      file_record(case / 'inputs.json')],
            'installed': package, 'boundary_cases': boundaries,
            'complete_boundary_cases': 11, 'complete_decoded_archive_count': 12,
            'lifecycle_and_source_refusals_bound_to_complete_20_method_ids': True,
            'standalone_permission_or_refusal_ledger_invented': False}


def elf_component_builds(evidence, context):
    return {name: single_build('elf', Path(evidence) / 'fixture' / name / 'qualified', context)
            for name in ('MachineElfNativeTests', 'MachineElfBoundaryTests')}


def validate_elf_component(report, expected, bindings, runtime, context):
    require(report.get('schema') == 'hepta.hia.compiler-owner-component.v1'
            and report.get('owner') == 'elf' and report.get('status') == 'PASS'
            and report.get('scope') == 'MATCHING_SOURCE_COLD_COMPONENT', 'ELF component status/scope differs')
    previous.complete_ids(report, expected['ids'], 20)
    require(report.get('modules') == expected['modules'] and report.get('loader_errors') == []
            and report.get('unittest_successful') is True, 'ELF complete module execution differs')
    require(report.get('source_before') == context['source_manifest'] == report.get('source_after')
            and report.get('source_preserved') is True and report.get('cold_inputs_preserved') is True
            and report.get('cold_inputs') == context['identities'], 'ELF component source/cold bytes differ')
    require(report.get('build_bindings_before') == bindings == report.get('build_bindings_after')
            and report.get('builds_preserved') is True, 'ELF class-specific cold builds changed')
    require(type(runtime) is dict and runtime and report.get('runtime_observations') == runtime,
            'ELF component original runtime readback differs')


def inspect_elf_component(evidence, context, expected):
    evidence = Path(evidence).resolve(strict=True)
    report = json_file(evidence / 'report.json')
    bindings = elf_component_builds(evidence, context)
    runtime = inspect_elf_observations(evidence, context, bindings)
    validate_elf_component(report, expected[0], bindings, runtime, context)
    return {'owner': 'elf', 'gates': {OWNERS['elf']['gates'][0]: True},
            'producer_report': file_record(evidence / 'report.json'), 'groups': [expected[0]],
            'actual_builds': bindings, 'component_runtime': runtime,
            'unittest_logs': [file_record(evidence / 'unittest.log')]}


def elf_file_observation(path):
    pin = file_record(path)
    st = Path(pin['path']).stat()
    pin['identity'] = [st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns]
    return pin


def inspect_elf_callers(evidence, context, expected):
    evidence = Path(evidence).resolve(strict=True)
    report = json_file(evidence / 'report.json')
    from tools.qualify_hia_machine_elf import MODULE_SOURCE_PINS
    require(report.get('schema') == OWNERS['elf']['caller_schema']
            and report.get('status') == 'SELECTED_NATIVE_ELF_CALLERS_PASS'
            and report.get('scope') == 'MATCHING_SOURCE_COLD_BUILD', 'ELF caller status/scope differs')
    wanted = expected[1]
    require(report.get('modules') == wanted['modules'] and report.get('expected_test_ids') == wanted['ids']
            == report.get('loaded_test_ids') == report.get('executed_test_ids')
            and report.get('tests_loaded') == 51 == report.get('tests_run') == report.get('expected_count')
            and report.get('loader_errors') == [], 'ELF original 51 caller denominator differs')
    require(report.get('anomaly_counts') == {key: 0 for key in (
                'errors', 'failures', 'skips', 'expected_failures', 'unexpected_successes')}
            and report.get('failures') == [] and report.get('errors') == []
            and report.get('retained_writer_calls') == [], 'ELF caller anomalies/retained writer entered')
    require(report.get('actual_module_sources') == MODULE_SOURCE_PINS == report.get('expected_module_sources')
            and all(context['source_manifest'].get(name) == digest for name, digest in MODULE_SOURCE_PINS.items()),
            'ELF original caller source bytes differ')
    require(report.get('source_before') == context['source_manifest'] == report.get('source_after')
            and report.get('source_stable') is True
            and report.get('cold_report_sha256') == context['cold_sha256'], 'ELF caller source/cold changed')
    binding = single_build('elf', evidence / 'qualified', context)
    actual = {'manifest': elf_file_observation(binding['files'][0]['path']),
              'image': elf_file_observation(binding['files'][1]['path'])}
    require(report.get('bundle_before') == actual == report.get('bundle_after')
            and report.get('bundle_stable') is True
            and report.get('manifest_sha256') == binding['files'][0]['sha256']
            and report.get('image_sha256') == binding['manifest']['image_sha256'],
            'ELF caller actual mapped image/manifest differs')
    positive_counts(report.get('native_operation_counts'))
    require(report.get('whole_writer_qualified') is False
            and report.get('whole_native_delivery_qualified') is False
            and report.get('foreign_timsort_schedule_closed') is False, 'ELF retained scope boundary differs')
    return {'owner': 'elf', 'gates': {OWNERS['elf']['gates'][1]: True},
            'producer_report': file_record(evidence / 'report.json'), 'groups': [wanted],
            'actual_builds': binding, 'native_operation_counts': report['native_operation_counts']}


def require_successor_gates(gates):
    """Exactly preserve the old 21-key map, then conjoin all nine new gates."""
    require(type(gates) is dict and set(gates) == set(SUCCESSOR_GATES),
            'exact complete 30-key successor gate map required')
    previous.require_successor_gates({key: gates[key] for key in previous.SUCCESSOR_GATES})
    require(all(gates[key] is True for key in COMPILER_GATES), 'all nine new compiler-owner gates must pass')
    return True


CORE_STEP_SEMANTICS = 'Actual admitted HIA unit entry and output framing returned status0/1/2/3; status3 is HIA yield, not method or product success.'
CORE_STEP_INDEX_BASIS = 'owner.images excludes literal pool; unit_index0 is core_lowering_000; bundle_image_index is unit_index+1; complete bundle index0 is core_lowering_pool.'


def validate_core_steps(report, builds, abi):
    roles = {'component': 'component', 'original-machine': 'caller', 'original-core': 'caller'}
    generators = ['_native_generator_0', '_native_generator_1']
    require(abi.get('units') == ['core_lowering_' + format(i, '03d') for i in range(38)]
            and len(abi['modes']) == 36 and abi.get('generator_modes') == generators
            and abi['modes']['_native_globals']['number'] == 28
            and [abi['modes'][name]['number'] for name in generators] == [35, 36],
            'complete Core v2 ABI unit/private/generator inventory differs')
    require(set(builds) == {'caller', 'component'}, 'both complete Core builds required')
    require(report.get('native_step_ledger_schema') == 'hepta.hia.core-lowering-native-step-returns.v2'
            and report.get('native_step_return_semantics') == CORE_STEP_SEMANTICS
            and report.get('native_step_unit_index_basis') == CORE_STEP_INDEX_BASIS
            and report.get('native_mode_entries_are_attempts') is True
            and report.get('group_bundle_roles') == roles, 'Core actual-step meaning/index roles differ')
    observations = report.get('bundle_observations')
    require(type(observations) is dict and set(observations) == {'caller', 'component'},
            'both actual Core bundle observations required')
    for role, binding in builds.items():
        observation = observations[role]
        files = [*binding['bundle_files'], binding['build_file']]
        names = binding['unit_order']
        require(names == ['core_lowering_pool', *abi['units']]
                and set(binding['units']) == set(names)
                and observation.get('scope') == 'MATCHING_SOURCE_COLD_BUILD'
                and observation.get('manifest') == files[0]['path']
                and observation.get('manifest_sha256') == files[0]['sha256']
                and observation.get('bundle_sha256') == files[0]['sha256']
                and observation.get('abi_sha256') == binding['bundle']['abi_sha256']
                and observation.get('unit_names') == names
                and observation.get('unit_image_sha256') == [
                    binding['units'][name]['manifest']['image_sha256'] for name in names]
                and observation.get('source_sha256') == {
                    name: binding['units'][name]['manifest']['source_sha256'] for name in names}
                and observation.get('input_bindings_before') == files == observation.get('input_bindings_after')
                and observation.get('stable') is True and report.get(role + '_bundle_stable') is True,
                'Core observed bundle differs from its actual cold build: ' + role)
    attempts = positive_counts(report.get('native_mode_entries'))
    require(set(attempts) <= set(abi['modes']), 'Core attempted unknown mode')
    group_attempts, aggregate_attempts = {}, {}
    rows = report.get('group_native_mode_attempts')
    require(type(rows) is list and rows, 'Core grouped original attempts missing')
    for row in rows:
        require(type(row) is dict and set(row) == {'group', 'mode', 'count'}
                and row['group'] in roles and row['mode'] in abi['modes']
                and type(row['count']) is int and row['count'] > 0,
                'Core grouped attempt record differs')
        key = (row['group'], row['mode'])
        require(key not in group_attempts, 'duplicate Core group/mode attempt row')
        group_attempts[key] = row['count']
        aggregate_attempts[row['mode']] = aggregate_attempts.get(row['mode'], 0) + row['count']
    require(attempts == aggregate_attempts, 'Core total/group attempt ledger differs')
    normal = report.get('native_mode_normal_returns')
    require(type(normal) is list, 'Core original normal-return ledger absent')
    seen_normal = set()
    for row in normal:
        require(type(row) is dict and set(row) == {'group', 'mode', 'count'}
                and type(row['count']) is int and row['count'] > 0,
                'Core normal method return row differs')
        key = (row['group'], row['mode'])
        require(key not in seen_normal and row['count'] <= group_attempts.get(key, 0),
                'Core method normal returns exceed attempts or repeat')
        seen_normal.add(key)
    steps = report.get('native_step_returns')
    require(type(steps) is list and steps, 'actual admitted Core step returns are missing')
    fields = {'group', 'mode', 'mode_number', 'unit_index', 'bundle_image_index', 'unit_name',
              'image_sha256', 'abi_sha256', 'bundle_sha256', 'status', 'count'}
    seen, groups, modes, status_totals = set(), set(), set(), {}
    for row in steps:
        require(type(row) is dict and set(row) == fields and row['group'] in roles
                and row['mode'] in abi['modes'] and type(row['count']) is int and row['count'] > 0
                and type(row['status']) is int and row['status'] in (0, 1, 2, 3),
                'Core step row or actual frame-return status differs')
        index = row['unit_index']
        require(type(index) is int and 0 <= index < len(abi['units'])
                and type(row['bundle_image_index']) is int and row['bundle_image_index'] == index + 1
                and row['unit_name'] == abi['units'][index]
                and type(row['mode_number']) is int
                and row['mode_number'] == abi['modes'][row['mode']]['number'],
                'Core actual mode/unit index differs')
        binding = builds[roles[row['group']]]
        unit = binding['units'][row['unit_name']]
        require(row['image_sha256'] == unit['manifest']['image_sha256']
                and row['abi_sha256'] == binding['bundle']['abi_sha256']
                and row['bundle_sha256'] == binding['bundle_files'][0]['sha256'],
                'Core step returned from another group/unit image')
        key = tuple(row[name] for name in sorted(fields - {'count'}))
        require(key not in seen, 'duplicate Core step accounting row')
        seen.add(key)
        groups.add(row['group'])
        modes.add(row['mode'])
        status_totals[str(row['status'])] = status_totals.get(str(row['status']), 0) + row['count']
    require(report.get('public_control_mode_count') == 33
            and report.get('abi_control_mode_count') == 36
            and report.get('private_fixture_modes') == ['_native_globals']
            and report.get('private_generator_modes') == generators
            and report.get('private_fixture_mode_has_actual_step_returns') is True
            and any(row['group'] == 'component' and row['mode'] == '_native_globals'
                    and row['mode_number'] == 28 for row in steps),
            'Core component private ABI fixture lacks a real returned step')
    required_modes = set(abi['modes']) - {'_native_globals', *generators}
    require(len(required_modes) == 33 and required_modes <= set(attempts)
            and required_modes <= modes and groups == set(roles),
            'complete original mode union or actual group steps missing')
    # Generator sessions enter directly, without an ordinary invoke() attempt.
    # Only actual component image returns can establish the two lazy HIA yields.
    component_yields = {row['mode'] for row in steps
                        if row['group'] == 'component' and row['status'] == 3}
    require(set(generators) <= component_yields,
            'both Core generator modes require actual component HIA yield returns')
    for flag in ('all_required_modes_attempted', 'all_required_modes_have_actual_step_returns',
                 'all_generator_modes_have_actual_step_returns',
                 'all_generator_modes_have_actual_yield_returns', 'all_native_step_statuses_observed'):
        require(report.get(flag) is True, 'Core actual coverage flag missing: ' + flag)
    positive_counts(status_totals, ('0', '1', '2', '3'))
    require(report.get('actual_native_step_statuses') == status_totals,
            'Core global step counts differ from actual group/unit ledger')
    return {'step_ledger': steps, 'actual_status_totals': status_totals,
            'required_mode_union': sorted(required_modes), 'group_bundle_roles': roles,
            'attempts': rows, 'normal_method_returns': normal,
            'generator_modes_with_component_yield_returns': sorted(set(generators) & component_yields),
            'generator_invoke_attempts_required': False,
            'yield_status_is_method_or_product_success': False,
            'reject_mode_required_to_return_a_method_value': False,
            'each_group_claimed_to_cover_every_mode': False}


def inspect_core_callers(evidence, context, expected):
    from hepta.hia_core_lowering_selection import ABI_SOURCE, checked_abi
    from tools.qualify_hia_core_lowering_callers import COMPONENT_IDS, ORIGINAL_COMPONENT_IDS
    evidence = Path(evidence).resolve(strict=True)
    report = json_file(evidence / 'report.json')
    require(report.get('schema') == OWNERS['core']['caller_schema']
            and report.get('status') == 'PASS'
            and report.get('scope') == 'MATCHING_SOURCE_COLD_SELECTED_CALLERS',
            'Core complete qualifier status/scope differs')
    require(report.get('complete_three_groups_executed') is True
            and report.get('complete_three_groups_required_for_qualification') is True
            and report.get('development_group') is None
            and report.get('expected_groups') == ['component', 'original-core', 'original-machine'],
            'Core development-only group cannot qualify the complete cold gate')
    validate_groups(report.get('groups'), expected)
    for row, wanted in zip(report['groups'][1:], expected[1:]):
        require(row.get('frozen_original_ids') == wanted['ids'], 'Core original frozen caller IDs differ')
    require(report.get('component_denominator') == 15
            and report.get('original_component_denominator') == 12
            and report.get('original_component_ids') == ORIGINAL_COMPONENT_IDS
            and report.get('added_Emitter_component_ids') == [
                name for name in COMPONENT_IDS if name not in ORIGINAL_COMPONENT_IDS]
            and len(ORIGINAL_COMPONENT_IDS) == 12 and len(COMPONENT_IDS) == 15
            and set(ORIGINAL_COMPONENT_IDS) <= set(COMPONENT_IDS)
            and expected[0]['ids'] == COMPONENT_IDS
            and report.get('original_machine_denominator') == 51
            and report.get('original_core_denominator') == 50
            and report.get('original_methods_modified') is False
            and report.get('hosted_primitive_kinds') == 19
            and report.get('Emitter_control_still_hosted') is False
            and report.get('generator_object_suspension_transport_still_hosted') is True
            and report.get('native_byte_ABI_wrapper_policy_still_hosted') is True
            and report.get('default_activated') is False and report.get('whole_native_claimed') is False,
            'Core denominator or declared hosted boundary differs')
    require(report.get('retained_owner_entries') == []
            and report.get('source_before') == context['source_manifest'] == report.get('source_after')
            and report.get('source_stable') is True and report.get('manifest_images_bundle_stable') is True,
            'Core retained owner or current source/bundle drift observed')
    builds = {'caller': core_build(evidence / 'build', context),
              'component': core_build(evidence / 'component-fixture' / 'qualified', context)}
    caller = builds['caller']
    require(report.get('manifest') == caller['bundle_files'][0]['path']
            and report.get('manifest_sha256') == caller['bundle_files'][0]['sha256']
            and report.get('abi_sha256') == caller['bundle']['abi_sha256']
            and report.get('complete_image_sha256') == [
                caller['units'][name]['manifest']['image_sha256'] for name in caller['unit_order']]
            and report.get('input_bindings') == [*caller['bundle_files'], caller['build_file']],
            'Core original caller bundle input bytes differ')
    abi = checked_abi((ROOT / ABI_SOURCE).read_bytes())
    counters = validate_core_steps(report, builds, abi)
    runtime = inspect_core_observations(evidence, context, builds['component'])
    return {'owner': 'core', 'gates': {name: True for name in OWNERS['core']['gates']},
            'producer_report': file_record(evidence / 'report.json'), 'groups': expected,
            'actual_builds': builds, 'native_observations': counters, 'component_runtime': runtime,
            'unittest_logs': [file_record(evidence / (row['label'] + '.unittest.log')) for row in expected]}


def inspect_evidence(owner, part, evidence, context, expected):
    source_now(context)
    for name in ('tools/hia_compiler_owner_gates.py', 'tools/qualify_hia_compiler_owner_ci.py',
                 'tools/hia_store_page_gates.py',
                 OWNERS[owner]['module'].replace('.', '/') + '.py',
                 OWNERS[owner]['qualifier'].replace('.', '/') + '.py'):
        source_record(name, context)
    if owner == 'elf':
        require(part in ('component', 'callers'), 'ELF gate part differs')
        result = (inspect_elf_component(evidence, context, expected) if part == 'component'
                  else inspect_elf_callers(evidence, context, expected))
    else:
        require(part == 'callers', 'complete component belongs to its unchanged caller qualifier')
        result = (inspect_core_callers(evidence, context, expected) if owner == 'core'
                  else inspect_code_callers(owner, evidence, context, expected))
    source_now(context)
    return result


def validate_gate_report(report, owner, operation, inspection, context):
    require(report.get('schema') == 'hepta.hia.compiler-owner-gate.v1'
            and report.get('owner') == owner and report.get('operation') == operation
            and report.get('status') == 'PASS'
            and report.get('scope') == 'MATCHING_SOURCE_COLD_OWNER_GATES',
            'compiler owner gate status/identity differs')
    require(report.get('source_before') == context['source_manifest'] == report.get('source_after')
            and report.get('source_preserved') is True and report.get('cold_inputs_preserved') is True
            and report.get('cold_inputs') == context['identities'], 'compiler owner gate source/cold changed')
    require(type(inspection) is dict and inspection and report.get('inspection') == inspection
            and report.get('gates') == inspection['gates']
            and all(value is True for value in inspection['gates'].values()),
            'gate report differs from actual independent artifact readback')
    require(report.get('whole_native_delivery_qualified') is False
            and report.get('development_or_prior_result_reused') is False, 'gate scope boundary differs')
    return True


def owned_product_command(owner, part, cold, evidence, process_evidence):
    """Return only one of the five fixed complete product commands."""
    require(owner in OWNERS and part in ('callers', 'component'), 'owned product kind differs')
    cold = Path(cold).resolve(strict=True)
    evidence = Path(evidence).resolve()
    process_evidence = Path(process_evidence).resolve()
    if part == 'component':
        require(owner == 'elf', 'other complete components belong to their unchanged qualifiers')
        return [sys.executable, '-B', str(ROOT / 'tools/qualify_hia_compiler_owner_ci.py'),
                'component', '--owner', 'elf', '--cold-report', str(cold),
                '--evidence-dir', str(evidence),
                '--output', str(process_evidence / 'component-child-gate.json')]
    option = '--output' if owner == 'elf' else '--evidence'
    return [sys.executable, '-B', '-m', OWNERS[owner]['qualifier'],
            '--cold-report', str(cold), option, str(evidence)]


def inspect_owned_product(owner, part, cold, evidence, process_evidence, context):
    """Independently bind the original 180/3 subreaper request, receipt and logs."""
    directory = Path(process_evidence).resolve(strict=True)
    command = owned_product_command(owner, part, cold, evidence, directory)
    paths = {name: directory / name for name in (
        'run-result.json', 'process-owner.json', 'process-owner.json.request.json',
        'stdout.log', 'stderr.log', 'process-owner.json.stdout.log', 'process-owner.json.stderr.log')}
    records = {name: file_record(path) for name, path in paths.items()}
    result = json_file(paths['run-result.json'])
    request = json_file(paths['process-owner.json.request.json'])
    receipt = json_file(paths['process-owner.json'])
    implementation = source_record('tools/hia_selfhost_process_owner.py', context)
    require(result.get('schema') == 'hepta.hia.compiler-owner-owned-command.v1'
            and result.get('status') == 'OWNED_COMMAND_RETURNED_PENDING_READBACK'
            and result.get('owner') == owner and result.get('part') == part
            and result.get('command') == command and result.get('cwd') == str(ROOT)
            and result.get('source_before') == context['source_manifest'] == result.get('source_after')
            and result.get('source_preserved') is True and result.get('cold_inputs_preserved') is True
            and result.get('cold_inputs') == context['identities'],
            'owned product source/command completion differs')
    require(request.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
            and request.get('command') == command and request.get('cwd') == str(ROOT)
            and request.get('qualification_seconds') == 180 and request.get('cleanup_seconds') == 3
            and request.get('implementation_sha256') == implementation['sha256']
            and request.get('stdout_path') == str(paths['stdout.log'])
            and request.get('stderr_path') == str(paths['stderr.log'])
            and request.get('receipt_path') == str(paths['process-owner.json']),
            'original owned product request/180/3 binding differs')
    environment = request.get('env')
    require(type(environment) is dict
            and environment.get(OWNERS[owner]['prefix'] + '_COLD_REPORT') == str(Path(cold).resolve(strict=True))
            and all(config['prefix'] + config['development_suffix'] not in environment
                    for config in OWNERS.values()),
            'owned product source-bound cold/development environment differs')
    require(receipt.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
            and receipt.get('request_sha256') == records['process-owner.json.request.json']['sha256']
            and receipt.get('implementation_sha256') == implementation['sha256']
            and receipt.get('qualification_seconds') == 180 and receipt.get('cleanup_seconds') == 3
            and receipt.get('status') == 'OWNED_PROCESS_COMPLETED'
            and receipt.get('returncode') == 0 and receipt.get('timed_out') is False
            and receipt.get('qualification_started') is True
            and receipt.get('exit_observed_before_deadline') is True
            and receipt.get('subreaper_enabled') is True
            and receipt.get('interrupted_signals') == []
            and 'owner_error' not in receipt and receipt.get('event_overflow') is False,
            'original owned product did not naturally complete within 180 seconds')
    cleanup = receipt.get('cleanup', {})
    require(cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('leader_reaped') is True and cleanup.get('observed_echild') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [],
            'original owned product cleanup is not closed')
    events = receipt.get('events')
    natural = {'qualification_started', 'owned_child_observed',
               'qualification_exit_observed', 'owned_child_reaped'}
    require(type(events) is list and events
            and all(type(row) is dict and row.get('kind') in natural for row in events)
            and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                <= {row['kind'] for row in events},
            'owned product needed a kill or has incomplete natural-exit evidence')
    returned = result.get('returned_owner')
    require(type(returned) is dict and returned.get('supervisor_returncode') == 0
            and returned.get('receipt_sha256') == records['process-owner.json']['sha256']
            and {key: value for key, value in returned.items()
                 if key not in ('supervisor_returncode', 'receipt_sha256')} == receipt,
            'original owner API return differs from its complete original receipt')
    return {'schema': 'hepta.hia.compiler-owner-owned-command-readback.v1',
            'owner': owner, 'part': part, 'command': command, 'cwd': str(ROOT),
            'qualification_seconds': 180, 'cleanup_seconds': 3,
            'natural_exit_and_echild': True, 'files': list(records.values()),
            'implementation': implementation,
            'historical_descendant_inventory_complete': receipt.get('historical_descendant_inventory_complete')}
