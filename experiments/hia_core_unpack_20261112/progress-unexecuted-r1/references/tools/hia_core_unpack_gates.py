"""Read complete matching-cold UNPACK evidence; development reports never qualify.

Both new gates are the conjunction of the same cold/B3 identity, the original
complete Core116, all eighteen additional controls, two natural 180/3 owners,
and the actual installed wheel. The old thirty gates remain a separate exact
prefix. CPython objects and the C-API transaction remain hosted dependencies.
"""
from __future__ import annotations

import ast
from collections import Counter
from hashlib import sha256
from pathlib import Path
import platform
import sys

from tools import hia_compiler_owner_gates as previous

ROOT = Path(__file__).resolve().parents[1]
require = previous.require
json_file = previous.json_file
file_record = previous.file_record
source_now = previous.source_now
cold_inputs = previous.cold_inputs
GROUPS = ('component', 'original-machine', 'original-core')
COMPOSITION_MODULE = 'tests.test_hia_core_unpack_native'
NEW_GATES = ('core_unpack_complete_composition', 'core_unpack_selected_complete_callers')
SUCCESSOR_GATES = (*previous.SUCCESSOR_GATES, *NEW_GATES)
SCOPE = 'MATCHING_SOURCE_COLD_UNPACK_CONJUNCTION'
COMPONENT_SCOPE = 'MATCHING_SOURCE_COLD_COMPOSITION_REUSING_THIS_CALLER_BUILD'
LEDGER_MEANING = 'Actual UnpackSession._step returned; neither an attempt nor whole-method success.'
OUTER_MEANING = 'Opcode14 primitive dispatch returns before outer ACK registration; not whole method success.'
COMPILE_SUFFIXES = ('.receipt.json', '.stdout.log', '.stderr.log', '.request.json', '.input.bin', '.output.bin')
ERROR_FIELDS = ('error', 'preservation_error', 'final_identity_error')
FINITE_CONTROL = 'tools/hia_core_unpack_controls/finite_controls.py'
FINITE_LAUNCHER = 'tools/hia_core_unpack_controls/finite_launcher.py'
FINITE_PINS = {FINITE_CONTROL: '7c6712585c81dc27561637e206c2c109cdb9f4cf082e3eda227ed6984e525d03',
               FINITE_LAUNCHER: '945817c984ef749bdad2167ce3fa2d8b8f4c3c318b8e999e9c4727870525635a'}
FINITE_IDS = {
    'shim': ['__main__.ShimControls.' + name for name in (
        'test_exact_assembly_literal', 'test_gil_and_error_transfer',
        'test_pending_error_cleanup_preserves_handled_context', 'test_post_entry_exception_still_adopts_owned_result')],
    'finite-native': ['__main__.NativeControls.' + name for name in (
        'test_bad_ack_closes_and_hia_releases', 'test_builtin_cardinality_and_version_messages',
        'test_duplicate_observe_and_terminal_result', 'test_foreign_failure_cleanup_and_ambient_context',
        'test_generic_next_count_and_release_order', 'test_noniterable_and_iter_errors')]}
SOURCE_FILES = (
    'tools/hia_core_unpack_gates.py', 'tools/qualify_hia_core_unpack_ci.py',
    'tools/qualify_hia_core_unpack_callers.py', 'tools/build_hia_core_unpack.py',
    'tools/hia_core_unpack_transaction.S', 'tools/hia_compiler_owner_gates.py',
    'tools/qualify_hia_core_lowering_callers.py', 'tools/hia_store_page_gates.py',
    'tools/hia_selfhost_process_owner.py', 'tools/hia_selfhost_child.py',
    'tests/test_hia_core_unpack_native.py', 'tests/test_hia_core_lowering_native.py',
    'tests/test_hia_core_unpack_gates.py', 'docs/HIA_CORE_UNPACK_QUALIFICATION_GATES.json',
    FINITE_CONTROL, FINITE_LAUNCHER)


def no_errors(value):
    require(type(value) is dict and all(value.get(name) is None for name in ERROR_FIELDS),
            'a preserved error cannot qualify')


def admit_dependencies(context):
    source_now(context)
    for name in SOURCE_FILES:
        previous.source_record(name, context)
    for name, digest in FINITE_PINS.items():
        require(context['source_manifest'][name] == digest, 'retained finite source differs before execution')
    return context


def runtime_identity():
    require(platform.python_implementation() == 'CPython' and sys.version_info[:3] == (3, 14, 4),
            'matching-cold UNPACK gates require the supported CPython 3.14.4')
    return {'implementation': 'CPython', 'version': list(sys.version_info[:3]),
            'runtime_profile': 31404, 'executable': file_record(Path(sys.executable).resolve(strict=True))}


def require_successor_gates(values):
    require(type(values) is dict and set(values) == set(SUCCESSOR_GATES)
            and len(values) == 32, 'the exact thirty old and two new mandatory gates are required')
    previous.require_successor_gates({name: values[name] for name in previous.SUCCESSOR_GATES})
    require(all(values[name] is True for name in NEW_GATES), 'both UNPACK conjunction gates must pass')
    return True


def expected_component_ids():
    """Derive ordered unittest names from the full current source, without setup."""
    tree = ast.parse((ROOT / 'tests/test_hia_core_unpack_native.py').read_bytes())
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    names = ('UnpackCompositionNativeTests', 'UnpackCompositionSourceTests')
    require(set(classes) == set(names), 'the complete composition class inventory changed')
    ids, counts = [], []
    for name in names:
        methods = sorted(node.name for node in classes[name].body
                         if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
        require(len(methods) == len(set(methods)), 'duplicate composition method')
        ids.extend(COMPOSITION_MODULE + '.' + name + '.' + method for method in methods)
        counts.append(len(methods))
    require(counts == [6, 2] and len(ids) == len(set(ids)) == 8,
            'the original six native and two source methods must remain complete')
    return ids


def caller_groups():
    value = previous.expected_groups('core')
    require([row['label'] for row in value] == list(GROUPS)
            and [len(row['ids']) for row in value] == [15, 51, 50],
            'the original full Core116 groups changed')
    ids = [name for row in value for name in row['ids']]
    require(len(ids) == len(set(ids)) == 116, 'the full Core116 IDs are not unique')
    return value


def size_pin(path):
    value = file_record(path)
    return {'path': value['path'], 'size': value['bytes'], 'sha256': value['sha256']}


def finite_command(label, base, binding):
    require(label in FINITE_IDS, 'unknown retained finite group')
    command = [sys.executable, '-I', '-S', '-B', str(ROOT / FINITE_LAUNCHER), str(ROOT),
        '--phase', 'shim' if label == 'shim' else 'native',
        '--bridge', str(ROOT / 'hepta/hia_core_unpack_native.py'),
        '--shim-source', str(ROOT / 'tools/hia_core_unpack_transaction.S'),
        '--evidence-dir', str(Path(base).resolve() / 'component' / label)]
    if label == 'finite-native':
        command.extend(('--image', binding['UNPACK']['files'][1]['path']))
    return command


def inspect_finite(label, base, binding, context, row):
    """Keep the unchanged inner schema false; bind its real current-cold inputs here."""
    for name, digest in FINITE_PINS.items():
        require(previous.source_record(name, context)['sha256'] == digest,
                'retained finite control or isolated launcher bytes changed')
    directory = Path(base).resolve(strict=True) / 'component'
    actual = json_file(directory / label / 'report.json')
    no_errors(actual)
    ids = FINITE_IDS[label]
    phase = 'shim' if label == 'shim' else 'native'
    paths = [ROOT / FINITE_CONTROL, ROOT / 'hepta/hia_core_unpack_native.py',
             ROOT / 'tools/hia_core_unpack_transaction.S']
    if label == 'finite-native':
        paths.append(Path(binding['UNPACK']['files'][1]['path']))
    source = {str(path.resolve(strict=True)): file_record(path)['sha256'] for path in paths}
    require(type(row) is dict and row.get('label') == label
            and row.get('command') == finite_command(label, base, binding)
            and type(row.get('returncode')) is int and row['returncode'] == 0
            and row.get('report_original') == file_record(directory / label / 'report.json')
            and row.get('report') == actual, 'retained finite process command/report differs')
    require(actual.get('schema') == 'hepta.hia.core-unpack-experimental-control.v1'
            and actual.get('status') == 'EXPERIMENTAL_CONTROL_PASS' and actual.get('phase') == phase
            and actual.get('loaded_test_ids') == actual.get('executed_test_ids') == ids
            and type(actual.get('tests_run')) is int and actual['tests_run'] == len(ids)
            and all(type(actual.get(key)) is int and actual[key] == 0 for key in (
                'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
            and actual.get('source_before') == source == actual.get('source_after')
            and actual.get('source_stable') is True
            and actual.get('shim_sha256') == binding['UNPACK']['transaction_sha256']
            and actual.get('ordinary_entry_116_executed') is False
            and actual.get('cold_qualified') is False
            and actual.get('whole_python_object_runtime_in_hia') is False,
            'complete retained four/six controls or their actual new input binding differs')
    files = [file_record(directory / label / 'report.json'), file_record(directory / label / 'unittest.log')]
    for stream in ('stdout', 'stderr'):
        pin = file_record(directory / (label + '.' + stream + '.log'))
        require(row.get(stream) == pin, 'retained finite original process stream differs')
        files.append(pin)
    return {'label': label, 'ids': ids, 'complete_method_count': len(ids), 'files': files,
            'actual_input_files': [file_record(path) for path in paths],
            'inner_experimental_schema_and_false_cold_flag_retained': True}


def compile_originals(folder, manifest, receipt, context):
    """Bind all six original compiler files, including the full one-MiB output."""
    folder = Path(folder).resolve(strict=True)
    label = 'core-unpack'
    paths = [folder / (label + suffix) for suffix in COMPILE_SUFFIXES]
    before = [file_record(path) for path in paths]
    raws = {suffix: path.read_bytes() for suffix, path in zip(COMPILE_SUFFIXES, paths)}
    require(json_file(paths[0]) == receipt, 'UNPACK raw compiler receipt differs from build.json')
    added = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format',
             'runner_sha256', 'wall_elapsed_ns', 'produced_image', 'produced_bytes', 'produced_sha256'}
    require(json_file(paths[1]) == {key: value for key, value in receipt.items() if key not in added},
            'UNPACK compiler stdout differs from the complete retained receipt')
    compiler = context['identities'][2]
    source = ROOT / 'examples/hia_bootstrap/core_unpack.hiaasm'
    image = folder / 'core-unpack.image.bin'
    image_pin = file_record(image)
    previous.previous.compile_receipt(receipt, manifest, image, context)
    require(receipt.get('case') == label and receipt.get('format') == 'flat-x86-64'
            and receipt.get('runner_sha256') == context['source_manifest']['tools/hia_selfhost_child.py']
            and receipt.get('core_u32') == receipt.get('produced_bytes') == image_pin['bytes']
            and type(receipt.get('core_u32')) is int
            and receipt.get('produced_image') == str(image)
            and type(receipt.get('wall_elapsed_ns')) is int and receipt['wall_elapsed_ns'] >= 0,
            'UNPACK compile stage or original child identity differs')
    require(json_file(paths[3]) == {
        'format': 'flat-x86-64', 'image': compiler['path'], 'image_sha256': context['compiler_sha256'],
        'source': str(paths[4]), 'source_sha256': manifest['source_sha256'],
        'capacity': 1048576, 'workspace_size': 1048576, 'workspace_fill': 0, 'output': str(paths[5])},
        'UNPACK original compile request differs')
    require(raws['.input.bin'] == source.read_bytes()
            and receipt.get('input_bytes') == len(raws['.input.bin'])
            and len(raws['.output.bin']) == 1048576
            and sha256(raws['.output.bin']).hexdigest() == receipt.get('output_sha256')
            and raws['.output.bin'][:image_pin['bytes']] == image.read_bytes(),
            'UNPACK complete compiler input/output or produced image prefix differs')
    require(before == [file_record(path) for path in paths], 'UNPACK compile originals changed during readback')
    return before


def companion_build(folder, context):
    from hepta import hia_core_unpack_selection as selection
    from hepta import hia_core_unpack_native as native
    from tools.hia_selfhost_contract import PROFILE
    folder = Path(folder).resolve(strict=True)
    sources = {name: previous.source_record(name, context)['sha256'] for name in (
        selection.HIA_SOURCE, selection.ABI_SOURCE, selection.BRIDGE_SOURCE, selection.SELECTION_SOURCE)}
    abi = selection.checked_abi((ROOT / selection.ABI_SOURCE).read_bytes())
    previous.source_record('tools/hia_core_unpack_transaction.S', context)
    manifest = json_file(folder / 'manifest.json')
    image = folder / 'core-unpack.image.bin'
    image_pin = file_record(image)
    expected = {'schema': selection.SCHEMA, 'image_path': image.name,
        'image_sha256': image_pin['sha256'], 'compiler_sha256': context['compiler_sha256'],
        **{field: sources[name] for field, name in (
            ('source_sha256', selection.HIA_SOURCE), ('abi_sha256', selection.ABI_SOURCE),
            ('bridge_sha256', selection.BRIDGE_SOURCE), ('selection_sha256', selection.SELECTION_SOURCE))}}
    require(manifest == expected and 0 < image_pin['bytes'] <= 1048576,
            'UNPACK manifest/image/current source/B3 identity differs')
    build = json_file(folder / 'build.json')
    require(set(build) == {'schema', 'status', 'profile', 'manifest', 'source_manifest',
            'cold_report_sha256', 'native_compile_receipt', 'original_Core_39_units_unchanged',
            'unpack_control_in_HIA', 'CPython_primitives_still_hosted',
            'whole_stack_rewritten_in_hia', 'production_activated'}
            and build['schema'] == 'hepta.hia.core-unpack-build.v1'
            and build['status'] == 'NATIVE_CANDIDATE_BUILT' and build['profile'] == PROFILE
            and build['manifest'] == manifest and build['source_manifest'] == context['source_manifest']
            and build['cold_report_sha256'] == context['cold_sha256']
            and build['original_Core_39_units_unchanged'] is True and build['unpack_control_in_HIA'] is True
            and build['CPython_primitives_still_hosted'] is True
            and build['whole_stack_rewritten_in_hia'] is False and build['production_activated'] is False,
            'UNPACK must be a real current matching-cold build, not a development bundle')
    files = [file_record(folder / 'manifest.json'), image_pin, file_record(folder / 'build.json')]
    return {'manifest': manifest, 'files': files, 'sources': sources, 'abi': abi,
            'transaction_ABI': native.TRANSACTION_ABI, 'transaction_sha256': native.SHIM_SHA256,
            'runtime_profile': 31404,
            'compile_originals': compile_originals(folder, manifest, build['native_compile_receipt'], context)}


def admitted_companion(binding):
    value = {key: item for key, item in binding['manifest'].items() if key not in ('schema', 'image_path')}
    return {**value, 'manifest_sha256': binding['files'][0]['sha256'],
            'transaction_sha256': binding['transaction_sha256'], 'runtime_profile': 31404}


def implementation_digest(binding):
    from hepta.hia_core_unpack_selection import SCHEMA
    admitted = admitted_companion(binding)
    values = [SCHEMA, admitted['manifest_sha256'], admitted['compiler_sha256'],
              admitted['image_sha256'], admitted['transaction_sha256'], str(admitted['runtime_profile'])]
    for name, digest in sorted(binding['sources'].items()):
        values.extend((name, digest))
    return sha256('\0'.join(values).encode()).hexdigest()


def validate_callers(report, groups, binding, context, cold, evidence):
    no_errors(report)
    require(report.get('schema') == 'hepta.hia.core-unpack-selected-callers.v1'
            and report.get('status') == 'PASS'
            and report.get('scope') == 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
            and report.get('original_groups') == [15, 51, 50]
            and type(report.get('original_complete_methods')) is int and report['original_complete_methods'] == 116
            and type(report.get('original_Core_image_count')) is int and report['original_Core_image_count'] == 39
            and type(report.get('additional_UNPACK_image_count')) is int and report['additional_UNPACK_image_count'] == 1
            and report.get('complete_116_passed') is True, 'complete matching-cold Core116+UNPACK result required')
    require(report.get('outer_opcode14_permission_still_consumed_once') is True
            and report.get('outer_return_counter_semantics') == OUTER_MEANING
            and report.get('old_complete_unpack_entries') == []
            and report.get('CPython_object_runtime_still_hosted') is True
            and report.get('whole_stack_rewritten_in_hia') is False and report.get('default_activated') is False,
            'UNPACK old-owner boundary or scope differs')
    require(report.get('transaction_ABI') == binding['transaction_ABI']
            and report.get('transaction_sha256') == binding['transaction_sha256']
            and report.get('admitted_companion') == admitted_companion(binding)
            and report.get('identity_before') == implementation_digest(binding) == report.get('identity_after'),
            'UNPACK actual admitted companion/source/transaction identity differs')
    files = [{**{key: value for key, value in pin.items() if key != 'bytes'}, 'size': pin['bytes']}
             for pin in binding['files']]
    require(report.get('source_before') == context['source_manifest'] == report.get('source_after')
            and report.get('companion_inputs_before') == files == report.get('companion_inputs_after')
            and report.get('stable') is True, 'UNPACK original source/build inputs changed')
    require(report.get('original_qualifier_argv') == ['qualify_hia_core_lowering_callers.py',
            '--cold-report', str(Path(cold).resolve(strict=True)), '--evidence', str(Path(evidence) / 'core-callers')],
            'UNPACK did not invoke the original default, unsplit cold qualifier')
    ids = {name: group['label'] for group in groups for name in group['ids']}
    image = binding['manifest']['image_sha256']
    columns = {'group', 'test', 'arity', 'image_sha256', 'count'}
    counts = {}
    def key(row):
        require(type(row) is dict and row.get('group') in GROUPS
                and ids.get(row.get('test')) == row['group'] and row.get('image_sha256') == image
                and type(row.get('arity')) is int and 1 <= row['arity'] <= 4
                and type(row.get('count')) is int and row['count'] > 0,
                'UNPACK counter is not a positive original-test/arity/image observation')
        return row['group'], row['test'], row['arity'], row['image_sha256']
    for field in ('outer_opcode14_attempts', 'outer_opcode14_normal_returns', 'outer_opcode14_exceptions'):
        rows = report.get(field)
        require(type(rows) is list, 'UNPACK attempt/return/exception ledger missing')
        values = Counter()
        for row in rows:
            entry = key(row)
            require(set(row) == columns and entry not in values, 'duplicate or extended UNPACK counter row')
            values[entry] = row['count']
        counts[field] = values
    require(counts['outer_opcode14_attempts'] == counts['outer_opcode14_normal_returns']
            + counts['outer_opcode14_exceptions'], 'UNPACK outer attempt/return/exception accounting does not balance')
    rows = report.get('actual_UNPACK_step_returns')
    require(type(rows) is list and rows, 'actual returned UNPACK steps missing')
    seen, statuses = set(), {name: set() for name in GROUPS}
    for row in rows:
        entry = key(row)
        require(set(row) == columns | {'status'} and type(row.get('status')) is int
                and row['status'] in (0, 1, 2) and entry in counts['outer_opcode14_attempts'],
                'actual UNPACK return is not bound to an observed outer operation')
        full = (*entry, row['status'])
        require(full not in seen, 'duplicate actual UNPACK return row')
        seen.add(full)
        statuses[row['group']].add(row['status'])
    require(all({0, 1} <= actual for actual in statuses.values()),
            'each original Core group requires actual UNPACK continue and completion returns')
    return {'outer_attempts': report['outer_opcode14_attempts'],
            'outer_normal_returns': report['outer_opcode14_normal_returns'],
            'outer_exceptions': report['outer_opcode14_exceptions'], 'actual_step_returns': rows,
            'normal_method_return_required_for_rejections': False}


def validate_installed(value, binding):
    from hepta import hia_core_unpack_selection as selection
    require(type(value) is dict and value.get('schema') == 'hepta.hia.core-unpack-installed-observation.v1'
            and value.get('retained_unpack_forbidden') is True
            and type(value.get('runtime_profile')) is int and value['runtime_profile'] == 31404
            and value.get('transaction_sha256') == binding['transaction_sha256']
            and type(value.get('actual_step_returns')) is int and value['actual_step_returns'] > 0
            and value.get('actual_statuses') == [0, 1]
            and all(type(status) is int for status in value['actual_statuses'])
            and value.get('refusals') == [name + suffix for name in (selection.ABI_SOURCE, selection.HIA_SOURCE)
                                        for suffix in (':changed', ':missing')]
            and value.get('restored_identity_sha256') == implementation_digest(binding),
            'actual installed UNPACK returns, refusals or restored identity differ')
    for key in ('source_sha256', 'abi_sha256', 'bridge_sha256', 'selection_sha256', 'image_sha256', 'compiler_sha256'):
        require(value.get(key) == binding['manifest'][key], 'installed UNPACK identity differs: ' + key)
    return value


def inspect_callers(base, cold, context):
    evidence = Path(base).resolve(strict=True) / 'callers'
    admit_dependencies(context)
    groups = caller_groups()
    companion = companion_build(evidence / 'unpack-build', context)
    report = json_file(evidence / 'report.json')
    ledger = validate_callers(report, groups, companion, context, cold, evidence)
    core = previous.inspect_core_callers(evidence / 'core-callers', context, groups,
                                        unpack_manifest=companion['files'][0]['path'])
    require(report.get('original_report') == size_pin(evidence / 'core-callers/report.json'),
            'UNPACK original Core116 report pin differs')
    installed_path = evidence / 'core-callers/component-fixture/installed-control/report.json'
    value = json_file(installed_path).get('unpack_observations')
    require(report.get('installed_report') == size_pin(installed_path)
            and report.get('installed_observation') == value, 'UNPACK installed original bytes differ')
    installed = validate_installed(value, companion)
    source_now(context)
    return {'producer': file_record(evidence / 'report.json'), 'groups': groups,
            'complete_method_count': 116, 'companion': companion, 'core': core,
            'ledger': ledger, 'installed': installed}


def component_binding(callers):
    """Reuse this new cold caller bundle; do not claim another compiler execution."""
    return {'Core39': callers['core']['actual_builds']['caller'], 'UNPACK': callers['companion']}


def validate_component(report, ids, binding, context, callers_pin):
    no_errors(report)
    require(report.get('schema') == 'hepta.hia.core-unpack-composition.v1'
            and report.get('status') == 'PASS' and report.get('scope') == COMPONENT_SCOPE
            and report.get('complete_source_methods') == 2 and report.get('complete_native_methods') == 6
            and type(report.get('complete_component_count')) is int and report['complete_component_count'] == 18
            and report.get('complete_component_groups') == [4, 6, 8]
            and report.get('all_component_ids') == [*FINITE_IDS['shim'], *FINITE_IDS['finite-native'], *ids]
            and type(report.get('finite_groups')) is list and len(report['finite_groups']) == 2
            and [row.get('label') for row in report['finite_groups']] == ['shim', 'finite-native']
            and report.get('loaded_test_ids') == report.get('chosen_test_ids') == report.get('executed_test_ids') == ids
            and all(type(report.get(key)) is int and report[key] == 8
                    for key in ('tests_loaded', 'tests_chosen', 'tests_run'))
            and report.get('loader_errors') == [] and report.get('unittest_successful') is True
            and all(report.get(key) == [] for key in previous.previous.ANOMALIES),
            'complete two source plus six native composition methods required')
    require(report.get('source_before') == context['source_manifest'] == report.get('source_after')
            and report.get('source_preserved') is True and report.get('cold_inputs_preserved') is True
            and report.get('cold_inputs') == context['identities']
            and report.get('caller_report') == callers_pin
            and report.get('build_bindings_before') == binding == report.get('build_bindings_after')
            and report.get('builds_preserved') is True,
            'composition did not use the same actual cold Core39/UNPACK pair and complete116')
    require(report.get('native_step_semantics') == LEDGER_MEANING
            and report.get('CPython_object_runtime_still_hosted') is True
            and report.get('default_activated') is False and report.get('whole_native_delivery_qualified') is False,
            'composition runtime boundary differs')
    rows = report.get('actual_UNPACK_step_returns')
    require(type(rows) is list and rows, 'composition actual native return rows missing')
    seen = set()
    for row in rows:
        require(type(row) is dict and set(row) == {'test', 'image_sha256', 'status', 'count'}
                and row.get('test') in ids and '.UnpackCompositionNativeTests.' in row['test']
                and row.get('image_sha256') == binding['UNPACK']['manifest']['image_sha256']
                and type(row.get('status')) is int and row['status'] in (0, 1, 2)
                and type(row.get('count')) is int and row['count'] > 0,
                'composition step is not an actual source/image/test-bound native return')
        key = row['test'], row['image_sha256'], row['status']
        require(key not in seen, 'duplicate composition native return row')
        seen.add(key)
    require({0, 1} <= {key[2] for key in seen}, 'composition lacks actual continue/completion returns')
    return rows


def owned_command(part, cold, base):
    require(part in ('callers', 'component'), 'unknown UNPACK product phase')
    cold, base = Path(cold).resolve(strict=True), Path(base).resolve()
    if part == 'callers':
        return [sys.executable, '-B', '-m', 'tools.qualify_hia_core_unpack_callers',
                '--cold-report', str(cold), '--evidence', str(base / 'callers')]
    return [sys.executable, '-B', str(ROOT / 'tools/qualify_hia_core_unpack_ci.py'),
            'component-child', '--cold-report', str(cold), '--evidence-dir', str(base)]


def validate_owned(result, request, receipt, pins, command, part, cold, context):
    no_errors(result)
    implementation = context['source_manifest']['tools/hia_selfhost_process_owner.py']
    require(result.get('schema') == 'hepta.hia.core-unpack-owned-command.v1'
            and result.get('status') == 'OWNED_COMMAND_RETURNED_PENDING_READBACK'
            and result.get('part') == part and result.get('command') == command
            and result.get('cwd') == str(ROOT)
            and result.get('source_before') == context['source_manifest'] == result.get('source_after')
            and result.get('source_preserved') is True and result.get('cold_inputs_preserved') is True
            and result.get('cold_inputs') == context['identities'], 'UNPACK owned command/source completion differs')
    require(request.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
            and request.get('command') == command and request.get('cwd') == str(ROOT)
            and type(request.get('qualification_seconds')) is int and request['qualification_seconds'] == 180
            and type(request.get('cleanup_seconds')) is int and request['cleanup_seconds'] == 3
            and request.get('implementation_sha256') == implementation
            and request.get('stdout_path') == pins['stdout.log']['path']
            and request.get('stderr_path') == pins['stderr.log']['path']
            and request.get('receipt_path') == pins['process-owner.json']['path'],
            'UNPACK original command request or 180/3 boundary differs')
    env = request.get('env')
    require(type(env) is dict and env.get('HEPTA_HIA_CORE_UNPACK_COLD_REPORT') == str(Path(cold).resolve(strict=True))
            and not any(name.startswith('HEPTA_') and
                        ('DEVELOPMENT' in name or name.endswith(('_MANIFEST', '_BUNDLE'))) for name in env),
            'UNPACK owned environment admits a development or ambient image selector')
    require(receipt.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
            and receipt.get('request_sha256') == pins['process-owner.json.request.json']['sha256']
            and receipt.get('implementation_sha256') == implementation
            and receipt.get('qualification_seconds') == 180 and receipt.get('cleanup_seconds') == 3
            and receipt.get('status') == 'OWNED_PROCESS_COMPLETED'
            and type(receipt.get('returncode')) is int and receipt['returncode'] == 0
            and receipt.get('timed_out') is False and receipt.get('qualification_started') is True
            and receipt.get('exit_observed_before_deadline') is True and receipt.get('subreaper_enabled') is True
            and receipt.get('interrupted_signals') == [] and receipt.get('owner_error') is None
            and receipt.get('event_overflow') is False, 'UNPACK original owner did not complete naturally')
    cleanup = receipt.get('cleanup', {})
    require(cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('leader_reaped') is True and cleanup.get('observed_echild') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [], 'UNPACK original owner cleanup remains open')
    events = receipt.get('events')
    allowed = {'qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'}
    require(type(events) is list and events and all(type(row) is dict and row.get('kind') in allowed for row in events)
            and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                <= {row['kind'] for row in events}, 'UNPACK original owner used a kill or lacks natural events')
    returned = result.get('returned_owner')
    require(type(returned) is dict and type(returned.get('supervisor_returncode')) is int
            and returned['supervisor_returncode'] == 0
            and returned.get('receipt_sha256') == pins['process-owner.json']['sha256']
            and {key: value for key, value in returned.items() if key not in ('supervisor_returncode', 'receipt_sha256')} == receipt,
            'UNPACK owner API return differs from the complete raw lifecycle receipt')
    return True


def inspect_owned(part, cold, base, context):
    directory = Path(base).resolve(strict=True) / (part + '-owner')
    names = ('run-result.json', 'process-owner.json', 'process-owner.json.request.json',
             'stdout.log', 'stderr.log', 'process-owner.json.stdout.log', 'process-owner.json.stderr.log')
    pins = {name: file_record(directory / name) for name in names}
    result = json_file(directory / 'run-result.json')
    receipt = json_file(directory / 'process-owner.json')
    request = json_file(directory / 'process-owner.json.request.json')
    command = owned_command(part, cold, base)
    validate_owned(result, request, receipt, pins, command, part, cold, context)
    runtime = result.get('runtime_before')
    require(type(runtime) is dict and runtime == result.get('runtime_after')
            and runtime.get('implementation') == 'CPython' and runtime.get('version') == [3, 14, 4]
            and runtime.get('runtime_profile') == 31404
            and runtime.get('executable') == file_record(Path(command[0]).resolve(strict=True)),
            'UNPACK actual interpreter identity changed or is unsupported')
    return {'part': part, 'command': command, 'qualification_seconds': 180, 'cleanup_seconds': 3,
            'natural_exit_and_echild': True, 'runtime': runtime, 'files': list(pins.values())}


def inspect_all(base, cold, context):
    source_now(context)
    owners_before = {part: inspect_owned(part, cold, base, context) for part in ('callers', 'component')}
    callers = inspect_callers(base, cold, context)
    component_path = Path(base).resolve(strict=True) / 'component'
    report = json_file(component_path / 'report.json')
    ids = expected_component_ids()
    binding = component_binding(callers)
    rows = validate_component(report, ids, binding, context, callers['producer'])
    finite = [inspect_finite(label, base, binding, context, row)
              for label, row in zip(('shim', 'finite-native'), report['finite_groups'])]
    require(report.get('runtime_before') == report.get('runtime_after') == owners_before['component']['runtime']
            and report.get('caller_process') == owners_before['callers'],
            'component runtime or initial complete116 process readback differs')
    require(owners_before['callers']['runtime'] == owners_before['component']['runtime'],
            'UNPACK independent phases used different interpreters')
    owners_after = {part: inspect_owned(part, cold, base, context) for part in ('callers', 'component')}
    require(owners_before == owners_after, 'UNPACK process originals changed during independent readback')
    source_now(context)
    return {'gates': {name: True for name in NEW_GATES}, 'cold_inputs': context['identities'],
            'B3_sha256': context['compiler_sha256'], 'source_manifest': context['source_manifest'],
            'callers': callers, 'component': {'report': file_record(component_path / 'report.json'),
                'unittest_log': file_record(component_path / 'unittest.log'), 'ids': ids,
                'complete_groups': [4, 6, 8], 'complete_method_count': 18,
                'all_component_ids': report['all_component_ids'], 'finite_controls': finite,
                'source_method_count': 2, 'native_method_count': 6, 'actual_step_returns': rows},
            'process_owners': owners_after, 'separate_original_180_second_owners': 2,
            'split_original116_accepted': False, 'development_capsule_accepted': False,
            'CPython_object_runtime_still_hosted': True, 'whole_native_delivery_qualified': False}


def validate_gate_report(value, inspection, context):
    no_errors(value)
    require(value.get('schema') == 'hepta.hia.core-unpack-gates.v1' and value.get('status') == 'PASS'
            and value.get('scope') == SCOPE and value.get('operation') in ('owned-component', 'check')
            and value.get('source_before') == context['source_manifest'] == value.get('source_after')
            and value.get('source_preserved') is True and value.get('cold_inputs_preserved') is True
            and value.get('cold_inputs') == context['identities']
            and type(inspection) is dict and inspection and value.get('inspection') == inspection
            and value.get('gates') == inspection['gates'] == {name: True for name in NEW_GATES}
            and value.get('whole_native_delivery_qualified') is False,
            'UNPACK gate differs from complete actual cold/116/composition/process readback')
    return True
