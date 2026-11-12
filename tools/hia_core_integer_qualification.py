"""Read integer companion build and installed originals from this exact cold.

These functions do not execute an image or grant an additional mandatory gate.
The existing thirty-two gates, complete Core116 and eighteen UNPACK controls
remain separate requirements. An integer runtime result needs a new execution;
the historical finite native experiment is not a matching-cold substitute.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from tools import hia_compiler_owner_gates as previous

ROOT = Path(__file__).resolve().parents[1]
require = previous.require
file_record = previous.file_record
json_file = previous.json_file
COMPILE_SUFFIXES = ('.receipt.json', '.stdout.log', '.stderr.log',
                    '.request.json', '.input.bin', '.output.bin')
STEP_MEANING = 'IntegerSession.step returned normally after admitted HIA output validation; not a raw entry return or whole-method PASS.'
FINISH_MEANING = 'IntegerSession.finish returned the materialized exact int normally; separate from a native DONE step.'


def compile_originals(folder, manifest, receipt, context):
    folder = Path(folder).resolve(strict=True)
    label = 'core-integer'
    paths = [folder / (label + suffix) for suffix in COMPILE_SUFFIXES]
    before = [file_record(path) for path in paths]
    raws = {suffix: path.read_bytes() for suffix, path in zip(COMPILE_SUFFIXES, paths)}
    require(json_file(paths[0]) == receipt, 'integer raw compile receipt differs from build.json')
    added = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format',
             'runner_sha256', 'wall_elapsed_ns', 'produced_image', 'produced_bytes', 'produced_sha256'}
    require(json_file(paths[1]) == {key: value for key, value in receipt.items() if key not in added},
            'integer compiler stdout differs from the complete retained receipt')
    compiler = context['identities'][2]
    source = ROOT / 'examples/hia_bootstrap/core_integer.hiaasm'
    image = folder / 'core-integer.image.bin'
    image_pin = file_record(image)
    previous.previous.compile_receipt(receipt, manifest, image, context)
    require(receipt.get('case') == label and receipt.get('format') == 'flat-x86-64'
            and type(receipt.get('abi_status')) is int and receipt['abi_status'] == 0
            and receipt.get('runner_sha256') == context['source_manifest']['tools/hia_selfhost_child.py']
            and type(receipt.get('core_u32')) is int
            and receipt['core_u32'] == receipt.get('produced_bytes') == image_pin['bytes']
            and receipt.get('produced_image') == str(image)
            and type(receipt.get('wall_elapsed_ns')) is int and receipt['wall_elapsed_ns'] >= 0,
            'integer compile stage or original child identity differs')
    request = json_file(paths[3])
    require(request == {
        'format': 'flat-x86-64', 'image': compiler['path'], 'image_sha256': context['compiler_sha256'],
        'source': str(paths[4]), 'source_sha256': manifest['source_sha256'],
        'capacity': 1048576, 'workspace_size': 1048576, 'workspace_fill': 0, 'output': str(paths[5])}
            and all(type(request[key]) is int for key in ('capacity', 'workspace_size', 'workspace_fill')),
        'integer original compile request differs')
    require(raws['.input.bin'] == source.read_bytes()
            and receipt.get('input_bytes') == len(raws['.input.bin'])
            and len(raws['.output.bin']) == 1048576
            and sha256(raws['.output.bin']).hexdigest() == receipt.get('output_sha256')
            and raws['.output.bin'][:image_pin['bytes']] == image.read_bytes(),
            'integer complete compiler input/output or image prefix differs')
    require(before == [file_record(path) for path in paths],
            'integer compile originals changed during independent readback')
    return before


def companion_build(folder, context):
    from hepta import hia_core_integer_selection as selection
    from tools.hia_selfhost_contract import PROFILE
    folder = Path(folder).resolve(strict=True)
    sources = {name: previous.source_record(name, context)['sha256'] for name in (
        selection.HIA_SOURCE, selection.ABI_SOURCE, selection.BRIDGE_SOURCE, selection.SELECTION_SOURCE)}
    abi = selection.checked_abi((ROOT / selection.ABI_SOURCE).read_bytes())
    manifest = json_file(folder / 'manifest.json')
    image = folder / 'core-integer.image.bin'
    image_pin = file_record(image)
    expected = {'schema': selection.SCHEMA, 'image_path': image.name,
        'image_sha256': image_pin['sha256'], 'compiler_sha256': context['compiler_sha256'],
        **{field: sources[name] for field, name in (
            ('source_sha256', selection.HIA_SOURCE), ('abi_sha256', selection.ABI_SOURCE),
            ('bridge_sha256', selection.BRIDGE_SOURCE), ('selection_sha256', selection.SELECTION_SOURCE))}}
    require(manifest == expected and 0 < image_pin['bytes'] <= 1048576,
            'integer manifest/image/current source/B3 identity differs')
    build = json_file(folder / 'build.json')
    require(set(build) == {'schema', 'status', 'profile', 'manifest', 'source_manifest',
            'cold_report_sha256', 'native_compile_receipt', 'original_Core_39_units_unchanged',
            'integer_arithmetic_control_in_HIA', 'CPython_primitives_still_hosted',
            'whole_stack_rewritten_in_hia', 'production_activated'}
            and build['schema'] == 'hepta.hia.core-integer-build.v1'
            and build['status'] == 'NATIVE_CANDIDATE_BUILT' and build['profile'] == PROFILE
            and build['manifest'] == manifest and build['source_manifest'] == context['source_manifest']
            and build['cold_report_sha256'] == context['cold_sha256']
            and build['original_Core_39_units_unchanged'] is True
            and build['integer_arithmetic_control_in_HIA'] is True
            and build['CPython_primitives_still_hosted'] is True
            and build['whole_stack_rewritten_in_hia'] is False and build['production_activated'] is False,
            'integer companion is not a complete matching-source cold build')
    files = [file_record(folder / 'manifest.json'), image_pin, file_record(folder / 'build.json')]
    return {'manifest': manifest, 'files': files, 'sources': sources, 'abi': abi,
            'compile_originals': compile_originals(folder, manifest, build['native_compile_receipt'], context)}


def admitted_companion(binding):
    value = {key: item for key, item in binding['manifest'].items() if key not in ('schema', 'image_path')}
    return {**value, 'manifest_sha256': binding['files'][0]['sha256']}


def implementation_digest(binding):
    from hepta import hia_core_integer_selection as selection
    admitted = admitted_companion(binding)
    values = [selection.SCHEMA, admitted['manifest_sha256'], admitted['compiler_sha256'], admitted['image_sha256']]
    for name in sorted(binding['sources']):
        values.extend((name, binding['sources'][name]))
    return sha256('\0'.join(values).encode('ascii')).hexdigest()


def _outer_operation(opcode, operation):
    return (type(opcode) is int and type(operation) is int
            and (opcode == 11 and operation in (*range(1, 13), *range(129, 141))
                 or opcode == 12 and operation in (1, 2, 3)))


def _native_operation(opcode, operation):
    if opcode == 11 and operation in (1, 2):
        return operation
    if opcode == 12 and operation in (2, 3):
        return operation + 1
    return None


def validate_returns(value, groups, image_sha256):
    """Join original opcode IDs, accepted step returns and materialized results."""
    require(type(value) is dict and value.get('native_step_semantics') == STEP_MEANING
            and value.get('finish_return_semantics') == FINISH_MEANING
            and value.get('fixture_step_rows_are_not_test_pass') is True
            and value.get('retained_builtin_target_entries') == []
            and value.get('unbound_native_returns') == [],
            'integer observation scope or retained builtin entries differ')
    labels = {'component', 'original-machine', 'original-core'}
    require(type(groups) is dict and set(groups.values()) == labels and len(groups) == 116,
            'integer observation requires all original Core116 IDs')

    def belongs(test, group):
        return (type(test) is str and type(group) is str and group in labels
                and (groups.get(test) == group or test == '@fixture:' + group))

    def counter(field):
        rows = value.get(field)
        require(type(rows) is list, 'integer original effect rows missing: ' + field)
        result = {}
        for row in rows:
            require(type(row) is dict
                    and set(row) == {'group', 'test', 'opcode', 'operation', 'image_sha256', 'count'}
                    and belongs(row['test'], row['group'])
                    and _outer_operation(row['opcode'], row['operation'])
                    and row['image_sha256'] == image_sha256
                    and type(row['count']) is int and row['count'] > 0,
                    'integer effect row differs: ' + field)
            key = (row['group'], row['test'], row['opcode'], row['operation'], row['image_sha256'])
            require(key not in result, 'duplicate integer effect row: ' + field)
            result[key] = row['count']
        return result

    attempts = counter('outer_integer_attempts')
    eligible = counter('outer_integer_eligible')
    normal = counter('outer_integer_normal_returns')
    failed = counter('outer_integer_exceptions')
    eligible_normal = counter('eligible_normal_returns')
    eligible_failed = counter('eligible_exceptions')
    failed_done = counter('eligible_exception_terminal_returns')
    failed_finish = counter('eligible_exception_finish_returns')
    finishes = counter('actual_integer_finish_returns')
    require(attempts and eligible and set(normal) | set(failed) == set(attempts)
            and all(normal.get(key, 0) + failed.get(key, 0) == count for key, count in attempts.items())
            and all(_native_operation(key[2], key[3]) is not None
                    and count <= attempts.get(key, 0) for key, count in eligible.items()),
            'integer attempts or exact eligibility accounting differs')
    require(set(eligible_normal) | set(eligible_failed) == set(eligible)
            and all(eligible_normal.get(key, 0) + eligible_failed.get(key, 0) == count
                    for key, count in eligible.items())
            and all(count <= normal.get(key, 0) for key, count in eligible_normal.items())
            and all(count <= failed.get(key, 0) for key, count in eligible_failed.items())
            and all(count <= eligible_failed.get(key, 0) for key, count in failed_done.items())
            and all(count <= failed_done.get(key, 0) for key, count in failed_finish.items()),
            'integer eligible normal/exception/DONE/materialization counts differ')
    rows = value.get('actual_integer_step_returns')
    require(type(rows) is list and rows, 'integer actual normal step-return matrix is empty')
    seen, completions = set(), {}
    statuses = {label: set() for label in labels}
    for row in rows:
        require(type(row) is dict
                and set(row) == {'group', 'test', 'opcode', 'operation', 'native_operation',
                                 'image_sha256', 'status', 'count'}
                and belongs(row['test'], row['group'])
                and _outer_operation(row['opcode'], row['operation'])
                and type(row['native_operation']) is int
                and row['native_operation'] == _native_operation(row['opcode'], row['operation'])
                and row['image_sha256'] == image_sha256
                and type(row['status']) is int and row['status'] in (0, 1, 2)
                and type(row['count']) is int and row['count'] > 0,
                'integer actual normal step-return row differs')
        key = (row['group'], row['test'], row['opcode'], row['operation'], row['image_sha256'])
        full = (*key, row['status'])
        require(full not in seen and key in eligible, 'duplicate or unbound integer actual step')
        seen.add(full)
        statuses[row['group']].add(row['status'])
        if row['status'] == 0:
            completions[key] = row['count']
    wanted_done = {key: eligible_normal.get(key, 0) + failed_done.get(key, 0)
                   for key in set(eligible_normal) | set(failed_done)}
    wanted_finish = {key: eligible_normal.get(key, 0) + failed_finish.get(key, 0)
                     for key in set(eligible_normal) | set(failed_finish)}
    require(all({0, 2} <= observed for observed in statuses.values())
            and set().union(*statuses.values()) == {0, 1, 2}
            and completions == wanted_done and finishes == wanted_finish,
            'eligible integer return requires one actual DONE and one actual finish; errors remain separate')
    vm = value.get('independent_Core_VM_effects_not_native_proof')
    require(type(vm) is list, 'independent integer Core VM exclusions are missing')
    vm_seen = set()
    for row in vm:
        require(type(row) is dict and set(row) == {'group', 'test', 'opcode', 'operation', 'count'}
                and row['group'] == 'component' and groups.get(row['test']) == 'component'
                and '.CoreLoweringSourceTests.' in row['test']
                and _outer_operation(row['opcode'], row['operation'])
                and type(row['count']) is int and row['count'] > 0,
                'unadmitted integer VM effect was mislabeled native')
        key = (row['test'], row['opcode'], row['operation'])
        require(key not in vm_seen, 'duplicate integer VM exclusion')
        vm_seen.add(key)
    return {'actual_step_returns': rows, 'actual_finish_returns': value['actual_integer_finish_returns'],
            'eligible_effects': value['outer_integer_eligible'], 'retained_builtin_target_entries': [],
            'fixture_steps_are_not_method_success': True, 'all116_methods_required_separately': True,
            'independent_Core_VM_effects_not_native_proof': vm}


def validate_installed(value, binding):
    from hepta import hia_core_integer_selection as selection
    require(type(value) is dict and value.get('schema') == 'hepta.hia.core-integer-installed-observation.v1'
            and value.get('actual_step_semantics') == STEP_MEANING
            and value.get('finish_return_semantics') == FINISH_MEANING
            and value.get('retained_builtin_target_forbidden') is True
            and value.get('retained_builtin_target_entries') == []
            and value.get('CPython_object_primitives_still_hosted') is True,
            'installed integer scope, original target guard or step meaning differs')
    for key, expected in admitted_companion(binding).items():
        require(value.get(key) == expected, 'installed integer source/compiler/image differs: ' + key)
    effects = value.get('ordinary_eligible_effects')
    require(type(effects) is list and effects, 'installed integer ordinary effects are missing')
    for row in effects:
        require(type(row) is dict and set(row) == {'opcode', 'operation', 'native_operation', 'returned',
                                                 'done_returns', 'finish_returns'}
                and _outer_operation(row['opcode'], row['operation'])
                and type(row['native_operation']) is int
                and row['native_operation'] == _native_operation(row['opcode'], row['operation'])
                and row['returned'] is True
                and type(row['done_returns']) is int and row['done_returns'] == 1
                and type(row['finish_returns']) is int and row['finish_returns'] == 1,
                'installed integer effect lacks one actual normal DONE and finish')
    step_rows = value.get('step_returns')
    finish_rows = value.get('finish_returns')
    require(type(step_rows) is list and step_rows and type(finish_rows) is list and finish_rows,
            'installed integer actual return originals are missing')
    counts, finished = {}, {}
    for row in step_rows:
        require(type(row) is dict and set(row) == {'phase', 'native_operation', 'image_sha256', 'status', 'count'}
                and row['phase'] in ('ordinary', 'window-probe')
                and type(row['native_operation']) is int and 1 <= row['native_operation'] <= 4
                and row['image_sha256'] == binding['manifest']['image_sha256']
                and type(row['status']) is int and row['status'] in (0, 1, 2)
                and type(row['count']) is int and row['count'] > 0,
                'installed integer step-return row differs')
        key = (row['phase'], row['native_operation'], row['status'])
        require(key not in counts, 'duplicate installed integer step row')
        counts[key] = row['count']
    for row in finish_rows:
        require(type(row) is dict and set(row) == {'phase', 'native_operation', 'image_sha256', 'count'}
                and row['phase'] in ('ordinary', 'window-probe')
                and type(row['native_operation']) is int and 1 <= row['native_operation'] <= 4
                and row['image_sha256'] == binding['manifest']['image_sha256']
                and type(row['count']) is int and row['count'] > 0,
                'installed integer finish-return row differs')
        key = (row['phase'], row['native_operation'])
        require(key not in finished, 'duplicate installed integer finish row')
        finished[key] = row['count']
    wanted = {}
    for row in effects:
        key = ('ordinary', row['native_operation'])
        wanted[key] = wanted.get(key, 0) + 1
    for operation in (1, 2, 3, 4):
        wanted[('window-probe', operation)] = 1
        require(counts.get(('window-probe', operation, 0), 0) == 1
                and all(counts.get(('window-probe', operation, status), 0) >= 2 for status in (1, 2)),
                'installed integer probe did not cross actual READ/WRITE/DONE states')
    done = {(phase, operation): count for (phase, operation, status), count in counts.items() if status == 0}
    require(done == finished == wanted, 'installed integer DONE/finish counts do not match actual effects')
    expected_probes = [
        {'operation': 1, 'left': '(1<<1025)-1', 'right': '1', 'result': '1<<1025'},
        {'operation': 2, 'left': '1<<1025', 'right': '1', 'result': '(1<<1025)-1'},
        {'operation': 3, 'left': '1<<1025', 'right': None, 'result': '-(1<<1025)'},
        {'operation': 4, 'left': '(1<<1025)-1', 'right': None, 'result': '-(1<<1025)'},
    ]
    require(type(value.get('window_probes')) is list and value['window_probes'] == expected_probes
            and all(type(row.get('operation')) is int for row in value['window_probes'])
            and value.get('refusals') == [name + suffix for name in (
                selection.ABI_SOURCE, selection.HIA_SOURCE, selection.BRIDGE_SOURCE, selection.SELECTION_SOURCE)
                for suffix in (':changed', ':missing')]
            and value.get('restored_identity_sha256') == implementation_digest(binding),
            'installed integer window arithmetic, four-source refusals or restoration differs')
    return value


def inspect_selected(directory, cold, context):
    """Read the fixed integer -> numeric -> UNPACK -> original-Core hierarchy."""
    from tools import hia_core_compare_qualification as numeric_reader
    from tools import hia_core_unpack_gates as unpack_reader
    directory = Path(directory).resolve(strict=True)
    numeric_directory = directory / 'numeric'
    integer = companion_build(directory / 'integer-build', context)
    numeric = numeric_reader.companion_build(numeric_directory / 'numeric-build', context)
    paths = {
        'integer': directory / 'integer-report.json',
        'numeric': numeric_directory / 'numeric-report.json',
        'UNPACK': numeric_directory / 'callers/report.json',
        'original': numeric_directory / 'callers/core-callers/report.json',
        'installed': numeric_directory / 'callers/core-callers/component-fixture/installed-control/report.json',
    }
    before = {name: file_record(path) for name, path in paths.items()}
    integer_value, numeric_value = json_file(paths['integer']), json_file(paths['numeric'])
    installed = json_file(paths['installed'])
    runtime = unpack_reader.runtime_identity()
    groups = {test: row['label'] for row in unpack_reader.caller_groups() for test in row['ids']}

    def size_pin(path):
        row = file_record(path)
        return {'path': row['path'], 'size': row['bytes'], 'sha256': row['sha256']}

    def common(report, binding, reader, schema):
        unpack_reader.no_errors(report)
        require(report.get('schema') == schema and report.get('status') == 'PASS'
                and report.get('scope') == 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
                and report.get('original_groups') == [15, 51, 50]
                and type(report.get('original_complete_methods')) is int
                and report['original_complete_methods'] == 116
                and type(report.get('original_Core_image_count')) is int
                and report['original_Core_image_count'] == 39
                and report.get('complete_116_passed') is True
                and report.get('source_before') == context['source_manifest'] == report.get('source_after')
                and report.get('matching_cold_inputs') == context['identities']
                and report.get('matching_cold_build') == binding
                and report.get('runtime_before') == runtime == report.get('runtime_after')
                and report.get('stable') is True
                and report.get('CPython_object_runtime_still_hosted') is True
                and report.get('whole_native_delivery_qualified') is False
                and report.get('default_activated') is False,
                'selected companion producer is not a complete stable current-cold Core116 execution')
        for name in ('additional_UNPACK_image_count', 'additional_numeric_image_count'):
            require(type(report.get(name)) is int and report[name] == 1,
                    'selected companion image population differs: ' + name)
        inputs = [{'path': row['path'], 'size': row['bytes'], 'sha256': row['sha256']}
                  for row in binding['files']]
        require(report.get('companion_inputs_before') == inputs == report.get('companion_inputs_after')
                and report.get('admitted_companion') == reader.admitted_companion(binding)
                and report.get('identity_before') == reader.implementation_digest(binding) == report.get('identity_after'),
                'selected companion actual source/image/manifest identities differ')

    common(integer_value, integer, sys_module(), 'hepta.hia.core-integer-selected-callers.v1')
    common(numeric_value, numeric, numeric_reader, 'hepta.hia.core-compare-selected-callers.v1')
    require(type(integer_value.get('additional_integer_image_count')) is int
            and integer_value['additional_integer_image_count'] == 1
            and type(integer_value.get('complete_numeric_wrapper_calls')) is int
            and integer_value['complete_numeric_wrapper_calls'] == 1
            and type(integer_value.get('complete_numeric_wrapper_calls_required')) is int
            and integer_value['complete_numeric_wrapper_calls_required'] == 1
            and integer_value.get('numeric_and_UNPACK_observation_required') is True
            and integer_value.get('raw_entry_returns_counted_as_step_returns') is False,
            'integer producer did not make exactly one complete numeric wrapper call')
    require(type(numeric_value.get('complete_UNPACK_wrapper_calls')) is int
            and numeric_value['complete_UNPACK_wrapper_calls'] == 1
            and type(numeric_value.get('complete_original_qualifier_calls_required')) is int
            and numeric_value['complete_original_qualifier_calls_required'] == 1
            and numeric_value.get('UNPACK_observation_required') is True
            and numeric_value.get('matching_integer_build') == integer,
            'numeric producer did not retain the original single UNPACK wrapper and explicit integer build')
    require(integer_value.get('original_numeric_qualifier_argv') == [
                'qualify_hia_core_compare_callers.py', '--cold-report', str(Path(cold).resolve(strict=True)),
                '--integer-manifest', integer['files'][0]['path'], '--evidence', str(numeric_directory)]
            and numeric_value.get('original_UNPACK_qualifier_argv') == [
                'qualify_hia_core_unpack_callers.py', '--cold-report', str(Path(cold).resolve(strict=True)),
                '--evidence', str(numeric_directory / 'callers')],
            'selected companion wrapper argv is not the fixed unsplit original hierarchy')
    for field, label in (('numeric_report', 'numeric'), ('UNPACK_report', 'UNPACK'),
                         ('original_report', 'original'), ('installed_report', 'installed')):
        require(integer_value.get(field) == size_pin(paths[label]),
                'integer producer original receipt pin differs: ' + field)
    for field, label in (('UNPACK_report', 'UNPACK'), ('original_report', 'original'),
                         ('installed_report', 'installed')):
        require(numeric_value.get(field) == size_pin(paths[label]),
                'numeric producer original receipt pin differs: ' + field)
    integer_ledger = validate_returns(integer_value, groups, integer['manifest']['image_sha256'])
    numeric_ledger = numeric_reader.validate_returns(numeric_value, groups, numeric['manifest']['image_sha256'])
    for report in (integer_value, numeric_value):
        require(report.get('installed_integer_observation') == installed.get('integer_observations')
                and report.get('installed_numeric_observation') == installed.get('numeric_compare_observations')
                and report.get('installed_UNPACK_observation') == installed.get('unpack_observations'),
                'three-companion installed observation was omitted or detached from the actual original report')
    validate_installed(installed.get('integer_observations'), integer)
    numeric_reader.validate_installed(installed.get('numeric_compare_observations'), numeric)
    original = unpack_reader.inspect_callers(numeric_directory, cold, context,
                numeric_manifest=numeric['files'][0]['path'], integer_manifest=integer['files'][0]['path'])
    require(numeric_value.get('independent_current_cold_readback') == original,
            'numeric retained original Core116/UNPACK/installed readback differs')
    require(before == {name: file_record(path) for name, path in paths.items()},
            'selected companion original reports changed during readback')
    previous.source_now(context)
    return {**original, 'selected_companions': {
        'integer_build': integer, 'numeric_build': numeric,
        'integer_ledger': integer_ledger, 'numeric_ledger': numeric_ledger,
        'producer_files': before, 'one_original116_execution': True,
        'separate_probe_ledger_not_original_methods': True,
        'all_three_installed_observations_required': True}}


def sys_module():
    """Use the current reader object without importing an alternate source copy."""
    import sys
    return sys.modules[__name__]


