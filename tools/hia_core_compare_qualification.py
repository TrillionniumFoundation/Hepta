"""Read numeric companion build and installed originals from this exact cold.

These functions do not execute an image or grant an additional mandatory gate.
The existing thirty-two gates, complete Core116 and eighteen UNPACK controls
remain separate requirements. A numeric runtime result needs a new execution;
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
STEP_MEANING = 'NumericCompareSession.step returned from the admitted image; not a whole-method PASS.'


def compile_originals(folder, manifest, receipt, context):
    folder = Path(folder).resolve(strict=True)
    label = 'core-compare'
    paths = [folder / (label + suffix) for suffix in COMPILE_SUFFIXES]
    before = [file_record(path) for path in paths]
    raws = {suffix: path.read_bytes() for suffix, path in zip(COMPILE_SUFFIXES, paths)}
    require(json_file(paths[0]) == receipt, 'numeric raw compile receipt differs from build.json')
    added = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format',
             'runner_sha256', 'wall_elapsed_ns', 'produced_image', 'produced_bytes', 'produced_sha256'}
    require(json_file(paths[1]) == {key: value for key, value in receipt.items() if key not in added},
            'numeric compiler stdout differs from the complete retained receipt')
    compiler = context['identities'][2]
    source = ROOT / 'examples/hia_bootstrap/core_compare.hiaasm'
    image = folder / 'core-compare.image.bin'
    image_pin = file_record(image)
    previous.previous.compile_receipt(receipt, manifest, image, context)
    require(receipt.get('case') == label and receipt.get('format') == 'flat-x86-64'
            and type(receipt.get('abi_status')) is int and receipt['abi_status'] == 0
            and receipt.get('runner_sha256') == context['source_manifest']['tools/hia_selfhost_child.py']
            and type(receipt.get('core_u32')) is int
            and receipt['core_u32'] == receipt.get('produced_bytes') == image_pin['bytes']
            and receipt.get('produced_image') == str(image)
            and type(receipt.get('wall_elapsed_ns')) is int and receipt['wall_elapsed_ns'] >= 0,
            'numeric compile stage or original child identity differs')
    request = json_file(paths[3])
    require(request == {
        'format': 'flat-x86-64', 'image': compiler['path'], 'image_sha256': context['compiler_sha256'],
        'source': str(paths[4]), 'source_sha256': manifest['source_sha256'],
        'capacity': 1048576, 'workspace_size': 1048576, 'workspace_fill': 0, 'output': str(paths[5])}
            and all(type(request[key]) is int for key in ('capacity', 'workspace_size', 'workspace_fill')),
        'numeric original compile request differs')
    require(raws['.input.bin'] == source.read_bytes()
            and receipt.get('input_bytes') == len(raws['.input.bin'])
            and len(raws['.output.bin']) == 1048576
            and sha256(raws['.output.bin']).hexdigest() == receipt.get('output_sha256')
            and raws['.output.bin'][:image_pin['bytes']] == image.read_bytes(),
            'numeric complete compiler input/output or image prefix differs')
    require(before == [file_record(path) for path in paths],
            'numeric compile originals changed during independent readback')
    return before


def companion_build(folder, context):
    from hepta import hia_core_compare_selection as selection
    from tools.hia_selfhost_contract import PROFILE
    folder = Path(folder).resolve(strict=True)
    sources = {name: previous.source_record(name, context)['sha256'] for name in (
        selection.HIA_SOURCE, selection.ABI_SOURCE, selection.BRIDGE_SOURCE, selection.SELECTION_SOURCE)}
    abi = selection.checked_abi((ROOT / selection.ABI_SOURCE).read_bytes())
    manifest = json_file(folder / 'manifest.json')
    image = folder / 'core-compare.image.bin'
    image_pin = file_record(image)
    expected = {'schema': selection.SCHEMA, 'image_path': image.name,
        'image_sha256': image_pin['sha256'], 'compiler_sha256': context['compiler_sha256'],
        **{field: sources[name] for field, name in (
            ('source_sha256', selection.HIA_SOURCE), ('abi_sha256', selection.ABI_SOURCE),
            ('bridge_sha256', selection.BRIDGE_SOURCE), ('selection_sha256', selection.SELECTION_SOURCE))}}
    require(manifest == expected and 0 < image_pin['bytes'] <= 1048576,
            'numeric manifest/image/current source/B3 identity differs')
    build = json_file(folder / 'build.json')
    require(set(build) == {'schema', 'status', 'profile', 'manifest', 'source_manifest',
            'cold_report_sha256', 'native_compile_receipt', 'original_Core_39_units_unchanged',
            'numeric_comparison_control_in_HIA', 'CPython_primitives_still_hosted',
            'whole_stack_rewritten_in_hia', 'production_activated'}
            and build['schema'] == 'hepta.hia.core-compare-build.v1'
            and build['status'] == 'NATIVE_CANDIDATE_BUILT' and build['profile'] == PROFILE
            and build['manifest'] == manifest and build['source_manifest'] == context['source_manifest']
            and build['cold_report_sha256'] == context['cold_sha256']
            and build['original_Core_39_units_unchanged'] is True
            and build['numeric_comparison_control_in_HIA'] is True
            and build['CPython_primitives_still_hosted'] is True
            and build['whole_stack_rewritten_in_hia'] is False and build['production_activated'] is False,
            'numeric companion is not a complete matching-source cold build')
    files = [file_record(folder / 'manifest.json'), image_pin, file_record(folder / 'build.json')]
    return {'manifest': manifest, 'files': files, 'sources': sources, 'abi': abi,
            'compile_originals': compile_originals(folder, manifest, build['native_compile_receipt'], context)}


def admitted_companion(binding):
    value = {key: item for key, item in binding['manifest'].items() if key not in ('schema', 'image_path')}
    return {**value, 'manifest_sha256': binding['files'][0]['sha256']}


def implementation_digest(binding):
    from hepta import hia_core_compare_selection as selection
    admitted = admitted_companion(binding)
    values = [selection.SCHEMA, admitted['manifest_sha256'], admitted['compiler_sha256'], admitted['image_sha256']]
    for name in sorted(binding['sources']):
        values.extend((name, binding['sources'][name]))
    return sha256('\0'.join(values).encode('ascii')).hexdigest()


def validate_installed(value, binding):
    from hepta import hia_core_compare_selection as selection
    require(type(value) is dict
            and value.get('schema') == 'hepta.hia.core-compare-installed-observation.v1'
            and value.get('actual_step_semantics') == STEP_MEANING
            and value.get('retained_builtin_target_forbidden') is True
            and value.get('retained_builtin_target_entries') == []
            and value.get('CPython_object_primitives_still_hosted') is True,
            'installed numeric scope or actual-step meaning differs')
    for key, expected in admitted_companion(binding).items():
        require(value.get(key) == expected, 'installed numeric image/source/compiler differs: ' + key)
    counts = [value.get(key) for key in ('ordinary_step_returns', 'window_probe_step_returns', 'actual_step_returns')]
    require(all(type(count) is int and count > 0 for count in counts)
            and counts[0] + counts[1] == counts[2], 'installed numeric actual return counts differ')
    ordinary = value.get('ordinary_statuses')
    require(type(ordinary) is list and ordinary in ([0], [0, 1])
            and all(type(status) is int for status in ordinary)
            and value.get('window_probe_statuses') == [0, 1]
            and value.get('actual_statuses') == [0, 1]
            and all(type(status) is int for status in value['window_probe_statuses'] + value['actual_statuses']),
            'installed numeric ordinary and separate window returns differ')
    effects = value.get('ordinary_eligible_effects')
    require(type(effects) is list and effects
            and all(type(row) is dict and set(row) == {'operation', 'returned'}
                    and type(row['operation']) is int and 1 <= row['operation'] <= 6
                    and row['returned'] is True for row in effects),
            'installed eligible effects were omitted or not completed')
    require(value.get('window_probe') == {
                'operation': 3, 'left': '1<<1025', 'right': '(1<<1025)+1', 'predicate': True}
            and type(value['window_probe']['operation']) is int
            and value['window_probe']['predicate'] is True
            and value.get('refusals') == [name + suffix for name in (selection.ABI_SOURCE, selection.HIA_SOURCE)
                                        for suffix in (':changed', ':missing')]
            and value.get('restored_identity_sha256') == implementation_digest(binding),
            'installed numeric window, source refusals or final restoration differs')
    return value


def validate_returns(value, groups, image_sha256):
    """Independently join attempts, eligibility and actual returned HIA steps."""
    require(type(value) is dict and value.get('native_step_semantics') == STEP_MEANING
            and value.get('fixture_step_rows_are_not_test_pass') is True
            and value.get('retained_builtin_target_entries') == [],
            'numeric ledger meaning or retained builtin entries differ')
    labels = {'component', 'original-machine', 'original-core'}
    require(type(groups) is dict and set(groups.values()) == labels and len(groups) == 116,
            'numeric ledger requires all original Core116 IDs')
    def belongs(test, group):
        return (groups.get(test) == group or test == '@fixture:' + group) and group in labels
    def counter(field):
        rows = value.get(field)
        require(type(rows) is list, 'numeric original effect rows missing: ' + field)
        result = {}
        for row in rows:
            require(type(row) is dict and set(row) == {'group', 'test', 'operation', 'image_sha256', 'count'}
                    and type(row['group']) is str and type(row['test']) is str
                    and belongs(row['test'], row['group'])
                    and type(row['operation']) is int and 1 <= row['operation'] <= 8
                    and row['image_sha256'] == image_sha256
                    and type(row['count']) is int and row['count'] > 0,
                    'numeric effect record differs: ' + field)
            key = (row['group'], row['test'], row['operation'], row['image_sha256'])
            require(key not in result, 'duplicate numeric effect row: ' + field)
            result[key] = row['count']
        return result
    attempts = counter('outer_opcode13_attempts')
    eligible = counter('outer_opcode13_eligible')
    normal = counter('outer_opcode13_normal_returns')
    failed = counter('outer_opcode13_exceptions')
    eligible_normal = counter('eligible_normal_returns')
    eligible_failed = counter('eligible_exceptions')
    failed_completions = counter('eligible_exception_terminal_returns')
    require(attempts and eligible and set(normal) | set(failed) == set(attempts)
            and all(normal.get(key, 0) + failed.get(key, 0) == count for key, count in attempts.items())
            and all(key[2] <= 6 and count <= attempts.get(key, 0) for key, count in eligible.items()),
            'numeric attempts, eligibility or normal/exception accounting differs')
    require(set(eligible_normal) | set(eligible_failed) == set(eligible)
            and all(eligible_normal.get(key, 0) + eligible_failed.get(key, 0) == count
                    for key, count in eligible.items())
            and all(count <= normal.get(key, 0) for key, count in eligible_normal.items())
            and all(count <= failed.get(key, 0) for key, count in eligible_failed.items())
            and all(count <= eligible_failed.get(key, 0) for key, count in failed_completions.items()),
            'eligible normal/exception accounting differs from actual dispatch')
    rows = value.get('actual_numeric_step_returns')
    require(type(rows) is list and rows, 'actual numeric step-return matrix is empty')
    seen, completions, statuses = set(), {}, {label: set() for label in labels}
    for row in rows:
        require(type(row) is dict and set(row) == {'group', 'test', 'operation', 'image_sha256', 'status', 'count'}
                and type(row['group']) is str and type(row['test']) is str
                and belongs(row['test'], row['group'])
                and type(row['operation']) is int and 1 <= row['operation'] <= 6
                and row['image_sha256'] == image_sha256
                and type(row['status']) is int and row['status'] in (0, 1)
                and type(row['count']) is int and row['count'] > 0,
                'numeric actual-step record differs')
        key = (row['group'], row['test'], row['operation'], row['image_sha256'])
        full = (*key, row['status'])
        require(full not in seen and key in eligible, 'duplicate or unbound numeric actual-step row')
        seen.add(full)
        statuses[row['group']].add(row['status'])
        if row['status'] == 0:
            completions[key] = row['count']
    wanted_completions = {key: eligible_normal.get(key, 0) + failed_completions.get(key, 0)
                          for key in set(eligible_normal) | set(failed_completions)}
    require(all(0 in status for status in statuses.values()) and completions == wanted_completions,
            'every eligible normal return needs its actual completion; attempts are not returns')
    vm = value.get('independent_Core_VM_effects_not_native_proof')
    require(type(vm) is list, 'independent Core VM exclusion ledger missing')
    vm_seen = set()
    for row in vm:
        require(type(row) is dict and set(row) == {'group', 'test', 'operation', 'count'}
                and row['group'] == 'component' and groups.get(row['test']) == 'component'
                and '.CoreLoweringSourceTests.' in row['test']
                and type(row['operation']) is int and 1 <= row['operation'] <= 8
                and type(row['count']) is int and row['count'] > 0,
                'unadmitted source-VM effect was mislabeled native')
        key = (row['test'], row['operation'])
        require(key not in vm_seen, 'duplicate source-VM exclusion')
        vm_seen.add(key)
    return {'actual_step_returns': rows, 'eligible_effects': value['outer_opcode13_eligible'],
            'retained_builtin_target_entries': [], 'fixture_steps_are_not_method_success': True,
            'all116_methods_required_separately': True,
            'independent_Core_VM_effects_not_native_proof': vm}
