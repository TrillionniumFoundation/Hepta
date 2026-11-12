"""Read original Core39/116 plus the independently selected UNPACK observations.

The retained Core reader keeps its original 39-unit, 36-mode and 116-ID gates.
The additional companion and component readers add conjunctions; they do not
turn three separate owners into a single cold qualification.
"""
from __future__ import annotations
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import zipfile
from common import (GENERATED, LIMITS, COMPILE_SUFFIXES, document, inspect_file, read, require,
                    retained, snapshot, tree_identity)

def bundle(root, policy, compiler_sha):
    manifest, pin = document(root / 'manifest.json', 16384)
    names = policy['unit_names']
    require(manifest == {'schema': 'hepta.hia.core-lowering-native.v2',
                        'abi_sha256': policy['original_generated_assets']['abi_sha256'],
                        'compiler_sha256': compiler_sha,
                        'unit_manifests': {name: name + '/manifest.json' for name in names}},
            'actual complete v2 bundle manifest differs')
    originals = [pin]
    image_hashes = {}
    source_hashes = {}
    for name in manifest['unit_manifests']:
        unit, unit_pin = document(root / name / 'manifest.json', 16384)
        require(set(unit) == {'schema', 'source_sha256', 'image_path',
                             'image_sha256', 'compiler_sha256'}
                and unit['schema'] == 'hepta.hia.core-lowering-unit-native.v2'
                and unit['compiler_sha256'] == compiler_sha,
                'native unit schema/compiler binding differs')
        path = Path(unit['image_path'])
        require(not path.is_absolute() and path.name == unit['image_path'],
                'unit image is not a sibling basename')
        _, image_pin = inspect_file(root / name / path, 1048576)
        source = 'examples/hia_bootstrap/' + name + '.hiaasm'
        wanted = policy['original_generated_assets']['sources'][source]
        require(unit['source_sha256'] == wanted['sha256']
                and unit['image_sha256'] == image_pin['sha256'] and image_pin['bytes'] > 0,
                'unit source/image original bytes differ')
        originals += [unit_pin, image_pin]
        image_hashes[name] = image_pin['sha256']
        source_hashes[name] = wanted['sha256']
    require(len(originals) == 79 and len(image_hashes) == 39, 'complete actual bundle denominator differs')
    return {'manifest': manifest, 'manifest_original': pin, 'files': originals,
            'image_sha256': [image_hashes[name] for name in names], 'source_sha256': source_hashes}

def compile_record(folder, label, wanted, receipt, artifact, input_pin, produced, runner_sha):
    require(wanted['stage'] == label and type(wanted['files']) is list
            and len(wanted['files']) == 6, 'complete compile original denominator differs')
    raws, originals = {}, []
    for suffix, pin in zip(COMPILE_SUFFIXES, wanted['files']):
        path = folder / (label + suffix)
        raw, observed = retained(path, pin, 2 << 20)
        require(observed == pin, 'compile original file identity or bytes changed')
        raws[suffix] = raw
        originals.append(observed)
    require(json.loads(raws['.receipt.json']) == receipt,
            'native compile original receipt differs from the retained report')
    produced_fields = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format',
                       'runner_sha256', 'wall_elapsed_ns', 'produced_image',
                       'produced_bytes', 'produced_sha256'}
    child = json.loads(raws['.stdout.log'])
    require(child == {name: value for name, value in receipt.items() if name not in produced_fields},
            'native compile receipt does not retain the actual child stdout')
    require(receipt['case'] == label and receipt['runner_sha256'] == runner_sha
            and receipt['limits'] == {'cpu_seconds': 10, 'address_bytes': 256 << 20,
                 'core_dumpable': False, 'stack_bytes': 8 << 20,
                 'output_capacity': 1048576, 'workspace_bytes': 1048576}
            and receipt['core_u32'] == produced['bytes']
            and receipt['produced_image'] == produced['path']
            and receipt['image_sha256'] == artifact['sha256']
            and receipt['source_sha256'] == receipt['input_sha256'] == input_pin['sha256']
            and receipt['input_bytes'] == input_pin['bytes'],
            'actual child source, image, runner or original resource ceilings differ')
    require(json.loads(raws['.request.json']) == {
                'format': receipt['format'], 'image': artifact['path'],
                'image_sha256': artifact['sha256'], 'source': str(folder / (label + '.input.bin')),
                'source_sha256': input_pin['sha256'], 'capacity': 1048576,
                'workspace_size': 1048576, 'workspace_fill': 0,
                'output': str(folder / (label + '.output.bin'))},
            'actual native compile request differs')
    require(len(raws['.input.bin']) == input_pin['bytes']
            and sha256(raws['.input.bin']).hexdigest() == input_pin['sha256']
            and len(raws['.output.bin']) == 1048576
            and sha256(raws['.output.bin']).hexdigest() == receipt['output_sha256']
            and sha256(raws['.output.bin'][:produced['bytes']]).hexdigest() == produced['sha256'],
            'actual native compile input/output or produced prefix differs')
    return {'stage': label, 'files': originals}

def source_idempotence(initial, before, derived, after, policy, report):
    """Bind all source bytes/modes, including both regenerated JSON inputs."""
    require(initial == before == derived == after
            and len(before['rows']) == policy['candidate']['leaves']
            and tree_identity(before['rows']) == policy['candidate']['tree']
            and before['actual_worktree_tree'] == policy['candidate']['tree']
            and report['derived_worktree_tree'] == policy['candidate']['tree']
            and report['derived_source_delta'] == []
            and report['mutable_source_paths'] == []
            and report['regenerated_source_paths'] == list(GENERATED)
            and report['source_derivation_idempotent'] is True
            and report['derived_tree_has_published_commit'] is True,
            'actual complete source is not the exact idempotently regenerated candidate')

def preparation_core39(root, source, context, policy):
    evidence = root / 'preparation'
    report, report_pin = document(evidence / 'report.json', 8 << 20)
    require(report['schema'] == 'hia.core-unpack-native-preparation.v1'
            and report['status'] == 'DEVELOPMENT_B0_B1_B2_39_BUILT'
            and report.get('error') is None and report.get('preservation_error') is None
            and report['candidate'] == policy['candidate']
            and report['context_sha256'] == inspect_file(root / 'context.json')[1]['sha256']
            and report['policy_sha256'] == context['policy_sha256']
            and report['controller_seconds'] == 180 and report['cleanup_seconds'] == 3
            and report['compile_child_wall_seconds'] == 20
            and report['compile_child_CPU_seconds'] == 10
            and report['original_compile_capacity_bytes'] == 1048576
            and report['unchanged_limits'] == LIMITS,
            'complete development preparation status, scope, or bounds differ')
    for name in ('generated_HIA_sources_recreated', 'cold_qualified', 'old_compiler_image_reused',
                 'B3_or_mutation_qualified', 'complete_116_tests_executed', 'whole_native_claimed',
                 'original_limits_changed', 'production_activated', 'desktop_interpreter_identity_claimed'):
        require(report[name] is False, 'preparation widened its actual scope')
    require(report['source_preserved_except_declared_derivations'] is True
            and report['source_stable_after_derivation'] is True
            and report['actual_HEAD_remains_initial_candidate'] is True
            and report['original_generated_asset_identity_verified'] is True
            and report['mutable_source_paths'] == []
            and report['regenerated_source_paths'] == list(GENERATED)
            and report['source_derivation_idempotent'] is True
            and report['derived_tree_has_published_commit'] is True,
            'preparation immutable source boundaries differ')
    initial, initial_pin = document(root / 'initial-source.json', 8 << 20)
    originals = {'report': report_pin, 'initial_source': initial_pin}
    snapshots = {}
    for name, key in (('source-before.json', 'source_before'),
                      ('derived-source.json', 'derived_source'), ('source-after.json', 'source_after')):
        raw, pin = retained(evidence / name, report[key], 8 << 20)
        snapshots[key] = json.loads(raw)
        originals[key] = pin
    before, derived, after = (snapshots[name] for name in ('source_before', 'derived_source', 'source_after'))
    source_idempotence(initial, before, derived, after, policy, report)
    require(snapshot(source, context['git']['resolved'], policy['candidate'], derived['rows']) == derived,
            'current complete derived source is not the captured source')
    for name in GENERATED:
        raw, pin = retained(evidence / 'derived' / Path(name).name, report['derived_originals'][name])
        require(raw == read(source / name)[0], 'actual derived JSON original is not the tested source')
        originals[name] = pin
        final_raw, final_pin = retained(evidence / ('final-' + Path(name).name),
                                        report['final_inventory_originals'][name])
        require(final_raw == raw, 'final retained generated inventory differs')
        originals['final:' + name] = final_pin
    require(len(report['derived_commands']) == 3
            and all(row['returncode'] == 0 for row in report['derived_commands']),
            'derived inventory/check execution is incomplete')
    for index, row in enumerate(report['derived_commands']):
        for kind in ('stdout', 'stderr'):
            retained(evidence / ('derive-%02d.%s.log' % (index, kind)), row[kind])

    compiler, compiler_pin = retained(Path(report['compiler_original']['path']),
                                      report['compiler_original'], 1048576)
    require(Path(compiler_pin['path']) == evidence / 'bootstrap/B2.image.bin',
            'development compiler location differs')
    native = evidence / 'bootstrap'
    seed, seed_pin = retained(native / 'B0.so', report['B0_originals']['image'], 64 << 20)
    seed_raw, seed_receipt_pin = retained(native / 'B0.receipt.json',
                                         report['B0_originals']['receipt'], 2 << 20)
    require(json.loads(seed_raw) == report['B0'] and seed_pin == report['B0_originals']['image']
            and seed_receipt_pin == report['B0_originals']['receipt'],
            'actual B0 seed receipt/image identity differs from the report')
    first, first_pin = read(native / 'B1.image.bin', 1048576)
    require(first == compiler and report['B1_equals_B2'] is True
            and report['B0']['seed_only'] is True, 'actual B0/B1/B2 development boundary differs')
    compile_pins = report['compile_originals']
    require(type(compile_pins) is list and len(compile_pins) == 41
            and [item['stage'] for item in compile_pins] == ['B1', 'B2', *policy['unit_names']],
            'complete original 41 native compile stages differ')
    selfhost_pin = inspect_file(source / 'examples/hia_bootstrap/selfhost.hiaasm', 1048576)[1]
    require(selfhost_pin == report['selfhost_source'], 'actual bootstrap source original differs')
    runner_sha = inspect_file(source / 'tools/hia_selfhost_child.py')[1]['sha256']
    observed_compile = []
    for index, (label, artifact, produced, input_format) in enumerate((
            ('B1', seed_pin, first_pin, 'seed-shared'),
            ('B2', first_pin, compiler_pin, 'flat-x86-64'))):
        value = report[label]
        require(value['status'] == 'returned' and value['abi_status'] == 0
                and value['source_unchanged'] is True and value['forbidden_compiler_modules_loaded'] == []
                and value['format'] == input_format and value['artifact_sha256'] == artifact['sha256']
                and value['produced_sha256'] == produced['sha256']
                and value['produced_bytes'] == produced['bytes'],
                'actual new compiler generation receipt differs')
        observed_compile.append(compile_record(native, label, compile_pins[index], value,
                                                artifact, selfhost_pin, produced, runner_sha))
    observed_bundle = bundle(evidence / 'bundle', policy, compiler_pin['sha256'])
    require([row['name'] for row in report['unit_receipts']] == policy['unit_names'],
            'actual complete 39 compile receipt order differs')
    for index, (item, name) in enumerate(zip(report['unit_receipts'], policy['unit_names']), 2):
        folder = evidence / 'bundle' / name
        receipt = item['native_compile_receipt']
        image_pin = retained(Path(item['image_original']['path']), item['image_original'], 1048576)[1]
        source_name = 'examples/hia_bootstrap/' + name + '.hiaasm'
        input_pin = policy['original_generated_assets']['sources'][source_name]
        require(item['source'] == source_name
                and receipt['status'] == 'returned' and receipt['abi_status'] == 0
                and receipt['source_unchanged'] is True and receipt['forbidden_compiler_modules_loaded'] == []
                and receipt['input_sha256'] == input_pin['sha256']
                and receipt['artifact_sha256'] == compiler_pin['sha256']
                and receipt['format'] == 'flat-x86-64'
                and receipt['produced_sha256'] == image_pin['sha256']
                and receipt['produced_bytes'] == image_pin['bytes'],
                'actual unit receipt/image/compiler binding differs')
        observed_compile.append(compile_record(folder, name, compile_pins[index], receipt,
                                                compiler_pin, input_pin, image_pin, runner_sha))
    build, build_pin = document(evidence / 'bundle/build.json', 8 << 20)
    require(build['schema'] == 'hia.core-emitter-development-build.v1'
            and build['status'] == 'DEVELOPMENT_39_UNIT_BUNDLE_BUILT'
            and build['scope'] == 'CURRENT_SOURCE_B0_B1_B2_DEVELOPMENT_NOT_COLD'
            and build['bundle'] == observed_bundle['manifest']
            and build['compiler_sha256'] == compiler_pin['sha256']
            and build['units'] == report['unit_receipts']
            and build['source_manifest'] == report['development_source_manifest']
            and build['actual_unit_count'] == build['expected_unit_count'] == 39
            and build['cold_qualified'] is False, 'original development build receipt differs')
    observed_files = {pin['path']: pin for pin in observed_bundle['files']}
    expected_build_files = []
    for name in policy['unit_names']:
        expected_build_files.extend(observed_files[str(evidence / 'bundle' / name / suffix)]
                                    for suffix in ('manifest.json', name + '.image.bin'))
    expected_build_files.extend((observed_bundle['manifest_original'], build_pin))
    require(report['build_files'] == expected_build_files and len(expected_build_files) == 80,
            'complete actual preparation build-file inventory differs')
    current_rows = {row['path']: row for row in derived['rows']}
    require(build['source_manifest'] and all(current_rows[name]['sha256'] == wanted
            for name, wanted in build['source_manifest'].items()), 'source manifest is not the derived tree')
    return {'report_original': report_pin, 'report': report, 'derived_source': derived,
            'compiler_original': compiler_pin, 'build_original': build_pin,
            'bundle': observed_bundle, 'retained_originals': originals,
            'compile_originals': observed_compile,
            'B0_originals': {'image': seed_pin, 'receipt': seed_receipt_pin}}

def selected_callers_core39(root, source, context, policy, prepared):
    evidence = root / 'callers/core-callers'
    report, report_pin = document(evidence / 'report.json', 8 << 20)
    require(report['schema'] == 'hepta.hia.core-lowering-selected-callers.v2'
            and report['status'] == 'PASS' and report['scope'] == 'EXPLICIT_DEVELOPMENT_ONLY'
            and report.get('exception') is None and report.get('final_identity_error') is None
            and report['development_group'] is None
            and report['complete_three_groups_required_for_qualification'] is True
            and report['complete_three_groups_executed'] is True
            and report['expected_groups'] == ['component', 'original-core', 'original-machine']
            and report['expected_bundle_roles'] == ['caller', 'component']
            and report['component_denominator'] == 15
            and report['original_machine_denominator'] == 51 and report['original_core_denominator'] == 50
            and report['public_control_mode_count'] == 33 and report['abi_control_mode_count'] == 36
            and report['private_fixture_modes'] == ['_native_globals']
            and report['private_generator_modes'] == ['_native_generator_0', '_native_generator_1']
            and report['native_step_ledger_schema'] == 'hepta.hia.core-lowering-native-step-returns.v2'
            and report['group_bundle_roles'] == {'component': 'component',
                'original-machine': 'caller', 'original-core': 'caller'}
            and report['native_mode_entries_are_attempts'] is True
            and report['retained_owner_entries'] == [] and report['hosted_primitive_kinds'] == 19
            and report['default_activated'] is False and report['whole_native_claimed'] is False,
            'default complete 116 development qualifier scope differs')
    for flag in ('source_stable', 'manifest_images_bundle_stable', 'caller_bundle_stable',
                 'component_bundle_stable', 'all_required_modes_attempted',
                 'all_required_modes_have_actual_step_returns', 'private_fixture_mode_has_actual_step_returns',
                 'all_generator_modes_have_actual_step_returns', 'all_generator_modes_have_actual_yield_returns',
                 'all_native_step_statuses_observed'):
        require(report[flag] is True, 'missing actual complete native observation: ' + flag)
    require(report['source_before'] == report['source_after']
            == prepared['report']['development_source_manifest'], 'qualifier did not use complete derived closure')
    groups = report['groups']
    require([row['label'] for row in groups] == ['component', 'original-machine', 'original-core'],
            'complete group order differs')
    all_ids = []
    logs = []
    for row in groups:
        expected = policy['test_groups'][row['label']]
        require(row['modules'] == expected['modules'] and row['expected_methods'] == expected['count']
                and row['loaded_ids'] == row['executed_ids'] == row['frozen_original_ids'] == expected['ids']
                and row['tests_run'] == expected['count'] and row['strict_pass'] is True
                and row['loader_errors'] == [], 'original group method identities/denominator differ')
        for field in ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
            require(row[field] == [], 'nonzero original unittest anomaly: ' + field)
        all_ids.extend(row['executed_ids'])
        logs.append(inspect_file(evidence / (row['label'] + '.unittest.log'), 32 << 20)[1])
    require(len(all_ids) == len(set(all_ids)) == 116, 'complete unique 116 method denominator differs')
    compiler_sha = prepared['compiler_original']['sha256']
    observed = bundle(evidence / 'build', policy, compiler_sha)
    require(observed['image_sha256'] == prepared['bundle']['image_sha256'],
            'actual selected caller images differ from the new compiled bundle')
    bindings = [{'path': pin['path'], 'bytes': pin['bytes'], 'sha256': pin['sha256']}
                for pin in observed['files']]
    require(report['manifest'] == str(evidence / 'build/manifest.json')
            and report['manifest_sha256'] == observed['manifest_original']['sha256']
            and report['abi_sha256'] == policy['original_generated_assets']['abi_sha256']
            and report['complete_image_sha256'] == observed['image_sha256']
            and report['input_bindings'] == bindings,
            'actual caller report is not bound to its complete 39 native images')
    for role in ('caller', 'component'):
        value = report['bundle_observations'][role]
        require(value['scope'] == 'EXPLICIT_DEVELOPMENT_ONLY' and value['stable'] is True
                and value['manifest'] == str(evidence / 'build/manifest.json')
                and value['manifest_sha256'] == value['bundle_sha256'] == observed['manifest_original']['sha256']
                and value['abi_sha256'] == report['abi_sha256']
                and value['unit_names'] == policy['unit_names']
                and value['unit_image_sha256'] == observed['image_sha256']
                and value['source_sha256'] == observed['source_sha256']
                and value['input_bindings_before'] == value['input_bindings_after'] == bindings,
                'actual development bundle observation differs')
    abi, _ = document(source / 'hepta/hia_core_lowering_abi.json', 1 << 20)
    modes = abi['modes']
    private = {'_native_globals', '_native_generator_0', '_native_generator_1'}
    public = set(modes) - private
    require(len(modes) == 36 and len(public) == 33, 'full public/private ABI mode denominator differs')
    totals, per_group, witnessed, yielded = Counter(), Counter(), set(), set()
    component_private, component_yielded = set(), set()
    entries = report['native_step_returns']
    require(type(entries) is list and entries, 'no actual HIA step return observations')
    keys = set()
    for row in entries:
        require(row['group'] in policy['test_groups'] and row['mode'] in modes
                and type(row['count']) is int and row['count'] > 0
                and type(row['status']) is int and row['status'] in (0, 1, 2, 3)
                and type(row['unit_index']) is int and 0 <= row['unit_index'] < 38
                and row['bundle_image_index'] == row['unit_index'] + 1
                and row['unit_name'] == policy['unit_names'][row['bundle_image_index']]
                and row['image_sha256'] == observed['image_sha256'][row['bundle_image_index']]
                and row['mode_number'] == modes[row['mode']]['number']
                and row['abi_sha256'] == report['abi_sha256']
                and row['bundle_sha256'] == observed['manifest_original']['sha256'],
                'actual step matrix row differs from its mode/unit/image')
        key = (row['group'], row['mode'], row['unit_index'], row['status'])
        require(key not in keys, 'duplicate native step matrix key')
        keys.add(key)
        totals[str(row['status'])] += row['count']
        per_group[row['group']] += row['count']
        witnessed.add(row['mode'])
        if row['group'] == 'component' and row['mode'] in private:
            component_private.add(row['mode'])
        if row['status'] == 3:
            yielded.add(row['mode'])
            if row['group'] == 'component':
                component_yielded.add(row['mode'])
    require(dict(totals) == report['actual_native_step_statuses'] and set(totals) == {'0', '1', '2', '3'}
            and set(per_group) == set(policy['test_groups']) and public <= witnessed
            and '_native_globals' in component_private
            and {'_native_generator_0', '_native_generator_1'} <= yielded
            and {'_native_generator_0', '_native_generator_1'} <= component_yielded,
            'complete actual step coverage does not support the report')
    installed = installed_control(evidence / 'component-fixture/installed-control', source,
                                  observed, policy)
    return {'report_original': report_pin, 'complete_method_count': 116, 'unique_test_ids': all_ids,
            'unittest_log_originals': logs, 'bundle': observed,
            'actual_step_totals': dict(totals), 'group_actual_step_totals': dict(per_group),
            'public_actual_modes': sorted(public & witnessed), 'private_actual_modes': sorted(private & witnessed),
            'component_private_actual_modes': sorted(component_private),
            'component_actual_yield_modes': sorted(component_yielded),
            'installed': installed, 'cold_qualified': False, 'one_original_180_second_owner_required': True}

def installed_control(case, source, caller_bundle, policy):
    expected, expected_pin = document(case / 'expected.json', 8 << 20)
    installed, installed_pin = document(case / 'report.json', 8 << 20)
    processes, process_pin = document(case / 'processes.json')
    require(type(processes) is list and len(processes) == 3
            and all(row['returncode'] == 0 for row in processes), 'actual wheel/installed process failed')
    for row, label in zip(processes, ('wheel-build', 'wheel-install', 'installed-execution')):
        for stream in ('stdout', 'stderr'):
            _, pin = inspect_file(case / (label + '.' + stream), 32 << 20)
            require(pin['sha256'] == row[stream + '_sha256'], 'installed raw stream differs')
    require(processes[2]['argv'][1:4] == ['-I', '-S', '-B']
            and Path(processes[2]['argv'][4]) == case / 'installed-child.py'
            and installed['status'] == 'INSTALLED_CORE_LOWERING_PASS'
            and installed['units'] == 39
            and installed['source_sha256'] == caller_bundle['source_sha256']
            and installed['abi_sha256'] == policy['original_generated_assets']['abi_sha256']
            and installed['image_sha256'] == caller_bundle['image_sha256']
            and type(installed['actual_native_steps']) is int and installed['actual_native_steps'] > 0
            and all(installed[flag] is True for flag in ('retained_lowering_forbidden',
                'authoring_forbidden', 'isolated_without_site', 'empty_PATH')),
            'actual installed child scope or native bundle differs')
    stdout, _ = read(case / 'installed-execution.stdout', 8 << 20)
    require(json.loads(stdout) == installed, 'installed report does not equal actual child stdout')
    for name, digest in expected['python'].items():
        require(inspect_file(source / name)[1]['sha256']
                == inspect_file(case / 'installed' / name)[1]['sha256'] == digest,
                'installed Python original differs from actual source')
    for name, digest in expected['resources'].items():
        require(inspect_file(source / name)[1]['sha256']
                == inspect_file(case / 'installed/hepta/_data' / name)[1]['sha256'] == digest,
                'installed package resource differs from actual source')
    require(installed['python_files'] == len(expected['python'])
            and installed['resource_files'] == len(expected['resources'])
            and {'examples/hia_bootstrap/' + name + '.hiaasm' for name in policy['unit_names']}
                <= set(expected['resources'])
            and 'hepta/hia_core_lowering_abi.json' in expected['resources'],
            'complete installed source/resource denominator differs')
    wheels = list((case / 'wheels').glob('*.whl'))
    require(len(wheels) == 1, 'one actual wheel required')
    _, wheel_pin = inspect_file(wheels[0], 128 << 20)
    with zipfile.ZipFile(wheels[0]) as archive:
        require(archive.testzip() is None, 'actual wheel CRC failure')
    return {'report_original': installed_pin, 'expected_original': expected_pin,
            'processes_original': process_pin, 'wheel_original': wheel_pin,
            'actual_originals_and_installed_resources_verified': True}


def preparation(root, source, context, policy):
    result = preparation_core39(root, source, context, policy)
    report = result['report']
    require(report['companion_status'] == 'DEVELOPMENT_UNPACK_IMAGE_BUILT'
            and report['total_actual_compile_stage_count'] == 42,
            'actual independent UNPACK compilation was not completed')
    folder = root / 'preparation/unpack'
    manifest, manifest_pin = document(folder / 'manifest.json', 16384)
    fields = {'source_sha256': 'examples/hia_bootstrap/core_unpack.hiaasm',
              'abi_sha256': 'hepta/hia_core_unpack_abi.json',
              'bridge_sha256': 'hepta/hia_core_unpack_native.py',
              'selection_sha256': 'hepta/hia_core_unpack_selection.py'}
    hashes = {field: policy['unpack_inputs'][name]['sha256'] for field, name in fields.items()}
    image_raw, image_pin = read(folder / 'core-unpack.image.bin', 1048576)
    compiler = result['compiler_original']
    expected = {'schema': 'hepta.hia.core-unpack-native.v1', **hashes,
                'image_path': 'core-unpack.image.bin', 'image_sha256': image_pin['sha256'],
                'compiler_sha256': compiler['sha256']}
    require(manifest == report['companion_manifest'] == expected and image_raw,
            'UNPACK image manifest differs from its exact sources/compiler/image')
    for field, name in fields.items():
        raw, pin = read(source / name, 1 << 20)
        require(pin['sha256'] == hashes[field]
                and pin['git_blob_sha1'] == policy['unpack_inputs'][name]['git_blob_sha1']
                and pin['bytes'] == policy['unpack_inputs'][name]['bytes']
                and report['development_source_manifest'][name] == pin['sha256'],
                'UNPACK source/ABI/bridge/selection is not the current complete source')
    receipt = report['companion_native_compile_receipt']
    require(receipt['status'] == 'returned' and receipt['abi_status'] == 0
            and receipt['source_unchanged'] is True and receipt['forbidden_compiler_modules_loaded'] == []
            and receipt['format'] == 'flat-x86-64'
            and receipt['artifact_sha256'] == compiler['sha256']
            and receipt['input_sha256'] == hashes['source_sha256']
            and receipt['produced_sha256'] == image_pin['sha256']
            and receipt['produced_bytes'] == image_pin['bytes'],
            'UNPACK original native compile receipt differs')
    original = compile_record(folder, 'core-unpack', report['companion_compile_original'],
        receipt, compiler, policy['unpack_inputs'][fields['source_sha256']], image_pin,
        inspect_file(source / 'tools/hia_selfhost_child.py')[1]['sha256'])
    build, build_pin = document(folder / 'build.json', 8 << 20)
    require(build == {'schema': 'hia.core-unpack-development-build.v1',
            'status': 'DEVELOPMENT_UNPACK_IMAGE_BUILT',
            'scope': 'CURRENT_SOURCE_B0_B1_B2_DEVELOPMENT_NOT_COLD',
            'candidate': policy['candidate'], 'source_manifest': report['development_source_manifest'],
            'derived_worktree_tree': result['derived_source']['actual_worktree_tree'],
            'manifest': manifest, 'native_compile_receipt': receipt,
            'cold_qualified': False, 'CPython_primitives_still_hosted': True,
            'whole_stack_rewritten_in_hia': False, 'production_activated': False}
            and report['companion_build_files'] == [manifest_pin, image_pin, build_pin],
            'UNPACK complete actual build originals differ')
    result['companion'] = {'manifest': manifest, 'manifest_original': manifest_pin,
                          'image_original': image_pin, 'build_original': build_pin,
                          'compile_original': original}
    return result


def components(root, source, context, policy, prepared):
    directory = root / 'components'
    report, report_pin = document(directory / 'report.json', 8 << 20)
    require(report['schema'] == 'hia.core-unpack-components.v1'
            and report['status'] == 'DEVELOPMENT_ALL_18_COMPONENT_METHODS_PASS'
            and report.get('error') is None and report.get('preservation_error') is None
            and report['candidate'] == policy['candidate']
            and report['policy_sha256'] == context['policy_sha256']
            and report['context_sha256'] == inspect_file(root / 'context.json')[1]['sha256']
            and report['controller_seconds'] == 180 and report['cleanup_seconds'] == 3
            and report['expected_groups'] == [4, 6, 8] and report['expected_method_count'] == 18
            and report['cold_qualified'] is False and report['complete_original116_executed'] is False
            and report['CPython_primitives_still_hosted'] is True
            and report['source_stable'] is True
            and report['source_before'] == report['source_after']
                == prepared['report']['development_source_manifest'],
            'complete 18 component result/scope/source differs')
    require([row['label'] for row in report['groups']] == ['shim', 'finite-native', 'ordinary'],
            'complete component group order differs')
    originals = [report_pin]
    expected_paths = [root / 'preparation/bundle/manifest.json',
                      root / 'preparation/unpack/manifest.json',
                      root / 'preparation/unpack/core-unpack.image.bin',
                      source / 'hepta/hia_core_unpack_native.py',
                      source / 'tools/hia_core_unpack_transaction.S',
                      root / 'control/finite_controls.py', root / 'control/finite_launcher.py']
    observed = [read(path, 1 << 20)[1] for path in expected_paths]
    require(observed == report['input_originals_before'] == report['input_originals_after'],
            'actual 18 component source/image identities changed')
    for row, label, phase in zip(report['groups'][:2], ('shim', 'finite-native'), ('shim', 'native')):
        actual, pin = document(directory / label / 'report.json', 2 << 20)
        expected = policy['component_groups'][label]['ids']
        require(row['report'] == actual and row['report_original'] == pin and row['returncode'] == 0
                and actual['status'] == 'EXPERIMENTAL_CONTROL_PASS' and actual['phase'] == phase
                and actual['loaded_test_ids'] == actual['executed_test_ids'] == expected
                and actual['tests_run'] == len(expected)
                and all(actual[name] == 0 for name in ('failures', 'errors', 'skipped',
                    'expected_failures', 'unexpected_successes'))
                and actual['source_stable'] is True and actual['source_before'] == actual['source_after']
                and actual['shim_sha256'] == policy['unpack_transaction']['sha256'],
                'complete original finite group differs')
        paths = [root / 'control/finite_controls.py', source / 'hepta/hia_core_unpack_native.py',
                 source / 'tools/hia_core_unpack_transaction.S']
        if phase == 'native':
            paths.append(root / 'preparation/unpack/core-unpack.image.bin')
        require(actual['source_before'] == {str(path): read(path, 1 << 20)[1]['sha256'] for path in paths},
                'finite control did not bind exact new runtime source/image')
        command = [context['python']['resolved'], '-I', '-S', '-B', str(root / 'control/finite_launcher.py'),
                   str(source), '--phase', phase, '--bridge', str(source / 'hepta/hia_core_unpack_native.py'),
                   '--shim-source', str(source / 'tools/hia_core_unpack_transaction.S'),
                   '--evidence-dir', str(directory / label)]
        if phase == 'native':
            command += ['--image', str(root / 'preparation/unpack/core-unpack.image.bin')]
        require(row['command'] == command, 'finite control actual argv differs')
        originals += [pin, inspect_file(directory / label / 'unittest.log', 8 << 20)[1]]
        for stream in ('stdout', 'stderr'):
            _, raw_pin = retained(directory / (label + '.' + stream + '.log'), row[stream], 8 << 20)
            originals.append(raw_pin)
    ordinary = report['groups'][2]
    expected = policy['component_groups']['ordinary']['ids']
    require(ordinary['loaded_ids'] == ordinary['executed_ids'] == expected
            and ordinary['tests_run'] == 8
            and all(ordinary[name] == [] for name in ('loader_errors', 'errors', 'failures',
                'skipped', 'expectedFailures', 'unexpectedSuccesses')), 'complete ordinary eight differs')
    originals.append(inspect_file(directory / 'ordinary.unittest.log', 8 << 20)[1])
    matrix = ordinary['actual_UNPACK_step_returns']
    keys = set()
    for row in matrix:
        key = (row['test'], row['image_sha256'], row['status'])
        require(set(row) == {'test', 'image_sha256', 'status', 'count'}
                and key not in keys and row['test'] in expected
                and row['image_sha256'] == prepared['companion']['manifest']['image_sha256']
                and type(row['status']) is int and row['status'] in (0, 1, 2)
                and type(row['count']) is int and row['count'] > 0,
                'component actual UNPACK return matrix differs')
        keys.add(key)
    require(matrix and {0, 1} <= {key[2] for key in keys}, 'ordinary eight lacks actual native returns')
    return {'report_original': report_pin, 'complete_method_count': 18,
            'groups': [4, 6, 8], 'actual_originals': originals,
            'actual_step_returns': matrix, 'scope': 'DEVELOPMENT_ONLY_NOT_CORE116_OR_COLD'}


def selected_callers(root, source, context, policy, prepared):
    core = selected_callers_core39(root, source, context, policy, prepared)
    report, pin = document(root / 'callers/report.json', 8 << 20)
    manifest = prepared['companion']['manifest']
    admitted = {name: manifest[name] for name in ('source_sha256', 'abi_sha256', 'bridge_sha256',
                'selection_sha256', 'image_sha256', 'compiler_sha256')}
    admitted.update({'manifest_sha256': prepared['companion']['manifest_original']['sha256'],
                     'transaction_sha256': policy['unpack_transaction']['sha256'], 'runtime_profile': 31404})
    identity_parts = ['hepta.hia.core-unpack-native.v1', admitted['manifest_sha256'],
                      admitted['compiler_sha256'], admitted['image_sha256'],
                      admitted['transaction_sha256'], str(admitted['runtime_profile'])]
    identity_sources = {'examples/hia_bootstrap/core_unpack.hiaasm': admitted['source_sha256'],
                        'hepta/hia_core_unpack_abi.json': admitted['abi_sha256'],
                        'hepta/hia_core_unpack_native.py': admitted['bridge_sha256'],
                        'hepta/hia_core_unpack_selection.py': admitted['selection_sha256']}
    for name in sorted(identity_sources):
        identity_parts.extend((name, identity_sources[name]))
    expected_identity = sha256('\0'.join(identity_parts).encode('ascii')).hexdigest()
    require(report['schema'] == 'hepta.hia.core-unpack-selected-callers.v1'
            and report['status'] == 'PASS' and report['scope'] == 'EXPLICIT_DEVELOPMENT_ONLY'
            and report.get('error') is None and report.get('preservation_error') is None
            and report['original_groups'] == [15, 51, 50] and report['original_complete_methods'] == 116
            and report['original_Core_image_count'] == 39 and report['additional_UNPACK_image_count'] == 1
            and report['complete_116_passed'] is True and report['stable'] is True
            and report['outer_opcode14_permission_still_consumed_once'] is True
            and report['old_complete_unpack_entries'] == []
            and report['CPython_object_runtime_still_hosted'] is True
            and report['whole_stack_rewritten_in_hia'] is False and report['default_activated'] is False
            and report['transaction_ABI'] == policy['unpack_transaction']['abi']
            and report['transaction_sha256'] == policy['unpack_transaction']['sha256']
            and report['admitted_companion'] == admitted
            and report['identity_before'] == report['identity_after'] == expected_identity
            and report['source_before'] == report['source_after']
                == prepared['report']['development_source_manifest'],
            'complete original116 UNPACK poison/scope/identity differs')
    expected_files = [prepared['companion'][name] for name in
                      ('manifest_original', 'image_original', 'build_original')]
    simple_pins = [{'path': item['path'], 'size': item['bytes'], 'sha256': item['sha256']}
                   for item in expected_files]
    require(report['companion_inputs_before'] == report['companion_inputs_after'] == simple_pins
            and report['original_report'] == {'path': core['report_original']['path'],
                 'size': core['report_original']['bytes'], 'sha256': core['report_original']['sha256']},
            'wrapper source inputs or original full Core report binding differs')
    require(report['original_qualifier_argv'] == ['qualify_hia_core_lowering_callers.py',
                '--development-manifest', str(root / 'preparation/bundle/manifest.json'),
                '--evidence', str(root / 'callers/core-callers')],
            'the original116 qualifier was split or redirected')
    ids_to_group = {name: label for label, group in policy['test_groups'].items() for name in group['ids']}
    counts = {}
    for field in ('outer_opcode14_attempts', 'outer_opcode14_normal_returns', 'outer_opcode14_exceptions'):
        entries = {}
        for row in report[field]:
            key = (row['group'], row['test'], row['arity'], row['image_sha256'])
            require(set(row) == {'group', 'test', 'arity', 'image_sha256', 'count'}
                    and key not in entries and row['test'] in ids_to_group
                    and row['group'] == ids_to_group[row['test']]
                    and type(row['arity']) is int and 1 <= row['arity'] <= 4
                    and row['image_sha256'] == manifest['image_sha256']
                    and type(row['count']) is int and row['count'] > 0,
                    'outer opcode14 attempt/normal/exception row differs')
            entries[key] = row['count']
        counts[field] = Counter(entries)
    require(counts['outer_opcode14_attempts'] == counts['outer_opcode14_normal_returns']
            + counts['outer_opcode14_exceptions'], 'outer14 attempt accounting does not balance')
    keys, statuses, total = set(), {}, 0
    for row in report['actual_UNPACK_step_returns']:
        key = (row['group'], row['test'], row['arity'], row['image_sha256'])
        full = (*key, row['status'])
        require(set(row) == {'group', 'test', 'arity', 'image_sha256', 'status', 'count'}
                and key in counts['outer_opcode14_attempts'] and full not in keys
                and type(row['arity']) is int and 1 <= row['arity'] <= 4
                and type(row['status']) is int and row['status'] in (0, 1, 2)
                and type(row['count']) is int and row['count'] > 0,
                'actual UNPACK step return row is not bound to a real outer effect')
        keys.add(full); statuses.setdefault(row['group'], set()).add(row['status']); total += row['count']
    require(set(statuses) == set(policy['test_groups'])
            and all({0, 1} <= value for value in statuses.values()),
            'actual UNPACK returns do not cover all original116 groups')
    installed_path = root / 'callers/core-callers/component-fixture/installed-control/report.json'
    installed, installed_pin = document(installed_path, 8 << 20)
    value = installed['unpack_observations']
    expected_refusals = [name + suffix for name in ('hepta/hia_core_unpack_abi.json',
                         'examples/hia_bootstrap/core_unpack.hiaasm') for suffix in (':changed', ':missing')]
    require(report['installed_report'] == {'path': str(installed_path), 'size': installed_pin['bytes'],
                                         'sha256': installed_pin['sha256']}
            and report['installed_observation'] == value
            and value['schema'] == 'hepta.hia.core-unpack-installed-observation.v1'
            and value['retained_unpack_forbidden'] is True and value['runtime_profile'] == 31404
            and value['transaction_sha256'] == admitted['transaction_sha256']
            and value['actual_statuses'] == [0, 1] and type(value['actual_step_returns']) is int
            and value['actual_step_returns'] > 0 and value['refusals'] == expected_refusals
            and all(value[name] == admitted[name] for name in ('source_sha256', 'abi_sha256',
                'bridge_sha256', 'selection_sha256', 'image_sha256', 'compiler_sha256')),
            'actual installed UNPACK returns/refusals/source binding differs')
    processes, _ = document(installed_path.parent / 'processes.json')
    require(processes[2]['argv'][-1] == str(root / 'preparation/unpack/manifest.json')
            and len(processes[2]['argv']) == 9,
            'installed isolated child did not receive the actual paired companion manifest')
    return {'core39_original116': core, 'unpack_report_original': pin,
            'actual_UNPACK_step_total': total, 'installed_UNPACK_observation': value,
            'complete_original_method_count': 116, 'single_original_180_owner_required': True,
            'CPython_primitives_still_hosted': True, 'cold_qualified': False}
