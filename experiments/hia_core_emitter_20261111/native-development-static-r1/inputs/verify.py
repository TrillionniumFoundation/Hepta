"""Read actual development originals; never execute a product or reclassify cold."""
from __future__ import annotations
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import zipfile
from common import (GENERATED, LIMITS, document, inspect_file, read, require,
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

def preparation(root, source, context, policy):
    evidence = root / 'preparation'
    report, report_pin = document(evidence / 'report.json', 8 << 20)
    require(report['schema'] == 'hia.core-emitter-native-preparation.v1'
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
                 'original_limits_changed', 'production_activated', 'desktop_interpreter_identity_claimed',
                 'derived_tree_has_published_commit'):
        require(report[name] is False, 'preparation widened its actual scope')
    require(report['source_preserved_except_declared_derivations'] is True
            and report['source_stable_after_derivation'] is True
            and report['actual_HEAD_remains_initial_candidate'] is True
            and report['original_generated_asset_identity_verified'] is True
            and report['mutable_source_paths'] == list(GENERATED), 'preparation source boundaries differ')
    initial, initial_pin = document(root / 'initial-source.json', 8 << 20)
    originals = {'report': report_pin, 'initial_source': initial_pin}
    snapshots = {}
    for name, key in (('source-before.json', 'source_before'),
                      ('derived-source.json', 'derived_source'), ('source-after.json', 'source_after')):
        raw, pin = retained(evidence / name, report[key], 8 << 20)
        snapshots[key] = json.loads(raw)
        originals[key] = pin
    before, derived, after = (snapshots[name] for name in ('source_before', 'derived_source', 'source_after'))
    require(before == initial and derived == after and before['metadata'] == derived['metadata']
            and before['physical'] == derived['physical']
            and tree_identity(before['rows']) == policy['candidate']['tree']
            and tree_identity(derived['rows']) == derived['actual_worktree_tree']
            and derived['actual_worktree_tree'] == report['derived_worktree_tree'],
            'complete original/derived physical source identity differs')
    changes = [{'path': old['path'], 'before': old, 'after': new}
               for old, new in zip(before['rows'], derived['rows']) if old != new]
    require(len(before['rows']) == len(derived['rows']) == policy['candidate']['leaves']
            and [row['path'] for row in changes] == sorted(GENERATED)
            and changes == report['derived_source_delta']
            and all(row['before']['mode'] == row['after']['mode']
                    and row['before']['posix_mode'] == row['after']['posix_mode'] for row in changes),
            'actual source derivation changed more than the two fixed JSON inventories')
    require(snapshot(source, context['git']['resolved'], policy['candidate'], derived['rows']) == derived,
            'current complete derived source is not the captured source')
    for name in GENERATED:
        raw, pin = retained(evidence / 'derived' / Path(name).name, report['derived_originals'][name])
        require(raw == read(source / name)[0], 'actual derived JSON original is not the tested source')
        originals[name] = pin
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
    first, first_pin = read(evidence / 'bootstrap/B1.image.bin', 1048576)
    require(first == compiler and report['B1_equals_B2'] is True
            and report['B0']['seed_only'] is True, 'actual B0/B1/B2 development boundary differs')
    for label, artifact, input_format in (
            ('B1', read(evidence / 'bootstrap/B0.so', 64 << 20)[1], 'seed-shared'),
            ('B2', first_pin, 'flat-x86-64')):
        value = report[label]
        raw, _ = read(evidence / 'bootstrap' / (label + '.receipt.json'))
        require(json.loads(raw) == value
                and value['status'] == 'returned' and value['abi_status'] == 0
                and value['source_unchanged'] is True and value['forbidden_compiler_modules_loaded'] == []
                and value['format'] == input_format and value['artifact_sha256'] == artifact['sha256']
                and value['produced_sha256'] == compiler_pin['sha256']
                and value['produced_bytes'] == compiler_pin['bytes'],
                'actual new compiler generation receipt differs')
    observed_bundle = bundle(evidence / 'bundle', policy, compiler_pin['sha256'])
    require([row['name'] for row in report['unit_receipts']] == policy['unit_names'],
            'actual complete 39 compile receipt order differs')
    for item, name in zip(report['unit_receipts'], policy['unit_names']):
        folder = evidence / 'bundle' / name
        receipt, _ = document(folder / (name + '.receipt.json'))
        image_pin = retained(Path(item['image_original']['path']), item['image_original'], 1048576)[1]
        require(receipt == item['native_compile_receipt']
                and receipt['status'] == 'returned' and receipt['abi_status'] == 0
                and receipt['source_unchanged'] is True and receipt['forbidden_compiler_modules_loaded'] == []
                and receipt['input_sha256'] == policy['original_generated_assets']['sources'][item['source']]['sha256']
                and receipt['artifact_sha256'] == compiler_pin['sha256']
                and receipt['format'] == 'flat-x86-64'
                and receipt['produced_sha256'] == image_pin['sha256']
                and receipt['produced_bytes'] == image_pin['bytes'],
                'actual unit receipt/image/compiler binding differs')
        for suffix in ('.stdout.log', '.stderr.log', '.request.json', '.input.bin', '.output.bin'):
            inspect_file(folder / (name + suffix), 2 << 20)
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
    current_rows = {row['path']: row for row in derived['rows']}
    require(build['source_manifest'] and all(current_rows[name]['sha256'] == wanted
            for name, wanted in build['source_manifest'].items()), 'source manifest is not the derived tree')
    return {'report_original': report_pin, 'report': report, 'derived_source': derived,
            'compiler_original': compiler_pin, 'build_original': build_pin,
            'bundle': observed_bundle, 'retained_originals': originals}

def selected_callers(root, source, context, policy, prepared):
    evidence = root / 'callers'
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
        if row['status'] == 3:
            yielded.add(row['mode'])
    require(dict(totals) == report['actual_native_step_statuses'] and set(totals) == {'0', '1', '2', '3'}
            and set(per_group) == set(policy['test_groups']) and public <= witnessed
            and '_native_globals' in witnessed
            and {'_native_generator_0', '_native_generator_1'} <= yielded,
            'complete actual step coverage does not support the report')
    installed = installed_control(evidence / 'component-fixture/installed-control', source,
                                  observed, policy)
    return {'report_original': report_pin, 'complete_method_count': 116, 'unique_test_ids': all_ids,
            'unittest_log_originals': logs, 'bundle': observed,
            'actual_step_totals': dict(totals), 'group_actual_step_totals': dict(per_group),
            'public_actual_modes': sorted(public & witnessed), 'private_actual_modes': sorted(private & witnessed),
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
