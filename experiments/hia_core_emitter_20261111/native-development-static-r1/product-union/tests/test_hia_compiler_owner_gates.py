"""Source-only controls for strict current-cold compiler-owner gate readers.

Toy receipts and tiny inert files test gate rejection. They are not native
execution, real build evidence, a cold replay, or a whole-delivery result.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_compiler_owner_gates as gates
from tools import qualify_hia_compiler_owner_ci as ci

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'experiments/hia_native_successor_runner_20261111/run_hia_qualification_v9.py'
OLD_RUNNER = ROOT / 'experiments/hia_v67_qualification_runner_20261111/run_hia_qualification_v8.py'
LEDGER = ROOT / 'docs/HIA_COMPILER_OWNER_QUALIFICATION_GATES.json'


def toy_code():
    requirements = {'state': ('emit', 'label'), 'encoding': ('ret',)}
    bindings, returned = {}, {}
    for index, group in enumerate(('component', 'original-callers')):
        owners = {}
        values = {}
        for kind in requirements:
            image = sha256((group + kind).encode()).hexdigest()
            owners[kind] = {'manifest': {'image_sha256': image}}
            operations = ({'emit': 1} if index == 0 else {'label': 1}) if kind == 'state' else {'ret': 1}
            values[kind] = {image: operations}
        bindings[group] = {'owners': owners}
        returned[group] = values
    report = {
        'native_counter_semantics': {
            'existing_native_entries': 'selected-call attempts before the original method',
            'normal_returns_by_group_image_operation': 'original selected method returned normally',
            'exceptional_calls_removed_from_attempt_ledger': False,
            'component_counts_relabelled_as_caller_counts': False},
        'normal_return_image_identity_changes': [],
        'native_group_bindings': {group: {'before': value, 'after': value,
            'all_actual_file_bytes_stable': True, 'binding_stable': True}
            for group, value in bindings.items()},
        'normal_native_returns_by_group_image_operation': returned,
        'normal_return_coverage_complete': True,
        'normal_return_coverage': {'state': ['emit', 'label'], 'encoding': ['ret']},
        'native_state_entries': {'emit': 3, 'label': 2},
        'native_instruction_entries': {'ret': 4},
    }
    return requirements, bindings, report


def toy_core():
    modes = ['_reject'] + ['mode' + str(index) for index in range(1, 27)] + ['_native_globals']
    abi = {'units': ['core_lowering_' + format(i, '03d') for i in range(31)],
           'modes': {name: {'number': index + 1, 'arity': 1} for index, name in enumerate(modes)}}
    builds = {}
    for role in ('caller', 'component'):
        names = ['core_lowering_pool', *abi['units']]
        manifest = {'path': '/' + role + '/manifest.json', 'bytes': 100,
                    'sha256': sha256((role + '-bundle').encode()).hexdigest()}
        builds[role] = {
            'bundle': {'abi_sha256': sha256(b'toy-abi').hexdigest()},
            'unit_order': names, 'bundle_files': [manifest],
            'build_file': {'path': '/' + role + '/build.json', 'bytes': 100, 'sha256': 'b' * 64},
            'units': {name: {'manifest': {'image_sha256': sha256((role + name).encode()).hexdigest(),
                                         'source_sha256': sha256(name.encode()).hexdigest()}}
                      for name in names},
        }
    roles = {'component': 'component', 'original-machine': 'caller', 'original-core': 'caller'}
    report = {'native_step_ledger_schema': 'hepta.hia.core-lowering-native-step-returns.v1',
        'native_step_return_semantics': gates.CORE_STEP_SEMANTICS,
        'native_step_unit_index_basis': gates.CORE_STEP_INDEX_BASIS,
        'native_mode_entries_are_attempts': True, 'group_bundle_roles': roles,
        'bundle_observations': {}, 'native_step_returns': [],
        'group_native_mode_attempts': [], 'native_mode_normal_returns': [],
        'native_mode_entries': {}, 'actual_native_step_statuses': {},
        'public_control_mode_count': 27, 'abi_control_mode_count': 28,
        'private_fixture_modes': ['_native_globals'],
        'private_fixture_mode_has_actual_step_returns': True}
    for role, binding in builds.items():
        files = [*binding['bundle_files'], binding['build_file']]
        names = binding['unit_order']
        report['bundle_observations'][role] = {
            'scope': 'MATCHING_SOURCE_COLD_BUILD', 'manifest': files[0]['path'],
            'manifest_sha256': files[0]['sha256'], 'bundle_sha256': files[0]['sha256'],
            'abi_sha256': binding['bundle']['abi_sha256'],
            'unit_names': names,
            'unit_image_sha256': [binding['units'][name]['manifest']['image_sha256'] for name in names],
            'source_sha256': {name: binding['units'][name]['manifest']['source_sha256'] for name in names},
            'input_bindings_before': files, 'input_bindings_after': files, 'stable': True}
        report[role + '_bundle_stable'] = True
    for group, mode, status in (
            *[('component', name, 0) for name in modes],
            ('original-machine', '_reject', 1), ('original-core', '_reject', 2)):
        binding = builds[roles[group]]
        row = {'group': group, 'mode': mode, 'mode_number': abi['modes'][mode]['number'],
            'unit_index': 0, 'bundle_image_index': 1, 'unit_name': abi['units'][0],
            'image_sha256': binding['units'][abi['units'][0]]['manifest']['image_sha256'],
            'abi_sha256': binding['bundle']['abi_sha256'],
            'bundle_sha256': binding['bundle_files'][0]['sha256'], 'status': status, 'count': 1}
        report['native_step_returns'].append(row)
        report['group_native_mode_attempts'].append({'group': group, 'mode': mode, 'count': 1})
        if mode != '_reject':
            report['native_mode_normal_returns'].append({'group': group, 'mode': mode, 'count': 1})
        report['native_mode_entries'][mode] = report['native_mode_entries'].get(mode, 0) + 1
        report['actual_native_step_statuses'][str(status)] = report['actual_native_step_statuses'].get(str(status), 0) + 1
    return abi, builds, report


class CompilerOwnerGateTests(unittest.TestCase):
    def test_exact_original_21_plus_nine_boolean_gates(self):
        self.assertEqual(len(gates.previous.SUCCESSOR_GATES), 21)
        self.assertEqual(len(gates.COMPILER_GATES), 9)
        self.assertEqual(len(gates.SUCCESSOR_GATES), 30)
        complete = dict.fromkeys(gates.SUCCESSOR_GATES, True)
        self.assertTrue(gates.require_successor_gates(complete))
        self.assertTrue(gates.previous.require_successor_gates(
            {name: complete[name] for name in gates.previous.SUCCESSOR_GATES}))
        for name in gates.SUCCESSOR_GATES:
            for value in (False, None, 1):
                with self.subTest(name=name, value=value):
                    broken = {**complete, name: value}
                    with self.assertRaises(ValueError):
                        gates.require_successor_gates(broken)
        for broken in (dict.fromkeys(gates.previous.SUCCESSOR_GATES, True),
                       {**complete, 'unreviewed_gate': True}):
            with self.assertRaises(ValueError):
                gates.require_successor_gates(broken)

    def test_complete_group_ids_reject_class_skip_and_every_anomaly(self):
        expected = [{'label': 'component', 'modules': ['tests.example'],
                     'count': 2, 'ids': ['tests.example.A.test_one', 'tests.example.A.test_two']}]
        row = {'label': 'component', 'modules': expected[0]['modules'], 'expected_methods': 2,
            'tests_run': 2, 'loaded_ids': expected[0]['ids'], 'executed_ids': expected[0]['ids'],
            'loader_errors': [], 'strict_pass': True, **dict.fromkeys(gates.GROUP_ANOMALIES, [])}
        gates.validate_groups([row], expected)
        mutations = [('executed_ids', []), ('tests_run', 0), ('loader_errors', ['cannot import']),
                     ('loaded_ids', list(reversed(row['loaded_ids']))),
                     *[(key, ['original anomaly']) for key in gates.GROUP_ANOMALIES]]
        for key, value in mutations:
            with self.subTest(field=key), self.assertRaises(ValueError):
                gates.validate_groups([{**row, key: value}], expected)

    def test_component_and_caller_use_separate_images_and_coverage_union(self):
        needed, bindings, report = toy_code()
        with patch.object(gates, 'code_operations', return_value=needed):
            result = gates.validate_code_returns('state', report, bindings)
        self.assertFalse(result['each_group_claimed_to_cover_every_operation'])
        self.assertEqual(result['coverage_union']['state'], ['emit', 'label'])
        self.assertEqual(report['native_state_entries'], {'emit': 3, 'label': 2})

    def test_attempts_or_wrong_group_image_cannot_replace_normal_returns(self):
        needed, bindings, report = toy_code()
        mutations = []
        missing = deepcopy(report)
        missing['normal_native_returns_by_group_image_operation'] = {}
        mutations.append(missing)
        wrong = deepcopy(report)
        component_image = bindings['component']['owners']['state']['manifest']['image_sha256']
        wrong['normal_native_returns_by_group_image_operation']['original-callers']['state'] = {
            component_image: {'label': 1}}
        mutations.append(wrong)
        drift = deepcopy(report)
        drift['normal_return_image_identity_changes'] = [{'before': 'a', 'after': 'b'}]
        mutations.append(drift)
        for value in mutations:
            with patch.object(gates, 'code_operations', return_value=needed), self.assertRaises(ValueError):
                gates.validate_code_returns('state', value, bindings)

    def test_stale_group_build_and_missing_return_coverage_are_refused(self):
        needed, bindings, report = toy_code()
        drift = deepcopy(report)
        drift['native_group_bindings']['component']['after']['owners']['state']['manifest']['image_sha256'] = '0' * 64
        missing = deepcopy(report)
        del missing['normal_native_returns_by_group_image_operation']['original-callers']['state']
        inflated = deepcopy(report)
        inflated['native_state_entries']['emit'] = 0
        for value in (drift, missing, inflated):
            with patch.object(gates, 'code_operations', return_value=needed), self.assertRaises(ValueError):
                gates.validate_code_returns('state', value, bindings)

    def test_core_actual_step_union_keeps_legal_reject_without_method_return(self):
        abi, builds, report = toy_core()
        actual = gates.validate_core_steps(report, builds, abi)
        self.assertFalse(actual['reject_mode_required_to_return_a_method_value'])
        self.assertFalse(actual['each_group_claimed_to_cover_every_mode'])
        self.assertNotIn('_reject', {row['mode'] for row in report['native_mode_normal_returns']})

    def test_core_pool_index_wrong_group_bundle_and_duplicate_steps_refuse(self):
        abi, builds, report = toy_core()
        pool = deepcopy(report)
        pool['native_step_returns'][0]['unit_index'] = -1
        wrong = deepcopy(report)
        wrong['native_step_returns'][0]['bundle_sha256'] = builds['caller']['bundle_files'][0]['sha256']
        duplicate = deepcopy(report)
        duplicate['native_step_returns'].append(duplicate['native_step_returns'][0].copy())
        for value in (pool, wrong, duplicate):
            with self.assertRaises(ValueError):
                gates.validate_core_steps(value, builds, abi)

    def test_core_attempt_only_coverage_and_missing_caller_steps_refuse(self):
        abi, builds, report = toy_core()
        attempts_only = deepcopy(report)
        attempts_only['native_step_returns'].pop(3)
        caller_missing = deepcopy(report)
        caller_missing['native_step_returns'] = [
            row for row in caller_missing['native_step_returns'] if row['group'] != 'original-core']
        totals = deepcopy(report)
        totals['actual_native_step_statuses']['0'] += 1
        private_missing = deepcopy(report)
        private_missing['native_step_returns'] = [
            row for row in private_missing['native_step_returns'] if row['mode'] != '_native_globals']
        private_missing['actual_native_step_statuses']['0'] -= 1
        for value in (attempts_only, caller_missing, totals, private_missing):
            with self.assertRaises(ValueError):
                gates.validate_core_steps(value, builds, abi)

    def test_single_build_reads_actual_v2_encoding_and_original_compile_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            raw = b'inert image, not native qualification'
            (folder / 'image.bin').write_bytes(raw)
            source = 'examples/hia_bootstrap/machine_encoding.hiaasm'
            context = {'source_manifest': {source: 'a' * 64},
                       'cold_sha256': 'b' * 64, 'compiler_sha256': 'c' * 64}
            manifest = {'schema': 'hepta.hia.machine-encoding-native.v2',
                'source_sha256': 'a' * 64, 'image_path': 'image.bin',
                'image_sha256': sha256(raw).hexdigest(), 'compiler_sha256': 'c' * 64}
            receipt = {'status': 'returned', 'abi_status': 0,
                'source_sha256': 'a' * 64, 'input_sha256': 'a' * 64,
                'image_sha256': 'c' * 64, 'artifact_sha256': 'c' * 64,
                'produced_sha256': manifest['image_sha256'], 'produced_bytes': len(raw),
                'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
                'limits': {'address_bytes': 268435456, 'core_dumpable': False, 'cpu_seconds': 10,
                           'output_capacity': 1048576, 'stack_bytes': 8388608, 'workspace_bytes': 1048576}}
            build = {'schema': 'hepta.hia.machine-encoding-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
                'source_manifest': context['source_manifest'], 'cold_report_sha256': context['cold_sha256'],
                'manifest': manifest, 'production_activated': False, 'native_compile_receipt': receipt}
            (folder / 'manifest.json').write_text(json.dumps(manifest))
            (folder / 'build.json').write_text(json.dumps(build))
            self.assertNotIn('scope', build)
            self.assertEqual(gates.single_build('encoding', folder, context)['manifest'], manifest)
            (folder / 'image.bin').write_bytes(raw[:-1] + b'!')
            with self.assertRaises(ValueError):
                gates.single_build('encoding', folder, context)
            (folder / 'image.bin').write_bytes(raw)
            receipt['limits']['cpu_seconds'] = 11
            (folder / 'build.json').write_text(json.dumps(build))
            with self.assertRaises(ValueError):
                gates.single_build('encoding', folder, context)

    def test_complete_gzip_replay_reads_beyond_first_chunk_and_rejects_difference(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            raw = b'a' * ((1 << 20) + 7)
            row = {'case': 'toy'}
            for side in ('original', 'native'):
                name = 'toy-' + side + '.elf.gz'
                (folder / name).write_bytes(gzip.compress(raw, mtime=0))
                row[side] = {'kind': 'bytes', 'archive': name,
                    'archive_sha256': sha256((folder / name).read_bytes()).hexdigest(),
                    'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
            actual = gates.compare_gzip_pair(folder, row)
            self.assertEqual(actual['decoded_bytes_each'], len(raw))
            self.assertTrue(actual['independently_read_both_complete_decoded_objects'])
            other = raw[:-1] + b'b'
            changed = folder / row['native']['archive']
            changed.write_bytes(gzip.compress(other, mtime=0))
            row['native'].update(archive_sha256=sha256(changed.read_bytes()).hexdigest(),
                                 sha256=sha256(other).hexdigest())
            with self.assertRaises(ValueError):
                gates.compare_gzip_pair(folder, row)

    def test_elf_environment_removes_development_presence_including_empty_string(self):
        with tempfile.TemporaryDirectory() as temporary:
            cold = Path(temporary) / 'cold.json'
            cold.write_text('{}')
            original = {'PATH': '/original', 'HOME': '/original-home',
                'HEPTA_HIA_MACHINE_ELF_DEVELOPMENT_MANIFEST': '',
                'HEPTA_HIA_MACHINE_STATE_DEVELOPMENT_BUNDLE': '/old/development'}
            updated = ci.component_environment(original, cold, Path(temporary) / 'fixture')
            self.assertNotIn('HEPTA_HIA_MACHINE_ELF_DEVELOPMENT_MANIFEST', updated)
            self.assertNotIn('HEPTA_HIA_MACHINE_STATE_DEVELOPMENT_BUNDLE', updated)
            self.assertEqual(updated['HOME'], original['HOME'])
            self.assertEqual(updated['PATH'], original['PATH'])
            self.assertEqual(updated['HEPTA_HIA_MACHINE_ELF_COLD_REPORT'], str(cold))
            self.assertIn('HEPTA_HIA_MACHINE_ELF_DEVELOPMENT_MANIFEST', original)

    def test_gate_report_cannot_substitute_nonempty_wrong_runtime_inspection(self):
        context = {'source_manifest': {'test': 'a' * 64}, 'identities': [{'path': '/original'}]}
        inspection = {'gates': {'machine_elf_complete_module': True}, 'original': {'sha256': 'a' * 64}}
        value = {'schema': 'hepta.hia.compiler-owner-gate.v1', 'owner': 'elf', 'operation': 'component',
            'status': 'PASS', 'scope': 'MATCHING_SOURCE_COLD_OWNER_GATES',
            'source_before': context['source_manifest'], 'source_after': context['source_manifest'],
            'source_preserved': True, 'cold_inputs_preserved': True, 'cold_inputs': context['identities'],
            'inspection': inspection, 'gates': inspection['gates'],
            'whole_native_delivery_qualified': False, 'development_or_prior_result_reused': False}
        self.assertTrue(gates.validate_gate_report(value, 'elf', 'component', inspection, context))
        with self.assertRaises(ValueError):
            gates.validate_gate_report(value, 'elf', 'component', {**inspection, 'extra': 'forged'}, context)
        with self.assertRaises(ValueError):
            gates.validate_gate_report({**value, 'status': 'HOLD'}, 'elf', 'component', inspection, context)

    def test_ledger_complete_denominators_and_distinct_original_deadlines(self):
        ledger = json.loads(LEDGER.read_bytes())
        self.assertEqual(ledger['required_gates'], list(gates.SUCCESSOR_GATES))
        self.assertEqual(ledger['required_gate_count'], 30)
        self.assertEqual(ledger['legacy_gate_count'], 21)
        self.assertEqual(ledger['generator_order'], list(gates.SOURCE_GENERATORS))
        self.assertEqual(ledger['generator_count'], 59)
        self.assertEqual(ledger['controller_seconds'], 10800)
        self.assertEqual(ledger['full_retained_seconds'], 5400)
        self.assertEqual(ledger['cold_seconds'], 180)
        self.assertEqual((ledger['cold_workers'], ledger['cold_phases']), (2, 38))
        self.assertEqual(ledger['new_denominators'], {
            'state': [12, 51], 'instructions': [12, 51], 'core': [12, 51, 50], 'elf': [20, 51]})
        self.assertEqual(ledger['elf_boundary_cases'], 11)
        self.assertEqual(ledger['elf_full_decoded_archives'], 12)
        self.assertFalse(ledger['default_activation_or_whole_native_delivery_claimed'])

        # Receipt readers require these actual test bytes in the cold closure.
        # Follow the declared module providers as source, without importing or
        # running any component/caller test or constructing a native image.
        from tools.hia_selfhost_contract import CONTRACT_PATH, SOURCE_FILES
        from tools.hia_release import BOOTSTRAP_FILES
        declared = json.loads((ROOT / CONTRACT_PATH).read_bytes())['source_identity']['files']
        modules = {owner['module'] for owner in gates.OWNERS.values()}
        pending = {owner['qualifier'].replace('.', '/') + '.py'
                   for owner in gates.OWNERS.values()}
        providers = {}
        module_bindings = {'MODULES', 'ORIGINAL_MODULES', 'COMPONENT_MODULES', 'CORE_MODULES'}
        while pending:
            name = min(pending)
            pending.remove(name)
            if name in providers:
                continue
            syntax = ast.parse((ROOT / name).read_bytes())
            providers[name] = syntax
            modules.update(node.value for node in ast.walk(syntax)
                           if isinstance(node, ast.Constant) and type(node.value) is str
                           and re.fullmatch(r'tests\.test_[A-Za-z0-9_]+', node.value))
            for node in syntax.body:
                if (isinstance(node, ast.ImportFrom) and node.module
                        and node.module.startswith('tools.')
                        and any(alias.name in module_bindings for alias in node.names)):
                    pending.add(node.module.replace('.', '/') + '.py')
        required = set(providers) | {name.replace('.', '/') + '.py' for name in modules}
        for name in sorted(required):
            with self.subTest(cold_source=name):
                self.assertIn(name, SOURCE_FILES)
                self.assertIn(name, BOOTSTRAP_FILES)
                self.assertIn(name, declared)
                self.assertEqual(declared[name], sha256((ROOT / name).read_bytes()).hexdigest())
        elf = providers['tools/qualify_hia_machine_elf.py']
        constants = {target.id: ast.literal_eval(node.value)
                     for node in elf.body if isinstance(node, ast.Assign)
                     for target in node.targets
                     if isinstance(target, ast.Name)
                     and target.id in {'MODULES', 'MODULE_SOURCE_PINS'}}
        self.assertEqual(set(constants['MODULE_SOURCE_PINS']),
                         {name.replace('.', '/') + '.py' for name in constants['MODULES']})
        for name, digest in constants['MODULE_SOURCE_PINS'].items():
            with self.subTest(original_elf_source=name):
                self.assertEqual(declared[name], digest)
                self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest)

    def test_v9_preserves_original_suite_observer_helpers_and_limits(self):
        old_tree, tree = ast.parse(OLD_RUNNER.read_bytes()), ast.parse(RUNNER.read_bytes())
        def function(tree, name):
            return next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
        for name in ('_pinned_state', 'file_record', 'suite', 'selected_journal_callers',
                     'selected_machine_plan_callers', 'selected_json_wire_callers',
                     'selected_machine_encoding_callers', 'retained_cli_fixture'):
            with self.subTest(function=name):
                self.assertEqual(ast.dump(function(old_tree, name), include_attributes=False),
                                 ast.dump(function(tree, name), include_attributes=False))
        def cold_call(tree):
            return next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name) and node.func.id == 'run'
                and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == 'cold')
        self.assertEqual(ast.dump(cold_call(old_tree), include_attributes=False),
                         ast.dump(cold_call(tree), include_attributes=False))
        old_run, new_run = function(old_tree, 'run'), function(tree, 'run')
        self.assertEqual(ast.dump(old_run.args), ast.dump(new_run.args))
        original_owner = next(node for node in ast.walk(old_run) if isinstance(node, ast.Call)
                              and isinstance(node.func, ast.Name) and node.func.id == 'run_workflow_step')
        actual_owner = next(node for node in ast.walk(new_run) if isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Name) and node.func.id == 'run_workflow_step')
        self.assertEqual(ast.dump(original_owner), ast.dump(actual_owner))
        self.assertIn('5400 if discover else 1800', ast.get_source_segment(
            OLD_RUNNER.read_text(), function(old_tree, 'suite')))

    def test_v9_adjacent_original_helpers_are_byte_identical(self):
        old = OLD_RUNNER.parent
        new = RUNNER.parent
        for name in ('guardian.py', 'process_owner_impl.py', 'workflow_process.py',
                     'qualification_prerequisites.py', 'native_owner_gates.py'):
            with self.subTest(helper=name):
                self.assertEqual((old / name).read_bytes(), (new / name).read_bytes())

    def test_workflow_keeps_two_original_name_groups_and_all_59_generators(self):
        workflow = (ROOT / '.github/workflows/hia-core.yml').read_text()
        names = re.findall(r'          names = \((.*?)\n          \)', workflow, re.S)
        self.assertEqual(len(names), 2)
        actual = re.search(r'for component in ([^;]+); do', workflow).group(1).split()
        self.assertEqual(actual, list(gates.SOURCE_GENERATORS))
        self.assertEqual(len(actual), 59)
        self.assertEqual(len(set(actual)), 59)
        for name in ('MachineStateSourceTests', 'MachineInstructionsSourceTests',
                     'MachineElfSourceTests', 'CoreLoweringSourceTests', 'test_hia_compiler_owner_gates'):
            self.assertIn(name, names[0])
        self.assertEqual(workflow.count('qualify_hia_compiler_owner_ci.py owned-callers'), 4)
        self.assertEqual(workflow.count('qualify_hia_compiler_owner_ci.py owned-component'), 1)
        for owner in ('state', 'instructions', 'core', 'elf'):
            self.assertIn('--owner ' + owner + ' --cold-report', workflow)
        for stem in ('hia-machine-state-callers-evidence', 'hia-machine-instructions-callers-evidence',
                     'hia-core-lowering-callers-evidence', 'hia-machine-elf-component-evidence',
                     'hia-machine-elf-callers-evidence'):
            self.assertIn(stem + '/', workflow)
        for marker in ('--check', '--generate-inventory', 'git diff --exit-code'):
            self.assertIn(marker, workflow)


    def test_original_owned_receipt_command_cleanup_and_failure_remain_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            cold = base / 'cold.json'
            cold.write_text('{}')
            evidence = base / 'product'
            process = base / 'process'
            process.mkdir()
            context = {'source_manifest': {'toy-source': 'a' * 64},
                       'identities': [{'path': str(cold), 'bytes': 2, 'sha256': sha256(b'{}').hexdigest()}]}
            implementation = {'path': str(gates.ROOT / 'tools/hia_selfhost_process_owner.py'),
                              'bytes': 1, 'sha256': 'b' * 64}
            command = gates.owned_product_command('state', 'callers', cold, evidence, process)
            def fixture(mutate=None):
                request = {'schema': 'hepta.hia.selfhost-process-owner.v1',
                    'command': command, 'cwd': str(gates.ROOT),
                    'qualification_seconds': 180, 'cleanup_seconds': 3,
                    'implementation_sha256': implementation['sha256'],
                    'stdout_path': str(process / 'stdout.log'),
                    'stderr_path': str(process / 'stderr.log'),
                    'receipt_path': str(process / 'process-owner.json'),
                    'env': {'HEPTA_HIA_MACHINE_STATE_COLD_REPORT': str(cold)}}
                receipt = {'schema': 'hepta.hia.selfhost-process-owner.v1',
                    'implementation_sha256': implementation['sha256'],
                    'qualification_seconds': 180, 'cleanup_seconds': 3,
                    'status': 'OWNED_PROCESS_COMPLETED', 'returncode': 0, 'timed_out': False,
                    'qualification_started': True, 'exit_observed_before_deadline': True,
                    'subreaper_enabled': True, 'interrupted_signals': [], 'event_overflow': False,
                    'cleanup': {'attempted': True, 'complete': True, 'leader_reaped': True,
                        'observed_echild': True, 'deadline_exceeded': False, 'errors': [],
                        'remaining_direct_children': []},
                    'events': [{'kind': name} for name in ('qualification_started',
                        'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped')],
                    'historical_descendant_inventory_complete': False}
                result = {'schema': 'hepta.hia.compiler-owner-owned-command.v1',
                    'status': 'OWNED_COMMAND_RETURNED_PENDING_READBACK',
                    'owner': 'state', 'part': 'callers', 'command': command, 'cwd': str(gates.ROOT),
                    'source_before': context['source_manifest'], 'source_after': context['source_manifest'],
                    'source_preserved': True, 'cold_inputs_preserved': True,
                    'cold_inputs': context['identities']}
                if mutate:
                    mutate(request, receipt, result)
                raw = json.dumps(request, sort_keys=True).encode()
                (process / 'process-owner.json.request.json').write_bytes(raw)
                receipt['request_sha256'] = sha256(raw).hexdigest()
                raw = json.dumps(receipt, sort_keys=True).encode()
                (process / 'process-owner.json').write_bytes(raw)
                result['returned_owner'] = {**receipt, 'supervisor_returncode': 0,
                                            'receipt_sha256': sha256(raw).hexdigest()}
                (process / 'run-result.json').write_text(json.dumps(result))
                for name in ('stdout.log', 'stderr.log', 'process-owner.json.stdout.log',
                             'process-owner.json.stderr.log'):
                    (process / name).write_bytes(b'')
            fixture()
            with patch.object(gates, 'source_record', return_value=implementation):
                result = gates.inspect_owned_product('state', 'callers', cold, evidence, process, context)
                self.assertTrue(result['natural_exit_and_echild'])
                self.assertFalse(result['historical_descendant_inventory_complete'])
                mutations = [
                    lambda req, rec, res: req.update(qualification_seconds=181),
                    lambda req, rec, res: rec.update(qualification_seconds=181),
                    lambda req, rec, res: req.update(command=[*command, '--development']),
                    lambda req, rec, res: req.update(cwd='/wrong-source'),
                    lambda req, rec, res: req['env'].update(
                        HEPTA_HIA_MACHINE_STATE_DEVELOPMENT_BUNDLE=''),
                    lambda req, rec, res: rec.update(returncode=1),
                    lambda req, rec, res: rec.update(timed_out=True),
                    lambda req, rec, res: rec['cleanup'].update(observed_echild=False),
                    lambda req, rec, res: rec['cleanup'].update(remaining_direct_children=[1234]),
                    lambda req, rec, res: rec['events'].append({'kind': 'owned_child_sigkill'}),
                    lambda req, rec, res: rec.update(implementation_sha256='0' * 64),
                    lambda req, rec, res: res.update(source_after={'changed': '0' * 64}),
                ]
                for index, mutate in enumerate(mutations):
                    with self.subTest(mutation=index):
                        fixture(mutate)
                        with self.assertRaises(ValueError):
                            gates.inspect_owned_product('state', 'callers', cold, evidence, process, context)

    def test_five_new_products_use_original_180_3_and_exclude_ci_credentials(self):
        tree = ast.parse((ROOT / 'tools/qualify_hia_compiler_owner_ci.py').read_bytes())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == 'run_owned']
        self.assertEqual(len(calls), 1)
        values = {node.arg: ast.literal_eval(node.value) for node in calls[0].keywords
                  if node.arg in ('qualification_seconds', 'cleanup_seconds')}
        self.assertEqual(values, {'qualification_seconds': 180, 'cleanup_seconds': 3})
        runner = ast.parse(RUNNER.read_bytes())
        for name in ('compiler_owner_callers', 'machine_elf_component'):
            function = next(node for node in runner.body
                            if isinstance(node, ast.FunctionDef) and node.name == name)
            calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id == 'run']
            self.assertEqual(len(calls), 1)
            self.assertEqual({node.arg: ast.literal_eval(node.value) for node in calls[0].keywords},
                             {'timeout': 180})
        with tempfile.TemporaryDirectory() as temporary:
            cold = Path(temporary) / 'cold.json'
            cold.write_text('{}')
            original = {'HOME': '/original', 'PATH': '/tools', 'LANG': 'C.UTF-8',
                'ACTIONS_RUNTIME_TOKEN': 'inert-test-sentinel',
                'GITHUB_TOKEN': 'another-inert-test-sentinel',
                'HEPTA_HIA_MACHINE_STATE_DEVELOPMENT_BUNDLE': '',
                'HEPTA_HIA_AGENT_BINARY64_MANIFEST': '/declared/input'}
            actual = ci.owned_environment(original, 'state', cold)
            self.assertEqual(actual['HOME'], original['HOME'])
            self.assertEqual(actual['PATH'], original['PATH'])
            self.assertEqual(actual['HEPTA_HIA_AGENT_BINARY64_MANIFEST'], '/declared/input')
            self.assertNotIn('GITHUB_TOKEN', actual)
            self.assertNotIn('ACTIONS_RUNTIME_TOKEN', actual)
            self.assertNotIn('HEPTA_HIA_MACHINE_STATE_DEVELOPMENT_BUNDLE', actual)


if __name__ == '__main__':
    unittest.main()
