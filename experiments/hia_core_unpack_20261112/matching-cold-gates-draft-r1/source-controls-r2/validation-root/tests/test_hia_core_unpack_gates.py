"""Source-only refusal controls; inert receipts are never native/cold evidence."""
from __future__ import annotations
import ast
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_core_unpack_gates as gates
from tools import qualify_hia_core_unpack_ci as ci

ROOT = Path(__file__).resolve().parents[1]
RUNNERS = ROOT / 'experiments/hia_native_successor_runner_20261111'


def component_fixture(binding, context, caller_pin):
    ids = gates.expected_component_ids()
    row = {'schema': 'hepta.hia.core-unpack-composition.v1', 'status': 'PASS',
        'scope': gates.COMPONENT_SCOPE, 'complete_source_methods': 2, 'complete_native_methods': 6,
        'complete_component_count': 18, 'complete_component_groups': [4, 6, 8],
        'all_component_ids': [*gates.FINITE_IDS['shim'], *gates.FINITE_IDS['finite-native'], *ids],
        'finite_groups': [{'label': 'shim'}, {'label': 'finite-native'}],
        'loaded_test_ids': ids, 'chosen_test_ids': ids, 'executed_test_ids': ids,
        'tests_loaded': 8, 'tests_chosen': 8, 'tests_run': 8, 'loader_errors': [],
        'unittest_successful': True, 'source_before': context['source_manifest'],
        'source_after': context['source_manifest'], 'source_preserved': True,
        'cold_inputs_preserved': True, 'cold_inputs': context['identities'],
        'caller_report': caller_pin, 'build_bindings_before': binding, 'build_bindings_after': binding,
        'builds_preserved': True, 'native_step_semantics': gates.LEDGER_MEANING,
        'CPython_object_runtime_still_hosted': True, 'default_activated': False,
        'whole_native_delivery_qualified': False,
        'actual_UNPACK_step_returns': [dict(test=ids[0], image_sha256=binding['UNPACK']['manifest']['image_sha256'],
                                          status=status, count=1) for status in (0, 1)]}
    row.update({key: [] for key in gates.previous.previous.ANOMALIES})
    return row


def caller_fixture(folder):
    from hepta import hia_core_unpack_selection as selection
    from hepta import hia_core_unpack_native as native
    cold = folder / 'synthetic-cold.json'
    cold.write_text('{}\n')
    names = (selection.HIA_SOURCE, selection.ABI_SOURCE, selection.BRIDGE_SOURCE, selection.SELECTION_SOURCE)
    sources = {name: sha256(name.encode()).hexdigest() for name in names}
    fields = ('source_sha256', 'abi_sha256', 'bridge_sha256', 'selection_sha256')
    manifest = {'schema': selection.SCHEMA, **dict(zip(fields, sources.values())),
        'image_path': 'core-unpack.image.bin', 'image_sha256': 'a' * 64, 'compiler_sha256': 'b' * 64}
    files = [{'path': str(folder / name), 'bytes': 5, 'sha256': sha256(name.encode()).hexdigest()}
             for name in ('manifest.json', 'core-unpack.image.bin', 'build.json')]
    binding = {'manifest': manifest, 'files': files, 'sources': sources,
               'transaction_ABI': native.TRANSACTION_ABI, 'transaction_sha256': native.SHIM_SHA256}
    context = {'source_manifest': sources, 'identities': [], 'compiler_sha256': 'b' * 64, 'cold_sha256': 'c' * 64}
    tree = ast.parse((ROOT / 'tools/qualify_hia_core_lowering_callers.py').read_bytes())
    literals = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in ('COMPONENT_IDS', 'ORIGINAL_IDS', 'CORE_IDS')}
    groups = [{'label': label, 'ids': literals[name]} for label, name in zip(gates.GROUPS,
              ('COMPONENT_IDS', 'ORIGINAL_IDS', 'CORE_IDS'))]
    row = {'schema': 'hepta.hia.core-unpack-selected-callers.v1', 'status': 'PASS',
        'scope': 'MATCHING_SOURCE_COLD_SELECTED_CALLERS', 'original_groups': [15, 51, 50],
        'original_complete_methods': 116, 'original_Core_image_count': 39, 'additional_UNPACK_image_count': 1,
        'complete_116_passed': True, 'outer_opcode14_permission_still_consumed_once': True,
        'outer_return_counter_semantics': gates.OUTER_MEANING, 'old_complete_unpack_entries': [],
        'CPython_object_runtime_still_hosted': True, 'whole_stack_rewritten_in_hia': False,
        'default_activated': False, 'transaction_ABI': native.TRANSACTION_ABI, 'transaction_sha256': native.SHIM_SHA256,
        'admitted_companion': gates.admitted_companion(binding),
        'identity_before': gates.implementation_digest(binding), 'identity_after': gates.implementation_digest(binding),
        'source_before': sources, 'source_after': sources, 'stable': True,
        'companion_inputs_before': [{'path': item['path'], 'size': item['bytes'], 'sha256': item['sha256']} for item in files],
        'original_qualifier_argv': ['qualify_hia_core_lowering_callers.py', '--cold-report', str(cold),
                                  '--evidence', str(folder / 'core-callers')],
        'outer_opcode14_attempts': [], 'outer_opcode14_normal_returns': [],
        'outer_opcode14_exceptions': [], 'actual_UNPACK_step_returns': []}
    row['companion_inputs_after'] = deepcopy(row['companion_inputs_before'])
    for group in groups:
        item = {'group': group['label'], 'test': group['ids'][0], 'arity': 2,
                'image_sha256': manifest['image_sha256'], 'count': 3}
        row['outer_opcode14_attempts'].append(item)
        row['outer_opcode14_normal_returns'].append({**item, 'count': 2})
        row['outer_opcode14_exceptions'].append({**item, 'count': 1})
        row['actual_UNPACK_step_returns'].extend({**item, 'status': status} for status in (0, 1))
    return row, groups, binding, context, cold


def owned_fixture(cold):
    source = {'tools/hia_selfhost_process_owner.py': 'd' * 64}
    context = {'source_manifest': source, 'identities': []}
    names = ('run-result.json', 'process-owner.json', 'process-owner.json.request.json',
             'stdout.log', 'stderr.log', 'process-owner.json.stdout.log', 'process-owner.json.stderr.log')
    pins = {name: {'path': str(cold.parent / name), 'bytes': 1, 'sha256': sha256(name.encode()).hexdigest()}
            for name in names}
    command = ['synthetic-only', '-B', 'no-product']
    request = {'schema': 'hepta.hia.selfhost-process-owner.v1', 'command': command, 'cwd': str(gates.ROOT),
        'qualification_seconds': 180, 'cleanup_seconds': 3, 'implementation_sha256': 'd' * 64,
        'stdout_path': pins['stdout.log']['path'], 'stderr_path': pins['stderr.log']['path'],
        'receipt_path': pins['process-owner.json']['path'],
        'env': {'HEPTA_HIA_CORE_UNPACK_COLD_REPORT': str(cold)}}
    receipt = {'schema': request['schema'], 'request_sha256': pins['process-owner.json.request.json']['sha256'],
        'implementation_sha256': 'd' * 64, 'qualification_seconds': 180, 'cleanup_seconds': 3,
        'status': 'OWNED_PROCESS_COMPLETED', 'returncode': 0, 'timed_out': False,
        'qualification_started': True, 'exit_observed_before_deadline': True, 'subreaper_enabled': True,
        'interrupted_signals': [], 'event_overflow': False,
        'cleanup': {'attempted': True, 'complete': True, 'leader_reaped': True, 'observed_echild': True,
                    'deadline_exceeded': False, 'errors': [], 'remaining_direct_children': []},
        'events': [{'kind': kind} for kind in ('qualification_started', 'owned_child_observed',
                   'qualification_exit_observed', 'owned_child_reaped')]}
    result = {'schema': 'hepta.hia.core-unpack-owned-command.v1', 'status': 'OWNED_COMMAND_RETURNED_PENDING_READBACK',
        'part': 'callers', 'command': command, 'cwd': str(gates.ROOT), 'source_before': source,
        'source_after': source, 'source_preserved': True, 'cold_inputs_preserved': True, 'cold_inputs': [],
        'returned_owner': {**deepcopy(receipt), 'supervisor_returncode': 0,
                           'receipt_sha256': pins['process-owner.json']['sha256']}}
    return result, request, receipt, pins, command, context


class CoreUnpackGateSourceTests(unittest.TestCase):
    def test_exact_thirty_old_gates_and_each_new_gate_are_mandatory(self):
        expected = {name: True for name in gates.SUCCESSOR_GATES}
        self.assertEqual(len(gates.previous.SUCCESSOR_GATES), 30)
        self.assertEqual(gates.SUCCESSOR_GATES[:30], gates.previous.SUCCESSOR_GATES)
        self.assertTrue(gates.require_successor_gates(expected))
        for name in expected:
            for operation in ('missing', 'false', 'integer'):
                value = dict(expected)
                if operation == 'missing':
                    del value[name]
                else:
                    value[name] = False if operation == 'false' else 1
                with self.subTest(name=name, operation=operation), self.assertRaises(ValueError):
                    gates.require_successor_gates(value)
        with self.assertRaises(ValueError):
            gates.require_successor_gates({**expected, 'invented': True})

    def test_original_eighteen_ids_and_finite_control_bytes_are_complete(self):
        ledger = json.loads((ROOT / 'docs/HIA_CORE_UNPACK_QUALIFICATION_GATES.json').read_bytes())
        ordinary = gates.expected_component_ids()
        self.assertEqual(ledger['component_groups']['ordinary']['ids'], ordinary)
        for label in gates.FINITE_IDS:
            self.assertEqual(ledger['component_groups'][label]['ids'], gates.FINITE_IDS[label])
        self.assertEqual([len(gates.FINITE_IDS['shim']), len(gates.FINITE_IDS['finite-native']), len(ordinary)], [4, 6, 8])
        self.assertEqual(len(set([*gates.FINITE_IDS['shim'], *gates.FINITE_IDS['finite-native'], *ordinary])), 18)
        for name, digest in gates.FINITE_PINS.items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest)

    def test_callers_accept_actual_step_semantics_with_legal_exceptions(self):
        with tempfile.TemporaryDirectory() as value:
            report, groups, binding, context, cold = caller_fixture(Path(value))
            result = gates.validate_callers(report, groups, binding, context, cold, cold.parent)
            self.assertFalse(result['normal_method_return_required_for_rejections'])
            self.assertEqual([len(group['ids']) for group in groups], [15, 51, 50])
            report['outer_opcode14_exceptions'][0]['count'] += 1
            with self.assertRaises(ValueError):
                gates.validate_callers(report, groups, binding, context, cold, cold.parent)

    def test_callers_reject_development_split_source_identity_and_retained_owner(self):
        changes = [('scope', 'EXPLICIT_DEVELOPMENT_ONLY'), ('status', 'DEVELOPMENT_GROUP_PASS'),
                   ('original_groups', [15]), ('original_complete_methods', 15),
                   ('additional_UNPACK_image_count', True), ('complete_116_passed', False),
                   ('identity_after', '0' * 64), ('source_after', {}), ('companion_inputs_after', []),
                   ('old_complete_unpack_entries', ['entered']), ('error', 'late failure'),
                   ('CPython_object_runtime_still_hosted', False), ('stable', False)]
        with tempfile.TemporaryDirectory() as value:
            report, groups, binding, context, cold = caller_fixture(Path(value))
            for key, replacement in changes:
                changed = deepcopy(report); changed[key] = replacement
                with self.subTest(key=key), self.assertRaises(ValueError):
                    gates.validate_callers(changed, groups, binding, context, cold, cold.parent)
            changed = deepcopy(report)
            changed['original_qualifier_argv'].insert(1, '--development-group')
            with self.assertRaises(ValueError):
                gates.validate_callers(changed, groups, binding, context, cold, cold.parent)

    def test_attempts_cannot_substitute_for_native_returns_or_other_group_images(self):
        with tempfile.TemporaryDirectory() as value:
            report, groups, binding, context, cold = caller_fixture(Path(value))
            variants = []
            changed = deepcopy(report); changed['actual_UNPACK_step_returns'] = []; variants.append(changed)
            changed = deepcopy(report); changed['actual_UNPACK_step_returns'] += [deepcopy(changed['actual_UNPACK_step_returns'][0])]; variants.append(changed)
            for key, replacement in (('status', True), ('count', True), ('arity', True), ('arity', 5),
                                     ('image_sha256', 'e' * 64), ('group', 'outside'), ('test', 'missing')):
                changed = deepcopy(report); changed['actual_UNPACK_step_returns'][0][key] = replacement; variants.append(changed)
            changed = deepcopy(report); changed['actual_UNPACK_step_returns'] = changed['actual_UNPACK_step_returns'][:-2]; variants.append(changed)
            for index, changed in enumerate(variants):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    gates.validate_callers(changed, groups, binding, context, cold, cold.parent)

    def test_component_eight_cannot_silently_replace_eighteen(self):
        with tempfile.TemporaryDirectory() as value:
            _, _, unpack, context, cold = caller_fixture(Path(value))
            binding = {'Core39': {'actual': 'inert'}, 'UNPACK': unpack}
            pin = {'path': 'inert', 'bytes': 1, 'sha256': 'c' * 64}
            report = component_fixture(binding, context, pin)
            ids = gates.expected_component_ids()
            gates.validate_component(report, ids, binding, context, pin)
            for key, replacement in (('complete_component_count', 8), ('complete_component_groups', [8]),
                    ('finite_groups', []), ('all_component_ids', ids), ('tests_run', True), ('skipped', ['missing']),
                    ('caller_report', {}), ('build_bindings_after', {}), ('source_after', {}),
                    ('scope', 'DEVELOPMENT_ONLY'), ('error', 'late failure')):
                changed = deepcopy(report); changed[key] = replacement
                with self.subTest(key=key), self.assertRaises(ValueError):
                    gates.validate_component(changed, ids, binding, context, pin)

    def test_installed_observation_requires_every_identity_and_actual_refusal(self):
        with tempfile.TemporaryDirectory() as value:
            _, _, binding, _, _ = caller_fixture(Path(value))
            installed = {**{key: item for key, item in binding['manifest'].items() if key not in ('schema', 'image_path')},
                'schema': 'hepta.hia.core-unpack-installed-observation.v1', 'runtime_profile': 31404,
                'transaction_sha256': binding['transaction_sha256'], 'actual_step_returns': 2, 'actual_statuses': [0, 1],
                'retained_unpack_forbidden': True, 'restored_identity_sha256': gates.implementation_digest(binding),
                'refusals': [name + suffix for name in ('hepta/hia_core_unpack_abi.json', 'examples/hia_bootstrap/core_unpack.hiaasm')
                             for suffix in (':changed', ':missing')]}
            self.assertEqual(gates.validate_installed(installed, binding), installed)
            for key in ('source_sha256', 'abi_sha256', 'bridge_sha256', 'selection_sha256', 'image_sha256',
                        'compiler_sha256', 'transaction_sha256', 'restored_identity_sha256'):
                changed = deepcopy(installed); changed[key] = 'f' * 64
                with self.subTest(key=key), self.assertRaises(ValueError):
                    gates.validate_installed(changed, binding)
            for key, replacement in (('runtime_profile', 31410), ('actual_step_returns', True),
                    ('actual_statuses', [False, True]), ('refusals', []), ('retained_unpack_forbidden', False)):
                changed = deepcopy(installed); changed[key] = replacement
                with self.subTest(key=key), self.assertRaises(ValueError):
                    gates.validate_installed(changed, binding)

    def test_original_180_3_owner_and_projection_reject_kill_late_or_ambient_image(self):
        with tempfile.TemporaryDirectory() as value:
            cold = Path(value) / 'synthetic-cold'; cold.write_bytes(b'{}')
            result, request, receipt, pins, command, context = owned_fixture(cold)
            gates.validate_owned(result, request, receipt, pins, command, 'callers', cold, context)
            variants = []
            for key, replacement in (('qualification_seconds', 181), ('cleanup_seconds', 4), ('command', ['other']),
                                     ('implementation_sha256', 'f' * 64)):
                r = deepcopy(request); r[key] = replacement; variants.append((deepcopy(result), r, deepcopy(receipt)))
            for name in ('HEPTA_HIA_CORE_UNPACK_MANIFEST', 'HEPTA_HIA_CORE_LOWERING_DEVELOPMENT_MANIFEST'):
                r = deepcopy(request); r['env'][name] = '/different'; variants.append((deepcopy(result), r, deepcopy(receipt)))
            for key, replacement in (('returncode', True), ('timed_out', True), ('owner_error', 'failure'),
                                     ('event_overflow', True), ('events', [{'kind': 'owned_child_sigkill'}])):
                r = deepcopy(receipt); r[key] = replacement; variants.append((deepcopy(result), deepcopy(request), r))
            for key in ('complete', 'observed_echild', 'leader_reaped'):
                r = deepcopy(receipt); r['cleanup'][key] = False; variants.append((deepcopy(result), deepcopy(request), r))
            r = deepcopy(result); r['returned_owner']['receipt_sha256'] = '0' * 64; variants.append((r, deepcopy(request), deepcopy(receipt)))
            for index, (a, b, c) in enumerate(variants):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    gates.validate_owned(a, b, c, pins, command, 'callers', cold, context)

    def test_gate_report_does_not_accept_pending_or_single_side_evidence(self):
        context = {'source_manifest': {'a': 'b'}, 'identities': []}
        inspection = {'gates': {name: True for name in gates.NEW_GATES}, 'synthetic_only': True}
        report = {'schema': 'hepta.hia.core-unpack-gates.v1', 'status': 'PASS', 'scope': gates.SCOPE,
            'operation': 'owned-component', 'source_before': context['source_manifest'],
            'source_after': context['source_manifest'], 'source_preserved': True, 'cold_inputs_preserved': True,
            'cold_inputs': [], 'inspection': inspection, 'gates': inspection['gates'], 'whole_native_delivery_qualified': False}
        gates.validate_gate_report(report, inspection, context)
        for key, value in (('status', 'CALLERS_READBACK_ACCEPTED_PENDING_COMPOSITION'), ('operation', 'owned-callers'),
                           ('inspection', {}), ('gates', {}), ('error', 'after PASS'), ('source_preserved', False)):
            changed = deepcopy(report); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                gates.validate_gate_report(changed, inspection, context)

    def test_environment_strips_selectors_without_overwriting_home(self):
        with tempfile.TemporaryDirectory() as value:
            cold = Path(value) / 'cold'; cold.write_bytes(b'{}')
            env = ci.owned_environment({'HOME': '/unchanged', 'PATH': '/bin', 'SECRET_TOKEN': 'never',
                'HEPTA_HIA_CORE_UNPACK_MANIFEST': '/old', 'HEPTA_HIA_CORE_LOWERING_DEVELOPMENT_MANIFEST': '/old',
                'HEPTA_HIA_MACHINE_INSTRUCTIONS_DEVELOPMENT_BUNDLE': '/old'}, cold)
            self.assertEqual(env['HOME'], '/unchanged')
            self.assertNotIn('SECRET_TOKEN', env)
            self.assertFalse(any('DEVELOPMENT' in key or key.endswith(('_MANIFEST', '_BUNDLE')) for key in env))
            self.assertEqual(env['HEPTA_HIA_CORE_UNPACK_COLD_REPORT'], str(cold))

    def test_companion_reads_all_six_compile_originals_and_rejects_other_builds(self):
        from hepta import hia_core_unpack_selection as selection
        from tools.hia_selfhost_contract import PROFILE
        with tempfile.TemporaryDirectory() as value:
            root = Path(value); folder = root / 'build'; folder.mkdir()
            inputs = selection.current_inputs()
            inputs['tools/hia_selfhost_child.py'] = b'SYNTHETIC child source, never executed\n'
            inputs['tools/hia_core_unpack_transaction.S'] = b'SYNTHETIC transaction source, never executed\n'
            for name, raw in inputs.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            compiler = root / 'SYNTHETIC-B3'; compiler.write_bytes(b'not an executable')
            image = folder / 'core-unpack.image.bin'; image.write_bytes(b'RAW')
            context = {'source_manifest': {name: sha256(raw).hexdigest() for name, raw in inputs.items()},
                       'compiler_sha256': sha256(compiler.read_bytes()).hexdigest(), 'cold_sha256': 'c' * 64,
                       'identities': [{}, {}, gates.file_record(compiler)]}
            manifest = {'schema': selection.SCHEMA, 'image_path': image.name,
                'image_sha256': sha256(b'RAW').hexdigest(), 'compiler_sha256': context['compiler_sha256'],
                **{field: context['source_manifest'][name] for field, name in (
                    ('source_sha256', selection.HIA_SOURCE), ('abi_sha256', selection.ABI_SOURCE),
                    ('bridge_sha256', selection.BRIDGE_SOURCE), ('selection_sha256', selection.SELECTION_SOURCE))}}
            output = b'RAW' + bytes(1048573)
            child = {'status': 'returned', 'abi_status': 0, 'core_u32': 3,
                'source_sha256': manifest['source_sha256'], 'image_sha256': context['compiler_sha256'],
                'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
                'output_sha256': sha256(output).hexdigest(),
                'limits': {'cpu_seconds': 10, 'address_bytes': 268435456, 'core_dumpable': False,
                           'stack_bytes': 8388608, 'output_capacity': 1048576, 'workspace_bytes': 1048576}}
            receipt = {**child, 'case': 'core-unpack', 'input_sha256': manifest['source_sha256'],
                'input_bytes': len(inputs[selection.HIA_SOURCE]), 'artifact_sha256': context['compiler_sha256'],
                'format': 'flat-x86-64', 'runner_sha256': context['source_manifest']['tools/hia_selfhost_child.py'],
                'wall_elapsed_ns': 1, 'produced_image': str(image), 'produced_bytes': 3,
                'produced_sha256': manifest['image_sha256']}
            request = {'format': 'flat-x86-64', 'image': str(compiler), 'image_sha256': context['compiler_sha256'],
                'source': str(folder / 'core-unpack.input.bin'), 'source_sha256': manifest['source_sha256'],
                'capacity': 1048576, 'workspace_size': 1048576, 'workspace_fill': 0,
                'output': str(folder / 'core-unpack.output.bin')}
            dump = lambda path, val: path.write_text(json.dumps(val) + '\n')
            dump(folder / 'manifest.json', manifest)
            build = {'schema': 'hepta.hia.core-unpack-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
                'profile': PROFILE, 'manifest': manifest, 'source_manifest': context['source_manifest'],
                'cold_report_sha256': context['cold_sha256'], 'native_compile_receipt': receipt,
                'original_Core_39_units_unchanged': True, 'unpack_control_in_HIA': True,
                'CPython_primitives_still_hosted': True, 'whole_stack_rewritten_in_hia': False,
                'production_activated': False}
            dump(folder / 'build.json', build)
            dump(folder / 'core-unpack.receipt.json', receipt)
            dump(folder / 'core-unpack.stdout.log', child)
            (folder / 'core-unpack.stderr.log').write_bytes(b'')
            dump(folder / 'core-unpack.request.json', request)
            (folder / 'core-unpack.input.bin').write_bytes(inputs[selection.HIA_SOURCE])
            (folder / 'core-unpack.output.bin').write_bytes(output)
            with patch.object(gates, 'ROOT', root), patch.object(gates.previous, 'ROOT', root):
                before = gates.companion_build(folder, context)
                self.assertEqual(len(before['compile_originals']), 6)
                self.assertEqual(before['compile_originals'][-1]['bytes'], 1048576)
                for name, invalid in (('schema', 'hia.core-unpack-development-build.v1'),
                                      ('cold_report_sha256', 'f' * 64), ('source_manifest', {})):
                    changed = deepcopy(build); changed[name] = invalid; dump(folder / 'build.json', changed)
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        gates.companion_build(folder, context)
                dump(folder / 'build.json', build)
                original = (folder / 'core-unpack.output.bin').read_bytes()
                (folder / 'core-unpack.output.bin').write_bytes(original[:-1] + b'X')
                with self.assertRaises(ValueError):
                    gates.companion_build(folder, context)
                (folder / 'core-unpack.output.bin').write_bytes(original)
                (folder / 'core-unpack.stderr.log').write_bytes(b'after initial readback')
                after = gates.companion_build(folder, context)
                self.assertNotEqual(before, after)  # Captured component before/after must reject this drift.

    def test_finite_reports_require_original_ids_files_and_same_companion(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value); base = root / 'evidence'; directory = base / 'component/finite-native'
            directory.mkdir(parents=True)
            names = [gates.FINITE_CONTROL, gates.FINITE_LAUNCHER]
            inputs = {name: (ROOT / name).read_bytes() for name in names}
            inputs.update({'hepta/hia_core_unpack_native.py': b'SYNTHETIC bridge',
                           'tools/hia_core_unpack_transaction.S': b'SYNTHETIC transaction'})
            for name, raw in inputs.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            image = root / 'image'; image.write_bytes(b'inert')
            binding = {'UNPACK': {'files': [{}, gates.file_record(image)], 'transaction_sha256': 'a' * 64}}
            context = {'source_manifest': {name: sha256(raw).hexdigest() for name, raw in inputs.items()}}
            paths = [root / gates.FINITE_CONTROL, root / 'hepta/hia_core_unpack_native.py',
                     root / 'tools/hia_core_unpack_transaction.S', image]
            sources = {str(path): gates.file_record(path)['sha256'] for path in paths}
            actual = {'schema': 'hepta.hia.core-unpack-experimental-control.v1', 'status': 'EXPERIMENTAL_CONTROL_PASS',
                'phase': 'native', 'loaded_test_ids': gates.FINITE_IDS['finite-native'],
                'executed_test_ids': gates.FINITE_IDS['finite-native'], 'tests_run': 6,
                'failures': 0, 'errors': 0, 'skipped': 0, 'expected_failures': 0, 'unexpected_successes': 0,
                'source_before': sources, 'source_after': sources, 'source_stable': True,
                'shim_sha256': 'a' * 64, 'ordinary_entry_116_executed': False, 'cold_qualified': False,
                'whole_python_object_runtime_in_hia': False}
            report_path = directory / 'report.json'
            report_path.write_text(json.dumps(actual))
            (directory / 'unittest.log').write_text('SYNTHETIC — no tests executed')
            row = {'label': 'finite-native', 'returncode': 0, 'report': actual,
                   'report_original': gates.file_record(report_path)}
            for stream in ('stdout', 'stderr'):
                path = directory.parent / ('finite-native.' + stream + '.log'); path.write_bytes(b'')
                row[stream] = gates.file_record(path)
            with patch.object(gates, 'ROOT', root), patch.object(gates.previous, 'ROOT', root):
                row['command'] = gates.finite_command('finite-native', base, binding)
                self.assertEqual(gates.inspect_finite('finite-native', base, binding, context, row)['complete_method_count'], 6)
                for key, replacement in (('loaded_test_ids', []), ('tests_run', True), ('skipped', 1),
                                         ('source_after', {}), ('cold_qualified', True)):
                    bad = deepcopy(actual); bad[key] = replacement
                    report_path.write_text(json.dumps(bad))
                    changed = deepcopy(row); changed['report'] = bad
                    changed['report_original'] = gates.file_record(report_path)
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        gates.inspect_finite('finite-native', base, binding, context, changed)

    def test_old_full_harness_suite_and_all_old_functions_except_run_are_unchanged(self):
        old = ast.parse((RUNNERS / 'run_hia_qualification_v9.py').read_bytes())
        new = ast.parse((RUNNERS / 'run_hia_qualification_v10.py').read_bytes())
        functions = lambda tree: {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        left, right = functions(old), functions(new)
        self.assertEqual(set(right) - set(left), {'complete_core_unpack'})
        for name in set(left) - {'run'}:
            self.assertEqual(ast.dump(left[name]), ast.dump(right[name]), name)
        self.assertIn('timeout=5400 if discover else 1800', ast.unparse(right['suite']))
        text = (RUNNERS / 'run_hia_qualification_v10.py').read_text()
        self.assertIn('compiler_owner_gates.require_successor_gates(mandatory_v9_gates)', text)
        self.assertIn('core_unpack_gates.require_successor_gates(mandatory_v10_gates)', text)
        self.assertIn('core_unpack_outcome = complete_core_unpack()', text)

    def test_complete_ledger_keeps_all_original_limits_and_denominators(self):
        value = json.loads((ROOT / 'docs/HIA_CORE_UNPACK_QUALIFICATION_GATES.json').read_bytes())
        self.assertEqual(value['old_mandatory_gates'], list(gates.previous.SUCCESSOR_GATES))
        self.assertEqual(value['additional_mandatory_gates'], list(gates.NEW_GATES))
        self.assertEqual(value['source_generator_order'], list(gates.previous.SOURCE_GENERATORS))
        self.assertEqual(value['source_generator_count'], 61)
        self.assertEqual(value['original_caller_counts'], [15, 51, 50])
        self.assertEqual(value['complete_original_callers'], 116)
        self.assertEqual(value['complete_component_methods'], 18)
        self.assertEqual(value['limits'], {'cold_seconds': 180, 'cold_workers': 2, 'cold_phases': 38,
            'phase_qualification_seconds': 180, 'phase_cleanup_seconds': 3, 'product_owner_count': 2,
            'compile_child_wall_seconds': 20, 'compile_child_CPU_seconds': 10, 'compile_output_bytes': 1048576,
            'full_retained_seconds': 5400, 'outer_guardian_seconds': 10800,
            'original_native_timeout_seconds': 5, 'original_evaluation_seconds': 3})
        self.assertFalse(value['development_capsule_accepted'])
        self.assertTrue(value['both_new_gates_require_full18_and_full116'])


if __name__ == '__main__':
    unittest.main()
