"""Focused accounting controls only; no compiler, HIA image or cold process runs."""
from __future__ import annotations
import argparse
import ast
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import time
import traceback
import unittest
from unittest.mock import patch
from types import SimpleNamespace

EXPECTED = {
    'tools/qualify_hia_machine_state_callers.py': '9df4b35742c342a61262733287d68157eb66f1a9bc10032a235309825d2be52c',
    'tools/qualify_hia_machine_instructions_callers.py': '76f87d7938f9bb69526e3f1d545510b0acfd821454f5cf280406e28e4cdcb944',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    if output == source or output.is_relative_to(source):
        raise ValueError('control evidence must be outside source')
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    report = {'schema': 'hepta.hia.native-caller-accounting-controls.v1',
              'status': 'HOLD', 'scope': 'SYNTHETIC_RECEIPT_AND_SOURCE_CONTROLS_ONLY',
              'product_execution': False, 'cold_qualification': False,
              'compiler_or_native_image_executed': False}
    def pins():
        return {name: sha256((source / name).read_bytes()).hexdigest() for name in EXPECTED}
    try:
        report['source_before'] = pins()
        if report['source_before'] != EXPECTED:
            raise ValueError('controls require their exact preexecution candidate source')
        parsed = {name: ast.parse((source / name).read_text()) for name in EXPECTED}
        sys.path.insert(0, str(source))
        from tools import qualify_hia_machine_state_callers as policy
        from tools import qualify_hia_machine_instructions_callers as instructions
        if (Path(policy.__file__).resolve() != source / 'tools/qualify_hia_machine_state_callers.py'
                or Path(instructions.__file__).resolve() != source / 'tools/qualify_hia_machine_instructions_callers.py'):
            raise ValueError('controls imported another source checkout')
        base_dir = Path(__file__).resolve().parent / 'base'
        original = {name: ast.parse((base_dir / (Path(name).name + '.txt')).read_text())
                    for name in EXPECTED}

        class AccountingControls(unittest.TestCase):
            def case(self, edit=None):
                with tempfile.TemporaryDirectory(prefix='accounting-', dir=output) as folder:
                    retained = Path(folder) / 'retained'
                    retained.write_bytes(b'original')
                    expected_sources = {'test-source': 'pinned'}
                    requirements = {'state': ('initialize', 'emit'), 'encoding': ('mov', 'ret')}
                    manifests = {
                        'component': {'state': 'component-state', 'encoding': 'component-encoding'},
                        'original-callers': {'state': 'caller-state', 'encoding': 'caller-encoding'},
                    }
                    def binding(values, context, sources):
                        owners = {kind: {'manifest': {'image_sha256': name}}
                                  for kind, name in values.items()}
                        return {'owners': owners, 'admission': 'SYNTHETIC_CONTROL'}, [(retained, b'original')]
                    groups = {label: {'manifests': values, 'before': binding(values, None, None)[0],
                                      'inputs': [(retained, b'original')]}
                              for label, values in manifests.items()}
                    returns = {
                        'component': {'state': {'component-state': {'initialize': 1}},
                                      'encoding': {'component-encoding': {'mov': 1}}},
                        'original-callers': {'state': {'caller-state': {'emit': 1}},
                                             'encoding': {'caller-encoding': {'ret': 1}}},
                    }
                    value = {'status': 'PASS', 'native_state_entries': {'initialize': 99, 'emit': 99}}
                    context = {'source_manifest': expected_sources, 'synthetic': True}
                    scenario = {'groups': groups, 'returns': returns, 'value': value,
                                'context': context, 'context_after': deepcopy(context),
                                'sources_after': dict(expected_sources), 'identity_changes': [],
                                'retained': retained}
                    if edit is not None:
                        edit(scenario)
                    with patch.object(policy, 'source_pins', return_value=scenario['sources_after']), \
                         patch.object(policy, 'cold_accounting_context', return_value=scenario['context_after']), \
                         patch.object(policy, 'native_group_binding', side_effect=binding):
                        policy.finish_native_accounting(
                            value, scenario['groups'], scenario['returns'], scenario['identity_changes'],
                            requirements, context, Path(folder) / 'synthetic-cold',
                            expected_sources, [(retained, b'original')])
                    return value

            def test_distinct_group_images_and_partial_per_group_coverage_are_admitted(self):
                value = self.case()
                self.assertEqual(value['status'], 'PASS')
                self.assertIs(value['normal_return_coverage_complete'], True)
                self.assertEqual(value['normal_return_coverage'],
                                 {'state': ['emit', 'initialize'], 'encoding': ['mov', 'ret']})
                self.assertEqual(set(value['native_group_bindings']), {'component', 'original-callers'})

            def test_attempts_alone_cannot_supply_normal_return_coverage(self):
                value = self.case(lambda s: s['returns'].clear())
                self.assertEqual(value['status'], 'FAIL')
                self.assertEqual(value['native_state_entries'], {'initialize': 99, 'emit': 99})
                self.assertIs(value['normal_return_coverage_complete'], False)

            def test_component_image_cannot_be_counted_as_the_caller_image(self):
                def edit(s):
                    s['returns']['original-callers']['state'] = {'component-state': {'emit': 1}}
                self.assertEqual(self.case(edit)['status'], 'FAIL')

            def test_missing_group_and_missing_operations_are_refused(self):
                def missing_group(s):
                    s['groups'].pop('original-callers')
                    s['returns'].pop('original-callers')
                self.assertEqual(self.case(missing_group)['status'], 'FAIL')
                def missing_operation(s):
                    s['returns']['original-callers']['state'] = {'caller-state': {'initialize': 1}}
                self.assertEqual(self.case(missing_operation)['status'], 'FAIL')

            def test_source_and_cold_drift_are_refused_without_discarding_before_bindings(self):
                def source_change(s):
                    s['sources_after']['test-source'] = 'changed'
                value = self.case(source_change)
                self.assertEqual(value['status'], 'FAIL')
                self.assertEqual(set(value['native_group_bindings']), {'component', 'original-callers'})
                self.assertIsNone(value['native_group_bindings']['component']['after'])
                def cold_change(s):
                    s['context_after']['synthetic'] = False
                self.assertEqual(self.case(cold_change)['status'], 'FAIL')

            def test_actual_retained_file_change_is_refused(self):
                def edit(s):
                    s['retained'].write_bytes(b'changed')
                value = self.case(edit)
                self.assertEqual(value['status'], 'FAIL')
                self.assertIs(value['manifest_images_bundle_stable'], False)

            def test_existing_failure_and_attempt_ledger_are_not_upgraded(self):
                def edit(s):
                    s['value'].update(status='FAIL', exception='original foreign failure')
                value = self.case(edit)
                self.assertEqual(value['status'], 'FAIL')
                self.assertEqual(value['exception'], 'original foreign failure')
                self.assertEqual(value['native_state_entries'], {'initialize': 99, 'emit': 99})
                self.assertIs(value['normal_return_coverage_complete'], False)

            def test_return_ledger_preserves_cross_return_image_change(self):
                rows, changes = {}, []
                owner = SimpleNamespace(image_sha256='after')
                policy.record_native_return(rows, changes, 'component', 'state', owner, 'before', 'emit')
                self.assertEqual(rows, {'component': {'state': {'before': {'emit': 1}}}})
                self.assertEqual(changes[0]['before'], 'before')
                self.assertEqual(changes[0]['after'], 'after')
                self.assertEqual(self.case(lambda s: s['identity_changes'].extend(changes))['status'], 'FAIL')

            def test_group_capture_cannot_overwrite_previous_binding(self):
                groups = {'component': {'before': 'original'}}
                with self.assertRaisesRegex(ValueError, 'captured twice'):
                    policy.capture_native_group(groups, 'component', {}, None, {})
                self.assertEqual(groups, {'component': {'before': 'original'}})

            def test_original_helpers_and_complete_group_selection_are_unchanged(self):
                def function(tree, name):
                    return next(node for node in tree.body
                                if isinstance(node, ast.FunctionDef) and node.name == name)
                def group_loop(tree):
                    main = function(tree, 'main')
                    return next(node for node in ast.walk(main)
                                if isinstance(node, ast.For) and isinstance(node.target, ast.Tuple)
                                and [getattr(v, 'id', None) for v in node.target.elts]
                                == ['label', 'modules', 'expected_count', 'guard'])
                state_path = 'tools/qualify_hia_machine_state_callers.py'
                for name in ('flatten', 'strict_pass', 'source_pins', 'copy_manifest'):
                    self.assertEqual(ast.dump(function(original[state_path], name)),
                                     ast.dump(function(parsed[state_path], name)))
                for name in EXPECTED:
                    self.assertEqual(ast.dump(group_loop(original[name]).iter),
                                     ast.dump(group_loop(parsed[name]).iter))
                self.assertEqual(policy.ORIGINAL_MODULES, instructions.ORIGINAL_MODULES)
                self.assertEqual(len(policy.ORIGINAL_MODULES), 5)

            def test_normal_return_recording_follows_original_call_and_retains_attempts(self):
                for name, tree in parsed.items():
                    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
                    old_main = next(n for n in original[name].body
                                    if isinstance(n, ast.FunctionDef) and n.name == 'main')
                    functions = {n.name: n for n in main.body if isinstance(n, ast.FunctionDef)}
                    old_functions = {n.name: n for n in old_main.body if isinstance(n, ast.FunctionDef)}
                    for fname in ('tracked_run', 'tracked_state', 'tracked_encode'):
                        if fname not in old_functions:
                            continue
                        old, new = old_functions[fname], functions[fname]
                        self.assertIsInstance(old.body[-1], ast.Return)
                        self.assertEqual(ast.dump(old.body[-1].value), ast.dump(new.body[-3].value))
                        self.assertEqual([ast.dump(n) for n in old.body[:-1]],
                                         [ast.dump(n) for n in new.body[1:-3]])
                        self.assertEqual(new.body[-2].value.func.id, 'record_native_return')
                        self.assertIsInstance(new.body[-1], ast.Return)

        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(AccountingControls)
        loaded = [test.id() for test in suite]
        executed = []
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                executed.append(test.id())
                super().startTest(test)
        with (output / 'unittest.log').open('x') as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
        report.update(loaded_ids=loaded, executed_ids=executed, tests_run=result.testsRun,
                      loader_errors=list(loader.errors))
        for name in ('errors', 'failures', 'skipped', 'expectedFailures'):
            report[name] = [[test.id(), detail] for test, detail in getattr(result, name)]
        report['unexpectedSuccesses'] = [test.id() for test in result.unexpectedSuccesses]
        if (loaded and loaded == executed and len(set(loaded)) == len(loaded)
                and result.testsRun == len(loaded) and not loader.errors
                and not any(report[name] for name in (
                    'errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))):
            report['status'] = 'CONTROL_ONLY_PASS'
    except BaseException:
        report['failure'] = traceback.format_exc()
    finally:
        try:
            report['source_after'] = pins()
            report['source_stable'] = report.get('source_before') == report['source_after'] == EXPECTED
            if not report['source_stable']:
                report['status'] = 'HOLD'
        except BaseException:
            report['status'] = 'HOLD'
            report['final_source_failure'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        (output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'tests_run': report.get('tests_run'),
                          'scope': report['scope']}))
    return 0 if report['status'] == 'CONTROL_ONLY_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
