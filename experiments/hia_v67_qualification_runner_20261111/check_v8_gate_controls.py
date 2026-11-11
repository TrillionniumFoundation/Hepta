"""Exercise actual v8 admission against explicitly synthetic controller receipts.

No fixture image is executable. No HIA product, cold or release pass is claimed.
Original caller validators and the full regression observer are compared by AST.
"""
import argparse
import ast
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import native_owner_gates as gates


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def change(path, keys, value):
    current = json.loads(path.read_bytes())
    target = current
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    write(path, current)


def receipt(raw, source, compiler):
    return {'status': 'returned', 'abi_status': 0, 'source_unchanged': True,
            'produced_sha256': sha256(raw).hexdigest(), 'produced_bytes': len(raw),
            'input_sha256': source, 'artifact_sha256': compiler,
            'forbidden_compiler_modules_loaded': []}


def ids(modules, count):
    return [modules[index % len(modules)] + '.Synthetic.test_%03d' % index for index in range(count)]


def fixture(root):
    compiler = sha256(b'controller fixture compiler, never executable').hexdigest()
    sources = {name: sha256(name.encode()).hexdigest() for name in (*gates.CLI_OWNER_FILES,
               'examples/hia_bootstrap/machine_encoding.hiaasm', 'docs/HIA_SELFHOST_CORE_SUPPORT.json')}
    cold = {'schema': 'hepta.hia.selfhost-cold-replay.v1', 'profile': 'controller-fixture-only',
            'status': 'COLD_SELFHOST_REPLAY_PASS', 'returncode': 0,
            'checks': dict.fromkeys(gates.COLD_CHECKS, True), 'source_manifest': sources,
            'generation_sha256': [compiler] * 3}
    write(root / 'cold.json', cold)
    encoding = root / 'encoding'
    raw = b'instruction-byte controller fixture, never executable'
    manifest = {'schema': 'hepta.hia.machine-encoding-native.v2',
                'source_sha256': sources['examples/hia_bootstrap/machine_encoding.hiaasm'],
                'compiler_sha256': compiler, 'image_path': 'image.bin', 'image_sha256': sha256(raw).hexdigest()}
    write(encoding / 'build/manifest.json', manifest)
    (encoding / 'build/image.bin').write_bytes(raw)
    build = {'schema': 'hepta.hia.machine-encoding-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
             'profile': cold['profile'], 'source_manifest': sources, 'manifest': manifest,
             'cold_report_sha256': sha256((root / 'cold.json').read_bytes()).hexdigest(),
             'native_compile_receipt': receipt(raw, manifest['source_sha256'], compiler)}
    write(encoding / 'build/build.json', build)
    groups = []
    for name, count, modules in [('component', 9, ('tests.test_hia_machine_encoding_native',)),
                                  ('original-callers', 51, gates.ENCODING_MODULES)]:
        loaded = ids(modules, count)
        groups.append({'label': name, 'modules': list(modules), 'loaded_ids': loaded,
                       'executed_ids': loaded[:], 'tests_run': count, 'strict_pass': True,
                       **dict.fromkeys(('loader_errors', 'failures', 'errors', 'skipped',
                                        'expectedFailures', 'unexpectedSuccesses'), [])})
    write(encoding / 'report.json', {
        'schema': 'hepta.hia.machine-encoding-selected-callers.v1', 'status': 'PASS',
        'scope': 'MATCHING_SOURCE_COLD_SELECTED_CALLERS', 'source_before': sources, 'source_after': sources,
        'source_stable': True, 'manifest_image_stable': True, 'retained_encoding_entries': [],
        'default_or_whole_stack_claimed': False, 'groups': groups,
        'native_entries': dict.fromkeys(gates.ENCODING_COMMANDS, 1), 'manifest': manifest,
        'manifest_sha256': gates.record(encoding / 'build/manifest.json')['sha256'],
        'native_image_sha256': manifest['image_sha256'],
    })
    cli = root / 'cli'
    bundle = {'schema': 'hepta.hia.cli-native-bundle.v1'}
    children = {}
    for name, source in gates.CLI_SOURCES.items():
        raw = ('CLI ' + name + ' controller fixture, never executable').encode()
        manifest = {'schema': 'hepta.hia.cli-' + name + '-native.v1',
                    'source_sha256': sources[source], 'compiler_sha256': compiler,
                    'image_path': 'image.bin', 'image_sha256': sha256(raw).hexdigest()}
        path = cli / 'qualified' / name / 'manifest.json'
        write(path, manifest)
        path.with_name('image.bin').write_bytes(raw)
        bundle[name + '_manifest'] = name + '/manifest.json'
        bundle[name + '_manifest_sha256'] = gates.record(path)['sha256']
        children[name] = {'manifest': manifest, 'native_compile_receipt': receipt(raw, sources[source], compiler)}
    write(cli / 'qualified/manifest.json', bundle)
    owner_sources = {name: sources[name] for name in gates.CLI_OWNER_FILES}
    write(cli / 'qualified/build.json', {
        'schema': 'hepta.hia.cli-native-build.v1', 'scope': 'MATCHING_SOURCE_COLD_BUILD',
        'source_manifest': sources, 'owner_sources_before': owner_sources, 'owner_sources_after': owner_sources,
        'compiler_sha256': compiler, 'cold_report_sha256': sha256((root / 'cold.json').read_bytes()).hexdigest(),
        'children': children, 'bundle': bundle, 'native_compiler_profile_expanded': False,
        'production_activated': False, 'whole_cli_native': False, 'whole_native_delivery_qualified': False})
    write(cli / 'observations.json', {
        'schema': 'hia.cli.native-test-observations.v1', 'scope': 'MATCHING_SOURCE_COLD_BUILD',
        'manifest': str((cli / 'qualified/manifest.json').resolve()), 'whole_native_delivery_qualified': False,
        'observations': [{'all_actions': sorted(gates.CLI_ACTIONS), 'cases': [
            {'equal': True, 'actual': ['return', 0], 'expected': ['return', 0]} for _ in range(23)]}]})
    loaded = ids(('tests.test_hia_agent_entry',), 6)
    write(cli / 'original-agent-entry/report.json', {
        'schema': 'hia.cli.original-agent-entry-native-selection.v1', 'status': 'PASS',
        'loaded_test_ids': loaded, 'executed_test_ids': loaded[:], 'tests_run': 6,
        'selected_child_argv': [['verify', 'fixture']], **dict.fromkeys(
            ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'), [])})
    return sources


def mutate(kind, directory, case):
    def edit(name, keys, value):
        change(directory / kind / name, keys, value)
    if case == 'normal':
        return
    if case == 'missing-report':
        (directory / kind / ('report.json' if kind == 'encoding' else 'observations.json')).unlink()
    elif case == 'cold-check':
        change(directory / 'cold.json', ['checks', 'nested_full_qualification_pass'], False)
    elif case == 'cold-source':
        change(directory / 'cold.json', ['source_manifest'], {})
    elif case == 'cold-generations':
        change(directory / 'cold.json', ['generation_sha256'], ['7' * 64, '8' * 64, '7' * 64])
    elif case == 'image-bytes':
        (directory / kind / ('build/image.bin' if kind == 'encoding' else 'qualified/control/image.bin')).write_bytes(b'changed')
    elif case == 'image-symlink':
        path = directory / kind / ('build/image.bin' if kind == 'encoding' else 'qualified/control/image.bin')
        path.rename(path.with_name('held.bin'))
        path.symlink_to('held.bin')
    elif kind == 'encoding':
        changes = {
            'development': ('report.json', ['scope'], 'EXPLICIT_DEVELOPMENT_ONLY'),
            'status': ('report.json', ['status'], 'FAIL'),
            'source-before': ('report.json', ['source_before'], {}),
            'source-after': ('report.json', ['source_after'], {}),
            'retained-owner': ('report.json', ['retained_encoding_entries'], ['mov_rr']),
            'missing-command': ('report.json', ['native_entries'], {'align': 1}),
            'zero-command': ('report.json', ['native_entries', 'align'], 0),
            'bool-command': ('report.json', ['native_entries', 'align'], True),
            'dropped-original': ('report.json', ['groups', 1, 'tests_run'], 50),
            'bool-count': ('report.json', ['groups', 1, 'tests_run'], True),
            'wrong-modules': ('report.json', ['groups', 1, 'modules'], ['tests.foreign']),
            'build-source': ('build/build.json', ['source_manifest'], {}),
            'build-cold': ('build/build.json', ['cold_report_sha256'], '7' * 64),
            'compile-failed': ('build/build.json', ['native_compile_receipt', 'abi_status'], 1),
            'bool-abi': ('build/build.json', ['native_compile_receipt', 'abi_status'], True),
            'source-mutated': ('build/build.json', ['native_compile_receipt', 'source_unchanged'], False),
            'forbidden-compiler': ('build/build.json', ['native_compile_receipt', 'forbidden_compiler_modules_loaded'], ['retained']),
        }
        if case.startswith('anomaly-'):
            edit('report.json', ['groups', 1, case.removeprefix('anomaly-')], ['controller anomaly'])
        elif case == 'duplicate-ids':
            value = gates.json_file(directory / kind / 'report.json')
            loaded = value['groups'][1]['loaded_ids']; loaded[1] = loaded[0]
            value['groups'][1]['executed_ids'] = loaded[:]
            write(directory / kind / 'report.json', value)
        else:
            name, keys, value = changes[case]; edit(name, keys, value)
    else:
        changes = {
            'development': ('qualified/build.json', ['scope'], 'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD'),
            'observed-development': ('observations.json', ['scope'], 'EXPLICIT_DEVELOPMENT_ONLY'),
            'owner-source': ('qualified/build.json', ['owner_sources_after'], {}),
            'build-cold': ('qualified/build.json', ['cold_report_sha256'], '7' * 64),
            'expanded-profile': ('qualified/build.json', ['native_compiler_profile_expanded'], True),
            'whole-claim': ('qualified/build.json', ['whole_cli_native'], True),
            'missing-child': ('qualified/build.json', ['children'], {}),
            'bundle-path': ('qualified/manifest.json', ['control_manifest'], '../escape'),
            'missing-actions': ('observations.json', ['observations', 0, 'all_actions'], []),
            'missing-cases': ('observations.json', ['observations', 0, 'cases'], []),
            'different-case': ('observations.json', ['observations', 0, 'cases', 0, 'equal'], False),
            'original-count': ('original-agent-entry/report.json', ['tests_run'], 5),
            'missing-selection': ('original-agent-entry/report.json', ['selected_child_argv'], []),
            'original-failed': ('original-agent-entry/report.json', ['status'], 'FAIL'),
        }
        if case.startswith('anomaly-'):
            edit('original-agent-entry/report.json', [case.removeprefix('anomaly-')], ['controller anomaly'])
        else:
            name, keys, value = changes[case]; edit(name, keys, value)


def assignment(tree, name):
    return next(node for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))


def static_and_conjunction_controls(directory):
    runner = Path(__file__).with_name('run_hia_qualification_v8.py')
    original = Path(__file__).with_name('run_hia_qualification_v7_original.py')
    tree, old = ast.parse(runner.read_bytes()), ast.parse(original.read_bytes())
    def function(group, name):
        return next(node for node in group.body if isinstance(node, ast.FunctionDef) and node.name == name)
    preserved = {}
    for name in ('_pinned_state', 'file_record', 'suite', 'selected_journal_callers',
                 'selected_machine_plan_callers', 'selected_json_wire_callers'):
        raw = ast.dump(function(tree, name), include_attributes=False)
        assert raw == ast.dump(function(old, name), include_attributes=False), name
        preserved[name] = sha256(raw.encode()).hexdigest()
    assert ast.dump(assignment(tree, 'mandatory_gates')) == ast.dump(assignment(old, 'mandatory_gates'))
    assert ast.dump(assignment(tree, 'reproduce_code')) == ast.dump(assignment(old, 'reproduce_code'))
    assert ast.dump(assignment(tree, 'cold_completed')) == ast.dump(assignment(old, 'cold_completed'))
    old_groups = ast.literal_eval(next(node.value for node in ast.walk(old)
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'groups' for t in node.targets)))
    new_groups = ast.literal_eval(next(node.value for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'groups' for t in node.targets)))
    assert all(new_groups.get(key) == value for key, value in old_groups.items())
    assert set(new_groups) - set(old_groups) == {'json-wire-cache', 'cli'}
    assert sha256(runner.with_name('process_owner_impl.py').read_bytes()).hexdigest() == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
    assert sha256(runner.with_name('guardian.py').read_bytes()).hexdigest() == 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
    names = ('mandatory_gates', 'mandatory_v8_gates', 'all_passed', 'full_outcome', 'full_qualified', 'status')
    compiled = compile(ast.Module(body=[assignment(tree, name) for name in names], type_ignores=[]), str(runner), 'exec')
    cases = ['normal', 'json-wire-cache', 'cli', 'cli-fixture', 'encoding-callers', 'journal-denominator',
             'plan-denominator', 'wire-denominator', 'full-retained-regression', 'prerequisite', 'source', 'harness']
    rows = []
    for case in cases:
        outcomes = {name: {'passed': name != case} for name in (*new_groups, 'full-retained-regression')}
        environment = {'prerequisite_admission': {'status': 'CURRENT_SOURCE_PREREQUISITES_ADMITTED_NOT_TEST_PASS'},
            'prerequisites_preserved': case != 'prerequisite', 'suite_outcomes': outcomes,
            'caller_outcome': {'passed': True, 'tests_run': 93 if case == 'journal-denominator' else 94},
            'machine_plan_caller_outcome': {'passed': True, 'tests_run': 43 if case == 'plan-denominator' else 44},
            'json_wire_caller_outcome': {'passed': True, 'tests_run': 88 if case == 'wire-denominator' else 89},
            'machine_encoding_caller_outcome': {'passed': case != 'encoding-callers'},
            'cli_fixture_outcome': {'passed': case != 'cli-fixture'}, 'ok': True,
            'preserved': case != 'source', 'harness_preserved': case != 'harness', 'a': SimpleNamespace(full=True)}
        exec(compiled, environment)
        assert environment['status'] == ('FULL_RETAINED_PASS' if case == 'normal' else 'HOLD'), case
        rows.append({'case': case, 'status': environment['status']})
    return {'preserved_function_ast_sha256': preserved, 'old_groups_preserved': old_groups,
            'additional_complete_groups': {name: new_groups[name] for name in set(new_groups) - set(old_groups)},
            'conjunction_controls': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    common = ['normal', 'missing-report', 'cold-check', 'cold-source', 'cold-generations', 'image-bytes', 'image-symlink']
    selections = {
        'encoding': common + ['development', 'status', 'source-before', 'source-after', 'retained-owner',
            'missing-command', 'zero-command', 'bool-command', 'dropped-original', 'bool-count', 'wrong-modules',
            'build-source', 'build-cold', 'compile-failed', 'bool-abi', 'source-mutated', 'forbidden-compiler', 'duplicate-ids']
            + ['anomaly-' + name for name in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')],
        'cli': common + ['development', 'observed-development', 'owner-source', 'build-cold', 'expanded-profile',
            'whole-claim', 'missing-child', 'bundle-path', 'missing-actions', 'missing-cases', 'different-case',
            'original-count', 'missing-selection', 'original-failed']
            + ['anomaly-' + name for name in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')],
    }
    rows = []
    for kind, cases in selections.items():
        for case in cases:
            directory = output / kind / case; directory.mkdir(parents=True)
            sources = fixture(directory)
            mutate(kind, directory, case)
            passed, error = False, None
            try:
                arguments = (directory / kind, (directory / 'cold.json').read_bytes(), sources)
                result = (gates.encoding_callers(*arguments, 'controller-fixture-only') if kind == 'encoding'
                          else gates.cli_fixture(*arguments, sources, 'controller-fixture-only'))
                passed = True
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as failure:
                error = repr(failure)
            row = {'kind': kind, 'case': case, 'expected_pass': case == 'normal', 'actual_pass': passed, 'error': error}
            rows.append(row)
            write(output / 'progress.json', {'scope': 'SYNTHETIC_CONTROLLER_CONTROLS_ONLY', 'cases': rows})
            assert passed is (case == 'normal'), row
    static = static_and_conjunction_controls(output)
    result = {'schema': 'hia.v8-controller-admission-controls.v1', 'status': 'CONTROLLER_CONTROLS_PASS',
              'scope': 'SYNTHETIC_CONTROLLER_CONTROLS_ONLY', 'cases': rows, **static,
              'runner_sha256': sha256(Path(__file__).with_name('run_hia_qualification_v8.py').read_bytes()).hexdigest(),
              'helper_sha256': sha256(Path(gates.__file__).read_bytes()).hexdigest(),
              'controller_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
              'product_or_cold_qualification_claimed': False}
    write(output / 'receipt.json', result)
    print(json.dumps({'status': result['status'], 'receipt_controls': len(rows),
                      'conjunction_controls': len(static['conjunction_controls']),
                      'product_or_cold_qualification_claimed': False}))


if __name__ == '__main__':
    main()
