"""Exercise six HIA Code state owners and all original 51 encoder callers."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

ORIGINAL_MODULES = (
    'tests.test_hia_machine_x64',
    'tests.test_hia_machine_plan',
    'tests.test_hia_machine_registers',
    'tests.test_hia_machine_leaf_registers',
    'tests.test_hia_agent_native_machine_choices',
)
COMPONENT_MODULES = ('tests.test_hia_machine_state_native',)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def strict_pass(result, loaded, executed):
    return bool(loaded and len(set(loaded)) == len(loaded) and loaded == executed
                and result.testsRun == len(loaded)
                and not any(getattr(result, name) for name in (
                    'failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')))


def source_pins():
    from tools.hia_selfhost_contract import CONTRACT_PATH, file_digests
    return {**file_digests(ROOT), CONTRACT_PATH: sha256((ROOT / CONTRACT_PATH).read_bytes()).hexdigest()}


def copy_manifest(original, destination):
    raw = original.read_bytes()
    value = json.loads(raw)
    image = original.parent / value['image_path']
    image_bytes = image.read_bytes()
    if sha256(image_bytes).hexdigest() != value['image_sha256']:
        raise ValueError('development image differs from its original manifest')
    destination.mkdir(mode=0o700)
    (destination / image.name).write_bytes(image_bytes)
    value['image_path'] = image.name
    manifest = destination / 'manifest.json'
    manifest.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    (destination / 'original-manifest.json').write_bytes(raw)
    return manifest


_NATIVE_BUILD_SPECS = {
    'state': ('machine_state', 'machine-state', 1),
    'instructions': ('machine_instructions', 'machine-instructions', 1),
    'encoding': ('machine_encoding', 'machine-encoding', 2),
}


def _require(value, message):
    if not value:
        raise ValueError(message)


def _read_json(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            _require(key not in value, 'duplicate native accounting receipt field')
            value[key] = item
        return value
    raw = Path(path).read_bytes()
    return raw, json.loads(raw, object_pairs_hook=unique)


def _file_binding(path, raw):
    return {'path': str(Path(path).resolve(strict=True)), 'bytes': len(raw),
            'sha256': sha256(raw).hexdigest()}


def cold_accounting_context(path):
    """Bind actual outer/nested/B3 bytes through the unchanged cold admission."""
    if path is None:
        return None
    from tools.build_hia_json_preflight import admit_cold_build
    path = Path(path).resolve(strict=True)
    cold_raw, outer = _read_json(path)
    nested_path = Path(outer['nested_report']).resolve(strict=True)
    nested_raw, nested = _read_json(nested_path)
    _require(sha256(nested_raw).hexdigest() == outer.get('nested_report_sha256'),
             'native caller cold nested identity differs')
    compiler = Path(nested['generations'][-1]['produced_image']).resolve(strict=True)
    compiler_raw = compiler.read_bytes()
    sources = admit_cold_build(compiler_raw, cold_raw)
    _require(nested.get('source_manifest') == sources
             and [row.get('produced_sha256') for row in nested['generations']]
             == outer.get('generation_sha256'), 'native caller cold generation/source differs')
    return {'source_manifest': sources, 'cold_sha256': sha256(cold_raw).hexdigest(),
            'compiler_sha256': sha256(compiler_raw).hexdigest(),
            'files': [_file_binding(p, raw) for p, raw in (
                (path, cold_raw), (nested_path, nested_raw), (compiler, compiler_raw))]}


def native_group_binding(manifests, context, sources):
    """Read each group's own actual files; do not borrow another instance's pins."""
    _require(source_pins() == sources, 'source changed before native group binding')
    if context is not None:
        _require(context['source_manifest'] == sources, 'native group cold source differs')
    owners, inputs = {}, []
    for kind, requested in manifests.items():
        source_name, protocol, version = _NATIVE_BUILD_SPECS[kind]
        manifest_path = Path(requested).resolve(strict=True)
        manifest_raw, manifest = _read_json(manifest_path)
        _require(type(manifest) is dict and set(manifest) == {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            and manifest['schema'] == 'hepta.hia.' + protocol + '-native.v' + str(version),
            'native group manifest schema differs: ' + kind)
        relative = 'examples/hia_bootstrap/' + source_name + '.hepta'
        _require(manifest['source_sha256'] == sources.get(relative),
                 'native group source differs: ' + kind)
        image_name = manifest['image_path']
        _require(type(image_name) is str and image_name and Path(image_name).name == image_name,
                 'native group image must be one retained filename')
        image_path = (manifest_path.parent / image_name).resolve(strict=True)
        _require(image_path.parent == manifest_path.parent,
                 'native group image escaped its retained build')
        image_raw = image_path.read_bytes()
        _require(image_raw and sha256(image_raw).hexdigest() == manifest['image_sha256'],
                 'native group actual image differs: ' + kind)
        files = [(manifest_path, manifest_raw), (image_path, image_raw)]
        if context is not None:
            build_path = manifest_path.parent / 'build.json'
            build_raw, build = _read_json(build_path)
            _require(build.get('schema') == 'hepta.hia.' + protocol + '-build.v1'
                     and build.get('status') == 'NATIVE_CANDIDATE_BUILT'
                     and build.get('source_manifest') == sources
                     and build.get('cold_report_sha256') == context['cold_sha256']
                     and build.get('manifest') == manifest
                     and build.get('production_activated') is False
                     and manifest['compiler_sha256'] == context['compiler_sha256'],
                     'native group actual cold build differs: ' + kind)
            receipt = build.get('native_compile_receipt', {})
            _require(receipt.get('status') == 'returned' and receipt.get('abi_status') == 0
                     and receipt.get('source_sha256') == manifest['source_sha256']
                     and receipt.get('input_sha256') == manifest['source_sha256']
                     and receipt.get('image_sha256') == context['compiler_sha256']
                     and receipt.get('artifact_sha256') == context['compiler_sha256']
                     and receipt.get('produced_sha256') == manifest['image_sha256']
                     and receipt.get('produced_bytes') == len(image_raw)
                     and receipt.get('source_unchanged') is True
                     and receipt.get('forbidden_compiler_modules_loaded') == []
                     and receipt.get('limits') == {
                         'address_bytes': 268435456, 'core_dumpable': False, 'cpu_seconds': 10,
                         'output_capacity': 1048576, 'stack_bytes': 8388608,
                         'workspace_bytes': 1048576},
                     'native group compile receipt differs: ' + kind)
            files.append((build_path, build_raw))
        owners[kind] = {'manifest': manifest, 'files': [_file_binding(p, raw) for p, raw in files]}
        inputs.extend(files)
    return {'owners': owners,
            'source_manifest_sha256': sha256(json.dumps(
                sources, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'admission': ('INDEPENDENT_MATCHING_COLD_BUILD_READBACK' if context is not None
                          else 'EXPLICIT_DEVELOPMENT_ONLY')}, inputs


def capture_native_group(groups, label, manifests, context, sources):
    _require(label not in groups, 'native group binding was captured twice')
    binding, inputs = native_group_binding(manifests, context, sources)
    groups[label] = {'manifests': dict(manifests), 'before': binding, 'inputs': inputs}


def record_native_return(ledger, identity_changes, group, kind, owner, image_before, operation):
    """A normal selected-method return, not an attempted call or raw CPU counter."""
    if image_before is None:
        return
    after = getattr(owner, 'image_sha256', None)
    if after != image_before:
        identity_changes.append({'group': group, 'kind': kind,
                                 'before': image_before, 'after': after, 'operation': operation})
    images = ledger.setdefault(group, {}).setdefault(kind, {})
    counts = images.setdefault(image_before, {})
    counts[operation] = counts.get(operation, 0) + 1


def finish_native_accounting(report, groups, returns, identity_changes, requirements,
                             context, cold_report, before, inputs):
    """Keep partial ledgers on failure; coverage uses only stable admitted images."""
    report['native_counter_semantics'] = {
        'existing_native_entries': 'selected-call attempts before the original method',
        'normal_returns_by_group_image_operation': 'original selected method returned normally',
        'exceptional_calls_removed_from_attempt_ledger': False,
        'component_counts_relabelled_as_caller_counts': False,
    }
    report['normal_native_returns_by_group_image_operation'] = returns
    report['normal_return_image_identity_changes'] = identity_changes
    report['native_group_bindings'] = {
        label: {'before': captured['before'], 'after': None,
                'all_actual_file_bytes_stable': None, 'binding_stable': None}
        for label, captured in groups.items()}
    report['normal_return_coverage'] = {}
    report['normal_return_coverage_complete'] = False
    report['cold_input_binding_before'] = context
    report['source_after'] = None
    report['source_stable'] = False
    report['manifest_images_bundle_stable'] = False
    report['cold_input_binding_after'] = None
    report['cold_input_binding_stable'] = False
    try:
        report['source_after'] = source_pins()
        report['source_stable'] = before == report['source_after']
        report['manifest_images_bundle_stable'] = bool(inputs) and all(
            path.read_bytes() == raw for path, raw in inputs)
        after_context = cold_accounting_context(cold_report)
        report['cold_input_binding_after'] = after_context
        report['cold_input_binding_stable'] = context == after_context
        _require(report['source_stable'] and report['manifest_images_bundle_stable']
                 and report['cold_input_binding_stable'], 'native caller final source/build/cold changed')
        for label, captured in groups.items():
            after, _ = native_group_binding(captured['manifests'], context, before)
            raw_stable = all(path.read_bytes() == raw for path, raw in captured['inputs'])
            row = {'before': captured['before'], 'after': after,
                   'all_actual_file_bytes_stable': raw_stable,
                   'binding_stable': captured['before'] == after}
            report['native_group_bindings'][label] = row
            _require(raw_stable and row['binding_stable'], 'native group retained bytes changed: ' + label)
        if report['status'] == 'PASS':
            _require(set(groups) == {'component', 'original-callers'}
                     and set(returns) == set(groups) and not identity_changes,
                     'complete separate component/caller return bindings required')
            coverage = {kind: set() for kind in requirements}
            for label, captured in groups.items():
                _require(set(captured['before']['owners']) == set(requirements)
                         and set(returns[label]) == set(requirements),
                         'native return owner group differs: ' + label)
                for kind, expected in requirements.items():
                    digest = captured['before']['owners'][kind]['manifest']['image_sha256']
                    actual = returns[label][kind]
                    _require(set(actual) == {digest} and actual[digest]
                             and all(type(count) is int and count > 0 for count in actual[digest].values()),
                             'native returns were not bound to this group image: ' + label + '/' + kind)
                    _require(set(actual[digest]) <= set(expected),
                             'native return operation differs: ' + kind)
                    coverage[kind].update(actual[digest])
            report['normal_return_coverage'] = {kind: sorted(values) for kind, values in coverage.items()}
            _require(all(coverage[kind] == set(expected) for kind, expected in requirements.items()),
                     'complete admitted normal-return operation coverage was not observed')
            report['normal_return_coverage_complete'] = True
    except BaseException:
        report['status'] = 'FAIL'
        report['final_identity_or_accounting_error'] = traceback.format_exc()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development-bundle', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    directory = args.evidence.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    from hepta import hia_machine_x64 as reference
    from hepta.hia_machine_encoding_native import (
        SELECTOR as ENCODING_SELECTOR, COMMANDS, NativeEncodedCode, NativeMachineEncoding,
        installed_machine_encoding)
    from hepta.hia_machine_state_native import SELECTOR, MODES, NativeMachineState, installed_machine_state
    before = source_pins()
    report = {'schema': 'hepta.hia.machine-state-selected-callers.v1', 'status': 'STARTED',
              'scope': 'MATCHING_SOURCE_COLD_SELECTED_CALLERS' if args.cold_report else 'EXPLICIT_DEVELOPMENT_ONLY',
              'source_before': before, 'groups': [], 'retained_owner_entries': [],
              'default_or_whole_stack_claimed': False, 'python': sys.version,
              'guarded_original_caller_denominator': 51,
              'component_denominator': 12, 'all_original_methods_unchanged': True}
    started = time.monotonic()
    native_entries, encoding_entries, per_test = Counter(), Counter(), Counter()
    active_test = ['outside-test']
    active_group = ['outside-group']
    group_bindings, normal_returns, image_identity_changes = {}, {}, []
    cold_context = None
    original_run, original_encode = NativeMachineState.run, NativeMachineEncoding.encode
    def tracked_run(owner, receiver, mode, *arguments):
        image_before = getattr(owner, 'image_sha256', None)
        if hasattr(owner, 'image_sha256'):
            native_entries[MODES[mode - 1]] += 1
            per_test[active_test[0]] += 1
        value = original_run(owner, receiver, mode, *arguments)
        record_native_return(normal_returns, image_identity_changes, active_group[0],
                             'state', owner, image_before, MODES[mode - 1])
        return value
    def tracked_encode(owner, command, **values):
        image_before = getattr(owner, 'image_sha256', None)
        if hasattr(owner, 'image_sha256'):
            encoding_entries[command] += 1
        value = original_encode(owner, command, **values)
        record_native_return(normal_returns, image_identity_changes, active_group[0],
                             'encoding', owner, image_before, command)
        return value
    def forbidden(name):
        def fail(*args, **kwargs):
            report['retained_owner_entries'].append(name)
            raise AssertionError('retained Code owner entered: ' + name)
        return fail
    inputs = []
    try:
        cold_context = cold_accounting_context(args.cold_report)
        if args.cold_report:
            from tools.build_hia_machine_state import build
            from tools.build_hia_machine_encoding import build as build_encoding
            outer = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            state_manifest = build(directory / 'state', compiler, args.cold_report)
            encoding_manifest = build_encoding(directory / 'encoding', compiler, args.cold_report)
        else:
            raw = args.development_bundle.read_bytes()
            bundle = json.loads(raw)
            state_manifest = copy_manifest(Path(bundle['state_manifest']).resolve(strict=True), directory / 'state')
            encoding_manifest = copy_manifest(Path(bundle['encoding_manifest']).resolve(strict=True), directory / 'encoding')
            (directory / 'original-development-bundle.json').write_bytes(raw)
            report['original_development_bundle_sha256'] = sha256(raw).hexdigest()
        native = installed_machine_state(str(state_manifest))
        encoding = installed_machine_encoding(str(encoding_manifest))
        for manifest in (state_manifest, encoding_manifest):
            raw = manifest.read_bytes()
            value = json.loads(raw)
            image = manifest.parent / value['image_path']
            inputs.extend([(manifest, raw), (image, image.read_bytes())])
        bundle = directory / 'bundle.json'
        bundle.write_text(json.dumps({'state_manifest': str(state_manifest),
                                      'encoding_manifest': str(encoding_manifest)},
                                     sort_keys=True, indent=2) + '\n')
        inputs.append((bundle, bundle.read_bytes()))
        report.update(state_manifest=str(state_manifest), encoding_manifest=str(encoding_manifest),
                      state_image_sha256=native.image_sha256, encoding_image_sha256=encoding.image_sha256,
                      input_bindings=[{'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                                      for path, raw in inputs])
        with patch.object(NativeMachineState, 'run', tracked_run), patch.object(NativeMachineEncoding, 'encode', tracked_encode):
            for label, modules, expected_count, guard in (
                    ('component', COMPONENT_MODULES, 12, False),
                    ('original-callers', ORIGINAL_MODULES, 51, True)):
                active_group[0] = label
                loader = unittest.TestLoader()
                suite = loader.loadTestsFromNames(modules)
                loaded = [test.id() for test in flatten(suite)]
                executed = []
                class Result(unittest.TextTestResult):
                    def startTest(self, test):
                        active_test[0] = test.id()
                        executed.append(test.id())
                        super().startTest(test)
                row = {'label': label, 'modules': list(modules), 'expected_methods': expected_count,
                       'loaded_ids': loaded, 'loader_errors': list(loader.errors)}
                report['groups'].append(row)
                if loader.errors or len(loaded) != expected_count or len(set(loaded)) != len(loaded):
                    raise AssertionError('complete unchanged method denominator did not load')
                with ExitStack() as guards:
                    if guard:
                        capture_native_group(group_bindings, label, {
                            'state': state_manifest, 'encoding': encoding_manifest}, cold_context, before)
                        guards.enter_context(patch.dict(os.environ, {
                            SELECTOR: str(state_manifest), ENCODING_SELECTOR: str(encoding_manifest)}))
                        for name, member in reference.Code.__dict__.items():
                            if inspect.isfunction(member) and name != '__new__':
                                guards.enter_context(patch.object(reference.Code, name, forbidden('Code.' + name)))
                        guards.enter_context(patch.object(reference.Code, 'offset', property(forbidden('Code.offset'))))
                        guards.enter_context(patch.object(reference, '_reg', forbidden('_reg')))
                        guards.enter_context(patch.object(NativeEncodedCode, '__init__', forbidden('NativeEncodedCode.__init__')))
                        guards.enter_context(patch.object(NativeEncodedCode, 'finalize', forbidden('NativeEncodedCode.finalize')))
                    else:
                        guards.enter_context(patch.dict(os.environ, {
                            SELECTOR: '', ENCODING_SELECTOR: '',
                            'HEPTA_HIA_MACHINE_STATE_COLD_REPORT': str(args.cold_report.resolve()) if args.cold_report else '',
                            'HEPTA_HIA_MACHINE_STATE_DEVELOPMENT_BUNDLE': '' if args.cold_report else str(bundle),
                            'HEPTA_HIA_MACHINE_STATE_FIXTURE_EVIDENCE': str(directory / 'component-fixture')}))
                        component = sys.modules[COMPONENT_MODULES[0]].MachineStateNativeTests
                        original_setup = component.setUpClass
                        def setup(cls):
                            original_setup()
                            _require(cls.scope == ('MATCHING_SOURCE_COLD_BUILD' if args.cold_report
                                                   else 'EXPLICIT_DEVELOPMENT_ONLY'),
                                     'native state component selected the wrong scope')
                            capture_native_group(group_bindings, label, {
                                'state': cls.manifest, 'encoding': cls.encoding_manifest}, cold_context, before)
                        guards.enter_context(patch.object(component, 'setUpClass', classmethod(setup)))
                    at = time.monotonic()
                    with (directory / (label + '.unittest.log')).open('x') as stream:
                        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
                    row['seconds'] = time.monotonic() - at
                row['executed_ids'], row['tests_run'] = executed, result.testsRun
                for key in ('failures', 'errors', 'skipped', 'expectedFailures'):
                    row[key] = [[test.id(), detail] for test, detail in getattr(result, key)]
                row['unexpectedSuccesses'] = [test.id() for test in result.unexpectedSuccesses]
                row['strict_pass'] = strict_pass(result, loaded, executed)
                if not row['strict_pass']:
                    raise AssertionError('selected caller group failed: ' + label)
        if report['retained_owner_entries'] or set(native_entries) != set(MODES) or set(encoding_entries) != set(COMMANDS):
            raise AssertionError('complete state and instruction ownership was not observed')
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'FAIL'
        report['exception'] = traceback.format_exc()
    report['native_state_entries'] = dict(native_entries)
    report['native_instruction_entries'] = dict(encoding_entries)
    report['per_test_native_state_entries'] = dict(per_test)
    finish_native_accounting(report, group_bindings, normal_returns, image_identity_changes,
                             {'state': MODES, 'encoding': COMMANDS}, cold_context,
                             args.cold_report, before, inputs)
    report['seconds'] = time.monotonic() - started
    (directory / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in (
        'schema', 'scope', 'status', 'source_stable', 'manifest_images_bundle_stable', 'seconds')}
        | {'groups': [{'label': row['label'], 'tests_run': row.get('tests_run'),
                       'strict_pass': row.get('strict_pass')} for row in report['groups']],
           'exception': report.get('exception')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
