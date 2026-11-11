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
    original_run, original_encode = NativeMachineState.run, NativeMachineEncoding.encode
    def tracked_run(owner, receiver, mode, *arguments):
        if hasattr(owner, 'image_sha256'):
            native_entries[MODES[mode - 1]] += 1
            per_test[active_test[0]] += 1
        return original_run(owner, receiver, mode, *arguments)
    def tracked_encode(owner, command, **values):
        if hasattr(owner, 'image_sha256'):
            encoding_entries[command] += 1
        return original_encode(owner, command, **values)
    def forbidden(name):
        def fail(*args, **kwargs):
            report['retained_owner_entries'].append(name)
            raise AssertionError('retained Code owner entered: ' + name)
        return fail
    inputs = []
    try:
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
                            'HEPTA_HIA_MACHINE_STATE_COLD_REPORT': '',
                            'HEPTA_HIA_MACHINE_STATE_DEVELOPMENT_BUNDLE': str(bundle),
                            'HEPTA_HIA_MACHINE_STATE_FIXTURE_EVIDENCE': str(directory / 'component-fixture')}))
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
    report['source_after'] = source_pins()
    report['source_stable'] = before == report['source_after']
    report['manifest_images_bundle_stable'] = bool(inputs) and all(path.read_bytes() == raw for path, raw in inputs)
    if not report['source_stable'] or not report['manifest_images_bundle_stable']:
        report['status'] = 'FAIL'
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
