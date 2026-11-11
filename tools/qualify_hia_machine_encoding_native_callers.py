"""Run complete selected Code callers with retained instruction encoders forbidden."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import shutil
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
COMPONENT_MODULES = ('tests.test_hia_machine_encoding_native',)


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    directory = args.evidence.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    from hepta import hia_machine_x64 as reference
    from hepta.hia_machine_encoding_native import SOURCE, SELECTOR, installed_machine_encoding, NativeMachineEncoding
    from tools.hia_selfhost_contract import CONTRACT_PATH, file_digests
    def source_pins():
        result = file_digests(ROOT)
        for name in (CONTRACT_PATH, 'tools/generate_hia_machine_encoding.py',
                     'tools/build_hia_machine_encoding.py', 'tools/qualify_hia_machine_encoding_native_callers.py',
                     'hepta/hia_machine_encoding_native.py', 'examples/hia_bootstrap/machine_encoding.hiaasm',
                     'tests/test_hia_machine_encoding_native.py'):
            result[name] = sha256((ROOT / name).read_bytes()).hexdigest()
        return result
    before = source_pins()
    report = {'schema': 'hepta.hia.machine-encoding-selected-callers.v1', 'status': 'STARTED',
              'scope': 'MATCHING_SOURCE_COLD_SELECTED_CALLERS' if args.cold_report else 'EXPLICIT_DEVELOPMENT_ONLY',
              'source_before': before, 'groups': [], 'retained_encoding_entries': [],
              'default_or_whole_stack_claimed': False, 'python': sys.version}
    started = time.monotonic()
    native_entries, per_test = Counter(), Counter()
    active_test = ['outside-test']
    original_encode = NativeMachineEncoding.encode
    def tracked(owner, command, **values):
        if hasattr(owner, 'image_sha256'):
            native_entries[command] += 1
            per_test[active_test[0]] += 1
        return original_encode(owner, command, **values)
    def forbidden(name):
        def fail(*args, **kwargs):
            report['retained_encoding_entries'].append(name)
            raise AssertionError('retained machine byte encoding entered: ' + name)
        return fail
    manifest_before = image_before = None
    try:
        if args.cold_report:
            from tools.build_hia_machine_encoding import build
            outer = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            manifest = build(directory / 'build', Path(nested['generations'][-1]['produced_image']), args.cold_report)
        else:
            original_manifest = args.development_manifest.resolve(strict=True)
            raw = original_manifest.read_bytes()
            value = json.loads(raw)
            original_image = original_manifest.parent / value['image_path']
            bundle = directory / 'development-input'
            bundle.mkdir()
            image_bytes = original_image.read_bytes()
            if sha256(image_bytes).hexdigest() != value['image_sha256']:
                raise ValueError('development image bytes differ')
            destination = bundle / original_image.name
            destination.write_bytes(image_bytes)
            value['image_path'] = destination.name
            manifest = bundle / 'manifest.json'
            manifest.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
            (bundle / 'original-manifest.json').write_bytes(raw)
            report['original_development_manifest'] = str(original_manifest)
            report['original_development_manifest_sha256'] = sha256(raw).hexdigest()
        owner = installed_machine_encoding(str(manifest))
        manifest_before = manifest.read_bytes()
        value = json.loads(manifest_before)
        image = manifest.parent / value['image_path']
        image_before = image.read_bytes()
        report['manifest'] = value
        report['manifest_sha256'] = sha256(manifest_before).hexdigest()
        report['native_image_sha256'] = owner.image_sha256
        with patch.object(NativeMachineEncoding, 'encode', tracked):
            for label, modules, guard_reference in (
                    ('component', COMPONENT_MODULES, False),
                    ('original-callers', ORIGINAL_MODULES, True)):
                loader = unittest.TestLoader()
                suite = loader.loadTestsFromNames(modules)
                loaded = [test.id() for test in flatten(suite)]
                executed = []
                class Result(unittest.TextTestResult):
                    def startTest(self, test):
                        active_test[0] = test.id()
                        executed.append(test.id())
                        super().startTest(test)
                row = {'label': label, 'modules': list(modules),
                       'loaded_ids': loaded, 'loader_errors': list(loader.errors)}
                report['groups'].append(row)
                if loader.errors or not loaded or len(set(loaded)) != len(loaded):
                    raise AssertionError('complete unique caller suite did not load')
                with ExitStack() as guards:
                    if guard_reference:
                        guards.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
                        for name, member in reference.Code.__dict__.items():
                            if inspect.isfunction(member) and name not in {'__new__', '__init__', '_reg', 'emit', 'label'}:
                                guards.enter_context(patch.object(reference.Code, name, forbidden(name)))
                    else:
                        guards.enter_context(patch.dict(os.environ, {
                            SELECTOR: '', 'HEPTA_HIA_MACHINE_ENCODING_COLD_REPORT': '',
                            'HEPTA_HIA_MACHINE_ENCODING_DEVELOPMENT_MANIFEST': str(manifest),
                            'HEPTA_HIA_MACHINE_ENCODING_FIXTURE_EVIDENCE': str(directory / 'component-fixture')}))
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
        if report['retained_encoding_entries'] or not native_entries:
            raise AssertionError('native byte ownership not established')
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'FAIL'
        report['exception'] = traceback.format_exc()
    report['native_entries'] = dict(native_entries)
    report['per_test_native_entries'] = dict(per_test)
    report['source_after'] = source_pins()
    report['source_stable'] = before == report['source_after']
    report['manifest_image_stable'] = (manifest_before is not None and manifest.read_bytes() == manifest_before
                                        and image.read_bytes() == image_before)
    if not report['source_stable'] or not report['manifest_image_stable']:
        report['status'] = 'FAIL'
    report['seconds'] = time.monotonic() - started
    (directory / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('schema', 'scope', 'status', 'source_stable', 'manifest_image_stable', 'seconds')}
        | {'groups': [{'label': row['label'], 'tests_run': row.get('tests_run'), 'strict_pass': row.get('strict_pass')}
                      for row in report['groups']], 'exception': report.get('exception')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

