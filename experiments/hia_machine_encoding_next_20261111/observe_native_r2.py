"""One development compile and original caller run for HIA instruction bytes."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
HERE = Path(__file__).resolve().parent
COMPILER_SHA = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
MODULES = (
    'tests.test_hia_machine_x64',
    'tests.test_hia_machine_plan',
    'tests.test_hia_machine_registers',
    'tests.test_hia_machine_leaf_registers',
    'tests.test_hia_agent_native_machine_choices',
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    compiler_bytes = args.compiler.read_bytes()
    if sha(compiler_bytes) != COMPILER_SHA:
        raise ValueError('this observation requires its explicitly pinned development compiler')
    local_compiler = directory / 'development-compiler.image.bin'
    local_compiler.write_bytes(compiler_bytes)
    source = HERE / 'source-r2/machine_encoding.hiaasm'
    from tools.hia_selfhost_contract import CONTRACT_PATH, file_digests
    def pins():
        result = file_digests(ROOT)
        for path in (ROOT / CONTRACT_PATH, source, HERE / 'generate_machine_encoding.py',
                     HERE / 'native_encoding_bridge.py', HERE / 'observe_core_r2.py', Path(__file__)):
            result[path.relative_to(ROOT).as_posix()] = sha(path.read_bytes())
        return result
    before = pins()
    report = {'schema': 'hepta.hia.machine-encoding.native-development.v1',
              'scope': 'PINNED_DEVELOPMENT_COMPILER_NOT_CURRENT_COLD_OR_RELEASE',
              'status': 'STARTED', 'compiler_sha256': COMPILER_SHA,
              'compiler_original_path': str(args.compiler.resolve()),
              'compiler_origin': '416 desktop B3; that complete cold run remained HOLD',
              'source_before': before, 'modules': list(MODULES),
              'retained_encoding_entries': [], 'cases': [], 'python': sys.version}
    (directory / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    started = time.monotonic()
    try:
        from tools.qualify_hia_selfhost import compile_stage
        image, compilation = compile_stage(directory, 'machine-encoding', local_compiler, source.read_bytes())
        report['compilation'] = compilation
        manifest = {'schema': 'hepta.hia.machine-encoding-native.v2', 'source_sha256': sha(source.read_bytes()),
                    'image_path': image.name, 'image_sha256': sha(image.read_bytes()), 'compiler_sha256': COMPILER_SHA}
        manifest_path = directory / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        bridge = load(HERE / 'native_encoding_bridge.py', 'native_encoding_trial_bridge')
        oracle = load(HERE / 'observe_core_r2.py', 'native_encoding_independent_oracle')
        from hepta.hia_json_preflight_native import _installed_json_image
        encoding = _installed_json_image(str(manifest_path), source, manifest['schema'], bridge.NativeMachineEncoding)
        from hepta import hia_machine_x64 as reference
        original_class = reference.Code
        selected_class = bridge.selected_code_class(encoding)
        rows = oracle.cases()
        expected = [oracle.observe(original_class, row) for row in rows]
        hosted_methods = {'__init__', '_reg', 'emit', 'label'}
        forbidden_methods = [
            name for name, member in original_class.__dict__.items()
            if inspect.isfunction(member) and name not in hosted_methods
        ]
        report['forbidden_retained_encoding_methods'] = forbidden_methods
        def forbidden(name):
            def fail(*args, **kwargs):
                report['retained_encoding_entries'].append(name)
                raise AssertionError('retained machine byte encoder entered: ' + name)
            return fail
        with ExitStack() as guards:
            for name in forbidden_methods:
                guards.enter_context(patch.object(original_class, name, forbidden(name)))
            for row, wanted in zip(rows, expected):
                actual = oracle.observe(selected_class, row)
                report['cases'].append({**row, 'reference': wanted, 'candidate': actual, 'equal': actual == wanted})
                if actual != wanted:
                    raise AssertionError('native complete Code observation differs: ' + row['id'])
        if set(encoding.calls) != set(bridge.COMMANDS):
            raise AssertionError('not every numeric packing command reached HIA')
        report['paired_commands'] = dict(encoding.calls)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(MODULES)
        loaded = [test.id() for test in flatten(suite)]
        report['loaded_ids'] = loaded
        report['loader_errors'] = list(loader.errors)
        if not loaded or loader.errors or len(set(loaded)) != len(loaded):
            raise AssertionError('original caller suite did not load completely')
        executed = []
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                executed.append(test.id())
                super().startTest(test)
        # Existing modules may already hold a from-import alias. Replace every
        # actual repository alias to the same original class, preserving the
        # original test IDs, methods, inputs, assertions and module denominator.
        with ExitStack() as guards:
            aliases = []
            for name, module in tuple(sys.modules.items()):
                if not module or not (name == 'hepta' or name.startswith(('hepta.', 'tests.', 'tools.'))):
                    continue
                for key, value in tuple(vars(module).items()):
                    if value is original_class:
                        guards.enter_context(patch.object(module, key, selected_class))
                        aliases.append(name + '.' + key)
            report['actual_code_aliases_selected'] = aliases
            for name in forbidden_methods:
                guards.enter_context(patch.object(original_class, name, forbidden(name)))
            start = time.monotonic()
            with (directory / 'unittest.log').open('x') as stream:
                result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
            report['test_seconds'] = time.monotonic() - start
        report['executed_ids'] = executed
        report['testsRun'] = result.testsRun
        for kind in ('failures', 'errors', 'skipped', 'expectedFailures'):
            report[kind] = [[test.id(), detail] for test, detail in getattr(result, kind)]
        report['unexpectedSuccesses'] = [test.id() for test in result.unexpectedSuccesses]
        report['native_calls_by_command'] = dict(encoding.calls)
        report['native_image_sha256'] = manifest['image_sha256']
        if (loaded != executed or result.testsRun != len(loaded)
                or any(report[kind] for kind in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))
                or report['retained_encoding_entries']):
            raise AssertionError('original caller gate did not pass completely')
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'FAIL'
        report['exception'] = traceback.format_exc()
    report['source_after'] = pins()
    report['source_stable'] = before == report['source_after']
    report['compiler_stable'] = local_compiler.read_bytes() == compiler_bytes == args.compiler.read_bytes()
    if not report['source_stable'] or not report['compiler_stable']:
        report['status'] = 'FAIL'
    report['seconds'] = time.monotonic() - started
    (directory / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('schema', 'scope', 'status', 'seconds', 'source_stable', 'compiler_stable')} |
        {'cases': len(report['cases']), 'testsRun': report.get('testsRun'), 'exception': report.get('exception')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
