"""Run the unchanged four/six finite controls and eight ordinary composition methods.

This entire command requires its own original 180/3 owner. It never substitutes
for the separate, unsplit original Core116 command. Each finite transaction
control is confined to a child; a pending PyErr never returns to arbitrary
controller Python code.
"""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import clean_environment, create, document, read, require, save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    root, source = args.root, args.source
    context, context_pin = document(root / 'context.json', 2 << 20)
    policy_raw, policy_pin = read(root / 'control/policy.json', 1 << 20)
    policy = json.loads(policy_raw)
    require(context['policy_sha256'] == policy_pin['sha256'] == args.policy_sha256
            and context['source'] == str(source) and context['root'] == str(root)
            and context['candidate'] == policy['candidate'], 'component context differs')
    require(sys.version_info[:3] == (3, 14, 4)
            and str(Path(sys.executable).resolve()) == context['python']['resolved'],
            'component interpreter differs')
    directory = root / 'components'
    directory.mkdir(mode=0o700)
    report = {'schema': 'hia.core-unpack-components.v1', 'status': 'HOLD',
              'candidate': policy['candidate'], 'context_sha256': context_pin['sha256'],
              'policy_sha256': policy_pin['sha256'], 'python': sys.version,
              'controller_seconds': 180, 'cleanup_seconds': 3,
              'expected_groups': [4, 6, 8], 'expected_method_count': 18,
              'groups': [], 'complete_original116_executed': False,
              'cold_qualified': False, 'CPython_primitives_still_hosted': True}
    started = time.monotonic()
    before = None
    try:
        sys.path.insert(0, str(source))
        from tools.qualify_hia_core_lowering_callers import source_pins
        from hepta import hia_core_unpack_native as primitive
        before = source_pins()
        report['source_before'] = before
        inputs = [root / 'preparation/bundle/manifest.json',
                  root / 'preparation/unpack/manifest.json',
                  root / 'preparation/unpack/core-unpack.image.bin',
                  source / 'hepta/hia_core_unpack_native.py',
                  source / 'tools/hia_core_unpack_transaction.S',
                  root / 'control/finite_controls.py', root / 'control/finite_launcher.py']
        report['input_originals_before'] = [read(path, 1 << 20)[1] for path in inputs]
        for label, phase in (('shim', 'shim'), ('finite-native', 'native')):
            command = [sys.executable, '-I', '-S', '-B', str(root / 'control/finite_launcher.py'),
                       str(source), '--phase', phase,
                       '--bridge', str(source / 'hepta/hia_core_unpack_native.py'),
                       '--shim-source', str(source / 'tools/hia_core_unpack_transaction.S'),
                       '--evidence-dir', str(directory / label)]
            if phase == 'native':
                command += ['--image', str(root / 'preparation/unpack/core-unpack.image.bin')]
            at = time.monotonic()
            process = subprocess.run(command, cwd=source, env=clean_environment(),
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
            row = {'label': label, 'command': command, 'returncode': process.returncode,
                   'seconds': time.monotonic() - at,
                   'stdout': create(directory / (label + '.stdout.log'), process.stdout),
                   'stderr': create(directory / (label + '.stderr.log'), process.stderr)}
            report['groups'].append(row)
            actual, pin = document(directory / label / 'report.json', 2 << 20)
            row['report_original'], row['report'] = pin, actual
            expected = policy['component_groups'][label]['ids']
            require(process.returncode == 0 and actual['status'] == 'EXPERIMENTAL_CONTROL_PASS'
                    and actual['phase'] == phase and actual['loaded_test_ids'] == expected
                    and actual['executed_test_ids'] == expected and actual['tests_run'] == len(expected)
                    and all(actual[name] == 0 for name in ('failures', 'errors', 'skipped',
                        'expected_failures', 'unexpected_successes'))
                    and actual['source_before'] == actual['source_after']
                    and actual['source_stable'] is True and actual['shim_sha256'] == primitive.SHIM_SHA256,
                    'complete retained finite group failed: ' + label)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName('tests.test_hia_core_unpack_native')
        def flatten(value):
            for item in value:
                if isinstance(item, unittest.TestSuite):
                    yield from flatten(item)
                else:
                    yield item.id()
        loaded = list(flatten(suite))
        require(not loader.errors and loaded == policy['component_groups']['ordinary']['ids']
                and len(loaded) == 8, 'complete ordinary eight loaded IDs differ')
        executed, current, returns = [], ['outside-test'], Counter()
        class RecordingResult(unittest.TextTestResult):
            def startTest(self, test):
                current[0] = test.id()
                executed.append(test.id())
                super().startTest(test)
        original_step = primitive.UnpackSession._step
        def record_step(session, packet):
            status = original_step(session, packet)
            returns[(current[0], session.image.image_sha256, status)] += 1
            return status
        env = {'HEPTA_HIA_CORE_LOWERING_DEVELOPMENT_MANIFEST': str(root / 'preparation/bundle/manifest.json'),
               'HEPTA_HIA_CORE_UNPACK_MANIFEST': str(root / 'preparation/unpack/manifest.json'),
               'HEPTA_HIA_CORE_UNPACK_FIXTURE_EVIDENCE': str(directory / 'ordinary-fixture')}
        at = time.monotonic()
        with (directory / 'ordinary.unittest.log').open('x') as stream, \
                patch.dict(os.environ, env), patch.object(primitive.UnpackSession, '_step', record_step):
            result = unittest.TextTestRunner(stream=stream, verbosity=2,
                                            resultclass=RecordingResult).run(suite)
        ordinary = {'label': 'ordinary', 'loaded_ids': loaded, 'executed_ids': executed,
                    'tests_run': result.testsRun, 'seconds': time.monotonic() - at,
                    'loader_errors': loader.errors,
                    'errors': [(test.id(), detail) for test, detail in result.errors],
                    'failures': [(test.id(), detail) for test, detail in result.failures],
                    'skipped': [(test.id(), detail) for test, detail in result.skipped],
                    'expectedFailures': [(test.id(), detail) for test, detail in result.expectedFailures],
                    'unexpectedSuccesses': [test.id() for test in result.unexpectedSuccesses],
                    'actual_UNPACK_step_returns': [dict(test=key[0], image_sha256=key[1], status=key[2], count=n)
                                                  for key, n in sorted(returns.items())]}
        report['groups'].append(ordinary)
        require(result.wasSuccessful() and result.testsRun == 8 and loaded == executed
                and all(ordinary[name] == [] for name in ('loader_errors', 'errors', 'failures',
                    'skipped', 'expectedFailures', 'unexpectedSuccesses')),
                'complete ordinary composition eight failed')
        manifest, _ = document(root / 'preparation/unpack/manifest.json')
        require(returns and all(key[0] in loaded and key[1] == manifest['image_sha256'] for key in returns)
                and {0, 1} <= {key[2] for key in returns},
                'ordinary composition has no bound actual UNPACK step returns')
        report['input_originals_after'] = [read(path, 1 << 20)[1] for path in inputs]
        require(report['input_originals_before'] == report['input_originals_after'],
                'component primitive/image originals changed')
        report['status'] = 'DEVELOPMENT_ALL_18_COMPONENT_METHODS_PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
        traceback.print_exc()
    finally:
        try:
            from tools.qualify_hia_core_lowering_callers import source_pins
            report['source_after'] = source_pins()
            report['source_stable'] = before is not None and before == report['source_after']
            if not report['source_stable']:
                report['status'] = 'HOLD'
        except BaseException:
            report['status'] = 'HOLD'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        save(directory / 'report.json', report)
    print(json.dumps({'status': report['status'], 'seconds': report['seconds'],
                      'executed_groups': len(report['groups']), 'report': str(directory / 'report.json')}), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_ALL_18_COMPONENT_METHODS_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
