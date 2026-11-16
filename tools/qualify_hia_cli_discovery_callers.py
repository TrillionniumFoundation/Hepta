"""Observe explicit HIA discovery JSON through both ordinary CLI routes.

The four original JSON qualification groups remain unchanged. This additional
gate admits current cold evidence, compiles the current CLI companions and
observes the complete discovery outputs, parser diagnostics and refusal paths.
Development execution is recorded separately and never grants cold authority.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.hia_cli_discovery_custody import (
    admit_cold, admit_compilation, binding, check_bindings, guard_authority,
    owner_sources, publish, read_json, require,
)
from tools import qualify_hia_cli_discovery_json as original

CLASS = 'tests.test_hia_cli_discovery_selection.CliDiscoverySelectionNativeTests'
EXPECTED_IDS = (
    CLASS + '.test_01_all_original_outputs_through_both_ordinary_cli_routes',
    CLASS + '.test_02_parser_errors_and_help_remain_exact_under_both_routes',
    CLASS + '.test_03_selected_missing_or_empty_manifest_never_falls_back',
)


def child(request_path):
    from tools.run_hia_unittest_gate import load_declared_suite
    request = read_json(request_path.read_bytes())
    require(request['source_pins'] == owner_sources(), 'CLI discovery caller sources changed')
    check_bindings(request['bindings'])
    suite, planned = load_declared_suite((CLASS,))
    require(tuple(planned) == EXPECTED_IDS, 'complete CLI discovery test IDs required')
    started, stopped = [], []
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id())
            super().startTest(test)
        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
    anomalies = {
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), error) for test, error in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
    }
    stable = owner_sources() == request['source_pins']
    check_bindings(request['bindings'])
    passed = (result.wasSuccessful() and not any(anomalies.values()) and stable
              and started == stopped == list(EXPECTED_IDS) and result.testsRun == len(EXPECTED_IDS))
    report = {'status': 'PASS' if passed else 'FAIL', 'scope': request['scope'],
        'request_sha256': sha256(request_path.read_bytes()).hexdigest(),
        'planned': list(planned), 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'source_and_inputs_unchanged': stable, **anomalies}
    publish(request['output'], report)
    return 0 if passed else 1


def qualify(output, *, cold_report=None, development_manifest=None, development_cli_manifest=None):
    require((cold_report is not None) != (development_manifest is not None), 'one explicit qualification scope required')
    require((development_manifest is None) == (development_cli_manifest is None), 'both development manifests required')
    authority = admit_cold(cold_report) if cold_report is not None else None
    output = Path(output).absolute()
    require(not output.is_relative_to(ROOT), 'CLI discovery evidence must be outside the source tree')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = owner_sources()
    scope = ('MATCHING_SOURCE_COLD_ORDINARY_CLI_DISCOVERY_CALLERS' if authority is not None
             else 'EXPLICIT_DEVELOPMENT_CLI_DISCOVERY_CALLERS_NOT_CURRENT_COLD')
    report = {'schema': 'hepta.hia.cli-discovery-callers.v1', 'status': 'FAIL', 'scope': scope,
              'matching_cold': authority is not None, 'source_before': before,
              'whole_native_delivery_qualified': False}
    try:
        environment = {key: value for key, value in os.environ.items() if not key.startswith('HEPTA_HIA_')}
        if authority is not None:
            from tools.build_hia_cli_native import build, SOURCES
            fixture = original.prepare_fixture(output / 'json-fixture', cold_report)
            selected = original.admit_fixture(fixture)
            manifest = Path(selected['build']['manifest'])
            cli_manifest = build(output / 'cli', Path(authority['compiler']), Path(cold_report))
            for name, source_name in SOURCES.items():
                directory = cli_manifest.parent / name
                admit_compilation(directory, 'cli-' + name, authority['compiler'],
                    (ROOT / source_name).read_bytes(), directory / ('cli-' + name + '.image.bin'))
            environment[original.COLD_FIXTURE] = str(fixture)
        else:
            manifest = Path(development_manifest).resolve(strict=True)
            cli_manifest = Path(development_cli_manifest).resolve(strict=True)
            cli_build = read_json((cli_manifest.parent / 'build.json').read_bytes())
            from tools.build_hia_cli_native import owner_sources as cli_sources
            require(cli_build.get('scope') == 'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD'
                    and cli_build.get('source_manifest') is None
                    and cli_build.get('owner_sources_before') == cli_sources() == cli_build.get('owner_sources_after'),
                    'current explicit development CLI build required')
            environment[original.DEVELOPMENT] = str(manifest)
        controls = output / 'controls'
        controls.mkdir(mode=0o700)
        environment.update({original.EVIDENCE: str(controls),
                            'HEPTA_HIA_CLI_DISCOVERY_CALLERS_CLI_MANIFEST': str(cli_manifest)})
        bindings = [binding(path) for directory in (manifest.parent, cli_manifest.parent)
                    for path in sorted(directory.rglob('*')) if path.is_file()]
        request = {'schema': 'hepta.hia.cli-discovery-callers-request.v1', 'scope': scope,
                   'source_pins': before, 'bindings': bindings, 'output': str(output / 'TESTS.json')}
        request_path = output / 'REQUEST.json'
        publish(request_path, request)
        observed = original._owned([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                                    '--_child', str(request_path)], output / 'command', environment)
        report['process_owner'] = observed
        tests = read_json((output / 'TESTS.json').read_bytes())
        report['tests'] = tests
        native = read_json((controls / 'ORDINARY_CLI.json').read_bytes())
        report['native_observations'] = native
        require(original._owner_pass(observed) and tests.get('status') == 'PASS'
                and tests.get('request_sha256') == sha256(request_path.read_bytes()).hexdigest()
                and tests.get('planned') == tests.get('started') == tests.get('stopped') == list(EXPECTED_IDS)
                and type(tests.get('actual_tests')) is int and tests['actual_tests'] == len(EXPECTED_IDS)
                and tests.get('source_and_inputs_unchanged') is True
                and all(type(tests.get(name)) is list and not tests[name] for name in original.ANOMALIES)
                and native.get('status') == 'PASS' and native.get('actual_native_json_calls') == 20,
                'complete ordinary CLI discovery caller observations required')
        check_bindings(bindings)
        require(before == owner_sources(), 'CLI discovery caller inputs changed')
        if authority is not None:
            guard_authority(authority)
            original.admit_fixture(fixture)
        report.update(status='PASS', source_after=owner_sources(), source_and_inputs_unchanged=True)
    except BaseException:
        report['traceback'] = traceback.format_exc()
    publish(output / 'REPORT.json', report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path)
    parser.add_argument('--development-manifest', type=Path)
    parser.add_argument('--development-cli-manifest', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--_child', type=Path)
    args = parser.parse_args(argv)
    if args._child is not None:
        require(all(value is None for value in (args.cold_report, args.development_manifest,
                args.development_cli_manifest, args.evidence)), 'child arguments must remain separate')
        return child(args._child)
    require(args.evidence is not None, 'explicit evidence directory required')
    report = qualify(args.evidence, cold_report=args.cold_report,
                     development_manifest=args.development_manifest,
                     development_cli_manifest=args.development_cli_manifest)
    print(json.dumps({name: report[name] for name in ('status', 'scope', 'matching_cold')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
