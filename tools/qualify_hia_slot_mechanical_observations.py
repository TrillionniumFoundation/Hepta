"""Complete original248 + derived7574 expectations and actual VM/Native driver.

Each original group runs twice in fresh owned Python children before either
candidate backend begins. Candidate children do not receive expectation paths.
The original 180s child / 5s cleanup bounds are preserved. Each new candidate
child and this new supervisor have 1800s bounds; no original suite is replaced.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import os
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    ORIGINAL_SECONDS, CANDIDATE_SECONDS, TOTAL_SECONDS, CLEANUP_SECONDS,
    ORACLE_PREFIX, DERIVED_FILE, admit_originals, admit_cases, admit_product,
    canonical, clean_environment, pin, read_json, regular_bytes, run_owned,
    successful_exit, write_json,
)
from tools.read_hia_slot_mechanical_observations import RAW_FILES


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--oracle-root', type=Path)
    parser.add_argument('--derived-inputs', type=Path)
    parser.add_argument('--product-freeze', type=Path, required=True)
    parser.add_argument('--product-freeze-sha256', required=True)
    parser.add_argument('--python', type=Path, default=Path(sys.executable))
    parser.add_argument('--backend', action='append', choices=('vm', 'native'), required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--bridge-bundle', type=Path, required=True)
    parser.add_argument('--expected-bridge-sha256', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--ld-library-path')
    options = parser.parse_args(argv)
    root = options.root.resolve(strict=True)
    oracle_root = (options.oracle_root or root / ORACLE_PREFIX).resolve(strict=True)
    derived = (options.derived_inputs or root / DERIVED_FILE).resolve(strict=True)
    if options.backend != ['native']:
        raise ValueError('v5 is a real mapped native worker capsule; original VM gates stay separate')
    if ('native' in options.backend) != (options.manifest is not None):
        raise ValueError('only the actual native backend needs an explicit compiled manifest')
    evidence = options.evidence.resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    bridge_raw = regular_bytes(options.bridge_bundle)
    from hashlib import sha256
    if sha256(bridge_raw).hexdigest() != options.expected_bridge_sha256:
        raise ValueError('explicit v5 administrator digest differs')
    bridge_pin = {'path': str(options.bridge_bundle.resolve(strict=True)),
                  'bytes': len(bridge_raw), 'sha256': options.expected_bridge_sha256}
    sources = admit_originals(oracle_root)
    product = admit_product(root, options.product_freeze, options.product_freeze_sha256)
    cases = {group: admit_cases(oracle_root, derived, group)
             for group in ('original248', 'derived7574')}
    environment = clean_environment()
    if options.ld_library_path is not None:
        environment['LD_LIBRARY_PATH'] = options.ld_library_path
    plan = {'schema': 'hepta.slot-mechanical.complete-observations-plan.v1',
        'parent_pid': os.getpid(), 'groups': list(cases), 'backends': options.backend,
        'mechanical_bundle': bridge_pin,
        'original_repetitions': 2, 'source_freeze': pin(options.product_freeze),
        'original_seconds': ORIGINAL_SECONDS, 'candidate_seconds': CANDIDATE_SECONDS,
        'total_seconds': TOTAL_SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
        'original_cases': {name: {'count': len(value[0]), 'input': value[1],
                                 'ordered_ids': [case['id'] for case in value[0]]}
                           for name, value in cases.items()},
        'same_runtime': str(options.python.resolve()),
        'source_before': sources, 'product_before': product,
        'scope': 'explicit VM/native finite controls; original complete caller gates remain separate',
        'no_expected_read_by_candidate_children': True,
        'old_248_and_7574_bytes_unchanged': True}
    write_json(evidence / 'plan.json', plan)
    started = time.monotonic()
    child_results, failure = {}, None

    def launch(group, backend, name):
        if time.monotonic() - started >= TOTAL_SECONDS:
            raise TimeoutError('new complete observation supervisor exhausted its declared 1800s bound')
        command = [str(options.python), '-I', '-B',
                   str(root / 'tests/hia_slot_operations_observer.py'),
                   '--root', str(root), '--oracle-root', str(oracle_root),
                   '--derived-inputs', str(derived), '--group', group, '--backend', backend,
                   '--product-freeze', str(options.product_freeze.resolve()),
                   '--product-freeze-sha256', options.product_freeze_sha256,
                   '--output', str(evidence / name / 'observation')]
        if backend == 'native':
            command += ['--manifest', str(options.manifest.resolve(strict=True))]
            command = command[:3] + [
                str(root / 'tests/hia_slot_mechanical_capsule_observer.py'),
                '--bundle', bridge_pin['path'], '--expected-bundle-sha256', bridge_pin['sha256'],
                '--observer', 'finite', '--'] + command[3:]
        seconds = ORIGINAL_SECONDS if backend == 'original' else CANDIDATE_SECONDS
        result = run_owned(command, cwd=root, directory=evidence / name,
                           timeout_seconds=seconds, environment=environment, deadline=started + TOTAL_SECONDS)
        child_results[name] = result
        if not successful_exit(result):
            raise RuntimeError('complete observation child did not naturally pass: ' + name)
        if time.monotonic() - started >= TOTAL_SECONDS:
            raise TimeoutError('complete observations exceed the 1800s supervisor bound')
        if (admit_product(root, options.product_freeze, options.product_freeze_sha256) != product
                or admit_originals(oracle_root) != sources):
            raise AssertionError('complete observation source changed after child')
        return evidence / name / 'observation'

    try:
        expected = {}
        # All independent original expectations exist before the first candidate.
        for group in cases:
            expected[group] = {'originals': {}}
            first = None
            for repetition in (1, 2):
                directory = launch(group, 'original', group + '-original-' + str(repetition))
                report = read_json(directory / 'report.json')
                if (report['status'] != 'RECORDED' or report['planned'] != len(cases[group][0])
                        or report['started'] != report['stopped']
                        or report['stopped'] != [case['id'] for case in cases[group][0]]):
                    raise AssertionError('complete original expectation missing identities')
                expected[group]['originals'][str(repetition)] = {
                    name: pin(directory / name) for name in RAW_FILES}
                if first is None:
                    first = directory
                elif (regular_bytes(first / 'observations.jsonl') != regular_bytes(directory / 'observations.jsonl')
                        or regular_bytes(first / 'raw-exceptions.jsonl') != regular_bytes(directory / 'raw-exceptions.jsonl')):
                    raise AssertionError('fresh same-runtime original observations are not stable')
        write_json(evidence / 'expectations-frozen.json', {
            'schema': 'hepta.slot-mechanical.independent-expectations.v1',
            'candidate_started': False, 'groups': expected,
            'product_freeze': pin(options.product_freeze), 'source': sources,
            'observer_expected_source': 'immutable original class and fake providers only'})
        frozen_bytes = regular_bytes(evidence / 'expectations-frozen.json')
        for backend in options.backend:
            for group in cases:
                launch(group, backend, group + '-' + backend)
                if regular_bytes(evidence / 'expectations-frozen.json') != frozen_bytes:
                    raise AssertionError('candidate phase changed independent expectation freeze')
    except BaseException as error:
        failure = {'type': type(error).__module__ + '.' + type(error).__qualname__,
                   'message': str(error), 'traceback': traceback.format_exc()}
    finally:
        # A custody readback failure must still leave a nonzero/HOLD supervisor
        # record; it must not erase the already captured child evidence.
        product_after = None
        custody_failure = None
        try:
            source_after = admit_originals(oracle_root)
            product_after = admit_product(root, options.product_freeze, options.product_freeze_sha256)
            stable = (source_after == sources and product_after == product
                      and regular_bytes(options.bridge_bundle) == bridge_raw)
        except BaseException as error:
            stable = False
            custody_failure = {'type': type(error).__module__ + '.' + type(error).__qualname__,
                               'message': str(error), 'traceback': traceback.format_exc()}
        report = {'schema': 'hepta.slot-mechanical.complete-observations-supervisor.v1',
            'status': 'RECORDED' if failure is None and stable else 'HOLD',
            'failure': failure, 'children': child_results, 'wall_seconds': time.monotonic() - started,
            'source_stable': stable, 'product_after': product_after,
            'custody_failure': custody_failure,
            'comparison_pending_independent_reader': failure is None,
            'old_deadlines_inputs_cases_tests_modified': False}
        write_json(evidence / 'supervisor.json', report)
    if failure is not None or not stable:
        return 1
    # Pure-data reader runs after all children; its rejection cannot be hidden
    # by an outer zero exit. Its complete diff files are retained on failure.
    from tools.read_hia_slot_mechanical_observations import read_evidence
    try:
        readback = read_evidence(root, oracle_root, derived,
            options.product_freeze, options.product_freeze_sha256,
            evidence, evidence / 'independent-readback',
            bridge_bundle=options.bridge_bundle, expected_bridge_sha256=options.expected_bridge_sha256)
    except BaseException as error:
        write_json(evidence / 'independent-readback-HOLD.json', {
            'status': 'HOLD', 'type': type(error).__module__ + '.' + type(error).__qualname__,
            'message': str(error), 'traceback': traceback.format_exc()})
        return 1
    return 0 if readback['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
