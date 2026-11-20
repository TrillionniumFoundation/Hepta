"""Explicit root qualification entry for complete service rollback/adopt control.

Preparation generates only this owner's declared source. Qualification requires
an already frozen composed tree, one matching current-cold report or explicit
DEV compiler, and every original scope below. This producer does not replace
the whole retained harness or its independent leaf readers.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
if __package__ in (None, ''): sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.hia_service_slot_controls import ROOT, COLD, DEV, ORIGINALS, EVIDENCE, SOURCE_EVIDENCE
from tests.hia_service_slot_controls import put, digest, environment, run_child, originals

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-compiler', type=Path)
    parser.add_argument('--companion-environment', type=Path, required=True)
    args = parser.parse_args(); args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    from tools.build_hia_json_preflight import current_sources
    before = current_sources()
    originals_path, original_report = originals(args.output)
    original_authority_path = args.output / 'original-authority.json'
    original_authority_raw = original_authority_path.read_bytes()
    original_authority = json.loads(original_authority_raw)
    original_bundle_raw = (originals_path / 'original-bundle.json').read_bytes()
    if (original_authority['path'] != str(originals_path)
            or sha256(original_bundle_raw).hexdigest() != original_authority['sha256']
            or json.loads(original_bundle_raw) != original_report):
        raise ValueError('original authority does not bind the admitted report bytes')
    env = environment(); additions = json.loads(args.companion_environment.read_bytes())
    if type(additions) is not dict or any(type(k) is not str or type(v) is not str
            or not k.startswith('HEPTA_HIA_') for k, v in additions.items()):
        raise ValueError('explicit original companion environment is required')
    if args.cold_report is not None:
        for key, value in additions.items():
            if 'DEVELOPMENT' in key: raise ValueError('DEV cannot qualify matching cold')
            if key.endswith('_COLD_REPORT') and Path(value).resolve() != args.cold_report.resolve():
                raise ValueError('original companion cold source differs')
        env[COLD] = str(args.cold_report.resolve())
    else:
        env[DEV] = str(args.development_compiler.resolve())
    env.update(additions)
    env[ORIGINALS] = str(originals_path)
    env[SOURCE_EVIDENCE] = str(args.output / 'source-evidence')
    env[EVIDENCE] = str(args.output / 'native-evidence')
    records = []
    def stage(label, argv, output, seconds, expected_count=None):
        error = None
        try:
            run_child(args.output / 'commands', label, argv, timeout=seconds, env=env)
        except BaseException as value:
            error = {'type': type(value).__name__, 'message': str(value)}
        report_path = Path(output) / 'report.json'
        inner_raw = report_path.read_bytes() if report_path.is_file() else None
        inner = json.loads(inner_raw) if inner_raw is not None else None
        good = (error is None and inner is not None and inner.get('status') == 'PASS'
                and report_path.read_bytes() == inner_raw)
        if expected_count is not None:
            good = good and inner.get('actual_tests') == expected_count
        records.append({'label': label, 'seconds': seconds, 'command_arguments': list(map(str, argv)),
            'status': 'PASS' if good else 'HOLD', 'error': error, 'inner_report': str(report_path),
            'inner_report_sha256': None if inner_raw is None else sha256(inner_raw).hexdigest(),
            'inner_status': None if inner is None else inner.get('status'),
            'expected_tests': expected_count})
        return good
    observer = ROOT / 'tests/hia_service_slot_suite_observer.py'
    stage('source3', [observer, '--kind', 'source', '--output', args.output / 'source3'],
          args.output / 'source3', 1800, 3)
    stage('native8', [observer, '--kind', 'native', '--output', args.output / 'native8'],
          args.output / 'native8', 1800, 8)
    authorities = list((args.output / 'native-evidence').glob('invocation-*/companion-authority.json'))
    if len(authorities) == 1:
        authority_path = authorities[0]; authority = json.loads(authority_path.read_bytes())
        service_manifest = Path(authority['manifests']['service'])
        for scope, count in (('ordinary112', 112), ('separate128', 128)):
            destination = args.output / scope
            selection = ['--cold-report', args.cold_report] if args.cold_report else ['--development-manifest', service_manifest]
            stage(scope, [ROOT / 'tools/qualify_hia_service_slot_callers.py',
                *selection, '--scope', scope, '--companion-environment', args.companion_environment,
                '--evidence', destination], destination, 1800, count)
        for label, script, component, count in (
            ('original-TX61', 'tools/qualify_hia_store_transaction.py', 'transaction', None),
            ('original-Store130', 'tools/qualify_hia_store_artifact_profile_callers.py', 'store', 130)):
            destination = args.output / label
            if args.cold_report:
                selection = ['--cold-report', args.cold_report]
            elif label == 'original-TX61':
                selection = ['--development-compiler', args.development_compiler,
                             '--development-manifest', authority['manifests'][component]]
            else:
                selection = ['--development-manifest', authority['manifests'][component]]
            stage(label, [ROOT / script, *selection, '--evidence', destination],
                  destination, 1800, count)
    else:
        for label in ('ordinary112', 'separate128', 'original-TX61', 'original-Store130'):
            records.append({'label': label, 'status': 'NOT_STARTED',
                'reason': 'missing unique same-attempt companion authority; never a PASS'})
    after = current_sources()
    complete = (len(records) == 6 and all(row['status'] == 'PASS' for row in records)
                and before == after
                and (originals_path / 'original-bundle.json').read_bytes() == original_bundle_raw
                and original_authority_path.read_bytes() == original_authority_raw)
    put(args.output / 'report.json', {
        'schema': 'hepta.hia.service-slot-qualification-producer.v1',
        'status': 'PASS_PRODUCER_ONLY' if complete else 'HOLD',
        'runtime': sys.version, 'source_before': before, 'source_after': after,
        'original_bundle': str(originals_path), 'original_bundle_sha256': original_authority['sha256'],
        'base_count': original_report['base_count'], 'fault_count': original_report['fault_count'],
        'stages': records, 'original_17_modules_240_preserved': True,
        'ordinary112_is_selected_new_owner_scope': True,
        'separate128_preserves_original_selection_fixture': True,
        'TX61_and_Store130_not_replaced_by_new_controls': True,
        'old_tests_or_deadlines_modified': False, 'independent_readback_pending': True,
        'whole_retained_qualification': False, 'whole_native_stack_qualified': False})
    return 0 if complete else 1
if __name__ == '__main__': raise SystemExit(main())
