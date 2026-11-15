"""Supervise complete Source3 and Native8+Resource4 lease gates."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    clean_environment, product_snapshot, read_json, write_json, pin, run_owned, successful_exit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', choices=('source', 'component', 'all'), required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-compiler', type=Path)
    args = parser.parse_args()
    if args.selection != 'source' and args.cold_report is None and args.development_compiler is None:
        parser.error('native qualification requires one exact cold report or explicit DEV compiler')
    from tests.hia_service_lease_controls import source_paths
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = product_snapshot(ROOT, source_paths())
    source_freeze = args.evidence / 'source-freeze.json'
    write_json(source_freeze, {'files': before})
    plan = read_json(ROOT / 'tests/fixtures/hia_service_lease_original_r3/gate-plan.json')
    stages = ('source', 'component') if args.selection == 'all' else (args.selection,)
    observations = []
    report = {'status': 'HOLD', 'stages': observations, 'source_before': before,
        'cold_report': None if args.cold_report is None else pin(args.cold_report),
        'development_compiler': None if args.development_compiler is None else pin(args.development_compiler),
        'scope': 'MATCHING_SOURCE_COLD' if args.cold_report is not None else
                 'EXPLICIT_DEVELOPMENT' if args.development_compiler is not None else 'SOURCE_VM_ONLY',
        'whole_native_qualified': False}
    try:
        for stage in stages:
            environment = clean_environment()
            prefix = 'HEPTA_HIA_SERVICE_LEASE'
            environment[prefix + '_SOURCE_EVIDENCE'] = str(args.evidence / 'source-components')
            environment[prefix + '_EVIDENCE'] = str(args.evidence / 'native-components')
            if args.cold_report is not None:
                environment[prefix + '_COLD_REPORT'] = str(args.cold_report.resolve(strict=True))
            if args.development_compiler is not None:
                environment[prefix + '_DEVELOPMENT_COMPILER'] = str(args.development_compiler.resolve(strict=True))
            code = ('import runpy,sys;sys.path.insert(0,sys.argv.pop(1));'
                    'runpy.run_module("tests.hia_service_lease_suite_observer",run_name="__main__")')
            command = [sys.executable, '-I', '-B', '-c', code, str(ROOT),
                '--selection', stage, '--output', str(args.evidence / (stage + '-observed')),
                '--source-freeze', str(source_freeze), '--source-freeze-sha256', pin(source_freeze)['sha256']]
            process = run_owned(command, cwd=ROOT, directory=args.evidence / (stage + '-process'),
                timeout_seconds=1800, environment=environment)
            row = {'stage': stage, 'process': process, 'observed': None}
            observations.append(row)
            observed_path = args.evidence / (stage + '-observed/report.json')
            if observed_path.exists():
                row['observed'] = read_json(observed_path)
            if not successful_exit(process) or row['observed'] is None:
                return 1
            actual = row['observed']
            expected = plan['gates'][stage]['ordered_ids']
            if (actual['status'] != 'PASS' or actual['planned'] != expected
                    or actual['started'] != expected or actual['stopped'] != expected
                    or type(actual['actual_tests']) is not int or actual['actual_tests'] != len(expected)
                    or actual['source_before'] != before or actual['source_after'] != before
                    or actual['pid'] != process['pid']
                    or actual['ppid'] != process['command']['parent_pid']
                    or actual['pgid'] != process['command']['pgid']):
                return 1
        report['status'] = 'PASS'
        return 0
    finally:
        report['source_after'] = product_snapshot(ROOT, before)
        if report['source_after'] != before:
            report['status'] = 'HOLD'
        write_json(args.evidence / 'report.json', report)
        if report['source_after'] != before:
            raise AssertionError('source changed during complete supervised qualification')


if __name__ == '__main__':
    raise SystemExit(main())
