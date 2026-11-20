"""Pure-data reader for complete same-runtime service lease observations."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    read_json, pin, canonical, successful_exit, product_snapshot, checked_int, write_json,
    regular_bytes, unique_pairs)

def _raw_pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def _capture_raw(path, captured, expected=None):
    path = Path(path)
    raw = regular_bytes(path)
    if expected is not None and canonical(_raw_pin(raw)) != canonical(expected):
        raise ValueError('captured evidence bytes differ from the prior pin: ' + str(path))
    if path in captured and raw != captured[path]:
        raise ValueError('previously captured evidence changed: ' + str(path))
    captured[path] = raw
    return raw


def _capture_json(path, captured, expected=None):
    raw = _capture_raw(path, captured, expected)
    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def _require_captured_unchanged(captured):
    for path, raw in captured.items():
        if regular_bytes(path) != raw:
            raise ValueError('consumed evidence changed before terminal readback: ' + str(path))


def _rows(directory, expected_ids, source, case_pin, process, backend, captured):
    report = _capture_json(directory / 'report.json', captured)
    if report['schema'] != 'hepta.service-lease.finite-observations.v1' or report['backend'] != backend:
        raise ValueError('finite role identity differs')
    for key in ('planned', 'started', 'stopped'):
        if report[key] != expected_ids:
            raise ValueError('complete finite IDs differ: ' + key)
    if (report['failure'] is not None or report['source_stable'] is not True
            or canonical(report['source_before']) != canonical(source)
            or canonical(report['source_after']) != canonical(source)
            or canonical(report['input_before']) != canonical(case_pin)
            or canonical(report['input_after']) != canonical(case_pin)):
        raise ValueError('finite source/input/terminal evidence differs')
    for key in ('pid', 'ppid', 'pgid', 'entries', 'step_limit', 'scratch_bytes', 'call_depth'):
        checked_int(report[key])
    if (report['pid'] != process['pid'] or report['pgid'] != process['command']['pgid']
            or report['ppid'] != process['command']['parent_pid']
            or report['step_limit'] != 4_000_000 or report['scratch_bytes'] != 16 << 20
            or report['call_depth'] != 128):
        raise ValueError('owned child or unchanged VM limit binding differs')
    if backend in ('original', 'unselected'):
        if report['entries'] != 0 or report['events'] or report['modes']:
            raise ValueError('original child executed a candidate')
    elif (report['entries'] <= 0 or set(report['modes']) != {'1', '2', '3', '4'}
          or not all(type(n) is int and n > 0 for n in report['modes'].values())
          or report['candidate_used_to_create_expected'] is not False
          or report['originals_invoked_by_selected_route'] is not False):
        raise ValueError('actual complete selected owner execution absent')
    path = directory / 'observations.json'
    rows = _capture_json(path, captured, report['observations'])
    jsonl_raw = _capture_raw(directory / 'observations.jsonl', captured, report['jsonl'])
    if type(rows) is not list or [row['id'] for row in rows] != expected_ids:
        raise ValueError('raw finite observations are incomplete')
    jsonl = b''.join(canonical(row) + b'\n' for row in rows)
    if jsonl_raw != jsonl:
        raise ValueError('raw array/jsonl bytes disagree')
    for row in rows:
        checked_int(row['mode'])
        checked_int(row['fault_hits'])
        if row['explicit_gc_collected'] is not None:
            checked_int(row['explicit_gc_collected'])
    return rows, report


def read_finite(evidence, repository, *, backend):
    evidence, repository = Path(evidence), Path(repository)
    if backend not in ('unselected', 'vm', 'native'):
        raise ValueError('undeclared complete candidate backend')
    captured = {}
    fixture = repository / 'tests/fixtures/hia_service_lease_original_r3'
    case_path = fixture / 'cases.json'
    cases = _capture_json(case_path, captured)
    case_pin = _raw_pin(captured[case_path])
    expected_ids = [case['id'] for case in cases]
    if len(expected_ids) != 258 or len(set(expected_ids)) != 258:
        raise ValueError('frozen complete 258 inputs differ')
    freeze = _capture_json(evidence / 'source-freeze.json', captured)
    source = freeze['files']
    if canonical(case_pin) != canonical(source[str(case_path.relative_to(repository))]):
        raise ValueError('consumed complete case bytes differ from the source freeze')
    if canonical(product_snapshot(repository, source)) != canonical(source):
        raise ValueError('current source differs from complete finite freeze')
    supervision = _capture_json(evidence / 'supervision.json', captured)
    roles = ('original-1', 'original-2', backend)
    if set(supervision) != set(roles):
        raise ValueError('all three original/candidate children are required')
    values, reports = {}, {}
    for role in roles:
        process = supervision[role]
        if not successful_exit(process):
            raise ValueError('owned finite child did not exit cleanly: ' + role)
        expected_budget = 180 if role.startswith('original-') else 1800
        checked_int(process['command']['timeout_seconds'], expected_budget)
        if process['command']['new_session'] is not True or type(process['command']['cleanup_seconds']) is not int or process['command']['cleanup_seconds'] != 5:
            raise ValueError('owned child supervision differs')
        command_dir = evidence / (role + '-process')
        if canonical(_capture_json(command_dir / 'result.json', captured)) != canonical(process):
            raise ValueError('supervisor/result records differ')
        _capture_raw(command_dir / 'stdout.log', captured, process['stdout'])
        _capture_raw(command_dir / 'stderr.log', captured, process['stderr'])
        values[role], reports[role] = _rows(evidence / (role + '-observations'),
            expected_ids, source, case_pin, process,
            'original' if role.startswith('original-') else backend, captured)
    if len({reports[role]['runtime'] for role in roles}) != 1:
        raise ValueError('original and candidate runtime identity differs')
    if canonical(values['original-1']) != canonical(values['original-2']):
        raise ValueError('independent originals are unstable')
    expected_path = evidence / 'expected-frozen.json'
    expected_seal = _capture_json(expected_path, captured,
                                  reports[backend]['expected_seal_before'])
    first_pin = _raw_pin(captured[evidence / 'original-1-observations/observations.json'])
    second_pin = _raw_pin(captured[evidence / 'original-2-observations/observations.json'])
    if (canonical(expected_seal['original_1']) != canonical(first_pin)
            or canonical(expected_seal['original_2']) != canonical(second_pin)
            or expected_seal['before_candidate'] is not True
            or expected_seal['candidate_results_used'] is not False):
        raise ValueError('expected was not independently sealed')
    expected_pin = _raw_pin(captured[expected_path])
    if (canonical(reports[backend]['expected_seal_before']) != canonical(expected_pin)
            or canonical(reports[backend]['expected_seal_after']) != canonical(expected_pin)):
        raise ValueError('candidate did not bind the prior expected seal')
    differences = [{'id': a['id'], 'expected': a, 'actual': b}
                   for a, b in zip(values['original-1'], values[backend])
                   if canonical(a) != canonical(b)]
    difference_path = evidence / 'all-differences.json'
    difference_raw = canonical(differences) + b'\n'
    write_json(difference_path, differences)
    _capture_raw(difference_path, captured, _raw_pin(difference_raw))
    _require_captured_unchanged(captured)
    return {'schema': 'hepta.service-lease.finite-readback.v1',
            'status': 'PASS' if not differences else 'HOLD',
            'backend': backend, 'original_cases': 258, 'actual_cases': 258,
            'different_cases': len(differences),
            'runtime': reports[backend]['runtime'], 'entries': reports[backend]['entries'],
            'events': reports[backend]['events'], 'modes': reports[backend]['modes'],
            'expected': first_pin,
            'actual': _raw_pin(captured[evidence / (backend + '-observations/observations.json')]),
            'differences': _raw_pin(difference_raw),
            'complete_source_before_after_equal': True,
            'whole_native_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--backend', choices=('vm', 'native'), required=True)
    args = parser.parse_args()
    report = read_finite(args.evidence, args.repository, backend=args.backend)
    write_json(args.evidence / 'readback.json', report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
