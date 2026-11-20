"""Complete independent original-first public84 and handled12 under explicit v5."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys
import traceback
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    ORACLE_PREFIX, DERIVED_FILE, admit_product, regular_bytes, read_json,
    write_json, pin, sha, run_owned, successful_exit)

def supplement(directory, backend, group, freeze, digest, manifest, bridge):
    from tools.read_hia_slot_mechanical_observations import (
        compare, read_lines, mechanical_launch, read_bytes_at_pin, read_json_at_pin, typed_equal)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    expected_count = 84 if group == 'public' else 12
    groups = []
    expected_bytes = None
    expected_raw = {}
    candidate_raw = None
    frozen_pin = None
    for label, current in (('original-1', 'original'), ('original-2', 'original'), ('candidate', backend)):
        if label == 'candidate':
            write_json(directory / 'expectations-frozen.json', {
                'source': 'independent original functions only',
                'candidate_started': False, 'groups': expected_raw})
            frozen_pin = pin(directory / 'expectations-frozen.json')
        target = directory / label
        command = [sys.executable, '-I', '-B', str(ROOT / 'tests/hia_slot_operations_public_observer.py'),
            '--root', str(ROOT), '--oracle-root', str(ROOT / ORACLE_PREFIX),
            '--derived-inputs', str(ROOT / DERIVED_FILE), '--group', group, '--backend', current,
            '--product-freeze', str(freeze), '--product-freeze-sha256', digest,
            '--output', str(target / 'observation')]
        if current == 'native':
            command += ['--manifest', str(manifest)]
            command = command[:3] + [str(ROOT / 'tests/hia_slot_mechanical_capsule_observer.py'),
                '--bundle', bridge['path'], '--expected-bundle-sha256', bridge['sha256'],
                '--observer', 'public', '--'] + command[3:]
        result = run_owned(command, cwd=ROOT, directory=target, timeout_seconds=180)
        if not successful_exit(result):
            raise AssertionError('complete supplemental child HOLD: ' + str(target))
        raw_pins = {name: pin(target / 'observation' / name)
                    for name in ('report.json', 'planned.json', 'observations.jsonl', 'raw-exceptions.jsonl')}
        report = read_json_at_pin(target / 'observation/report.json', raw_pins['report.json'])
        planned = read_json_at_pin(target / 'observation/planned.json', raw_pins['planned.json'])
        raw = read_bytes_at_pin(target / 'observation/observations.jsonl', raw_pins['observations.jsonl'])
        if (report['status'] != 'RECORDED' or report['failures']
                or report['planned'] != report['started'] or report['planned'] != report['stopped']
                or len(report['planned']) != expected_count
                or [row['id'] for row in read_lines(target / 'observation/observations.jsonl', expected_pin=raw_pins['observations.jsonl'])] != report['planned']
                or report['planned'] != planned['ordered_ids']
                or type(report['pid']) is not int or report['pid'] != result['pid']
                or type(report['pgid']) is not int or report['pgid'] != result['pid']
                or type(report['ppid']) is not int or report['ppid'] != os.getpid()
                or report['source_before'] != report['source_after']
                or report['product_before'] != report['product_after']):
            raise AssertionError('supplemental full raw/report/supervisor binding differs')
        if label.startswith('original'):
            if expected_bytes is None:
                expected_bytes = raw
            elif raw != expected_bytes:
                raise AssertionError('fresh same-runtime supplemental originals are not stable')
            expected_raw[label] = raw_pins
        else:
            candidate_raw = raw_pins
            for original, pins in expected_raw.items():
                for name, expected in pins.items():
                    if pin(directory / original / 'observation' / name) != expected:
                        raise AssertionError('candidate phase changed frozen original raw')
            counts = report['counts']
            if counts['retained_calls'] or (counts['returned_entries'] <= 0 if backend in ('native', 'vm')
                                            else counts['returned_entries'] != 0):
                raise AssertionError('selected/unselected public route execution differs')
        if label == 'candidate':
            marker = read_json(target / 'observation/mechanical-launch.json')
            launch = mechanical_launch(target, result['command'],
                {'argv': marker['inner_argv'], 'pid': report['pid'], 'ppid': report['ppid'],
                 'pgid': report['pgid']}, bridge, ROOT, admit_product(ROOT, freeze, digest), 'public')
        else:
            launch = None
        groups.append({'mechanical_launch': launch, 'label': label, 'result': result, 'report': report,
                       'raw_sha256': sha(raw), 'raw': raw_pins})
    comparison = compare(directory / 'original-1/observation/observations.jsonl',
        directory / 'candidate/observation/observations.jsonl', directory / 'all-diffs.jsonl',
        expected_pin=expected_raw['original-1']['observations.jsonl'],
        actual_pin=candidate_raw['observations.jsonl'])
    if not typed_equal(pin(directory / 'expectations-frozen.json'), frozen_pin):
        raise AssertionError('supplemental expectation authority changed before terminal readback')
    for child in groups:
        if not all(typed_equal(pin(directory / child['label'] / 'observation' / name), saved)
                   for name, saved in child['raw'].items()):
            raise AssertionError('supplemental consumed raw changed before terminal readback')
        saved = child['mechanical_launch']
        if saved is not None and pin(saved['path']) != {k: saved[k] for k in ('bytes', 'sha256')}:
            raise AssertionError('mechanical launcher changed before comparison receipt')
    write_json(directory / 'comparison.json', {'status': 'PASS' if comparison['different_cases'] == 0 else 'HOLD',
        'group': group, 'backend': backend, 'explicit_v5_administrator_bundle': bridge, 'all_raw_fields_compared': True,
        'originals_before_candidate': True, 'cases': expected_count, 'comparison': comparison,
        'children': groups, 'new_inputs_not_replacements_for_248_or_7574': True})
    if comparison['different_cases']:
        raise AssertionError('supplemental complete original observations differ: ' + str(directory))
    return comparison

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--product-freeze', type=Path, required=True)
    parser.add_argument('--product-freeze-sha256', required=True)
    parser.add_argument('--bridge-bundle', type=Path, required=True)
    parser.add_argument('--expected-bridge-sha256', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    raw = regular_bytes(args.bridge_bundle)
    if sha(raw) != args.expected_bridge_sha256:
        raise ValueError('explicit administrator capsule differs')
    bridge = {'path': str(args.bridge_bundle.resolve(strict=True)),
              'bytes': len(raw), 'sha256': args.expected_bridge_sha256}
    product = admit_product(ROOT, args.product_freeze, args.product_freeze_sha256)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    outcomes = []
    for group in ('public', 'handled-traceback'):
        try:
            comparison = supplement(args.evidence / group, 'native', group,
                args.product_freeze, args.product_freeze_sha256, args.manifest, bridge)
            outcomes.append({'group': group, 'status': 'PASS', 'comparison': comparison})
        except Exception as error:
            outcomes.append({'group': group, 'status': 'HOLD',
                'type': type(error).__module__ + '.' + type(error).__qualname__,
                'message': str(error), 'traceback': traceback.format_exc()})
    stable = (regular_bytes(args.bridge_bundle) == raw and
        admit_product(ROOT, args.product_freeze, args.product_freeze_sha256) == product)
    passed = stable and all(value['status'] == 'PASS' for value in outcomes)
    write_json(args.evidence / 'report.json', {
        'schema': 'hepta.slot.mechanical.public-complete.v1',
        'status': 'PASS' if passed else 'HOLD', 'groups': outcomes,
        'public_inputs': 84, 'handled_inputs': 12, 'old_inputs_or_fields_changed': False,
        'actual_originals_twice_before_each_candidate': True,
        'administrator_bundle': bridge, 'source_stable': stable,
        'original_child_seconds': 180, 'new_scope_does_not_replace_old_Native6': True})
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
