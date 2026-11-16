"""Additional independent receipt-v2 controls: Source2 and Native4.

The original executable-capture Source3/Native5 and 218 inputs are unchanged.
Each complete new group runs in an owned child with the existing 180+3 limit.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import unittest

from tests import hia_executable_capture_receipt_controls as controls
from tests.test_hia_executable_capture import child, evidence, selected

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = r"""
import sys
sys.path.insert(0, sys.argv[1])
sys.argv = [sys.argv[0], *sys.argv[2:]]
from tests.hia_executable_capture_receipt_controls import main
raise SystemExit(main())
"""


def run_group(case, mode, group):
    raw_input, table = controls.inputs()
    expected = controls._select_rows(table, group)
    expected_ids = [row['id'] for row in expected]
    directory = evidence(type(case).__name__ + '-' + case._testMethodName)
    destination = directory / 'complete'
    arguments = [str(ROOT), '--mode', mode, '--group', group, '--output', str(destination)]
    if mode == 'native':
        owner, manifest, digest, development = selected()
        arguments.extend(('--manifest', str(manifest), '--manifest-sha256', digest,
                          '--development', development))
        owner.check()
    process = child(directory, 'controls', SCRIPT, arguments=arguments, seconds=180)
    path = destination / 'report.json'
    raw = path.read_bytes()
    report = json.loads(raw)
    plan_path = destination / 'planned.json'
    plan_raw = plan_path.read_bytes()
    plan = json.loads(plan_raw)
    case.assertEqual(report['schema'], 'hepta.executable-capture.receipt-control-report.v2')
    case.assertEqual(report['status'], 'PASS')
    case.assertEqual((report['mode'], report['group']), (mode, group))
    case.assertEqual(plan['ordered_ids'], expected_ids)
    case.assertEqual(report['planned'], expected_ids)
    case.assertEqual(report['started'], expected_ids)
    case.assertEqual(report['stopped'], expected_ids)
    case.assertEqual(report['count'], len(expected_ids))
    case.assertEqual(report['failures'], [])
    case.assertEqual(report['source_drift'], [])
    case.assertEqual(report['input'], plan['input'])
    case.assertEqual(report['input']['sha256'], controls.INPUT_SHA256)
    case.assertEqual(report['input']['bytes'], len(raw_input))
    case.assertEqual(report['source_pins'], plan['source_pins'])
    case.assertEqual([row['id'] for row in report['results']], expected_ids)
    case.assertEqual(report['actual_pid'], process['pid'])
    case.assertEqual(report['actual_pgid'], process['pid'])
    captured = [(path, raw), (plan_path, plan_raw)]
    for row in report['results']:
        case.assertEqual(row['status'], 'PASS')
        one_path = destination / (sha256(row['id'].encode()).hexdigest() + '.json')
        one_raw = one_path.read_bytes()
        case.assertEqual(json.loads(one_raw), row)
        captured.append((one_path, one_raw))
        if group == 'policy':
            case.assertTrue(row['actual_policy_entry'])
            case.assertEqual(row['actual_kernel'], mode == 'native')
            case.assertEqual(row['counts']['injected'], 1)
            case.assertTrue(row['policy_child_unconfirmed'])
            case.assertTrue(row['whole_unconfirmed'])
            case.assertTrue(row['same_workspace_refused'])
        elif group == 'prewrite':
            case.assertTrue(row['synthetic_projection'])
            case.assertEqual((row['buffer_writes'], row['raw_entries']), (0, 0))
            case.assertTrue(row['before_after_bytes_equal'])
            case.assertTrue(row['not_policy_or_original_equivalence'])
        elif group == 'callbacks':
            case.assertTrue(row['actual_parent_policy_entry'])
            case.assertTrue(row['parent_kernel_is_explicit_fake'])
            case.assertTrue(row['actual_child_kernel'])
            case.assertTrue(row['actual_child_loss_origin_identity'])
            case.assertTrue(row['whole_unconfirmed'])
            case.assertTrue(row['same_workspace_refused'])
        elif row['id'].endswith('negative-result.complete'):
            case.assertTrue(row['actual_kernel'])
            case.assertTrue(row['ordinary_terminal_confirmed'])
            case.assertTrue(row['loss_absent'])
            case.assertEqual((row['errno'], row['context_errno']), (9, 9))
        else:
            case.assertTrue(row['actual_kernel'])
            case.assertEqual(row['counts']['injected'], 1)
            case.assertTrue(row['whole_unconfirmed'])
            case.assertTrue(row['same_workspace_refused'])
    if group == 'prewrite':
        case.assertEqual(report['valid_prewrite_boundaries'], [
            {'input_bytes': n, 'pread_count': n + 1,
             'first_write_reached': True, 'raw_executed': False}
            for n in (0, 1, 1 << 20)])
    else:
        case.assertEqual(report['valid_prewrite_boundaries'], [])
    for name in ('whole_native_closed', 'ordinary_route_changed', 'legacy_removal_authorized'):
        case.assertIs(report[name], False)
        case.assertIs(plan[name], False)
    # Reopen exactly the consumed bytes; no post-comparison replacement pin.
    for captured_path, captured_raw in captured:
        case.assertEqual(captured_path.read_bytes(), captured_raw)
    case.assertEqual(controls.INPUT.read_bytes(), raw_input)
    (directory / 'readback.json').write_text(json.dumps({
        'schema': 'hepta.executable-capture.receipt-control-readback.v2',
        'status': 'PASS_GROUP_ONLY', 'planned': expected_ids,
        'mode': mode, 'group': group, 'process': process,
        'consumed': [{'path': str(p), 'bytes': len(b), 'sha256': sha256(b).hexdigest()}
                     for p, b in captured],
        'whole_native_closed': False, 'ordinary_route_changed': False,
        'legacy_removal_authorized': False}, indent=2, sort_keys=True) + '\n')


class ExecutableCaptureReceiptSourceTests(unittest.TestCase):
    def test_00_all_24_actual_vm_policy_receipt_refusals(self):
        run_group(self, 'vm', 'policy')

    def test_01_all_31_prewrite_refusals_and_three_valid_extents(self):
        run_group(self, 'vm', 'prewrite')


class ExecutableCaptureReceiptNativeTests(unittest.TestCase):
    def test_00_all_24_actual_native_policy_receipt_refusals(self):
        run_group(self, 'native', 'policy')

    def test_01_all_31_admitted_prewrite_refusals_and_three_valid_extents(self):
        run_group(self, 'native', 'prewrite')

    def test_02_all_14_actual_raw_losses_and_complete_negative_receipt(self):
        run_group(self, 'native', 'raw')

    def test_03_both_actual_nested_child_losses_swallowed_and_replaced(self):
        run_group(self, 'native', 'callbacks')
