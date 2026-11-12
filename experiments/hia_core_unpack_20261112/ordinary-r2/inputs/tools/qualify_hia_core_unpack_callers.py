"""Run the original complete Core116 with the UNPACK policy forbidden in Python.

This adds an independent companion ledger around the existing, unshortened
15+51+50 qualifier. The 39-image Core bundle and its v2 ledger remain separate.
An enclosing process owner must retain the original single 180+3 boundary.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import ExitStack
from contextvars import ContextVar
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))


def pin(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {'path': str(path), 'size': len(raw), 'sha256': sha256(raw).hexdigest()}


def companion_files(path):
    path = Path(path).resolve(strict=True)
    value = json.loads(path.read_bytes())
    if value['image_path'] != 'core-unpack.image.bin':
        raise ValueError('UNPACK fixed image path differs')
    files = [path, path.parent / value['image_path']]
    build = path.parent / 'build.json'
    if build.exists():
        files.append(build)
    return files


def validate_original(report):
    from tools.qualify_hia_core_lowering_callers import COMPONENT_IDS, ORIGINAL_IDS, CORE_IDS
    expected = [('component', COMPONENT_IDS), ('original-machine', ORIGINAL_IDS), ('original-core', CORE_IDS)]
    if (report.get('schema') != 'hepta.hia.core-lowering-selected-callers.v2'
            or report.get('status') != 'PASS'
            or report.get('complete_three_groups_executed') is not True
            or report.get('development_group') is not None
            or report.get('component_denominator') != 15
            or report.get('original_machine_denominator') != 51
            or report.get('original_core_denominator') != 50
            or report.get('source_stable') is not True
            or report.get('manifest_images_bundle_stable') is not True
            or report.get('retained_owner_entries') != []
            or len(report.get('groups', [])) != 3):
        raise ValueError('original complete Core116 did not pass')
    for row, (name, ids) in zip(report['groups'], expected):
        if (row.get('label') != name or row.get('loaded_ids') != ids
                or row.get('executed_ids') != ids or row.get('tests_run') != len(ids)
                or row.get('strict_pass') is not True
                or any(row.get(key) != [] for key in ('loader_errors', 'errors', 'failures',
                    'skipped', 'expectedFailures', 'unexpectedSuccesses'))):
            raise ValueError('original Core group IDs or zero-anomaly condition differs: ' + name)
    return [name for _, ids in expected for name in ids]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--cold-report', type=Path)
    mode.add_argument('--core-development-manifest', type=Path)
    parser.add_argument('--unpack-development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if bool(args.core_development_manifest) != bool(args.unpack_development_manifest):
        parser.error('development requires both explicit manifests; cold accepts neither')
    from hepta import hia_program_native as backend
    from hepta import hia_core_lowering_native as outer
    from hepta import hia_core_lowering_selection as core
    from hepta import hia_core_unpack_native as primitive
    from hepta import hia_core_unpack_selection as selection
    from tools import qualify_hia_core_lowering_callers as original
    directory = args.evidence.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'hepta.hia.core-unpack-selected-callers.v1', 'status': 'STARTED',
        'scope': 'MATCHING_SOURCE_COLD_SELECTED_CALLERS' if args.cold_report else 'EXPLICIT_DEVELOPMENT_ONLY',
        'original_groups': [15, 51, 50], 'original_complete_methods': 116,
        'original_Core_image_count': 39, 'additional_UNPACK_image_count': 1,
        'outer_opcode14_permission_still_consumed_once': True,
        'CPython_object_runtime_still_hosted': True,
        'transaction_ABI': primitive.TRANSACTION_ABI,
        'transaction_sha256': primitive.SHIM_SHA256,
        'old_complete_unpack_entries': [], 'complete_116_passed': False,
        'whole_stack_rewritten_in_hia': False, 'default_activated': False}
    started = time.monotonic()
    source_before = original.source_pins()
    companion_before, files = [], []
    context = ContextVar('hia_unpack_qualification_current_effect', default=None)
    test_context = ['outside-test', 'outside-group']
    groups = {test: label for label, ids in (
        ('component', original.COMPONENT_IDS), ('original-machine', original.ORIGINAL_IDS),
        ('original-core', original.CORE_IDS)) for test in ids}
    attempts, normal, failed, returns = Counter(), Counter(), Counter(), Counter()
    def forbid(*arguments, **keywords):
        report['old_complete_unpack_entries'].append(list(test_context))
        raise AssertionError('old complete Python UNPACK policy entered selected Core116')
    original_start = unittest.TextTestResult.startTest
    def start(result, test):
        name = test.id()
        test_context[:] = [name, groups.get(name, 'unknown-group')]
        return original_start(result, test)
    original_primitive, original_step = outer.LoweringSession._primitive, primitive.UnpackSession._step
    def outer_primitive(session, opcode, arguments, vector):
        if opcode != 14:
            return original_primitive(session, opcode, arguments, vector)
        companion = session.owner.unpack
        if session.pending or companion is None or not hasattr(companion, '_admitted_unpack'):
            raise AssertionError('opcode14 lacks consumed permission or admitted UNPACK image')
        key = (test_context[1], test_context[0], arguments[1], companion.image.image_sha256)
        attempts[key] += 1
        token = context.set(key)
        try:
            value = original_primitive(session, opcode, arguments, vector)
            normal[key] += 1
            return value
        except BaseException as error:
            failed[(*key, type(error).__module__, type(error).__qualname__)] += 1
            raise
        finally:
            context.reset(token)
    def unpack_step(session, packet):
        key = context.get()
        result = original_step(session, packet)
        if key is not None:
            if session.image.image_sha256 != key[3]:
                raise AssertionError('actual UNPACK step used another image')
            returns[(*key, result)] += 1
        return result
    try:
        if args.cold_report:
            from tools.build_hia_core_unpack import build
            cold = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(cold['nested_report']).read_bytes())
            manifest = build(directory / 'unpack-build', Path(nested['generations'][-1]['produced_image']), args.cold_report)
            compiler_sha = json.loads(manifest.read_bytes())['compiler_sha256']
            original_args = ['--cold-report', str(args.cold_report.resolve())]
        else:
            manifest = args.unpack_development_manifest.resolve(strict=True)
            compiler_sha = json.loads(args.core_development_manifest.read_bytes())['compiler_sha256']
            original_args = ['--development-manifest', str(args.core_development_manifest.resolve())]
        companion = selection.installed_unpack(manifest, compiler_sha)
        report['admitted_companion'] = vars(companion._admitted_unpack)
        files = companion_files(manifest)
        companion_before = [pin(path) for path in files]
        report['companion_inputs_before'] = companion_before
        report['source_before'] = source_before
        report['identity_before'] = sha256(selection.implementation_identity(companion)).hexdigest()
        argv = ['qualify_hia_core_lowering_callers.py', *original_args, '--evidence', str(directory / 'core-callers')]
        report['original_qualifier_argv'] = argv
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {selection.SELECTOR: str(manifest)}))
            stack.enter_context(patch.object(sys, 'argv', argv))
            stack.enter_context(patch.object(outer, '_host_unpack', forbid))
            stack.enter_context(patch.object(outer.LoweringSession, '_primitive', outer_primitive))
            stack.enter_context(patch.object(primitive.UnpackSession, '_step', unpack_step))
            stack.enter_context(patch.object(unittest.TextTestResult, 'startTest', start))
            result = original.main()
        original_path = directory / 'core-callers/report.json'
        report['original_report'] = pin(original_path)
        original_report = json.loads(original_path.read_bytes())
        ids = validate_original(original_report)
        if result != 0 or len(ids) != 116 or len(set(ids)) != 116:
            raise ValueError('original full qualifier return or complete116 differs')
        if (report['old_complete_unpack_entries'] or not returns
                or {key[0] for key in returns} != {'component', 'original-machine', 'original-core'}
                or any(key[1] not in groups or groups[key[1]] != key[0] for key in returns)
                or {key[3] for key in returns} != {companion.image.image_sha256}):
            raise ValueError('actual UNPACK returns did not cover all three original groups')
        for group in ('component', 'original-machine', 'original-core'):
            if not {0, 1} <= {key[-1] for key in returns if key[0] == group}:
                raise ValueError('UNPACK did not actually continue and return in group: ' + group)
        installed_path = directory / 'core-callers/component-fixture/installed-control/report.json'
        report['installed_report'] = pin(installed_path)
        installed = json.loads(installed_path.read_bytes()).get('unpack_observations')
        expected_refusals = [name + suffix for name in (selection.ABI_SOURCE, selection.HIA_SOURCE)
                             for suffix in (':changed', ':missing')]
        if (type(installed) is not dict
                or installed.get('schema') != 'hepta.hia.core-unpack-installed-observation.v1'
                or installed.get('retained_unpack_forbidden') is not True
                or installed.get('image_sha256') != companion.image.image_sha256
                or installed.get('compiler_sha256') != compiler_sha
                or installed.get('transaction_sha256') != primitive.SHIM_SHA256
                or installed.get('runtime_profile') != companion.leaves.profile
                or type(installed.get('actual_step_returns')) is not int
                or installed['actual_step_returns'] <= 0
                or installed.get('actual_statuses') != [0, 1]
                or installed.get('refusals') != expected_refusals):
            raise ValueError('real installed UNPACK image/returns/refusals differ')
        for name in ('source_sha256', 'abi_sha256', 'bridge_sha256', 'selection_sha256'):
            if installed.get(name) != getattr(companion._admitted_unpack, name):
                raise ValueError('installed companion source identity differs: ' + name)
        report['installed_observation'] = installed
        report['complete_116_passed'] = True
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'FAIL'
        report['error'] = traceback.format_exc()
    finally:
        report['outer_opcode14_attempts'] = [dict(group=k[0], test=k[1], arity=k[2], image_sha256=k[3], count=n)
                                             for k, n in sorted(attempts.items())]
        report['outer_opcode14_normal_returns'] = [dict(group=k[0], test=k[1], arity=k[2], image_sha256=k[3], count=n)
                                                   for k, n in sorted(normal.items())]
        report['outer_opcode14_exceptions'] = [dict(group=k[0], test=k[1], arity=k[2], image_sha256=k[3],
                                                   exception_module=k[4], exception_class=k[5], count=n)
                                              for k, n in sorted(failed.items())]
        report['actual_UNPACK_step_returns'] = [dict(group=k[0], test=k[1], arity=k[2], image_sha256=k[3], status=k[4], count=n)
                                               for k, n in sorted(returns.items())]
        try:
            report['source_after'] = original.source_pins()
            report['companion_inputs_after'] = [pin(path) for path in files]
            report['identity_after'] = sha256(selection.implementation_identity(companion)).hexdigest()
            report['stable'] = bool(companion_before) and (
                source_before == report['source_after']
                and companion_before == report['companion_inputs_after']
                and report.get('identity_before') == report['identity_after'])
            if not report['stable']:
                report['status'] = 'FAIL'
        except BaseException:
            report['status'] = 'FAIL'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        (directory / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({name: report.get(name) for name in ('schema', 'scope', 'status', 'seconds', 'stable', 'error')}, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
