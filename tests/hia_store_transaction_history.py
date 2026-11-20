"""Fresh-process finite histories with independent original transaction output.

This component observer drives the frozen original and selected public owner
through one shared finite history. Historical candidate output never becomes
an expectation; no live code is reset, normalized, or warmed in a loop.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import traceback
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
HISTORIES = ('H0', 'H1')
SQL_STATEMENTS = (
    'CREATE TABLE transaction_probe(value INTEGER)',
    'BEGIN IMMEDIATE', 'INSERT INTO transaction_probe VALUES (1)', 'COMMIT',
    'BEGIN IMMEDIATE', 'INSERT INTO transaction_probe VALUES (2)', 'ROLLBACK',
    'SELECT value FROM transaction_probe',
    'BEGIN IMMEDIATE', 'BEGIN IMMEDIATE', 'ROLLBACK',
)
# Exact observed runtime builds, not version thresholds or an emulation of
# another interpreter's metadata. Other builds produce their own complete
# independent original output before any candidate execution.
KNOWN_H0_ORIGINALS = {
    '3.12.14 (main, Aug 25 2026, 14:00:49) [Clang 22.1.3 ]':
        'cb4ab84007af4ec6bdc420dbfc658185014d6e02eb79bb6790fe133d48bfe523',
    '3.13.5 (main, Aug 10 2026, 12:06:59) [GCC 14.2.0]':
        '568e59fdd2eab06d5aa9a7649c039bc78ea9e6fb40585a8545e8145a8f431cec',
}


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode()


def finite_history(factory, api, ControlStore, *, held, history, phase):
    """Drive exactly six transactions, preserving the two suspended contexts.

    These healthy contexts reproduce a finite foreign-call history, not lost
    acknowledgements or every event of the old R1 process. Callers keep strong
    ownership until all 521 observations have been frozen, then record close.
    The lists are supplied before the first effect so partial failure also
    preserves the actual contexts and history already obtained.
    """
    def hold(label):
        phase(label)
        subject = ControlStore()
        cm = factory(subject, {})
        held.append((label, subject, cm))
        cm.__enter__()
        if subject.events != ['enter', 'BEGIN IMMEDIATE'] or not subject.lock.held:
            raise AssertionError('declared Control BEGIN history differs')
        history.append({'label': label, 'events': list(subject.events),
                        'generator_suspended': cm.gen.gi_frame is not None})

    hold('control_BEGIN_foreign_ACK_cutoff')
    phase('three_SQLite_transactions')
    statements = []
    with tempfile.TemporaryDirectory(prefix='hia-transaction-history-') as directory:
        store = api.AgentStore(Path(directory) / 'state')
        try:
            if type(store.db) is not sqlite3.Connection:
                raise AssertionError('history must retain the actual SQLite connection type')
            store.db.set_trace_callback(statements.append)
            store.db.execute('CREATE TABLE transaction_probe(value INTEGER)')
            with factory(store, {}):
                store.db.execute('INSERT INTO transaction_probe VALUES (1)')
            error = ValueError('ordinary foreign body error')
            try:
                with factory(store, {}):
                    store.db.execute('INSERT INTO transaction_probe VALUES (2)')
                    raise error
            except ValueError as caught:
                if caught is not error:
                    raise AssertionError('history replaced the original body exception')
            rows = [row[0] for row in store.db.execute('SELECT value FROM transaction_probe')]
            if rows != [1]:
                raise AssertionError('history COMMIT/ROLLBACK effects differ')
            store.db.execute('BEGIN IMMEDIATE')
            try:
                with factory(store, {}):
                    raise AssertionError('failed nested BEGIN entered its body')
            except sqlite3.OperationalError as caught:
                nested = {'type': type(caught).__name__, 'args': list(caught.args)}
            else:
                raise AssertionError('history nested BEGIN did not refuse')
            if not store.db.in_transaction:
                raise AssertionError('failed nested BEGIN rolled back its caller transaction')
            store.db.execute('ROLLBACK')
        finally:
            store.close()
    if statements != list(SQL_STATEMENTS):
        raise AssertionError('declared finite SQLite statement order differs')
    history.append({'label': 'three_SQLite_transactions', 'statements': statements,
                    'nested_refusal': nested, 'connection_type': 'sqlite3.Connection'})
    phase('discarded_Control_context')
    subject = ControlStore()
    factory(subject, {}).__enter__()
    if subject.events != ['enter', 'BEGIN IMMEDIATE', 'ROLLBACK', 'exit']:
        raise AssertionError('discarded context history differs')
    history.append({'label': 'discarded_Control_context', 'events': list(subject.events)})
    hold('control_BEGIN_resume_allocation_cutoff')


def close_held(held, *, phase):
    rows = []
    for label, subject, cm in reversed(held):
        phase('held_cleanup:' + label)
        row = {'label': label, 'events_before': list(subject.events),
               'held_before': subject.lock.held,
               'observations_frozen_before_cleanup': True}
        try:
            cm.gen.close()
            row['cleanup_error'] = None
        except BaseException:
            row['cleanup_error'] = traceback.format_exc()
        row.update(events_after=list(subject.events), held_after=subject.lock.held,
                   generator_closed=cm.gen.gi_frame is None)
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--history', choices=HISTORIES, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.absolute();out.mkdir(mode=0o700, exist_ok=False)
    os.chdir(ROOT)
    for key in tuple(os.environ):
        if key.startswith('HEPTA_HIA_'):
            del os.environ[key]

    from hepta import hia_agent_store as api
    from hepta import hia_store_transaction_native as native
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from hepta.hia_program_runtime import _Machine
    from tests import test_hia_store_transaction_native as tests
    from tools.build_hia_json_preflight import current_sources
    from tools.build_hia_store_transaction import INPUTS

    values = tests.original_inputs()
    source_before = current_sources()
    manifest = args.manifest.resolve(strict=True)
    manifest_raw, compiler_raw = manifest.read_bytes(), args.compiler.read_bytes()
    value = json.loads(manifest_raw)
    build_path = manifest.parent / 'build.json';build_raw = build_path.read_bytes()
    build = json.loads(build_raw)
    image_path = manifest.parent / value['image_path'];image_raw = image_path.read_bytes()
    start = {
        'schema': 'hepta.hia.transaction-isolated-history.v1', 'history': args.history,
        'python': sys.version, 'executable': sys.executable, 'process': os.getpid(),
        'declared_original_count': len(values), 'case_order': [case['id'] for case in values],
        'source_before': source_before, 'manifest_path': str(manifest),
        'manifest_sha256': sha256(manifest_raw).hexdigest(),
        'compiler_sha256': sha256(compiler_raw).hexdigest(),
        'image_sha256': sha256(image_raw).hexdigest(), 'build_scope': build['scope'],
        'runner_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
        'no_compilation_performed_in_child': True,
        'not_all_possible_call_histories_or_python_builds_proved': True,
        'historical_R1_actual_used_as_expected': False,
    }
    (out / 'start.json').write_bytes(encoded(start) + b'\n')
    (out / 'runner.py').write_bytes(Path(__file__).read_bytes())
    (out / 'inputs-521.json').write_bytes(encoded(values) + b'\n')
    originals, actuals, comparisons, original_history, candidate_history = [], [], [], [], []
    original_cleanup, candidate_cleanup = [], []
    held_original, held_candidate = [], []
    guards = Counter()
    events, frames, attempts, returns = Counter(), Counter(), Counter(), Counter()
    by_phase = defaultdict(Counter)
    active = ['admission']
    original_anchor = None
    failure = None
    begin = time.monotonic()

    def phase(label):
        active[0] = label

    def forbidden(label):
        def reject(*arguments, **keywords):
            guards[label] += 1
            raise AssertionError('isolated transaction observer forbids ' + label)
        return reject

    expected_frozen = selected_started = False
    original_raw = None
    try:
        if (start['manifest_sha256'] != args.expected_manifest_sha256
                or build['manifest'] != value
                or value['compiler_sha256'] != start['compiler_sha256']
                or value['image_sha256'] != start['image_sha256']
                or build['component_inputs'] != {
                    name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}):
            raise ValueError('isolated comparison does not match its one actual parent build')
        with ExitStack() as restrictions:
            restrictions.enter_context(patch.object(_Machine, 'invoke', forbidden('HIA_VM')))
            restrictions.enter_context(patch.object(subprocess, 'Popen', forbidden('nested_process_or_compiler')))
            with patch.object(NativeHiaJsonImage, '__init__', forbidden('native_before_expected_freeze')):
                try:
                    if args.history == 'H1':
                        finite_history(tests.oracle.original_factory, api, tests.ControlStore,
                                       held=held_original, history=original_history, phase=phase)
                    for case in values:
                        phase('original:' + case['id'])
                        originals.append(tests.oracle.observe(case))
                finally:
                    (out / 'originals-521.json').write_bytes(encoded(originals) + b'\n')
                    (out / 'original-history.json').write_bytes(encoded(original_history) + b'\n')
                    original_cleanup = close_held(held_original, phase=phase)
                    (out / 'original-held-cleanup.json').write_bytes(encoded(original_cleanup) + b'\n')
            original_raw = (out / 'originals-521.json').read_bytes()
            if len(originals) != 521:
                raise AssertionError('independent original corpus is incomplete')
            if args.history == 'H0':
                original_anchor = KNOWN_H0_ORIGINALS.get(sys.version)
                if original_anchor is not None and sha256(original_raw).hexdigest() != original_anchor:
                    raise AssertionError('H0 differs from this exact runtime build frozen original bytes')
            expected_frozen = True

            # Only after all original observations and their cleanup are frozen
            # can an image be mapped and the actual selected public route run.
            image = native.installed_store_transaction(str(manifest))
            entry = image._entry
            initialize = native.StoreTransactionFrame.__init__

            def frame_init(frame, *arguments, **keywords):
                initialize(frame, *arguments, **keywords)
                frames[active[0]] += 1

            def observed(source, size, output, capacity, state, extent):
                words = struct.unpack('<2Q', ctypes.string_at(source, 16)) if size >= 16 else (0, -1)
                key = str(words[1]) if words[0] == native.REQUEST_MAGIC else 'invalid-magic'
                attempts[key] += 1
                result = entry(source, size, output, capacity, state, extent)
                returns[str(result)] += 1
                events[key] += 1;by_phase[active[0]][key] += 1
                return result

            def public_factory(store, namespace):
                return api.AgentStore.transaction(store)

            with ExitStack() as selected:
                selected.enter_context(patch.dict(os.environ, {native.SELECTOR: str(manifest)}))
                selected.enter_context(patch.object(image, '_entry', observed))
                selected.enter_context(patch.object(native.StoreTransactionFrame, '__init__', frame_init))
                tests.poison(selected)
                selected_started = True
                try:
                    if args.history == 'H1':
                        finite_history(public_factory, api, tests.ControlStore,
                                       held=held_candidate, history=candidate_history, phase=phase)
                    for case, expected in zip(values, originals):
                        phase('candidate:' + case['id'])
                        actual = tests.public_observation(case)
                        actuals.append(actual)
                        comparisons.append({'case': case['id'], 'expected': expected, 'actual': actual,
                                            'equal': encoded(actual) == encoded(expected)})
                finally:
                    (out / 'actuals-521.json').write_bytes(encoded(actuals) + b'\n')
                    (out / 'complete-observations.json').write_bytes(encoded(comparisons) + b'\n')
                    (out / 'candidate-history.json').write_bytes(encoded(candidate_history) + b'\n')
                    candidate_cleanup = close_held(held_candidate, phase=phase)
                    (out / 'candidate-held-cleanup.json').write_bytes(encoded(candidate_cleanup) + b'\n')
    except BaseException:
        failure = traceback.format_exc()
        (out / 'exception.txt').write_text(failure)

    source_after = current_sources()
    expected_unchanged = original_raw is not None and (out / 'originals-521.json').read_bytes() == original_raw
    stable = (source_before == source_after and manifest.read_bytes() == manifest_raw
              and image_path.read_bytes() == image_raw and args.compiler.read_bytes() == compiler_raw
              and build_path.read_bytes() == build_raw)
    differences = [row['case'] for row in comparisons if not row['equal']]
    history_equal = encoded(original_history) == encoded(candidate_history)
    cleanup_equal = encoded(original_cleanup) == encoded(candidate_cleanup)
    succeeded = (failure is None and stable and expected_unchanged
                 and len(originals) == len(actuals) == len(comparisons) == 521
                 and not differences and not any(guards.values()) and history_equal and cleanup_equal
                 and not any(row['cleanup_error'] is not None for row in original_cleanup + candidate_cleanup)
                 and sum(frames.values()) > 0 and all(events[str(event)] > 0 for event in range(6))
                 and events['1'] == events['2'] + events['3'] and attempts == events
                 and set(returns) == {str(native.OUTPUT_BYTES)})
    report = {
        **start, 'status': 'PASS' if succeeded else 'HOLD', 'exception': failure,
        'source_after': source_after, 'source_image_manifest_build_and_compiler_unchanged': stable,
        'original_count': len(originals), 'actual_count': len(actuals),
        'comparison_count': len(comparisons), 'differences': differences,
        'history_equal': history_equal, 'held_cleanup_equal': cleanup_equal,
        'guards': dict(guards), 'known_exact_runtime_H0_anchor': original_anchor,
        'known_exact_runtime_H0_anchor_checked': original_anchor is not None,
        'originals_sha256': sha256((out / 'originals-521.json').read_bytes()).hexdigest()
            if (out / 'originals-521.json').exists() else None,
        'actuals_sha256': sha256((out / 'actuals-521.json').read_bytes()).hexdigest()
            if (out / 'actuals-521.json').exists() else None,
        'actual_frames': sum(frames.values()), 'actual_frames_by_phase': dict(frames),
        'actual_native_entry_attempts': dict(attempts), 'actual_native_entry_events': dict(events),
        'actual_native_return_codes': dict(returns),
        'actual_native_entry_events_by_phase': {key: dict(value) for key, value in by_phase.items()},
        'count_scope': 'this fresh child; original fork-grandchild entries are not merged or invented',
        'both_retained_aliases_poisoned': selected_started,
        'expected_written_before_native_mapping': expected_frozen,
        'expected_file_unchanged_after_candidate': expected_unchanged,
        'no_reset_no_new_warmup_loop_no_exception_attribute_normalization': True,
        'elapsed_seconds': time.monotonic() - begin,
    }
    (out / 'report.json').write_bytes(encoded(report) + b'\n')
    print(encoded({key: report[key] for key in ('history', 'status', 'original_count', 'actual_count',
          'differences', 'actual_frames', 'elapsed_seconds')}).decode(), flush=True)
    return 0 if succeeded else 1


if __name__ == '__main__':
    raise SystemExit(main())
