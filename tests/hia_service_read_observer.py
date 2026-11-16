"""Stream all frozen original read inputs, optionally against an actual image.

This is a finite semantic comparison, not matching-cold or whole-language
qualification. Original raw exception fields and destructor traces are kept.
"""
from __future__ import annotations

import argparse
from hashlib import file_digest, sha256
import ctypes
import json
import os
from pathlib import Path
import sys
import struct
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tests.hia_service_read_fixture import (BASE_COUNT, FAULT_COUNT, IDENTITY_SHA256,
    canonical, original_inputs, originals, observe_original, observe_candidate)


def freeze_originals(output, groups, oracle, bodies, runtime):
    """Finish both complete original passes before any candidate admission."""
    path = output / 'originals-before-candidate.jsonl'
    counts, digest = {'base': 0, 'fault': 0}, sha256()
    with path.open('xb') as stream, (output / 'original-traceback-diagnostics.jsonl').open('xb') as traces:
        for group, cases in groups:
            for index, case in enumerate(cases):
                first, first_traces = observe_original(case, oracle, bodies)
                second, second_traces = observe_original(case, oracle, bodies)
                equal = canonical(first) == canonical(second)
                raw = canonical({'group': group, 'index': index, 'case_id': case['id'],
                    'original': first, 'second_original': second, 'canonical_bytes_equal': equal}) + b'\n'
                stream.write(raw); stream.flush(); digest.update(raw)
                traces.write(canonical({'group': group, 'index': index, 'case_id': case['id'],
                    'original': first_traces, 'second_original': second_traces}) + b'\n')
                traces.flush()
                if not equal:
                    raise AssertionError('fresh original observations differ before any candidate')
                counts[group] += 1
                del first, second, first_traces, second_traces, raw
    pin = digest.hexdigest()
    (output / 'original-freeze-before-candidate.json').write_bytes(canonical({
        'schema': 'hepta.hia.service-read-originals-before-candidate.v1', 'runtime': runtime,
        'counts': counts, 'two_complete_passes_equal': True,
        'originals_jsonl_sha256': pin, 'originals_jsonl_bytes': path.stat().st_size,
        'candidate_imported_mapped_or_executed': False, 'source_identity_sha256': IDENTITY_SHA256}))
    return path, counts, pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--original-only', action='store_true')
    selection.add_argument('--manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    identity, base, faults = original_inputs()
    oracle, bodies = originals()
    source_before = {str(ROOT / 'tests/hia_service_read_fixture.py'):
        sha256((ROOT / 'tests/hia_service_read_fixture.py').read_bytes()).hexdigest(),
        str(Path(__file__).resolve()): sha256(Path(__file__).read_bytes()).hexdigest()}
    source_before.update({str(ROOT / 'tests/fixtures/hia_service_read_original_91bbd077' / name): row['sha256']
                          for name, row in identity['file_pins'].items()})
    runtime = {'implementation': sys.implementation.name, 'cache_tag': sys.implementation.cache_tag,
               'python': sys.version, 'platform': sys.platform}
    start = time.monotonic()
    groups = (('base', base), ('fault', faults))
    original_path, original_counts, original_pin = freeze_originals(args.output, groups, oracle, bodies, runtime)
    image = None
    bundle = {}
    entry_attempts, entry_returns = {}, {}
    if args.manifest is not None:
        from hepta.hia_service_read_native import installed_service_read
        from tools.build_hia_service_read import INPUTS
        image = installed_service_read(str(args.manifest))
        source_before.update({str(ROOT / name): sha256((ROOT / name).read_bytes()).hexdigest()
                              for name in INPUTS})
        bundle = {str(path): sha256(path.read_bytes()).hexdigest()
                  for path in sorted(args.manifest.parent.rglob('*')) if path.is_file()}
        actual_entry = image._entry
        def counted(source, size, output, capacity, state, extent):
            event = str(struct.unpack('<2Q', ctypes.string_at(source, 16))[1])
            entry_attempts[event] = entry_attempts.get(event, 0) + 1
            result = actual_entry(source, size, output, capacity, state, extent)
            entry_returns[event] = entry_returns.get(event, 0) + 1
            return result
        image._entry = counted
    counts = {'base': 0, 'fault': 0}
    mismatch_count, mismatch_ids = 0, []
    digest = sha256()
    raw_path = args.output / 'observations.jsonl'
    diagnostics = args.output / 'traceback-diagnostics.jsonl'
    with original_path.open('rb') as expected_stream, raw_path.open('xb') as stream, diagnostics.open('xb') as traces:
        for group, cases in groups:
            for index, case in enumerate(cases):
                original_record = json.loads(next(expected_stream))
                if (original_record['group'], original_record['index'], original_record['case_id']) != (group, index, case['id']):
                    raise AssertionError('frozen original observation order differs')
                expected = original_record['original']
                if image is None:
                    actual, actual_tracebacks = original_record['second_original'], None
                    actual_kind = 'second_original'
                else:
                    actual, actual_tracebacks = observe_candidate(case, image,
                        oracle=oracle, bodies=bodies, fresh=True)
                    actual_kind = 'native_candidate'
                expected_raw, actual_raw = canonical(expected), canonical(actual)
                equal = expected_raw == actual_raw
                record = {'group': group, 'index': index, 'case_id': case['id'],
                          'original': expected, actual_kind: actual, 'canonical_bytes_equal': equal}
                raw = canonical(record) + b'\n'
                stream.write(raw)
                stream.flush()
                digest.update(raw)
                if image is not None:
                    traces.write(canonical({'group': group, 'index': index, 'case_id': case['id'],
                        actual_kind: actual_tracebacks}) + b'\n')
                    traces.flush()
                counts[group] += 1
                if not equal:
                    mismatch_count += 1
                    if len(mismatch_ids) < 32:
                        mismatch_ids.append(case['id'])
                del record, raw, expected, actual, expected_raw, actual_raw
                del original_record, actual_tracebacks
        if expected_stream.read(1):
            raise AssertionError('frozen original observation stream has extra entries')
    if image is not None:
        image._entry = actual_entry
    source_after = {name: sha256(Path(name).read_bytes()).hexdigest() for name in source_before}
    stable = source_after == source_before and all(
        sha256(Path(name).read_bytes()).hexdigest() == value for name, value in bundle.items())
    with original_path.open('rb') as stream:
        originals_unchanged = file_digest(stream, 'sha256').hexdigest() == original_pin
    stable = stable and originals_unchanged
    remaining = []
    if image is not None:
        from hepta.hia_native_delivery import custody_snapshot
        remaining = custody_snapshot()
    passed = counts == {'base': BASE_COUNT, 'fault': FAULT_COUNT} and mismatch_count == 0 and stable and not remaining
    report = {'schema': 'hepta.hia.service-read-finite-observations.v1',
        'status': 'PASS' if passed else 'FAIL', 'runtime': runtime,
        'scope': 'ORIGINAL_ONLY' if image is None else 'FINITE_ACTUAL_IMAGE_FRESH_PROVIDER_CODE',
        'counts': counts, 'total_cases': sum(counts.values()),
        'ordered_case_ids_sha256': sha256(canonical([case['id'] for case in (*base, *faults)])).hexdigest(),
        'mismatch_count': mismatch_count, 'first_mismatch_ids': mismatch_ids,
        'all_inputs_run_from_first_to_last': True, 'observations_jsonl_sha256': digest.hexdigest(),
        'observations_jsonl_bytes': raw_path.stat().st_size,
        'originals_completed_and_frozen_before_candidate_import': True,
        'original_counts': original_counts, 'originals_jsonl_sha256': original_pin,
        'originals_jsonl_unchanged': originals_unchanged,
        'source_identity_sha256': IDENTITY_SHA256, 'source_before': source_before,
        'source_after': source_after, 'source_and_bundle_unchanged': stable, 'bundle_pins': bundle,
        'elapsed_seconds': time.monotonic() - start,
        'native_image_sha256': None if image is None else image.image_sha256,
        'actual_entry_attempts': entry_attempts, 'actual_entry_returns': entry_returns,
        'remaining_delivery_custody': remaining,
        'original_code_history': 'complete original compiled freshly for every input',
        'candidate_code_history': None if image is None else 'exact linear-provider/effect code cloned freshly per input',
        'candidate_product_defaults_or_public_caller_history_changed': False,
        'exception_fields_normalized': False,
        'whole_stack_native_or_current_cold_qualified': False,
        'all_interpreter_execution_histories_proved': False,
        'all_input_equivalence_proved': False}
    (args.output / 'report.json').write_bytes(canonical(report))
    print(json.dumps({name: report[name] for name in ('status', 'scope', 'counts', 'mismatch_count', 'elapsed_seconds')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
