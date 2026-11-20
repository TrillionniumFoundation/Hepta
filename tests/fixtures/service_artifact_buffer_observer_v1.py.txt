"""Freeze all 146 original observations before mapping the candidate image.

This finite comparison uses the explicit fake-provider namespace seam. Actual
public selection, Store custody and installed worker effects are separate gates.
"""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import struct
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests import hia_service_artifact_oracle as oracle
from tests.hia_service_artifact_preparation import admit_preparation

KNOWN_ORIGINALS = {
    '3.12.14': 'beac0108873f4b64e757747d3d1542fe99b9fe2a242f599032e9e16caafd6804',
    '3.13.5': '83411913ceaa02abd32e697dfebc7fe383054a209b1b227838c6445bb046895f',
}


def differences(expected, actual, path='$'):
    if type(expected) is not type(actual):
        return [{'path': path, 'expected': expected, 'actual': actual}]
    rows = []
    if type(expected) is dict:
        for key in sorted(set(expected) | set(actual)):
            if key not in expected or key not in actual:
                rows.append({'path': path + '.' + key, 'expected': expected.get(key), 'actual': actual.get(key)})
            else:
                rows.extend(differences(expected[key], actual[key], path + '.' + key))
    elif type(expected) is list:
        if len(expected) != len(actual):
            rows.append({'path': path + '.length', 'expected': len(expected), 'actual': len(actual)})
        for index, (left, right) in enumerate(zip(expected, actual)):
            rows.extend(differences(left, right, path + '[' + str(index) + ']'))
    elif expected != actual:
        rows.append({'path': path, 'expected': expected, 'actual': actual})
    return rows


def preparation_sources():
    proof = admit_preparation(ROOT)
    if (proof['preparation_identity'] != oracle.PREPARATION_IDENTITY
            or proof['legacy_known_originals'] != KNOWN_ORIGINALS
            or proof['captured_files']['tests/hia_service_artifact_preparation.py']
                != {'bytes': 8832, 'sha256': 'd928034b9b68d56c825bc94c9ab082c4454cba0bf86d2e493ce9a82dffcce7e9'}):
        raise AssertionError('artifact oracle preparation identity differs')
    return proof


def observation_readback(output, sealed):
    """Compare the complete sealed bytes; parsing or normalization cannot pass."""
    if (type(sealed) is not dict or not sealed
            or any(type(name) is not str or Path(name).name != name or type(raw) is not bytes
                   for name, raw in sealed.items())):
        raise ValueError('artifact observation readback requires exact named byte records')
    actual = {name: (output / name).read_bytes() for name in sealed}
    return {'unchanged': actual == sealed,
            'files': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                      for name, raw in actual.items()}}


def original_inputs():
    preparation = preparation_sources()
    freeze = json.loads((oracle.ROOT / 'freeze.json').read_bytes())
    for name, historical in freeze['inputs'].items():
        item = preparation['admitted_original_inputs'][name]
        raw = (ROOT / name).read_bytes()
        if len(raw) != item['bytes'] or sha256(raw).hexdigest() != item['sha256']:
            raise AssertionError('independent original input differs: ' + name)
    cases = oracle.cases()
    if len(cases) != 146 or [case['id'] for case in cases] != freeze['ordered_ids']:
        raise AssertionError('complete original finite inventory differs')
    return cases


def run(manifest, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cases = original_inputs()
    preparation = preparation_sources()
    manifest = Path(manifest).resolve(strict=True)
    manifest_raw = manifest.read_bytes()
    image_path = manifest.parent / json.loads(manifest_raw)['image_path']
    image_raw = image_path.read_bytes()
    expected = [oracle.observe(case) for case in cases]
    expected_raw = oracle.canonical(expected)
    original_path = output / 'originals-146.json'
    original_path.write_bytes(expected_raw)
    expected_sha = sha256(expected_raw).hexdigest()
    repeated = [oracle.observe(case) for case in cases]
    repeated_raw = oracle.canonical(repeated)
    (output / 'originals-repeat-146.json').write_bytes(repeated_raw)
    replay_differences = differences(expected, repeated)
    replay_difference_raw = oracle.canonical(replay_differences)
    (output / 'original-replay-differences.json').write_bytes(replay_difference_raw)
    sealed_replays = {'originals-repeat-146.json': repeated_raw,
                      'original-replay-differences.json': replay_difference_raw}
    if len(repeated) != 146 or repeated_raw != expected_raw or replay_differences:
        raise AssertionError('preparation-v2 original146 replays differ before candidate imports')
    known = preparation['current_known_originals'].get(platform.python_version())
    original_late = list(oracle.LATE)
    # The independent expectation above is immutable before candidate imports,
    # mapping or execution. Do not synthesize or normalize an expectation.
    import ctypes
    from tools.build_hia_json_preflight import current_sources
    from tools.build_hia_service_artifact import INPUTS
    before = current_sources()
    if any(before.get(name) != item['sha256']
           for name, item in preparation['captured_files'].items()):
        raise AssertionError('artifact preparation differs from the actual component source closure')
    inputs = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    from hepta import hia_service_artifact_native as native
    from hepta import hia_agent_service as api
    from hepta import hia_native_delivery as delivery
    image = native.installed_service_artifact(str(manifest))
    events, frame_count, reference_calls = Counter(), [0], []
    entry, reference = image._entry, api._NATIVE_SERVICE_ARTIFACT_REFERENCE

    def counted(source, size, out, capacity, state, extent):
        magic, event = struct.unpack('<2Q', ctypes.string_at(source, 16))
        code = entry(source, size, out, capacity, state, extent)
        if magic != native.REQUEST_MAGIC or code != native.OUTPUT_BYTES:
            raise AssertionError('actual candidate image returned another ABI')
        events[str(event)] += 1
        return code

    def forbidden(*arguments, **keywords):
        reference_calls.append(True)
        raise AssertionError('candidate invoked the retained artifact handler')

    def factory(namespace):
        def invoke(service, arguments):
            frame = native.ServiceArtifactFrame(image, service, arguments, namespace=namespace)
            frame_count[0] += 1
            return frame.finish()
        return invoke

    image._entry, api._NATIVE_SERVICE_ARTIFACT_REFERENCE = counted, forbidden
    actual, exception = [], None
    try:
        actual = [oracle.observe(case, factory=factory) for case in cases]
    except BaseException:
        exception = traceback.format_exc()
    finally:
        image._entry, api._NATIVE_SERVICE_ARTIFACT_REFERENCE = entry, reference
    actual_raw = oracle.canonical(actual)
    (output / 'actuals-146.json').write_bytes(actual_raw)
    comparisons = [{'case': case['id'], 'expected': left, 'actual': right, 'equal': left == right}
                   for case, left, right in zip(cases, expected, actual)]
    (output / 'complete-observations.json').write_bytes(oracle.canonical(comparisons))
    after = current_sources()
    preparation_after = preparation_sources()
    replay_readback = observation_readback(output, sealed_replays)
    stable = (preparation_after == preparation and before == after and inputs == {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
              and manifest.read_bytes() == manifest_raw and image_path.read_bytes() == image_raw
              and original_path.read_bytes() == expected_raw)
    custody = list(delivery.custody_snapshot())
    passed = (exception is None and stable and replay_readback['unchanged'] and expected_raw == actual_raw
              and (known is None or known == expected_sha) and not oracle.LATE
              and len(actual) == frame_count[0] == 146 and not reference_calls and not custody
              and events['0'] == 146 and events['1'] == events['2'] + events['3'])
    report = {'schema': 'hepta.hia.service-artifact-finite-observer.v1',
        'status': 'PASS' if passed else 'FAIL', 'runtime': sys.version, 'executable': sys.executable,
        'process': os.getpid(), 'original_count': len(expected), 'actual_count': len(actual),
        'actual_frames': frame_count[0], 'case_order': [case['id'] for case in cases],
        'differences': differences(expected, actual), 'exception': exception,
        'originals_sha256': expected_sha, 'actuals_sha256': sha256(actual_raw).hexdigest(),
        'known_same_runtime_original_sha256': known,
        'oracle_preparation': preparation, 'oracle_preparation_after': preparation_after,
        'original_repeat_count': len(repeated),
        'original_repeat_sha256': sha256(repeated_raw).hexdigest(),
        'original_replay_differences': replay_differences,
        'original_replay_files_after_candidate': replay_readback,
        'original_replays_equal_before_candidate_imports': repeated_raw == expected_raw,
        'legacy_v1_known_same_runtime_original_sha256': KNOWN_ORIGINALS.get(platform.python_version()),
        'known_original_equal': known is None or known == expected_sha,
        'expected_written_before_native_mapping': True,
        'expected_file_unchanged_after_candidate': original_path.read_bytes() == expected_raw,
        'retained_reference_poisoned': True, 'reference_calls': reference_calls,
        'original_late_events': original_late, 'all_late_events': oracle.LATE,
        'actual_native_entry_events': dict(events), 'remaining_delivery_custody': custody,
        'source_before': before, 'source_after': after, 'component_input_pins': inputs,
        'source_image_and_manifest_unchanged': stable, 'manifest': str(manifest),
        'manifest_sha256': sha256(manifest_raw).hexdigest(),
        'native_image_sha256': sha256(image_raw).hexdigest(),
        'scope': '146 finite original vs actual-image frame with explicit fake namespace',
        'public_selection_qualified_by_this_observer': False,
        'resource_retirement_qualified_by_this_observer': False,
        'all_input_equivalence_proved': False, 'whole_native_stack_qualified': False}
    (output / 'report.json').write_bytes(oracle.canonical(report))
    print(json.dumps({key: report[key] for key in (
        'status', 'original_count', 'actual_count', 'actual_frames', 'actual_native_entry_events')}))
    return 0 if passed else 1


def run_original(output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.meta_path.insert(0, oracle.NoProduct())
    sys.addaudithook(oracle.no_effect)
    values = original_inputs()
    preparation = preparation_sources()
    rows = [oracle.observe(case) for case in values]
    repeated = [oracle.observe(case) for case in values]
    original_inputs()
    preparation_after = preparation_sources()
    raw = oracle.canonical(rows)
    (output / 'originals-146.json').write_bytes(raw)
    repeated_raw = oracle.canonical(repeated)
    (output / 'originals-repeat-146.json').write_bytes(repeated_raw)
    replay_differences = differences(rows, repeated)
    replay_difference_raw = oracle.canonical(replay_differences)
    (output / 'original-replay-differences.json').write_bytes(replay_difference_raw)
    replay_readback = observation_readback(output, {'originals-146.json': raw,
        'originals-repeat-146.json': repeated_raw,
        'original-replay-differences.json': replay_difference_raw})
    known = preparation['current_known_originals'].get(platform.python_version())
    passed = (len(rows) == len(repeated) == 146 and preparation_after == preparation
              and raw == repeated_raw and replay_readback['unchanged'] and not replay_differences and not oracle.LATE
              and (known is None or sha256(raw).hexdigest() == known))
    report = {'status': 'PASS' if passed else 'FAIL', 'runtime': sys.version,
        'count': len(rows), 'ordered_ids': [case['id'] for case in values],
        'sha256': sha256(raw).hexdigest(), 'known_same_runtime_sha256': known,
        'oracle_preparation': preparation, 'oracle_preparation_after': preparation_after,
        'original_repeat_count': len(repeated), 'original_repeat_sha256': sha256(repeated_raw).hexdigest(),
        'original_replay_differences': replay_differences,
        'original_replay_files_readback': replay_readback,
        'original_replays_equal_before_candidate_imports': raw == repeated_raw,
        'legacy_v1_known_same_runtime_sha256': KNOWN_ORIGINALS.get(platform.python_version()),
        'late_events': oracle.LATE, 'selected_or_native_or_VM_execution': False}
    (output / 'report.json').write_bytes(oracle.canonical(report))
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--manifest', type=Path)
    choice.add_argument('--original-only', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run_original(args.output) if args.original_only else run(args.manifest, args.output))
