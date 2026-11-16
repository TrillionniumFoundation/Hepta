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


def original_inputs():
    freeze = json.loads((oracle.ROOT / 'freeze.json').read_bytes())
    for name, item in freeze['inputs'].items():
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
    manifest = Path(manifest).resolve(strict=True)
    manifest_raw = manifest.read_bytes()
    image_path = manifest.parent / json.loads(manifest_raw)['image_path']
    image_raw = image_path.read_bytes()
    expected = [oracle.observe(case) for case in cases]
    expected_raw = oracle.canonical(expected)
    original_path = output / 'originals-146.json'
    original_path.write_bytes(expected_raw)
    expected_sha = sha256(expected_raw).hexdigest()
    known = KNOWN_ORIGINALS.get(platform.python_version())
    original_late = list(oracle.LATE)
    # The independent expectation above is immutable before candidate imports,
    # mapping or execution. Do not synthesize or normalize an expectation.
    import ctypes
    from tools.build_hia_json_preflight import current_sources
    from tools.build_hia_service_artifact import INPUTS
    before = current_sources()
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
    stable = (before == after and inputs == {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
              and manifest.read_bytes() == manifest_raw and image_path.read_bytes() == image_raw
              and original_path.read_bytes() == expected_raw)
    custody = list(delivery.custody_snapshot())
    passed = (exception is None and stable and expected_raw == actual_raw
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
    rows = [oracle.observe(case) for case in values]
    original_inputs()
    raw = oracle.canonical(rows)
    (output / 'originals-146.json').write_bytes(raw)
    known = KNOWN_ORIGINALS.get(platform.python_version())
    passed = len(rows) == 146 and not oracle.LATE and (known is None or sha256(raw).hexdigest() == known)
    report = {'status': 'PASS' if passed else 'FAIL', 'runtime': sys.version,
        'count': len(rows), 'ordered_ids': [case['id'] for case in values],
        'sha256': sha256(raw).hexdigest(), 'known_same_runtime_sha256': known,
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
