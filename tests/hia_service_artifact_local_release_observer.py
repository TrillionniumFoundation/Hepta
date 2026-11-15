"""Fresh-process original146 then independent-VM146; no native mapping.

The parent owns a new 180-second Source-control deadline. This child remains
in that parent's process group and cannot launch another process. It does not
collect, reset or normalize garbage; only the immutable original observer's
three declared GC cases perform collection.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import struct
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests import hia_service_artifact_oracle as oracle
from tests.hia_service_artifact_observer import KNOWN_ORIGINALS, differences, original_inputs

SCHEMA = 'hepta.hia.service-artifact-local-release-observer.v1'
SOURCE_PATHS = (
    'tests/hia_service_artifact_local_release_observer.py',
    'tests/test_hia_service_artifact_local_release.py',
    'tests/test_hia_service_artifact_native.py',
    'tests/hia_service_artifact_observer.py',
    'tests/hia_service_artifact_oracle.py',
    'examples/hia_bootstrap/service_artifact.hepta',
    'tools/generate_hia_service_artifact.py',
    'hepta/hia_service_artifact_native.py',
    'hepta/hia_service_artifact_protocol.py',
    'hepta/hia_native_delivery.py',
    'hepta/hia_agent_service.py',
    'hepta/hia_agent_assembly.py',
    'hepta/hia_program.py',
    'hepta/hia_program_runtime.py',
    'hepta/hia_program_tools.py',
    'hepta/hia_bounded_memory.py',
    'hepta/hia_schema.py',
    'hepta/hia_opcodes.py',
    'hepta/hia_json_preflight.py',
    'hepta/hia_json_preflight_native.py',
    'tests/fixtures/hia_service_artifact_original_5bf/freeze.json',
)
PHASE = 'startup'
AUDIT_REFUSALS = []
MAPPING_CALLS = []
REFERENCE_CALLS = []


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def source_snapshot():
    # This Source control can run before metadata regeneration. Bind actual
    # bytes directly; do not import a source-contract/current_sources checker.
    freeze = json.loads((oracle.ROOT / 'freeze.json').read_bytes())
    names = sorted(set(SOURCE_PATHS) | set(freeze['inputs']))
    return {name: pin((ROOT / name).read_bytes()) for name in names}


def audit_event(event, arguments):
    blocked = event in {'subprocess.Popen', 'os.system', 'sqlite3.connect',
        'socket.__new__', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'mmap.__new__'} or event.startswith('os.exec')
    if PHASE in ('original', 'candidate-vm'):
        blocked = blocked or event in ('ctypes.dlopen', 'ctypes.dlsym')
    if blocked:
        AUDIT_REFUSALS.append({'phase': PHASE, 'event': event})
        raise AssertionError('finite Source control attempted a real provider: ' + event)


def forbid_mapping(*arguments, **keywords):
    MAPPING_CALLS.append(True)
    raise AssertionError('local-release Source control cannot map a native image')


def forbid_reference(*arguments, **keywords):
    REFERENCE_CALLS.append(True)
    raise AssertionError('independent VM cannot call the retained artifact handler')


def write_new(path, value):
    raw = value if isinstance(value, bytes) else oracle.canonical(value)
    with path.open('xb') as stream:
        stream.write(raw)
    return pin(raw)


def run(output):
    global PHASE
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    source_before = source_snapshot()
    write_new(output / 'source-before.json', source_before)
    cases = original_inputs()
    ordered = [case['id'] for case in cases]
    product_before = sorted(name for name in sys.modules
        if name == 'hepta' or name.startswith('hepta.') or name == 'tools' or name.startswith('tools.'))
    if product_before:
        raise AssertionError('fresh child imported candidate before independent originals')
    phases = []

    def phase(name, **values):
        global PHASE
        PHASE = name
        phases.append({'name': name, 'time_ns': time.time_ns(), **values})
        (output / 'ordering.json').write_bytes(oracle.canonical(phases))

    sys.addaudithook(audit_event)
    finder = oracle.NoProduct()
    sys.meta_path.insert(0, finder)
    phase('original', product_modules=product_before)
    try:
        expected = [oracle.observe(case) for case in cases]
    finally:
        sys.meta_path.remove(finder)
    expected_raw = oracle.canonical(expected)
    original_path = output / 'originals-146.json'
    original_pin = write_new(original_path, expected_raw)
    original_late = json.loads(oracle.canonical(oracle.LATE))
    phase('originals-written', original_file=original_pin, count=len(expected))
    # No candidate import, assembly or VM invocation precedes this frozen file.
    assert original_path.read_bytes() == expected_raw
    phase('candidate-imports')
    import ctypes
    from hepta import hia_agent_service as api
    from hepta import hia_native_delivery as delivery
    from hepta import hia_service_artifact_native as native
    from hepta.hia_agent_assembly import assemble_program
    from tests.test_hia_service_artifact_native import vm_image

    initializer = native.NativeHiaJsonImage.__init__
    reference = api._NATIVE_SERVICE_ARTIFACT_REFERENCE
    events, frames = {}, [0]
    actual, exception, image = [], None, None
    native.NativeHiaJsonImage.__init__ = forbid_mapping
    api._NATIVE_SERVICE_ARTIFACT_REFERENCE = forbid_reference
    try:
        program = assemble_program(native.SOURCE.read_bytes())
        image = vm_image(program)
        entry = image._entry

        def counted(source, size, result, capacity, state, extent):
            magic, event = struct.unpack('<2Q', ctypes.string_at(source, 16))
            code = entry(source, size, result, capacity, state, extent)
            if magic != native.REQUEST_MAGIC or code != native.OUTPUT_BYTES:
                raise AssertionError('independent VM returned another ABI')
            key = str(event)
            events[key] = events.get(key, 0) + 1
            return code

        def factory(namespace):
            def invoke(service, arguments):
                frame = native.ServiceArtifactFrame(image, service, arguments, namespace=namespace)
                frames[0] += 1
                # Drop only the forwarder's copies before any provider runs.
                del service, arguments
                return frame.finish()
            return invoke

        image._entry = counted
        phase('candidate-vm', original_file=pin(original_path.read_bytes()))
        for case in cases:
            actual.append(oracle.observe(case, factory=factory))
    except BaseException:
        exception = traceback.format_exc()
    finally:
        native.NativeHiaJsonImage.__init__ = initializer
        api._NATIVE_SERVICE_ARTIFACT_REFERENCE = reference
    phase('candidate-finished', actual_count=len(actual), actual_vm_frames=frames[0])
    actual_raw = oracle.canonical(actual)
    actual_pin = write_new(output / 'actuals-146.json', actual_raw)
    comparisons = [{'case': case['id'], 'expected': left, 'actual': right,
                    'equal': oracle.canonical(left) == oracle.canonical(right)}
                   for case, left, right in zip(cases, expected, actual)]
    complete_pin = write_new(output / 'complete-observations.json', comparisons)
    diff = differences(expected, actual)
    diff_pin = write_new(output / 'differences.json', diff)
    original_inputs()
    source_after = source_snapshot()
    write_new(output / 'source-after.json', source_after)
    original_after = pin(original_path.read_bytes())
    custody = list(delivery.custody_snapshot())
    known = KNOWN_ORIGINALS.get(platform.python_version())
    stable = source_before == source_after
    unchanged = original_path.read_bytes() == expected_raw and oracle.canonical(expected) == expected_raw
    passed = (exception is None and stable and unchanged and not diff
        and expected_raw == actual_raw and len(expected) == len(actual) == frames[0] == 146
        and (known is None or known == original_pin['sha256'])
        and not original_late and not oracle.LATE and not custody
        and not REFERENCE_CALLS and not MAPPING_CALLS and not AUDIT_REFUSALS
        and image is not None and image.entry_count > 0
        and sum(events.values()) == image.entry_count and events.get('0') == 146
        and events.get('1', 0) == events.get('2', 0) + events.get('3', 0))
    phase('readback', original_file=original_after, unchanged=unchanged)
    report = {'schema': SCHEMA, 'status': 'PASS' if passed else 'FAIL',
        'runtime': sys.version, 'runtime_version': platform.python_version(),
        'executable': sys.executable, 'pid': os.getpid(), 'ppid': os.getppid(),
        'pgid': os.getpgrp(), 'argv': sys.argv, 'cwd': str(Path.cwd()),
        'case_order': ordered, 'original_count': len(expected), 'actual_count': len(actual),
        'actual_vm_frames': frames[0], 'actual_vm_entries': 0 if image is None else image.entry_count,
        'actual_vm_entry_events': events, 'actual_native_entries': 0,
        'originals_before': original_pin, 'originals_after': original_after,
        'actuals': actual_pin, 'complete_observations': complete_pin, 'differences': diff_pin,
        'known_same_runtime_original_sha256': known,
        'product_modules_before_originals': product_before,
        'expected_file_unchanged_after_candidate': unchanged,
        'expected_written_before_candidate_imports': True,
        'source_before': source_before, 'source_after': source_after, 'source_unchanged': stable,
        'exception': exception, 'original_late_events': original_late, 'all_late_events': oracle.LATE,
        'remaining_delivery_custody': custody, 'reference_calls': REFERENCE_CALLS,
        'mapping_calls': MAPPING_CALLS, 'audit_refusals': AUDIT_REFUSALS,
        'scope': '146 finite fake-provider originals then independent VM in one fresh child',
        'native_mapping_permitted': False, 'test01_or_test02_executed_in_child': False,
        'new_gc_collection_or_observer_normalization': False,
        'source_contract_metadata_required': False, 'source_scope': 'explicit actual byte pins; outer gate binds full tree',
        'cold_or_native_qualification': False, 'public_or_resource_qualification': False,
        'whole_native_stack_qualified': False}
    write_new(output / 'report.json', report)
    print(json.dumps({key: report[key] for key in ('status', 'original_count', 'actual_count',
        'actual_vm_frames', 'actual_vm_entries', 'actual_vm_entry_events')}, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.output.resolve()))
