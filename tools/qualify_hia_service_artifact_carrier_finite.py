"""Same full146 domain through a freshly built, explicit v6 carrier capsule.

This is development evidence. The original observer/domain/GC policy is not
changed or pre-imported with the selected carrier. Source custody is terminal.
"""
from pathlib import Path
from collections import Counter
from hashlib import sha256
import json
import os
import struct
import sys
import traceback

SOURCE, OUTPUT, MANIFEST, CAPSULE = (Path(value) for value in sys.argv[1:5])
EXPECTED_CAPSULE = sys.argv[5]
OUTPUT.mkdir()
sys.path.insert(0, str(SOURCE))
from tests import hia_service_artifact_oracle as oracle
from tests.hia_service_artifact_observer import original_inputs, preparation_sources, differences

def inventory():
    return {path.relative_to(SOURCE).as_posix(): {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
            for path in sorted(SOURCE.rglob('*')) if path.is_file()
            for raw in [path.read_bytes()]}

captured = inventory()
capsule_raw, manifest_raw = CAPSULE.read_bytes(), MANIFEST.read_bytes()
assert sha256(capsule_raw).hexdigest() == EXPECTED_CAPSULE
cases = original_inputs()
preparation = preparation_sources()
expected = [oracle.observe(case) for case in cases]
expected_raw = oracle.canonical(expected)
(OUTPUT/'originals-146.json').write_bytes(expected_raw)
repeated = [oracle.observe(case) for case in cases]
repeated_raw = oracle.canonical(repeated)
(OUTPUT/'originals-repeat-146.json').write_bytes(repeated_raw)
if len(expected) != 146 or len(repeated) != 146 or expected_raw != repeated_raw:
    raise AssertionError('complete original replays differ before carrier imports')
prepared = set(sys.modules)
from hepta.hia_native_helpers import native_helpers_scope, native_helpers_identity
events, frames, reference_calls = Counter(), [0], []
actual, exception, identity, carrier_profile = [], None, None, None
try:
    with native_helpers_scope(str(CAPSULE), EXPECTED_CAPSULE) as binding:
        from hepta import hia_service_artifact_native as native
        from hepta import hia_agent_service as api
        from hepta import hia_native_delivery as delivery
        from hepta import hia_native_image as admitted
        image = native.installed_service_artifact(str(MANIFEST))
        carrier = admitted.extension()
        if image._native_image_carrier is not carrier or type(image._mapping) is not carrier.Image:
            raise AssertionError('actual selected image did not use the admitted mechanical carrier')
        identity = native_helpers_identity()
        carrier_profile = admitted._bundle()['profile']
        entry, reference = image._entry, api._NATIVE_SERVICE_ARTIFACT_REFERENCE

        def counted(source, size, out, capacity, state, extent):
            magic, event = struct.unpack_from('<2Q', source, 0)
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
                frames[0] += 1
                return frame.finish()
            return invoke

        image._entry, api._NATIVE_SERVICE_ARTIFACT_REFERENCE = counted, forbidden
        try:
            actual = [oracle.observe(case, factory=factory) for case in cases]
        finally:
            image._entry, api._NATIVE_SERVICE_ARTIFACT_REFERENCE = entry, reference
        remaining = list(delivery.custody_snapshot())
        if native_helpers_identity() != identity:
            raise AssertionError('v6 identity changed after the complete domain')
        binding.check()
except BaseException:
    exception = traceback.format_exc()
    remaining = []
actual_raw = oracle.canonical(actual)
(OUTPUT/'actuals-146.json').write_bytes(actual_raw)
comparison = [{'case': case['id'], 'expected': left, 'actual': right, 'equal': left == right}
              for case, left, right in zip(cases, expected, actual)]
(OUTPUT/'complete-observations.json').write_bytes(oracle.canonical(comparison))
changes = differences(expected, actual)
stable = (inventory() == captured and preparation_sources() == preparation
          and CAPSULE.read_bytes() == capsule_raw and MANIFEST.read_bytes() == manifest_raw
          and (OUTPUT/'originals-146.json').read_bytes() == expected_raw
          and (OUTPUT/'originals-repeat-146.json').read_bytes() == repeated_raw)
report = {
    'schema': 'hepta.development.artifact-native-carrier-v6-full146.v1',
    'scope': 'DEVELOPMENT_FRESH_BUILD_EXPLICIT_V6_REAL146_NOT_COLD_OR_NATIVE8_QUALIFICATION',
    'status': 'DEVELOPMENT_MATCH' if (not exception and not changes and stable
        and len(actual) == frames[0] == 146 and not reference_calls and not remaining
        and not oracle.LATE and events['0'] == 146 and events['1'] == events['2'] + events['3'])
        else 'DEVELOPMENT_HOLD',
    'runtime': sys.version, 'executable': sys.executable, 'process': os.getpid(),
    'original_count': len(expected), 'repeat_count': len(repeated), 'actual_count': len(actual),
    'frames': frames[0], 'entry_events': dict(events), 'differences': changes, 'exception': exception,
    'original_sha256': sha256(expected_raw).hexdigest(), 'repeat_sha256': sha256(repeated_raw).hexdigest(),
    'actual_sha256': sha256(actual_raw).hexdigest(), 'preparation': preparation,
    'source_before': captured, 'source_after': inventory(), 'current_candidate_all_files_unchanged': stable,
    'capsule': {'path': str(CAPSULE), 'bytes': len(capsule_raw), 'sha256': EXPECTED_CAPSULE},
    'native_helpers_identity': identity, 'carrier_profile': carrier_profile,
    'all_late_events': oracle.LATE, 'reference_calls': reference_calls, 'remaining_custody': remaining,
    'new_dependency_modules': sorted(set(sys.modules)-prepared),
    'complete_domain_changed': False, 'extra_gc_or_expected_normalization': False,
    'public_and_installed_qualification': False,
}
(OUTPUT/'report.json').write_bytes(oracle.canonical(report))
print(json.dumps({key: report[key] for key in ('status', 'runtime', 'original_count', 'repeat_count',
    'actual_count', 'frames', 'entry_events', 'differences', 'exception', 'current_candidate_all_files_unchanged')}))
raise SystemExit(0 if report['status'] == 'DEVELOPMENT_MATCH' else 1)
