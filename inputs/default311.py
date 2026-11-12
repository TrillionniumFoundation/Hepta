"""Observe actual default 3.11 behavior and its exact unsupported-ABI refusal."""
from __future__ import annotations
import base64
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback
import zlib


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')


def check(source, packet_path, output, report):
    if sys.version_info[:2] != (3, 11):
        raise ValueError('an actual Python 3.11 interpreter is required')
    sys.path.insert(0, str(source))
    from hepta import hia_agent_service as api
    from hepta import hia_service_artifacts_native as native
    from hepta import hia_machine_plan_control_native as control
    from hepta.hia_exception_delivery import ExceptionDeliveryUnavailable
    watched = ('hepta.hia_service_artifacts_foreign', 'hepta.hia_native_build_foreign',
               'hepta.hia_native_byte_abi_foreign', 'hepta.hia_proof_contract_foreign',
               'hepta.hia_service_verification_foreign', 'hepta.hia_service_requests_foreign')
    imported = [name for name in watched if name in sys.modules]
    before = native._mapped_artifacts.cache_info()._asdict()
    report.update(default_imported_native_ports=imported, default_mapping_cache=before)
    if imported or before['currsize']:
        raise ValueError('default import entered fixed native ABI ports or mapping')
    value = api.HIAAgentService._examples()
    if value['schema'] != 'hepta.hia.agent.examples.v1' or any(name in sys.modules for name in watched):
        raise ValueError('default static example entered fixed native ABI ports')
    report['default_example_schema'] = value['schema']
    packet = json.loads(packet_path.read_bytes())
    image = zlib.decompress(base64.b64decode(packet['zlib_base64'], validate=True))
    if len(image) != packet['bytes'] or sha256(image).hexdigest() != packet['sha256']:
        raise ValueError('exact retained development image differs')
    name = 'original-development.image.bin'
    (output/name).write_bytes(image)
    manifest = {'schema': native.SCHEMA, 'source_sha256': sha256(native.SOURCE.read_bytes()).hexdigest(),
                'image_path': name, 'image_sha256': packet['sha256'],
                'compiler_sha256': packet['compiler_sha256']}
    path = output/'unsupported-development-manifest.json'
    save(path, manifest)
    observed = {'initializers': 0, 'actual_machine_entries': 0, 'business_effects': []}
    original_initialize = control.NativeMachinePlanControl._initialize_control
    original_effect = native.ArtifactsFrame._effect

    def initialize(self):
        observed['initializers'] += 1
        original_entry = self._entry

        def entry(*arguments):
            observed['actual_machine_entries'] += 1
            return original_entry(*arguments)

        self._entry = entry
        try:
            return original_initialize(self)
        finally:
            self._entry = original_entry

    def effect(self):
        observed['business_effects'].append('business-effect')
        raise AssertionError('unsupported ABI entered business effects')

    control.NativeMachinePlanControl._initialize_control = initialize
    native.ArtifactsFrame._effect = effect
    caught_error = None
    try:
        native.installed_artifacts(path)
    except BaseException as caught:
        caught_error = caught
        report['selected_native_refusal'] = {'type': type(caught).__name__,
            'module': type(caught).__module__, 'message': str(caught),
            'traceback': traceback.format_exc()}
    finally:
        control.NativeMachinePlanControl._initialize_control = original_initialize
        native.ArtifactsFrame._effect = original_effect
        report.update(selection_observations=observed,
                      mapping_cache_after=native._mapped_artifacts.cache_info()._asdict())
        # Persist the actual error before asserting it, including failed cases.
        save(output/'ATTEMPT.json', report)
    expected = 'native frame transport requires a reviewed CPython 3.12, 3.13 or 3.14 ABI'
    if (type(caught_error) is not ExceptionDeliveryUnavailable or str(caught_error) != expected
            or observed != {'initializers': 1, 'actual_machine_entries': 0, 'business_effects': []}
            or native._mapped_artifacts.cache_info().currsize != 0):
        raise AssertionError('unsupported ABI did not refuse before real machine entry and effects')
    report.update(status='PASS', selected_abi_supported=False,
                  failed_admission_cached=False, default_import_native_ports=False)


def main():
    source, packet, output = (Path(p).resolve() for p in sys.argv[1:])
    output.mkdir(exist_ok=False)
    report = {'status': 'STARTED', 'python': sys.version,
        'scope': 'ACTUAL_311_DEFAULT_AND_UNSUPPORTED_SELECTION_ONLY',
        'current_source_cold': False, 'whole_native': False}
    try:
        check(source, packet, output, report)
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        save(output/'REPORT.json', report)
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
