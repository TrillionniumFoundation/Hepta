"""Build the requests owner with strict complete-source cold custody.

The separate build_development entry consumes an explicitly supplied compiler
and records no cold authority. Neither entry activates a service or replaces
the existing proof engines, proof contract, compiler, artifact publisher or SQLite journal.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_core_json_bytes import admit_compile_receipt
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage

SOURCE_NAME = 'examples/hia_bootstrap/service_requests.hiaasm'
SCHEMA = 'hepta.hia.service-requests-native.v1'
LABEL = 'service-requests'
REQUIRED_SOURCE_NAMES = (
    'MANIFEST.in',
    'setup.py',
    'tests/test_hia_joint_owner_integration.py',
    'examples/hia_bootstrap/service_requests.hiaasm',
    'hepta/hia_service_requests_native.py',
    'hepta/hia_service_requests_foreign.py',
    'tools/hia_service_requests_policy.py',
    'tools/hia_service_requests_control.py',
    'tools/generate_hia_service_requests.py',
    'tools/generate_hia_service_requests_foreign.py',
    'tools/build_hia_service_requests.py',
    'tools/qualify_hia_service_requests.py',
    'tests/test_hia_service_requests_native.py',
    'tests/test_hia_service_requests_builder.py',
    'tests/test_hia_service_requests_qualifier.py',
    'tests/hia_service_requests_fixtures.py',
    'tests/hia_native_name_resolution.py',
    'tests/fixtures/hia_service_requests_original_v81.json',
    'docs/HIA_SERVICE_REQUESTS_NATIVE.md',
    'hepta/hia_agent_service.py',
    'hepta/hia_agent_store.py',
    'hepta/hia_agent_contract.py',
    'hepta/hia_checker_identity.py',
    'hepta/hia_proof_contract.py',
    'hepta/hia_proof_contract_selection.py',
    'hepta/hia_native_helpers.py',
    'hepta/hia_exception_delivery.py',
    'hepta/hia_machine_plan_control_native.py',
    'hepta/hia_machine_transport.py',
    'tools/hia_exception_delivery.py',
    'tools/hia_machine_plan_control.py',
    'tools/generate_hia_machine_plan_control.py',
    'tools/hia_core_lowering_table.py',
    'tools/hia_core_lowering_control.py',
    'tools/generate_hia_core_lowering.py',
    'tools/hia_native_build_control.py',
    'tools/generate_hia_native_build_foreign.py',
    'tests/test_hia_checker_identity.py',
    'tests/test_hia_checker_identity_agent.py',
    'tests/test_hia_agent_native_tools.py',
    'tests/test_hia_agent_native_campaign.py',
    'tests/test_hia_agent_buffer_lifecycle.py',
    'tests/test_hia_agent_native_lease_snapshot.py',
    'tests/test_hia_artifact_namespace_native.py',
    'tests/test_hia_slot_ledger_native.py',
)


DEVELOPMENT_INPUT_NAMES = REQUIRED_SOURCE_NAMES + (
    'hepta/hia_json_preflight_native.py',
    'hepta/hia_agent_assembly.py',
    'tools/build_hia_core_json_bytes.py',
    'tools/build_hia_json_preflight.py',
    'tools/qualify_hia_selfhost.py',
    'tools/hia_selfhost_contract.py',
    'tools/generate_hia_selfhost.py',
)


def _digest(raw):
    return sha256(raw).hexdigest()


def _encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate service-requests build receipt field')
        result[key] = value
    return result


def _publish(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
    if path.read_bytes() != raw:
        raise ValueError('service-requests publication readback differs: ' + path.name)


def _build(output, compiler, compiler_bytes, component, consumed, recheck,
           *, scope, cold_bytes=None, sources=None):
    source_bytes = component[SOURCE_NAME]
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, LABEL, compiler, source_bytes)
    image = Path(image)
    if image.parent != output or image.name != LABEL + '.image.bin':
        raise ValueError('service-requests compiler published an unexpected image path')
    image_bytes = image.read_bytes()
    admit_compile_receipt(receipt, compiler_bytes=compiler_bytes,
                          source_bytes=source_bytes, image_bytes=image_bytes)
    if receipt.get('case') != LABEL or receipt.get('produced_image') != str(image):
        raise ValueError('service-requests receipt names a different invocation or image')
    receipt_path = output / (LABEL + '.receipt.json')
    receipt_bytes = receipt_path.read_bytes()
    recorded = json.loads(receipt_bytes, object_pairs_hook=_pairs)
    admit_compile_receipt(recorded, compiler_bytes=compiler_bytes,
                          source_bytes=source_bytes, image_bytes=image_bytes)
    if _encoded(recorded) != _encoded(receipt):
        raise ValueError('service-requests compile receipt readback differs')
    consumed[image], consumed[receipt_path] = image_bytes, receipt_bytes
    recheck()
    manifest = {'schema': SCHEMA, 'source_sha256': _digest(source_bytes),
                'image_path': image.name, 'image_sha256': _digest(image_bytes),
                'compiler_sha256': _digest(compiler_bytes)}
    path = output / ('manifest.json' if cold_bytes is not None else 'development-manifest.json')
    manifest_bytes = _encoded(manifest)
    _publish(path, manifest_bytes)
    consumed[path] = manifest_bytes
    recheck()
    report = {'schema': 'hepta.hia.service-requests-build.v1',
              'status': 'NATIVE_CANDIDATE_BUILT', 'scope': scope,
              'manifest': manifest, 'native_compile_receipt': receipt,
              'native_compile_receipt_sha256': _digest(receipt_bytes),
              'component_sources': {name: _digest(component[name]) for name in REQUIRED_SOURCE_NAMES},
              'source_manifest': sources,
              'cold_report_sha256': None if cold_bytes is None else _digest(cold_bytes),
              'eight_original_requests_and_their_with_and_generator_regions_in_hia': True,
              'original_discovery_page_inspection_candidate_and_effect_order_preserved': True,
              'storage_sql_codec_core_assembly_edit_proof_and_compiler_providers_remain_dependencies': True,
              'cpython_call_mapping_object_and_generator_mechanisms_hosted': True,
              'foreign_numeric_protocols_hosted': True,
              'cpython_exception_delivery_api_hosted': True,
              'production_activated': False, 'default_changed': False,
              'all_input_equivalence_proved': False, 'whole_stack_rewritten_in_hia': False,
              'original_compiler_child_timeout_seconds': 20}
    if cold_bytes is None:
        report['development_input_manifest'] = {name: _digest(component[name]) for name in DEVELOPMENT_INPUT_NAMES}
    else:
        from tools.hia_selfhost_contract import PROFILE
        report['profile'] = PROFILE
    report_path = output / ('build.json' if cold_bytes is not None else 'development-build.json')
    report_bytes = _encoded(report)
    _publish(report_path, report_bytes)
    consumed[report_path] = report_bytes
    recheck()
    return path


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    """Production admission; never fall back to a development compiler."""
    output, compiler, cold_report = (Path(path).resolve() for path in (output, compiler, cold_report))
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    cold = json.loads(cold_bytes, object_pairs_hook=_pairs)
    if (type(cold.get('qualification_wall_limit_seconds')) is not int
            or cold['qualification_wall_limit_seconds'] != 180
            or type(cold.get('cleanup_wall_limit_seconds')) is not int
            or cold['cleanup_wall_limit_seconds'] != 3):
        raise ValueError('service-requests cold report changed the original 180+3 limits')
    component = {name: (ROOT / name).read_bytes() for name in REQUIRED_SOURCE_NAMES}
    if any(sources.get(name) != _digest(raw) for name, raw in component.items()):
        raise ValueError('service-requests inputs are outside the complete matching cold source contract')
    consumed = {compiler: compiler_bytes, cold_report: cold_bytes,
                **{ROOT / name: raw for name, raw in component.items()}}

    def recheck():
        if (any(path.read_bytes() != raw for path, raw in consumed.items())
                or current_sources() != sources):
            raise ValueError('service-requests build inputs, receipts or published bytes changed')

    recheck()
    return _build(output, compiler, compiler_bytes, component, consumed, recheck,
                  scope='MATCHING_SOURCE_COLD', cold_bytes=cold_bytes, sources=sources)


def build_development(output: Path, compiler: Path) -> Path:
    """Explicit component development; no cold-source qualification is inferred."""
    output, compiler = (Path(path).resolve() for path in (output, compiler))
    compiler_bytes = compiler.read_bytes()
    component = {name: (ROOT / name).read_bytes() for name in DEVELOPMENT_INPUT_NAMES}
    consumed = {compiler: compiler_bytes, **{ROOT / name: raw for name, raw in component.items()}}

    def recheck():
        if any(path.read_bytes() != raw for path, raw in consumed.items()):
            raise ValueError('service-requests development input or output bytes changed')

    recheck()
    return _build(output, compiler, compiler_bytes, component, consumed, recheck,
                  scope='EXPLICIT_COMPILER_DEVELOPMENT_COMPONENT')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development', action='store_true')
    args = parser.parse_args()
    path = (build_development(args.output, args.compiler) if args.development
            else build(args.output, args.compiler, args.cold_report))
    print(json.dumps({'status': 'NATIVE_CANDIDATE_BUILT', 'manifest': str(path),
                      'scope': 'DEVELOPMENT' if args.development else 'MATCHING_SOURCE_COLD'}))


if __name__ == '__main__':
    main()
