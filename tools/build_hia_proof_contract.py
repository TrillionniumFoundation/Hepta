"""Build the complete eight-function proof-contract owner with strict complete-source cold custody.

The separate build_development entry consumes an explicitly supplied compiler
and records no cold authority. Neither entry activates a service or replaces
the independent solver/checker engines, compiler, artifact publisher or SQLite journal.
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

SOURCE_NAME = 'examples/hia_bootstrap/proof_contract.hepta'
SCHEMA = 'hepta.hia.proof-contract-native.v1'
LABEL = 'proof-contract'
REQUIRED_SOURCE_NAMES = (
    'examples/hia_bootstrap/proof_contract.hepta',
    'hepta/hia_proof_contract_native.py',
    'hepta/hia_proof_contract_foreign.py',
    'hepta/hia_proof_contract_selection.py',
    'hepta/hia_proof_contract.py',
    'hepta/hia_agent_service.py',
    'hepta/hia_agent_contract.py',
    'hepta/hia_checker_identity.py',
    'hepta/hia_native_helpers.py',
    'hepta/hia_exception_delivery.py',
    'hepta/hia_machine_plan_control_native.py',
    'tools/hia_exception_delivery.py',
    'tools/hia_machine_plan_control.py',
    'tools/generate_hia_machine_plan_control.py',
    'tools/hia_core_lowering_table.py',
    'tools/hia_service_verification_control.py',
    'tools/hia_proof_contract_policy.py',
    'tools/hia_proof_contract_control.py',
    'tools/generate_hia_proof_contract.py',
    'tools/build_hia_proof_contract.py',
    'tools/qualify_hia_proof_contract.py',
    'tests/test_hia_proof_contract_native.py',
    'tests/test_hia_proof_contract_builder.py',
    'tests/test_hia_proof_contract_qualifier.py',
    'tests/hia_proof_contract_fixtures.py',
    'tests/fixtures/hia_proof_contract_original_v78.py.txt',
    'docs/HIA_PROOF_CONTRACT_NATIVE.md',
    'tests/test_hia_checker_identity.py',
    'tests/test_hia_checker_identity_agent.py',
    'tests/test_hia_agent_native_tools.py',
    'tests/test_hia_agent_native_proof_contract.py',
    'tests/test_hia_agent_native_machine_validation.py',
    'tools/hia_agent_native_qualification.py',
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
            raise ValueError('duplicate proof-contract build receipt field')
        result[key] = value
    return result


def _publish(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
    if path.read_bytes() != raw:
        raise ValueError('proof-contract publication readback differs: ' + path.name)


def _build(output, compiler, compiler_bytes, component, consumed, recheck,
           *, scope, cold_bytes=None, sources=None):
    source_bytes = component[SOURCE_NAME]
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, LABEL, compiler, source_bytes)
    image = Path(image)
    if image.parent != output or image.name != LABEL + '.image.bin':
        raise ValueError('proof-contract compiler published an unexpected image path')
    image_bytes = image.read_bytes()
    admit_compile_receipt(receipt, compiler_bytes=compiler_bytes,
                          source_bytes=source_bytes, image_bytes=image_bytes)
    if receipt.get('case') != LABEL or receipt.get('produced_image') != str(image):
        raise ValueError('proof-contract receipt names a different invocation or image')
    receipt_path = output / (LABEL + '.receipt.json')
    receipt_bytes = receipt_path.read_bytes()
    recorded = json.loads(receipt_bytes, object_pairs_hook=_pairs)
    admit_compile_receipt(recorded, compiler_bytes=compiler_bytes,
                          source_bytes=source_bytes, image_bytes=image_bytes)
    if _encoded(recorded) != _encoded(receipt):
        raise ValueError('proof-contract compile receipt readback differs')
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
    report = {'schema': 'hepta.hia.proof-contract-build.v1',
              'status': 'NATIVE_CANDIDATE_BUILT', 'scope': scope,
              'manifest': manifest, 'native_compile_receipt': receipt,
              'native_compile_receipt_sha256': _digest(receipt_bytes),
              'component_sources': {name: _digest(component[name]) for name in REQUIRED_SOURCE_NAMES},
              'source_manifest': sources,
              'cold_report_sha256': None if cold_bytes is None else _digest(cold_bytes),
              'eight_proof_functions_and_eight_lazy_frames_in_hia': True,
              'original_subject_checker_assumptions_and_obligation_order_preserved': True,
              'independent_solver_checker_identity_and_storage_providers_remain_dependencies': True,
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
        raise ValueError('proof-contract cold report changed the original 180+3 limits')
    component = {name: (ROOT / name).read_bytes() for name in REQUIRED_SOURCE_NAMES}
    if any(sources.get(name) != _digest(raw) for name, raw in component.items()):
        raise ValueError('proof-contract inputs are outside the complete matching cold source contract')
    consumed = {compiler: compiler_bytes, cold_report: cold_bytes,
                **{ROOT / name: raw for name, raw in component.items()}}

    def recheck():
        if (any(path.read_bytes() != raw for path, raw in consumed.items())
                or current_sources() != sources):
            raise ValueError('proof-contract build inputs, receipts or published bytes changed')

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
            raise ValueError('proof-contract development input or output bytes changed')

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
