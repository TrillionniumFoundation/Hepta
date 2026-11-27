"""Build complete service bootstrap control with exact source custody."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.hia_component_input_custody import capture_component_custody, verify_component_custody
from tools.build_hia_source_build import _check_pack_output
from tools.qualify_hia_selfhost import compile_stage

SOURCE_NAME = 'examples/hia_bootstrap/service_bootstrap.hepta'
INPUTS = ('tools/hia_component_input_custody.py',
    'examples/hia_bootstrap/service_bootstrap.hepta',
    'tools/generate_hia_service_bootstrap.py',
    'tools/build_hia_service_bootstrap.py',
    'tools/qualify_hia_service_bootstrap_callers.py',
    'hepta/hia_service_bootstrap_native.py',
    'hepta/hia_service_bootstrap_protocol.py',
    'hepta/hia_agent_service.py',
    'hepta/hia_agent_store.py',
    'hepta/hia_native_delivery.py',
    'hepta/hia_native_helpers.py',
    'hepta/hia_agent_contract.py',
    'hepta/hia_candidate_budget_native.py',
    'hepta/hia_execution_budget_native.py',
    'hepta/hia_slot_ledger_native.py',
    'hepta/hia_store_lifecycle_native.py',
    'hepta/hia_store_lifecycle_selection.py',
    'hepta/hia_store_artifact_profile_native.py',
    'hepta/hia_emission_native.py',
    'hepta/hia_json_preflight_native.py',
    'hepta/hia_program.py',
    'hepta/hia_program_native.py',
    'hepta/hia_agent_assembly.py',
    'hepta/hia_schema.py',
    'hepta/hia_safe_core.py',
    'hepta/hia_agent_macro_discovery.py',
    'tools/generate_hia_service_context.py',
    'tools/generate_hia_selfhost.py',
    'tests/test_hia_service_bootstrap_sources.py',
    'docs/HIA_SERVICE_BOOTSTRAP_NATIVE.md',
    'tests/fixtures/hia_service_bootstrap_original_r12/__init__.py.txt',
    'tests/fixtures/hia_service_bootstrap_original_r12/close.py.txt',
    'tests/fixtures/hia_service_bootstrap_original_r12/_profiles.py.txt',
    'tests/fixtures/hia_service_bootstrap_original_r12/_profile.py.txt',
    'tests/fixtures/hia_service_bootstrap_original_r12/_program.py.txt',
    'tests/fixtures/hia_service_bootstrap_original_r12/source-identity.json',
    'tests/fixtures/hia_service_bootstrap_original_r12/callers.json',
    'tests/fixtures/hia_service_bootstrap_original_r12/caller-scopes.json',
    'tests/fixtures/hia_service_bootstrap_original_r12/observation-domain.json',
    'tests/hia_service_bootstrap_oracle.py',
    'tests/hia_service_bootstrap_support.py',
    'tests/hia_service_bootstrap_observer.py',
    'tests/hia_bootstrap_compatibility.py',
    'tests/hia_bootstrap_current_dispatch.py',
    'tools/hia_bootstrap_source_history.py',
    'tests/fixtures/hia_bootstrap_current_source_relation_v2.json',
    'hepta/hia_program_tools.py',
    'tools/qualify_hia_service_bootstrap_finite.py',
    'tests/hia_service_bootstrap_controls.py',
    'tests/hia_service_bootstrap_resources.py',
    'tests/hia_service_bootstrap_installed.py',
    'tests/test_hia_service_bootstrap_qualification.py',
    'tests/hia_service_bootstrap_suite.py',
    'tools/qualify_hia_service_bootstrap.py',
    'tools/read_hia_service_bootstrap.py',
    'tools/qualify_hia_service_bootstrap_callers_owned.py',
    'tests/hia_slot_operations_qualification_support.py',
    'tests/test_hia_agent_installed_resources.py',
    'tests/test_hia_native_byte_abi.py',
    'tools/build_hia_store_artifact_profile.py',
    'tools/build_hia_store_transaction.py',
    'tools/build_hia_service_context.py',
    'tools/build_hia_candidate_budget.py',
    'tools/build_hia_slot_ledger.py',
    'tools/build_hia_source_build.py',
    'tools/build_hia_json_preflight.py',
    'tools/qualify_hia_selfhost.py',
    'tools/hia_selfhost_contract.py',
    'tools/run_hia_unittest_gate.py',
    'hepta/hia_agent_worker.py',
    'hepta/hia_service_context_native.py',
    'hepta/hia_store_transaction_native.py',
    'examples/hia_bootstrap/store_artifact_profile.hepta',
    'examples/hia_bootstrap/store_transaction.hepta',
    'examples/hia_bootstrap/service_context.hepta',
    'examples/hia_bootstrap/candidate_budget.hepta',
    'examples/hia_bootstrap/slot_ledger.hepta',
    'hepta/hia_budget_resource_custody.py',
    'hepta/hia_slot_operation_series.py',
    'hepta/hia_slot_operations_native.py',
    'hepta/hia_slot_operations_protocol.py',
    'hepta/hia_slot_operations_selection.py',
    'tools/build_hia_slot_operations.py',
    'examples/hia_bootstrap/slot_operations.hepta',
    'tests/test_hia_candidate_budget_native.py',
    'tests/test_hia_execution_budget_native.py',
    'tests/hia_budget_resource_retirement_controls.py',
    'tests/hia_budget_resource_retirement_installed.py',
    'tests/test_hia_budget_resource_retirement.py',
    'tests/hia_budget_resource_retirement_suite.py',
    'tools/qualify_hia_budget_resource_retirement.py',
    'tools/read_hia_budget_resource_retirement.py',
    'tests/test_hia_service_bootstrap_fixed_words.py',
    # Exact Journal preparation source admission and independent readback controls.
    'tests/hia_journal_installed_preparation.py',
    'tests/fixtures/journal_installed_preparation_v2.json',
    'tests/fixtures/journal_installed_preparation_v1.py.txt',
    'tests/test_hia_service_bootstrap_journal_preparation.py',
)


def build(output, compiler, cold_report=None, *, development=False):
    if type(development) is not bool or development == (cold_report is not None):
        raise ValueError('choose exactly one matching cold report or explicit development mode')
    output, compiler = Path(output), Path(compiler)
    compiler_bytes = compiler.read_bytes()
    captured = {name: (ROOT / name).read_bytes() for name in INPUTS}
    cold_bytes = None if development else Path(cold_report).read_bytes()
    sources = None if development else admit_cold_build(compiler_bytes, cold_bytes)
    cold_inputs, custody, development_inputs = None, None, {}
    if sources is not None:
        from tools.hia_native_cold_admission import SCHEMA, read_json
        if read_json(cold_bytes).get('schema') == SCHEMA:
            from tools.hia_cold_compiler import NATIVE_CUSTODY_INPUTS, read_cold_build_inputs
            cold_inputs = read_cold_build_inputs(cold_report)
            if cold_inputs.compiler_bytes != compiler_bytes or cold_inputs.sources != sources:
                raise ValueError('component compiler or source differs from the admitted cold inputs')
            development_inputs = {name: (ROOT / name).read_bytes() for name in NATIVE_CUSTODY_INPUTS}
            custody = cold_inputs.capture_custody({**captured, **development_inputs}, root=ROOT)
        else:
            custody = capture_component_custody(
                compiler_bytes, cold_bytes, sources, captured, root=ROOT)
    output.mkdir(mode=0o700)
    source = captured[SOURCE_NAME]
    image, receipt = compile_stage(output, 'service_bootstrap', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'service_bootstrap.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('service bootstrap construction inputs or output changed')
    if not development:
        verify_component_custody(custody, compiler_bytes, cold_bytes, sources,
                                 {**captured, **development_inputs}, root=ROOT)
    if cold_inputs is not None:
        cold_inputs.unchanged()
    manifest = {'schema': 'hepta.hia.service-bootstrap.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    report = {
        'schema': 'hepta.hia.service-bootstrap-build.v1',
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'authored_owner': 'complete HIAAgentService.__init__/close/_profiles/_profile/_program control candidate',
        'selected_public_route_invokes_retained_handler': False,
        'unselected_retained_original_still_present': True,
        'opaque_object_and_provider_protocols_hosted': True,
        'original_catalog_schema_Store_budget_ledger_OS_SQL_providers_hosted': True,
        'segmented_generator_ABI_qualified': False,
        'independent_budget_connection_resource_boundary_qualified': False,
        'resource_custody_policy': 'independent per-port and whole-method weak registered-resource facts; terminal FINALIZE ACK',
        'resource_qualification_established_by_build': False,
        'complete_input_equivalence_established_by_build': False,
        'new_replay_retry_or_production_deadline': False,
        'all_python_versions_tested': False,
        'whole_native_stack_qualified': False,
    }
    if custody is not None:
        report['component_input_custody'] = custody
        report['development_inputs'] = {name: sha256(raw).hexdigest() for name, raw in development_inputs.items()}
    (output / 'build.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return output / 'manifest.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development', action='store_true')
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, development=args.development))


if __name__ == '__main__':
    main()
