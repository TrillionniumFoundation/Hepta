"""Build complete Slot operations control with exact source custody."""
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
from tools.build_hia_source_build import _check_pack_output
from tools.qualify_hia_selfhost import compile_stage

SOURCE_NAME = 'examples/hia_bootstrap/slot_operations.hepta'
INPUTS = (
    'examples/hia_bootstrap/slot_operations.hepta',
    'tools/generate_hia_slot_operations.py',
    'tools/build_hia_slot_operations.py',
    'tools/qualify_hia_slot_operations_callers.py',
    'hepta/hia_slot_operations_native.py',
    'hepta/hia_slot_operations_protocol.py',
    'hepta/hia_slot_operation_series.py',
    'hepta/hia_slot_operations_selection.py',
    'hepta/hia_slot_ledger_native.py',
    'hepta/hia_native_delivery.py',
    'hepta/hia_native_helpers.py',
    'hepta/hia_native_host_support.py',
    'hepta/hia_json_preflight_native.py',
    'hepta/hia_store_lifecycle_native.py',
    'hepta/hia_emission_native.py',
    'tools/generate_hia_service_context.py',
    'tools/generate_hia_selfhost.py',
    'tools/build_hia_slot_ledger.py',
    'tests/test_hia_slot_ledger_native.py',
    'tests/hia_slot_operations_resource_controls.py',
    'tests/test_hia_slot_operation_series_native.py',
    'tests/hia_slot_operations_component_fixture.py',
    'tests/hia_slot_operations_installed_observer.py',
    'hepta/hia_agent_worker.py',
    'tests/hia_slot_worker_terminal.py',
    'tools/read_hia_slot_worker_terminal.py',
    'tools/read_hia_slot_definition_lifetime.py',
    'tests/test_hia_slot_worker_terminal.py',
    'tests/fixtures/slot_worker_terminal_v2.json',
    'tests/fixtures/worker_unknown_original_r17b/hia_agent_worker.py.txt',
    'tests/hia_slot_operations_observer.py',
    'tests/hia_slot_operations_public_observer.py',
    'tests/hia_slot_operations_qualification_support.py',
    'tests/hia_slot_operations_transport_controls.py',
    'tests/test_hia_slot_operations_native.py',
    'tools/qualify_hia_slot_operations_observations.py',
    'tools/read_hia_slot_operations_observations.py',
    'tests/fixtures/hia_slot_operations_derived_r1/basis.json',
    'tests/fixtures/hia_slot_operations_derived_r1/inputs.json',
    'tests/fixtures/hia_slot_operations_original_r1/DESIGN.md',
    'tests/fixtures/hia_slot_operations_original_r1/README.md',
    'tests/fixtures/hia_slot_operations_original_r1/caller-plan.json',
    'tests/fixtures/hia_slot_operations_original_r1/cases.json',
    'tests/fixtures/hia_slot_operations_original_r1/draft-history/pre-external-freeze-pin/README.md.txt',
    'tests/fixtures/hia_slot_operations_original_r1/draft-history/pre-external-freeze-pin/observe_originals.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/draft-history/pre-external-freeze-pin/run_originals_twice.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/method-inventory.json',
    'tests/fixtures/hia_slot_operations_original_r1/observe_originals.py',
    'tests/fixtures/hia_slot_operations_original_r1/originals/NativeSlotLedgerStore.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/originals/_SelectedRendererFailure.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/originals/_claimed_artifact_wire.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/originals/_custody.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/originals/_decimal.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/originals/_raise.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/originals/_text.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/originals/_untext.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/originals/hepta/hia_agent_store.py',
    'tests/fixtures/hia_slot_operations_original_r1/originals/hepta/hia_slot_ledger_native.py',
    'tests/fixtures/hia_slot_operations_original_r1/originals/request_packet.py.txt',
    'tests/fixtures/hia_slot_operations_original_r1/originals/tests/test_hia_slot_ledger_native.py',
    'tests/fixtures/hia_slot_operations_original_r1/originals/tools/build_hia_slot_ledger.py',
    'tests/fixtures/hia_slot_operations_original_r1/port-map.json',
    'tests/fixtures/hia_slot_operations_original_r1/recovered-design/CALLER-GATES.json',
    'tests/fixtures/hia_slot_operations_original_r1/recovered-design/CONTROL-PLAN.json',
    'tests/fixtures/hia_slot_operations_original_r1/recovered-design/DESIGN.md',
    'tests/fixtures/hia_slot_operations_original_r1/recovered-design/HANDOFF.json',
    'tests/fixtures/hia_slot_operations_original_r1/recovered-design/RESOURCE-API-PROPOSAL.md',
    'tests/fixtures/hia_slot_operations_original_r1/recovered-design/SOURCE-FREEZE.json',
    'tests/fixtures/hia_slot_operations_original_r1/recovered-design/call-order.json',
    'tests/fixtures/hia_slot_operations_original_r1/recovered-design/public-caller-map.json',
    'tests/fixtures/hia_slot_operations_original_r1/resource-controls.json',
    'tests/fixtures/hia_slot_operations_original_r1/run_originals_twice.py',
    'tests/fixtures/hia_slot_operations_original_r1/source-freeze.json',
    'tests/fixtures/hia_slot_operations_original_r1/source-identity.json',
    'tests/fixtures/hia_slot_operations_original_r1/sql-sites.json',
    'tests/fixtures/hia_slot_operations_original_r1/static_check.py',
    'tests/fixtures/hia_slot_operations_qualification/handled-traceback-inputs.json',
    'tests/fixtures/hia_slot_operations_qualification/public-inputs.json',
    'hepta/hia_program_runtime_prepared.py',
    'hepta/hia_program_runtime.py',
    'hepta/hia_program.py',
    'hepta/hia_json_decode.py',
    'hepta/hia_agent_assembly.py',
    'hepta/hia_schema.py',
    'hepta/hia_bounded_memory.py',
    'hepta/hia_opcodes.py',
    'tests/test_hia_program_runtime_prepared.py',
    'tests/test_hia_program.py',
    'hepta/hia_program_runtime_arithmetic.py',
    'tests/test_hia_program_runtime_arithmetic.py',
    'MANIFEST.in',
    'docs/HIA_SLOT_MECHANICAL_BOUNDARY.md',
    'docs/HIA_SLOT_MECHANICAL_V5.md',
    'hepta/hia_mechanical_worker_bundle.py',
    'hepta/hia_slot_continuations.py',
    'hepta/hia_slot_mechanical.py',
    'hepta/native/slot_mechanical.c',
    'hepta/native/slot_mechanical_build.py',
    'pyproject.toml',
    'setup.py',
    'tests/hia_slot_mechanical_admission_controls.py',
    'tests/hia_slot_mechanical_capsule_observer.py',
    'tests/hia_slot_mechanical_installed_probe.py',
    'tests/hia_slot_mechanical_worker_probe.py',
    'tests/test_hia_slot_mechanical_native.py',
    'tools/build_hia_slot_mechanical.py',
    'tools/build_hia_slot_mechanical_bundle.py',
    'tools/qualify_hia_slot_mechanical_admission.py',
    'tools/qualify_hia_slot_mechanical_installed.py',
    'tools/qualify_hia_slot_mechanical_observations.py',
    'tools/qualify_hia_slot_mechanical_public.py',
    'tools/read_hia_slot_mechanical_admission.py',
    'tools/read_hia_slot_mechanical_installed.py',
    'tools/read_hia_slot_mechanical_observations.py',
    'docs/HIA_SLOT_MECHANICAL_DUAL_ROUTE.md',
    'tests/fixtures/slot_mechanical_dual_route_originals.json',
    'tests/fixtures/slot_mechanical_dual_route_cases.json',
    'tests/hia_slot_mechanical_route_controls.py',
    'tests/test_hia_slot_mechanical_routes.py',
    'tools/read_hia_slot_mechanical_routes.py',
)


def build(output, compiler, cold_report=None, *, development=False):
    if type(development) is not bool or development == (cold_report is not None):
        raise ValueError('choose exactly one matching cold report or explicit development mode')
    output, compiler = Path(output), Path(compiler)
    compiler_bytes = compiler.read_bytes()
    captured = {name: (ROOT / name).read_bytes() for name in INPUTS}
    cold_bytes = None if development else Path(cold_report).read_bytes()
    sources = None if development else admit_cold_build(compiler_bytes, cold_bytes)
    if sources is not None and any(sources.get(name) != sha256(raw).hexdigest()
                                   for name, raw in captured.items()):
        raise ValueError('Slot operations inputs are not bound by current cold source')
    output.mkdir(mode=0o700)
    source = captured[SOURCE_NAME]
    image, receipt = compile_stage(output, 'slot_operations', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'slot_operations.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('Slot operations construction inputs or output changed')
    manifest = {'schema': 'hepta.hia.slot-operations.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    report = {
        'schema': 'hepta.hia.slot-operations-build.v1',
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'authored_owner': 'complete NativeSlotLedgerStore control: all fifteen original methods',
        'selected_public_route_invokes_retained_15_methods': False,
        'unselected_retained_original_still_present': True,
        'opaque_object_and_provider_protocols_hosted': True,
        'existing_slot_decision_image_required': True,
        'complete_original_SQLite_and_provider_effects_hosted': True,
        'new_implementation_static_only_until_full_gates': True,
        'path_capture_filesystem_and_sqlite_native': False,
        'resource_custody_policy': 'actual SQL argument handoff; independent growable operation series; explicit final HIA receipt',
        'resource_qualification_established_by_build': False,
        'complete_input_equivalence_established_by_build': False,
        'new_replay_retry_or_production_deadline': False,
        'all_python_versions_tested': False,
        'whole_native_stack_qualified': False,
    }
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
