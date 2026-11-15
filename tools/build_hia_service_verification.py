"""Build complete service verification control with exact source custody."""
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

SOURCE_NAME = 'examples/hia_bootstrap/service_verification.hepta'
INPUTS = (
    "examples/hia_bootstrap/service_verification.hepta",
    "tools/generate_hia_service_verification.py",
    "tools/hia_service_verification_graph.py",
    "tools/build_hia_service_verification.py",
    "tools/qualify_hia_service_verification_finite.py",
    "tools/read_hia_service_verification_finite.py",
    "tools/qualify_hia_service_verification_callers.py",
    "hepta/hia_service_verification_native.py",
    "hepta/hia_service_verification_protocol.py",
    "hepta/hia_native_delivery.py",
    "hepta/hia_agent_service.py",
    "hepta/hia_agent_store.py",
    "hepta/hia_store_lifecycle_selection.py",
    "hepta/hia_store_lifecycle_native.py",
    "hepta/hia_store_artifact_profile_native.py",
    "hepta/artifact_publication_native.py",
    "hepta/hia_native_helpers.py",
    "hepta/hia_agent_contract.py",
    "hepta/hia_emission_native.py",
    "hepta/hia_json_preflight_native.py",
    "hepta/hia_service_lease_native.py",
    "hepta/hia_service_lease_protocol.py",
    "hepta/hia_opcodes.py",
    "hepta/hia_agent_assembly.py",
    "hepta/hia_program.py",
    "hepta/hia_program_runtime.py",
    "hepta/hia_program_runtime_prepared.py",
    "hepta/hia_optimization.py",
    "hepta/hia_optimization_contract.py",
    "hepta/hia_machine_plan.py",
    "hepta/hia_program_native.py",
    "hepta/hia_safe_core.py",
    "hepta/hia_safe_core_elf.py",
    "hepta/hia_safe_core_x64.py",
    "tools/generate_hia_service_context.py",
    "tools/generate_hia_selfhost.py",
    "tests/test_hia_service_verification_native.py",
    "tests/test_hia_service_verification_imports.py",
    "tests/hia_service_verification_oracle.py",
    "tests/hia_service_verification_observer.py",
    "tests/hia_service_verification_controls.py",
    "tests/hia_service_verification_lazy.py",
    "tests/hia_service_verification_cells.py",
    "tests/hia_service_verification_installed.py",
    "tests/fixtures/hia_emission_original_73f1634/original-freeze.json",
    "docs/HIA_SERVICE_VERIFICATION_NATIVE.md",
    "tests/fixtures/hia_service_verification_original_r12/_behavior_equivalence.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/_subject.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/_hia_verify.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/_verification.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/_replay_verification.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/_native_refinement_binding.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/_independent_native_refinement.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/_check_native_refinement_evidence.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/_required_claims.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/AgentRejected.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/reject.py.txt",
    "tests/fixtures/hia_service_verification_original_r12/cases.json",
    "tests/fixtures/hia_service_verification_original_r12/source-identity.json",
    "tests/fixtures/hia_service_verification_original_r12/caller-scopes.json",
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
        raise ValueError('service verification inputs are not bound by current cold source')
    output.mkdir(mode=0o700)
    source = captured[SOURCE_NAME]
    image, receipt = compile_stage(output, 'service_verification', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'service_verification.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('service verification construction inputs or output changed')
    manifest = {'schema': 'hepta.hia.service-verification.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    report = {
        'schema': 'hepta.hia.service-verification-build.v1',
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'authored_owner': 'nine complete Service proof workflows, twelve eager private bodies and five lazy generator modes',
        'selected_public_route_invokes_retained_handler': False,
        'unselected_retained_original_still_present': True,
        'opaque_object_and_provider_protocols_hosted': True,
        'Core_solver_emission_Store_object_and_OS_providers_still_hosted': True,
        'resource_custody_policy': 'per-port and method-or-generator-segment weak registered facts; FINALIZE before retirement or PAUSED; fresh record on every actual resume',
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
