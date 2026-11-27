"""Build complete file-capture HIA control with exact current cold custody."""
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
SOURCE_NAME = 'examples/hia_bootstrap/store_file_capture.hepta'
ORIGINAL_DIRECTORY = 'tests/fixtures/hia_store_file_capture_original_65630/'
INPUTS = (
    'hepta/hia_native_admission_io.py',
    'tests/test_hia_native_admission_io.py',
    'tests/hia_native_admission_io_controls.py',
    'tools/read_hia_native_admission_io.py',
    'tests/fixtures/hia_native_admission_io/regular_bytes.py.txt',
    'tests/fixtures/hia_native_admission_io/source_resource_path.py.txt',
    'tests/fixtures/hia_native_admission_io/source-identity.json',
    'docs/HIA_NATIVE_ADMISSION_IO.md',
    SOURCE_NAME, 'tools/generate_hia_store_file_capture.py', 'tools/build_hia_store_file_capture.py',
    'hepta/hia_store_file_capture_native.py', 'hepta/hia_store_file_capture_protocol.py',
    'hepta/hia_agent_store.py', 'hepta/hia_agent_service.py', 'hepta/hia_agent_runner.py',
    'hepta/hia_native_delivery.py', 'hepta/hia_native_helpers.py', 'hepta/hia_emission_native.py',
    'hepta/hia_json_preflight_native.py', 'hepta/hia_store_lifecycle_native.py',
    'hepta/hia_store_artifact_profile_native.py', 'hepta/hia_service_artifact_native.py',
    'hepta/hia_agent_assembly.py', 'hepta/hia_program.py',
    'hepta/hia_program_runtime.py', 'hepta/hia_program_runtime_prepared.py',
    'tools/generate_hia_service_context.py', 'tools/generate_hia_selfhost.py',
    'tests/test_hia_store_file_capture_native.py', 'tests/hia_store_file_capture_oracle.py',
    'tests/hia_independent_vm.py',
    'tests/hia_store_file_capture_observer.py', 'tests/hia_store_file_capture_controls.py',
    'tests/hia_store_file_capture_installed.py',
    'tests/fixtures/hia_store_file_capture_inputs_v1.json',
    'tools/qualify_hia_store_file_capture_originals.py',
    'tools/qualify_hia_store_file_capture_callers.py',
    *(ORIGINAL_DIRECTORY + name for name in ('stable_read.py.txt', 'capture_path.py.txt',
        'AgentRejected.py.txt', 'reject.py.txt', 'source-identity.json', 'local-slots.json',
        'caller-modules.json')),
    'tools/read_hia_store_file_capture_callers.py',
    'tests/hia_store_file_capture_owned_fd_v2_oracle.py',
    'tests/hia_store_file_capture_owned_fd_v2_observer.py',
    'tools/qualify_hia_store_file_capture_owned_fd_v2.py',
    'tests/hia_store_file_capture_owned_fd_v2_controls.py',
    'tests/test_hia_store_file_capture_owned_fd_v2.py',
    'tests/fixtures/hia_store_file_capture_owned_fd_v2/legacy-complete-inputs.json',
    'tests/fixtures/hia_store_file_capture_owned_fd_v2/AgentRejected.py.txt',
    'tests/fixtures/hia_store_file_capture_owned_fd_v2/reject.py.txt',
    'tests/fixtures/hia_store_file_capture_owned_fd_v2/stable_read.py.txt',
    'tests/fixtures/hia_store_file_capture_owned_fd_v2/capture_path.py.txt',
    'tests/fixtures/hia_store_file_capture_owned_fd_v2/source-identity.json',
    'tests/fixtures/hia_store_file_capture_owned_fd_v2/local-slots.json',
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
        elif any(sources.get(name) != sha256(raw).hexdigest() for name, raw in captured.items()):
            raise ValueError('store file capture inputs are not bound by current cold source')
    output.mkdir(mode=0o700)
    source = captured[SOURCE_NAME]
    image, receipt = compile_stage(output, 'store_file_capture', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'store_file_capture.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('store file capture construction inputs or output changed')
    if cold_inputs is not None:
        if custody != cold_inputs.capture_custody({**captured, **development_inputs}, root=ROOT):
            raise ValueError('component native and development custody changed during construction')
    manifest = {'schema': 'hepta.hia.store-file-capture.v2',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    report = {
        'schema': 'hepta.hia.store-file-capture-build.v2',
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'authored_owners': ['hia_agent_store.stable_read', 'hia_agent_store.capture_path'],
        'selected_public_route_invokes_retained_handler': False,
        'unselected_retained_originals_still_present': True,
        'original_root_and_file_descriptor_extent_identity_checks_preserved': True,
        'new_handler_transaction_or_retry_or_deadline': False,
        'opaque_object_and_provider_protocols_hosted': True,
        'OS_stream_Path_effects_hosted': True,
        'raw_descriptor_primitive_substituted_for_os_fdopen': False,
        'whole_method_pending_resources': 'weak registered observations until separate FINALIZE ACK',
        'per_port_ACK_retires_whole_method_observation': False,
        'same_frame_reentry_refused_before_cleanup_region': True,
        'normal_local_storage_transferred_without_clearing_held_tracebacks': True,
        'semantic_reference': 'owned-fd-v2',
        'stable_stream_borrows_descriptor_closefd_false': True,
        'descriptor_close_issued_by_HIA_ports': [72, 73],
        'close_claim_means_effect_completed': False,
        'v1_fdopen_close_side_effects_claimed_equivalent': False,
        'descriptor_IO_equivalence_established_by_build': False,
        'complete_input_equivalence_established_by_build': False,
        'current_caller_controls_not_replaced_by_build': True,
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
