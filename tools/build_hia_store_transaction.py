"""Build complete Store transaction control with exact source custody."""
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

SOURCE_NAME = 'examples/hia_bootstrap/store_transaction.hepta'
ORIGINAL_DIRECTORY = 'tests/fixtures/hia_store_transaction_original_c019/'
INPUTS = ('tools/hia_component_input_custody.py',
    SOURCE_NAME, 'tools/generate_hia_store_transaction.py',
    'tools/build_hia_store_transaction.py', 'tools/qualify_hia_store_transaction_callers.py',
    'tools/qualify_hia_store_transaction.py', 'tools/qualify_hia_emission_callers.py',
    'hepta/hia_store_transaction_native.py', 'hepta/hia_store_transaction_protocol.py',
    'hepta/hia_native_delivery.py', 'hepta/hia_agent_store.py',
    'hepta/hia_store_lifecycle_selection.py', 'hepta/hia_store_lifecycle_native.py',
    'hepta/hia_store_artifact_profile_native.py', 'hepta/hia_native_helpers.py',
    'hepta/hia_emission_native.py', 'hepta/hia_json_preflight_native.py',
    'tools/generate_hia_service_context.py', 'tools/generate_hia_selfhost.py',
    'tests/test_hia_store_transaction_native.py',
    'tests/test_hia_store_transaction_owner_native.py',
    'tests/hia_store_transaction_oracle.py', 'tests/hia_store_transaction_scenarios.py',
    'tests/hia_store_transaction_history.py',
    'tests/fixtures/hia_emission_original_73f1634/original-freeze.json',
    'tests/fixtures/hia_store_transaction_separate_5bf.json',
    *(ORIGINAL_DIRECTORY + name for name in (
        'transaction.c019.py.txt', 'source-identity.json', 'cases.json', 'freeze.json')),
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
    image, receipt = compile_stage(output, 'store_transaction', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'store_transaction.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('Store transaction construction inputs or output changed')
    if not development:
        verify_component_custody(custody, compiler_bytes, cold_bytes, sources,
                                 {**captured, **development_inputs}, root=ROOT)
    if cold_inputs is not None:
        cold_inputs.unchanged()
    manifest = {'schema': 'hepta.hia.store-transaction.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    report = {
        'schema': 'hepta.hia.store-transaction-build.v1',
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'complete_original_transaction_control_owned_by_hia': True,
        'lock_BEGIN_yield_COMMIT_ROLLBACK_exit_suppression_owned_by_hia': True,
        'selected_public_route_invokes_retained_original': False,
        'unselected_retained_original_still_present': True,
        'original_SQL_literals_and_dynamic_method_calls_preserved': True,
        'sqlite_lock_object_and_generator_protocols_hosted': True,
        'native_custody_scope': 'one actual process/thread advance; confirmed BODY_WAIT may migrate',
        'yield_resource_scope_is_not_native_ancestry': True,
        'explicit_resource_loss_blocks_resume_and_retirement': True,
        'body_observation_custody_reserved_before_BEGIN': True,
        'unknown_resources_only_retained_not_claimed_cleaned': True,
        'new_replay_retry_SQL_or_production_deadline': False,
        'all_python_versions_tested': False,
        'all_input_equivalence_proved': False,
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
