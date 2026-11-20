"""Build complete service read control with exact source custody."""
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

SOURCE_NAME = 'examples/hia_bootstrap/service_read.hepta'
ORIGINAL_DIRECTORY = 'tests/fixtures/hia_service_read_original_91bbd077/'
INPUTS = (SOURCE_NAME, 'hepta/hia_native_delivery.py',
          'tools/generate_hia_service_read.py', 'tools/build_hia_service_read.py',
          'hepta/hia_service_read_native.py', 'hepta/hia_service_read_protocol.py',
          'hepta/hia_agent_service.py', 'hepta/hia_native_helpers.py',
          'hepta/hia_emission_native.py',
          'tools/qualify_hia_service_read_callers.py',
          'tests/test_hia_service_read_native.py', 'tests/hia_service_read_fixture.py',
          'tests/hia_service_read_observer.py', 'tests/hia_service_read_sql_observer.py',
          'tests/hia_service_read_controls.py',
          'tests/hia_service_read_resources.py',
          'tests/hia_service_read_installed.py',
          'docs/HIA_SERVICE_READ_NATIVE.md', 'docs/HIA_SERVICE_READ_SQL_DELIVERY_DESIGN.md',
          'docs/HIA_SERVICE_READ_VALIDATION.md',
          'tools/generate_hia_service_context.py', 'tools/generate_hia_selfhost.py',
          'hepta/hia_json_preflight_native.py', 'hepta/hia_store_lifecycle_native.py',
          'hepta/hia_service_artifact_native.py', 'hepta/hia_service_artifact_protocol.py',
          'tools/build_hia_service_artifact.py',
          'tests/test_hia_service_artifact_local_release.py',
          'tests/hia_service_artifact_local_release_observer.py',
          'tests/hia_service_artifact_preparation.py',
          'tests/test_hia_service_artifact_preparation.py',
          'tests/fixtures/hia_service_artifact_preparation_v2.json',
          'tests/fixtures/hia_service_artifact_original_5bf/oracle-preparation-v1.py.txt',
          'tests/fixtures/hia_service_read_sql_original_e7/README.md',
          'tests/fixtures/hia_service_read_sql_original_e7/freeze.json',
          'tests/fixtures/hia_service_read_sql_original_e7/inputs.json',
          'tests/fixtures/hia_service_read_sql_original_e7/make_inputs.py',
          'tests/fixtures/hia_service_read_sql_original_e7/original_hia_read.py.txt',
          'tests/fixtures/hia_service_read_sql_original_e7/source-identity.json',
          'tests/fixtures/hia_service_read_sql_original_e7/sql_original_oracle.py',
          *(ORIGINAL_DIRECTORY + name for name in ('audit-caller-inventory.json', 'audit-complete-gates.json', 'audit-packaging-and-gate-source.json', 'audit-source-manifest.json', 'base-inputs.json', 'fault-inputs-FROZEN-before-execution.json', 'global-bindings.json', 'original_read_oracle.py', 'originals/AgentRejected.py.txt', 'originals/_hia_read.py.txt', 'originals/_reference_call.py.txt', 'originals/call.py.txt', 'originals/keys.py.txt', 'originals/reject.py.txt', 'originals/session-__init__.py.txt', 'originals/session-read.py.txt', 'originals/session-read_json.py.txt', 'originals/store-_get_reference.py.txt', 'originals/store-_resolve_uri_reference.py.txt', 'originals/store-digest.py.txt', 'originals/store-get.py.txt', 'originals/store-resolve_uri.py.txt', 'originals/store-wire.py.txt', 'source-identity.json')))


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
        raise ValueError('service_read inputs are not bound by current cold source')
    output.mkdir(mode=0o700)
    source = captured[SOURCE_NAME]
    image, receipt = compile_stage(output, 'service_read', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'service_read.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('service_read construction inputs or output changed')
    manifest = {'schema': 'hepta.hia.service-read-native.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    report = {'schema': 'hepta.hia.service-read-build.v1',
              'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
              'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
              'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
              'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
              'complete_original_method': 'HIAAgentService._hia_read',
              'control_branches_loops_exception_continuations_owned_by_hia': True,
              'hosted_boundaries': ['opaque object and numeric protocols', 'decode/base64 codecs',
                                    'original wire/digest providers', 'SQLite expressions'],
              'cursor_and_double_JSON_budget_policy_owner': 'HIA',
              'three_original_wire_calls_per_budget_iteration': True,
              'whole_data_decode_precedes_page_decode': True,
              'original_inner_outer_exception_match_order_preserved': True,
              'normal_local_release_issued_by_hia': True,
              'local_storage_order_owner': 'observed interpreter frame and builtin dict mechanics',
              'exceptional_locals_remain_traceback_owned': True,
              'pending_actual_downstream_resource_capture_api_required': False,
              'weak_registered_SQL_retention_design_implemented': True,
              'weak_registered_SQL_runtime_qualified_by_build': False,
              'direct_SQL_calls_per_foreign_activation': 1,
              'direct_SQL_resource_identity_capture_closed': False,
              'implicit_retained_body_fallback': False,
              'retained_body_claim_scope': 'canonical explicitly selected route',
              'additional_input_shape_integer_wall_or_loop_limits': False,
              'independent_original_finite_base_cases': 86,
              'independent_original_frozen_fault_cases': 6286,
              'additional_independent_original_SQL_expression_cases': 86,
              'all_python_versions_tested': False,
              'all_interpreter_execution_histories_proved': False,
              'whole_stack_rewritten_in_hia': False, 'all_input_equivalence_proved': False}
    (output / 'build.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
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
