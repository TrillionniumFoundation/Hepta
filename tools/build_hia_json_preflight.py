"""Build an explicitly selected HIA component with a qualified native image.

Consumes a flat compiler from a completed cold run of the current complete
source contract; does not synthesize successors with Python or activate a
service. The output manifest is an operator-local trusted code selection, not
a proof of all-input equivalence or a release promotion.
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


def current_sources():
    from tools.hia_selfhost_contract import CONTRACT_PATH, validate_contract
    contract = validate_contract()
    return {**contract['source_identity']['files'],
            CONTRACT_PATH: sha256((ROOT / CONTRACT_PATH).read_bytes()).hexdigest()}


def admit_cold_build(compiler_bytes: bytes, cold_bytes: bytes):
    """Admit frozen build inputs without creating directories or artifacts.

    Outer application builders use this same gate before creating their parent
    output. They retain their own input readback and recheck the returned full
    source map before publishing executable bytes.
    """
    from tools.hia_selfhost_contract import PROFILE
    qualification = json.loads(cold_bytes)
    compiler_sha = sha256(compiler_bytes).hexdigest()
    required_checks = {
        'export_manifest_matches_qualification', 'isolated_python_without_site',
        'nested_full_qualification_pass', 'nested_process_exit_zero',
        'no_ancestor_git_identity', 'no_bytecode_cache_created',
        'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
        'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed',
        'source_export_hashes_preserved'}
    if (type(qualification) is not dict
            or qualification.get('schema') != 'hepta.hia.selfhost-cold-replay.v1'
            or qualification.get('profile') != PROFILE
            or qualification.get('status') != 'COLD_SELFHOST_REPLAY_PASS'
            or type(qualification.get('returncode')) is not int or qualification['returncode'] != 0
            or type(qualification.get('checks')) is not dict
            or set(qualification['checks']) != required_checks
            or any(value is not True for value in qualification['checks'].values())
            or type(qualification.get('generation_sha256')) is not list
            or len(qualification['generation_sha256']) != 3
            or any(value != compiler_sha for value in qualification['generation_sha256'])):
        raise ValueError('a completed matching native cold qualification is required')
    sources = current_sources()
    if qualification.get('source_manifest') != sources:
        raise ValueError('cold qualification source identity does not match current source')
    return sources


CANDIDATES = {
    'machine-plan': ('machine_plan', 'machine-plan'),
    'safe-core-x64-decode': ('safe_core_x64_decode', 'safe-core-x64-decode'),
    'core-proof-wire': ('core_proof_wire', 'core-proof-wire'),
    'safe-core-elf-inventory': ('safe_core_elf_inventory', 'safe-core-elf-inventory'),
    'safe-core-loader-filter': ('safe_core_loader_filter_packer', 'safe-core-loader-filter'),
    'machine-encoding': ('machine_encoding', 'machine-encoding'),
    'candidate-budget': ('candidate_budget', 'candidate-budget'),
    'agent-journal': ('agent_journal', 'agent-journal'),
    'journal-cost': ('agent_journal_transport', 'journal-cost'),
    'mcp-request': ('mcp_request_route', 'mcp-request'),
    'mcp-reply': ('mcp_reply_wire', 'mcp-reply'),
    'job-terminal-receipt': ('job_terminal_receipt', 'job-terminal-receipt'),
    'mcp-terminal': ('mcp_terminal_admission', 'mcp-terminal'),
    'mcp-negotiation': ('mcp_negotiation', 'mcp-negotiation'),
    'mcp-connection': ('mcp_connection', 'mcp-connection'),
    'mcp-catalog': ('mcp_catalog_wire', 'mcp-catalog'),
    'mcp-uri': ('mcp_resource_uri', 'mcp-uri'),
    'execution-budget': ('execution_budget', 'execution-budget'),
    'execution-ledger': ('execution_ledger', 'execution-ledger'),
    'retirement-state': ('retirement_state', 'retirement-state'),
    'worker-prepare': ('worker_prepare', 'worker-prepare'),
    'worker-request': ('worker_request', 'worker-request'),
    'worker-read-capsule': ('worker_read_capsule', 'worker-read-capsule'),
    'worker-request-filter': ('worker_request_filter_packer', 'worker-request-filter'),
    'core-admission': ('core_admission', 'core-admission'),
    'composite-types': ('composite_types', 'composite-types'),
    'task-helpers': ('task_helpers', 'task-helpers'),
    'composite-function-admit': ('composite_function_admit', 'composite-function-admit'),
    'composite-function-records': ('composite_function_records', 'composite-function-records'),
    'composite-function-advanced': ('composite_function_advanced', 'composite-function-advanced'),
    'composite-function-terms': ('composite_function_terms', 'composite-function-terms'),
    'composite-function-render': ('composite_function_render', 'composite-function-render'),
    'composite-constructor-owner': ('composite_constructor_owner', 'composite-constructor-owner'),
    'composite-constructor-render': ('composite_constructor_render', 'composite-constructor-render'),
    'composite-outer-owner': ('composite_outer_owner', 'composite-outer-owner'),
    'composite-outer-render': ('composite_outer_render', 'composite-outer-render'),
    'instruction-policy': ('instruction_policy','instruction-policy'),
    'core-workspace-materialize': ('core_workspace_materialize','core-workspace-materialize'),
    'core-workspace-facts': ('core_workspace_facts','core-workspace-facts'),
    'program-shape': ('program_shape', 'program-shape'),
    'function-shape': ('function_shape', 'function-shape'),
    'capability-renaming': ('capability_renaming', 'capability-renaming'),
    'agent-slice': ('agent_slice', 'agent-slice'),
    'agent-identity': ('agent_identity', 'agent-identity'),
    'agent-inspection': ('agent_inspection', 'agent-inspection'),
    'agent-discovery': ('agent_discovery', 'agent-discovery'),
    'agent-describe-answer': ('agent_describe_answer', 'agent-describe-answer'),
    'worker-describe-request': ('worker_describe_request', 'worker-describe-request'),
    'worker-artifact-request': ('worker_artifact_request', 'worker-artifact-request'),
    'journal-records': ('worker_journal_records', 'journal-records'),
    'journal-observation': ('worker_journal_observation', 'journal-observation'),
    'artifact-authority': ('worker_artifact_authority', 'artifact-authority'),
    'artifact-diagnostic': ('worker_artifact_diagnostic', 'artifact-diagnostic'),
    'context-store': ('worker_context_store', 'context-store'),
    'context-record': ('worker_context_record', 'context-record'),
    'context-request': ('worker_context_request', 'context-request'),
    'inspection-request': ('worker_inspection_request', 'inspection-request'),
    'candidate-request': ('worker_candidate_request', 'candidate-request'),
    'worker-rollback': ('worker_rollback', 'worker-rollback'),
    'emit-request': ('worker_emit_request', 'emit-request'),
    'emit-receipt': ('worker_emit_receipt', 'emit-receipt'),
    'emit-verification': ('worker_emit_verification', 'emit-verification'),
    'emit-build-observation': ('worker_emit_build_observation', 'emit-build-observation'),
    'emit-effect': ('worker_emit_effect', 'emit-effect'),
    'worker-profile-bindings': ('worker_profile_bindings', 'worker-profile-bindings'),
    'worker-proof-scope': ('worker_proof_scope', 'worker-proof-scope'),
    'retained-build': ('worker_retained_build', 'retained-build'),
    'publication-observation': ('worker_publication_observation', 'publication-observation'),
    'rollback-journal': ('worker_rollback_journal', 'rollback-journal'),
    'rollback-journal-observation': ('worker_rollback_journal_observation', 'rollback-journal-observation'),
    'rollback-journal-records': ('worker_rollback_journal_records', 'rollback-journal-records'),
    'rollback-diagnostic': ('worker_rollback_diagnostic', 'rollback-diagnostic'),
    'native-artifact-metadata': ('worker_native_artifact', 'native-artifact-metadata'),
    'candidate-effect': ('worker_candidate_effect', 'candidate-effect'),
    'candidate-json-ingress': ('worker_candidate_json_ingress', 'candidate-json-ingress'),
    'candidate-admission-diagnostic': ('worker_candidate_admission_diagnostic', 'candidate-admission-diagnostic'),
    'inspection-effect': ('worker_inspection_effect', 'inspection-effect'),
    'borrowed-export-wire': ('borrowed_export_wire', 'borrowed-export-wire'),
    'borrowed-wrapper': ('borrowed_wrapper', 'borrowed-wrapper'),
    'inspection-journal': ('worker_inspection_journal', 'inspection-journal'),
    'inspection-journal-observation': ('worker_inspection_journal_observation', 'inspection-journal-observation'),
    'inspection-journal-records': ('worker_inspection_journal_records', 'inspection-journal-records'),
    'inspection-diagnostic': ('worker_inspection_diagnostic', 'inspection-diagnostic'),
    'candidate-journal': ('worker_candidate_journal', 'candidate-journal'),
    'candidate-journal-observation': ('worker_candidate_journal_observation', 'candidate-journal-observation'),
    'candidate-journal-records': ('worker_candidate_journal_records', 'candidate-journal-records'),
    'candidate-diagnostic': ('worker_candidate_diagnostic', 'candidate-diagnostic'),
    'inspection-lowering-elf': ('inspection_lowering_elf', 'inspection-lowering-elf'),
    'inspection-lowering-frames': ('inspection_lowering_frames', 'inspection-lowering-frames'),
    'context-workload': ('worker_context_workload', 'context-workload'),
    'context-cost': ('worker_context_cost', 'context-cost'),
    'context-cost-diagnostic': ('worker_context_cost_diagnostic', 'context-cost-diagnostic'),
    'context-effect': ('worker_context_effect', 'context-effect'),
    'context-diagnostic': ('worker_context_diagnostic', 'context-diagnostic'),
    'context-journal': ('worker_context_journal', 'context-journal'),
    'context-journal-records': ('worker_context_journal_records', 'context-journal-records'),
    'context-journal-observation': ('worker_context_journal_observation', 'context-journal-observation'),
    'artifact-journal': ('worker_artifact_journal', 'artifact-journal'),
    'discovery-artifact': ('discovery_artifact', 'discovery-artifact'),
    'discovery-effect': ('discovery_effect', 'discovery-effect'),
    'describe-bind': ('describe_bind', 'describe-bind'),
    'discovery-bootstrap-assemble': ('discovery_bootstrap_assemble', 'discovery-bootstrap-assemble'),
    'discovery-bootstrap-plan': ('discovery_bootstrap_plan', 'discovery-bootstrap-plan'),
    'agent-read-page': ('agent_read_page', 'agent-read-page'),
    'agent-read-request': ('agent_read_request', 'agent-read-request'),
    'agent-store-transport': ('agent_store_transport', 'agent-store-transport'),
    'agent-schema': ('agent_schema', 'agent-schema'),
    'agent-payload-schema': ('agent_payload_schema', 'agent-payload-schema'),
    'agent-plan-schema': ('agent_plan_schema', 'agent-plan-schema'),
    'agent-response-schema': ('agent_response_schema', 'agent-response-schema'),
    'agent-verify-response-schema': ('agent_verify_response_schema', 'agent-verify-response-schema'),
    'core-workspace-json': ('core_workspace_json', 'core-workspace-json'),
    'core-module-graph': ('core_module_graph', 'core-module-graph'),
    'preflight': ('json_preflight', 'json-preflight'),
    'decode': ('json_decode', 'json-decode'),
    'canonical': ('json_canonical', 'json-canonical'),
    'core-frontend': ('core_json_frontend', 'core-json-frontend'),
    'elf-linker': ('elf_static_linker', 'elf-linker'),
    'elf-shared-linker': ('elf_shared_linker', 'elf-shared-linker'),
    'elf-direct-shared-linker-filter': ('direct_shared_linker_filter_packer', 'elf-direct-shared-linker-filter'),
    'elf-verified-linker': ('elf_verified_linker', 'elf-verified-linker'),
    'scalar-reference': ('scalar_reference', 'scalar-reference'),
    'scalar-symbolic': ('scalar_symbolic', 'scalar-symbolic'),
    'cnf': ('cnf', 'cnf'),
    'elf-linker-filter': ('elf_linker_filter_packer', 'elf-linker-filter'),
    'native-filter': ('native_filter_packer', 'native-filter'),
    'agent-snapshot': ('agent_snapshot', 'agent-snapshot'),
    'agent-snapshot-json': ('agent_snapshot_json', 'agent-snapshot-json'),
    'sqlite-wal-snapshot': ('sqlite_wal_snapshot', 'sqlite-wal-snapshot'),
    'sqlite-rowid-lookup': ('sqlite_rowid_lookup', 'sqlite-rowid-lookup'),
    'sqlite-agent-row-import': ('sqlite_agent_row_import', 'sqlite-agent-row-import'),
    'sqlite-agent-import-batch': ('sqlite_agent_import_batch', 'sqlite-agent-import-batch'),
    'sqlite-agent-cost-sequence': ('sqlite_agent_cost_sequence', 'sqlite-agent-cost-sequence'),
    'sqlite-agent-artifact-catalog': ('sqlite_agent_artifact_catalog', 'sqlite-agent-artifact-catalog'),
    'sqlite-agent-catalog': ('sqlite_agent_catalog', 'sqlite-agent-catalog'),
    'sqlite-record-layout': ('sqlite_record_layout', 'sqlite-record-layout'),
}


def _image_manifest(candidate, protocol, source, image, image_name, compiler_sha):
    version = '2' if candidate in ('agent-journal', 'machine-encoding') else '1'
    return {'schema': 'hepta.hia.' + protocol + '-native.v' + version,
            'source_sha256': sha256(source).hexdigest(), 'image_path': image_name,
            'image_sha256': sha256(image).hexdigest(), 'compiler_sha256': compiler_sha}


def build_batch(output, compiler, cold_report, *, candidates):
    """Compile generic helper sources in the sealed HIA source builder."""
    from tools.build_hia_source_build import compile_source_batch

    if not candidates or len(set(candidates)) != len(candidates) or any(
            name not in CANDIDATES for name in candidates):
        raise ValueError('expected distinct known HIA JSON candidates')
    raw, compiler_bytes = cold_report.read_bytes(), compiler.read_bytes()
    source_identity = admit_cold_build(compiler_bytes, raw)
    files = {}
    for candidate in candidates:
        name, _ = CANDIDATES[candidate]
        path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
        source = path.read_bytes()
        if sha256(source).hexdigest() != source_identity.get(path.relative_to(ROOT).as_posix()):
            raise ValueError('native candidate source changed after contract admission')
        files[path] = source
    output.mkdir(mode=0o700)
    images = compile_source_batch(output / 'bootstrap', compiler, cold_report,
                                  {path.name: source for path, source in files.items()})
    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != raw
            or any(path.read_bytes() != source for path, source in files.items())
            or current_sources() != source_identity):
        raise ValueError('native batch build inputs changed')
    compiler_sha = sha256(compiler_bytes).hexdigest()
    manifests = {}
    for candidate in candidates:
        name, protocol = CANDIDATES[candidate]
        source_name = name + '.hepta'
        source = files[ROOT / 'examples/hia_bootstrap' / source_name]
        image = images[source_name]
        manifest = _image_manifest(candidate, protocol, source, image, protocol + '.image.bin', compiler_sha)
        directory = output / candidate
        directory.mkdir(mode=0o700)
        image_path = directory / manifest['image_path']
        image_path.write_bytes(image)
        image_path.chmod(0o600)
        path = directory / 'manifest.json'
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        path.chmod(0o600)
        manifests[candidate] = path
    return manifests


def build(output: Path, compiler: Path, cold_report: Path, *, candidate='preflight') -> Path:
    from tools.qualify_hia_selfhost import compile_stage
    from tools.hia_selfhost_contract import PROFILE
    if candidate not in CANDIDATES:
        raise ValueError('unknown HIA JSON candidate')
    source_name, protocol = CANDIDATES[candidate]
    raw = cold_report.read_bytes()
    compiler_bytes = compiler.read_bytes()
    compiler_sha = sha256(compiler_bytes).hexdigest()
    sources = admit_cold_build(compiler_bytes, raw)
    source_path = ROOT / ('examples/hia_bootstrap/' + source_name + '.hepta')
    if source_path.relative_to(ROOT).as_posix() not in sources:
        raise ValueError('cold qualification source identity does not match current source')
    source = source_path.read_bytes()
    if sha256(source).hexdigest() != sources[source_path.relative_to(ROOT).as_posix()]:
        raise ValueError('native candidate source changed after contract admission')
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, protocol, compiler, source)
    image_bytes = image.read_bytes()
    if (source_path.read_bytes() != source or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != raw or current_sources() != sources
            or image.read_bytes() != image_bytes):
        raise ValueError('native candidate build inputs changed')
    manifest = _image_manifest(candidate, protocol, source, image_bytes, image.name, compiler_sha)
    path = output / 'manifest.json'
    image.chmod(0o600)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    path.chmod(0o600)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.' + protocol + '-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
        'profile': PROFILE, 'source_manifest': sources,
        'manifest': manifest, 'cold_report_sha256': sha256(raw).hexdigest(),
        'native_compile_receipt': receipt, 'production_activated': False,
        'all_input_equivalence_proved': False, 'full_json_value_decoder_implemented': False,
        'hia_json_value_arena_implemented': candidate in ('decode', 'canonical'),
        'hia_json_canonical_wire_implemented': candidate == 'canonical',
        'hia_primitive_Core_representation_frontend': candidate == 'core-frontend',
        'hia_workspace_JSON_graph_and_Core_materialization': candidate == 'core-workspace-json',
        'foreign_object_bridge_is_python': candidate == 'decode',
        'whole_stack_rewritten_in_hia': False}, indent=2, sort_keys=True) + '\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--candidate', default='preflight',
                        choices=('preflight', 'agent-identity', 'agent-inspection', 'agent-discovery',
                                 'mcp-request',
                                 'mcp-reply',
                                 'job-terminal-receipt',
                                 'mcp-terminal',
                                 'mcp-negotiation', 'mcp-connection',
                                 'mcp-catalog',
                                 'mcp-uri',
                                 'agent-describe-answer', 'agent-read-page', 'agent-read-request', 'agent-store-transport',
                                 'agent-schema', 'agent-payload-schema',
                                 'agent-plan-schema', 'agent-response-schema',
                                 'agent-verify-response-schema', 'execution-ledger', 'sqlite-wal-snapshot',
                                 'sqlite-rowid-lookup', 'sqlite-record-layout', 'sqlite-agent-row-import',
                                 'sqlite-agent-import-batch', 'sqlite-agent-cost-sequence',
                                 'sqlite-agent-artifact-catalog', 'sqlite-agent-catalog', 'elf-shared-linker',
                                 'elf-verified-linker',
                                 'scalar-reference', 'scalar-symbolic', 'cnf', 'safe-core-x64-decode',
                                 'safe-core-elf-inventory', 'core-proof-wire', 'worker-prepare'))
    args = parser.parse_args()
    path = build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(),
                 candidate=args.candidate)
    print(json.dumps({'status': 'NATIVE_CANDIDATE_BUILT', 'manifest': str(path)}))


if __name__ == '__main__':
    main()
