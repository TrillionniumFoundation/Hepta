"""Build the explicitly selected HIA JSON candidate with a qualified native image.

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


def build(output: Path, compiler: Path, cold_report: Path, *, candidate='preflight') -> Path:
    from tools.qualify_hia_selfhost import compile_stage
    from tools.hia_selfhost_contract import PROFILE
    candidates = {'machine-plan': ('machine_plan', 'machine-plan'),
                  'worker-request': ('worker_request', 'worker-request'),
                  'program-execution': ('program_execution', 'program-execution'),
                  'static-budget': ('static_budget', 'static-budget'),
                  'heap-bound': ('heap_bound', 'heap-bound'),
                  'heap-live-engine': ('heap_live_engine', 'heap-live-engine'),
                  'heap-payload': ('heap_payload', 'heap-payload'),
                  'enum-match': ('enum_match', 'enum-match'),
                  'enum-operations': ('enum_operations', 'enum-operations'),
                  'record-operations': ('record_operations', 'record-operations'),
                  'record-transitions': ('record_transitions', 'record-transitions'),
                  'nominal-terminators': ('nominal_terminators', 'nominal-terminators'),
                  'nominal-function': ('nominal_function', 'nominal-function'),
                  'call-primitive': ('call_primitive', 'call-primitive'),
                  'task-operations': ('task_operations', 'task-operations'),
                  'nominal-module': ('nominal_module', 'nominal-module'),
                  'nominal-admission': ('nominal_admission', 'nominal-admission'),
                  'core-admission': ('core_admission', 'core-admission'),
                  'composite-types': ('composite_types', 'composite-types'),
                  'task-helpers': ('task_helpers', 'task-helpers'),
                  'task-helper-cache': ('task_helper_cache', 'task-helper-cache'),
                  'artifact-namespace': ('artifact_namespace', 'artifact-namespace'),
                  'slot-ledger': ('slot_ledger', 'slot-ledger'),
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
                  'retirement-state': ('retirement_state', 'retirement-state'),
                  'execution-budget': ('execution_budget', 'execution-budget'),
                  'request-journal': ('request_journal', 'request-journal'),
                  'core-workspace-json': ('core_workspace_json', 'core-workspace-json'),
                  'core-module-graph': ('core_module_graph', 'core-module-graph'),
                  'preflight': ('json_preflight', 'json-preflight'),
                  'decode': ('json_decode', 'json-decode'),
                  'canonical': ('json_canonical', 'json-canonical'),
                  'core-frontend': ('core_json_frontend', 'core-json-frontend'),
                  'elf-linker': ('elf_static_linker', 'elf-linker'),
                  'native-filter': ('native_filter_packer', 'native-filter'),
                  'agent-snapshot': ('agent_snapshot', 'agent-snapshot'),
                  'agent-snapshot-json': ('agent_snapshot_json', 'agent-snapshot-json')}
    if candidate not in candidates:
        raise ValueError('unknown HIA JSON candidate')
    source_name, protocol = candidates[candidate]
    raw = cold_report.read_bytes()
    compiler_bytes = compiler.read_bytes()
    compiler_sha = sha256(compiler_bytes).hexdigest()
    sources = admit_cold_build(compiler_bytes, raw)
    source_path = ROOT / ('examples/hia_bootstrap/' + source_name + '.hiaasm')
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
    manifest = {'schema': 'hepta.hia.' + protocol + '-native.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(), 'compiler_sha256': compiler_sha}
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
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
    args = parser.parse_args()
    path = build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve())
    print(json.dumps({'status': 'NATIVE_CANDIDATE_BUILT', 'manifest': str(path)}))


if __name__ == '__main__':
    main()
