"""Build the explicitly selected HIA JSON candidate with a qualified native image.

Consumes an already qualified flat compiler; does not synthesize successors with
Python or activate a service. The output manifest is an operator-local trusted
code selection, not a proof of all-input equivalence or a release promotion.
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


def build(output: Path, compiler: Path, cold_report: Path, *, candidate='preflight') -> Path:
    from tools.qualify_hia_selfhost import compile_stage
    candidates = {'core-workspace-json': ('core_workspace_json', 'core-workspace-json'),'core-module-graph': ('core_module_graph', 'core-module-graph'),
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
    qualification = json.loads(raw)
    compiler_bytes = compiler.read_bytes()
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
            or qualification.get('status') != 'COLD_SELFHOST_REPLAY_PASS'
            or qualification.get('returncode') != 0
            or type(qualification.get('checks')) is not dict
            or set(qualification['checks']) != required_checks
            or any(value is not True for value in qualification['checks'].values())
            or type(qualification.get('generation_sha256')) is not list
            or len(qualification['generation_sha256']) != 3
            or any(value != compiler_sha for value in qualification['generation_sha256'])):
        raise ValueError('a completed matching native cold qualification is required')
    source_path = ROOT / ('examples/hia_bootstrap/' + source_name + '.hiaasm')
    source = source_path.read_bytes()
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, protocol, compiler, source)
    if source_path.read_bytes() != source or compiler.read_bytes() != compiler_bytes:
        raise ValueError('native candidate build inputs changed')
    manifest = {'schema': 'hepta.hia.' + protocol + '-native.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image.read_bytes()).hexdigest(), 'compiler_sha256': compiler_sha}
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.' + protocol + '-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
        'manifest': manifest, 'cold_report_sha256': sha256(raw).hexdigest(),
        'native_compile_receipt': receipt, 'production_activated': False,
        'all_input_equivalence_proved': False, 'full_json_value_decoder_implemented': False,
        'hia_json_value_arena_implemented': candidate in ('decode', 'canonical'),
        'hia_json_canonical_wire_implemented': candidate == 'canonical',
        'hia_primitive_Core_representation_frontend': candidate == 'core-frontend',
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
