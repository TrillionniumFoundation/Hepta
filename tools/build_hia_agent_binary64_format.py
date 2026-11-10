"""Build source-bound native Agent finite binary64 shortest printing; no default activation."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from tools.hia_selfhost_contract import CONTRACT_PATH, PROFILE, validate_contract
from tools.qualify_hia_selfhost import compile_stage

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'examples/hia_bootstrap/agent_binary64_format.hiaasm'


def build(output, compiler, cold_report):
    compiler_raw = compiler.read_bytes()
    cold_raw = cold_report.read_bytes()
    cold = json.loads(cold_raw)
    contract = validate_contract()
    sources = {**contract['source_identity']['files'], CONTRACT_PATH: sha256((ROOT / CONTRACT_PATH).read_bytes()).hexdigest()}
    required = {'export_manifest_matches_qualification', 'isolated_python_without_site',
        'nested_full_qualification_pass', 'nested_process_exit_zero', 'no_ancestor_git_identity',
        'no_bytecode_cache_created', 'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
        'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed', 'source_export_hashes_preserved'}
    if (type(cold) is not dict or cold.get('schema') != 'hepta.hia.selfhost-cold-replay.v1'
            or cold.get('status') != 'COLD_SELFHOST_REPLAY_PASS' or cold.get('returncode') != 0
            or cold.get('profile') != PROFILE or cold.get('source_manifest') != sources
            or cold.get('qualification_wall_limit_seconds') != 180 or cold.get('cleanup_wall_limit_seconds') != 3
            or type(cold.get('checks')) is not dict or set(cold['checks']) != required
            or any(value is not True for value in cold['checks'].values())
            or cold.get('generation_sha256') != [sha256(compiler_raw).hexdigest()] * 3):
        raise ValueError('completed matching-source cold qualification required for Agent binary64 printing')
    source = (ROOT / SOURCE).read_bytes()
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'agent-binary64-format', compiler, source)
    if (compiler.read_bytes() != compiler_raw or cold_report.read_bytes() != cold_raw
            or (ROOT / SOURCE).read_bytes() != source or validate_contract() != contract):
        raise ValueError('Agent binary64 printing native build custody changed')
    manifest = {'schema': 'hepta.hia.agent-binary64-format-native.v1', 'source_sha256': sha256(source).hexdigest(),
        'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
        'compiler_sha256': sha256(compiler_raw).hexdigest()}
    path = output / 'manifest.json'
    with path.open('x') as stream: json.dump(manifest, stream, indent=2, sort_keys=True); stream.write('\n')
    record = {'status': 'NATIVE_AGENT_BINARY64_FORMAT_BUILT', 'source_manifest': sources,
        'cold_report_sha256': sha256(cold_raw).hexdigest(), 'native_compile_receipt': receipt,
        'native_shortest_roundtrip_binary64_printing': True,
        'native_float_printing': True, 'foreign_float_boxing_is_hosted': True,
        'native_Agent_persistence': False, 'default_changed': False, 'whole_native_delivery_qualified': False}
    with (output / 'build.json').open('x') as stream: json.dump(record, stream, indent=2, sort_keys=True); stream.write('\n')
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'): parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))
