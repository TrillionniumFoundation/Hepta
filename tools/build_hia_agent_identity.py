"""Build an operator-selected HIA Agent scalar identity guard from matching cold B3."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def build(output:Path,compiler:Path,cold_report:Path)->Path:
    from tools.qualify_hia_selfhost import compile_stage
    cold=cold_report.read_bytes();report=json.loads(cold);compiler_bytes=compiler.read_bytes();compiler_sha=sha256(compiler_bytes).hexdigest()
    checks={'export_manifest_matches_qualification','isolated_python_without_site',
        'nested_full_qualification_pass','nested_process_exit_zero','no_ancestor_git_identity',
        'no_bytecode_cache_created','no_inherited_home_or_python_cache','no_inherited_seed_or_successor_images',
        'origin_hashes_preserved','owned_process_tree_cleanup_confirmed','source_export_hashes_preserved'}
    if (type(report)is not dict or report.get('schema')!='hepta.hia.selfhost-cold-replay.v1'
            or report.get('status')!='COLD_SELFHOST_REPLAY_PASS'
            or type(report.get('returncode'))is not int or report.get('returncode')!=0
            or type(report.get('checks'))is not dict or set(report['checks'])!=checks
            or any(v is not True for v in report['checks'].values())
            or type(report.get('generation_sha256'))is not list or len(report['generation_sha256'])!=3
            or any(v!=compiler_sha for v in report['generation_sha256'])):
        raise ValueError('a completed matching native cold qualification is required')
    source_path=ROOT/'examples/hia_bootstrap/agent_identity.hiaasm';source=source_path.read_bytes()
    output.mkdir(mode=0o700)
    image,receipt=compile_stage(output,'agent-identity',compiler,source)
    if source_path.read_bytes()!=source or compiler.read_bytes()!=compiler_bytes or cold_report.read_bytes()!=cold:
        raise ValueError('HIA Agent identity build inputs changed')
    manifest={'schema':'hepta.hia.agent-identity-native.v1','source_sha256':sha256(source).hexdigest(),
        'image_path':image.name,'image_sha256':sha256(image.read_bytes()).hexdigest(),'compiler_sha256':compiler_sha}
    path=output/'manifest.json';path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    (output/'build.json').write_text(json.dumps({'schema':'hepta.hia.agent-identity-build.v1',
        'status':'NATIVE_CANDIDATE_BUILT','manifest':manifest,'cold_report_sha256':sha256(cold).hexdigest(),
        'native_compile_receipt':receipt,'production_activated':False,'agent_scalar_identity_application_built':True,
        'whole_agent_protocol_and_persistence_replaced':False,'all_input_equivalence_proved':False,
        'whole_stack_rewritten_in_hia':False},indent=2,sort_keys=True)+'\n')
    return path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler',required=True,type=Path);parser.add_argument('--cold-report',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    print(build(args.output.resolve(),args.compiler.resolve(),args.cold_report.resolve()))


if __name__=='__main__':main()
