"""Build an explicitly selected module-symbol HIA image from a cold compiler.

This does not switch defaults or replace filesystem/package/AST authorities.
"""
from __future__ import annotations
import argparse,json
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def build(output:Path,compiler:Path,cold_report:Path):
    from tools.qualify_hia_selfhost import compile_stage
    source_path=ROOT/'examples/hia_bootstrap/module_symbols.hiaasm'
    source=source_path.read_bytes();image_bytes=compiler.read_bytes();cold=cold_report.read_bytes()
    qualification=json.loads(cold)
    checks={'export_manifest_matches_qualification','isolated_python_without_site',
        'nested_full_qualification_pass','nested_process_exit_zero',
        'no_ancestor_git_identity','no_bytecode_cache_created',
        'no_inherited_home_or_python_cache','no_inherited_seed_or_successor_images',
        'origin_hashes_preserved','owned_process_tree_cleanup_confirmed',
        'source_export_hashes_preserved'}
    if (type(qualification) is not dict or qualification.get('schema')!='hepta.hia.selfhost-cold-replay.v1'
            or qualification.get('status')!='COLD_SELFHOST_REPLAY_PASS' or qualification.get('returncode')!=0
            or type(qualification.get('checks')) is not dict or set(qualification['checks'])!=checks
            or any(value is not True for value in qualification['checks'].values())
            or type(qualification.get('generation_sha256')) is not list
            or len(qualification['generation_sha256'])!=3
            or any(value!=sha256(image_bytes).hexdigest() for value in qualification['generation_sha256'])):
        raise ValueError('a completed matching native cold qualification is required')
    output.mkdir(mode=0o700)
    image,receipt=compile_stage(output,'module-symbols',compiler,source)
    if source_path.read_bytes()!=source or compiler.read_bytes()!=image_bytes or cold_report.read_bytes()!=cold:
        raise ValueError('HIA module-symbol build inputs changed')
    manifest={'schema':'hepta.hia.module-symbols-native.v1','source_sha256':sha256(source).hexdigest(),
        'image_path':image.name,'image_sha256':sha256(image.read_bytes()).hexdigest(),
        'compiler_sha256':sha256(image_bytes).hexdigest()}
    path=output/'manifest.json';path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    (output/'build.json').write_text(json.dumps({'schema':'hepta.hia.module-symbols-build.v1',
        'status':'NATIVE_CANDIDATE_BUILT','manifest':manifest,'cold_report_sha256':sha256(cold).hexdigest(),
        'native_compile_receipt':receipt,'production_activated':False,'filesystem_package_AST_rewritten':False,
        'whole_stack_rewritten_in_hia':False},sort_keys=True,indent=2)+'\n')
    return path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('compiler','cold-report','output'):p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();print(build(args.output.resolve(),args.compiler.resolve(),args.cold_report.resolve()))


if __name__=='__main__':main()
