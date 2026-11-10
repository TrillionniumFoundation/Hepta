"""Build an explicitly selected, source-bound native filesystem publisher.

Build/install/code custody are hosted; runtime policy, exact byte verification,
receipt and SHA are HIA behind a fixed Linux syscall adapter. Not default Agent
persistence, a transaction journal, directory durability or native-only release.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json,struct
from pathlib import Path
from tools.hia_selfhost_contract import CONTRACT_PATH,PROFILE,validate_contract
from tools.qualify_hia_selfhost import compile_stage,invoke
from tools.qualify_hia_selfhost_cli import inspect_executable
from tools.generate_hia_artifact_publication import MAGIC
ROOT=Path(__file__).resolve().parents[1]
SOURCES=('examples/hia_bootstrap/artifact_publication_policy.hiaasm',
         'examples/hia_bootstrap/artifact_publication_packer.hiaasm',
         'examples/hia_bootstrap/sha256_stream.hiaasm',
         'tools/hia_artifact_publication_syscalls.S',
         'tools/generate_hia_artifact_publication.py')


def current_sources():
    contract=validate_contract()
    return {**contract['source_identity']['files'],
            CONTRACT_PATH:sha256((ROOT/CONTRACT_PATH).read_bytes()).hexdigest()}


def build(output:Path,compiler:Path,cold_report:Path):
    paths=[compiler,cold_report,*(ROOT/name for name in SOURCES)]
    pins={path:path.read_bytes() for path in paths};sources=current_sources()
    cold=json.loads(pins[cold_report]);required={
        'export_manifest_matches_qualification','isolated_python_without_site',
        'nested_full_qualification_pass','nested_process_exit_zero','no_ancestor_git_identity',
        'no_bytecode_cache_created','no_inherited_home_or_python_cache','no_inherited_seed_or_successor_images',
        'origin_hashes_preserved','owned_process_tree_cleanup_confirmed','source_export_hashes_preserved'}
    if (type(cold) is not dict or cold.get('schema')!='hepta.hia.selfhost-cold-replay.v1'
            or cold.get('status')!='COLD_SELFHOST_REPLAY_PASS' or cold.get('returncode')!=0
            or cold.get('profile')!=PROFILE or cold.get('source_manifest')!=sources
            or type(cold.get('checks')) is not dict or set(cold['checks'])!=required
            or any(value is not True for value in cold['checks'].values())
            or cold.get('generation_sha256')!=[sha256(pins[compiler]).hexdigest()]*3
            or any(name not in sources for name in SOURCES)):
        raise ValueError('completed matching-source cold qualification required for native publication')
    output.mkdir(mode=0o700);images={};receipts={}
    for label,name in zip(('policy','packer','sha256'),SOURCES[:3]):
        image,receipts[label]=compile_stage(output,label,compiler,pins[ROOT/name])
        images[label]=(image,image.read_bytes())
    policy,sha=images['policy'][1],images['sha256'][1]
    frame=struct.pack('<3Q',MAGIC,len(policy),len(sha))+policy+sha
    result,packed=invoke(output,'publication-pack',images['packer'][0],frame)
    count=result.get('core_u32')
    if result.get('status')!='returned' or type(count) is not int or not 0<count<=len(packed):
        raise ValueError('native publication packer refused component images')
    executable=packed[:count];inspection=inspect_executable(executable)
    if (any(path.read_bytes()!=raw for path,raw in pins.items()) or current_sources()!=sources
            or any(path.read_bytes()!=raw for path,raw in images.values())):
        raise ValueError('native publication build custody changed')
    path=output/'hia-artifact'
    with path.open('xb') as stream:stream.write(executable)
    path.chmod(0o700)
    report={'schema':'hepta.hia.artifact-publication-build.v1','status':'NATIVE_ARTIFACT_PUBLICATION_BUILT',
        'profile':PROFILE,'source_manifest':sources,'source_sha256':{name:sha256(pins[ROOT/name]).hexdigest() for name in SOURCES},
        'compiler_sha256':sha256(pins[compiler]).hexdigest(),'cold_report_sha256':sha256(pins[cold_report]).hexdigest(),
        'executable_path':path.name,'executable_sha256':sha256(executable).hexdigest(),'executable':inspection,
        'image_sha256':{label:sha256(raw).hexdigest() for label,(_,raw) in images.items()},
        'compile_receipts':receipts,'native_packer_receipt':result,'frame_sha256':sha256(frame).hexdigest(),
        'operations':['publish','verify','withdraw'],'artifact_payload_fixed_size_limit':None,
        'runtime_Python_or_libc_or_child_required':False,'host_build_and_code_custody':True,
        'point_in_time_consistency_only':True,'directory_fsync_or_crash_recovery_provided':False,
        'full_Agent_persistence_replaced':False,'default_changed':False,'whole_native_delivery_qualified':False}
    with (output/'build.json').open('x') as stream:json.dump(report,stream,indent=2,sort_keys=True);stream.write('\n')
    return path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('compiler','cold-report','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(build(args.output.resolve(),args.compiler.resolve(),args.cold_report.resolve()))

if __name__=='__main__':main()
