"""Source-bound hosted custody for the four-stage native workspace filter.

This builder does not grant native-only installation or whole Core compilation.
Full primitive Core admission precedes the existing bounded native compiler.
"""
import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
from tools.build_hia_json_preflight import build as build_candidate
import struct
from tools.generate_hia_core_workspace_pipeline import MAGIC,BUNDLE_LIMIT
from tools.hia_selfhost_contract import CONTRACT_PATH,PROFILE,validate_contract
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable
from hepta.hia_json_preflight_native import NativeHiaJsonImage

ROOT=Path(__file__).resolve().parents[1]
SCHEMA='hepta.hia.core-workspace-pipeline-build.v2'
SOURCES=('examples/hia_bootstrap/core_workspace_json.hepta',
         'examples/hia_bootstrap/core_admission.hepta',
         'examples/hia_bootstrap/core_json_frontend.hepta',
         'examples/hia_bootstrap/core_workspace_pipeline_packer.hepta',
         'examples/hia_bootstrap/selfhost.hepta')


def current_sources():
    contract=validate_contract()
    return {**contract['source_identity']['files'],
            CONTRACT_PATH:sha256((ROOT/CONTRACT_PATH).read_bytes()).hexdigest()}


def build(output,compiler,cold_report):
    paths=[compiler,cold_report,*(ROOT/name for name in SOURCES)]
    pins={p:p.read_bytes() for p in paths};cold=json.loads(pins[cold_report]);sources=current_sources()
    required={'export_manifest_matches_qualification','isolated_python_without_site',
        'nested_full_qualification_pass','nested_process_exit_zero','no_ancestor_git_identity',
        'no_bytecode_cache_created','no_inherited_home_or_python_cache','no_inherited_seed_or_successor_images',
        'origin_hashes_preserved','owned_process_tree_cleanup_confirmed','source_export_hashes_preserved'}
    if (type(cold) is not dict or cold.get('schema')!='hepta.hia.selfhost-cold-replay.v1'
            or cold.get('status')!='COLD_SELFHOST_REPLAY_PASS'
            or type(cold.get('returncode')) is not int or cold['returncode']!=0
            or cold.get('profile')!=PROFILE or cold.get('source_manifest')!=sources
            or type(cold.get('checks')) is not dict or set(cold['checks'])!=required
            or any(value is not True for value in cold['checks'].values())
            or cold.get('generation_sha256')!=[sha256(pins[compiler]).hexdigest()]*3
            or any(name not in sources for name in SOURCES)):
        raise ValueError('completed matching-source cold qualification required for native workspace pipeline')
    output.mkdir(mode=0o700)
    images={}
    for name,candidate in [('workspace','core-workspace-json'),('admission','core-admission'),('frontend','core-frontend')]:
        manifest=build_candidate(output/name,compiler,cold_report,candidate=candidate)
        metadata=json.loads(manifest.read_bytes());path=manifest.parent/metadata['image_path'];raw=path.read_bytes()
        if sha256(raw).hexdigest()!=metadata['image_sha256']:
            raise ValueError('native workspace pipeline component image changed')
        images[name]=(path,raw)
    packer,compile_receipt=compile_stage(output,'pipeline-packer',compiler,pins[ROOT/SOURCES[3]])
    images['packer']=(packer,packer.read_bytes());images['compiler']=(compiler,pins[compiler])
    parts=[images[name][1] for name in ('workspace','admission','frontend','compiler')]
    if any(not 0<len(raw)<=1<<20 for raw in parts):raise ValueError('component exceeds unchanged 1-MiB image profile')
    frame=struct.pack('<6Q',MAGIC,*(len(raw) for raw in parts),1)+b''.join(parts)
    if len(frame)>BUNDLE_LIMIT:raise ValueError('native application bundle exceeds explicit packer profile')
    native=NativeHiaJsonImage(images['packer'][1],sha256(images['packer'][1]).hexdigest())
    source=ctypes.create_string_buffer(frame,len(frame));arena=ctypes.create_string_buffer(BUNDLE_LIMIT)
    scratch=ctypes.create_string_buffer(1);size=native._entry(source,len(frame),arena,BUNDLE_LIMIT,scratch,0)
    if not 0<size<=BUNDLE_LIMIT:raise ValueError('native workspace pipeline packer refused frame')
    raw=ctypes.string_at(arena,size);inspection=inspect_executable(raw)
    if (any(path.read_bytes()!=before for path,before in pins.items()) or current_sources()!=sources
            or any(path.read_bytes()!=before for path,before in images.values())):
        raise ValueError('native workspace pipeline build custody changed')
    executable=output/'hia-workspace-compile'
    with executable.open('xb') as stream:stream.write(raw)
    executable.chmod(0o700)
    record={'schema':SCHEMA,'status':'NATIVE_WORKSPACE_PIPELINE_BUILT','profile':PROFILE,
        'source_manifest':sources,'source_sha256':{name:sha256(pins[ROOT/name]).hexdigest() for name in SOURCES},
        'executable_path':executable.name,'executable_sha256':sha256(raw).hexdigest(),'executable':inspection,
        'cold_report_sha256':sha256(pins[cold_report]).hexdigest(),
        'image_sha256':{name:sha256(data).hexdigest() for name,(_,data) in images.items()},
        'native_packer_compile_receipt':compile_receipt,'frame_sha256':sha256(frame).hexdigest(),
        'bundle_profile_bytes':BUNDLE_LIMIT,'compiler_and_qualification_child_caps_unchanged':True,
        'runtime_host_payload_decoder_materializer_renderer_or_semantic_checker_required':False,
        'host_authoring_build_filesystem_custody_and_installation':True,
        'Core_profile':'primitive v8; existing native compiler limits; ELF object only',
        'mandatory_complete_primitive_Core_admission':True,
        'whole_native_delivery_qualified':False,'production_activated':False}
    with (output/'build.json').open('x') as stream:json.dump(record,stream,indent=2,sort_keys=True);stream.write('\n')
    return executable


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('compiler','cold-report','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(build(args.output.resolve(),args.compiler.resolve(),args.cold_report.resolve()))


if __name__=='__main__':main()
