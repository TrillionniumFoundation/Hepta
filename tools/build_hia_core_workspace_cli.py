"""Build explicitly selected native primitive workspace-to-ELF filter.

Trusted hosted build custody only; runtime payload materialization and semantic
compilation are HIA. General Core/nominal/runtime/install closure remains open.
"""
import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_json_preflight import (admit_cold_build, current_sources,
                                           build as build_kernel)
from tools.generate_hia_core_workspace_cli import MAGIC,BUNDLE_LIMIT
from tools.hia_selfhost_contract import CONTRACT_PATH,PROFILE,validate_contract
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'examples/hia_bootstrap/core_workspace_materialize.hiaasm'
PACKER=ROOT/'examples/hia_bootstrap/core_workspace_cli_packer.hiaasm'


def build(output,compiler,cold_report):
    inputs={p:p.read_bytes() for p in (compiler,cold_report,SOURCE,PACKER)}
    qualification=json.loads(inputs[cold_report]);contract=validate_contract()
    expected={**contract['source_identity']['files'],CONTRACT_PATH:sha256((ROOT/CONTRACT_PATH).read_bytes()).hexdigest()}
    if (type(qualification) is not dict or qualification.get('status')!='COLD_SELFHOST_REPLAY_PASS'
            or qualification.get('profile')!=PROFILE or qualification.get('source_manifest')!=expected
            or str(SOURCE.relative_to(ROOT)) not in expected or str(PACKER.relative_to(ROOT)) not in expected):
        raise ValueError('completed matching-source cold qualification required for native workspace')
    admitted_sources=admit_cold_build(inputs[compiler],inputs[cold_report])
    output.mkdir(mode=0o700)
    manifest=build_kernel(output/'materializer',compiler,cold_report,candidate='core-workspace-materialize')
    metadata=json.loads(manifest.read_bytes());image=manifest.parent/metadata['image_path'];application=image.read_bytes()
    if sha256(application).hexdigest()!=metadata['image_sha256']:raise ValueError('workspace materializer image changed')
    packer,compiled=compile_stage(output,'workspace-CLI-packer',compiler,inputs[PACKER])
    frame=struct.pack('<4Q',MAGIC,len(application),len(inputs[compiler]),1)+application+inputs[compiler]
    if len(frame)>BUNDLE_LIMIT:raise ValueError('workspace application bundle exceeds 2 MiB')
    # This separate trusted application packs two <=1-MiB images. It does not
    # broaden the existing 1-MiB compiler/qualification-child buffer profile.
    native=NativeHiaJsonImage(packer.read_bytes(),sha256(packer.read_bytes()).hexdigest())
    source=ctypes.create_string_buffer(frame,len(frame));arena=ctypes.create_string_buffer(BUNDLE_LIMIT)
    scratch=ctypes.create_string_buffer(1)
    size=native._entry(source,len(frame),arena,BUNDLE_LIMIT,scratch,1)
    if not 0<size<=BUNDLE_LIMIT:raise ValueError('native workspace packer refused image bundle')
    executable=ctypes.string_at(arena,size);inspection=inspect_executable(executable)
    if (any(p.read_bytes()!=b for p,b in inputs.items()) or image.read_bytes()!=application
            or current_sources()!=admitted_sources):
        raise ValueError('native workspace build inputs changed')
    target=output/'hia-workspace-elf';target.write_bytes(executable);target.chmod(0o700)
    (output/'build.json').write_text(json.dumps({'schema':'hepta.hia.core-workspace-cli-build.v1',
        'status':'NATIVE_WORKSPACE_ELF_FILTER_BUILT','output_profile':'elf-only',
        'executable':inspection,'executable_sha256':sha256(executable).hexdigest(),
        'input_sha256':{str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else p.name:sha256(b).hexdigest() for p,b in inputs.items()},
        'materializer_image_sha256':sha256(application).hexdigest(),'packer_image_sha256':sha256(packer.read_bytes()).hexdigest(),
        'native_packer_compile_receipt':compiled,'frame_sha256':sha256(frame).hexdigest(),
        'bundle_profile_bytes':BUNDLE_LIMIT,'compiler_source_output_workspace_caps_unchanged':True,
        'trusted_in_process_build_packer':True,'runtime_foreign_payload_driver_or_second_executable_required':False,
        'semantic_acceptance':'existing mandatory native HIA compiler; representation success alone grants nothing',
        'host_build_custody_and_installation':True,'whole_native_workspace_qualified':False,
        'production_activated':False},indent=2,sort_keys=True)+'\n')
    return target


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--compiler',type=Path,required=True)
    p.add_argument('--cold-report',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(build(a.output.resolve(),a.compiler.resolve(),a.cold_report.resolve()))


if __name__=='__main__':main()
