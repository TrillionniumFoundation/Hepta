"""Build an explicitly selected HIA workspace JSON transport after matching cold."""
import argparse,json
from hashlib import sha256
from pathlib import Path
from tools.build_hia_json_preflight import build as build_kernel
from tools.generate_hia_core_workspace_facts_cli import MAGIC
from tools.qualify_hia_selfhost import compile_stage,invoke
from tools.qualify_hia_selfhost_cli import inspect_executable
from tools.hia_selfhost_contract import CONTRACT_PATH,PROFILE,validate_contract
import struct
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'examples/hia_bootstrap/core_workspace_facts.hiaasm'
PACKER=ROOT/'examples/hia_bootstrap/core_workspace_facts_packer.hiaasm'


def build(output,compiler,cold_report):
    inputs={p:p.read_bytes() for p in (compiler,cold_report,SOURCE,PACKER)}
    qualification=json.loads(inputs[cold_report]);contract=validate_contract()
    expected={**contract['source_identity']['files'],CONTRACT_PATH:sha256((ROOT/CONTRACT_PATH).read_bytes()).hexdigest()}
    if (type(qualification) is not dict or qualification.get('status')!='COLD_SELFHOST_REPLAY_PASS'
            or qualification.get('profile')!=PROFILE or qualification.get('source_manifest')!=expected
            or str(SOURCE.relative_to(ROOT)) not in expected or str(PACKER.relative_to(ROOT)) not in expected):
        raise ValueError('completed matching-source cold qualification required for workspace JSON')
    output.mkdir(mode=0o700)
    manifest=build_kernel(output/'kernel',compiler,cold_report,candidate='core-workspace-facts')
    metadata=json.loads(manifest.read_bytes());image=manifest.parent/metadata['image_path'];application=image.read_bytes()
    if sha256(application).hexdigest()!=metadata['image_sha256']:
        raise ValueError('workspace JSON kernel image changed')
    packer,compiled=compile_stage(output,'workspace-json-packer',compiler,inputs[PACKER])
    packed,arena=invoke(output,'workspace-json-pack',packer,struct.pack('<QQ',MAGIC,len(application))+application)
    size=packed['core_u32']
    if not 0<size<=1<<20:
        raise ValueError('workspace JSON native packer refused image')
    executable=arena[:size];inspection=inspect_executable(executable)
    if (any(p.read_bytes()!=b for p,b in inputs.items()) or image.read_bytes()!=application
            or validate_contract()['source_identity']['files']!=contract['source_identity']['files']):
        raise ValueError('workspace JSON build inputs changed')
    target=output/'hia-workspace-json';target.write_bytes(executable);target.chmod(0o700)
    (output/'build.json').write_text(json.dumps({'schema':'hepta.hia.core-workspace-facts-cli-build.v1',
        'status':'NATIVE_WORKSPACE_JSON_FACT_TRANSPORT_BUILT','executable':inspection,
        'executable_sha256':sha256(executable).hexdigest(),
        'input_sha256':{str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else p.name:sha256(b).hexdigest() for p,b in inputs.items()},
        'kernel_image_sha256':sha256(application).hexdigest(),'native_packer_compile_receipt':compiled,
        'native_pack_receipt':packed,'runtime_foreign_JSON_decoder_required':False,
        'facts_grant_Core_or_module_policy_admission':False,'host_build_custody':True,
        'whole_native_workspace_qualified':False,'production_activated':False},indent=2,sort_keys=True)+'\n')
    return target


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--compiler',type=Path,required=True)
    p.add_argument('--cold-report',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(build(a.output.resolve(),a.compiler.resolve(),a.cold_report.resolve()))


if __name__=='__main__':
    main()
