"""Build a syscall-only HIA ELF linker from an admitted cold native compiler.

Only custody, file operations and build receipts are host-owned. Object parsing,
resolution, relocations, ELF layout and CLI packing execute in the HIA images.
The produced stdin/stdout application has no Python or external linker runtime.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
from tools.build_hia_json_preflight import (admit_cold_build, current_sources,
                                           build as build_application)
from tools.generate_hia_native_filter import MAGIC
from tools.qualify_hia_selfhost import invoke
from tools.qualify_hia_selfhost_cli import inspect_executable
ROOT=Path(__file__).resolve().parents[1]


def build(output:Path,compiler:Path,cold_report:Path)->Path:
    pins={p:p.read_bytes() for p in (compiler,cold_report,
        ROOT/'examples/hia_bootstrap/elf_static_linker.hiaasm',
        ROOT/'examples/hia_bootstrap/native_filter_packer.hiaasm')}
    admitted_sources=admit_cold_build(pins[compiler],pins[cold_report])
    output.mkdir(mode=0o700)
    manifests={name:build_application(output/name,compiler,cold_report,candidate=name)
               for name in ('elf-linker','native-filter')}
    applications={}
    for name,path in manifests.items():
        manifest=json.loads(path.read_bytes());image=path.parent/manifest['image_path']
        applications[name]=(image,image.read_bytes(),manifest)
    image,raw,manifest=applications['elf-linker']
    frame=struct.pack('<2Q',MAGIC,len(raw))+raw
    receipt,packed=invoke(output,'native-pack',applications['native-filter'][0],frame)
    size=receipt['core_u32']
    if not 0<size<=1048576 or size>len(packed):
        raise ValueError('native filter packer refused the linker image')
    executable_raw=packed[:size];inspection=inspect_executable(executable_raw)
    if (any(p.read_bytes()!=before for p,before in pins.items())
            or current_sources()!=admitted_sources):
        raise ValueError('native linker build input changed')
    for p,raw,metadata in applications.values():
        if p.read_bytes()!=raw or sha256(raw).hexdigest()!=metadata['image_sha256']:
            raise ValueError('native application build image changed')
    executable=output/'hia-elf-link'
    executable.write_bytes(executable_raw);executable.chmod(0o700)
    record={'schema':'hepta.hia.elf-static-linker-build.v1','status':'NATIVE_ELF_LINKER_BUILT',
        'executable':inspection,'compiler_sha256':sha256(pins[compiler]).hexdigest(),
        'cold_report_sha256':sha256(pins[cold_report]).hexdigest(),
        'applications':{name:metadata for name,(_,_,metadata) in applications.items()},
        'native_pack_receipt':receipt,'frame_sha256':sha256(frame).hexdigest(),
        'runtime_Python_or_external_linker_required':False,
        'host_filesystem_build_and_evidence_driver':True,
        'default_backend_switched':False,'whole_production_linker_replaced':False,
        'whole_stack_rewritten_in_hia':False}
    (output/'build.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    return executable


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler',type=Path,required=True)
    p.add_argument('--cold-report',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();print(build(args.output.resolve(),args.compiler.resolve(),args.cold_report.resolve()))
if __name__=='__main__':main()
