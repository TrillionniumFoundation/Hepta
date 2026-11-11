"""Build the explicitly selected HIA-native Agent stdio executable.

The host driver binds custody/build receipts. At runtime the executable uses
only its three HIA images and fixed Linux syscall adapter, not this driver.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import (admit_cold_build, current_sources,
                                           build as build_frontend)
from tools.generate_hia_agent_stdio import MAGIC, LIMIT
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
DISPATCH = ROOT/'examples/hia_bootstrap/agent_stdio_dispatch.hiaasm'
PACKER = ROOT/'examples/hia_bootstrap/agent_stdio_packer.hiaasm'


def build(output: Path, compiler: Path, cold_report: Path, *, output_profile='flat'):
    if type(output_profile) is not str or output_profile not in ('flat','elf','exec'):
        raise ValueError('unknown Agent stdio output profile')
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources = {path: path.read_bytes() for path in
               (DISPATCH, PACKER, ROOT/'examples/hia_bootstrap/core_json_frontend.hiaasm')}
    admitted_sources = admit_cold_build(compiler_bytes, cold_bytes)
    if any(admitted_sources.get(path.relative_to(ROOT).as_posix()) != sha256(raw).hexdigest()
           for path, raw in sources.items()):
        raise ValueError('Agent build source differs from admitted cold source')
    output.mkdir(mode=0o700)
    frontend_manifest = build_frontend(output/'frontend', compiler, cold_report, candidate='core-frontend')
    frontend_manifest_bytes = frontend_manifest.read_bytes()
    metadata = json.loads(frontend_manifest_bytes)
    frontend = frontend_manifest.parent/metadata['image_path']
    dispatch, dispatch_receipt = compile_stage(output, 'agent-dispatch', compiler, sources[DISPATCH])
    packer, packer_receipt = compile_stage(output, 'agent-packer', compiler, sources[PACKER])
    packer_bytes = packer.read_bytes()
    dispatch_bytes, frontend_bytes = dispatch.read_bytes(), frontend.read_bytes()
    if sha256(frontend_bytes).hexdigest() != metadata['image_sha256']:
        raise ValueError('Agent frontend bytes changed')
    profile = ('flat','elf','exec').index(output_profile)
    frame = struct.pack('<5Q',MAGIC,len(dispatch_bytes),len(frontend_bytes),len(compiler_bytes),profile)
    frame += dispatch_bytes+frontend_bytes+compiler_bytes
    if len(frame)>LIMIT:
        raise ValueError('Agent images exceed unchanged packer frame limit')
    result, packed = invoke(output,'agent-pack',packer,frame)
    count = result.get('core_u32')
    if result.get('status')!='returned' or type(count) is not int or not 0<count<=LIMIT:
        raise ValueError('native HIA Agent packer rejected frame')
    raw = packed[:count]
    inspection = inspect_executable(raw)
    if (len(raw)!=count or compiler.read_bytes()!=compiler_bytes or cold_report.read_bytes()!=cold_bytes
            or any(path.read_bytes()!=data for path,data in sources.items())
            or dispatch.read_bytes()!=dispatch_bytes or frontend.read_bytes()!=frontend_bytes
            or packer.read_bytes()!=packer_bytes or frontend_manifest.read_bytes()!=frontend_manifest_bytes
            or current_sources()!=admitted_sources):
        raise ValueError('Agent build inputs changed')
    executable = output/'hia-native'
    executable.write_bytes(raw)
    executable.chmod(0o700)
    report = {
        'schema':'hepta.hia.agent-stdio-build.v1', 'status':'NATIVE_AGENT_STDIO_BUILT',
        'output_profile':output_profile, 'executable':inspection,
        'compiler_sha256':sha256(compiler_bytes).hexdigest(),
        'dispatch_sha256':sha256(dispatch_bytes).hexdigest(),
        'frontend_sha256':sha256(frontend_bytes).hexdigest(),
        'packer_sha256':sha256(packer_bytes).hexdigest(),
        'source_sha256':{path.relative_to(ROOT).as_posix():sha256(raw).hexdigest()
                         for path,raw in sources.items()},
        'cold_report_sha256':sha256(cold_bytes).hexdigest(),
        'frame_sha256':sha256(frame).hexdigest(),
        'dispatch_compile_receipt':dispatch_receipt,'packer_compile_receipt':packer_receipt,
        'pack_receipt':result, 'runtime_Python_or_host_payload_driver_required':False,
        'host_filesystem_build_and_custody_driver':True,
        'edit_and_persistence_implemented':False,'whole_native_delivery_qualified':False,
        'production_activated':False,
    }
    (output/'build.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return executable


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler',type=Path,required=True)
    parser.add_argument('--cold-report',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--output-profile',choices=('flat','elf','exec'),default='flat')
    args=parser.parse_args()
    print(build(args.output.resolve(),args.compiler.resolve(),args.cold_report.resolve(),
                output_profile=args.output_profile))


if __name__=='__main__':
    main()
