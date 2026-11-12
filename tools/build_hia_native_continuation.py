"""Cold-admitted HIA scheduling plus complete execution-ledger image bundle.

Object effects remain hosted. The new packer has its own aggregate transport;
neither the compiler nor the existing byte-observer caps are changed.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
SCHEMA='hepta.hia.native-continuation.v1'
INPROCESS_SCHEMA='hepta.hia.native-continuation-inprocess.v1'


def _checked_pack_result(receipt, output, *, image, source, capacity, transport):
    """Admit actual bounded bytes before publishing either native transport."""
    if (type(receipt) is not dict or type(output) is not bytes
            or type(image) is not bytes or not 0 < len(image) <= 1 << 20
            or type(source) is not bytes or not 0 < len(source) <= 64 << 20
            or type(capacity) is not int or not 0 < capacity <= 64 << 20
            or len(output) != capacity or type(transport) is not str
            or transport not in ('subprocess', 'inprocess')):
        raise ValueError('native continuation pack transport differs')
    if (receipt.get('status') != 'returned'
            or type(receipt.get('result_u64')) is not int
            or type(receipt.get('core_u32')) is not int
            or type(receipt.get('abi_status')) is not int or receipt['abi_status'] != 0
            or not 176 < receipt['core_u32'] <= min(capacity, len(output))
            or receipt['result_u64'] != receipt['core_u32']
            or receipt.get('image_sha256') != sha256(image).hexdigest()
            or receipt.get('source_sha256') != sha256(source).hexdigest()
            or receipt.get('input_sha256') != sha256(source).hexdigest()
            or type(receipt.get('input_bytes')) is not int
            or receipt['input_bytes'] != len(source)
            or receipt.get('output_sha256') != sha256(output).hexdigest()
            or any(receipt.get(k) is not True for k in (
                'source_unchanged', 'buffer_redzones_unchanged',
                'output_tail_unchanged', 'input_pages_read_only'))
            or type(receipt.get('forbidden_compiler_modules_loaded')) is not list
            or receipt['forbidden_compiler_modules_loaded'] != []):
        raise ValueError('native continuation native pack receipt differs')
    executable = output[:receipt['core_u32']]
    if transport == 'inprocess':
        header = bytearray(176)
        header[:8] = b'HIAINP01'
        struct.pack_into('<2Q', header, 8, 1, 176)
        struct.pack_into('<2Q', header, 96, len(executable), len(executable))
        if executable[:176] != header:
            raise ValueError('native continuation packed container extent differs')
    else:
        from tools.qualify_hia_selfhost_cli import inspect_executable
        inspect_executable(executable)
    return executable


def pack_input(policy,pool,units,abi):
    modes=sorted(abi['modes'].values(),key=lambda x:x['number'])
    words=(int.from_bytes(b'HIACTPK1','little'),len(policy),len(units),abi['workspace_bytes'],
        abi['output_bytes'],abi['pool_bytes'],abi['literal_count'],len(modes),len(pool))
    return struct.pack('<9Q',*words)+struct.pack('<'+'Q'*len(units),*(len(x) for x in units))+b''.join(struct.pack('<QQ',x['number'],x['arity']) for x in modes)+policy+pool+b''.join(units)


def build(output:Path,compiler:Path,cold_report:Path,*,in_process=False,kind='execution-observation')->Path:
    from hepta.hia_agent_contract import CONTINUATION_BUILD_FILES
    from importlib import import_module
    families={'execution-observation':'execution_observation','core-lowering':'core_lowering',
        'core-emitter':'core_emitter','byte-wrapper':'byte_wrapper','machine-object':'machine_object'}
    if type(kind) is not str or kind not in families or (not in_process and kind!='execution-observation'):
        raise ValueError('native continuation family or transport differs')
    family=families[kind];selection=import_module('hepta.hia_'+family+'_selection')
    ABI_SOURCE,checked_abi=selection.ABI_SOURCE,selection.checked_abi
    from tools.build_hia_json_preflight import admit_cold_build,current_sources
    build_policy=import_module('tools.build_hia_'+family).build
    from tools.qualify_hia_selfhost import compile_stage
    compiler_raw=compiler.read_bytes();cold_raw=cold_report.read_bytes()
    sources=admit_cold_build(compiler_raw,cold_raw)
    abi_raw=(ROOT/ABI_SOURCE).read_bytes();abi=checked_abi(abi_raw)
    names=(family+'_pool',*abi['units'])
    needed=(*CONTINUATION_BUILD_FILES,ABI_SOURCE,*(('examples/hia_bootstrap/'+name+'.hepta') for name in names),
        'tools/build_hia_native_continuation.py','tools/hia_continuation_pack_child.py',
        'hepta/hia_native_continuation.py','hepta/hia_native_continuation_selection.py',
        'hepta/hia_native_continuation_inprocess.py','hepta/hia_native_helpers.py','hepta/hia_core_lowering_native.py')
    inputs={name:(ROOT/name).read_bytes() for name in needed}
    for name,raw in inputs.items():
        if sources.get(name)!=sha256(raw).hexdigest():raise ValueError('continuation source differs from admitted cold: '+name)
    output.mkdir(mode=0o700)
    policy_manifest=build_policy(output/'policy',compiler,cold_report)
    base_raw=policy_manifest.read_bytes();base=json.loads(base_raw);images=[];pins=[(policy_manifest,base_raw)]
    for name in names:
        path=policy_manifest.parent/base['unit_manifests'][name];row=json.loads(path.read_bytes())
        image=path.parent/row['image_path'];raw=image.read_bytes()
        if sha256(raw).hexdigest()!=row['image_sha256']:raise ValueError('continuation policy image changed')
        images.append(raw);pins.extend(((path,path.read_bytes()),(image,raw)))
    generated={};receipts=[]
    for name in ('continuation_policy','continuation_packer','continuation_inprocess_packer'):
        folder=output/name;folder.mkdir(mode=0o700)
        image,receipt=compile_stage(folder,name,compiler,inputs['examples/hia_bootstrap/'+name+'.hepta'])
        generated[name]=(image,image.read_bytes());receipts.append(receipt)
    raw=pack_input(generated['continuation_policy'][1],images[0],images[1:],abi)
    source=output/'pack.input';source.write_bytes(raw)
    manifests={};pack_receipts=[]
    for transport,packer,target_name,schema in (
            ('subprocess','continuation_packer','continuation.native',SCHEMA),
            ('inprocess','continuation_inprocess_packer','continuation.image.bin',INPROCESS_SCHEMA)):
        if kind!='execution-observation' and transport!='inprocess':continue
        packed=output/(transport+'.pack.output')
        request=dict(image=str(generated[packer][0]),image_sha256=sha256(generated[packer][1]).hexdigest(),source=str(source),source_sha256=sha256(raw).hexdigest(),capacity=64<<20,output=str(packed))
        request_path=output/(transport+'.pack.request.json');request_path.write_text(json.dumps(request,sort_keys=True)+'\n')
        stdout_path=output/(transport+'.pack.stdout.log')
        with stdout_path.open('xb') as stdout,(output/(transport+'.pack.stderr.log')).open('xb') as stderr:
            result=subprocess.run([sys.executable,'-B','-E','-s',str(ROOT/'tools/hia_continuation_pack_child.py'),str(request_path)],env={'PATH':''},stdout=stdout,stderr=stderr,timeout=20)
        if result.returncode:raise ValueError('bounded HIA continuation packer refused; raw evidence retained')
        receipt=json.loads(stdout_path.read_bytes());all_output=packed.read_bytes()
        executable=_checked_pack_result(receipt,all_output,image=generated[packer][1],source=raw,capacity=request['capacity'],transport=transport)
        if (compiler.read_bytes()!=compiler_raw or cold_report.read_bytes()!=cold_raw or current_sources()!=sources
                or any((ROOT/name).read_bytes()!=value for name,value in inputs.items())
                or any(path.read_bytes()!=value for path,value in (*pins,*generated.values()))
                or source.read_bytes()!=raw):raise ValueError('continuation build inputs changed')
        target=output/target_name
        with target.open('xb') as f:f.write(executable)
        target.chmod(0o400 if transport=='inprocess' else 0o500)
        manifest=dict(schema=schema,kind=kind,policy_bundle='policy/manifest.json',
            policy_bundle_sha256=sha256(policy_manifest.read_bytes()).hexdigest(),compiler_sha256=sha256(compiler_raw).hexdigest(),
            image_path=target.name,image_sha256=sha256(executable).hexdigest(),
            resource_sha256={name:sha256(inputs[name]).hexdigest() for name in CONTINUATION_BUILD_FILES},
            runtime_sha256={name:sha256(inputs[name]).hexdigest() for name in
                ('hepta/hia_native_continuation.py','hepta/hia_native_continuation_selection.py','hepta/hia_native_continuation_inprocess.py','hepta/hia_native_helpers.py','hepta/hia_core_lowering_native.py')})
        path=output/('inprocess-manifest.json' if transport=='inprocess' else 'manifest.json')
        with path.open('xb') as f:f.write((json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode())
        manifests[transport]=path;pack_receipts.append(dict(transport=transport,receipt=receipt))
    with (output/'build.json').open('xb') as f:f.write((json.dumps(dict(status='NATIVE_CONTINUATION_BUILT',source_manifest=sources,cold_report_sha256=sha256(cold_raw).hexdigest(),native_compile_receipts=receipts,native_pack_receipts=pack_receipts,whole_native_delivery_qualified=False),sort_keys=True,indent=2)+'\n').encode())
    return manifests['inprocess' if in_process else 'subprocess']


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('output','compiler','cold-report'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--in-process',action='store_true')
    parser.add_argument('--kind',default='execution-observation',choices=('execution-observation','core-lowering','core-emitter','byte-wrapper','machine-object'))
    args=parser.parse_args();print(build(args.output.resolve(),args.compiler.resolve(),args.cold_report.resolve(),in_process=args.in_process,kind=args.kind))
