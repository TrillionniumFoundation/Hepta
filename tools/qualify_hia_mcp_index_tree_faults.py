"""Actual native refusals for malformed disk pages and explicit I/O faults."""
from __future__ import annotations
import argparse
import ctypes
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import struct

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.qualify_hia_mcp_index_tree import Observer, record, STATE, MASK


def qualify(image_path, output):
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    raw=image_path.read_bytes();image=NativeHiaJsonImage(raw,sha256(raw).hexdigest())
    report={'schema':'hia.native.index-page-fault-controls.v1','passed':False,
            'native_image_sha256':sha256(raw).hexdigest(),'observer_sha256':sha256(Path(__file__).read_bytes()).hexdigest(),
            'checks':[],'counts':{'calls':0,'raw_bytes':0,'reads':0,'writes':0},
            'fault_return_values_are_explicit_injections':True,'public_integration_qualified':False}
    stream=gzip.open(output/'native-observations.bin.gz','wb',compresslevel=6)
    def check(name,value):
        assert value,name
        report['checks'].append({'case':name,'passed':True})
    base=Observer(image,output/'baseline.pages',stream,report['counts'])
    try:
        base.call(0);base.call(3)
        for n in range(20):base.call(2,record(n,state=1,elapsed=n))
        base.call(4);disk=base.path.read_bytes();base.close()
        root=struct.unpack_from('<Q',disk,16)[0]
        left=struct.unpack_from('<Q',disk,root*4096+64)[0]
        right=struct.unpack_from('<Q',disk,root*4096+136)[0]
        mutations=[('header-magic',0,b'BROKEN!!',True),('header-version',8,struct.pack('<Q',2),True),
                   ('header-root-zero',16,bytes(8),True),('header-next-bound',24,struct.pack('<Q',1<<51),True),
                   ('header-reserved',48,b'\1',True),('node-magic',root*4096,b'BROKEN!!',False),
                   ('node-kind',root*4096+8,struct.pack('<Q',3),False),('node-count',root*4096+16,struct.pack('<Q',56),False),
                   ('node-reserved',root*4096+24,b'\1',False),('child-zero',root*4096+64,bytes(8),False),
                   ('child-self-cycle',root*4096+64,struct.pack('<Q',root),False),
                   ('child-outside-key-range',root*4096+64,struct.pack('<Q',right),False),
                   ('leaf-count',left*4096+16,struct.pack('<Q',11),False),
                   ('leaf-id-nonhex',left*4096+64,b'G',False),('leaf-owner-nonhex',left*4096+128,b'G',False),
                   ('leaf-invalid-terminal',left*4096+64+200,struct.pack('<Q',3),False),
                   ('leaf-unused-byte',left*4096+4095,b'\1',False)]
        for label,at,patch,header in mutations:
            obs=Observer(image,output/(label+'.pages'),stream,report['counts'])
            try:
                changed=bytearray(disk);changed[at:at+len(patch)]=patch
                assert os.pwrite(obs.fd,changed,0)==len(changed)
                words,_=obs.call(0)
                if not header:
                    assert words[:2]==(0,0)
                    words,_=obs.call(1,f'{0:064x}'.encode())
                check(label,words[:2]==(3,2))
            finally:obs.close()
        for errno in (5,4,11):
            obs=Observer(image,output/f'read-minus-{errno}.pages',stream,report['counts'])
            try:
                words,_=obs.call(0,fault=lambda kind,page,n,b:(-errno,b'') if kind=='read' else (n,b))
                check('native-plan-rejects-unhandled-negative-read-'+str(errno),words[:2]==(3,2))
            finally:obs.close()
        for size in (0,1,4095,MASK-4):
            obs=Observer(image,output/f'write-result-{size}.pages',stream,report['counts'])
            try:
                words,_=obs.call(0,fault=lambda kind,page,n,b:(size,b) if kind=='write' else (n,b))
                check('native-plan-rejects-incomplete-write-'+str(size),words[:2]==(3,2))
            finally:obs.close()
        obs=Observer(image,output/'rollback-refused-cohort.pages',stream,report['counts'])
        try:
            os.pwrite(obs.fd,disk,0);obs.call(0);obs.call(3)
            words,_=obs.call(2,record(0,owner='b'*64,state=1,elapsed=0))
            assert words[:2]==(3,3)
            words,_=obs.call(5);check('owner-can-discard-refused-private-cohort',words[:2]==(0,0))
            words,found=obs.call(1,f'{0:064x}'.encode())
            check('refusal-rollback-retains-committed-record',words[:2]==(0,1) and found==record(0,state=1,elapsed=0))
            check('refusal-rollback-never-changes-old-file',obs.path.read_bytes()==disk)
        finally:obs.close()
        for name,input_size,capacity,workspace_size in [('short-input',63,4160,STATE),('short-output',64,4159,STATE),('short-workspace',64,4160,STATE-1)]:
            source=ctypes.create_string_buffer(bytes(64));out=ctypes.create_string_buffer(b'\xa7'*4192)
            workspace=ctypes.create_string_buffer(b'\xa5'*(STATE+64))
            result=image._entry(source,input_size,out,capacity,ctypes.addressof(workspace)+32,workspace_size)
            check(name+'-refuses-before-any-write',result==4294967295 and out.raw[:4192]==b'\xa7'*4192 and workspace.raw[:STATE+64]==b'\xa5'*(STATE+64))
            report.setdefault('boundary_observations',[]).append({'case':name,'source_length':input_size,'output_capacity':capacity,'workspace_length':workspace_size,'returncode':result,'complete_output_sha256':sha256(out.raw).hexdigest(),'complete_workspace_sha256':sha256(workspace.raw).hexdigest()})
        report['passed']=True
    except BaseException as error:
        report['error']=repr(error);raise
    finally:
        base.close();stream.close()
        report['files']=[{'path':p.name,'bytes':p.stat().st_size,'sha256':sha256(p.read_bytes()).hexdigest()} for p in sorted(output.iterdir()) if p.is_file()]
        (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'passed':report['passed'],'checks':len(report['checks']),'error':report.get('error')}),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    qualify(a.image,a.output)
