"""Fixed four-role native number-owner packaging guards."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,struct
from tools import generate_hia_multiversion_runtime_identity_packer as p
from tools.qualify_hia_multiversion_components import Image
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--directory',type=Path,required=True);a=ap.parse_args();D=a.directory
    image=Image(D/'multiversion_runtime_identity_packer.flat');cases=[]
    def run(name,request,want=None,size=None):
        expected=p.reference_object(want) if want is not None else None
        nout=(len(expected) if size is None else size) if expected is not None else (1048576 if size is None else size)
        o=C.create_string_buffer(max(1,nout));C.memset(o,0xa5,len(o));w=C.create_string_buffer(1048576);before=o.raw
        rc=image(request,o,w,output_bytes=nout) if False else image(request,o,w)
        if expected is None:assert rc>=0xfffffff0 and o.raw==before,(name,rc)
        elif size is None:assert rc==len(expected) and o.raw[:rc]==expected,(name,rc,len(expected))
        else:assert rc>=0xfffffff0 and o.raw==before,(name,rc)
        cases.append({'case':name,'returncode':rc,'output_bytes':nout})
    def wire(parts):return struct.pack('<8s5Q',b'HIAMVIP1',4,*map(len,parts))+b''.join(parts)
    rows=json.loads((D/'build.json').read_text())['roles'];parts=[Path(row['path']).read_bytes() for row in rows]
    run('actual-four-role-object',wire(parts),parts)
    for i in range(4):
        for n in [1,4194304]:
            ps=[b'\xc3']*4;ps[i]=b'\x90'*(n-1)+b'\xc3';run(f'role-{i}-extent-{n}',wire(ps),ps)
        for n in [0,4194305,(1<<64)-1]:
            raw=bytearray(wire([b'\xc3']*4));struct.pack_into('<Q',raw,16+8*i,n);run(f'role-{i}-bad-extent-{n}',bytes(raw))
    good=wire([b'\xc3']*4);expect=p.reference_object([b'\xc3']*4)
    run('short-output',good,[b'\xc3']*4,size=len(expect)-1)
    for n in [0,7,8,15,16,47,len(good)-1]:run(f'truncated-{n}',good[:n])
    for at,n in [(0,0),(8,0),(8,2),(8,5),(8,(1<<64)-1)]:
        bad=bytearray(good);struct.pack_into('<Q',bad,at,n);run(f'header-{at}-{n}',bytes(bad))
    run('trailing-byte',good+b'X')
    run('combined-text-over-sixteen-MiB',wire([b'\x90'*4194304]*4))
    report={'schema':'hepta.hia.multiversion-runtime-identity-packer.v1','whole_native_runtime':False,'passed':len(cases),'failed':0,'packer':image.pin,'cases':cases}
    (D/'packer-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('RUNTIME_IDENTITY_PACK_PASS',len(cases),flush=True)
if __name__=='__main__':main()
