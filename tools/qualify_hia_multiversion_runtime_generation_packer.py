"""Thirty-role native packer differential and atomic bounds qualification."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,struct
from tools.qualify_hia_multiversion_components import Image
from tools.generate_hia_multiversion_runtime_generation_packer import ROLES,BRIDGE,reference_object
sha=lambda x:hashlib.sha256(x).hexdigest()
def packet(flats):return struct.pack('<8s31Q',b'HIAMVGK1',30,*map(len,flats))+b''.join(flats)
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    D=a.output;D.mkdir(parents=True,exist_ok=True);build=json.loads((a.directory/'build.json').read_text());flats=[Path(x['path']).read_bytes() for x in build['roles']]
    native=Image(a.directory/'multiversion_runtime_generation_packer.flat');rows=[]
    def check(label,raw,want,oc=None,wc=1024):
        expected=want if isinstance(want,bytes) else None;n=len(expected) if expected is not None else 4096
        o=C.create_string_buffer(n+64);C.memset(o,0xa5,len(o));w=C.create_string_buffer(max(1024,wc));s=C.create_string_buffer(raw)
        rc=native.entry(s,len(raw),o,len(o) if oc is None else oc,w,wc)
        assert s.raw==raw+b'\0',(label,'input changed')
        if expected is None:assert rc==want and o.raw==b'\xa5'*len(o),(label,rc,want)
        else:
            assert rc==len(expected) and o.raw[:rc]==expected and o.raw[rc:]==b'\xa5'*(len(o)-rc),(label,rc,len(expected))
        rows.append(dict(case=label,status=rc,input_bytes=len(raw),input_sha256=sha(raw),output_sha256=None if expected is None else sha(expected)));print('GENERATION_PACK_PASS',label,rc,flush=True)
    actual=packet(flats);obj=reference_object(flats);check('actual-all-thirty-roles',actual,obj)
    small=[b'\xc3']*30;short=packet(small);sobj=reference_object(small);check('all-minimum-one-byte',short,sobj)
    check('magic',b'INVALID!'+short[8:],0xffffffff);check('truncated-header',short[:255],0xffffffff);check('truncated-payload',short[:-1],0xffffffff);check('extra-byte',short+b'!',0xffffffff)
    for count in (0,29,31,(1<<64)-1):
        raw=bytearray(short);struct.pack_into('<Q',raw,8,count);check('role-count-'+str(count),bytes(raw),0xffffffff)
    for i in range(30):
        for size in (0,4194305,(1<<64)-1):
            raw=bytearray(short);struct.pack_into('<Q',raw,16+i*8,size);check('role-'+str(i)+'-size-'+str(size),bytes(raw),0xffffffff)
        fs=small.copy();fs[i]=b'Z'*4194304;check('role-'+str(i)+'-exact-four-MiB',packet(fs),reference_object(fs))
    check('short-work',short,0xfffffffe,wc=1023)
    check('short-output',short,0xfffffffe,oc=len(sobj)-1)
    check('exact-output',short,sobj,oc=len(sobj))
    # Full text budget, including every actual bridge and alignment byte.
    fs=small.copy();fs[0]=fs[1]=fs[2]=b'Z'*4194304
    at=(len(BRIDGE)+15)&-16
    for body in fs[:-1]:at=(at+len(body)+15)&-16
    fs[-1]=b'Q'*((1<<24)-at)
    expected=reference_object(fs);assert struct.unpack_from('<Q',expected,struct.unpack_from('<Q',expected,40)[0]+96)[0]==1<<24
    check('exact-original-sixteen-MiB-text',packet(fs),expected)
    fs[-1]+=b'Q';check('text-budget-plus-one',packet(fs),0xffffffff)
    report=dict(schema='hepta.hia.multiversion-runtime-generation-packer.v1',whole_native_runtime=False,passed=len(rows),failed=0,packer_sha256=native.pin['sha256'],actual_image_sha256=sha((a.directory/'generation-component.so').read_bytes()),cases=rows)
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('GENERATION_PACK_QUALIFIED',len(rows),flush=True)
if __name__=='__main__':main()
