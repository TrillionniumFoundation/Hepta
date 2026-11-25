"""Fixed three-role native number-owner packaging guards."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,struct
from tools import generate_hia_multiversion_runtime_numbers_packer as p
from tools.qualify_hia_multiversion_components import Image
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--directory',type=Path,required=True);a=ap.parse_args();D=a.directory
    image=Image(D/'multiversion_runtime_numbers_packer.flat');cases=[]
    def run(name,request,want=None,size=None):
        expected=p.reference_object(want) if want is not None else None
        nout=(len(expected) if size is None else size) if expected is not None else (1048576 if size is None else size)
        o=C.create_string_buffer(max(1,nout));C.memset(o,0xa5,len(o));w=C.create_string_buffer(1048576);before=o.raw
        rc=image(request,o,w,output_bytes=nout) if False else image(request,o,w)
        if expected is None:assert rc>=0xfffffff0 and o.raw==before,(name,rc)
        elif size is None:assert rc==len(expected) and o.raw[:rc]==expected,(name,rc,len(expected))
        else:assert rc>=0xfffffff0 and o.raw==before,(name,rc)
        cases.append({'case':name,'returncode':rc,'output_bytes':nout})
    def wire(parts):return struct.pack('<8s4Q',b'HIAMVNP2',3,*map(len,parts))+b''.join(parts)
    parts=[(D/'multiversion_runtime_numbers.flat').read_bytes(),Path(D.parent/'native-multiversion-values-v1/multiversion_values.flat').read_bytes(),Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/root-proof/unsigned-decimal-f07aca.flat').read_bytes()]
    run('actual-three-role-object',wire(parts),parts)
    for i in range(3):
        for n in [1,4194304]:
            ps=[b'\xc3']*3;ps[i]=b'\x90'*(n-1)+b'\xc3';run(f'role-{i}-extent-{n}',wire(ps),ps)
        for n in [0,4194305,(1<<64)-1]:
            raw=bytearray(wire([b'\xc3']*3));struct.pack_into('<Q',raw,16+8*i,n);run(f'role-{i}-bad-extent-{n}',bytes(raw))
    good=wire([b'\xc3']*3);expect=p.reference_object([b'\xc3']*3)
    run('short-output',good,[b'\xc3']*3,size=len(expect)-1)
    for n in [0,7,8,15,16,39,len(good)-1]:run(f'truncated-{n}',good[:n])
    for at,n in [(0,0),(8,0),(8,2),(8,4),(8,(1<<64)-1)]:
        bad=bytearray(good);struct.pack_into('<Q',bad,at,n);run(f'header-{at}-{n}',bytes(bad))
    run('trailing-byte',good+b'X')
    report={'schema':'hepta.hia.multiversion-runtime-numbers-packer.v1','whole_native_runtime':False,'passed':len(cases),'failed':0,'packer':image.pin,'cases':cases}
    (D/'packer-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('RUNTIME_NUMBERS_PACK_PASS',len(cases),flush=True)
if __name__=='__main__':main()
