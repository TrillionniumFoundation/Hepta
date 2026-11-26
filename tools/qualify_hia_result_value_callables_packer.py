"""Exercise the actual fourteen-role packer's bounds and unchanged text limit."""
from pathlib import Path
import argparse, ctypes as C, hashlib, json, struct
from tools.qualify_hia_multiversion_components import Image
from tools import generate_hia_result_value_callables_packer as pack

def pin(data):return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--build',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    receipt=json.loads((args.build/'build.json').read_bytes())
    names=[r['role']for r in receipt['roles']]
    assert names[-1]=='result_value_callables_packer' and len(names)==15
    flats=[]
    for row in receipt['roles']:
        raw=(args.build/(row['role']+'.flat')).read_bytes()
        assert pin(raw)=={k:row[k]for k in('bytes','sha256')}
        flats.append(raw)
    native=Image(args.build/'result_value_callables_packer.flat')
    pieces=flats[:-1];rows=[]
    def request(mode=1,parts=pieces):
        return struct.pack('<8s16Q',b'HIABVP07',14,*map(len,parts),mode)+b''.join(parts)
    def invoke(raw,on,want,wn=512,expected=None):
        src=C.create_string_buffer(raw);out=C.create_string_buffer(b'\xa5'*(on+64))
        work=C.create_string_buffer(b'\x5a'*(wn+64))
        rc=native.entry(src,len(raw),out,on,work,wn)
        assert rc==want,(rc,want)
        assert src.raw==raw+b'\0' and out.raw[on:]==b'\xa5'*64+b'\0'
        assert work.raw[wn:]==b'\x5a'*64+b'\0'
        if expected is not None:assert out.raw[:on]==expected
        else:assert out.raw[:on]==b'\xa5'*on
    for mode in(0,1):
        expected=pack.reference_object(pieces)if mode==0 else pack.reference_flat(pieces)
        invoke(request(mode),len(expected),len(expected),expected=expected)
        invoke(request(mode),len(expected)-1,0xfffffffe)
        rows.append(dict(case='native-valid-and-short-output',mode=mode,bytes=len(expected)))
    base=request()
    invalid=[]
    for at,value in((0,0),(8,0),(8,13),(8,15),(128,2),(128,(1<<64)-1)):
        raw=bytearray(base);struct.pack_into('<Q',raw,at,value);invalid.append(bytes(raw))
    for i in range(14):
        for length in(0,4194305,(1<<64)-1):
            raw=bytearray(base);struct.pack_into('<Q',raw,16+i*8,length);invalid.append(bytes(raw))
    invalid.extend((base[:127],base[:135],base[:-1],base+b'\0'))
    for raw in invalid:invoke(raw,64,0xffffffff)
    rows.append(dict(case='native-magic-role-count-mode-length-and-trailing-data-controls',cases=len(invalid)))
    invoke(base,64,0xfffffffe,wn=511)
    rows.append(dict(case='native-workspace-boundary'))
    oversized=[b'x'*4194304]*4+[b'x']*10
    wire=request(parts=oversized)
    try:pack.reference_flat(oversized)
    except ValueError as exc:assert str(exc)=='preserved text domain'
    else:raise AssertionError('reference accepted text larger than 16 MiB')
    invoke(wire,64,0xffffffff)
    rows.append(dict(case='native-preserved-sixteen-MiB-text-boundary',input_bytes=len(wire)))
    report=dict(schema='hia.native-value-fourteen-role-packer.qualification.v1',passed=True,
                packer=pin(flats[-1]),bridge=pin(pack.BRIDGE),cases=rows,
                maximum_role_bytes=4194304,maximum_text_bytes=16777216,
                original_limits_unchanged=True)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,groups=len(rows),invalid=len(invalid))),flush=True)

if __name__=='__main__':main()
