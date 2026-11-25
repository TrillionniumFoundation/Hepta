"""Compare every generated probe vector against the frozen original helper."""
from pathlib import Path
import argparse,ctypes,json,random,struct
from tools.qualify_hia_multiversion_components import Image,put,get,sha
from tools.generate_hia_multiversion_abi import TYPES
from hepta.hia_multiversion import ScalarABI,_probe_vectors
ROOT=Path(__file__).resolve().parents[1];U64=(1<<64)-1
def frame(types,name='probe'):
    row=bytearray(320);struct.pack_into('<4Q',row,0,0,len(name),len(types),9);row[32:32+len(name)]=name.encode()
    for i,t in enumerate(types):struct.pack_into('<Q',row,160+i*8,TYPES.index(t)+1)
    return b'HIAMVAB1'+struct.pack('<Q',1)+row
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();D=a.directory
    image=Image(D/'multiversion_probes.flat');w=ctypes.create_string_buffer(32768);out=ctypes.create_string_buffer(304+168*128);cases=[];vector_count=0
    inputs=[([typ]*n,typ+'-'+str(n)) for typ in TYPES for n in range(17)]
    rng=random.Random(0x4d565052)
    inputs.extend(([rng.choice(TYPES) for _ in range(rng.randrange(17))],'mixed-'+str(i)) for i in range(96))
    for types,label in inputs:
        raw=frame(types);put(out,0,0);rc=image(raw,out,w);assert rc<=len(out),(label,rc)
        assert out.raw[:8]==b'HIAMVPV1' and get(out,16)==len(types) and get(out,24)==9
        count=get(out,8);assert rc==304+count*128
        expected=_probe_vectors(ScalarABI('probe',tuple(types),'u64'))
        actual=[]
        for i in range(count):
            row=struct.unpack_from('<16Q',out.raw,304+i*128)
            actual.append(tuple(row[:len(types)]));assert row[len(types):]==(0,)*(16-len(types))
        wanted=tuple(tuple(int(x)&U64 for x in r) for r in expected)
        assert tuple(actual)==wanted,(label,actual,wanted)
        vector_count+=count;cases.append({'case':label,'arguments':types,'vectors':count,'wire_sha256':sha(out.raw[:rc])})
    refused=[]
    original=frame(['u64'])
    mutations=[('short',original[:-1]),('trailing',original+b'\0'),('magic',b'BADMAGIC'+original[8:]),('too-many-functions',original[:8]+struct.pack('<Q',17)+original[16:]),('too-many-arguments',original[:32]+struct.pack('<Q',17)+original[40:]),('bad-type',original[:176]+bytes(8)+original[184:])]
    for name,raw in mutations:
        ctypes.memset(out,0xa5,len(out));put(out,0,0);before=out.raw;rc=image(raw,out,w);assert rc>len(out) and out.raw==before,(name,rc);refused.append(name)
    for selector in [1,U64]:
        ctypes.memset(out,0xa5,len(out));put(out,0,selector);before=out.raw;rc=image(original,out,w);assert rc>len(out) and out.raw==before;refused.append('selector-'+str(selector))
    for size in [0,8,303,304,431]:
        short=ctypes.create_string_buffer(max(1,size));put(short,0,0) if size>=8 else None
        rc=image(original,short,w);assert rc>len(short);refused.append('output-'+str(size))
    report={'schema':'hepta.hia.multiversion-probe-vector-qualification.v1','scope':'exact original finite probe selection/order only; no proof or loader authority','passed':len(cases)+len(refused),'failed':0,'vectors_compared':vector_count,'image':image.pin,'original_source_sha256':sha((ROOT/'hepta/hia_multiversion.py').read_bytes()),'cases':cases,'refusals':refused}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MV_PROBES_PASS',report['passed'],vector_count,flush=True)
if __name__=='__main__':main()
