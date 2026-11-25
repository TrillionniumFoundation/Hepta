"""Whole-byte development packer checks; actual native execution is separate."""
from pathlib import Path
import argparse, ctypes as C, hashlib, importlib, json, random, struct, sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT.parents[1]/'root_native_recovery')]
import tools
tools.__path__=[str(ROOT/'tools'),str(ROOT.parent/'native_path_value_source/tools'),str(ROOT.parents[1]/'root_native_recovery/tools')]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--class-packer');ap.add_argument('--factory-packer');args=ap.parse_args()
    if bool(args.class_packer)!=bool(args.factory_packer):ap.error('both actual native packers are required')
    output=Path(args.output);output.mkdir(parents=True,exist_ok=False);rows=[];rng=random.Random(772)
    for name,magic,count,header in (('result_value_class_packer',b'HIABVP03',10,104),('native_posix_path_factory_packer',b'HIANXP01',2,40)):
        m=importlib.import_module('tools.generate_hia_'+name)
        ns=dict(length=len,byte=lambda b,i:b[i],store=lambda b,i,v:b.__setitem__(i,v&255))
        exec('from __future__ import annotations\n'+m.source_program(),ns)
        if args.class_packer:
            from tools.qualify_hia_multiversion_components import Image
            actual=Image(Path(args.class_packer if name=='result_value_class_packer'else args.factory_packer))
            def native_pack(raw,o,w):
                output=(C.c_ubyte*len(o)).from_buffer(o)
                work=(C.c_ubyte*len(w)).from_buffer(w)
                return actual(raw,output,work)&0xffffffff
            ns['pack']=native_pack
        good=None
        for size in (1,7,16,31,257,1023):
            flats=[rng.randbytes(size+i*3)for i in range(count)]
            for mode in (0,1):
                raw=struct.pack('<8s'+'Q'*(count+2),magic,count,*map(len,flats),mode)+b''.join(flats)
                want=m.reference_flat(flats)if mode else m.reference_object(flats)
                o=bytearray(b'\xa5'*(len(want)+16));w=bytearray(512)
                rc=ns['pack'](raw,memoryview(o)[:len(want)],w)
                assert rc==len(want) and o[:len(want)]==want and o[len(want):]==b'\xa5'*16
                short=bytearray(b'\xa5'*(len(want)-1));assert ns['pack'](raw,short,bytearray(512))==0xfffffffe and short==b'\xa5'*len(short)
                rows.append(dict(role=name,size=size,mode=mode,bytes=len(want),sha256=hashlib.sha256(want).hexdigest()))
                good=raw
        controls=[good[:-1],good+b'\0']
        for at,value in ((0,0),(8,count-1),(16,0),(16,4194305),(header-8,2),(header-8,(1<<64)-1)):
            bad=bytearray(good);struct.pack_into('<Q',bad,at,value);controls.append(bytes(bad))
        for raw in controls:
            o=bytearray(b'\xa5'*8192);assert ns['pack'](raw,o,bytearray(512))==0xffffffff and o==b'\xa5'*8192
        assert ns['pack'](good,bytearray(8192),bytearray(511))==0xfffffffe
        rows.append(dict(role=name,private_controls=len(controls)+1))
    report=dict(schema='hia.native-class-packers.qualification.v1',native_qualified=bool(args.class_packer),rows=rows,groups=len(rows))
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(groups=len(rows),native_qualified=bool(args.class_packer))))

if __name__=='__main__':main()
