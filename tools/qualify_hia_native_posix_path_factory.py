"""Fixed PosixPath factory ownership and actual class graph composition.

--author-mechanical runs real x86 capsules/syscalls and the exact development
HIA authors. It is not native HIA qualification. --image plus --value-image
is reserved for the actual independently constructed pair.
"""
from pathlib import Path, PosixPath
import argparse, ctypes as C, hashlib, json, mmap, os, random, struct, sys, traceback

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT.parents[1]/'root_native_recovery')]
import tools
tools.__path__=[str(ROOT/'tools'),str(ROOT.parent/'native_path_value_source/tools'),str(ROOT.parent/'native_value_extension/candidate'),str(ROOT.parents[1]/'root_native_recovery/tools')]
from tools import generate_hia_native_posix_path_factory as policy
from tools import generate_hia_native_posix_path_factory_packer as packer
from tools.qualify_hia_result_value_classes import MechanicalEngine, NativeEngine, Values, frame, word, put, ZERO

SIG=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
def ptr(value):return C.cast(value,C.c_void_p).value
def view(p,n):return memoryview((C.c_ubyte*n).from_address(p or 0)).cast('B')


class Pipeline:
    def __init__(self,image=None,value_image=None):
        self.errors=[];self.faults=[];self.value_calls=[]
        self.engine=NativeEngine(value_image) if value_image else MechanicalEngine()
        self.values=Values(self.engine)
        self.w=C.create_string_buffer(4096)
        self.value_callback=SIG(self.value_call)
        context=self.engine.context
        for at,value in ((0,int.from_bytes(b'HIANPXC1','little')),(8,ptr(self.value_callback)),(16,C.addressof(context)),(24,len(context)),(32,os.getpid())):
            put(self.w,at,value)
        if image:
            raw=Path(image).read_bytes()
        else:
            ns=dict(length=len,word_load=word,word_store=put,byte=lambda b,i:b[i],store=lambda b,i,v:b.__setitem__(i,v&255))
            exec('from __future__ import annotations\n'+policy.source_program(),ns)
            self.ns=ns
            self.policy_callback=SIG(self.policy_call)
            self.unused_callback=SIG(lambda *args:0xfffffffd)
            trampoline=lambda f:b'\x48\xb8'+struct.pack('<Q',ptr(f))+b'\xff\xe0'
            raw=packer.reference_flat([trampoline(self.policy_callback),trampoline(self.unused_callback)])
        self.mapping=mmap.mmap(-1,len(raw),prot=7);self.mapping.write(raw)
        self.buffer=(C.c_ubyte*len(raw)).from_buffer(self.mapping)
        self.entry=SIG(C.addressof(self.buffer))

    def value_call(self,s,sn,o,on,w,wn):
        try:
            assert w==C.addressof(self.engine.context) and wn==len(self.engine.context)
            request=C.string_at(s,sn);op=word(request,8);self.value_calls.append(op)
            if self.faults and self.faults[0]['op']==op:
                fault=self.faults.pop(0)
                if fault.get('actual_consume'):
                    rc,data=self.engine.call(request,on)
                    assert rc==0 and word(data,96)==1
                reply=bytearray(128);reply[:8]=b'HIABVR02'if op in(29,31)else b'HIABVR01'
                for at,value in fault.get('fields',{}).items():put(reply,int(at),value)
                C.memmove(o,bytes(reply),128);return fault.get('rc',0)
            rc,data=self.engine.call(request,on);C.memmove(o,data,len(data));return rc
        except BaseException:
            self.errors.append(traceback.format_exc());return 0xfffffffd

    def policy_call(self,s,sn,o,on,w,wn):
        try:return self.ns['native_posix_path_factory'](view(s,sn),view(o,on),view(w,wn))
        except BaseException:
            self.errors.append(traceback.format_exc());return 0xfffffffd

    def call(self,cap=ZERO,op=0):
        raw=bytearray(128);raw[:8]=b'HIANPX01';put(raw,8,op);struct.pack_into('<3Q',raw,16,*cap)
        source=C.create_string_buffer(bytes(raw));out=C.create_string_buffer(b'\xa5'*(32768+64));prefix=self.w.raw[:128]
        rc=self.entry(source,128,out,32768,self.w,4096)
        assert not self.errors,self.errors
        assert rc==0 and out.raw[:8]==b'HIANPXR1',(rc,out.raw[:128].hex())
        assert self.w.raw[:128]==prefix and out.raw[32768:]==b'\xa5'*64+b'\0'
        return out.raw[:128]

    def inspect(self,cap):
        v=self.values
        cls=v.keep(v.raw(36,a=cap));posix=v.builtin(18);pure=v.builtin(14)
        assert v.same(cls,posix) and v.isinst(cap,pure)
        raw=v.raw(26,a=cap)
        assert word(raw,8200)==14
        refs=[v.keep(raw,8224+i*24)for i in range(3)]
        assert v.python(refs[0])is None and v.python(refs[2])=='PosixPath'
        items=v.copy_caps(refs[1]);parts=[v.python(x)for x in items]
        for item in items+refs+[cls,posix,pure]:v.drop(item)
        return parts

    def finish(self):
        assert word(self.w.raw,128)==0 and word(self.w.raw,136)==0
        self.values.finish()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image');ap.add_argument('--value-image');ap.add_argument('--output',required=True);args=ap.parse_args()
    if bool(args.image)!=bool(args.value_image):ap.error('both native images are required together')
    output=Path(args.output);output.mkdir(parents=True,exist_ok=False);rows=[]
    p=Pipeline(args.image,args.value_image);v=p.values
    cases=['','/','//','///','a','a/../b','./a//b/','/already/resolved','汉字/🙂','\ud800/\udfff','\0','a\\b','x'*1048577]
    rng=random.Random(932)
    for _ in range(60):cases.append(''.join(rng.choice('/.abc\\')for _ in range(rng.randrange(0,200))))
    for index,text in enumerate(cases):
        source=v.scalar(text);out=p.call(source)
        assert word(out,8)==0 and word(out,96)==word(out,104)==0,out.hex()
        cap=struct.unpack_from('<3Q',out,16);v.held.add(cap)
        assert p.inspect(cap)==PosixPath(text)._raw_paths==[text]
        v.drop(source)
        assert p.inspect(cap)==[text]
        v.drop(cap);rows.append(dict(case='fixed-class-construction',index=index,utf8_bytes=len(text.encode('utf-8','surrogatepass'))))
    p.finish()
    # Public leaf publishes no partial output after any normal value failure.
    if not args.image:
        for op in(5,32,2,3,16,35,36,8):
            p=Pipeline();v=p.values;source=v.scalar('/tmp/factory')
            p.faults=[dict(op=op,fields={8:5})]
            out=p.call(source)
            assert word(out,8)==3 and word(out,96)==word(out,104)==0,out.hex()
            assert out[16:88]==bytes(72)
            v.drop(source);p.finish();rows.append(dict(case='value-allocation-failure',op=op))
        p=Pipeline();v=p.values;source=v.scalar('/retry')
        p.faults=[dict(op=29,fields={8:11,80:0,88:1,96:0})]
        out=p.call(source);assert word(out,8)==4 and word(out,96)==1 and word(out,104)==0
        count=p.value_calls.count(35);out=p.call(op=2)
        assert word(out,8)==0 and word(out,96)==0 and p.value_calls.count(35)==count==1
        cap=struct.unpack_from('<3Q',out,16);v.held.add(cap);assert p.inspect(cap)==['/retry']
        v.drop(cap);v.drop(source);p.finish();rows.append(dict(case='cleanup-only-no-reconstruction'))
        # Actual already-consumed nodes stay cleared; unknown objects are held.
        for fields,consume in (({8:11,80:0,88:1,96:1},True),({8:11,80:1,88:1,96:0},False),({8:0,80:1,88:1,96:1},False)):
            p=Pipeline();v=p.values;source=v.scalar('/quarantine')
            p.faults=[dict(op=29,fields=fields,actual_consume=consume)]
            out=p.call(source);assert word(out,8)==4 and word(out,96)==word(out,104)==1
            saved=p.w.raw;calls=len(p.value_calls);again=p.call(op=2)
            assert again==out and len(p.value_calls)==calls
            # Forensic test disposal is explicit and never claimed production
            # recovery. It drops only actually still present nodes once.
            for i in range(16):
                at=512+i*32
                if word(saved,at+24):
                    cap=struct.unpack_from('<3Q',saved,at)
                    v.held.add(cap)
            v.finish();rows.append(dict(case='explicit-quarantine',fields=fields,actual_consumption=consume))
    report=dict(schema='hia.native-posix-path-factory.qualification.v1',scope='actual-native-components'if args.image else'actual-x86-effects-and-exact-development-authors',native_qualified=bool(args.image),groups=rows,public_path_methods_closed=False,full_public_factory_closed=False)
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(groups=len(rows),native_qualified=bool(args.image))))


if __name__=='__main__':main()
