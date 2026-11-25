"""C3 arithmetic/ordering compared with actual interpreter-created classes."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,platform,random,struct,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT.parents[1]/'root_native_recovery')]
import tools
tools.__path__=[str(ROOT/'tools'),str(ROOT.parents[1]/'root_native_recovery/tools')]
from tools import generate_hia_native_class_mro as author
MASK=(1<<64)-1
word=lambda b,p:struct.unpack_from('<Q',b,p)[0]
def put(b,p,v):struct.pack_into('<Q',b,p,v&MASK)
def frame(bases,ids=None):
    key=id if ids is None else ids.__getitem__
    total=sum(len(x.__mro__)for x in bases)
    out=struct.pack('<8s7Q',b'HIAC3M01',len(bases),total,0,0,0,0,0)
    for base in bases:
        out+=struct.pack('<2Q',key(base),len(base.__mro__))
        out+=struct.pack('<'+'Q'*len(base.__mro__),*(key(x)for x in base.__mro__))
    return out
class Entry:
    def __init__(self,path):
        self.native=bool(path)
        if path:
            raw=Path(path).read_bytes();self.image=mmap.mmap(-1,len(raw),prot=7);self.image.write(raw);self.array=(C.c_ubyte*len(raw)).from_buffer(self.image)
            self.fn=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)(C.addressof(self.array))
            self.pin=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        else:
            ns=dict(length=len,word_load=word,word_store=put)
            exec('from __future__ import annotations\n'+author.source_program(),ns);self.fn=ns['native_class_mro'];self.pin=None
    def call(self,raw,on,wn):
        if self.native:
            s=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xa5'*(on+16));w=C.create_string_buffer(wn)
            rc=int(self.fn(s,len(raw),o,on,w,wn));assert s.raw==raw+b'\0'and o.raw[on:]==b'\xa5'*16+b'\0'
            return rc,o.raw[:on],w.raw
        o=bytearray(b'\xa5'*on);w=bytearray(wn);rc=self.fn(raw,o,w);return rc,bytes(o),bytes(w)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image');ap.add_argument('--output',required=True);args=ap.parse_args()
    out=Path(args.output);out.mkdir(parents=True,exist_ok=False);f=Entry(args.image);rows=[];pool=[object];rng=random.Random(551013)
    cases=[(object,)]
    # Both successful and inconsistent hierarchies are created by the actual
    # running interpreter; no historical graph or golden MRO is substituted.
    for i in range(600):
        bases=tuple(rng.choices(pool,k=rng.randrange(1,min(6,len(pool))+1)))
        cases.append(bases)
        try:new=type('M'+str(i),bases,{})
        except TypeError:continue
        pool.append(new)
    from pathlib import PurePath,PurePosixPath,PureWindowsPath,PosixPath
    cases += [(x,)for x in(str,bytes,type,PurePath,PurePosixPath,PureWindowsPath,PosixPath)]
    class Left:pass
    class Right:pass
    class LR(Left,Right):pass
    class RL(Right,Left):pass
    cases += [(Left,Left),(LR,RL),(Left,LR),(LR,Left),(object,LR),(LR,object)]
    deep=object
    for i in range(400):deep=type('Deep'+str(i),(deep,),{})
    cases.append((deep,))
    for index,bases in enumerate(cases):
        raw=frame(bases);total=word(raw,16);wn=96+len(bases)*32+8*(total+len(bases))
        expected_status=0;message=None;original=None
        try:original=type('Probe'+str(index),bases,{})
        except TypeError as exc:
            message=str(exc);expected_status=1 if message.startswith('duplicate base class ')else 2
            assert expected_status==1 or 'consistent method resolution' in message,message
        rc,empty,w=f.call(raw,0,wn);assert rc==0xfffffffe and empty==b''
        n=word(w,0);rc,data,w=f.call(raw,n,wn);assert rc==0 and data[:8]==b'HIAC3R01'and word(data,8)==expected_status
        actual=tuple(word(data,32+i*8)for i in range(word(data,16)))
        if expected_status==0:assert actual==tuple(id(c)for c in original.__mro__[1:]),(index,actual,original.__mro__)
        elif expected_status==1:
            duplicate=next(b for b in bases if message=='duplicate base class '+b.__name__)
            assert actual==(id(duplicate),)
        else:
            names=message.split('for bases ',1)[1].split(', ')
            registry={id(c):c for b in bases for c in b.__mro__}
            assert [registry[x].__name__ for x in actual]==names
        if index%19==0:
            rc,bad,_=f.call(raw,n-1,wn);assert rc==0xfffffffe and bad==b'\xa5'*(n-1)
            rc,bad,w=f.call(raw,n,wn-1);assert rc==0xfffffffc and bad==b'\xa5'*n and word(w,8)==wn
        rows.append(dict(index=index,bases=len(bases),mro_entries=total,status=expected_status,output_words=len(actual)))
    # Class identities are opaque full-u64 words; no signed/32-bit narrowing.
    bases=(LR,Right);classes=set(c for b in bases for c in b.__mro__)
    ids={c:MASK-i*65537 for i,c in enumerate(classes)};raw=frame(bases,ids);wn=96+len(bases)*32+8*(word(raw,16)+len(bases))
    rc,_,w=f.call(raw,0,wn);rc,data,_=f.call(raw,word(w,0),wn);assert rc==0
    result=type('FullWidth',bases,{})
    assert tuple(word(data,32+i*8)for i in range(word(data,16)))==tuple(ids[c]for c in result.__mro__[1:])
    good=frame((object,));controls=[]
    for at in(0,8,16,24,32,40,48,56,64,72):
        bad=bytearray(good);put(bad,at,0 if at in(64,72)else MASK);controls.append(bytes(bad))
    bad=bytearray(good);put(bad,80,0);controls.extend((bytes(bad),good[:-1],good+b'\0'))
    for raw in controls:
        rc,o,w=f.call(raw,256,4096);assert rc==0xfffffffd and o==b'\xa5'*256,(rc,raw.hex())
    report=dict(schema='hia.native-class-c3.qualification.v1',scope='actual-native-pure-role'if args.image else'development-author-only',native_qualified=bool(args.image),public_class_factory_closed=False,oracle=platform.python_version(),rows=rows,groups=len(rows),private_controls=len(controls),image=f.pin)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in('scope','groups','private_controls','native_qualified')}))
if __name__=='__main__':main()
