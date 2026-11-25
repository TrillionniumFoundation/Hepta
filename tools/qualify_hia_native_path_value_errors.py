"""Original interpreter comparison, explicitly separate from native execution."""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib,json,mmap,os,random,struct,sys,platform
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT.parent.parent/'root_native_recovery')]
from tools import generate_hia_native_path_value_error as author
MAGIC=b'HIANPER1'
def word(b,p):return struct.unpack_from('<Q',b,p)[0]
def packet(kind,a,b=''):
    a=a.encode();b=b.encode();return struct.pack('<8s7Q',MAGIC,kind,len(a),len(b),0,0,0,0)+a+b
def original(kind,a,b=''):
    if kind==1:
        value=type(b,(),{})()
        cls=type(a,(),{'__fspath__':lambda self:value})
    else:cls=type(a,(),{})
    try:
        if kind==2:Path(cls())
        else:os.fspath(cls())
    except TypeError as error:
        return json.dumps(dict(type='TypeError',message=str(error)),ensure_ascii=True,separators=(',',':')).encode()
    raise AssertionError('original operation did not raise TypeError')
class Author:
    scope='development-author-only'
    def __init__(self):
        ns=dict(length=len,byte=lambda b,i:b[i],store=lambda b,i,v:b.__setitem__(i,v&255),word_load=word,word_store=lambda b,i,v:struct.pack_into('<Q',b,i,v&((1<<64)-1)))
        exec('from __future__ import annotations\n'+author.source_program(),ns)
        self.function=ns['native_path_value_error']
    def __call__(self,s,on=0,wn=65536):
        o=bytearray(b'\xa5'*on);w=bytearray(wn);rc=self.function(s,o,w);return rc,bytes(o),bytes(w)
class Native:
    scope='actual-native-pure-role'
    def __init__(self,path):
        self.raw=Path(path).read_bytes();self.m=mmap.mmap(-1,len(self.raw),prot=7);self.m.write(self.raw);self.v=(C.c_ubyte*len(self.raw)).from_buffer(self.m)
        self.f=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)(C.addressof(self.v))
    def __call__(self,s,on=0,wn=65536):
        sb=C.create_string_buffer(s);o=C.create_string_buffer(b'\xa5'*(on+64));w=C.create_string_buffer(wn)
        rc=int(self.f(sb,len(s),o,on,w,wn));assert sb.raw==s+b'\0'and o.raw[on:on+64]==b'\xa5'*64
        return rc,o.raw[:on],w.raw
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image');ap.add_argument('--output',required=True);ap.add_argument('--author-stable-unicode',action='store_true');args=ap.parse_args()
    if args.image and args.author_stable_unicode:ap.error('the original native matrix cannot narrow random Unicode')
    out=Path(args.output);out.mkdir(parents=True,exist_ok=False);f=Native(args.image)if args.image else Author();rows=[]
    names=['','NoneType','bytes','Quotes\'and"','\n\t\r\b\f\\','\u00a0\u200b\u2028\u0378','汉字🙂', 'a'*199,'a'*200,'a'*201,'a'*199+'汉','a'*198+'🙂','a'*197+'🙂','é'*101,'x'*1500,'⚡'*1700,'.','a.b','abc.','x'*300+'.'+ '汉'*100]
    rng=random.Random(729)
    for i in range(64):
        cps=[]
        for j in range(rng.randrange(1,24)):
            cp=rng.randrange(1,128 if args.author_stable_unicode else 0x110000)
            if not 0xd800<=cp<=0xdfff:cps.append(chr(cp))
        names.append(''.join(cps))
    for index,name in enumerate(names):
        for kind in range(3):
            other=names[(index*7+3)%len(names)]if kind==1 else''
            s=packet(kind,name,other);expected=original(kind,name,other)
            rc,o,w=f(s);assert rc==0xfffffffe and word(w,0)==len(expected),(kind,name,rc,word(w,0),len(expected))
            rc,o,w=f(s,len(expected));assert rc==0 and o==expected,(kind,name,other,rc,o,expected)
            if index<8:
                rc,o,w=f(s,len(expected)-1);assert rc==0xfffffffe and o==b'\xa5'*(len(expected)-1)
            rows.append(dict(kind=kind,source_bytes=len(s),output_bytes=len(expected),output_sha256=hashlib.sha256(expected).hexdigest()))
    controls=[]
    good=packet(0,'Good')
    for at in(0,8,16,24,32,40,48,56):
        data=bytearray(good);struct.pack_into('<Q',data,at,(1<<64)-1);controls.append(bytes(data))
    controls.extend((good[:-1],good+b'\0',packet(0,'Good','Other')))
    for raw in(b'\0',b'\xff',b'\xc3',b'\xed\xa0\x80',b'\xf4\x90\x80\x80'):
        controls.append(struct.pack('<8s7Q',MAGIC,0,len(raw),0,0,0,0,0)+raw)
    for s in controls:
        rc,o,w=f(s,512);assert rc==0xfffffffd and o==b'\xa5'*512,(rc,s[:128])
    rc,o,w=f(good,512,65535);assert rc==0xfffffffd and o==b'\xa5'*512
    report=dict(scope=f.scope,python=platform.python_version(),passed=True,groups=len(rows),private_controls=len(controls)+1,rows=rows,native_qualified=bool(args.image),whole_path_conversion_closed=False,author_stable_unicode=args.author_stable_unicode)
    if args.image:report['image']=dict(bytes=len(f.raw),sha256=hashlib.sha256(f.raw).hexdigest())
    (out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(f.scope,len(rows),len(controls)+1,flush=True)
if __name__=='__main__':main()
