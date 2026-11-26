"""Actual native nested structure, snapshot transport and checked freezer.

The three private dependency contexts borrow the native-bound sole Value arena.
No host callback dispatches policy or performs a production continuation.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib.util,json,math,os,random,struct,sys,traceback
from tools import qualify_hia_future_native_callbacks as callbacks
from tools.qualify_hia_multiversion_components import Image
from hepta.hia_program import _structure,_bounded_detached_snapshot,HIAProgramRejected
from tools.generate_hia_background_optimizer_value_structure import ERRORS
ZERO=(0,0,0)
def word(b,p):return struct.unpack_from("<Q",b,p)[0]
def cap(b,p=24):return struct.unpack_from("<3Q",b,p)
def put(b,p,*v):struct.pack_into("<"+"Q"*len(v),b,p,*v)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,r):p.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
class Nested:
    def __init__(self,owner,components,deps):
        self.f=callbacks.Fixture(owner);self.libs={};self.entries={}
        for name in ("structure","transport","freeze"):
            lib=C.CDLL(str(components/(name+".so")));fn=getattr(lib,"hia_background_value_"+name+"_deferred")
            fn.argtypes=[C.c_void_p,C.c_uint64]*3;fn.restype=C.c_uint32
            self.libs[name]=lib;self.entries[name]=fn
        self.capture=Image(deps/"background_optimizer_json_capture.flat")
        self.freezer=Image(deps/"background_optimizer_freeze.flat")
        self.threshold=(Path(__file__).resolve().parents[1]/"examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat").read_bytes()
        assert pin(self.threshold)==dict(bytes=10100891,sha256="735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706")
        self.sctx=C.create_string_buffer(128);self.ictx=C.create_string_buffer(256);self.fctx=C.create_string_buffer(2048)
        value=word(self.f.bound.owner.context,40);vctx=C.addressof(self.f.engine.context)
        assert vctx==C.addressof(self.f.bound.owner.context)+512
        struct.pack_into("<8s3Q",self.sctx,0,b"HIABVC03",value,vctx,256)
        struct.pack_into("<8s3Q",self.ictx,0,b"HIABIC03",value,vctx,256)
        provider=(C.c_char*768).from_address(C.addressof(self.f.bound.owner.context)+1280)
        self.payload=callbacks.inv.ENTRY(word(provider,104))
        self.payloadctx=(C.c_char*256).from_address(word(provider,112))
        self.payload_calls=0
        struct.pack_into("<8s10Q",self.fctx,0,b"HIABFZC3",value,vctx,256,
            C.cast(self.entries["transport"],C.c_void_p).value,
            self.capture.address,self.freezer.address,
            word(provider,104),word(provider,112),256,4300)
        self.sout=C.create_string_buffer(96<<20);self.iout=C.create_string_buffer(131072);self.fout=C.create_string_buffer(262144)
        self.calls=0
    def capture_value(self,x,memo=None):
        if memo is None:memo={}
        if id(x)in memo:return memo[id(x)]
        if type(x)is list:
            c=self.f.v.lst([]);memo[id(x)]=c
            for item in x:self.f.v.raw(16,a=c,b=self.capture_value(item,memo))
        elif type(x)is dict:
            c=self.f.v.dictionary([]);memo[id(x)]=c
            for key,item in x.items():self.f.v.raw(10,a=c,b=self.capture_value(key,memo),c=self.capture_value(item,memo))
        else:c=self.f.v.scalar(x);memo[id(x)]=c
        return c
    def call(self,kind,owned,mode=0,limit=4300):
        raw=bytearray(128+(len(self.threshold)if kind=="structure"else 0))
        raw[:8]={"structure":b"HIABTC05","transport":b"HIABIQ03","freeze":b"HIABFZQ3"}[kind]
        put(raw,8,mode)
        if kind=="structure":
            put(raw,16,*owned);put(raw,40,limit,len(self.threshold));raw[128:]=self.threshold
            out,ctx=self.sout,self.sctx
        else:
            put(raw,24,*owned)
            out,ctx=(self.iout,self.ictx)if kind=="transport"else(self.fout,self.fctx)
            if kind=="freeze":put(ctx,80,limit)
        source=C.create_string_buffer(bytes(raw),len(raw))
        rc=self.entries[kind](source,len(raw),out,len(out),ctx,len(ctx))
        assert source.raw==raw
        self.calls+=1
        assert rc==0,(kind,rc,out.raw[:192].hex())
        expected={"structure":b"HIABTV03","transport":b"HIABIO03","freeze":b"HIABFZR3"}[kind]
        r=out.raw if kind=="freeze"else out.raw[:192]
        assert r[:8]==expected,(kind,r[:192].hex())
        at=72 if kind=="transport"else 128
        assert all(word(r,p)<=1 for p in (at,at+8,at+16))and word(r,at+24)==1
        return r
    def payload_read(self,owned,n):
        raw=bytearray(128);raw[:8]=b"HIABPY01";put(raw,8,4);put(raw,24,*owned);put(raw,56,n)
        src=C.create_string_buffer(bytes(raw));out=C.create_string_buffer(512+n)
        rc=self.payload(src,128,out,len(out),self.payloadctx,256);self.payload_calls+=1
        assert rc==0 and out.raw[:8]==b"HIABPYR1"and word(out,8)==0,out.raw[:128].hex()
        return out.raw[512:512+n]
    def payload_drop(self,owned):
        raw=bytearray(128);raw[:8]=b"HIABPY01";put(raw,8,3);put(raw,24,*owned)
        src=C.create_string_buffer(bytes(raw));out=C.create_string_buffer(512)
        rc=self.payload(src,128,out,512,self.payloadctx,256);self.payload_calls+=1
        assert rc==0 and out.raw[:8]==b"HIABPYR1"and word(out,8)==0,out.raw[:128].hex()
    def release_inputs(self):
        for c in list(self.f.v.held):self.f.v.drop(c)
    def finish(self):
        self.release_inputs()
        assert all(word(self.ictx,p)==0 for p in (32,40,64,88,96,104,112,120))
        assert word(self.fctx,96)==0
        self.f.finish()
def oracle_structure(x,mode,limit):
    old=sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(limit)
        detached=_bounded_detached_snapshot(x)if mode else x
        return 0,_structure(detached),detached
    except HIAProgramRejected as exc:
        ids=[k for k,v in ERRORS.items()if v==str(exc)];assert len(ids)==1,(str(exc),ids)
        return ids[0],None,None
    except ValueError as exc:
        assert "integer string conversion"in str(exc);return 9,None,None
    finally:sys.set_int_max_str_digits(old)
def structure_cases(n):
    rows=[];xs=[None,False,True,0,-123,10**100,"", "é😀", [], {}, [None,1,"x"],
        {"z":[1,{"a":True}],"a":"中"},float("nan"),float("inf"),1.5,b"x","\ud800",{1:2}]
    cycle=[];cycle.append(cycle);xs.append(cycle)
    for mode in(0,1):
        for i,x in enumerate(xs):
            owned=n.capture_value(x);error,size,expected=oracle_structure(x,mode,4300)
            r=n.call("structure",owned,mode)
            assert (word(r,8),word(r,16))==(int(error!=0),error),(mode,i,error,r.hex())
            assert word(r,104)==word(r,136)==word(r,144)==0
            if error==0:
                got=n.f.v.keep(r);assert n.f.v.python_value(got)==expected
                assert word(r,56)==size
                if type(x)in(list,dict):assert not n.f.v.same(owned,got)
            else:assert cap(r)==ZERO
            n.release_inputs();rows.append(dict(case="structure-"+str(mode)+"-"+str(i),mode=mode,error=error,passed=True))
    return rows
def freeze_cases(n):
    rows=[]
    atoms=[None,False,True,-1,10**100,-0.0,5e-324,1.7976931348623157e308,"\ud800","\ud800\udc00","𐀀",
        float("inf"),float("-inf"),float("nan"),[],{},["x",{"z":3,"a":2}]]
    big=int("9"*4301)
    priority=[{"z":big,"a":float("inf")},{"z":float("inf"),"a":big},{"a":"\ud800","z":big},
        {"a":"\ud800","z":float("nan")},{"a":big,"z":"\ud800"},{"\ud800":"x","z":float("inf")},
        {"x":"\ud800\udfff\udc00"},{"a":"\ud800","b":"\udfff"}]
    cases=[("atom-"+str(i),x,4300)for i,x in enumerate(atoms)]
    cases +=[("error-order-"+str(i),x,4300)for i,x in enumerate(priority)]
    rng=random.Random(8744)
    for i in range(100):
        bad="".join(chr(rng.randrange(0xd800,0xe000))for _ in range(rng.randrange(1,5)))
        x={rng.choice(["a","z","中","😀"])+str(i):rng.choice(["é","中","😀","\0",'"',"\\"])+bad,
           "m":rng.choice([big,float("nan"),float("inf"),1.25])}
        cases.append(("sorted-error-"+str(i),x,4300))
    for i in range(80):
        bits=rng.getrandbits(64);x=struct.unpack("<d",struct.pack("<Q",bits))[0]
        cases.append(("binary64-"+hex(bits),{"z":x,"a":[x]},4300))
    for limit in(0,640,4300):
        for size in(639,640,641,4300,4301,100001):
            cases.append(("digits-"+str(limit)+"-"+str(size),{"a":int("9"*size)},limit))
    cases.extend([("actual-9MiB",{"z":"x"*(9<<20),"a":1},4300),("wide-5001",list(range(5001)),4300)])
    for name,x,limit in cases:
        owned=n.capture_value(x);old=sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(limit)
            try:expected=json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode();span=None
            except BaseException as exc:
                expected={"type":type(exc).__name__,"message":str(exc)}
                span=(exc.start,exc.end)if isinstance(exc,UnicodeEncodeError)else None
        finally:sys.set_int_max_str_digits(old)
        before=len(os.listdir("/proc/self/fd"));r=n.call("freeze",owned,limit=limit)
        assert word(r,56)==word(r,136)==word(r,144)==0,(name,r[:192].hex())
        if isinstance(expected,bytes):
            assert word(r,8)==0 and word(r,40)==len(expected),(name,r[:192].hex())
            payload=cap(r,16);actual=n.payload_read(payload,len(expected));assert actual==expected,(name,actual[:100],expected[:100])
            n.payload_drop(payload)
        else:
            assert word(r,8)==1,(name,r[:192].hex(),expected)
            actual=json.loads(r[256:256+word(r,48)])
            assert actual==expected,(name,actual,expected)
            if span is not None:assert(word(r,80),word(r,88))==span
        assert len(os.listdir("/proc/self/fd"))==before
        n.release_inputs();rows.append(dict(case=name,error=expected if isinstance(expected,dict)else None,passed=True))
        if len(rows)%40==0:print("ACTUAL_NESTED_FREEZE_CASES",len(rows),flush=True)
    return rows
def pending_case(n):
    owned=n.capture_value({"z":[1,True,"actual pending"],"a":None})
    helper=Path("/home/qian-qi/hia-native-llvm-public-followthrough-20261126-620a/tools/qualify_hia_result_value_deferred_capture.py")
    spec=importlib.util.spec_from_file_location("nested_actual_pending",helper);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    mod.pending_function(n.f.v,n.f.bound)
    assert word(n.f.engine.context,176)==1
    replies={}
    for kind in("structure","transport","freeze"):
        r=n.call(kind,owned,mode=1 if kind=="structure"else 0)
        assert word(r,8)==0 and word(n.f.engine.context,176)==1,(kind,r[:192].hex())
        at=72 if kind=="transport"else 128
        assert word(r,at)==1 and word(r,at+8)==word(r,at+16)==0
        replies[kind]=r[:192].hex()
        if kind=="structure":
            # Private consumed facts release the result without running the pending finalizer.
            from tools.qualify_hia_result_value_invocations import frame
            rc,drop=n.f.engine.call(frame(78,a=cap(r)))
            assert rc==0 and drop[:8]==b"HIABVR02"and(word(drop,88),word(drop,96))==(1,1)
        elif kind=="transport":
            os.close(word(r,16))
        else:n.payload_drop(cap(r,16))
        assert word(n.f.engine.context,176)==1
    n.f.v.raw(47)
    assert word(n.f.engine.context,176)==word(n.f.engine.context,184)==0
    n.release_inputs()
    return dict(case="actual-code-retirement-pending-through-all-three-private-nested-owners",passed=True,replies=replies,
        actual_native_pending=True,no_inner_finalizer_drain=True,outer_native_drain=True)
def main():
    p=argparse.ArgumentParser()
    for key in("owner","components","deps","output"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True)
    sys.set_int_max_str_digits(0)
    r=dict(schema="hia.BG-deferred-nested.component.v1",passed=False,component_qualified=False,
      whole_BG_closed=False,production_BG_initializer=False,host_policy_callbacks=False,
      owner=dict(path=str(a.owner),**pin(a.owner.read_bytes())),cases=[])
    try:
        n=Nested(a.owner,a.components,a.deps)
        r["cases"]+=structure_cases(n);save(a.output/"report.json",r)
        print("ACTUAL_NESTED_STRUCTURE_PASS",len(r["cases"]),flush=True)
        r["cases"]+=freeze_cases(n);save(a.output/"report.json",r)
        r["cases"].append(pending_case(n));n.finish()
        r["native_calls"]=n.calls;r["component_qualified"]=r["passed"]=True
    except BaseException as exc:r["error"]=repr(exc);r["traceback"]=traceback.format_exc();raise
    finally:save(a.output/"report.json",r)
    print("ACTUAL_NESTED_DEFERRED_PASS",len(r["cases"]),flush=True)
if __name__=="__main__":main()
