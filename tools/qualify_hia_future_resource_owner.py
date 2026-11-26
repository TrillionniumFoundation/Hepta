"""Actual native compound Future custody gates.

This gate proves the resource producer over the unique Value/Future fusion.
Canonical Value kind 7, managed edges, public dispatch and cycle collection are
separate gates and are not inferred from raw compound-cap success.
"""
from pathlib import Path
import argparse,concurrent.futures,ctypes as C,hashlib,json,os,struct,subprocess
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_generation_lease_owner_resources as resources
from tools.qualify_hia_generation_lease_owner_provider import ObjectImage,libc,pin,get
from tools.qualify_hia_future_retirement import Public,facts
from tools import generate_hia_future_resource_owner_packer as spec
from tools import generate_hia_future_resource_registry_packer as registry_spec
ROOT=Path(__file__).resolve().parents[1]
ZERO=(0,0,0)
COMPILER_SHA='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
NAMES=('future_resource_owner','future_resource_registry','future_resource_owner_packer','future_resource_registry_packer')
def cap(raw,at):return struct.unpack_from('<3Q',raw,at)
def put(raw,at,*args):struct.pack_into('<'+'Q'*len(args),raw,at,*args)
def save(path,data):path.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
def address(fn):return C.cast(fn,C.c_void_p).value
def build(compiler,out):
    assert pin(compiler.read_bytes())==dict(bytes=813129,sha256=COMPILER_SHA)
    flats={};sources={};rows=[]
    for name in NAMES:
        source=(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes();sources[name]=source
        pair=[]
        for _ in range(2):
            p=subprocess.run([str(compiler),'compile'],input=source,capture_output=True,timeout=30)
            assert p.returncode==0 and not p.stderr,(name,p.returncode,p.stderr)
            pair.append(p.stdout)
        assert pair[0]==pair[1];flats[name]=pair[0];(out/(name+'.flat')).write_bytes(pair[0])
        rows.append(dict(source_path='examples/hia_bootstrap/'+name+'.hepta',source=pin(source),flat=pin(pair[0]),double_compile_identical=True))
        print('FUTURE_RESOURCE_NATIVE_COMPILE',name,len(pair[0]),flush=True)
    products={}
    for label,names,author in (
        ('owner',NAMES[:2],spec),('registry',('future_resource_registry',),registry_spec)):
        blobs=[flats[x]for x in names]
        wire=struct.pack('<'+'Q'*(len(blobs)+2),author.MAGIC,len(blobs),*map(len,blobs))+b''.join(blobs)
        raw=q.old.run_packer(flats['future_resource_'+label+'_packer'],wire)
        assert raw==author.reference_object(blobs)
        (out/(label+'.o')).write_bytes(raw);products[label]=dict(**pin(raw),native_pack=True,independent_byte_comparison=True)
        print('FUTURE_RESOURCE_NATIVE_PACK',label,len(raw),flush=True)
    bridge=out/'actual-owner-bridge'
    subprocess.run(['as','--64',str(ROOT/'tools/hia_future_resource_owner_bridge.S'),'-o',str(bridge)+'.o'],check=True,capture_output=True)
    subprocess.run(['objcopy','-O','binary','--only-section=.text',str(bridge)+'.o',str(bridge)+'.bin'],check=True,capture_output=True)
    assert Path(str(bridge)+'.bin').read_bytes()==spec.OUTER
    assert all((ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()==raw for name,raw in sources.items())
    result=dict(compiler=pin(compiler.read_bytes()),modules=rows,products=products,mechanical_bridge_exact=True)
    save(out/'build.json',result);return result

class FusionImage:
    def __init__(self,path):
        self.lib=C.CDLL(str(path));self.entry=self.lib.hia_background_optimizer_future_public
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32

class Producer:
    def __init__(self,owner,public,raw):
        self.owner=owner;self.public=public;self.ctx=C.create_string_buffer(512)
        imports={n:address(getattr(libc,n))for n in ('malloc','free')}
        imports.update(hia_resource_future=address(public.image.entry),hia_resource_values=get(owner.context,40))
        imports['hia_owner_carrier']=address(public.image.entry)
        self.image=ObjectImage(raw,imports);self.entry=self.image.entry
        own=C.addressof(self.ctx);value=C.addressof(owner.context)+512
        assert get(public.ctx,72)==get(owner.context,40) and get(public.ctx,112)==value
        # This component gate captures exact existing native bindings. The final
        # enclosing initializer must perform this capture in native code.
        prefix=[int.from_bytes(b'HIAFRCX1','little'),os.getpid(),own,self.image.base,
                address(public.image.entry),C.addressof(public.ctx),256,get(owner.context,40),
                value,256,0,0,0,0,0,0,0,self.image.base+spec.REGISTRY_OFFSET,own+256,256,get(owner.context,664)]
        for i,x in enumerate(prefix):put(self.ctx,8*i,x)
        self.rows=[];self.control(0)
    def raw(self,data,want=0,ctx=None):
        src=C.create_string_buffer(data,len(data));out=C.create_string_buffer(b'\xa5'*160,160)
        target=self.ctx if ctx is None else ctx
        rc=self.entry(src,len(data),out,128,target,512)
        assert rc==0 and src.raw==data and out.raw[128:]==b'\xa5'*32,(rc,data[:16].hex())
        result=out.raw[:128]
        final=data[:8]==b'HIAVRFQ1'
        assert result[:8]==(b'HIAVRFR1'if final else b'HIAFRR01'),result.hex()
        if want is not None:assert get(result,8)==want,(data[:16].hex(),result.hex())
        self.rows.append(dict(family=data[:8].decode(),op=get(data,8),status=get(result,8),
                         known=get(result,16 if final else 96),consumed=get(result,24 if final else 104),
                         pending=get(result,32 if final else 112)))
        return result
    def control(self,op,want=0):
        return self.raw(b'HIAFRCQ1'+struct.pack('<Q',op)+bytes(112),want)
    def capture(self,factory,future,want=0):
        raw=bytearray(128);raw[:8]=b'HIAFRQ01';put(raw,8,0)
        put(raw,16,*future[0]);put(raw,40,*future[1]);put(raw,64,*factory[1])
        return self.raw(bytes(raw),want)
    def q(self,op,owned,want=0):
        raw=bytearray(128);raw[:8]=b'HIAFRQ01';put(raw,8,op);put(raw,16,*owned)
        return self.raw(bytes(raw),want)
    def final(self,owned,want=0):
        return self.raw(struct.pack('<8s6Q',b'HIAVRFQ1',0,get(self.ctx,80),7,*owned)+bytes(72),want)
    def close(self):
        self.control(1);self.control(3)
        assert get(self.ctx,96)==3 and get(self.ctx,104)==get(self.ctx,112)==get(self.ctx,272)==0
        assert get(self.ctx,280)==1

def behavior(fusion,out):
    owner,carrier,v=resources.setup(fusion)
    image=FusionImage(fusion);p=Public(v,image);producer=Producer(owner,p,(out/'owner.o').read_bytes())
    rows=[]
    def record(name,**more):
        rows.append(dict(case=name,passed=True,**more));print('FUTURE_RESOURCE_NATIVE',name,flush=True)
    # A raw caller can independently release its factory and Future aliases.
    baseline=get(v.raw(47),48)
    factory=p.factory();future=p.make(factory)
    r=producer.capture(factory,future);owned=cap(r,24)
    assert get(r,16)==1 and owned[0] and get(r,96)==1
    copied=cap(producer.q(1,owned),24);assert copied!=owned
    facts(p.typed(26,*future),1)
    p.futures.remove(future)
    retired=p.typed(27,*factory);assert get(retired,96)==1
    p.factories.remove(factory)
    queried=producer.q(3,copied);fid=cap(queried,48);cell=cap(queried,72)
    assert fid==future[0] and cell!=future[1]
    value=v.scalar(1234567);identity=(get(v.raw(7,a=value),104),get(v.raw(7,a=value),112))
    p.call(22,fid,cell,value=value,kind=1)
    returned=p.call(10,fid,cell);actual=v.keep(returned,72)
    assert v.python(actual)==1234567 and (get(v.raw(7,a=actual),104),get(v.raw(7,a=actual),112))==identity
    v.drop(actual);v.drop(value)
    dropped=producer.q(2,owned)
    assert tuple(get(dropped,x)for x in(96,104,112))==(1,1,0)
    producer.q(3,owned,want=1);producer.q(3,copied)
    final=producer.final(copied);assert tuple(get(final,x)for x in(16,24,32))==(1,1,0)
    assert get(producer.ctx,272)==0 and get(v.raw(47),48)==baseline
    record('factory-and-cell-strong-custody-result-identity-final-ack',original_caller_aliases_consumed=True)
    # Bad late factory-lease capture compensates the already cloned Future.
    factory=p.factory();future=p.make(factory);before=get(v.raw(47),48)
    bad=(factory[0],(factory[1][0],factory[1][1]^1,factory[1][2]))
    refused=producer.capture(bad,future,want=3)
    assert cap(refused,24)==ZERO and tuple(get(refused,x)for x in(96,104,112))==(1,0,0)
    assert get(producer.ctx,272)==0 and get(v.raw(47),48)==before
    record('late-capture-failure-native-compensation')
    # Actual registry aliases survive parallel retain/query/drop.
    owned=cap(producer.capture(factory,future),24)
    def aliases(i):
        for _ in range(16):
            alias=cap(producer.q(1,owned),24)
            probe=producer.q(3,alias);assert cap(probe,48)==future[0]
            assert get(producer.q(2,alias),104)==1
        return i
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:assert len(list(pool.map(aliases,range(8))))==8
    record('parallel-aliases',threads=8,cycles=128)
    producer.control(1,want=6)
    copyctx=C.create_string_buffer(producer.ctx.raw,512)
    raw=b'HIAFRQ01'+struct.pack('<4Q',3,*owned)+bytes(88)
    badctx=producer.raw(raw,want=11,ctx=copyctx);assert get(badctx,96)==0
    rd,wr=os.pipe();pid=os.fork()
    if pid==0:
        os.close(rd)
        try:
            r=producer.q(3,owned,want=11);ok=get(r,96)==0
            os.write(wr,b'1'if ok else b'0')
        finally:os._exit(0)
    os.close(wr);assert os.read(rd,1)==b'1';os.close(rd);assert os.waitpid(pid,0)[1]==0
    record('copied-context-and-fork-refusal')
    assert get(producer.q(2,owned),104)==1
    assert get(producer.ctx,272)==0
    for item in list(p.futures):p.typed(26,*item);p.futures.remove(item)
    for item in list(p.factories):
        r=p.typed(27,*item)
        if get(r,112):p.typed(28,item[0])
        p.factories.remove(item)
    producer.control(1);producer.control(2);producer.close()
    closed=p.typed(29);facts(closed,1)
    assert not v.held and get(v.raw(47),48)==0
    answer=owner.call(3);assert answer['status']==0 and answer['state']==3
    record('prepare-rollback-commit-and-borrowed-context-custody',actual_owner_destroyed=True)
    return dict(cases=rows,calls=producer.rows,raw_compound_custody_qualified=True,
        canonical_future_value_qualified=False,managed_edges_qualified=False,whole_background_qualified=False,
        fusion=pin(fusion.read_bytes()),fixed_unique_value=True)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--compiler',type=Path,required=True);ap.add_argument('--fusion',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--reuse-build',action='store_true')
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    construction=json.loads((a.output/'build.json').read_text())if a.reuse_build else build(a.compiler,a.output)
    result=behavior(a.fusion,a.output);result['construction']=construction;save(a.output/'report.json',result)
    print('FUTURE_RESOURCE_RAW_QUALIFIED',len(result['cases']),len(result['calls']),flush=True)
if __name__=='__main__':main()
