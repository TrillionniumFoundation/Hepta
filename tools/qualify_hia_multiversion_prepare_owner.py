"""Actual HIA preparation: construction, pinned report, loader, VM and retirement."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,random,struct,time
from tools.qualify_hia_multiversion_prepare_process import sealed,NONE
from tools.qualify_hia_multiversion_prepare_intake import abi_bytes
from tools.qualify_hia_multiversion_prepare_build import packet as build_packet
from tools.qualify_hia_multiversion_call import function,document
from tools.generate_hia_multiversion_abi import TYPES
from hepta.hia_multiversion import _admit,ScalarABI,_probe_vectors
get=lambda x,a:struct.unpack_from('<Q',x,a)[0]
sha=lambda x:hashlib.sha256(x).hexdigest()
ROOT=Path(__file__).resolve().parents[1]
def packet(core,abi,path,fd,image,cancel=0,deadline=None):
    h=bytearray(build_packet(core,abi,path,fd,image,cancel,deadline))
    h[:8]=b'HIAMVGF1'
    return bytes(h)
def operation(op):
    h=bytearray(256);struct.pack_into('<8sQ',h,0,b'HIAMVGF1',op);return bytes(h)
class Owner:
    def __init__(self,directory):
        self.directory=Path(directory);self.lib=C.CDLL(str(self.directory/'prepare-owner.so'))
        self.f=self.lib.hia_mv_prepare_owner;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
        self.w=C.create_string_buffer(192<<20);self.o=C.create_string_buffer((1<<20)+2048)
    def run(self,raw,oc=None,wc=None,driver=None):
        source=C.create_string_buffer(raw);C.memset(self.o,0xa5,len(self.o));start=time.monotonic_ns()
        rc=(self.f if driver is None else driver)(source,len(raw),self.o,len(self.o) if oc is None else oc,self.w,len(self.w) if wc is None else wc)
        elapsed=time.monotonic_ns()-start
        assert source.raw==raw+b'\0'
        if rc>=0xfffffff0:
            assert self.o.raw[:2048]==b'\xa5'*2048
            return rc,self.o.raw[:2048],None,(),elapsed
        out=self.o.raw;assert out[:8]==b'HIAMVGR1' and get(out,8)==rc,(rc,out[:128].hex())
        n=get(out,72);assert n<=1<<20
        out=out[:2048+n]
        streams=[]
        for at in (104,112):
            fd=get(out,at)
            if fd==NONE:streams.append(None)
            else:
                streams.append(os.pread(fd,os.fstat(fd).st_size,0));os.close(fd)
        receipt=json.loads(out[2048:]) if n and rc==0 else None
        return rc,out,receipt,tuple(streams),elapsed
def source_groups(all_signatures):
    inputs=[([typ]*n,typ+'-'+str(n),typ) for typ in TYPES for n in range(17)]
    rng=random.Random(0x4d565052)
    for i in range(96):
        inputs.append(([rng.choice(TYPES) for _ in range(rng.randrange(17))],'mixed-'+str(i),TYPES[i%len(TYPES)]))
    if not all_signatures:inputs=inputs[:16]
    for first in range(0,len(inputs),16):
        fs=[];expected=0;sigs=[]
        for i,(types,label,result0) in enumerate(inputs[first:first+16],first):
            selected=i%len(types) if types else 0;result=types[selected] if types else result0;name='signature_'+str(i).zfill(4)
            fs.append(function(name,types,result=result,selected=selected))
            count=len(_probe_vectors(ScalarABI(name,tuple(types),result)));expected+=count
            sigs.append(dict(case=label,function=name,parameters=types,result=result,selected=selected,vectors=count))
        raw=json.dumps(document(fs),separators=(',',':')).encode();original,sigs0,_=_admit(raw)
        yield 'batch-'+str(first//16).zfill(2),original.canonical_bytes,abi_bytes(original,sigs0),expected,sigs
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--builder',type=Path,required=True);p.add_argument('--all-signatures',action='store_true');a=p.parse_args()
    D=a.output;D.mkdir(parents=True,exist_ok=True);builder=a.builder.read_bytes();fd=sealed(builder);rows=[];start=time.monotonic_ns()
    for name,core,abi,expected,sigs in source_groups(a.all_signatures):
        owner=Owner(a.directory);path=D/(name+'-actual-built.so');baseline=set(os.listdir('/proc/self/fd'))
        req=packet(core,abi,path,fd,builder);rc,out,receipt,streams,elapsed=owner.run(req)
        (D/(name+'.response')).write_bytes(out);(D/(name+'.core.json')).write_bytes(core);(D/(name+'.abi')).write_bytes(abi)
        assert rc==0,(name,'prepare',rc,[get(out,x) for x in range(8,128,8)],streams)
        assert get(out,40)==1 and get(out,32)==NONE and get(out,88)==expected,(name,'actual-probes',get(out,88),expected)
        assert receipt is not None and streams==(None,None)
        artifact=path.read_bytes();stat=path.stat()
        assert sha(artifact)==out[224:256].hex()==receipt['artifact_sha256']
        assert len(artifact)==get(out,328)==receipt['artifact_bytes']
        assert sha(core)==out[160:192].hex()==receipt['core_sha256']
        assert sha(abi)==out[192:224].hex() and sha(builder)==out[128:160].hex()
        assert (stat.st_dev,stat.st_ino)==(get(out,608),get(out,616))
        assert out[512:520]==b'HIAMVIR1' and out[1024:1032]==b'HIAMVPR1'
        loaded_fds=set(os.listdir('/proc/self/fd'));addresses=out[768:896]
        assert get(out,768)>0
        rcq,query,_,qstreams,qns=owner.run(operation(2),oc=2048)
        (D/(name+'.query')).write_bytes(query)
        assert get(query,40)==1 and query[768:896]==addresses and path.exists(),(name,'query',rcq,get(query,40))
        assert set(os.listdir('/proc/self/fd'))==loaded_fds and qstreams==(None,None)
        # No second preparation may reuse the actual holder.
        rcb,_,_,_,_=owner.run(req)
        assert rcb==0xfffffffd and set(os.listdir('/proc/self/fd'))==loaded_fds
        rcr,ret,_,rstreams,rns=owner.run(operation(1),oc=2048)
        (D/(name+'.retirement')).write_bytes(ret)
        assert rcr==0 and get(ret,40)==0 and ret[768:1024]==bytes(256),(name,'retire',rcr,[get(ret,x) for x in range(8,128,8)])
        assert not path.exists() and set(os.listdir('/proc/self/fd'))==baseline and rstreams==(None,None)
        rc2,ret2,_,_,_=owner.run(operation(1),oc=2048)
        assert rc2==0 and not path.exists() and set(os.listdir('/proc/self/fd'))==baseline
        row=dict(case=name,signatures=sigs,actual_native_calls=expected,actual_vm_calls=expected,vm_steps=get(out,96),prepare_ns=elapsed,build_ns=get(out,80),query_ns=qns,retirement_ns=rns,
                 artifact_bytes=len(artifact),artifact_sha256=sha(artifact),core_sha256=sha(core),abi_sha256=sha(abi),response_sha256=sha(out),query_sha256=sha(query),retirement_sha256=sha(ret),
                 same_path_and_holder=True,native_stage_sequencing=True,native_pin_before_report_validation=True)
        rows.append(row);print('NATIVE_PREPARE_OWNER_PASS',name,expected,elapsed,flush=True)
        del owner
    os.close(fd);total=sum(x['actual_native_calls'] for x in rows);count=sum(len(x['signatures']) for x in rows)
    if a.all_signatures:assert (len(rows),count,total)==(18,283,16547)
    report=dict(schema='hepta.hia.multiversion-native-prepare-owner.v1',whole_native_runtime=False,passed=len(rows),failed=0,positive_signatures=count,actual_native_calls=total,actual_vm_calls=total,
                vm_max_steps=4224,vm_max_depth=256,elapsed_ns=time.monotonic_ns()-start,owner_image_sha256=sha((a.directory/'prepare-owner.so').read_bytes()),
                builder=dict(path=str(a.builder),bytes=len(builder),sha256=sha(builder)),original_source_sha256=sha((ROOT/'hepta/hia_multiversion.py').read_bytes()),cases=rows)
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('NATIVE_PREPARE_OWNER_QUALIFIED',len(rows),count,total,flush=True)
if __name__=='__main__':main()
