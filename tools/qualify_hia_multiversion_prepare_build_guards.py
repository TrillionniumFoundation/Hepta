"""Actual constructor capture guards; private corruption is solely external QA."""
from pathlib import Path
import argparse,ctypes as C,copy,hashlib,json,os,struct,time
from tools.qualify_hia_multiversion_prepare_build import Build,packet,get,sha
from tools.qualify_hia_multiversion_prepare_proof import FaultDriver as BaseFaultDriver
from tools.qualify_hia_multiversion_components import Image
from tools.qualify_hia_multiversion_prepare_process import sealed,NONE
class FaultDriver(BaseFaultDriver):
    def __init__(self,directory,mutation):
        D=Path(directory);self.policy=Image(D/'multiversion_prepare_build.flat');self.mutation=mutation
        b=json.loads((D/'build.json').read_text());self.roles={i+2:Image(x['path']) for i,x in enumerate(b['roles'][1:]) if i!=0}
        self.process=C.CDLL(str(D.parent/'native-multiversion-prepare-process-v4/process-component.so')).hia_mv_prepare_process
        self.process.argtypes=[C.c_void_p,C.c_uint64]*3;self.process.restype=C.c_uint32
        self.libc=C.CDLL(None,use_errno=True);self.libc.syscall.restype=C.c_long

def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--chain',type=Path,required=True);p.add_argument('--builder',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    D=a.output;D.mkdir(exist_ok=True,parents=True);new=Build(a.directory)
    core=(a.chain/'batch-00.core.json').read_bytes();abi=(a.chain/'batch-00.abi').read_bytes();image=a.builder.read_bytes();fd=sealed(image);rows=[]
    def case(label,raw,want,driver=None,detail=None,oc=None,wc=None):
        rc,out,receipt,streams,wall=new.run(raw,driver=driver,oc=oc,wc=wc)
        assert rc==want,(label,rc,want,get(out,16),streams)
        if detail is not None:assert get(out,16)==detail,(label,get(out,16),detail)
        rows.append({'case':label,'status':rc,'detail':get(out,16) if rc<0xfffffff0 else None,'wall_ns':wall,'output_sha256':sha(out),'streams':[None if x is None else {'bytes':len(x),'sha256':sha(x)} for x in streams]})
        print('BUILD_GUARD_PASS',label,rc,flush=True);return out,receipt,streams
    first=packet(core,abi,D/'not-built-private.so',fd,image)
    variants=[('magic',b'INVALID!'+first[8:]),('truncated',first[:-1]),('tail',first+b' ')]
    for at,values in [(8,[1]),(16,[0,2,1<<31]),(24,[0]),(32,[1,3]),(40,[0,8388609,NONE]),(48,[0,335,5137,NONE]),(56,[0,4096,NONE])]+[(i,[1]) for i in list(range(64,128,8))+list(range(160,256,8))]:
        for value in values:
            raw=bytearray(first);struct.pack_into('<Q',raw,at,value);variants.append((str(at)+'-'+str(value),bytes(raw)))
    for label,raw in variants:case('frame/'+label,raw,0xfffffffd)
    for oc,wc in [(511,len(new.w)),(len(new.o),len(new.w)-1)]:case('short-private/'+str(oc)+'/'+str(wc),first,0xfffffffd,oc=oc,wc=wc)
    assert not (D/'not-built-private.so').exists()
    raw=bytearray(first);raw[128]^=1;case('wrong-sealed-image-sha',bytes(raw),3,detail=3)
    for label,mode,seals in [('unsealed',0o500,0),('nonexec',0o600,15)]:
        bad=sealed(image,mode=mode,seal=seals)
        try:case(label,packet(core,abi,D/(label+'.so'),bad,image),3)
        finally:os.close(bad)
    case('expired-before-child',packet(core,abi,D/'expired.so',fd,image,deadline=time.monotonic_ns()-1),2,detail=1)
    cancel=C.c_uint64(1);case('cancel-before-child',packet(core,abi,D/'cancel.so',fd,image,cancel=C.addressof(cancel)),2,detail=2)
    bad=sealed(b'X'*64)
    try:case('actual-exec-refusal',packet(core,abi,D/'bad-exec.so',bad,b'X'*64),2)
    finally:os.close(bad)
    out,receipt,streams=case('actual-constructor-rejects-invalid-Core',packet(b'!',abi,D/'invalid-core.so',fd,image),1)
    assert get(out,24)!=0 and streams[0] is not None and streams[1] is not None and get(out,104)==1 and not (D/'invalid-core.so').exists()
    case('short-receipt-after-real-construction',packet(core,abi,D/'short-result.so',fd,image),4,oc=512)
    changes={
      'schema':lambda r:r.update(schema='wrong'),'profile':lambda r:r.update(profile='wrong'),'target':lambda r:r.update(target='wrong'),'kind':lambda r:r.update(kind='object'),'status':lambda r:r.update(status='proved'),'ok':lambda r:r.update(ok=False),
      'Core-binding':lambda r:r.update(core_sha256='0'*64),'input-binding':lambda r:r.update(input_sha256='0'*64),'artifact-format':lambda r:r.update(artifact_sha256='x'*64),'object-format':lambda r:r.update(object_sha256='x'*64),'text-format':lambda r:r.update(machine_text_sha256='x'*64),
      'artifact-min':lambda r:r.update(artifact_bytes=63),'artifact-max':lambda r:r.update(artifact_bytes=67108865),'artifact-type':lambda r:r.update(artifact_bytes=True),'text-zero':lambda r:r.update(machine_text_bytes=0),'text-max':lambda r:r.update(machine_text_bytes=16777217),'exports':lambda r:r.update(exports=[]),'foreign-exports':lambda r:r.update(foreign_buffer_exports=['other']),
      'Core-reverified':lambda r:r['claims'].update(standalone_core_reverified=False),'fallback':lambda r:r['claims'].update(fallback_used=True),'llvm-ir':lambda r:r['claims'].update(llvm_ir_used=True),'external-linker':lambda r:r['claims'].update(external_linker_used=True),
      'inventory-schema':lambda r:r['binary_inventory'].update(schema='wrong'),'inventory-format':lambda r:r['binary_inventory'].update(format='wrong'),'inventory-kind':lambda r:r['binary_inventory'].update(kind='wrong'),'inventory-machine':lambda r:r['binary_inventory'].update(machine=3),'inventory-exports':lambda r:r['binary_inventory'].update(dynamic_exports=[]),'inventory-source':lambda r:r['binary_inventory'].update(source_exports_rechecked=False)
    }
    for i,(label,change) in enumerate(changes.items()):
        def mutate(captured,change=change):
            r=json.loads(captured);change(r);return json.dumps(r,separators=(',',':')).encode()
        case('captured/'+label,packet(core,abi,D/('fault-'+str(i)+'.so'),fd,image),3,driver=FaultDriver(a.directory,mutate),detail=10)
    for i,(label,mutate) in enumerate([('empty',lambda x:b''),('truncated',lambda x:x[:-2]),('not-json',lambda x:b'!'),('over-capture-declaration',lambda x:x+bytes(1048577-len(x))) ]):
        case('captured-frame/'+label,packet(core,abi,D/('frame-'+str(i)+'.so'),fd,image),3,driver=FaultDriver(a.directory,mutate))
    os.close(fd)
    report={'schema':'hepta.hia.multiversion-build-preparation-guards.v1','whole_native_runtime':False,'passed':len(rows),'failed':0,'image_sha256':sha((a.directory/'build-preparation.so').read_bytes()),'actual_constructor_sha256':sha(image),'scope':'Private frame/capture/ownership and actual native constructor receipt guards. Every changed receipt originates in a completed actual sealed constructor call; an external QA observer alters only the captured stdout.','cases':rows}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('BUILD_GUARDS_QUALIFIED',len(rows),flush=True)
if __name__=='__main__':main()
