"""Fresh constructor -> exact same path/holder -> complete native VM probes."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,random,struct,time
from tools.qualify_hia_multiversion_prepare_process import sealed,NONE
from tools.qualify_hia_multiversion_prepare_intake import Intake,packet as intake_packet,abi_bytes
from tools.qualify_hia_multiversion_probe_owner import Probe
from tools.qualify_hia_multiversion_call import function,document
from tools.generate_hia_multiversion_abi import TYPES
from hepta.hia_multiversion import _admit,ScalarABI,_probe_vectors
get=lambda x,a:struct.unpack_from('<Q',x,a)[0]
sha=lambda x:hashlib.sha256(x).hexdigest()
def packet(core,abi,path,fd,image,cancel=0,deadline=None):
    p=os.fsencode(path);h=bytearray(256)
    struct.pack_into('<8s7Q',h,0,b'HIAMVBF1',0,fd,time.monotonic_ns()+60_000_000_000 if deadline is None else deadline,cancel,len(core),len(abi),len(p))
    h[128:160]=hashlib.sha256(image).digest()
    return bytes(h)+core+abi+p
class Build:
    def __init__(self,D):
        self.D=Path(D);self.lib=C.CDLL(str(self.D/'build-preparation.so'));self.f=self.lib.hia_mv_prepare_build
        self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
        self.o=C.create_string_buffer((1<<20)+512);self.w=C.create_string_buffer(128<<20)
    def run(self,raw,oc=None,wc=None,driver=None):
        source=C.create_string_buffer(raw);C.memset(self.o,0xa5,len(self.o));before=set(os.listdir('/proc/self/fd'));start=time.monotonic_ns()
        rc=(self.f if driver is None else driver)(source,len(raw),self.o,len(self.o) if oc is None else oc,self.w,len(self.w) if wc is None else wc)
        elapsed=time.monotonic_ns()-start;assert source.raw==raw+b'\0';out=self.o.raw
        if rc>=0xfffffff0:
            assert out[:512]==b'\xa5'*512 and set(os.listdir('/proc/self/fd'))==before
            return rc,out[:512],None,(),elapsed
        assert out[:8]==b'HIAMVBR1' and get(out,8)==rc
        streams=[]
        for at in (88,96):
            fd=get(out,at)
            if fd==NONE:streams.append(None)
            else:
                streams.append(os.pread(fd,os.fstat(fd).st_size,0));os.close(fd)
        assert set(os.listdir('/proc/self/fd'))==before
        n=get(out,80);assert n<=len(out)-512
        receipt=json.loads(out[512:512+n]) if n else None
        return rc,out[:512+n],receipt,tuple(streams),elapsed
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--normalizer',type=Path,required=True);p.add_argument('--builder',type=Path,required=True);p.add_argument('--all-signatures',action='store_true');a=p.parse_args()
    D=a.output;D.mkdir(exist_ok=True,parents=True);B=a.directory.parent
    new=Build(a.directory);normal=Intake(B/'native-multiversion-prepare-intake-v1/prepare-intake-component.so')
    normalbytes=a.normalizer.read_bytes();builderbytes=a.builder.read_bytes();normalfd=sealed(normalbytes);buildfd=sealed(builderbytes)
    # This symlink selects only the already-qualified immutable owner component.
    target=B/'native-multiversion-probe-owner-v2/probe-component.so'
    if not (D/'probe-component.so').exists():os.symlink(target,D/'probe-component.so')
    probe=Probe(D,B/'native-multiversion-image-v5',B/'native-multiversion-retirement-v2')
    rows=[];start=time.monotonic_ns();total=0
    inputs=[([typ]*n,typ+'-'+str(n),typ) for typ in TYPES for n in range(17)]
    rng=random.Random(0x4d565052)
    for i in range(96):inputs.append(([rng.choice(TYPES) for _ in range(rng.randrange(17))],'mixed-'+str(i),TYPES[i%len(TYPES)]))
    if not a.all_signatures:inputs=inputs[:16]
    for first in range(0,len(inputs),16):
        group=inputs[first:first+16];functions=[];expected=0;signatures=[]
        for i,(types,label,result0) in enumerate(group,first):
            selected=i%len(types) if types else 0;result=types[selected] if types else result0;name='signature_'+str(i).zfill(4)
            functions.append(function(name,types,result=result,selected=selected))
            count=len(_probe_vectors(ScalarABI(name,tuple(types),result)));expected+=count
            signatures.append({'case':label,'function':name,'parameters':types,'result':result,'selected':selected,'vectors':count})
        label='batch-'+str(first//16).zfill(2);raw=json.dumps(document(functions),separators=(',',':')).encode()
        original,original_abi,_=_admit(raw)
        rc,intake,streams,intake_ns=normal.run(intake_packet(raw,normalfd));assert rc==0,(label,'intake',rc,get(intake,16),streams)
        origN,coreN,abiN=(get(intake,x) for x in (32,40,48));core=intake[320+origN:320+origN+coreN];abi=intake[320+origN+coreN:320+origN+coreN+abiN]
        assert sha(core)==original.sha256 and abi==abi_bytes(original,original_abi)
        path=D/(label+'-actual-built.so');request=packet(core,abi,path,buildfd,builderbytes)
        rc,out,receipt,streams,build_ns=new.run(request);assert rc==0,(label,'actual-build',rc,get(out,16),streams)
        artifact=path.read_bytes();assert len(artifact)==get(out,32)==receipt['artifact_bytes'] and sha(artifact)==out[224:256].hex()==receipt['artifact_sha256']
        (D/(label+'.core.json')).write_bytes(core);(D/(label+'.abi')).write_bytes(abi);(D/(label+'.build.response')).write_bytes(out)
        # Load the constructor's exact published pathname: no copying it to a
        # different QA artifact and no second holder before actual native probes.
        probe.path=path;probe.abi=abi;C.memset(probe.f.work,0,8192);pathraw=os.fsencode(path)
        frame=struct.pack('<8sQQQ',b'HIAMVI01',len(pathraw),len(abi),len(artifact))+hashlib.sha256(artifact).digest()+pathraw+abi
        s=C.create_string_buffer(frame);fds=set(os.listdir('/proc/self/fd'))
        rc=probe.f.entry(s,len(frame),probe.f.out,512,probe.f.work,len(probe.f.work));assert rc==0,(label,'same-path-capture',rc)
        image_result=probe.f.out.raw;assert image_result[64:96]==hashlib.sha256(artifact).digest()
        inode=path.stat();assert (inode.st_dev,inode.st_ino)==(get(image_result,96),get(image_result,104))
        try:row=probe.probe(label,core,0,expected);total+=expected
        finally:probe.retire()
        assert not path.exists() and set(os.listdir('/proc/self/fd'))==fds
        row.update({'actual_constructor_sha256':sha(builderbytes),'actual_artifact_sha256':sha(artifact),'artifact_bytes':len(artifact),'intake_ns':intake_ns,'build_ns':build_ns,'constructor_reply_sha256':sha(out),'image_reply_sha256':sha(image_result),'retirement_reply_sha256':sha(probe.rout.raw),'same_path_and_holder':True,'original_abi_verified':True,'signatures':signatures});rows.append(row)
        print('NATIVE_PREPARATION_CHAIN_PASS',label,expected,build_ns,flush=True)
    os.close(normalfd);os.close(buildfd)
    if a.all_signatures:assert len(inputs)==283 and len(rows)==18 and total==16547
    report={'schema':'hepta.hia.multiversion-native-preparation-chain.v1','whole_native_runtime':False,'scope':'All stages execute actual HIA native owners and actual child, loader, mapping, VM, ABI and retirement. This QA harness supplies the component sequencing; final native coordinator composition remains pending.','passed':len(rows),'failed':0,'positive_signatures':len(inputs),'actual_native_calls':total,'actual_vm_calls':total,'vm_max_steps':4224,'vm_max_depth':256,'elapsed_ns':time.monotonic_ns()-start,'normalizer':{'path':str(a.normalizer),'bytes':len(normalbytes),'sha256':sha(normalbytes)},'constructor':{'path':str(a.builder),'bytes':len(builderbytes),'sha256':sha(builderbytes)},'build_image_sha256':sha((a.directory/'build-preparation.so').read_bytes()),'image_owner_sha256':sha((B/'native-multiversion-image-v5/image-component.so').read_bytes()),'probe_owner_sha256':sha(target.read_bytes()),'retirement_owner_sha256':sha((B/'native-multiversion-retirement-v2/retirement-component.so').read_bytes()),'cases':rows}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('NATIVE_PREPARATION_CHAIN_QUALIFIED',len(rows),total,flush=True)
if __name__=='__main__':main()
