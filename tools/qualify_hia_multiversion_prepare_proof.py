"""Actual fresh per-export native proof preparation, with original MV oracle.

Fault injection replaces captured bytes only in a private mechanical observer.
No substituted evidence is accepted by the product or used as an expectation.
"""
from pathlib import Path
import argparse,copy,ctypes as C,fcntl,hashlib,json,os,struct,threading,time
from tools.qualify_hia_multiversion_components import Image
from tools.qualify_hia_multiversion_prepare_process import sealed,NONE
from tools.qualify_hia_multiversion_prepare_intake import Intake,packet as intake_packet
from hepta.hia_multiversion import _admit,_prove,MultiversionRejected
from tests.test_hia_multiversion import scalar_program
ROOT=Path(__file__).resolve().parents[1]
TYPES=('bool','i8','u8','i16','u16','i32','u32','i64','u64','isize','usize')
get=lambda x,a:struct.unpack_from('<Q',x,a)[0]
sha=lambda x:hashlib.sha256(x).hexdigest()
def packet(mode,core,after,abi,fd,image,timeout=2000,cancel=0):
    h=bytearray(256)
    struct.pack_into('<8s7Q',h,0,b'HIAMVPF1',mode,timeout,fd,cancel,len(core),len(after),len(abi))
    h[128:160]=hashlib.sha256(image).digest()
    return bytes(h)+core+after+abi
class Proof:
    def __init__(self,directory):
        self.directory=Path(directory);self.lib=C.CDLL(str(self.directory/'proof-preparation.so'))
        self.f=self.lib.hia_mv_prepare_proof;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
        self.o=C.create_string_buffer(16<<20);self.w=C.create_string_buffer(128<<20)
    def run(self,raw,*,oc=None,wc=None,driver=None):
        s=C.create_string_buffer(raw);C.memset(self.o,0xa5,len(self.o))
        before=set(os.listdir('/proc/self/fd'));started=time.monotonic_ns()
        rc=(self.f if driver is None else driver)(s,len(raw),self.o,len(self.o) if oc is None else oc,self.w,len(self.w) if wc is None else wc)
        elapsed=time.monotonic_ns()-started
        assert s.raw==raw+b'\0'
        out=self.o.raw;after=set(os.listdir('/proc/self/fd'));assert before==after,('FD leak',before,after)
        if rc==0xfffffffd:
            assert out[:512]==b'\xa5'*512
            return rc,out,[],elapsed
        assert out[:8]==b'HIAMVFR2' and get(out,8)==rc,(rc,out[:512].hex())
        extent=get(out,64);assert 512<=extent<=len(out)
        receipts=[];at=512
        while at<extent:
            n=get(out,at);assert n<=extent-at-8
            receipts.append(json.loads(out[at+8:at+8+n]));at+=8+n
        assert at==extent and out[extent:extent+64]==b'\xa5'*64
        return rc,out[:extent],receipts,elapsed
class FaultDriver:
    def __init__(self,directory,mutation):
        D=Path(directory);self.policy=Image(D/'multiversion_prepare_proof.flat');self.mutation=mutation
        b=json.loads((D/'build.json').read_text());self.roles={i+2:Image(x['path']) for i,x in enumerate(b['roles'][1:]) if i!=0}
        self.process=C.CDLL(str(D.parent/'native-multiversion-prepare-process-v4/process-component.so')).hia_mv_prepare_process
        self.process.argtypes=[C.c_void_p,C.c_uint64]*3;self.process.restype=C.c_uint32
        self.libc=C.CDLL(None,use_errno=True);self.libc.syscall.restype=C.c_long
    def __call__(self,s,sn,o,on,w,wn):
        waddr=C.addressof(w);saddr=C.addressof(s);oaddr=C.addressof(o)
        struct.pack_into('<Q',w,0,0);struct.pack_into('<Q',w,64,waddr)
        steps=0
        while True:
            action=self.policy.entry(s,sn,o,on,w,wn);steps+=1;assert steps<10000
            if action==0:return get(o,8)
            if action>=0xfffffff0:return action
            if action==6:continue
            if action==1:
                nr=get(o,0);mask=get(o,8);args=[]
                for i in range(6):args.append(get(o,16+i*8)+[0,waddr,saddr,oaddr][(mask>>(2*i))&3])
                C.set_errno(0);r=self.libc.syscall(C.c_long(nr),*[C.c_uint64(a) for a in args])
                if r==-1:r=-C.get_errno()
            else:
                vals=[get(w,a) for a in (16,24,32,40,48,56)]
                ptrs=(waddr+vals[0],vals[1],waddr+vals[2],vals[3],waddr+vals[4],vals[5])
                if action==2:
                    r=self.process(*ptrs)
                    if r==0:
                        po=vals[2];fd=get(w,po+48);n=get(w,po+64)
                        captured=os.pread(fd,n,0)
                        updated=self.mutation(captured)
                        if updated is not None:
                            newfd=sealed(updated,mode=0o600);os.close(fd)
                            struct.pack_into('<Q',w,po+48,newfd);struct.pack_into('<Q',w,po+64,len(updated))
                else:r=self.roles[action].entry(*ptrs)
            struct.pack_into('<Q',w,8,r&NONE)
def main():
    a=argparse.ArgumentParser();a.add_argument('--directory',type=Path,required=True);a.add_argument('--normalizer',type=Path,required=True);a.add_argument('--proof',type=Path,required=True);a.add_argument('--smoke',action='store_true');args=a.parse_args()
    D=args.directory;B=D.parent;native=Proof(D);normalfd=sealed(args.normalizer.read_bytes());proofbytes=args.proof.read_bytes();prooffd=sealed(proofbytes)
    normalizer=Intake(B/'native-multiversion-prepare-intake-v1/prepare-intake-component.so')
    rows=[];cache={}
    def admitted(doc,total=False):
        raw=json.dumps(doc,separators=(',',':')).encode();key=(raw,total)
        if key in cache:return cache[key]
        r,out,streams,elapsed=normalizer.run(intake_packet(raw,normalfd,total=total))
        assert r==0,('fresh-intake',r,get(out,16),streams)
        a,b,c=(get(out,x) for x in (32,40,48))
        core=out[320+a:320+a+b];abi=out[320+a+b:320+a+b+c];cache[key]=(core,abi)
        return core,abi
    def case(label,mode,before,after=None,total=False):
        core,abi=admitted(before,total);nextcore=admitted(after,total)[0] if mode==2 else b''
        status='proved';original_error=None
        try:
            bp,ba,proofs=_admit(before,prove_total=(mode==1 or total),timeout_ms=2000)
            if mode==2:
                ap,aa,_=_admit(after,prove_total=total,timeout_ms=2000);assert aa==ba
                _prove(bp,ap,ba,2000)
        except MultiversionRejected as e:status='not_proved';original_error=str(e)
        raw=packet(mode,core,nextcore,abi,prooffd,proofbytes)
        rc,out,receipts,elapsed=native.run(raw)
        assert (rc==0)==(status=='proved'),(label,rc,get(out,16),original_error,receipts)
        assert out[96:128]==hashlib.sha256(proofbytes).digest() and out[128:160]==hashlib.sha256(core).digest() and out[192:224]==hashlib.sha256(abi).digest()
        if rc==0:
            assert get(out,40)==get(abi,8)==len(receipts)
            assert all(r['status']=='proved' and r['validator_sha256']==sha(proofbytes) for r in receipts)
        else:assert rc==1 and receipts and receipts[-1]['status'] in ('unknown','disproved')
        rows.append({'case':label,'status':rc,'exports':get(abi,8),'successful':get(out,40),'original_error':original_error,'elapsed_ns':elapsed,'receipt_statuses':[r['status'] for r in receipts],'output_sha256':sha(out)})
        print('PREPARE_PROOF_PASS',label,rc,get(out,40),elapsed,flush=True)
        return raw,out
    base=scalar_program(None)
    first,firstout=case('identity-totality',1,base)
    case('identity-translation',2,base,base)
    if not args.smoke:
        for typ in TYPES:
            doc=scalar_program(None,typ=typ)
            case('scalar-totality-'+typ,1,doc)
            case('scalar-translation-'+typ,2,doc,doc)
        case('real-rewrite',2,scalar_program(),scalar_program('bit.xor'))
        case('different-behavior',2,base,scalar_program(value=1))
        checked=scalar_program('int.div.checked',value=0,typ='u8');checked['functions'][0]['effects']=['trap']
        case('actual-counterexample-totality',1,checked,total=True)
        safe=scalar_program('int.div.checked',value=1,typ='u8');safe['functions'][0]['effects']=['trap']
        case('proved-division-totality',1,safe,total=True)
        case('proved-division-translation',2,safe,safe,total=True)
        multi=scalar_program(None);multi['functions']=[]
        for i in range(16):
            fn=scalar_program(None,typ=TYPES[i%len(TYPES)])['functions'][0];fn['name']='entry_'+str(15-i);multi['functions'].append(fn)
        case('sixteen-sorted-exports-totality',1,multi)
        case('sixteen-sorted-exports-translation',2,multi,multi)
        # Malformed private framing must fail before any owned FD is duplicated.
        variants=[('magic',b'INVALID!'+first[8:]),('truncated',first[:-1]),('tail',first+b' ')]
        for at,vals in [(8,[0,3,NONE]),(16,[0,30001,NONE]),(24,[0,2,1<<31]),(32,[1,3]),(40,[0,8388609,NONE]),(48,[1,NONE]),(56,[0,335,NONE])]+[(i,[1]) for i in list(range(64,128,8))+list(range(160,256,8))]:
            for v in vals:
                x=bytearray(first);struct.pack_into('<Q',x,at,v);variants.append((str(at)+'-'+str(v),bytes(x)))
        for label,raw in variants:
            rc,out,_,_=native.run(raw);assert rc==0xfffffffd,(label,rc);rows.append({'case':'frame/'+label,'status':rc})
        for oc,wc in [(511,len(native.w)),(len(native.o),len(native.w)-1)]:
            rc,_,_,_=native.run(first,oc=oc,wc=wc);assert rc==0xfffffffd;rows.append({'case':'short-memory/'+str(oc)+'/'+str(wc),'status':rc})
        rc,out,_,_=native.run(first,oc=512);assert rc==6 and get(out,16)>512;rows.append({'case':'short-receipt-output','status':rc})
        x=bytearray(first);x[128]^=1;rc,out,_,_=native.run(bytes(x));assert rc==5 and get(out,16)==3;rows.append({'case':'wrong-actual-image-pin','status':rc})
        for label,body,mode,seals,want in [('unsealed',proofbytes,0o500,0,5),('wrong-mode',proofbytes,0o600,15,5),('bad-exec',b'X'*64,0o500,15,4)]:
            fd=sealed(body,mode=mode,seal=seals);core,abi=admitted(base);raw=packet(1,core,b'',abi,fd,body)
            rc,out,_,_=native.run(raw);os.close(fd);assert rc==want,(label,rc,get(out,16));rows.append({'case':label,'status':rc,'detail':get(out,16)})
        token=C.c_uint64(1);core,abi=admitted(base);raw=packet(1,core,b'',abi,prooffd,proofbytes,cancel=C.addressof(token))
        rc,out,_,_=native.run(raw);assert rc==4 and get(out,16)==2;rows.append({'case':'cancel-before-owned-child','status':rc,'detail':get(out,16)})
        token.value=0
        def cancel():time.sleep(.04);token.value=1
        t=threading.Thread(target=cancel);t.start();rc,out,_,elapsed=native.run(raw);t.join()
        assert rc==4 and get(out,16)==2 and elapsed<2_000_000_000;rows.append({'case':'cancel-during-child','status':rc,'detail':get(out,16),'elapsed_ns':elapsed})
        # Actual child replies are captured first. A private observer then replaces
        # its sealed stdout with controlled corruption; the actual HIA policy must reject.
        mutations={
          'schema':lambda r:r.update(schema='wrong'),
          'profile':lambda r:r.update(profile='wrong'),
          'function':lambda r:r.update(function='other'),
          'core-hash':lambda r:r.update(program_sha256='0'*64),
          'input-hash':lambda r:r.update(input_sha256='0'*64),
          'validator-image':lambda r:r.update(validator_sha256='0'*64),
          'scope':lambda r:r.update(scope='wrong'),
          'structural':lambda r:r.update(structural_verification=False),
          'canonical-claim':lambda r:r['claims'].update(canonical_core_reverified=False),
          'all-input-claim':lambda r:r['claims'].update(all_inputs_return_normally_proved=False),
          'counterexample':lambda r:r.update(counterexample={}),
          'authority':lambda r:r.update(execution_authority=True),
          'checker-kind':lambda r:r['checker'].update(kind='wrong'),
          'checker-runtime':lambda r:r['checker']['runtime'].update(implementation='wrong'),
          'checker-inventory':lambda r:r['checker'].update(source_identity_sha256='0'*64),
          'checker-source-image':lambda r:r['checker']['source_identity'].update({'native-closure.image.bin':'0'*64}),
          'checker-extra-image':lambda r:r['checker']['source_identity'].update({'extra':'0'*64}),
          'solver-closure':lambda r:r['solver']['identity'].update(native_closure_sha256='0'*64),
          'solver-result':lambda r:r['solver'].update(result='sat'),
          'subject-function':lambda r:r['subject'].update(function='other'),
        }
        for label,change in mutations.items():
            def mutate(captured,change=change):
                assert captured[:8]==b'HIAMVR01'
                report=json.loads(captured[64:]);change(report);body=json.dumps(report,separators=(',',':')).encode()
                h=bytearray(captured[:64]);struct.pack_into('<Q',h,24,len(body));return bytes(h)+body
            driver=FaultDriver(D,mutate);rc,out,_,elapsed=native.run(first,driver=driver)
            assert rc==5,(label,rc,get(out,16));rows.append({'case':'captured-fault/'+label,'status':rc,'detail':get(out,16),'elapsed_ns':elapsed})
        for label,mutate in [('empty',lambda b:b''),('truncated',lambda b:b[:-1]),('tail',lambda b:b+b' '),('wrong-header',lambda b:b'INVALID!'+b[8:])]:
            rc,out,_,elapsed=native.run(first,driver=FaultDriver(D,mutate));assert rc in (3,5),(label,rc,get(out,16));rows.append({'case':'captured-frame/'+label,'status':rc,'detail':get(out,16)})
    os.close(normalfd);os.close(prooffd)
    report={'schema':'hepta.hia.multiversion-proof-preparation.qualification.v1','whole_native_runtime':False,'scope':'fresh actual normalized Core and native per-export proof; fixed HIA parent/captured child identity and receipt binding, not final runtime publication','image_sha256':sha((D/'proof-preparation.so').read_bytes()),'proof_image_sha256':sha(proofbytes),'passed':len(rows),'failed':0,'cases':rows}
    (D/('smoke-qualification.json' if args.smoke else 'qualification.json')).write_text(json.dumps(report,indent=2)+'\n')
    print('PREPARE_PROOF_QUALIFICATION_PASS',len(rows),flush=True)
if __name__=='__main__':main()
