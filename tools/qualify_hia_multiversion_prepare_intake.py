"""Fresh original verification/profile versus native normalized intake.

This external observer does not provide normalized bytes or profile facts to
native code. The actual captured constructor produces them in a child process.
"""
from pathlib import Path
import argparse,ctypes as C,fcntl,hashlib,json,os,struct,time,copy
from tools.qualify_hia_multiversion_prepare_process import sealed,NONE
from tools.qualify_hia_multiversion_components import profile_cases
from hepta.hia_program import verify_program,HIAProgramRejected
from hepta.hia_multiversion import MultiversionRejected
from hepta.hia_scalar_profile_native import REASONS
from tests.test_hia_scalar_profile_native import original_functions,basic

TYPES=('bool','i8','u8','i16','u16','i32','u32','i64','u64','isize','usize')
def abi_bytes(program, abi):
    data = program.as_dict()
    names = [f['name'] for f in data['functions']]
    raw = bytearray(struct.pack('<8sQ', b'HIAMVAB1', len(abi)))
    for a in abi:
        name = a.function.encode()
        row = bytearray(320)
        struct.pack_into('<4Q', row, 0, names.index(a.function), len(name), len(a.parameters), 1 + TYPES.index(a.result))
        row[32:32 + len(name)] = name
        for i, t in enumerate(a.parameters):
            struct.pack_into('<Q', row, 160 + i * 8, 1 + TYPES.index(t))
        raw.extend(row)
    return bytes(raw)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def get(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def packet(raw,fd,total=False,deadline=None,cancel=0):
    if deadline is None:deadline=time.monotonic_ns()+30_000_000_000
    return struct.pack('<8s15Q',b'HIAMVNQ1',int(total),fd,deadline,cancel,len(raw),*([0]*10))+raw
class Intake:
    def __init__(self,path):
        self.lib=C.CDLL(str(path));self.f=self.lib.hia_mv_prepare_intake;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
        self.o=C.create_string_buffer((16<<20)+16384);self.w=C.create_string_buffer(256<<20)
    def run(self,request,oc=None,wc=None):
        s=C.create_string_buffer(request);C.memset(self.o,0xa5,len(self.o));before=set(os.listdir('/proc/self/fd'));begin=time.monotonic_ns()
        rc=self.f(s,len(request),self.o,len(self.o) if oc is None else oc,self.w,len(self.w) if wc is None else wc);elapsed=time.monotonic_ns()-begin
        assert s.raw==request+b'\0'
        raw=self.o.raw;streams=[]
        if rc!=0xfffffffd:
            assert raw[:8]==b'HIAMVNP1' and get(raw,8)==rc,(rc,raw[:320].hex())
            for at,nat in [(256,232),(264,240)]:
                fd=get(raw,at);n=get(raw,nat)
                if fd==NONE:streams.append(None);continue
                assert rc==1 and fd>=3 and fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15 and os.fstat(fd).st_size==n
                body=os.pread(fd,n,0);assert len(body)==n;os.close(fd);streams.append(body)
        assert before==set(os.listdir('/proc/self/fd')),('FD leak',rc,before,set(os.listdir('/proc/self/fd')))
        return rc,raw,streams,elapsed

def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--normalizer',type=Path,required=True);p.add_argument('--fixtures',type=Path);p.add_argument('--smoke',action='store_true');a=p.parse_args();D=a.directory
    image=a.normalizer.read_bytes();fd=sealed(image);native=Intake(D/'prepare-intake-component.so');_,original=original_functions();rows=[];cases={}
    def add(label,raw,total=False):
        k=(sha(raw),total)
        if k not in cases:cases[k]={'raw':raw,'total':total,'labels':[]}
        cases[k]['labels'].append(label)
    if a.smoke:
        for label,d,total in list(profile_cases())[:4]:add(label,json.dumps(d,separators=(',',':')).encode(),total)
        raw=json.dumps(basic(),separators=(',',':')).encode();add('truncated',raw[:-1]);add('pretty',json.dumps(basic(),indent=2).encode())
    else:
        for label,d,total in profile_cases():
            for pretty in (False,True):add(label+('-pretty' if pretty else '-compact'),json.dumps(d,ensure_ascii=False,indent=2 if pretty else None,separators=None if pretty else (',',':')).encode(),total)
        if a.fixtures:
            for path in sorted(a.fixtures.glob('*.json')):add('normalizer/'+path.name,path.read_bytes())
        for folder in [D.parent/'native-multiversion-call-v5',D.parent/'native-multiversion-probe-owner-all-v2']:
            for path in sorted(folder.rglob('*.core.json')):add('actual-built/'+str(path.relative_to(folder)),path.read_bytes(),'proved-total' in path.name)
        raw=json.dumps(basic(),separators=(',',':')).encode()
        for label,data in [('exact-eight-MiB',raw+b' '*(8388608-len(raw))),('truncated',raw[:-1]),('duplicate',raw.replace(b'{',b'{"schema":"hepta.hia.program.v1",',1)),('invalid-utf8',raw+b'\xff'),('trailing',raw+b'0')]:add(label,data)
        for suffix in [b'\n',b' \r\n\t '*127]:add('raw-whitespace-'+str(len(suffix)),raw+suffix)
    for index,item in enumerate(cases.values()):
        raw=item['raw'];total=item['total'];error=None;program=None;abi=None;detail=None
        try:
            program=verify_program(raw)
            try:abi=original(program,program.as_dict(),prove_total=total);expected=0;detail=0
            except MultiversionRejected as exc:
                expected=3;message=str(exc).removeprefix('E_HIA_MULTIVERSION: ');detail=next(k for k,v in REASONS.items() if v==message)
        except HIAProgramRejected as exc:expected=1;error=str(exc)
        request=packet(raw,fd,total);rc,out,streams,elapsed=native.run(request)
        if rc!=expected or (expected==3 and get(out,16)!=detail):
            (D/'failed-prepare-intake.input').write_bytes(request);(D/'failed-prepare-intake.output').write_bytes(out[:65536]);raise AssertionError((index,item['labels'],rc,expected,get(out,16),detail,out[:320].hex()))
        assert get(out,24)==len(raw) and out[80:112]==hashlib.sha256(raw).digest()
        if program is not None:
            core=program.canonical_bytes;orig=program.structured_bytes or core
            assert out[112:144]==hashlib.sha256(orig).digest() and out[144:176]==hashlib.sha256(core).digest()
            assert get(out,32)==len(orig) and get(out,40)==len(core) and get(out,64)==total
        if rc==0:
            aw=abi_bytes(program,abi);end=320+len(orig)+len(core)+len(aw)
            assert get(out,48)==len(aw) and get(out,56)==len(abi) and get(out,72)==0 and get(out,248)==63
            assert out[176:208]==hashlib.sha256(aw).digest() and out[320:end]==orig+core+aw and out[end:end+64]==b'\xa5'*64
            assert get(out,256)==NONE and get(out,264)==NONE and out[272:320]==bytes(48)
        elif rc==1:
            assert streams[0] is not None and streams[1] is not None and get(out,216)==512
            diagnostic=json.loads(streams[0]);assert diagnostic['diagnostics'][0]['message']==error,(item['labels'],diagnostic,error)
            assert streams[1]==b'' and out[320:576]==b'\xa5'*256
        else:
            assert get(out,256)==NONE and get(out,264)==NONE and out[320:576]==b'\xa5'*256
        rows.append({'case':index,'labels':item['labels'],'raw_bytes':len(raw),'raw_sha256':sha(raw),'status':rc,'detail':get(out,16),'elapsed_ns':elapsed,'original_canonical_sha256':out[112:144].hex(),'core_sha256':out[144:176].hex(),'totality_proof_not_claimed':True})
        print('PREPARE_INTAKE_PAIR_PASS',index,item['labels'][0],rc,get(out,16),elapsed,flush=True)
    if not a.smoke:
        raw=json.dumps(basic(),separators=(',',':')).encode();base=packet(raw,fd)
        variants=[('magic',b'INVALID!'+base[8:]),('truncated',base[:-1]),('tail',base+b' ')]
        for at,values in [(8,[2,NONE]),(16,[0,2,2147483648]),(24,[0]),(32,[1]),(40,[8388609,NONE])]+[(n,[1]) for n in range(48,128,8)]:
            for value in values:
                v=bytearray(base);struct.pack_into('<Q',v,at,value);variants.append(('field-'+str(at)+'-'+str(value),bytes(v)))
        for label,request in variants:
            rc,out,_,elapsed=native.run(request);assert rc==0xfffffffd and out[:320]==b'\xa5'*320,(label,rc);rows.append({'case':'private/'+label,'status':rc})
        for label,oc,wc in [('short-output',319,len(native.w)),('short-work',len(native.o),len(native.w)-1)]:
            rc,out,_,_=native.run(base,oc,wc);assert rc==0xfffffffd and out[:320]==b'\xa5'*320;rows.append({'case':label,'status':rc})
        rc,out,_,_=native.run(packet(raw,fd),320);assert rc==6 and get(out,16)>320 and out[320:576]==b'\xa5'*256;rows.append({'case':'insufficient-payload','status':rc,'required_bytes':get(out,16)})
        rc,out,_,_=native.run(packet(raw,fd,deadline=time.monotonic_ns()-1));assert rc==7 and get(out,16)==1;rows.append({'case':'expired-before-launch','status':rc})
        token=C.c_uint64(1);rc,out,_,_=native.run(packet(raw,fd,cancel=C.addressof(token)));assert rc==7 and get(out,16)==2;rows.append({'case':'cancel-before-launch','status':rc})
        token.value=2;rc,out,_,_=native.run(packet(raw,fd,cancel=C.addressof(token)));assert rc==0;rows.append({'case':'committed-token','status':rc})
    os.close(fd);assert image==a.normalizer.read_bytes()
    report={'schema':'hepta.hia.multiversion-prepare-intake.qualification.v1','whole_native_runtime':False,'scope':'fresh original normalization/verification, exact three identities, original scalar profile and sorted ABI; no proof/publication claim','image_sha256':sha((D/'prepare-intake-component.so').read_bytes()),'normalizer_sha256':sha(image),'passed':len(rows),'failed':0,'cases':rows}
    (D/('smoke.json' if a.smoke else 'qualification.json')).write_text(json.dumps(report,indent=2)+'\n');print('PREPARE_INTAKE_PASS',len(rows),flush=True)
if __name__=='__main__':main()
