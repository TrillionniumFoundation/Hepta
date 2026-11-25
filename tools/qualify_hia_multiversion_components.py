"""Development-only independent QA for private HIA MV components.

This is not a runtime adapter. Python here supplies original frozen facts and
checks real HIA machine calls. Original public-runtime proofs/filesystem and
native construction are separately compared; no injected success becomes a
production proof or publication capability.
"""
from pathlib import Path
import argparse,copy,ctypes,hashlib,json,mmap,os,struct,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[1]
U64=(1<<64)-1
ENTRY=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)
class Image:
    def __init__(self,path):
        self.path=Path(path);self.raw=self.path.read_bytes();self.memory=mmap.mmap(-1,len(self.raw),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
        self.memory.write(self.raw);self.address=ctypes.addressof(ctypes.c_ubyte.from_buffer(self.memory));self.entry=ENTRY(self.address)
    def __call__(self,raw,output,workspace):
        source=ctypes.create_string_buffer(raw,max(1,len(raw)))
        rc=self.entry(source,len(raw),output,len(output),workspace,len(workspace))
        assert source.raw==(raw or b'\0'),'immutable source changed'
        return rc
    @property
    def pin(self):return {'path':str(self.path),'bytes':len(self.raw),'sha256':hashlib.sha256(self.raw).hexdigest()}
def get(buffer,at):return struct.unpack_from('<Q',buffer,at)[0]
def put(buffer,at,value):struct.pack_into('<Q',buffer,at,value)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def compile_components(source,directory,seed):
    directory.mkdir(parents=True,exist_ok=True);rows=[]
    for role in ('multiversion_coordinator','multiversion_profile'):
        run=subprocess.run([sys.executable,'-m','tools.generate_hia_'+role],cwd=source,env={**os.environ,'PYTHONPATH':str(source)},capture_output=True,timeout=120)
        if run.returncode:raise RuntimeError(run.stderr.decode())
    for role in ('multiversion_coordinator','multiversion_profile','scalar_profile','generation_retention'):
        src=source/'examples/hia_bootstrap'/f'{role}.hepta';run=subprocess.run([str(seed),'compile'],input=src.read_bytes(),capture_output=True,timeout=60)
        (directory/f'{role}.stderr').write_bytes(run.stderr)
        if run.returncode:raise RuntimeError((role,run.returncode,run.stderr))
        (directory/f'{role}.flat').write_bytes(run.stdout);rows.append({'role':role,'source_sha256':sha(src.read_bytes()),'bytes':len(run.stdout),'sha256':sha(run.stdout)})
    result={'seed':str(seed),'seed_sha256':sha(seed.read_bytes()),'components':rows};(directory/'build.json').write_text(json.dumps(result,indent=2)+'\n');return result

def profile_cases():
    from tests.test_hia_scalar_profile_native import witnesses,basic,chain,repeated_operations
    from tests.test_hia_multiversion import scalar_program
    cases=witnesses()
    for n in (1,2,16,17,64,65):
        d=basic();d['functions']=[basic('f'+str(i))['functions'][0] for i in range(n)];cases.append(('functions-'+str(n),d,False))
    for n in (1,2,63,64,65):cases.append(('blocks-'+str(n),chain(n),False))
    for n in (2047,2048,2049):cases.append(('operations-'+str(n),repeated_operations(n),False))
    for typ in ('bool','i8','u8','i16','u16','i32','u32','i64','u64','isize','usize'):
        cases.append(('type-'+typ,scalar_program(None,typ=typ),False))
    for mode in ('wrap','checked','other',None,False,12):
        d=basic(typ='u64');b=d['functions'][0]['blocks'][0];b['ops']=[{'op':'int.cast','args':['x0'],'out':[{'name':'r','type':'u8'}],'attrs':{'mode':mode}}];b['term']['values']=['r'];d['functions'][0]['returns']=['u8'];d['functions'][0]['effects']=['trap'] if mode=='checked' else []
        cases.append(('cast-mode-'+repr(mode),d,True))
    return cases

def qualify_profile(directory):
    from hepta.hia_scalar_profile_native import packet,header
    from hepta.hia_program import verify_program,HIAProgramRejected
    from tests.test_hia_scalar_profile_native import original_functions,outcome,decode
    from types import SimpleNamespace
    native=Image(directory/'multiversion_profile.flat');policy=Image(directory/'scalar_profile.flat');_,original=original_functions();rows=[]
    scratch=ctypes.create_string_buffer(32<<20);out=ctypes.create_string_buffer(8<<20)
    for label,source,total in profile_cases():
        try:program=verify_program(source);data=program.as_dict();valid=True
        except HIAProgramRejected:program=SimpleNamespace(structured_bytes=None);data=source;valid=False
        raw=json.dumps(data,ensure_ascii=True,separators=(',',':')).encode()
        for phase in (0,1):
            for formatted in (False,True):
                inp=json.dumps(data,ensure_ascii=True,indent=2).encode() if formatted else raw
                put(out,0,int(total));put(out,8,phase);put(out,16,int(program.structured_bytes is not None))
                rc=native(inp,out,scratch)
                expected=header(program,data,prove_total=total) if phase==0 else packet(program,data,prove_total=total)
                if rc!=len(expected) or out.raw[:rc]!=expected:
                    (directory/'profile-failure.input').write_bytes(inp);(directory/'profile-failure.actual').write_bytes(out.raw[:min(rc,len(out))]);(directory/'profile-failure.expected').write_bytes(expected)
                    raise AssertionError((label,phase,formatted,'wire',rc,len(expected)))
                sink=ctypes.create_string_buffer(b'\xa5'*144,144);work=ctypes.create_string_buffer(8192);decision=policy(expected,sink,work)
                if phase==1 and valid:
                    actual=decode(decision,sink.raw,data);wanted=outcome(lambda: original(program,data,prove_total=total))
                    assert actual==wanted,(label,actual,wanted)
                rows.append({'case':label,'phase':phase,'pretty':formatted,'bytes':rc,'sha256':sha(expected),'decision':decision,'core_verified':valid})
    report={'schema':'hepta.hia.multiversion-profile-projection-qualification.v1','scope':'private Core-fact projection and original scalar policy, not complete runtime/proof','passed':len(rows),'failed':0,'images':[native.pin,policy.pin],'cases':rows}
    (directory/'profile-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('PROFILE_PASS',len(rows),flush=True);return report

def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=ROOT);p.add_argument('--directory',type=Path,required=True);p.add_argument('--seed',type=Path);a=p.parse_args()
    if a.seed:compile_components(a.source,a.directory,a.seed)
    qualify_profile(a.directory)
if __name__=='__main__':main()
