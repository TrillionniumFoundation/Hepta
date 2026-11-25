"""Independent, development-only qualification of HIA MV ABI/call components.

Runs actual general-native shared objects produced with PATH empty, original
exact scalar predicates and a fresh independent Core VM for every native call.
The tiny assembly invoker is built as a development mechanical fixture only.
This does not claim a completed generation loader or publication controller.
"""
from pathlib import Path
import argparse,copy,ctypes,hashlib,json,mmap,os,random,struct,subprocess,sys,time
from tools.qualify_hia_multiversion_components import Image,get,put,sha
from tools.generate_hia_multiversion_abi import TYPES
from hepta.hia_program import verify_program,execute_program,scalar_value_valid
from hepta.hia_multiversion import _reference_scalar_profile,_CTYPES,_probe_vectors,ScalarABI
ROOT=Path(__file__).resolve().parents[1]
U64=(1<<64)-1
CODES={name:i+1 for i,name in enumerate(TYPES)}
def function(name,types,result=None,selected=0,operation=None):
    result=result or (types[selected] if types else 'u64')
    params=[{'name':'x'+str(i),'type':t} for i,t in enumerate(types)]
    ops=[];value='x'+str(selected)
    if not types:
        value='zero';ops=[{'op':'const','args':[],'out':[{'name':value,'type':result}],'attrs':{'value':False if result=='bool' else 0}}]
    if operation:
        ops=[{'op':'const','args':[],'out':[{'name':'one','type':result}],'attrs':{'value':1}},
             {'op':operation,'args':[value,'one'],'out':[{'name':'answer','type':result}],'attrs':{}}];value='answer'
    return {'name':name,'params':params,'returns':[result],'effects':['trap'] if operation else [],'entry':'entry',
            'blocks':[{'id':'entry','params':copy.deepcopy(params),'ops':ops,'term':{'op':'ret','values':[value]}}]}
def document(functions):return {'schema':'hepta.hia.program.v7','module':'native_mv_call','functions':functions}
def decode_abi(raw):
    assert raw[:8]==b'HIAMVAB1'
    n=struct.unpack_from('<Q',raw,8)[0];assert len(raw)==16+320*n
    result=[]
    for i in range(n):
        r=raw[16+i*320:16+(i+1)*320];index,name_n,argc,typ=struct.unpack_from('<4Q',r)
        assert r[32+name_n:160]==bytes(128-name_n) and r[160+argc*8:320]==bytes(160-argc*8)
        result.append((index,r[32:32+name_n].decode(),tuple(TYPES[x-1] for x in struct.unpack_from('<'+'Q'*argc,r,160)),TYPES[typ-1]))
    return result
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--profile-directory',type=Path,required=True);p.add_argument('--builder',type=Path,required=True);a=p.parse_args()
    D=a.directory;D.mkdir(exist_ok=True)
    call=Image(D/'multiversion_call.flat');materializer=Image(D/'multiversion_abi.flat')
    profile=Image(a.profile_directory/'multiversion_profile.flat');policy=Image(a.profile_directory/'scalar_profile.flat')
    out=ctypes.create_string_buffer(152);work=ctypes.create_string_buffer(512)
    pwork=ctypes.create_string_buffer(32<<20);pout=ctypes.create_string_buffer(8<<20)
    awork=ctypes.create_string_buffer(8192);abiout=ctypes.create_string_buffer(16+320*16)
    rows=[];builds=[];normal=0;refused=0;returns=0;actualcalls=0;abi_cases=0
    def arguments(types,vals,raw=None):
        put(work,0,0);put(work,8,len(types));put(work,16,9)
        for i,t in enumerate(types):put(work,24+i*8,CODES[t])
        value=json.dumps(vals,separators=(',',':'),ensure_ascii=True,allow_nan=True).encode() if raw is None else raw
        rc=call(value,out,work)
        return rc,bytes(out.raw[:rc]) if rc<=len(out) else b''
    for typ in TYPES:
        ctype=_CTYPES[typ]
        if typ=='bool':domain=[False,True,0,1,-1,None,'false',[],{},0.0,1.0]
        else:
            bits=ctypes.sizeof(ctype)*8;signed=typ.startswith('i');lo=-(1<<(bits-1)) if signed else 0;hi=(1<<(bits-int(signed)))-1
            domain=[lo-1,lo,lo+1,-1,0,1,hi-1,hi,hi+1,True,False,None,'0',0.0,1.0,-0.0,[],{},1<<2048,-(1<<2048)]
        for val in domain:
            rc,raw=arguments([typ],[val]);wanted=scalar_value_valid(val,typ)
            assert (rc==152)==wanted,(typ,repr(val)[:200],rc,wanted)
            if wanted:
                expect=int(val)&U64;assert raw[:8]==b'HIAMVCAL' and struct.unpack_from('<Q',raw,24)[0]==expect
                assert raw[32:]==bytes(120);normal+=1
            else:refused+=1
        for raw in (b'[-0]',b'[1e0]',b'[1.0]',b'[1e400]',b'["1"]',b'null',b'{}',b'[]',b'[0,0]',b'[NaN]',b'[Infinity]',b'['+b'9'*4097+b']'):
            rc,_=arguments([typ],[],raw)
            wanted=raw==b'[-0]' and typ!='bool'
            assert (rc==152)==wanted,(typ,raw[:30],rc,wanted)
            normal+=int(wanted);refused+=int(not wanted)
    for n in range(17):
        vals=[U64 if i&1 else 0 for i in range(n)]
        rc,raw=arguments(['u64']*n,vals);assert rc==152
        assert list(struct.unpack_from('<16Q',raw,24))==vals+[0]*(16-n);normal+=1
    return_memory=mmap.mmap(-1,4096,prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
    return_address=ctypes.addressof(ctypes.c_ubyte.from_buffer(return_memory))
    rng=random.Random(0x4d563031)
    for typ in TYPES:
        ctype=_CTYPES[typ]
        values=[0,1,127,128,255,256,32767,32768,65535,65536,(1<<31)-1,1<<31,(1<<32)-1,1<<32,(1<<63)-1,1<<63,U64]
        values.extend(rng.getrandbits(64) for _ in range(75))
        for raw in values:
            put(work,0,1);put(work,8,0);put(work,16,CODES[typ]);put(work,160,raw)
            rc=call(b'',out,work);assert rc<=21,(typ,raw,rc)
            value=json.loads(out.raw[:rc]);return_memory.seek(0);return_memory.write(b'\x48\xb8'+struct.pack('<Q',raw)+b'\xc3');want=ctypes.CFUNCTYPE(ctype)(return_address)()
            assert type(value) is type(want) and value==want,(typ,raw,value,want);returns+=1
    compile=subprocess.run(['cc','-shared','-fPIC','-Wl,-z,noexecstack',str(ROOT/'tools/hia_multiversion_scalar_call.S'),'-o',str(D/'scalar-call.so')],capture_output=True)
    (D/'mechanical-build.stderr').write_bytes(compile.stderr);assert compile.returncode==0
    mechanical=ctypes.CDLL(str(D/'scalar-call.so'));invoke=mechanical.hia_mv_scalar_call
    invoke.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint64)];invoke.restype=ctypes.c_uint64
    programs=[
      ('all-types',document([function('identity_'+t,[t]) for t in reversed(TYPES)]),False),
      ('arity-0-15',document([function('arity_'+str(n).zfill(2),['u64']*n,selected=max(0,n-1)) for n in range(16)]),False),
      ('arity-16',document([function('wide_'+str(i).zfill(2),['u64']*16,selected=i) for i in range(16)]),False),
      ('mixed-16',document([function('mixed_'+str(i).zfill(2),(list(TYPES)*2)[:16],selected=i) for i in range(16)]),False),
      ('proved-total-ops',document([function(op+'_'+t,[t],operation='int.'+op+'.checked') for op in ('div','rem') for t in ('u8','u16')]),True),
      ('long-names',document([function('z'+'a'*127,['i64']),function('A'+'z'*127,['bool'])]),False)]
    for label,doc,total in programs:
        program=verify_program(doc);canonical=program.as_dict();raw=json.dumps(canonical,separators=(',',':'),sort_keys=True).encode()
        put(pout,0,int(total));put(pout,8,1);put(pout,16,0)
        prc=profile(raw,pout,pwork);assert prc<len(pout)
        facts=bytes(pout.raw[:prc]);decision=ctypes.create_string_buffer(b'\xa5'*144,144);policywork=ctypes.create_string_buffer(8192)
        assert policy(facts,decision,policywork)==0
        ctypes.memmove(awork,decision,144);rc=materializer(facts,abiout,awork)
        assert rc<=len(abiout),(label,rc)
        actual_abi=decode_abi(abiout.raw[:rc]);signatures=_reference_scalar_profile(program,canonical,prove_total=total)
        want=[(next(i for i,x in enumerate(canonical['functions']) if x['name']==sig.function),sig.function,sig.parameters,sig.result) for sig in signatures]
        assert actual_abi==want,(label,actual_abi,want);abi_cases+=1
        output=D/(label+'.so');(D/(label+'.core.json')).write_bytes(raw)
        started=time.monotonic_ns();result=subprocess.run(['hia-build-shared',str(output)],executable=str(a.builder),input=raw,env={'PATH':''},capture_output=True,timeout=60)
        (D/(label+'.build.stdout')).write_bytes(result.stdout);(D/(label+'.build.stderr')).write_bytes(result.stderr)
        assert result.returncode==0,(label,result.returncode,result.stderr)
        builds.append({'label':label,'elapsed_ns':time.monotonic_ns()-started,'source_sha256':sha(raw),'artifact_bytes':output.stat().st_size,'artifact_sha256':sha(output.read_bytes()),'report_sha256':sha(result.stdout)})
        image=ctypes.CDLL(str(output))
        for signature in signatures:
            fn=getattr(image,signature.function);fn.argtypes=[_CTYPES[t] for t in signature.parameters];fn.restype=_CTYPES[signature.result]
            for values in _probe_vectors(signature):
                expected=execute_program(program,signature.function,list(values),max_steps=4224)['result']
                original=fn(*values);assert type(original) is type(expected) and original==expected
                rc,packet=arguments(signature.parameters,list(values));assert rc==152
                words=(ctypes.c_uint64*16)(*struct.unpack_from('<16Q',packet,24))
                rawreturn=invoke(ctypes.cast(fn,ctypes.c_void_p),words)
                put(work,0,1);put(work,8,len(values));put(work,16,CODES[signature.result]);put(work,160,rawreturn)
                rc=call(b'',out,work);assert rc<=21
                actual=json.loads(out.raw[:rc]);assert type(actual) is type(expected) and actual==expected,(label,signature,values,actual,expected)
                actualcalls+=1
        rows.append({'case':label,'functions':len(signatures),'abi_bytes':16+320*len(signatures)})
        # The private materializer never turns malformed transport/permutation
        # into a callable ABI. Output remains byte-for-byte untouched on refusal.
        mutations=[('truncated',facts[:-1]),('trailing',facts+b'\0'),('bad-phase',facts[:48]+struct.pack('<Q',0)+facts[56:]),('bad-magic',b'BADMAGIC'+facts[8:])]
        for case,bad in mutations:
            ctypes.memmove(awork,decision,144);ctypes.memset(abiout,0xa5,len(abiout));rc=materializer(bad,abiout,awork)
            assert rc>len(abiout) and abiout.raw==b'\xa5'*len(abiout),(label,case,rc);refused+=1
        if len(signatures)>1:
            ctypes.memmove(awork,decision,144);put(awork,24,get(awork,16));ctypes.memset(abiout,0xa5,len(abiout));rc=materializer(facts,abiout,awork)
            assert rc>len(abiout) and abiout.raw==b'\xa5'*len(abiout);refused+=1
    report={'schema':'hepta.hia.multiversion-call-qualification.v1','scope':'ABI, exact argument/return, actual general-native ELF and mechanical SysV calls; generation custody/coordinator/proof engine not claimed','passed':normal+refused+returns+actualcalls+abi_cases,'failed':0,'argument_accepts':normal,'refusals':refused,'return_cases':returns,'actual_native_vm_calls':actualcalls,'abi_cases':abi_cases,'images':[call.pin,materializer.pin,profile.pin,policy.pin],'mechanical_source_sha256':sha((ROOT/'tools/hia_multiversion_scalar_call.S').read_bytes()),'mechanical_image_sha256':sha((D/'scalar-call.so').read_bytes()),'native_builder':{'path':str(a.builder),'sha256':sha(a.builder.read_bytes())},'builds':builds,'programs':rows,'originals':{rel:sha((ROOT/rel).read_bytes()) for rel in ['hepta/hia_multiversion.py','hepta/hia_program_runtime.py','hepta/hia_opcodes.py']}}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MV_CALL_PASS',report['passed'],report['actual_native_vm_calls'],flush=True)
if __name__=='__main__':main()
