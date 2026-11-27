"""Installed native frontend: the original seven semantic gates plus actual loader/session custody."""
from pathlib import Path
import argparse
import ctypes as C,hashlib,json,os,struct,traceback
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_generation_runtime_global import Global,sidecar
from tools.qualify_hia_native_runtime_resources import ready,retired
from tools.qualify_hia_result_value_exceptions import Values,frame,ZERO
from tools.qualify_hia_clang_compile import small
from hepta.hia_program import verify_program,VerifiedProgram
from hepta.hia_multiversion import ScalarMultiversionRuntime,MultiversionRejected

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args()
    B=a.build.resolve();O=a.output.resolve();O.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(O.with_suffix('.claim'),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd);O.mkdir()
    pin=lambda b:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
    path=B/'install/hia-generation-component-root.so';build=json.loads((B/'build.json').read_bytes())
    assert pin(path.read_bytes())==build['products']['hia-generation-component-root.so']
    report=dict(passed=False,owner=pin(path.read_bytes()),construction=dict(path=str(B/'build.json'),**pin((B/'build.json').read_bytes())),qualifier=dict(path=__file__,**pin(Path(__file__).read_bytes())),stages=[],calls=[],
     public_constructor_qualified=False,scalar_admission_and_directory_qualified=False,whole_public_runtime_qualified=False)
    def save():(O/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    def stage(name,**data):
     report['stages'].append(dict(name=name,passed=True,**data));save();print('RUNTIME_FRONTEND_PASS',name,flush=True)
    def wire(magic,op=0,cap=ZERO,n=128):
     b=bytearray(n);b[:8]=magic;struct.pack_into('<Q',b,8,op)
     struct.pack_into('<3Q',b,24,*cap);return bytes(b)
    def entry(name):
     f=getattr(owner.lib,name);f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32;return f
    def call(f,raw,out,ctx,wn):
     src=C.create_string_buffer(raw);n=len(out);rc=int(f(src,len(raw),out,n,ctx,wn))
     assert src.raw==raw+b'\0';return rc
    owner=q.Owner(path);owner.initialize();g=Global(owner)
    initial_fds=set(os.listdir('/proc/self/fd'));ready(g.call(0))
    assert sidecar(owner,0)['status']==0
    installer=entry('hia_generation_runtime_frontend_install')
    install_output=C.create_string_buffer(3145728)
    def installcall(op):
     rc=call(installer,wire(b'HIARTIQ1',op),install_output,owner.context,2048)
     data=install_output.raw
     row={k:q.get(data,off)for k,off in dict(status=8,state=16,known=24,pending=32,retired=40,detail=48,active=56,stage=64,guards=72,mask=80,globalcap=88,loadercap=96,sessions=104,nonce=112).items()}
     report['calls'].append(dict(operation='installed-frontend',op=op,rc=rc,**row));save()
     assert rc==0 and data[:8]==b'HIARTIR1',(rc,data[:128].hex())
     return row
    install_before=q.get(owner.context,72)
    row=installcall(0)
    assert row['status']==0 and row['state']==2 and row['known']==1 and row['pending']==row['active']==row['sessions']==0 and row['nonce']!=0,row
    assert row['globalcap']==row['loadercap']==1 and row['guards']==2,row
    assert q.get(owner.context,72)==install_before+1
    stage('actual-fixed-child-catalog-hash-seal-load-and-global-borrow')
    v=Values(q.ValueTransport(owner));front=C.create_string_buffer(1<<20)
    bind=entry('hia_generation_runtime_frontend_bind')
    options=entry('hia_generation_runtime_constructor_options')
    verify=entry('hia_generation_runtime_verify')
    oc=(C.c_char*8192).from_buffer(front,4096);yc=(C.c_char*8192).from_buffer(front,16384)
    oo=C.create_string_buffer(32768);yo=C.create_string_buffer(524288)
    def bindcall(op):
     rc=call(bind,wire(b'HIARTBQ1',op),front,owner.context,2048)
     row={k:q.get(front,1024+off)for k,off in dict(status=8,state=16,pending=80,known=88,consumed=96,retired=104,detail=112).items()}
     report['calls'].append(dict(operation='bind',op=op,rc=rc,**row));save()
     assert rc==0 and front.raw[1024:1032]==b'HIARTBR1',(rc,front.raw[:256].hex(),row)
     return row
    def optioncall(caps):
     raw=bytearray(wire(b'HIARTOQ1',n=256))
     for i,cap in enumerate(caps):struct.pack_into('<3Q',raw,24+i*24,*cap)
     rc=call(options,bytes(raw),oo,oc,8192);data=oo.raw
     row={k:q.get(data,off)for k,off in dict(status=8,disposition=16,pending=80,known=88,delivered=96,quarantine=104,detail=112).items()}
     report['calls'].append(dict(operation='options',rc=rc,**row));save()
     assert rc==0 and data[:8]==b'HIARTOR1',(rc,data[:256].hex())
     return row,data
    def verifycall(cap):
     rc=call(verify,wire(b'HIARTVQ1',cap=cap),yo,yc,8192);data=yo.raw
     row={k:q.get(data,off)for k,off in dict(status=8,format=16,size=48,profile=56,core_n=64,input_n=72,quarantine=80,known=88,pending=96,core_ptr=104,input_ptr=112,detail=120).items()}
     row['cap']=struct.unpack_from('<3Q',data,24)
     report['calls'].append(dict(operation='fresh-verify',rc=rc,**row));save()
     assert rc==0 and data[:8]==b'HIARTVR1',(rc,data[:128].hex())
     return row
    Payload=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
    payload=None
    def payload_call(op,cap):
     raw=wire(b'HIABPY01',op,cap);out=C.create_string_buffer(512)
     rc=call(payload,raw,out,C.c_void_p(q.get(yc,48)),256)
     assert rc==0 and out.raw[:8]==b'HIABPYR1' and q.get(out,8)==0,(rc,out.raw.hex())
     return out.raw
    def original_reject(**kwargs):
     try:ScalarMultiversionRuntime(None,None,**kwargs)
     except MultiversionRejected as exc:return type(exc).__name__,exc.args
     raise AssertionError('original Runtime did not reject primitive options')
    def exception_data(cap):
     parts=v.parts(cap);namespace,args,name=parts
     cls=v.keep(v.raw(36,a=cap));classname=v.keep(v.raw(38,a=cls))
     result=(v.python(classname),v.python_value(args))
     for c in [*parts,cls,classname]:v.drop(c)
     return result
    def collect_new(before):
     for cap in list(v.held):
      if cap not in before:v.drop(cap)
    try:
     active=q.get(owner.context,72);row=bindcall(0);assert row==dict(status=0,state=1,pending=0,known=1,consumed=0,retired=0,detail=0),row
     assert q.get(owner.context,72)==active+1
     assert front.raw[:8]==b'HIARTFC1'and q.get(front,32)==q.get(owner.context,40)and q.get(front,40)==C.addressof(owner.context)+512
     assert q.get(front,64)and q.get(front,88)
     assert g.call(1)['status']==6
     payload=Payload(q.get(yc,40))
     stage('fixed-native-binder-real-value-token-resource-borrow-and-parent-guard')
     busy=installcall(1)
     assert busy['status']==6 and busy['state']==2 and busy['sessions']==1 and busy['active']==0 and busy['retired']==0,busy
     stage('actual-bound-session-blocks-native-child-unload')
     program=verify_program(small(7));baseline=v.scalar(program.canonical_bytes);directory=v.scalar(None)
     before=set(v.held);row,out=optioncall([baseline,directory])
     assert row['status']==0 and row['disposition']==row['known']==row['delivered']==1 and row['quarantine']==0,row
     args=[v.keep(out,at)for at in(160,184,208)]
     assert v.same(args[0],baseline)and v.same(args[1],directory)and v.python(args[2])=='clang'
     assert tuple(q.get(out,at)for at in(128,136,144))==(2000,8,0)
     assert out[232:256]==bytes(24)
     collect_new(before)
     stage('native-defaults-real-argument-retains-and-default-clang-value')
     invalid=[
      ('timeout-type',dict(validation_timeout_ms=True),[ZERO,v.scalar(True)]),
      ('timeout-low',dict(validation_timeout_ms=0),[ZERO,v.scalar(0)]),
      ('timeout-high',dict(validation_timeout_ms=30001),[ZERO,v.scalar(30001)]),
      ('timeout-negative',dict(validation_timeout_ms=-1),[ZERO,v.scalar(-1)]),
      ('limit-type',dict(max_live_generations=False),[ZERO,ZERO,v.scalar(False)]),
      ('limit-low',dict(max_live_generations=1),[ZERO,ZERO,v.scalar(1)]),
      ('limit-high',dict(max_live_generations=65),[ZERO,ZERO,v.scalar(65)]),
      ('prove-type',dict(prove_total=1),[ZERO,ZERO,ZERO,v.scalar(1)]),
      ('timeout-priority',dict(validation_timeout_ms=0,max_live_generations=1,prove_total=1),[ZERO,v.scalar(0),v.scalar(1),v.scalar(1)])]
     for name,kw,tail in invalid:
      before=set(v.held);row,out=optioncall([baseline,directory,*tail])
      assert row['status']==1 and row['disposition']==2 and row['known']==row['delivered']==1 and row['quarantine']==0,(name,row)
      exc=v.keep(out);got=exception_data(exc);expected=original_reject(**kw);assert got==expected,(name,got,expected)
      collect_new(before)
     stage('original-error-order-exact-option-types-and-real-exception-class',cases=len(invalid))
     before=set(v.held);values=[v.scalar('clang-actual'),v.scalar(1),v.scalar(64),v.scalar(True)]
     row,out=optioncall([baseline,directory,*values])
     assert row['status']==0 and tuple(q.get(out,at)for at in(128,136,144))==(1,64,1),row
     owned=[v.keep(out,at)for at in(160,184,208)];assert v.same(owned[2],values[0])
     collect_new(before)
     stage('native-explicit-option-boundaries-and-clang-identity')
     raw_inputs=[('canonical-bytes',baseline,program),
       ('canonical-text',v.scalar(program.canonical_bytes.decode()),program)]
     for name,cap,oracle in raw_inputs:
      row=verifycall(cap);assert row['status']==0 and row['format']==0 and row['quarantine']==row['pending']==0 and all(row['cap']),row
      raw=payload_call(6,row['cap']);actual=C.string_at(q.get(raw,64),q.get(raw,40))
      assert actual[:8]==b'HIAVCF01'and len(actual)==row['size']
      assert C.string_at(row['core_ptr'],row['core_n'])==oracle.canonical_bytes
      assert hashlib.sha256(C.string_at(row['input_ptr'],row['input_n'])).hexdigest()==oracle.input_sha256
      payload_call(3,row['cap'])
     stage('actual-normalizer-raw-bytes-and-text-vfy3')
     verified=v.keep(v.raw(67,a=baseline))
     row=verifycall(verified);assert row['status']==0 and row['format']==0,row
     assert C.string_at(row['core_ptr'],row['core_n'])==program.canonical_bytes
     payload_call(3,row['cap'])
     stage('actual-verified-program-class-two-fields-fresh-vfy4')
     wrong=v.scalar(b'not a HIA program');bad_record=v.keep(v.raw(67,a=baseline,b=wrong))
     row=verifycall(bad_record);assert row['status']!=0 and row['format']in(1,2)and all(row['cap']),row
     payload_call(3,row['cap'])
     stage('verified-program-structured-field-is-reverified')
     for cap in list(v.held):v.drop(cap)
     row=bindcall(1);assert row['status']==0 and row['retired']==1 and row['state']==3,row
     assert q.get(owner.context,72)==active
     closed=installcall(1)
     assert closed['status']==0 and closed['state']==4 and closed['known']==closed['retired']==1 and closed['pending']==closed['active']==closed['sessions']==closed['guards']==closed['globalcap']==closed['loadercap']==0,closed
     assert q.get(owner.context,72)==install_before
     stage('actual-session-and-loader-retirement-before-parent-close')
     assert sidecar(owner,1)['retired']==1
     retired(g.call(1));last=owner.call(3);assert last['status']==0 and last['state']==3,last
     assert set(os.listdir('/proc/self/fd'))==initial_fds
     report.update(passed=True,groups=len(report['stages']),actual_native_binder=True,original_primitive_order=True,
      fresh_verified_both_fields=True,true_value_exceptions=True,all_caps_payloads_fds_and_parent_guard_retired=True)
    except BaseException as error:
     report.update(error=repr(error),traceback=traceback.format_exc());raise
    finally:save()
    print('RUNTIME_FRONTEND_ACTUAL_PASS',len(report['stages']),flush=True)
    

if __name__=='__main__':
    main()
