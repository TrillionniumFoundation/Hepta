"""Frozen measurement oracle versus actual native capture, numeric policy and report."""
from pathlib import Path
import argparse,ctypes as C,copy,hashlib,json,math,random,struct,sys,types
from tools.qualify_hia_multiversion_components import Image
from hepta import hia_multiversion as original
from hepta.hia_publication_measurement_native import packet as original_packet
from tests.test_hia_publication_measurement_native import original_policy,measurement,PublicationMeasurementNativeTests,FIXTURE_SHA256
def typed(value):
    t=type(value)
    if value is None:tag,payload=0,b''
    elif t is bool:tag,payload=1,struct.pack('<Q',int(value))
    elif t is int:tag,payload=2,str(value).encode('ascii')
    elif t is float:tag,payload=3,struct.pack('<d',value)
    elif t is str:tag,payload=4,b''.join(struct.pack('<I',ord(c)) for c in value)
    elif t in (list,tuple):tag,payload=(5 if t is list else 6),struct.pack('<Q',len(value))+b''.join(typed(x) for x in value)
    elif t is dict:tag,payload=7,struct.pack('<Q',len(value))+b''.join(typed(k)+typed(v) for k,v in value.items())
    else:tag,payload=8,b''
    return struct.pack('<QQ',tag,len(payload))+payload
def frame(value,prepare=0):
    raw=typed(value);n=abs(prepare);magnitude=n.to_bytes((n.bit_length()+7)//8,'little')
    return struct.pack('<8s7Q',b'HIAMVMT1',len(raw),int(prepare<0),len(magnitude),0,0,0,0)+raw+magnitude
def get(b,at):return struct.unpack_from('<Q',b,at)[0]
class Native:
    def __init__(self,D):
        self.typed=Image(D/'multiversion_measurement_typed.flat');self.lib=C.CDLL(str(D/'measurement-component.so'));self.fn=self.lib.hia_mv_measurement;self.fn.argtypes=[C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64];self.fn.restype=C.c_uint32;self.calls=0;self.typed_calls=0
    def run(self,raw,*,oc=None,wc=None,owner=True):
        on=max(32768,len(raw)+32768) if oc is None else oc;wn=max(131072,len(raw)+131072) if wc is None else wc
        s=C.create_string_buffer(raw,max(1,len(raw)));o=C.create_string_buffer(on+16);w=C.create_string_buffer(wn+16);C.memset(o,0xa5,on+16);C.memset(C.addressof(w)+wn,0x91,16)
        if owner:rc=self.fn(s,len(raw),o,on,w,wn);self.calls+=1
        else:rc=self.typed.entry(s,len(raw),o,on,w,wn);self.typed_calls+=1
        assert s.raw[:len(raw)]==raw and o.raw[on:]==b'\xa5'*16 and w.raw[wn:]==b'\x91'*16
        return rc,o.raw[:on]
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();D=a.directory;q=Native(D);rows=[];oracle=original_policy()
    def check(value,prepare=0,name='case'):
        raw=frame(value,prepare)
        try:
            frozen=original._measurement_snapshot(value);canonical=json.dumps(frozen,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
            expected_wire=original_packet(frozen,prepare);capture_error=None
        except Exception as e:canonical=expected_wire=None;capture_error=(type(e).__name__,str(e))
        rc,out=q.run(raw,owner=False);assert rc==0 and out[:8]==b'HIAMVMR1',(name,rc,out[:128].hex())
        if capture_error:
            assert get(out,8)==1 and out[128:128+get(out,48)].decode()==capture_error[1],(name,capture_error,out[:512])
            wanted=('raised',*capture_error)
        else:
            assert get(out,8)==0 and out[128:128+get(out,24)]==canonical,(name,'canonical',canonical[:200],out[128:328])
            packet_at=128+get(out,24);assert out[packet_at:packet_at+get(out,32)]==expected_wire,(name,'policy packet')
            try:wanted=('returned',oracle(frozen,prepare_ns=prepare))
            except Exception as e:wanted=('raised',type(e).__name__,str(e))
        rc,out=q.run(raw);assert rc==0 and out[:8]==b'HIAMVMR1' and get(out,56)==1,(name,rc,out[:128].hex())
        if get(out,8):
            actual=('raised','MultiversionRejected',out[128:128+get(out,48)].decode())
        else:
            at=128+get(out,24);actual=('returned',json.loads(out[at:at+get(out,32)]));assert out[128:at]==canonical
            assert out[64:96]==hashlib.sha256(canonical).digest()
        assert actual==wanted,(name,prepare,actual,wanted)
        rows.append({'case':name,'request_bytes':len(raw),'request_sha256':hashlib.sha256(raw).hexdigest(),'outcome':'returned' if actual[0]=='returned' else actual[2],'snapshot_sha256':None if canonical is None else hashlib.sha256(canonical).hexdigest()})
        return actual
    base=measurement()
    check(base,name='default')
    # All original finite numerical families use their current original inputs.
    obj=PublicationMeasurementNativeTests()
    def compare(self,value,prepare=0):return check(value,prepare,'original-numerical-family')
    obj.compare=types.MethodType(compare,obj)
    methods=['test_each_allowed_odd_sample_count_and_ceil_remainder_boundaries','test_complete_ordered_refusal_reasons_and_signed_saving_deviation','test_projection_finite_limits_and_arbitrary_exact_preparation_integer','test_every_fixed_threshold_equality_and_immediate_neighbors','test_deterministic_full_domain_native_differentials_preserve_frozen_object']
    for name in methods:getattr(obj,name)()
    for value in [None,True,False,0,1,1.0,'x',[],(),set(),type('D',(dict,),{})()]:check(value,name='root-exact-type')
    for key in list(base):
        value=copy.deepcopy(base);del value[key];check(value,name='missing-'+key)
    value=copy.deepcopy(base);value['unexpected']=1;check(value,name='extra')
    value=copy.deepcopy(base);value[1]=value.pop('schema');check(value,name='non-string-key')
    for bad in [None,False,1,1.0,[],{},'','other']:
        value=copy.deepcopy(base);value['schema']=bad;check(value,name='schema-type')
    for key in ['before_sha256','after_sha256','before_artifact_sha256','after_artifact_sha256','workload_sha256']:
        for bad in [None,1,True,[],{},b'0'*64,'0'*63,'0'*65,'A'*64,'g'*64,'\x00'*64,'é'*64]:
            value=copy.deepcopy(base);value[key]=bad;check(value,name='hash-'+key)
    for bad in [None,True,0,1.0,[],{},(),b'x','', 'x'*257]:
        value=copy.deepcopy(base);value['function']=bad;check(value,name='function-type')
    for text in ['x','\0','a"\\\n\t\b\f\r',chr(0x7f),chr(0xd800),chr(0xdfff),chr(0xd800)+chr(0xdc00),chr(0x10ffff),'測試🙂','a'*256,chr(0x10ffff)*256,chr(0xd800)*256,chr(0x10ffff)*257]:
        value=copy.deepcopy(base);value['function']=text;check(value,name='function-unicode')
    for key,lo,hi in [('calls_per_sample',1,64000000),('horizon_calls',1,10**12),('search_cost_ns',0,3600000000000),('maximum_search_ns',1,3600000000000)]:
        for bad in [None,False,True,1.0,float('nan'),float('inf'),'1',[],{},lo-1,lo,hi,hi+1,1<<300,-(1<<300)]:
            value=copy.deepcopy(base);value[key]=bad;check(value,name='exact-int-'+key)
    for bad in [None,{},(),tuple(base['samples']),[],base['samples'][:14],base['samples']*2,base['samples']*5]:
        value=copy.deepcopy(base);value['samples']=bad;check(value,name='sample-list')
    for bad in [None,[],(),True,1,{'baseline_ns':1},{'baseline_ns':1,'candidate_ns':1,'x':1},{1:1,'candidate_ns':1}]:
        value=copy.deepcopy(base);value['samples'][3]=bad;check(value,name='sample-dict')
    for key in ['baseline_ns','candidate_ns']:
        for bad in [None,False,True,1.0,float('nan'),'1',[],{},0,1,60000000000,60000000001,1<<300]:
            value=copy.deepcopy(base);value['samples'][4][key]=bad;check(value,name='sample-int')
    # Error ordering: every earlier original field beats every later defect.
    bads=[('schema','x'),('before_sha256','x'),('after_sha256','x'),('before_artifact_sha256','x'),('after_artifact_sha256','x'),('workload_sha256','x'),('function',''),('calls_per_sample',0),('horizon_calls',0),('search_cost_ns',-1),('maximum_search_ns',0),('samples',[])]
    for i,(key,bad) in enumerate(bads):
        for later,other in bads[i+1:]:
            value=copy.deepcopy(base);value[key]=bad;value[later]=other;check(value,name='priority-'+key+'-'+later)
    raw=frame(base)
    guards=[]
    for at in [0,8,16,24,32,40,48,56]:
        changed=bytearray(raw);struct.pack_into('<Q',changed,at,(1<<64)-1);rc,out=q.run(bytes(changed));assert rc==0xfffffffd,(at,rc);guards.append({'offset':at,'rc':rc})
    for on,wn in [(127,131072),(32768,65535),(128,131072)]:
        rc,out=q.run(raw,oc=on,wc=wn);assert rc in (0xfffffffd,0xfffffffe),(on,wn,rc);guards.append({'out':on,'work':wn,'rc':rc})
    report={'schema':'hepta.hia.multiversion-measurement-native-qualification.v1','whole_native_runtime':False,'passed':len(rows)+len(guards),'failed':0,'original_policy_sha256':FIXTURE_SHA256,'original_methods':methods,'actual_owner_calls':q.calls,'actual_typed_calls':q.typed_calls,'image_sha256':hashlib.sha256((D/'measurement-component.so').read_bytes()).hexdigest(),'observations':rows,'private_guards':guards,'input_and_outer_canaries_unchanged':True}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MEASUREMENT_NATIVE_PASS',report['passed'],q.calls,q.typed_calls,flush=True)
if __name__=='__main__':main()
