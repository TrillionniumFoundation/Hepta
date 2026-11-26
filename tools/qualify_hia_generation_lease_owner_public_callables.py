"""Public sole-owner invocation qualification over the actual Value15 code path.

The original invocation and custody gates retain their assertions. Only their
development Engine transport is supplied here: normal requests enter owner.op4.
Private 56 remains a named fixture-only cleanup; additional gates prove that a
single ordinary public query performs the same real deferred cleanup.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,struct,sys,threading
from tools import qualify_hia_generation_lease_owner as owner
from tools import qualify_hia_result_value_invocations as calls
from tools import qualify_hia_result_value_invocation_custody as custody

LOCK=threading.Lock()
COUNTS={'public':{},'trusted_cleanup56':0,'public_query_retries':0}
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def count(name,key=None):
    with LOCK:
        if key is None:COUNTS[name]+=1
        else:COUNTS[name][key]=COUNTS[name].get(key,0)+1
class PublicEngine(calls.Engine):
    query_cleanup=False
    def allocate_output(self,on=16384):
        mapping=mmap.mmap(-1,owner.OUT+1)
        output=(C.c_char*(owner.OUT+1)).from_buffer(mapping)
        C.memset(C.addressof(output)+owner.CHILD+on,165,64)
        output[owner.CHILD+on+64]=b'\0'
        return output
    def value_output(self,output,on=16384):
        return (C.c_char*(on+65)).from_buffer(output,owner.CHILD)
    def invoke(self,request,output,on=16384):
        magic=request[:8];op=calls.word(request,8)
        if magic==b'HIABVQ05' and op==56:
            if self.query_cleanup:
                request=calls.frame(47)
                count('public_query_retries')
            else:
                # Trusted development cleanup only, never public authorization.
                count('trusted_cleanup56')
                source=C.create_string_buffer(request)
                value=self.value_output(output,on)
                rc=int(self.entry(source,len(request),value,on,self.context,256))&0xffffffff
                assert source.raw==request+b'\0'
                return rc
        raw=owner.envelope(4,request);source=C.create_string_buffer(raw)
        rc=int(self.bound.owner.entry(source,len(raw),output,owner.OUT,
                                     self.bound.owner.context,owner.CONTEXT_BYTES))&0xffffffff
        assert source.raw==raw+b'\0'
        count('public',request[:8].decode('ascii')+'/'+str(calls.word(request,8)))
        if rc==owner.BAD:return rc
        head=bytes(output[:128])
        assert rc==0 and head[:8]==b'HIAGLOR1',(rc,head.hex())
        assert calls.word(head,8)==0 and calls.word(head,16)==4 and calls.word(head,24)==owner.CHILD,head.hex()
        assert calls.word(head,48)==1 and calls.word(head,64)==0 and calls.word(head,72)==0,head.hex()
        return calls.word(head,40)
class PublicQueryEngine(PublicEngine):
    query_cleanup=True

def public_private_guards(path):
    b=calls.Bound(path);row=b.call(0);assert row['status']==0
    cases=[]
    for magic,ops in [(b'HIABVQ05',[48,49,52,53,54,55,56,58,59,60,61,64,65,66,71,72,73,74,76,77,78,79,80,81,82,83,84,85,86,88,89,90,91,92,93,94,95,96]),
                      (b'HIABVQ06',[7,8,17,19,21,26,32,36,37,38,39]),(b'HIABVQ01',[0,20]),(b'HIABVQ02',[30,31])]:
        for op in ops:
            request=bytearray(128);struct.pack_into('<8sQ',request,0,magic,op)
            source=C.create_string_buffer(owner.envelope(4,request));stable=bytes(b.owner.context)
            with mmap.mmap(-1,owner.OUT)as output:
                output[:128]=b'\xa5'*128
                rc=int(b.owner.entry(source,len(source)-1,owner.address(output),owner.OUT,b.owner.context,owner.CONTEXT_BYTES))&0xffffffff
                assert rc==owner.BAD and output[:128]==b'\xa5'*128 and bytes(b.owner.context)==stable,(magic,op,rc)
            cases.append(magic.decode()+'/'+str(op))
    v=calls.Values(PublicEngine(b));assert calls.word(v.raw(47),48)==1
    calls.sweep(v,b);b.close()
    return dict(passed=True,actual_public_no_write_refusals=cases,private_cleanup56_never_public=True)
def exception_catalog(path):
    b=calls.Bound(path);assert b.call(0)['status']==0
    v=calls.Values(PublicEngine(b))
    cls=v.keep(v.raw(87,arg0=41))
    args=v.tuple([v.scalar('E_HIA_MULTIVERSION: actual constructor diagnostic')])
    namespace=v.dictionary([])
    cleanup=v.dictionary([('status','retained')])
    key=v.scalar('hia_cleanup')
    v.raw(10,a=namespace,b=key,c=cleanup)
    exception=v.exception(cls,args,namespace)
    value_error=v.builtin(24)
    assert v.isinst(exception,cls) and v.isinst(exception,value_error)
    actual=v.keep(v.raw(36,a=exception));assert v.same(actual,cls)
    env,actual_args,name=v.parts(exception)
    assert v.python_value(actual_args)==('E_HIA_MULTIVERSION: actual constructor diagnostic',)
    assert v.python_value(env)=={'hia_cleanup':{'status':'retained'}}
    calls.sweep(v,b);b.close()
    return dict(passed=True,actual_public75_and87=True,canonical_multiversion_rejected_mro=True,actual_args_and_cleanup_namespace=True)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--owner',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    assert hasattr(calls,'ENGINE_FACTORY') and hasattr(calls.Engine,'value_output')
    report_path=args.output/'report.json';old_argv=sys.argv;old_factory=calls.ENGINE_FACTORY
    try:
        calls.ENGINE_FACTORY=PublicEngine
        sys.argv=['public-normal','--owner',str(args.owner),'--output',str(args.output/'normal')]
        calls.main()
        sys.argv=['public-custody','--owner',str(args.owner),'--output',str(args.output/'custody')]
        custody.main()
        private=public_private_guards(args.owner);(args.output/'private.json').write_text(json.dumps(private,indent=2)+'\n')
        exception=exception_catalog(args.owner);(args.output/'exception.json').write_text(json.dumps(exception,indent=2)+'\n')
        # The original eight gates above still use their exact native 56 fixture.
        # These three additional gates explicitly recover with public op47 instead.
        calls.ENGINE_FACTORY=PublicQueryEngine
        query=args.output/'query-recovery';query.mkdir()
        previous_trusted=COUNTS['trusted_cleanup56'];queries_before=COUNTS['public_query_retries']
        rows=[]
        for label,component in [('public-query-code-retirement','code'),('public-query-call-record-retirement','value')]:
            rows.append(custody.retirement_case(args.owner,query,label,component))
        rows.append(custody.adoption_contention_case(args.owner,query))
        assert COUNTS['trusted_cleanup56']==previous_trusted
        assert COUNTS['public_query_retries']-queries_before==3
        query_report=dict(passed=True,actual_operation='HIABVQ04/47 through owner.op4',groups=rows,
                          actual_retry_entries=3,private56_executed=False,reply_fields_not_synthesized=True)
        (query/'report.json').write_text(json.dumps(query_report,indent=2)+'\n')
        normal=json.loads((args.output/'normal/report.json').read_bytes())
        fault=json.loads((args.output/'custody/report.json').read_bytes())
        assert len(normal['groups'])==15 and len(fault['groups'])==8
        for op in (68,69,70,75,87):assert COUNTS['public']['HIABVQ05/'+str(op)]>0
        assert COUNTS['public'].get('HIABVQ05/56',0)==0
        source_files=['tools/qualify_hia_generation_lease_owner_public_callables.py',
                      'tools/qualify_hia_result_value_invocations.py','tools/qualify_hia_result_value_invocation_custody.py']
        root=Path(__file__).resolve().parents[1]
        report=dict(schema='hia.generation-lease-owner.public-callables.v1',passed=True,groups=28,
                    product=pin(args.owner.read_bytes()),build=pin((args.owner.parent/'build.json').read_bytes()),
                    actual_public_invocations=15,actual_public_fault_groups=8,actual_public_query_recovery_groups=3,
                    guard_group=True,exception_catalog_group=True,counts=COUNTS,
                    normal_report=pin((args.output/'normal/report.json').read_bytes()),
                    custody_report=pin((args.output/'custody/report.json').read_bytes()),
                    query_report=pin((query/'report.json').read_bytes()),
                    source_files={p:pin((root/p).read_bytes())for p in source_files},
                    public_owner_whitelist_qualified=True,single_actual_value_arena=True,
                    native_initialized_code_binding=True,original_assertions_unchanged=True,
                    host_context_writes=False,host_runtime_callbacks=False,
                    custom_protocol_dispatch_qualified=False,public_runtime_constructor_qualified=False,
                    whole_public_runtime_qualified=False)
        report_path.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(passed=True,groups=28,public_owner_whitelist_qualified=True)),flush=True)
    finally:
        calls.ENGINE_FACTORY=old_factory;sys.argv=old_argv
if __name__=='__main__':main()
