"""Native cold owned/chain plans with both independent reference arms.

Source fixtures and their declared assertions are data. Every pre-B0 reference
runs the complete independent HIA VM. Each original/modified qualification
rebuilds an independent native allocator program and the target program, links
both, and observes actual dynamic-loader processes. The seven allocator cases
retain all real libc events, failure injection and the 5000-node control.
"""
import json,struct
from tools.generate_hia_cold_qualification_plan import U64
from tools.hia_cold_qualification_plan_parts import call,build,observe,observe_linked,check_flat,utility,assert_gate
from tools.hia_cold_qualification_vm_plan import vm_reference

RECORD_BYTES=216
AUX_BYTES=1048712
SEMANTICS={'overflow':1,'division_by_zero':2,'bounds':3,'allocation':4,'user':5,'steps':6,'calls':7,'heap':8}


def category(case):
    if case.get('vm_budget_expected'):return 2,8,0
    if 'expected_trap' in case:return 1,SEMANTICS[case['expected_trap']],0
    return 0,0,1


def vm_gate(p,h,observed,case,*,label):
    kind,semantic,returns=category(case)
    header=p.literal(b'HIAQCG01'+struct.pack('<7Q',0,kind,semantic,10000000,returns,8,0))
    request=p.concat(header,observed);gate=call(p,h['cases_gate'],request,label=label+':exact-VM-trap-budget-class')
    assert_gate(p,gate,label=label+':original-VM-category');p.drop(header,request)
    if not kind:p.word(observed,32,case['expected_result'],label=label+':original-reference-return')
    output=p.slice(observed,144+returns*8,8);expected=p.literal(bytes.fromhex(case['expected_output_hex']))
    p.compare(output,expected,label=label+':original-reference-complete-output');p.drop(expected)
    ledger=32+returns*8
    if kind==0:
        for a,b in ((3,4),(7,8)):
            first=p.slice(observed,ledger+a*8,8);second=p.slice(observed,ledger+b*8,8)
            p.compare(first,second,label=label+':reference-resource-conservation-'+str(a));p.drop(first,second)
        for field in (5,13):p.word(observed,ledger+field*8,0,label=label+':reference-zero-live-'+str(field))
    for field,key in enumerate(('allocation_attempts','allocations','frees')):
        if 'expected_'+key in case:p.word(observed,ledger+field*8,case['expected_'+key],label=label+':reference-'+key)
    return output


def reference_family(p,h,cases,*,family):
    records=[]
    for index,case in enumerate(cases):
        label=family+':reference:'+case['id'];source=p.literal(case['source'].encode())
        observed=vm_reference(p,h,source,label=label,args=((14,0),(15,8),(15,0)),snapshots=b'\xa5'*8,max_steps=10000000,max_call_depth=256,max_heap_bytes=16<<20,allocation_fail_at=case.get('allocation_fail_at',0))
        output=vm_gate(p,h,observed,case,label=label);p.drop(output)
        kind,semantic,returns=category(case);size=152+8*returns
        source_pin=p.sha256(source);metadata=p.literal(struct.pack('<3Q',size,case.get('allocation_fail_at',0),kind));padding=p.literal(bytes(160-size))
        records.append(p.concat(source_pin,metadata,observed,padding));p.drop(source,source_pin,metadata,observed,padding)
    header=p.literal(b'HIAOWR01'+struct.pack('<Q',len(cases)));bundle=p.concat(header,*records)
    name=family+'-reference.bin';p.publish(bundle,name);p.drop(header,*records,bundle);return name


def reference_record(p,h,bundle,index,case,source,*,label):
    base=16+index*RECORD_BYTES;kind,semantic,returns=category(case);size=152+8*returns
    p.word(bundle,base+32,size);p.word(bundle,base+40,case.get('allocation_fail_at',0));p.word(bundle,base+48,kind)
    source_pin=p.sha256(source);prior=p.slice(bundle,base,32);p.compare(source_pin,prior,label=label+':same-round-reference-source');p.drop(source_pin,prior)
    observed=p.slice(bundle,base+56,size);output=vm_gate(p,h,observed,case,label=label+':retained-current-reference')
    if kind==0:returned=p.slice(observed,32,8)
    elif case.get('vm_budget_expected'):returned=p.literal(struct.pack('<Q',case['expected_result']))
    else:returned=p.literal(bytes(8))
    p.drop(observed);return output,returned


def open_reference(p,family,count):
    bundle=p.imported(family+'-reference.bin');p.word(bundle,0,int.from_bytes(b'HIAOWR01','little'));p.word(bundle,8,count)
    length=p.length(bundle);p.word(length,0,16+count*RECORD_BYTES);p.drop(length);return bundle


def project(p,h,source,label):
    core=call(p,h['assembly'],source,label=label+':fresh-independent-Core',argv=('child','--agent-compact'))
    left=p.literal(b'[');right=p.literal(b',"f0",1]');request=p.concat(left,core,right)
    projected=call(p,h['projector'],request,label=label+':full-resource-reference-wire');p.drop(core,left,right,request);return projected


def general_inventory(p,h,obj,label):
    begin=p.literal(b'HIAEXI01');size=p.length(obj);table=p.literal(struct.pack('<3Q',1,136,2)+b'f0'+bytes(126));wire=p.concat(begin,size,table,obj)
    actual=call(p,h['export_inventory'],wire,label=label+':independent-native-export-and-import-inventory');p.word(actual,0,1);p.drop(begin,size,table,wire,actual)


def invoke_linked(p,h,dso,expected,returned,initial,empty,*,label,trapped,direct):
    shared=p.shared(initial)
    run,snapshot=observe_linked(p,h['linked_observer'],dso,empty,label=label+':actual-dlopen',cap=8,work=0,shared=shared)
    gate=check_flat(p,h['linked_check'],run,empty,mode=2 if trapped else 1,cap=8,work=0,initial_handle=initial,expected_handle=expected,core_word=returned,code=(-6 if direct else -4) if trapped else 0,snapshot_handle=snapshot,label=label+':original-complete-byte-ABI')
    assert_gate(p,gate,label=label+':actual-return-signal-output-and-snapshot');p.drop(shared,run,snapshot)


def short_output(p,h,compiler,source,obj,*,label):
    n=p.length(obj);cap=p.number(n,1,subtract=True,maximum=1<<20);initial=utility(p,h['utility'],0,arg_word=cap,label=label+':short-A5-preimage')
    observed=observe(p,h['observer'],compiler,source,cap_word=cap,label=label+':actual-short-output')
    gate=check_flat(p,h['check'],observed,source,mode=1,cap_word=cap,core=0xfffffffe,initial_handle=initial,expected_handle=initial,label=label+':transactional-short-output')
    assert_gate(p,gate,label=label+':original-short-output');p.drop(n,cap,initial,observed)


def rejection_cases(p,h,compiler,cases,*,family,label):
    initial=utility(p,h['utility'],0,arg=1<<20,label=label+':refusal-A5-preimage');empty=p.literal(b'')
    for row in cases:
        name=label+':'+family+':refusal:'+row['id'];source=p.literal(row['source'].encode())
        if row['general_accepts']:
            core=call(p,h['assembly'],source,label=name+':original-general-admission',argv=('child','--agent-compact'));p.drop(core)
        else:
            run=p.run(h['assembly'],source,argv=('child','--agent-compact'),label=name+':original-general-rejection')
            receipt=p.resultpart(run,0);p.word(receipt,8,2);stdout=p.resultpart(run,1);stderr=p.resultpart(run,2)
            p.compare(stdout,empty);p.compare(stderr,empty);p.drop(run,receipt,stdout,stderr)
        observed=observe(p,h['observer'],compiler,source,label=name+':actual-target-refusal')
        gate=check_flat(p,h['check'],observed,source,mode=1,core=0xffffffff,initial_handle=initial,expected_handle=initial,label=name+':original-refusal-assertions')
        assert_gate(p,gate,label=name+':refused-with-full-source-and-output-preservation');p.drop(source,observed)
    p.drop(initial,empty)


def qualify_family(p,h,compiler,cases,refusals,*,family,label):
    reference=open_reference(p,family,len(cases));initial=p.literal(b'\xa5'*8);empty=p.literal(b'')
    short={'try-8','owned-call-consumes-input'} if family=='owned' else {'empty-query-and-pop','chain-flow-three-result-ssa-boundary'}
    for index,case in enumerate(cases):
        name=label+':'+family+':'+case['id'];source=p.literal(case['source'].encode())
        expected,returned=reference_record(p,h,reference,index,case,source,label=name)
        projected=project(p,h,source,name);general=call(p,h['general_backend'],projected,label=name+':independent-native-allocation-backend')
        general_inventory(p,h,general,name);oracle=call(p,h['general_linker'],general,label=name+':independent-native-libc-link')
        invoke_linked(p,h,oracle,expected,returned,initial,empty,label=name+':independent-native',trapped='expected_trap' in case,direct=True)
        obj=build(p,h['observer'],h['check'],compiler,source,label=name+':current-target-object')
        text=call(p,h['owned_inventory'],obj,label=name+':all-original-owned-ELF-predicates');p.drop(text)
        dso=call(p,h['linker'],obj,label=name+':current-target-native-libc-link')
        invoke_linked(p,h,dso,expected,returned,initial,empty,label=name+':target',trapped='expected_trap' in case,direct=False)
        if case['id'] in short:short_output(p,h,compiler,source,obj,label=name)
        p.drop(source,expected,returned,projected,general,oracle,obj,dso)
    p.drop(reference,initial,empty);rejection_cases(p,h,compiler,refusals,family=family,label=label)


def actual_fast_receipt(p,run,code,*,label):
    receipt=p.resultpart(run,0);p.word(receipt,0,int.from_bytes(b'HIASBR01','little'));length=p.length(receipt);p.word(length,0,128)
    for offset,value in ((8,code&U64),(16,0),(72,0),(80,0),(88,0),(96,1),(104,1),(120,1)):p.word(receipt,offset,value,label=label+':process-receipt-'+str(offset))
    stdout=p.resultpart(run,1);stderr=p.resultpart(run,2);outsize=p.length(stdout);errsize=p.length(stderr);empty=p.literal(b'');p.compare(stderr,empty)
    for offset,actual in ((40,outsize),(48,outsize),(56,errsize),(64,errsize)):
        field=p.slice(receipt,offset,8);p.compare(field,actual);p.drop(field)
    p.drop(receipt,length,stderr,outsize,errsize,empty);return stdout


def allocator_arm(p,h,obj,case,expected,returned,zero,*,direct,label):
    head=p.literal(b'HIACAWP1');policy_size=p.length(h['allocator_policy']);object_size=p.length(obj)
    request=p.concat(head,policy_size,object_size,h['allocator_policy'],obj)
    bundle=call(p,h['allocator_bundle'],request,label=label+':actual-witness-object')
    linked=call(p,h['general_linker'],bundle,label=label+':real-libc-link')
    bound=call(p,h['allocator_bind'],linked,label=label+':private-witness-context-binding')
    auxiliary=p.allocator_buffer(zero);descriptor=p.fdword(auxiliary);image_size=p.length(bound)
    begin=p.literal(b'HIACAO01');failure=p.literal(struct.pack('<Q',case['allocation_fail_at']));wire=p.concat(begin,image_size,failure,descriptor,bound)
    run=p.run(h['allocator_observer'],wire,passed=(auxiliary,),seconds=20,label=label+':real-allocator-process')
    actual=p.slice(auxiliary);size=p.length(actual);p.word(size,0,AUX_BYTES)
    trapped='expected_trap' in case;code=(-6 if direct else -4) if trapped else 0
    stdout=actual_fast_receipt(p,run,code,label=label)
    if trapped:
        empty=p.literal(b'');p.compare(stdout,empty);p.drop(empty)
    else:
        p.word(stdout,0,int.from_bytes(b'HIAOBR03','little'));r=p.slice(stdout,8,8);p.compare(r,returned);n=p.length(stdout);p.word(n,0,32);out=p.slice(stdout,24,8);p.compare(out,expected);p.drop(r,n,out)
    failedkind=0 if not case['allocation_fail_at'] else 2 if direct and '-node-null-' in case['id'] else 1
    contract=p.literal(b'HIACAV01'+struct.pack('<8Q',AUX_BYTES,case['expected_allocation_attempts'],case['expected_allocations'],case['expected_frees'],case['allocation_fail_at'],case['expected_failed_allocations'],int(not trapped),failedkind))
    validation=p.concat(contract,expected,actual)
    validated=call(p,h['allocator_gate'],validation,label=label+':all-32768-slots-and-16-counters')
    prefix=p.slice(actual,0,136);p.compare(validated,prefix,label=label+':unmodified-actual-counter-publication')
    output=p.slice(actual,0,8);p.compare(output,expected,label=label+':full-output-before-exit')
    p.publish(actual,label.replace(':','-')+'-allocator.bin')
    p.drop(head,policy_size,object_size,request,bundle,linked,bound,auxiliary,descriptor,image_size,begin,failure,wire,run,actual,size,stdout,contract,validation,validated,prefix,output)


def qualify_allocator(p,h,compiler,cases,*,label):
    reference=open_reference(p,'allocator',len(cases));large=p.literal(bytes(1<<20));tail=p.literal(bytes(AUX_BYTES-(1<<20)));zero=p.concat(large,tail);p.drop(large,tail)
    for index,case in enumerate(cases):
        name=label+':allocator:'+case['id'];source=p.literal(case['source'].encode());expected,returned=reference_record(p,h,reference,index,case,source,label=name)
        projected=project(p,h,source,name);general=call(p,h['general_backend'],projected,label=name+':independent-resource-object');general_inventory(p,h,general,name)
        obj=build(p,h['observer'],h['check'],compiler,source,label=name+':current-target-object');text=call(p,h['owned_inventory'],obj,label=name+':original-owned-inspection');p.drop(text)
        for direct,image in ((True,general),(False,obj)):
            allocator_arm(p,h,image,case,expected,returned,zero,direct=direct,label=name+(':independent' if direct else ':target'))
        p.drop(source,expected,returned,projected,general,obj)
    p.drop(reference,zero)
