"""Source-bound original names controls in the native qualification plan."""
import struct

from tools.hia_cold_qualification_plan_parts import (
    assert_gate,build,call,check_flat,cli,observe,observe_linked,utility)
from tools.hia_cold_qualification_vm_plan import assert_vm,vm_reference


def alpha_source(p,h,source,table,*,label):
    prefix=p.literal(b'HIAQAL01'+struct.pack('<Q',len(table)))
    size=p.length(source);reserved=p.literal(bytes(8))
    names=p.literal(b''.join(struct.pack('<Q',len(name.encode()))+name.encode() for name in table))
    request=p.concat(prefix,size,reserved,names,source)
    result=call(p,h['alpha_tool'],request,label=label+':actual-alpha-transform')
    p.drop(prefix,size,reserved,names,request)
    return result


def diagnostic(p,h,source,code,*,label):
    run=p.run(h['assembly'],source,argv=('child',),label=label+':fresh-independent-diagnostic')
    receipt=p.resultpart(run,0);p.word(receipt,8,2,label=label+':actual-rejection-exit')
    stderr=p.resultpart(run,2);empty=p.literal(b'');p.compare(stderr,empty,label=label+':diagnostic-stderr')
    report=p.resultpart(run,1)
    expected=code.encode();prefix=p.literal(b'HIAQCG01'+struct.pack('<2Q',1,len(expected)))
    size=p.length(report);reserved=p.literal(bytes(32));name=p.literal(expected)
    request=p.concat(prefix,size,reserved,name,report)
    gate=call(p,h['cases_gate'],request,label=label+':exact-independent-error-category')
    assert_gate(p,gate,label=label+':independent-error-category')
    p.drop(run,receipt,stderr,empty,report,prefix,size,reserved,name,request)


def reference_names(p,h,inputs):
    rows=inputs['cases'];references=[]
    for row in rows:
        label='names-reference:'+row['id'];source=p.literal(row['source'].encode())
        inp=bytes.fromhex(row['source_hex']);initial=bytes.fromhex(row['initial_hex'])
        observed=vm_reference(p,h,source,label=label,entry=row['entry'],
            args=((14,len(inp)),(15,len(initial)),(15,0)),snapshots=inp+initial,
            max_steps=1_000_000,max_call_depth=256,max_heap_bytes=16<<20)
        assert_vm(p,observed,label=label,values=(row['expected_result'],),
            snapshots=inp+bytes.fromhex(row['expected_hex']),max_steps=1_000_000)
        references.append(observed);p.drop(source)
    for row in inputs['refusals']:
        source=p.literal(row['source'].encode());label='names-reference:'+row['id']
        if row['general_core_expected']=='accepted':
            core=call(p,h['assembly'],source,label=label+':retained-valid-Core-profile-exclusion',argv=('child','--agent-compact'));p.drop(core)
        else:
            diagnostic(p,h,source,row['error_code'],label=label)
        p.drop(source)
    head=p.literal(b'HIAQNR01'+struct.pack('<3Q',len(rows),0,0));parts=[head]
    for start in range(0,len(references),100):
        parts.append(p.concat(*references[start:start+100]))
    bundle=p.concat(*parts);p.drop(*parts,*references)
    outputs={'names-reference.bin':bundle}
    for label,key in [('original','source'),('modified','modified_source')]:
        canonical=call(p,h['assembly'],h[key],label=label+':names-canonical-independent-admission',argv=('child','--agent-compact'));p.drop(canonical)
        alpha=alpha_source(p,h,h[key],inputs['function_names'],label=label+':names-pre-B0')
        checked=call(p,h['assembly'],alpha,label=label+':names-alpha-independent-admission',argv=('child','--agent-compact'));p.drop(checked)
        outputs['names-alpha-'+label+'.hepta']=alpha
    for name,handle in outputs.items():p.publish(handle,name)
    return outputs


def qualify_names(p,h,inputs,*,label):
    rows=inputs['cases'];bundle=h['names_reference'];images={};compilations=[];checks=[]
    p.word(bundle,0,int.from_bytes(b'HIAQNR01','little'))
    p.word(bundle,8,len(rows));p.word(bundle,16,0);p.word(bundle,24,0)
    expected_size=32+sum(152+len(bytes.fromhex(row['source_hex']))+len(bytes.fromhex(row['initial_hex'])) for row in rows)
    size=p.length(bundle);p.word(size,0,expected_size,label=label+':complete-reference-inventory');p.drop(size)
    zero=p.literal(bytes(1<<20));eight=p.literal(bytes(8));zero_base=p.concat(eight,zero);p.drop(zero,eight)
    cursor=32
    for row in rows:
        program=row['program'];name=label+':names-'+row['id']
        inp=bytes.fromhex(row['source_hex']);initial=bytes.fromhex(row['initial_hex'])
        length=152+len(inp)+len(initial);reference=p.slice(bundle,cursor,length);cursor+=length
        assert_vm(p,reference,label=name+':same-run-reference',values=(row['expected_result'],),
            snapshots=inp+bytes.fromhex(row['expected_hex']),max_steps=1_000_000)
        value=p.slice(reference,32,8);expected=p.slice(reference,152+len(inp),len(initial))
        if program not in images:
            source=p.literal(row['source'].encode())
            flat=build(p,h['observer'],h['check'],h['compiler'],source,label=label+':names-'+program+'-flat')
            obj_source=utility(p,h['util'],1,source,module=b'selfhost_elf',label=label+':names-'+program+'-ELF-module')
            obj=build(p,h['observer'],h['check'],h['compiler'],obj_source,label=label+':names-'+program+'-object')
            text=utility(p,h['util'],2,obj,label=label+':names-'+program+'-complete-ELF-inspection')
            p.compare(text,flat,label=label+':names-'+program+'-same-run-text')
            linked=call(p,h['linker'],obj,label=label+':names-'+program+'-native-shared-link')
            images[program]=(flat,linked);compilations.extend([program+'-flat',program+'-object'])
            p.drop(source,obj_source,obj,text)
        data=p.literal(inp);before=p.literal(initial)
        for kind,image in zip(('flat','linked'),images[program]):
            shared=p.shared(before)
            if kind=='flat':
                result=observe(p,h['observer'],image,data,cap=len(initial),work=0,shared=shared,label=name+':actual-flat')
                snapshot=None;checker=h['check']
            else:
                result,snapshot=observe_linked(p,h['linked_observer'],image,data,cap=len(initial),work=0,shared=shared,zero_base=zero_base,label=name+':actual-dlopen')
                checker=h['linked_check']
            gate=check_flat(p,checker,result,data,mode=1,cap=len(initial),work=0,core_word=value,
                initial_handle=before,expected_handle=expected,snapshot_handle=snapshot,label=name+':'+kind+'-complete-observation')
            assert_gate(p,gate,label=name+':'+kind+'-actual-return-writes-source-ABI')
            p.drop(shared,result)
            if snapshot is not None:p.drop(snapshot)
            checks.append(row['id']+':'+kind)
        p.drop(reference,value,expected,data,before)
    for flat,linked in images.values():p.drop(flat,linked)
    before=p.literal(b'\xa5'*512)
    for row in inputs['refusals']:
        source=p.literal(row['source'].encode());name=label+':names-'+row['id']
        result=observe(p,h['observer'],h['compiler'],source,cap=512,label=name)
        gate=check_flat(p,h['check'],result,source,mode=1,cap=512,core=0xffffffff,
            initial_handle=before,expected_handle=before,label=name+':transactional-rejection')
        assert_gate(p,gate,label=name);p.drop(source,result);checks.append(row['id'])
    p.drop(before)
    alpha=alpha_source(p,h,h['source'],inputs['function_names'],label=label+':names')
    p.compare(alpha,h['alpha'],label=label+':same-pre-B0-alpha-source')
    previous=h['compiler'];made=[]
    for generation in (1,2):
        image=build(p,h['observer'],h['check'],previous,alpha,label=label+':names-alpha-R'+str(generation))
        p.compare(image,h['compiler'],label=label+':names-alpha-fixed-point-'+str(generation))
        made.append(image);previous=image;compilations.append('alpha-R'+str(generation))
    executable_source=utility(p,h['util'],1,alpha,module=b'selfhost_exec',label=label+':names-alpha-CLI-module')
    executable=build(p,h['observer'],h['check'],h['compiler'],executable_source,label=label+':names-alpha-E1')
    inspected=utility(p,h['util'],3,executable,label=label+':names-alpha-complete-CLI-inspection')
    assert_gate(p,inspected,label=label+':names-alpha-ELF-envelope')
    cli(p,h['check'],executable,executable_source,expected_handle=executable,label=label+':names-alpha-E2-actual-kernel-fixed-point')
    compilations.append('alpha-E1');p.drop(alpha,*made,executable_source,executable)
    module_source=utility(p,h['util'],1,h['source'],module=('Compiler_'+label).encode(),label=label+':names-compiler-module')
    previous=h['compiler'];made=[]
    for generation in (1,2):
        image=build(p,h['observer'],h['check'],previous,module_source,label=label+':names-module-R'+str(generation))
        p.compare(image,h['compiler'],label=label+':names-module-fixed-point-'+str(generation))
        made.append(image);previous=image;compilations.append('module-R'+str(generation))
    p.drop(module_source,*made,zero_base)
    if len(compilations)!=2*len(images)+5 or len(set(compilations))!=len(compilations):
        raise ValueError('original complete names compilation inventory differs')
    return {'compilations':compilations,'checks':checks,'reference_cases':len(rows),'refusals':len(inputs['refusals'])}
