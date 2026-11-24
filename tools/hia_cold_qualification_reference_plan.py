"""Retain original base/Core and CLI independent controls before B0."""
import struct
from tools.hia_cold_qualification_plan_parts import call
from tools.hia_cold_qualification_vm_plan import vm_reference,assert_vm
from tools.hia_cold_qualification_names_plan import diagnostic


def reference_core(p,h,inputs):
    rows=[]
    for index,(left,right) in enumerate(((0,0),(5381,255),(0xffffffff,1),(0x80000000,128))):
        source=p.literal(inputs['backward_source'].encode())
        observed=vm_reference(p,h,source,entry='f2',args=((5,left),(5,right)),label='core-reference:backward-'+str(index))
        assert_vm(p,observed,values=(((left*33)^right)&0xffffffff,),label='core-reference:backward-'+str(index));rows.append(observed);p.drop(source)
    source=p.literal(inputs['chain_source'].encode())
    observed=vm_reference(p,h,source,entry='f127',args=((5,1),),max_call_depth=128,label='core-reference:128-function-call-depth')
    assert_vm(p,observed,values=(127,),label='core-reference:128-function-call-depth');rows.append(observed);p.drop(source)
    for row in inputs['admission']:
        source=p.literal(row['source'].encode());label='core-reference:'+row['id']
        if row['general_core_expected']=='rejected':
            diagnostic(p,h,source,row['error_code'],label=label)
        else:
            core=call(p,h['assembly'],source,label=label+':original-general-Core-acceptance',argv=('child','--agent-compact'));p.drop(core)
        p.drop(source)
    core=call(p,h['assembly'],h['source'],label='core-reference:actual-compiler-independent-admission',argv=('child','--agent-compact'));p.drop(core)
    structure=call(p,h['structure'],h['source'],label='core-reference:actual-compiler-call-structure')
    p.word(structure,0,int.from_bytes(b'HIAQST01','little'))
    for i,key in enumerate(('functions','blocks','backward_direct_calls','direct_tail_self_calls')):
        p.word(structure,8+i*8,inputs['structure'][key],label='core-reference:actual-'+key)
    result=p.concat(structure,*rows);p.publish(result,'core-reference.bin');p.drop(structure,*rows)
    return result


def reference_cli(p,h,inputs):
    rows=[]
    for row in inputs['echo']:
        source=p.literal(row['source'].encode());label='cli-reference:echo-'+str(row['byte'])
        observed=vm_reference(p,h,source,entry='reference_entry',label=label)
        assert_vm(p,observed,values=(1,row['byte']),label=label);rows.append(observed);p.drop(source)
    for name in ('large','previous','padded'):
        source=p.literal(inputs[name].encode());core=call(p,h['assembly'],source,label='cli-reference:'+name+'-full-Core-admission',argv=('child','--agent-compact'));p.drop(source,core)
    source=p.literal(inputs['previous_reference'].encode())
    observed=vm_reference(p,h,source,entry='f0',label='cli-reference:retained-eight-argument-capacity')
    assert_vm(p,observed,values=(0,),label='cli-reference:retained-eight-argument-capacity');rows.append(observed);p.drop(source)
    head=p.literal(b'HIAQCR01'+struct.pack('<Q',len(rows)));result=p.concat(head,*rows)
    p.publish(result,'cli-reference.bin');p.drop(head,*rows)
    return result
