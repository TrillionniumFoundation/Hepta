"""Serialize the complete original ELF family into native sealed operations."""
from tools.hia_cold_qualification_plan_parts import (call,build,observe,observe_linked,
                                                     check_flat,utility,assert_gate)
from tools.hia_selfhost_cases import recursion_refusals,call_graph_invalid_sources


def append_elf(p,h,sample,*,label):
    zero=p.literal(bytes(1<<20));eight=p.literal(bytes(8));zero_base=p.concat(eight,zero);initial=p.literal(b'\xa5'*(1<<20));empty=p.literal(b'')
    sample_image=build(p,h['observer'],h['check'],h['compiler'],h['sample'],label=label+':ELF-sample-flat')
    for subject,src,plain in [('compiler',h['source'],h['compiler']),('bytesum',h['sample'],sample_image)]:
        case=label+':ELF-'+subject
        objsource=utility(p,h['util'],1,src,module=b'selfhost_elf',label=case+':actual-module')
        obj=build(p,h['observer'],h['check'],h['compiler'],objsource,label=case+':compile-object')
        text=utility(p,h['util'],2,obj,label=case+':complete-ELF-inspection');p.compare(text,plain,label=case+':same-run-text-flat')
        linked=call(p,h['linker'],obj,label=case+':actual-HIA-dynamic-linker')
        if subject=='compiler':
            result,snapshot=observe_linked(p,h['linked_observer'],linked,src,label=case+':actual-dlopen-rebuild',zero_base=zero_base)
            rebuilt=check_flat(p,h['linked_check'],result,src,snapshot_handle=snapshot,label=case+':actual-returned-compiler')
            p.compare(rebuilt,plain,label=case+':linked-self-rebuild-exact');p.drop(result,snapshot,rebuilt)
        else:
            for index,data in enumerate((b'',bytes(range(256))*4)):
                expected=5381
                for byte in data:expected=((expected*33)^byte)&0xffffffff
                inp=p.literal(data);result,snapshot=observe_linked(p,h['linked_observer'],linked,inp,label=case+':actual-dlopen-'+str(index),cap=1,work=1,zero_base=zero_base)
                gate=check_flat(p,h['linked_check'],result,inp,snapshot_handle=snapshot,mode=1,cap=1,work=1,initial=b'\xa5',expected=bytes([expected&255]),core=expected,label=case+':full-observation-'+str(index))
                assert_gate(p,gate,label=case+':behavior-'+str(index));p.drop(inp,result,snapshot)
        length=p.length(obj);short=p.number(length,1,subtract=True,maximum=1<<20)
        small=utility(p,h['util'],0,arg_word=short,label=case+':short-transaction-preimage')
        result=observe(p,h['observer'],h['compiler'],objsource,cap_word=short,label=case+':short-output')
        gate=check_flat(p,h['check'],result,objsource,mode=1,cap_word=short,core=0xfffffffe,initial_handle=small,expected_handle=small,label=case+':short-output-transactional')
        assert_gate(p,gate,label=case+':short-output');p.drop(objsource,obj,text,linked,length,short,small,result)
    recursive=p.literal(recursion_refusals()['mutual-recursion']);recursive_elf=utility(p,h['util'],1,recursive,module=b'selfhost_elf',label=label+':ELF-recursion-module')
    obj=build(p,h['observer'],h['check'],h['compiler'],recursive_elf,label=label+':ELF-recursive-object')
    linked=call(p,h['linker'],obj,label=label+':ELF-recursive-real-link');shared=p.shared(empty)
    result,snapshot=observe_linked(p,h['linked_observer'],linked,empty,label=label+':ELF-recursive-real-trap',cap=0,work=0,shared=shared,zero_base=zero_base)
    gate=check_flat(p,h['linked_check'],result,empty,snapshot_handle=snapshot,mode=2,cap=0,work=0,code=-4,label=label+':ELF-recursive-SIGILL-and-writes')
    assert_gate(p,gate,label=label+':ELF-recursive-budget-trap');p.drop(recursive,recursive_elf,obj,linked,shared,result,snapshot)
    bad=p.literal(call_graph_invalid_sources(sample)['backward-signature']);badelf=utility(p,h['util'],1,bad,module=b'selfhost_elf',label=label+':ELF-invalid-call-module')
    result=observe(p,h['observer'],h['compiler'],badelf,label=label+':ELF-invalid-call')
    gate=check_flat(p,h['check'],result,badelf,mode=1,core=0xffffffff,initial_handle=initial,expected_handle=initial,label=label+':ELF-invalid-transaction')
    assert_gate(p,gate,label=label+':ELF-reject-bad-call')
