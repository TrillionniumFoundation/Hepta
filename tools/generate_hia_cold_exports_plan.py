"""Development composition of the original exports family as native plan data.

No execution or expected numeric outputs occur in this author. Every expected
export value comes from a live complete independent HIA VM during plan replay.
Dynamic get/put source and ordered-write expectations come from HIA owners fed
the actual compiler source. The native driver owns all processes and evidence.
"""
import json,struct
from tools.generate_hia_cold_qualification_plan import U64
from tools.hia_cold_qualification_plan_parts import call,build,observe,check_flat,assert_gate,utility,cli
from tools.hia_cold_qualification_vm_plan import assert_vm

KINDS=('void','unit','bool','u8','u16','u32','u64','usize','i8','i16','i32','i64','isize')

def concatenate_owned(p,parts):
    parts=list(parts)
    while len(parts)>100:
        following=[]
        for i in range(0,len(parts),100):
            group=parts[i:i+100];following.append(p.concat(*group));p.drop(*group)
        parts=following
    result=p.concat(*parts);p.drop(*parts);return result

def project(p,h,core,entry,label):
    left=p.literal(b'[');right=p.literal(b','+json.dumps(entry).encode()+b',1]')
    request=p.concat(left,core,right);wire=call(p,h['projector'],request,label=label)
    p.drop(left,right,request);return wire

def reference_packet(p,h,projected,args,*,label,snapshots=None):
    start=p.literal(b'HIAEVP01'+struct.pack('<Q',2));n=p.length(projected)
    argc=p.literal(struct.pack('<Q',len(args)));empty=None
    if snapshots is None:snapshots=empty=p.literal(b'')
    size=p.length(snapshots)
    budget=p.literal(struct.pack('<5Q',1000000,256,16<<20,0,0))
    arg=p.literal(b''.join(struct.pack('<2Q',kind,value&U64) for kind,value in args))
    frame=p.concat(start,n,argc,size,budget,arg,projected,snapshots)
    packet=call(p,h['reference_packet'],frame,label=label+':reference-packet')
    result=call(p,h['vm'],packet,label=label+':complete-independent-VM')
    p.drop(start,n,argc,size,budget,arg,frame,packet)
    if empty is not None:p.drop(empty)
    return result

def scalar_vm_shape(p,observed,returns,label):
    p.word(observed,0,int.from_bytes(b'HIASPR01','little'),label=label+':VM-header')
    p.word(observed,8,0,label=label+':VM-returned')
    steps=p.number(observed,0,offset=16,maximum=1000000);p.drop(steps)
    length=p.length(observed);p.word(length,0,144+returns*8,label=label+':full-VM-extent');p.drop(length)
    base=32+returns*8
    for a,b in ((3,4),(7,8)):
        x=p.slice(observed,base+a*8,8);y=p.slice(observed,base+b*8,8)
        p.compare(x,y,label=label+':VM-resource-conservation-'+str(a));p.drop(x,y)
    for index in (5,13):p.word(observed,base+index*8,0,label=label+':VM-zero-live-'+str(index))

def reference_exports(p,h,programs):
    """Run before constructing B0; returns sealed current VM response handles."""
    references={}
    for row in programs:
        name=row['name'];source=p.literal(row['source'].encode())
        core=call(p,h['assembly'],source,label=name+':source-independent-admission',argv=('child','--agent-compact'))
        entries={};pieces=[p.literal(b'HIAEXR01'+struct.pack('<3Q',len(row['calls']),24*len(row['calls']),0))]
        for index,case in enumerate(row['calls']):
            entry=case['function'];label=name+':reference:'+str(index)
            if entry not in entries:entries[entry]=project(p,h,core,entry,label+':fresh-source-projection')
            args=[(KINDS.index(t),v) for t,v in zip(case['parameter_types'],case['arguments'])]
            observed=reference_packet(p,h,entries[entry],args,label=label)
            returns=int(case['return_type']!='void');scalar_vm_shape(p,observed,returns,label)
            value=p.slice(observed,32,8) if returns else p.literal(bytes(8))
            head=p.literal(struct.pack('<2Q',index,KINDS.index(case['return_type'])))
            pieces.append(p.concat(head,value));p.drop(head,value,observed)
        references[name]=concatenate_owned(p,pieces)
        p.publish(references[name],'reference-'+name+'.bin')
        p.drop(source,core)
        p.drop(*entries.values())
    return references

def word_field(p,h,compiler_source,op,mode,offset,size,label):
    start=p.literal(b'HIAEXWQ1'+struct.pack('<4Q',op,mode,offset,size))
    extent=p.length(compiler_source);zero=p.literal(bytes(16));request=p.concat(start,extent,zero,compiler_source)
    output=call(p,h['word_source'],request,label=label)
    p.drop(start,extent,zero,request);return output

def reference_words(p,h,compiler_source):
    rows=[];layouts=[(0,n) for n in range(9)]+[(1,8),(1,9),(8,15),(8,16),(U64,8)]
    for op,operation in enumerate(('get','put')):
        for offset,size in layouts:
            label='compiler-word-'+operation+'-'+str(offset)+'-'+str(size)
            source=word_field(p,h,compiler_source,op,0,offset,size,label+':actual-author-helper')
            initial=word_field(p,h,compiler_source,op,1,offset,size,label+':initial')
            expected=word_field(p,h,compiler_source,op,2,offset,size,label+':independent-ordered-writes')
            metadata=word_field(p,h,compiler_source,op,3,offset,size,label+':independent-outcome')
            trapped=offset>size or size-offset<8
            p.word(metadata,0,int(trapped),label=label+':bounds-fact');p.word(metadata,8,7);p.drop(metadata)
            core=call(p,h['assembly'],source,label=label+':independent-admission',argv=('child','--agent-compact'))
            projected=project(p,h,core,'f0',label+':reference-projection')
            observed=reference_packet(p,h,projected,((14,0),(15,size),(15,0)),label=label,snapshots=initial)
            assert_vm(p,observed,label=label,values=() if trapped else (7,),status=18 if trapped else 0,snapshots_handle=expected,max_steps=1000000)
            p.drop(core,projected,observed)
            rows.append(dict(name=label,source=source,initial=initial,expected=expected,trapped=trapped,size=size))
    return rows

def export_request(p,dso,calls):
    records=[]
    for case in calls:
        name=case['function'].encode();args=case['arguments']
        records.append(struct.pack('<4Q',len(name),len(args),KINDS.index(case['return_type']),0)+name.ljust(128,b'\0')+struct.pack('<16Q',*args,*([0]*(16-len(args)))))
    start=p.literal(b'HIAEXQ01');n=p.length(dso)
    fields=p.literal(struct.pack('<5Q',len(calls),288*len(calls),0,0,0))
    extent=p.number(n,64+288*len(calls));table=p.literal(b''.join(records))
    wire=p.concat(start,n,fields,extent,table,dso);p.drop(start,n,fields,extent,table);return wire

def qualify_exports(p,h,compiler,programs,refusals,references,words,*,label):
    for row in programs:
        name=label+'-exports-'+row['name'];source=p.literal(row['source'].encode())
        obj=build(p,h['observer'],h['check'],compiler,source,label=name+':actual-target-object')
        names=b''.join(struct.pack('<Q',len(n.encode()))+n.encode().ljust(128,b'\0') for n in row['exports'])
        start=p.literal(b'HIAEXI01');size=p.length(obj);table=p.literal(struct.pack('<2Q',len(row['exports']),len(names))+names)
        wire=p.concat(start,size,table,obj);inventory=call(p,h['inventory'],wire,label=name+':actual-symbol-inventory')
        p.word(inventory,0,1);p.drop(start,size,table,wire,inventory)
        dso=call(p,h['linker'],obj,label=name+':native-link');request=export_request(p,dso,row['calls'])
        cli(p,h['check'],h['export_observer'],request,label=name+':actual-dlopen-SysV',expected_handle=references[row['name']])
        extent=p.length(obj);cap=p.number(extent,1,subtract=True);initial=utility(p,h['utility'],0,arg_word=cap,label=name+':short-preimage')
        observed=observe(p,h['observer'],compiler,source,cap_word=cap,label=name+':short-target-output')
        gate=check_flat(p,h['check'],observed,source,mode=1,cap_word=cap,core=0xfffffffe,initial_handle=initial,expected_handle=initial,label=name+':original-short-assertions')
        assert_gate(p,gate,label=name+':short-output')
        p.drop(source,obj,dso,request,extent,cap,initial,observed)
    initial=utility(p,h['utility'],0,arg=8192,label=label+':refusal-preimage')
    for index,row in enumerate(refusals):
        name=label+'-exports-reject-'+row['name'];source=p.literal(row['source'].encode())
        observed=observe(p,h['observer'],compiler,source,cap=8192,fill=165,label=name)
        gate=check_flat(p,h['check'],observed,source,mode=1,cap=8192,core=0xffffffff,initial_handle=initial,expected_handle=initial,label=name+':original-assertions')
        assert_gate(p,gate,label=name);p.drop(source,observed)
    p.drop(initial)
    empty=p.literal(b'')
    for row in words:
        name=label+'-'+row['name'];image=build(p,h['observer'],h['check'],compiler,row['source'],label=name+':actual-helper-build')
        shared=p.shared(row['initial']);observed=observe(p,h['observer'],image,empty,cap=row['size'],work=0,shared=shared,label=name+':actual-writes-before-exit')
        gate=check_flat(p,h['check'],observed,empty,mode=2 if row['trapped'] else 1,cap=row['size'],work=0,core=7,code=-4 if row['trapped'] else 0,initial_handle=row['initial'],expected_handle=row['expected'],label=name+':original-full-output-assertions')
        assert_gate(p,gate,label=name);p.drop(image,shared,observed)
    p.drop(empty)
