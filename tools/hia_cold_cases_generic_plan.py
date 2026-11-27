"""Compose immutable native plans for the original thirteen generic families.

The author serializes inputs and original predicates. Every runtime admission,
reference execution, compilation, ELF check/link, machine call and assertion is
performed by HIA. No target compiler is supplied to a reference phase.
"""
from pathlib import Path
from hashlib import sha256
import json,struct
from tools.generate_hia_cold_qualification_plan import Plan,U64
from tools.hia_cold_qualification_plan_parts import call,observe,observe_linked,check_flat,assert_gate,utility
TYPE={'bool':2,'u8':3,'u16':4,'u32':5,'u64':6,'usize':7,'i8':8,'i16':9,'i32':10,'i64':11,'isize':12,'readbuf':14,'mutbuf':15}
ERROR={'overflow':1,'division_by_zero':2,'bounds':3,'allocation':4,'user':5,'steps':6,'calls':7,'heap':8}
FAMILIES=('signed','scalar-casts','multi','keyword','effects','cfg','bulk','loan','resource','select','tail','capacity','explicit-traps')

def source_pool(data,directory,*,families=FAMILIES):
    data,directory=Path(data),Path(directory);directory.mkdir(parents=True,exist_ok=True)
    family_rows=[json.loads((data/(family+'.json')).read_text()) for family in families]
    paths={row['source'] for rows in family_rows for name in ('admissions','references','native_programs','native_refusals','retained_promotions') for row in rows.get(name,[])}
    paths.update(row['expected_core'] for rows in family_rows for row in rows['admissions'] if 'expected_core' in row)
    paths=sorted(paths)
    raw=bytearray(b'HIAQCS01'+struct.pack('<3Q',len(paths),0,0));entries={}
    for name in paths:
        value=(data/name).read_bytes()
        entries[name]={'offset':len(raw),'bytes':len(value),'sha256':sha256(value).hexdigest()}
        raw+=value
    a5=len(raw);raw+=b'\xa5'*(1<<20)
    zero=len(raw);raw+=bytes((1<<20)+8)
    struct.pack_into('<Q',raw,16,len(raw))
    path=directory/'sources.hiadat';path.write_bytes(raw)
    index={'source':str(path),'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'entries':entries,'a5':a5,'zero':zero}
    (directory/'source-index.json').write_text(json.dumps(index,indent=2)+'\n')
    return index

class Context:
    def __init__(self,rows,index,tools,*,compiler=False,reference_paths=None):
        self.p=Plan();self.rows=rows;self.index=index;self.imports=dict(tools)
        self.imports['case_sources']=Path(index['source'])
        self.h={name:self.p.imported(name) for name in self.imports if name not in ('fast','cold')}
        self.sources={};self.cores={};self.projections={}
        self.a5=self.p.slice(self.h['case_sources'],index['a5'],1<<20)
        self.zero=self.p.slice(self.h['case_sources'],index['zero'],(1<<20)+8)
        self.references={}
        for key,path in sorted((reference_paths or {}).items()):
            name='reference_'+key;self.imports[name]=Path(path);self.references[key]=self.p.imported(name)
        self.counts={'accepted':0,'rejected':0,'references':0,'programs':0,'calls':0,'objects':0,'linked_calls':0,'short':0,'refusals':0,'promotions':0}
    def source(self,name):
        if name not in self.sources:
            row=self.index['entries'][name]
            value=self.p.slice(self.h['case_sources'],row['offset'],row['bytes'])
            digest=self.p.sha256(value);wanted=self.p.literal(bytes.fromhex(row['sha256']))
            self.p.compare(digest,wanted,label='exact-fixture-source:'+name)
            self.p.drop(digest,wanted);self.sources[name]=value
        return self.sources[name]
    def core(self,name):
        if name not in self.cores:
            source=self.source(name)
            core=call(self.p,self.h['assembly'],source,label='original-Core-admission:'+name,argv=('child','--agent-compact'))
            size=self.p.length(core);positive=self.p.number(size,1,subtract=True);self.p.drop(size,positive)
            self.cores[name]=core
        return self.cores[name]
    def projection(self,name,entry):
        key=(name,entry)
        if key not in self.projections:
            left=self.p.literal(b'[');right=self.p.literal(b','+json.dumps(entry).encode()+b',1]')
            request=self.p.concat(left,self.core(name),right)
            projected=call(self.p,self.h['projector'],request,label='original-reference-entry:'+entry)
            self.p.drop(left,right,request);self.projections[key]=projected
        return self.projections[key]

def diagnostic(c,source,code,label):
    p,h=c.p,c.h
    run=p.run(h['assembly'],source,argv=('child',),label=label+':actual-plain-Core-diagnostic')
    receipt=p.resultpart(run,0);p.word(receipt,8,2,label=label+':original-Core-rejection')
    output=p.resultpart(run,1);stderr=p.resultpart(run,2);empty=p.literal(b'')
    p.compare(stderr,empty,label=label+':stderr-empty')
    desired=p.literal(code.encode());head=p.literal(b'HIAQCG01'+struct.pack('<2Q',1,len(code)))
    size=p.length(output);tail=p.literal(bytes(32));request=p.concat(head,size,tail,desired,output)
    gate=call(p,h['case_gate'],request,label=label+':exact-original-error-category')
    assert_gate(p,gate,label=label+':category-accepted')
    p.drop(run,receipt,output,stderr,empty,desired,head,size,tail,request)

def reference(c,row):
    p,h=c.p,c.h;label=row['id'];budget=row['budgets']
    steps=budget.get('max_steps',1000000);depth=budget.get('max_call_depth',256)
    heap=budget.get('max_heap_bytes',16<<20);fail=budget.get('allocation_fail_at') or 0
    projected=c.projection(row['source'],row['entry'])
    snap=bytes.fromhex(row.get('snapshots_hex',''))
    expected_snap=bytes.fromhex(row.get('expected_snapshots_hex',''))
    params=list(zip(row['types'],row['args'],strict=True))
    start=p.literal(b'HIAEVP01'+struct.pack('<Q',2));n=p.length(projected)
    controls=p.literal(struct.pack('<7Q',len(params),len(snap),steps,depth,heap,fail,0))
    arguments=p.literal(b''.join(struct.pack('<2Q',TYPE[typ],int(value)&U64) for typ,value in params))
    snapshots=p.literal(snap);frame=p.concat(start,n,controls,arguments,projected,snapshots)
    packet=call(p,h['reference_packet'],frame,label=label+':fresh-typed-reference-packet')
    observed=call(p,h['vm'],packet,label=label+':current-full-independent-VM')
    expect=row['expect'];returned=expect['status']=='returned'
    kind=0 if returned else 2 if expect['status']=='budget_exceeded' else 1
    values=expect.get('values',[]) if returned else []
    semantic=0 if returned else ERROR[expect['code']]
    head=p.literal(b'HIAQCG01'+struct.pack('<7Q',0,kind,semantic,steps,len(values),len(expected_snap),0))
    request=p.concat(head,observed)
    gate=call(p,h['case_gate'],request,label=label+':original-VM-outcome-and-budget')
    assert_gate(p,gate,label=label+':VM-outcome-accepted')
    for i,value in enumerate(values):p.word(observed,32+i*8,int(value),label=label+':fixed-semantic-value-'+str(i))
    base=32+8*len(values);actual=p.slice(observed,base+112);expected=p.literal(expected_snap)
    p.compare(actual,expected,label=label+':complete-external-views')
    if returned or 'expected_live_owners' in row:
        owner_count=p.slice(observed,base+24,8);drops=p.slice(observed,base+32,8)
        expected_owner=p.number(drops,row.get('expected_live_owners',0))
        p.compare(owner_count,expected_owner,label=label+':original-live-owner-obligation')
        starts=p.slice(observed,base+56,8);ends=p.slice(observed,base+64,8)
        expected_loans=p.number(ends,row.get('expected_live_loans',0))
        p.compare(starts,expected_loans,label=label+':original-live-loan-obligation')
        p.drop(owner_count,drops,expected_owner,starts,ends,expected_loans)
        if returned and not row.get('expected_live_owners',0):
            p.word(observed,base+40,0,label=label+':no-live-heap')
            p.word(observed,base+104,0,label=label+':no-live-chains')
    p.drop(start,n,controls,arguments,snapshots,frame,packet,head,request,actual,expected)
    c.counts['references']+=1
    return observed

def references_plan(rows,index,tools):
    c=Context(rows,index,tools);p=c.p
    for row in rows['admissions']:
        if row['accepted']:
            actual=c.core(row['source'])
            if 'expected_core' in row:
                expected=c.source(row['expected_core'])
                p.compare(actual,expected,label=rows['family']+':original-exact-Core-tree-'+row['source'])
            c.counts['accepted']+=1
        else:
            diagnostic(c,c.source(row['source']),row['code'],rows['family']+':'+row['source'])
            c.counts['rejected']+=1
    needed={call['fresh_reference_return'] for program in rows['native_programs'] for call in program['calls'] if call.get('fresh_reference_return')}
    for row in rows['references']:
        result=reference(c,row)
        if row['id'] in needed:p.publish(result,row['id']+'.hiaspr')
        p.drop(result)
    return c

def dynamic_check(p,tool,observed,source,*,cap_word,initial,expected,work=0,mode=1,core_word=None,core=0,code=0,words=(),word_value=None,label):
    made=[]
    def literal(raw):
        value=p.literal(raw);made.append(value);return value
    start=literal(b'HIAQFV01'+struct.pack('<Q',mode));source_n=p.length(source)
    middle=literal(struct.pack('<2Q',work,0));ini_n=p.length(initial);expected_n=p.length(expected)
    core_h=literal(struct.pack('<Q',core&U64)) if core_word is None else core_word
    control=literal(struct.pack('<2Q',code&U64,len(words)+(word_value is not None)))
    zeros=literal(bytes(8));size=p.length(observed);tail=literal(bytes(24))
    head=p.concat(start,source_n,cap_word,middle,ini_n,expected_n,core_h,control,zeros,size,tail)
    data=literal(b''.join(struct.pack('<3Q',*x) for x in words))
    extra=[]
    if word_value is not None:
        descriptor=literal(struct.pack('<2Q',224,8));data=p.concat(data,descriptor,word_value);extra.append(data)
    request=p.concat(head,source,initial,expected,data,observed)
    gate=call(p,tool,request,label=label)
    p.drop(*made,source_n,ini_n,expected_n,size,head,request,*extra)
    return gate

def build(c,compiler,source,*,label,fill=0,words=(),capture_word=None):
    p,h=c.p,c.h
    result=observe(p,h['observer'],compiler,source,fill=fill,label=label+':actual-build')
    image=check_flat(p,h['check'],result,source,words=words,label=label+':all-compilation-publication-gates')
    value=None
    if capture_word is not None:
        stdout=p.resultpart(result,1)
        # All compile calls retain the original 1 MiB output/workspace.
        source_size=c.index['entries'][capture_word[0]]['bytes']
        value=p.slice(stdout,24+source_size+(1<<20)+capture_word[1],8)
        p.drop(stdout)
    p.drop(result)
    return image,value

def native_plan(rows,index,tools,*,label,reference_paths=None):
    c=Context(rows,index,tools,compiler=True,reference_paths=reference_paths)
    p,h=c.p,c.h;compiler=h['compiler']
    for program in rows['native_programs']:
        source=c.source(program['source']);name=label+'-'+program['id']
        flat=obj=linked=None;frame_word=None
        if program['flat']:
            flat,frame_word=build(c,compiler,source,label=name+'-flat',fill=program['fill'],words=program['compile_words'],
                capture_word=(program['source'],program['short_word']) if program['short_word'] is not None else None)
        if program['object']:
            object_source=source if program['owned'] else utility(p,h['util'],1,source,module=b'selfhost_elf',label=name+':exact-object-module')
            obj,_=build(c,compiler,object_source,label=name+'-object',fill=program['fill'],words=program['compile_words'])
            text=call(p,h['owned_inventory'],obj,label=name+':original-owned-object-inspector') if program['owned'] else utility(p,h['util'],2,obj,label=name+':original-six-section-object-inspector')
            if flat is not None:p.compare(text,flat,label=name+':actual-ELF-text-equals-current-flat')
            p.drop(text);c.counts['objects']+=1
            if program['linked']:
                linked=call(p,h['linker'],obj,label=name+':actual-native-dynamic-link')
            if object_source!=source:p.drop(object_source)
        if program['short']:
            image=obj if program['short']=='object' else flat
            target=source if program['short']=='flat' or program['owned'] else utility(p,h['util'],1,source,module=b'selfhost_elf',label=name+':original-short-object-source')
            size=p.length(image);cap=p.number(size,1,subtract=True,maximum=(1<<20)-1)
            preimage=utility(p,h['util'],0,arg_word=cap,fill=165,label=name+':original-short-preimage')
            observation=observe(p,h['observer'],compiler,target,cap_word=cap,label=name+':original-short-output')
            gate=dynamic_check(p,h['check'],observation,target,cap_word=cap,initial=preimage,expected=preimage,work=1<<20,
                               core=0xfffffffe,word_value=frame_word,label=name+':transactional-short-output')
            assert_gate(p,gate,label=name+':all-original-short-gates')
            p.drop(size,cap,preimage,observation)
            if target!=source:p.drop(target)
            c.counts['short']+=1
        for row in program['calls']:
            data=p.literal(bytes.fromhex(row['input_hex']));initial=p.literal(bytes.fromhex(row['initial_hex']));expected=p.literal(bytes.fromhex(row['expected_hex']))
            capacity=len(bytes.fromhex(row['initial_hex']))
            for form,image in [('flat',flat),('linked',linked)]:
                if image is None:continue
                tag=label+'-'+row['id']+'-'+form
                shared=p.shared(initial) if row['shared'] or bytes.fromhex(row['initial_hex'])!=b'\xa5'*capacity else 0
                snapshot=None
                if form=='flat':
                    observation=observe(p,h['observer'],image,data,cap=capacity,work=0,shared=shared,label=tag)
                else:
                    observation,snapshot=observe_linked(p,h['linked_observer'],image,data,cap=capacity,work=0,shared=shared,label=tag,zero_base=c.zero,util=h['util'])
                    c.counts['linked_calls']+=1
                if row['signal']:
                    p.word(observation,8,0,label=tag+':original-trap-stdout-empty')
                    p.word(observation,16,0,label=tag+':original-trap-stderr-empty')
                if row.get('fresh_reference_return'):
                    reference=c.references[row['fresh_reference_return']]
                    p.word(reference,0,int.from_bytes(b'HIASPR01','little'),label=tag+':current-reference-receipt')
                    p.word(reference,8,0,label=tag+':current-reference-returned')
                    scalar=p.slice(reference,32,4);zero=p.literal(bytes(4));core=p.concat(scalar,zero);cap=p.literal(struct.pack('<Q',capacity))
                    gate=dynamic_check(p,h['check'],observation,data,cap_word=cap,initial=initial,expected=expected,core_word=core,
                                       code=-row['signal'],label=tag+':same-run-VM-value-comparison')
                    p.drop(scalar,zero,core,cap)
                else:
                    gate=check_flat(p,h['linked_check'] if snapshot is not None else h['check'],observation,data,mode=2 if row['signal'] else 1,cap=capacity,work=0,
                                    initial_handle=initial,expected_handle=expected,core=row['core_u32'],code=-row['signal'],
                                    snapshot_handle=snapshot,label=tag+':complete-original-observation')
                assert_gate(p,gate,label=tag+':original-execution-gate')
                p.drop(observation)
                if snapshot is not None:p.drop(snapshot)
                if shared:p.drop(shared)
                c.counts['calls']+=1
            p.drop(data,initial,expected)
        for value in (flat,obj,linked,frame_word):
            if value is not None:p.drop(value)
        c.counts['programs']+=1
    for row in rows['native_refusals']:
        source=c.source(row['source']);name=label+'-'+row['id'];capacity=row['capacity']
        result=observe(p,h['observer'],compiler,source,cap=capacity,fill=row['fill'],label=name)
        initial=p.slice(c.a5,0,capacity)
        gate=check_flat(p,h['check'],result,source,mode=1,cap=capacity,work=1<<20,
                        initial_handle=initial,expected_handle=initial,core=row['core_u32'],words=row['workspace_words'],label=name+':original-refusal-and-workspace')
        assert_gate(p,gate,label=name+':refusal-gate')
        p.drop(result,initial);c.counts['refusals']+=1
    for row in rows['retained_promotions']:
        expected=c.source(row['source'])
        for identity in row['cases']:
            matches=[program for program in rows['native_programs'] if any(call['id']==rows['family']+'-'+identity for call in program['calls'])]
            assert matches
            for program in matches:p.compare(expected,c.source(program['source']),label=label+':original-promotion-source-'+row['id'])
        c.counts['promotions']+=1
    return c
