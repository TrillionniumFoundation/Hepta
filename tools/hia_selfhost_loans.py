"""Independent Core and native checks for block-local borrowed reborrowing.

Locally created loans must end in their creation block. This deliberately smaller
profile neither implements ownership nor claims general cross-block loan flow.
"""
from __future__ import annotations
from tools.hia_selfhost_cases import HEADER
from tools.hia_selfhost_bulk import Body


def loan_cases():
    rows=[]
    def add(name,body):
        rows.append({'id':name,'source':(HEADER+body+'  v99:u32 = const() {"value":0}\n  ret(v99)\nend\n').encode(),
                     'source_hex':bytes(range(101,109)).hex(), 'initial_hex':bytes(range(31,39)).hex()})
    add('readonly-source','  v3:readbuf = borrow.read(v0)\n  v4:usize = const() {"value":0}\n'
        '  v5:u8 = buffer.load(v3,v4)\n  _ = loan.end(v3)\n  _ = buffer.store(v1,v4,v5)\n')
    add('mutable-child','  v3:mutbuf = borrow.mut(v1)\n  v4:u8 = const() {"value":173}\n'
        '  _ = buffer.fill(v3,v4)\n  _ = loan.end(v3)\n')
    add('nested-mutable','  v3:mutbuf = borrow.mut(v1)\n  v4:mutbuf = borrow.mut(v3)\n'
        '  v5:u8 = const() {"value":173}\n  _ = buffer.fill(v4,v5)\n'
        '  _ = loan.end(v4)\n  _ = loan.end(v3)\n')
    add('nested-readonly','  v3:mutbuf = borrow.mut(v1)\n  v4:readbuf = borrow.read(v3)\n'
        '  v5:usize = const() {"value":0}\n  v6:u8 = buffer.load(v4,v5)\n'
        '  _ = loan.end(v4)\n  _ = buffer.store(v3,v5,v6)\n  _ = loan.end(v3)\n')
    add('readonly-siblings','  v3:readbuf = borrow.read(v1)\n  v4:readbuf = borrow.read(v1)\n'
        '  v5:usize = const() {"value":0}\n  v6:u8 = buffer.load(v3,v5)\n'
        '  v7:u8 = buffer.load(v4,v5)\n  _ = loan.end(v3)\n  _ = loan.end(v4)\n'
        '  _ = buffer.store(v1,v5,v7)\n')
    add('restored-parent','  v3:mutbuf = borrow.mut(v1)\n  _ = loan.end(v3)\n'
        '  v4:u8 = const() {"value":255}\n  _ = buffer.fill(v1,v4)\n'
        '  v5:mutbuf = borrow.mut(v1)\n  v6:u8 = const() {"value":173}\n'
        '  _ = buffer.fill(v5,v6)\n  _ = loan.end(v5)\n')
    add('disjoint-copy','  v3:readbuf = borrow.read(v0)\n  v4:mutbuf = borrow.mut(v1)\n'
        '  v5:usize = const() {"value":8}\n  _ = buffer.copy(v4,v3,v5)\n'
        '  _ = loan.end(v4)\n  _ = loan.end(v3)\n')
    add('borrowed-extent','  v3:readbuf = borrow.read(v1)\n  v4:usize = buffer.len(v1)\n'
        '  v5:usize = buffer.len(v3)\n  _ = loan.end(v3)\n')
    add('mutable-child-call','  v3:mutbuf = borrow.mut(v1)\n'
        '  v4:u32 = call(v3) {"function":"f1"}\n  _ = loan.end(v3)\n')
    rows[-1]['source'] += ('fn f1(v0:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n'
        'block b0(v0:mutbuf)\n  v1:u8 = const() {"value":173}\n'
        '  _ = buffer.fill(v0,v1)\n  v2:u32 = const() {"value":0}\n  ret(v2)\nend\n').encode()
    add('shared-sibling-call','  v3:readbuf = borrow.read(v1)\n  v4:readbuf = borrow.read(v1)\n'
        '  v5:u32 = call(v3,v4) {"function":"f1"}\n  _ = loan.end(v3)\n  _ = loan.end(v4)\n')
    rows[-1]['source'] += ('fn f1(v0:readbuf,v1:readbuf) -> (u32) effects(read,write,trap) entry(b0)\n'
        'block b0(v0:readbuf,v1:readbuf)\n  v2:usize = const() {"value":0}\n'
        '  v3:u8 = buffer.load(v0,v2)\n  v4:u8 = buffer.load(v1,v2)\n'
        '  v5:u32 = const() {"value":0}\n  ret(v5)\nend\n').encode()
    return rows


def loan_refusals():
    base=next(r['source'] for r in loan_cases() if r['id']=='mutable-child')
    rows={
        'readonly-to-mutable':base.replace(b'borrow.mut(v1)',b'borrow.mut(v0)'),
        'wrong-read-result':base.replace(b'v3:mutbuf = borrow.mut',b'v3:mutbuf = borrow.read'),
        'wrong-mutable-result':base.replace(b'v3:mutbuf',b'v3:readbuf'),
        'scalar-result':base.replace(b'v3:mutbuf',b'v3:u64'),
        'missing-result':base.replace(b'v3:mutbuf =',b'_ ='),
        'short-arity':base.replace(b'borrow.mut(v1)',b'borrow.mut()'),
        'long-arity':base.replace(b'borrow.mut(v1)',b'borrow.mut(v1,v1)'),
        'external-end':base.replace(b'loan.end(v3)',b'loan.end(v1)'),
        'suspended-parent-write':base.replace(b'buffer.fill(v3,',b'buffer.fill(v1,'),
        'suspended-parent-read':base.replace(b'  _ = buffer.fill(v3,v4)',b'  v5:usize = const() {"value":0}\n  v6:u8 = buffer.load(v1,v5)'),
        'double-end':base.replace(b'  _ = loan.end(v3)',b'  _ = loan.end(v3)\n  _ = loan.end(v3)'),
        'use-after-end':base.replace(b'  _ = loan.end(v3)',b'  _ = loan.end(v3)\n  _ = buffer.fill(v3,v4)'),
        'live-local-return':base.replace(b'  _ = loan.end(v3)\n',b''),
        'end-parent-first':base.replace(b'  _ = loan.end(v3)',b'  v5:readbuf = borrow.read(v3)\n  _ = loan.end(v3)\n  _ = loan.end(v5)'),
        'mutable-sibling':base.replace(b'  v4:u8',b'  v5:mutbuf = borrow.mut(v1)\n  _ = loan.end(v5)\n  v4:u8'),
        'readonly-with-mutable-sibling':base.replace(b'  v4:u8',b'  v5:readbuf = borrow.read(v1)\n  _ = loan.end(v5)\n  v4:u8'),
        'mutable-with-readonly-sibling':base.replace(b'  v3:mutbuf',b'  v5:readbuf = borrow.read(v1)\n  v3:mutbuf').replace(b'  _ = loan.end(v3)',b'  _ = loan.end(v3)\n  _ = loan.end(v5)'),
        'end-result':base.replace(b'_ = loan.end(v3)',b'v6:u32 = loan.end(v3)'),
        'end-short-arity':base.replace(b'loan.end(v3)',b'loan.end()'),
        'end-long-arity':base.replace(b'loan.end(v3)',b'loan.end(v3,v3)'),
        'suspended-bulk-source':base.replace(b'  _ = buffer.fill(v3,v4)',b'  v5:readbuf = borrow.read(v0)\n  v6:usize = const() {"value":0}\n  _ = buffer.copy(v3,v0,v6)\n  _ = loan.end(v5)'),
    }
    # A local loan may legally cross a Core edge but that is outside this profile.
    cross=(HEADER+'  v3:mutbuf = borrow.mut(v1)\n  jump b1(v1,v3)\n'
        'block b1(v4:mutbuf,v5:mutbuf)\n  _ = loan.end(v5)\n  v6:u32 = const() {"value":0}\n  ret(v6)\nend\n').encode()
    rows['local-loan-across-edge']=cross
    call=next(r['source'] for r in loan_cases() if r['id']=='mutable-child-call')
    rows['suspended-parent-call']=call.replace(b'call(v3)',b'call(v1)')
    rows['ended-loan-call']=call.replace(b'  v4:u32 = call',b'  _ = loan.end(v3)\n  v4:u32 = call')
    return rows


def reference_source(case):
    b=Body(0);owners=[];loans=[]
    for initial in (bytes.fromhex(case['source_hex']),bytes.fromhex(case['initial_hex']),b''):
        owner=b.value('buffer','buffer.new',[b.const('usize',len(initial))])
        loan=b.value('mutbuf','borrow.mut',[owner])
        for i,value in enumerate(initial):b.effect('buffer.store',[loan,b.const('usize',i),b.const('u8',value)])
        owners.append(owner);loans.append(loan)
    b.effect('loan.end',[loans[0]]);loans[0]=b.value('readbuf','borrow.read',[owners[0]])
    b.value('u32','call',loans,{'function':'f0'})
    values=[b.value('u8','buffer.load',[loans[1],b.const('usize',i)]) for i in range(8)]
    for loan in loans:b.effect('loan.end',[loan])
    for owner in owners:b.effect('owner.drop',[owner])
    wrapper=('hia-asm.v1 hepta.hia.program.v8 loan_reference\nfn reference_entry() -> ('+','.join(['u8']*8)+
        ') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+b.text()+'  ret('+','.join(values)+')\nend\n')
    return (wrapper+case['source'].decode().split('\n',1)[1]).encode()


def independent_loan_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program,HIAProgramRejected
    rows=[]
    for case in loan_cases():
        result=execute_program(assemble_program(reference_source(case)),'reference_entry',[])
        assert result['status']=='returned',result
        expected=bytes(result['result'])
        rows.append({k:v for k,v in case.items() if k!='source'}|{'expected_hex':expected.hex(),
            'reference_source':reference_source(case).decode(),'reference_result':result})
    refusals=[]
    for name,source in loan_refusals().items():
        try:assemble_program(source)
        except HIAProgramRejected as exc:
            refusals.append({'id':name,'general_core':'rejected','code':exc.code})
        else:
            assert name=='local-loan-across-edge',name
            refusals.append({'id':name,'general_core':'accepted','boundary':'block-local-only'})
    return {'cases':rows,'rejections':refusals}


def qualify_loans(directory,compilers,checks,reference):
    from tools.qualify_hia_selfhost import INVALID,compile_stage,invoke,inspect_selfhost_object
    observations=[];cases={r['id']:r for r in loan_cases()}
    for label,compiler in compilers:
        for row in reference['cases']:
            name=label+'-loan-'+row['id'];source=cases[row['id']]['source']
            artifact,build=compile_stage(directory,name+'-build',compiler,source);observations.append(build)
            result,output=invoke(directory,name,artifact,bytes.fromhex(row['source_hex']),
                capacity=8,workspace_size=0,output_initial=bytes.fromhex(row['initial_hex']))
            checks[name.replace('-','_')]=(result.get('status')=='returned' and result.get('core_u32')==0
                and output.hex()==row['expected_hex'])
            observations.append(result)
            object_source=source.replace(b'v8 selfhost\n',b'v8 selfhost_elf\n',1)
            obj,build=compile_stage(directory,name+'-elf',compiler,object_source,output_extension='.o');observations.append(build)
            checks[name.replace('-','_')+'_flat_elf_text_equal']=inspect_selfhost_object(obj.read_bytes())['text_sha256']==__import__('hashlib').sha256(artifact.read_bytes()).hexdigest()
        for name,source in loan_refusals().items():
            result,output=invoke(directory,label+'-loan-refuse-'+name,compiler,source)
            checks[(label+'_loan_refuse_'+name).replace('-','_')]=(result.get('status')=='returned' and result.get('core_u32')==INVALID
                and result.get('source_unchanged') and result.get('output_unchanged'))
            observations.append(result)
    return observations
