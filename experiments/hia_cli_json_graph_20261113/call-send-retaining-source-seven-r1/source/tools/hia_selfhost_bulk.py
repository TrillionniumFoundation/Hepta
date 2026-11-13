"""Independent byte oracles and native witnesses for five bulk operations.

Core VM wrappers own the buffers; native successors receive live, disjoint
borrowed allocations. These finite cases are not an all-input correctness proof.
"""
from __future__ import annotations
import json
from tools.hia_selfhost_cases import HEADER

OPS = ('buffer.fill','buffer.fill_range','buffer.copy','buffer.copy_range','buffer.move_within')
class Body:
    def __init__(self,first=3): self.next,self.lines=first,[]
    def value(self,typ,op,args=(),attrs=None):
        name='v'+str(self.next);self.next+=1
        self.lines.append(f'  {name}:{typ} = {op}('+','.join(args)+')'+
            (' '+json.dumps(attrs,separators=(',',':')) if attrs is not None else '')+'\n')
        return name
    def const(self,typ,value):return self.value(typ,'const',attrs={'value':value})
    def effect(self,op,args):self.lines.append(f'  _ = {op}('+','.join(args)+')\n')
    def text(self):return ''.join(self.lines)


def bulk_cases():
    rows=[]
    def add(op,values,*,size=8,source_size=8,prior=False):
        rows.append({'id':op.replace('buffer.','')+'-'+str(len(rows)),'opcode':op,
            'values':list(values),'initial_hex':bytes(range(31,31+size)).hex(),
            'source_hex':bytes(range(101,101+source_size)).hex(),'prior_store':prior})
    for value in (0,173,255):add('buffer.fill',(value,))
    add('buffer.fill',(255,),size=0)
    for args in ((0,8,255),(2,4,173),(8,0,0),(0,0,0),(9,0,0),(8,1,0),
                 (2**64-1,0,1),(1,2**64-1,255)):add('buffer.fill_range',args)
    add('buffer.fill_range',(0,0,255),size=0)
    for count in (0,1,4,8,9,2**64-1):add('buffer.copy',(count,))
    add('buffer.copy',(8,),source_size=7);add('buffer.copy',(8,),size=7)
    add('buffer.copy',(0,),size=0,source_size=0)
    for args in ((0,0,8),(2,3,4),(8,8,0),(8,0,0),(0,8,0),(9,0,0),
                 (0,9,0),(7,7,2),(2**64-1,0,0),(0,2**64-1,0),(1,1,2**64-1)):
        add('buffer.copy_range',args)
    add('buffer.copy_range',(0,0,0),size=0,source_size=0)
    add('buffer.copy_range',(0,1,5),source_size=5);add('buffer.copy_range',(1,0,5),size=5)
    for args in ((2,0,6),(0,2,6),(0,0,8),(4,0,4),(0,4,4),(3,3,2),
                 (7,0,1),(0,7,1),(8,8,0),(8,0,0),(0,8,0),(9,0,0),
                 (0,9,0),(7,7,2),(2**64-1,0,0),(0,2**64-1,0),(1,1,2**64-1)):
        add('buffer.move_within',args)
    add('buffer.move_within',(0,0,0),size=0)
    # Earlier writes must remain observable after a later operation traps.
    for op,args in [('buffer.fill_range',(8,1,255)),('buffer.copy',(9,)),
                    ('buffer.copy_range',(7,7,2)),('buffer.move_within',(7,7,2))]:
        add(op,args,prior=True)
    return rows


def oracle(case):
    dest=bytearray.fromhex(case['initial_hex']);src=bytes.fromhex(case['source_hex'])
    if case['prior_store']:dest[0]=99
    op,args,extent=case['opcode'],case['values'],len(dest)
    def fits(offset,count,n):return offset<=n and count<=n-offset
    trap=False
    if op=='buffer.fill':dest[:]=bytes([args[0]])*extent
    elif op=='buffer.fill_range':
        offset,count,value=args;trap=not fits(offset,count,extent)
        if not trap:dest[offset:offset+count]=bytes([value])*count
    elif op=='buffer.copy':
        count,=args;trap=count>extent or count>len(src)
        if not trap:dest[:count]=src[:count]
    elif op=='buffer.copy_range':
        dst,source,count=args;trap=not(fits(dst,count,extent) and fits(source,count,len(src)))
        if not trap:dest[dst:dst+count]=src[source:source+count]
    else:
        dst,source,count=args;trap=not(fits(dst,count,extent) and fits(source,count,extent))
        if not trap:dest[dst:dst+count]=bytes(dest[source:source+count])
    return trap,bytes(dest)


def fixture_source(case):
    b=Body()
    if case['prior_store']:b.effect('buffer.store',['v1',b.const('usize',0),b.const('u8',99)])
    op,values=case['opcode'],case['values']
    types={'buffer.fill':['u8'],'buffer.fill_range':['usize','usize','u8'],
        'buffer.copy':['usize'],'buffer.copy_range':['usize']*3,'buffer.move_within':['usize']*3}[op]
    args=['v1','v0'] if op in ('buffer.copy','buffer.copy_range') else ['v1']
    args += [b.const(typ,value) for typ,value in zip(types,values)]
    b.effect(op,args);result=b.const('u32',0)
    return (HEADER+b.text()+f'  ret({result})\nend\n').encode()


def reference_source(case):
    b=Body(0);owners,loans=[],[]
    for initial in (bytes.fromhex(case['source_hex']),bytes.fromhex(case['initial_hex']),b''):
        owner=b.value('buffer','buffer.new',[b.const('usize',len(initial))])
        loan=b.value('mutbuf','borrow.mut',[owner])
        for i,value in enumerate(initial):b.effect('buffer.store',[loan,b.const('usize',i),b.const('u8',value)])
        owners.append(owner);loans.append(loan)
    b.effect('loan.end',[loans[0]]);loans[0]=b.value('readbuf','borrow.read',[owners[0]])
    b.value('u32','call',loans,{'function':'f0'})
    values=[b.value('u8','buffer.load',[loans[1],b.const('usize',i)]) for i in range(len(bytes.fromhex(case['initial_hex'])))]
    types=['u8']*len(values)
    if not values:values,types=[b.const('u32',0)],['u32']
    for loan in loans:b.effect('loan.end',[loan])
    for owner in owners:b.effect('owner.drop',[owner])
    wrapper=('hia-asm.v1 hepta.hia.program.v8 bulk_reference\nfn reference_entry() -> ('+','.join(types)+
        ') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+b.text()+'  ret('+','.join(values)+')\nend\n')
    return (wrapper+fixture_source(case).decode().split('\n',1)[1]).encode()


def bulk_refusals():
    rows={}
    for op in OPS:
        case=next(c for c in bulk_cases() if c['opcode']==op);src=fixture_source(case)
        statement=next(line for line in src.splitlines() if b'_ = '+op.encode()+b'(' in line)
        args=statement.split(b'(',1)[1].split(b')',1)[0].split(b',')
        def replace(new):return src.replace(statement,new)
        prefix=b'  _ = '+op.encode()+b'('
        rows[op+'-readonly-destination']=replace(prefix+b','.join([b'v0',*args[1:]])+b')')
        rows[op+'-short-arity']=replace(prefix+b','.join(args[:-1])+b')')
        rows[op+'-long-arity']=replace(prefix+b','.join([*args,args[-1]])+b')')
        rows[op+'-unexpected-result']=replace(statement.replace(b'_',b'v99:u32',1))
        rows[op+'-unexpected-attribute']=replace(statement+b' {"value":0}')
        rows[op+'-wrong-scalar']=src.replace(args[-1]+b':'+(b'u8' if op in ('buffer.fill','buffer.fill_range') else b'usize'),args[-1]+b':u32')
        if op in ('buffer.copy','buffer.copy_range'):
            rows[op+'-mutable-source']=replace(prefix+b','.join([args[0],b'v2',*args[2:]])+b')')
            rows[op+'-aliased-source']=replace(prefix+b','.join([args[0],args[0],*args[2:]])+b')')
    return rows


def independent_bulk_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program,HIAProgramRejected
    from hepta.hia_program_runtime import HIAProgramTrap
    cases,rejected=[],[]
    for case in bulk_cases():
        source=reference_source(case);program=assemble_program(source);trap,expected=oracle(case)
        try:result=execute_program(program,'reference_entry',[])
        except HIAProgramTrap as exc:result={'status':'trapped','trap':exc.code}
        if trap:assert result=={'status':'trapped','trap':'bounds'},(case,result)
        else:assert result['status']=='returned' and result['values']==(list(expected) or [0]),(case,result,expected)
        cases.append({**case,'trap':trap,'expected_hex':expected.hex(),'reference_source':source.decode(),'reference_result':result})
    for name,source in bulk_refusals().items():
        try:assemble_program(source)
        except HIAProgramRejected as exc:rejected.append({'id':name,'code':exc.code})
        else:raise AssertionError('independent Core admitted '+name)
    return {'cases':cases,'rejected':rejected,'before_B0':True}


def qualify_bulk(directory,compilers,checks,reference):
    from tools.qualify_hia_selfhost import INVALID,compile_stage,invoke,inspect_selfhost_object,digest
    observations=[]
    for label,compiler in compilers:
        for case in reference['cases']:
            name=label+'-bulk-'+case['id'];source=fixture_source(case)
            image,build=compile_stage(directory,name+'-build',compiler,source)
            initial=bytes.fromhex(case['initial_hex'])
            result,actual=invoke(directory,name,image,bytes.fromhex(case['source_hex']),capacity=len(initial),
                workspace_size=0,output_initial=initial,observe_trap_writes=True)
            good=(result.get('status')=='child_failed' and result.get('returncode')==-4) if case['trap'] else (
                result.get('status')=='returned' and result.get('core_u32')==0 and result.get('abi_status')==0
                and result.get('source_unchanged') is True and not result.get('forbidden_compiler_modules_loaded'))
            checks[name]=bool(good and result.get('shared_output_observation',{}).get('available') and actual.hex()==case['expected_hex'])
            observations.append({'compiler':label,'id':case['id'],'build':build,'execution':result,
                'expected_hex':case['expected_hex'],'actual_hex':actual.hex()})
        for name,source in bulk_refusals().items():
            result,actual=invoke(directory,label+'-bulk-reject-'+name,compiler,source,capacity=512)
            checks[label+'-bulk-reject-'+name]=bool(result.get('status')=='returned' and result.get('core_u32')==INVALID
                and result.get('source_unchanged') and result.get('output_unchanged') and actual==bytes([0xa5])*512)
            observations.append(result)
        for op in OPS:
            case=next(c for c in reference['cases'] if c['opcode']==op);source=fixture_source(case)
            name=label+'-bulk-object-'+op
            flat,flat_receipt=compile_stage(directory,name+'-flat',compiler,source)
            obj,obj_receipt=compile_stage(directory,name+'-elf',compiler,
                source.replace(b'v8 selfhost\n',b'v8 selfhost_elf\n',1),output_extension='.o')
            inspected=inspect_selfhost_object(obj.read_bytes())
            checks[name]=inspected['text_sha256']==digest(flat.read_bytes())
            observations.append({'flat':flat_receipt,'object':obj_receipt,'inspection':inspected})
    return observations
