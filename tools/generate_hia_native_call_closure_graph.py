"""Native HIA direct-call closure, exact profile, order and graph framing.

The input is the exact independently admitted primitive Core JSON. This pure
role never accepts a summary or proof bit. It emits original operation graphs
and a bounded table of callee fixups for the native summary owner.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import document
from tools.generate_hia_cold_sha_alias import Builder
from tools.generate_hia_core_inspect_json import source_program
from tools.generate_hia_core_proof_wire import match
from tools import generate_hia_multiversion_proof_graph as primitive
ROOT=Path(__file__).resolve().parents[1]
ENTRY=r'''
def native_call_closure_graph(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)>8388608 or length(o)<26752 or length(w)<33554432:
        return 4294967292
    selected=get(o,0)
    named=selected==18446744073709551614
    name_size=0
    if named:
        name_size=get(o,8)
        if name_size==0 or name_size>128 or name_size>length(o)-16:
            return 4294967292
        i=0
        while i<name_size:
            store(w,length(w)-name_size+i,byte(o,16+i))
            i=i+1
    put(o,48,262144)
    put(o,56,64)
    end=widen(decode_json(s,w,o))
    if end>=4294967292:
        return end
    if end>length(w)-65536-2106400:
        return profile_refused(w,10)
    fill_range(w,length(w)-65536,8192,0)
    mput(w,120,end)
    if proof_schema(w,field(w,0,K_schema))==0:
        return profile_refused(w,1)
    functions=field(w,0,K_functions)
    total=count(w,functions)
    if named:
        selected=total
        index=0
        fn=child(w,functions)
        while fn!=NONE:
            if requested_name(w,field(w,fn,K_name),name_size)!=0:
                selected=index
            index=index+1
            fn=next_node(w,fn)
    if selected==NONE:
        if total!=1:
            return profile_refused(w,2)
        selected=0
    if selected>=total:
        return profile_refused(w,2)
    fn=child(w,functions)
    index=0
    while index<selected:
        fn=next_node(w,fn)
        index=index+1
    if public_function(w,fn)==0:
        return profile_refused(w,3)
    reason=enter_function(w,fn,selected)
    if reason!=0:
        return profile_refused(w,reason)
    mput(w,40,0)
    mput(w,32,1)
    mput(w,4608,0)
    while mget(w,32)!=0:
        depth=mget(w,32)-1
        current=mget(w,4608+8*depth)
        row=closure_record(w,current)
        callee=next_callee(w,get(w,row),get(w,row+24))
        if callee==NONE:
            post=mget(w,8)
            put(w,row+16,2)
            put(w,row+40,post)
            mput(w,4096+8*post,current)
            mput(w,8,post+1)
            mput(w,32,depth)
        else:
            put(w,row+24,callee)
            target=find_function(w,callee)
            if target==NONE:
                return profile_refused(w,70)
            old=find_record(w,target)
            if old<mget(w,0):
                if get(w,closure_record(w,old)+16)==1:
                    return profile_refused(w,64)
            else:
                index=function_index(w,target)
                reason=enter_function(w,target,index)
                if reason!=0:
                    return profile_refused(w,reason)
                if depth+1>=16:
                    return profile_refused(w,65)
                mput(w,4608+8*(depth+1),old)
                mput(w,32,depth+2)
    fill_range(o,0,26752,0)
    put(o,0,3544416758515452232)
    put(o,8,mget(w,8))
    put(o,16,get(w,closure_record(w,0)+40))
    put(o,24,mget(w,16))
    put(o,32,mget(w,24))
    put(o,48,selected)
    put(o,64,26752)
    mput(w,48,26752)
    mput(w,80,0)
    index=0
    while index<mget(w,8):
        current=mget(w,4096+8*index)
        mput(w,56,current)
        if emit_closure_function(s,o,w,index)==0:
            return profile_refused(w,10)
        index=index+1
    put(o,40,get(w,closure_record(w,0)+48))
    put(o,56,mget(w,48))
    put(o,72,mget(w,80))
    return mget(w,48)

def mget(w:mutbuf,offset:u64) -> u64:
    return get(w,length(w)-65536+offset)

def mput(w:mutbuf,offset:u64,value:u64) -> u64:
    put(w,length(w)-65536+offset,value)
    return 0

def closure_record(w:mutbuf,index:u64) -> u64:
    return length(w)-65536+128+128*index

def call_name(w:mutbuf,node:u64) -> u64:
    item=child(w,field(w,node,K_attrs))
    while item!=NONE:
        row=64+item*56
        if get(w,row+48)==8 and get(w,get(w,row+40))==7957695015192261990:
            return item
        item=next_node(w,item)
    return NONE

def next_callee(w:mutbuf,fn:u64,previous:u64) -> u64:
    answer=NONE
    block=child(w,field(w,fn,K_blocks))
    while block!=NONE:
        op=child(w,field(w,block,K_ops))
        while op!=NONE:
            if proof_call(w,field(w,op,K_op))!=0:
                name=call_name(w,op)
                later=previous==NONE or name_before(w,previous,name)!=0
                if later and (answer==NONE or name_before(w,name,answer)!=0):
                    answer=name
            op=next_node(w,op)
        block=next_node(w,block)
    return answer

def find_function(w:mutbuf,name:u64) -> u64:
    fn=child(w,field(w,0,K_functions))
    while fn!=NONE:
        if same_name(w,name,field(w,fn,K_name)):
            return fn
        fn=next_node(w,fn)
    return NONE

def function_index(w:mutbuf,fn:u64) -> u64:
    item=child(w,field(w,0,K_functions))
    index=0
    while item!=NONE:
        if item==fn:
            return index
        item=next_node(w,item)
        index=index+1
    return NONE

def find_record(w:mutbuf,fn:u64) -> u64:
    index=0
    while index<mget(w,0):
        if get(w,closure_record(w,index))==fn:
            return index
        index=index+1
    return index

def enter_function(w:mutbuf,fn:u64,index:u64) -> u64:
    total=mget(w,0)
    if total>=16:
        return 65
    if count(w,field(w,fn,K_returns))>16:
        return 66
    blocks=count(w,field(w,fn,K_blocks))
    operations=0
    block=child(w,field(w,fn,K_blocks))
    while block!=NONE:
        operations=operations+count(w,field(w,block,K_ops))
        block=next_node(w,block)
    if blocks>32-mget(w,16) or operations>512-mget(w,24):
        return 67
    mput(w,16,mget(w,16)+blocks)
    mput(w,24,mget(w,24)+operations)
    reason=profile_reason(w,fn)
    if reason!=0:
        return reason
    if setup_call_blocks(w,fn)==0:
        return 9
    row=closure_record(w,total)
    put(w,row,fn)
    put(w,row+8,field(w,fn,K_name))
    put(w,row+16,1)
    put(w,row+24,NONE)
    put(w,row+32,index)
    put(w,row+56,blocks)
    put(w,row+64,operations)
    mput(w,0,total+1)
    return 0

def setup_call_blocks(w:mutbuf,fn:u64) -> u64:
    end=mget(w,120)
    put(w,8,end)
    put(w,16,0)
    put(w,24,end+9216)
    put(w,32,end+9216+2097152)
    blocks=field(w,fn,K_blocks)
    n=count(w,blocks)
    i=0
    block=child(w,blocks)
    while block!=NONE:
        row=end+64*i
        put(w,row,block)
        put(w,row+8,field(w,block,K_id))
        put(w,row+16,n)
        put(w,row+24,n)
        put(w,row+32,n)
        put(w,row+48,0)
        put(w,row+56,0)
        block=next_node(w,block)
        i=i+1
    entry=block_slot(w,n,field(w,fn,K_entry))
    if entry>=n or graph_order(w,n,entry)==0:
        return 0
    put(w,end+64*entry+56,1)
    mput(w,112,entry)
    return 1

def profile_reason(w:mutbuf,fn:u64) -> u64:
    blocks=field(w,fn,K_blocks)
    operations=0
    block=child(w,blocks)
    while block!=NONE:
        op=child(w,field(w,block,K_ops))
        while op!=NONE:
            amount=1
            if proof_call(w,field(w,op,K_op))!=0:
                amount=count(w,field(w,op,K_out))
            operations=operations+amount
            op=next_node(w,op)
        block=next_node(w,block)
    if count(w,blocks)>128 or operations>2048:
        return 4
    if count(w,field(w,fn,K_params))>32 or count(w,field(w,fn,K_returns))>16:
        return 5
    if function_effects(w,fn)==0:
        return 6
    if scalar_records(w,field(w,fn,K_params))==0 or scalar_returns(w,field(w,fn,K_returns))==0:
        return 7
    block=child(w,blocks)
    while block!=NONE:
        if scalar_records(w,field(w,block,K_params))==0:
            return 7
        op=child(w,field(w,block,K_ops))
        while op!=NONE:
            if scalar_records(w,field(w,op,K_out))==0:
                return 7
            op=next_node(w,op)
        block=next_node(w,block)
    block=child(w,blocks)
    while block!=NONE:
        op=child(w,field(w,block,K_ops))
        while op!=NONE:
            opname=field(w,op,K_op)
            if proof_call(w,opname)==0 and proof_op(w,opname)==0:
                return 8
            op=next_node(w,op)
        block=next_node(w,block)
    return 0

def operation_rows(w:mutbuf,op:u64) -> u64:
    if proof_call(w,field(w,op,K_op))==0:
        return 1
    results=count(w,field(w,op,K_out))
    return choose(results==0,1,results)

def measure_call_function(w:mutbuf,fn:u64) -> u64:
    size=24
    args=0
    block=child(w,field(w,fn,K_blocks))
    while block!=NONE:
        term=field(w,block,K_term)
        kind=proof_term(w,field(w,term,K_op))
        exits=0
        if kind==1:
            exits=count(w,field(w,term,K_values))
        elif kind==3:
            exits=count(w,field(w,term,K_args))
        elif kind==4:
            exits=count(w,field(w,field(w,term,K_then),K_args))+count(w,field(w,field(w,term,K_else),K_args))
        rows=0
        op=child(w,field(w,block,K_ops))
        while op!=NONE:
            rows=rows+operation_rows(w,op)
            if proof_call(w,field(w,op,K_op))!=0:
                args=args+8*count(w,field(w,op,K_args))
            op=next_node(w,op)
        size=size+64+8*(count(w,field(w,block,K_params))+exits)+48*rows
        block=next_node(w,block)
    mput(w,104,args)
    return size

def closure_cost(w:mutbuf,fn:u64) -> u64:
    n=count(w,field(w,fn,K_blocks))
    table=get(w,8)
    cost=1
    i=0
    while i<n:
        source=get(w,table+64*i+40)
        row=table+64*source
        if get(w,row+56)!=0:
            op=child(w,field(w,get(w,row),K_ops))
            while op!=NONE:
                if proof_call(w,field(w,op,K_op))!=0:
                    target=find_record(w,find_function(w,call_name(w,op)))
                    if target>=mget(w,0):
                        return 0
                    amount=get(w,closure_record(w,target)+48)
                    cost=choose(cost+amount>32,33,cost+amount)
                op=next_node(w,op)
            first=get(w,row+16)
            second=get(w,row+24)
            if first<n:
                put(w,table+64*first+56,1)
            if second<n:
                put(w,table+64*second+56,1)
        i=i+1
    return cost

def emit_closure_function(s:readbuf,o:mutbuf,w:mutbuf,index:u64) -> u64:
    source=closure_record(w,mget(w,56))
    fn=get(w,source)
    if setup_call_blocks(w,fn)==0:
        return 0
    cost=closure_cost(w,fn)
    if cost==0:
        return 0
    put(w,source+48,cost)
    params=field(w,fn,K_params)
    returns=field(w,fn,K_returns)
    inputs=count(w,params)
    outputs=count(w,returns)
    body=measure_call_function(w,fn)
    base=mget(w,48)
    tail=40+8*(inputs+outputs)+body
    extra=mget(w,104)
    if base>length(o) or tail>length(o)-base or extra>length(o)-base-tail:
        return 0
    mput(w,64,base)
    mput(w,72,base+tail)
    mput(w,88,base+tail)
    mput(w,96,mget(w,80))
    put(o,base,3616478832187492680)
    put(o,base+8,3)
    put(o,base+16,inputs)
    put(o,base+24,outputs)
    put(o,base+32,tail)
    record=128+640*index
    put(o,record,get(w,source+32))
    put(o,record+8,base)
    put(o,record+24,tail)
    put(o,record+32,mget(w,80))
    put(o,record+48,inputs)
    put(o,record+56,outputs)
    put(o,record+72,inputs+outputs)
    put(o,record+80,cost)
    put(o,record+88,get(w,source+56))
    put(o,record+96,get(w,source+64))
    at=base+40
    sig=record+256
    node=child(w,params)
    while node!=NONE:
        typ=field(w,node,K_type)
        put(o,at,proof_type(w,typ))
        put(o,sig,proof_identity_type(w,typ))
        at=at+8
        sig=sig+8
        node=next_node(w,node)
    node=child(w,returns)
    while node!=NONE:
        put(o,at,proof_type(w,node))
        put(o,sig,proof_identity_type(w,node))
        at=at+8
        sig=sig+8
        node=next_node(w,node)
    name=get(w,source+8)
    name_at=get(w,64+56*name+24)
    name_n=get(w,64+56*name+32)
    if name_n==0 or name_n>128:
        return 0
    put(o,record+64,name_n)
    i=0
    while i<name_n:
        store(o,record+128+i,byte(w,name_at+i))
        i=i+1
    n=count(w,field(w,fn,K_blocks))
    start=at
    put(o,start,body)
    put(o,start+8,n)
    put(o,start+16,get(w,get(w,8)+64*mget(w,112)+32))
    put(w,0,start+24)
    i=0
    while i<n:
        bi=get(w,get(w,8)+64*i+40)
        block=get(w,get(w,8)+64*bi)
        if write_call_block(s,o,w,n,block)==0:
            return 0
        i=i+1
    if get(w,0)!=base+tail or mget(w,88)!=base+tail+extra:
        return 0
    put(o,record+16,tail+extra)
    put(o,record+40,mget(w,80)-mget(w,96))
    mput(w,48,base+tail+extra)
    return 1

def write_call_block(s:readbuf,o:mutbuf,w:mutbuf,n:u64,block:u64) -> u64:
    term=field(w,block,K_term)
    role=proof_term(w,field(w,term,K_op))
    params=field(w,block,K_params)
    ops=field(w,block,K_ops)
    nparams=count(w,params)
    rows=0
    slots=nparams
    op=child(w,ops)
    while op!=NONE:
        rows=rows+operation_rows(w,op)
        slots=slots+count(w,field(w,op,K_out))
        op=next_node(w,op)
    if slots>262144:
        return 0
    slots_begin(w,slots)
    block_edges(w,n,term,role)
    cursor=get(w,0)
    if block_header(o,w,cursor,role,nparams,rows)==0:
        return 0
    at=write_call_values(s,o,w,cursor+64,params,ops)
    if at==0:
        return 0
    return finish_block(o,w,cursor,role,at,slots,term)

def write_call_values(s:readbuf,o:mutbuf,w:mutbuf,at:u64,params:u64,ops:u64) -> u64:
    slot=0
    param=child(w,params)
    while param!=NONE:
        typ=proof_type(w,field(w,param,K_type))
        if typ==0 or slot_define(w,field(w,param,K_name),slot)==0:
            return 0
        put(o,at,typ)
        at=at+8
        slot=slot+1
        param=next_node(w,param)
    op=child(w,ops)
    while op!=NONE:
        if proof_call(w,field(w,op,K_op))!=0:
            rows=write_direct_call(o,w,at,op,slot)
            if rows==0:
                return 0
            at=at+48*rows
            slot=slot+count(w,field(w,op,K_out))
        else:
            if write_operation(s,o,w,at,op,slot)==0:
                return 0
            at=at+48
            slot=slot+1
        op=next_node(w,op)
    return at

def write_direct_call(o:mutbuf,w:mutbuf,at:u64,op:u64,slots:u64) -> u64:
    target=find_record(w,find_function(w,call_name(w,op)))
    if target>=mget(w,0):
        return 0
    source=closure_record(w,mget(w,56))
    callee=closure_record(w,target)
    current=get(w,source+40)
    callee_index=get(w,callee+40)
    if callee_index>=current:
        return 0
    args=field(w,op,K_args)
    outs=field(w,op,K_out)
    argc=count(w,args)
    returns=count(w,outs)
    rows=choose(returns==0,1,returns)
    if argc>32 or returns>16 or mget(w,80)>=512:
        return 0
    arg_at=mget(w,88)
    if arg_at>length(o) or 8*argc>length(o)-arg_at:
        return 0
    if capture_slots(o,w,arg_at,args,slots)!=arg_at+8*argc:
        return 0
    mput(w,88,arg_at+8*argc)
    fill_range(o,at,48*rows,0)
    put(o,at,40)
    put(o,at+24,arg_at-mget(w,64))
    put(o,at+32,argc)
    put(o,at+40,choose(returns==1,0,returns))
    fix=10368+32*mget(w,80)
    put(o,fix,current)
    put(o,fix+8,at-mget(w,64))
    put(o,fix+16,callee_index)
    mput(w,80,mget(w,80)+1)
    item=child(w,outs)
    index=0
    while item!=NONE:
        typ=proof_type(w,field(w,item,K_type))
        if typ==0 or slot_define(w,field(w,item,K_name),slots+index)==0:
            return 0
        if index!=0:
            put(o,at+48*index,41)
        put(o,at+48*index+8,typ)
        index=index+1
        item=next_node(w,item)
    return rows
'''
def policy_source():
    original=primitive.policy()
    nodes={n.name:n for n in ast.parse(original).body if isinstance(n,ast.FunctionDef)}
    additions=ast.parse(ENTRY).body
    replaced={n.name for n in additions}
    retained=[n for n in nodes.values() if n.name not in replaced and n.name!='multiversion_proof_graph']
    source=ast.unparse(ast.Module(body=additions+retained,type_ignores=[]))+'\n'+match('call',{'call':1})
    return source
def program():
    nodes=ast.parse(source_program(entry=policy_source())).body
    retained={'native_call_closure_graph'}
    while True:
        called={x.func.id for n in nodes if n.name in retained for x in ast.walk(n) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name)}
        if called<=retained:break
        retained.update(called)
    source=ast.unparse(ast.Module(body=[n for n in nodes if n.name in retained],type_ignores=[]))
    return document(source,'native_call_closure_graph',builder_type=Builder)
if __name__=='__main__':
    tree=program();p=ROOT/'examples/hia_bootstrap/native_call_closure_graph.hepta';p.write_text(render_assembly(tree))
    print(p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),flush=True)
