"""Native closed initialization coverage analysis for LLVM allocation choice.

The full original CFG limits, finite origin domain, cycle exclusion, complete
counted-store witnesses and dominance checks remain native HIA decisions.
"""
from tools.generate_hia_program_llvm_common import write_module
from tools.generate_hia_program_llvm_flow import SOURCE as FLOW_SOURCE
from tools.generate_hia_program_llvm_vector import MATCH_SOURCE
from tools.generate_hia_program_llvm_outline import MATCH_SOURCE as OUTLINE_MATCH_SOURCE
SOURCE=r'''
def llvm_analysis(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if meta(w,get(w,FN),80)==1:
        if initialization(s,w)==1:
            setmeta(w,get(w,FN),80,0)
    match_vectors(s,w)
    match_outline(w)
    return 2

def table_name(w:mutbuf,name:u64,node:u64,create:u64) -> u64:
    at=hash_text(w,name)&8191
    n=0
    while n<8192:
        p=INAMES+at*24
        key=get(w,p)
        if key==0:
            if create==0:
                return NONE
            put(w,p,name+1)
            put(w,p+8,node)
            return node
        if text_equal(w,key-1,name)==1:
            return get(w,p+8)
        at=(at+1)&8191
        n=n+1
    return NONE

def representative(w:mutbuf,node:u64) -> u64:
    return table_name(w,field(w,node,K_name),0,0)

def origin_arg(w:mutbuf,op:u64,index:u64) -> u64:
    return table_name(w,nth(w,field(w,op,K_args),index),0,0)

def origin_one(w:mutbuf,node:u64) -> u64:
    if node==NONE or meta(w,node,80)==NONE or meta(w,node,88)!=0:
        return 0
    return meta(w,node,80)

def merge_origin(w:mutbuf,node:u64,a:u64,b:u64) -> u64:
    before=meta(w,node,80)
    second=meta(w,node,88)
    x=before
    y=second
    if x==NONE or a==NONE:
        x=NONE
        y=0
    else:
        if a!=0 and a!=x and a!=y:
            if x==0:
                x=a
            elif y==0:
                y=a
            else:
                x=NONE
                y=0
        if x!=NONE and b!=0 and b!=x and b!=y:
            if x==0:
                x=b
            elif y==0:
                y=b
            else:
                x=NONE
                y=0
        if y!=0 and y<x:
            swap=x
            x=y
            y=swap
    setmeta(w,node,80,x)
    setmeta(w,node,88,y)
    return choose(x!=before or y!=second,1,0)

def numeric(s:readbuf,w:mutbuf,node:u64) -> u64:
    k=kind(w,node)
    if k==0 or k==1:
        return 0
    if k==2:
        return 1
    at=get(w,64+node*56+24)+ARG_HEADER
    n=count(w,node)
    negative=0
    if n>0 and byte(s,at)==45:
        at=at+1
        n=n-1
        negative=1
    value=0
    i=0
    while i<n:
        value=value*10+byte(s,at+i)-48
        i=i+1
    if negative==1:
        value=0-value
    return value

def constant_origin(w:mutbuf,typ:u64,value:u64) -> u64:
    at=((value^(value>>32))*1099511628211+typ)&8191
    i=0
    while i<8192:
        p=ICONSTS+at*24
        key=get(w,p)
        if key==0:
            put(w,p,typ)
            put(w,p+8,value)
            return 4294967296+at+1
        if key==typ and get(w,p+8)==value:
            return 4294967296+at+1
        at=(at+1)&8191
        i=i+1
    return NONE

def graph_word(w:mutbuf,index:u64,part:u64) -> u64:
    return get(w,IGRAPH+index*64+part)

def graph_put(w:mutbuf,index:u64,part:u64,value:u64) -> u64:
    return put(w,IGRAPH+index*64+part,value)

def graph_set(w:mutbuf,index:u64,part:u64,bit:u64) -> u64:
    at=part
    if bit>=64:
        at=part+8
    return graph_put(w,index,at,graph_word(w,index,at)|(1<<(bit&63)))

def graph_has(w:mutbuf,index:u64,part:u64,bit:u64) -> u64:
    at=part
    if bit>=64:
        at=part+8
    return choose((graph_word(w,index,at)&(1<<(bit&63)))!=0,1,0)

def single_predecessor(w:mutbuf,index:u64,expected:u64) -> u64:
    a=0
    b=0
    if expected<64:
        a=1<<expected
    else:
        b=1<<(expected-64)
    return choose(graph_word(w,index,0)==a and graph_word(w,index,8)==b,1,0)

def closed_profile(w:mutbuf) -> u64:
    if get(w,BLOCK_COUNT)>128:
        return 0
    fn=get(w,FN)
    p=first(w,field(w,fn,K_params))
    while p!=NONE:
        t=typecode(w,field(w,p,K_type))
        if t==0 or t>12:
            return 0
        p=next(w,p)
    p=first(w,field(w,fn,K_returns))
    while p!=NONE:
        t=typecode(w,p)
        if t==0 or t>12:
            return 0
        p=next(w,p)
    operations=0
    values=0
    i=0
    while i<get(w,BLOCK_COUNT):
        b=get(w,BLOCKS+i*8)
        term=field(w,field(w,b,K_term),K_op)
        if is_text(w,term,"ret")==0 and is_text(w,term,"jump")==0 and is_text(w,term,"branch")==0 and is_text(w,term,"trap")==0:
            return 0
        values=values+count(w,field(w,b,K_params))
        op=first(w,field(w,b,K_ops))
        while op!=NONE:
            code=opcode(w,field(w,op,K_op))
            allowed=(code>=OP_const and code<=OP_select) or (code>=OP_buffer_new and code<=OP_buffer_len) or (code>=OP_owner_move and code<=OP_owner_drop) or code==OP_buffer_load or code==OP_buffer_store
            if allowed==False:
                return 0
            values=values+count(w,field(w,op,K_out))
            operations=operations+1
            op=next(w,op)
        i=i+1
    return choose(operations<=2048 and values<=4096,1,0)

def register_names(w:mutbuf) -> u64:
    allocations=0
    i=0
    while i<get(w,BLOCK_COUNT):
        block=get(w,BLOCKS+i*8)
        p=first(w,field(w,block,K_params))
        while p!=NONE:
            node=table_name(w,field(w,p,K_name),p,1)
            setmeta(w,node,24,typecode(w,field(w,p,K_type)))
            setmeta(w,node,80,0)
            setmeta(w,node,88,0)
            setmeta(w,node,56,0)
            setmeta(w,node,64,0)
            p=next(w,p)
        op=first(w,field(w,block,K_ops))
        while op!=NONE:
            code=opcode(w,field(w,op,K_op))
            p=first(w,field(w,op,K_out))
            while p!=NONE:
                node=table_name(w,field(w,p,K_name),p,1)
                setmeta(w,node,24,typecode(w,field(w,p,K_type)))
                setmeta(w,node,32,op)
                setmeta(w,node,56,0)
                setmeta(w,node,64,0)
                if (code==OP_buffer_new or code==OP_buffer_try_new) and typecode(w,field(w,p,K_type))==13:
                    setmeta(w,node,16,op)
                    setmeta(w,node,48,i)
                    graph_put(w,i,48,1)
                    allocations=allocations+1
                p=next(w,p)
            op=next(w,op)
        term=field(w,block,K_term)
        j=0
        while j<2:
            edge=each_edge(w,term,j)
            if edge!=NONE:
                target=block_index(w,field(w,edge,K_target))
                graph_set(w,target,0,i)
                graph_set(w,i,16,target)
            j=j+1
        i=i+1
    return allocations

def allocation_acyclic(w:mutbuf) -> u64:
    n=get(w,BLOCK_COUNT)
    k=0
    while k<n:
        i=0
        while i<n:
            if graph_has(w,i,16,k)==1:
                graph_put(w,i,16,graph_word(w,i,16)|graph_word(w,k,16))
                graph_put(w,i,24,graph_word(w,i,24)|graph_word(w,k,24))
            i=i+1
        k=k+1
    i=0
    while i<n:
        if graph_word(w,i,48)==1 and graph_has(w,i,16,i)==1:
            return 0
        i=i+1
    return 1

def enqueue(w:mutbuf,index:u64) -> u64:
    if get(w,IQUEUED+index*8)==0:
        tail=get(w,AUX+8)
        put(w,IQUEUE+(tail&127)*8,index)
        put(w,AUX+8,tail+1)
        put(w,IQUEUED+index*8,1)
    return 0

def definition_flow(s:readbuf,w:mutbuf,op:u64) -> u64:
    code=opcode(w,field(w,op,K_op))
    out=first(w,field(w,op,K_out))
    while out!=NONE:
        node=representative(w,out)
        a=0
        b=0
        if code==OP_const:
            a=constant_origin(w,typecode(w,field(w,out,K_type)),numeric(s,w,field(w,field(w,op,K_attrs),K_value)))
        elif code==OP_borrow_read or code==OP_borrow_mut or code==OP_owner_move:
            source=origin_arg(w,op,0)
            a=meta(w,source,80)
            b=meta(w,source,88)
        elif (code==OP_buffer_new or code==OP_buffer_try_new) and typecode(w,field(w,out,K_type))==13:
            a=8589934592+node+1
        elif code==OP_int_cast and meta(w,origin_arg(w,op,0),24)==typecode(w,field(w,out,K_type)):
            source=origin_arg(w,op,0)
            a=meta(w,source,80)
            b=meta(w,source,88)
        else:
            a=17179869184+node+1
        merge_origin(w,node,a,b)
        out=next(w,out)
    return 0

def edge_flow(w:mutbuf,edge:u64) -> u64:
    index=block_index(w,field(w,edge,K_target))
    block=get(w,BLOCKS+index*8)
    param=first(w,field(w,block,K_params))
    arg=first(w,field(w,edge,K_args))
    changed=0
    while param!=NONE:
        source=table_name(w,arg,0,0)
        changed=changed|merge_origin(w,representative(w,param),meta(w,source,80),meta(w,source,88))
        param=next(w,param)
        arg=next(w,arg)
    if changed==1:
        enqueue(w,index)
    return 0

def origin_flow(s:readbuf,w:mutbuf) -> u64:
    p=first(w,field(w,get(w,FN),K_params))
    while p!=NONE:
        node=representative(w,p)
        setmeta(w,node,80,12884901888+node+1)
        setmeta(w,node,88,0)
        p=next(w,p)
    enqueue(w,get(w,ENTRY_INDEX))
    steps=0
    work=0
    while get(w,AUX)<get(w,AUX+8):
        head=get(w,AUX)
        index=get(w,IQUEUE+(head&127)*8)
        put(w,AUX,head+1)
        put(w,IQUEUED+index*8,0)
        block=get(w,BLOCKS+index*8)
        steps=steps+1
        work=work+1+count(w,field(w,block,K_ops))
        term=field(w,block,K_term)
        j=0
        while j<2:
            edge=each_edge(w,term,j)
            if edge!=NONE:
                work=work+count(w,field(w,edge,K_args))
            j=j+1
        if steps>4096 or work>262144:
            return 0
        op=first(w,field(w,block,K_ops))
        while op!=NONE:
            definition_flow(s,w,op)
            op=next(w,op)
        j=0
        while j<2:
            edge=each_edge(w,term,j)
            if edge!=NONE:
                edge_flow(w,edge)
            j=j+1
    i=0
    while i<get(w,BLOCK_COUNT):
        p=first(w,field(w,get(w,BLOCKS+i*8),K_params))
        while p!=NONE:
            if meta(w,representative(w,p),80)==0:
                return 0
            p=next(w,p)
        i=i+1
    return 1

def dominators(w:mutbuf) -> u64:
    n=get(w,BLOCK_COUNT)
    entry=get(w,ENTRY_INDEX)
    all_a=NONE
    all_b=NONE
    if n<64:
        all_a=(1<<n)-1
        all_b=0
    elif n<128:
        all_b=(1<<(n-64))-1
    i=0
    while i<n:
        if i==entry:
            graph_set(w,i,32,i)
        else:
            graph_put(w,i,32,all_a)
            graph_put(w,i,40,all_b)
        i=i+1
    changed=1
    while changed==1:
        changed=0
        i=0
        while i<n:
            if i!=entry:
                a=all_a
                b=all_b
                predecessors=0
                j=0
                while j<n:
                    if graph_has(w,i,0,j)==1:
                        a=a&graph_word(w,j,32)
                        b=b&graph_word(w,j,40)
                        predecessors=predecessors+1
                    j=j+1
                if predecessors==0:
                    return 0
                if i<64:
                    a=a|(1<<i)
                else:
                    b=b|(1<<(i-64))
                if a!=graph_word(w,i,32) or b!=graph_word(w,i,40):
                    graph_put(w,i,32,a)
                    graph_put(w,i,40,b)
                    changed=1
            i=i+1
    return 1

def param_position(w:mutbuf,block:u64,name:u64) -> u64:
    at=first(w,field(w,block,K_params))
    i=0
    while at!=NONE:
        if text_equal(w,field(w,at,K_name),name)==1:
            return i
        i=i+1
        at=next(w,at)
    return NONE

def value_position(w:mutbuf,array:u64,name:u64) -> u64:
    at=first(w,array)
    i=0
    while at!=NONE:
        if text_equal(w,at,name)==1:
            return i
        i=i+1
        at=next(w,at)
    return NONE

def witness_body(w:mutbuf,header:u64,body:u64,exit_index:u64,index_position:u64,limit_position:u64,index_name:u64,limit_name:u64) -> u64:
    term=field(w,header,K_term)
    then=field(w,term,K_then)
    transported=value_position(w,field(w,then,K_args),index_name)
    if transported==NONE:
        return 0
    body_index=field(w,nth(w,field(w,body,K_params),transported),K_name)
    store_op=NONE
    store_ordinal=0
    i=0
    op=first(w,field(w,body,K_ops))
    while op!=NONE:
        code=opcode(w,field(w,op,K_op))
        if code==OP_buffer_store:
            if store_op!=NONE:
                return 0
            store_op=op
            store_ordinal=i
        elif (code<OP_const or code>OP_select) and code!=OP_borrow_mut and code!=OP_loan_end:
            return 0
        op=next(w,op)
        i=i+1
    if store_op==NONE or text_equal(w,nth(w,field(w,store_op,K_args),1),body_index)==0:
        return 0
    root=origin_one(w,origin_arg(w,store_op,0))
    if root<=8589934592 or root>8589934592+MAX_NODES:
        return 0
    allocation=root-8589934593
    requested=origin_one(w,origin_arg(w,meta(w,allocation,16),0))
    if requested==0 or origin_one(w,table_name(w,limit_name,0,0))!=requested:
        return 0
    back=field(w,body,K_term)
    step_name=nth(w,field(w,back,K_args),index_position)
    step=meta(w,table_name(w,step_name,0,0),32)
    code=opcode(w,field(w,step,K_op))
    if (code!=OP_int_add_checked and code!=OP_int_add_wrap) or count(w,field(w,step,K_out))!=1:
        return 0
    if typecode(w,field(w,first(w,field(w,step,K_out)),K_type))!=10 or text_equal(w,nth(w,field(w,step,K_args),0),body_index)==0:
        return 0
    if origin_one(w,origin_arg(w,step,1))!=constant_origin(w,10,1):
        return 0
    if origin_one(w,table_name(w,nth(w,field(w,back,K_args),limit_position),0,0))!=requested:
        return 0
    found=0
    i=0
    op=first(w,field(w,body,K_ops))
    while op!=NONE:
        if op==step and i>store_ordinal:
            found=1
        i=i+1
        op=next(w,op)
    if found==0:
        return 0
    entries=0
    i=0
    hindex=meta(w,header,48)
    bindex=meta(w,body,48)
    while i<get(w,BLOCK_COUNT):
        if i!=bindex and graph_has(w,hindex,0,i)==1:
            other=field(w,get(w,BLOCKS+i*8),K_term)
            j=0
            while j<2:
                incoming=each_edge(w,other,j)
                if incoming!=NONE and block_index(w,field(w,incoming,K_target))==hindex:
                    if origin_one(w,origin_arg(w,incoming,index_position))!=constant_origin(w,10,0):
                        return 0
                    if origin_one(w,origin_arg(w,incoming,limit_position))!=requested:
                        return 0
                    entries=entries+1
                j=j+1
        i=i+1
    if entries==0:
        return 0
    part=56
    if exit_index>=64:
        part=64
    setmeta(w,allocation,part,meta(w,allocation,part)|(1<<(exit_index&63)))
    return 1

def collect_witness(w:mutbuf,header:u64) -> u64:
    term=field(w,header,K_term)
    if is_text(w,field(w,term,K_op),"branch")==0 or count(w,field(w,header,K_ops))!=1:
        return 0
    compare=first(w,field(w,header,K_ops))
    if opcode(w,field(w,compare,K_op))!=OP_compare_lt or text_equal(w,field(w,first(w,field(w,compare,K_out)),K_name),field(w,term,K_cond))==0:
        return 0
    index_name=nth(w,field(w,compare,K_args),0)
    limit_name=nth(w,field(w,compare,K_args),1)
    ip=param_position(w,header,index_name)
    lp=param_position(w,header,limit_name)
    if ip==NONE or lp==NONE:
        return 0
    if meta(w,table_name(w,index_name,0,0),24)!=10 or meta(w,table_name(w,limit_name,0,0),24)!=10:
        return 0
    bindex=block_index(w,field(w,field(w,term,K_then),K_target))
    eindex=block_index(w,field(w,field(w,term,K_else),K_target))
    hindex=meta(w,header,48)
    if single_predecessor(w,bindex,hindex)==0 or single_predecessor(w,eindex,hindex)==0:
        return 0
    body=get(w,BLOCKS+bindex*8)
    back=field(w,body,K_term)
    if is_text(w,field(w,back,K_op),"jump")==0 or block_index(w,field(w,back,K_target))!=hindex:
        return 0
    return witness_body(w,header,body,eindex,ip,lp,index_name,limit_name)

def reads_covered(w:mutbuf) -> u64:
    i=0
    while i<get(w,BLOCK_COUNT):
        op=first(w,field(w,get(w,BLOCKS+i*8),K_ops))
        while op!=NONE:
            if opcode(w,field(w,op,K_op))==OP_buffer_load:
                token=origin_one(w,origin_arg(w,op,0))
                if token<=8589934592 or token>8589934592+MAX_NODES:
                    return 0
                root=token-8589934593
                if (meta(w,root,56)&graph_word(w,i,32))==0 and (meta(w,root,64)&graph_word(w,i,40))==0:
                    return 0
            op=next(w,op)
        i=i+1
    return 1

def initialization(s:readbuf,w:mutbuf) -> u64:
    if closed_profile(w)==0:
        return 0
    fill_range(w,AUX,526336,0)
    if register_names(w)==0 or allocation_acyclic(w)==0:
        return 0
    if origin_flow(s,w)==0 or dominators(w)==0:
        return 0
    i=0
    while i<get(w,BLOCK_COUNT):
        collect_witness(w,get(w,BLOCKS+i*8))
        i=i+1
    return reads_covered(w)
'''
if __name__=='__main__':
    write_module('program_llvm_analysis',SOURCE+'\n'+FLOW_SOURCE+'\n'+MATCH_SOURCE+'\n'+OUTLINE_MATCH_SOURCE,'llvm_analysis')
