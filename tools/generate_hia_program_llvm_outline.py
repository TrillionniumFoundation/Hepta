"""Native guarded entry partition and exact LLVM dispatch layout."""
from tools.generate_hia_program_llvm_common import write_module
from tools.generate_hia_program_llvm_flow import SOURCE as FLOW_SOURCE

MATCH_SOURCE=r'''
def outline_types(w:mutbuf,fn:u64,entry:u64) -> u64:
    p=first(w,field(w,fn,K_params))
    q=first(w,field(w,entry,K_params))
    if count(w,field(w,fn,K_params))!=count(w,field(w,entry,K_params)):
        return 0
    while p!=NONE:
        typ=typecode(w,field(w,p,K_type))
        if typ==0 or typ>10 or typ!=typecode(w,field(w,q,K_type)) or text_equal(w,field(w,p,K_name),field(w,q,K_name))==0:
            return 0
        p=next(w,p)
        q=next(w,q)
    returns=field(w,fn,K_returns)
    if count(w,returns)!=1:
        return 0
    typ=typecode(w,first(w,returns))
    return choose(typ>=1 and typ<=10,1,0)

def outline_transport(w:mutbuf,edge:u64,params:u64) -> u64:
    if count(w,field(w,edge,K_args))!=count(w,params):
        return 0
    p=first(w,params)
    arg=first(w,field(w,edge,K_args))
    while p!=NONE:
        if text_equal(w,field(w,p,K_name),arg)==0:
            return 0
        p=next(w,p)
        arg=next(w,arg)
    return 1

def outline_component(w:mutbuf,root:u64,entry:u64,mark:u64) -> u64:
    if root==entry:
        return 0
    params=field(w,get(w,FN),K_params)
    target=field(w,get(w,BLOCKS+root*8),K_params)
    if count(w,params)!=count(w,target):
        return 0
    p=first(w,params)
    q=first(w,target)
    while p!=NONE:
        if typecode(w,field(w,p,K_type))!=typecode(w,field(w,q,K_type)):
            return 0
        p=next(w,p)
        q=next(w,q)
    head=0
    tail=1
    queue=AUX+6291456
    put(w,queue,root)
    setmeta(w,get(w,BLOCKS+root*8),112,meta(w,get(w,BLOCKS+root*8),112)|mark)
    while head<tail:
        index=get(w,queue+head*8)
        head=head+1
        term=field(w,get(w,BLOCKS+index*8),K_term)
        j=0
        while j<2:
            edge=each_edge(w,term,j)
            if edge!=NONE:
                successor=block_index(w,field(w,edge,K_target))
                if successor==root or successor==entry:
                    return 0
                node=get(w,BLOCKS+successor*8)
                if (meta(w,node,112)&mark)==0:
                    setmeta(w,node,112,meta(w,node,112)|mark)
                    put(w,queue+tail*8,successor)
                    tail=tail+1
            j=j+1
    return tail

def outline_shape(w:mutbuf,fn:u64,entry:u64) -> u64:
    if outline_types(w,fn,entry)==0 or count(w,field(w,entry,K_ops))!=2:
        return 0
    constant=first(w,field(w,entry,K_ops))
    comparison=next(w,constant)
    value=field(w,field(w,constant,K_attrs),K_value)
    if opcode(w,field(w,constant,K_op))!=OP_const or count(w,field(w,constant,K_args))!=0 or count(w,field(w,constant,K_out))!=1 or typecode(w,field(w,first(w,field(w,constant,K_out)),K_type))!=10 or count(w,field(w,constant,K_attrs))!=1 or kind(w,value)!=3:
        return 0
    if opcode(w,field(w,comparison,K_op))!=OP_compare_le or count(w,field(w,comparison,K_args))!=2 or count(w,field(w,comparison,K_out))!=1 or typecode(w,field(w,first(w,field(w,comparison,K_out)),K_type))!=11 or count(w,field(w,comparison,K_attrs))!=0:
        return 0
    limit=field(w,first(w,field(w,constant,K_out)),K_name)
    if text_equal(w,nth(w,field(w,comparison,K_args),1),limit)==0:
        return 0
    argument=nth(w,field(w,comparison,K_args),0)
    params=field(w,fn,K_params)
    p=first(w,params)
    position=0
    found=0
    selected=0
    while p!=NONE:
        if typecode(w,field(w,p,K_type))==10 and text_equal(w,field(w,p,K_name),argument)==1:
            found=found+1
            selected=position
        p=next(w,p)
        position=position+1
    if found!=1:
        return 0
    term=field(w,entry,K_term)
    if is_text(w,field(w,term,K_op),"branch")==0 or text_equal(w,field(w,term,K_cond),field(w,first(w,field(w,comparison,K_out)),K_name))==0:
        return 0
    if outline_transport(w,field(w,term,K_then),params)==0 or outline_transport(w,field(w,term,K_else),params)==0:
        return 0
    left=block_index(w,field(w,field(w,term,K_then),K_target))
    right=block_index(w,field(w,field(w,term,K_else),K_target))
    a=outline_component(w,left,get(w,ENTRY_INDEX),1)
    b=outline_component(w,right,get(w,ENTRY_INDEX),2)
    if a==0 or b==0:
        return 0
    i=0
    while i<get(w,BLOCK_COUNT):
        mark=meta(w,get(w,BLOCKS+i*8),112)
        if i!=get(w,ENTRY_INDEX) and mark!=1 and mark!=2:
            return 0
        i=i+1
    setmeta(w,fn,0,1)
    setmeta(w,fn,8,get(w,BLOCKS+left*8))
    setmeta(w,fn,16,get(w,BLOCKS+right*8))
    setmeta(w,fn,24,selected)
    setmeta(w,fn,32,value)
    setmeta(w,fn,40,get(w,HELPER_NEXT))
    setmeta(w,fn,48,a)
    setmeta(w,fn,56,b)
    put(w,HELPER_NEXT,get(w,HELPER_NEXT)+2)
    put(w,OUTLINED,get(w,OUTLINED)+1)
    return 1

def match_outline(w:mutbuf) -> u64:
    fn=get(w,FN)
    setmeta(w,fn,0,0)
    if get(w,LAYOUT)==0:
        return 0
    i=0
    while i<get(w,BLOCK_COUNT):
        setmeta(w,get(w,BLOCKS+i*8),112,0)
        i=i+1
    return outline_shape(w,fn,get(w,BLOCKS+get(w,ENTRY_INDEX)*8))
'''

SOURCE=r'''
def llvm_outline(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    outline_dispatch(s,w)
    return 2

def entry_arguments(w:mutbuf,zero:u64) -> u64:
    fn=get(w,FN)
    p=first(w,field(w,fn,K_params))
    i=0
    while p!=NONE:
        if i>0:
            emit(w,", ")
        emit_type(w,typecode(w,field(w,p,K_type)))
        if zero==1 and i==meta(w,fn,24):
            emit(w," 0")
        else:
            emit(w," %entry_")
            emit_number(w,i)
        p=next(w,p)
        i=i+1
    return 0

def entry_result_name(w:mutbuf,which:u64) -> u64:
    if which==0:
        emit(w,"%zero_result")
    elif which==1:
        emit(w,"%fast_result")
    else:
        emit(w,"%slow_result")
    return 0

def entry_call(w:mutbuf,which:u64) -> u64:
    fn=get(w,FN)
    emit(w,"  ")
    entry_result_name(w,which)
    emit(w," = ")
    if which!=0:
        emit(w,"tail ")
    emit(w,"call ")
    return_type(w,field(w,fn,K_returns))
    emit(w," @__hia_fn_")
    helper=meta(w,fn,40)
    if which==2:
        helper=helper+1
    emit_number(w,helper)
    emit(w,"(")
    entry_arguments(w,choose(which==0,1,0))
    if which==0:
        emit(w,") alwaysinline\n")
    else:
        emit(w,") noinline\n")
    emit(w,"  ret ")
    return_type(w,field(w,fn,K_returns))
    emit(w," ")
    entry_result_name(w,which)
    end_line(w)
    return 0

def outline_dispatch(s:readbuf,w:mutbuf) -> u64:
    fn=get(w,FN)
    emit(w,"define internal ")
    return_type(w,field(w,fn,K_returns))
    emit(w," @__hia_fn_")
    emit_number(w,get(w,FN_INDEX))
    emit(w,"(")
    entry_arguments(w,0)
    emit(w,") {\nentry:\n  %empty = icmp eq i64 %entry_")
    emit_number(w,meta(w,fn,24))
    emit(w,", 0\n  br i1 %empty, label %zero, label %guard, !prof !0\nzero:\n")
    entry_call(w,0)
    emit(w,"guard:\n  %eligible = icmp ule i64 %entry_")
    emit_number(w,meta(w,fn,24))
    emit(w,", ")
    node=meta(w,fn,32)
    start=get(w,64+node*56+24)+ARG_HEADER
    n=count(w,node)
    i=0
    while i<n:
        append(w,byte(s,start+i))
        i=i+1
    emit(w,"\n  br i1 %eligible, label %fast, label %fallback\nfast:\n")
    entry_call(w,1)
    emit(w,"fallback:\n")
    entry_call(w,2)
    emit(w,"}")
    return 0
'''
if __name__=='__main__':
    write_module('program_llvm_outline',SOURCE,'llvm_outline')
