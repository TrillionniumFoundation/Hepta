"""HIA LLVM control flow, edge transport and parameter phi emission."""
from tools.generate_hia_program_llvm_common import write_module

SOURCE=r'''
def llvm_flow(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,ROOT_RESULT)==1:
        render_function(s,w)
    elif get(w,ROOT_RESULT)==2:
        render_wrapper(s,w)
    else:
        terminal(s,w,get(w,INS))
    return 2

def edge(w:mutbuf,node:u64) -> u64:
    index=get(w,EDGE_COUNT)
    put(w,EDGE_COUNT,index+1)
    target=block_index(w,field(w,node,K_target))
    setmeta(w,node,96,index)
    setmeta(w,node,104,target)
    a=first(w,field(w,node,K_args))
    while a!=NONE:
        setmeta(w,a,112,symbol(w,a,0,0))
        a=next(w,a)
    return index

def edge_text(w:mutbuf,index:u64) -> u64:
    emit(w,"%edge_")
    emit_number(w,index)
    return 0

def terminal(s:readbuf,w:mutbuf,term:u64) -> u64:
    op=field(w,term,K_op)
    if is_text(w,op,"jump")==1:
        index=edge(w,term)
        emit(w,"  br label ")
        edge_text(w,index)
        end_line(w)
    elif is_text(w,op,"branch")==1:
        yes=edge(w,field(w,term,K_then))
        no=edge(w,field(w,term,K_else))
        condition=symbol(w,field(w,term,K_cond),0,0)
        emit(w,"  br i1 ")
        reference(s,w,condition)
        emit(w,", label ")
        edge_text(w,yes)
        emit(w,", label ")
        edge_text(w,no)
        end_line(w)
    elif is_text(w,op,"trap")==1:
        emit(w,"  call void @abort()\n  unreachable\n")
    elif is_text(w,op,"ret")==1:
        returns=field(w,get(w,FN),K_returns)
        n=count(w,returns)
        values=field(w,term,K_values)
        if n==0:
            emit(w,"  ret void\n")
        elif n==1:
            emit(w,"  ret ")
            typed_reference(s,w,symbol(w,first(w,values),0,0))
            end_line(w)
        else:
            combined=0
            i=0
            while i<n:
                value=instruction_start(s,w)
                emit(w,"insertvalue ")
                return_type(w,returns)
                emit(w," ")
                if i==0:
                    emit(w,"zeroinitializer")
                else:
                    reference(s,w,combined)
                emit(w,", ")
                typed_reference(s,w,symbol(w,nth(w,values,i),0,0))
                emit(w,", ")
                emit_number(w,i)
                end_line(w)
                combined=value
                i=i+1
            emit(w,"  ret ")
            return_type(w,returns)
            emit(w," ")
            reference(s,w,combined)
            end_line(w)
    else:
        fail(w,4294967291)
    return 0

def ordered_block(w:mutbuf,index:u64,entry:u64) -> u64:
    if index==0:
        return get(w,BLOCKS+entry*8)
    original=index-1
    if original>=entry:
        original=original+1
    return get(w,BLOCKS+original*8)

def each_edge(w:mutbuf,term:u64,index:u64) -> u64:
    op=field(w,term,K_op)
    if is_text(w,op,"jump")==1:
        if index==0:
            return term
    elif is_text(w,op,"branch")==1:
        if index==0:
            return field(w,term,K_then)
        if index==1:
            return field(w,term,K_else)
    return NONE

def render_phi(s:readbuf,w:mutbuf,bindex:u64,parameter:u64,ordinal:u64,entry:u64) -> u64:
    emit(w,"  ")
    reference(s,w,parameter)
    emit(w," = phi ")
    emit_type(w,meta(w,parameter,24))
    emit(w," ")
    n=0
    i=0
    while i<get(w,BLOCK_COUNT):
        block=ordered_block(w,i,entry)
        term=field(w,block,K_term)
        j=0
        while j<2:
            incoming=each_edge(w,term,j)
            if incoming!=NONE and meta(w,incoming,104)==bindex:
                if n>0:
                    emit(w,", ")
                value=nth(w,field(w,incoming,K_args),ordinal)
                emit(w,"[ ")
                reference(s,w,meta(w,value,112))
                emit(w,", ")
                edge_text(w,meta(w,incoming,96))
                emit(w," ]")
                n=n+1
            j=j+1
        i=i+1
    if n==0:
        return fail(w,4294967291)
    return end_line(w)

def render_function(s:readbuf,w:mutbuf) -> u64:
    fn=get(w,FN)
    entry=get(w,ENTRY_INDEX)
    block=get(w,BLOCKS+entry*8)
    emit(w,"define internal ")
    return_type(w,field(w,fn,K_returns))
    emit(w," @__hia_fn_")
    emit_number(w,get(w,FN_INDEX))
    emit(w,"(")
    param=first(w,field(w,block,K_params))
    n=0
    while param!=NONE:
        if n>0:
            emit(w,", ")
        typed_reference(s,w,param)
        param=next(w,param)
        n=n+1
    emit(w,") {\n")
    i=0
    while i<get(w,BLOCK_COUNT):
        block=ordered_block(w,i,entry)
        bindex=meta(w,block,48)
        emit(w,"b")
        emit_number(w,bindex)
        emit(w,":\n")
        if bindex!=entry:
            param=first(w,field(w,block,K_params))
            ordinal=0
            while param!=NONE:
                render_phi(s,w,bindex,param,ordinal,entry)
                param=next(w,param)
                ordinal=ordinal+1
        copy_output(w,BODY+meta(w,block,56),meta(w,block,64))
        i=i+1
    i=0
    while i<get(w,BLOCK_COUNT):
        block=ordered_block(w,i,entry)
        term=field(w,block,K_term)
        j=0
        while j<2:
            incoming=each_edge(w,term,j)
            if incoming!=NONE:
                emit(w,"edge_")
                emit_number(w,meta(w,incoming,96))
                emit(w,":\n  br label %b")
                emit_number(w,meta(w,incoming,104))
                end_line(w)
            j=j+1
        i=i+1
    emit(w,"}")
    return 0

def wrapper_admitted(w:mutbuf,fn:u64) -> u64:
    params=first(w,field(w,fn,K_params))
    while params!=NONE:
        t=typecode(w,field(w,params,K_type))
        if t==0 or t>11:
            return 0
        params=next(w,params)
    returns=field(w,fn,K_returns)
    if count(w,returns)>1:
        return 0
    if count(w,returns)==1:
        t=typecode(w,first(w,returns))
        if t==0 or t>12:
            return 0
    name=field(w,fn,K_name)
    if identifier(w,name)==0:
        return fail(w,4294967291)
    if is_text(w,name,"abort")==1 or is_text(w,name,"calloc")==1 or is_text(w,name,"malloc")==1 or is_text(w,name,"free")==1 or is_text(w,name,"memcpy")==1 or is_text(w,name,"memset")==1 or is_text(w,name,"memmove")==1:
        return fail(w,4294967291)
    p=get(w,64+name*56+24)
    if count(w,name)>=6 and same(w,p,6,6,104871984914271,0,0)==1:
        return fail(w,4294967291)
    exports=field(w,0,K_exports)
    if exports!=NONE:
        item=first(w,exports)
        found=0
        while item!=NONE:
            if text_equal(w,item,name)==1:
                found=1
            item=next(w,item)
        return found
    return 1

def render_wrapper(s:readbuf,w:mutbuf) -> u64:
    fn=get(w,FN)
    returns=field(w,fn,K_returns)
    typ=0
    if count(w,returns)==1:
        typ=typecode(w,first(w,returns))
    void=choose(typ==0 or typ==12,1,0)
    emit(w,"define ")
    if void==1:
        emit(w,"void")
    else:
        abi_attr(w,typ)
        emit_type(w,typ)
    emit(w," @")
    emit_text(w,field(w,fn,K_name))
    emit(w,"(")
    param=first(w,field(w,fn,K_params))
    i=0
    while param!=NONE:
        if i>0:
            emit(w,", ")
        t=typecode(w,field(w,param,K_type))
        emit_type(w,t)
        emit(w," ")
        abi_attr(w,t)
        emit(w,"%a")
        emit_number(w,i)
        param=next(w,param)
        i=i+1
    emit(w,") {\nentry:\n  ")
    if typ!=0:
        emit(w,"%result = ")
    emit(w,"call ")
    return_type(w,returns)
    emit(w," @__hia_fn_")
    emit_number(w,get(w,FN_INDEX))
    emit(w,"(")
    param=first(w,field(w,fn,K_params))
    i=0
    while param!=NONE:
        if i>0:
            emit(w,", ")
        emit_type(w,typecode(w,field(w,param,K_type)))
        emit(w," %a")
        emit_number(w,i)
        param=next(w,param)
        i=i+1
    emit(w,")\n  ret ")
    if void==1:
        emit(w,"void")
    else:
        emit_type(w,typ)
        emit(w," %result")
    emit(w,"\n}")
    return 0
'''
if __name__=='__main__':
    write_module('program_llvm_flow',SOURCE,'llvm_flow')
