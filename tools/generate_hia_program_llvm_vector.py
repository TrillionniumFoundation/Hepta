"""Native exact forward byte-sum matcher and guarded SSE2 LLVM rendering."""
from tools.generate_hia_program_llvm_common import write_module
from tools.generate_hia_program_llvm_memory import SOURCE as MEMORY_SOURCE

MATCH_SOURCE=r'''
def vector_position(w:mutbuf,block:u64,name:u64) -> u64:
    p=first(w,field(w,block,K_params))
    i=0
    while p!=NONE:
        if text_equal(w,field(w,p,K_name),name)==1:
            return i
        p=next(w,p)
        i=i+1
    return NONE

def vector_param(w:mutbuf,block:u64,index:u64) -> u64:
    return field(w,nth(w,field(w,block,K_params),index),K_name)

def vector_output(w:mutbuf,op:u64) -> u64:
    return field(w,first(w,field(w,op,K_out)),K_name)

def vector_arg(w:mutbuf,op:u64,index:u64,name:u64) -> u64:
    return text_equal(w,nth(w,field(w,op,K_args),index),name)

def vector_one(w:mutbuf,op:u64,code:u64,typ:u64,argc:u64,attrs:u64) -> u64:
    return choose(opcode(w,field(w,op,K_op))==code and count(w,field(w,op,K_out))==1 and typecode(w,field(w,first(w,field(w,op,K_out)),K_type))==typ and count(w,field(w,op,K_args))==argc and count(w,field(w,op,K_attrs))==attrs,1,0)

def vector_predecessors(w:mutbuf,body:u64,header:u64) -> u64:
    i=0
    found=0
    while i<get(w,BLOCK_COUNT):
        b=get(w,BLOCKS+i*8)
        term=field(w,b,K_term)
        j=0
        while j<2:
            incoming=each_edge(w,term,j)
            if incoming!=NONE and block_index(w,field(w,incoming,K_target))==body:
                if i!=header:
                    return 0
                found=found+1
            j=j+1
        i=i+1
    return choose(found==1,1,0)

def vector_body_match(s:readbuf,w:mutbuf,body:u64,header_index:u64,ip:u64,np:u64) -> u64:
    ops=field(w,body,K_ops)
    borrow=first(w,ops)
    load=next(w,borrow)
    end=next(w,load)
    widen=next(w,end)
    add=next(w,widen)
    one=next(w,add)
    advance=next(w,one)
    owner=nth(w,field(w,borrow,K_args),0)
    owner_position=vector_position(w,body,owner)
    if owner_position==NONE or typecode(w,field(w,nth(w,field(w,body,K_params),owner_position),K_type))!=13:
        return 0
    if vector_one(w,borrow,OP_borrow_read,14,1,0)==0:
        return 0
    loan=vector_output(w,borrow)
    if vector_one(w,load,OP_buffer_load,2,2,0)==0 or vector_arg(w,load,0,loan)==0 or vector_arg(w,load,1,vector_param(w,body,ip))==0:
        return 0
    if opcode(w,field(w,end,K_op))!=OP_loan_end or count(w,field(w,end,K_out))!=0 or count(w,field(w,end,K_args))!=1 or count(w,field(w,end,K_attrs))!=0 or vector_arg(w,end,0,loan)==0:
        return 0
    if vector_one(w,widen,OP_int_cast,8,1,1)==0 or vector_arg(w,widen,0,vector_output(w,load))==0 or is_text(w,field(w,field(w,widen,K_attrs),K_mode),"wrap")==0:
        return 0
    total=nth(w,field(w,add,K_args),0)
    ap=vector_position(w,body,total)
    if ap==NONE or typecode(w,field(w,nth(w,field(w,body,K_params),ap),K_type))!=8:
        return 0
    if vector_one(w,add,OP_int_add_wrap,8,2,0)==0 or vector_arg(w,add,1,vector_output(w,widen))==0:
        return 0
    number=field(w,field(w,one,K_attrs),K_value)
    if vector_one(w,one,OP_const,10,0,1)==0 or kind(w,number)!=3 or count(w,number)!=1 or byte(s,ARG_HEADER+get(w,64+number*56+24))!=49:
        return 0
    if vector_one(w,advance,OP_int_add_wrap,10,2,0)==0 or vector_arg(w,advance,0,vector_param(w,body,ip))==0 or vector_arg(w,advance,1,vector_output(w,one))==0:
        return 0
    term=field(w,body,K_term)
    if is_text(w,field(w,term,K_op),"jump")==0 or block_index(w,field(w,term,K_target))!=header_index or count(w,field(w,term,K_args))!=count(w,field(w,body,K_params)):
        return 0
    i=0
    while i<count(w,field(w,body,K_params)):
        expected=vector_param(w,body,i)
        if i==ap:
            expected=vector_output(w,add)
        if i==ip:
            expected=vector_output(w,advance)
        if vector_arg(w,term,i,expected)==0:
            return 0
        i=i+1
    setmeta(w,body,72,1)
    setmeta(w,body,80,owner_position)
    setmeta(w,body,88,ip)
    setmeta(w,body,96,np)
    setmeta(w,body,104,ap)
    put(w,FEATURES,get(w,FEATURES)|16)
    return 1

def vector_header_match(s:readbuf,w:mutbuf,header:u64) -> u64:
    term=field(w,header,K_term)
    if count(w,field(w,header,K_ops))!=1 or is_text(w,field(w,term,K_op),"branch")==0:
        return 0
    compare=first(w,field(w,header,K_ops))
    if vector_one(w,compare,OP_compare_lt,11,2,0)==0 or text_equal(w,field(w,term,K_cond),vector_output(w,compare))==0:
        return 0
    then=field(w,term,K_then)
    hp=field(w,header,K_params)
    if count(w,field(w,then,K_args))!=count(w,hp):
        return 0
    i=0
    while i<count(w,hp):
        if vector_arg(w,then,i,vector_param(w,header,i))==0:
            return 0
        i=i+1
    ip=vector_position(w,header,nth(w,field(w,compare,K_args),0))
    np=vector_position(w,header,nth(w,field(w,compare,K_args),1))
    if ip==NONE or np==NONE or ip==np or typecode(w,field(w,nth(w,hp,ip),K_type))!=10 or typecode(w,field(w,nth(w,hp,np),K_type))!=10:
        return 0
    index=block_index(w,field(w,then,K_target))
    body=get(w,BLOCKS+index*8)
    if index==get(w,ENTRY_INDEX) or vector_predecessors(w,index,meta(w,header,48))==0 or count(w,field(w,body,K_ops))!=7:
        return 0
    bp=field(w,body,K_params)
    if count(w,hp)!=count(w,bp):
        return 0
    i=0
    while i<count(w,hp):
        if typecode(w,field(w,nth(w,hp,i),K_type))!=typecode(w,field(w,nth(w,bp,i),K_type)):
            return 0
        i=i+1
    return vector_body_match(s,w,body,meta(w,header,48),ip,np)

def match_vectors(s:readbuf,w:mutbuf) -> u64:
    i=0
    while i<get(w,BLOCK_COUNT):
        setmeta(w,get(w,BLOCKS+i*8),72,0)
        i=i+1
    if get(w,TARGET)!=0:
        return 0
    i=0
    while i<get(w,BLOCK_COUNT):
        vector_header_match(s,w,get(w,BLOCKS+i*8))
        i=i+1
    return 0
'''

SOURCE=r'''
def llvm_vector(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    vector_render(s,w)
    return 2

def vget(w:mutbuf,offset:u64) -> u64:
    return get(w,CTRL+512+offset)

def vput(w:mutbuf,offset:u64,value:u64) -> u64:
    return put(w,CTRL+512+offset,value)

def label(w:mutbuf,which:u64) -> u64:
    if which==1:
        emit(w,"byte_sum_start_")
    elif which==2:
        emit(w,"byte_sum_vector_head_")
    elif which==3:
        emit(w,"byte_sum_vector_body_")
    elif which==4:
        emit(w,"byte_sum_half_head_")
    elif which==5:
        emit(w,"byte_sum_half_body_")
    elif which==6:
        emit(w,"byte_sum_scalar_head_")
    elif which==7:
        emit(w,"byte_sum_scalar_body_")
    elif which==8:
        emit(w,"byte_sum_scalar_done_")
    else:
        emit(w,"byte_sum_finished_")
    emit_number(w,vget(w,0))
    return 0

def label_line(w:mutbuf,which:u64) -> u64:
    label(w,which)
    emit(w,":\n")
    return 0

def jump_label(w:mutbuf,which:u64) -> u64:
    emit(w,"  br label %")
    label(w,which)
    end_line(w)
    return 0

def branch_label(s:readbuf,w:mutbuf,cond:u64,yes:u64,no:u64) -> u64:
    emit(w,"  br i1 ")
    reference(s,w,cond)
    emit(w,", label %")
    label(w,yes)
    emit(w,", label %")
    label(w,no)
    end_line(w)
    return 0

def phi_piece(s:readbuf,w:mutbuf,value:u64,predecessor:u64) -> u64:
    emit(w,"[ ")
    reference(s,w,value)
    emit(w,", %")
    label(w,predecessor)
    emit(w," ]")
    return 0

def vector_phi(s:readbuf,w:mutbuf,which:u64) -> u64:
    out=vget(w,48+which*8)
    a=vget(w,24)
    b=vget(w,88)
    if which==1:
        a=vget(w,40)
        b=vget(w,80)
    emit(w,"  ")
    reference(s,w,out)
    emit(w," = phi i64 ")
    phi_piece(s,w,a,1)
    emit(w,", ")
    phi_piece(s,w,b,3)
    end_line(w)
    return 0

def scalar_phi(s:readbuf,w:mutbuf,which:u64) -> u64:
    out=vget(w,64+which*8)
    a=vget(w,48+which*8)
    b=vget(w,104)
    c=vget(w,120)
    if which==1:
        b=vget(w,96)
        c=vget(w,112)
    emit(w,"  ")
    reference(s,w,out)
    emit(w," = phi i64 ")
    phi_piece(s,w,a,4)
    emit(w,", ")
    phi_piece(s,w,b,5)
    emit(w,", ")
    phi_piece(s,w,c,8)
    end_line(w)
    return 0

def vector_group(s:readbuf,w:mutbuf) -> u64:
    pointer=address(s,w,vget(w,8),vget(w,48))
    lanes=instruction_start(s,w)
    emit(w,"load <16 x i8>, ptr ")
    reference(s,w,pointer)
    emit(w,", align 1\n")
    pair=instruction_start(s,w)
    emit(w,"call <2 x i64> @llvm.x86.sse2.psad.bw(<16 x i8> ")
    reference(s,w,lanes)
    emit(w,", <16 x i8> zeroinitializer)\n")
    left=instruction_start(s,w)
    emit(w,"extractelement <2 x i64> ")
    reference(s,w,pair)
    emit(w,", i32 0\n")
    right=instruction_start(s,w)
    emit(w,"extractelement <2 x i64> ")
    reference(s,w,pair)
    emit(w,", i32 1\n")
    subtotal=binary(s,w,1,8,left,right)
    vput(w,80,binary(s,w,1,8,vget(w,56),subtotal))
    index=instruction_start(s,w)
    emit(w,"add i64 ")
    reference(s,w,vget(w,48))
    emit(w,", 16\n")
    vput(w,88,index)
    return 0

def half_group(s:readbuf,w:mutbuf) -> u64:
    pointer=address(s,w,vget(w,8),vget(w,48))
    packed=instruction_start(s,w)
    emit(w,"load i64, ptr ")
    reference(s,w,pointer)
    emit(w,", align 1\n")
    low=instruction_start(s,w)
    emit(w,"insertelement <2 x i64> zeroinitializer, i64 ")
    reference(s,w,packed)
    emit(w,", i32 0\n")
    lanes=instruction_start(s,w)
    emit(w,"bitcast <2 x i64> ")
    reference(s,w,low)
    emit(w," to <16 x i8>\n")
    pair=instruction_start(s,w)
    emit(w,"call <2 x i64> @llvm.x86.sse2.psad.bw(<16 x i8> ")
    reference(s,w,lanes)
    emit(w,", <16 x i8> zeroinitializer)\n")
    subtotal=instruction_start(s,w)
    emit(w,"extractelement <2 x i64> ")
    reference(s,w,pair)
    emit(w,", i32 0\n")
    vput(w,96,binary(s,w,1,8,vget(w,56),subtotal))
    index=instruction_start(s,w)
    emit(w,"add i64 ")
    reference(s,w,vget(w,48))
    emit(w,", 8\n")
    vput(w,104,index)
    return 0

def scalar_group(s:readbuf,w:mutbuf) -> u64:
    block=get(w,BLOCK)
    ip=nth(w,field(w,block,K_params),meta(w,block,88))
    ap=nth(w,field(w,block,K_params),meta(w,block,104))
    setmeta(w,ip,0,0)
    setmeta(w,ip,8,vget(w,64))
    setmeta(w,ap,0,0)
    setmeta(w,ap,8,vget(w,72))
    op=first(w,field(w,block,K_ops))
    output_value(w,op,0,argument(w,op,0))
    op=next(w,op)
    access(s,w,op,OP_buffer_load)
    op=next(w,next(w,op))
    output_value(w,op,0,cast_value(s,w,argument(w,op,0),2,8))
    op=next(w,op)
    total=binary(s,w,1,8,argument(w,op,0),argument(w,op,1))
    output_value(w,op,0,total)
    vput(w,112,total)
    op=next(w,op)
    output_constant(w,op,3,field(w,field(w,op,K_attrs),K_value))
    op=next(w,op)
    index=binary(s,w,1,10,argument(w,op,0),argument(w,op,1))
    output_value(w,op,0,index)
    vput(w,120,index)
    setmeta(w,ip,0,1)
    setmeta(w,ip,8,meta(w,block,48))
    setmeta(w,ap,0,1)
    setmeta(w,ap,8,meta(w,block,48))
    return 0

def contains_chunk(s:readbuf,w:mutbuf,bound:u64,width:u64) -> u64:
    ordered=compare(s,w,6,8,vget(w,48),bound)
    remaining=binary(s,w,2,8,bound,vget(w,48))
    enough=compare_literal(s,w,10,8,remaining,width)
    return binary(s,w,11,11,ordered,enough)

def chunk_guard(s:readbuf,w:mutbuf,width:u64) -> u64:
    logical=contains_chunk(s,w,vget(w,32),width)
    physical=contains_chunk(s,w,vget(w,16),width)
    return binary(s,w,11,11,logical,physical)

def vector_render(s:readbuf,w:mutbuf) -> u64:
    block=get(w,BLOCK)
    params=field(w,block,K_params)
    owner=nth(w,params,meta(w,block,80))
    vput(w,24,nth(w,params,meta(w,block,88)))
    vput(w,32,nth(w,params,meta(w,block,96)))
    vput(w,40,nth(w,params,meta(w,block,104)))
    vput(w,8,buffer_part(s,w,owner,0))
    vput(w,16,buffer_part(s,w,owner,1))
    vput(w,0,new_temp(w)-TEMP)
    vput(w,48,new_temp(w))
    vput(w,56,new_temp(w))
    vput(w,64,new_temp(w))
    vput(w,72,new_temp(w))
    vput(w,152,get(w,DEST))
    vput(w,160,get(w,POS))
    put(w,DEST,AUX+1048576)
    put(w,POS,0)
    vector_group(s,w)
    vput(w,128,get(w,POS))
    put(w,DEST,AUX+2097152)
    put(w,POS,0)
    half_group(s,w)
    vput(w,136,get(w,POS))
    put(w,DEST,AUX+3145728)
    put(w,POS,0)
    scalar_group(s,w)
    vput(w,144,get(w,POS))
    put(w,DEST,vget(w,152))
    put(w,POS,vget(w,160))
    jump_label(w,1)
    label_line(w,1)
    jump_label(w,2)
    label_line(w,2)
    vector_phi(s,w,0)
    vector_phi(s,w,1)
    branch_label(s,w,chunk_guard(s,w,16),3,4)
    label_line(w,3)
    copy_output(w,AUX+1048576,vget(w,128))
    jump_label(w,2)
    label_line(w,4)
    branch_label(s,w,chunk_guard(s,w,8),5,6)
    label_line(w,5)
    copy_output(w,AUX+2097152,vget(w,136))
    jump_label(w,6)
    label_line(w,6)
    scalar_phi(s,w,0)
    scalar_phi(s,w,1)
    more=compare(s,w,4,8,vget(w,64),vget(w,32))
    branch_label(s,w,more,7,9)
    label_line(w,7)
    copy_output(w,AUX+3145728,vget(w,144))
    jump_label(w,8)
    label_line(w,8)
    jump_label(w,6)
    label_line(w,9)
    ops=field(w,block,K_ops)
    output_value(w,nth(w,ops,4),0,vget(w,72))
    output_value(w,nth(w,ops,6),0,vget(w,64))
    return 0
'''
if __name__=='__main__':
    write_module('program_llvm_vector',SOURCE+'\n'+MEMORY_SOURCE,'llvm_vector')
