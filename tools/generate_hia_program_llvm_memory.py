"""HIA LLVM lowering for byte owners, loans, chains and atomic checked accesses."""
from tools.generate_hia_program_llvm_common import write_module

SOURCE=r'''
def llvm_memory(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    ins=get(w,INS)
    op=opcode(w,field(w,ins,K_op))
    if op==OP_buffer_new or op==OP_buffer_try_new:
        allocation(s,w,ins,op)
    elif op==OP_buffer_len:
        output_value(w,ins,0,buffer_part(s,w,argument(w,ins,0),1))
    elif op==OP_chain_empty:
        output_constant(w,ins,5,0)
    elif op==OP_chain_is_empty:
        a=argument(w,ins,0)
        value=pointer_compare(s,w,a,1)
        output_value(w,ins,0,value)
    elif op==OP_chain_try_push or op==OP_chain_pop:
        chain_transfer(s,w,ins,op)
    elif op==OP_chain_head_read or op==OP_chain_head_mut:
        a=argument(w,ins,0)
        guard(s,w,pointer_compare(s,w,a,0))
        value=instruction_start(s,w)
        emit(w,"load %hia.buffer, ptr ")
        reference(s,w,a)
        emit(w,", align 8\n")
        output_value(w,ins,0,value)
    elif op==OP_owner_move or op==OP_borrow_read or op==OP_borrow_mut:
        output_value(w,ins,0,argument(w,ins,0))
    elif op==OP_loan_end:
        end=0
    elif op==OP_owner_drop:
        owner_drop(s,w,ins)
    elif op>=OP_buffer_load_u64_le and op<=OP_buffer_store:
        access(s,w,ins,op)
    else:
        fail(w,4294967291)
    return 2

def pointer_compare(s:readbuf,w:mutbuf,a:u64,equal:u64) -> u64:
    result=instruction_start(s,w)
    if equal==1:
        emit(w,"icmp eq ptr ")
    else:
        emit(w,"icmp ne ptr ")
    reference(s,w,a)
    emit(w,", null\n")
    return result

def allocation(s:readbuf,w:mutbuf,ins:u64,op:u64) -> u64:
    size=argument(w,ins,0)
    pair=instruction_start(s,w)
    emit(w,"call %hia.alloc @__hia_allocate(i64 ")
    reference(s,w,size)
    emit(w,", i1 ")
    if get(w,ZERO_BYTES)==0:
        emit(w,"false")
    else:
        emit(w,"true")
    emit(w,")\n")
    owner=instruction_start(s,w)
    emit(w,"extractvalue %hia.alloc ")
    reference(s,w,pair)
    emit(w,", 0\n")
    success=instruction_start(s,w)
    emit(w,"extractvalue %hia.alloc ")
    reference(s,w,pair)
    emit(w,", 1\n")
    extent=size
    if op==OP_buffer_new:
        guard(s,w,success)
    else:
        extent=instruction_start(s,w)
        emit(w,"select i1 ")
        reference(s,w,success)
        emit(w,", i64 ")
        reference(s,w,size)
        emit(w,", i64 0\n")
    result=instruction_start(s,w)
    emit(w,"insertvalue %hia.buffer ")
    reference(s,w,owner)
    emit(w,", i64 ")
    reference(s,w,extent)
    emit(w,", 1\n")
    output_value(w,ins,0,result)
    if op==OP_buffer_try_new:
        output_value(w,ins,1,success)
    return 0

def chain_transfer(s:readbuf,w:mutbuf,ins:u64,op:u64) -> u64:
    result=instruction_start(s,w)
    emit(w,"call %hia.chain.result @__hia_chain_")
    if op==OP_chain_try_push:
        emit(w,"push")
    else:
        emit(w,"pop")
    emit(w,"(ptr ")
    reference(s,w,argument(w,ins,0))
    if op==OP_chain_try_push:
        emit(w,", %hia.buffer ")
        reference(s,w,argument(w,ins,1))
    emit(w,")\n")
    i=0
    while i<3:
        value=instruction_start(s,w)
        emit(w,"extractvalue %hia.chain.result ")
        reference(s,w,result)
        emit(w,", ")
        emit_number(w,i)
        end_line(w)
        output_value(w,ins,i,value)
        i=i+1
    return 0

def owner_drop(s:readbuf,w:mutbuf,ins:u64) -> u64:
    owner=argument(w,ins,0)
    if reference_type(w,owner)==16:
        emit(w,"  call void @__hia_chain_drop(ptr ")
        reference(s,w,owner)
        emit(w,")\n")
        return 0
    pointer=buffer_part(s,w,owner,0)
    nonnull=pointer_compare(s,w,pointer,0)
    label=new_temp(w)-TEMP
    emit(w,"  br i1 ")
    reference(s,w,nonnull)
    emit(w,", label %drop_nonnull_")
    emit_number(w,label)
    emit(w,", label %drop_after_")
    emit_number(w,label)
    emit(w,"\ndrop_nonnull_")
    emit_number(w,label)
    emit(w,":\n  call void @free(ptr ")
    reference(s,w,pointer)
    emit(w,") nobuiltin\n  br label %drop_after_")
    emit_number(w,label)
    emit(w,"\ndrop_after_")
    emit_number(w,label)
    emit(w,":\n")
    return 0

def address(s:readbuf,w:mutbuf,pointer:u64,index:u64) -> u64:
    value=instruction_start(s,w)
    emit(w,"getelementptr i8, ptr ")
    reference(s,w,pointer)
    emit(w,", i64 ")
    reference(s,w,index)
    end_line(w)
    return value

def byte_swap(s:readbuf,w:mutbuf,value:u64) -> u64:
    result=instruction_start(s,w)
    emit(w,"call i64 @llvm.bswap.i64(i64 ")
    reference(s,w,value)
    emit(w,")\n")
    return result

def access(s:readbuf,w:mutbuf,ins:u64,op:u64) -> u64:
    owner=argument(w,ins,0)
    pointer=buffer_part(s,w,owner,0)
    length_value=buffer_part(s,w,owner,1)
    index=argument(w,ins,1)
    wide=choose(op<=OP_buffer_store_u64_be,1,0)
    if wide==1:
        guard(s,w,compare(s,w,6,8,index,length_value))
        remaining=binary(s,w,2,8,length_value,index)
        guard(s,w,compare_literal(s,w,10,8,remaining,8))
    else:
        guard(s,w,compare(s,w,4,8,index,length_value))
    dest=address(s,w,pointer,index)
    read=choose(op==OP_buffer_load_u64_le or op==OP_buffer_load_u64_be or op==OP_buffer_load,1,0)
    big=choose(op==OP_buffer_load_u64_be or op==OP_buffer_store_u64_be,1,0)
    if read==1:
        value=instruction_start(s,w)
        if wide==1:
            emit(w,"load i64, ptr ")
        else:
            emit(w,"load i8, ptr ")
        reference(s,w,dest)
        emit(w,", align 1\n")
        if big==1:
            value=byte_swap(s,w,value)
        output_value(w,ins,0,value)
    else:
        value=argument(w,ins,2)
        if big==1:
            value=byte_swap(s,w,value)
        if wide==1:
            emit(w,"  store i64 ")
        else:
            emit(w,"  store i8 ")
        reference(s,w,value)
        emit(w,", ptr ")
        reference(s,w,dest)
        emit(w,", align 1\n")
    return 0
'''
if __name__=='__main__':
    write_module('program_llvm_memory',SOURCE,'llvm_memory')
