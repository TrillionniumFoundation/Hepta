"""HIA LLVM lowering for zero-safe bulk byte operations and swaps."""
from tools.generate_hia_program_llvm_common import write_module
from tools.generate_hia_program_llvm_memory import SOURCE as MEMORY_SOURCE

SOURCE=r'''
def llvm_bulk(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    ins=get(w,INS)
    op=opcode(w,field(w,ins,K_op))
    if op==OP_buffer_fill:
        render_fill(s,w,ins)
    elif op==OP_buffer_copy:
        render_copy(s,w,ins)
    elif op==OP_buffer_move_within:
        render_move(s,w,ins)
    elif op==OP_buffer_fill_range:
        render_fill_range(s,w,ins)
    elif op==OP_buffer_copy_range:
        render_copy_range(s,w,ins)
    elif op==OP_buffer_swap:
        render_swap(s,w,ins)
    else:
        fail(w,4294967291)
    return 2

def nonempty(s:readbuf,w:mutbuf,size:u64) -> u64:
    positive=compare_literal(s,w,2,8,size,0)
    index=new_temp(w)-TEMP
    emit(w,"  br i1 ")
    reference(s,w,positive)
    emit(w,", label %bulk_nonzero_")
    emit_number(w,index)
    emit(w,", label %bulk_after_")
    emit_number(w,index)
    emit(w,"\nbulk_nonzero_")
    emit_number(w,index)
    emit(w,":\n")
    return index

def bulk_end(w:mutbuf,index:u64) -> u64:
    emit(w,"  br label %bulk_after_")
    emit_number(w,index)
    emit(w,"\nbulk_after_")
    emit_number(w,index)
    emit(w,":\n")
    return 0

def memset(s:readbuf,w:mutbuf,dest:u64,value:u64,size:u64) -> u64:
    emit(w,"  call void @llvm.memset.p0.i64(ptr align 1 ")
    reference(s,w,dest)
    emit(w,", i8 ")
    reference(s,w,value)
    emit(w,", i64 ")
    reference(s,w,size)
    emit(w,", i1 false)\n")
    return 0

def memcpy(s:readbuf,w:mutbuf,dest:u64,source:u64,size:u64,move:u64) -> u64:
    if move==1:
        emit(w,"  call void @llvm.memmove.p0.p0.i64(ptr align 1 ")
    else:
        emit(w,"  call void @llvm.memcpy.p0.p0.i64(ptr align 1 ")
    reference(s,w,dest)
    emit(w,", ptr align 1 ")
    reference(s,w,source)
    emit(w,", i64 ")
    reference(s,w,size)
    emit(w,", i1 false)\n")
    return 0

def render_fill(s:readbuf,w:mutbuf,ins:u64) -> u64:
    owner=argument(w,ins,0)
    pointer=buffer_part(s,w,owner,0)
    length_value=buffer_part(s,w,owner,1)
    label=nonempty(s,w,length_value)
    memset(s,w,pointer,argument(w,ins,1),length_value)
    return bulk_end(w,label)

def render_copy(s:readbuf,w:mutbuf,ins:u64) -> u64:
    a=argument(w,ins,0)
    b=argument(w,ins,1)
    dest=buffer_part(s,w,a,0)
    dn=buffer_part(s,w,a,1)
    source=buffer_part(s,w,b,0)
    sn=buffer_part(s,w,b,1)
    size=argument(w,ins,2)
    guard(s,w,compare(s,w,6,8,size,dn))
    guard(s,w,compare(s,w,6,8,size,sn))
    label=nonempty(s,w,size)
    memcpy(s,w,dest,source,size,0)
    return bulk_end(w,label)

def render_move(s:readbuf,w:mutbuf,ins:u64) -> u64:
    owner=argument(w,ins,0)
    pointer=buffer_part(s,w,owner,0)
    extent=buffer_part(s,w,owner,1)
    dest=argument(w,ins,1)
    source=argument(w,ins,2)
    size=argument(w,ins,3)
    guard(s,w,compare(s,w,6,8,dest,extent))
    guard(s,w,compare(s,w,6,8,source,extent))
    da=binary(s,w,2,8,extent,dest)
    sa=binary(s,w,2,8,extent,source)
    guard(s,w,compare(s,w,6,8,size,da))
    guard(s,w,compare(s,w,6,8,size,sa))
    label=nonempty(s,w,size)
    dp=address(s,w,pointer,dest)
    sp=address(s,w,pointer,source)
    memcpy(s,w,dp,sp,size,1)
    return bulk_end(w,label)

def render_fill_range(s:readbuf,w:mutbuf,ins:u64) -> u64:
    owner=argument(w,ins,0)
    pointer=buffer_part(s,w,owner,0)
    extent=buffer_part(s,w,owner,1)
    offset=argument(w,ins,1)
    size=argument(w,ins,2)
    value=argument(w,ins,3)
    guard(s,w,compare(s,w,6,8,offset,extent))
    remaining=binary(s,w,2,8,extent,offset)
    guard(s,w,compare(s,w,6,8,size,remaining))
    label=new_temp(w)-TEMP
    positive=compare_literal(s,w,2,8,size,0)
    emit(w,"  br i1 ")
    reference(s,w,positive)
    emit(w,", label %fill_nonempty_")
    emit_number(w,label)
    emit(w,", label %fill_after_")
    emit_number(w,label)
    emit(w,"\nfill_nonempty_")
    emit_number(w,label)
    emit(w,":\n")
    dest=address(s,w,pointer,offset)
    memset(s,w,dest,value,size)
    emit(w,"  br label %fill_after_")
    emit_number(w,label)
    emit(w,"\nfill_after_")
    emit_number(w,label)
    emit(w,":\n")
    return 0

def render_copy_range(s:readbuf,w:mutbuf,ins:u64) -> u64:
    a=argument(w,ins,0)
    b=argument(w,ins,1)
    destination=buffer_part(s,w,a,0)
    dn=buffer_part(s,w,a,1)
    source=buffer_part(s,w,b,0)
    sn=buffer_part(s,w,b,1)
    doffset=argument(w,ins,2)
    soffset=argument(w,ins,3)
    size=argument(w,ins,4)
    guard(s,w,compare(s,w,6,8,doffset,dn))
    guard(s,w,compare(s,w,6,8,soffset,sn))
    da=binary(s,w,2,8,dn,doffset)
    sa=binary(s,w,2,8,sn,soffset)
    guard(s,w,compare(s,w,6,8,size,da))
    guard(s,w,compare(s,w,6,8,size,sa))
    label=nonempty(s,w,size)
    dp=address(s,w,destination,doffset)
    sp=address(s,w,source,soffset)
    memcpy(s,w,dp,sp,size,0)
    return bulk_end(w,label)

def load_byte(s:readbuf,w:mutbuf,address:u64) -> u64:
    result=instruction_start(s,w)
    emit(w,"load i8, ptr ")
    reference(s,w,address)
    emit(w,", align 1\n")
    return result

def store_byte(s:readbuf,w:mutbuf,address:u64,value:u64) -> u64:
    emit(w,"  store i8 ")
    reference(s,w,value)
    emit(w,", ptr ")
    reference(s,w,address)
    emit(w,", align 1\n")
    return 0

def render_swap(s:readbuf,w:mutbuf,ins:u64) -> u64:
    owner=argument(w,ins,0)
    pointer=buffer_part(s,w,owner,0)
    extent=buffer_part(s,w,owner,1)
    left=argument(w,ins,1)
    right=argument(w,ins,2)
    guard(s,w,compare(s,w,4,8,left,extent))
    guard(s,w,compare(s,w,4,8,right,extent))
    lp=address(s,w,pointer,left)
    rp=address(s,w,pointer,right)
    lv=load_byte(s,w,lp)
    rv=load_byte(s,w,rp)
    store_byte(s,w,lp,rv)
    store_byte(s,w,rp,lv)
    return 0
'''
if __name__=='__main__':
    write_module('program_llvm_bulk',SOURCE+'\n'+MEMORY_SOURCE,'llvm_bulk')
