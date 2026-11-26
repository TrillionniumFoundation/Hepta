"""HIA scalar LLVM instruction emission with exact SSA and trap ordering."""
from tools.generate_hia_program_llvm_common import write_module

SOURCE=r'''
def llvm_scalar(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    ins=get(w,INS)
    op=opcode(w,field(w,ins,K_op))
    if op==OP_const:
        target=nth(w,field(w,ins,K_out),0)
        typ=typecode(w,field(w,target,K_type))
        if typ==12:
            output_constant(w,ins,4,0)
        else:
            output_constant(w,ins,3,field(w,field(w,ins,K_attrs),K_value))
    elif op>=OP_int_add_checked and op<=OP_int_mul_wrap:
        a=argument(w,ins,0)
        b=argument(w,ins,1)
        t=reference_type(w,a)
        action=op-OP_int_add_checked+1
        if op<=OP_int_mul_checked:
            result=checked_binary(s,w,action,t,a,b,0)
        else:
            result=binary(s,w,op-OP_int_add_wrap+1,t,a,b)
        output_value(w,ins,0,result)
    elif op==OP_int_div_checked or op==OP_int_rem_checked:
        division(s,w,ins,op)
    elif op==OP_int_shl_checked or op==OP_int_shr_checked:
        a=argument(w,ins,0)
        b=argument(w,ins,1)
        typ=reference_type(w,a)
        counter=reference_type(w,b)
        guard(s,w,compare_literal(s,w,4,counter,b,bits(w,typ)))
        amount=cast_value(s,w,b,counter,typ)
        action=8
        if op==OP_int_shr_checked:
            action=choose(signed_type(typ)==1,9,10)
        output_value(w,ins,0,binary(s,w,action,typ,a,amount))
    elif op==OP_int_neg_checked:
        a=argument(w,ins,0)
        output_value(w,ins,0,checked_binary(s,w,2,reference_type(w,a),0,a,1))
    elif op>=OP_bit_and and op<=OP_bit_not:
        a=argument(w,ins,0)
        typ=reference_type(w,a)
        if op==OP_bit_not:
            result=instruction_start(s,w)
            emit(w,"xor ")
            emit_type(w,typ)
            emit(w," ")
            reference(s,w,a)
            emit(w,", -1\n")
        else:
            result=binary(s,w,op-OP_bit_and+11,typ,a,argument(w,ins,1))
        output_value(w,ins,0,result)
    elif op>=OP_compare_eq and op<=OP_compare_ge:
        a=argument(w,ins,0)
        typ=reference_type(w,a)
        predicate=op-OP_compare_eq+1
        if predicate>=3:
            predicate=3+(predicate-3)*2+choose(signed_type(typ)==1,0,1)
        output_value(w,ins,0,compare(s,w,predicate,typ,a,argument(w,ins,1)))
    elif op>=OP_bool_not and op<=OP_bool_or:
        a=argument(w,ins,0)
        if op==OP_bool_not:
            result=boolean_not(s,w,a)
        else:
            result=binary(s,w,op-OP_bool_and+11,11,a,argument(w,ins,1))
        output_value(w,ins,0,result)
    elif op==OP_int_cast:
        integer_cast(s,w,ins)
    elif op==OP_select:
        result=instruction_start(s,w)
        emit(w,"select i1 ")
        reference(s,w,argument(w,ins,0))
        emit(w,", ")
        typed_reference(s,w,argument(w,ins,1))
        emit(w,", ")
        typed_reference(s,w,argument(w,ins,2))
        end_line(w)
        output_value(w,ins,0,result)
    elif op==OP_call:
        internal_call(s,w,ins)
    else:
        fail(w,4294967291)
    return 2

def checked_name(w:mutbuf,action:u64,typ:u64) -> u64:
    emit(w,"llvm.")
    if signed_type(typ)==1:
        emit(w,"s")
    else:
        emit(w,"u")
    emit_binary_name(w,action)
    emit(w,".with.overflow.i")
    emit_number(w,bits(w,typ))
    return 0

def checked_binary(s:readbuf,w:mutbuf,action:u64,typ:u64,a:u64,b:u64,zero_left:u64) -> u64:
    pair=instruction_start(s,w)
    emit(w,"call { ")
    emit_type(w,typ)
    emit(w,", i1 } @")
    checked_name(w,action,typ)
    emit(w,"(")
    emit_type(w,typ)
    emit(w," ")
    if zero_left==1:
        emit(w,"0")
    else:
        reference(s,w,a)
    emit(w,", ")
    emit_type(w,typ)
    emit(w," ")
    reference(s,w,b)
    emit(w,")\n")
    value=instruction_start(s,w)
    emit(w,"extractvalue { ")
    emit_type(w,typ)
    emit(w,", i1 } ")
    reference(s,w,pair)
    emit(w,", 0\n")
    overflow=instruction_start(s,w)
    emit(w,"extractvalue { ")
    emit_type(w,typ)
    emit(w,", i1 } ")
    reference(s,w,pair)
    emit(w,", 1\n")
    guard(s,w,boolean_not(s,w,overflow))
    return value

def emit_bound(w:mutbuf,typ:u64,high:u64) -> u64:
    width=bits(w,typ)
    if high==0:
        if signed_type(typ)==1:
            emit(w,"-")
            emit_number(w,1<<(width-1))
        else:
            emit(w,"0")
    elif signed_type(typ)==1:
        emit_number(w,(1<<(width-1))-1)
    elif width==64:
        emit_number(w,NONE)
    else:
        emit_number(w,(1<<width)-1)
    return 0

def maximum(w:mutbuf,typ:u64) -> u64:
    width=bits(w,typ)
    if signed_type(typ)==1:
        return (1<<(width-1))-1
    if width==64:
        return NONE
    return (1<<width)-1

def division(s:readbuf,w:mutbuf,ins:u64,op:u64) -> u64:
    a=argument(w,ins,0)
    b=argument(w,ins,1)
    typ=reference_type(w,a)
    guard(s,w,compare_literal(s,w,2,typ,b,0))
    if signed_type(typ)==1:
        left=instruction_start(s,w)
        emit(w,"icmp eq ")
        emit_type(w,typ)
        emit(w," ")
        reference(s,w,a)
        emit(w,", ")
        emit_bound(w,typ,0)
        end_line(w)
        right=instruction_start(s,w)
        emit(w,"icmp eq ")
        emit_type(w,typ)
        emit(w," ")
        reference(s,w,b)
        emit(w,", -1\n")
        both=binary(s,w,11,11,left,right)
        guard(s,w,boolean_not(s,w,both))
    action=choose(signed_type(typ)==1,4,5)
    if op==OP_int_rem_checked:
        action=action+2
    output_value(w,ins,0,binary(s,w,action,typ,a,b))
    return 0

def integer_cast(s:readbuf,w:mutbuf,ins:u64) -> u64:
    a=argument(w,ins,0)
    source=reference_type(w,a)
    destination=typecode(w,field(w,first(w,field(w,ins,K_out)),K_type))
    mode=field(w,field(w,ins,K_attrs),K_mode)
    if is_text(w,mode,"checked")==1:
        if signed_type(source)==1 and (signed_type(destination)==0 or bits(w,destination)<bits(w,source)):
            value=instruction_start(s,w)
            emit(w,"icmp sge ")
            emit_type(w,source)
            emit(w," ")
            reference(s,w,a)
            emit(w,", ")
            emit_bound(w,destination,0)
            end_line(w)
            guard(s,w,value)
        if maximum(w,destination)<maximum(w,source):
            value=instruction_start(s,w)
            if signed_type(source)==1:
                emit(w,"icmp sle ")
            else:
                emit(w,"icmp ule ")
            emit_type(w,source)
            emit(w," ")
            reference(s,w,a)
            emit(w,", ")
            emit_bound(w,destination,1)
            end_line(w)
            guard(s,w,value)
    elif is_text(w,mode,"wrap")==0:
        return fail(w,4294967291)
    output_value(w,ins,0,cast_value(s,w,a,source,destination))
    return 0

def internal_call(s:readbuf,w:mutbuf,ins:u64) -> u64:
    index=function_index(w,field(w,field(w,ins,K_attrs),K_function))
    fn=get(w,FUNCS+index*8)
    returns=field(w,fn,K_returns)
    n=count(w,returns)
    value=0
    if n==0:
        emit(w,"  ")
    else:
        value=instruction_start(s,w)
    emit(w,"call ")
    return_type(w,returns)
    emit(w," @__hia_fn_")
    emit_number(w,index)
    emit(w,"(")
    argc=count(w,field(w,ins,K_args))
    i=0
    while i<argc:
        if i>0:
            emit(w,", ")
        typed_reference(s,w,argument(w,ins,i))
        i=i+1
    emit(w,")\n")
    if n==1:
        output_value(w,ins,0,value)
    elif n>1:
        i=0
        while i<n:
            result=instruction_start(s,w)
            emit(w,"extractvalue ")
            return_type(w,returns)
            emit(w," ")
            reference(s,w,value)
            emit(w,", ")
            emit_number(w,i)
            end_line(w)
            output_value(w,ins,i,result)
            i=i+1
    return 0
'''
if __name__=='__main__':
    write_module('program_llvm_scalar',SOURCE,'llvm_scalar')
