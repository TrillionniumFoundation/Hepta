"""HIA LLVM module framing, declarations and native function inventories."""
from tools.generate_hia_program_llvm_common import write_module
from tools.generate_hia_program_llvm_flow import SOURCE as FLOW_SOURCE

BUFFER_RUNTIME="\n; A failed allocation is an empty, valid owner plus false. Zero length succeeds.\n; The independent verifier still requires every resulting owner to be consumed.\ndefine internal %hia.alloc @__hia_allocate(i64 %length, i1 %zero_bytes) {\nentry:\n  %zero = icmp eq i64 %length, 0\n  br i1 %zero, label %empty, label %nonempty\nempty:\n  %empty_result = insertvalue %hia.alloc zeroinitializer, i1 true, 1\n  ret %hia.alloc %empty_result\nnonempty:\n  %valid = icmp ule i64 %length, 9223372036854775807\n  br i1 %valid, label %allocate, label %failed\nallocate:\n  br i1 %zero_bytes, label %zeroed, label %unread\nzeroed:\n  %zero_pointer = call ptr @calloc(i64 1, i64 %length) nobuiltin\n  br label %allocated\nunread:\n  %unread_pointer = call ptr @malloc(i64 %length) nobuiltin\n  br label %allocated\nallocated:\n  %pointer = phi ptr [ %zero_pointer, %zeroed ], [ %unread_pointer, %unread ]\n  %success = icmp ne ptr %pointer, null\n  br i1 %success, label %ready, label %failed\nready:\n  %b0 = insertvalue %hia.buffer zeroinitializer, ptr %pointer, 0\n  %b1 = insertvalue %hia.buffer %b0, i64 %length, 1\n  %r0 = insertvalue %hia.alloc zeroinitializer, %hia.buffer %b1, 0\n  %r1 = insertvalue %hia.alloc %r0, i1 true, 1\n  ret %hia.alloc %r1\nfailed:\n  ret %hia.alloc zeroinitializer\n}\n"
CHAIN_RUNTIME="\n; v7 inductive owner: Nil | Node(buffer payload, chain tail).\n; No raw pointer constructor is admitted. push consumes both input owners.\n; Its failure returns both unchanged, while success returns an empty fallback.\ndefine internal %hia.chain.result @__hia_chain_push(ptr %tail, %hia.buffer %payload) {\nentry:\n  %node = call ptr @malloc(i64 24) nobuiltin\n  %ok = icmp ne ptr %node, null\n  br i1 %ok, label %ready, label %failed\nready:\n  store %hia.buffer %payload, ptr %node, align 8\n  %tail_slot = getelementptr %hia.chain.node, ptr %node, i32 0, i32 1\n  store ptr %tail, ptr %tail_slot, align 8\n  %r0 = insertvalue %hia.chain.result zeroinitializer, ptr %node, 0\n  %r1 = insertvalue %hia.chain.result %r0, i1 true, 2\n  ret %hia.chain.result %r1\nfailed:\n  %f0 = insertvalue %hia.chain.result zeroinitializer, ptr %tail, 0\n  %f1 = insertvalue %hia.chain.result %f0, %hia.buffer %payload, 1\n  ret %hia.chain.result %f1\n}\n\n; Empty pop returns Nil, an empty payload owner, and false. Nonempty pop\n; deallocates exactly the header and transfers payload/tail ownership out.\ndefine internal %hia.chain.result @__hia_chain_pop(ptr %head) {\nentry:\n  %empty = icmp eq ptr %head, null\n  br i1 %empty, label %none, label %some\nnone:\n  ret %hia.chain.result zeroinitializer\nsome:\n  %payload = load %hia.buffer, ptr %head, align 8\n  %tail_slot = getelementptr %hia.chain.node, ptr %head, i32 0, i32 1\n  %tail = load ptr, ptr %tail_slot, align 8\n  call void @free(ptr %head) nobuiltin\n  %r0 = insertvalue %hia.chain.result zeroinitializer, ptr %tail, 0\n  %r1 = insertvalue %hia.chain.result %r0, %hia.buffer %payload, 1\n  %r2 = insertvalue %hia.chain.result %r1, i1 true, 2\n  ret %hia.chain.result %r2\n}\n\n; Explicit loop bounds native stack usage independently of recursive length.\n; Every nonempty payload and node receives one real free; empty payloads do not.\ndefine internal void @__hia_chain_drop(ptr %initial) {\nentry:\n  br label %loop\nloop:\n  %head = phi ptr [ %initial, %entry ], [ %tail, %release_node ]\n  %empty = icmp eq ptr %head, null\n  br i1 %empty, label %done, label %read_node\nread_node:\n  %payload = load %hia.buffer, ptr %head, align 8\n  %payload_ptr = extractvalue %hia.buffer %payload, 0\n  %tail_slot = getelementptr %hia.chain.node, ptr %head, i32 0, i32 1\n  %tail = load ptr, ptr %tail_slot, align 8\n  %has_payload = icmp ne ptr %payload_ptr, null\n  br i1 %has_payload, label %release_payload, label %release_node\nrelease_payload:\n  call void @free(ptr %payload_ptr) nobuiltin\n  br label %release_node\nrelease_node:\n  call void @free(ptr %head) nobuiltin\n  br label %loop\ndone:\n  ret void\n}\n"
SOURCE=r'''
def llvm_module(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    operation=get(w,ROOT_RESULT)
    if operation==0:
        analyze(w)
    elif operation==1:
        header(w)
    elif operation==2:
        prepare_function(w)
    elif operation==3:
        prepare_block(w)
    else:
        fail(w,4294967291)
    return 2

def analyze(w:mutbuf) -> u64:
    functions=field(w,0,K_functions)
    if kind(w,functions)!=5 or count(w,functions)==0 or count(w,functions)>1024:
        return fail(w,4294967291)
    put(w,FUNCTION_COUNT,count(w,functions))
    put(w,HELPER_NEXT,count(w,functions))
    put(w,OUTLINED,0)
    put(w,FEATURES,0)
    put(w,INTRINSICS,0)
    put(w,WRAPPER_COUNT,0)
    fn=first(w,functions)
    index=0
    while fn!=NONE:
        put(w,FUNCS+index*8,fn)
        index=index+1
        export=wrapper_admitted(w,fn)
        setmeta(w,fn,72,export)
        put(w,WRAPPER_COUNT,get(w,WRAPPER_COUNT)+export)
        setmeta(w,fn,80,unread_initialization(w,fn))
        block=first(w,field(w,fn,K_blocks))
        while block!=NONE:
            ins=first(w,field(w,block,K_ops))
            while ins!=NONE:
                op=opcode(w,field(w,ins,K_op))
                if op==0:
                    fail(w,4294967291)
                if (op>=OP_int_add_checked and op<=OP_int_mul_checked) or op==OP_int_neg_checked:
                    action=op-OP_int_add_checked
                    if op==OP_int_neg_checked:
                        action=1
                    typ=typecode(w,field(w,first(w,field(w,ins,K_out)),K_type))
                    n=bits(w,typ)
                    width=0
                    if n==16:
                        width=1
                    elif n==32:
                        width=2
                    elif n==64:
                        width=3
                    sign=choose(signed_type(typ)==1,0,4)
                    put(w,INTRINSICS,get(w,INTRINSICS)|(1<<(action*8+sign+width)))
                if op==OP_buffer_fill or op==OP_buffer_fill_range:
                    put(w,FEATURES,get(w,FEATURES)|1)
                if op==OP_buffer_copy or op==OP_buffer_copy_range:
                    put(w,FEATURES,get(w,FEATURES)|2)
                if op==OP_buffer_move_within:
                    put(w,FEATURES,get(w,FEATURES)|4)
                ins=next(w,ins)
            block=next(w,block)
        fn=next(w,fn)
    if get(w,WRAPPER_COUNT)==0 or get(w,WRAPPER_COUNT)>128:
        return fail(w,4294967289)
    exports=field(w,0,K_exports)
    if exports!=NONE and count(w,exports)!=get(w,WRAPPER_COUNT):
        return fail(w,4294967289)
    return 0

def unread_initialization(w:mutbuf,fn:u64) -> u64:
    p=first(w,field(w,fn,K_params))
    while p!=NONE:
        t=typecode(w,field(w,p,K_type))
        if t==0 or t>12:
            return 1
        p=next(w,p)
    p=first(w,field(w,fn,K_returns))
    while p!=NONE:
        t=typecode(w,p)
        if t==0 or t>12:
            return 1
        p=next(w,p)
    b=first(w,field(w,fn,K_blocks))
    while b!=NONE:
        term=field(w,field(w,b,K_term),K_op)
        if is_text(w,term,"ret")==0 and is_text(w,term,"jump")==0 and is_text(w,term,"branch")==0 and is_text(w,term,"trap")==0:
            return 1
        i=first(w,field(w,b,K_ops))
        while i!=NONE:
            op=opcode(w,field(w,i,K_op))
            if (op<1 or op>OP_select) and (op<OP_buffer_new or op>OP_buffer_len) and (op<OP_owner_move or op>OP_owner_drop):
                return 1
            i=next(w,i)
        b=next(w,b)
    return 0

def prepare_function(w:mutbuf) -> u64:
    fn=get(w,FN)
    blocks=field(w,fn,K_blocks)
    n=count(w,blocks)
    if kind(w,blocks)!=5 or n==0 or n>4096:
        return fail(w,4294967291)
    block=first(w,blocks)
    index=0
    component=get(w,COMPONENT)
    while block!=NONE:
        if component==0 or meta(w,block,112)==component:
            put(w,BLOCKS+index*8,block)
            setmeta(w,block,48,index)
            setmeta(w,block,56,0)
            setmeta(w,block,64,0)
            index=index+1
        block=next(w,block)
    put(w,BLOCK_COUNT,index)
    entry=field(w,fn,K_entry)
    if component!=0:
        entry=field(w,meta(w,fn,component*8),K_id)
    put(w,ENTRY_INDEX,block_index(w,entry))
    put(w,SERIAL,0)
    put(w,EDGE_COUNT,0)
    put(w,ZERO_BYTES,meta(w,fn,80))
    put(w,ORDER_INDEX,0)
    put(w,POS,0)
    put(w,DEST,BODY)
    return 0

def prepare_block(w:mutbuf) -> u64:
    block=get(w,BLOCK)
    bindex=meta(w,block,48)
    put(w,BLOCK_INDEX,bindex)
    setmeta(w,block,56,get(w,POS))
    param=first(w,field(w,block,K_params))
    index=0
    while param!=NONE:
        t=typecode(w,field(w,param,K_type))
        if t==0:
            return fail(w,4294967291)
        setmeta(w,param,0,1)
        setmeta(w,param,8,bindex)
        setmeta(w,param,16,index)
        setmeta(w,param,24,t)
        setmeta(w,param,40,block)
        symbol(w,field(w,param,K_name),param,1)
        index=index+1
        param=next(w,param)
    put(w,INS_NEXT,first(w,field(w,block,K_ops)))
    return 0

def header(w:mutbuf) -> u64:
    emit(w,"; Standalone HIA: verified core -> LLVM. No source AST or Rust safety gate.\n")
    emit(w,"target triple = ")
    if get(w,TARGET)==0:
        emit(w,'"x86_64-unknown-linux-gnu"\n')
    elif get(w,TARGET)==1:
        emit(w,'"aarch64-unknown-linux-gnu"\n')
    else:
        emit(w,'"riscv64-unknown-linux-gnu"\n')
    emit(w,"%hia.buffer = type { ptr, i64 }\n%hia.alloc = type { %hia.buffer, i1 }\n")
    if get(w,VERSION)>=7:
        emit(w,"%hia.chain.node = type { %hia.buffer, ptr }\n%hia.chain.result = type { ptr, %hia.buffer, i1 }\n")
    emit(w,"declare void @abort() noreturn\n")
    emit(w,'declare noalias ptr @calloc(i64, i64) "no-builtins"\n')
    emit(w,'declare noalias ptr @malloc(i64) "no-builtins"\n')
    emit(w,'declare void @free(ptr) "no-builtins"\n')
    if get(w,VERSION)>=9:
        emit(w,"declare i64 @llvm.bswap.i64(i64)\n")
    if (get(w,FEATURES)&1)!=0:
        emit(w,"declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)\n")
    if (get(w,FEATURES)&2)!=0:
        emit(w,"declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1 immarg)\n")
    if (get(w,FEATURES)&4)!=0:
        emit(w,"declare void @llvm.memmove.p0.p0.i64(ptr, ptr, i64, i1 immarg)\n")
    if (get(w,FEATURES)&16)!=0:
        emit(w,"declare <2 x i64> @llvm.x86.sse2.psad.bw(<16 x i8>, <16 x i8>)\n")
    intrinsic_declarations(w)
    buffer_runtime(w)
    emit(w,"\n")
    if get(w,VERSION)>=7:
        chain_runtime(w)
    return 0
'''

def source_program():
    text=SOURCE
    for name,value in [('buffer_runtime',BUFFER_RUNTIME),('chain_runtime',CHAIN_RUNTIME)]:
        text+='\ndef '+name+'(w:mutbuf) -> u64:\n    emit(w,'+repr(value)+')\n    return 0\n'
    text+='\ndef intrinsic_declarations(w:mutbuf) -> u64:\n'
    records=[]
    for ai,action in enumerate(('add','sub','mul')):
        for si,sign in enumerate(('s','u')):
            for bi,bits in enumerate((8,16,32,64)):
                name='llvm.'+sign+action+'.with.overflow.i'+str(bits)
                records.append((name,ai*8+si*4+bi,bits))
    for name,index,bits in sorted(records):
        line='declare { i'+str(bits)+', i1 } @'+name+'(i'+str(bits)+', i'+str(bits)+')\n'
        text+='    if (get(w,INTRINSICS)&'+str(1<<index)+')!=0:\n        emit(w,'+repr(line)+')\n'
    text+='    return 0\n'
    return text+'\n'+FLOW_SOURCE

if __name__=='__main__':
    write_module('program_llvm_module',source_program(),'llvm_module')
