"""Pure native successful-Clang receipt formatting with exact original fields.

All observations are fixed-role outer state. This module reads no filesystem,
runs no tool, grants no verification authority, and has no callback transport.
Development oracle compares the original return expression independently.
"""
from pathlib import Path
from tools import generate_hia_clang_compile_common as base
ROOT=Path(__file__).resolve().parents[1]
C={"RR_BAD":4294967293,"RR_SHORT":4294967294,"L_PREFIX":0,"L_X86":1,"L_ARM":2,"L_RISCV":3,"L_BULK":4,"L_OVERLAP":5,"L_BSWAP":6,"L_OFFSET":7,"L_FILL":8,"L_RECURSIVE":9,"L_LOANS":10,"L_WORDS":11,"L_OBJECT_SUFFIX":12,"L_VERSION_SUFFIX":13,"L_TARGET_FIELD":14,"L_TARGET_X86":15,"L_TARGET_ARM":16,"L_TARGET_RISCV":17,"L_LAYOUT_FIELD":18,"L_CANONICAL":19,"L_OUTLINE":20,"L_KIND_FIELD":21,"L_SHARED":22,"L_OBJECT":23,"L_OUTPUT_FIELD":24,"L_CORE_FIELD":25,"L_HOST_BEGIN":26,"L_NORMALIZED_FIELD":27,"L_HOST_X86":28,"L_HOST_ARM":29,"L_TARGET_KEY":30,"L_HOST_X86_ABI":31,"L_HOST_ARM_ABI":32,"L_HOST_END":33,"L_TRUE":34,"L_FALSE":35,"L_INPUT_FIELD":36,"L_NULL":37,"L_IR_FIELD":38,"L_IMPL_FIELD":39,"L_ARTIFACT_FIELD":40,"L_ARTIFACT_N":41,"L_EXPORTS":42,"L_INVENTORY_SHARED":43,"L_UNRESOLVED":44,"L_INVENTORY_SHARED_END":45,"L_INVENTORY_OBJECT":46,"L_UNDEFINED":47,"L_CLOSE_OBJECT":48,"L_ASSUMPTIONS":49,"L_INVOCATION":50,"L_MULTICALL":51,"L_TOOL_SHA":52,"L_TOOL_VERSION":53,"L_DEFAULT_TARGET":54,"L_FLAGS":55,"L_FLAG_TARGET_X86":56,"L_FLAG_TARGET_ARM":57,"L_FLAG_TARGET_RISCV":58,"L_FLAGS_COMMON":59,"L_FLAG_SHARED":60,"L_FLAG_OBJECT":61,"L_FLAGS_RISCV":62,"L_CLAIMS":63}
C.update(RR_INVENTORY=int.from_bytes(b'HIAINV01','little'),RR_POS=(283<<20),RR_MODE=(283<<20)+8,RR_ERROR=(283<<20)+16,RR_VERSION_N=(283<<20)+24,RR_DRIVER_AT=(283<<20)+32,RR_DRIVER_N=(283<<20)+40,RR_MACHINE_N=(283<<20)+48,RR_IMPORT_AT=(283<<20)+56)
LITERALS=["{\"schema\":\"hepta.hia.program.native.v1\",\"ok\":true,\"status\":\"native_compiled_not_executed\",\"profile\":\"hepta.hia.program.llvm-linux-","x86_64","aarch64","riscv64-lp64d-object","-bulk","-overlap","-byte-swap","-offset-copy","-range-fill","-recursive-chain","-parameter-loan-returns","-word-memory","-object",".v","\",\"target\":","\"x86_64-unknown-linux-gnu\"","\"aarch64-unknown-linux-gnu\"","\"riscv64-unknown-linux-gnu\"",",\"entry_layout\":","\"canonical\"","\"guarded-outline-v1\"",",\"kind\":","\"shared\"","\"object\"",",\"output\":",",\"core_sha256\":",",\"build_host\":{\"system\":\"Linux\",\"machine\":",",\"normalized_machine\":","\"x86_64\"","\"aarch64\"",",\"target\":",",\"elf_machine\":62,\"abi\":\"SysV AMD64 LP64\"",",\"elf_machine\":183,\"abi\":\"AAPCS64 LP64\"",",\"byteorder\":\"little\",\"pointer_bits\":64,\"size_t_bits\":64,\"long_bits\":64},\"cross_target_compilation\":","true","false",",\"input_sha256\":","null",",\"llvm_ir_sha256\":",",\"implementation_sha256\":",",\"artifact_sha256\":",",\"artifact_bytes\":",",\"exports\":",",\"binary_inventory\":{\"schema\":\"hepta.elf-shared-abi.v1\",\"format\":\"ELF64\",\"machine\":62,\"kind\":\"ET_DYN\",\"dynamic_exports\":",",\"unresolved_imports\":",",\"source_exports_rechecked\":true,\"claims\":{\"binary_abi_observed\":true,\"native_execution_proven\":false,\"whole_language_memory_safety_proven\":false,\"backend_refinement_proven\":false}}",",\"binary_inventory\":{\"defined\":",",\"undefined\":","}",",\"external_abi\":\"scalar-only C functions; resource and multiple-result functions are internal\",\"runtime_assumptions\":[\"Linux LP64 target with 64-bit pointers and size_t\",\"C calloc returns null or an initialized nonaliasing allocation of the requested size\",\"C malloc returns null or a fresh nonaliasing allocation of the requested size; bytes are initialized before read or remain unobserved\",\"C free accepts a live allocation from calloc or malloc, or null\",\"abort terminates execution; no cleanup after traps is promised\",\"native compiler, linker, loader, libc and host hardware are trusted\"],\"toolchain\":{\"path\":",",\"invocation\":[",",\"clang\"","],\"sha256\":",",\"version\":",",\"default_target\":","},\"flags\":[","\"--target=x86_64-unknown-linux-gnu\"","\"--target=aarch64-unknown-linux-gnu\"","\"--target=riscv64-unknown-linux-gnu\"",",\"-x\",\"ir\",\"-O3\",\"-fPIC\",","\"-shared\"","\"-c\"",",\"-march=rv64gc\",\"-mabi=lp64d\"","],\"claims\":{\"standalone_core_reverified\":true,\"source_ast_required\":false,\"rust_reference_required\":false,\"rust_codegen_used\":false,\"c_codegen_used\":false,\"fallback_used\":false,\"native_execution_qualified\":false,\"backend_refinement_proved\":false,\"cross_target_execution_qualified\":false,\"whole_language_soundness_proved\":false,\"foreign_buffer_entrypoints_exposed\":false}}"]
SOURCE=r'''
def receipt(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)!=P_WORK or length(o)>1048576:
        return RR_BAD
    clear(w,RR_POS,4096)
    if validate(s,w)==False:
        return RR_BAD
    emit(s,o,w)
    if get(w,RR_ERROR)==1:
        return RR_BAD
    n=get(w,RR_POS)
    if get(w,RR_ERROR)==2 or n>length(o):
        return RR_SHORT
    put(w,RR_POS,0)
    put(w,RR_MODE,1)
    emit(s,o,w)
    if get(w,RR_ERROR)!=0 or get(w,RR_POS)!=n:
        return RR_BAD
    return n

def validate(s:readbuf,w:mutbuf) -> bool:
    if get(w,ERROR)!=0 or get(w,P_SCHEMA)<1 or get(w,P_SCHEMA)>9:
        return False
    if get(w,P_TARGET)>2 or get(w,P_HOST)>1 or get(w,P_KIND)>1:
        return False
    if get(w,P_LAYOUT)>1 or get(w,P_MULTICALL)>1 or get(w,P_INPUT_HASH_PRESENT)>1:
        return False
    if get(w,P_TARGET)!=0 and (get(w,P_KIND)==0 or get(w,P_LAYOUT)!=0):
        return False
    if get(w,P_KIND)==0 and get(w,P_HOST)!=0:
        return False
    if get(w,P_ART_N)<64 or get(w,P_ART_N)>67108864:
        return False
    if path_valid(s,get(w,P_COMPILER_OFF),get(w,P_COMPILER_N))==False:
        return False
    if path_valid(s,get(w,P_DEST_OFF),get(w,P_DEST_N))==False:
        return False
    if metadata_valid(w)==False or inventory_valid(s,w)==False:
        return False
    if host_valid(w)==False or streams_valid(w)==False:
        return False
    return True

def span_s(s:readbuf,at:u64,n:u64) -> bool:
    if at>length(s):
        return False
    return n<=length(s)-at

def path_valid(s:readbuf,at:u64,n:u64) -> bool:
    if n==0 or span_s(s,at,n)==False:
        return False
    if byte(s,at)!=47:
        return False
    i=0
    while i<n:
        if byte(s,at+i)==0:
            return False
        i=i+1
    return True

def metadata_valid(w:mutbuf) -> bool:
    n=get(w,P_META_N)
    if n<64 or n>65536:
        return False
    if get(w,P_META)!=META_REPLY or get(w,P_META+8)!=get(w,P_SCHEMA):
        return False
    if get(w,P_META+16)!=get(w,P_TARGET) or get(w,P_META+24)!=get(w,P_LAYOUT):
        return False
    if get(w,P_META+32)>128 or get(w,P_META+48)!=n-64 or get(w,P_META+56)!=0:
        return False
    if get(w,P_IR_N)==0 or get(w,P_IR_N)>16777216 or get(w,P_META+40)!=get(w,P_IR_N):
        return False
    at=P_META+64
    end=P_META+n
    i=0
    previous=0
    previous_n=0
    while i<get(w,P_META+32):
        if at>end or end-at<8:
            return False
        size=get(w,at)
        at=at+8
        if size==0 or size>end-at:
            return False
        j=0
        while j<size:
            c=byte(w,at+j)
            if ident(c,j==0)==False:
                return False
            j=j+1
        if i!=0 and compare_w(w,previous,previous_n,at,size)!=1:
            return False
        previous=at
        previous_n=size
        at=at+size
        i=i+1
    return at==end

def inventory_valid(s:readbuf,w:mutbuf) -> bool:
    start=get(w,P_INV_OFF)
    n=get(w,P_INV_N)
    if n<64 or span_s(s,start,n)==False:
        return False
    end=start+n
    if word(s,start)!=RR_INVENTORY or word(s,start+24)!=n:
        return False
    exports=word(s,start+8)
    imports=word(s,start+16)
    if exports!=get(w,P_META+32) or exports>(n-64)//9 or imports>(n-64)//9:
        return False
    i=32
    while i<64:
        if word(s,start+i)!=0:
            return False
        i=i+8
    at=start+64
    after=symbols_s(s,at,end,exports)
    if after==0:
        return False
    put(w,RR_IMPORT_AT,after)
    if symbols_s(s,after,end,imports)!=end:
        return False
    i=0
    m=P_META+64
    while i<exports:
        size=word(s,at)
        if size!=get(w,m):
            return False
        at=at+8
        m=m+8
        j=0
        while j<size:
            if byte(s,at+j)!=byte(w,m+j):
                return False
            j=j+1
        at=at+size
        m=m+size
        i=i+1
    return True

def symbols_s(s:readbuf,at:u64,end:u64,count:u64) -> u64:
    i=0
    previous=0
    previous_n=0
    while i<count:
        if at>end or end-at<8:
            return 0
        n=word(s,at)
        at=at+8
        if n==0 or n>end-at:
            return 0
        j=0
        while j<n:
            c=byte(s,at+j)
            if c==0 or c>127:
                return 0
            j=j+1
        if i!=0 and compare_s(s,previous,previous_n,at,n)!=1:
            return 0
        previous=at
        previous_n=n
        at=at+n
        i=i+1
    return at

def ident(c:u64,first:bool) -> bool:
    if c==95 or (c>=65 and c<=90) or (c>=97 and c<=122):
        return True
    return first==False and c>=48 and c<=57

def compare_s(s:readbuf,a:u64,an:u64,b:u64,bn:u64) -> u64:
    i=0
    while i<an and i<bn:
        x=byte(s,a+i)
        y=byte(s,b+i)
        if x<y:
            return 1
        if x>y:
            return 2
        i=i+1
    if an<bn:
        return 1
    if an>bn:
        return 2
    return 0

def compare_w(w:mutbuf,a:u64,an:u64,b:u64,bn:u64) -> u64:
    i=0
    while i<an and i<bn:
        x=byte(w,a+i)
        y=byte(w,b+i)
        if x<y:
            return 1
        if x>y:
            return 2
        i=i+1
    if an<bn:
        return 1
    if an>bn:
        return 2
    return 0

def streams_valid(w:mutbuf) -> bool:
    n=get(w,P_VERSION_N)
    if n==0 or n>196608:
        return False
    i=0
    first=n
    found=False
    while i<n:
        d=decode_w(w,P_VERSION+i,P_VERSION+n,False)
        if d==0:
            return False
        c=d&4294967295
        if found==False and linebreak(c):
            first=i
            found=True
        i=i+(d>>32)
    put(w,RR_VERSION_N,first)
    n=get(w,P_DRIVER_N)
    if n==0 or n>196608:
        return False
    i=0
    start=n
    end=0
    while i<n:
        d=decode_w(w,P_DRIVER+i,P_DRIVER+n,False)
        if d==0:
            return False
        c=d&4294967295
        step=d>>32
        if whitespace(c)==False:
            if start==n:
                start=i
            end=i+step
        i=i+step
    if end==0:
        return False
    put(w,RR_DRIVER_AT,P_DRIVER+start)
    put(w,RR_DRIVER_N,end-start)
    return True

def lower(c:u64) -> u64:
    if c>=65 and c<=90:
        return c+32
    return c

def linebreak(c:u64) -> bool:
    if c>=10 and c<=13:
        return True
    if c>=28 and c<=30:
        return True
    return c==133 or c==8232 or c==8233

def whitespace(c:u64) -> bool:
    if c>=9 and c<=13:
        return True
    if c>=28 and c<=32:
        return True
    if c==133 or c==160 or c==5760:
        return True
    if c>=8192 and c<=8202:
        return True
    return c==8232 or c==8233 or c==8239 or c==8287 or c==12288

def emit(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    lit(o,w,L_PREFIX)
    target=get(w,P_TARGET)
    schema=get(w,P_SCHEMA)
    if target==2:
        lit(o,w,L_RISCV)
    else:
        if target==0:
            lit(o,w,L_X86)
        else:
            lit(o,w,L_ARM)
        if schema==2:
            lit(o,w,L_BULK)
        elif schema==3:
            lit(o,w,L_OVERLAP)
        elif schema==4:
            lit(o,w,L_BSWAP)
        elif schema==5:
            lit(o,w,L_OFFSET)
        elif schema==6:
            lit(o,w,L_FILL)
        elif schema==7:
            lit(o,w,L_RECURSIVE)
        elif schema==8:
            lit(o,w,L_LOANS)
        elif schema==9:
            lit(o,w,L_WORDS)
        if target==1:
            lit(o,w,L_OBJECT_SUFFIX)
    lit(o,w,L_VERSION_SUFFIX)
    decimal(o,w,schema)
    lit(o,w,L_TARGET_FIELD)
    target_name(o,w,target)
    lit(o,w,L_LAYOUT_FIELD)
    if get(w,P_LAYOUT)==0:
        lit(o,w,L_CANONICAL)
    else:
        lit(o,w,L_OUTLINE)
    lit(o,w,L_KIND_FIELD)
    if get(w,P_KIND)==0:
        lit(o,w,L_SHARED)
    else:
        lit(o,w,L_OBJECT)
    lit(o,w,L_OUTPUT_FIELD)
    text_s(s,o,w,get(w,P_DEST_OFF),get(w,P_DEST_N),True)
    lit(o,w,L_CORE_FIELD)
    digest(o,w,P_CORE_SHA)
    lit(o,w,L_HOST_BEGIN)
    text_w(o,w,P_UNAME+260,get(w,RR_MACHINE_N),True)
    lit(o,w,L_NORMALIZED_FIELD)
    if get(w,P_HOST)==0:
        lit(o,w,L_HOST_X86)
    else:
        lit(o,w,L_HOST_ARM)
    lit(o,w,L_TARGET_KEY)
    target_name(o,w,get(w,P_HOST))
    if get(w,P_HOST)==0:
        lit(o,w,L_HOST_X86_ABI)
    else:
        lit(o,w,L_HOST_ARM_ABI)
    lit(o,w,L_HOST_END)
    if target!=get(w,P_HOST):
        lit(o,w,L_TRUE)
    else:
        lit(o,w,L_FALSE)
    lit(o,w,L_INPUT_FIELD)
    if get(w,P_INPUT_HASH_PRESENT)==0:
        lit(o,w,L_NULL)
    else:
        digest(o,w,P_INPUT_SHA)
    lit(o,w,L_IR_FIELD)
    digest(o,w,P_IR_SHA)
    lit(o,w,L_IMPL_FIELD)
    digest(o,w,P_IMPL_SHA)
    lit(o,w,L_ARTIFACT_FIELD)
    digest(o,w,P_ART_SHA)
    lit(o,w,L_ARTIFACT_N)
    decimal(o,w,get(w,P_ART_N))
    lit(o,w,L_EXPORTS)
    names_w(o,w,P_META+64,get(w,P_META+32))
    start=get(w,P_INV_OFF)
    if get(w,P_KIND)==0:
        lit(o,w,L_INVENTORY_SHARED)
        names_s(s,o,w,start+64,word(s,start+8))
        lit(o,w,L_UNRESOLVED)
        names_s(s,o,w,get(w,RR_IMPORT_AT),word(s,start+16))
        lit(o,w,L_INVENTORY_SHARED_END)
    else:
        lit(o,w,L_INVENTORY_OBJECT)
        names_s(s,o,w,start+64,word(s,start+8))
        lit(o,w,L_UNDEFINED)
        names_s(s,o,w,get(w,RR_IMPORT_AT),word(s,start+16))
        lit(o,w,L_CLOSE_OBJECT)
    lit(o,w,L_ASSUMPTIONS)
    text_s(s,o,w,get(w,P_COMPILER_OFF),get(w,P_COMPILER_N),True)
    lit(o,w,L_INVOCATION)
    text_s(s,o,w,get(w,P_COMPILER_OFF),get(w,P_COMPILER_N),True)
    if get(w,P_MULTICALL)!=0:
        lit(o,w,L_MULTICALL)
    lit(o,w,L_TOOL_SHA)
    digest(o,w,P_TOOL_SHA)
    lit(o,w,L_TOOL_VERSION)
    text_w(o,w,P_VERSION,get(w,RR_VERSION_N),False)
    lit(o,w,L_DEFAULT_TARGET)
    text_w(o,w,get(w,RR_DRIVER_AT),get(w,RR_DRIVER_N),False)
    lit(o,w,L_FLAGS)
    if target==0:
        lit(o,w,L_FLAG_TARGET_X86)
    elif target==1:
        lit(o,w,L_FLAG_TARGET_ARM)
    else:
        lit(o,w,L_FLAG_TARGET_RISCV)
    lit(o,w,L_FLAGS_COMMON)
    if get(w,P_KIND)==0:
        lit(o,w,L_FLAG_SHARED)
    else:
        lit(o,w,L_FLAG_OBJECT)
    if target==2:
        lit(o,w,L_FLAGS_RISCV)
    lit(o,w,L_CLAIMS)
    return 0

def target_name(o:mutbuf,w:mutbuf,target:u64) -> u64:
    if target==0:
        return lit(o,w,L_TARGET_X86)
    if target==1:
        return lit(o,w,L_TARGET_ARM)
    return lit(o,w,L_TARGET_RISCV)

def names_s(s:readbuf,o:mutbuf,w:mutbuf,at:u64,count:u64) -> u64:
    emit_byte(o,w,91)
    i=0
    while i<count:
        if i!=0:
            emit_byte(o,w,44)
        n=word(s,at)
        at=at+8
        text_s(s,o,w,at,n,False)
        at=at+n
        i=i+1
    emit_byte(o,w,93)
    return 0

def names_w(o:mutbuf,w:mutbuf,at:u64,count:u64) -> u64:
    emit_byte(o,w,91)
    i=0
    while i<count:
        if i!=0:
            emit_byte(o,w,44)
        n=get(w,at)
        at=at+8
        text_w(o,w,at,n,False)
        at=at+n
        i=i+1
    emit_byte(o,w,93)
    return 0

def digest(o:mutbuf,w:mutbuf,at:u64) -> u64:
    emit_byte(o,w,34)
    i=0
    while i<32:
        c=byte(w,at+i)
        emit_byte(o,w,hex_digit(c>>4))
        emit_byte(o,w,hex_digit(c&15))
        i=i+1
    emit_byte(o,w,34)
    return 0

def decimal(o:mutbuf,w:mutbuf,value:u64) -> u64:
    divisor=1
    while value//divisor>=10:
        divisor=divisor*10
    while divisor>0:
        emit_byte(o,w,48+(value//divisor)%10)
        divisor=divisor//10
    return 0

def text_s(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64,fs:bool) -> u64:
    emit_byte(o,w,34)
    i=0
    while i<n and get(w,RR_ERROR)==0:
        d=decode_s(s,at+i,at+n,fs)
        if d==0:
            put(w,RR_ERROR,1)
            return 0
        codepoint(o,w,d&4294967295)
        i=i+(d>>32)
    emit_byte(o,w,34)
    return 0

def text_w(o:mutbuf,w:mutbuf,at:u64,n:u64,fs:bool) -> u64:
    emit_byte(o,w,34)
    i=0
    while i<n and get(w,RR_ERROR)==0:
        d=decode_w(w,at+i,at+n,fs)
        if d==0:
            put(w,RR_ERROR,1)
            return 0
        codepoint(o,w,d&4294967295)
        i=i+(d>>32)
    emit_byte(o,w,34)
    return 0

def codepoint(o:mutbuf,w:mutbuf,c:u64) -> u64:
    if c>=32 and c<127:
        if c==34 or c==92:
            emit_byte(o,w,92)
        return emit_byte(o,w,c)
    if c<=65535:
        return hex_escape(o,w,c)
    c=c-65536
    hex_escape(o,w,55296+(c>>10))
    return hex_escape(o,w,56320+(c&1023))

def hex_escape(o:mutbuf,w:mutbuf,c:u64) -> u64:
    emit_byte(o,w,92)
    emit_byte(o,w,117)
    emit_byte(o,w,hex_digit((c>>12)&15))
    emit_byte(o,w,hex_digit((c>>8)&15))
    emit_byte(o,w,hex_digit((c>>4)&15))
    emit_byte(o,w,hex_digit(c&15))
    return 0

def hex_digit(c:u64) -> u64:
    if c<10:
        return 48+c
    return 87+c

def emit_byte(o:mutbuf,w:mutbuf,c:u64) -> u64:
    if get(w,RR_ERROR)!=0:
        return 0
    at=get(w,RR_POS)
    if at>=1048576:
        put(w,RR_ERROR,2)
        return 0
    if get(w,RR_MODE)!=0:
        if at>=length(o):
            put(w,RR_ERROR,2)
            return 0
        store(o,at,c)
    put(w,RR_POS,at+1)
    return 0

def host_valid(w:mutbuf) -> bool:
    if byte(w,P_UNAME)!=76 or byte(w,P_UNAME+1)!=105 or byte(w,P_UNAME+2)!=110:
        return False
    if byte(w,P_UNAME+3)!=117 or byte(w,P_UNAME+4)!=120 or byte(w,P_UNAME+5)!=0:
        return False
    n=0
    while n<65 and byte(w,P_UNAME+260+n)!=0:
        n=n+1
    if n==0 or n==65:
        return False
    put(w,RR_MACHINE_N,n)
    if get(w,P_HOST)==0:
        if n==6:
            if lower(byte(w,P_UNAME+260))!=120:
                return False
            if lower(byte(w,P_UNAME+261))!=56:
                return False
            if lower(byte(w,P_UNAME+262))!=54:
                return False
            if lower(byte(w,P_UNAME+263))!=95:
                return False
            if lower(byte(w,P_UNAME+264))!=54:
                return False
            if lower(byte(w,P_UNAME+265))!=52:
                return False
            return True
        if n==5:
            if lower(byte(w,P_UNAME+260))!=97:
                return False
            if lower(byte(w,P_UNAME+261))!=109:
                return False
            if lower(byte(w,P_UNAME+262))!=100:
                return False
            if lower(byte(w,P_UNAME+263))!=54:
                return False
            if lower(byte(w,P_UNAME+264))!=52:
                return False
            return True
        return False
    if get(w,P_HOST)==1:
        if n==7:
            if lower(byte(w,P_UNAME+260))!=97:
                return False
            if lower(byte(w,P_UNAME+261))!=97:
                return False
            if lower(byte(w,P_UNAME+262))!=114:
                return False
            if lower(byte(w,P_UNAME+263))!=99:
                return False
            if lower(byte(w,P_UNAME+264))!=104:
                return False
            if lower(byte(w,P_UNAME+265))!=54:
                return False
            if lower(byte(w,P_UNAME+266))!=52:
                return False
            return True
        if n==5:
            if lower(byte(w,P_UNAME+260))!=97:
                return False
            if lower(byte(w,P_UNAME+261))!=114:
                return False
            if lower(byte(w,P_UNAME+262))!=109:
                return False
            if lower(byte(w,P_UNAME+263))!=54:
                return False
            if lower(byte(w,P_UNAME+264))!=52:
                return False
            return True
        return False
    return False

def decode_s(s:readbuf,at:u64,end:u64,fs:bool) -> u64:
    a=byte(s,at)
    if a<128:
        return 4294967296+a
    need=0
    low=128
    high=191
    cp=0
    if a>=194 and a<=223:
        need=1
        cp=a&31
    elif a>=224 and a<=239:
        need=2
        cp=a&15
        if a==224:
            low=160
        if a==237:
            high=159
    elif a>=240 and a<=244:
        need=3
        cp=a&7
        if a==240:
            low=144
        if a==244:
            high=143
    valid=need!=0 and end-at>need
    if valid:
        b=byte(s,at+1)
        if b<low or b>high:
            valid=False
        j=1
        while j<=need:
            b=byte(s,at+j)
            if b<128 or b>191:
                valid=False
            cp=(cp<<6)|(b&63)
            j=j+1
    if valid:
        return ((need+1)<<32)|cp
    if fs:
        return 4294967296+56320+a
    return 0

def decode_w(w:mutbuf,at:u64,end:u64,fs:bool) -> u64:
    a=byte(w,at)
    if a<128:
        return 4294967296+a
    need=0
    low=128
    high=191
    cp=0
    if a>=194 and a<=223:
        need=1
        cp=a&31
    elif a>=224 and a<=239:
        need=2
        cp=a&15
        if a==224:
            low=160
        if a==237:
            high=159
    elif a>=240 and a<=244:
        need=3
        cp=a&7
        if a==240:
            low=144
        if a==244:
            high=143
    valid=need!=0 and end-at>need
    if valid:
        b=byte(w,at+1)
        if b<low or b>high:
            valid=False
        j=1
        while j<=need:
            b=byte(w,at+j)
            if b<128 or b>191:
                valid=False
            cp=(cp<<6)|(b&63)
            j=j+1
    if valid:
        return ((need+1)<<32)|cp
    if fs:
        return 4294967296+56320+a
    return 0
'''
def literal_program():
    rows=['def lit(o:mutbuf,w:mutbuf,which:u64) -> u64:',
          '    if get(w,RR_ERROR)!=0:','        return 0']
    groups=(len(LITERALS)+15)//16
    for group in range(groups):
        rows.extend([f'    if which<{min((group+1)*16,len(LITERALS))}:',
                     f'        return lit_{group}(o,w,which)'])
    rows.extend(['    put(w,RR_ERROR,1)','    return 0'])
    for group in range(groups):
        rows.extend(['',f'def lit_{group}(o:mutbuf,w:mutbuf,which:u64) -> u64:',
                     '    at=get(w,RR_POS)'])
        for i in range(group*16,min((group+1)*16,len(LITERALS))):
            raw=LITERALS[i].encode('ascii');n=len(raw)
            rows.extend([f'    if which=={i}:',f'        if at>1048576-{n}:','            put(w,RR_ERROR,2)','            return 0',
                         '        if get(w,RR_MODE)!=0:',f'            if at>length(o) or {n}>length(o)-at:',
                         '                put(w,RR_ERROR,2)','                return 0'])
            j=0
            while j+8<=n:
                rows.append(f'            word_store(o,at+{j},{int.from_bytes(raw[j:j+8],"little")})');j+=8
            while j<n:
                rows.append(f'            store(o,at+{j},{raw[j]})');j+=1
            rows.extend([f'        put(w,RR_POS,at+{n})','        return 0'])
        rows.extend(['    put(w,RR_ERROR,1)','    return 0'])
    return '\n'.join(rows)
def source_program():
    return SOURCE+'\n'+literal_program()
def main():
    base.capture.C.update(C)
    return base.write_module('clang_compile_receipt',source_program(),'receipt')
if __name__=='__main__':main()
