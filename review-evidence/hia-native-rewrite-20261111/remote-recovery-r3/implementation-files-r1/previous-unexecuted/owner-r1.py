"""Native implementation-file fingerprint continuation.

The HIA owner selects the exact original ordered twenty names, issues every
open/read/close, and feeds actual file bytes to the independent HIA SHA stream.
The fixed carrier performs only bounded-view and raw descriptor mechanics.
NEW SOURCE ONLY: no AST, generation, compilation or execution is claimed.
"""
import ast,copy
COMMON_SHA="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
REFERENCE_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
FILES=(
 "hia_schema.py","hia_program.py","hia_capability_flow.py","hia_opcodes.py",
 "hia_json_preflight.py","hia_program_composite.py","hia_program_native.py",
 "hia_machine_x64.py","hia_machine_elf.py","hia_machine_plan.py","hia_native_byte_abi.py",
 "hia_agent_exec.py","hia_static_budget.py","hia_heap_bound.py","artifact_publication.py",
 "clang_capture.py","elf_shared_abi.py","object_symbols.py","object_structure.py",
 "native_tool_identity.py")
def magic(text):return int.from_bytes(text.encode("ascii"),"little")
CONSTANTS=dict(LOWER_MAGIC=magic("HIAIFS01"),INIT=magic("HIAIFI01"),RESULT=magic("HIAIFR01"),
 MIN_WORK=65536,DRIVER=1,I_HASH=2,CHUNK=65536,HASH_MAX=(1<<61)-1,
 B_PATH=4,B_CHUNK=5,B_HASH_INPUT=6,B_HASH_OUTPUT=7,B_HASH_STATE=8,B_RESULT=9,
 NAME_AT=20000,RESULT_AT=20128)
_FIELDS=("REQUEST","ROOT_N","SEPARATOR","NAME_N","PATH_N","INDEX","FILE_LIVE",
 "FILE_BYTES","ALL_BYTES","HASH_BYTES","ERROR_OP","ERROR_NO","CLOSE_ERROR",
 "ERROR_INDEX","HASH_SOURCE","HASH_AT","HASH_N","HASH_AFTER","READ_N","FILES_DONE")
CONSTANTS.update({"F_"+name:16000+8*i for i,name in enumerate(_FIELDS)})
BODY=r'''
def implementation_files(s:readbuf,o:mutbuf,w:mutbuf)->u32:
    if length(o) < 128 or length(w) < MIN_WORK:
        return ABI
    if get(w,L_MAGIC) == 0:
        if files_begin(s,w) == 0:
            return refuse(w,4000)
    elif files_ack(s,w) == 0:
        return refuse(w,4001)
    result = 0
    while result == 0:
        if get(w,L_STATUS) != 1:
            return refuse(w,4002)
        phase = get(w,C_PHASE)
        if phase >= 100 and phase < 110:
            result = files_update(o,w)
        else:
            result = files_step(o,w,phase)
    return result

def files_begin(s:readbuf,w:mutbuf)->u64:
    if length(s) < 64 or word(s,0) != INIT or word(s,8) != 1:
        return 0
    if word(s,16) == 0 or word(s,24) == 0 or word(s,32) != 64:
        return 0
    size = word(s,40)
    if size != length(s)-64 or word(s,48) != length(s) or word(s,56) != 0:
        return 0
    i = 0
    while i < size:
        if byte(s,64+i) == 0:
            return 0
        i = i + 1
    if size > MAX-128:
        return 0
    zero(w,0,MIN_WORK)
    put(w,L_MAGIC,LOWER_MAGIC)
    put(w,L_STATUS,1)
    put(w,L_DRIVER,DRIVER)
    put(w,C_LEASE,word(s,16))
    put(w,F_REQUEST,word(s,24))
    put(w,F_ROOT_N,size)
    if size != 0 and byte(s,63+size) != 47:
        put(w,F_SEPARATOR,1)
    put(w,CAPS,0)
    put(w,CAPS+8,length(s))
    put(w,CAPS+16,MIN_WORK)
    put(w,CAPS+24,128)
    put(w,C_PHASE,1)
    return 1

def files_ack(s:readbuf,w:mutbuf)->u64:
    if get(w,L_MAGIC) != LOWER_MAGIC or get(w,L_STATUS) != 1 or get(w,L_DRIVER) != DRIVER:
        return 0
    pending = get(w,C_PENDING)
    if pending != 19:
        return acknowledge(s,w,DRIVER)
    if length(s) != 64 or get(w,C_OBSERVE) != 0:
        return 0
    if word(s,0) != ACK_MAGIC or word(s,8) != get(w,C_LEASE) or word(s,16) != get(w,C_SEQUENCE):
        return 0
    if word(s,24) != 19 or word(s,32) != 0 or word(s,48) != 0 or word(s,56) != 0:
        return 0
    phase = get(w,C_NEXT)
    operation = get(w,ARGS)
    if operation == 1:
        if phase != 31 or get(w,C_PHASE) != 30 or get(w,F_FILE_LIVE) != 0:
            return 0
    elif operation == 2:
        if phase != 33 or get(w,C_PHASE) != 32 or get(w,F_FILE_LIVE) != 1:
            return 0
    elif operation == 3:
        if phase != 41 or get(w,C_PHASE) != 40 or get(w,F_FILE_LIVE) != 1:
            return 0
    else:
        return 0
    put(w,C_RETURN,word(s,40))
    put(w,C_PENDING,0)
    put(w,C_PHASE,phase)
    return 1

def files_phase(w:mutbuf,phase:u64)->u64:
    put(w,C_PHASE,phase)
    return 0

def files_errno(value:u64)->u64:
    if value >= MAX-4094:
        return MAX-value+1
    return 0

def files_sys(o:mutbuf,w:mutbuf,operation:u64,phase:u64)->u64:
    put(w,C_OBSERVE,0)
    if operation == 1:
        args(w,1,B_PATH,0,get(w,F_PATH_N),524288,0,0,0,0,0,0,0)
    elif operation == 2:
        args(w,2,1,B_CHUNK,0,CHUNK,0,0,0,0,0,0,0)
    elif operation == 3:
        args(w,3,1,0,0,0,0,0,0,0,0,0,0)
    else:
        return refuse(w,4003)
    return event(o,w,19,phase)

def files_hash_command(w:mutbuf,source:u64,at:u64,size:u64,after:u64)->u64:
    if size > CHUNK or inside(w,source,at,size) == 0:
        return refuse(w,4004)
    if get(w,F_HASH_BYTES) > HASH_MAX or size > HASH_MAX-get(w,F_HASH_BYTES):
        return refuse(w,4005)
    put(w,F_HASH_SOURCE,source)
    put(w,F_HASH_AT,at)
    put(w,F_HASH_N,size)
    put(w,F_HASH_AFTER,after)
    return files_phase(w,100)

def files_update(o:mutbuf,w:mutbuf)->u64:
    phase = get(w,C_PHASE)
    if phase == 100:
        return protect(o,w,B_HASH_INPUT,0,101)
    if phase == 101:
        store(w,WIRE,1)
        return copy(o,w,2,WIRE,B_HASH_INPUT,0,1,102)
    if phase == 102:
        return copy(o,w,get(w,F_HASH_SOURCE),get(w,F_HASH_AT),B_HASH_INPUT,1,get(w,F_HASH_N),103)
    if phase == 103:
        return protect(o,w,B_HASH_INPUT,1,104)
    if phase == 104:
        return invoke(o,w,I_HASH,B_HASH_INPUT,0,get(w,F_HASH_N)+1,B_HASH_OUTPUT,32,
            B_HASH_STATE,1184,B_HASH_OUTPUT,0,0,105)
    if phase == 105:
        if get(w,C_RETURN) != 0:
            return refuse(w,4006)
        put(w,F_HASH_BYTES,get(w,F_HASH_BYTES)+get(w,F_HASH_N))
        return files_phase(w,get(w,F_HASH_AFTER))
    return refuse(w,4007)

def files_error(w:mutbuf,operation:u64,number:u64)->u64:
    if number == 0 or number > 4095 or operation < 1 or operation > 3:
        return refuse(w,4008)
    put(w,F_ERROR_OP,operation)
    put(w,F_ERROR_NO,number)
    put(w,F_ERROR_INDEX,get(w,F_INDEX))
    return 0

def files_descriptor(w:mutbuf)->u64:
    zero(w,RESULT_AT,128)
    put(w,RESULT_AT,RESULT)
    put(w,RESULT_AT+8,1)
    put(w,RESULT_AT+16,get(w,C_LEASE))
    put(w,RESULT_AT+24,get(w,F_REQUEST))
    put(w,RESULT_AT+40,get(w,F_FILES_DONE))
    put(w,RESULT_AT+48,get(w,F_ALL_BYTES))
    put(w,RESULT_AT+56,get(w,F_HASH_BYTES))
    if get(w,F_ERROR_NO) != 0:
        put(w,RESULT_AT+32,1)
        put(w,RESULT_AT+64,get(w,F_ERROR_OP))
        put(w,RESULT_AT+72,get(w,F_ERROR_NO))
        put(w,RESULT_AT+80,get(w,F_ERROR_INDEX))
        put(w,RESULT_AT+88,B_PATH)
        put(w,RESULT_AT+96,get(w,F_PATH_N)-1)
        put(w,RESULT_AT+104,get(w,F_CLOSE_ERROR))
    else:
        if get(w,F_FILES_DONE) != 20 or get(w,F_INDEX) != 20:
            return refuse(w,4009)
        put(w,RESULT_AT+88,B_HASH_OUTPUT)
        put(w,RESULT_AT+96,32)
    return 0

def files_terminal(o:mutbuf,w:mutbuf)->u64:
    if get(w,F_FILE_LIVE) != 0 or get(w,C_PENDING) != 0:
        return refuse(w,4010)
    args(w,get(w,F_ERROR_NO),get(w,F_ERROR_OP),B_RESULT,0,128,
         get(w,F_FILES_DONE),get(w,F_ALL_BYTES),get(w,F_HASH_BYTES),0,0,0,0)
    put(o,0,EVENT_MAGIC)
    put(o,8,7)
    put(o,16,get(w,C_LEASE))
    put(o,24,get(w,C_SEQUENCE))
    i = 0
    while i < 96:
        store(o,32+i,byte(w,ARGS+i))
        i = i + 1
    put(w,L_STATUS,2)
    return 128

def files_step(o:mutbuf,w:mutbuf,phase:u64)->u64:
    if phase == 1:
        return grow(o,w,B_HASH_INPUT,CHUNK+1,2)
    if phase == 2:
        return grow(o,w,B_HASH_OUTPUT,32,3)
    if phase == 3:
        return grow(o,w,B_HASH_STATE,1184,4)
    if phase == 4:
        return grow(o,w,B_CHUNK,CHUNK,5)
    if phase == 5:
        store(w,WIRE,0)
        return copy(o,w,2,WIRE,B_HASH_INPUT,0,1,6)
    if phase == 6:
        return protect(o,w,B_HASH_INPUT,1,7)
    if phase == 7:
        return invoke(o,w,I_HASH,B_HASH_INPUT,0,1,B_HASH_OUTPUT,32,
            B_HASH_STATE,1184,B_HASH_OUTPUT,0,0,8)
    if phase == 8:
        if get(w,C_RETURN) != 0:
            return refuse(w,4011)
        return files_phase(w,20)
    if phase == 20:
        index = get(w,F_INDEX)
        if index == 20:
            return protect(o,w,B_HASH_INPUT,0,60)
        if index > 20 or get(w,F_FILE_LIVE) != 0:
            return refuse(w,4012)
        size = files_name(w,index)
        if size == 0 or size > 63:
            return refuse(w,4013)
        put(w,F_NAME_N,size)
        put(w,F_PATH_N,get(w,F_ROOT_N)+get(w,F_SEPARATOR)+size+1)
        put(w,F_FILE_BYTES,0)
        return grow(o,w,B_PATH,get(w,F_PATH_N),21)
    if phase == 21:
        return protect(o,w,B_PATH,0,22)
    if phase == 22:
        return copy(o,w,1,64,B_PATH,0,get(w,F_ROOT_N),23)
    if phase == 23:
        if get(w,F_SEPARATOR) == 0:
            return files_phase(w,24)
        store(w,WIRE,47)
        return copy(o,w,2,WIRE,B_PATH,get(w,F_ROOT_N),1,24)
    if phase == 24:
        return copy(o,w,2,NAME_AT,B_PATH,get(w,F_ROOT_N)+get(w,F_SEPARATOR),get(w,F_NAME_N)+1,25)
    if phase == 25:
        return protect(o,w,B_PATH,1,26)
    if phase == 26:
        return files_hash_command(w,B_PATH,get(w,F_ROOT_N)+get(w,F_SEPARATOR),get(w,F_NAME_N)+1,30)
    if phase == 30:
        return files_sys(o,w,1,31)
    if phase == 31:
        number = files_errno(get(w,C_RETURN))
        if number != 0:
            files_error(w,1,number)
            return files_phase(w,70)
        if get(w,C_RETURN) != 1:
            return refuse(w,4014)
        put(w,F_FILE_LIVE,1)
        return files_phase(w,32)
    if phase == 32:
        return files_sys(o,w,2,33)
    if phase == 33:
        value = get(w,C_RETURN)
        number = files_errno(value)
        if number == 4:
            return files_phase(w,32)
        if number != 0:
            files_error(w,2,number)
            return files_phase(w,40)
        if value > CHUNK or value > MAX-get(w,F_ALL_BYTES) or value > MAX-get(w,F_FILE_BYTES):
            return refuse(w,4015)
        if value == 0:
            return files_phase(w,40)
        put(w,F_READ_N,value)
        put(w,F_ALL_BYTES,get(w,F_ALL_BYTES)+value)
        put(w,F_FILE_BYTES,get(w,F_FILE_BYTES)+value)
        return files_hash_command(w,B_CHUNK,0,value,32)
    if phase == 40:
        return files_sys(o,w,3,41)
    if phase == 41:
        put(w,F_FILE_LIVE,0)
        number = files_errno(get(w,C_RETURN))
        if number != 0:
            put(w,F_CLOSE_ERROR,number)
            files_error(w,3,number)
            return files_phase(w,70)
        if get(w,C_RETURN) != 0:
            return refuse(w,4016)
        if get(w,F_ERROR_NO) != 0:
            return files_phase(w,70)
        store(w,WIRE,0)
        put(w,F_FILES_DONE,get(w,F_FILES_DONE)+1)
        put(w,F_INDEX,get(w,F_INDEX)+1)
        return files_hash_command(w,2,WIRE,1,20)
    if phase == 60:
        store(w,WIRE,2)
        return copy(o,w,2,WIRE,B_HASH_INPUT,0,1,61)
    if phase == 61:
        return protect(o,w,B_HASH_INPUT,1,62)
    if phase == 62:
        return invoke(o,w,I_HASH,B_HASH_INPUT,0,1,B_HASH_OUTPUT,32,
            B_HASH_STATE,1184,B_HASH_OUTPUT,0,32,63)
    if phase == 63:
        if get(w,C_RETURN) != 32:
            return refuse(w,4017)
        return protect(o,w,B_HASH_OUTPUT,1,70)
    if phase == 70:
        if files_descriptor(w) != 0:
            return ABI
        return grow(o,w,B_RESULT,128,71)
    if phase == 71:
        return copy(o,w,2,RESULT_AT,B_RESULT,0,128,72)
    if phase == 72:
        return protect(o,w,B_RESULT,1,73)
    if phase == 73:
        return files_terminal(o,w)
    return refuse(w,4018)
'''
def names_source():
 lines=["def files_name(w:mutbuf,index:u64)->u64:"]
 for index,name in enumerate(FILES):
  lines.append("    "+("if" if index==0 else "elif")+" index == "+str(index)+":")
  for offset,value in enumerate(name.encode("ascii")+b"\0"):
   lines.append("        store(w,NAME_AT+"+str(offset)+","+str(value)+")")
  lines.append("        return "+str(len(name)))
 lines.append("    return 0")
 return "\n".join(lines)+"\n"
def source(common):
 constants=dict(common.CONSTANTS);constants.update(CONSTANTS)
 nodes=ast.parse(BODY+"\n"+names_source()+"\n"+common.COMMON).body
 functions={node.name:node for node in nodes};assert len(functions)==len(nodes)
 keep={"implementation_files"};pending=list(keep)
 while pending:
  for called in ast.walk(functions[pending.pop()]):
   if isinstance(called,ast.Call) and isinstance(called.func,ast.Name):
    name=called.func.id
    if name in functions and name not in keep:keep.add(name);pending.append(name)
 selected=[copy.deepcopy(functions["implementation_files"])]
 selected.extend(copy.deepcopy(node) for node in nodes if node.name in keep and node.name!="implementation_files")
 for node in selected:
  if node.name in("word","get"):
   arg="s" if node.name=="word" else "w"
   node.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,i*8) for i in range(8))).body
  elif node.name=="put":
   node.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,i*8) for i in range(8))+"\nreturn 0").body
 assert constants["F_FILES_DONE"]+8<constants["NAME_AT"]
 assert constants["NAME_AT"]+64<constants["RESULT_AT"]
 assert constants["RESULT_AT"]+128<constants["MIN_WORK"]
 return "\n".join(ast.unparse(ast.fix_missing_locations(node)) for node in selected)+"\n",constants,dict(
  status="NEW_SOURCE_ONLY",exact_original_names=list(FILES),header_is_authentication=False,
  fixed_fs_mechanics_only=True,actual_native_incremental_SHA_required=True,
  no_8MiB_file_budget=True,read_window_bytes=65536,regular_file_or_no_symlink_gate=False,
  source_paths_use_original_following_open=True,one_owned_descriptor=True,
  errno4_read_retry_HIA_owned=True,close_consumes_once=True,
  aggregate_SHA_byte_domain=(1<<61)-1,public_OSError_text_formatter=False,
  whole_public_emit=False,whole_compile=False,installed=False)
