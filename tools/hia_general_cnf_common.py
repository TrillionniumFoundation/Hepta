"""Development author fragments for the independent resumable 32-bit CNF role."""
import ast, copy
from tools.generate_hia_cold_sha_alias import nonalias_source

MIB=1<<20
CONSTANTS={
 'W_BYTES':512*MIB,'GRAPH_BASE':65536,'GRAPH_MAX':16*MIB,
 'P_BASE':17*MIB,'LOCAL_BASE':18*MIB,'PHI_BASE':26*MIB,
 'NODE_BASE':34*MIB,'NODE_CAP':1<<20,'NODE_HASH':74*MIB,'NODE_HASH_SLOTS':1<<20,
 'BITS_BASE':82*MIB,'CNF_BASE':338*MIB,'TOKEN_CAP':16*MIB,
 'CLAUSE_BASE':402*MIB,'CLAUSE_CAP':1<<20,'HEAD_BASE':434*MIB,
 'ASSIGN_BASE':450*MIB,'TRAIL_BASE':452*MIB,'LEVEL_BASE':460*MIB,
 'LIMIT_BASE':468*MIB,'REASON_BASE':476*MIB,'SEEN_BASE':484*MIB,
 'LEARN_BASE':486*MIB,'GATE_BASE':494*MIB,'GATE_SLOTS':1<<20,
 'MARK_BASE':510*MIB,'TEMP_BASE':511*MIB,'VAR_CAP':(1<<21)-1,
 'BB_BASE':2048,'PAIR_BASE':16384,'SHA_BASE':8192,'NIL':(1<<32)-1,
 'REQUEST_MAGIC':int.from_bytes(b'HIAGCN01','little'),
 'REPLY_MAGIC':int.from_bytes(b'HIAGCR01','little'),
 'STATE_MAGIC':int.from_bytes(b'HIAWGC01','little'),
 'GRAPH_MAGIC':int.from_bytes(b'HIABVP01','little'),
 'WORD_MASK':(1<<64)-1,'PROJECT_UNIT_TYPE':65,
 'WORD_UNSIGNED_DIV':33,'WORD_UNSIGNED_REM':34,'WORD_PRODUCT_EXCEEDS':35,
 'WORD_VARIABLE_SHL':36,'WORD_VARIABLE_SHR':37,'WORD_ARITHMETIC_SHR':38,
 'WORD_SIGNED_DIV':39,'WORD_SIGNED_REM':40,
 'PROJECT_CHECKED_SHL':34,'PROJECT_CHECKED_SHR':35,'PROJECT_CHECKED_DIV':36,
 'PROJECT_CHECKED_REM':37,'PROJECT_CHECKED_CAST':38,'PROJECT_CHECKED_MUL':39,
 'CIRCUIT_NODES':1<<20,
 'CIRCUIT_DIVISION_TEMP':((511*MIB)-(82*MIB)+64)//2,
 'CIRCUIT_SIGNED_MAGNITUDES':((511*MIB+4096)-(82*MIB)+64)//2,
}

ENTRY=r'''def general_cnf(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o) < 128:
        return 4294967295
    if length(w) < W_BYTES or length(s) < 128:
        return invalid_reply(o,1)
    if word_load(s,0) != REQUEST_MAGIC:
        return invalid_reply(o,1)
    op=word_load(s,8)
    size=word_load(s,16)
    remaining=word_load(s,24)
    quantum=word_load(s,32)
    if op > 1 or remaining == 0 or remaining > 60000 or quantum == 0 or quantum > 16384:
        return invalid_reply(o,1)
    if word_load(s,40) != 0 or word_load(s,48) != 0 or word_load(s,56) != 0 or word_load(s,96) != 0 or word_load(s,104) != 0 or word_load(s,112) != 0 or word_load(s,120) != 0:
        return invalid_reply(o,1)
    if op == 0:
        if size < 56 or size > GRAPH_MAX or length(s) != 128+size:
            return invalid_reply(o,1)
        i=0
        while i < 4096:
            word_store(w,i,0)
            i=i+8
        word_store(w,0,STATE_MAGIC)
        word_store(w,8,1)
        word_store(w,16,3)
        word_store(w,24,1)
        word_store(w,48,remaining)
        word_store(w,64,size)
        word_store(w,736,W_BYTES)
        i=0
        while i < 32:
            store(w,128+i,byte(s,64+i))
            i=i+1
        i=0
        while i+8 <= size:
            word_store(w,GRAPH_BASE+i,word_load(s,128+i))
            i=i+8
        while i < size:
            store(w,GRAPH_BASE+i,byte(s,128+i))
            i=i+1
        sha_initialize(w)
    else:
        if size != 0 or length(s) != 128 or word_load(w,0) != STATE_MAGIC or word_load(w,8) != 1:
            return invalid_reply(o,5)
        if word_load(w,16) > 4 or remaining > word_load(w,48):
            return invalid_reply(o,5)
        i=0
        while i < 32:
            if byte(s,64+i) != byte(w,128+i):
                return invalid_reply(o,5)
            i=i+1
    word_store(w,48,remaining)
    word_store(w,56,0)
    word_store(w,744,quantum)
    word_store(w,760,0)
    while word_load(w,16) == 3 and word_load(w,56) < quantum:
        phase=word_load(w,24)
        if phase == 1:
            hash_step(w)
        elif phase == 2:
            projection_step(w)
        elif phase == 3:
            mark_step(w)
        elif phase == 4:
            bitblast_step(w)
        elif phase == 5:
            solver_step(w)
        elif phase == 6:
            witness_step(w)
        else:
            stop(w,4,5)
        total=word_load(w,40)
        if total == WORD_MASK:
            stop(w,4,5)
        else:
            word_store(w,40,total+1)
        word_store(w,56,word_load(w,56)+1)
        if word_load(w,760) != 0:
            return general_reply(o,w)
    return general_reply(o,w)

def invalid_reply(o:mutbuf,reason:u64) -> u32:
    i=0
    while i < 128:
        word_store(o,i,0)
        i=i+8
    word_store(o,0,REPLY_MAGIC)
    word_store(o,8,4)
    word_store(o,24,reason)
    return 128

def general_reply(o:mutbuf,w:mutbuf) -> u32:
    i=0
    while i < 128:
        word_store(o,i,0)
        i=i+8
    status=word_load(w,16)
    word_store(o,0,REPLY_MAGIC)
    word_store(o,8,status)
    word_store(o,16,word_load(w,24))
    word_store(o,24,word_load(w,32))
    word_store(o,32,word_load(w,736))
    word_store(o,40,word_load(w,BB_BASE))
    word_store(o,48,word_load(w,BB_BASE+8))
    word_store(o,56,word_load(w,40))
    word_store(o,112,word_load(w,56))
    i=0
    while i < 32:
        store(o,64+i,byte(w,160+i))
        i=i+1
    if status != 1:
        return 128
    inputs=word_load(w,88)
    variables=word_load(w,BB_BASE)
    amount=(variables+7)>>3
    if inputs > 32 or amount > 262144 or length(o) < 128+8*inputs+amount:
        return invalid_reply(o,2)
    word_store(o,96,inputs)
    word_store(o,104,amount)
    i=0
    while i < inputs:
        word_store(o,128+8*i,word_load(w,PHI_BASE+8*i))
        i=i+1
    i=0
    while i < amount:
        value=0
        bit=0
        while bit < 8:
            var=1+8*i+bit
            if var <= variables and byte(w,ASSIGN_BASE+var-1) == 2:
                value=value | (1<<bit)
            bit=bit+1
        store(o,128+8*inputs+i,value)
        i=i+1
    return 128+8*inputs+amount

def stop(w:mutbuf,status:u64,reason:u64) -> u64:
    word_store(w,16,status)
    word_store(w,32,reason)
    if status == 1 or status == 2:
        word_store(w,24,7)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,at,value)
    return 0

def get32(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)&4294967295

def put32(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,at,(word_load(w,at)&18446744069414584320)|(value&4294967295))
    return 0

def graph(w:mutbuf,at:u64) -> u64:
    return word_load(w,GRAPH_BASE+at)

def pget(w:mutbuf,at:u64) -> u64:
    return word_load(w,P_BASE+at)

def pput(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,P_BASE+at,value)
    return 0

def nget(w:mutbuf,at:u64) -> u64:
    return word_load(w,NODE_BASE+at-32)

def nput(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,NODE_BASE+at-32,value)
    return 0

def bget(w:mutbuf,at:u64) -> u64:
    return word_load(w,BB_BASE+at)

def bput(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,BB_BASE+at,value)
    return 0

def load_token(w:mutbuf,position:u64) -> u64:
    return get32(w,BITS_BASE+2*position-64)

def put_token(w:mutbuf,position:u64,value:u64) -> u64:
    put32(w,BITS_BASE+2*position-64,value)
    return 0

def node_width(w:mutbuf,node:u64) -> u64:
    return word_load(w,NODE_BASE+40*node+8)
'''

HASH=r'''def hash_step(w:mutbuf) -> u64:
    size=get(w,64)
    cursor=get(w,72)
    if cursor <= size and size-cursor >= 64:
        i=0
        while i < 64:
            put(w,SHA_BASE+1112+i,get(w,GRAPH_BASE+cursor+i))
            i=i+8
        sha_compress(w)
        put(w,72,cursor+64)
        return 0
    used=size-cursor
    i=0
    while i < 64:
        store(w,SHA_BASE+1112+i,0)
        i=i+1
    i=0
    while i < used:
        store(w,SHA_BASE+1112+i,byte(w,GRAPH_BASE+cursor+i))
        i=i+1
    store(w,SHA_BASE+1112+used,128)
    if used >= 56:
        sha_compress(w)
        i=0
        while i < 64:
            store(w,SHA_BASE+1112+i,0)
            i=i+1
    bits=size*8
    i=0
    while i < 8:
        store(w,SHA_BASE+1175-i,(bits>>(8*i))&255)
        i=i+1
    sha_compress(w)
    i=0
    while i < 8:
        value=get(w,SHA_BASE+1024+8*i)
        store(w,160+4*i,(value>>24)&255)
        store(w,161+4*i,(value>>16)&255)
        store(w,162+4*i,(value>>8)&255)
        store(w,163+4*i,value&255)
        i=i+1
    i=0
    while i < 32:
        if byte(w,128+i) != byte(w,160+i):
            return stop(w,4,4)
        i=i+1
    put(w,24,2)
    put(w,192,0)
    return 0
'''

def sha_source():
    raw=nonalias_source();tree=ast.parse(raw)
    stream=next(n for n in tree.body if n.name=='stream')
    initialize=next(n for n in stream.body if isinstance(n,ast.If) and ast.unparse(n.test)=='op == 0')
    initbody=copy.deepcopy(initialize.body)
    assert isinstance(initbody[0],ast.If)
    initbody=initbody[1:]
    init=ast.parse('def sha_initialize(w:mutbuf) -> u64:\n    return 0').body[0];init.body=initbody
    compress=copy.deepcopy(next(n for n in tree.body if n.name=='compress'));compress.name='sha_compress'
    class Relocate(ast.NodeTransformer):
        def visit_Call(self,n):
            n=self.generic_visit(n)
            if isinstance(n.func,ast.Name) and n.func.id in ('put','get','word_load','word_store','word_load_be','byte','store'):
                assert isinstance(n.args[0],ast.Name) and n.args[0].id=='w'
                n.args[1]=ast.BinOp(ast.Name('SHA_BASE',ast.Load()),ast.Add(),n.args[1])
                if n.func.id=='put':n.func.id='word_store'
                if n.func.id=='get':n.func.id='word_load'
            return n
    return '\n\n'.join(ast.unparse(ast.fix_missing_locations(Relocate().visit(n))) for n in (init,compress))+'\n'

FORMULA_HASH=r'''def formula_begin(w:mutbuf) -> u64:
    put(w,1024,0)
    put(w,1032,bget(w,0))
    put(w,1040,bget(w,8))
    put(w,1048,bget(w,16))
    put(w,1088,32+4*bget(w,16))
    put(w,1096,0)
    put(w,1152,3544388102543984968)
    put(w,1160,bget(w,0))
    put(w,1168,bget(w,8))
    put(w,1176,bget(w,16))
    sha_initialize(w)
    put(w,1000,1)
    return 0

def formula_hash_step(w:mutbuf) -> u64:
    size=get(w,1088)
    cursor=get(w,1096)
    if cursor <= size and size-cursor >= 64:
        i=0
        while i < 64:
            offset=cursor+i
            value=0
            if offset < 32:
                value=get(w,1152+offset)
            else:
                value=get(w,CNF_BASE+offset-32)
            put(w,SHA_BASE+1112+i,value)
            i=i+8
        sha_compress(w)
        put(w,1096,cursor+64)
        return 0
    used=size-cursor
    i=0
    while i < 64:
        store(w,SHA_BASE+1112+i,0)
        i=i+1
    i=0
    while i < used:
        offset=cursor+i
        value=0
        if offset < 32:
            value=byte(w,1152+offset)
        else:
            value=byte(w,CNF_BASE+offset-32)
        store(w,SHA_BASE+1112+i,value)
        i=i+1
    store(w,SHA_BASE+1112+used,128)
    if used >= 56:
        sha_compress(w)
        i=0
        while i < 64:
            store(w,SHA_BASE+1112+i,0)
            i=i+1
    bits=size*8
    i=0
    while i < 8:
        store(w,SHA_BASE+1175-i,(bits>>(8*i))&255)
        i=i+1
    sha_compress(w)
    i=0
    while i < 8:
        value=get(w,SHA_BASE+1024+8*i)
        store(w,1056+4*i,(value>>24)&255)
        store(w,1057+4*i,(value>>16)&255)
        store(w,1058+4*i,(value>>8)&255)
        store(w,1059+4*i,value&255)
        i=i+1
    put(w,1024,1)
    put(w,24,5)
    put(w,440,0)
    put(w,472,0)
    return 0
'''
