"""Render the public VM observation array from actual owned reference rows.

Input is the literal [canonical Core,workload] JSON, the actual HIAEBT01
batch, and '<8s2Q' (HIAERJ01, JSON byte length, batch byte length). The
HIA policy derives all names, scalar/loan types and sizes from the parsed
documents. HIAERJ02 inserts the two actual monotonic boundaries and the
selected owned reference ELF between batch and footer. Its output wraps the
same rows in the original public reference outcome, hashing physical stdout
and the selected executable. HIAEFI04 is issued only after exit zero and empty
stderr. The public execution-ledger policy checks the physical counters.
"""

import ast
import json
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_execution_ledger_native import ERRORS, RESOURCES, CHAINS
from hepta.hia_scalar_reference_wire import TYPES, RESOURCE_NAMES
from hepta.hia_schema import PRIMITIVE_PROFILES, supports_feature
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_paired_batch import snapshot_hash
from tools.generate_hia_evaluate_reference_batch import program as batch_source, FIELDS as BATCH_FIELDS, NONE
from tools.generate_hia_evaluate_reference_wire import compact_enum
from tools.generate_hia_evaluate_settlement import POLICY as SETTLE
from tools.generate_hia_execution_ledger import SOURCE as LEDGER
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_worker_emit_verification import key_table
from tools.generate_hia_worker_inspection_effect import function

SOURCE=Path('examples/hia_bootstrap/evaluate_reference_report.hepta')
PACKER=SOURCE.with_name('evaluate_reference_report_packer.hepta')
MAGIC=int.from_bytes(b'HIAERP01','little')
FIELDS=(*BATCH_FIELDS,'schema')

POLICY=r'''
def reference_report(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n = length(s)
    if n < 48 or (read_word(s,n-24) != REQUEST and read_word(s,n-24) != OUTCOME):
        return BAD
    text = read_word(s,n-16)
    batch = read_word(s,n-8)
    if text > 16777219 or text > n-24 or batch > n-text-24 or batch < 24 or batch > 67108864:
        return BAD
    end = text+batch
    mode = read_word(s,n-24)
    if mode == REQUEST and end != n-24:
        return BAD
    if mode == OUTCOME:
        if n-24-end < 80 or read_word(s,end) == 0 or read_word(s,end+8) < read_word(s,end) or (read_word(s,end+16) & 4294967295) != 1179403647:
            return BAD
    if read_word(s,text) != BATCH or length(w) < 67108864 or length(o) < 8388608:
        return BAD
    put(o,48,524289)
    put(o,56,128)
    extent = widen(decode_json(s,w,o))
    if extent > length(w)-32768 or kind(w,64) != 5 or get(w,96) != 2:
        return BAD
    core = child(w,64)
    work = next(w,core)
    if kind(w,core) != 6 or kind(w,work) != 6:
        return BAD
    chain = recursive(w,lookup(w,core,K_schema))
    if chain > 1:
        return BAD
    cases = lookup(w,work,K_cases)
    if kind(w,cases) != 5 or get(w,cases+32) != read_word(s,text+8):
        return BAD
    count = read_word(s,text+8)
    done = read_word(s,text+16)
    if count == 0 or count > 512 or done == 0 or done > count:
        return BAD
    if widen(pair_hash_sha256(s,w,get(w,core+56),get(w,core+64))) != 32:
        return BAD
    i = 0
    while i < 32:
        store(w,CORE_HASH+i,byte(w,length(w)-4096+1088+i))
        i = i+1
    put(w,CTX,core)
    put(w,CTX+8,work)
    put(w,CTX+16,chain)
    put(w,CTX+24,text)
    put(w,CTX+32,batch)
    put(w,CTX+40,mode)
    return emit_cases(s,o,w,child(w,cases))

def emit_cases(s:readbuf,o:mutbuf,w:mutbuf,case:u64) -> u64:
    text = get(w,CTX+24)
    done = read_word(s,text+16)
    end = text+get(w,CTX+32)
    row = text+24
    at = 0
    if get(w,CTX+40) == OUTCOME:
        at = report_start(s,o,w,text,get(w,CTX+32),done)
        if at == BAD:
            return BAD
    at = literal('[')
    i = 0
    while i < done:
        if row > end or end-row < 160 or read_word(s,row) != i:
            return BAD
        size = read_word(s,row+8)
        row = row+16
        if size < 144 or size > end-row or read_word(s,row) != RECEIPT:
            return BAD
        fn = public_function(w,get(w,CTX),lookup(w,case,K_function))
        if fn == NONE or case == NONE:
            return BAD
        if i != 0:
            at = literal(',')
        at = observation(s,o,w,at,fn,case,get(w,CTX+8),row,size,get(w,CTX+16))
        if at >= 8384512:
            return BAD
        budget = get(w,FRAME+8) == 3
        if budget and i+1 != done:
            return BAD
        if i+1 == done and done != read_word(s,text+8) and budget == False:
            return BAD
        row = row+size
        case = next(w,case)
        i = i+1
    if row != end:
        return BAD
    at = literal(']')
    if get(w,CTX+40) == OUTCOME:
        return report_end(s,o,w,at,text,get(w,CTX+32))
    return at

def report_start(s:readbuf,o:mutbuf,w:mutbuf,text:u64,batch:u64,done:u64) -> u64:
    last = text+24
    i = 0
    while i+1 < done:
        if last > text+batch or text+batch-last < 16:
            return BAD
        size = read_word(s,last+8)
        if size > text+batch-last-16:
            return BAD
        last = last+16+size
        i = i+1
    if last > text+batch or text+batch-last < 48:
        return BAD
    status = read_word(s,last+24)
    complete = done == read_word(s,text+8) and status != 5 and status != 6 and status != 16
    at = 0
    at = literal('{"report":{"artifact_sha256":"')
    at = hash_hex(o,w,at,CORE_HASH)
    at = literal('","complete":')
    if complete:
        at = literal('true')
    else:
        at = literal('false')
    at = literal(',"completed_cases":')
    at = decimal(o,at,done)
    at = literal(',"native_code_executed":false,"observations":')
    return at

def report_end(s:readbuf,o:mutbuf,w:mutbuf,at:u64,text:u64,batch:u64) -> u64:
    end = text+batch
    if widen(pair_hash_sha256(s,w,end+16,length(s)-end-40)) != 32:
        return BAD
    at = literal(',"owned_reference_executable_sha256":"')
    at = hash_hex(o,w,at,length(w)-4096+1088)
    at = literal('","owned_reference_standalone_calls":')
    at = decimal(o,at,read_word(s,text+16))
    at = literal(',"planned_cases":')
    at = decimal(o,at,read_word(s,text+8))
    at = literal(',"repetitions":1,"schema":"hepta.hia.agent.reference-observation.v1","warmup":0},"returncode":0,"started":true,"status":"returned","stderr_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","stdout_sha256":"')
    if widen(pair_hash_sha256(s,w,text,batch)) != 32:
        return BAD
    at = hash_hex(o,w,at,length(w)-4096+1088)
    at = literal('","termination_confirmed":true,"wall_ns":"')
    at = decimal(o,at,read_word(s,end+8)-read_word(s,end))
    at = literal('"}')
    return at

def observation(s:readbuf,o:mutbuf,w:mutbuf,at:u64,fn:u64,case:u64,work:u64,row:u64,size:u64,chain:u64) -> u64:
    name = lookup(w,fn,K_name)
    args = lookup(w,case,K_arguments)
    params = lookup(w,fn,K_params)
    returns = lookup(w,fn,K_returns)
    if kind(w,name) != 4 or kind(w,args) != 5 or kind(w,params) != 5 or kind(w,returns) != 5:
        return BAD
    rc = get(w,returns+32)
    if rc > 1 or get(w,params+32) != get(w,args+32):
        return BAD
    typ = type_code(w,child(w,returns))
    if rc == 1 and typ >= SCALARS:
        return BAD
    put(w,ROW,name)
    put(w,ROW+8,args)
    put(w,ROW+16,params)
    put(w,ROW+24,rc)
    put(w,ROW+32,typ)
    selected = named(w,lookup(w,work,K_foreign_buffer_exports),name,K_function)
    put(w,ROW+40,choose(selected != NONE,1,0))
    put(w,FRAME+16,chain)
    return emit_row(s,o,w,at,row,size)

def emit_row(s:readbuf,o:mutbuf,w:mutbuf,at:u64,row:u64,size:u64) -> u64:
    status = read_word(s,row+8)
    which = error_id(status,read_word(s,row+24))
    if which == NONE:
        return BAD
    role = choose(status == 0,1,choose(which == 6 or which == 7 or which == 8,3,2))
    put(w,FRAME+8,role)
    put(w,FRAME+32,0)
    put(w,FRAME+40,read_word(s,row+16))
    put(w,FRAME+56,16777216)
    put(w,FRAME+64,which)
    put(w,ROW+48,0)
    rc = get(w,ROW+24)
    if role == 1 and rc == 1:
        if size < 152:
            return BAD
        value = read_word(s,row+32)
        if scalar_valid(get(w,ROW+32),value) == False:
            return BAD
        put(w,ROW+48,value)
    counters = row+32+choose(role == 1,8*rc,0)
    if size < counters-row+112:
        return BAD
    read_counters(s,w,counters)
    first = counters+112
    end = row+size
    borrowed = get(w,ROW+40) == 1
    put(w,FRAME+48,choose(borrowed,10000000,1000000))
    at = literal('{')
    if role == 3:
        at = literal('"budget_code":')
        at = error_name(o,at,which)
        at = literal(',')
    if borrowed:
        at = literal('"buffers":[')
        at = buffers(s,o,w,at,get(w,ROW+16),get(w,ROW+8),first,end)
        if at == BAD:
            return BAD
        at = literal('],')
    elif first != end:
        return BAD
    put(w,ROW+56,end-first)
    return emit_ledger(s,o,w,at,row)

def emit_ledger(s:readbuf,o:mutbuf,w:mutbuf,at:u64,row:u64) -> u64:
    role = get(w,FRAME+8)
    which = get(w,FRAME+64)
    if valid_resources(w) != 0 or valid_outcome(w,role) != 0:
        return BAD
    at = literal('"ledger":{"claims":{"backend_refinement_proved":false,"finite_core_execution":true,"whole_language_soundness_proved":false}')
    if role != 1:
        at = literal(',"error":{"code":')
        at = error_name(o,at,which)
        at = literal(',"message":')
        at = error_message(o,at,read_word(s,row+8),read_word(s,row+24))
        at = literal('}')
    if get(w,ROW+40) == 1:
        at = literal(',"external_buffers":{"byte_length":')
        at = decimal(o,at,get(w,ROW+56))
        at = literal(',"distinct_roots":')
        at = decimal(o,at,get(w,FRAME+32))
        at = literal(',"included_in_core_heap_ledger":false,"profile":"hepta.hia.agent.borrowed-byte-snapshots.v1"}')
    at = literal(',"function":')
    name = get(w,ROW)
    at = copy_wire(s,o,get(w,name+56),at,get(w,name+64))
    at = literal(',"input_sha256":"')
    at = hash_hex(o,w,at,CORE_HASH)
    at = literal('","program_sha256":"')
    at = hash_hex(o,w,at,CORE_HASH)
    at = literal('","resources":')
    at = resource_json(o,w,at)
    if role == 1:
        at = literal(',"result":')
        if get(w,ROW+24) == 0:
            at = literal('[]')
        else:
            at = scalar_json(o,at,get(w,ROW+32),get(w,ROW+48))
    at = literal(',"schema":"hepta.hia.program-execution.v1","source_used":false,"status":')
    at = status_json(o,at,role)
    at = literal(',"steps":')
    at = decimal(o,at,get(w,FRAME+40))
    if role == 1:
        at = literal(',"values":')
        at = values_json(o,at,get(w,ROW+32),get(w,ROW+24),get(w,ROW+48))
    at = literal(',"word_bits":64},"status":')
    at = status_json(o,at,role)
    if role == 1:
        at = literal(',"values":')
        at = values_json(o,at,get(w,ROW+32),get(w,ROW+24),get(w,ROW+48))
    elif role == 2:
        at = literal(',"trap_code":')
        at = error_name(o,at,which)
    at = literal('}')
    return at

def buffers(s:readbuf,o:mutbuf,w:mutbuf,at:u64,params:u64,args:u64,pos:u64,end:u64) -> u64:
    typ = child(w,params)
    arg = child(w,args)
    idx = 0
    roots = 0
    while typ != NONE:
        role = type_code(w,lookup(w,typ,K_type))
        if role == READBUF or role == MUTBUF:
            size = snapshot(s,w,arg)
            if size > 1048576 or size > end-pos or roots >= 8:
                return BAD
            if role == READBUF and unchanged(s,w,arg,pos,size) == False:
                return BAD
            if roots != 0:
                at = literal(',')
            at = literal('{"argument":')
            at = decimal(o,at,idx)
            at = literal(',"byte_length":')
            at = decimal(o,at,size)
            if role == READBUF:
                at = literal(',"kind":"readbuf"')
            else:
                at = literal(',"kind":"mutbuf"')
            if widen(pair_hash_sha256(s,w,pos,size)) != 32:
                return BAD
            at = literal(',"sha256":"')
            at = hash_hex(o,w,at,length(w)-4096+1088)
            at = literal('"}')
            pos = pos+size
            roots = roots+1
        arg = next(w,arg)
        typ = next(w,typ)
        idx = idx+1
    if pos != end or roots == 0:
        return BAD
    put(w,FRAME+32,roots)
    return at

def unchanged(s:readbuf,w:mutbuf,arg:u64,pos:u64,size:u64) -> bool:
    node = lookup(w,arg,K_bytes_hex)
    fill = 0
    source = 0
    if node == NONE:
        fill = uint(s,w,lookup(w,arg,K_fill_byte),255)
    else:
        source = get(w,node+24)
    i = 0
    while i < size:
        want = fill
        if node != NONE:
            want = 16*nibble(w,source+2*i)+nibble(w,source+2*i+1)
        if byte(s,pos+i) != want:
            return False
        i = i+1
    return True

def status_json(o:mutbuf,at:u64,status:u64) -> u64:
    if status == 1:
        at = literal('"returned"')
    elif status == 2:
        at = literal('"trapped"')
    else:
        at = literal('"budget_exceeded"')
    return at

def hash_hex(o:mutbuf,w:mutbuf,at:u64,root:u64) -> u64:
    i = 0
    while i < 32:
        value = widen(byte(w,root+i))
        store(o,at+2*i,hexchar(value >> 4))
        store(o,at+2*i+1,hexchar(value & 15))
        i = i+1
    return at+64

def scalar_valid(typ:u64,value:u64) -> bool:
    if typ == BOOL:
        return value <= 1
    if typ == UNIT:
        return value == 0
    n = width(typ)
    if n == 64:
        return True
    mask = (1 << n)-1
    if signed_type(typ) != 0 and ((value & mask) >> (n-1)) != 0:
        return (value | mask) == NONE
    return value <= mask

def scalar_json(o:mutbuf,at:u64,typ:u64,value:u64) -> u64:
    if typ == UNIT:
        at = literal('null')
    elif typ == BOOL:
        if value == 1:
            at = literal('true')
        else:
            at = literal('false')
    elif signed_type(typ) != 0 and (value >> 63) != 0:
        at = literal('-')
        at = decimal(o,at,0-value)
    else:
        at = decimal(o,at,value)
    return at

def values_json(o:mutbuf,at:u64,typ:u64,count:u64,value:u64) -> u64:
    at = literal('[')
    if count == 1:
        at = scalar_json(o,at,typ,value)
    at = literal(']')
    return at
'''

def literals(source):
    def expand(match):
        indent=match[1]
        raw=ast.literal_eval(match[2]).encode()
        lines=[]
        for i in range(0,len(raw),8):
            chunk=raw[i:i+8]
            # The bounded output reserves eight bytes beyond its logical end.
            # A subsequent append overwrites this private tail.
            lines.append(f'put(o,at+{i},{int.from_bytes(chunk,"little")})')
        return '\n'.join(indent+line for line in (*lines,f'at = at+{len(raw)}'))
    return re.sub(r'^([ \t]*)at = literal\((.+)\)$',expand,source,flags=re.M)


def errors():
    from hepta.hia_scalar_reference_native import BYTE_OPERATIONS
    from hepta.hia_scalar_reference_wire import TRAPS
    groups=[]
    for i,t in enumerate(TYPES):
        groups.append((f'status == 1 and detail == {i}','overflow','result is outside '+t))
    groups.extend((f'status == {i}',error,message) for i,(error,message) in enumerate((
        ('division_by_zero','integer divisor is zero'),('overflow','signed minimum divided by minus one'),
        ('overflow','shift count is outside the word width'),('steps','finite step limit reached'),
        ('calls','finite call-depth limit reached')),2))
    groups.extend((f'status == {i}',name,'explicit core trap') for i,name in enumerate(TRAPS,7))
    for i,op in enumerate(RESOURCE_NAMES,1):
        if op=='buffer.new':
            groups.extend(((f'status == 15 and detail == {i}','allocation','allocation exceeds the 64-bit object-size model'),
                           (f'status == 17 and detail == {i}','allocation','allocator returned failure')))
        if op in ('buffer.new','buffer.try_new','chain.try_push'):
            groups.append((f'status == 16 and detail == {i}','heap','finite live-byte limit reached'))
        operation={'fill_range':'fill','move_within':'move'}.get(op[7:],op[7:])
        if op.startswith('buffer.') and operation in BYTE_OPERATIONS:
            groups.append((f'status == 18 and detail == {i}','bounds',BYTE_OPERATIONS[operation][1]))
        if op in ('chain.head_read','chain.head_mut'):
            groups.append((f'status == 19 and detail == {i}','bounds','head borrow of an empty chain'))
    lines=['def error_id(status:u64,detail:u64) -> u64:','    if status == 0:','        return 0']
    lines.extend((f'    if status == 1 and detail < {len(TYPES)}:', f'        return {ERRORS["overflow"]}'))
    for cond,code,_ in groups[len(TYPES):]:
        lines.extend((f'    if {cond}:',f'        return {ERRORS[code]}'))
    lines+=['    return NONE','def error_message(o:mutbuf,at:u64,status:u64,detail:u64) -> u64:',
            '    if status < 15:', '        return scalar_message(o,at,status,detail)',
            '    return resource_message(o,at,status,detail)']
    for part, subset in (('scalar',groups[len(TYPES):len(TYPES)+10]),('resource',groups[len(TYPES)+10:])):
        lines.append(f'def {part}_message(o:mutbuf,at:u64,status:u64,detail:u64) -> u64:')
        if part=='scalar':
            lines.append('    if status == 1:')
            lines.append('        at = literal(' +repr('"E_HIA_TRAP_OVERFLOW: result is outside ')+')')
            for i,kind in enumerate(TYPES):
                suffix=kind+'"'
                lines.extend((f'        if detail == {i}:',f'            at = literal({suffix!r})','            return at'))
        messages={}
        for condition,code,message in subset:
            category='BUDGET' if ERRORS[code]>=6 else 'TRAP'
            text=json.dumps(f'E_HIA_{category}_{code.upper()}: {message}',separators=(',',':'))
            messages.setdefault(text,[]).append(condition)
        for text,conditions in messages.items():
            condition=' or '.join('('+c+')' for c in conditions)
            lines.extend((f'    if {condition}:',f'        at = literal({text!r})','        return at'))
        lines.append('    return at')
    lines.append('def error_name(o:mutbuf,at:u64,code:u64) -> u64:')
    for name,index in ERRORS.items():
        lines.extend((f'    if code == {index}:',f'        at = literal({json.dumps(name)!r})','        return at'))
    return '\n'.join((*lines,'    return at'))


def counters():
    # Native owned evaluator uses 14 physical words. Its public HIA ledger
    # descriptor uses 11 resource fields and 6 chain fields in fixed order.
    raw=('allocation_attempts','allocations','frees','owners_created','owners_dropped','live_bytes','peak_bytes',
         'loans_started','loans_ended','chains_created','chains_consumed','chain_nodes_created','chain_nodes_dropped','live_chains')
    fields=RESOURCES+CHAINS
    extra={'live_owners':('owners_created','owners_dropped'),'live_local_loans':('loans_started','loans_ended'),
           'live_chain_nodes':('chain_nodes_created','chain_nodes_dropped')}
    def cell(name):
        return f'read_word(s,base+{8*raw.index(name)})'
    lines=['def read_counters(s:readbuf,w:mutbuf,base:u64) -> u64:']
    for i,name in enumerate(fields):
        val='-'.join(cell(n) for n in extra[name]) if name in extra else cell(name)
        lines.append(f'    put(w,FRAME+{80+8*i},{val})')
    lines+=['    return 0','def resource_json(o:mutbuf,w:mutbuf,at:u64) -> u64:',"    at = literal('{')"]
    for i,name in enumerate(sorted(fields)):
        indent='    '
        if name in CHAINS:
            lines.append('    if get(w,FRAME+16) == 1:')
            indent+='    '
        prefix=(',' if i else '')+json.dumps(name)+':'
        lines.extend((f'{indent}at = literal({prefix!r})',f'{indent}at = decimal(o,at,get(w,FRAME+{80+8*fields.index(name)}))'))
    return '\n'.join((*lines,"    at = literal('}')",'    return at'))


def program():
    from hepta.hia_scalar_reference_wire import RESOURCE_KINDS
    from tools.generate_hia_mcp_request import WIRE_HELPERS
    batch=batch_source()
    helpers=('public_function','published','named','object','kind','child','next','eq_text','lookup','snapshot','uint',
             'read_word','nibble','type_code','width','signed_type')
    base='\n'.join(function(batch,n) for n in helpers)
    # The original JSON starts at byte zero. Its sealed binary suffix is
    # outside the JSON decoder's declared length, supplied in the final frame.
    decoder=json_decoder(wire_spans=True).replace('length(s) > 8388608 or','length(s) > 16777219 or')
    decoder=decoder.replace('length(s)','read_word(s,length(s)-16)')
    valid=LEDGER[LEDGER.index('def resources('):LEDGER.index('def word(')]
    valid=valid.replace('s:readbuf','w:mutbuf').replace('resources(s', 'valid_resources(w').replace('chains(s','valid_chains(w').replace('outcome_code(s','valid_outcome(w').replace('word(s, ','get(w,FRAME+')
    valid=valid.replace('def resources(w','def valid_resources(w').replace('def chains(w','def valid_chains(w').replace('def outcome_code(w','def valid_outcome(w')
    source=literals(POLICY+'\n'+errors()+'\n'+counters())+'\n'+valid
    constants={f'K_{key}':i for i,key in enumerate(FIELDS,1)}
    types=(*TYPES,*RESOURCE_KINDS[1:])
    constants.update(REQUEST=int.from_bytes(b'HIAERJ01','little'),OUTCOME=int.from_bytes(b'HIAERJ02','little'), BATCH=int.from_bytes(b'HIAEBT01','little'),
                     RECEIPT=int.from_bytes(b'HIASPR01','little'),NONE=NONE,BAD=0xfffffffd,
                     CORE_HASH=(64<<20)-19000,CTX=(64<<20)-22000,FRAME=(64<<20)-20000,ROW=(64<<20)-21000,SCALARS=len(TYPES),
                     READBUF=types.index('readbuf'),MUTBUF=types.index('mutbuf'),UNIT=TYPES.index('unit'),BOOL=TYPES.index('bool'))
    source=re.sub(r'\b('+'|'.join(constants)+r')\b',lambda m:str(constants[m[0]]),source)
    return '\n'.join((source,base,function(WIRE_HELPERS,'match_word'),key_table(FIELDS),
                     compact_enum('recursive',[(n,int(supports_feature(n,'recursive_chain'))) for n in PRIMITIVE_PROFILES]),
                     decoder,snapshot_hash(),function(SETTLE,'copy_wire'),function(SETTLE,'decimal'),
                     function(SETTLE,'hexchar'),
                     'def next_power(p:u64) -> u64:\n    return (p >> 1) * 14757395258967641293'))


def packer_document():
    from tools.generate_hia_native_filter import document as packer, template
    return packer(magic=MAGIC,module=PACKER.stem,image_template=template(
        wire_bytes=96<<20,output_bytes=8<<20,workspace_bytes=64<<20))

if __name__=='__main__':
    SOURCE.write_text(render_assembly(document(program(),SOURCE.stem)),encoding='utf-8')
    PACKER.write_text(render_assembly(packer_document()),encoding='utf-8')
