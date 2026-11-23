"""Drive the issued HIA Evaluate documents and terminal transaction from retained descriptors."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_evaluate_document_flow import ENTRY, ROLES as DOCUMENT_ROLES, program as document_program

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_closeout_flow.hepta')
ROLES = (*DOCUMENT_ROLES,'hia-evaluate-publication','hia-evaluate-settlement','hia-agent-journal-cost')

LATE = r'''
def begin_closeout(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if length(s) == 112 and input_word(s,64) == KEYED_SCHEMA and slot_bytes(w,ORIGINAL) > 678 and slot_bytes(w,ORIGINAL) <= 676+DIAGNOSTIC_LIMIT:
        return read_span(o,w,ERROR_HEADER,0,0,676)
    if length(s) == 112 and input_word(s,64) == KEYED_REFUSAL and slot_bytes(w,ORIGINAL) == 676:
        return read_span(o,w,ERROR_HEADER,0,0,676)
    if length(s) != 112 or input_word(s,64) != CLOSE_INPUT or input_word(s,72) == 0:
        return BAD
    put(w,ADMISSION_NS,input_word(s,72))
    pos = 48
    total = slot_bytes(w,ORIGINAL)
    i = 0
    while i < 4:
        width = input_word(s,80+8*i)
        if width == 0 or width > total-pos:
            return BAD
        hold(w,LATE_PARTS+24*i,0,pos,width)
        pos = pos+width
        i = i+1
    if pos != total or get(w,LATE_PARTS+16) < 40+760:
        return BAD
    return read_span(o,w,CLAIM_FIXED,0,48+40,322)

def plan_publication(o:mutbuf,w:mutbuf,mode:u64) -> u64:
    put(w,LATE_MODE,mode)
    put(w,LATE_INDEX,4)
    put(o,HEADER,PROJECTION)
    put(o,HEADER+8,mode)
    i = 0
    while i < 8:
        put(o,HEADER+16+8*i,get(w,LATE_PARTS+24*i+16))
        i = i+1
    fragment(o,0,0,48,slot_bytes(w,ORIGINAL)-48)
    return action(o,w,PLAN_EXTEND,MAKE,0,0,1,80)

def add_publication_ref(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    i = get(w,LATE_INDEX)
    while i < 8 and get(w,LATE_PARTS+24*i+16) == 0:
        i = i+1
    fd = input_word(s,32)
    extent = input_word(s,40)
    fragment(o,0,fd,0,extent)
    if i == 8:
        return action(o,w,PLAN_READY,RUN,PLANNER_ROLE,0,1,0)
    use_span(w,o,LATE_PARTS+24*i,1)
    put(w,LATE_INDEX,i+1)
    return action(o,w,PLAN_EXTEND,MAKE,0,0,2,0)

def late_product(s:readbuf,o:mutbuf,w:mutbuf,state:u64) -> u64:
    fd = input_word(s,32)
    size = input_word(s,40)
    mode = get(w,LATE_MODE)
    if state == CLOSE_HEADER:
        return begin_closeout(s,o,w)
    if state == CLAIM_FIXED:
        if length(s) != 386 or input_word(s,64) != CLAIM_MAGIC or input_word(s,96) == 0:
            return BAD
        put(w,CLAIM_TIME,input_word(s,96))
        copy_span(s,w,64+128,CLAIM_DIGEST,64)
        copy_span(s,w,64+192,CLAIM_KEY,64)
        copy_span(s,w,64+256,CLAIM_PUBLIC,66)
        return plan_publication(o,w,0)
    if state == PLAN_EXTEND:
        return add_publication_ref(s,o,w)
    if state == PLAN_READY:
        if mode == 2 or mode == 4:
            if size < 390:
                return BAD
            fragment(o,0,fd,0,size)
            return action(o,w,SETTLEMENT_READY,RUN,SETTLE_ROLE,0,1,0)
        if size <= 96:
            return BAD
        put(w,FRAME_FD,fd)
        put(w,FRAME_SIZE,size)
        return read_span(o,w,DOC_HEADER,fd,0,96)
    if state == SETTLEMENT_READY:
        if mode == 2 and size >= 2 and size <= 8388608:
            hold(w,LATE_PARTS+144,fd,0,size)
            return plan_publication(o,w,3)
        if mode == 4 and size > 48:
            hold(w,FINAL_FRAME,fd,0,size)
            return read_span(o,w,TERMINAL_HEADER,fd,0,48)
    if state == TERMINAL_HEADER:
        return terminal_begin(s,o,w)
    return BAD

def document_stored(o:mutbuf,w:mutbuf) -> u64:
    kind = get(w,EMIT_PUB_KIND)
    mode = get(w,LATE_MODE)
    if (mode == 0 and kind != 20) or (mode == 1 and kind != 21) or (mode == 3 and kind != 22):
        return BAD
    source = EMIT_ARTIFACT_REFS+24*(kind-EVAL_FIRST)
    if get(w,source+16) != 176:
        return BAD
    target = choose(mode == 0,4,choose(mode == 1,5,7))
    move_fragment(w,source,LATE_PARTS+24*target)
    return plan_publication(o,w,mode+1)
'''

# The Journal closure is completed only after a Store-confirmed two-write commit.
JOURNAL = r'''
def terminal_begin(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if length(s) != 112 or input_word(s,64) != TERMINAL or input_word(s,72) != choose(get(w,FINAL_STATUS) == 2,2,1) or input_word(s,104) != 0:
        return BAD
    reply = input_word(s,80)
    side = input_word(s,88)
    stmt = input_word(s,96)
    total = get(w,FINAL_FRAME+16)
    if reply < 2 or reply > 8388608 or side < 68 or reply > total-48 or side > total-48-reply or stmt != total-48-reply-side or stmt != 152+reply:
        return BAD
    fd = get(w, FINAL_FRAME)
    hold(w,FINAL_REPLY,fd,48,reply)
    hold(w,FINAL_STMT,fd,48+reply+side,stmt)
    hold(w,ERROR_BODY,fd,48+reply+68,side-68)
    return read_span(o,w,SIDEBAND_CONTEXT,fd,48+reply,68)

def commit_steps(s:readbuf,o:mutbuf,w:mutbuf,state:u64) -> u64:
    fd = input_word(s,32)
    size = input_word(s,40)
    if state == SIDEBAND_CONTEXT:
        if length(s) != 132 or input_word(s,64) != SIDEBAND or input_word(s,72) != choose(get(w,FINAL_STATUS) == 2,2,1) or input_word(s,80) != 36:
            return BAD
        copy_span(s,w,96,FINAL_CONTEXT,36)
        put(o,144,0)
        return action(o,w,FINAL_CLOCK,CLOCK,0,0,0,0)
    if state == FINAL_CLOCK:
        if length(s) != 72 or input_word(s,64) < get(w,ADMISSION_NS):
            return BAD
        put(o,HEADER,COST)
        put(o,HEADER+8,input_word(s,64)-get(w,ADMISSION_NS))
        put(o,HEADER+16,choose(get(w,FINAL_STATUS) == 2,2,1))
        context_size = choose(get(w,GLOBAL_COST) == 1,0,36)
        put(o,HEADER+24,context_size)
        put(o,HEADER+32,12)
        put(o,HEADER+40,66)
        put(o,HEADER+48,31)
        if context_size != 0:
            copy_private(w,o,FINAL_CONTEXT,HEADER+56,36)
        arguments = HEADER+56+context_size
        put(o,arguments,TOOL_A)
        put(o,arguments+8,TOOL_B)
        copy_private(w,o,CLAIM_PUBLIC,arguments+12,66)
        if get(w,FINAL_STATUS) == 2:
            extent = get(w,ERROR_BODY+16)
            if extent < 2 or extent > choose(context_size == 0,DIAGNOSTIC_LIMIT,1024):
                return BAD
            put(o,HEADER+48,9+extent+18)
            put(o,arguments+78,ERROR_PREFIX0)
            store(o,arguments+86,58)
            use_span(w,o,ERROR_BODY,0)
            put(o,400,ERROR_END0)
            put(o,408,ERROR_END1)
            put(o,416,ERROR_END2)
            fragment(o,1,INLINE_FRAGMENT,400,18)
            return action(o,w,COST_READY,RUN,FINAL_COST_ROLE,0,2,143+context_size)
        put(o,HEADER+170,DETAIL0)
        put(o,HEADER+178,DETAIL1)
        put(o,HEADER+186,DETAIL2)
        put(o,HEADER+194,DETAIL3)
        return action(o,w,COST_READY,RUN,FINAL_COST_ROLE,0,0,201)
    if state == COST_READY:
        if size < 192 or size > choose(get(w,GLOBAL_COST) == 1,DIAGNOSTIC_LIMIT+2048,2048):
            return BAD
        hold(w,FINAL_COST,fd,8,size-8)
        return read_span(o,w,COST_WIRE_CHECK,fd,0,16)
    if state == COST_WIRE_CHECK:
        if length(s) != 80 or input_word(s,64) != get(w,FINAL_COST+16) or input_word(s,72) != INSERT:
            return BAD
        return open_store(o,w,FINAL_DB_OPEN)
    if state == KEY_PREPARED:
        if size != 120:
            return BAD
        return store_transaction(o,w,FINAL_LOOKUP,9,0,fd,0,120)
    if state == ROW_CUSTODY:
        return certify_running(s,o,w)
    if state == RECEIPT_CAPTURE:
        return attest_two_writes(s,o,w)
    if state == FINAL_DONE:
        if length(s) != 64:
            return BAD
        return action(o,w,FINAL_DONE,FINISHED,0,0,0,0)
    return BAD

def final_opened(o:mutbuf,w:mutbuf) -> u64:
    put(o,HEADER,QUERY)
    put(o,HEADER+8,1)
    put(o,HEADER+16,1)
    put(o,HEADER+24,120)
    put(o,HEADER+32,3)
    put(o,HEADER+40,56)
    put(o,HEADER+48,64)
    copy_private(w,o,CLAIM_KEY,HEADER+56,64)
    return action(o,w,KEY_PREPARED,MAKE,0,0,0,120)

def row_cell(s:readbuf,at:u64,kind:u64,pos:u64,width:u64) -> bool:
    return input_word(s,at) == kind and input_word(s,at+8) == pos and input_word(s,at+16) == width

def certify_running(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    width = length(s)-64
    if width < 324 or width > 343 or input_word(s,64) != ROW or input_word(s,72) != 1 or input_word(s,80) != 4 or input_word(s,88) != 6:
        return BAD
    if row_cell(s,96,3,176,64) == False or row_cell(s,120,3,240,64) == False or row_cell(s,144,3,304,12) == False:
        return BAD
    if row_cell(s,168,3,316,7) == False or row_cell(s,192,0,323,0) == False or row_cell(s,216,3,323,width-323) == False:
        return BAD
    i = 0
    while i < 64:
        if byte(s,240+i) != byte(w,CLAIM_KEY+i) or byte(s,304+i) != byte(w,CLAIM_DIGEST+i):
            return BAD
        i = i+1
    if input_word(s,368) != TOOL_A or (input_word(s,376) & 4294967295) != TOOL_B or (input_word(s,380) & 72057594037927935) != RUNNING:
        return BAD
    # Compare decimal text without overflow, including the maximum u64 UTC.
    value = get(w,CLAIM_TIME)
    end = 64+width
    i = 0
    while end-i > 387:
        quotient = divide_ten(value)
        if byte(s,end-i-1) != 48+value-10*quotient:
            return BAD
        value = quotient
        i = i+1
    if value != 0 or byte(s,387) == 48:
        return BAD
    return store_transaction(o,w,FINAL_UPDATE,22,0,get(w,FINAL_STMT),get(w,FINAL_STMT+8),get(w,FINAL_STMT+16))

def divide_ten(value:u64) -> u64:
    total = 0
    bit = 1152921504606846976
    while bit != 0:
        if value >= bit*10:
            value = value-bit*10
            total = total+bit
        bit = bit >> 1
    return total

def final_store_ack(s:readbuf,o:mutbuf,w:mutbuf,which:u64,n:u64,found:u64) -> u64:
    if which == FINAL_LOOKUP:
        if found != 1 or n < 324 or n > 343:
            return BAD
        return read_span(o,w,ROW_CUSTODY,slot_fd(w,STORE_RESULT),0,n)
    if which == FINAL_COMMIT:
        if found != 2 or n != 8:
            return BAD
        return read_span(o,w,COMMIT_INTENT_SEEN,slot_fd(w,STORE_RESULT),0,8)
    if found != 1 or n != 0:
        return BAD
    return read_span(o,w,RECEIPT_CAPTURE,slot_fd(w,STORE_RESULT),0,48)

def attest_two_writes(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if length(s) != 112:
        return BAD
    purpose = get(w,STORE_PURPOSE)
    if purpose == FINAL_UPDATE:
        copy_span(s,w,64,FIRST_WRITE,48)
        return store_transaction(o,w,FINAL_INSERT,18,0,get(w,FINAL_COST),get(w,FINAL_COST+8),get(w,FINAL_COST+16))
    if purpose != FINAL_INSERT:
        return BAD
    put(o,HEADER+48,EVAL_COMMIT)
    put(o,HEADER+56,2)
    copy_private(w,o,FIRST_WRITE,HEADER+64,48)
    copy_span(s,o,64,HEADER+112,48)
    return store_transaction(o,w,FINAL_COMMIT,37,0,0,0,112)
'''

def program():
    data = b'{"error":null,"replayed":false}'
    words = dict(KEYED_SCHEMA=b'HIAESR01',KEYED_REFUSAL=b'HIAERJ01',CONTEXT_PREFIX=b'ctx-',CLAIM_STATE=b'HIAJRN02',CLAIM_ROUTE=b'HIAJMO01',UPDATE_WIRE=b'HIAUPB01',CLOSE_INPUT=b'HIAEFC01', PROJECTION=b'HIAEPU01', CLAIM_MAGIC=b'HIAEJC01',
                 TERMINAL=b'HIAESTR1', SIDEBAND=b'HIAIND01', COST=b'HIAJCF01', INSERT=b'HIAINS01',
                 QUERY=b'HIAQPA01', ROW=b'HIAROW01', RUNNING=b'running', EVAL_COMMIT=b'HIAETC01',
                 INTENT=b'HIASTCP1', TOOL_A=b'hia_eval', TOOL_B=b'uate')
    words.update(ERROR_PREFIX0=b'{"error"',ERROR_END0=b',"replay',ERROR_END1=b'ed":fals',ERROR_END2=b'e}')
    words.update({f'DETAIL{i}':data[8*i:8*i+8] for i in range(4)})
    constants = {k:int.from_bytes(v,'little') for k,v in words.items()}
    states=('CLOSE_HEADER','CLAIM_FIXED','PLAN_EXTEND','PLAN_READY','SETTLEMENT_READY','TERMINAL_HEADER',
            'SIDEBAND_CONTEXT','FINAL_CLOCK','COST_READY','COST_WIRE_CHECK','KEY_PREPARED','ROW_CUSTODY',
            'RECEIPT_CAPTURE','COMMIT_INTENT_SEEN','FINAL_DONE')
    constants.update({name:1700+i for i,name in enumerate(states)})
    purposes=('FINAL_DB_OPEN','FINAL_LOOKUP','FINAL_UPDATE','FINAL_INSERT','FINAL_COMMIT','FINAL_DB_CLOSED')
    constants.update({name:1800+i for i,name in enumerate(purposes)})
    constants.update(SHAPE_REASON=256,GLOBAL_COST=13008,DIAGNOSTIC_LIMIT=65536,EMIT_WORK_BYTES=16384,ERROR_HEADER=1750,ERROR_REPLY=1751,ERROR_UPDATE=1752,FINAL_STATUS=12968,ERROR_BODY=12976,PLANNER_ROLE=7,SETTLE_ROLE=8,FINAL_COST_ROLE=9,
                     LATE_PARTS=12320,LATE_MODE=12512,LATE_INDEX=12520,ADMISSION_NS=12528,
                     FRAME_FD=12536,FRAME_SIZE=12544,CLAIM_TIME=12552,CLAIM_DIGEST=12560,
                     CLAIM_KEY=12624,CLAIM_PUBLIC=12688,FINAL_CONTEXT=12760,
                     FINAL_FRAME=12800,FINAL_REPLY=12824,FINAL_STMT=12848,FINAL_COST=12872,FIRST_WRITE=12900)
    entry=ENTRY.replace('def evaluate_document(', 'def evaluate_closeout(')
    entry=entry.replace('if size <= 96:', 'if size < 676 or size == 677:')
    entry=entry.replace('return read_span(o, w, DOC_HEADER, 0, 0, 96)','return read_span(o,w,CLOSE_HEADER,0,0,48)')
    entry=entry.replace('    if state == DOC_HEADER:', '''    if state == ERROR_HEADER:
        return refusal_header(s,o,w)
    if state == ERROR_REPLY or state == ERROR_UPDATE:
        return refusal_products(s,o,w,state)
    if state >= CLOSE_HEADER and state <= TERMINAL_HEADER:
        return late_product(s,o,w,state)
    if state == COMMIT_INTENT_SEEN:
        if length(s) != 72 or input_word(s,64) != INTENT:
            return BAD
        return close_store(o,w,FINAL_DB_CLOSED)
    if state >= SIDEBAND_CONTEXT and state <= FINAL_DONE:
        return commit_steps(s,o,w,state)
    if state == DOC_HEADER:''')
    entry=entry.replace('slot_bytes(w, ORIGINAL) - 96','get(w,FRAME_SIZE)-96')
    entry=entry.replace('hold(w, DOC_BODY, 0, 96, size)','hold(w,DOC_BODY,get(w,FRAME_FD),96,size)')
    start=entry.index('    ref = EMIT_ARTIFACT_REFS',entry.index('def emit_publication_complete'))
    entry=entry[:start]+'    return document_stored(o,w)\n'
    def adjust(name,src):
        if name=='opened_store':
            src=src.replace('    if get(w, STORE_PURPOSE)', '    if get(w,STORE_PURPOSE) == FINAL_DB_OPEN:\n        return final_opened(o,w)\n    if get(w, STORE_PURPOSE)',1)
        if name=='closed_store':
            src=src.replace('    if get(w, STORE_PURPOSE)', '    if get(w,STORE_PURPOSE) == FINAL_DB_CLOSED:\n        use_span(w,o,FINAL_REPLY,0)\n        return action(o,w,FINAL_DONE,PUBLISH,0,0,1,0)\n    if get(w, STORE_PURPOSE)',1)
        if name=='store_transaction':
            src=src.replace('if purpose == STORE_RESERVATION_COMMIT:', 'if purpose == STORE_RESERVATION_COMMIT or purpose == FINAL_COMMIT:')
        if name=='settle_transaction':
            src=src.replace('found > 1','found > choose(get(w,STORE_PURPOSE) == FINAL_COMMIT,2,1)')
            src=src.replace('    if purpose != EMIT_PUB_LOOKUP', '    if purpose >= FINAL_LOOKUP and purpose <= FINAL_COMMIT:\n        return final_store_ack(s,o,w,purpose,bytes,found)\n    if purpose != EMIT_PUB_LOOKUP')
        return src
    from tools.generate_hia_worker_evaluate_keyed_rejection import CLOSEOUT,closeout_literals
    return document_program(entry=entry+LATE+JOURNAL+CLOSEOUT+closeout_literals(),roles=ROLES,root='evaluate_closeout',extra=constants,adjust=adjust)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(),SOURCE.stem)))
