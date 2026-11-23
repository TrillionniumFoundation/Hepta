"""Drive one paired Evaluate through a live Store, native budget session and physical runner."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_adopt_proof import reachable_policy
from tools.generate_hia_worker_artifact_flow import ENTRY_POLICY, POLICY as ARTIFACT
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_describe_flow import POLICY as DESCRIBE
from tools.generate_hia_worker_read_store_flow import POLICY as READ
from tools.generate_hia_worker_verify_publication_flow import recipe as publication


SOURCE = Path('examples/hia_bootstrap/worker_evaluate_run_flow.hepta')
ROLES = ('hia-agent-store', 'hia-execution-budget-session', 'hia-evaluate-budget-observation',
         'hia-evaluate-budget-store', 'hia-evaluate-paired-batch', 'hia-direct-call')

POLICY = '''
def execute(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o) != 2048 or length(w) != 12288 or length(s) < 8:
        return BAD
    state = get(w,0)
    if state == 0:
        if input_word(s,0) != ENTRY or admit_entry(s,o) != 344:
            return BAD
        keep(w,0,0,input_word(s,8))
        j = 0
        while j < ROLE_COUNT:
            put(w,ROLE_BASE+8*j,input_word(s,376+40*j))
            j = j+1
        return read_span(o,w,PLAN_HEADER,0,0,196)
    if length(s) < 64 or input_word(s,0) != OBSERVATION or input_word(s,8) != get(w,8) or input_word(s,16) != get(w,16) or input_word(s,24) != 0:
        return BAD
    size = input_word(s,40)
    if input_word(s,56) != length(s)-64 or size > MAX_INPUT or input_word(s,56) > size:
        return BAD
    if state == PLAN_HEADER:
        if size != slot_bytes(w,0) or length(s) != 260 or input_word(s,64) != PLAN:
            return BAD
        begin = input_word(s,72)
        expiry = input_word(s,80)
        maximum = input_word(s,88)
        mem = input_word(s,96)
        if begin == 0 or expiry == 0 or maximum == 0 or maximum > 3600000 or mem < 67108864 or mem > 4294967296:
            return BAD
        put(w,ENTERED,begin)
        put(w,EXPIRES,expiry)
        put(w,MAX_MS,maximum)
        put(w,MEMORY,mem)
        at = 196
        i = 0
        while i < 7:
            bytes = input_word(s,104+8*i)
            if bytes == 0 or at > size or bytes > size-at:
                return BAD
            put(w,SPANS+16*i,at)
            put(w,SPANS+16*i+8,bytes)
            at = at+bytes
            i = i+1
        if at != size or (input_word(s,160) & 4294967295) != CTX:
            return BAD
        i = 4
        while i < 100:
            if is_hex(byte(s,160+i)) == False:
                return BAD
            i = i+1
        copy_span(s,w,160,IDENTITY,100)
        return slice_input(o,w,0)
    if state == SEGMENT_MADE:
        i = get(w,INDEX)
        if i >= 7 or size != get(w,SPANS+16*i+8):
            return BAD
        observe_slot(s,w,i+1)
        if i < 6:
            return slice_input(o,w,i+1)
        return clock_sample(o,w,SAMPLED_MONO,0)
    if state == SAMPLED_MONO:
        if length(s) != 72 or input_word(s,64) < get(w,ENTERED):
            return BAD
        put(w,SAMPLE_MONO,input_word(s,64))
        return clock_sample(o,w,SAMPLED_UTC,1)
    if state == SAMPLED_UTC:
        now = input_word(s,64)
        expiry = get(w,EXPIRES)
        if length(s) != 72 or now == 0 or now >= expiry or expiry-now > 86400000000000 or get(w,SAMPLE_MONO) > MAX-(expiry-now):
            return BAD
        put(w,DEADLINE_AT,get(w,SAMPLE_MONO)+expiry-now)
        put(o,HEADER,CHECK_CONTROL)
        put(o,HEADER+8,get(w,MEMORY))
        put(o,HEADER+16,get(w,DEADLINE_AT))
        return action(o,w,CHECK_LIMITS,MAKE,0,0,0,24)
    if state >= CHECK_LIMITS and state <= CHECK_REFUSED:
        return reference_precheck(s,o,w,state,size)
    if state == RANDOM_IDS:
        if length(s) != 96 or input_word(s,72) == 0 or input_word(s,88) == 0:
            return BAD
        copy_span(s,w,64,TOKENS,32)
        argv(o,0,INPUT_ARG,2)
        put(o,160,STORE_ARG)
        argv(o,1,LITERAL_ARG,160)
        argv(o,2,INPUT_ARG,3)
        put(o,176,0)
        return action(o,w,OPEN_STORE,START_PEER,0,3,0,0)
    if state == OPEN_STORE:
        if good_peer(s) == False:
            return BAD
        return receive(o,w,FIRST_ACK,0,80,True)
    if state == FIRST_ACK:
        if length(s) != 144 or input_word(s,64) != ACK:
            return BAD
        put(w,EPOCH,input_word(s,112))
        observe_slot(s,w,DATA_SLOT)
        put(o,176,1)
        return action(o,w,OPEN_BUDGET,START_PEER,1,0,0,0)
    if state == OPEN_BUDGET:
        if good_peer(s) == False:
            return BAD
        return observe_budget(o,w,0)
    if state == OBS_PROJECTED:
        if size < 128 or size > 4700 or input_word(s,64) != BUDGET_REQUEST:
            return BAD
        put(o,HEADER,size)
        fragment(o,0,input_word(s,32),0,size)
        put(o,176,1)
        return action(o,w,BUDGET_SENT,SEND_PEER,0,0,1,8)
    if state == BUDGET_SENT:
        return receive(o,w,BUDGET_SIZE,1,8,False)
    if state == BUDGET_SIZE:
        n = input_word(s,64)
        if length(s) != 72 or n < 128 or n > 8192:
            return BAD
        return receive(o,w,BUDGET_REPLY,1,n,True)
    if state == BUDGET_REPLY:
        if length(s) != 64+size or size < 128 or input_word(s,64) != BUDGET_RECEIPT or input_word(s,72) != 0 or input_word(s,120) != 1:
            return BAD
        next = input_word(s,112)
        if next != get(w,BUDGET_SEQ)+1 or input_word(s,88) != next:
            return BAD
        put(w,BUDGET_SEQ,next)
        put(w,AUTH_ACTION,input_word(s,80))
        put(w,AUTH_PHASE,input_word(s,104))
        put(w,GRANT_MS,input_word(s,96))
        observe_slot(s,w,RECEIPT_SLOT)
        if get(w,MODE) == 2:
            return send_pair_reply(o,w)
        return budget_effect(o,w)
    if state == COMMAND_READY:
        if size < 48 or size > 8192 or input_word(s,64) != STORE_COMMAND:
            return BAD
        fragment(o,0,input_word(s,32),0,size)
        put(o,176,0)
        return action(o,w,COMMAND_SENT,SEND_PEER,0,0,1,0)
    if state == COMMAND_SENT:
        a = get(w,AUTH_ACTION)
        if a == 2:
            keep(w,DATA_SLOT,0,0)
            return receive(o,w,ROW_HEADER,0,64,True)
        return receive(o,w,FIXED_STORE,0,choose(a==6,336,80),True)
    if state == FIXED_STORE:
        observe_slot(s,w,DATA_SLOT)
        return observe_budget(o,w,1)
    if state >= ROW_HEADER and state <= ROW_ENDED:
        return query_receive(s,o,w,state)
    if state == LIMITS_MADE:
        observe_slot(s,w,LIMITS_SLOT)
        pair_arguments(o,w)
        put(o,176,2)
        return action(o,w,PAIR_STARTED,START_PEER,4,9,0,0)
    if state == PAIR_STARTED:
        if good_peer(s) == False:
            return BAD
        return receive(o,w,PAIR_TAG,2,8,False)
    if state == PAIR_TAG:
        if length(s) != 72:
            return BAD
        tag = input_word(s,64)
        if tag == GATE:
            return receive(o,w,GATE_BODY,2,56,True)
        if tag == ARCHIVE:
            return receive(o,w,ARCHIVE_SIZES,2,24,False)
        return BAD
    if state == GATE_BODY:
        if size != 56 or length(s) != 120:
            return BAD
        put(o,HEADER,GATE)
        fragment(o,0,input_word(s,32),0,56)
        put(w,CURRENT_GATE,input_word(s,64))
        return action(o,w,GATE_MADE,MAKE,0,0,1,8)
    if state == GATE_MADE:
        observe_slot(s,w,DATA_SLOT)
        return clock_sample(o,w,GATE_CLOCK,0)
    if state == GATE_CLOCK:
        if length(s) != 72:
            return BAD
        put(w,NOW,input_word(s,64))
        return observe_budget(o,w,2)
    if state == PAIR_ACKED:
        return receive(o,w,PAIR_TAG,2,8,False)
    if state == ARCHIVE_SIZES:
        head = input_word(s,64)
        bytes = input_word(s,72)
        count = input_word(s,80)
        if length(s) != 88 or head < 80 or head > 1048576 or bytes > MAX_INPUT-32-head or count > bytes:
            return BAD
        put(w,ARCHIVE_HEAD,head)
        put(w,ARCHIVE_BYTES,bytes)
        put(w,ARCHIVE_COUNT,count)
        put(o,144,head+bytes)
        put(o,176,2)
        put(o,184,2)
        return action(o,w,ARCHIVE_STREAMED,RECEIVE_PEER,0,0,0,0)
    if state == ARCHIVE_STREAMED:
        if size != get(w,ARCHIVE_HEAD)+get(w,ARCHIVE_BYTES) or input_word(s,64) != PAIR_RESULT:
            return BAD
        put(o,HEADER,ARCHIVE)
        put(o,HEADER+8,get(w,ARCHIVE_HEAD))
        put(o,HEADER+16,get(w,ARCHIVE_BYTES))
        put(o,HEADER+24,get(w,ARCHIVE_COUNT))
        fragment(o,0,input_word(s,32),0,size)
        return action(o,w,ARCHIVE_MADE,MAKE,0,0,1,32)
    if state == ARCHIVE_MADE:
        observe_slot(s,w,ARCHIVE_SLOT)
        return close(o,w,PAIR_CLOSED,2)
    if state == PAIR_CLOSED:
        return observe_budget(o,w,3)
    if state == BUDGET_CLOSED:
        return close(o,w,STORE_CLOSED,0)
    if state == STORE_CLOSED:
        put(o,HEADER,RESULT)
        put(o,HEADER+8,get(w,ENTERED))
        put(o,HEADER+16,slot_bytes(w,ARCHIVE_SLOT))
        put(o,HEADER+24,slot_bytes(w,RECEIPT_SLOT))
        whole_slot(w,o,ARCHIVE_SLOT,0)
        whole_slot(w,o,RECEIPT_SLOT,1)
        return action(o,w,RESULT_MADE,MAKE,0,0,2,32)
    if state == RESULT_MADE:
        if input_word(s,64) != RESULT:
            return BAD
        fragment(o,0,input_word(s,32),0,size)
        return action(o,w,PUBLISHED,PUBLISH,0,0,1,0)
    if state == PUBLISHED:
        return action(o,w,PUBLISHED,FINISHED,0,0,0,0)
    return BAD

def reference_precheck(s:readbuf,o:mutbuf,w:mutbuf,state:u64,size:u64) -> u64:
    if state == CHECK_LIMITS:
        if size != 24 or input_word(s,64) != CHECK_CONTROL:
            return BAD
        observe_slot(s,w,LIMITS_SLOT)
        pair_arguments(o,w)
        return action(o,w,CHECK_SCANNED,RUN,4,9,0,0)
    if state == CHECK_SCANNED:
        if size != 80 or input_word(s,64) != PAIR_RESULT:
            return BAD
        return read_span(o,w,CHECK_RESULT,input_word(s,32),0,80)
    if state == CHECK_RESULT:
        if length(s) != 144 or input_word(s,64) != PAIR_RESULT:
            return BAD
        status = input_word(s,72)
        count = input_word(s,80)
        if count == 0 or count > 512 or input_word(s,88) != 0 or input_word(s,96) != 0 or input_word(s,104) != 0 or input_word(s,112) != 0 or input_word(s,120) != 0:
            return BAD
        if status == 5:
            index = input_word(s,128)
            if index >= count or input_word(s,136) != 2:
                return BAD
            put(o,HEADER,EXPECTED_REFUSAL)
            put(o,HEADER+8,get(w,ENTERED))
            put(o,HEADER+16,index)
            put(o,HEADER+24,count)
            copy_private(w,o,IDENTITY,HEADER+32,36)
            return action(o,w,CHECK_REFUSED,MAKE,0,0,0,68)
        if status > 2:
            return BAD
        put(o,144,32)
        return action(o,w,RANDOM_IDS,RANDOM,0,0,0,0)
    if state == CHECK_REFUSED:
        if size != 68 or input_word(s,64) != EXPECTED_REFUSAL:
            return BAD
        fragment(o,0,input_word(s,32),0,68)
        return action(o,w,PUBLISHED,PUBLISH,0,0,1,0)
    return BAD

def pair_arguments(o:mutbuf,w:mutbuf) -> u64:
    argv(o,0,FD_ARG,slot_fd(w,1))
    argv(o,1,FD_ARG,slot_fd(w,2))
    argv(o,2,FD_ARG,slot_fd(w,3))
    argv(o,3,FD_ARG,get(w,ROLE_BASE+40))
    argv(o,4,FD_ARG,slot_fd(w,4))
    argv(o,5,FD_ARG,slot_fd(w,LIMITS_SLOT))
    argv(o,6,FD_ARG,slot_fd(w,5))
    argv(o,7,FD_ARG,slot_fd(w,6))
    argv(o,8,FD_ARG,slot_fd(w,7))
    return 0

def good_peer(s:readbuf) -> bool:
    return length(s) == 80 and valid_fd(input_word(s,64)) and valid_fd(input_word(s,72)) and input_word(s,64) != input_word(s,72)

def close(o:mutbuf,w:mutbuf,next:u64,peer:u64) -> u64:
    put(o,176,peer)
    return action(o,w,next,FINISH_PEER,0,0,0,0)

def slice_input(o:mutbuf,w:mutbuf,i:u64) -> u64:
    put(w,INDEX,i)
    fragment(o,0,0,get(w,SPANS+16*i),get(w,SPANS+16*i+8))
    return action(o,w,SEGMENT_MADE,MAKE,0,0,1,0)

def observe_budget(o:mutbuf,w:mutbuf,mode:u64) -> u64:
    put(w,MODE,mode)
    put(o,HEADER,OBS_INPUT)
    put(o,HEADER+8,mode)
    put(o,HEADER+16,get(w,STORE_ORD))
    put(o,HEADER+24,get(w,EPOCH))
    put(o,HEADER+32,get(w,BUDGET_SEQ))
    put(o,HEADER+40,choose(mode==0,get(w,SAMPLE_MONO),get(w,NOW)))
    put(o,HEADER+48,get(w,DEADLINE_AT))
    put(o,HEADER+56,get(w,MAX_MS))
    copy_private(w,o,TOKENS,HEADER+64,32)
    prior = slot_bytes(w,RECEIPT_SLOT)
    data = choose(mode==1 or mode==2,slot_bytes(w,DATA_SLOT),0)
    put(o,HEADER+96,prior)
    put(o,HEADER+104,data)
    copy_private(w,o,IDENTITY,HEADER+112,100)
    k = 0
    if prior != 0:
        whole_slot(w,o,RECEIPT_SLOT,0)
        k = 1
    if data != 0:
        whole_slot(w,o,DATA_SLOT,k)
        k = k+1
    return action(o,w,OBS_PROJECTED,RUN,2,0,k,212)

def budget_effect(o:mutbuf,w:mutbuf) -> u64:
    phase = get(w,AUTH_PHASE)
    op = get(w,AUTH_ACTION)
    if op == 1 and get(w,STORE_ORD) == 0 and get(w,BUDGET_SEQ) == 1:
        return observe_budget(o,w,1)
    if op == 0 and phase == 7:
        if get(w,PAIR_BEGAN) != 0:
            return BAD
        put(w,PAIR_BEGAN,1)
        put(o,HEADER,CONTROL)
        put(o,HEADER+8,get(w,MEMORY))
        put(o,HEADER+16,get(w,DEADLINE_AT))
        whole_slot(w,o,RECEIPT_SLOT,0)
        return action(o,w,LIMITS_MADE,MAKE,0,0,1,24)
    if op == 0 and phase == 8:
        if slot_bytes(w,ARCHIVE_SLOT) < 112:
            return BAD
        return close(o,w,BUDGET_CLOSED,1)
    if op != 1 and op != 2 and op != 4 and op != 5 and op != 6:
        return BAD
    if op == 1 and get(w,PAIR_BEGAN) == 1:
        put(w,EPOCH,get(w,EPOCH)+1)
    n = get(w,STORE_ORD)+1
    put(w,STORE_ORD,n)
    put(o,HEADER,COMMAND_INPUT)
    put(o,HEADER+8,n)
    copy_private(w,o,IDENTITY,HEADER+16,100)
    whole_slot(w,o,RECEIPT_SLOT,0)
    return action(o,w,COMMAND_READY,RUN,3,0,1,116)

def query_receive(s:readbuf,o:mutbuf,w:mutbuf,state:u64) -> u64:
    if state == ROW_HEADER:
        if length(s) != 128 or input_word(s,64) != ROW_FRAME:
            return BAD
        kind = input_word(s,72)
        size = input_word(s,104)
        if kind < 1 or kind > 4 or size > 8128:
            return BAD
        put(w,ROW_KIND,kind)
        put(w,ROW_LENGTH,size)
        observe_slot(s,w,CHUNK_SLOT)
        if size == 0:
            return append_row(o,w,False)
        return receive(o,w,ROW_BODY,0,size,True)
    if state == ROW_BODY:
        if input_word(s,40) != get(w,ROW_LENGTH):
            return BAD
        observe_slot(s,w,PAYLOAD_SLOT)
        return append_row(o,w,True)
    if state == ROW_JOINED:
        if input_word(s,40) > 8192:
            return BAD
        observe_slot(s,w,DATA_SLOT)
        if get(w,ROW_KIND) == 4:
            return receive(o,w,ROW_ACK,0,80,True)
        return receive(o,w,ROW_HEADER,0,64,True)
    if state == ROW_ACK:
        if length(s) != 144 or input_word(s,64) != ACK:
            return BAD
        whole_slot(w,o,DATA_SLOT,0)
        fragment(o,1,input_word(s,32),0,80)
        return action(o,w,ROW_ENDED,MAKE,0,0,2,0)
    if state == ROW_ENDED:
        observe_slot(s,w,DATA_SLOT)
        return observe_budget(o,w,1)
    return BAD

def append_row(o:mutbuf,w:mutbuf,body:bool) -> u64:
    count = 0
    if slot_bytes(w,DATA_SLOT) != 0:
        whole_slot(w,o,DATA_SLOT,0)
        count = 1
    whole_slot(w,o,CHUNK_SLOT,count)
    count = count+1
    if body:
        whole_slot(w,o,PAYLOAD_SLOT,count)
        count = count+1
    return action(o,w,ROW_JOINED,MAKE,0,0,count,0)

def send_pair_reply(o:mutbuf,w:mutbuf) -> u64:
    event = get(w,CURRENT_GATE)
    action_code = get(w,AUTH_ACTION)
    if get(w,AUTH_PHASE) != 7 or (event == 5 and action_code != 7) or (event == 6 and action_code != 0) or (event != 5 and event != 6):
        return BAD
    put(o,HEADER,slot_bytes(w,RECEIPT_SLOT))
    whole_slot(w,o,RECEIPT_SLOT,0)
    put(o,176,2)
    return action(o,w,PAIR_ACKED,SEND_PEER,0,0,1,8)
'''


def program():
    constants, _, controls = publication()
    states = ('PLAN_HEADER SEGMENT_MADE SAMPLED_MONO SAMPLED_UTC RANDOM_IDS OPEN_STORE FIRST_ACK OPEN_BUDGET '
              'OBS_PROJECTED BUDGET_SENT BUDGET_SIZE BUDGET_REPLY COMMAND_READY COMMAND_SENT FIXED_STORE '
              'ROW_HEADER ROW_BODY ROW_JOINED ROW_ACK ROW_ENDED LIMITS_MADE PAIR_STARTED PAIR_TAG GATE_BODY '
              'GATE_MADE GATE_CLOCK PAIR_ACKED ARCHIVE_SIZES ARCHIVE_STREAMED ARCHIVE_MADE PAIR_CLOSED '
              'BUDGET_CLOSED STORE_CLOSED RESULT_MADE PUBLISHED CHECK_LIMITS CHECK_SCANNED CHECK_RESULT CHECK_REFUSED').split()
    constants.update({name: 2000 + i for i, name in enumerate(states)})
    fields = ('ENTERED EXPIRES MAX_MS MEMORY INDEX SAMPLE_MONO DEADLINE_AT EPOCH MODE BUDGET_SEQ '
              'AUTH_ACTION AUTH_PHASE STORE_ORD PAIR_BEGAN CURRENT_GATE NOW ARCHIVE_HEAD ARCHIVE_BYTES '
              'ARCHIVE_COUNT ROW_KIND ROW_LENGTH GRANT_MS').split()
    constants.update({name: 2304 + 8*i for i,name in enumerate(fields)})
    constants.update(SPANS=2560, IDENTITY=2720, TOKENS=2832, MAX_INPUT=67108864,
                     ROLE_COUNT=len(ROLES), ENTRY_BYTES=376+40*len(ROLES), MAX=(1<<64)-1,
                     RECEIPT_SLOT=9, DATA_SLOT=10, CHUNK_SLOT=11, PAYLOAD_SLOT=12,
                     LIMITS_SLOT=13, ARCHIVE_SLOT=14)
    labels = dict(PLAN=b'HIAEXI01', RESULT=b'HIAEXO01', ACK=b'HIATXR01', CTX=b'ctx-',
                  BUDGET_REQUEST=b'HIAEBRQ1', BUDGET_RECEIPT=b'HIAEBRS1', OBS_INPUT=b'HIAEBO01',
                  COMMAND_INPUT=b'HIAEBC01', CONTROL=b'HIAEPL04', CHECK_CONTROL=b'HIAEPL05', EXPECTED_REFUSAL=b'HIAEXR01', GATE=b'HIAEPGT1', ARCHIVE=b'HIAEMT01',
                  STORE_COMMAND=b'HIATCM01', ROW_FRAME=b'HIAQRF01', PAIR_RESULT=b'HIAEPM01')
    constants.update({name: int.from_bytes(value,'little') for name,value in labels.items()})
    names = ('admit_entry','dossier_identity','trusted_descriptors')
    entries = [POLICY, *controls]
    for policy, name in [*((ENTRY_POLICY, name) for name in names), (ARTIFACT,'clock_sample'), (READ,'receive')]:
        if not any('def '+name+'(' in item for item in entries):
            entries.append(function(policy, name))
    source = '\n'.join(entries)
    source = source.replace('seq > 160','seq > 4096')
    source = source.replace('        put(o, 152, DEFAULT_CHILD_LEASE)',
        '        lease = DEFAULT_CHILD_LEASE\n'
        '        if next == CHECK_SCANNED:\n            lease = lease+get(w,DEADLINE_AT)-get(w,SAMPLE_MONO)\n'
        '        if next == PAIR_TAG and get(w,AUTH_ACTION) == 7:\n'
        '            available = get(w,GRANT_MS)\n'
        '            if available > 3600000:\n'
        '                return BAD\n'
        '            lease = lease+1000000*available\n'
        '        put(o,152,lease)')
    entry, helpers = reachable_policy(source, 'execute')
    return flow_source(entry, helpers, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
