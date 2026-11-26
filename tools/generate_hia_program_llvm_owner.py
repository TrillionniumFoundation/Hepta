"""Native HIA owner for bounded canonical Core to LLVM rendering.

This author emits source for the fixed decoder and all rendering phases.
Independent Core verification and public origin binding are enclosing owners.
"""
from pathlib import Path
from tools.generate_hia_program_llvm_common import write_module,document,ROOT
from tools.generate_hia_program_llvm_flow import SOURCE as FLOW_SOURCE
from tools.generate_hia_json_decode import source_program as decoder_source
from hepta.hia_agent_assembly import render_assembly

SOURCE=r'''
def llvm_owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<WORK:
        return 4294967293
    phase=get(w,PHASE)
    if phase==0:
        return begin(s,o,w)
    if get(w,ERROR)!=0:
        return get(w,ERROR)
    if phase==1:
        if get(w,ROOT_RESULT)>=4294967292 or get(w,0)!=5208772604367785521 or get(w,8)==0 or get(w,8)>MAX_NODES:
            return 4294967291
        if get(w,24)>CTRL or get(w,40)!=length(s)-ARG_HEADER:
            return 4294967291
        fill_range(w,META,get(w,8)*128,0)
        slots=2
        while slots<get(w,8)*2:
            slots=slots*2
        put(w,SLOTS,slots)
        fill_range(w,HASH,slots*24,0)
        version=version_number(w,field(w,0,K_schema))
        if version==0:
            return 4294967291
        put(w,VERSION,version)
        put(w,ROOT_RESULT,0)
        put(w,PHASE,2)
        return 25
    if phase==2:
        if get(w,LAYOUT)!=0 and get(w,TARGET)!=0:
            return 4294967288
        put(w,FN_CURSOR,0)
        put(w,PHASE,20)
        return 2
    if phase==20:
        index=get(w,FN_CURSOR)
        if index==get(w,FUNCTION_COUNT):
            if get(w,LAYOUT)!=0 and get(w,OUTLINED)==0:
                return 4294967288
            put(w,DEST,FINAL)
            put(w,POS,0)
            put(w,ROOT_RESULT,1)
            put(w,PHASE,3)
            return 25
        put(w,FN,get(w,FUNCS+index*8))
        put(w,FN_INDEX,index)
        put(w,ROOT_RESULT,2)
        put(w,PHASE,21)
        return 25
    if phase==21:
        put(w,PHASE,22)
        return 24
    if phase==22:
        put(w,FN_CURSOR,get(w,FN_CURSOR)+1)
        put(w,PHASE,20)
        return 2
    if phase==3:
        put(w,FINAL_POS,get(w,POS))
        put(w,FN_CURSOR,0)
        put(w,PHASE,4)
        return 2
    if phase==4:
        index=get(w,FN_CURSOR)
        if index==get(w,FUNCTION_COUNT):
            put(w,FN_CURSOR,0)
            put(w,WRAPPER_CURSOR,0)
            put(w,PHASE,10)
            return 2
        put(w,FN,get(w,FUNCS+index*8))
        put(w,FN_INDEX,index)
        if meta(w,get(w,FN),0)==1:
            put(w,DEST,FINAL)
            put(w,POS,get(w,FINAL_POS))
            put(w,PHASE,30)
            return 27
        put(w,ROOT_RESULT,2)
        put(w,PHASE,5)
        return 25
    if phase==30:
        emit(w,"\n\n")
        put(w,FINAL_POS,get(w,POS))
        put(w,COMPONENT,1)
        put(w,FN_INDEX,meta(w,get(w,FN),40))
        put(w,ROOT_RESULT,2)
        put(w,PHASE,5)
        return 25
    if phase==5:
        ordinal=get(w,ORDER_INDEX)
        if ordinal==get(w,BLOCK_COUNT):
            put(w,DEST,FINAL)
            put(w,POS,get(w,FINAL_POS))
            put(w,ROOT_RESULT,1)
            put(w,PHASE,8)
            return 23
        block=ordered_block(w,ordinal,get(w,ENTRY_INDEX))
        put(w,BLOCK,block)
        put(w,ROOT_RESULT,3)
        put(w,PHASE,6)
        return 25
    if phase==6:
        block=get(w,BLOCK)
        if meta(w,block,72)==1 and get(w,INS_NEXT)!=NONE:
            put(w,INS_NEXT,NONE)
            return 26
        ins=get(w,INS_NEXT)
        if ins==NONE:
            put(w,INS,field(w,get(w,BLOCK),K_term))
            put(w,ROOT_RESULT,0)
            put(w,PHASE,7)
            return 23
        put(w,INS,ins)
        put(w,INS_NEXT,next(w,ins))
        op=opcode(w,field(w,ins,K_op))
        if op>=1 and op<=OP_call:
            return 20
        if op>=OP_buffer_new and op<=OP_buffer_store:
            return 21
        if op>=OP_buffer_fill and op<=OP_buffer_swap:
            return 22
        return 4294967291
    if phase==7:
        block=get(w,BLOCK)
        setmeta(w,block,64,get(w,POS)-meta(w,block,56))
        put(w,ORDER_INDEX,get(w,ORDER_INDEX)+1)
        put(w,PHASE,5)
        return 2
    if phase==8:
        emit(w,"\n\n")
        put(w,FINAL_POS,get(w,POS))
        if get(w,COMPONENT)==1:
            put(w,COMPONENT,2)
            put(w,FN_INDEX,meta(w,get(w,FN),40)+1)
            put(w,ROOT_RESULT,2)
            put(w,PHASE,5)
            return 25
        put(w,COMPONENT,0)
        put(w,FN_CURSOR,get(w,FN_CURSOR)+1)
        put(w,PHASE,4)
        return 2
    if phase==10:
        index=get(w,FN_CURSOR)
        if index==get(w,FUNCTION_COUNT):
            put(w,PHASE,12)
            return 2
        put(w,FN_CURSOR,index+1)
        fn=get(w,FUNCS+index*8)
        if meta(w,fn,72)==0:
            return 2
        put(w,FN,fn)
        put(w,FN_INDEX,index)
        put(w,ROOT_RESULT,2)
        put(w,PHASE,11)
        return 23
    if phase==11:
        put(w,WRAPPER_CURSOR,get(w,WRAPPER_CURSOR)+1)
        if get(w,WRAPPER_CURSOR)<get(w,WRAPPER_COUNT):
            emit(w,"\n\n")
        else:
            emit(w,"\n")
        put(w,PHASE,10)
        return 2
    if phase==12:
        if get(w,OUTLINED)>0:
            emit(w,'!0 = !{!"branch_weights", i32 2, i32 1}\n')
        n=get(w,POS)
        if n==0 or n>MAX_IR or n>length(o):
            return 4294967290
        i=0
        while i<n:
            store(o,i,byte(w,FINAL+i))
            i=i+1
        put(w,OUTPUT_SIZE,n)
        put(w,PHASE,13)
        return 0
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<ARG_HEADER or word(s,0)!=3544427792437430600 or length(s)-ARG_HEADER>8388608:
        return 4294967293
    if word(s,8)>2 or word(s,16)>1 or word(s,24)!=length(s)-ARG_HEADER:
        return 4294967293
    i=32
    while i<ARG_HEADER:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    fill_range(w,CTRL,4096,0)
    put(w,TARGET,word(s,8))
    put(w,LAYOUT,word(s,16))
    put(w,PHASE,1)
    put(w,109051904+48,MAX_NODES)
    put(w,109051904+56,64)
    return 11
'''

def source_program():
    text=SOURCE+'\ndef version_number(w:mutbuf,node:u64) -> u64:\n'
    for i in range(1,10):
        text+='    if is_text(w,node,'+repr('hepta.hia.program.v'+str(i))+')==1:\n        return '+str(i)+'\n'
    return text+'    return 0\n'+FLOW_SOURCE

def main():
    write_module('program_llvm_owner',source_program(),'llvm_owner')
    doc=document(decoder_source(),'program_llvm_decode')
    counts=(len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),
            sum(len(b['ops'])for f in doc['functions']for b in f['blocks']))
    assert counts[0]<=128 and counts[1]<=1536 and counts[2]<=8192,counts
    path=ROOT/'examples/hia_bootstrap/program_llvm_decode.hepta'
    path.write_text(render_assembly(doc))
    print('program_llvm_decode',path.stat().st_size,*counts,flush=True)
if __name__=='__main__':main()
