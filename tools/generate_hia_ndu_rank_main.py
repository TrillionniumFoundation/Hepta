"""Complete HIA rank policy; native effects are fixed mechanical operations."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_ndu_rank_prepare import SOURCE as PREPARE
from tools.generate_hia_ndu_rank_decide import SOURCE as DECIDE
from tools.generate_hia_ndu_rank_owner_common import C,common_source,resolve
ROOT=Path(__file__).resolve().parents[1]
ENTRY=r'''
def rank_main(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<65536:
        return 4294967293
    if get(o,TASK)!=0:
        return 7
    phase=get(o,PHASE)
    if phase==9990:
        return clock(o,9991)
    if phase==9991:
        if get(o,FEEDBACK)!=0:
            put(o,RESULT_STATUS,4)
            put(o,RESULT_KIND,2)
            put(o,RESULT_N,0)
        else:
            put(o,RESULT_ELAPSED,now(o)-get(o,START))
        return 0
    if phase>=9000:
        return error_steps(s,o,w)
    if phase<300:
        return rank_prepare(s,o,w)
    return rank_decide(s,o,w)
'''
def source_program():return resolve(ENTRY+'\n'+PREPARE+'\n'+DECIDE+'\n'+common_source())
def program():return document(source_program(),'ndu_rank_main')
if __name__=='__main__':
 path=ROOT/'examples/hia_bootstrap/ndu_rank_main.hepta';path.write_text(render_assembly(program()));print(path.name,path.stat().st_size,flush=True)
