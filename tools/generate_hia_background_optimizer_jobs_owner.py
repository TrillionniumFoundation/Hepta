"""Private BG Jobs owner using the real deferred Future-cell protocol."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_multiversion_background_jobs as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update(MANAGED_INPUT=int.from_bytes(b'HIABJM01','little'),
         STATE=int.from_bytes(b'HIABJS02','little'),
         REPLY=int.from_bytes(b'HIABJMR1','little'),REPLY2=int.from_bytes(b'HIABJMR1','little'),
         CELL_INPUT=int.from_bytes(b'HIABFQ06','little'),CELL_INPUT4=int.from_bytes(b'HIABFQ06','little'),
         CELL_REPLY=int.from_bytes(b'HIABFR03','little'),CELL_REPLY2=int.from_bytes(b'HIABFR03','little'),
         JM_QUEUE=968,JM_UNMAP=976,JM_UNKNOWN=984)
def replace(text,before,after):
    assert text.count(before)==1,before
    return text.replace(before,after)
def source_program():
    text=replace(original.SOURCE,'def multiversion_background_jobs(','def background_optimizer_jobs_owner(')
    start=text.index('    if magic!=MAGIC and magic!=MAGIC2 and magic!=MAGIC3:')
    stop=text.index('    n=readword(s,72)',start)
    text=text[:start]+"""    if magic!=MANAGED_INPUT:
        return 4294967293
    op=readword(s,8)
    if op<2 or op>13 or op==3 or op==9:
        return 4294967293
"""+text[stop:]
    text=replace(text,'put(o,PROFILE,choose(magic==MAGIC3,1,0))','put(o,PROFILE,1)')
    text=replace(text,'3,RP,choose(get(w,120)!=0,160,128))','3,RP,192)')
    text=replace(text,"""    if phase==841:
        put(o,FEEDBACK,get(o,CELL_RC))
        return again(o,get(o,CELL_NEXT))""","""    if phase==841:
        put(o,FEEDBACK,get(o,CELL_RC))
        managed_cell_receipt(o)
        return again(o,get(o,CELL_NEXT))""")
    text=replace(text,"""        put(o,144,get(o,CLEAN_PENDING))
    return 0""","""        put(o,144,get(o,CLEAN_PENDING))
    put(o,152,get(o,JM_QUEUE))
    put(o,160,get(o,JM_UNMAP))
    put(o,168,get(o,JM_UNKNOWN))
    put(o,176,1)
    put(o,184,0)
    return 0""")
    text+="""
def managed_cell_receipt(o:mutbuf) -> u64:
    if get(o,FEEDBACK)!=0 or get(o,RP)!=CELL_REPLY:
        put(o,JM_UNKNOWN,1)
        return 0
    if get(o,RP+160)>1 or get(o,RP+168)>1:
        put(o,JM_UNKNOWN,1)
        return 0
    if get(o,RP+160)!=0:
        put(o,JM_QUEUE,1)
    if get(o,RP+168)!=0:
        put(o,JM_UNMAP,1)
    return 0
"""
    for key,value in sorted(C.items(),key=lambda item:-len(item[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    d=document(source_program(),'background_optimizer_jobs_owner')
    p=ROOT/'examples/hia_bootstrap/background_optimizer_jobs_owner.hepta'
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
