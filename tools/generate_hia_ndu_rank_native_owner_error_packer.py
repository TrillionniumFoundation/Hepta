"""Mechanical six-word u64 size adapter; generated packer is pure HIA."""
from pathlib import Path
import re
from tools.generate_hia_ndu_evaluator import document
from tools.generate_hia_ndu_evaluator_packer import capsule,literal
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<16 or length(o)<2097152:
        return 4294967293
    if word_load(s,0)!=MAGIC or word_load(s,8)!=length(s)-16 or length(s)-16<16 or length(s)-16>1048576:
        return 4294967295
    prefix(o,0)
    poke32(o,CALL_AT,PREFIX_BYTES-CALL_AT-4)
    i=0
    while i<length(s)-16:
        store(o,PREFIX_BYTES+i,byte(s,16+i))
        i=i+1
    return PREFIX_BYTES+i
def poke32(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<4:
        store(o,at+i,value>>(8*i))
        i=i+1
    return 0
'''
def program():
    raw,syms=capsule('hia_ndu_rank_native_owner_error.S')
    source=SOURCE+'\n'+literal('prefix',raw,True)
    for key,value in {'MAGIC':int.from_bytes(b'HIAERR01','little'),'CALL_AT':syms['error_call'],'PREFIX_BYTES':len(raw)}.items():source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    d=document(program(),'ndu_rank_native_owner_error_packer');p=ROOT/'examples/hia_bootstrap/ndu_rank_native_owner_error_packer.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size)
if __name__=='__main__':main()
