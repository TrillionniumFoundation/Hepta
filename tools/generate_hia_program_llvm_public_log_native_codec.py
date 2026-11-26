"""Q2 log codec consumes actual WTF-8 cwd; private OS message uses real slot bytes."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_program_llvm_public_log_codec as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update(MAGIC=int.from_bytes(b'HIALLGQ2','little'),OS_MAGIC=int.from_bytes(b'HIACLOM1','little'))
LITERALS=list(original.LITERALS)+['[Errno ','] ',': ',' -> ']
SOURCE=original.SOURCE.replace(
 'quoted(s,o,w,field_offset(s,1),word_load(s,24),True)',
 'quoted(s,o,w,field_offset(s,1),word_load(s,24),False)')
SOURCE=r'''
def native_log_codec(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)>=8 and word_load(s,0)==OS_MAGIC:
        return os_message(s,o,w)
    return public_log_codec(s,o,w)
'''+SOURCE+r'''

def os_message(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or length(w)<128:
        return BAD
    flags=word_load(s,8)
    if flags>3 or flags==2 or word_load(s,48)!=0 or word_load(s,56)!=0:
        return BAD
    at=64
    i=0
    while i<4:
        n=word_load(s,16+i*8)
        if n>length(s)-at:
            return BAD
        if i>=2 and (flags&(1<<(i-2)))==0 and n!=0:
            return BAD
        at=at+n
        i=i+1
    if at!=length(s) or word_load(s,16)==0:
        return BAD
    put(w,0,0)
    put(w,8,0)
    put(w,16,0)
    os_render(s,o,w)
    if word_load(w,8)!=0:
        return word_load(w,8)
    n=word_load(w,0)
    if n>length(o):
        return SHORT
    put(w,0,0)
    put(w,16,1)
    os_render(s,o,w)
    return n

def os_render(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    literal(o,w,26)
    at=64
    i=0
    while i<4:
        if i==1:
            literal(o,w,27)
        elif i>=2:
            if (word_load(s,8)&(1<<(i-2)))!=0:
                literal(o,w,26+i)
        n=word_load(s,16+i*8)
        j=0
        while j<n:
            emit(o,w,byte(s,at+j))
            j=j+1
        at=at+n
        i=i+1
    return 0
'''
def source_program():
 source=SOURCE+'\ndef literal(o:mutbuf,w:mutbuf,index:u64) -> u64:\n'
 for i,text in enumerate(LITERALS):
  source+=f'    if index=={i}:\n'
  raw=text.encode('ascii')
  for at in range(0,len(raw),8):
   piece=raw[at:at+8]
   source+=f'        bytes_literal(o,w,{int.from_bytes(piece,"little")},{len(piece)})\n'
  source+='        return 0\n'
 source+='    return 0\n'
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):source=re.sub(r'\b'+key+r'\b',str(value),source)
 return source
def program():return document(source_program(),'native_log_codec')
if __name__=='__main__':
 tree=program()
 stats=(len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']))
 assert stats[0]<=128 and stats[1]<=1536 and stats[2]<=8192,stats
 target=ROOT/'examples/hia_bootstrap/program_llvm_public_log_native_codec.hepta'
 target.write_text(render_assembly(tree));print(target.name,target.stat().st_size,stats,flush=True)
