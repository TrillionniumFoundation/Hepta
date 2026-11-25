"""Original bounded raw JSON preflight followed by captured integer conversion policy."""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_preflight import SOURCE as PREFLIGHT
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
def verify_raw(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<4096 or length(o)<4194304:
        return 3
    limit=get(w,80)
    if limit!=0 and (limit<640 or limit>2147483647):
        return 3
    put(w,48,262144)
    put(w,56,64)
    status=preflight(s,o,w)
    if status==4:
        return 1
    if status!=0:
        return status
    index=0
    quoted=False
    escaped=False
    digits=0
    while index<length(s):
        ch=byte(s,index)
        if quoted:
            if escaped:
                escaped=False
            elif ch==92:
                escaped=True
            elif ch==34:
                quoted=False
        elif ch==34:
            quoted=True
            digits=0
        elif ch>=48 and ch<=57:
            digits=digits+1
            if limit!=0 and digits>limit:
                return 4
        else:
            digits=0
        index=index+1
    if legacy_collision(s):
        return 5
    return 0

def legacy_collision(s:readbuf) -> bool:
    index=whitespace(s,0)
    if index==length(s) or byte(s,index)!=123:
        return False
    index=index+1
    schema=False
    types=False
    while index<length(s):
        index=whitespace(s,index)
        if byte(s,index)==125:
            return schema and types
        is_schema=literal_name(s,index+1,0)
        is_types=literal_name(s,index+1,1)
        index=string_end(s,index+1)
        index=whitespace(s,index)
        index=whitespace(s,index+1)
        if is_types:
            types=True
        if is_schema and byte(s,index)==34:
            schema=literal_name(s,index+1,2)
        if schema and types:
            return True
        index=value_end(s,index)
        if index>=length(s) or byte(s,index)==125:
            return schema and types
        index=index+1
    return False

def literal_name(s:readbuf,index:u64,which:u64) -> bool:
    at=0
    while index<length(s):
        value=decoded(s,index)
        cp=value&4294967295
        expected=name_byte(which,at)
        if cp==1114112:
            return expected==256
        if cp!=expected:
            return False
        at=at+1
        index=value>>32
    return False

def string_end(s:readbuf,index:u64) -> u64:
    while index<length(s):
        value=decoded(s,index)
        index=value>>32
        if (value&4294967295)==1114112:
            return index
    return length(s)

def value_end(s:readbuf,index:u64) -> u64:
    depth=0
    quoted=False
    escaped=False
    while index<length(s):
        ch=byte(s,index)
        if quoted:
            if escaped:
                escaped=False
            elif ch==92:
                escaped=True
            elif ch==34:
                quoted=False
        elif ch==34:
            quoted=True
        elif ch==91 or ch==123:
            depth=depth+1
        elif ch==93 or ch==125:
            if depth==0:
                return index
            depth=depth-1
        elif ch==44 and depth==0:
            return index
        index=index+1
    return index

'''
def source_program():
    return SOURCE+"\ndef name_byte(which:u64,at:u64) -> u64:\n    if which==0:\n        if at>=0 and at<6:\n            return (107122480669555>>((at-0)*8))&255\n        return 256\n    if which==1:\n        if at>=0 and at<5:\n            return (495623108980>>((at-0)*8))&255\n        return 256\n    if which==2:\n        if at>=0 and at<8:\n            return (7595371767660569960>>((at-0)*8))&255\n        if at>=8 and at<16:\n            return (7021788497383009889>>((at-8)*8))&255\n        if at>=16 and at<20:\n            return (846605933>>((at-16)*8))&255\n        return 256\n    return 256\n"+'\n'+PREFLIGHT.replace('def preflight(s:readbuf, o:mutbuf, w:mutbuf) -> u32:', 'def preflight(s:readbuf, o:mutbuf, w:mutbuf) -> u64:')
def program():
    return document(source_program(),'background_optimizer_verify_raw')
def main():
    d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_verify_raw.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),flush=True)
if __name__=='__main__':main()
