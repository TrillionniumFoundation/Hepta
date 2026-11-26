"""Exact Path/os.fspath TypeError text from actual captured native type names.

This pure leaf creates no type, method, path, ownership or verification fact.
It reuses the qualified snapshot Unicode primitives and keeps full message
lengths; the snapshot's independent 1024-character display bound is unchanged.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
from tools import generate_hia_multiversion_runtime_snapshot as snapshot
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIANPER1','little')
SOURCE=r'''
def native_path_value_error(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<65536:
        return 4294967293
    zero(w,0,256)
    if length(s)<64 or word(s,0)!=ERROR_MAGIC or word(s,8)>2:
        return 4294967293
    first=word(s,16)
    second=word(s,24)
    if first>length(s)-64 or second!=length(s)-64-first:
        return 4294967293
    if word(s,8)!=1 and second!=0:
        return 4294967293
    i=32
    while i<64:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    if type_name(s,w,64,first)==False or type_name(s,w,64+first,second)==False:
        return 4294967293
    initialize(w)
    path_message(s,o,w)
    if get(w,48)!=0:
        return 4294967293
    need=get(w,32)
    put(w,0,need)
    if need>length(o):
        return 4294967294
    put(w,32,0)
    put(w,40,1)
    path_message(s,o,w)
    if get(w,48)!=0 or get(w,32)!=need:
        return 4294967293
    return 0

def type_name(s:readbuf,w:mutbuf,p:u64,n:u64) -> bool:
    at=p
    end=p+n
    while at<end:
        cp=decode(s,w,at,end,False)
        if get(w,48)!=0 or cp==0 or (cp>=55296 and cp<=57343):
            return False
        at=at+get(w,64)
    return True

def path_message(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    prefix(o,w)
    kind=word(s,8)
    first=word(s,16)
    if kind==0:
        missing_prefix(o,w)
        limited_type(s,o,w,64,first)
    elif kind==1:
        wrong_prefix(o,w)
        limited_type(s,o,w,64,first)
        wrong_middle(o,w)
        limited_type(s,o,w,64+first,word(s,24))
    else:
        path_prefix(o,w)
        repr_path(s,o,w,64,first)
    emit(o,w,34)
    emit(o,w,125)
    return 0

def limited_type(s:readbuf,o:mutbuf,w:mutbuf,p:u64,n:u64) -> u64:
    i=0
    start=0
    while i<n:
        if byte(s,p+i)==46:
            start=i+1
        i=i+1
    p=p+start
    n=n-start
    end=p+choose(n>200,200,n)
    at=p
    while at<end:
        b=byte(s,at)
        size=1
        if b>=194 and b<=223:
            size=2
        elif b>=224 and b<=239:
            size=3
        elif b>=240:
            size=4
        if size>end-at:
            json_cp(o,w,65533)
            at=end
        else:
            cp=decode(s,w,at,end,False)
            if get(w,48)!=0:
                return 0
            json_cp(o,w,cp)
            at=at+size
    return 0

def message_cp(o:mutbuf,w:mutbuf,cp:u64) -> u64:
    return json_cp(o,w,cp)
'''
def functions(source):
    marks=list(re.finditer(r'(?m)^def (\w+)\(',source))
    return {m.group(1):source[m.start():marks[i+1].start()if i+1<len(marks)else len(source)].strip()+'\n'for i,m in enumerate(marks)}
def source_program():
    f=functions(snapshot.source_program())
    f.update(functions(SOURCE.replace('ERROR_MAGIC',str(MAGIC))))
    for name,text,method in (
        ('prefix','{"type":"TypeError","message":"','emit'),
        ('missing_prefix','expected str, bytes or os.PathLike object, not ','message_cp'),
        ('wrong_prefix','expected ','message_cp'),
        ('wrong_middle','.__fspath__() to return str or bytes, not ','message_cp'),
        ('path_prefix','argument should be a str or an os.PathLike object where __fspath__ returns a str, not ','message_cp')):
        f[name]='def '+name+'(o:mutbuf,w:mutbuf) -> u64:\n'+''.join('    '+method+'(o,w,'+str(b)+')\n'for b in text.encode())+'    return 0\n'
    order=[];seen=set()
    def include(name):
        if name in seen:return
        seen.add(name);order.append(name)
        for child in re.findall(r'\b(\w+)\(',f[name]):
            if child in f and child!=name:include(child)
    include('native_path_value_error')
    return '\n'.join(f[name]for name in order)
def program():return document(source_program(),'native_path_value_error')
if __name__=='__main__':
    raw=render_assembly(program()).encode();p=ROOT/'examples/hia_bootstrap/native_path_value_error.hepta';p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);print(p,len(raw),flush=True)
