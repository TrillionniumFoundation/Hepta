"""Exact ELF64 object-symbol inventory for the native Clang outer.

The source preserves the original ELF structure, symbol-kind and duplicate
checks. A growable caller-owned trie stores only distinct external names;
no fixed symbol-name length or unique-symbol-count ceiling is introduced.
"""
from tools.generate_hia_clang_capture_common import C,write_module
C.update(OBJ_ELF_IDENT=int.from_bytes(b'\x7fELF\x02\x01','little'),OBJ_MAGIC=int.from_bytes(b'HIAOEL01','little'),OBJ_REPLY=int.from_bytes(b'HIAOER01','little'),
 OBJ_COUNT=0,OBJ_ROOT=8,OBJ_OUT_NEED=16,OBJ_WORK_NEED=24,OBJ_TABLE=32,OBJ_SECTIONS=40,
 OBJ_OBSERVED=48,OBJ_EXPECTED_AT=56,OBJ_EXPORTS=64,OBJ_IMPORTS=72,OBJ_BYTES=80,
 OBJ_EXPECTED_COUNT=88,OBJ_MACHINE=96,OBJ_NODES=256,OBJ_HEAD=64)
SOURCE=r'''
def inventory(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or length(o)<64 or length(w)<256:
        return 4294967293
    if word(s,0)!=OBJ_MAGIC or word(s,8)!=62 and word(s,8)!=183 and word(s,8)!=243:
        return 4294967293
    size=word(s,16)
    count=word(s,24)
    if size>67108864 or size>length(s)-64 or count>128:
        return 4294967293
    i=32
    while i<64:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    at=64+size
    expected_at=at
    i=0
    while i<count:
        if at>length(s) or length(s)-at<8:
            return 4294967293
        n=word(s,at)
        at=at+8
        if n>length(s)-at:
            return 4294967293
        j=0
        while j<n:
            if byte(s,at+j)==0 or byte(s,at+j)>127:
                return 4294967293
            j=j+1
        at=at+n
        i=i+1
    if at!=length(s):
        return 4294967293
    clear(w,0,256)
    put(w,OBJ_BYTES,size)
    put(w,OBJ_EXPECTED_AT,expected_at)
    put(w,OBJ_EXPECTED_COUNT,count)
    put(w,OBJ_MACHINE,word(s,8))
    if shape(s,w)==0:
        return finish_object(o,w,1,0)
    code=section_ranges(s,w)
    if code!=0:
        return finish_object(o,w,code,0)
    return symbols(s,o,w)

def uint(s:readbuf,at:u64,n:u64) -> u64:
    value=0
    i=0
    while i<n:
        value=value|(byte(s,at+i)<<(8*i))
        i=i+1
    return value

def bounded(total:u64,at:u64,n:u64,minimum:u64) -> bool:
    return at>=minimum and at<=total and n<=total-at

def shape(s:readbuf,w:mutbuf) -> u64:
    size=get(w,OBJ_BYTES)
    if size<64 or uint(s,64,6)!=OBJ_ELF_IDENT or uint(s,80,2)!=1 or uint(s,82,2)!=get(w,OBJ_MACHINE) or uint(s,116,2)!=64:
        return 0
    at=word(s,104)
    n=uint(s,124,2)
    if uint(s,122,2)!=64 or n==0 or n>4096 or bounded(size,at,n*64,64)==False:
        return 0
    put(w,OBJ_TABLE,64+at)
    put(w,OBJ_SECTIONS,n)
    return 1

def section_ranges(s:readbuf,w:mutbuf) -> u64:
    i=0
    while i<get(w,OBJ_SECTIONS):
        row=get(w,OBJ_TABLE)+64*i
        kind=uint(s,row+4,4)
        n=word(s,row+32)
        if kind==0:
            if i!=0 or n!=0:
                return 1
        elif kind!=8 and n!=0:
            if bounded(get(w,OBJ_BYTES),word(s,row+24),n,64)==False:
                return 1
        i=i+1
    return 0

def symbols(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    table=get(w,OBJ_TABLE)
    sections=get(w,OBJ_SECTIONS)
    i=0
    while i<sections:
        row=table+64*i
        if uint(s,row+4,4)==2:
            put(w,OBJ_OBSERVED,1)
            link=uint(s,row+40,4)
            at=word(s,row+24)
            n=word(s,row+32)
            if link>=sections or word(s,row+56)!=24 or n%24!=0:
                return finish_object(o,w,2,row)
            strings=table+64*link
            if uint(s,strings+4,4)!=3:
                return finish_object(o,w,2,strings)
            names=word(s,strings+24)
            names_n=word(s,strings+32)
            if bounded(get(w,OBJ_BYTES),names,names_n,0)==False:
                return finish_object(o,w,2,strings)
            j=0
            while j<n:
                symbol=64+at+j
                code=one_symbol(s,o,w,symbol,64+names,names_n)
                if code==4294967294:
                    return 4294967294
                if code!=0:
                    return finish_object(o,w,code,symbol)
                j=j+24
        i=i+1
    if get(w,OBJ_OBSERVED)==0:
        return finish_object(o,w,2,0)
    if get(w,OBJ_EXPORTS)==0:
        return finish_object(o,w,11,0)
    if get(w,OBJ_MACHINE)==243 and uint(s,112,4)!=5:
        return finish_object(o,w,13,112)
    if closure(s,o,w)==0:
        return finish_object(o,w,12,0)
    return finish_object(o,w,0,0)

def one_symbol(s:readbuf,o:mutbuf,w:mutbuf,at:u64,names:u64,names_n:u64) -> u64:
    offset=uint(s,at,4)
    if offset==0:
        return 0
    info=byte(s,at+4)
    binding=info>>4
    kind=info&15
    if binding!=0 and binding!=1 and binding!=2:
        return 6
    if binding==0:
        return 0
    if offset>=names_n:
        return 3
    name=names+offset
    n=name_extent(s,name,names_n-offset)
    if n==NONE:
        return 4
    if n==NONE-1:
        return 5
    if n==0:
        return 0
    section=uint(s,at+6,2)
    previous=find_name(s,o,w,name,n)
    if section==0:
        if previous!=0 and get(o,previous-1+16)==1:
            return 7
        if previous!=0:
            return 0
        return add_symbol(s,o,w,name,n,0)
    if kind!=2:
        return 10
    if binding!=1:
        return 8
    if section>=get(w,OBJ_SECTIONS):
        return 9
    row=get(w,OBJ_TABLE)+64*section
    value=word(s,at+8)
    extent=word(s,at+16)
    section_n=word(s,row+32)
    if uint(s,row+4,4)!=1 or word(s,row+8)&6!=6 or extent==0 or value>=section_n or extent>section_n-value:
        return 9
    if previous!=0:
        return 7
    return add_symbol(s,o,w,name,n,1)

def name_extent(s:readbuf,at:u64,n:u64) -> u64:
    i=0
    ascii=1
    while i<n:
        c=byte(s,at+i)
        if c==0:
            if ascii==0:
                return NONE-1
            return i
        if c>127:
            ascii=0
        i=i+1
    return NONE

def name_bit(s:readbuf,name:u64,n:u64,bit:u64) -> u64:
    if bit//8>=n:
        return 0
    return (byte(s,name+bit//8)>>(7-bit%8))&1

def first_bit(value:u64) -> u64:
    i=0
    while i<8:
        if (value<<i)&128!=0:
            return i
        i=i+1
    return 8

def difference(s:readbuf,o:mutbuf,row:u64,other:u64) -> u64:
    a=get(o,row)
    b=get(o,other)
    an=get(o,row+8)
    bn=get(o,other+8)
    n=choose(an<bn,an,bn)
    i=0
    while i<n:
        if byte(s,a+i)!=byte(s,b+i):
            return i*8+first_bit(byte(s,a+i)^byte(s,b+i))
        i=i+1
    if an==bn:
        return NONE
    longer=choose(an>bn,a,b)
    return i*8+first_bit(byte(s,longer+i))

def find_name(s:readbuf,o:mutbuf,w:mutbuf,name:u64,n:u64) -> u64:
    current=get(w,OBJ_ROOT)
    if current==0:
        return 0
    while current&1==0:
        node=current//2
        arm=name_bit(s,name,n,get(w,node))
        current=get(w,node+8+arm*8)
    row=current//2
    if get(o,row+8)!=n:
        return 0
    start=get(o,row)
    i=0
    while i<n:
        if byte(s,name+i)!=byte(s,start+i):
            return 0
        i=i+1
    return row+1

def insert_name(s:readbuf,o:mutbuf,w:mutbuf,row:u64,branch:u64) -> u64:
    leaf=row*2+1
    root=get(w,OBJ_ROOT)
    if root==0:
        put(w,OBJ_ROOT,leaf)
        return 0
    name=get(o,row)
    n=get(o,row+8)
    current=root
    while current&1==0:
        node=current//2
        current=get(w,node+8+name_bit(s,name,n,get(w,node))*8)
    bit=difference(s,o,row,current//2)
    current=root
    parent=OBJ_ROOT
    descending=1
    while current&1==0 and descending==1:
        node=current//2
        if get(w,node)>=bit:
            descending=0
        else:
            parent=node+8+name_bit(s,name,n,get(w,node))*8
            current=get(w,parent)
    arm=name_bit(s,name,n,bit)
    put(w,branch,bit)
    put(w,branch+8+arm*8,leaf)
    put(w,branch+16-arm*8,current)
    put(w,parent,branch*2)
    return 0

def add_symbol(s:readbuf,o:mutbuf,w:mutbuf,name:u64,n:u64,kind:u64) -> u64:
    count=get(w,OBJ_COUNT)
    row=OBJ_HEAD+count*24
    branch=OBJ_NODES+count*24
    if row+24>length(o) or branch+24>length(w):
        put(w,OBJ_OUT_NEED,row+24)
        put(w,OBJ_WORK_NEED,branch+24)
        return 4294967294
    put(o,row,name)
    put(o,row+8,n)
    put(o,row+16,kind)
    insert_name(s,o,w,row,branch)
    put(w,OBJ_COUNT,count+1)
    if kind==1:
        put(w,OBJ_EXPORTS,get(w,OBJ_EXPORTS)+1)
    else:
        put(w,OBJ_IMPORTS,get(w,OBJ_IMPORTS)+1)
    return 0

def closure(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if get(w,OBJ_EXPORTS)!=get(w,OBJ_EXPECTED_COUNT):
        return 0
    at=get(w,OBJ_EXPECTED_AT)
    i=0
    previous=0
    previous_n=0
    while i<get(w,OBJ_EXPECTED_COUNT):
        n=word(s,at)
        at=at+8
        if i!=0 and ordered(s,previous,previous_n,at,n)==0:
            return 0
        row=find_name(s,o,w,at,n)
        if row==0 or get(o,row-1+16)!=1:
            return 0
        previous=at
        previous_n=n
        at=at+n
        i=i+1
    i=0
    while i<get(w,OBJ_COUNT):
        row=OBJ_HEAD+i*24
        if get(o,row+16)==0 and allowed_import(s,get(o,row),get(o,row+8))==0:
            return 0
        i=i+1
    return 1

def ordered(s:readbuf,a:u64,an:u64,b:u64,bn:u64) -> u64:
    i=0
    while i<an and i<bn:
        x=byte(s,a+i)
        y=byte(s,b+i)
        if x!=y:
            return choose(x<y,1,0)
        i=i+1
    return choose(an<bn,1,0)

def finish_object(o:mutbuf,w:mutbuf,code:u64,at:u64) -> u32:
    clear(o,0,64)
    put(o,0,OBJ_REPLY)
    put(o,8,code)
    put(o,16,get(w,OBJ_COUNT))
    put(o,24,get(w,OBJ_EXPORTS))
    put(o,32,get(w,OBJ_IMPORTS))
    put(o,40,at)
    if code!=0:
        return 64
    return OBJ_HEAD+get(w,OBJ_COUNT)*24
'''
def imports():
 lines=['def allowed_import(s:readbuf,name:u64,n:u64) -> u64:']
 for name in ('abort','calloc','free','malloc','memset','memcpy','memmove'):
  raw=name.encode();lines.extend([f'    if n=={len(raw)} and uint(s,name,{len(raw)})=={int.from_bytes(raw,"little")}:','        return 1'])
 return '\n'.join(lines+['    return 0',''])
if __name__=='__main__':write_module('clang_object_inventory',SOURCE+'\n'+imports(),'inventory')
