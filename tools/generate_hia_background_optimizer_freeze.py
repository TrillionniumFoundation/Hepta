"""Serialize an owned JSON subtree with the original conversion errors.

The capture owner supplies the real int_max_str_digits policy. There is no
background submission byte/node/depth limit in this reusable role. The
background caller applies its independent, original _structure gate first.
"""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_worker_request import canonical_program,decimal_program,format_program
from tools.generate_hia_background_optimizer_structure import SOURCE as structure_source
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIABJF01','little'),'REPLY':int.from_bytes(b'HIABJR01','little'),
   'ARENA':5208772604367785521,'NONE':(1<<64)-1,'BAD':4294967293,'SHORT':4294967294}
ENTRY=r'''
def background_optimizer_freeze(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(w)<131072 or read64(s,0)!=REQUEST:
        return BAD
    if length(o)<128:
        return SHORT
    action=read64(s,8)
    root=read64(s,16)
    jn=read64(s,24)
    an=read64(s,32)
    limit=read64(s,40)
    if action>1 or jn==0 or an<64 or jn>length(s)-128 or an!=length(s)-128-jn:
        return BAD
    if limit!=0 and (limit<640 or limit>2147483647):
        return BAD
    i=48
    while i<128:
        if read64(s,i)!=0:
            return BAD
        i=i+8
    if an>length(w)-16384 or arena_valid(s,w,128+jn,an,jn)==False or root>=read64(s,128+jn+8):
        return BAD
    if strings_valid(s,128+jn)==False:
        return BAD
    i=0
    while i<an:
        store(w,i,byte(s,128+jn+i))
        i=i+1
    p=length(w)-16384
    zero(w,p,128)
    put(w,p+8,root)
    put(w,p+24,limit)
    put(w,p+56,NONE)
    error=serialize(s,o,w)
    if error==64 or get(w,p+16)!=0 or get(w,p+40)!=0:
        return BAD
    needed=get(w,56)
    if error==0 and get(w,p+56)!=NONE:
        error=5
    if error!=0:
        if length(o)<512:
            return SHORT
        return finish(o,w,error)
    if action==1:
        if needed>length(o)-128:
            return SHORT
        put(w,p,1)
        put(w,p+32,0)
        put(w,p+40,0)
        put(w,p+48,0)
        put(w,p+56,NONE)
        put(w,p+64,0)
        put(w,p+72,0)
        put(w,p+80,0)
        if serialize(s,o,w)!=0 or get(w,p+16)!=0 or get(w,56)!=needed:
            return BAD
    return finish(o,w,0)

def append_byte(o:mutbuf,w:mutbuf,value:u64) -> u64:
    index=get(w,56)
    p=length(w)-16384
    if index==NONE:
        put(w,p+16,1)
        return 0
    if get(w,p)==1:
        store(o,128+index,value)
    put(w,56,index+1)
    remaining=get(w,p+40)
    if remaining!=0:
        if value<128 or value>191:
            put(w,p+16,1)
            return 0
        point=(get(w,p+48)<<6)|(value&63)
        put(w,p+48,point)
        put(w,p+40,remaining-1)
        if remaining==1:
            complete_point(w,point)
    elif value<128:
        complete_point(w,value)
    elif value>=194 and value<=223:
        put(w,p+40,1)
        put(w,p+48,value&31)
    elif value>=224 and value<=239:
        put(w,p+40,2)
        put(w,p+48,value&15)
    elif value>=240 and value<=244:
        put(w,p+40,3)
        put(w,p+48,value&7)
    else:
        put(w,p+16,1)
    return 0

def complete_point(w:mutbuf,point:u64) -> u64:
    p=length(w)-16384
    at=get(w,p+32)
    put(w,p+32,at+1)
    if point>=55296 and point<=57343:
        if get(w,p+56)==NONE:
            put(w,p+56,at)
            put(w,p+64,at+1)
            put(w,p+72,point)
            put(w,p+80,1)
        elif get(w,p+80)==1:
            put(w,p+64,at+1)
    elif get(w,p+80)==1:
        put(w,p+80,2)
    return 0

def strings_valid(s:readbuf,base:u64) -> bool:
    count=read64(s,base+8)
    node=0
    while node<count:
        row=base+64+node*72
        if read64(s,row)==4:
            if string_valid(s,base+read64(s,row+24),read64(s,row+32))==False:
                return False
        if read64(s,row+40)!=0:
            if string_valid(s,base+read64(s,row+40),read64(s,row+48))==False:
                return False
        node=node+1
    return True

def string_valid(s:readbuf,at:u64,n:u64) -> bool:
    index=0
    while index<n:
        width=utf8_width(s,at+index,n-index)
        if width==0:
            return False
        index=index+width
    return True

def number_kind(s:readbuf,at:u64,n:u64) -> u64:
    if n==3 and byte(s,at)==78 and byte(s,at+1)==97 and byte(s,at+2)==78:
        return 2
    skip=0
    if n!=0 and byte(s,at)==45:
        skip=1
    if n-skip==8:
        if byte(s,at+skip)==73 and byte(s,at+skip+1)==110 and byte(s,at+skip+2)==102 and byte(s,at+skip+3)==105 and byte(s,at+skip+4)==110 and byte(s,at+skip+5)==105 and byte(s,at+skip+6)==116 and byte(s,at+skip+7)==121:
            return choose(skip==0,3,4)
    if n==skip:
        return 64
    i=skip
    first=byte(s,at+i)
    if first==48:
        i=i+1
    elif first>=49 and first<=57:
        i=i+1
        while i<n and byte(s,at+i)>=48 and byte(s,at+i)<=57:
            i=i+1
    else:
        return 64
    if i==n:
        return 0
    if byte(s,at+i)==46:
        i=i+1
        first=i
        while i<n and byte(s,at+i)>=48 and byte(s,at+i)<=57:
            i=i+1
        if first==i:
            return 64
    if i<n and (byte(s,at+i)==101 or byte(s,at+i)==69):
        i=i+1
        if i<n and (byte(s,at+i)==43 or byte(s,at+i)==45):
            i=i+1
        first=i
        while i<n and byte(s,at+i)>=48 and byte(s,at+i)<=57:
            i=i+1
        if first==i:
            return 64
    if i!=n:
        return 64
    return 1

def float_error(s:readbuf,at:u64) -> u64:
    return choose(byte(s,at)==45,4,3)

def finish(o:mutbuf,w:mutbuf,error:u64) -> u32:
    p=length(w)-16384
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,choose(error==0,0,1))
    put(o,16,error)
    put(o,24,get(w,56))
    put(o,40,get(w,p+32))
    if error==1:
        at=128+limit_prefix(o,128)
        at=decimal_unsigned(o,at,get(w,p+24))
        put(o,32,at+limit_suffix(o,at)-128)
    elif error>=2 and error<=4:
        put(o,32,float_message(o,error))
    elif error==5:
        first=get(w,p+56)
        end=get(w,p+64)
        put(o,48,first)
        put(o,56,end)
        put(o,64,get(w,p+72))
        at=128
        if end==first+1:
            at=at+unicode_one_prefix(o,at)
            point=get(w,p+72)
            store(o,at,hex_digit((point>>12)&15))
            store(o,at+1,hex_digit((point>>8)&15))
            store(o,at+2,hex_digit((point>>4)&15))
            store(o,at+3,hex_digit(point&15))
            at=at+4
            at=at+unicode_one_middle(o,at)
            at=decimal_unsigned(o,at,first)
        else:
            at=at+unicode_many_prefix(o,at)
            at=decimal_unsigned(o,at,first)
            store(o,at,45)
            at=decimal_unsigned(o,at+1,end-1)
        at=at+unicode_suffix(o,at)
        put(o,32,at-128)
    return 0

def decimal_unsigned(o:mutbuf,at:u64,value:u64) -> u64:
    divisor=1
    while value//divisor>=10:
        divisor=divisor*10
    while divisor!=0:
        store(o,at,48+(value//divisor)%10)
        at=at+1
        divisor=divisor//10
    return at

def widen(value:u32) -> u64:
    return value
'''
def source_program():
    serializer=canonical_program().replace('* 56','* 72')
    serializer=serializer.replace('    node = 0','    root = get(w,length(w)-16384+8)\n    node = root')
    serializer=serializer.replace('if parent != 18446744073709551615:', 'if node != root:')
    serializer=serializer.replace('if parent == 18446744073709551615:', 'if node == root:')
    serializer=serializer.replace('                sibling = get(w, record + 16)\n','                sibling = get(w, record + 16)\n                if node == root:\n                    sibling = 18446744073709551615\n')
    old='            start = get(w, record + 24)\n            size = get(w, record + 32)'
    assert serializer.count(old)==1
    serializer=serializer.replace(old,old+"""
            if kind!=4:
                start=start+128
            if kind==3:
                category=number_kind(s,start,size)
                if category>=2:
                    return category
                if category==0:
                    digits=size
                    if byte(s,start)==45:
                        digits=digits-1
                    limit=get(w,length(w)-16384+24)
                    if limit!=0 and digits>limit:
                        return 1
                else:
                    kind=7
""")
    serializer=serializer.replace('                    return 4294967280','                    return float_error(s,start)')
    for indent in ('        ','    '):
        old=indent+'if get(w, 56) > 8388608:\n'+indent+'    return 4294967274\n'
        assert old in serializer
        serializer=serializer.replace(old,'')
    serializer=serializer.replace('    return get(w, 56)\n','    return 0\n')
    serializer='\n'.join(ast.unparse(n) for n in ast.parse(serializer).body if n.name!='append_byte')+'\n'
    wanted={'arena_valid','nodeword','read64','get','put','zero','choose','utf8_width'}
    helpers=[ast.unparse(n).replace('SEEN','0') for n in ast.parse(structure_source).body if n.name in wanted]
    assert len(helpers)==len(wanted)
    decimal=decimal_program().replace('if n == 0 or n > 8388608:', 'if n == 0:')
    text=ENTRY+'\n'+serializer+'\n'+'\n'.join(helpers)+'\n'+decimal+'\n'+format_program()
    fragments={
      'limit_prefix':b'{"message":"Exceeds the limit (',
      'limit_suffix':b' digits) for integer string conversion; use sys.set_int_max_str_digits() to increase the limit","type":"ValueError"}',
      'unicode_one_prefix':b'{"message":"\'utf-8\' codec can\'t encode character \'\\\\u',
      'unicode_one_middle':b"\' in position ",
      'unicode_many_prefix':b'{"message":"\'utf-8\' codec can\'t encode characters in position ',
      'unicode_suffix':b': surrogates not allowed","type":"UnicodeEncodeError"}',
    }
    for name,raw in fragments.items():
        lines=[f'def {name}(o:mutbuf,at:u64) -> u64:']
        lines += [f'    store(o,at+{i},{b})' for i,b in enumerate(raw)]
        lines += [f'    return {len(raw)}']
        text+='\n'+'\n'.join(lines)+'\n'
    lines=['def float_message(o:mutbuf,kind:u64) -> u64:']
    for number in (2,3,4):
        lines += [f'    if kind=={number}:',f'        return float_message_{number}(o)']
    lines += ['    return 0'];text+='\n'+'\n'.join(lines)+'\n'
    for number,token in [(2,'nan'),(3,'inf'),(4,'-inf')]:
        raw=json.dumps({'type':'ValueError','message':'Out of range float values are not JSON compliant: '+token},sort_keys=True,separators=(',',':')).encode()
        lines=[f'def float_message_{number}(o:mutbuf) -> u64:']+[f'    store(o,{128+i},{b})' for i,b in enumerate(raw)]+[f'    return {len(raw)}']
        text+='\n'+'\n'.join(lines)+'\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    names=[n.name for n in ast.parse(text).body];assert len(names)==len(set(names)),names
    return text
def main():
    tree=document(source_program(),'background_optimizer_freeze')
    path=ROOT/'examples/hia_bootstrap/background_optimizer_freeze.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),flush=True)
if __name__=='__main__':main()
