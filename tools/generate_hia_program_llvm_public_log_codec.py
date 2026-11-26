"""Native capture-log JSON codec; pure framing, no Value ownership or callbacks."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(MAGIC=int.from_bytes(b'HIALLGQ1','little'),CAPTURE=int.from_bytes(b'HIACAP01','little'),
 BAD=4294967293,SHORT=4294967294,OVERFLOW=4294967292)
LITERALS=[
 '{"argv":[','],"cwd":',',"limits":{"timeout":',',"stdout_limit":',',"stderr_limit":',',"stdin_limit":',
 '},"status":"attempted","returncode":null,"stdout_hex":null,"stderr_hex":null,"stdout_total_bytes":null,"stderr_total_bytes":null,"stdout_complete":null,"stderr_complete":null}',
 '{"status":"completed","returncode":','{"status":"capture_failed","error":{"type":',',"message":',',"code":',
 'null',',"returncode":',',"capture_error":',',"stdout_hex":',',"stderr_hex":',
 ',"stdout_retained_bytes":',',"stderr_retained_bytes":',',"stdout_total_bytes":',',"stderr_total_bytes":',
 ',"stdout_complete":',',"stderr_complete":','true','false',',"stdout_text_fallback":',',"stderr_text_fallback":']
SOURCE=r'''
def public_log_codec(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(w)<128:
        return BAD
    if word_load(s,0)!=MAGIC or word_load(s,8)>2 or word_load(s,120)!=0:
        return BAD
    at=128
    i=0
    while i<8:
        n=field_length(s,i)
        if n>length(s)-at:
            return BAD
        at=at+n
        i=i+1
    if at!=length(s):
        return BAD
    if word_load(s,64)>1:
        return BAD
    op=word_load(s,8)
    flags=word_load(s,112)
    if op==0:
        if flags!=0 or word_load(s,16)<128:
            return BAD
        i=32
        while i<112:
            if word_load(s,i)!=0:
                return BAD
            i=i+8
        if frame_valid(s)==False:
            return BAD
    elif op==1:
        if (flags&18446744073709551609)!=0 or word_load(s,64)!=1:
            return BAD
        if word_load(s,16)!=0 or word_load(s,24)!=0:
            return BAD
        i=80
        while i<112:
            if word_load(s,i)!=0:
                return BAD
            i=i+8
        if word_load(s,48)!=word_load(s,32) or word_load(s,56)!=word_load(s,40):
            return BAD
    else:
        if (flags&18446744073709551590)!=0 or word_load(s,16)!=0 or word_load(s,24)!=0 or word_load(s,80)==0:
            return BAD
        if (flags&8)==0 and word_load(s,96)!=0:
            return BAD
        if (flags&16)==0 and word_load(s,104)!=0:
            return BAD
        if (flags&1)==0:
            i=32
            while i<80:
                if word_load(s,i)!=0:
                    return BAD
                i=i+8
        elif word_load(s,48)<word_load(s,32) or word_load(s,56)<word_load(s,40):
            return BAD
        if word_load(s,64)==0 and word_load(s,72)!=0:
            return BAD
    put(w,0,0)
    put(w,8,0)
    put(w,16,0)
    render(s,o,w)
    if word_load(w,8)!=0:
        return word_load(w,8)
    n=word_load(w,0)
    if n>length(o):
        return SHORT
    put(w,0,0)
    put(w,16,1)
    render(s,o,w)
    return n

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0

def field_length(s:readbuf,index:u64) -> u64:
    if index<4:
        return word_load(s,16+index*8)
    return word_load(s,80+(index-4)*8)

def field_offset(s:readbuf,index:u64) -> u64:
    at=128
    i=0
    while i<index:
        at=at+field_length(s,i)
        i=i+1
    return at

def frame_valid(s:readbuf) -> bool:
    n=word_load(s,16)
    if word_load(s,128)!=CAPTURE or word_load(s,136)!=0:
        return False
    if word_load(s,152)!=0 or word_load(s,160)!=0:
        return False
    if word_load(s,168)%1000000000!=0:
        return False
    i=72
    while i<128:
        if word_load(s,128+i)!=0:
            return False
        i=i+8
    at=128
    i=0
    count=word_load(s,144)
    while i<count:
        if n-at<9:
            return False
        size=word_load(s,128+at)
        at=at+8
        if size>=n-at:
            return False
        if byte(s,128+at+size)!=0:
            return False
        at=at+size+1
        i=i+1
    return at==n

def emit(o:mutbuf,w:mutbuf,value:u64) -> u64:
    at=word_load(w,0)
    if at>=OVERFLOW:
        put(w,8,OVERFLOW)
        return 0
    if word_load(w,16)!=0:
        store(o,at,value)
    put(w,0,at+1)
    return 0

def bytes_literal(o:mutbuf,w:mutbuf,value:u64,n:u64) -> u64:
    i=0
    while i<n:
        emit(o,w,(value>>(i*8))&255)
        i=i+1
    return 0

def decimal(o:mutbuf,w:mutbuf,value:u64) -> u64:
    if value==0:
        emit(o,w,48)
        return 0
    n=value
    i=0
    while n!=0:
        store(w,64+i,48+n%10)
        n=n//10
        i=i+1
    while i!=0:
        i=i-1
        emit(o,w,byte(w,64+i))
    return 0

def signed_decimal(o:mutbuf,w:mutbuf,value:u64) -> u64:
    if value>=9223372036854775808:
        emit(o,w,45)
        decimal(o,w,0-value)
    else:
        decimal(o,w,value)
    return 0

def hex_digit(value:u64) -> u64:
    if value<10:
        return value+48
    return value+87

def utf8_width(s:readbuf,at:u64,n:u64,filesystem:bool) -> u64:
    first=byte(s,at)
    if first<128:
        return 1
    width=0
    if first>=194 and first<=223:
        width=2
    elif first>=224 and first<=239:
        width=3
    elif first>=240 and first<=244:
        width=4
    if width==0 or n<width:
        return 0
    second=byte(s,at+1)
    if second<128 or second>191:
        return 0
    if (first==224 and second<160) or (first==240 and second<144) or (first==244 and second>=144):
        return 0
    if filesystem and first==237 and second>=160:
        return 0
    i=2
    while i<width:
        value=byte(s,at+i)
        if value<128 or value>191:
            return 0
        i=i+1
    return width

def quoted(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64,filesystem:bool) -> u64:
    emit(o,w,34)
    i=0
    while i<n:
        value=byte(s,at+i)
        if value==34 or value==92:
            emit(o,w,92)
            emit(o,w,value)
            i=i+1
        elif value<32:
            emit(o,w,92)
            short=0
            if value==8:
                short=98
            elif value==9:
                short=116
            elif value==10:
                short=110
            elif value==12:
                short=102
            elif value==13:
                short=114
            if short!=0:
                emit(o,w,short)
            else:
                emit(o,w,117)
                emit(o,w,48)
                emit(o,w,48)
                emit(o,w,hex_digit(value>>4))
                emit(o,w,hex_digit(value&15))
            i=i+1
        else:
            width=utf8_width(s,at+i,n-i,filesystem)
            if width==0:
                if filesystem==False:
                    put(w,8,BAD)
                    return 0
                emit(o,w,237)
                emit(o,w,176+(value>>6))
                emit(o,w,128+(value&63))
                i=i+1
            else:
                j=0
                while j<width:
                    emit(o,w,byte(s,at+i+j))
                    j=j+1
                i=i+width
    emit(o,w,34)
    return 0

def hex_string(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64) -> u64:
    emit(o,w,34)
    i=0
    while i<n:
        value=byte(s,at+i)
        emit(o,w,hex_digit(value>>4))
        emit(o,w,hex_digit(value&15))
        i=i+1
    emit(o,w,34)
    return 0

def stream(s:readbuf,o:mutbuf,w:mutbuf,index:u64,total:u64) -> u64:
    n=word_load(s,32+index*8)
    literal(o,w,14+index)
    hex_string(s,o,w,field_offset(s,2+index),n)
    literal(o,w,16+index)
    decimal(o,w,n)
    literal(o,w,18+index)
    decimal(o,w,total)
    literal(o,w,20+index)
    if n==total:
        literal(o,w,22)
    else:
        literal(o,w,23)
    return 0

def render(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=word_load(s,8)
    flags=word_load(s,112)
    if op==0:
        literal(o,w,0)
        count=word_load(s,144)
        i=0
        at=256
        while i<count:
            n=word_load(s,at)
            at=at+8
            if i!=0:
                emit(o,w,44)
            quoted(s,o,w,at,n,True)
            at=at+n+1
            i=i+1
        literal(o,w,1)
        quoted(s,o,w,field_offset(s,1),word_load(s,24),True)
        literal(o,w,2)
        decimal(o,w,word_load(s,168)//1000000000)
        i=0
        while i<3:
            literal(o,w,3+i)
            decimal(o,w,word_load(s,176+i*8))
            i=i+1
        literal(o,w,6)
        return 0
    if op==1:
        literal(o,w,7)
        signed_decimal(o,w,word_load(s,72))
        i=0
        while i<2:
            if (flags&(2<<i))!=0:
                stream(s,o,w,i,word_load(s,32+i*8))
            i=i+1
        i=0
        while i<2:
            if (flags&(2<<i))==0:
                literal(o,w,24+i)
                quoted(s,o,w,field_offset(s,2+i),word_load(s,32+i*8),False)
            i=i+1
    else:
        literal(o,w,8)
        quoted(s,o,w,field_offset(s,4),word_load(s,80),False)
        literal(o,w,9)
        quoted(s,o,w,field_offset(s,5),word_load(s,88),False)
        literal(o,w,10)
        if (flags&8)!=0:
            quoted(s,o,w,field_offset(s,6),word_load(s,96),False)
        else:
            literal(o,w,11)
        emit(o,w,125)
        if (flags&1)!=0:
            literal(o,w,12)
            if word_load(s,64)!=0:
                signed_decimal(o,w,word_load(s,72))
            else:
                literal(o,w,11)
            stream(s,o,w,0,word_load(s,48))
            stream(s,o,w,1,word_load(s,56))
        if (flags&16)!=0:
            literal(o,w,13)
            quoted(s,o,w,field_offset(s,7),word_load(s,104),False)
    emit(o,w,125)
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
def program():return document(source_program(),'program_llvm_public_log_codec')
if __name__=='__main__':
 tree=program();stats=(len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']))
 assert stats[0]<=128 and stats[1]<=1536 and stats[2]<=8192,stats
 target=ROOT/'examples/hia_bootstrap/program_llvm_public_log_codec.hepta'
 target.write_text(render_assembly(tree));print(target.name,target.stat().st_size,stats,flush=True)
