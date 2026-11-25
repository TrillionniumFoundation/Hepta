"""Exact original NDU exception records from private native owner diagnostics.
The generated pure HIA role uses u64 lengths and supports an O=0 sizing pass.
"""
from pathlib import Path
import ast
import os,re
from tools.generate_hia_ndu_evaluator import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
TEXT={
 'prefix':'{"message":"','middle':'","type":"','suffix':'"}',
 'ndu':'E_HIA_NDU: ','json':'E_HIA_NDU: invalid JSON: ',
 'shape':'bridge requires binary and build_receipt paths',
 'path_type':"argument should be a str or an os.PathLike object where __fspath__ returns a str, not '",
 'quote':"'",'none':'NoneType','bool':'bool','int':'int','float':'float','list':'list','dict':'dict',
 'null':'lstat: embedded null character in path','bounded':'expected bounded regular file: ',
 'changed':'file changed during read','length':'file length changed during read',
 'read':'bounded regular file read failed','contract':'bridge build receipt has wrong source, scope or build gates',
 'source':'bridge adapter, lock or builder differs from the recorded build',
 'binary':'bridge executable differs from the recorded build','request':'native request exceeds byte limit',
 'budget':'native budget exhausted before process start',
 'seal':'sealed executable snapshot unavailable','write':'sealed native snapshot write made no progress',
 'seals':'sealed executable snapshot does not retain the admitted bytes and seals',
 'pump':'native evaluator could not complete: E_HIA_RUST_CROSSCHECK: ',
 'deadline':'shadow exceeded execution deadline','output':'shadow exceeded bounded output budget',
 'unavailable':'bounded shadow child unavailable or timed out',
 'cleanup':'shadow process-group cleanup or leader reap unconfirmed',
 'failed':'native evaluator failed or exceeded output bounds',
 'post':'native evaluator changed during invocation','internal':'native NDU owner invariant failed',
 'duplicate':'duplicate JSON key','nonfinite':'non-finite JSON number',
 'utf8':"'utf-8'",'utf16le':"'utf-16-le'",'utf16be':"'utf-16-be'",'utf32le':"'utf-32-le'",'utf32be':"'utf-32-be'",
 'encodeone':" codec can't encode character '\\u",'encodemany':' codec can\'t encode characters in position ',
 'position':"' in position ",'surrogates':': surrogates not allowed','hyphen':'-',
 'decodeone':" codec can't decode byte 0x",'decodemany':" codec can't decode bytes in position ",
 'inposition':' in position ','colon':': ',
 'startbyte':'invalid start byte','enddata':'unexpected end of data','continuation':'invalid continuation byte',
 'truncated':'truncated data','range':'code point not in range(0x110000)',
 'expectvalue':'Expecting value','extra':'Extra data','property':'Expecting property name enclosed in double quotes',
 'expectcolon':"Expecting ':' delimiter",'comma':"Expecting ',' delimiter",
 'unterminated':'Unterminated string starting at','control':'Invalid control character at','hex':'Invalid \\uXXXX escape',
 'trailingobject':'Illegal trailing comma before end of object','trailingarray':'Illegal trailing comma before end of array',
 'escape':'Invalid \\escape','line':': line ','column':' column ','char':' (char ','close':')',
 'digits1':'Exceeds the limit (','digitslimit':' digits) for integer string conversion: value has ',
 'digits2':' digits; use sys.set_int_max_str_digits() to increase the limit',
 'recursion':'maximum recursion depth exceeded while decoding a JSON array from a unicode string',
 'errno':'[Errno ','errnoend':'] ',
 'OptimizationRejected':'OptimizationRejected','TypeError':'TypeError','ValueError':'ValueError',
 'UnicodeEncodeError':'UnicodeEncodeError','RuntimeError':'RuntimeError','MemoryError':'MemoryError',
 'RecursionError':'RecursionError','OSError':'OSError','FileNotFoundError':'FileNotFoundError',
 'PermissionError':'PermissionError','NotADirectoryError':'NotADirectoryError','IsADirectoryError':'IsADirectoryError',
 'FileExistsError':'FileExistsError','BlockingIOError':'BlockingIOError','BrokenPipeError':'BrokenPipeError',
 'ChildProcessError':'ChildProcessError','ProcessLookupError':'ProcessLookupError','InterruptedError':'InterruptedError',
 'ConnectionAbortedError':'ConnectionAbortedError','ConnectionRefusedError':'ConnectionRefusedError',
 'ConnectionResetError':'ConnectionResetError','TimeoutError':'TimeoutError',
 '_NativeBudgetExhausted':'_NativeBudgetExhausted','KeyboardInterrupt':'KeyboardInterrupt'
}
for e in range(1,134):TEXT['errno_'+str(e)]=os.strerror(e)
IDS={k:i for i,k in enumerate(TEXT)}
C={'NONE':2**64-1,'NOSPACE':2**64-2,'MAGIC':int.from_bytes(b'HIANER01','little'),'JSON_MAGIC':int.from_bytes(b'HIANJD01','little'),'UNICODE_MAGIC':int.from_bytes(b'HIAPUE01','little')}
SOURCE=r'''
def render(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<32768 or length(s)<128 or word_load(s,0)!=MAGIC:
        return NONE
    at=128
    i=32
    while i<64:
        amount=word_load(s,i)
        if amount>length(s)-at:
            return NONE
        put(w,64+(i-32)*2,at)
        at=at+amount
        i=i+8
    if at!=length(s) or (word_load(s,40)!=0 and word_load(s,40)!=128):
        return NONE
    i=64
    while i<128:
        if word_load(s,i)!=0:
            return NONE
        i=i+8
    put(w,0,0)
    put(w,8,0)
    literals(w)
    raw(o,w,T_prefix)
    code=word_load(s,8)
    err=word_load(s,16)
    detail=word_load(s,24)
    kind=T_OptimizationRejected
    if code==11 or code==12:
        kind=T_TypeError
        text(o,w,T_path_type)
        text(o,w,choose(detail==1,T_none,choose(detail==2,T_bool,choose(detail==3,T_int,choose(detail==4,T_float,choose(detail==5,T_list,T_dict))))))
        text(o,w,T_quote)
    elif code==13:
        kind=T_ValueError
        text(o,w,T_null)
    elif code==14:
        meta=get(w,80)
        if word_load(s,40)!=128 or word_load(s,meta)!=UNICODE_MAGIC:
            return NONE
        kind=T_UnicodeEncodeError
        unicode_message(s,o,w,meta)
    elif code==15 or code==50:
        eno=0-err
        kind=errno_type(eno)
        text(o,w,T_errno)
        number(o,w,eno)
        text(o,w,T_errnoend)
        errno_text(o,w,eno)
    elif code==16:
        kind=T_MemoryError
    elif code==33:
        meta=get(w,80)
        if word_load(s,40)!=128 or word_load(s,meta)!=JSON_MAGIC:
            return NONE
        kind=json_message(s,o,w,meta)
        if kind==NONE:
            return NONE
    elif code==90:
        kind=T_RuntimeError
        text(o,w,T_internal)
    elif code==99:
        kind=T_KeyboardInterrupt
    else:
        text(o,w,T_ndu)
        if code==10:
            text(o,w,T_shape)
        elif code==20:
            text(o,w,T_bounded)
            path_text(s,o,w,get(w,64),word_load(s,32))
        elif code==21:
            text(o,w,T_changed)
        elif code==22:
            text(o,w,T_length)
        elif code==23:
            text(o,w,T_read)
        elif code==30:
            text(o,w,T_contract)
        elif code==31:
            text(o,w,T_source)
        elif code==32:
            text(o,w,T_binary)
        elif code==40:
            text(o,w,T_request)
        elif code==41:
            text(o,w,T_budget)
            kind=T__NativeBudgetExhausted
        elif code==42:
            text(o,w,choose(detail==1001,T_write,choose(detail==1002,T_seals,T_seal)))
        elif code>=43 and code<=46:
            text(o,w,T_pump)
            text(o,w,choose(code==43,T_deadline,choose(code==44,T_output,choose(code==45,T_unavailable,T_cleanup))))
        elif code==47:
            text(o,w,T_failed)
        elif code==48:
            text(o,w,T_post)
        else:
            return NONE
    raw(o,w,T_middle)
    raw(o,w,kind)
    raw(o,w,T_suffix)
    if get(w,8)==2:
        return NONE
    if get(w,8)!=0:
        return NOSPACE
    return 0

def unicode_message(s:readbuf,o:mutbuf,w:mutbuf,meta:u64) -> unit:
    cp=word_load(s,meta+8)
    start=word_load(s,meta+16)
    end=word_load(s,meta+24)
    text(o,w,T_utf8)
    if end==start+1:
        text(o,w,T_encodeone)
        hex4(o,w,cp)
        text(o,w,T_position)
        number(o,w,start)
    else:
        text(o,w,T_encodemany)
        number(o,w,start)
        text(o,w,T_hyphen)
        number(o,w,end-1)
    text(o,w,T_surrogates)

def json_message(s:readbuf,o:mutbuf,w:mutbuf,meta:u64) -> u64:
    status=word_load(s,meta+8)
    if status==3 or status==4:
        text(o,w,T_ndu)
        text(o,w,choose(status==3,T_duplicate,T_nonfinite))
        return T_OptimizationRejected
    if status==5:
        text(o,w,T_digits1)
        number(o,w,choose(word_load(s,meta+96)==0,4300,word_load(s,meta+96)))
        text(o,w,T_digitslimit)
        number(o,w,word_load(s,meta+112))
        text(o,w,T_digits2)
        return T_ValueError
    if status==6:
        text(o,w,T_recursion)
        return T_RecursionError
    text(o,w,T_json)
    if status==1:
        code=word_load(s,meta+24)
        name=T_expectvalue
        if code==2:
            name=T_extra
        elif code==3:
            name=T_property
        elif code==4:
            name=T_expectcolon
        elif code==5:
            name=T_comma
        elif code==6:
            name=T_unterminated
        elif code==7:
            name=T_control
        elif code==8:
            name=T_hex
        elif code==9:
            name=T_trailingobject
        elif code==10:
            name=T_trailingarray
        elif code==11:
            name=T_escape
        text(o,w,name)
        text(o,w,T_line)
        number(o,w,word_load(s,meta+48))
        text(o,w,T_column)
        number(o,w,word_load(s,meta+56))
        text(o,w,T_char)
        number(o,w,word_load(s,meta+40))
        text(o,w,T_close)
        return T_OptimizationRejected
    if status==2:
        kind=word_load(s,meta+64)
        text(o,w,choose(kind==1,T_utf8,choose(kind==2,T_utf16le,choose(kind==3,T_utf16be,choose(kind==4,T_utf32le,T_utf32be)))))
        start=word_load(s,meta+72)
        end=word_load(s,meta+80)
        if end==start+1:
            text(o,w,T_decodeone)
            hex2(o,w,word_load(s,meta+88))
            text(o,w,T_inposition)
            number(o,w,start)
        else:
            text(o,w,T_decodemany)
            number(o,w,start)
            text(o,w,T_hyphen)
            number(o,w,end-1)
        text(o,w,T_colon)
        reason=word_load(s,meta+24)
        text(o,w,choose(reason==1,T_startbyte,choose(reason==2,T_enddata,choose(reason==3,T_continuation,choose(reason==4,T_truncated,T_range)))))
        return T_OptimizationRejected
    return NONE

def errno_type(eno:u64) -> u64:
    if eno==2:
        return T_FileNotFoundError
    if eno==1 or eno==13:
        return T_PermissionError
    if eno==20:
        return T_NotADirectoryError
    if eno==21:
        return T_IsADirectoryError
    if eno==17:
        return T_FileExistsError
    if eno==11 or eno==114 or eno==115:
        return T_BlockingIOError
    if eno==32 or eno==108:
        return T_BrokenPipeError
    if eno==10:
        return T_ChildProcessError
    if eno==3:
        return T_ProcessLookupError
    if eno==4:
        return T_InterruptedError
    if eno==103:
        return T_ConnectionAbortedError
    if eno==111:
        return T_ConnectionRefusedError
    if eno==104:
        return T_ConnectionResetError
    if eno==110:
        return T_TimeoutError
    return T_OSError

def errno_text(o:mutbuf,w:mutbuf,eno:u64) -> unit:
    if eno>=1 and eno<=133:
        text(o,w,T_errno_1+eno-1)
    else:
        text(o,w,T_internal)

def path_text(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64) -> unit:
    end=at+n
    while at<end:
        ch=byte(s,at)
        width=1
        if ch>=194 and ch<=244:
            need=choose(ch<224,2,choose(ch<240,3,4))
            if need<=end-at:
                b=byte(s,at+1)
                valid=b>=128 and b<=191 and (ch!=224 or b>=160) and (ch!=237 or b<160) and (ch!=240 or b>=144) and (ch!=244 or b<144)
                j=2
                while j<need:
                    c=byte(s,at+j)
                    if c<128 or c>191:
                        valid=False
                    j=j+1
                if valid:
                    width=need
        if ch>=128 and width==1:
            emit(o,w,92)
            emit(o,w,117)
            emit(o,w,100)
            emit(o,w,99)
            hex2(o,w,ch)
        elif width>1:
            j=0
            while j<width:
                emit(o,w,byte(s,at+j))
                j=j+1
        else:
            quoted(o,w,ch)
        at=at+width

def raw(o:mutbuf,w:mutbuf,index:u64) -> unit:
    at=get(w,1024+index*16)
    n=get(w,1032+index*16)
    i=0
    while i<n:
        emit(o,w,byte(w,at+i))
        i=i+1

def text(o:mutbuf,w:mutbuf,index:u64) -> unit:
    at=get(w,1024+index*16)
    n=get(w,1032+index*16)
    i=0
    while i<n:
        quoted(o,w,byte(w,at+i))
        i=i+1

def quoted(o:mutbuf,w:mutbuf,c:u64) -> unit:
    if c==34 or c==92:
        emit(o,w,92)
        emit(o,w,c)
    elif c==8 or c==9 or c==10 or c==12 or c==13:
        emit(o,w,92)
        emit(o,w,choose(c==8,98,choose(c==9,116,choose(c==10,110,choose(c==12,102,114)))))
    elif c<32:
        emit(o,w,92)
        emit(o,w,117)
        emit(o,w,48)
        emit(o,w,48)
        hex2(o,w,c)
    else:
        emit(o,w,c)

def hex2(o:mutbuf,w:mutbuf,c:u64) -> unit:
    a=(c>>4)&15
    b=c&15
    emit(o,w,a+choose(a<10,48,87))
    emit(o,w,b+choose(b<10,48,87))

def hex4(o:mutbuf,w:mutbuf,c:u64) -> unit:
    hex2(o,w,(c>>8)&255)
    hex2(o,w,c&255)

def number(o:mutbuf,w:mutbuf,value:u64) -> unit:
    pos=512
    while value>=10:
        store(w,pos,48+value%10)
        pos=pos+1
        value=value//10
    store(w,pos,48+value)
    pos=pos+1
    while pos>512:
        pos=pos-1
        emit(o,w,byte(w,pos))

def emit(o:mutbuf,w:mutbuf,value:u64) -> unit:
    pos=get(w,0)
    if pos==NONE:
        put(w,8,2)
    else:
        if pos<length(o):
            store(o,pos,value)
        elif get(w,8)==0:
            put(w,8,1)
        put(w,0,pos+1)

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> unit:
    word_store(w,at,value)
'''
def program():
    source=SOURCE
    for name,value in {**C,**{'T_'+k:v for k,v in IDS.items()}}.items():
        source=re.sub(r'\b'+name+r'\b',str(value),source)
    pool=bytearray();rows=[]
    for key,text in TEXT.items():
        raw=text.encode();rows.append((8192+len(pool),len(raw)));pool.extend(raw)
    assert 8192+len(pool)<32768 and 1024+len(rows)*16<8192
    stm=[]
    for i,(at,n)in enumerate(rows):stm +=[f'    put(w,{1024+i*16},{at})',f'    put(w,{1032+i*16},{n})']
    for i in range(0,len(pool),8):
        raw=pool[i:i+8]
        if len(raw)==8:stm.append(f'    word_store(w,{8192+i},{int.from_bytes(raw,"little")})')
        else:
            for j,b in enumerate(raw):stm.append(f'    store(w,{8192+i+j},{b})')
    chunks=[stm[i:i+128]for i in range(0,len(stm),128)]
    source+='\ndef literals(w:mutbuf) -> unit:\n'+''.join(f'    literal_{i}(w)\n'for i in range(len(chunks)))
    for i,chunk in enumerate(chunks):source+=f'\ndef literal_{i}(w:mutbuf) -> unit:\n'+'\n'.join(chunk)+'\n'
    tree=ast.parse(source)
    for fn in tree.body:
        if fn.returns.id=="unit":
            fn.returns=ast.Name(id="u64",ctx=ast.Load())
            fn.body.append(ast.Return(value=ast.Constant(value=0)))
    return ast.unparse(ast.fix_missing_locations(tree))
def main():
    d=document(program(),'ndu_rank_native_owner_error');p=ROOT/'examples/hia_bootstrap/ndu_rank_native_owner_error.hepta';p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']))
if __name__=='__main__':main()
