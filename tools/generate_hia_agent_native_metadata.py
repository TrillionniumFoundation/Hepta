"""Author native Agent signature selection and borrowed-byte manifest policy.

The HIA kernel consumes exact primitive Core bytes plus either a raw JSON manifest
or a bounded exact-type immutable-tuple snapshot.
Standard JSON fractions and exponents are retained as a non-integer tag so
invalid extents are refused in manifest order. The raw JSON profile does not coerce arbitrary Python objects. A separate
immutable-tuple snapshot preserves type, prefix, length and integer observations. Full Core admission remains mandatory.
This component
does not replace nominal normalization, file custody, compilation or publication.
"""
from __future__ import annotations
import argparse
import ast
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC=int.from_bytes(b'HIANMQ01','little')
RESULT_MAGIC=int.from_bytes(b'HIANMD01','little')
SNAPSHOT_MAGIC=int.from_bytes(b'HIAMT001','little')
NONE=(1<<64)-1
KEYS=('functions','exports','name','params','returns','type')
WIDTHS=('i8','i16','i32','i64','u8','u16','u32','u64','isize','usize','bool')
RESERVED=('abort','calloc','malloc','free','memset','memcpy','memmove',
          '_init','_fini','__gmon_start__','__cxa_finalize','__dso_handle',
          '_ITM_registerTMCloneTable','_ITM_deregisterTMCloneTable')
BYTE_PROFILE='hepta.hia.agent.borrowed-byte-snapshots.v1'

SOURCE=r'''
def agent_native_metadata(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or length(o)<4194304 or length(w)<128:
        return 4294967293
    version=header_word(s,8)
    if header_word(s,0)!=REQUEST_MAGIC or (version!=1 and version!=2):
        return 4294967293
    core_size=header_word(s,16)
    manifest_size=header_word(s,24)
    structured=header_word(s,32)
    if core_size>8388608 or manifest_size>8388608 or structured>1:
        return 4294967293
    if header_word(s,40)!=0 or header_word(s,48)!=0 or header_word(s,56)!=0:
        return 4294967293
    if length(s)!=64+core_size+manifest_size:
        return 4294967293
    largest=choose(core_size>manifest_size,core_size,manifest_size)
    nodes=((largest+1)>>1)+1
    if nodes>262144:
        nodes=262144
    arena=64+nodes*56+largest
    if arena<8192:
        arena=8192
    auxiliary=(arena+15)&18446744073709551600
    if length(w)<auxiliary+65536 or length(o)<core_size+65600:
        return 4294967294
    if version==1:
        put(o,48,262144)
        put(o,56,64)
        result=widen(decode_json(s,w,o,(64+core_size)|(manifest_size<<32)))
        if result>=4294967292:
            return 4294967280
        status=capture_exports(s,w,auxiliary,64+core_size)
    else:
        status=capture_object_exports(s,w,auxiliary,64+core_size,manifest_size)
    if status!=0:
        return status
    put(o,48,262144)
    put(o,56,64)
    result=widen(decode_json(s,w,o,64|(core_size<<32)))
    if result>=4294967292:
        return 4294967279
    functions=field(w,0,K_functions)
    exports=field(w,0,K_exports)
    if kind(w,0)!=6 or kind(w,functions)!=5 or count(w,functions)==0 or count(w,functions)>1024:
        return 4294967279
    if exports!=NONE and kind(w,exports)!=5:
        return 4294967279
    foreign_count=get(w,auxiliary)
    if foreign_count!=0 and (structured!=0 or exports!=NONE):
        return 4294967289
    status=validate_functions(w,functions,exports,auxiliary)
    if status!=0:
        return status
    sort_exports(w,auxiliary)
    put(w,48,0)
    put(w,56,64)
    emit(o,w,L_foreign)
    i=0
    while i<foreign_count:
        if i!=0:
            append_byte(o,w,44)
        row=manifest_row(auxiliary,get(w,auxiliary+20608+i*8))
        append_byte(o,w,91)
        append_text(o,w,row+32,get(w,row))
        append_byte(o,w,44)
        decimal(o,w,get(w,row+8))
        append_byte(o,w,93)
        i=i+1
    emit(o,w,L_signatures)
    written=0
    phase=0
    while phase<2:
        fn=child(w,functions)
        while fn!=NONE:
            name=field(w,fn,K_name)
            foreign=lookup_export(w,auxiliary,name)
            chosen=0
            if phase==0:
                chosen=scalar_callable(w,fn,exports)
            else:
                if foreign!=NONE:
                    chosen=1
            if chosen!=0:
                if written!=0:
                    append_byte(o,w,44)
                append_node_text(o,w,name)
                append_byte(o,w,58)
                signature(o,w,fn,foreign,auxiliary)
                written=written+1
            fn=next_node(w,fn)
        phase=phase+1
    emit(o,w,L_close)
    if get(w,48)!=0:
        return 4294967294
    size=get(w,56)
    put(o,0,RESULT_MAGIC)
    put(o,8,1)
    put(o,16,count(w,functions))
    put(o,24,written)
    put(o,32,foreign_count)
    put(o,40,size-64)
    put(o,48,0)
    put(o,56,0)
    return size

def capture_exports(s:readbuf,w:mutbuf,auxiliary:u64,source_base:u64) -> u64:
    if kind(w,0)!=5 or count(w,0)>128:
        return 4294967291
    amount=count(w,0)
    put(w,auxiliary,amount)
    pair=child(w,0)
    i=0
    while pair!=NONE:
        row=manifest_row(auxiliary,i)
        put(w,row,0)
        put(w,row+8,0)
        put(w,row+16,0)
        put(w,row+24,NONE)
        if kind(w,pair)==5 and count(w,pair)==2:
            name=child(w,pair)
            limit=next_node(w,name)
            if kind(w,name)==4 and kind(w,limit)==3:
                name_start=get(w,64+name*56+24)
                name_size=count(w,name)
                put(w,row,name_size)
                copied=choose(name_size>128,128,name_size)
                j=0
                while j<copied:
                    store(w,row+32+j,byte(w,name_start+j))
                    j=j+1
                number_start=get(w,64+limit*56+24)
                number_size=count(w,limit)
                if number_size>0 and number_size<=7:
                    extent=0
                    valid=1
                    j=0
                    while j<number_size:
                        digit=byte(s,source_base+number_start+j)
                        if digit<48 or digit>57:
                            valid=0
                        else:
                            extent=extent*10+digit-48
                        j=j+1
                    put(w,row+8,extent)
                    put(w,row+16,valid)
        put(w,auxiliary+20608+i*8,i)
        pair=next_node(w,pair)
        i=i+1
    if i!=amount:
        return 4294967293
    return 0

def capture_object_exports(s:readbuf,w:mutbuf,auxiliary:u64,base:u64,size:u64) -> u64:
    if size<32 or header_word(s,base)!=SNAPSHOT_MAGIC or header_word(s,base+24)!=0:
        return 4294967293
    amount=header_word(s,base+16)
    if header_word(s,base+8)!=1 or amount>128:
        return 4294967291
    if size!=32+amount*576:
        return 4294967293
    put(w,auxiliary,amount)
    i=0
    while i<amount:
        row=manifest_row(auxiliary,i)
        capture_object_pair(s,w,row,base+32+i*576)
        put(w,auxiliary+20608+i*8,i)
        i=i+1
    return 0

def capture_object_pair(s:readbuf,w:mutbuf,row:u64,base:u64) -> u64:
    put(w,row,0)
    put(w,row+8,0)
    put(w,row+16,0)
    put(w,row+24,NONE)
    if header_word(s,base)!=1 or header_word(s,base+8)!=2:
        return 0
    if header_word(s,base+16)!=1 or header_word(s,base+32)!=1:
        return 0
    name_size=header_word(s,base+24)
    put(w,row,name_size)
    copied=choose(name_size>128,128,name_size)
    i=0
    while i<copied:
        value=source_word32(s,base+64+i*4)
        store(w,row+32+i,choose(value<=127,value,255))
        i=i+1
    if header_word(s,base+40)==0 and header_word(s,base+48)<=64:
        value=header_word(s,base+56)
        rest=value
        bits=0
        while rest!=0:
            rest=rest>>1
            bits=bits+1
        if bits==header_word(s,base+48):
            put(w,row+8,value)
            put(w,row+16,1)
    return 0

def source_word32(s:readbuf,at:u64) -> u64:
    return byte(s,at) | (byte(s,at+1)<<8) | (byte(s,at+2)<<16) | (byte(s,at+3)<<24)

def validate_functions(w:mutbuf,functions:u64,exports:u64,auxiliary:u64) -> u64:
    fn=child(w,functions)
    while fn!=NONE:
        name=field(w,fn,K_name)
        params=field(w,fn,K_params)
        returns=field(w,fn,K_returns)
        if kind(w,fn)!=6 or kind(w,name)!=4 or kind(w,params)!=5 or kind(w,returns)!=5:
            return 4294967279
        p=child(w,params)
        while p!=NONE:
            if kind(w,p)!=6 or kind(w,field(w,p,K_type))!=4:
                return 4294967279
            p=next_node(w,p)
        r=child(w,returns)
        while r!=NONE:
            if kind(w,r)!=4:
                return 4294967279
            r=next_node(w,r)
        fn=next_node(w,fn)
    # Preserve normalize_exports' input order, including duplicate/extent
    # refusal before reserved-name/function/signature policy for each pair.
    i=0
    while i<get(w,auxiliary):
        row=manifest_row(auxiliary,i)
        extent=get(w,row+8)
        if get(w,row+16)!=1 or extent<1 or extent>1048576:
            return 4294967290
        j=0
        while j<i:
            previous=manifest_row(auxiliary,j)
            if bytes_equal(w,row+32,get(w,row),previous+32,get(w,previous))!=0:
                return 4294967290
            j=j+1
        if reserved_name(w,row+32,get(w,row))!=0:
            return 4294967288
        # No valid Core identifier exceeds 128 bytes. The retained prefix
        # above suffices for reserved-prefix refusal without copying an
        # arbitrarily large invalid manifest name into the fixed row.
        if get(w,row)>128:
            return 4294967287
        found=NONE
        fn=child(w,functions)
        while fn!=NONE:
            name=field(w,fn,K_name)
            if bytes_equal(w,row+32,get(w,row),get(w,64+name*56+24),count(w,name))!=0:
                found=fn
            fn=next_node(w,fn)
        if found==NONE:
            return 4294967287
        params=field(w,found,K_params)
        returns=field(w,found,K_returns)
        if count(w,returns)!=1 or text_is(w,child(w,returns),L_u32)==0:
            return 4294967286
        loans=0
        p=child(w,params)
        while p!=NONE:
            typ=field(w,p,K_type)
            if loan_type(w,typ)!=0:
                loans=loans+1
            else:
                if scalar_type(w,typ)==0:
                    return 4294967286
            p=next_node(w,p)
        if loans<1 or loans>8:
            return 4294967286
        put(w,row+24,found)
        i=i+1
    return 0

def scalar_callable(w:mutbuf,fn:u64,exports:u64) -> u64:
    if exports!=NONE:
        found=0
        item=child(w,exports)
        while item!=NONE:
            if nodes_equal(w,item,field(w,fn,K_name))!=0:
                found=1
            item=next_node(w,item)
        if found==0:
            return 0
    params=child(w,field(w,fn,K_params))
    while params!=NONE:
        if scalar_type(w,field(w,params,K_type))==0:
            return 0
        params=next_node(w,params)
    returns=field(w,fn,K_returns)
    if count(w,returns)>1:
        return 0
    item=child(w,returns)
    if item!=NONE:
        if scalar_type(w,item)==0 and text_is(w,item,L_unit)==0:
            return 0
    return 1

def lookup_export(w:mutbuf,auxiliary:u64,name:u64) -> u64:
    if kind(w,name)!=4:
        return NONE
    start=get(w,64+name*56+24)
    size=count(w,name)
    i=0
    while i<get(w,auxiliary):
        row=manifest_row(auxiliary,i)
        if bytes_equal(w,start,size,row+32,get(w,row))!=0:
            return i
        i=i+1
    return NONE

def sort_exports(w:mutbuf,auxiliary:u64) -> u64:
    i=1
    while i<get(w,auxiliary):
        item=get(w,auxiliary+20608+i*8)
        j=i
        moving=True
        while j>0 and moving:
            previous=get(w,auxiliary+20608+(j-1)*8)
            a=manifest_row(auxiliary,item)
            b=manifest_row(auxiliary,previous)
            if bytes_less(w,a+32,get(w,a),b+32,get(w,b))!=0:
                put(w,auxiliary+20608+j*8,previous)
                j=j-1
            else:
                moving=False
        put(w,auxiliary+20608+j*8,item)
        i=i+1
    return 0

def signature(o:mutbuf,w:mutbuf,fn:u64,foreign:u64,auxiliary:u64) -> u64:
    if foreign==NONE:
        emit(o,w,L_params)
    else:
        emit(o,w,L_abi)
        emit(o,w,L_profile)
        emit(o,w,L_limit)
        decimal(o,w,get(w,manifest_row(auxiliary,foreign)+8))
        emit(o,w,L_foreign_params)
    p=child(w,field(w,fn,K_params))
    i=0
    while p!=NONE:
        if i!=0:
            append_byte(o,w,44)
        append_node_text(o,w,field(w,p,K_type))
        p=next_node(w,p)
        i=i+1
    emit(o,w,L_returns)
    r=child(w,field(w,fn,K_returns))
    i=0
    while r!=NONE:
        if i!=0:
            append_byte(o,w,44)
        append_node_text(o,w,r)
        r=next_node(w,r)
        i=i+1
    emit(o,w,L_signature_end)
    return 0

def decimal(o:mutbuf,w:mutbuf,value:u64) -> u64:
    divisor=1000000
    started=False
    while divisor>0:
        digit=0
        while value>=divisor:
            value=value-divisor
            digit=digit+1
        if digit!=0 or started or divisor==1:
            append_byte(o,w,48+digit)
            started=True
        divisor=choose(divisor==1000000,100000,choose(divisor==100000,10000,choose(divisor==10000,1000,choose(divisor==1000,100,choose(divisor==100,10,choose(divisor==10,1,0))))))
    return 0

def append_node_text(o:mutbuf,w:mutbuf,node:u64) -> u64:
    return append_text(o,w,get(w,64+node*56+24),count(w,node))

def append_text(o:mutbuf,w:mutbuf,start:u64,size:u64) -> u64:
    append_byte(o,w,34)
    i=0
    while i<size:
        value=byte(w,start+i)
        if value<32:
            append_byte(o,w,92)
            escape=0
            if value==8:
                escape=98
            if value==9:
                escape=116
            if value==10:
                escape=110
            if value==12:
                escape=102
            if value==13:
                escape=114
            if escape!=0:
                append_byte(o,w,escape)
            else:
                append_byte(o,w,117)
                append_byte(o,w,48)
                append_byte(o,w,48)
                append_byte(o,w,hex_digit(value>>4))
                append_byte(o,w,hex_digit(value&15))
        else:
            if value==34 or value==92:
                append_byte(o,w,92)
            append_byte(o,w,value)
        i=i+1
    append_byte(o,w,34)
    return 0

def append_byte(o:mutbuf,w:mutbuf,value:u64) -> u64:
    index=get(w,56)
    if index>=length(o):
        put(w,48,1)
    else:
        store(o,index,value)
        put(w,56,index+1)
    return 0

def hex_digit(value:u64) -> u64:
    return choose(value<10,value+48,value+87)

def emit(o:mutbuf,w:mutbuf,n:u64,a:u64,b:u64,c:u64) -> u64:
    i=0
    while i<n:
        value=a
        shift=i*8
        if i>=8:
            value=b
            shift=(i-8)*8
        if i>=16:
            value=c
            shift=(i-16)*8
        append_byte(o,w,(value>>shift)&255)
        i=i+1
    return 0

def header_word(s:readbuf,at:u64) -> u64:
    return byte(s,at) | (byte(s,at+1)<<8) | (byte(s,at+2)<<16) | (byte(s,at+3)<<24) | (byte(s,at+4)<<32) | (byte(s,at+5)<<40) | (byte(s,at+6)<<48) | (byte(s,at+7)<<56)

def manifest_row(auxiliary:u64,index:u64) -> u64:
    return auxiliary+128+index*160

def bytes_equal(w:mutbuf,a:u64,n:u64,b:u64,m:u64) -> u64:
    if n!=m:
        return 0
    i=0
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return 0
        i=i+1
    return 1

def bytes_less(w:mutbuf,a:u64,n:u64,b:u64,m:u64) -> u64:
    i=0
    while i<n and i<m:
        x=byte(w,a+i)
        y=byte(w,b+i)
        if x<y:
            return 1
        if x>y:
            return 0
        i=i+1
    return choose(n<m,1,0)

def nodes_equal(w:mutbuf,a:u64,b:u64) -> u64:
    if kind(w,a)!=4 or kind(w,b)!=4:
        return 0
    return bytes_equal(w,get(w,64+a*56+24),count(w,a),get(w,64+b*56+24),count(w,b))

def kind(w:mutbuf,node:u64) -> u64:
    if node==NONE:
        return NONE
    return get(w,64+node*56)

def count(w:mutbuf,node:u64) -> u64:
    if node==NONE:
        return 0
    return get(w,64+node*56+32)

def child(w:mutbuf,node:u64) -> u64:
    if kind(w,node)!=5 and kind(w,node)!=6:
        return NONE
    return get(w,64+node*56+24)

def next_node(w:mutbuf,node:u64) -> u64:
    return get(w,64+node*56+16)

def field(w:mutbuf,node:u64,flag:u64) -> u64:
    if kind(w,node)!=6:
        return NONE
    current=child(w,node)
    while current!=NONE:
        if key_id(w,current)==flag:
            return current
        current=next_node(w,current)
    return NONE

def same(w:mutbuf,start:u64,size:u64,n:u64,a:u64,b:u64,c:u64) -> u64:
    if size!=n:
        return 0
    i=0
    while i<n:
        word=a
        shift=i*8
        if i>=8:
            word=b
            shift=(i-8)*8
        if i>=16:
            word=c
            shift=(i-16)*8
        if byte(w,start+i)!=((word>>shift)&255):
            return 0
        i=i+1
    return 1

def text_is(w:mutbuf,node:u64,n:u64,a:u64,b:u64,c:u64) -> u64:
    if kind(w,node)!=4:
        return 0
    return same(w,get(w,64+node*56+24),count(w,node),n,a,b,c)
'''


# Metadata-only lexical number support. Non-integer JSON numbers are tagged;
# no floating-point value is computed or accepted as a manifest extent.
JSON_NUMBER_SOURCE=r'''
def atom(s:readbuf,index:u64) -> u64:
    size=length(s)
    if index>=size:
        return 4294967295
    if size-index>=4:
        if byte(s,index)==116 and byte(s,index+1)==114 and byte(s,index+2)==117 and byte(s,index+3)==101:
            return index+4
        if byte(s,index)==110 and byte(s,index+1)==117 and byte(s,index+2)==108 and byte(s,index+3)==108:
            return index+4
    if size-index>=5:
        if byte(s,index)==102 and byte(s,index+1)==97 and byte(s,index+2)==108 and byte(s,index+3)==115 and byte(s,index+4)==101:
            return index+5
    if byte(s,index)==45:
        index=index+1
    if index>=size:
        return 4294967295
    ch=byte(s,index)
    if ch<48 or ch>57:
        return 4294967295
    if ch==48:
        index=index+1
    else:
        going=True
        while going and index<size:
            ch=byte(s,index)
            if ch>=48 and ch<=57:
                index=index+1
            else:
                going=False
    if index<size and byte(s,index)==46:
        index=index+1
        digits=index
        going=True
        while going and index<size:
            ch=byte(s,index)
            if ch>=48 and ch<=57:
                index=index+1
            else:
                going=False
        if index==digits:
            return 4294967295
    if index<size and (byte(s,index)==101 or byte(s,index)==69):
        index=index+1
        if index<size and (byte(s,index)==43 or byte(s,index)==45):
            index=index+1
        digits=index
        going=True
        while going and index<size:
            ch=byte(s,index)
            if ch>=48 and ch<=57:
                index=index+1
            else:
                going=False
        if index==digits:
            return 4294967295
    return index

def classify_number(s:readbuf,start:u64,end:u64) -> u64:
    while start<end:
        value=byte(s,start)
        if value==46 or value==101 or value==69:
            return 7
        start=start+1
    return 3
'''

LITERALS={
    'foreign':'{"foreign_buffer_exports":[',
    'signatures':'],"signatures":{',
    'close':'}}',
    'params':'{"params":[',
    'abi':'{"abi":"',
    'profile':BYTE_PROFILE,
    'limit':'","max_buffer_bytes":',
    'foreign_params':',"params":[',
    'returns':'],"returns":[',
    'signature_end':']}',
    'unit':'unit','u32':'u32',
}

def packed(value):
    raw=value.encode('utf-8')
    if len(raw)>24:raise ValueError('literal chunk')
    return [len(raw),*(int.from_bytes(raw[i:i+8],'little') for i in (0,8,16))]

def _text_test(start,size,value):
    pieces=[value[i:i+24] for i in range(0,len(value),24)]
    tests=[f'same(w,{start}+{i*24},{len(part)},'+','.join(map(str,packed(part)))+')!=0'
           for i,part in enumerate(pieces)]
    return f'{size}=={len(value)} and ('+' and '.join(tests)+')'

def source_program():
    constants={'REQUEST_MAGIC':REQUEST_MAGIC,'RESULT_MAGIC':RESULT_MAGIC,'SNAPSHOT_MAGIC':SNAPSHOT_MAGIC,'NONE':NONE,
               **{'K_'+key:1<<i for i,key in enumerate(KEYS)}}
    class Expand(ast.NodeTransformer):
        def visit_Expr(self,node):
            call=node.value
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='emit':
                label=call.args[-1]
                if isinstance(label,ast.Name) and label.id.startswith('L_'):
                    raw=LITERALS[label.id[2:]]
                    return [ast.Expr(value=ast.Call(func=ast.Name(id='emit',ctx=ast.Load()),
                        args=[ast.Name(id='o',ctx=ast.Load()),ast.Name(id='w',ctx=ast.Load()),
                              *[ast.Constant(x) for x in packed(raw[i:i+24])]],keywords=[]))
                        for i in range(0,len(raw),24)]
            return self.generic_visit(node)
        def visit_Call(self,node):
            node=self.generic_visit(node)
            args=[]
            for arg in node.args:
                if isinstance(arg,ast.Name) and arg.id.startswith('L_'):
                    args.extend(ast.Constant(x) for x in packed(LITERALS[arg.id[2:]]))
                else:args.append(arg)
            node.args=args
            return node
        def visit_Name(self,node):
            return ast.Constant(constants[node.id]) if node.id in constants else node
    primary=Expand().visit(ast.parse(SOURCE)).body
    key=['def key_id(w:mutbuf,node:u64) -> u64:',
         '    start=get(w,64+node*56+40)','    size=get(w,64+node*56+48)']
    for i,name in enumerate(KEYS):
        key += ['    if '+_text_test('start','size',name)+':','        return '+str(1<<i)]
    key += ['    return 0']
    scalar=['def scalar_type(w:mutbuf,node:u64) -> u64:',
            '    if kind(w,node)!=4:','        return 0',
            '    start=get(w,64+node*56+24)','    size=count(w,node)']
    for name in WIDTHS:
        scalar += ['    if '+_text_test('start','size',name)+':','        return 1']
    scalar += ['    return 0']
    loan=['def loan_type(w:mutbuf,node:u64) -> u64:',
          '    if kind(w,node)!=4:','        return 0',
          '    start=get(w,64+node*56+24)','    size=count(w,node)']
    for name in ('readbuf','mutbuf'):
        loan += ['    if '+_text_test('start','size',name)+':','        return 1']
    loan += ['    return 0']
    reserved=['def reserved_name(w:mutbuf,start:u64,size:u64) -> u64:',
              '    if size>=6:',
              '        if same(w,start,6,'+','.join(map(str,packed('__hia_')))+')!=0:',
              '            return 1']
    for name in RESERVED:
        reserved += ['    if '+_text_test('start','size',name)+':','        return 1']
    reserved += ['    return 0']

    # The existing decoder sees an exact bounded source slice. Each header
    # bound is below 2**32, so one u64 carries size in the upper32 bits
    # and base in the lower32. The view preserves relative offsets; only the
    # metadata-specific numeric tag extension below changes number handling.
    decoder=ast.parse(decoder_source())
    numeric=ast.parse(JSON_NUMBER_SOURCE).body
    atoms=[node for node in decoder.body if node.name=='atom']
    decoders=[node for node in decoder.body if node.name=='decode_json']
    if len(atoms)!=1 or len(decoders)!=1:raise ValueError('decoder numeric hook changed')
    class NumberKind(ast.NodeTransformer):
        def __init__(self):self.edits=0
        def visit_Assign(self,node):
            if (len(node.targets)==1 and isinstance(node.targets[0],ast.Name)
                    and node.targets[0].id=='kind' and isinstance(node.value,ast.Constant)
                    and type(node.value.value) is int and node.value.value==3):
                self.edits+=1
                node.value=ast.Call(func=ast.Name(id='classify_number',ctx=ast.Load()),
                    args=[ast.Name(id=name,ctx=ast.Load()) for name in ('s','index','end')],keywords=[])
            return self.generic_visit(node)
    tagging=NumberKind()
    tagging.visit(decoders[0])
    if tagging.edits!=1:raise ValueError('decoder numeric tag changed')
    decoder.body=[numeric[0] if node.name=='atom' else node for node in decoder.body]+[numeric[1]]
    sliced={n.name for n in decoder.body
            if any(a.arg=='s' and isinstance(a.annotation,ast.Name) and a.annotation.id=='readbuf'
                   for a in n.args.args)}
    class SliceSource(ast.NodeTransformer):
        def visit_FunctionDef(self,node):
            self.active=node.name in sliced
            if self.active:
                node.args.args += [ast.arg(arg='source_view',annotation=ast.Name(id='u64',ctx=ast.Load()))]
            node=self.generic_visit(node)
            self.active=False
            return node
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if isinstance(node.func,ast.Name):
                if self.active and node.func.id=='length' and len(node.args)==1 and isinstance(node.args[0],ast.Name) and node.args[0].id=='s':
                    return ast.BinOp(left=ast.Name(id='source_view',ctx=ast.Load()),op=ast.RShift(),right=ast.Constant(32))
                if self.active and node.func.id=='byte' and isinstance(node.args[0],ast.Name) and node.args[0].id=='s':
                    node.args[1]=ast.BinOp(left=ast.BinOp(left=ast.Name(id='source_view',ctx=ast.Load()),
                        op=ast.BitAnd(),right=ast.Constant(4294967295)),op=ast.Add(),right=node.args[1])
                if node.func.id in sliced:
                    if not self.active:raise ValueError('source slice passed from a sourceless helper')
                    node.args += [ast.Name(id='source_view',ctx=ast.Load())]
            return node
    decoder=SliceSource().visit(decoder)
    helpers=ast.parse('\n'.join(key+['']+scalar+['']+loan+['']+reserved)).body
    nodes=primary+helpers+decoder.body
    if len({n.name for n in nodes})!=len(nodes):raise ValueError('duplicate native authoring name')
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])))

def profile_inventory(document, assembly):
    """Inspect every logical argument position in the actual lowered CFG.

    This deliberately does not report a native image/relocation result.
    Those require the original real compiler and captured native receipt.
    """
    functions = document['functions']
    evidence = {'functions': len(functions), 'blocks': 0, 'operations': 0,
                'assembly_bytes': len(assembly.encode('utf-8')), 'per_function': [],
                'max_logical_call_arguments': 0, 'max_logical_edge_arguments': 0,
                'max_logical_block_parameters': 0, 'max_function_parameters': 0,
                'max_function_values': 0,
                'native_image_bytes': None, 'native_relocations': None,
                'native_compile_executed': False,
                'required_native_image_limit_bytes': 1048576,
                'required_native_relocation_limit': 12000}
    if not functions or functions[0]['name'] != 'f0':
        raise ValueError('wrong native entry identity')
    if [param['type'] for param in functions[0]['params']] != ['readbuf', 'mutbuf', 'mutbuf']:
        raise ValueError('entry escaped the existing flat 3-buffer ABI')
    if functions[0]['returns'] != ['u32']:
        raise ValueError('entry result ABI changed')
    for function in functions:
        values = {param['name'] for param in function['params']}
        blocks = function['blocks']
        item = {'name': function['name'], 'blocks': len(blocks), 'operations': 0,
                'parameters': len(function['params']), 'values': None,
                'max_block_parameters': 0, 'max_edge_arguments': 0,
                'max_call_arguments': 0}
        for block in blocks:
            values.update(param['name'] for param in block['params'])
            item['max_block_parameters'] = max(item['max_block_parameters'], len(block['params']))
            item['operations'] += len(block['ops'])
            for operation in block['ops']:
                values.update(out['name'] for out in operation['out'])
                if operation['op'] == 'call':
                    item['max_call_arguments'] = max(item['max_call_arguments'], len(operation['args']))
            term = block['term']
            edges = ([term] if term['op'] == 'jump' else
                     [term['then'], term['else']] if term['op'] == 'branch' else [])
            for edge in edges:
                item['max_edge_arguments'] = max(item['max_edge_arguments'], len(edge['args']))
            if term['op'] == 'ret' and len(term['values']) > 16:
                raise ValueError(('native return arity exceeded', function['name'], block['id']))
        item['values'] = len(values)
        evidence['per_function'].append(item)
        evidence['blocks'] += item['blocks']
        evidence['operations'] += item['operations']
        evidence['max_function_parameters'] = max(evidence['max_function_parameters'], item['parameters'])
        evidence['max_logical_block_parameters'] = max(evidence['max_logical_block_parameters'], item['max_block_parameters'])
        evidence['max_logical_edge_arguments'] = max(evidence['max_logical_edge_arguments'], item['max_edge_arguments'])
        evidence['max_logical_call_arguments'] = max(evidence['max_logical_call_arguments'], item['max_call_arguments'])
        evidence['max_function_values'] = max(evidence['max_function_values'], item['values'])
        if item['blocks'] > 256 or item['values'] > 2048:
            raise ValueError(('native function profile exceeded', item))
        if max(item['parameters'], item['max_block_parameters'],
               item['max_edge_arguments'], item['max_call_arguments']) > 16:
            raise ValueError(('native logical argument profile exceeded', item))
    if (evidence['functions'] > 128 or evidence['blocks'] > 1536
            or evidence['operations'] > 8192 or evidence['assembly_bytes'] > 1048576):
        raise ValueError(('native module profile exceeded', evidence))
    evidence['static_generated_profile_within_existing_limits'] = True
    evidence['status'] = 'GENERATED_STRUCTURE_ONLY_NOT_NATIVE_OR_COLD_QUALIFIED'
    return evidence


def document():
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],
                          'entry':'b0','blocks':builder.blocks})
    result = compact_authoring_cfg({'schema':'hepta.hia.program.v8',
                                   'module':'agent_native_metadata','functions':functions})
    profile_inventory(result, render_assembly(result))
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--authoring-source', type=Path)
    args = parser.parse_args()
    targets = [args.output, args.inventory, *([args.authoring_source] if args.authoring_source else [])]
    if len({str(path.absolute()) for path in targets}) != len(targets) or any(path.exists() for path in targets):
        raise ValueError('generation requires distinct absent output paths')
    result = document()
    assembly = render_assembly(result)
    inventory = profile_inventory(result, assembly)
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(assembly)
    with args.inventory.open('x', encoding='utf-8') as stream:
        json.dump(inventory, stream, sort_keys=True, indent=2)
        stream.write('\n')
    if args.authoring_source:
        with args.authoring_source.open('x', encoding='utf-8') as stream:
            stream.write(source_program())


if __name__ == '__main__':
    main()
