"""Native immutable tuples and scalar-generation records over the shared value graph.

Q04 owns new nodes and actual class edges. The scalar call preparation executes
under the value owner mutex; callers must hold their lease mutex through the
subsequent native call. No class-name string grants type authority.
"""
from tools.generate_hia_result_value_common import ROOT, document, render_assembly, resolve
from tools.generate_hia_result_value_core import SOURCE as CORE
from tools.generate_hia_result_value_classes import SOURCE as CLASSES, catalog_source

SOURCE = r'''
def result_value_records(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,G_PHASE)
    if phase==0:
        return records_prepare(s,o,w)
    if phase==1:
        if class_catalog(w)==False:
            return growth(o,w)
        put(o,G_PHASE,10)
    if get(o,G_PHASE)==10:
        random=allocate(w,16)
        if random==0:
            return growth(o,w)
        put(o,G_RANDOM,random)
        put(o,G_RN,16)
        put(o,G_RUSED,0)
        put(o,G_PHASE,11)
        return 5
    if get(o,G_PHASE)==11:
        result=get(o,G_FEEDBACK)
        if result==MAX-3:
            return 5
        if result==0 or result>=18446744073709547521 or result>16-get(o,G_RUSED):
            return class_finish(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+result)
        if get(o,G_RUSED)!=16:
            return 5
        put(o,G_PHASE,20)
    if get(o,G_PHASE)==20:
        return records_execute(s,o,w)
    return class_finish(o,w,11)

def records_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    zero(o,256,448)
    zero(o,768,128)
    op=readword(s,8)
    put(o,G_OP,op)
    put(w,16,0)
    if op==47:
        put(o,G_N,get(w,88))
        return done(o,0)
    if op!=46:
        a=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
        if a==0:
            return done(o,1)
        put(o,G_A,a)
    if op==45:
        return records_typed_call(s,o,w)
    if op==41:
        b=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
        c=cap_lookup(w,readword(s,72),readword(s,80),readword(s,88))
        if b==0 or c==0:
            return done(o,1)
        put(o,G_B,b)
        put(o,G_C,c)
    if op==40 or op==42:
        kind=get(w,get(o,G_A)+8)
        if kind!=5 and kind!=11:
            return done(o,2)
        if op==42 and get(w,get(o,G_A)+16)!=12:
            return done(o,7)
    if op==43:
        if get(w,get(o,G_A)+8)!=12:
            return done(o,2)
        if readword(s,104)>=get(w,get(o,G_A)+16):
            return done(o,4)
    if get(w,112)>=4096:
        collect(w)
    put(w,112,get(w,112)+1)
    put(o,G_PHASE,1)
    return 10

def records_new(o:mutbuf,w:mutbuf,kind:u64,id:u64,source:u64,n:u64) -> u64:
    if n>1152921504606846975:
        put(w,16,MAX)
        return 0
    obj=object_new(w,kind)
    if obj==0:
        return 0
    data=allocate(w,choose(n==0,8,n*8))
    if data==0:
        object_unlink(w,obj)
        return 0
    put(w,obj+24,data)
    put(w,obj+16,n)
    put(w,obj+40,get(w,160+(id-1)*8))
    put(w,obj+48,id)
    put(w,obj+56,(obj^get(w,40))*11400714819323198485)
    i=0
    while i<n:
        child=0
        if id==29:
            child=get(o,G_A+i*8)
        else:
            child=get(w,source+i*8)
        put(w,data+i*8,child)
        i=i+1
    class_links(w,obj)
    return obj

def records_execute(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=get(o,G_OP)
    a=get(o,G_A)
    result=0
    fresh=False
    if op==40:
        if get(w,a+8)==11:
            result=a
        elif get(w,a+16)==0 and get(w,400)!=0:
            result=get(w,400)
        else:
            result=records_new(o,w,11,28,get(w,a+24),get(w,a+16))
            fresh=True
            if result!=0 and get(w,a+16)==0:
                put(w,400,result)
                edge_add(w,result)
    elif op==41:
        result=records_new(o,w,12,29,0,3)
        fresh=True
    elif op==42:
        result=records_new(o,w,12,30,get(w,a+24),12)
        fresh=True
    elif op==43:
        result=get(w,get(w,a+24)+readword(s,104)*8)
    elif op==46:
        result=get(w,160+(readword(s,104)-1)*8)
    if result==0:
        return growth(o,w)
    if publish_one(o,w,result)!=0:
        if fresh:
            object_release(w,result)
        return growth(o,w)
    return class_finish(o,w,0)

def records_typed_call(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    function=get(o,G_A)
    if get(w,function+8)!=4:
        return done(o,20)
    count=readword(s,136)
    if count==0 or count>16:
        return done(o,11)
    n=get(w,function+32)
    if n>128:
        return done(o,20)
    i=0
    found=False
    while i<count and found==False:
        row=144+i*320
        if readword(s,row+8)==n:
            k=0
            same=True
            while k<n:
                if byte(w,get(w,function+24)+k)!=byte(s,row+32+k):
                    same=False
                k=k+1
            if same:
                found=True
        if found==False:
            i=i+1
    if found==False:
        return done(o,20)
    arguments=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
    if arguments==0:
        return done(o,1)
    kind=get(w,arguments+8)
    if kind!=5 and kind!=11:
        return done(o,21)
    row=144+i*320
    argc=readword(s,row+16)
    result=readword(s,row+24)
    if argc>16 or result==0 or result>11:
        return done(o,11)
    if get(w,arguments+16)!=argc:
        return done(o,22)
    if length(o)<8344:
        put(o,G_REQUIRED,8344)
        return done(o,13)
    zero(o,8192,152)
    put(o,8192,5494747058311088456)
    put(o,8200,argc)
    put(o,8208,result)
    j=0
    while j<argc:
        typ=readword(s,row+160+j*8)
        if typ==0 or typ>11:
            return done(o,11)
        child=get(w,get(w,arguments+24)+j*8)
        value=records_scalar(o,w,child,typ)
        if get(o,P_ERROR)!=0:
            return done(o,get(o,P_ERROR))
        put(o,8216+j*8,value)
        j=j+1
    put(o,G_INDEX,i)
    put(o,G_N,argc)
    put(o,G_PLAN,152)
    put(o,G_REQUIRED,8344)
    return done(o,0)

def records_scalar(o:mutbuf,w:mutbuf,obj:u64,typ:u64) -> u64:
    kind=get(w,obj+8)
    if typ==1:
        if kind!=1:
            put(o,P_ERROR,22)
            return 0
        return get(w,obj+48)
    if kind!=2:
        put(o,P_ERROR,22)
        return 0
    data=get(w,obj+24)
    n=get(w,obj+32)
    negative=byte(w,data)==45
    bits=64
    if typ==2 or typ==3:
        bits=8
    elif typ==4 or typ==5:
        bits=16
    elif typ==6 or typ==7:
        bits=32
    signed=(typ&1)==0
    limit=18446744073709551615
    if signed:
        limit=(1<<(bits-1))-choose(negative,0,1)
    elif bits<64:
        limit=(1<<bits)-1
    if negative and signed==False:
        put(o,P_ERROR,22)
        return 0
    ten_q=records_div10(limit)
    ten_r=limit-ten_q*10
    value=0
    pos=choose(negative,1,0)
    while pos<n:
        digit=byte(w,data+pos)-48
        if value>ten_q or (value==ten_q and digit>ten_r):
            put(o,P_ERROR,22)
            return 0
        value=value*10+digit
        pos=pos+1
    if negative:
        return (18446744073709551615-value)+1
    return value

def records_div10(value:u64) -> u64:
    quotient=0
    remainder=0
    bit=64
    while bit>0:
        bit=bit-1
        remainder=(remainder<<1)|((value>>bit)&1)
        if remainder>=10:
            remainder=remainder-10
            quotient=quotient|(1<<bit)
    return quotient
'''

def source_program():
    return resolve('result_value_records', SOURCE + '\n' + CLASSES + '\n' + catalog_source() + '\n' + CORE)

def program():
    return document(source_program(), 'result_value_records')

if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/result_value_records.hepta'
    path.write_text(render_assembly(program()))
    print(path.name, path.stat().st_size, flush=True)
