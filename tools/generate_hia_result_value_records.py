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
    if get(o,1800)!=0:
        return records_import_step(o,w)
    phase=get(o,G_PHASE)
    if phase==0:
        return records_prepare(s,o,w)
    if phase==30:
        return records_asdict_prepare(o,w)
    if phase==1:
        if class_catalog(w)==False:
            return records_growth(o,w)
        put(o,G_PHASE,10)
    if get(o,G_PHASE)==10:
        random=allocate(w,16)
        if random==0:
            return records_growth(o,w)
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
            return records_finish(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+result)
        if get(o,G_RUSED)!=16:
            return 5
        put(o,G_PHASE,20)
    if get(o,G_PHASE)==20:
        return records_execute(s,o,w)
    return records_finish(o,w,11)

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
    if op==44:
        a=get(o,G_A)
        if get(w,a+8)!=12 or get(w,a+48)!=30:
            return done(o,2)
        if records_asdict_valid(w,a)==False:
            return done(o,2)
        put(o,1808,a)
        put(o,G_PHASE,30)
        return 10
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
    if op==44:
        return records_as_dict(o,w)
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
        return records_growth(o,w)
    if publish_one(o,w,result)!=0:
        if fresh:
            object_release(w,result)
        return records_growth(o,w)
    return records_finish(o,w,0)

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

def records_finish(o:mutbuf,w:mutbuf,status:u64) -> u64:
    if get(o,1832)!=0:
        cap_drop(w,get(o,1832))
        put(o,1832,0)
    deallocate(w,get(o,1816))
    put(o,1816,0)
    put(o,1800,0)
    return class_finish(o,w,status)

def records_growth(o:mutbuf,w:mutbuf) -> u64:
    action=growth(o,w)
    if action==0:
        return records_finish(o,w,get(o,P_ERROR))
    return action

def records_truth(w:mutbuf,obj:u64) -> bool:
    obj=native_base(w,obj)
    kind=get(w,obj+8)
    if kind==0:
        return False
    if kind==1:
        return get(w,obj+48)!=0
    if kind==2:
        return get(w,obj+32)!=1 or byte(w,get(w,obj+24))!=48
    if kind==3:
        return (get(w,obj+48)&9223372036854775807)!=0
    if kind==4 or kind==5 or kind==6 or kind==7 or kind==11:
        return get(w,obj+16)!=0
    return True

def records_asdict_prepare(o:mutbuf,w:mutbuf) -> u64:
    obj=get(o,1808)
    value=get(w,get(w,obj+24)+88)
    if records_truth(w,value)==False:
        put(o,1840,get(w,128))
        put(o,G_PHASE,10)
        return 10
    value=native_base(w,value)
    kind=get(w,value+8)
    if kind!=4 and kind!=7:
        return records_finish(o,w,2)
    n=get(w,value+32)
    if n>MAX-128:
        return records_finish(o,w,5)
    buf=allocate(w,n+128)
    if buf==0:
        return records_growth(o,w)
    zero(w,buf,128)
    put(w,buf,MAGIC)
    put(w,buf+8,1)
    put(w,buf+96,n)
    copy(w,buf+128,get(w,value+24),n)
    put(o,1816,buf)
    put(o,1824,n+128)
    put(o,G_PHASE,0)
    return records_import_call(o,w)

def records_import_call(o:mutbuf,w:mutbuf) -> u64:
    put(o,1800,1)
    return role(o,2,1,get(o,1816),get(o,1824),3,0,length(o),1,0,length(w))

def records_import_step(o:mutbuf,w:mutbuf) -> u64:
    if get(o,1800)==2:
        return records_import_call(o,w)
    action=get(o,G_FEEDBACK)
    if action==0:
        status=get(o,P_ERROR)
        if status!=0:
            return records_finish(o,w,status)
        cap=get(o,G_CAP)
        if cap==0:
            return records_finish(o,w,11)
        put(o,1832,cap)
        put(o,1840,get(w,cap+8))
        deallocate(w,get(o,1816))
        put(o,1816,0)
        put(o,1800,0)
        zero(o,256,448)
        put(o,G_OP,44)
        put(o,G_A,get(o,1808))
        put(o,G_PHASE,10)
        return 10
    if action==10:
        return records_import_call(o,w)
    if action==4:
        # The enclosing owner reuses its call tuple when reentering this role.
        # The nested import preserves its own pending tuple before that reuse.
        copy(o,192,1856,64)
        # Nested import sees its captured JSON request inside the arena.
        # Its private input selectors must address that captured region.
        select=get(o,P_SELECT)
        i=0
        while i<6:
            shift=i*3
            if ((select>>shift)&7)==2:
                select=(select&(MAX^(7<<shift)))|(1<<shift)
                put(o,P_ARG+i*8,get(o,P_ARG+i*8)+get(o,1816))
            i=i+1
        put(o,P_SELECT,select)
        put(o,1800,2)
        return 4
    if action==1 or action==5:
        put(o,1800,2)
        return action
    return records_finish(o,w,11)

def records_text(w:mutbuf,index:u64) -> u64:
    obj=object_new(w,4)
    if obj==0:
        return 0
    data=allocate(w,32)
    if data==0:
        object_unlink(w,obj)
        return 0
    put(w,obj+24,data)
    n=records_name(w,data,index)
    put(w,obj+16,n)
    put(w,obj+32,n)
    put(w,obj+56,bytes_hash(w,data,n))
    return obj

def records_map_field(w:mutbuf,obj:u64,index:u64,value:u64) -> bool:
    key=records_text(w,index)
    if key==0:
        return False
    if dict_reserve(w,obj)==False:
        object_release(w,key)
        return False
    dict_insert(w,obj,key,value)
    return True

def records_list_append(w:mutbuf,obj:u64,value:u64) -> bool:
    if list_reserve(w,obj)==False:
        return False
    n=get(w,obj+16)
    put(w,get(w,obj+24)+n*8,value)
    put(w,obj+16,n+1)
    edge_add(w,value)
    return True

def records_parameter_list(w:mutbuf,source:u64) -> u64:
    source=native_base(w,source)
    kind=get(w,source+8)
    if kind==5 or kind==11:
        return class_clone_list(w,get(w,source+24),0,get(w,source+16))
    obj=object_new(w,5)
    if obj==0:
        return 0
    data=get(w,source+24)
    if kind==6:
        i=0
        while i<get(w,source+112):
            key=get(w,data+i*32)
            if key!=0:
                if records_list_append(w,obj,key)==False:
                    object_release(w,obj)
                    return 0
            i=i+1
        return obj
    if kind==4:
        i=0
        while i<get(w,source+32):
            b=byte(w,data+i)
            n=1
            if b>=240:
                n=4
            elif b>=224:
                n=3
            elif b>=192:
                n=2
            child=object_scalar(w,4,data+i,n,0)
            if child==0:
                object_release(w,obj)
                return 0
            if records_list_append(w,obj,child)==False:
                object_release(w,child)
                object_release(w,obj)
                return 0
            i=i+n
        return obj
    if kind==7:
        i=0
        while i<get(w,source+16):
            v=byte(w,data+i)
            child=object_new(w,2)
            if child==0:
                object_release(w,obj)
                return 0
            text=allocate(w,3)
            if text==0:
                object_unlink(w,child)
                object_release(w,obj)
                return 0
            put(w,child+24,text)
            n=1
            if v>=100:
                n=3
                store(w,text,48+v//100)
                store(w,text+1,48+(v//10)%10)
            elif v>=10:
                n=2
                store(w,text,48+v//10)
            store(w,text+n-1,48+v%10)
            put(w,child+32,n)
            put(w,child+56,bytes_hash(w,text,n))
            if records_list_append(w,obj,child)==False:
                object_release(w,child)
                object_release(w,obj)
                return 0
            i=i+1
        return obj
    object_release(w,obj)
    return 0

def records_abi_list(w:mutbuf,abi:u64) -> u64:
    obj=object_new(w,5)
    if obj==0:
        return 0
    i=0
    while i<get(w,abi+16):
        original=get(w,get(w,abi+24)+i*8)
        fields=get(w,original+24)
        row=object_new(w,6)
        if row==0:
            object_release(w,obj)
            return 0
        if records_map_field(w,row,12,get(w,fields))==False:
            object_release(w,row)
            object_release(w,obj)
            return 0
        parameters=records_parameter_list(w,get(w,fields+8))
        if parameters==0:
            object_release(w,row)
            object_release(w,obj)
            return 0
        if records_map_field(w,row,13,parameters)==False:
            object_release(w,parameters)
            object_release(w,row)
            object_release(w,obj)
            return 0
        if records_map_field(w,row,14,get(w,fields+16))==False:
            object_release(w,row)
            object_release(w,obj)
            return 0
        if records_list_append(w,obj,row)==False:
            object_release(w,row)
            object_release(w,obj)
            return 0
        i=i+1
    return obj

def records_asdict_valid(w:mutbuf,obj:u64) -> bool:
    abi=get(w,get(w,obj+24)+40)
    kind=get(w,abi+8)
    if kind!=5 and kind!=11:
        return False
    i=0
    while i<get(w,abi+16):
        row=get(w,get(w,abi+24)+i*8)
        if get(w,row+8)!=12 or get(w,row+48)!=29:
            return False
        parameters=native_base(w,get(w,get(w,row+24)+8))
        kind=get(w,parameters+8)
        if kind!=4 and kind!=5 and kind!=6 and kind!=7 and kind!=11:
            return False
        i=i+1
    return True

def records_as_dict(o:mutbuf,w:mutbuf) -> u64:
    original=get(o,1808)
    fields=get(w,original+24)
    abi=get(w,fields+40)
    kind=get(w,abi+8)
    if kind!=5 and kind!=11:
        return records_finish(o,w,2)
    i=0
    while i<get(w,abi+16):
        row=get(w,get(w,abi+24)+i*8)
        if get(w,row+8)!=12 or get(w,row+48)!=29:
            return records_finish(o,w,2)
        parameters=native_base(w,get(w,get(w,row+24)+8))
        kind=get(w,parameters+8)
        if kind!=4 and kind!=5 and kind!=6 and kind!=7 and kind!=11:
            return records_finish(o,w,2)
        i=i+1
    obj=object_new(w,6)
    if obj==0:
        return records_growth(o,w)
    i=0
    while i<12:
        value=get(w,fields+i*8)
        if i==5:
            value=records_abi_list(w,abi)
            if value==0:
                object_release(w,obj)
                return records_growth(o,w)
        if i==11:
            value=get(o,1840)
        if records_map_field(w,obj,i,value)==False:
            object_release(w,value)
            object_release(w,obj)
            return records_growth(o,w)
        i=i+1
    if publish_one(o,w,obj)!=0:
        object_release(w,obj)
        return records_growth(o,w)
    return records_finish(o,w,0)

def records_name(w:mutbuf,data:u64,index:u64) -> u64:
    if index==0:
        store(w,data+0,103)
        store(w,data+1,101)
        store(w,data+2,110)
        store(w,data+3,101)
        store(w,data+4,114)
        store(w,data+5,97)
        store(w,data+6,116)
        store(w,data+7,105)
        store(w,data+8,111)
        store(w,data+9,110)
        return 10
    if index==1:
        store(w,data+0,112)
        store(w,data+1,114)
        store(w,data+2,111)
        store(w,data+3,103)
        store(w,data+4,114)
        store(w,data+5,97)
        store(w,data+6,109)
        store(w,data+7,95)
        store(w,data+8,115)
        store(w,data+9,104)
        store(w,data+10,97)
        store(w,data+11,50)
        store(w,data+12,53)
        store(w,data+13,54)
        return 14
    if index==2:
        store(w,data+0,105)
        store(w,data+1,110)
        store(w,data+2,112)
        store(w,data+3,117)
        store(w,data+4,116)
        store(w,data+5,95)
        store(w,data+6,115)
        store(w,data+7,104)
        store(w,data+8,97)
        store(w,data+9,50)
        store(w,data+10,53)
        store(w,data+11,54)
        return 12
    if index==3:
        store(w,data+0,97)
        store(w,data+1,114)
        store(w,data+2,116)
        store(w,data+3,105)
        store(w,data+4,102)
        store(w,data+5,97)
        store(w,data+6,99)
        store(w,data+7,116)
        store(w,data+8,95)
        store(w,data+9,115)
        store(w,data+10,104)
        store(w,data+11,97)
        store(w,data+12,50)
        store(w,data+13,53)
        store(w,data+14,54)
        return 15
    if index==4:
        store(w,data+0,97)
        store(w,data+1,114)
        store(w,data+2,116)
        store(w,data+3,105)
        store(w,data+4,102)
        store(w,data+5,97)
        store(w,data+6,99)
        store(w,data+7,116)
        store(w,data+8,95)
        store(w,data+9,98)
        store(w,data+10,121)
        store(w,data+11,116)
        store(w,data+12,101)
        store(w,data+13,115)
        return 14
    if index==5:
        store(w,data+0,97)
        store(w,data+1,98)
        store(w,data+2,105)
        return 3
    if index==6:
        store(w,data+0,116)
        store(w,data+1,114)
        store(w,data+2,97)
        store(w,data+3,110)
        store(w,data+4,115)
        store(w,data+5,108)
        store(w,data+6,97)
        store(w,data+7,116)
        store(w,data+8,105)
        store(w,data+9,111)
        store(w,data+10,110)
        store(w,data+11,95)
        store(w,data+12,112)
        store(w,data+13,114)
        store(w,data+14,111)
        store(w,data+15,111)
        store(w,data+16,102)
        store(w,data+17,115)
        return 18
    if index==7:
        store(w,data+0,110)
        store(w,data+1,97)
        store(w,data+2,116)
        store(w,data+3,105)
        store(w,data+4,118)
        store(w,data+5,101)
        store(w,data+6,95)
        store(w,data+7,112)
        store(w,data+8,114)
        store(w,data+9,111)
        store(w,data+10,98)
        store(w,data+11,101)
        store(w,data+12,95)
        store(w,data+13,99)
        store(w,data+14,97)
        store(w,data+15,108)
        store(w,data+16,108)
        store(w,data+17,115)
        return 18
    if index==8:
        store(w,data+0,98)
        store(w,data+1,97)
        store(w,data+2,115)
        store(w,data+3,101)
        store(w,data+4,108)
        store(w,data+5,105)
        store(w,data+6,110)
        store(w,data+7,101)
        return 8
    if index==9:
        store(w,data+0,97)
        store(w,data+1,100)
        store(w,data+2,109)
        store(w,data+3,105)
        store(w,data+4,115)
        store(w,data+5,115)
        store(w,data+6,105)
        store(w,data+7,111)
        store(w,data+8,110)
        store(w,data+9,95)
        store(w,data+10,112)
        store(w,data+11,114)
        store(w,data+12,111)
        store(w,data+13,102)
        store(w,data+14,105)
        store(w,data+15,108)
        store(w,data+16,101)
        return 17
    if index==10:
        store(w,data+0,116)
        store(w,data+1,111)
        store(w,data+2,116)
        store(w,data+3,97)
        store(w,data+4,108)
        store(w,data+5,105)
        store(w,data+6,116)
        store(w,data+7,121)
        store(w,data+8,95)
        store(w,data+9,112)
        store(w,data+10,114)
        store(w,data+11,111)
        store(w,data+12,111)
        store(w,data+13,102)
        store(w,data+14,115)
        return 15
    if index==11:
        store(w,data+0,108)
        store(w,data+1,111)
        store(w,data+2,97)
        store(w,data+3,100)
        store(w,data+4,101)
        store(w,data+5,100)
        store(w,data+6,95)
        store(w,data+7,109)
        store(w,data+8,97)
        store(w,data+9,112)
        store(w,data+10,112)
        store(w,data+11,105)
        store(w,data+12,110)
        store(w,data+13,103)
        return 14
    if index==12:
        store(w,data+0,102)
        store(w,data+1,117)
        store(w,data+2,110)
        store(w,data+3,99)
        store(w,data+4,116)
        store(w,data+5,105)
        store(w,data+6,111)
        store(w,data+7,110)
        return 8
    if index==13:
        store(w,data+0,112)
        store(w,data+1,97)
        store(w,data+2,114)
        store(w,data+3,97)
        store(w,data+4,109)
        store(w,data+5,101)
        store(w,data+6,116)
        store(w,data+7,101)
        store(w,data+8,114)
        store(w,data+9,115)
        return 10
    if index==14:
        store(w,data+0,114)
        store(w,data+1,101)
        store(w,data+2,115)
        store(w,data+3,117)
        store(w,data+4,108)
        store(w,data+5,116)
        return 6
    return 0

'''

def source_program():
    return resolve('result_value_records', SOURCE + '\n' + CLASSES + '\n' + catalog_source() + '\n' + CORE)

def program():
    return document(source_program(), 'result_value_records')

if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/result_value_records.hepta'
    path.write_text(render_assembly(program()))
    print(path.name, path.stat().st_size, flush=True)
