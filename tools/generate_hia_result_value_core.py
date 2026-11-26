"""Mutable value operations over the HIA-owned arena; all capabilities validate first."""
from tools.generate_hia_result_value_common import ROOT,document,render_assembly,resolve,SOURCE as COMMON
SOURCE=r'''
def result_value_core(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,G_PHASE)
    if phase==90:
        arena_extend(w,0)
        put(w,40,get(o,G_TAG0))
        put(w,48,get(o,G_INPUT))
        si=0
        while si<3:
            p=object_new(w,choose(si==0,0,1))
            if p==0:
                return 4294967293
            bit=choose(si==2,1,0)
            put(w,p+48,bit)
            put(w,p+72,1)
            hash=11400714819323198485
            if si!=0:
                hash=(14695981039346656037^(48+bit))*1099511628211
            put(w,p+56,hash)
            put(w,128+si*8,p)
            si=si+1
        zero(o,256,448)
        return 0
    if phase==91:
        put(o,G_N,get(w,88))
        return 0
    if phase==92:
        arena_extend(w,get(o,P_OLD))
        put(o,G_PHASE,get(o,704))
        put(o,G_ALLOC_FAILED,0)
        return 10
    if phase==0:
        return prepare(s,o,w)
    if phase==6:
        return dictionary_conversion(o,w)
    if phase==4:
        work=allocate(w,8192)
        if work==0:
            return growth(o,w)
        put(o,G_WORK,work)
        put(o,G_PHASE,5)
        return role(o,5,3,1408,8,3,1440,32,1,work,8192)
    if phase==5:
        n=get(o,G_FEEDBACK)
        deallocate(w,get(o,G_WORK))
        put(o,G_WORK,0)
        if n==0 or n>32:
            return done(o,11)
        put(o,G_OUT_N,n)
        put(o,G_PHASE,10)
    if get(o,G_PHASE)==10:
        count=get(o,G_COUNT)
        if count==0:
            put(o,G_PHASE,20)
        else:
            if count>576460752303423487:
                return done(o,5)
            random=allocate(w,count*16)
            if random==0:
                return growth(o,w)
            put(o,G_RANDOM,random)
            put(o,G_RN,count*16)
            put(o,G_RUSED,0)
            put(o,G_PHASE,11)
            return 5
    if get(o,G_PHASE)==11:
        result=get(o,G_FEEDBACK)
        if result==MAX-3:
            return 5
        if result==0 or result>=18446744073709547521 or result>get(o,G_RN)-get(o,G_RUSED):
            return cleanup_done(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+result)
        if get(o,G_RUSED)!=get(o,G_RN):
            return 5
        put(o,G_PHASE,20)
    if get(o,G_PHASE)==20:
        result=execute(s,o,w)
        if result==1 or result==10 or result==4:
            return result
        return cleanup_done(o,w,get(o,P_ERROR))
    return done(o,11)
def input_string_count(s:readbuf,at:u64,n:u64) -> u64:
    i=0
    count=0
    while i<n:
        b=byte(s,at+i)
        size=1
        value=b
        if b>=194 and b<=223:
            size=2
            value=b&31
        elif b>=224 and b<=239:
            size=3
            value=b&15
        elif b>=240 and b<=244:
            size=4
            value=b&7
        elif b>=128:
            return MAX
        if size>n-i:
            return MAX
        j=1
        while j<size:
            c=byte(s,at+i+j)
            if c<128 or c>191:
                return MAX
            value=(value<<6)|(c&63)
            j=j+1
        if (size==2 and value<128) or (size==3 and value<2048) or (size==4 and (value<65536 or value>1114111)):
            return MAX
        count=count+1
        i=i+size
    return count
def input_integer_valid(s:readbuf,n:u64) -> bool:
    if n==0:
        return False
    i=0
    if byte(s,128)==45:
        if n==1:
            return False
        i=1
    if byte(s,128+i)==48:
        return i==0 and n==1
    if byte(s,128+i)<49 or byte(s,128+i)>57:
        return False
    while i<n:
        b=byte(s,128+i)
        if b<48 or b>57:
            return False
        i=i+1
    return True
def prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    zero(o,256,448)
    op=input_operation(s)
    put(o,G_OP,op)
    put(w,16,0)
    if get(w,112)>=4096:
        collect(w)
    put(w,112,get(w,112)+1)
    if op==25:
        env=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
        if env==0:
            return done(o,1)
        put(o,G_A,env)
        base=0
        basekind=readword(s,104)
        if basekind!=0:
            base=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
            if base==0:
                return done(o,1)
            if get(w,base+8)!=basekind:
                return done(o,2)
        put(o,G_B,base)
        name=cap_lookup(w,readword(s,72),readword(s,80),readword(s,88))
        if name==0:
            return done(o,1)
        if get(w,name+8)!=4:
            return done(o,2)
        name_status=native_name(w,name)
        if name_status!=0:
            return done(o,name_status)
        put(o,G_C,name)
        put(o,G_COUNT,1)
        put(o,G_PHASE,10)
        return 10
    if op==2 or op==3 or op==4 or op==21:
        put(o,G_COUNT,1)
        put(o,G_PHASE,10)
        if op==2:
            kind=readword(s,104)
            n=readword(s,96)
            if kind>7 or kind==5 or kind==6:
                return done(o,7)
            if (kind==0 or kind==1) and n!=0:
                return done(o,7)
            if kind==1 and readword(s,112)>1:
                return done(o,7)
            if kind!=1 and readword(s,112)!=0:
                return done(o,7)
            if kind==2 and input_integer_valid(s,n)==False:
                return done(o,8)
            if kind==4 and input_string_count(s,128,n)==MAX:
                return done(o,10)
            if kind==3:
                if n!=8:
                    return done(o,7)
                bits=readword(s,128)
                put(o,1408,bits)
                exponent=(bits>>52)&2047
                if exponent==2047:
                    if (bits&4503599627370495)!=0:
                        put(o,1440,5136718)
                        put(o,G_OUT_N,3)
                    elif bits>>63==0:
                        put(o,1440,8751735898823355977)
                        put(o,G_OUT_N,8)
                    else:
                        put(o,1440,8388357179923384621)
                        store(o,1448,121)
                        put(o,G_OUT_N,9)
                else:
                    put(o,G_PHASE,4)
        return 10
    if op==22:
        token=cap_lookup_node(w,readword(s,24),readword(s,32),readword(s,40))
        if token==0 or get(w,token+8)!=0:
            return done(o,1)
        put(o,G_RESULT,token)
        put(o,G_PHASE,20)
        return 10
    a=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
    if a==0:
        return done(o,1)
    put(o,G_A,a)
    object_kind_size(o,w,a)
    if op==26:
        if get(w,a+8)!=8:
            return done(o,2)
        if length(o)<8320:
            put(o,G_REQUIRED,8320)
            return done(o,13)
        put(o,G_COUNT,3)
    if op==5:
        put(o,G_RESULT,a)
        put(o,G_COUNT,1)
    elif op==8 or (op>=9 and op<=15) or op==24:
        b=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
        if b==0:
            return done(o,1)
        put(o,G_B,b)
        if op==10 or op==13 or op==14:
            c=cap_lookup(w,readword(s,72),readword(s,80),readword(s,88))
            if c==0:
                return done(o,1)
            put(o,G_C,c)
    elif op==16:
        b=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
        if b==0:
            return done(o,1)
        put(o,G_B,b)
    if op==24:
        if get(w,a+8)!=2 or get(w,get(o,G_B)+8)!=2:
            return done(o,2)
        put(o,G_COUNT,1)
    if op>=9 and op<=11:
        if get(w,a+8)!=6:
            return done(o,2)
        key=get(o,G_B)
        if get(w,key+8)==5 or get(w,key+8)==6:
            return done(o,2)
        found=dict_find(w,a,key)
        put(o,G_FOUND,found)
        if op==10 and found==MAX and get(w,key+8)!=4 and get(w,a+120)==0:
            put(o,G_PHASE,6)
            return 10
        if found==MAX and op!=10:
            return done(o,3)
        if op==9:
            put(o,G_RESULT,get(w,get(w,a+24)+found*32+8))
            put(o,G_COUNT,1)
    if op>=12 and op<=16:
        if get(w,a+8)!=5:
            return done(o,2)
        index=get(w,a+16)
        if op!=16:
            index=integer_index(w,get(o,G_B),get(w,a+16),op==14)
            if index==MAX:
                return done(o,4)
            if index==MAX-1:
                return done(o,2)
            if index==MAX-2:
                return done(o,choose(op==14,9,4))
        put(o,G_INDEX,index)
        if op==12:
            put(o,G_RESULT,get(w,get(w,a+24)+index*8))
            put(o,G_COUNT,1)
    if op==17:
        actual=native_base(w,a)
        kind=get(w,actual+8)
        if kind<4 or kind>7:
            return done(o,2)
    if op==19:
        actual=native_base(w,a)
        kind=get(w,actual+8)
        if kind==5 or kind==6 or kind>=8:
            return done(o,2)
        n=get(o,G_BYTES)
        offset=readword(s,104)
        count=readword(s,112)
        if offset>n or count>n-offset:
            return done(o,4)
        put(o,G_INDEX,offset)
        put(o,G_PLAN,count)
        if count>length(o)-8192:
            put(o,G_REQUIRED,count+8192)
            return done(o,13)
    if op==23:
        kind=get(w,a+8)
        if kind!=5 and kind!=6:
            return done(o,2)
        n=get(w,a+16)
        start=readword(s,104)
        count=readword(s,112)
        if start>=n:
            count=0
        elif count>n-start:
            count=n-start
        if count>288230376151711615:
            return done(o,5)
        put(o,G_INDEX,start)
        put(o,G_PLAN,count)
        put(o,G_REQUIRED,8192+count*64)
        if count>(length(o)-8192)//64:
            return done(o,13)
        put(o,G_COUNT,count*choose(kind==6,2,1))
    put(o,G_PHASE,10)
    return 10
def dictionary_conversion(o:mutbuf,w:mutbuf) -> u64:
    obj=get(o,G_A)
    if dict_general(w,obj)==False:
        return growth(o,w)
    put(o,G_FOUND,dict_find(w,obj,get(o,G_B)))
    put(o,G_PHASE,10)
    return 10
def cleanup_done(o:mutbuf,w:mutbuf,status:u64) -> u64:
    deallocate(w,get(o,G_RANDOM))
    put(o,G_RANDOM,0)
    deallocate(w,get(o,G_WORK))
    put(o,G_WORK,0)
    return done(o,status)
def scalar_create(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    kind=readword(s,104)
    if kind<=1:
        return get(w,128+choose(kind==0,0,1+readword(s,112))*8)
    if kind==3:
        return float_object(w,o,readword(s,128),1440,get(o,G_OUT_N))
    p=object_new(w,kind)
    if p==0:
        return 0
    n=readword(s,96)
    if n!=0:
        data=allocate(w,n)
        if data==0:
            object_unlink(w,p)
            return 0
        from_input(s,w,data,128,n)
        put(w,p+24,data)
        put(w,p+32,n)
    if kind==1:
        put(w,p+48,readword(s,112))
    if kind==4:
        put(w,p+16,string_count(w,get(w,p+24),n))
    if kind==7:
        put(w,p+16,n)
    hash=11400714819323198485
    if kind==1:
        hash=(14695981039346656037^(48+readword(s,112)))*1099511628211
    if kind==2 or kind==4 or kind==7:
        hash=bytes_hash(w,get(w,p+24),n)
        if kind==7:
            hash=hash^13787848793156543929
    put(w,p+56,hash)
    return p
def publish_one(o:mutbuf,w:mutbuf,obj:u64) -> u64:
    if cap_reserve(w,1)==False:
        return 1
    random=get(o,G_RANDOM)
    t0=get(w,random)
    t1=get(w,random+8)
    cap=cap_new_unpublished(w,obj,t0,t1)
    if cap==0:
        return 1
    cap_publish(w,cap)
    put(o,G_CAP,cap)
    put(o,G_TAG0,t0)
    put(o,G_TAG1,t1)
    if obj!=0:
        object_kind_size(o,w,obj)
    return 0
def execute(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=get(o,G_OP)
    a=get(o,G_A)
    if op==25:
        obj=native_create(s,o,w)
        if obj==0:
            return growth(o,w)
        if publish_one(o,w,obj)!=0:
            object_release(w,obj)
            return growth(o,w)
        return done(o,0)
    if op==26:
        return native_inspect(o,w)
    if op==21:
        if publish_one(o,w,0)!=0:
            return growth(o,w)
        return done(o,0)
    if op==22:
        cap_drop(w,get(o,G_RESULT))
        if readword(s,0)==MAGIC2 and readword(s,8)==30:
            put(o,P_DROP_CONSUMED,1)
        return done(o,0)
    if op==2 or op==3 or op==4:
        obj=0
        if op==2:
            obj=scalar_create(s,o,w)
        else:
            obj=object_new(w,op+2)
        if obj==0:
            return growth(o,w)
        if publish_one(o,w,obj)!=0:
            object_release(w,obj)
            return growth(o,w)
        return done(o,0)
    if op==24:
        obj=integer_binary(w,a,get(o,G_B),readword(s,104))
        if obj==0:
            return growth(o,w)
        if publish_one(o,w,obj)!=0:
            object_release(w,obj)
            return growth(o,w)
        return done(o,0)
    if op==5 or op==9 or op==12:
        if publish_one(o,w,get(o,G_RESULT))!=0:
            return growth(o,w)
        return done(o,0)
    if op==6:
        cap_drop(w,readword(s,24))
        if readword(s,0)==MAGIC2 and readword(s,8)==29:
            put(o,P_DROP_CONSUMED,1)
        put(o,G_ID0,0)
        put(o,G_ID1,0)
        return done(o,0)
    if op==7 or op==17:
        return done(o,0)
    if op==8:
        put(o,G_KIND,1)
        put(o,G_N,choose(a==get(o,G_B),1,0))
        return done(o,0)
    if op==10 or op==11:
        return mutate_dict(o,w)
    if op>=13 and op<=16:
        return mutate_list(o,w)
    if op==19:
        a=native_base(w,a)
        at=get(w,a+24)
        kind=get(w,a+8)
        if kind==1 or kind==3:
            at=a+48
        to_output(w,o,8192,at+get(o,G_INDEX),get(o,G_PLAN))
        return done(o,0)
    if op==23:
        return enumerate_values(o,w)
    return done(o,7)
def native_name(w:mutbuf,name:u64) -> u64:
    data=get(w,name+24)
    n=get(w,name+32)
    i=0
    null=False
    while i<n:
        value=byte(w,data+i)
        if value==237 and i+1<n and byte(w,data+i+1)>=160:
            return 10
        if value==0:
            null=True
        i=i+1
    return choose(null,8,0)
def native_create(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    obj=object_new(w,8)
    if obj==0:
        return 0
    data=allocate(w,64)
    if data==0:
        object_unlink(w,obj)
        return 0
    zero(w,data,64)
    put(w,obj+24,data)
    put(w,data,readword(s,112))
    basekind=readword(s,104)
    put(w,data+8,basekind)
    env=get(o,G_A)
    base=get(o,G_B)
    name=get(o,G_C)
    put(w,data+16,env)
    put(w,data+24,base)
    put(w,data+32,name)
    edge_add(w,env)
    if base!=0:
        edge_add(w,base)
        put(w,obj+16,get(w,base+16))
        put(w,obj+32,get(w,base+32))
        put(w,obj+56,get(w,base+56))
    else:
        put(w,obj+56,(obj^get(w,get(o,G_RANDOM)))*11400714819323198485)
    edge_add(w,name)
    return obj
def native_inspect(o:mutbuf,w:mutbuf) -> u64:
    if cap_reserve(w,3)==False:
        return growth(o,w)
    obj=get(o,G_A)
    data=get(w,obj+24)
    zero(o,8192,128)
    put(o,8192,NATIVE_INFO)
    put(o,8200,get(w,data+8))
    put(o,8208,get(w,data))
    head=0
    i=0
    while i<3:
        child=get(w,data+16+i*8)
        if i==2 and get(w,data+40)!=0:
            child=get(w,get(w,get(w,data+40)+24))
        if child==0:
            child=get(w,128)
        cap=enum_cap(o,w,child,i,head,8224+i*24)
        if cap==0:
            enum_rollback(w,head)
            return growth(o,w)
        head=cap
        i=i+1
    while head!=0:
        next=get(w,head+72)
        cap_publish(w,head)
        head=next
    return done(o,0)

def integer_binary(w:mutbuf,a:u64,b:u64,subtract:u64) -> u64:
    ap=get(w,a+24)
    bp=get(w,b+24)
    an=get(w,a+32)
    bn=get(w,b+32)
    asign=choose(byte(w,ap)==45,1,0)
    bsign=choose(byte(w,bp)==45,1,0)
    ap=ap+asign
    bp=bp+bsign
    an=an-asign
    bn=bn-bsign
    bsign=bsign^subtract
    n=choose(an>bn,an,bn)
    obj=object_new(w,2)
    if obj==0:
        return 0
    data=allocate(w,n+2)
    if data==0:
        object_unlink(w,obj)
        return 0
    put(w,obj+24,data)
    sign=asign
    addition=asign==bsign
    if addition==False:
        comparison=0
        if an>bn:
            comparison=1
        elif an<bn:
            comparison=2
        else:
            i=0
            while i<an and comparison==0:
                av=byte(w,ap+i)
                bv=byte(w,bp+i)
                if av>bv:
                    comparison=1
                elif av<bv:
                    comparison=2
                i=i+1
        if comparison==2:
            p=ap
            ap=bp
            bp=p
            size=an
            an=bn
            bn=size
            sign=bsign
    at=data+n+2
    i=0
    carry=0
    while i<n:
        av=0
        bv=0
        if i<an:
            av=byte(w,ap+an-i-1)-48
        if i<bn:
            bv=byte(w,bp+bn-i-1)-48
        digit=0
        if addition:
            value=av+bv+carry
            digit=value%10
            carry=value//10
        elif av<bv+carry:
            digit=av+10-bv-carry
            carry=1
        else:
            digit=av-bv-carry
            carry=0
        at=at-1
        store(w,at,48+digit)
        i=i+1
    if addition and carry!=0:
        at=at-1
        store(w,at,48+carry)
    end=data+n+2
    while at<end-1 and byte(w,at)==48:
        at=at+1
    if at==end-1 and byte(w,at)==48:
        sign=0
    if sign!=0:
        at=at-1
        store(w,at,45)
    count=end-at
    copy(w,data,at,count)
    put(w,obj+32,count)
    put(w,obj+56,bytes_hash(w,data,count))
    return obj
def mutate_dict(o:mutbuf,w:mutbuf) -> u64:
    obj=get(o,G_A)
    key=get(o,G_B)
    found=get(o,G_FOUND)
    op=get(o,G_OP)
    if op==10:
        value=get(o,G_C)
        if found==MAX:
            if dict_reserve(w,obj)==False:
                return growth(o,w)
            dict_insert(w,obj,key,value)
        else:
            at=get(w,obj+24)+found*32+8
            previous=get(w,at)
            edge_add(w,value)
            put(w,at,value)
            edge_drop(w,previous)
    else:
        at=get(w,obj+24)+found*32
        oldkey=get(w,at)
        previous=get(w,at+8)
        put(w,at,0)
        put(w,obj+16,get(w,obj+16)-1)
        dict_rehash(w,obj)
        edge_drop(w,oldkey)
        edge_drop(w,previous)
    object_kind_size(o,w,obj)
    return done(o,0)
def mutate_list(o:mutbuf,w:mutbuf) -> u64:
    obj=get(o,G_A)
    op=get(o,G_OP)
    index=get(o,G_INDEX)
    n=get(w,obj+16)
    if op==14 or op==16:
        if list_reserve(w,obj)==False:
            return growth(o,w)
    data=get(w,obj+24)
    value=get(o,G_C)
    if op==16:
        value=get(o,G_B)
    if op==13:
        previous=get(w,data+index*8)
        edge_add(w,value)
        put(w,data+index*8,value)
        edge_drop(w,previous)
    elif op==14 or op==16:
        copy(w,data+(index+1)*8,data+index*8,(n-index)*8)
        put(w,data+index*8,value)
        put(w,obj+16,n+1)
        edge_add(w,value)
    else:
        previous=get(w,data+index*8)
        copy(w,data+index*8,data+(index+1)*8,(n-index-1)*8)
        put(w,obj+16,n-1)
        edge_drop(w,previous)
        remaining=n-1
        if remaining==0:
            deallocate(w,data)
            put(w,obj+24,0)
            put(w,obj+40,0)
        elif remaining<get(w,obj+40)//4:
            capacity=get(w,obj+40)
            while capacity>8 and remaining<capacity//4:
                capacity=capacity//2
            shrink_allocation(w,data,capacity*8)
            put(w,obj+40,capacity)
    object_kind_size(o,w,obj)
    return done(o,0)
def enum_rollback(w:mutbuf,head:u64) -> u64:
    while head!=0:
        next=get(w,head+72)
        deallocate(w,head)
        head=next
    return 0
def enum_cap(o:mutbuf,w:mutbuf,obj:u64,rindex:u64,head:u64,out:u64) -> u64:
    random=get(o,G_RANDOM)+rindex*16
    t0=get(w,random)
    t1=get(w,random+8)
    cap=cap_new_unpublished(w,obj,t0,t1)
    if cap==0:
        return 0
    put(w,cap+72,head)
    put(o,out,cap)
    put(o,out+8,t0)
    put(o,out+16,t1)
    return cap
def enumerate_values(o:mutbuf,w:mutbuf) -> u64:
    count=get(o,G_PLAN)
    if count==0:
        return done(o,0)
    if cap_reserve(w,get(o,G_COUNT))==False:
        return growth(o,w)
    obj=get(o,G_A)
    kind=get(w,obj+8)
    data=get(w,obj+24)
    start=get(o,G_INDEX)
    index=0
    logical=0
    if kind==6:
        while logical<start:
            if get(w,data+index*32)!=0:
                logical=logical+1
            index=index+1
    else:
        index=start
    i=0
    head=0
    rindex=0
    while i<count:
        out=8192+i*64
        zero(o,out,64)
        put(o,out,start+i)
        value=0
        if kind==6:
            while get(w,data+index*32)==0:
                index=index+1
            key=get(w,data+index*32)
            value=get(w,data+index*32+8)
            new=enum_cap(o,w,key,rindex,head,out+16)
            if new==0:
                enum_rollback(w,head)
                return growth(o,w)
            head=new
            rindex=rindex+1
        else:
            value=get(w,data+index*8)
        new=enum_cap(o,w,value,rindex,head,out+40)
        if new==0:
            enum_rollback(w,head)
            return growth(o,w)
        head=new
        rindex=rindex+1
        put(o,out+8,get(w,value+8))
        i=i+1
        index=index+1
    while head!=0:
        next=get(w,head+72)
        cap_publish(w,head)
        head=next
    return done(o,0)
'''
def source_program():return resolve('result_value_core',SOURCE)
def program():return document(source_program(),'result_value_core')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/result_value_core.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)

