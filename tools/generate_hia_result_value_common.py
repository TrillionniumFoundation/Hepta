"""HIA-owned mutable values: offset capabilities, growable arena and graph ownership."""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
ROOT=Path(__file__).resolve().parents[1]
C={'MAX':18446744073709551615,'ARENA':int.from_bytes(b'HIABVA01','little'),'BLOCK_FREE':int.from_bytes(b'HIAVFREE','little'),'BLOCK_USED':int.from_bytes(b'HIAVUSED','little'),'OBJECT':int.from_bytes(b'HIAVOBJ1','little'),'CAP_MAGIC':int.from_bytes(b'HIAVCAP1','little'),'REPLY':int.from_bytes(b'HIABVR01','little'),'MAGIC':int.from_bytes(b'HIABVQ01','little'),'STATE':int.from_bytes(b'HIABVC01','little'),'P_PHASE':128,'P_FEEDBACK':136,'P_PID':144,'P_HELD':152,'P_ERROR':160,'P_ARENA':168,'P_AN':176,'P_OLD':184,'P_ROLE':192,'P_SELECT':200,'P_ARG':208,'G_PHASE':256,'G_FEEDBACK':264,'G_RANDOM':272,'G_RN':280,'G_RUSED':288,'G_WANT':296,'G_PLAN':304,'G_A':312,'G_B':320,'G_C':328,'G_RESULT':336,'G_CAP':344,'G_KIND':352,'G_N':360,'G_BYTES':368,'G_INDEX':376,'G_FOUND':384,'G_COUNT':392,'G_REQUIRED':400,'G_DATA':408,'G_NEWOBJ':416,'G_TEMP':424,'G_ITER':432,'G_OP':440,'G_TAG0':448,'G_TAG1':456,'G_ID0':464,'G_ID1':472,'G_ALLOC_FAILED':480,'G_RETRY':488,'G_INPUT':496,'G_INPUT_N':504,'G_STACK':520,'G_AUX':528,'G_AUX_N':536,'G_ARENA':544,'G_ARENA_N':552,'G_PARSEW':560,'G_PARSEWN':568,'G_ROOT':576,'G_MODE':584,'G_WORK':592,'G_WORK_N':600,'G_OUT':608,'G_OUT_N':616,'G_PARSE_NODES':624,'G_PARSE_DEPTH':632,'G_PARSE_KEYS':640}
SOURCE=r'''
def shrink_allocation(w:mutbuf,p:u64,n:u64) -> u64:
    at=p-32
    old=get(w,at+8)
    k=size_class(n+32)
    if k>=old:
        return 0
    while old>k:
        old=old-1
        free_insert(w,at+(1<<old),old)
    put(w,at+8,k)
    return 0

def float_integer_key(w:mutbuf,data:u64,bits:u64) -> u64:
    magnitude=bits&9223372036854775807
    exponent=(magnitude>>52)&2047
    mantissa=magnitude&4503599627370495
    if magnitude==0:
        store(w,data+32,48)
        return 1
    if exponent<1023 or exponent==2047:
        return 0
    mantissa=mantissa|4503599627370496
    shift=0
    if exponent<1075:
        cut=1075-exponent
        if (mantissa&((1<<cut)-1))!=0:
            return 0
        mantissa=mantissa>>cut
    else:
        shift=exponent-1075
    n=0
    while mantissa!=0:
        store(w,data+32+n,mantissa%10)
        mantissa=mantissa//10
        n=n+1
    j=0
    while j<shift:
        i=0
        carry=0
        while i<n:
            value=byte(w,data+32+i)*2+carry
            store(w,data+32+i,value%10)
            carry=value//10
            i=i+1
        if carry!=0:
            store(w,data+32+n,carry)
            n=n+1
        j=j+1
    i=0
    while i<n//2:
        value=byte(w,data+32+i)
        store(w,data+32+i,byte(w,data+32+n-i-1))
        store(w,data+32+n-i-1,value)
        i=i+1
    negative=bits>>63
    if negative!=0:
        copy(w,data+33,data+32,n)
        store(w,data+32,45)
    i=0
    while i<n:
        store(w,data+32+negative+i,byte(w,data+32+negative+i)+48)
        i=i+1
    return n+negative
def float_object(w:mutbuf,o:mutbuf,bits:u64,lex:u64,n:u64) -> u64:
    p=object_new(w,3)
    if p==0:
        return 0
    data=allocate(w,384)
    if data==0:
        object_unlink(w,p)
        return 0
    from_output(o,w,data,lex,n)
    put(w,p+24,data)
    put(w,p+32,n)
    put(w,p+48,bits)
    keyn=float_integer_key(w,data,bits)
    put(w,p+120,keyn)
    hash=bits
    if keyn!=0:
        hash=bytes_hash(w,data+32,keyn)
    put(w,p+56,hash)
    return p
def numeric_kind(kind:u64) -> bool:
    return kind==1 or kind==2 or kind==3
def numeric_key_n(w:mutbuf,p:u64) -> u64:
    kind=get(w,p+8)
    if kind==1:
        return 1
    if kind==2:
        return get(w,p+32)
    return get(w,p+120)
def numeric_key_byte(w:mutbuf,p:u64,index:u64) -> u64:
    kind=get(w,p+8)
    if kind==1:
        return 48+get(w,p+48)
    if kind==2:
        return byte(w,get(w,p+24)+index)
    return byte(w,get(w,p+24)+32+index)

def get(w:mutbuf,at:u64) -> u64:
    v=0
    i=0
    while i<8:
        v=v|(byte(w,at+i)<<(i*8))
        i=i+1
    return v
def readword(s:readbuf,at:u64) -> u64:
    v=0
    i=0
    while i<8:
        v=v|(byte(s,at+i)<<(i*8))
        i=i+1
    return v
def put(w:mutbuf,at:u64,v:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(v>>(i*8))&255)
        i=i+1
    return 0
def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0
def copy(w:mutbuf,target:u64,source:u64,n:u64) -> u64:
    if target>source and target-source<n:
        i=n
        while i!=0:
            i=i-1
            store(w,target+i,byte(w,source+i))
        return 0
    i=0
    while i<n:
        store(w,target+i,byte(w,source+i))
        i=i+1
    return 0
def from_input(s:readbuf,w:mutbuf,target:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,target+i,byte(s,at+i))
        i=i+1
    return 0
def from_output(o:mutbuf,w:mutbuf,target:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,target+i,byte(o,at+i))
        i=i+1
    return 0
def to_output(w:mutbuf,o:mutbuf,target:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,target+i,byte(w,at+i))
        i=i+1
    return 0
def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
def size_class(size:u64) -> u64:
    k=6
    v=64
    while v<size and k<63:
        v=v*2
        k=k+1
    return k
def free_remove(w:mutbuf,at:u64,k:u64) -> u64:
    previous=get(w,at+24)
    next=get(w,at+16)
    if previous==0:
        put(w,512+k*8,next)
    else:
        put(w,previous+16,next)
    if next!=0:
        put(w,next+24,previous)
    return 0
def free_insert(w:mutbuf,at:u64,k:u64) -> u64:
    first=get(w,512+k*8)
    put(w,at,BLOCK_FREE)
    put(w,at+8,k)
    put(w,at+16,first)
    put(w,at+24,0)
    if first!=0:
        put(w,first+24,at)
    put(w,512+k*8,at)
    return 0
def arena_extend(w:mutbuf,old:u64) -> u64:
    if old==0:
        zero(w,0,4096)
        put(w,0,ARENA)
        old=4096
    at=old
    while at<length(w):
        k=size_class(at)
        free_insert(w,at,k)
        at=at*2
    put(w,8,length(w))
    put(w,16,0)
    return 0
def allocate(w:mutbuf,n:u64) -> u64:
    if n>9223372036854775776:
        put(w,16,MAX)
        return 0
    k=size_class(n+32)
    j=k
    while j<64 and get(w,512+j*8)==0:
        j=j+1
    if j==64:
        need=1<<k
        if need>get(w,16):
            put(w,16,need)
        return 0
    at=get(w,512+j*8)
    free_remove(w,at,j)
    while j>k:
        j=j-1
        free_insert(w,at+(1<<j),j)
    put(w,at,BLOCK_USED)
    put(w,at+8,k)
    put(w,at+16,0)
    put(w,at+24,0)
    return at+32
def deallocate(w:mutbuf,p:u64) -> u64:
    if p==0:
        return 0
    at=p-32
    k=get(w,at+8)
    while k<63:
        buddy=at^(1<<k)
        if buddy<4096 or buddy>=length(w) or get(w,buddy)!=BLOCK_FREE or get(w,buddy+8)!=k:
            free_insert(w,at,k)
            return 0
        free_remove(w,buddy,k)
        if buddy<at:
            at=buddy
        k=k+1
    free_insert(w,at,k)
    return 0
def object_new(w:mutbuf,kind:u64) -> u64:
    p=allocate(w,128)
    if p==0:
        return 0
    zero(w,p,128)
    put(w,p,OBJECT)
    put(w,p+8,kind)
    first=get(w,96)
    put(w,p+88,first)
    if first!=0:
        put(w,first+80,p)
    put(w,96,p)
    put(w,104,get(w,104)+1)
    return p
def object_unlink(w:mutbuf,p:u64) -> u64:
    previous=get(w,p+80)
    next=get(w,p+88)
    if previous!=0:
        put(w,previous+88,next)
    else:
        put(w,96,next)
    if next!=0:
        put(w,next+80,previous)
    put(w,104,get(w,104)-1)
    deallocate(w,get(w,p+24))
    deallocate(w,p)
    return 0
def edge_add(w:mutbuf,p:u64) -> u64:
    if get(w,p+8)<=1:
        return 0
    put(w,p+72,get(w,p+72)+1)
    return 0
def zero_queue(w:mutbuf,p:u64,head:u64) -> u64:
    if p!=0 and get(w,p+64)==0 and get(w,p+72)==0:
        put(w,p+104,head)
        return p
    return head
def object_release(w:mutbuf,p:u64) -> u64:
    head=zero_queue(w,p,0)
    while head!=0:
        p=head
        head=get(w,p+104)
        kind=get(w,p+8)
        n=get(w,p+16)
        data=get(w,p+24)
        if kind==5:
            i=0
            while i<n:
                child=get(w,data+i*8)
                if get(w,child+8)>1:
                    put(w,child+72,get(w,child+72)-1)
                    head=zero_queue(w,child,head)
                i=i+1
        if kind==6:
            i=0
            while i<get(w,p+112):
                key=get(w,data+i*32)
                if key!=0:
                    value=get(w,data+i*32+8)
                    if get(w,key+8)>1:
                        put(w,key+72,get(w,key+72)-1)
                        head=zero_queue(w,key,head)
                    if get(w,value+8)>1:
                        put(w,value+72,get(w,value+72)-1)
                        head=zero_queue(w,value,head)
                i=i+1
        object_unlink(w,p)
    return 0
def edge_drop(w:mutbuf,p:u64) -> u64:
    if get(w,p+8)<=1:
        return 0
    put(w,p+72,get(w,p+72)-1)
    return object_release(w,p)
def mark_add(w:mutbuf,p:u64,head:u64) -> u64:
    if p!=0 and get(w,p+96)==0:
        put(w,p+96,1)
        put(w,p+104,head)
        return p
    return head
def collect(w:mutbuf) -> u64:
    p=get(w,96)
    while p!=0:
        put(w,p+96,0)
        p=get(w,p+88)
    cap=get(w,80)
    head=0
    si=128
    while si<152:
        head=mark_add(w,get(w,si),head)
        si=si+8
    while cap!=0:
        head=mark_add(w,get(w,cap+8),head)
        cap=get(w,cap+56)
    while head!=0:
        p=head
        head=get(w,p+104)
        kind=get(w,p+8)
        data=get(w,p+24)
        i=0
        if kind==5:
            while i<get(w,p+16):
                head=mark_add(w,get(w,data+i*8),head)
                i=i+1
        if kind==6:
            while i<get(w,p+112):
                key=get(w,data+i*32)
                if key!=0:
                    head=mark_add(w,key,head)
                    head=mark_add(w,get(w,data+i*32+8),head)
                i=i+1
    p=get(w,96)
    while p!=0:
        next=get(w,p+88)
        if get(w,p+96)==0:
            kind=get(w,p+8)
            data=get(w,p+24)
            i=0
            n=0
            stride=8
            if kind==5:
                n=get(w,p+16)
            if kind==6:
                n=get(w,p+112)*2
                stride=16
            while i<n:
                child=0
                if kind==5:
                    child=get(w,data+i*8)
                else:
                    if get(w,data+(i//2)*32)!=0:
                        child=get(w,data+(i//2)*32+(i%2)*8)
                if child!=0 and get(w,child+96)!=0 and get(w,child+8)>1:
                    put(w,child+72,get(w,child+72)-1)
                i=i+1
        p=next
    p=get(w,96)
    while p!=0:
        next=get(w,p+88)
        if get(w,p+96)==0:
            object_unlink(w,p)
        p=next
    put(w,112,0)
    return 0
def cap_bucket(p:u64,n:u64) -> u64:
    return (((p>>6)*11400714819323198485)^((p>>17)*13787848793156543929))&(n-1)
def cap_reserve(w:mutbuf,additional:u64) -> bool:
    n=get(w,72)
    if additional>MAX-get(w,88):
        put(w,16,MAX)
        return False
    wanted=get(w,88)+additional
    size=choose(n==0,128,n)
    while wanted>size and size<1152921504606846976:
        size=size*2
    if wanted>size:
        put(w,16,MAX)
        return False
    if size==n:
        return True
    table=allocate(w,size*8)
    if table==0:
        return False
    zero(w,table,size*8)
    p=get(w,80)
    while p!=0:
        bucket=table+cap_bucket(p,size)*8
        put(w,p+32,get(w,bucket))
        put(w,bucket,p)
        p=get(w,p+56)
    deallocate(w,get(w,64))
    put(w,64,table)
    put(w,72,size)
    return True
def cap_lookup_node(w:mutbuf,p:u64,t0:u64,t1:u64) -> u64:
    n=get(w,72)
    if p==0 or n==0:
        return 0
    current=get(w,get(w,64)+cap_bucket(p,n)*8)
    while current!=0:
        if current==p:
            if (get(w,current+16)^t0)|(get(w,current+24)^t1)!=0:
                return 0
            return current
        current=get(w,current+32)
    return 0
def cap_lookup(w:mutbuf,p:u64,t0:u64,t1:u64) -> u64:
    node=cap_lookup_node(w,p,t0,t1)
    if node==0:
        return 0
    return get(w,node+8)
def cap_new_unpublished(w:mutbuf,obj:u64,t0:u64,t1:u64) -> u64:
    p=allocate(w,96)
    if p==0:
        return 0
    zero(w,p,96)
    put(w,p,CAP_MAGIC)
    put(w,p+8,obj)
    put(w,p+16,t0)
    put(w,p+24,t1)
    return p
def cap_publish(w:mutbuf,p:u64) -> u64:
    bucket=get(w,64)+cap_bucket(p,get(w,72))*8
    put(w,p+32,get(w,bucket))
    put(w,bucket,p)
    first=get(w,80)
    put(w,p+48,0)
    put(w,p+56,first)
    if first!=0:
        put(w,first+48,p)
    put(w,80,p)
    put(w,88,get(w,88)+1)
    obj=get(w,p+8)
    if obj!=0:
        put(w,obj+64,get(w,obj+64)+1)
    return p
def cap_drop(w:mutbuf,p:u64) -> u64:
    bucket=get(w,64)+cap_bucket(p,get(w,72))*8
    current=get(w,bucket)
    previous=0
    while current!=p:
        previous=current
        current=get(w,current+32)
    if previous==0:
        put(w,bucket,get(w,p+32))
    else:
        put(w,previous+32,get(w,p+32))
    previous=get(w,p+48)
    next=get(w,p+56)
    if previous==0:
        put(w,80,next)
    else:
        put(w,previous+56,next)
    if next!=0:
        put(w,next+48,previous)
    obj=get(w,p+8)
    if obj!=0:
        put(w,obj+64,get(w,obj+64)-1)
    put(w,88,get(w,88)-1)
    deallocate(w,p)
    object_release(w,obj)
    if get(w,88)==0:
        collect(w)
    return 0
def bytes_hash(w:mutbuf,at:u64,n:u64) -> u64:
    h=14695981039346656037
    i=0
    while i<n:
        h=(h^byte(w,at+i))*1099511628211
        i=i+1
    return h
def bytes_equal(w:mutbuf,a:u64,b:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return False
        i=i+1
    return True
def string_count(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    count=0
    while i<n:
        b=byte(w,at+i)
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
            c=byte(w,at+i+j)
            if c<128 or c>191:
                return MAX
            value=(value<<6)|(c&63)
            j=j+1
        if (size==2 and value<128) or (size==3 and value<2048) or (size==4 and (value<65536 or value>1114111)):
            return MAX
        count=count+1
        i=i+size
    return count
def integer_valid(w:mutbuf,at:u64,n:u64) -> bool:
    if n==0:
        return False
    i=0
    if byte(w,at)==45:
        if n==1:
            return False
        i=1
    if byte(w,at+i)==48:
        return i==0 and n==1
    if byte(w,at+i)<49 or byte(w,at+i)>57:
        return False
    while i<n:
        b=byte(w,at+i)
        if b<48 or b>57:
            return False
        i=i+1
    return True
def object_scalar(w:mutbuf,kind:u64,at:u64,n:u64,bits:u64) -> u64:
    if kind<=1:
        return get(w,128+choose(kind==0,0,1+bits)*8)
    p=object_new(w,kind)
    if p==0:
        return 0
    if n!=0:
        data=allocate(w,n)
        if data==0:
            object_unlink(w,p)
            return 0
        copy(w,data,at,n)
        put(w,p+24,data)
        put(w,p+32,n)
    put(w,p+48,bits)
    if kind==4:
        put(w,p+16,string_count(w,get(w,p+24),n))
    if kind==7:
        put(w,p+16,n)
    h=0
    if kind==0:
        h=11400714819323198485
    elif kind==1:
        h=(14695981039346656037^(48+bits))*1099511628211
    elif kind==2 or kind==4:
        h=bytes_hash(w,get(w,p+24),n)
    elif kind==7:
        h=bytes_hash(w,get(w,p+24),n)^13787848793156543929
    else:
        h=bits
    put(w,p+56,h)
    return p
def integer_index(w:mutbuf,p:u64,n:u64,insert:bool) -> u64:
    kind=get(w,p+8)
    if kind==1:
        v=get(w,p+48)
        if v>=n and insert==False:
            return MAX
        if v>n:
            v=n
        return v
    if kind!=2:
        return MAX-1
    at=get(w,p+24)
    size=get(w,p+32)
    negative=byte(w,at)==45
    i=choose(negative,1,0)
    v=0
    while i<size:
        d=byte(w,at+i)-48
        if v>922337203685477580 or (v==922337203685477580 and d>choose(negative,8,7)):
            return MAX-2
        v=v*10+d
        i=i+1
    if negative:
        if v>n:
            if insert:
                return 0
            return MAX
        return n-v
    if insert:
        return choose(v>n,n,v)
    if v>=n:
        return MAX
    return v
def key_equal(w:mutbuf,a:u64,b:u64) -> bool:
    if a==b:
        return True
    ak=get(w,a+8)
    bk=get(w,b+8)
    if numeric_kind(ak) and numeric_kind(bk):
        an=numeric_key_n(w,a)
        bn=numeric_key_n(w,b)
        if an!=0 and an==bn:
            i=0
            while i<an:
                if numeric_key_byte(w,a,i)!=numeric_key_byte(w,b,i):
                    return False
                i=i+1
            return True
        if ak!=3 or bk!=3:
            return False
    if ak!=bk:
        return False
    if ak==0:
        return True
    if ak==3:
        av=get(w,a+48)
        bv=get(w,b+48)
        if (av&9223372036854775807)==0 and (bv&9223372036854775807)==0:
            return True
        if ((av>>52)&2047)==2047 and (av&4503599627370495)!=0:
            return False
        return av==bv
    n=get(w,a+32)
    return n==get(w,b+32) and bytes_equal(w,get(w,a+24),get(w,b+24),n)
def dict_find(w:mutbuf,obj:u64,key:u64) -> u64:
    cap=get(w,obj+40)
    if cap==0:
        return MAX
    data=get(w,obj+24)
    hash=get(w,key+56)
    current=get(w,data+cap*32+(hash&(cap*2-1))*8)
    while current!=0:
        i=current-1
        k=get(w,data+i*32)
        if get(w,data+i*32+16)==hash and key_equal(w,k,key):
            return i
        current=get(w,data+i*32+24)
    return MAX
def dict_rehash(w:mutbuf,obj:u64) -> u64:
    cap=get(w,obj+40)
    data=get(w,obj+24)
    zero(w,data+cap*32,cap*16)
    i=0
    while i<get(w,obj+112):
        if get(w,data+i*32)!=0:
            bucket=data+cap*32+(get(w,data+i*32+16)&(cap*2-1))*8
            put(w,data+i*32+24,get(w,bucket))
            put(w,bucket,i+1)
        i=i+1
    return 0
def dict_reserve(w:mutbuf,obj:u64) -> bool:
    used=get(w,obj+112)
    cap=get(w,obj+40)
    if used<cap:
        return True
    n=choose(cap==0,8,cap*2)
    if cap!=0 and get(w,obj+16)<cap//2:
        n=cap
    if n>192153584101141162 or n<cap:
        put(w,16,MAX)
        return False
    data=allocate(w,n*48)
    if data==0:
        return False
    zero(w,data,n*48)
    old=get(w,obj+24)
    i=0
    j=0
    while i<used:
        if get(w,old+i*32)!=0:
            copy(w,data+j*32,old+i*32,32)
            j=j+1
        i=i+1
    deallocate(w,old)
    put(w,obj+24,data)
    put(w,obj+40,n)
    put(w,obj+112,j)
    dict_rehash(w,obj)
    return True
def dict_insert(w:mutbuf,obj:u64,key:u64,value:u64) -> u64:
    data=get(w,obj+24)
    i=get(w,obj+112)
    hash=get(w,key+56)
    bucket=data+get(w,obj+40)*32+(hash&(get(w,obj+40)*2-1))*8
    put(w,data+i*32,key)
    put(w,data+i*32+8,value)
    put(w,data+i*32+16,hash)
    put(w,data+i*32+24,get(w,bucket))
    put(w,bucket,i+1)
    put(w,obj+112,i+1)
    put(w,obj+16,get(w,obj+16)+1)
    edge_add(w,key)
    edge_add(w,value)
    return 0
def list_reserve(w:mutbuf,obj:u64) -> bool:
    n=get(w,obj+16)
    cap=get(w,obj+40)
    if n<cap:
        return True
    size=choose(cap==0,8,cap*2)
    if size>1152921504606846975 or size<cap:
        put(w,16,MAX)
        return False
    data=allocate(w,size*8)
    if data==0:
        return False
    copy(w,data,get(w,obj+24),n*8)
    deallocate(w,get(w,obj+24))
    put(w,obj+24,data)
    put(w,obj+40,size)
    return True
def object_kind_size(o:mutbuf,w:mutbuf,p:u64) -> u64:
    kind=get(w,p+8)
    put(o,G_KIND,kind)
    put(o,G_N,choose(kind>=4,get(w,p+16),0))
    n=get(w,p+32)
    if kind==0 or kind==5 or kind==6:
        n=0
    if kind==1:
        n=1
    if kind==3:
        n=8
    put(o,G_BYTES,n)
    put(o,G_ID0,p)
    put(o,G_ID1,get(w,40))
    return 0
def done(o:mutbuf,status:u64) -> u64:
    put(o,P_ERROR,status)
    return 0
def growth(o:mutbuf,w:mutbuf) -> u64:
    if get(w,16)==MAX:
        return done(o,5)
    if get(o,G_ALLOC_FAILED)!=0:
        if get(o,G_RETRY)==0:
            put(o,G_RETRY,1)
            collect(w)
            put(o,G_ALLOC_FAILED,0)
            return 10
        return done(o,5)
    need=get(w,16)
    if need<length(w):
        need=length(w)
    if need>9223372036854775807:
        return done(o,5)
    put(o,G_WANT,need*2)
    return 1
def role(o:mutbuf,id:u64,sr:u64,sa:u64,sn:u64,oreg:u64,oa:u64,on:u64,wr:u64,wa:u64,wn:u64) -> u64:
    put(o,P_ROLE,id)
    put(o,P_SELECT,sr|(oreg<<6)|(wr<<12))
    put(o,P_ARG,sa)
    put(o,P_ARG+8,sn)
    put(o,P_ARG+16,oa)
    put(o,P_ARG+24,on)
    put(o,P_ARG+32,wa)
    put(o,P_ARG+40,wn)
    return 4
'''
def resolve(entry,source):
    text=source+'\n'+SOURCE
    for key,value in sorted(C.items(),key=lambda p:-len(p[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    tree=ast.parse(text);functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    needed={entry};pending=[entry]
    while pending:
        name=pending.pop()
        for n in ast.walk(functions[name]):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in functions and n.func.id not in needed:
                needed.add(n.func.id);pending.append(n.func.id)
    return '\n\n'.join(ast.unparse(n) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in needed)+'\n'
