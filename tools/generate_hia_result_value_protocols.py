"""Native tuple/record hashing and equality over the one owned Value graph.

The HIA implementation uses explicit arena work stacks. Dictionary-key walks
operate only on already hashable immutable graphs and never allocate or invoke
a user callback while the table is being inspected.
"""
from tools.generate_hia_result_value_common import ROOT, document, render_assembly, resolve
from tools.generate_hia_result_value_core import SOURCE as CORE

SOURCE = r'''
def result_value_protocols(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,G_PHASE)
    if phase==0:
        return protocols_prepare(s,o,w)
    if phase==1:
        op=get(o,G_OP)
        if op==62:
            result=protocols_equal(o,w,get(o,G_A),get(o,G_B))
            if get(o,P_ERROR)==5:
                return protocols_growth(o,w)
            put(o,G_KIND,1)
            put(o,G_N,result)
            return protocols_finish(o,w,get(o,P_ERROR))
        key=get(o,G_A)
        if op!=63:
            key=get(o,G_B)
        if protocols_hash(o,w,key)==False:
            if get(o,P_ERROR)==5:
                return protocols_growth(o,w)
            return protocols_finish(o,w,get(o,P_ERROR))
        if op==63:
            put(o,G_KIND,2)
            put(o,G_N,get(o,G_INDEX))
            return protocols_finish(o,w,0)
        put(o,G_PHASE,2)
    if get(o,G_PHASE)==2:
        op=get(o,G_OP)
        obj=get(o,G_A)
        key=get(o,G_B)
        found=protocols_find(w,obj,key)
        put(o,G_FOUND,found)
        if found==MAX and op!=10:
            return protocols_finish(o,w,3)
        if op==10 and found==MAX and get(w,key+8)!=4 and get(w,obj+120)==0:
            if dict_general(w,obj)==False:
                return protocols_growth(o,w)
            put(o,G_FOUND,protocols_find(w,obj,key))
        if op==9:
            put(o,G_RESULT,get(w,get(w,obj+24)+found*32+8))
            put(o,G_PHASE,10)
        else:
            put(o,G_PHASE,20)
    if get(o,G_PHASE)==10:
        random=allocate(w,16)
        if random==0:
            return protocols_growth(o,w)
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
            return protocols_finish(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+result)
        if get(o,G_RUSED)!=16:
            return 5
        put(o,G_PHASE,20)
    if get(o,G_PHASE)==20:
        if get(o,G_OP)==9:
            if publish_one(o,w,get(o,G_RESULT))!=0:
                return protocols_growth(o,w)
            return protocols_finish(o,w,0)
        action=mutate_dict(o,w)
        if action==0:
            return protocols_finish(o,w,get(o,P_ERROR))
        return action
    return protocols_finish(o,w,11)

def protocols_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    zero(o,256,448)
    put(w,16,0)
    op=readword(s,8)
    put(o,G_OP,op)
    if get(w,112)>=4096:
        collect(w)
    put(w,112,get(w,112)+1)
    a=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
    if a==0:
        return done(o,1)
    put(o,G_A,a)
    if op!=63:
        b=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
        if b==0:
            return done(o,1)
        put(o,G_B,b)
    if op==10:
        c=cap_lookup(w,readword(s,72),readword(s,80),readword(s,88))
        if c==0:
            return done(o,1)
        put(o,G_C,c)
    if op>=9 and op<=11:
        if get(w,a+8)!=6:
            return done(o,2)
        object_kind_size(o,w,a)
    put(o,G_PHASE,1)
    return 10

def protocols_finish(o:mutbuf,w:mutbuf,status:u64) -> u64:
    deallocate(w,get(o,G_STACK))
    deallocate(w,get(o,G_RANDOM))
    put(o,G_STACK,0)
    put(o,G_RANDOM,0)
    return done(o,status)

def protocols_growth(o:mutbuf,w:mutbuf) -> u64:
    put(o,P_ERROR,0)
    action=growth(o,w)
    if action==0:
        return protocols_finish(o,w,get(o,P_ERROR))
    return action

def protocols_stack(o:mutbuf,w:mutbuf,wanted:u64) -> bool:
    capacity=get(o,G_AUX)
    if wanted<=capacity:
        return True
    size=choose(capacity==0,16,capacity*2)
    if size<wanted or size>288230376151711743:
        put(w,16,MAX)
        put(o,P_ERROR,5)
        return False
    data=allocate(w,size*64)
    if data==0:
        put(o,P_ERROR,5)
        return False
    old=get(o,G_STACK)
    if old!=0:
        copy(w,data,old,capacity*64)
        deallocate(w,old)
    put(o,G_STACK,data)
    put(o,G_AUX,size)
    return True

def protocols_nan(w:mutbuf,obj:u64) -> bool:
    if get(w,obj+8)!=3:
        return False
    bits=get(w,obj+48)
    return (bits&9223372036854775807)>9218868437227405312

def protocols_pair(w:mutbuf,a:u64,b:u64,identity:bool) -> u64:
    if a==b:
        if identity==False and protocols_nan(w,native_base(w,a)):
            return 0
        return 1
    a=native_base(w,a)
    b=native_base(w,b)
    if protocols_nan(w,a) or protocols_nan(w,b):
        return 0
    ak=get(w,a+8)
    bk=get(w,b+8)
    if ak==bk and (ak==5 or ak==6 or ak==11 or ak==12):
        if a==b:
            return 1
        if get(w,a+16)!=get(w,b+16):
            return 0
        if ak==12 and get(w,a+40)!=get(w,b+40):
            return 0
        return 2
    return choose(key_equal(w,a,b),1,0)

def protocols_key_equal(w:mutbuf,a:u64,b:u64) -> bool:
    top=0
    identity=True
    result=True
    running=True
    while running:
        comparison=protocols_pair(w,a,b,identity)
        if comparison==0:
            result=False
            running=False
        elif comparison==2:
            a=native_base(w,a)
            b=native_base(w,b)
            kind=get(w,a+8)
            if kind!=11 and kind!=12:
                result=False
                running=False
            elif get(w,a+16)!=0:
                put(w,a+96,top)
                put(w,a+104,b)
                put(w,a+120,1)
                top=a
                identity=kind!=12
                a=get(w,get(w,a+24))
                b=get(w,get(w,b+24))
                comparison=3
        if running and comparison!=3:
            more=False
            while top!=0 and more==False:
                i=get(w,top+120)
                if i<get(w,top+16):
                    a=get(w,get(w,top+24)+i*8)
                    b=get(w,get(w,get(w,top+104)+24)+i*8)
                    put(w,top+120,i+1)
                    identity=get(w,top+8)!=12
                    more=True
                else:
                    old=top
                    top=get(w,old+96)
                    put(w,old+96,0)
                    put(w,old+104,0)
                    put(w,old+120,0)
            if more==False:
                running=False
    while top!=0:
        old=top
        top=get(w,old+96)
        put(w,old+96,0)
        put(w,old+104,0)
        put(w,old+120,0)
    return result

def protocols_find(w:mutbuf,obj:u64,key:u64) -> u64:
    capacity=get(w,obj+40)
    if capacity==0:
        return MAX
    data=get(w,obj+24)
    hash=get(w,key+56)
    current=get(w,data+capacity*32+(hash&(capacity*2-1))*8)
    while current!=0:
        i=current-1
        other=get(w,data+i*32)
        if get(w,data+i*32+16)==hash and protocols_key_equal(w,other,key):
            return i
        current=get(w,data+i*32+24)
    return MAX

def protocols_equal(o:mutbuf,w:mutbuf,a:u64,b:u64) -> u64:
    depth=0
    identity=False
    while True:
        comparison=protocols_pair(w,a,b,identity)
        if comparison==0:
            return 0
        if comparison==2:
            a=native_base(w,a)
            b=native_base(w,b)
            i=0
            while i<depth:
                frame=get(o,G_STACK)+i*64
                if get(w,frame)==a and get(w,frame+8)==b:
                    put(o,P_ERROR,23)
                    return 0
                i=i+1
            if protocols_stack(o,w,depth+1)==False:
                return 0
            frame=get(o,G_STACK)+depth*64
            put(w,frame,a)
            put(w,frame+8,b)
            put(w,frame+16,0)
            put(w,frame+24,get(w,a+8))
            depth=depth+1
        more=False
        while more==False:
            if depth==0:
                return 1
            frame=get(o,G_STACK)+(depth-1)*64
            left=get(w,frame)
            right=get(w,frame+8)
            kind=get(w,frame+24)
            i=get(w,frame+16)
            if kind==6:
                while i<get(w,left+112) and get(w,get(w,left+24)+i*32)==0:
                    i=i+1
                if i<get(w,left+112):
                    key=get(w,get(w,left+24)+i*32)
                    found=protocols_find(w,right,key)
                    if found==MAX:
                        return 0
                    a=get(w,get(w,left+24)+i*32+8)
                    b=get(w,get(w,right+24)+found*32+8)
                    identity=True
                    more=True
            elif i<get(w,left+16):
                a=get(w,get(w,left+24)+i*8)
                b=get(w,get(w,right+24)+i*8)
                identity=kind!=12
                more=True
            if more:
                put(w,frame+16,i+1)
            else:
                depth=depth-1
    return 0

def protocols_scalar_hash(w:mutbuf,obj:u64) -> u64:
    kind=get(w,obj+8)
    if kind==0:
        return 4238894112
    if kind==1:
        return get(w,obj+48)
    value=0
    negative=False
    if kind==2:
        data=get(w,obj+24)
        n=get(w,obj+32)
        negative=byte(w,data)==45
        i=choose(negative,1,0)
        while i<n:
            eight=((value<<3)&2305843009213693951)|(value>>58)
            two=((value<<1)&2305843009213693951)|(value>>60)
            value=eight+two+byte(w,data+i)-48
            if value>=2305843009213693951:
                value=value-2305843009213693951
            if value>=2305843009213693951:
                value=value-2305843009213693951
            i=i+1
    elif kind==3:
        bits=get(w,obj+48)
        negative=(bits>>63)!=0
        exponent=(bits>>52)&2047
        mantissa=bits&4503599627370495
        if exponent==2047:
            if mantissa!=0:
                value=((obj>>4)|(obj<<60))^get(w,40)
                return choose(value==MAX,MAX-1,value)
            value=314159
        else:
            if exponent!=0:
                mantissa=mantissa|4503599627370496
            else:
                exponent=1
            shift=0
            if exponent>=1075:
                shift=(exponent-1075)%61
            else:
                shift=(61-((1075-exponent)%61))%61
            value=((mantissa<<shift)&2305843009213693951)|(mantissa>>(61-shift))
    else:
        if (kind==4 or kind==7) and get(w,obj+32)==0:
            return 0
        value=get(w,obj+56)
        return choose(value==MAX,MAX-1,value)
    if negative:
        value=0-value
    return choose(value==MAX,MAX-1,value)

def protocols_hash_lane(acc:u64,lane:u64) -> u64:
    acc=acc+lane*14029467366897019727
    acc=(acc<<31)|(acc>>33)
    return acc*11400714785074694791

def protocols_hash_finish(acc:u64,n:u64) -> u64:
    acc=acc+(n^(2870177450012600261^3527539))
    return choose(acc==MAX,1546275796,acc)

def protocols_hash(o:mutbuf,w:mutbuf,current:u64) -> bool:
    depth=0
    while True:
        plain=native_base(w,current)
        kind=get(w,plain+8)
        if kind==5 or kind==6:
            put(o,P_ERROR,2)
            return False
        internal=get(w,plain+56)
        public=0
        if kind==11 or kind==12:
            n=get(w,plain+16)
            if n!=0:
                if protocols_stack(o,w,depth+1)==False:
                    return False
                frame=get(o,G_STACK)+depth*64
                put(w,frame,current)
                put(w,frame+8,plain)
                put(w,frame+16,1)
                put(w,frame+24,2870177450012600261)
                put(w,frame+32,2870177450012600261)
                depth=depth+1
                current=get(w,get(w,plain+24))
            else:
                internal=protocols_hash_finish(2870177450012600261,0)
                public=internal
        else:
            public=protocols_scalar_hash(w,plain)
        descending=(kind==11 or kind==12) and get(w,plain+16)!=0
        if descending==False:
            put(w,plain+56,internal)
            put(w,current+56,internal)
        more=descending
        while more==False:
            if depth==0:
                put(o,G_INDEX,public)
                return True
            frame=get(o,G_STACK)+(depth-1)*64
            left=get(w,frame)
            plain=get(w,frame+8)
            i=get(w,frame+16)
            inner=protocols_hash_lane(get(w,frame+24),internal)
            outer=protocols_hash_lane(get(w,frame+32),public)
            if i<get(w,plain+16):
                put(w,frame+16,i+1)
                put(w,frame+24,inner)
                put(w,frame+32,outer)
                current=get(w,get(w,plain+24)+i*8)
                more=True
            else:
                internal=protocols_hash_finish(inner,i)
                public=protocols_hash_finish(outer,i)
                put(w,plain+56,internal)
                put(w,left+56,internal)
                depth=depth-1
    return False
'''

def source_program():
    return resolve('result_value_protocols', SOURCE + '\n' + CORE)

def program():
    return document(source_program(), 'result_value_protocols')

if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/result_value_protocols.hepta'
    path.write_text(render_assembly(program()))
    print(path.name, path.stat().st_size, flush=True)
