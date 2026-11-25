"""Fresh JSON-to-owned-value import using the actual lossless HIA capture profile."""
import ast
from tools.generate_hia_result_value_common import ROOT,document,render_assembly,resolve
from tools.generate_hia_result_value_core import SOURCE as CORE
SOURCE=r'''
def result_value_import(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,G_PHASE)
    if phase==0:
        zero(o,256,448)
        zero(o,1024,256)
        put(o,G_OP,1)
        put(o,G_INPUT_N,readword(s,96))
        put(w,16,0)
        put(o,G_PHASE,1)
        return role(o,4,2,128,readword(s,96),3,1024,64,3,1152,128)
    if phase==1:
        if get(o,G_FEEDBACK)!=0 or get(o,1024)!=3544424485346167112:
            return import_done(o,w,8)
        put(o,G_ARENA_N,get(o,1056))
        put(o,G_PARSEWN,get(o,1064))
        put(o,G_PARSE_NODES,get(o,1032))
        put(o,G_PARSE_KEYS,get(o,1040))
        put(o,G_PARSE_DEPTH,get(o,1048))
        put(o,G_PHASE,2)
        return 10
    if phase==2:
        arena=allocate(w,get(o,G_ARENA_N))
        if arena==0:
            return import_growth(o,w,2)
        work=allocate(w,get(o,G_PARSEWN))
        if work==0:
            deallocate(w,arena)
            return import_growth(o,w,2)
        put(o,G_ARENA,arena)
        put(o,G_PARSEW,work)
        zero(w,work,128)
        put(w,work+48,get(o,G_PARSE_NODES))
        put(w,work+56,get(o,G_PARSE_DEPTH))
        put(w,work+96,get(o,G_PARSE_KEYS))
        put(w,work+104,1)
        put(o,G_PHASE,3)
        return role(o,4,2,128,get(o,G_INPUT_N),1,arena,get(o,G_ARENA_N),1,work,get(o,G_PARSEWN))
    if phase==3:
        if get(o,G_FEEDBACK)!=0:
            return import_done(o,w,8)
        put(o,G_PARSE_NODES,get(w,get(o,G_ARENA)+8))
        deallocate(w,get(o,G_PARSEW))
        put(o,G_PARSEW,0)
        put(o,G_PHASE,4)
        return 10
    if phase==4:
        nodes=get(o,G_PARSE_NODES)
        if nodes==0 or nodes>1152921504606846975:
            return import_done(o,w,5)
        map=allocate(w,nodes*8)
        if map==0:
            return import_growth(o,w,4)
        work=allocate(w,8192)
        if work==0:
            deallocate(w,map)
            return import_growth(o,w,4)
        put(o,G_DATA,map)
        put(o,G_WORK,work)
        zero(w,map,nodes*8)
        put(o,G_ITER,0)
        put(o,G_PHASE,10)
        return 10
    if phase==10:
        return build_nodes(s,o,w)
    if phase>=11 and phase<=14:
        return float_node(s,o,w,phase)
    if phase==20:
        return link_nodes(o,w)
    if phase==30:
        random=allocate(w,16)
        if random==0:
            return import_growth(o,w,10)
        put(o,G_RANDOM,random)
        put(o,G_RN,16)
        put(o,G_RUSED,0)
        put(o,G_PHASE,31)
        return 5
    if phase==31:
        r=get(o,G_FEEDBACK)
        if r==MAX-3:
            return 5
        if r==0 or r>=18446744073709547521 or r>16-get(o,G_RUSED):
            return import_done(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+r)
        if get(o,G_RUSED)!=16:
            return 5
        obj=get(w,get(o,G_DATA))
        if publish_one(o,w,obj)!=0:
            deallocate(w,get(o,G_RANDOM))
            put(o,G_RANDOM,0)
            return import_growth(o,w,10)
        collect(w)
        return import_done(o,w,0)
    return import_done(o,w,11)
def import_rewind(o:mutbuf,w:mutbuf) -> u64:
    p=get(w,96)
    while p!=0 and get(w,p+96)==2:
        next=get(w,p+88)
        object_unlink(w,p)
        p=next
    put(o,G_ITER,0)
    return 0
def import_growth(o:mutbuf,w:mutbuf,next:u64) -> u64:
    import_rewind(o,w)
    put(o,G_PHASE,next)
    action=growth(o,w)
    if action==0:
        return import_done(o,w,get(o,P_ERROR))
    return action
def import_done(o:mutbuf,w:mutbuf,status:u64) -> u64:
    if status!=0:
        import_rewind(o,w)
    deallocate(w,get(o,G_ARENA))
    deallocate(w,get(o,G_PARSEW))
    deallocate(w,get(o,G_DATA))
    deallocate(w,get(o,G_WORK))
    deallocate(w,get(o,G_RANDOM))
    put(o,G_ARENA,0)
    put(o,G_PARSEW,0)
    put(o,G_DATA,0)
    put(o,G_WORK,0)
    put(o,G_RANDOM,0)
    return done(o,status)
def raw_integer(s:readbuf,w:mutbuf,at:u64,n:u64) -> u64:
    if n==2 and byte(s,at)==45 and byte(s,at+1)==48:
        at=at+1
        n=1
    obj=object_new(w,2)
    if obj==0:
        return 0
    data=allocate(w,n)
    if data==0:
        object_unlink(w,obj)
        return 0
    from_input(s,w,data,at,n)
    put(w,obj+24,data)
    put(w,obj+32,n)
    put(w,obj+56,bytes_hash(w,data,n))
    return obj
def node_attach(o:mutbuf,w:mutbuf,obj:u64) -> u64:
    if get(w,obj+8)>1:
        put(w,obj+96,2)
    put(w,get(o,G_DATA)+get(o,G_ITER)*8,obj)
    put(o,G_ITER,get(o,G_ITER)+1)
    return 0
def build_nodes(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    arena=get(o,G_ARENA)
    while get(o,G_ITER)<get(o,G_PARSE_NODES):
        index=get(o,G_ITER)
        node=arena+64+index*72
        kind=get(w,node)
        obj=0
        if kind==3:
            at=128+get(w,node+24)
            n=get(w,node+32)
            isfloat=False
            i=0
            while i<n:
                c=byte(s,at+i)
                if c==46 or c==69 or c==101 or c==78 or c==73:
                    isfloat=True
                i=i+1
            if isfloat:
                put(o,G_INPUT,at)
                put(o,G_AUX,n)
                if byte(s,at)==78:
                    put(o,1408,9221120237041090560)
                    put(o,G_PHASE,12)
                    return 10
                if byte(s,at)==73 or (n>1 and byte(s,at+1)==73):
                    bits=9218868437227405312
                    if byte(s,at)==45:
                        bits=bits|9223372036854775808
                    put(o,1408,bits)
                    put(o,G_PHASE,12)
                    return 10
                put(o,G_PHASE,11)
                return role(o,6,2,at,n,3,1408,8,1,get(o,G_WORK),8192)
            digits=n
            if byte(s,at)==45:
                digits=digits-1
            limit=get(w,48)
            if limit!=0 and digits>limit:
                return import_done(o,w,8)
            obj=raw_integer(s,w,at,n)
        elif kind==0:
            obj=object_scalar(w,0,0,0,0)
        elif kind==1 or kind==2:
            obj=object_scalar(w,1,0,0,kind-1)
        elif kind==4:
            obj=object_scalar(w,4,arena+get(w,node+24),get(w,node+32),0)
        elif kind==5 or kind==6:
            obj=object_new(w,kind)
        else:
            return import_done(o,w,11)
        if obj==0:
            return import_growth(o,w,10)
        node_attach(o,w,obj)
    put(o,G_ITER,0)
    put(o,G_PHASE,20)
    return 10
def float_node(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    if phase==11:
        r=get(o,G_FEEDBACK)
        if r==4294967292:
            bits=9218868437227405312
            if byte(s,get(o,G_INPUT))==45:
                bits=bits|9223372036854775808
            put(o,1408,bits)
        elif r!=8:
            return import_done(o,w,11)
        put(o,G_PHASE,12)
        return 10
    if phase==12:
        bits=get(o,1408)
        if ((bits>>52)&2047)!=2047:
            put(o,G_PHASE,13)
            return role(o,5,3,1408,8,3,1440,32,1,get(o,G_WORK),8192)
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
        put(o,G_PHASE,14)
        return 10
    if phase==13:
        n=get(o,G_FEEDBACK)
        if n==0 or n>32:
            return import_done(o,w,11)
        put(o,G_OUT_N,n)
        put(o,G_PHASE,14)
    obj=float_object(w,o,get(o,1408),1440,get(o,G_OUT_N))
    if obj==0:
        return import_growth(o,w,10)
    node_attach(o,w,obj)
    put(o,G_PHASE,10)
    return 10
def link_nodes(o:mutbuf,w:mutbuf) -> u64:
    arena=get(o,G_ARENA)
    map=get(o,G_DATA)
    count=get(o,G_PARSE_NODES)
    while get(o,G_ITER)<count:
        index=get(o,G_ITER)
        node=arena+64+index*72
        kind=get(w,node)
        obj=get(w,map+index*8)
        if kind==5 or kind==6:
            n=get(w,node+32)
            child=get(w,node+24)
            i=0
            while i<n:
                if child>=count:
                    return import_done(o,w,11)
                childnode=arena+64+child*72
                value=get(w,map+child*8)
                if kind==5:
                    if list_reserve(w,obj)==False:
                        return import_growth(o,w,10)
                    put(w,get(w,obj+24)+i*8,value)
                    put(w,obj+16,i+1)
                    edge_add(w,value)
                else:
                    key=object_scalar(w,4,arena+get(w,childnode+40),get(w,childnode+48),0)
                    if key==0:
                        return import_growth(o,w,10)
                    put(w,key+96,2)
                    if dict_reserve(w,obj)==False:
                        return import_growth(o,w,10)
                    dict_insert(w,obj,key,value)
                child=get(w,childnode+16)
                i=i+1
        put(o,G_ITER,index+1)
    put(o,G_PHASE,30)
    return 10
'''
def source_program():
 helper='\n'.join(ast.get_source_segment(CORE,n) for n in ast.parse(CORE).body if n.name=='publish_one')
 return resolve('result_value_import',SOURCE+'\n'+helper)
def program():return document(source_program(),'result_value_import')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/result_value_import.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)
