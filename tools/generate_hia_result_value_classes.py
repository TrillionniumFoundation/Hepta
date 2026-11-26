"""Actual shared-graph classes, bases, MRO, namespaces and typed instances.

Q03 is a new private protocol. It does not broaden Q01 or Q02, and a class
name is never used as evidence of inheritance. Native callable capture and
full public metaclass semantics are separate unfinished boundaries.
"""
from pathlib import Path
from tools.generate_hia_result_value_common import document, render_assembly, resolve
from tools.generate_hia_result_value_core import SOURCE as CORE

ROOT = Path(__file__).resolve().parents[1]

CATALOG = [
    ('object', (), (), 0, 0),
    ('type', (1,), (1,), 2, 0),
    ('int', (1,), (1,), 3, 0),
    ('bool', (3,), (3, 1), 3, 0),
    ('float', (1,), (1,), 5, 0),
    ('str', (1,), (1,), 6, 0),
    ('bytes', (1,), (1,), 7, 0),
    ('list', (1,), (1,), 8, 0),
    ('dict', (1,), (1,), 9, 0),
    ('NoneType', (1,), (1,), 10, 0),
    ('dict_keyiterator', (1,), (1,), 11, 0),
    ('dict_itemiterator', (1,), (1,), 12, 0),
    ('dict_valueiterator', (1,), (1,), 13, 0),
    ('PurePath', (1,), (1,), 14, 1),
    ('PurePosixPath', (14,), (14, 1), 14, 1),
    ('PureWindowsPath', (14,), (14, 1), 14, 2),
    ('Path', (14,), (14, 1), 14, 1),
    ('PosixPath', (17, 15), (17, 15, 14, 1), 14, 1),
    ('WindowsPath', (17, 16), (17, 16, 14, 1), 14, 2),
    ('ScalarMultiversionRuntime', (1,), (1,), 0, 0),
    ('BaseException', (1,), (1,), 21, 0),
    ('Exception', (21,), (21, 1), 21, 0),
    ('TypeError', (22,), (22, 21, 1), 21, 0),
    ('ValueError', (22,), (22, 21, 1), 21, 0),
    ('OSError', (22,), (22, 21, 1), 21, 0),
    ('RuntimeError', (22,), (22, 21, 1), 21, 0),
    ('MemoryError', (22,), (22, 21, 1), 21, 0),
    ('tuple', (1,), (1,), 28, 0),
    ('ScalarABI', (1,), (1,), 29, 0),
    ('GenerationInfo', (1,), (1,), 30, 0),
    ('GenerationLease', (1,), (1,), 0, 0),
    ('function', (1,), (1,), 32, 0),
    ('method', (1,), (1,), 33, 0),
    ('builtin_function_or_method', (1,), (1,), 34, 0),
    ('BackgroundOptimizer', (1,), (1,), 0, 0),
    ('VerifiedProgram', (1,), (1,), 36, 0),
    ('Future', (1,), (1,), 0, 0),
    ('ArithmeticError', (22,), (22, 21, 1), 21, 0),
    ('OverflowError', (38,), (38, 22, 21, 1), 21, 0),
    ('StopIteration', (22,), (22, 21, 1), 21, 0),
    ('MultiversionRejected', (24,), (24, 22, 21, 1), 21, 0),
    ('HIAProgramRejected', (24,), (24, 22, 21, 1), 21, 0),
]

SOURCE = r'''
def result_value_classes(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,G_PHASE)
    if phase==0:
        return class_prepare(s,o,w)
    if phase==1:
        if get(o,G_OP)==87:
            if class_catalog_extended(w)==False:
                return growth(o,w)
        elif class_catalog(w)==False:
            return growth(o,w)
        put(o,G_PHASE,10)
    if get(o,G_PHASE)==10:
        count=get(o,G_COUNT)
        if count==0:
            put(o,G_PHASE,20)
        else:
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
            return class_finish(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+result)
        if get(o,G_RUSED)!=get(o,G_RN):
            return 5
        put(o,G_PHASE,20)
    if get(o,G_PHASE)==20:
        return class_execute(s,o,w)
    if get(o,G_PHASE)==31:
        if get(o,G_FEEDBACK)!=0:
            return class_finish(o,w,11)
        result=get(o,816)
        if get(w,result)!=3544423286865742152:
            return class_finish(o,w,11)
        status=get(w,result+8)
        if status==1 or status==2:
            put(o,G_N,get(w,result+16))
            return class_finish(o,w,15+status)
        if status!=0 or get(w,result+16)>(get(o,824)-32)//8:
            return class_finish(o,w,11)
        put(o,G_PHASE,32)
    if get(o,G_PHASE)==32:
        return class_create(o,w)
    return class_finish(o,w,11)
def class_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    zero(o,256,448)
    zero(o,768,128)
    op=readword(s,8)
    put(o,G_OP,op)
    put(w,16,0)
    if get(w,112)>=4096:
        collect(w)
    put(w,112,get(w,112)+1)
    if op!=32 and op!=87:
        a=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
        if a==0:
            return done(o,1)
        put(o,G_A,a)
        if (op==34 or op==38) and get(w,a+8)!=10:
            return done(o,2)
    if op==33 or op==34 or op==35 or op==37 or op==39 or op==75:
        b=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
        if b==0:
            return done(o,1)
        put(o,G_B,b)
    if op==33 or (op==34 and readword(s,104)==0):
        c=cap_lookup(w,readword(s,72),readword(s,80),readword(s,88))
        if c==0:
            return done(o,1)
        put(o,G_C,c)
    if op==75:
        a=get(o,G_A)
        if get(w,a+8)!=10 or class_is_subclass(w,a,get(w,320))==False:
            return done(o,2)
        if get(w,get(o,G_B)+8)!=11:
            return done(o,2)
        if readword(s,72)!=0 or readword(s,80)!=0 or readword(s,88)!=0:
            namespace=cap_lookup(w,readword(s,72),readword(s,80),readword(s,88))
            if namespace==0:
                return done(o,1)
            if get(w,namespace+8)!=6:
                return done(o,2)
            put(o,G_C,namespace)
    if op==33:
        name=native_base(w,get(o,G_A))
        if get(w,name+8)!=4 or get(w,get(o,G_B)+8)!=5 or get(w,get(o,G_C)+8)!=6:
            return done(o,2)
        error=native_name(w,name)
        if error!=0:
            return done(o,error)
        bases=get(o,G_B)
        i=0
        while i<get(w,bases+16):
            base=get(w,get(w,bases+24)+i*8)
            if get(w,base+8)!=10:
                return done(o,2)
            id=get(w,get(w,base+24)+40)
            if id==4 or (id>=10 and id<=13) or (id>=32 and id<=34):
                return done(o,18)
            i=i+1
    if op==34 or op==39:
        if get(w,native_base(w,get(o,G_B))+8)!=4:
            return done(o,2)
    if op==35:
        a=get(o,G_A)
        if get(w,a+8)!=10:
            return done(o,2)
        layout=get(w,get(w,a+24)+32)
        if layout!=0 and layout!=6 and layout!=7 and layout!=14:
            return done(o,18)
        if layout==0:
            if readword(s,72)!=0 or readword(s,80)!=0 or readword(s,88)!=0:
                return done(o,7)
        else:
            c=cap_lookup(w,readword(s,72),readword(s,80),readword(s,88))
            if c==0:
                return done(o,1)
            if (layout==6 and get(w,c+8)!=4) or (layout==7 and get(w,c+8)!=7) or (layout==14 and get(w,c+8)!=5):
                return done(o,2)
            if layout==14:
                i=0
                while i<get(w,c+16):
                    child=get(w,get(w,c+24)+i*8)
                    if get(w,native_base(w,child)+8)!=4:
                        return done(o,2)
                    i=i+1
            put(o,G_C,c)
    if op==37 and get(w,get(o,G_B)+8)!=10:
        return done(o,2)
    if op==39 and get(w,get(o,G_A)+8)!=10:
        a=get(o,G_A)
        if get(w,a+8)!=8 or get(w,get(w,a+24)+40)==0:
            return done(o,2)
    put(o,G_COUNT,choose(op==34 or op==37,0,1))
    put(o,G_PHASE,1)
    return 10
def class_finish(o:mutbuf,w:mutbuf,status:u64) -> u64:
    deallocate(w,get(o,G_RANDOM))
    put(o,G_RANDOM,0)
    deallocate(w,get(o,800))
    deallocate(w,get(o,816))
    deallocate(w,get(o,832))
    put(o,800,0)
    put(o,816,0)
    put(o,832,0)
    return done(o,status)
def class_links(w:mutbuf,obj:u64) -> u64:
    i=0
    n=managed_count(w,obj)
    while i<n:
        child=managed_child(w,obj,i)
        if child!=0:
            edge_add(w,child)
        i=i+1
    return 0
def class_catalog(w:mutbuf) -> bool:
    while get(w,152)<37:
        id=get(w,152)+1
        obj=class_builtin(w,id)
        if obj==0:
            return False
        class_links(w,obj)
        edge_add(w,obj)
        put(w,160+(id-1)*8,obj)
        put(w,152,id)
    return True
def class_catalog_extended(w:mutbuf) -> bool:
    while get(w,152)<42:
        id=get(w,152)+1
        obj=class_builtin(w,id)
        if obj==0:
            return False
        class_links(w,obj)
        edge_add(w,obj)
        put(w,160+(id-1)*8,obj)
        put(w,152,id)
    return True
def class_exception(o:mutbuf,w:mutbuf) -> u64:
    namespace=get(o,G_C)
    owned=namespace==0
    if owned:
        namespace=object_new(w,6)
        if namespace==0:
            return growth(o,w)
    obj=object_new(w,8)
    if obj==0:
        if owned:
            object_release(w,namespace)
        return growth(o,w)
    data=allocate(w,64)
    if data==0:
        object_unlink(w,obj)
        if owned:
            object_release(w,namespace)
        return growth(o,w)
    zero(w,data,64)
    cls=get(o,G_A)
    put(w,obj+24,data)
    put(w,obj+56,(obj^get(w,get(o,G_RANDOM)))*11400714819323198485)
    put(w,data+16,namespace)
    put(w,data+24,get(o,G_B))
    put(w,data+32,get(w,get(w,cls+24)))
    put(w,data+40,cls)
    put(w,data+48,3544429961563687240)
    if publish_one(o,w,obj)!=0:
        object_unlink(w,obj)
        if owned:
            object_release(w,namespace)
        return growth(o,w)
    class_links(w,obj)
    return class_finish(o,w,0)
def class_builtin(w:mutbuf,id:u64) -> u64:
    name=object_new(w,4)
    if name==0:
        return 0
    data=allocate(w,32)
    if data==0:
        object_unlink(w,name)
        return 0
    put(w,name+24,data)
    n=class_builtin_name(w,data,id)
    put(w,name+32,n)
    put(w,name+16,n)
    put(w,name+56,bytes_hash(w,data,n))
    namespace=object_new(w,6)
    if namespace==0:
        object_unlink(w,name)
        return 0
    obj=object_new(w,10)
    if obj==0:
        object_unlink(w,namespace)
        object_unlink(w,name)
        return 0
    data=allocate(w,128)
    if data==0:
        object_unlink(w,obj)
        object_unlink(w,namespace)
        object_unlink(w,name)
        return 0
    zero(w,data,128)
    put(w,obj+24,data)
    put(w,obj+32,128)
    put(w,obj+56,(obj^get(w,40))*11400714819323198485)
    put(w,data,name)
    put(w,data+8,namespace)
    put(w,data+40,id)
    class_builtin_shape(w,data,obj,id)
    return obj
def class_type(w:mutbuf,obj:u64) -> u64:
    kind=get(w,obj+8)
    if kind==8:
        return get(w,get(w,obj+24)+40)
    if kind==11 or kind==12:
        return get(w,obj+40)
    id=0
    if kind==0:
        id=10
    elif kind==1:
        id=4
    elif kind==2:
        id=3
    elif kind==3:
        id=5
    elif kind==4:
        id=6
    elif kind==5:
        id=8
    elif kind==6:
        id=9
    elif kind==7:
        id=7
    elif kind==9:
        id=11+get(w,get(w,obj+24)+32)
    elif kind==10:
        id=2
    if id==0:
        return 0
    return get(w,160+(id-1)*8)
def class_is_subclass(w:mutbuf,cls:u64,base:u64) -> bool:
    if cls==0:
        return False
    data=get(w,cls+24)
    at=data+64+get(w,data+16)*8
    i=0
    while i<get(w,data+24):
        if get(w,at+i*8)==base:
            return True
        i=i+1
    return False
def class_lookup(w:mutbuf,cls:u64,key:u64) -> u64:
    data=get(w,cls+24)
    at=data+64+get(w,data+16)*8
    i=0
    while i<get(w,data+24):
        owner=get(w,at+i*8)
        namespace=get(w,get(w,owner+24)+8)
        found=dict_find(w,namespace,key)
        if found!=MAX:
            return get(w,get(w,namespace+24)+found*32+8)
        i=i+1
    return 0
def class_clone_dict(w:mutbuf,source:u64) -> u64:
    obj=object_new(w,6)
    if obj==0:
        return 0
    if get(w,source+120)!=0:
        put(w,obj+120,1)
    i=0
    data=get(w,source+24)
    while i<get(w,source+112):
        key=get(w,data+i*32)
        if key!=0:
            if dict_reserve(w,obj)==False:
                object_release(w,obj)
                return 0
            dict_insert(w,obj,key,get(w,data+i*32+8))
        i=i+1
    return obj
def class_clone_list(w:mutbuf,source:u64,start:u64,n:u64) -> u64:
    obj=object_new(w,5)
    if obj==0:
        return 0
    if n>1152921504606846975:
        put(w,16,MAX)
        object_unlink(w,obj)
        return 0
    if n!=0:
        data=allocate(w,n*8)
        if data==0:
            object_unlink(w,obj)
            return 0
        put(w,obj+24,data)
        put(w,obj+40,n)
        i=0
        while i<n:
            child=get(w,source+start+i*8)
            put(w,data+i*8,child)
            edge_add(w,child)
            i=i+1
    put(w,obj+16,n)
    return obj
def class_execute(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=get(o,G_OP)
    a=get(o,G_A)
    result=0
    if op==32 or op==87:
        result=get(w,160+(readword(s,104)-1)*8)
    elif op==75:
        return class_exception(o,w)
    elif op==33:
        return class_project(o,w)
    elif op==34:
        return class_setattr(s,o,w)
    elif op==35:
        return class_instance(o,w)
    elif op==36:
        result=class_type(w,a)
        if result==0:
            return class_finish(o,w,2)
    elif op==37:
        put(o,G_KIND,1)
        put(o,G_N,choose(class_is_subclass(w,class_type(w,a),get(o,G_B)),1,0))
        return class_finish(o,w,0)
    elif op==38:
        return class_describe(s,o,w)
    elif op==39:
        cls=a
        if get(w,a+8)!=10:
            cls=class_type(w,a)
        result=class_lookup(w,cls,get(o,G_B))
        if result==0:
            return class_finish(o,w,3)
    if result==0:
        return class_finish(o,w,11)
    if publish_one(o,w,result)!=0:
        return growth(o,w)
    return class_finish(o,w,0)
def class_project(o:mutbuf,w:mutbuf) -> u64:
    bases=get(o,G_B)
    count=get(w,bases+16)
    actual=choose(count==0,1,count)
    if actual>576460752303423484:
        return class_finish(o,w,5)
    total=0
    i=0
    layout=0
    parser=0
    while i<actual:
        base=get(w,160)
        if count!=0:
            base=get(w,get(w,bases+24)+i*8)
        data=get(w,base+24)
        m=get(w,data+24)
        if m>MAX-total:
            return class_finish(o,w,5)
        total=total+m
        current=get(w,data+32)
        if current!=0:
            if layout!=0 and layout!=current:
                return class_finish(o,w,18)
            layout=current
        if parser==0:
            parser=get(w,data+48)
        i=i+1
    if total>MAX-actual or actual>(MAX-64)//16:
        return class_finish(o,w,5)
    frame=64+actual*16
    if total>(MAX-frame)//8 or total+actual>(MAX-96-actual*32)//8:
        return class_finish(o,w,5)
    frame=frame+total*8
    work=96+actual*32+(total+actual)*8
    if total>(MAX-32)//8:
        return class_finish(o,w,5)
    outn=32+total*8
    input=allocate(w,frame)
    if input==0:
        return growth(o,w)
    output=allocate(w,outn)
    if output==0:
        deallocate(w,input)
        return growth(o,w)
    scratch=allocate(w,work)
    if scratch==0:
        deallocate(w,input)
        deallocate(w,output)
        return growth(o,w)
    zero(w,input,64)
    put(w,input,3544417789307603272)
    put(w,input+8,actual)
    put(w,input+16,total)
    at=input+64
    i=0
    while i<actual:
        base=get(w,160)
        if count!=0:
            base=get(w,get(w,bases+24)+i*8)
        data=get(w,base+24)
        n=get(w,data+24)
        put(w,at,base)
        put(w,at+8,n)
        copy(w,at+16,data+64+get(w,data+16)*8,n*8)
        at=at+16+n*8
        i=i+1
    put(o,768,layout)
    put(o,776,parser)
    put(o,784,actual)
    put(o,800,input)
    put(o,808,frame)
    put(o,816,output)
    put(o,824,outn)
    put(o,832,scratch)
    put(o,840,work)
    put(o,G_PHASE,31)
    return role(o,10,1,input,frame,1,output,outn,1,scratch,work)
def class_create(o:mutbuf,w:mutbuf) -> u64:
    result=get(o,816)
    bases=get(o,784)
    mro=get(w,result+16)+1
    if bases>MAX-mro or bases+mro>(MAX-64)//8:
        return class_finish(o,w,5)
    n=64+(bases+mro)*8
    namespace=class_clone_dict(w,get(o,G_C))
    if namespace==0:
        return growth(o,w)
    obj=object_new(w,10)
    if obj==0:
        object_release(w,namespace)
        return growth(o,w)
    data=allocate(w,n)
    if data==0:
        object_unlink(w,obj)
        object_release(w,namespace)
        return growth(o,w)
    zero(w,data,64)
    put(w,obj+24,data)
    put(w,obj+32,n)
    put(w,obj+56,(obj^get(w,get(o,G_RANDOM)))*11400714819323198485)
    put(w,data,get(o,G_A))
    put(w,data+8,namespace)
    put(w,data+16,bases)
    put(w,data+24,mro)
    put(w,data+32,get(o,768))
    put(w,data+48,get(o,776))
    list=get(o,G_B)
    if get(w,list+16)==0:
        put(w,data+64,get(w,160))
    else:
        copy(w,data+64,get(w,list+24),bases*8)
    put(w,data+64+bases*8,obj)
    copy(w,data+64+(bases+1)*8,result+32,(mro-1)*8)
    if publish_one(o,w,obj)!=0:
        object_unlink(w,obj)
        object_release(w,namespace)
        return growth(o,w)
    class_links(w,obj)
    return class_finish(o,w,0)
def class_setattr(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    obj=get(o,G_A)
    data=get(w,obj+24)
    id=get(w,data+40)
    if id!=0 and (id<14 or id>20):
        return class_finish(o,w,18)
    key=get(o,G_B)
    plain=native_base(w,key)
    n=get(w,plain+32)
    at=get(w,plain+24)
    name=n==8 and get(w,at)==6872323076851130207
    bases=n==9 and get(w,at)==6877952602154360671 and byte(w,at+8)==95
    if bases:
        return class_finish(o,w,19)
    if name:
        if readword(s,104)!=0:
            return class_finish(o,w,18)
        value=get(o,G_C)
        actual=native_base(w,value)
        if get(w,actual+8)!=4:
            return class_finish(o,w,2)
        status=native_name(w,actual)
        if status!=0:
            return class_finish(o,w,status)
        old=get(w,data)
        edge_add(w,value)
        put(w,data,value)
        edge_drop(w,old)
        return class_finish(o,w,0)
    namespace=get(w,data+8)
    if get(w,key+8)!=4 and dict_general(w,namespace)==False:
        return growth(o,w)
    found=dict_find(w,namespace,key)
    if readword(s,104)!=0:
        if found==MAX:
            return class_finish(o,w,3)
        row=get(w,namespace+24)+found*32
        oldkey=get(w,row)
        oldvalue=get(w,row+8)
        put(w,row,0)
        put(w,row+8,0)
        put(w,namespace+16,get(w,namespace+16)-1)
        dict_rehash(w,namespace)
        edge_drop(w,oldkey)
        edge_drop(w,oldvalue)
        return class_finish(o,w,0)
    value=get(o,G_C)
    if found!=MAX:
        row=get(w,namespace+24)+found*32
        old=get(w,row+8)
        edge_add(w,value)
        put(w,row+8,value)
        edge_drop(w,old)
    else:
        if dict_reserve(w,namespace)==False:
            return growth(o,w)
        dict_insert(w,namespace,key,value)
    return class_finish(o,w,0)
def class_describe(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    data=get(w,get(o,G_A)+24)
    field=readword(s,104)
    result=0
    fresh=False
    if field==0:
        result=get(w,data)
    elif field==1:
        result=class_clone_list(w,data,64,get(w,data+16))
        fresh=True
    elif field==2:
        result=class_clone_list(w,data,64+get(w,data+16)*8,get(w,data+24))
        fresh=True
    else:
        result=class_clone_dict(w,get(w,data+8))
        fresh=True
    if result==0:
        return growth(o,w)
    if publish_one(o,w,result)!=0:
        if fresh:
            object_release(w,result)
        return growth(o,w)
    return class_finish(o,w,0)
def class_instance(o:mutbuf,w:mutbuf) -> u64:
    cls=get(o,G_A)
    classdata=get(w,cls+24)
    layout=get(w,classdata+32)
    if get(w,classdata+40)==6 or get(w,classdata+40)==7:
        if publish_one(o,w,get(o,G_C))!=0:
            return growth(o,w)
        return class_finish(o,w,0)
    base=get(o,G_C)
    ownbase=False
    if layout==14:
        base=class_clone_list(w,get(w,base+24),0,get(w,base+16))
        if base==0:
            return growth(o,w)
        ownbase=True
    obj=object_new(w,8)
    if obj==0:
        if ownbase:
            object_release(w,base)
        return growth(o,w)
    data=allocate(w,64)
    if data==0:
        object_unlink(w,obj)
        if ownbase:
            object_release(w,base)
        return growth(o,w)
    zero(w,data,64)
    put(w,obj+24,data)
    put(w,data+8,choose(layout==6,4,choose(layout==7,7,choose(layout==14,14,0))))
    put(w,data+16,get(o,G_B))
    put(w,data+24,base)
    put(w,data+40,cls)
    if layout==6 or layout==7:
        put(w,obj+16,get(w,base+16))
        put(w,obj+32,get(w,base+32))
        put(w,obj+56,get(w,base+56))
    else:
        put(w,obj+56,(obj^get(w,get(o,G_RANDOM)))*11400714819323198485)
    if publish_one(o,w,obj)!=0:
        object_unlink(w,obj)
        if ownbase:
            object_release(w,base)
        return growth(o,w)
    class_links(w,obj)
    return class_finish(o,w,0)
'''


def catalog_source(limit=37):
    result = ['def class_builtin_name(w:mutbuf,data:u64,id:u64) -> u64:']
    for index, (name, bases, mro, layout, parser) in enumerate(CATALOG[:limit], 1):
        result.append('    if id==' + str(index) + ':')
        raw = name.encode()
        for offset in range(0, len(raw), 8):
            part = raw[offset:offset+8]
            if len(part) == 8:
                result.append('        put(w,data+' + str(offset) + ',' + str(int.from_bytes(part, 'little')) + ')')
            else:
                for i, value in enumerate(part, offset):
                    result.append('        store(w,data+' + str(i) + ',' + str(value) + ')')
        result.append('        return ' + str(len(raw)))
    result.append('    return 0')
    result.append('def class_builtin_shape(w:mutbuf,data:u64,obj:u64,id:u64) -> u64:')
    for index, (name, bases, mro, layout, parser) in enumerate(CATALOG[:limit], 1):
        result.append('    if id==' + str(index) + ':')
        result.extend('        ' + x for x in (
            'put(w,data+16,' + str(len(bases)) + ')',
            'put(w,data+24,' + str(len(mro)+1) + ')',
            'put(w,data+32,' + str(layout) + ')',
            'put(w,data+48,' + str(parser) + ')'))
        for i, item in enumerate(bases):
            result.append('        put(w,data+' + str(64 + i*8) + ',get(w,' + str(160 + (item-1)*8) + '))')
        result.append('        put(w,data+' + str(64+len(bases)*8) + ',obj)')
        for i, item in enumerate(mro):
            result.append('        put(w,data+' + str(64+(len(bases)+1+i)*8) + ',get(w,' + str(160+(item-1)*8) + '))')
        result.append('        return 0')
    result.append('    return 0')
    return '\n'.join(result) + '\n'


def source_program():
    return resolve('result_value_classes', SOURCE + '\n' + catalog_source(len(CATALOG)) + '\n' + CORE)


def program():
    return document(source_program(), 'result_value_classes')


if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/result_value_classes.hepta'
    path.write_text(render_assembly(program()))
    print(path.name, path.stat().st_size, flush=True)
