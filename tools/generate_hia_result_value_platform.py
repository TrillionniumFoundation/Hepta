"""Native platform exception classes and capture records in the sole Value graph."""
from tools.generate_hia_result_value_common import ROOT, document, render_assembly, resolve
from tools.generate_hia_result_value_core import SOURCE as CORE
from tools.generate_hia_result_value_classes import SOURCE as CLASSES, CATALOG, catalog_source

# Existing class IDs and slots remain fixed. IDs >=48 use a separate arena-root table.
PLATFORM_CLASSES=(
 ('CaptureRejected',24),('ToolIdentityRejected',24),('PublicationRejected',24),
 ('ELFSharedABIRejected',24),('ObjectSymbolsRejected',24),
 ('CaptureFailure',1),('CaptureResult',1),('ConnectionError',25),
 ('BlockingIOError',25),('BrokenPipeError',55),('ChildProcessError',25),
 ('ConnectionAbortedError',55),('ConnectionRefusedError',55),('ConnectionResetError',55),
 ('FileExistsError',25),('FileNotFoundError',25),('InterruptedError',25),
 ('IsADirectoryError',25),('NotADirectoryError',25),('PermissionError',25),
 ('ProcessLookupError',25),('TimeoutError',25),('UnicodeDecodeError',43),
)
SUBPROCESS_CLASSES=(('SubprocessError',22),('TimeoutExpired',71))
BACKGROUND_CLASSES=(('BackgroundOptimizationRejected',24),)
OPTIMIZATION_CLASSES=(('_OptimizationFuture',37),)
HEAP_CLASSES=(('HIAHeapBoundRejected',24),)
SOURCE=r'''
def result_value_platform(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,G_PHASE)
    if phase==0:
        return platform_prepare(s,o,w)
    if phase==1:
        if platform_catalog(o,w)==False:
            return platform_growth(o,w)
        put(o,G_PHASE,10)
    if get(o,G_PHASE)==10:
        random=allocate(w,16)
        if random==0:
            return platform_growth(o,w)
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
        return platform_execute(s,o,w)
    return class_finish(o,w,11)
def platform_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    zero(o,256,448)
    zero(o,768,128)
    zero(o,1600,192)
    op=readword(s,8)
    put(o,G_OP,op)
    put(w,16,0)
    if op!=101 and op!=110 and op!=112 and op!=114 and op!=116:
        a=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
        if a==0:
            return done(o,1)
        put(o,G_A,a)
    if op==102 or op==103:
        a=get(o,G_A)
        if get(w,a+8)!=5 and get(w,a+8)!=11:
            return done(o,2)
        if get(w,a+16)!=choose(op==102,6,5):
            return done(o,7)
        if readword(s,48)!=0 or readword(s,56)!=0 or readword(s,64)!=0:
            cls=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
            if cls==0:
                return done(o,1)
            if get(w,cls+8)!=10 or class_is_subclass(w,cls,get(w,class_slot(choose(op==102,53,54))))==False:
                return done(o,2)
            put(o,G_C,cls)
    if op==104:
        a=get(o,G_A)
        if get(w,a+8)!=10 or class_is_subclass(w,a,get(w,class_slot(25)))==False:
            return done(o,2)
        b=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
        if b==0:
            return done(o,1)
        if get(w,b+8)!=11:
            return done(o,2)
        put(o,G_B,b)
    if op==108:
        status=platform_unicode_prepare(s,o,w)
        if status!=0:
            return done(o,status)
    if (op>=105 and op<=107) or op==109:
        obj=get(o,G_A)
        if get(w,obj+8)!=8:
            return done(o,2)
        data=get(w,obj+24)
        if get(w,data+48)!=3544429961563687240:
            return done(o,2)
        if op==105 and readword(s,104)!=5 and class_is_subclass(w,get(w,data+40),get(w,class_slot(25)))==False:
            return done(o,2)
        if op==109:
            if get(w,data+56)!=8 or get(w,data+64)!=2:
                return done(o,2)
            slots=get(w,data+136)
            if get(w,slots+16)!=13:
                return done(o,2)
        if op==106:
            b=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
            if b==0:
                return done(o,1)
            if readword(s,104)==2:
                if get(w,b+8)!=1:
                    return done(o,2)
            elif b!=get(w,128):
                if get(w,b+8)!=8 or get(w,get(w,b+24)+48)!=3544429961563687240:
                    return done(o,2)
            put(o,G_B,b)
    if get(w,112)>=4096:
        collect(w)
    put(w,112,get(w,112)+1)
    put(o,G_PHASE,1)
    return 10
def platform_growth(o:mutbuf,w:mutbuf) -> u64:
    action=growth(o,w)
    if action==0:
        return class_finish(o,w,get(o,P_ERROR))
    return action
def platform_catalog(o:mutbuf,w:mutbuf) -> bool:
    limit=70
    if get(o,G_OP)==110:
        limit=72
    elif get(o,G_OP)==112:
        limit=73
    elif get(o,G_OP)==114:
        limit=74
    elif get(o,G_OP)==116:
        limit=75
    while get(w,152)<limit:
        id=get(w,152)+1
        obj=class_builtin(w,id)
        if obj==0:
            return False
        class_links(w,obj)
        edge_add(w,obj)
        put(w,class_slot(id),obj)
        put(w,152,id)
    return True
def platform_sequence(o:mutbuf,w:mutbuf,kind:u64,id:u64,cls:u64,source:u64,n:u64,fromoutput:bool) -> u64:
    obj=object_new(w,kind)
    if obj==0:
        return 0
    data=allocate(w,choose(n==0,8,n*8))
    if data==0:
        object_unlink(w,obj)
        return 0
    put(w,obj+24,data)
    put(w,obj+16,n)
    put(w,obj+40,choose(cls==0,get(w,class_slot(id)),cls))
    put(w,obj+48,id)
    put(w,obj+56,(obj^get(w,40))*11400714819323198485)
    i=0
    while i<n:
        child=0
        if fromoutput:
            child=get(o,source+i*8)
        else:
            child=get(w,source+i*8)
        put(w,data+i*8,child)
        i=i+1
    class_links(w,obj)
    return obj
def platform_exception(w:mutbuf,cls:u64,args:u64,slots:u64,haswritten:u64) -> u64:
    namespace=object_new(w,6)
    if namespace==0:
        return 0
    obj=object_new(w,8)
    if obj==0:
        object_release(w,namespace)
        return 0
    data=allocate(w,choose(slots==0,64,144))
    if data==0:
        object_unlink(w,obj)
        object_release(w,namespace)
        return 0
    zero(w,data,choose(slots==0,64,144))
    put(w,obj+24,data)
    put(w,obj+56,(obj^get(w,40))*11400714819323198485)
    put(w,data+16,namespace)
    put(w,data+24,args)
    put(w,data+32,get(w,get(w,cls+24)))
    put(w,data+40,cls)
    put(w,data+48,3544429961563687240)
    if slots!=0:
        # The existing fifth managed edge owns an actual private slots tuple.
        # It does not use the native-resource marker or finalizer registry.
        put(w,data+56,8)
        put(w,data+64,haswritten)
        put(w,data+136,slots)
    class_links(w,obj)
    return obj
def platform_integer(o:mutbuf,w:mutbuf,obj:u64) -> u64:
    put(o,1680,0)
    put(o,1688,0)
    actual=native_base(w,obj)
    kind=get(w,actual+8)
    if kind==1:
        put(o,1688,1)
        return get(w,actual+48)
    if kind!=2:
        return 0
    data=get(w,actual+24)
    n=get(w,actual+32)
    if n==0:
        return 0
    start=0
    negative=byte(w,data)==45
    if negative:
        start=1
    if start==n:
        return 0
    put(o,1680,choose(negative,1,0))
    limit=9223372036854775807+choose(negative,1,0)
    value=0
    i=start
    while i<n:
        digit=byte(w,data+i)-48
        if digit>9 or value>limit//10 or (value==limit//10 and digit>limit%10):
            return 0
        value=value*10+digit
        i=i+1
    put(o,1688,1)
    return value
def platform_int_copy(w:mutbuf,source:u64) -> u64:
    actual=native_base(w,source)
    kind=get(w,actual+8)
    n=choose(kind==1,1,get(w,actual+32))
    obj=object_new(w,2)
    if obj==0:
        return 0
    data=allocate(w,n)
    if data==0:
        object_unlink(w,obj)
        return 0
    if kind==1:
        store(w,data,48+get(w,actual+48))
    else:
        copy(w,data,get(w,actual+24),n)
    put(w,obj+24,data)
    put(w,obj+32,n)
    put(w,obj+56,bytes_hash(w,data,n))
    return obj
def platform_has_index(w:mutbuf,obj:u64) -> bool:
    cls=class_type(w,obj)
    if cls==0:
        return False
    data=get(w,cls+24)
    mro=data+64+get(w,data+16)*8
    count=get(w,data+24)
    i=0
    while i<count:
        item=get(w,mro+i*8)
        namespace=get(w,get(w,item+24)+8)
        entries=get(w,namespace+24)
        used=get(w,namespace+112)
        j=0
        while j<used:
            key=get(w,entries+j*32)
            if key!=0:
                actual=native_base(w,key)
                if get(w,actual+8)==4 and get(w,actual+32)==9:
                    text=get(w,actual+24)
                    if get(w,text)==6879359912831967071 and byte(w,text+8)==95:
                        return True
            j=j+1
        i=i+1
    return False
def platform_os_class(number:u64) -> u64:
    if number==11 or number==114 or number==115:
        return 56
    if number==32 or number==108:
        return 57
    if number==10:
        return 58
    if number==103:
        return 59
    if number==111:
        return 60
    if number==104:
        return 61
    if number==17:
        return 62
    if number==2:
        return 63
    if number==4:
        return 64
    if number==21:
        return 65
    if number==20:
        return 66
    if number==1 or number==13:
        return 67
    if number==3:
        return 68
    if number==110:
        return 69
    return 25
def platform_os_error(o:mutbuf,w:mutbuf,source:u64) -> u64:
    cls=class_type(w,source)
    name=get(w,get(w,cls+24))
    n=get(w,name+32)
    obj=object_new(w,4)
    if obj==0:
        return 0
    data=allocate(w,n+41)
    if data==0:
        object_unlink(w,obj)
        return 0
    platform_range_message(w,data,get(w,name+24),n)
    put(w,obj+24,data)
    put(w,obj+16,get(w,name+16)+41)
    put(w,obj+32,n+41)
    put(w,obj+56,bytes_hash(w,data,n+41))
    put(o,1712,obj)
    args=platform_sequence(o,w,11,28,0,1712,1,True)
    if args==0:
        object_release(w,obj)
        return 0
    error=platform_exception(w,get(w,class_slot(24)),args,0,0)
    if error==0:
        object_release(w,args)
        return 0
    put(o,G_INDEX,2)
    return error
def platform_os_new(o:mutbuf,w:mutbuf) -> u64:
    cls=get(o,G_A)
    args=get(o,G_B)
    none=get(w,128)
    i=0
    while i<7:
        put(o,1600+i*8,none)
        i=i+1
    put(o,1656,get(w,136))
    put(o,1720,0)
    n=get(w,args+16)
    values=get(w,args+24)
    normalized=False
    ownwritten=False
    written=none
    if n>=2 and n<=5:
        err=get(w,values)
        put(o,1600,err)
        put(o,1608,get(w,values+8))
        if cls==get(w,class_slot(25)):
            number=platform_integer(o,w,err)
            if get(o,1688)==1 and get(o,1680)==0:
                cls=get(w,class_slot(platform_os_class(number)))
        if n>=3:
            filename=get(w,values+16)
            numberkind=get(w,native_base(w,filename)+8)
            if cls==get(w,class_slot(56)) and (numberkind==1 or numberkind==2):
                number=platform_integer(o,w,filename)
                if get(o,1688)==0:
                    return platform_os_error(o,w,filename)
                if get(o,1680)==0 or number!=1:
                    written=platform_int_copy(w,filename)
                    if written==0:
                        return 0
                    ownwritten=True
                    put(o,1632,written)
                    put(o,1720,1)
            elif cls==get(w,class_slot(56)) and platform_has_index(w,filename):
                put(o,P_ERROR,27)
                return 0
            elif filename!=none:
                put(o,1616,filename)
                if n>=5:
                    put(o,1624,get(w,values+32))
                normalized=True
    newargs=args
    if normalized:
        newargs=platform_sequence(o,w,11,28,0,values,2,False)
        if newargs==0:
            if ownwritten:
                object_release(w,written)
            return 0
    slots=platform_sequence(o,w,11,28,0,1600,8,True)
    if slots==0:
        if normalized:
            object_release(w,newargs)
        if ownwritten:
            object_release(w,written)
        return 0
    obj=platform_exception(w,cls,newargs,slots,get(o,1720))
    if obj==0:
        object_release(w,slots)
        if normalized:
            object_release(w,newargs)
        return 0
    return obj
def platform_unicode_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    args=get(o,G_A)
    if get(w,args+8)!=11:
        return 2
    if get(w,args+16)!=5:
        return 7
    cls=0
    encode=False
    if readword(s,48)!=0 or readword(s,56)!=0 or readword(s,64)!=0:
        cls=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
        if cls==0:
            return 1
        if get(w,cls+8)!=10:
            return 2
        encode=class_is_subclass(w,cls,get(w,class_slot(44)))
        if encode==False and class_is_subclass(w,cls,get(w,class_slot(70)))==False:
            return 2
    put(o,G_C,cls)
    values=get(w,args+24)
    i=0
    while i<5:
        field=get(w,values+i*8)
        kind=get(w,native_base(w,field)+8)
        if i==2 or i==3:
            if kind!=1 and kind!=2:
                if platform_has_index(w,field):
                    return 27
                return 2
            platform_integer(o,w,field)
            if get(o,1688)==0:
                return 4
        elif kind!=choose(i==1 and encode==False,7,4):
            return 2
        i=i+1
    return 0
def platform_unicode_new(o:mutbuf,w:mutbuf) -> u64:
    args=get(o,G_A)
    values=get(w,args+24)
    start=platform_int_copy(w,get(w,values+16))
    if start==0:
        return 0
    end=platform_int_copy(w,get(w,values+24))
    if end==0:
        object_release(w,start)
        return 0
    i=0
    while i<13:
        item=choose(i==7,get(w,136),get(w,128))
        if i>=8:
            item=get(w,values+(i-8)*8)
        put(o,1600+i*8,item)
        i=i+1
    put(o,1680,start)
    put(o,1688,end)
    slots=platform_sequence(o,w,11,28,0,1600,13,True)
    if slots==0:
        object_release(w,start)
        object_release(w,end)
        return 0
    cls=get(o,G_C)
    if cls==0:
        cls=get(w,class_slot(70))
    obj=platform_exception(w,cls,args,slots,2)
    if obj==0:
        object_release(w,slots)
    return obj
def platform_chain_set(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    obj=get(o,G_A)
    olddata=get(w,obj+24)
    oldslots=0
    if get(w,olddata+56)==8:
        oldslots=get(w,olddata+136)
    n=8
    if oldslots!=0 and get(w,oldslots+16)==13:
        n=13
    i=0
    while i<n:
        item=choose(i==7,get(w,136),get(w,128))
        if oldslots!=0 and i<get(w,oldslots+16):
            item=get(w,get(w,oldslots+24)+i*8)
        put(o,1600+i*8,item)
        i=i+1
    selector=readword(s,104)
    put(o,1640+selector*8,get(o,G_B))
    if selector==0:
        put(o,1656,get(w,144))
    slots=platform_sequence(o,w,11,28,0,1600,n,True)
    if slots==0:
        return platform_growth(o,w)
    data=olddata
    if oldslots==0:
        data=allocate(w,144)
        if data==0:
            object_release(w,slots)
            return platform_growth(o,w)
        zero(w,data,144)
        copy(w,data,olddata,64)
    if publish_one(o,w,get(w,128))!=0:
        object_release(w,slots)
        if data!=olddata:
            deallocate(w,data)
        return platform_growth(o,w)
    edge_add(w,slots)
    put(w,data+56,8)
    put(w,data+136,slots)
    put(w,obj+24,data)
    if oldslots!=0:
        edge_drop(w,oldslots)
    if data!=olddata:
        deallocate(w,olddata)
    put(o,P_DROP_KNOWN,1)
    put(o,P_DROP_CONSUMED,1)
    return class_finish(o,w,0)
def platform_execute(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=get(o,G_OP)
    result=0
    fresh=False
    put(o,G_INDEX,1)
    if op==106:
        return platform_chain_set(s,o,w)
    if op==107:
        selector=readword(s,104)
        result=choose(selector==2,get(w,136),get(w,128))
        data=get(w,get(o,G_A)+24)
        if get(w,data+56)==8:
            slots=get(w,data+136)
            if get(w,slots+16)>5+selector:
                result=get(w,get(w,slots+24)+(5+selector)*8)
    elif op==108:
        result=platform_unicode_new(o,w)
        fresh=True
    elif op==109:
        data=get(w,get(o,G_A)+24)
        slots=get(w,data+136)
        result=get(w,get(w,slots+24)+(8+readword(s,104))*8)
    elif op==101 or op==110 or op==112 or op==114 or op==116:
        result=get(w,class_slot(readword(s,104)))
    elif op==102 or op==103:
        a=get(o,G_A)
        id=choose(op==102,53,54)
        result=platform_sequence(o,w,12,id,get(o,G_C),get(w,a+24),get(w,a+16),False)
        fresh=True
    elif op==104:
        result=platform_os_new(o,w)
        fresh=True
    elif op==105:
        obj=get(o,G_A)
        data=get(w,obj+24)
        field=readword(s,104)
        if field==5:
            result=get(w,data+24)
        elif get(w,data+56)!=8:
            if field==4:
                return class_finish(o,w,3)
            result=get(w,128)
        elif field==4 and get(w,data+64)==0:
            return class_finish(o,w,3)
        else:
            slots=get(w,data+136)
            result=get(w,get(w,slots+24)+field*8)
    if result==0:
        if get(o,P_ERROR)!=0:
            return class_finish(o,w,get(o,P_ERROR))
        return platform_growth(o,w)
    if publish_one(o,w,result)!=0:
        if fresh:
            object_release(w,result)
        return platform_growth(o,w)
    put(o,P_DROP_KNOWN,1)
    put(o,P_DROP_CONSUMED,1)
    return class_finish(o,w,0)
'''
def platform_catalog_source():
    result=['def platform_builtin_name(w:mutbuf,data:u64,id:u64) -> u64:',
            '    if id<48:','        return class_builtin_name(w,data,id)']
    catalog=list(CATALOG)
    for index,(name,base)in enumerate(PLATFORM_CLASSES+SUBPROCESS_CLASSES+BACKGROUND_CLASSES+OPTIMIZATION_CLASSES+HEAP_CLASSES,48):
        mro=(base,)+catalog[base-1][2]
        catalog.append((name,(base,),mro,0 if index==74 else index if index in(53,54)else 21,0))
        result.append('    if id=='+str(index)+':')
        raw=name.encode('ascii')
        for offset in range(0,len(raw),8):
            chunk=raw[offset:offset+8]
            if len(chunk)==8:result.append(f'        put(w,data+{offset},{int.from_bytes(chunk,"little")})')
            else:
                for j,bytevalue in enumerate(chunk,offset):result.append(f'        store(w,data+{j},{bytevalue})')
        result.append(f'        return {len(raw)}')
    result+=['    return 0','def platform_builtin_shape(w:mutbuf,data:u64,obj:u64,id:u64) -> u64:',
             '    if id<48:','        return class_builtin_shape(w,data,obj,id)']
    result+=['    base=0','    layout=21']
    for index,(name,bases,mro,layout,parser)in enumerate(catalog[47:],48):
        assert len(bases)==1 and parser==0
        result.append(f'    if id=={index}:')
        result.append(f'        base={bases[0]}')
        if layout!=21:result.append(f'        layout={layout}')
    result+=['    if base==0:','        return 0',
             '    parent=get(w,class_slot(base))','    parent_data=get(w,parent+24)',
             '    n=get(w,parent_data+24)',
             '    put(w,data+16,1)','    put(w,data+24,n+1)',
             '    put(w,data+32,layout)','    put(w,data+48,0)',
             '    put(w,data+64,parent)','    put(w,data+72,obj)',
             '    copy(w,data+80,parent_data+64+get(w,parent_data+16)*8,n*8)']
    result+=['    return 0','def platform_range_message(w:mutbuf,data:u64,name:u64,n:u64) -> u64:']
    before=b"cannot fit '";after=b"' into an index-sized integer"
    assert len(before)+len(after)==41
    for j,value in enumerate(before):result.append(f'    store(w,data+{j},{value})')
    result.append(f'    copy(w,data+{len(before)},name,n)')
    for j,value in enumerate(after,len(before)):result.append(f'    store(w,data+n+{j},{value})')
    result.append('    return 0')
    return '\n'.join(result)+'\n'
def source_program():
    classes=CLASSES.replace('class_builtin_name(w,data,id)','platform_builtin_name(w,data,id)').replace('class_builtin_shape(w,data,obj,id)','platform_builtin_shape(w,data,obj,id)')
    return resolve('result_value_platform',SOURCE+'\n'+classes+'\n'+catalog_source(len(CATALOG))+'\n'+platform_catalog_source()+'\n'+CORE)
def program():return document(source_program(),'result_value_platform')
if __name__=='__main__':
    target=ROOT/'examples/hia_bootstrap/result_value_platform.hepta'
    target.write_text(render_assembly(program()))
    print(target.name,target.stat().st_size,flush=True)
