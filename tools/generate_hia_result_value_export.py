"""Owned detached JSON snapshots of mutable HIA values, with iterative cycle detection."""
import ast
from tools.generate_hia_result_value_common import ROOT,document,render_assembly,resolve
from tools.generate_hia_result_value_core import SOURCE as CORE
SOURCE=r'''
def result_value_export(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,G_PHASE)
    if phase==0:
        zero(o,256,448)
        put(o,G_OP,18)
        p=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
        if p==0:
            return done(o,1)
        put(o,G_RESULT,p)
        put(o,G_PHASE,1)
        return 10
    if phase==1:
        stack=allocate(w,4096)
        if stack==0:
            return export_growth(o,w,1)
        put(o,G_STACK,stack)
        put(o,G_AUX,128)
        put(o,G_PHASE,10)
        return 10
    if phase==10:
        put(o,G_MODE,0)
        put(o,G_ITER,0)
        put(o,G_AUX_N,0)
        put(o,G_TEMP,0)
        status=walk(o,w)
        if status==5:
            return export_growth(o,w,1)
        if status!=0:
            return export_done(o,w,status)
        if get(o,G_TEMP)!=0:
            return export_done(o,w,10)
        put(o,G_REQUIRED,get(o,G_ITER))
        put(o,G_PHASE,20)
        return 10
    if phase==20:
        obj=object_new(w,7)
        if obj==0:
            return export_growth(o,w,20)
        n=get(o,G_REQUIRED)
        data=allocate(w,n)
        if data==0:
            object_release(w,obj)
            return export_growth(o,w,20)
        put(w,obj+24,data)
        put(w,obj+32,n)
        put(w,obj+16,n)
        put(o,G_NEWOBJ,obj)
        put(o,G_OUT,data)
        put(o,G_MODE,1)
        put(o,G_ITER,0)
        put(o,G_AUX_N,0)
        put(o,G_TEMP,0)
        status=walk(o,w)
        if status!=0 or get(o,G_ITER)!=n:
            return export_done(o,w,11)
        put(w,obj+56,bytes_hash(w,data,n)^13787848793156543929)
        put(o,G_PHASE,30)
        return 10
    if phase==30:
        random=allocate(w,16)
        if random==0:
            object_release(w,get(o,G_NEWOBJ))
            put(o,G_NEWOBJ,0)
            return export_growth(o,w,20)
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
            return export_done(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+r)
        if get(o,G_RUSED)!=16:
            return 5
        if publish_one(o,w,get(o,G_NEWOBJ))!=0:
            object_release(w,get(o,G_NEWOBJ))
            put(o,G_NEWOBJ,0)
            deallocate(w,get(o,G_RANDOM))
            put(o,G_RANDOM,0)
            return export_growth(o,w,20)
        put(o,G_NEWOBJ,0)
        return export_done(o,w,0)
    return export_done(o,w,11)
def unmark_stack(o:mutbuf,w:mutbuf) -> u64:
    i=0
    while i<get(o,G_AUX_N):
        p=get(w,get(o,G_STACK)+i*32)
        put(w,p+96,0)
        i=i+1
    put(o,G_AUX_N,0)
    return 0
def export_done(o:mutbuf,w:mutbuf,status:u64) -> u64:
    unmark_stack(o,w)
    object_release(w,get(o,G_NEWOBJ))
    put(o,G_NEWOBJ,0)
    deallocate(w,get(o,G_STACK))
    deallocate(w,get(o,G_RANDOM))
    put(o,G_STACK,0)
    put(o,G_RANDOM,0)
    return done(o,status)
def export_growth(o:mutbuf,w:mutbuf,next:u64) -> u64:
    unmark_stack(o,w)
    if next==1:
        deallocate(w,get(o,G_STACK))
        put(o,G_STACK,0)
    put(o,G_PHASE,next)
    action=growth(o,w)
    if action==0:
        return export_done(o,w,get(o,P_ERROR))
    return action
def emit(o:mutbuf,w:mutbuf,value:u64) -> u64:
    at=get(o,G_ITER)
    if at==MAX:
        return 5
    if get(o,G_MODE)!=0:
        store(w,get(o,G_OUT)+at,value)
    put(o,G_ITER,at+1)
    return 0
def raw(o:mutbuf,w:mutbuf,at:u64,n:u64) -> u64:
    if n>MAX-get(o,G_ITER):
        return 5
    if get(o,G_MODE)!=0:
        copy(w,get(o,G_OUT)+get(o,G_ITER),at,n)
    put(o,G_ITER,get(o,G_ITER)+n)
    return 0
def literal(o:mutbuf,w:mutbuf,value:u64,n:u64) -> u64:
    if n>MAX-get(o,G_ITER):
        return 5
    i=0
    while i<n:
        emit(o,w,(value>>(i*8))&255)
        i=i+1
    return 0
def quoted(o:mutbuf,w:mutbuf,at:u64,n:u64) -> u64:
    if n>(MAX-get(o,G_ITER)-2)//6:
        return 5
    emit(o,w,34)
    i=0
    while i<n:
        b=byte(w,at+i)
        if b==237 and i+1<n and byte(w,at+i+1)>=160:
            put(o,G_TEMP,1)
        if b==34 or b==92:
            emit(o,w,92)
            emit(o,w,b)
        elif b==8 or b==9 or b==10 or b==12 or b==13:
            emit(o,w,92)
            if b==8:
                emit(o,w,98)
            elif b==9:
                emit(o,w,116)
            elif b==10:
                emit(o,w,110)
            elif b==12:
                emit(o,w,102)
            else:
                emit(o,w,114)
        elif b<32:
            literal(o,w,808482140,4)
            emit(o,w,48+(b>>4))
            low=b&15
            emit(o,w,choose(low<10,48+low,87+low))
        else:
            emit(o,w,b)
        i=i+1
    emit(o,w,34)
    return 0
def scalar(o:mutbuf,w:mutbuf,obj:u64,key:bool) -> u64:
    obj=native_base(w,obj)
    kind=get(w,obj+8)
    if kind==4:
        return quoted(o,w,get(w,obj+24),get(w,obj+32))
    if kind==5 or kind==6 or kind==7:
        return 2
    if key:
        emit(o,w,34)
    if kind==0:
        literal(o,w,1819047278,4)
    elif kind==1:
        if get(w,obj+48)==0:
            literal(o,w,435728179558,5)
        else:
            literal(o,w,1702195828,4)
    elif kind==2:
        at=get(w,obj+24)
        n=get(w,obj+32)
        digits=n
        if byte(w,at)==45:
            digits=digits-1
        if get(w,48)!=0 and digits>get(w,48):
            return 8
        status=raw(o,w,at,n)
        if status!=0:
            return status
    elif kind==3:
        if ((get(w,obj+48)>>52)&2047)==2047:
            return 8
        status=raw(o,w,get(w,obj+24),get(w,obj+32))
        if status!=0:
            return status
    else:
        return 2
    if key:
        emit(o,w,34)
    return 0
def push(o:mutbuf,w:mutbuf,obj:u64) -> u64:
    if get(w,obj+96)==3:
        return 8
    depth=get(o,G_AUX_N)
    cap=get(o,G_AUX)
    if depth==cap:
        if cap>144115188075855871:
            put(w,16,MAX)
            return 5
        next=allocate(w,cap*64)
        if next==0:
            return 5
        copy(w,next,get(o,G_STACK),depth*32)
        deallocate(w,get(o,G_STACK))
        put(o,G_STACK,next)
        put(o,G_AUX,cap*2)
    frame=get(o,G_STACK)+depth*32
    zero(w,frame,32)
    put(w,frame,obj)
    put(o,G_AUX_N,depth+1)
    put(w,obj+96,3)
    if get(w,obj+8)==5 or get(w,obj+8)==11:
        emit(o,w,91)
    else:
        emit(o,w,123)
    return 0
def visit(o:mutbuf,w:mutbuf,obj:u64) -> u64:
    kind=get(w,obj+8)
    if kind==5 or kind==6 or kind==11:
        return push(o,w,obj)
    return scalar(o,w,obj,False)
def walk(o:mutbuf,w:mutbuf) -> u64:
    status=visit(o,w,get(o,G_RESULT))
    if status!=0:
        return status
    while get(o,G_AUX_N)!=0:
        frame=get(o,G_STACK)+(get(o,G_AUX_N)-1)*32
        obj=get(w,frame)
        index=get(w,frame+8)
        n=get(w,obj+16)
        kind=get(w,obj+8)
        if index==n:
            if kind==5 or kind==11:
                emit(o,w,93)
            else:
                emit(o,w,125)
            put(w,obj+96,0)
            put(o,G_AUX_N,get(o,G_AUX_N)-1)
        else:
            if index!=0:
                emit(o,w,44)
            put(w,frame+8,index+1)
            child=0
            if kind==5 or kind==11:
                child=get(w,get(w,obj+24)+index*8)
            else:
                at=get(w,frame+16)
                data=get(w,obj+24)
                while at<get(w,obj+112) and get(w,data+at*32)==0:
                    at=at+1
                if at==get(w,obj+112):
                    return 11
                put(w,frame+16,at+1)
                status=scalar(o,w,get(w,data+at*32),True)
                if status!=0:
                    return status
                emit(o,w,58)
                child=get(w,data+at*32+8)
            status=visit(o,w,child)
            if status!=0:
                return status
    return 0
'''
def source_program():
 helper='\n'.join(ast.get_source_segment(CORE,n) for n in ast.parse(CORE).body if n.name=='publish_one')
 return resolve('result_value_export',SOURCE+'\n'+helper)
def program():return document(source_program(),'result_value_export')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/result_value_export.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)

