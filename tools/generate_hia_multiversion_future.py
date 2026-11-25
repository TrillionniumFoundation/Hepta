"""Native private Future/token owner with actual futex locks and lock-free callbacks.

The enclosing runtime owns the Future workspace and its strong result/closure
handles. This entry never stands in for the optimizer's ranking/publication logic.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly

import ast
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
class FutureBuilder(Builder):
    def expr(self,node):
        if isinstance(node,ast.BinOp) and isinstance(node.op,(ast.FloorDiv,ast.Mod)):
            a,b=self.expr(node.left),self.expr(node.right)
            return self.op('int.div.checked' if isinstance(node.op,ast.FloorDiv) else 'int.rem.checked',[a,b],a[1])
        return super().expr(node)
def document(source,module):
    nodes=ast.parse(source).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=FutureBuilder(node,names,sigs,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(p) for p in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':module,'functions':functions})
def split_dispatch(source):
    tree=ast.parse(source);entry=tree.body[0]
    groups={'future_transition':[],'future_callbacks':[],'future_wait':[],'future_destroy':[]}
    other=[]
    for node in entry.body:
        test=node.test if isinstance(node,ast.If) else None
        phase=(test.comparators[0].value if isinstance(test,ast.Compare) and isinstance(test.left,ast.Name) and test.left.id=='phase' and len(test.ops)==1 and isinstance(test.ops[0],ast.Eq) and isinstance(test.comparators[0],ast.Constant) else None)
        group=None
        if phase in [113,210,300,301,304,305,310,320,321,322,400,401,402,404,410]:group='future_callbacks'
        elif phase in [115,500,501,502]:group='future_wait'
        elif phase in [116,600,601,602,610]:group='future_destroy'
        elif phase is not None and 110<=phase<200:group='future_transition'
        if group:groups[group].append(node)
        else:other.append(node)
    assert len(groups['future_transition'])==13
    tail=other.pop();assert isinstance(tail,ast.Return)
    routing=ast.parse('''
if phase==113 or phase==210 or (phase>=300 and phase<500):
    return future_callbacks(s,o,w,phase)
if phase==115 or (phase>=500 and phase<600):
    return future_wait(s,o,w,phase)
if phase==116 or (phase>=600 and phase<700):
    return future_destroy(s,o,w,phase)
if phase>=110 and phase<200:
    return future_transition(s,o,w,phase)
''').body
    entry.body=other+routing+[tail]
    for name,body in groups.items():
        function=ast.parse('def '+name+'(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:\n    return finish(o,w,65)\n').body[0]
        function.body=body+function.body;tree.body.append(function)
    return ast.unparse(ast.fix_missing_locations(tree))+'\n'

ROOT=Path(__file__).resolve().parents[1]
C={'MAGIC':int.from_bytes(b'HIAMVFS1','little'),'INPUT_MAGIC':int.from_bytes(b'HIAMVFQ1','little'),'INPUT_MAGIC2':int.from_bytes(b'HIAMVFQ2','little'),
'OUTPUT_MAGIC':int.from_bytes(b'HIAMVFR1','little'),'NONE':(1<<64)-1,'NEGATIVE':(1<<64)-4095,
'PHASE':64,'OP':72,'NEXT':80,'LOCK':88,'VALUE':96,'ERROR':104,'CURSOR':112,'CALLBACK':120,'ARGUMENT':128,
'SEEN':136,'CAUGHT':144,'IMMEDIATE':152,'NODE':200,'SAVED_STATE':224,'SAVED_TOKEN':232,'ENTERED':240,
'NODEBUF':256,'TIME':352,'REMAIN':368,'START_SEC':176,'START_NANO':184,'STARTED':192}
SOURCE=r'''
def future(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=64 or length(o)<512 or length(w)<512:
        return 4294967293
    if readword(s,0)==INPUT_MAGIC:
        if readword(s,8)>10 or readword(s,48)!=0 or readword(s,56)!=0:
            return 4294967293
    elif readword(s,0)==INPUT_MAGIC2:
        op=readword(s,8)
        if op<11 or op>16:
            return 4294967293
        i=16
        while i<64:
            if (op!=11 and op!=12) or i>24:
                if readword(s,i)!=0:
                    return 4294967293
            i=i+8
        if (op==11 or op==12) and readword(s,16)==0:
            return 4294967293
    else:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        put(o,OP,readword(s,8))
        put(o,VALUE,0)
        put(o,ERROR,0)
        put(o,SEEN,0)
        put(o,CAUGHT,0)
        put(o,ENTERED,0)
        put(o,STARTED,0)
        put(o,IMMEDIATE,0)
        put(o,SAVED_STATE,0)
        put(o,SAVED_TOKEN,0)
        put(o,216,0)
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase==1:
        pid=get(o,448)
        if pid==0 or pid>=NEGATIVE:
            return finish(o,w,65)
        if get(o,OP)==0:
            if get(w,0)!=0:
                return finish(o,w,3)
            zero(w,0,512)
            put(w,0,MAGIC)
            put(w,8,pid)
            return finish(o,w,0)
        if get(w,0)!=MAGIC or get(w,8)!=pid or get(w,80)!=0:
            return finish(o,w,65)
        if get(o,OP)==4 and readword(s,16)==0:
            return finish(o,w,3)
        if get(o,OP)==6 and readword(s,24)>1:
            return finish(o,w,3)
        return lock(o,128,100)
    if phase>=20 and phase<=23:
        return lock_phase(o,phase)
    if phase==100:
        if get(w,80)!=0:
            put(o,ERROR,65)
            return release_finished(o,w)
        put(w,72,get(w,72)+1)
        put(o,ENTERED,1)
        op=get(o,OP)
        if op==1:
            return again(o,110)
        if op==2:
            return again(o,111)
        if op==3:
            return unlock(o,128,150)
        if op==4:
            return again(o,113)
        if op==5:
            put(o,VALUE,get(w,32))
            return release_finished(o,w)
        if op==6:
            return again(o,115)
        if op==7 or op==8 or op==9:
            return unlock(o,128,170)
        if op==11 or op==12:
            return again(o,180)
        if op==13:
            return again(o,181)
        if op==14:
            put(o,VALUE,get(w,96))
            return release_finished(o,w)
        if op==15:
            put(o,VALUE,get(w,32))
            return release_finished(o,w)
        if op==16:
            return again(o,182)
        return again(o,116)
    if phase==110:
        if get(w,16)!=0:
            put(o,VALUE,choose(get(w,16)==1,1,0))
            return release_finished(o,w)
        return unlock(o,128,120)
    if phase==120:
        return lock(o,132,130)
    if phase==130:
        if get(w,64)==2:
            put(o,VALUE,0)
            return unlock(o,132,800)
        put(w,64,1)
        return unlock(o,132,135)
    if phase==135:
        return lock(o,128,140)
    if phase==140:
        if get(w,16)!=0:
            put(o,VALUE,choose(get(w,16)==1,1,0))
            return release_finished(o,w)
        if get(w,96)!=0:
            put(o,VALUE,0)
            return release_finished(o,w)
        put(w,16,1)
        put(w,24,1)
        put(o,VALUE,1)
        return notify(o,w)
    if phase==111:
        if get(w,16)!=0:
            return unlock(o,128,320)
        # Original _complete checks done under one condition acquisition, then
        # set_result acquires it again. Preserve a competing completion between
        # the two checks: only a concurrently cancelled state is suppressed.
        return unlock(o,128,321)
    if phase==321:
        return lock(o,128,322)
    if phase==322:
        if get(w,16)!=0:
            if get(w,16)==2:
                put(o,ERROR,6)
            return unlock(o,128,320)
        put(w,32,readword(s,16))
        put(w,88,readword(s,24))
        put(w,96,0)
        put(w,112,1)
        put(w,16,2)
        put(w,24,1)
        return notify(o,w)
    if phase==150:
        return lock(o,132,151)
    if phase==151:
        if get(w,64)!=1:
            put(o,ERROR,3)
            return unlock(o,132,800)
        return unlock(o,132,135)
    if phase==170:
        return lock(o,132,171)
    if phase==171:
        op=get(o,OP)
        token=get(w,64)
        if op==7:
            if token!=1:
                put(w,64,2)
                put(o,VALUE,1)
        elif op==8:
            if token!=2:
                put(w,64,1)
                put(o,VALUE,1)
        else:
            put(o,VALUE,token)
        return unlock(o,132,800)
    if phase==180:
        if get(w,16)!=0:
            put(o,ERROR,6)
            return release_finished(o,w)
        put(w,32,readword(s,16))
        put(w,88,readword(s,24))
        put(w,96,0)
        put(w,112,choose(get(o,OP)==12,2,1))
        put(w,16,2)
        put(w,24,1)
        return notify(o,w)
    if phase==181:
        if get(w,16)==1 and get(w,104)==0:
            put(w,104,1)
            put(o,VALUE,0)
            return release_finished(o,w)
        if get(w,16)==0 and get(w,96)==0:
            put(w,96,1)
            put(o,VALUE,1)
            return release_finished(o,w)
        put(o,ERROR,7)
        return release_finished(o,w)
    if phase==182:
        if get(w,16)!=1:
            put(o,VALUE,0)
            return release_finished(o,w)
        if get(w,104)!=0:
            put(o,ERROR,7)
            return release_finished(o,w)
        put(w,104,1)
        put(o,VALUE,1)
        return release_finished(o,w)
    if phase==210:
        put(o,CURSOR,get(w,40))
        put(o,IMMEDIATE,0)
        return unlock(o,128,300)
    if phase==300:
        if get(o,CURSOR)==0:
            return again(o,800)
        put(o,PHASE,301)
        put(o,0,get(o,CURSOR))
        return 4
    if phase==301:
        put(o,CALLBACK,get(o,NODEBUF+8))
        put(o,ARGUMENT,get(o,NODEBUF+16))
        put(o,CURSOR,get(o,NODEBUF))
        return invoke(o,304,get(o,CALLBACK),get(o,ARGUMENT))
    if phase==304:
        status=get(o,448)
        put(o,SEEN,get(o,SEEN)+1)
        if status==1:
            put(o,CAUGHT,get(o,CAUGHT)+1)
        elif status!=0:
            put(o,ERROR,4)
        if get(o,IMMEDIATE)==1:
            if readword(s,32)!=0:
                return drop(o,305,readword(s,32),readword(s,24))
            return again(o,800)
        if get(o,ERROR)!=0:
            return again(o,800)
        return again(o,300)
    if phase==305:
        return again(o,800)
    if phase==320:
        if readword(s,24)!=0:
            return drop(o,800,readword(s,24),readword(s,16))
        return again(o,800)
    if phase==113:
        if get(w,16)!=0:
            put(o,IMMEDIATE,1)
            return unlock(o,128,310)
        put(o,PHASE,400)
        return 6
    if phase==310:
        return invoke(o,304,readword(s,16),readword(s,24))
    if phase==400:
        pointer=get(o,448)
        if pointer==0:
            put(o,ERROR,5)
            return unlock(o,128,410)
        put(o,NODE,pointer)
        zero(o,NODEBUF,64)
        put(o,NODEBUF+8,readword(s,16))
        put(o,NODEBUF+16,readword(s,24))
        put(o,NODEBUF+24,readword(s,32))
        put(o,NODEBUF+32,readword(s,40))
        put(o,PHASE,401)
        put(o,0,pointer)
        return 5
    if phase==401:
        if get(w,48)==0:
            put(w,40,get(o,NODE))
            return again(o,404)
        put(o,PHASE,402)
        put(o,0,get(w,48))
        return 4
    if phase==402:
        put(o,NODEBUF,get(o,NODE))
        put(o,PHASE,404)
        put(o,0,get(w,48))
        return 5
    if phase==404:
        put(w,48,get(o,NODE))
        put(w,56,get(w,56)+1)
        return release_finished(o,w)
    if phase==410:
        if readword(s,32)!=0:
            return drop(o,800,readword(s,32),readword(s,24))
        return again(o,800)
    if phase==115:
        state=get(w,16)
        if state==1:
            put(o,ERROR,1)
            return release_finished(o,w)
        if state==2:
            put(o,VALUE,get(w,32))
            return release_finished(o,w)
        return unlock(o,128,500)
    if phase==500:
        return system(o,501,228,12,1,TIME,0,0,0,0)
    if phase==501:
        if get(o,448)!=0 or get(o,TIME+8)>=1000000000:
            put(o,ERROR,65)
            return again(o,800)
        if get(o,STARTED)==0:
            put(o,STARTED,1)
            put(o,START_SEC,get(o,TIME))
            put(o,START_NANO,get(o,TIME+8))
        timeout=readword(s,16)
        if readword(s,24)==0:
            sec=get(o,TIME)-get(o,START_SEC)
            ns=get(o,TIME+8)
            if ns<get(o,START_NANO):
                if sec==0:
                    put(o,ERROR,65)
                    return again(o,800)
                sec=sec-1
                ns=ns+1000000000
            ns=ns-get(o,START_NANO)
            if sec>timeout//1000000000 or (sec==timeout//1000000000 and ns>=timeout%1000000000):
                put(o,ERROR,2)
                return again(o,800)
            remaining=timeout-(sec*1000000000+ns)
            put(o,REMAIN,remaining//1000000000)
            put(o,REMAIN+8,remaining%1000000000)
            return system(o,502,202,193,16,128,0,REMAIN,0,0)
        return system(o,502,202,1,16,128,0,0,0,0)
    if phase==502:
        raw=get(o,448)
        if raw!=0 and raw!=NONE-3 and raw!=NONE-10 and raw!=NONE-109:
            put(o,ERROR,65)
            return again(o,800)
        return lock(o,128,115)
    if phase==116:
        if get(w,72)!=1:
            put(o,ERROR,3)
            return release_finished(o,w)
        put(o,CURSOR,get(w,40))
        put(w,80,1)
        return unlock(o,128,600)
    if phase==600:
        if get(o,CURSOR)==0:
            if get(w,88)!=0:
                put(o,CALLBACK,get(w,88))
                put(w,88,0)
                return drop(o,610,get(o,CALLBACK),get(w,32))
            return again(o,610)
        put(o,PHASE,601)
        put(o,0,get(o,CURSOR))
        return 4
    if phase==601:
        if get(o,NODEBUF+24)!=0:
            return drop(o,602,get(o,NODEBUF+24),get(o,NODEBUF+16))
        return again(o,602)
    if phase==602:
        put(o,NODE,get(o,CURSOR))
        put(o,CURSOR,get(o,NODEBUF))
        put(o,0,get(o,NODE))
        put(o,PHASE,600)
        return 7
    if phase==610:
        put(w,40,0)
        put(w,48,0)
        put(w,56,0)
        put(w,80,1)
        return again(o,800)
    if phase==800:
        return lock(o,128,810)
    if phase==810:
        return release_finished(o,w)
    if phase==820:
        return finish(o,w,get(o,ERROR))
    return finish(o,w,65)

def notify(o:mutbuf,w:mutbuf) -> u32:
    return system(o,210,202,1,16,129,2147483647,0,0,0)

def release_finished(o:mutbuf,w:mutbuf) -> u32:
    put(o,SAVED_STATE,get(w,16))
    put(o,SAVED_TOKEN,get(w,64))
    put(o,216,get(w,56))
    put(o,408,get(w,96))
    put(o,416,get(w,104))
    put(o,424,get(w,112))
    if get(o,ENTERED)==1:
        if get(w,72)==0:
            put(o,ERROR,65)
        else:
            put(w,72,get(w,72)-1)
        put(o,ENTERED,0)
    return unlock(o,128,820)

def lock(o:mutbuf,offset:u64,next:u64) -> u32:
    put(o,NEXT,next)
    put(o,LOCK,offset)
    put(o,PHASE,20)
    put(o,0,offset)
    put(o,8,0)
    put(o,16,1)
    return 2

def unlock(o:mutbuf,offset:u64,next:u64) -> u32:
    put(o,NEXT,next)
    put(o,LOCK,offset)
    put(o,PHASE,22)
    put(o,0,offset)
    put(o,8,0)
    return 3

def lock_phase(o:mutbuf,phase:u64) -> u32:
    if phase==20:
        if get(o,448)==0:
            return again(o,get(o,NEXT))
        return system(o,21,202,1,get(o,LOCK),128,1,0,0,0)
    if phase==21:
        return lock(o,get(o,LOCK),get(o,NEXT))
    if phase==22:
        return system(o,23,202,1,get(o,LOCK),129,1,0,0,0)
    return again(o,get(o,NEXT))

def invoke(o:mutbuf,next:u64,fn:u64,arg:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,fn)
    put(o,8,arg)
    return 8

def drop(o:mutbuf,next:u64,fn:u64,arg:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,fn)
    put(o,8,arg)
    return 9

def system(o:mutbuf,phase:u64,number:u64,pointers:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PHASE,phase)
    put(o,0,number)
    put(o,8,pointers)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def again(o:mutbuf,phase:u64) -> u32:
    put(o,PHASE,phase)
    return 10

def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    inherited=get(o,OP)>=11
    value=get(o,VALUE)
    state=get(o,SAVED_STATE)
    token=get(o,SAVED_TOKEN)
    callbacks=get(o,216)
    seen=get(o,SEEN)
    caught=get(o,CAUGHT)
    zero(o,0,128)
    put(o,0,OUTPUT_MAGIC)
    put(o,8,status)
    put(o,16,value)
    put(o,24,state)
    put(o,32,token)
    put(o,40,callbacks)
    put(o,48,seen)
    put(o,56,caught)
    put(o,64,get(w,8))
    if inherited:
        put(o,72,get(o,408))
        put(o,80,get(o,416))
        put(o,88,get(o,424))
    return 0

def zero(w:mutbuf,at:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(w,at+i,0)
        i=i+1
    return 0
def readword(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value
def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value
def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
'''
def source_program():
    s=SOURCE
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+name+r'\b',str(value),s)
    return split_dispatch(s)
def main():
    t=document(source_program(),'multiversion_future');p=ROOT/'examples/hia_bootstrap/multiversion_future.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
