"""Managed submission: real canonical Futures and BG-owned GC edges.
The retained SQ01/SQ02 domains and their native policies remain unchanged.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_submission_owner as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIABSM01',REPLY='HIABSMR1',CONTEXT='HIABSCC3',
 FREEZE_INPUT='HIABFZQ3',FREEZE_REPLY='HIABFZR3',
 TINPUT='HIABTC05',TRETRY='HIABTC06',TCONTEXT='HIABVC03',TREPLY='HIABTV03',
 PUBLIC_INPUT='HIABFP04',PUBLIC_DROP_INPUT='HIABFP04',PUBLIC_REPLY='HIABFRP3',PUBLIC_DROP_REPLY='HIABFRP3',
 JOB_INPUT='HIABJM01',JOB_DROP_INPUT='HIABJM01',JOB_REPLY='HIABJMR1',JOB_DROP_REPLY='HIABJMR1',
 CELL_QUERY_INPUT='HIABFQ06',CELL_QUERY_REPLY='HIABFR03',
 SM_PROVIDER_INPUT='HIAFRD01',SM_PROVIDER_REPLY='HIAFRDR1',
 SM_VPRIVATE='HIABVQ05',SM_VQUERY='HIABVQ06',SM_VFIXED='HIABVQ07').items()})
C.update(SM_BG=1024,SM_PIN=1048,SM_RAW=1072,SM_FID=1096,SM_EDGE=1120,
 SM_EDGE_ADOPT=1144,SM_META_ADOPT=1152,SM_QUEUE=1160,SM_MAP=1168,SM_UNKNOWN=1176,
 SM_VOP=1184,SM_CLEAN=1192,SM_SAVED=1200,SM_DELIVERED=1208,SM_NATIVE_PENDING=1216,SM_GLOBAL_PENDING=1224)
def replace(text,before,after):
    assert text.count(before)==1,before
    return text.replace(before,after)
def replace_def(text,name,body):
    lines=text.splitlines(True);node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name)
    return ''.join(lines[:node.lineno-1])+body.strip()+'\n'+''.join(lines[node.end_lineno:])
def source_template():
    text=replace(original.source_template(),'def submission_owner(','def submission_managed(')
    text=replace(text,'    phase=get(o,PHASE)\n    if phase==0:',
                 '    phase=get(o,PHASE)\n    if phase>=1000:\n        return managed(s,o,w,phase)\n    if phase==0:')
    text=replace(text,'used=word_load(s,8)==0 and at>=24 and at<=88',
                 'used=word_load(s,8)==0 and at>=24 and at<=112')
    text=replace(text,'    zero(o,128,3968)\n    zero(o,FREEZE_WORK,2048)',
                 '    if get(w,832)==0 or get(w,840)==0 or get(w,848)!=512 or get(w,856)==0 or get(w,864)==0:\n        return 4294967293\n    zero(o,128,3968)\n    zero(o,FREEZE_WORK,2048)')
    text=replace(text,'        return system(o,2,228,12,1,TS,0,0,0,0)\n    if phase==2:',
                 '        request(o,VALUE_INPUT,5)\n        copy_source(s,o,96,RQ+24,24)\n        return values(o,w,1000,128)\n    if phase==2:')
    text=replace(text,'            from_work(w,o,3072,128,CONTROL_N)',
                 '            from_work(w,o,3072,128,CONTROL_N)\n            from_work(w,o,7168,1024,1024)')
    text=replace(text,'    to_work(o,w,128,3072,CONTROL_N)',
                 '    to_work(o,w,128,3072,CONTROL_N)\n    to_work(o,w,1024,7168,1024)')
    text=replace(text,'''        request(o,PUBLIC_INPUT,4)
        from_work(w,o,104,RQ+16,24)
        from_work(w,o,128,RQ+40,24)
        return public(o,w,400)''','''        request(o,SM_PROVIDER_INPUT,0)
        from_work(w,o,104,RQ+16,24)
        from_work(w,o,128,RQ+64,24)
        return managed_provider(o,w,400)''')
    text=replace(text,'''        if public_take(o,w,FUSER)==0:
            return fail(o,public_failure(o),400)
        request(o,PUBLIC_INPUT,5)
        from_work(w,o,104,RQ+16,24)
        within(o,RQ+40,FUSER,24)
        return public(o,w,401)''','''        if managed_provider_take(o,FUSER)==0:
            return fail(o,7,400)
        request(o,SM_PROVIDER_INPUT,1)
        within(o,RQ+16,FUSER,24)
        return managed_provider(o,w,1004)''')
    text=replace(text,'''        put(o,KERNEL,get(o,RP+64))
        request(o,QINPUT,1)
        within(o,RQ+24,JOB,24)
        put(o,RQ+48,get(o,KERNEL))
        put(o,RQ+56,512)
        return queue(o,w,602)''','''        put(o,KERNEL,get(o,RP+64))
        request(o,VALUE_INPUT,5)
        within(o,RQ+24,FUSER,24)
        return values(o,w,1005,128)''')
    text=replace(text,'if get(w,at)!=0 or get(w,at+24)!=0 or get(w,at+48)!=0:',
                 'if get(w,at)!=0 or get(w,at+24)!=0 or get(w,at+48)!=0 or get(w,at+72)!=0:')
    text=replace(text,'        to_work(o,w,FBG,at+48,24)\n        zero(o,JOB,24)',
                 '        to_work(o,w,FBG,at+48,24)\n        to_work(o,w,SM_EDGE,at+72,24)\n        zero(o,SM_EDGE,24)\n        put(o,SM_EDGE_ADOPT,0)\n        put(o,SM_META_ADOPT,0)\n        zero(o,JOB,24)')
    text=replace(text,'(at==FUSER and get(o,ERROR)==0 and get(o,OP)==0)','at==FUSER')
    text=replace(text,'        if at==FUSER or at==FBG:','        if at==FBG:')
    text=replace(text,'        return again(o,790)\n    if phase==761:',
                 '        put(o,SM_CLEAN,0)\n        return again(o,1008)\n    if phase==761:')
    text=replace(text,'    put(o,RQ+8,op)\n    return 0',
                 '    put(o,RQ+8,op)\n    if magic==VALUE_INPUT or magic==VALUE_DROP_INPUT:\n        managed_value_packet(o)\n    return 0')
    text=replace(text,'def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:\n    return invoke',
                 'def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:\n    managed_value_packet(o)\n    return invoke')
    text=replace(text,'''    if status==0 and get(o,OP)==0:
        from_work(w,o,104,24,24)
        within(o,48,FUSER,24)
        zero(o,FUSER,24)''','''    if status==0 and get(o,OP)==0:
        within(o,24,FUSER,24)
        put(o,SM_DELIVERED,choose(get(o,FUSER)!=0,1,0))
        zero(o,FUSER,24)''')
    text=replace(text,'''    if status==1:
        within(o,128,ERR,get(o,ERRN))
    return 0''','''    put(o,128,get(o,SM_QUEUE))
    put(o,136,get(o,SM_MAP))
    put(o,144,get(o,SM_UNKNOWN))
    put(o,152,get(o,SM_DELIVERED))
    put(o,160,1)
    pending=choose(get(o,JOB_PENDING)!=0 or get(o,FUTURE_PENDING)!=0 or get(o,PROVIDER_PENDING)!=0,1,0)
    put(o,168,pending)
    put(o,176,get(o,SM_GLOBAL_PENDING))
    put(o,184,0)
    if status==1:
        within(o,256,ERR,get(o,ERRN))
    return 0''')
    text=replace_def(text,'value_take',VALUE_TAKE)
    text=replace_def(text,'release_value_reply',VALUE_REPLY)
    text=replace_def(text,'release_value',VALUE_RELEASE)
    text=replace_def(text,'release_value_retry',VALUE_RETRY)
    for name,at,offsets,marker in [('release_job','RP',(152,160,168),176),
                                  ('release_job_retry','RP',(152,160,168),176),
                                  ('release_future','PUBLIC_OUT',(136,128,144),0),
                                  ('release_future_retry','PUBLIC_OUT',(136,128,144),0)]:
        # Interpret known/consumed first; independent pending can never resurrect
        # a token that the actual dependency has already consumed.
        arg=',at:u64'if not name.endswith('retry')else''
        callarg=',at'if arg else''
        text=replace(text,'def '+name+'(','def managed_old_'+name+'(')
        text+='\ndef '+name+'(o:mutbuf'+arg+') -> u64:\n'
        text+='    done=managed_old_'+name+'(o'+callarg+')\n'
        text+='    valid=managed_pending(o,'+at+','+','.join(map(str,offsets))+','+str(marker)+')\n'
        text+='    if valid==0 or get(o,SM_UNKNOWN)!=0:\n        return 0\n    return done\n'

    text=replace(text,'return memory(o,155,3,WORD,0,get(o,T_OUT)+128,8)',
                 'return memory(o,155,3,WORD,0,get(o,T_OUT)+256,8)')
    text=replace(text,'return memory(o,160,3,WORD,0,get(o,T_OUT)+136,8)',
                 'return memory(o,160,3,WORD,0,get(o,T_OUT)+264,8)')
    text=replace(text,'        status=get(o,INFO+8)\n',
                 '        if managed_pending(o,INFO,128,136,144,152)==0:\n'
                 '            put(o,T_STUCK,2)\n'
                 '            return bound_quarantine(o,w,2,162)\n'
                 '        status=get(o,INFO+8)\n')
    text=replace(text,'        status=get(o,FREEZE_OUT+8)\n',
                 '        if managed_pending(o,FREEZE_OUT,128,136,144,152)==0:\n'
                 '            return bound_quarantine(o,w,2,201)\n'
                 '        status=get(o,FREEZE_OUT+8)\n')
    text=replace(text,'        if get(o,FREEZE_WORK+96)!=0 or get(o,FREEZE_OUT+56)!=0:\n',
                 '        if managed_pending(o,FREEZE_OUT,128,136,144,152)==0:\n'
                 '            return bound_quarantine(o,w,2,701)\n'
                 '        if get(o,FREEZE_WORK+96)!=0 or get(o,FREEZE_OUT+56)!=0:\n')
    text=replace(text,'within(o,ERR,FREEZE_OUT+128,n)','within(o,ERR,FREEZE_OUT+256,n)')
    text=replace(text,'            return finish(o,w,8)\n',
                 '            return fail(o,8,get(o,FEEDBACK))\n')
    text=replace(text,'        if valid(o,RP,QREPLY)==0 or get(o,RP+8)!=0:\n            return finish(o,w,6)',
                 '        if valid(o,RP,QREPLY)==0 or get(o,RP+8)!=0:\n            return fail(o,6,3)')

    text+=MANAGED_SOURCE
    return text
VALUE_TAKE=r'''
def value_take(o:mutbuf,at:u64) -> u64:
    if valid(o,RP,VALUE_REPLY)==0:
        return 1
    if get(o,SM_VOP)==91:
        if get(o,RP+88)!=1 or get(o,RP+96)>1:
            put(o,SM_UNKNOWN,1)
            return 1
        if get(o,RP+96)!=0:
            if get(o,RP+24)==0 or get(o,at)!=0:
                put(o,SM_UNKNOWN,1)
                return 1
            within(o,at,RP+24,24)
        valid=managed_pending(o,RP,112,104,0,120)
        if valid==0 or get(o,RP+96)==0 or get(o,SM_MAP)!=0 or get(o,SM_UNKNOWN)!=0:
            return 1
        return 0
    if get(o,RP+8)!=0:
        return 1
    if get(o,RP+24)==0 or get(o,at)!=0:
        put(o,SM_UNKNOWN,1)
        return 1
    within(o,at,RP+24,24)
    return 0
'''
VALUE_REPLY=r'''
def release_value_reply(o:mutbuf,op:u64) -> u64:
    if valid(o,RP,VALUE_DROP_REPLY)==0 or get(o,RP+88)!=1 or get(o,RP+96)>1:
        return 0
    status=get(o,RP+8)
    consumed=get(o,RP+96)
    if status!=0 and status!=1 and status!=6 and status!=11:
        return 0
    if op==31 and (status==1 or consumed!=0):
        return 0
    if consumed!=0 and status!=0 and status!=11:
        return 0
    if status==0 and consumed!=choose(op==31,0,1):
        return 0
    at=16
    while at<80:
        if get(o,RP+at)!=0:
            return 0
        at=at+8
    return 1
'''
VALUE_RELEASE=r'''
def release_value(o:mutbuf,at:u64) -> u64:
    if release_value_reply(o,29)==0:
        put(o,SM_UNKNOWN,1)
        return 0
    put(o,DROP_KNOWN,1)
    consumed=get(o,RP+96)
    if consumed!=0:
        zero(o,at,24)
    if managed_pending(o,RP,112,104,0,120)==0:
        put(o,DROP_KNOWN,2)
        return 0
    both=choose(get(o,RP+104)!=0 or get(o,RP+112)!=0,1,0)
    if get(o,RP+80)!=both:
        put(o,DROP_KNOWN,2)
        put(o,SM_UNKNOWN,1)
        return 0
    if get(o,RP+104)!=0:
        put(o,VALUE_PENDING,1)
    if consumed==0:
        return 0
    if get(o,RP+8)==11 and get(o,RP+80)==0:
        put(o,DROP_KNOWN,2)
        put(o,SM_UNKNOWN,1)
        return 0
    put(o,DROP_ACTIVE,0)
    return 1
'''
VALUE_RETRY=r'''
def release_value_retry(o:mutbuf) -> u64:
    if release_value_reply(o,31)==0:
        put(o,SM_UNKNOWN,1)
        return 0
    put(o,DROP_KNOWN,1)
    if managed_pending(o,RP,112,104,0,120)==0:
        put(o,DROP_KNOWN,2)
        return 0
    both=choose(get(o,RP+104)!=0 or get(o,RP+112)!=0,1,0)
    if get(o,RP+80)!=both:
        put(o,DROP_KNOWN,2)
        put(o,SM_UNKNOWN,1)
        return 0
    if get(o,RP+104)!=0:
        return 0
    status=get(o,RP+8)
    if status==6 and get(o,RP+112)!=0:
        put(o,DROP_KNOWN,2)
        put(o,SM_UNKNOWN,1)
        return 0
    if status!=0 and status!=6 and get(o,RP+112)==0:
        return 0
    put(o,VALUE_PENDING,0)
    put(o,SM_MAP,0)
    put(o,DROP_ACTIVE,0)
    return 1
'''
MANAGED_SOURCE=r'''
def managed(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1000:
        if value_take(o,SM_BG)!=0:
            return fail(o,7,1000)
        request(o,SM_VQUERY,49)
        within(o,RQ+24,SM_BG,24)
        return values(o,w,1001,128)
    if phase==1001:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=6:
            return fail(o,7,1001)
        request(o,SM_VPRIVATE,80)
        within(o,RQ+24,SM_BG,24)
        return values(o,w,1002,128)
    if phase==1002:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+48)!=6:
            return fail(o,7,1002)
        if get(o,RP+24)!=get(w,864) or get(o,RP+32)!=get(w,872) or get(o,RP+40)!=get(w,880):
            return fail(o,7,1002)
        return system(o,2,228,12,1,TS,0,0,0,0)
    if phase==1004:
        if managed_provider_take(o,SM_PIN)==0:
            return fail(o,7,1004)
        within(o,SM_FID,RP+48,24)
        within(o,SM_RAW,RP+72,24)
        if get(o,SM_FID)!=get(w,104) or get(o,SM_FID+8)!=get(w,112) or get(o,SM_FID+16)!=get(w,120) or get(o,SM_RAW)==0:
            return fail(o,7,1004)
        request(o,PUBLIC_INPUT,5)
        within(o,RQ+16,SM_FID,24)
        within(o,RQ+40,SM_RAW,24)
        return public(o,w,401)
    if phase==1005:
        if value_take(o,SM_EDGE)!=0:
            return fail(o,7,1005)
        request(o,SM_VPRIVATE,77)
        within(o,RQ+24,SM_BG,24)
        within(o,RQ+48,SM_EDGE,24)
        return values(o,w,1006,128)
    if phase==1006 or phase==1007:
        if valid(o,RP,VALUE_DROP_REPLY)==0 or get(o,RP+88)!=1 or get(o,RP+96)!=1 or get(o,RP+8)!=0 or get(o,RP+80)>1:
            return quarantine(o,w,phase)
        if get(o,RP+104)!=0 or get(o,RP+112)!=0 or get(o,RP+120)!=0:
            return quarantine(o,w,phase)
        if get(o,RP+80)!=0:
            put(o,SM_GLOBAL_PENDING,1)
        if phase==1006:
            put(o,SM_EDGE_ADOPT,1)
            request(o,SM_VPRIVATE,77)
            within(o,RQ+24,SM_BG,24)
            within(o,RQ+48,META,24)
            return values(o,w,1007,128)
        put(o,SM_META_ADOPT,1)
        request(o,QINPUT,1)
        within(o,RQ+24,JOB,24)
        put(o,RQ+48,get(o,KERNEL))
        put(o,RQ+56,512)
        return queue(o,w,602)
    if phase==1008:
        index=get(o,SM_CLEAN)
        if index==4:
            return again(o,790)
        at=SM_EDGE
        if index==1:
            at=SM_PIN
        elif index==2:
            at=FUSER
        elif index==3:
            at=SM_BG
        if get(o,at)==0 or (at==FUSER and get(o,ERROR)==0 and get(o,OP)==0):
            put(o,SM_CLEAN,index+1)
            return again(o,1008)
        put(o,SM_SAVED,at)
        return drop_value(o,w,1009,at)
    if phase==1009:
        if release_value(o,get(o,SM_SAVED))==0:
            return quarantine(o,w,1009)
        if get(o,VALUE_PENDING)!=0:
            return quarantine(o,w,1009)
        put(o,SM_CLEAN,get(o,SM_CLEAN)+1)
        return again(o,1008)
    return quarantine(o,w,phase)
def managed_provider(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,832),51,RQ,128,RP,160,get(w,840),get(w,848))
def managed_provider_take(o:mutbuf,at:u64) -> u64:
    if valid(o,RP,SM_PROVIDER_REPLY)==0 or get(o,RP+96)!=1 or get(o,RP+104)>1:
        put(o,SM_UNKNOWN,1)
        return 0
    if get(o,RP+104)!=0:
        if get(o,RP+24)==0 or get(o,at)!=0:
            put(o,SM_UNKNOWN,1)
            return 0
        within(o,at,RP+24,24)
    if managed_pending(o,RP,128,120,136,144)==0:
        return 0
    if get(o,RP+152)>1:
        put(o,SM_UNKNOWN,1)
        return 0
    if get(o,RP+152)!=0:
        put(o,SM_NATIVE_PENDING,1)
        return 0
    if get(o,RP+104)!=1 or get(o,RP+16)!=7 or get(o,RP+8)!=0 or get(o,SM_MAP)!=0 or get(o,SM_UNKNOWN)!=0:
        return 0
    return 1
def managed_value_packet(o:mutbuf) -> u64:
    magic=get(o,RQ)
    op=get(o,RQ+8)
    if magic==VALUE_INPUT or magic==VALUE_DROP_INPUT or magic==SM_VQUERY or magic==SM_VFIXED:
        if op==5:
            op=91
        elif op==6 or op==29:
            op=78
        elif op==22 or op==30:
            op=92
        elif op==31:
            op=93
        if op==78 or op==91 or op==92 or op==93:
            magic=SM_VPRIVATE
        elif op==3 or op==12 or op==16 or op==18 or op==24:
            magic=SM_VFIXED
        else:
            magic=SM_VQUERY
        put(o,RQ,magic)
        put(o,RQ+8,op)
    put(o,SM_VOP,op)
    return 0
def managed_pending(o:mutbuf,at:u64,queue:u64,mapping:u64,unknown:u64,marker:u64) -> u64:
    if get(o,at+queue)>1 or get(o,at+mapping)>1:
        put(o,SM_UNKNOWN,1)
        return 0
    if marker!=0 and get(o,at+marker)!=1:
        put(o,SM_UNKNOWN,1)
        return 0
    if unknown!=0 and get(o,at+unknown)!=0:
        put(o,SM_UNKNOWN,1)
        return 0
    if get(o,at+queue)!=0:
        put(o,SM_QUEUE,1)
    if get(o,at+mapping)!=0:
        put(o,SM_MAP,1)
        put(o,VALUE_PENDING,1)
    return 1
'''
def source_program():
    text=source_template()
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    d=document(source_program(),'background_optimizer_submission_managed')
    p=ROOT/'examples/hia_bootstrap/background_optimizer_submission_managed.hepta';p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
