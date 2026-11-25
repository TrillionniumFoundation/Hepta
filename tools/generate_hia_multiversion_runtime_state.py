"""Private lifecycle policy with native arbitrary-precision identity callbacks.

No public generation or epoch is a machine counter. The effect owner supplies
fresh immutable decimal reference identities under the same original locks.
This private policy is only called by the fixed native runtime owner.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_coordinator as original
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIAMVC02','little')
STATE=original.STATE
NONE=original.NONE
def source_program():
    s=original.SOURCE
    # Slots and event-ring positions retain their original finite domains.
    # Generation/epoch words are immutable owned-reference identities only.
    s=s.replace('put(w,32,1)','put(w,32,0)')
    old='''    number=get(w,32)
    if number==NONE:
        return fail(o,28)
    put(w,32,number+1)
    reserve(w,slot,number,0)
    put(o,40,slot)
    put(o,136,number)
    return unlock(o,2,206)'''
    new='''    put(o,40,slot)
    return issue(o,40,234,slot,0)'''
    assert old in s;s=s.replace(old,new)
    marker='''    if phase == 230:
        return fail(o,get(o,120))
    return fail(o,127)'''
    add='''    if phase == 234:
        if get(o,8)!=0:
            put(o,40,NONE)
            return fail(o,29)
        number=get(o,304)
        slot=get(o,40)
        if number==0 or number==NONE or slot>=64:
            return fail(o,27)
        reserve(w,slot,number,0)
        put(o,136,number)
        return unlock(o,2,206)
    if phase == 235:
        if get(o,8)!=0:
            return prepare_failed(o,w,29)
        slot=get(o,40)
        if get(o,304)==0 or get(o,304)==NONE:
            return prepare_failed(o,w,27)
        put(o,152,get(w,48))
        put(o,312,get(w,40))
        put(w,record(slot),2)
        put(w,80,get(w,80)+1)
        put(w,48,slot)
        put(w,40,get(o,304))
        put(o,32,slot)
        return issue(o,35,220,get(o,80),1)
    if phase == 230:
        return fail(o,get(o,120))
    return fail(o,127)'''
    assert marker in s;s=s.replace(marker,add)
    old='''    if get(w,40)==NONE:
        return prepare_failed(o,w,28)
    put(o,152,previous)
    put(w,record(slot),2)
    put(w,80,get(w,80)+1)
    put(w,48,slot)
    put(w,40,get(w,40)+1)
    put(o,32,slot)
    # The token owner action has no user callback and stores its committed
    # marker while both selection and cancellation locks remain held.
    return issue(o,35,220,get(o,80),1)'''
    new='''    # The native decimal owner creates the next immutable epoch before
    # selection. It retains the prior value until the real token marker decides
    # commit or rollback. No supplied word is a numeric successor.
    return issue(o,41,235,get(w,40),0)'''
    assert old in s;s=s.replace(old,new)
    assert 'put(w,40,get(w,40)-1)' in s
    s=s.replace('put(w,40,get(w,40)-1)','put(w,40,get(o,312))')
    old='''        if previous>=64 or get(w,512)!=2 or get(w,40)==NONE:
            return fail(o,27)
        put(w,48,0)
        put(w,40,get(w,40)+1)
        event(o,w,3,0)
        put(o,32,previous)
        put(o,144,402)
        return issue(o,25,660,previous,3)'''
    new='''        if previous>=64 or get(w,512)!=2:
            return fail(o,27)
        put(o,320,previous)
        return issue(o,41,403,get(w,40),1)
    if phase==403:
        if get(o,8)!=0:
            return fail(o,29)
        if get(o,304)==0 or get(o,304)==NONE:
            return fail(o,27)
        previous=get(o,320)
        put(w,48,0)
        put(w,40,get(o,304))
        event(o,w,3,0)
        put(o,32,previous)
        put(o,144,402)
        return issue(o,25,660,previous,3)'''
    assert old in s;s=s.replace(old,new)
    assert 'get(w,32)+1' not in s and 'number+1' not in s and 'get(w,40)+1' not in s and 'get(w,40)-1' not in s
    s=s.replace('''        if get(o,96) != 0:
            return issue(o,24,209,0,get(o,40))''','''        if get(o,96) != 0:
            return lock(o,2,236)''')
    s=s.replace('''    if phase == 230:
        return fail(o,get(o,120))''','''    if phase==236:
        if get(o,8)!=0:
            return prepare_failed(o,w,17)
        held(o,2)
        if get(w,24)!=0:
            return prepare_failed(o,w,18)
        if current_matches(o,w)==0:
            return prepare_failed(o,w,19)
        return issue(o,24,237,2,get(o,40))
    if phase==237:
        if get(o,8)!=0:
            return prepare_failed(o,w,23)
        return unlock(o,2,238)
    if phase==238:
        return issue(o,24,209,0,get(o,40))
    if phase == 230:
        return fail(o,get(o,120))''')
    s=s.replace('reserve(w,0,0,1)','reserve(w,0,get(o,304),1)')
    s=s.replace('event(o,w,3,0)','event(o,w,3,get(w,520))')
    # Fixed outer owner drains these notifications before another policy step.
    # They carry private finite slots, never public numeric identities.
    assert '    phase=get(o,0)' in s
    s=s.replace('    phase=get(o,0)','    put(o,336,0)\n    put(o,352,0)\n    phase=get(o,0)')
    s=s.replace('release_record(w,','release_record(o,w,')
    s=s.replace('def release_record(w:mutbuf,','def release_record(o:mutbuf,w:mutbuf,')
    old="""        clear_record(w,slot)
    return 0

def clear_record"""
    new="""        clear_record(w,slot)
        put(o,352,get(o,352)|(1<<slot))
    return 0

def clear_record"""
    assert old in s;s=s.replace(old,new)
    # Preparation refusal also releases its reserved private slot, after the
    # same-holder cleanup decision already performed by this coordinator.
    s=s.replace('            clear_record(w,get(o,40))','            discard(o,w,get(o,40))')
    old="""    if get(o,264)==0:
        clear_record(w,slot)"""
    new="""    if get(o,264)==0:
        discard(o,w,slot)"""
    assert old in s;s=s.replace(old,new)
    old="""    head=get(w,112)
    at=17408+head*48"""
    new="""    head=get(w,112)
    put(o,336,head+1)
    at=17408+head*48"""
    assert old in s;s=s.replace(old,new)
    s += """
def discard(o:mutbuf,w:mutbuf,slot:u64) -> u64:
    if slot<64:
        clear_record(w,slot)
        put(o,352,get(o,352)|(1<<slot))
    return 0
"""
    # Exact insertion order is a finite ordering of the existing 64 owned
    # slots, not a numeric generation/epoch counter. Keep a locked copy for
    # close/retry so removing an entry cannot skip its successor.
    s=s.replace('        put(w,120,0)','        put(w,120,0)\n        put(w,128,0)\n        put(w,136,0)')
    s=s.replace('        put(w,512,2)','        put(w,512,2)\n        order_add(w,136,24064,0)')
    s=s.replace('        put(w,record(slot),2)','        put(w,record(slot),2)\n        order_add(w,136,24064,slot)')
    s=s.replace('        put(w,record(slot),6)','        put(w,record(slot),6)\n        order_add(w,128,23552,slot)')
    s=s.replace('            put(w,record(slot),6)','            put(w,record(slot),6)\n            order_add(w,128,23552,slot)') if False else s
    # The exact original indent is preserved by line-wise insertion.
    lines=[]
    for line in s.splitlines():
        lines.append(line)
        body=line.lstrip()
        indent=line[:-len(body)] if body else ''
        if body=='put(w,record(slot),4)':
            lines.append(indent+'order_add(w,128,23552,slot)')
            lines.append(indent+'order_remove(w,136,24064,slot)')
        if body=='put(w,record(get(o,40)),1)':
            lines.append(indent+'order_remove(w,136,24064,get(o,40))')
    s='\n'.join(lines)+'\n'
    # Correct the generic six-state insertion to its surrounding indent.
    s=s.replace('            put(w,record(slot),6)\n        order_add(w,128,23552,slot)',
                '            put(w,record(slot),6)\n            order_add(w,128,23552,slot)')
    s=s.replace('def clear_record(w:mutbuf,slot:u64) -> u64:\n    i=0',
                'def clear_record(w:mutbuf,slot:u64) -> u64:\n    order_remove(w,128,23552,slot)\n    order_remove(w,136,24064,slot)\n    i=0')
    s=s.replace('        put(o,232,0)\n        return close_next(o,w)',
                '        put(o,232,0)\n        order_capture(o,w,136,24064)\n        return close_next(o,w)')
    s=s.replace('        put(o,224,0)\n        return cleanup_next(o,w)',
                '        put(o,224,0)\n        order_capture(o,w,128,23552)\n        return cleanup_next(o,w)')
    old='''def close_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(o,224)
    while i<64:
        if (get(w,record(i))&2)!=0:
            put(o,224,i)
            put(o,32,i)
            put(o,144,503)
            return issue(o,25,660,i,3)
        i=i+1'''
    new='''def close_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(o,224)
    while i<get(o,368):
        slot=get(o,512+i*8)
        if slot<64 and (get(w,record(slot))&2)!=0:
            put(o,224,i)
            put(o,32,slot)
            put(o,144,503)
            return issue(o,25,660,slot,3)
        i=i+1'''
    assert old in s;s=s.replace(old,new)
    old='''def cleanup_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(o,224)
    while i<64:
        if (get(w,record(i))&4)!=0:
            put(o,224,i)
            put(o,32,i)
            if get(w,record(i))==6:
                put(o,144,603)
                return issue(o,25,661,i,5)
            # Mode 3 retries path cleanup only. fd/dlclose and identity-close
            # uncertainty remain with the same existing retirement owner.
            return issue(o,26,603,i,3)
        i=i+1'''
    new='''def cleanup_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(o,224)
    while i<get(o,368):
        slot=get(o,512+i*8)
        if slot<64 and (get(w,record(slot))&4)!=0:
            put(o,224,i)
            put(o,32,slot)
            if get(w,record(slot))==6:
                put(o,144,603)
                return issue(o,25,661,slot,5)
            return issue(o,26,603,slot,3)
        i=i+1'''
    assert old in s;s=s.replace(old,new)
    s+='''
def order_add(w:mutbuf,count:u64,base:u64,slot:u64) -> u64:
    n=get(w,count)
    i=0
    if n>64 or slot>=64:
        return 0
    while i<n:
        if get(w,base+i*8)==slot:
            return 1
        i=i+1
    if n==64:
        return 0
    put(w,base+n*8,slot)
    put(w,count,n+1)
    return 1

def order_remove(w:mutbuf,count:u64,base:u64,slot:u64) -> u64:
    n=get(w,count)
    if n>64:
        return 0
    i=0
    while i<n and get(w,base+i*8)!=slot:
        i=i+1
    if i==n:
        return 1
    while i+1<n:
        put(w,base+i*8,get(w,base+(i+1)*8))
        i=i+1
    put(w,base+(n-1)*8,0)
    put(w,count,n-1)
    return 1

def order_capture(o:mutbuf,w:mutbuf,count:u64,base:u64) -> u64:
    n=get(w,count)
    if n>64:
        put(o,368,0)
        return 0
    put(o,368,n)
    i=0
    while i<n:
        put(o,512+i*8,get(w,base+i*8))
        i=i+1
    return 1
'''

    s=s.replace('MAGIC',str(MAGIC)).replace('STATE',str(STATE)).replace('NONE',str(NONE))
    return s
def main():
    doc=document(source_program(),'multiversion_runtime_state')
    path=ROOT/'examples/hia_bootstrap/multiversion_runtime_state.hepta';path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
