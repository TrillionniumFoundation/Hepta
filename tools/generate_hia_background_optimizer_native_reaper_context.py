"""NI2 context variant with native reaper join-before-registry-close."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_native_context as original
from tools import hia_background_managed_value_source as M
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C);C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(INIT='HIABGNI2',REAPER_INPUT='HIABRMQ1',REAPER_REPLY='HIABRMR1',REAPER_LIST='HIABRL01').items()})
ENTRY_NAMES=original.ENTRY_NAMES
def source_program():
    text=M.replace(original.SOURCE,'def background_native_context(','def background_native_reaper_context(')
    text=M.replace(text,'word_load(s,56)==0 or word_load(s,64)!=10100891 or word_load(s,88)==0 or word_load(s,96)!=ENTRIES*8',
        'word_load(s,56)==0 or word_load(s,64)!=10100891 or word_load(s,88)!=0 or word_load(s,96)!=0')
    text=M.replace(text,'word_load(s,16)>MAX-2048 or word_load(s,56)>MAX-10100891 or word_load(s,88)>MAX-ENTRIES*8',
        'word_load(s,16)>MAX-2048 or word_load(s,56)>MAX-10100891')
    text=M.replace(text,'        return memory(o,8,0,word_load(s,88),3,TEMP,ENTRIES*8)',
        '        put(o,TEMP+33*8,get(o,VALUES+224))\n        return again(o,8)')
    text=M.replace(text,'        put(o,HEADER+128,ENTRIES)',
        '        put(o,HEADER+128,ENTRIES)\n        put(o,HEADER+456,REAPER_LIST)')
    text=M.replace(text,'            return lock(o,300)',
        '''            if get(w,272)!=0 and (get(o,OP)==1 or get(o,OP)==3 or get(o,OP)==4):
                request(o,REAPER_INPUT,1)
                put(o,PH,9)
                return 16
            return lock(o,300)''')
    anchor='''        return lock(o,200)
    return finish(o,w,11)

def locks'''
    text=M.replace(text,anchor,'''        return lock(o,200)
    if phase==9:
        if get(o,FB)!=0 or get(o,RP)!=REAPER_REPLY or get(o,RP+16)!=1 or get(o,RP+24)>1 or get(o,RP+32)>1:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        if get(o,RP+32)!=0:
            put(o,UNKNOWN,1)
            return fail(o,w,11)
        if get(o,RP+8)!=0:
            return fail(o,w,get(o,RP+8))
        if get(o,RP+24)!=0 or get(o,RP+48)!=0:
            return fail(o,w,6)
        return lock(o,300)
    return finish(o,w,11)

def locks''')
    return M.render(text,C,'background_native_reaper_context')
def main():
    name='background_optimizer_native_reaper_context'
    d=document(source_program(),name);p=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
    p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
