"""Serialized Info custody with deferred Value operations and an unlocked drain.

This derived core retains the previous public request domain and excludes the new
private Value profiles. Actual root72 guards span the final drain outside root64.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner_component_core as prior
from tools import generate_hia_generation_lease_owner as old
ROOT=Path(__file__).resolve().parents[1]
C=old.C
V6=int.from_bytes(b'HIABVQ06','little')
V14=int.from_bytes(b'HIABVQ14','little')
def replace(s,a,b):
 assert s.count(a)==1,(a,s.count(a))
 return s.replace(a,b,1)
def function(s,name,edit):
 m=re.search(r'^def '+name+r'\(.*?(?=^def |\Z)',s,re.S|re.M);assert m,name
 return s[:m.start()]+edit(m.group())+s[m.end():]
def source_program():
 s=prior.source_program()
 marker='        magic=word_load(s,64)\n'
 guards=marker
 for m in(b'HIABVQ12',b'HIABVQ13',b'HIABVQ14'):
  guards+=f'        if magic=={int.from_bytes(m,"little")}:\n            return {C["BAD"]}\n'
 s=replace(s,marker,guards)
 def begin(v):
  v=replace(v,f'put(o,{C["RQ"]},{C["VALUE1"]})',f'put(o,{C["RQ"]},{C["VALUE5"]})')
  return replace(v,f'put(o,{C["RQ"]}+8,5)',f'put(o,{C["RQ"]}+8,91)')
 s=function(s,'info_begin',begin)
 def phases(v):
  start=v.index('    if phase==60:\n')
  end=v.index('    if phase==61:\n')
  prefix=f'''    if phase==60:
        if get(o,{C["FEEDBACK"]})!=0 or get(o,8192)!={C["VREPLY1"]}:
            within(o,{C["CHILD"]},8192,128)
            put(o,1144,5)
            return info_tempdrop(o,w)
        if get(o,8216)!=0:
            within(o,640,8216,24)
            put(o,688,1)
        valid=get(o,8280)==1 and get(o,8288)==1 and get(o,8312)==1
        if valid:
            valid=get(o,8216)!=0 and get(o,8224)!=0 and get(o,8232)!=0 and get(o,8296)==0
        if valid:
            valid=get(o,8200)==0 or (get(o,8200)==11 and get(o,8304)==1)
        if valid==False:
            within(o,{C["CHILD"]},8192,128)
            put(o,1144,1)
            return info_tempdrop(o,w)
        zero(o,{C["RQ"]},128)
        zero(o,8192,128)
        put(o,{C["RQ"]},{V14})
        put(o,{C["RQ"]}+8,65)
        within(o,{C["RQ"]}+24,640,24)
        put(o,{C["PHASE"]},71)
        return 15
'''
  v=v[:start]+prefix+v[end:]
  v=replace(v,f'put(o,{C["INFO_FRAME"]},{C["VALUE5"]})\n        put(o,{C["INFO_FRAME"]}+8,60)',f'put(o,{C["INFO_FRAME"]},{V14})\n        put(o,{C["INFO_FRAME"]}+8,60)')
  v=replace(v,'        return unlock(o,w,get(o,1144),get(o,704))\n',f'''        put(o,784,1)
        put(o,696,get(o,1144))
        put(o,{C["PHASE"]},13)
        return 2
''')
  return v
 s=function(s,'info_phases',phases)
 def cache(v):
  v=replace(v,f'put(o,{C["RQ"]},{C["VALUE5"]})\n        put(o,{C["RQ"]}+8,49)',f'put(o,{C["RQ"]},{V6})\n        put(o,{C["RQ"]}+8,49)')
  for at,op in((C['INFO_FRAME'],66),(C['RQ'],64)):
   v=replace(v,f'put(o,{at},{C["VALUE5"]})\n        put(o,{at}+8,{op})',f'put(o,{at},{V14})\n        put(o,{at}+8,{op})')
  return v
 s=function(s,'info_cache_phases',cache)
 def drop(v):
  v=replace(v,f'put(o,{C["RQ"]},{C["VALUE2"]})\n        put(o,{C["RQ"]}+8,29)',f'put(o,{C["RQ"]},{C["VALUE5"]})\n        put(o,{C["RQ"]}+8,78)')
  v=replace(v,f'    put(o,{C["PHASE"]},70)\n    return 15\n',f'''    if get(w,72)==18446744073709551615:
        return unlock(o,w,2,get(o,704))
    put(w,72,get(w,72)+1)
    put(o,{C["PHASE"]},90)
    return 3
''')
  return v
 s=function(s,'info_tempdrop',drop)
 def owner(v):
  marker='    if phase==20:\n'
  return replace(v,marker,f'''    if phase==90:
        put(o,{C["PHASE"]},70)
        return 15
'''+marker)
 s=function(s,'owner',owner)
 return strict_info(s)
def strict_info(source):
 def segment(text,phase,next_phase,replacement):
  a=text.index('    if phase=='+str(phase)+':\n')
  b=text.index('    if phase=='+str(next_phase)+':\n',a)
  return text[:a]+replacement+text[b:]
 def phases(text):
  text=segment(text,65,66,'''    if phase==65:
        put(o,608,get(o,384))
        if get(o,608)!=0 or get(o,16384)!=3544423437172820296:
            put(o,1144,5)
        elif get(o,16392)!=0:
            put(o,1144,5)
        elif get(o,16400)!=12 or get(o,16408)==0 or get(o,16416)==0 or get(o,16424)==0:
            put(o,1144,5)
        put(o,704,4)
        if get(o,1144)==0:
            within(o,2048,16384,128)
            put(o,1160,1)
            if info_deferred_ready(o,16384):
                put(o,1168,72)
            else:
                put(o,1144,5)
                put(o,728,11)
        return info_release(o,w)
''')
  text=segment(text,69,70,'''    if phase==69:
        consumed=get(o,384)==0 and get(o,8192)==3616481031210748232
        if consumed:
            consumed=get(o,8280)==1 and get(o,8288)==1
        if consumed==False:
            within(o,736,640,24)
            put(o,720,1)
            put(o,1144,5)
            put(o,728,11)
        else:
            clean=get(o,8312)==1 and get(o,8296)==0 and get(o,8304)<=1
            if clean:
                clean=get(o,8200)==0 or (get(o,8200)==11 and get(o,8304)==1)
            if clean==False:
                put(o,728,choose(get(o,8200)==0,11,get(o,8200)))
                put(o,1144,5)
        put(o,688,0)
        return info_tempdrop(o,w)
''')
  return text
 source=function(source,'info_phases',phases)
 def cache(text):
  text=segment(text,71,72,'''    if phase==71:
        if get(o,384)!=0 or get(o,8192)!=3544423437172820296:
            within(o,16384,8192,128)
            put(o,1144,5)
            return info_tempdrop(o,w)
        if get(o,8200)==0:
            if get(o,8208)!=12 or get(o,8216)==0 or get(o,8224)==0 or get(o,8232)==0:
                put(o,1144,5)
                within(o,16384,8192,128)
                return info_tempdrop(o,w)
            within(o,2048,8192,128)
            put(o,1160,1)
            if info_deferred_ready(o,8192)==False:
                put(o,1144,5)
                put(o,728,11)
            return info_tempdrop(o,w)
        if get(o,8200)!=6:
            within(o,16384,8192,128)
            put(o,1144,1)
            return info_tempdrop(o,w)
        if info_deferred_ready(o,8192)==False:
            within(o,16384,8192,128)
            put(o,1144,5)
            put(o,728,11)
            return info_tempdrop(o,w)
        zero(o,4096,128)
        zero(o,8192,128)
        put(o,4096,3904710307850832200)
        put(o,4104,49)
        put(o,4200,2)
        within(o,4120,640,24)
        put(o,256,61)
        return 15
''')
  text=segment(text,75,76,'''    if phase==75:
        if get(o,384)!=0 or get(o,16384)!=3544423437172820296:
            put(o,1144,5)
            put(o,728,11)
        elif get(o,16392)!=0:
            put(o,1144,5)
            put(o,728,get(o,16392))
        elif info_deferred_ready(o,16384)==False:
            put(o,1144,5)
            put(o,728,11)
        else:
            put(o,1168,76)
        return info_release(o,w)
''')
  a=text.index('    if phase==77:\n')
  b=text.index('    return 4294967293\n',a)
  text=text[:a]+'''    if phase==77:
        if get(o,384)!=0 or get(o,8192)!=3544423437172820296:
            put(o,1144,5)
            put(o,728,11)
        elif get(o,8200)!=0:
            put(o,1144,5)
            put(o,728,get(o,8200))
        elif info_deferred_ready(o,8192)==False:
            put(o,1144,5)
            put(o,728,11)
        return info_tempdrop(o,w)
'''+text[b:]
  return text
 source=function(source,'info_cache_phases',cache)
 return source+'''
def info_deferred_ready(o:mutbuf,at:u64) -> bool:
    if get(o,at+128)!=3544408044010031432 or get(o,at+136)!=1:
        return False
    if get(o,at+144)!=0 or get(o,at+152)>1 or get(o,at+160)!=1:
        return False
    return True
'''

def main():
 t=document(source_program(),'generation_runtime_info_unlocked_core')
 p=ROOT/'examples/hia_bootstrap/generation_runtime_info_unlocked_core.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
