"""Public component-root core, retaining all existing public operation domains."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner_sidecar_future_core as base
from tools import generate_hia_generation_lease_owner_component_handles as handles
ROOT=Path(__file__).resolve().parents[1]
READY_SOURCE=r'''
def carrier_readiness(o:mutbuf,w:mutbuf) -> u32:
    put(o,608,get(o,384))
    if get(o,608)!=0 or get(o,16384)!=HREPLY:
        return unlock(o,w,5,1)
    if get(o,16472)!=get(o,400):
        return unlock(o,w,5,1)
    i=16
    while i<128:
        if i!=88 and get(o,16384+i)!=0:
            return unlock(o,w,5,1)
        i=i+8
    status=get(o,16392)
    if status==5:
        return unlock(o,w,2,1)
    if status!=0:
        return unlock(o,w,5,1)
    return value_control(o,VALUE5,52,15)
'''
def replace(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)
def source_program():
    source=base.source_program()
    token='        magic = word_load(s, 64)\n'
    if token not in source:token='        magic=word_load(s,64)\n'
    assert source.count(token)==1
    guards=''.join('        if magic=='+str(int.from_bytes(m,'little'))+':\n            return 4294967293\n'
        for m in(b'HIABVQ07',b'HIABVQ08',b'HIABVQ09',b'HIABVQ10',b'HIABVQ11'))
    source=source.replace(token,token+guards)
    source=replace(source,'    if phase==20:\n',
      '    if phase==86:\n        return carrier_readiness(o,w)\n    if phase==20:\n')
    value5=int.from_bytes(b'HIABVQ05','little')
    source=replace(source,f'        return value_control(o,{value5},52,15)\n',
      f'''        zero(o,4096,128)
        zero(o,16384,128)
        put(o,4096,{handles.PROBE})
        put(o,4104,5)
        put(o,560,1)
        put(o,256,86)
        return 12
''')
    extra=READY_SOURCE.replace('HREPLY',str(int.from_bytes(b'HIAMVHR1','little'))).replace('VALUE5',str(value5))
    return source+'\n'+extra
def main():
    tree=document(source_program(),'generation_lease_owner_component_core')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_component_core.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
      sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
