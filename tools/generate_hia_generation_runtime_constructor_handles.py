"""Private public-constructor carrier capture, preserving all earlier domains.

HIAMVHC1 is generated only by the fixed constructor. It retains the old raw
creation frame while capturing the actual caller-owned directory and clang
Value capabilities in the initialized native Runtime workspace. The enclosing
constructor keeps both Value references alive throughout this call.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_runtime_custody_handles as prior
ROOT=Path(__file__).resolve().parents[1]
REQUEST=int.from_bytes(b'HIAMVHC1','little')
CONTEXT=int.from_bytes(b'HIARTCW1','little')
def replace(s,a,b):
    assert s.count(a)==1,(a,s.count(a))
    return s.replace(a,b,1)
def source_program():
    s=prior.source_program();c=prior.prior.base.original.C
    public=c['MAGIC'];ack=prior.prior.base.REQUEST;probe=prior.prior.PROBE
    s=replace(s,
      f'    if length(s)<128 or (word(s,0)!={public} and word(s,0)!={ack} and word(s,0)!={probe}) or word(s,8)>7:',
      f'    if length(s)<128 or (word(s,0)!={public} and word(s,0)!={ack} and word(s,0)!={probe} and word(s,0)!={REQUEST}) or word(s,8)>7:')
    s=replace(s,'    op=word(s,8)\n',
      f'''    op=word(s,8)
    constructing=word(s,0)=={REQUEST}
    if constructing and (op!=1 or word(s,24)==0 or word(s,48)==0):
        return 4294967293
''')
    s=replace(s,'        used=i==72 or (private and i==16)\n',
      '        used=i==72 or (private and i==16) or (constructing and i>=24 and i<=64)\n')
    s=replace(s,f'    put(o,528,choose(probe,2,choose(private,1,0)))\n',
      '    put(o,528,choose(constructing,3,choose(probe,2,choose(private,1,0))))\n')
    marker=f'''    if phase==501:
        if get(o,{c['CALL_KIND']})==4:
'''
    addition=f'''    if phase==501:
        if get(o,528)==3:
            zero(o,608,56)
            put(o,608,{CONTEXT})
            put(o,616,word(s,24))
            put(o,624,word(s,32))
            put(o,632,word(s,40))
            put(o,640,word(s,48))
            put(o,648,word(s,56))
            put(o,656,word(s,64))
            return memory(o,502,3,608,0,get(o,{c['RUNTIME']})+680,56)
        if get(o,{c['CALL_KIND']})==4:
'''
    s=replace(s,marker,addition)
    s=replace(s,'    if phase==504:\n',
      '    if phase==502:\n        return again(o,504)\n    if phase==504:\n')
    # Only the native constructor may select its private creation profile.
    # Its actual child remains the independently validated public effects frame.
    s=replace(s,f'    if op==1 and ((word(s,128)!={c["EFFECTS"]} and word(s,128)!={c["PUBLIC_EFFECTS"]}) or word(s,136)!=0):\n',
      f'''    if constructing and word(s,128)!={c['PUBLIC_EFFECTS']}:
        return 4294967293
    if op==1 and ((word(s,128)!={c["EFFECTS"]} and word(s,128)!={c["PUBLIC_EFFECTS"]}) or word(s,136)!=0):
''')
    return s
def main():
    tree=document(source_program(),'generation_runtime_constructor_handles')
    path=ROOT/'examples/hia_bootstrap/generation_runtime_constructor_handles.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
      sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
