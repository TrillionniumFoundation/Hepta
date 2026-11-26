"""Private non-destructive carrier readiness for the component-root owner.

HIAMVHB1 is accepted only as a zero-filled 128-byte operation-5 frame. It reads
the same registry lists under the existing mutex as actual operation 5, without
closing that registry. Every earlier public and acknowledgement domain is kept.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_handles as base
ROOT=Path(__file__).resolve().parents[1]
PROBE=int.from_bytes(b'HIAMVHB1','little')
def replace(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)
def source_program():
    s=base.source_program()
    public=base.original.C['MAGIC']
    s=replace(s,
      f'    if length(s)<128 or (word(s,0)!={public} and word(s,0)!={base.REQUEST}) or word(s,8)>7:',
      f'    if length(s)<128 or (word(s,0)!={public} and word(s,0)!={base.REQUEST} and word(s,0)!={PROBE}) or word(s,8)>7:')
    s=replace(s,
      f'    private=word(s,0)=={base.REQUEST}\n',
      f'''    probe=word(s,0)=={PROBE}
    if probe and op!=5:
        return 4294967293
    private=word(s,0)=={base.REQUEST}
''')
    s=replace(s,f'    put(o,{base.MODE},choose(private,1,0))\n',
      f'    put(o,{base.MODE},choose(probe,2,choose(private,1,0)))\n')
    s=replace(s,'            put(w,24,1)\n            return fail(o,0)\n',
      f'''            if get(o,{base.MODE})!=2:
                put(w,24,1)
            return fail(o,0)
''')
    s=replace(s,f'    if get(o,{base.MODE})!=0:\n        put(o,0,{base.REPLY})\n',
      f'    if get(o,{base.MODE})==1:\n        put(o,0,{base.REPLY})\n')
    return s
def main():
    tree=document(source_program(),'generation_lease_owner_component_handles')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_component_handles.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
      sum(len(f['blocks'])for f in tree['functions']),
      sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
