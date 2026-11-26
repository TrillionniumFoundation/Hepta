"""Private registered Clang Runtime profile beside the frozen carrier domains.

HIAMVHQ2 carries a borrowed real clang Value capability held by the native
constructor/method owner for the complete call. HQ1/HA1/HB1 stay unchanged.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner_component_handles as base
ROOT=Path(__file__).resolve().parents[1]
REQUEST=int.from_bytes(b'HIAMVHQ2','little')
INITIAL=int.from_bytes(b'HIAMVEX5','little')
PUBLISH=int.from_bytes(b'HIAMVEX6','little')
def replace(s,old,new):
 assert s.count(old)==1,(old,s.count(old))
 return s.replace(old,new)
def source_program():
 s=base.source_program()
 old=int.from_bytes(b'HIAMVHQ1','little')
 s=replace(s,f'word(s,0)!={old}',f'(word(s,0)!={old} and word(s,0)!={REQUEST})')
 s=replace(s,'    op=word(s,8)\n',f'''    op=word(s,8)
    if word(s,0)=={REQUEST} and op!=1 and op!=4:
        return 4294967293
''')
 before=f'    if op==1 and ((word(s,128)!={int.from_bytes(b"HIAMVEX1","little")} and word(s,128)!={int.from_bytes(b"HIAMVEX3","little")}) or word(s,136)!=0):\n'
 after=f'''    if op==1 and word(s,0)=={REQUEST} and word(s,128)!={INITIAL}:
        return 4294967293
    if op==1 and (((word(s,128)!={int.from_bytes(b"HIAMVEX1","little")} and word(s,128)!={int.from_bytes(b"HIAMVEX3","little")}) and (word(s,0)!={REQUEST} or word(s,128)!={INITIAL})) or word(s,136)!=0):
'''
 s=replace(s,before,after)
 marker='def valid_command(s:readbuf,o:mutbuf,kind:u64) -> u64:\n'
 s=replace(s,marker,marker+f'''    if word(s,0)=={REQUEST}:
        if kind!=1 or word(s,128)!={PUBLISH} or (word(s,136)!=1 and word(s,136)!=2):
            return 0
        return 1
''')
 return s
def main():
 tree=document(source_program(),'generation_lease_owner_runtime_handles')
 path=ROOT/'examples/hia_bootstrap/generation_lease_owner_runtime_handles.hepta'
 path.write_text(render_assembly(tree))
 print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
