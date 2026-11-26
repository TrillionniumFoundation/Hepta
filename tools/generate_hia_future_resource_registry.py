"""Private compound-resource registry with native alias and unlink facts.

The byte owner remains the retained payload algorithm. A separate protocol and
context domain expose an actual sole-reference query and consumption at unlink.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_multiversion_background_payload as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIAFRG01',REPLY='HIAFRGR1',STATE='HIAFRGS1',
 OBJECT='HIAFRGO1',NODE_MAGIC='HIAFRGN1').items()})
C.update(KNOWN=496,CONSUMED=504)
def replace(text,before,after):
    assert text.count(before)==1,before
    return text.replace(before,after)
def source_program():
    text=replace(original.SOURCE,'def multiversion_background_payload(', 'def future_resource_registry(')
    text=replace(text,'if op>6 or','if op>7 or')
    text=replace(text,"""    if phase==20:
        if get(w,24)!=0:""",
"""    if phase==20:
        put(o,KNOWN,1)
        if get(w,24)!=0:""")
    text=replace(text,"""        if op==6:
            put(o,LIMIT,get(o,OBJ)+96)
            return fail(o,0)""",
"""        if op==6 or op==7:
            put(o,LIMIT,get(o,OBJ)+96)
            put(o,DROP_OBJECT,sole_reference(o))
            return fail(o,0)""")
    text=replace(text,"""    if phase==504:
        return deallocate(o,505,get(o,CAP))""",
"""    if phase==504:
        put(o,CONSUMED,1)
        return deallocate(o,505,get(o,CAP))""")
    text=replace(text,"""    put(o,64,borrowed)
    return 0""",
"""    put(o,64,borrowed)
    put(o,72,get(o,DROP_OBJECT))
    put(o,80,get(o,KNOWN))
    put(o,88,get(o,CONSUMED))
    return 0""")
    text+='\ndef sole_reference(o:mutbuf) -> u64:\n    if get(o,NODE+32)!=0:\n        return 0\n    return choose(get(o,NODE+40)==0,1,0)\n'
    present={n.name for n in ast.parse(original.SOURCE).body if isinstance(n,ast.FunctionDef)}
    for node in ast.parse(original.source_program()).body:
        if isinstance(node,ast.FunctionDef)and node.name not in present:
            text+=chr(10)+ast.unparse(node)+chr(10)
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    doc=document(source_program(),'future_resource_registry')
    p=ROOT/'examples/hia_bootstrap/future_resource_registry.hepta';p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
