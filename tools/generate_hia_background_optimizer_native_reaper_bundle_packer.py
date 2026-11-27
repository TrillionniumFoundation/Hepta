"""Installed BG bundle variant with a fixed native reaper control hole."""
from pathlib import Path
import ast,struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_background_optimizer_native_bundle_packer as original
from tools import generate_hia_background_optimizer_native_reaper_context_packer as context
from tools import hia_background_managed_value_source as M
ROOT=Path(__file__).resolve().parents[1]
ROLES=original.ROLES
MAGIC=int.from_bytes(b'HIABGBP2','little')
HEADER=original.HEADER
IMPORTS=original.IMPORTS
EXPORTS=original.EXPORTS
OBJECT_MASK=original.OBJECT_MASK
def run(fn,*args):
    old_context,old_magic=original.context,original.MAGIC
    try:
        original.context=context;original.MAGIC=MAGIC
        return fn(*args)
    finally:original.context=old_context;original.MAGIC=old_magic
def source_program():
    source=run(original.source_program)
    hole=context.REAPER_HOLE
    publicslot=1536+8*ROLES.index('public')
    contextslot=512+8*ROLES.index('context')
    source=M.replace(source,'    emit_relocations(s,o,w)',
        f'    write(o,context_at+{hole},get(w,{publicslot})+544-context_at-{hole+4},4)\n    emit_relocations(s,o,w)')
    node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='fixed_holes')
    body=ast.get_source_segment(source,node)
    before='    return 1'
    assert body.count(before)==1
    body=body.replace(before,f'    if uint(s,get(w,{contextslot})+{hole-1},1)!=232 or uint(s,get(w,{contextslot})+{hole},4)!=0:\n        return 0\n    return 1')
    return M.replace_def(source,'fixed_holes',body)
def reference_object(parts):
    raw=bytearray(run(original.reference_object,parts))
    starts=[];at=64+len(original.BRIDGE)
    for i,p in enumerate(parts):
        body=original.inspect_object(p)[0]if OBJECT_MASK>>i&1 else p
        at=(at+15)&~15;starts.append(at);at+=len(body)
    at=starts[ROLES.index('context')]+context.REAPER_HOLE
    if raw[at-1]!=232 or raw[at:at+4]!=bytes(4):raise ValueError('fixed actual reaper hole')
    struct.pack_into('<i',raw,at,starts[ROLES.index('public')]+544-at-4)
    return bytes(raw)
def main():
    name='background_optimizer_native_reaper_bundle_packer'
    d=document(source_program(),name);p=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
    p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
