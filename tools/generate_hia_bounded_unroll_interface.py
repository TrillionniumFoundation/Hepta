"""Development author for the exact bounded candidate interface projections.
Runtime input is independently admitted canonical primitive Core. The output
contains module fields, ordered names, and ordered function comparison records.
The public owner checks these in the original validator's order.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_bounded_unroll_transform import SOURCE as TRANSFORM_SOURCE
from tools.generate_hia_multiversion_proof_graph import policy as proof_policy
from tools.generate_hia_core_inspect_json import document, source_program
SOURCE = "\ndef bounded_unroll_interface(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n    if length(s)>8388608 or length(o)<128 or length(w)<33554432:\n        return 4294967293\n    selected=get(o,0)\n    put(o,48,262144)\n    put(o,56,64)\n    end=widen(decode_json(s,w,o))\n    if end>=4294967292:\n        return end\n    if end+16384>length(w):\n        return 4294967293\n    functions=field(w,0,K_functions)\n    if functions==NONE or kind(w,functions)!=5:\n        return 4294967292\n    put(w,8,end)\n    put(w,56,128)\n    append_byte(o,w,123)\n    node=child(w,0)\n    used=0\n    while node!=NONE:\n        if key_id(w,node)!=K_functions:\n            if used!=0:\n                append_byte(o,w,44)\n            bu_key(o,w,node)\n            fragment(s,o,w,node,0,0)\n            used=used+1\n        node=next_node(w,node)\n    append_byte(o,w,125)\n    module_end=get(w,56)\n    append_byte(o,w,91)\n    fn=child(w,functions)\n    while fn!=NONE:\n        fragment(s,o,w,field(w,fn,K_name),0,0)\n        fn=next_node(w,fn)\n        if fn!=NONE:\n            append_byte(o,w,44)\n    append_byte(o,w,93)\n    inventory_end=get(w,56)\n    fn=child(w,functions)\n    index=0\n    while fn!=NONE:\n        row=get(w,56)\n        put(w,56,row+32)\n        reason=0\n        if index==selected:\n            reason=ui_profile(w,fn,end)\n            ui_signature(s,o,w,fn)\n        else:\n            fragment(s,o,w,fn,0,0)\n        if row+32<=length(o):\n            put(o,row,index)\n            put(o,row+8,choose(index==selected,1,0))\n            put(o,row+16,reason)\n            put(o,row+24,get(w,56)-row-32)\n        fn=next_node(w,fn)\n        index=index+1\n    size=get(w,56)\n    if size>length(o) or size>33554432:\n        return 4294967293\n    at=0\n    while at<128:\n        put(o,at,0)\n        at=at+8\n    put(o,0,INTERFACE_MAGIC)\n    put(o,8,module_end-128)\n    put(o,16,inventory_end-module_end)\n    put(o,24,size-inventory_end)\n    put(o,32,index)\n    put(o,40,selected)\n    put(o,48,size)\n    return size\n\ndef ui_signature(s:readbuf,o:mutbuf,w:mutbuf,fn:u64) -> u64:\n    lit(o,w,'[[')\n    param=child(w,field(w,fn,K_params))\n    while param!=NONE:\n        fragment(s,o,w,field(w,param,K_type),0,0)\n        param=next_node(w,param)\n        if param!=NONE:\n            append_byte(o,w,44)\n    lit(o,w,'],')\n    fragment(s,o,w,field(w,fn,K_returns),0,0)\n    append_byte(o,w,93)\n    return 0\n\ndef ui_profile(w:mutbuf,fn:u64,table:u64) -> u64:\n    reason=profile_reason(w,fn)\n    if reason!=0:\n        return reason\n    n=count(w,field(w,fn,K_blocks))\n    put(w,8,table)\n    block=child(w,field(w,fn,K_blocks))\n    i=0\n    while block!=NONE:\n        row=table+64*i\n        put(w,row,block)\n        put(w,row+8,field(w,block,K_id))\n        put(w,row+16,n)\n        put(w,row+24,n)\n        put(w,row+32,n)\n        put(w,row+40,0)\n        put(w,row+48,0)\n        put(w,row+56,0)\n        block=next_node(w,block)\n        i=i+1\n    entry=block_slot(w,n,field(w,fn,K_entry))\n    if entry>=n:\n        return 30\n    if graph_order(w,n,entry)==0:\n        return 9\n    return 0\n"

def program():
    key=next(ast.get_source_segment(TRANSFORM_SOURCE,n) for n in ast.parse(TRANSFORM_SOURCE).body if isinstance(n,ast.FunctionDef) and n.name=='bu_key')
    policy=SOURCE.replace('INTERFACE_MAGIC',str(int.from_bytes(b'HIABUI01','little')))+key+'\n'+proof_policy()
    nodes=ast.parse(source_program(entry=policy)).body
    retained={'bounded_unroll_interface'}
    while True:
        called={c.func.id for node in nodes if node.name in retained for c in ast.walk(node) if isinstance(c,ast.Call) and isinstance(c.func,ast.Name)}
        if called<=retained:break
        retained.update(called)
    source=ast.unparse(ast.Module(body=[n for n in nodes if n.name in retained],type_ignores=[]))
    return document(source,'bounded_unroll_interface')
if __name__=='__main__':
    p=program()
    output=Path('examples/hia_bootstrap/bounded_unroll_interface.hepta')
    output.write_text(render_assembly(p))
    print(output,len(p['functions']),sum(len(f['blocks']) for f in p['functions']),sum(len(b['ops']) for f in p['functions'] for b in f['blocks']),output.stat().st_size)
