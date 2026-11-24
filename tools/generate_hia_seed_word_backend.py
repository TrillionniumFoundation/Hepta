"""Author a separate independent v1 seed profile adding bounded word stores.

The original v1 source and profile stay byte-for-byte unchanged. Resource 26
requires a mutable view, exactly three input values and no result. Both complete
range checks precede the sole eight-byte store, including full-u64 indices.
The author is compiled by the original independent v1 profile.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_backend import program as base_program
ROOT=Path(__file__).resolve().parents[1]


def program():
    module=ast.parse(base_program());counts={'entry':0,'admit':0,'width':0,'write':0}
    for fn in module.body:
        if fn.name=='seed_backend':
            fn.name='seed_word_backend';counts['entry']+=1
        if fn.name=='resource_admit':
            for node in list(ast.walk(fn)):
                if isinstance(node,ast.If) and ast.unparse(node.test)=='op == 5':
                    node.test=ast.parse('op == 5 or op == 26',mode='eval').body;counts['admit']+=1
        if fn.name=='resource':
            for node in list(ast.walk(fn)):
                if isinstance(node,ast.If) and ast.unparse(node.test)=='code == 24':
                    # The first occurrence checks the complete eight-byte range;
                    # the second is the read branch and must remain read-only.
                    if any(isinstance(x,ast.Expr) and isinstance(x.value,ast.Call) and isinstance(x.value.func,ast.Name) and x.value.func.id=='immediate' for x in node.body):
                        node.test=ast.parse('code == 24 or code == 26',mode='eval').body;counts['width']+=1
                if isinstance(node,ast.If) and ast.unparse(node.test)=='code == 5':
                    replacement=ast.parse('if code == 26:\n    value_load(o,w,2,word(s,inputs+16))\n    save(o,w,2,0,0)\n    return 0').body[0]
                    replacement.orelse=[ast.If(test=node.test,body=node.body,orelse=node.orelse)]
                    node.test=replacement.test;node.body=replacement.body;node.orelse=replacement.orelse;counts['write']+=1
    assert counts=={'entry':1,'admit':1,'width':1,'write':1},counts
    return ast.unparse(ast.fix_missing_locations(module))+'\n'


def main():
    doc=document(program(),'seed_word_backend');raw=render_assembly(doc).encode()
    path=ROOT/'examples/hia_bootstrap/seed_word_backend.hepta';path.write_bytes(raw)
    print(path.name,len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))
if __name__=='__main__':main()
