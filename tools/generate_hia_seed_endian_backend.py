"""Author an independent bounded seed profile for native endian word access.

The original v1 and word-store seed profiles remain unchanged. Resource 25
adds only the already specified Core v9 big-endian u64 load. It retains the
same complete eight-byte range guard as resource 24 and emits a BSWAP after
the load. Resource descriptors, result/operand counts and all bounds remain
checked. This author is a development aid; the generated HIA is the input to
the original independent native seed pipeline.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_word_backend import program as word_program

ROOT=Path(__file__).resolve().parents[1]

def program():
    tree=ast.parse(word_program())
    counts={'entry':0,'admit':0,'width':0,'read':0}
    for fn in tree.body:
        if fn.name=='seed_word_backend':
            fn.name='seed_endian_backend';counts['entry']+=1
        elif fn.name=='resource_admit':
            for n in ast.walk(fn):
                if isinstance(n,ast.If) and ast.unparse(n.test)=='op == 4 or op == 24':
                    n.test=ast.parse('op == 4 or op == 24 or op == 25',mode='eval').body
                    counts['admit']+=1
        elif fn.name=='resource':
            for n in list(ast.walk(fn)):
                if not isinstance(n,ast.If):continue
                if ast.unparse(n.test)=='code == 24 or code == 26':
                    n.test=ast.parse('code == 24 or code == 25 or code == 26',mode='eval').body
                    counts['width']+=1
                elif ast.unparse(n.test)=='code == 24':
                    assert len(n.body)==1 and ast.unparse(n.body[0])=='load(o, w, 0, 0, 0)'
                    n.test=ast.parse('code == 24 or code == 25',mode='eval').body
                    n.body.extend(ast.parse('if code == 25:\n    emit(o,w,72)\n    emit(o,w,15)\n    emit(o,w,200)').body)
                    counts['read']+=1
    assert counts=={'entry':1,'admit':1,'width':1,'read':1},counts
    return ast.unparse(ast.fix_missing_locations(tree))+'\n'

def main():
    doc=document(program(),'seed_endian_backend')
    raw=render_assembly(doc).encode()
    path=ROOT/'examples/hia_bootstrap/seed_endian_backend.hepta'
    path.write_bytes(raw)
    print(path.name,len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))

if __name__=='__main__':main()
