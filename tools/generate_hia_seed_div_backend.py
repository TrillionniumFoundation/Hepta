"""Extend the independent borrowed seed with unsigned checked division only."""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_backend import program as base_program
ROOT=Path(__file__).resolve().parents[1]
DIVISION=r"""
if op == 7 or op == 8:
    enc(o, w, 15, 1, 1, 0, 0, 0)
    failure(o, w, 4)
    enc(o, w, 13, 2, 2, 0, 0, 0)
    enc(o, w, 21, 1, 0, 0, 0, 0)
    if op == 8:
        enc(o, w, 2, 0, 2, 0, 0, 0)
"""
def program():
 raw=base_program();needle='op == 4 or op == 5 or op == 6 or op == 7 or op == 8 or op == 11 or op == 26'
 if raw.count(needle)!=1:raise ValueError('borrowed scalar admission shape differs')
 tree=ast.parse(raw.replace(needle,'op == 4 or op == 5 or op == 6 or op == 11 or op == 26'))
 for fn in tree.body:
  if fn.name=='seed_backend':fn.name='seed_div_backend'
  if fn.name=='scalar':
   indexes=[i for i,n in enumerate(fn.body) if isinstance(n,ast.If)]
   if len(indexes)!=1:raise ValueError('borrowed scalar emission shape differs')
   i=indexes[0];extension=ast.parse(DIVISION).body[0];extension.orelse=[fn.body[i]];fn.body[i]=extension
 return ast.unparse(ast.fix_missing_locations(tree))
def main():
 d=document(program(),'seed_div_backend');raw=render_assembly(d).encode();(ROOT/'examples/hia_bootstrap/seed_div_backend.hepta').write_bytes(raw)
 print('SEED_DIV_BACKEND_SOURCE',len(raw),len(d['functions']),sum(len(f['blocks']) for f in d['functions']),sum(len(b['ops']) for f in d['functions'] for b in f['blocks']))
if __name__=='__main__':main()
