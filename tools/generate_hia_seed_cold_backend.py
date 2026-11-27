"""Author cold construction profiles with compact constants and identity edges.

The original v1, word, endian, bulk and division profiles are unchanged. These
two new profiles preserve their parent admission, instruction emission, call
staging and ABI. A block edge's parallel assignment omits ``slot == index``
from both passes. All other sources are captured before any destination write.

Constants below 2**32 use the original encoder's zero-extending 32-bit MOV
form; all other u64 constants retain the 64-bit form. Both preserve flags and
the complete register value. The original encoder and its validation are used
unchanged, including the REX prefix required for registers eight to fifteen.

Each destination index occurs once, so an omitted identity destination cannot
be overwritten by another assignment. Its value remains available to every
nonidentity source during the first pass, including fanout and cycles. The
second pass reads only captured values. Calls retain the original complete
bounce staging, and the stack frame probing and every buffer guard are intact.

The author uses the original seed language. B1 is constructed by the original
v1 seed; the new emitter then reaches its own B2 == B3 fixed point. That is a
separate claim from the retained original profiles' B1 == B2 == B3 gate.
"""
from pathlib import Path
import ast

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_bulk_backend import program as bulk_program
from tools.generate_hia_seed_endian_backend import program as endian_program

ROOT = Path(__file__).resolve().parents[1]
PARENTS = {'bulk': bulk_program, 'endian': endian_program}

ORIGINAL_EDGE = '''
def edge(s:readbuf,o:mutbuf,w:mutbuf,record:u64)->u64:
    count=word(s,record+16)
    stage(s,o,w,word(s,record+8),count)
    index=0
    while index<count:
        load(o,w,0,5,get(w,96)+index*8)
        value_save(o,w,0,index)
        index=index+1
    patch(o,w,33,0,word(s,record))
    return 0
'''

COLD_EDGE = '''
def edge(s:readbuf,o:mutbuf,w:mutbuf,record:u64)->u64:
    count=word(s,record+16)
    list=word(s,record+8)
    index=0
    while index<count:
        slot=word(s,list+index*8)
        if slot!=index:
            value_load(o,w,0,slot)
            save(o,w,0,5,get(w,96)+index*8)
        index=index+1
    index=0
    while index<count:
        if word(s,list+index*8)!=index:
            load(o,w,0,5,get(w,96)+index*8)
            value_save(o,w,0,index)
        index=index+1
    patch(o,w,33,0,word(s,record))
    return 0
'''

ORIGINAL_IMMEDIATE = '''
def immediate(o:mutbuf,w:mutbuf,reg:u64,value:u64)->u64:
    return enc(o,w,3,reg,0,value,0,0)
'''

COMPACT_IMMEDIATE = '''
def immediate(o:mutbuf,w:mutbuf,reg:u64,value:u64)->u64:
    return enc(o,w,3,reg,0,value,0,choose(value<4294967296,1,0))
'''


def specialize(source, profile):
    if profile not in PARENTS:
        raise ValueError('undeclared cold seed profile')
    tree = ast.parse(source)
    entries = [node for node in tree.body
               if isinstance(node, ast.FunctionDef)
               and node.name == 'seed_' + profile + '_backend']
    edges = [node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name == 'edge']
    immediates = [node for node in tree.body
                  if isinstance(node, ast.FunctionDef) and node.name == 'immediate']
    if (len(entries) != 1 or len(edges) != 1 or len(immediates) != 1
            or ast.dump(edges[0]) != ast.dump(ast.parse(ORIGINAL_EDGE).body[0])
            or ast.dump(immediates[0]) != ast.dump(ast.parse(ORIGINAL_IMMEDIATE).body[0])):
        raise ValueError('cold seed parent source shape differs')
    entries[0].name = 'seed_cold_' + profile + '_backend'
    tree.body[tree.body.index(edges[0])] = ast.parse(COLD_EDGE).body[0]
    tree.body[tree.body.index(immediates[0])] = ast.parse(COMPACT_IMMEDIATE).body[0]
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n'


def program(profile):
    return specialize(PARENTS[profile](), profile)


def main():
    for profile in PARENTS:
        name = 'seed_cold_' + profile + '_backend'
        doc = document(program(profile), name)
        raw = render_assembly(doc).encode()
        path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
        path.write_bytes(raw)
        print('COLD_SEED_SOURCE', name, len(raw), len(doc['functions']),
              sum(len(f['blocks']) for f in doc['functions']),
              sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))


if __name__ == '__main__':
    main()
