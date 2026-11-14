"""Independent roundtrip controller owner, initially authored without qualification.

The frozen file/render failure prefix runs first. Only its accepted presentation
enters a separately captured three-request representation resident. The original
JSON, rendered assembly, first canonical wire and reparse wire occupy explicit
nonoverlapping slices of the existing 8MiB+1 file buffer. Every resident call
still uses three distinct owners, never mutable aliases of the same owner.
"""
from pathlib import Path
import ast
import hashlib
import inspect
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import generate_hia_native_file_read as reader
from tools.generate_hia_selfhost import total_scalar_functions, compact_authoring_cfg, TYPES
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_linux_file_roundtrip import PROFILE, MODULE

RUN = r'''
def run(f:mutbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(f) != 8388609 or length(o) != 1048576 or length(w) != 1048576:
        return 126
    if argc() != 3:
        return refuse(w, 64, 1, 0)
    if arglen(1) != 15:
        return refuse(w, 64, 1, 0)
    copied = argcopy(w, 0, 1, 0, 15)
    if copied != 15 or uint(w, 0, 8) != COMMAND_FIRST or uint(w, 8, 7) != COMMAND_LAST:
        return refuse(w, 64, 1, 0)
    raw_size = arglen(2)
    if raw_size > 524287:
        return refuse(w, 65, 1, raw_size)
    got = argcopy(w, 524288, 2, 0, raw_size)
    if got != raw_size:
        return 126
    path_size = path(w, 524288, raw_size, 256)
    if path_size > 262143:
        return refuse(w, 65, 1, path_size)
    fill_range(w, 0, 128, 0)
    write(w, 64, path_size, 8)
    status = bounded_read(f, w, 8388608)
    if status != 0:
        return refuse(w, 66, status, uint(w, 16, 8))
    wire_size = uint(w, 24, 8)
    # The actual file descriptor is already closed. Retain the old frontend
    # and semantic failure order before introducing a new roundtrip decision.
    fill_range(w, 0, 1048576, 0)
    write(w, 0, RENDER_MAGIC, 8)
    write(w, 48, 262144, 8)
    write(w, 56, 64, 8)
    rendered = raw_word(representation(f, 0, wire_size, o, 0, 1048576, w, 0, 1048576))
    if rendered == 0 or rendered > 1048576:
        return refuse(w, 67, 2, rendered)
    if rendered < 33:
        return refuse(w, 67, 2, rendered)
    schema_version = uint(o, 30, 1)
    if schema_version != 54 and schema_version != 55 and schema_version != 56:
        return refuse(w, 67, 2, schema_version)
    write(o, 30, 56, 1)
    fill_range(w, 0, 1048576, 0)
    checked = raw_word(semantic(o, 0, rendered, f, 4194304, 1048576, w, 0, 1048576))
    write(o, 30, schema_version, 1)
    if checked != 0:
        return refuse(w, 68, 3, uint(w, 40, 8))
    # A successful original preflight has slots<=131072 in its 1MiB key table;
    # key_bound=(wire_size>>2)+1 and MAX_NODES=262144 imply wire_size<=262143.
    # Keep the implication checked before using any later file-buffer slices.
    if wire_size > 262143:
        return refuse(w, 69, 4, wire_size)
    copy_region(f, o, 2097152, 0, rendered)
    fill_range(w, 0, 1048576, 0)
    write(w, 0, CANONICAL_MAGIC, 8)
    write(w, 8, 4300, 8)
    canonical_size = raw_word(representation(f, 0, wire_size, o, 0, 1048576, w, 0, 1048576))
    if canonical_size == 0 or canonical_size > wire_size:
        return refuse(w, 69, 4, canonical_size)
    copy_region(f, o, 1048576, 0, canonical_size)
    fill_range(w, 0, 1048576, 0)
    write(w, 0, REPARSE_MAGIC, 8)
    reparsed = raw_word(representation(f, 2097152, rendered, o, 0, 1048576, w, 0, 1048576))
    if reparsed == 0 or reparsed > 1048576:
        return refuse(w, 70, 5, reparsed)
    copy_region(f, o, 3145728, 0, reparsed)
    fill_range(w, 0, 1048576, 0)
    write(w, 0, CANONICAL_MAGIC, 8)
    write(w, 8, 4300, 8)
    second_size = raw_word(representation(f, 3145728, reparsed, o, 0, 1048576, w, 0, 1048576))
    if second_size == 0 or second_size > reparsed:
        return refuse(w, 71, 6, second_size)
    if second_size != canonical_size:
        return refuse(w, 72, 7, second_size)
    if same_region(f, 1048576, o, 0, canonical_size) == 0:
        return refuse(w, 72, 7, canonical_size)
    sent = send(f, 2097152, rendered, 1)
    if sent != 0:
        return 120
    return 0

def copy_region(destination:mutbuf, source:mutbuf, out:u64, begin:u64, count:u64) -> u64:
    index = 0
    while index < count:
        store(destination, out + index, byte(source, begin + index))
        index = index + 1
    return 0

def same_region(left:mutbuf, left_begin:u64, right:mutbuf, right_begin:u64, count:u64) -> u64:
    index = 0
    while index < count:
        if byte(left, left_begin + index) != byte(right, right_begin + index):
            return 0
        index = index + 1
    return 1

def refuse(w:mutbuf, status:u32, phase:u64, detail:u64) -> u32:
    write(w, 0, RESULT_MAGIC, 8)
    write(w, 8, raw_word(status), 8)
    write(w, 16, phase, 8)
    write(w, 24, detail, 8)
    sent = send(w, 0, 32, 2)
    if sent != 0:
        return 121
    return status
'''
for name, raw in {'COMMAND_FIRST':b'render-a', 'COMMAND_LAST':b'ssembly', 'RESULT_MAGIC':b'HRENDR1\x00',
                  'RENDER_MAGIC':b'HIARFR01', 'REPARSE_MAGIC':b'HIARPR01', 'CANONICAL_MAGIC':b'HIACIR01'}.items():
    RUN = RUN.replace(name, str(int.from_bytes(raw,'little')))


def author_source():
    retained = [ast.unparse(node) for node in ast.parse(reader.author_source()).body if node.name != 'run']
    return RUN + '\n\n' + '\n\n'.join(retained) + '\n'


class RoundtripBuilder(reader.FileBuilder):
    def expr(self, node):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in ('representation','semantic'):
            assert len(node.args)==9 and not node.keywords
            args=[self.expr(value) for value in node.args]
            args=[value if i in (0,3,6) else self.cast(value,'usize') for i,value in enumerate(args)]
            return self.op('linux.roundtrip.'+node.func.id,args,'u32')
        return super().expr(node)


def document():
    nodes=ast.parse(author_source()).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=RoundtripBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name], 'params':[builder.param(value) for value in builder.params],
            'returns':[builder.returns], 'effects':['read','write','trap','linux_io','linux_startup','linux_file','linux_roundtrip'],
            'entry':'b0','blocks':builder.blocks})
    doc={'schema':'hepta.hia.program.v8','module':MODULE,'functions':functions}
    tree=ast.parse(inspect.getsource(compact_authoring_cfg));changes=0
    for node in ast.walk(tree):
        if isinstance(node,ast.ImportFrom) and node.module=='hepta.hia_program':
            assert [(value.name,value.asname) for value in node.names]==[('verify_program',None)]
            node.module='hepta.hia_linux_file_roundtrip';node.names=[ast.alias(name='verify_linux_file_roundtrip_program',asname='verify_program')];changes+=1
    assert changes==1;ast.fix_missing_locations(tree);namespace={'TYPES':TYPES}
    exec(compile(tree,'<fixed-roundtrip-author-CFG>','exec'),namespace)
    result=namespace['compact_authoring_cfg'](doc)
    for before,after in zip(doc['functions'],result['functions'],strict=True):
        assert [op for b in before['blocks'] for op in b['ops']]==[op for b in after['blocks'] for op in b['ops']]
    return result


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args(argv)
    doc=document();raw=render_assembly(doc,profile=PROFILE).encode()
    target=ROOT/'examples/hia_bootstrap/native_file_roundtrip.hepta'
    if args.check: assert target.read_bytes()==raw
    else: target.write_bytes(raw)
    print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'functions':len(doc['functions']),
        'blocks':sum(len(f['blocks']) for f in doc['functions']),
        'operations':sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),
        'matching_cold':False,'whole':False},sort_keys=True))


if __name__=='__main__':
    main()
