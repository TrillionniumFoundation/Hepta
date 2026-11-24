"""Independent closed reference-VM code generator.

This separate profile preserves the original seed and resource backends.
HIAVMR01 carries an existing HIAERW02 projection with exactly three or seven
borrowed logical parameters at word 56. Mode 3 is the six-word SysV plan entry;
mode 7 is the original word/result-array private run entry. It admits only the borrowed operations
used by the complete reference VM, adds the separately qualified unsigned
division emitter, and produces the existing closed seven-section object.
No target selfhost compiler, host assembler, or linker is executed.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_owned_backend import program as owned_program
from tools.generate_hia_seed_div_backend import DIVISION

ROOT = Path(__file__).resolve().parents[1]
MAGIC = b'HIAVMR01'

PUBLIC = r'''
def public_entry(o:mutbuf, w:mutbuf) -> u64:
    count = get(w, 184)
    if count == 7:
        prologue(o, w, 48)
        save(o, w, 6, 5, 0 - 8)
        address(o, w, 6, 5, 0 - 32)
        patch(o, w, 35, 0, 9223372036854775808)
        load(o, w, 0, 5, 0 - 32)
        normalize(o, w, 32)
        load(o, w, 11, 5, 0 - 8)
        save(o, w, 0, 11, 0)
        enc(o, w, 31, 0, 0, 0, 0, 0)
        enc(o, w, 30, 0, 0, 0, 0, 0)
        return 0
    frame = count * 16 + 32
    arguments = 0 - count * 16 - 16
    prologue(o, w, frame)
    save(o, w, 7, 5, arguments)
    save(o, w, 6, 5, arguments + 8)
    save(o, w, 2, 5, arguments + 16)
    save(o, w, 1, 5, arguments + 24)
    save(o, w, 8, 5, arguments + 32)
    save(o, w, 9, 5, arguments + 40)
    index = 6
    while index < count * 2:
        load(o, w, 11, 5, 16 + (index - 6) * 8)
        save(o, w, 11, 5, arguments + index * 8)
        index = index + 1
    address(o, w, 7, 5, arguments)
    address(o, w, 6, 5, 0 - 16)
    patch(o, w, 35, 0, 9223372036854775808)
    load(o, w, 0, 5, 0 - 16)
    normalize(o, w, 32)
    enc(o, w, 31, 0, 0, 0, 0, 0)
    enc(o, w, 30, 0, 0, 0, 0, 0)
    return 0
'''


def program():
    tree = ast.parse(owned_program())
    counts = dict(entry=0, magic=0, arity=0, count=0, public=0,
                  unsigned=0, division=0, resources=0)
    for fn in tree.body:
        if fn.name == 'seed_owned_backend':
            fn.name = 'seed_vm_backend'
            counts['entry'] += 1
        if fn.name == 'borrowed_header':
            for node in ast.walk(fn):
                if isinstance(node, ast.Compare):
                    if ast.unparse(node) == f'word(s, 0) != {int.from_bytes(b"HIAERW02","little")}':
                        node.comparators[0] = ast.Constant(int.from_bytes(MAGIC,'little'))
                        counts['magic'] += 1
                if isinstance(node, ast.BoolOp):
                    for index, value in enumerate(node.values):
                        if ast.unparse(value) == 'word(s, 56) != 0':
                            node.values[index] = ast.parse(
                                'word(s, 56) != 3 and word(s, 56) != 7', mode='eval').body
                            counts['arity'] += 1
                if isinstance(node, ast.Call) and ast.unparse(node) == 'put(w, 256, 3)':
                    node.args[2] = ast.parse('word(s, 56)', mode='eval').body
                    counts['count'] += 1
            assert isinstance(fn.body[-1], ast.Return)
            fn.body[-1:-1] = ast.parse('put(w, 184, word(s, 56))').body
        if fn.name == 'public_entry':
            replacement = ast.parse(PUBLIC).body[0]
            fn.body = replacement.body
            counts['public'] += 1
        if fn.name == 'scalar_admit':
            node = fn.body[0]
            assert isinstance(node, ast.If)
            def flatten(value):
                if isinstance(value, ast.BoolOp) and isinstance(value.op, ast.Or):
                    return [piece for child in value.values for piece in flatten(child)]
                assert isinstance(value, ast.Compare) and ast.unparse(value.left) == 'op'
                assert len(value.ops) == 1 and isinstance(value.ops[0], ast.Eq)
                assert len(value.comparators) == 1 and isinstance(value.comparators[0], ast.Constant)
                return [value.comparators[0].value]
            assert flatten(node.test) == [4, 5, 6, 7, 8, 11, 26]
            node.test = ast.parse('op == 4 or op == 5 or op == 6 or op == 11 or op == 26', mode='eval').body
            counts['unsigned'] += 1
        if fn.name == 'scalar':
            positions = [i for i,node in enumerate(fn.body) if isinstance(node,ast.If)]
            assert len(positions) == 1
            at = positions[0]
            extension = ast.parse(DIVISION).body[0]
            extension.orelse = [fn.body[at]]
            fn.body[at] = extension
            counts['division'] += 1
        if fn.name == 'resource_admit':
            positions = [i for i,node in enumerate(fn.body)
                         if isinstance(node,ast.Assign) and ast.unparse(node) == 'want_in = 0']
            assert len(positions) == 1
            fn.body[positions[0]:positions[0]] = ast.parse(
                'if kind != 3 and kind != 4:\n    return 0\n'
                'if op != 3 and op != 4 and op != 5 and op != 7 and op != 9 and op != 12 and op != 14 and op != 24 and op != 25 and op != 26 and op != 27:\n    return 0'
            ).body
            counts['resources'] += 1
    assert counts == dict(entry=1, magic=1, arity=1, count=1, public=1,
                          unsigned=1, division=1, resources=1), counts
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n'


def main():
    doc = document(program(), 'seed_vm_backend')
    raw = render_assembly(doc).encode()
    path = ROOT/'examples/hia_bootstrap/seed_vm_backend.hepta'
    path.write_bytes(raw)
    print('SEED_VM_PROFILE', len(raw), len(doc['functions']),
          sum(len(f['blocks']) for f in doc['functions']),
          sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))


if __name__ == '__main__':
    main()
