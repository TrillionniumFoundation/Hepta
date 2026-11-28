"""Preserve exact cold bulk/word emission and cache admitted word-store programs.

The complete original emitter remains the fallback for every source without
resource 26. Its admission, resources, scalar lowering and all byte/bulk output
bytes are retained. A separate scalar path reuses the same bounded workspace
words as the cold-endian profile, with fresh knowledge at every control entry.
"""
import ast
import copy
from hashlib import sha256
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_cold_backend import program as cold_program
from tools.generate_hia_seed_cold_endian_shift_backend import MARK, cache_program
from tools.hia_seed_word_store import add_word_store

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = "7943019c96438fd6f39bcc3905061a4be8e56d86516fe28c5e4f82c0b96ff565"

ELIGIBLE = """
def scalar_cache_eligible(s:readbuf,w:mutbuf) -> u64:
    at=get(w,40)
    while at < get(w,48):
        if word(s,at) == 38:
            if word(s,word(s,at+8)) == 26:
                return 1
        at=at+64
    return 0
"""


def word_program():
    return add_word_store(cold_program('bulk'), expected_entry='seed_cold_bulk_backend',
                          new_entry='seed_cold_bulk_word_backend')


def marked_program(parent):
    if sha256(parent.encode()).hexdigest() != ORIGINAL:
        raise ValueError("fixed cold bulk-word parent differs")
    original = ast.parse(parent)
    tree = copy.deepcopy(original)
    functions = {node.name: node for node in tree.body}
    generate = functions["generate"]
    old_generate = copy.deepcopy(generate)
    if ast.unparse(generate.body[3]) != "public_entry(o, w)":
        raise ValueError("fixed bulk-word entry marking differs")
    generate.body.insert(3, ast.parse("mark_shift_entries(s,w)").body[0])
    loop = next(node for node in generate.body if isinstance(node, ast.While))
    expected = ast.parse("put(w,8192+((at-get(w,40))>>6)*8,get(w,0))").body[0]
    positions = [i for i, node in enumerate(loop.body) if ast.dump(node) == ast.dump(expected)]
    if len(positions) != 1:
        raise ValueError("fixed bulk-word offset marking differs")
    index = positions[0]
    if ast.unparse(loop.body[index + 1]) != "instruction(s, o, w, at)":
        raise ValueError("fixed bulk-word instruction position differs")
    loop.body[index:index + 2] = ast.parse(
        "position=get(w,0)\ninstruction(s,o,w,at)\n"
        "put(w,8192+((at-get(w,40))>>6)*8,position)").body
    tree.body.append(ast.parse(MARK).body[0])
    inverse = copy.deepcopy(tree)
    inverse.body.pop()
    for i, node in enumerate(inverse.body):
        if node.name == "generate":
            inverse.body[i] = old_generate
    if ast.dump(inverse) != ast.dump(original):
        raise ValueError("bulk-word entry transform changed an original function")
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"


def cached_program(parent):
    marked = marked_program(parent)
    original = ast.parse(parent)
    originals = {node.name: node for node in original.body}
    optimized = ast.parse(cache_program(marked, profile="bulk-word"))
    optimized_functions = {node.name: node for node in optimized.body}
    tree = copy.deepcopy(original)
    functions = {node.name: node for node in tree.body}
    renames = {name: name + "_cached" for name in ("generate", "instruction", "scalar")}

    class Rename(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            node = self.generic_visit(node)
            if node.name in renames:
                node.name = renames[node.name]
            return node

        def visit_Name(self, node):
            if node.id in renames:
                node.id = renames[node.id]
            return node

    added = [Rename().visit(copy.deepcopy(optimized_functions[name])) for name in renames]
    added.extend(copy.deepcopy(node) for node in optimized.body if node.name not in originals)
    added.append(ast.parse(ELIGIBLE).body[0])
    if set(node.name for node in added).intersection(originals):
        raise ValueError("cold bulk-word cache function collides with an original")
    functions["generate"].body[0:0] = ast.parse(
        "if scalar_cache_eligible(s,w) != 0:\n"
        "    return generate_cached(s,o,w)\n").body
    tree.body.extend(added)
    inverse = copy.deepcopy(tree)
    inverse.body = inverse.body[:-len(added)]
    for node in inverse.body:
        if node.name == "generate":
            node.body = node.body[1:]
    if ast.dump(inverse) != ast.dump(original):
        raise ValueError("cold bulk-word cache changed the complete original fallback")
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"


def program():
    return cached_program(word_program())


def main():
    name = 'seed_cold_bulk_word_backend'
    result = render_assembly(document(program(), name)).encode()
    path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
    path.write_bytes(result)
    print('COLD_BULK_WORD_SOURCE', name, len(result), sha256(result).hexdigest())


if __name__ == '__main__':
    main()
