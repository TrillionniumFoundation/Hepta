"""Development candidate for complete, pairwise-disjoint SHA input blocks.

All but the last complete block use scalar schedule words. The last complete
block still executes the original compression, restoring the entire original
1184-byte state layout before the update returns. The checked native view
dispatcher and original alias fallback are unchanged.
"""
import ast
import copy
from hashlib import sha256


def round_source(key, word, first=False):
    if first:
        upper = 's1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))\n'
        lower = 's0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))\n'
    else:
        upper = 'cold_e = e * 4294967297\ns1 = (cold_e >> 6) ^ (cold_e >> 11) ^ (cold_e >> 25)\n'
        lower = 'cold_a = a * 4294967297\ns0 = (cold_a >> 2) ^ (cold_a >> 13) ^ (cold_a >> 22)\n'
    return upper + f'''choose_bits = g ^ (e & (f ^ g))
t1 = h + s1 + choose_bits + word_load(w, {key}) + {word}
''' + lower + '''majority = (a & b) | (c & (a | b))
t2 = s0 + majority
h = g
g = f
f = e
e = (d + t1) & 4294967295
d = c
c = b
b = a
a = (t1 + t2) & 4294967295
'''


def indent(source, amount):
    return ''.join(' ' * amount + line + '\n' for line in source.splitlines())


def helper_source():
    group = 4
    source = 'def compress_complete_blocks(s:readbuf,w:mutbuf,at:u64,end:u64) -> u64:\n'
    for j, name in enumerate('abcdefgh'):
        source += f'    chain_{name} = word_load(w, {1024 + j * 8})\n'
    source += '    while at < end:\n'
    for j in range(8):
        source += f'        input_word = word_load_be(s, at + {j * 8})\n'
        source += f'        word_{j * 2} = input_word >> 32\n'
        source += f'        word_{j * 2 + 1} = input_word & 4294967295\n'
    for name in 'abcdefgh':
        source += f'        {name} = chain_{name}\n'
    for j in range(16):
        source += indent(round_source(str(j * 8), f'word_{j}', first=j == 0), 8)
    source += '        i = 16\n        while i < 64:\n            round_at = i * 8\n'
    for j in range(group):
        x = f'word_{j + 1}' if j < 15 else f'next_{j - 15}'
        y = f'word_{j + 14}' if j < 2 else f'next_{j - 2}'
        prior = f'word_{j + 9}' if j < 7 else f'next_{j - 7}'
        schedule = f'''x = {x}
y = {y}
cold_x = x * 4294967297
cold_y = y * 4294967297
sx = (cold_x >> 7) ^ (cold_x >> 18) ^ (x >> 3)
sy = (cold_y >> 17) ^ (cold_y >> 19) ^ (y >> 10)
next_{j} = (word_{j} + sx + {prior} + sy) & 4294967295
'''
        source += indent(schedule + round_source(f'round_at + {j * 8}', f'next_{j}'), 12)
    for j in range(16 - group):
        source += f'            word_{j} = word_{j + group}\n'
    for j in range(group):
        source += f'            word_{j + 16 - group} = next_{j}\n'
    source += f'            i = i + {group}\n'
    for name in 'abcdefgh':
        source += f'        chain_{name} = (chain_{name} + {name}) & 4294967295\n'
    source += '        at = at + 64\n'
    for j, name in enumerate('abcdefgh'):
        source += f'    word_store(w, {1024 + j * 8}, chain_{name})\n'
    return source + '    return at\n'


def prove_complete_blocks_source(original):
    if sha256(original.encode()).hexdigest() != "1d681d9790960ed11820af77fde9a1ddb945db74bab249a751eed9a442b41131":
        raise ValueError("cold nonalias SHA source identity changed")
    module = ast.parse(original)
    untouched = ast.dump(module)
    stream = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'stream')
    update = next(n for n in stream.body if isinstance(n, ast.If) and ast.unparse(n.test) == 'op == 1')
    loop = next(n for n in update.body if isinstance(n, ast.While))
    assert ast.unparse(loop.test) == 'i < length(s)'
    assert len(loop.body) == 1 and isinstance(loop.body[0], ast.If)
    assert ast.unparse(loop.body[0].test) == 'used == 0 and length(s) - i >= 64'
    added = ast.parse('''if used == 0 and length(s) - i >= 128:
    i = compress_complete_blocks(s, w, i, i + (((length(s) - i) >> 6) - 1) * 64)
''').body[0]
    loop.body.insert(0, added)
    helper = ast.parse(helper_source()).body[0]
    module.body.append(helper)
    output = ast.unparse(ast.fix_missing_locations(module)) + '\n'
    loop.body.pop(0)
    module.body.pop()
    assert ast.dump(module) == untouched
    return output, {'schema': 'hepta.hia.sha-complete-blocks-source-candidate.v1',
                    'original_source_sha256': sha256(original.encode()).hexdigest(),
                    'candidate_source_sha256': sha256(output.encode()).hexdigest(),
                    'original_compress_and_all_other_bodies_unchanged': True,
                    'complete_inverse_original_ast_equal': True,
                    'whole_cold_qualified': False}


def complete_blocks_source(original):
    return prove_complete_blocks_source(original)[0]
