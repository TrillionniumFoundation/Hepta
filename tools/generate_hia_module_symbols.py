"""Author module declaration/alias admission and complete name/privacy policy in HIA.

Host code transports AST facts and materializes returned strings/diagnostics.
Path IO, package loading, source traversal, and AST rewriting are not claimed here.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = 5208780291693556277
SOURCE = r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or length(s) > 8388608 or length(o) < 16:
        return 4294967293
    if word(s, 0) != @MAGIC@ or word(s, 56) != 0:
        return 4294967293
    nd = word(s, 16)
    ni = word(s, 24)
    if nd > 174762 or ni > 349525:
        return 4294967293
    base = 64 + nd * 48 + ni * 24
    if base > length(s) or valid_range(s, base, word(s, 32), word(s, 40)) == 0 or word(s, 48) > 1:
        return 4294967293
    i = 0
    while i < nd:
        row = 64 + i * 48
        flags = word(s, row + 40)
        if word(s, row) > ni or flags > 15 or (flags & 3) == 0 or (flags & 3) == 3:
            return 4294967293
        if valid_range(s, base, word(s, row + 8), word(s, row + 16)) == 0 or valid_range(s, base, word(s, row + 24), word(s, row + 32)) == 0:
            return 4294967293
        i = i + 1
    i = 0
    while i < ni:
        row = 64 + nd * 48 + i * 24
        if word(s, row + 16) != i + 1 or valid_range(s, base, word(s, row), word(s, row + 8)) == 0:
            return 4294967293
        i = i + 1
    op = word(s, 8)
    if op == 1:
        i = 0
        while i < nd:
            a = 64 + i * 48
            if word(s, a) == 0:
                j = 0
                while j < i:
                    b = 64 + j * 48
                    if word(s, b) == 0 and equal(s, word(s, a + 8), word(s, a + 16), word(s, b + 8), word(s, b + 16)) == 1:
                        return result(s, o, 1, 0, 0, 0, 0)
                    j = j + 1
            i = i + 1
        return result(s, o, 0, 0, 0, 0, 0)
    if op == 2:
        at = word(s, 32)
        size = word(s, 40)
        if declaration(s, 0, at, size, 0) != 0 or imported(s, at, size) != 0:
            return result(s, o, 2, 0, 0, 0, 0)
        return result(s, o, 0, 0, 0, 0, 0)
    if op != 3:
        return 4294967293
    return resolve(s, o)

def valid_range(s:readbuf, base:u64, at:u64, size:u64) -> u64:
    if at < base or at > length(s):
        return 0
    return choose(size <= length(s) - at, 1, 0)

def equal(s:readbuf, a:u64, an:u64, b:u64, bn:u64) -> u64:
    if an != bn:
        return 0
    i = 0
    while i < an:
        if byte(s, a + i) != byte(s, b + i):
            return 0
        i = i + 1
    return 1

def separator(s:readbuf, at:u64, size:u64) -> u64:
    i = 0
    while i + 1 < size:
        if byte(s, at + i) == 58 and byte(s, at + i + 1) == 58:
            return i
        i = i + 1
    return size

def declaration(s:readbuf, scope:u64, at:u64, size:u64, types:u64) -> u64:
    i = 0
    while i < word(s, 16):
        row = 64 + i * 48
        if word(s, row) == scope and (types == 0 or (word(s, row + 40) & 1) == 1):
            if equal(s, at, size, word(s, row + 8), word(s, row + 16)) == 1:
                return row
        i = i + 1
    return 0

def imported(s:readbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < word(s, 24):
        row = 64 + word(s, 16) * 48 + i * 24
        if equal(s, at, size, word(s, row), word(s, row + 8)) == 1:
            return i + 1
        i = i + 1
    return 0

def resolve(s:readbuf, o:mutbuf) -> u32:
    at = word(s, 32)
    size = word(s, 40)
    first = separator(s, at, size)
    if first == size:
        row = declaration(s, 0, at, size, word(s, 48))
        if row == 0:
            return result(s, o, 0, at, size, 0, 0)
        return result(s, o, 0, word(s, row + 24), word(s, row + 32), 0, 0)
    scope = imported(s, at, first)
    if scope != 0:
        start = at + first + 2
        left = size - first - 2
        second = separator(s, start, left)
        row = declaration(s, scope, start, second, choose(second < left, 1, word(s, 48)))
        if row == 0:
            return result(s, o, 3, 0, 0, 0, 0)
        if (word(s, row + 40) & 12) == 0:
            return result(s, o, 4, 0, 0, 0, 0)
        return result(s, o, 0, word(s, row + 24), word(s, row + 32), start + second, left - second)
    row = declaration(s, 0, at, first, 1)
    if row != 0:
        return result(s, o, 0, word(s, row + 24), word(s, row + 32), at + first, size - first)
    if first == 6:
        if byte(s, at) == 82 and byte(s, at + 1) == 101 and byte(s, at + 2) == 115 and byte(s, at + 3) == 117 and byte(s, at + 4) == 108 and byte(s, at + 5) == 116:
            return result(s, o, 0, at, size, 0, 0)
    return result(s, o, 5, 0, 0, 0, 0)

def result(s:readbuf, o:mutbuf, code:u64, at:u64, size:u64, suffix:u64, tail:u64) -> u32:
    if size + tail > length(o) - 16:
        return 4294967294
    put(o, 0, code)
    put(o, 8, size + tail)
    i = 0
    while i < size:
        store(o, 16 + i, byte(s, at + i))
        i = i + 1
    i = 0
    while i < tail:
        store(o, 16 + size + i, byte(s, suffix + i))
        i = i + 1
    return 16 + size + tail
'''


def source_program():
    from tools.generate_hia_type_parser import source_program as type_program
    helpers=ast.parse(type_program()).body
    source=SOURCE.replace('@MAGIC@',str(MAGIC))
    for node in helpers:
        if node.name in ('read_word','put'):
            text=ast.get_source_segment(type_program(),node)
            if node.name=='read_word':text=text.replace('def read_word(', 'def word(', 1)
            source+='\n'+text+'\n'
    return source


def document():
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'module_symbols','functions':functions})


def main():
    p=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/module_symbols.hiaasm'
    p.write_text(render_assembly(document()));print(p.name,p.stat().st_size)


if __name__=='__main__':main()
