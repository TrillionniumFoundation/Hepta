"""Author the experimental UNPACK control owner; no object policy in Python.

This module is an author, not a production runtime import. The HIA machine owns
cardinality, the n+1 probe, diagnostic choice and all ordinary release order.
The value bridge remains explicitly dependent on CPython object primitives.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIAUNP01', 'little')

SOURCE = r'''
def unpack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128 or length(o) < 256 or length(w) < 256:
        return 4294967293
    if read(s, 0) != UNPACK_MAGIC:
        return 4294967293
    kind = read(s, 8)
    if get(w, 0) == 0:
        if kind != 0 or read(s, 16) != 0:
            return 4294967293
        arity = read(s, 24)
        profile = read(s, 32)
        if arity < 1 or arity > 4 or (profile != 31214 and profile != 31404):
            return 4294967293
        at = 64
        while at < 128:
            if read(s, at) != 0:
                return 4294967293
            at = at + 8
        # A new invocation requires fresh zero workspace. Cached state or
        # manual magic reset is not an admitted public entry.
        at = 0
        while at < 256:
            if get(w, at) != 0:
                return 4294967293
            at = at + 8
        put(w, 0, UNPACK_MAGIC)
        put(w, 24, arity)
        put(w, 32, profile)
        put(w, 64, read(s, 40))
        put(w, 72, read(s, 48))
        put(w, 80, read(s, 56))
        return request(o, w, 1, 2, 1, 0, 0, 10)
    if get(w, 0) != UNPACK_MAGIC or get(w, 8) == 99:
        return 4294967293
    if kind == 2:
        # An infrastructure failure seals the public adapter first. The
        # private abort packet reports mechanically owned cells, never a
        # replacement semantic outcome. HIA still chooses every release.
        if read(s, 16) != get(w, 16) or read(s, 24) & 18446744073709551107 != 0 or read(s, 32) > 1:
            return 4294967293
        at = 40
        while at < 128:
            if read(s, at) != 0:
                return 4294967293
            at = at + 8
        put(w, 48, read(s, 24))
        put(w, 56, read(s, 32))
        put(w, 120, 1)
        put(w, 8, 80)
    else:
        if kind != 1 or read(s, 16) != get(w, 16) or read(s, 24) != get(w, 88) or read(s, 40) > 1:
            return 4294967293
        at = 48
        while at < 128:
            if read(s, at) != 0:
                return 4294967293
            at = at + 8
        put(w, 128, read(s, 32))
        put(w, 56, read(s, 40))
    while True:
        phase = ((((((((0 | (byte(w, 8) << 0)) | (byte(w, 9) << 8)) | (byte(w, 10) << 16)) | (byte(w, 11) << 24)) | (byte(w, 12) << 32)) | (byte(w, 13) << 40)) | (byte(w, 14) << 48)) | (byte(w, 15) << 56))
        value = ((((((((0 | (byte(w, 128) << 0)) | (byte(w, 129) << 8)) | (byte(w, 130) << 16)) | (byte(w, 131) << 24)) | (byte(w, 132) << 32)) | (byte(w, 133) << 40)) | (byte(w, 134) << 48)) | (byte(w, 135) << 56))
        error = ((((((((0 | (byte(w, 56) << 0)) | (byte(w, 57) << 8)) | (byte(w, 58) << 16)) | (byte(w, 59) << 24)) | (byte(w, 60) << 32)) | (byte(w, 61) << 40)) | (byte(w, 62) << 48)) | (byte(w, 63) << 56))
        if phase == 10:
            if value == 0:
                if error == 0:
                    return 4294967293
                return request(o, w, 3, 0, 9, 0, 0, 11)
            if error != 0:
                return 4294967293
            put(w, 48, get(w, 48) | 4)
            put(w, 8, 20)
        elif phase == 11:
            if value == 0:
                put(w, 8, 80)
            else:
                return request(o, w, 4, 0, 1, 0, 0, 12)
        elif phase == 12:
            put(w, 112, value)
            return request(o, w, 5, 0, value, 0, 0, 13)
        elif phase == 13:
            if value != 0:
                put(w, 8, 80)
            else:
                return request(o, w, 6, 0, 1, 0, 0, 14)
        elif phase == 14:
            if value != 0:
                put(w, 8, 80)
            else:
                return request(o, w, 7, 0, get(w, 112), 0, 0, 15)
        elif phase == 15:
            return diagnostic(o, w, 1, value, 0)
        elif phase == 16:
            if value != 0 or error != 1:
                return 4294967293
            put(w, 8, 80)
        elif phase == 20:
            got = get(w, 40)
            if got < get(w, 24):
                return request(o, w, 2, 3 + got, 2, 0, 0, 21)
            return request(o, w, 2, 7, 2, 0, 0, 21)
        elif phase == 21:
            got = get(w, 40)
            if got < get(w, 24):
                if value == 0:
                    if error != 0:
                        put(w, 8, 80)
                    else:
                        return diagnostic(o, w, 2, get(w, 24), got)
                else:
                    if error != 0:
                        return 4294967293
                    put(w, 48, get(w, 48) | (1 << (3 + got)))
                    put(w, 40, got + 1)
                    put(w, 8, 20)
            else:
                if value == 0:
                    if error != 0:
                        put(w, 8, 80)
                    else:
                        return request(o, w, 9, 0, 2, 0, 0, 30)
                else:
                    if error != 0:
                        return 4294967293
                    put(w, 48, get(w, 48) | 128)
                    return request(o, w, 9, 0, 7, 0, 0, 25)
        elif phase == 25:
            put(w, 48, get(w, 48) & 18446744073709551487)
            # Release the excess value BEFORE the 3.14 exact-container size
            # observation: its finalizer is allowed to mutate the container.
            if get(w, 32) == 31404:
                return request(o, w, 4, 0, 1, 0, 0, 26)
            return diagnostic(o, w, 3, get(w, 24), 0)
        elif phase == 26:
            size_kind = 0
            if value == get(w, 64):
                size_kind = 1
            elif value == get(w, 72):
                size_kind = 2
            elif value == get(w, 80):
                size_kind = 3
            if size_kind == 0:
                return diagnostic(o, w, 3, get(w, 24), 0)
            return request(o, w, 10, 0, 1, size_kind, 0, 27)
        elif phase == 27:
            if value > get(w, 24):
                return diagnostic(o, w, 4, get(w, 24), value)
            return diagnostic(o, w, 3, get(w, 24), 0)
        elif phase == 30:
            put(w, 48, get(w, 48) & 18446744073709551611)
            if error != 0:
                put(w, 8, 80)
            else:
                return request(o, w, 11, 8, get(w, 24), 0, 0, 31)
        elif phase == 31:
            if value == 0:
                if error == 0:
                    return 4294967293
                put(w, 8, 80)
            else:
                if error != 0:
                    return 4294967293
                put(w, 48, get(w, 48) | 256)
                put(w, 104, 0)
                put(w, 8, 32)
        elif phase == 32:
            index = get(w, 104)
            if index < get(w, 24):
                return request(o, w, 12, 0, 8, index, 3 + index, 33)
            return request(o, w, 13, 0, 8, 0, 0, 34)
        elif phase == 33:
            index = get(w, 104)
            put(w, 48, get(w, 48) & (18446744073709551615 ^ (1 << (3 + index))))
            if error != 0:
                put(w, 8, 80)
            else:
                if value != 0:
                    return 4294967293
                put(w, 104, index + 1)
                put(w, 8, 32)
        elif phase == 34:
            if value != 0 or error != 0:
                return 4294967293
            return request(o, w, 9, 0, 8, 0, 0, 35)
        elif phase == 35:
            put(w, 48, get(w, 48) & 18446744073709551359)
            if error != 0 or get(w, 48) != 0:
                return 4294967293
            return complete(o, w, 0)
        elif phase == 80:
            mask = get(w, 48)
            selected = 0
            if mask & 128 != 0:
                selected = 7
            else:
                index = 6
                while index > 2:
                    if selected == 0 and mask & (1 << index) != 0:
                        selected = index
                    index = index - 1
                if selected == 0 and mask & 256 != 0:
                    selected = 8
                if selected == 0 and mask & 4 != 0:
                    selected = 2
            if selected != 0:
                put(w, 96, selected)
                return request(o, w, 9, 0, selected, 0, 0, 81)
            if get(w, 120) != 0:
                if error != 0:
                    return request(o, w, 15, 0, 9, 0, 0, 82)
                return complete(o, w, 2)
            if error != 1:
                return 4294967293
            return request(o, w, 14, 0, 9, 0, 0, 99)
        elif phase == 81:
            put(w, 48, get(w, 48) & (18446744073709551615 ^ (1 << get(w, 96))))
            put(w, 8, 80)
        elif phase == 82:
            if error != 0:
                return 4294967293
            return complete(o, w, 2)
        else:
            return 4294967293
    return 4294967293

def request(o:mutbuf, w:mutbuf, opcode:u64, destination:u64, a:u64, b:u64, c:u64, phase:u64) -> u64:
    seq = get(w, 16)
    if seq == 18446744073709551615:
        return 4294967293
    seq = seq + 1
    put(w, 16, seq)
    put(w, 8, phase)
    put(w, 88, opcode)
    at = 0
    while at < 256:
        put(o, at, 0)
        at = at + 8
    put(o, 0, UNPACK_MAGIC)
    put(o, 8, seq)
    put(o, 16, opcode)
    put(o, 24, destination)
    put(o, 32, a)
    put(o, 40, b)
    put(o, 48, c)
    return 1

def diagnostic(o:mutbuf, w:mutbuf, kind:u64, a:u64, b:u64) -> u64:
    exception = choose(kind == 1, 1, 2)
    status = request(o, w, 8, 0, exception, a, b, 16)
    if status != 1:
        return status
    FORMAT_EMISSION
    return status

def complete(o:mutbuf, w:mutbuf, status:u64) -> u64:
    put(w, 8, 99)
    at = 0
    while at < 256:
        put(o, at, 0)
        at = at + 8
    put(o, 0, UNPACK_MAGIC)
    put(o, 8, get(w, 16))
    put(o, 16, status)
    return status

WORD_HELPERS
'''

FORMATS = (
    'cannot unpack non-iterable %.200s object',
    'not enough values to unpack (expected %d, got %d)',
    'too many values to unpack (expected %d)',
    'too many values to unpack (expected %d, got %zd)',
)


def source():
    emissions = []
    for number, text in enumerate(FORMATS, 1):
        emissions.append(('if' if number == 1 else 'elif') + f' kind == {number}:')
        for offset, byte in enumerate(text.encode('ascii') + b'\0', 128):
            emissions.append(f'    store(o, {offset}, {byte})')
    helpers = []
    for name, buffer_type in (('read', 'readbuf'), ('get', 'mutbuf')):
        helpers.extend([f'def {name}(w:{buffer_type}, index:u64) -> u64:', '    value = 0'])
        for i in range(8):
            helpers.append(f'    value = value | (byte(w, index + {i}) << {i * 8})')
        helpers.append('    return value')
    helpers.append('def put(w:mutbuf, index:u64, value:u64) -> u64:')
    for i in range(8):
        helpers.append(f'    store(w, index + {i}, value >> {i * 8})')
    helpers.append('    return value')
    return SOURCE.replace('UNPACK_MAGIC', str(MAGIC)).replace(
        'FORMAT_EMISSION', '\n    '.join(emissions)).replace('WORD_HELPERS', '\n'.join(helpers))


def document():
    nodes = ast.parse(source()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'core_unpack', 'functions': functions})


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    assembly = render_assembly(document())
    if args.output is None:
        target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_unpack.hiaasm'
        target.write_text(assembly)
    else:
        target = args.output
        with target.open('x') as handle:
            handle.write(assembly)
    print(target.name, target.stat().st_size)


if __name__ == '__main__':
    main()
