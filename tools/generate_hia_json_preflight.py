"""Author a bounded JSON syntax preflight in ordinary HIA Core.

Development-time AST authoring only. The resulting checked-in HIA assembly is
compiled by the native selfhost compiler, not by a Python JSON implementation.
This does not replace the JSON value decoder or the full Core frontend.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE = r'''
def preflight(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(w) < 128:
        return 3
    maximum = get(w, 48)
    maximum_depth = get(w, 56)
    if maximum < 1 or maximum > 1048576 or maximum_depth > 128:
        return 3
    if length(w) < 128 + (maximum_depth + 1) * 32:
        return 3
    # Even before a missing value is found, every inserted key consumed at
    # least four wire bytes, except the one currently waiting for its value.
    key_bound = choose(maximum < (length(s) >> 2) + 1, maximum, (length(s) >> 2) + 1)
    slots = 2
    while slots < key_bound * 2:
        slots = slots * 2
    if length(o) < slots * 8:
        return 3
    clear = 0
    while clear < slots * 8:
        put(o, clear, 0)
        clear = clear + 8
    put(w, 0, 0)
    nodes = 0
    depth = 0
    want_value = True
    done = False
    while True:
        index = whitespace(s, get(w, 0))
        put(w, 0, index)
        if done:
            if index == length(s):
                return 0
            return 1
        if want_value:
            if index >= length(s):
                return 1
            nodes = nodes + 1
            if nodes > maximum or depth > maximum_depth:
                return 2
            ch = byte(s, index)
            if ch == 91 or ch == 123:
                slot = 128 + depth * 32
                put(w, slot, choose(ch == 91, 1, 2))
                put(w, slot + 8, 0)
                put(w, slot + 16, index + 1)
                depth = depth + 1
                put(w, 0, index + 1)
            else:
                if ch == 34:
                    result = string_token(s, w)
                    if result != 0:
                        return 1
                else:
                    result = atom(s, index)
                    if result == 4294967295:
                        return 1
                    put(w, 0, result)
                if depth == 0:
                    done = True
                else:
                    put(w, 128 + (depth - 1) * 32 + 8, 5)
            want_value = False
        else:
            if depth == 0:
                return 1
            slot = 128 + (depth - 1) * 32
            kind = get(w, slot)
            state = get(w, slot + 8)
            ch = 256
            if index < length(s):
                ch = byte(s, index)
            closing = False
            if kind == 1:
                if state == 0 or state == 1:
                    if state == 0 and ch == 93:
                        closing = True
                    else:
                        put(w, slot + 8, 4)
                        want_value = True
                else:
                    if state != 5:
                        return 1
                    if ch == 44:
                        put(w, 0, index + 1)
                        put(w, slot + 8, 1)
                    else:
                        if ch == 93:
                            closing = True
                        else:
                            return 1
            else:
                if state == 0 or state == 1:
                    if state == 0 and ch == 125:
                        closing = True
                    else:
                        if ch != 34:
                            return 1
                        result = string_token(s, w)
                        if result != 0:
                            return 1
                        result = insert_key(s, o, w, slots, get(w, slot + 16), index + 1)
                        if result != 0:
                            return result
                        put(w, slot + 8, 2)
                else:
                    if state == 2:
                        if ch != 58:
                            return 1
                        put(w, 0, index + 1)
                        put(w, slot + 8, 3)
                    else:
                        if state == 3:
                            put(w, slot + 8, 4)
                            want_value = True
                        else:
                            if state != 5:
                                return 1
                            if ch == 44:
                                put(w, 0, index + 1)
                                put(w, slot + 8, 1)
                            else:
                                if ch == 125:
                                    closing = True
                                else:
                                    return 1
            if closing:
                put(w, 0, index + 1)
                depth = depth - 1
                if depth == 0:
                    done = True
                else:
                    put(w, 128 + (depth - 1) * 32 + 8, 5)
    return 1

def whitespace(s:readbuf, index:u64) -> u64:
    going = True
    while going and index < length(s):
        ch = byte(s, index)
        if ch == 32 or ch == 9 or ch == 10 or ch == 13:
            index = index + 1
        else:
            going = False
    return index

def atom(s:readbuf, index:u64) -> u64:
    size = length(s)
    if size - index >= 4:
        if byte(s, index) == 116 and byte(s, index + 1) == 114 and byte(s, index + 2) == 117 and byte(s, index + 3) == 101:
            return index + 4
        if byte(s, index) == 110 and byte(s, index + 1) == 117 and byte(s, index + 2) == 108 and byte(s, index + 3) == 108:
            return index + 4
    if size - index >= 5:
        if byte(s, index) == 102 and byte(s, index + 1) == 97 and byte(s, index + 2) == 108 and byte(s, index + 3) == 115 and byte(s, index + 4) == 101:
            return index + 5
    if byte(s, index) == 45:
        index = index + 1
    if index >= size:
        return 4294967295
    ch = byte(s, index)
    if ch < 48 or ch > 57:
        return 4294967295
    if ch == 48:
        return index + 1
    going = True
    while going and index < size:
        ch = byte(s, index)
        if ch >= 48 and ch <= 57:
            index = index + 1
        else:
            going = False
    return index

def string_token(s:readbuf, w:mutbuf) -> u64:
    index = get(w, 0) + 1
    hash = 14695981039346656037
    going = True
    while going:
        unit = decoded(s, index)
        cp = unit & 4294967295
        if cp == 1114113:
            return 1
        index = unit >> 32
        if cp == 1114112:
            going = False
        else:
            hash = (hash ^ cp) * 1099511628211
    put(w, 0, index)
    put(w, 40, hash)
    return 0

def insert_key(s:readbuf, o:mutbuf, w:mutbuf, slots:u64, scope:u64, start:u64) -> u64:
    # Every key belongs to its exact object's opening byte, not merely depth.
    # Closed and sibling scopes cannot alias. Entries never need tombstones.
    slot = (get(w, 40) ^ (scope * 1099511628211)) & (slots - 1)
    probes = 0
    while probes < slots:
        item = get(o, slot * 8)
        if item == 0:
            put(o, slot * 8, (scope << 32) | start)
            return 0
        if item >> 32 == scope:
            if same_key(s, item & 4294967295, start) == 1:
                return 4
        slot = (slot + 1) & (slots - 1)
        probes = probes + 1
    return 3

def same_key(s:readbuf, left:u64, right:u64) -> u64:
    going = True
    while going:
        l = decoded(s, left)
        r = decoded(s, right)
        cp = l & 4294967295
        if cp != r & 4294967295:
            return 0
        if cp == 1114112:
            return 1
        if cp == 1114113:
            return 0
        left = l >> 32
        right = r >> 32
    return 0

def hex4(s:readbuf, index:u64) -> u64:
    if index + 4 > length(s):
        return 4294967295
    count = 0
    value = 0
    while count < 4:
        ch = byte(s, index + count)
        digit = 16
        if ch >= 48 and ch <= 57:
            digit = ch - 48
        if ch >= 65 and ch <= 70:
            digit = ch - 55
        if ch >= 97 and ch <= 102:
            digit = ch - 87
        if digit == 16:
            return 4294967295
        value = value * 16 + digit
        count = count + 1
    return value

def decoded(s:readbuf, index:u64) -> u64:
    # Packed next-byte offset and Unicode scalar. Two out-of-range sentinels
    # distinguish closing quote from invalid grammar; escaped quotes are scalars.
    size = length(s)
    if index >= size:
        return 1114113
    ch = byte(s, index)
    index = index + 1
    if ch == 34:
        return (index << 32) | 1114112
    if ch < 32:
        return 1114113
    if ch == 92:
        if index >= size:
            return 1114113
        esc = byte(s, index)
        index = index + 1
        if esc == 34 or esc == 92 or esc == 47:
            return (index << 32) | esc
        if esc == 98:
            return (index << 32) | 8
        if esc == 102:
            return (index << 32) | 12
        if esc == 110:
            return (index << 32) | 10
        if esc == 114:
            return (index << 32) | 13
        if esc == 116:
            return (index << 32) | 9
        if esc != 117:
            return 1114113
        cp = hex4(s, index)
        if cp == 4294967295:
            return 1114113
        index = index + 4
        if cp >= 55296 and cp <= 56319:
            if index + 6 > size:
                return 1114113
            if byte(s, index) != 92 or byte(s, index + 1) != 117:
                return 1114113
            low = hex4(s, index + 2)
            if low < 56320 or low > 57343:
                return 1114113
            cp = 65536 + (cp - 55296) * 1024 + low - 56320
            index = index + 6
        else:
            if cp >= 56320 and cp <= 57343:
                return 1114113
        return (index << 32) | cp
    if ch < 128:
        return (index << 32) | ch
    needed = 0
    minimum = 0
    cp = 0
    if ch >= 194 and ch <= 223:
        needed = 1
        minimum = 128
        cp = ch & 31
    if ch >= 224 and ch <= 239:
        needed = 2
        minimum = 2048
        cp = ch & 15
    if ch >= 240 and ch <= 244:
        needed = 3
        minimum = 65536
        cp = ch & 7
    if needed == 0 or index + needed > size:
        return 1114113
    count = 0
    while count < needed:
        ch = byte(s, index)
        if ch < 128 or ch > 191:
            return 1114113
        cp = cp * 64 + (ch & 63)
        index = index + 1
        count = count + 1
    if cp < minimum or cp > 1114111:
        return 1114113
    if cp >= 55296 and cp <= 57343:
        return 1114113
    return (index << 32) | cp

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    count = 0
    while count < 8:
        value = value | (byte(w, index + count) << (count * 8))
        count = count + 1
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    count = 0
    while count < 8:
        store(w, index + count, value >> (count * 8))
        count = count + 1
    return value
'''


def document():
    nodes = ast.parse(SOURCE).body
    names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'json_preflight', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/json_preflight.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
