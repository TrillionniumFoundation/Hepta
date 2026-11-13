"""Author a native Core workspace JSON-to-facts transport, not a resolver.

The HIA JSON decoder and this HIA traversal own framing and exact fact packet
construction. Actual module name/privacy/cycle policy remains the separate HIA
module graph image; Core materialization and build custody remain host bridges.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIAMOD01', 'little')
NONE = (1 << 64) - 1
TOKENS = ('schema','entry','modules','core','imports','exports','module',
          'functions','name','blocks','ops','op','attrs','function','alias','symbol',
          'hepta.hia.core-workspace.v1','call',
          *(f'hepta.hia.program.v{i}' for i in range(1,9)))

ADAPTER = r'''
def workspace_json(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 16785408:
        return 4294967294
    put(w, 48, 1048576)
    put(w, 56, 128)
    decoded = widen(decode_json(s, o, w))
    if decoded == 4294967294 or decoded == 4294967293:
        return 4294967294
    if decoded == 4294967295 or decoded == 4294967292:
        return 4294967295
    if decoded < 120 or decoded > length(o):
        return 4294967294
    if three_fields(o, 0, 1, 2, 3) == 0:
        return 4294967295
    schema = field(o, 0, 1)
    entry = field(o, 0, 2)
    modules = field(o, 0, 3)
    if workspace_token(o, schema) != 17 or kind(o, entry) != 4 or kind(o, modules) != 5:
        return 4294967295
    if get(o, 64 + modules * 56 + 32) < 1 or get(o, 64 + modules * 56 + 32) > 1024:
        return 4294967295
    phase = 0
    while phase < 2:
        at = 0
        while at < 64:
            put(w, at, 0)
            at = at + 8
        put(w, 64, phase)
        put(w, 128, 0)
        entry_offset = append_name(o, w, entry)
        if entry_offset == 18446744073709551615:
            return 4294967295
        if workspace_facts(o, w, modules) == 0:
            return 4294967295
        size = 80 + 32 * (get(w, 0) + get(w, 8)) + 56 * get(w, 16) + 24 * (get(w, 24) + get(w, 32)) + get(w, 40)
        if size > 8388608:
            return 4294967295
        if phase == 0:
            put(w, 72, 4096 + 80)
            put(w, 80, get(w, 72) + get(w, 0) * 32)
            put(w, 88, get(w, 80) + get(w, 8) * 32)
            put(w, 96, get(w, 88) + get(w, 16) * 56)
            put(w, 104, get(w, 96) + get(w, 24) * 24)
            put(w, 112, get(w, 104) + get(w, 32) * 24)
        else:
            put(w, 4096, 3544408014129809736)
            at = 0
            while at < 48:
                put(w, 4104 + at, get(w, at))
                at = at + 8
            put(w, 4152, entry_offset)
            put(w, 4160, get(o, 64 + entry * 56 + 32))
            put(w, 4168, 0)
            at = 0
            while at < size:
                store(o, at, byte(w, 4096 + at))
                at = at + 1
            return size
        phase = phase + 1
    return 4294967295


def workspace_facts(o:mutbuf, w:mutbuf, modules:u64) -> u64:
    module_node = get(o, 64 + modules * 56 + 24)
    mi = 0
    while mi < get(o, 64 + modules * 56 + 32):
        if three_fields(o, module_node, 4, 5, 6) == 0:
            return 0
        core = field(o, module_node, 4)
        imports = field(o, module_node, 5)
        exports = field(o, module_node, 6)
        if three_fields(o, core, 1, 7, 8) == 0 or kind(o, imports) != 5 or kind(o, exports) != 5:
            return 0
        version = workspace_token(o, field(o, core, 1))
        if version < 19 or version > 26:
            return 0
        if get(w, 128) == 0:
            put(w, 128, version)
        if get(w, 128) != version:
            return 0
        functions = field(o, core, 8)
        if kind(o, functions) != 5:
            return 0
        name_node = field(o, core, 7)
        name_offset = append_name(o, w, name_node)
        if name_offset == 18446744073709551615:
            return 0
        if get(w, 64) != 0:
            row = get(w, 72) + mi * 32
            put(w, row, name_offset)
            put(w, row + 8, get(o, 64 + name_node * 56 + 32))
            put(w, row + 16, get(w, 8))
            put(w, row + 24, get(o, 64 + functions * 56 + 32))
        fn = get(o, 64 + functions * 56 + 24)
        j = 0
        while j < get(o, 64 + functions * 56 + 32):
            if get(w, 8) >= 1024 or function_facts(o, w, fn, mi) == 0:
                return 0
            put(w, 8, get(w, 8) + 1)
            fn = get(o, 64 + fn * 56 + 16)
            j = j + 1
        item = get(o, 64 + imports * 56 + 24)
        j = 0
        while j < get(o, 64 + imports * 56 + 32):
            if get(w, 16) >= 4096 or three_fields(o, item, 15, 7, 16) == 0:
                return 0
            alias = field(o, item, 15)
            target_module = field(o, item, 7)
            symbol = field(o, item, 16)
            a = append_name(o, w, alias)
            b = append_name(o, w, target_module)
            c = append_name(o, w, symbol)
            if a == 18446744073709551615 or b == 18446744073709551615 or c == 18446744073709551615:
                return 0
            if get(w, 64) != 0:
                row = get(w, 88) + get(w, 16) * 56
                put(w, row, mi)
                put(w, row + 8, a)
                put(w, row + 16, get(o, 64 + alias * 56 + 32))
                put(w, row + 24, b)
                put(w, row + 32, get(o, 64 + target_module * 56 + 32))
                put(w, row + 40, c)
                put(w, row + 48, get(o, 64 + symbol * 56 + 32))
            put(w, 16, get(w, 16) + 1)
            item = get(o, 64 + item * 56 + 16)
            j = j + 1
        item = get(o, 64 + exports * 56 + 24)
        j = 0
        while j < get(o, 64 + exports * 56 + 32):
            if get(w, 32) >= 1024:
                return 0
            name_offset = append_name(o, w, item)
            if name_offset == 18446744073709551615:
                return 0
            if get(w, 64) != 0:
                row = get(w, 104) + get(w, 32) * 24
                put(w, row, mi)
                put(w, row + 8, name_offset)
                put(w, row + 16, get(o, 64 + item * 56 + 32))
            put(w, 32, get(w, 32) + 1)
            item = get(o, 64 + item * 56 + 16)
            j = j + 1
        put(w, 0, get(w, 0) + 1)
        module_node = get(o, 64 + module_node * 56 + 16)
        mi = mi + 1
    return 1


def function_facts(o:mutbuf, w:mutbuf, fn:u64, mi:u64) -> u64:
    if kind(o, fn) != 6:
        return 0
    name_node = field(o, fn, 9)
    blocks = field(o, fn, 10)
    name_offset = append_name(o, w, name_node)
    if name_offset == 18446744073709551615 or kind(o, blocks) != 5:
        return 0
    if get(w, 64) != 0:
        row = get(w, 80) + get(w, 8) * 32
        put(w, row, mi)
        put(w, row + 8, name_offset)
        put(w, row + 16, get(o, 64 + name_node * 56 + 32))
        put(w, row + 24, 0)
    block = get(o, 64 + blocks * 56 + 24)
    j = 0
    while j < get(o, 64 + blocks * 56 + 32):
        ops = field(o, block, 11)
        if kind(o, block) != 6 or kind(o, ops) != 5:
            return 0
        op = get(o, 64 + ops * 56 + 24)
        k = 0
        while k < get(o, 64 + ops * 56 + 32):
            if kind(o, op) != 6:
                return 0
            if workspace_token(o, field(o, op, 12)) == 18:
                attrs = field(o, op, 13)
                if kind(o, attrs) != 6 or get(w, 24) >= 16384:
                    return 0
                target = field(o, attrs, 14)
                name_offset = append_name(o, w, target)
                if name_offset == 18446744073709551615:
                    return 0
                if get(w, 64) != 0:
                    row = get(w, 96) + get(w, 24) * 24
                    put(w, row, get(w, 8))
                    put(w, row + 8, name_offset)
                    put(w, row + 16, get(o, 64 + target * 56 + 32))
                put(w, 24, get(w, 24) + 1)
            op = get(o, 64 + op * 56 + 16)
            k = k + 1
        block = get(o, 64 + block * 56 + 16)
        j = j + 1
    return 1


def append_name(o:mutbuf, w:mutbuf, node:u64) -> u64:
    if kind(o, node) != 4:
        return 18446744073709551615
    size = get(o, 64 + node * 56 + 32)
    at = get(w, 40)
    if size > 8388608 or at > 8388608 - size:
        return 18446744073709551615
    if get(w, 64) != 0:
        if get(w, 112) + at + size > length(w):
            return 18446744073709551615
        src = get(o, 64 + node * 56 + 24)
        j = 0
        while j < size:
            store(w, get(w, 112) + at + j, byte(o, src + j))
            j = j + 1
    put(w, 40, at + size)
    return at


def kind(o:mutbuf, node:u64) -> u64:
    if node >= get(o, 8):
        return 18446744073709551615
    return get(o, 64 + node * 56)


def field(o:mutbuf, node:u64, code:u64) -> u64:
    if kind(o, node) != 6:
        return 18446744073709551615
    child = get(o, 64 + node * 56 + 24)
    j = 0
    while j < get(o, 64 + node * 56 + 32):
        if token(o, get(o, 64 + child * 56 + 40), get(o, 64 + child * 56 + 48)) == code:
            return child
        child = get(o, 64 + child * 56 + 16)
        j = j + 1
    return 18446744073709551615


def workspace_token(o:mutbuf, node:u64) -> u64:
    if kind(o, node) != 4:
        return 0
    return token(o, get(o, 64 + node * 56 + 24), get(o, 64 + node * 56 + 32))


def three_fields(o:mutbuf, node:u64, a:u64, b:u64, c:u64) -> u64:
    if kind(o, node) != 6:
        return 0
    if get(o, 64 + node * 56 + 32) != 3:
        return 0
    if field(o, node, a) == 18446744073709551615 or field(o, node, b) == 18446744073709551615 or field(o, node, c) == 18446744073709551615:
        return 0
    return 1
'''


def source_program():
    assert MAGIC == 3544408014129809736
    groups = {}
    for number,word in enumerate(TOKENS,1):
        groups.setdefault(len(word.encode()),[]).append((number,word.encode()))
    text = '\ndef token(o:mutbuf, start:u64, size:u64) -> u64:\n'
    text += '    if start > length(o) or size > length(o) - start:\n        return 0\n'
    for size in sorted(groups):
        text += f'    if size == {size}:\n        return workspace_word_{size}(o, start)\n'
    text += '    return 0\n'
    for size,words in sorted(groups.items()):
        text += f'\ndef workspace_word_{size}(o:mutbuf, start:u64) -> u64:\n'
        for number,raw in words:
            end = (size // 8) * 8
            checks = [f'get(o, start + {at}) == {int.from_bytes(raw[at:at+8], "little")}' for at in range(0,end,8)]
            checks += [f'byte(o, start + {at}) == {raw[at]}' for at in range(end,size)]
            text += '    if ' + ' and '.join(checks) + f':\n        return {number}\n'
        text += '    return 0\n'
    return ADAPTER + text + decoder_source()


def document():
    nodes = ast.parse(source_program()).body
    assert len({n.name for n in nodes}) == len(nodes)
    names = {n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures = {n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes); functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total); builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],
                          'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'core_workspace_facts','functions':functions})


def main():
    out=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_workspace_facts.hepta'
    out.write_text(render_assembly(document())); print(out.name,out.stat().st_size)


if __name__=='__main__':
    main()
