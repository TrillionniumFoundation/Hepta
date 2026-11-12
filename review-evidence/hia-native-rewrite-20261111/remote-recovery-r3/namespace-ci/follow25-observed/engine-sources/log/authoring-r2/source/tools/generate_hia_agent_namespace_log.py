"""Author the streaming immutable namespace record codec, physical revision 1.

No host record scanner, value parser or SQL implementation is called by HIA.
Actual segment/view/commit composition remains explicit development work.
"""
from __future__ import annotations
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES, catalog
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIANLG01', 'little')
RECORD_MAGIC = int.from_bytes(b'HIANLR01', 'little')

LOG = r'''
def namespace_log(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        return 4294967293
    if get(w, 8) == 4 or get(w, 8) == 5:
        return emit(o, w, 4294967293, 0)
    if length(o) < 192:
        return poison(w, 1)
    if get(w, 0) == 0:
        at = 0
        while at < 1024:
            if byte(w, at) != 0:
                poison(w, 2)
                return emit(o, w, 4294967293, 0)
            at = at + 1
        put(w, 0, LOG_MAGIC)
        put(w, 8, 1)
    if valid_state(w) == 0:
        poison(w, 2)
        return emit(o, w, 4294967293, 0)
    if frame(s, w) == 0:
        poison(w, 3)
        return emit(o, w, 4294967293, 0)
    copy_input(w, s, 320, 0, 128)
    move_workspace(w, 512, 0, 320)
    put(w, 520, phase(w))
    command = read64(s, 8)
    emitted = 0
    status = 2
    if command == 1 or command == 4:
        begin(s, w, 512)
        if command == 1:
            emitted = 64
    elif command == 2:
        if feed_payload(s, w, 512, 128, length(s)) == 0:
            poison(w, 4)
            return emit(o, w, 4294967293, 0)
        put(w, 624, get(w, 608))
        emitted = length(s) - 128
    elif command == 5:
        if decode_chunk(s, w, 512) == 0:
            poison(w, 5)
            return emit(o, w, 4294967293, 0)
    elif command == 3 or command == 6:
        if payload_complete(w, 512) == 0:
            poison(w, 6)
            return emit(o, w, 4294967293, 0)
        if command == 6:
            if get(w, 704) != 64 or get(w, 712) != 16 or get(w, 624) != get(w, 616):
                poison(w, 6)
                return emit(o, w, 4294967293, 0)
        else:
            put(w, 800, get(w, 616))
            put(w, 808, RECORD_MAGIC_VALUE)
            put(w, 712, 16)
            emitted = 16
        put(w, 520, 1)
        put(w, 816, 1)
        status = 0
    else:
        put(w, 544, read64(s, 32))
        put(w, 560, 0)
        put(w, 520, 5)
        status = 0
    if emitted > 18446744073709551423:
        poison(w, 7)
        return emit(o, w, 4294967293, 0)
    if length(o) < 192 + emitted:
        put(w, 448, phase(w))
        put(w, 456, 192 + emitted)
        put(w, 8, 3)
        return emit(o, w, 1, 0)
    if command != 1 and command != 4 and command != 7:
        put(w, 560, read64(s, 40))
    move_workspace(w, 0, 512, 320)
    put(w, 448, 0)
    put(w, 456, 0)
    emit(o, w, status, emitted)
    if command == 1:
        copy_workspace(o, w, 192, 224, 64)
    elif command == 2:
        copy_input(o, s, 192, 128, emitted)
    elif command == 3:
        copy_workspace(o, w, 192, 288, 16)
    return status

def poison(w:mutbuf, reason:u64) -> u64:
    if get(w, 8) != 4:
        put(w, 120, reason)
    put(w, 8, 4)
    return 4294967293

def phase(w:mutbuf) -> u64:
    if get(w, 8) == 3:
        return get(w, 448)
    return get(w, 8)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != LOG_MAGIC or phase(w) < 1 or phase(w) > 2:
        return 0
    if get(w, 8) == 3:
        if get(w, 456) <= 192:
            return 0
    elif get(w, 8) != 1 and get(w, 8) != 2:
        return 0
    elif get(w, 448) != 0 or get(w, 456) != 0:
        return 0
    if get(w, 120) != 0 or get(w, 208) != 0 or get(w, 216) != 0 or get(w, 304) > 1 or get(w, 312) != 0:
        return 0
    if get(w, 32) == 0:
        if phase(w) != 1:
            return 0
        at = 16
        while at < 320:
            if get(w, at) != 0:
                return 0
            at = at + 8
        return 1
    if get(w, 16) == 0 and get(w, 24) == 0:
        return 0
    if phase(w) == 1:
        if get(w, 304) != 1 or get(w, 192) != 64 or get(w, 200) != 16 or payload_complete(w, 0) == 0:
            return 0
    elif get(w, 304) != 0:
        return 0
    if get(w, 40) < 1 or get(w, 40) > 2 or get(w, 56) == 0:
        return 0
    if get(w, 192) > 64 or get(w, 200) > 16:
        return 0
    if get(w, 192) < 64:
        if get(w, 40) != 2 or get(w, 112) != get(w, 192):
            return 0
        at = 64
        while at < 112:
            if get(w, at) != 0:
                return 0
            at = at + 8
        if get(w, 128) != 0 or get(w, 136) != 0 or get(w, 144) != 0 or get(w, 152) != 0 or get(w, 160) != 0 or get(w, 168) != 0 or get(w, 176) != 0 or get(w, 184) != 0 or get(w, 200) != 0:
            return 0
        return 1
    if metadata(get(w, 64), get(w, 72), get(w, 80), get(w, 88)) == 0:
        return 0
    if get(w, 104) != 80 + get(w, 88) or get(w, 96) > get(w, 88):
        return 0
    expected = choose(get(w, 64) == 3, 1, choose(get(w, 64) == 2, 0, row_width(get(w, 72))))
    if get(w, 128) != expected or get(w, 136) > expected or get(w, 144) > 16 or get(w, 176) > 8:
        return 0
    if get(w, 40) == 1:
        if get(w, 112) != get(w, 96):
            return 0
    elif get(w, 112) != 64 + get(w, 96) + get(w, 200):
        return 0
    if get(w, 200) != 0 and payload_complete(w, 0) == 0:
        return 0
    if get(w, 64) == 2:
        if get(w, 96) != 0 or get(w, 136) != 0 or get(w, 144) != 0 or get(w, 152) != 0 or get(w, 160) != 0 or get(w, 168) != 0 or get(w, 176) != 0 or get(w, 184) != 0:
            return 0
    elif get(w, 176) < 8:
        if get(w, 96) != get(w, 176) or get(w, 184) >> (get(w, 176) * 8) != 0:
            return 0
        if get(w, 136) != 0 or get(w, 144) != 0 or get(w, 152) != 0 or get(w, 160) != 0 or get(w, 168) != 0:
            return 0
    else:
        if get(w, 184) != expected or get(w, 96) < 8 or get(w, 136) > (get(w, 96) - 8) >> 4:
            return 0
        if get(w, 136) == expected and get(w, 144) != 0:
            return 0
        header = get(w, 144)
        if header < 8:
            if get(w, 160) != 0 or get(w, 168) != 0 or get(w, 152) >> (header * 8) != 0:
                return 0
        elif header < 16:
            if get(w, 168) != 0 or get(w, 160) >> ((header - 8) * 8) != 0:
                return 0
        else:
            if get(w, 152) == 0 or get(w, 152) > 4 or get(w, 160) == 0 or get(w, 168) == 0 or get(w, 168) > get(w, 160):
                return 0
            if (get(w, 152) == 1 or get(w, 152) == 2) and get(w, 160) != 8:
                return 0
    if phase(w) == 1 and payload_complete(w, 0) == 0:
        return 0
    return 1

def metadata(kind:u64, table:u64, rowid:u64, size:u64) -> u64:
    if kind < 1 or kind > 3 or table < 1 or table > 10 or size > 18446744073709551535:
        return 0
    if kind == 2:
        return choose(size == 0, 1, 0)
    if kind == 3:
        if table != 5 or rowid != 0:
            return 0
        return choose(size >= 24, 1, 0)
    return choose(size >= 8 + row_width(table) * 16, 1, 0)

def zero(s:readbuf, start:u64, end:u64) -> u64:
    at = start
    while at < end:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    return 1

def frame(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 128 or read64(s, 0) != LOG_MAGIC or read64(s, 112) != 0 or read64(s, 120) != 0:
        return 0
    if read64(s, 16) == 0 and read64(s, 24) == 0:
        return 0
    if get(w, 32) != 0:
        if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24):
            return 0
    command = read64(s, 8)
    if command < 1 or command > 7 or read64(s, 104) != length(s) - 128:
        return 0
    if get(w, 8) == 3:
        at = 0
        while at < 128:
            if read64(s, at) != get(w, 320 + at):
                return 0
            at = at + 8
    if command == 1 or command == 4 or command == 7:
        if phase(w) != 1 or get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
            return 0
        if read64(s, 40) != 0 or read64(s, 48) != 0 or read64(s, 96) != 0 or read64(s, 104) != 0:
            return 0
        if command == 7:
            return zero(s, 56, 96)
        if read64(s, 56) <= get(w, 56):
            return 0
        if command == 4:
            return zero(s, 64, 96)
        return metadata(read64(s, 64), read64(s, 72), read64(s, 80), read64(s, 88))
    if phase(w) != 2 or read64(s, 32) != get(w, 32) or read64(s, 56) != get(w, 56):
        return 0
    if get(w, 48) == 18446744073709551615 or read64(s, 40) != get(w, 48) + 1:
        return 0
    if get(w, 40) == 1:
        if command != 2 and command != 3:
            return 0
        at = 64
        while at < 96:
            if read64(s, at) != get(w, at):
                return 0
            at = at + 8
        if read64(s, 96) != get(w, 96):
            return 0
    else:
        if command != 5 and command != 6:
            return 0
        if zero(s, 64, 96) == 0 or read64(s, 96) != get(w, 112):
            return 0
    if command == 2 or command == 5:
        return choose(read64(s, 48) != 0, 1, 0)
    return choose(read64(s, 48) == 0 and read64(s, 104) == 0, 1, 0)

def begin(s:readbuf, w:mutbuf, b:u64) -> u64:
    fill_range(w, b + 16, 304, 0)
    put(w, b + 8, 2)
    put(w, b + 16, read64(s, 16))
    put(w, b + 24, read64(s, 24))
    put(w, b + 32, read64(s, 32))
    put(w, b + 40, choose(read64(s, 8) == 1, 1, 2))
    put(w, b + 56, read64(s, 56))
    if read64(s, 8) == 1:
        put(w, b + 64, read64(s, 64))
        put(w, b + 72, read64(s, 72))
        put(w, b + 80, read64(s, 80))
        put(w, b + 88, read64(s, 88))
        put(w, b + 104, 80 + read64(s, 88))
        put(w, b + 128, choose(read64(s, 64) == 3, 1, choose(read64(s, 64) == 2, 0, row_width(read64(s, 72)))))
        put(w, b + 192, 64)
        put(w, b + 224, RECORD_MAGIC_VALUE)
        put(w, b + 232, 1)
        put(w, b + 240, read64(s, 64))
        put(w, b + 248, read64(s, 72))
        put(w, b + 256, read64(s, 80))
        put(w, b + 264, read64(s, 88))
        put(w, b + 272, 80 + read64(s, 88))
    return 0

def complete_cell(w:mutbuf, b:u64) -> u64:
    put(w, b + 136, get(w, b + 136) + 1)
    put(w, b + 144, 0)
    put(w, b + 152, 0)
    put(w, b + 160, 0)
    put(w, b + 168, 0)
    return 0

def feed_payload(s:readbuf, w:mutbuf, b:u64, cursor:u64, end:u64) -> u64:
    if end - cursor > get(w, b + 88) - get(w, b + 96):
        return 0
    while cursor < end:
        if get(w, b + 176) < 8:
            put(w, b + 184, get(w, b + 184) | (byte(s, cursor) << (get(w, b + 176) * 8)))
            put(w, b + 176, get(w, b + 176) + 1)
            put(w, b + 96, get(w, b + 96) + 1)
            cursor = cursor + 1
            if get(w, b + 176) == 8 and get(w, b + 184) != get(w, b + 128):
                return 0
        else:
            if get(w, b + 136) == get(w, b + 128):
                return 0
            header = get(w, b + 144)
            while header < 16 and cursor < end:
                value = byte(s, cursor)
                if header < 8:
                    put(w, b + 152, get(w, b + 152) | (value << (header * 8)))
                else:
                    put(w, b + 160, get(w, b + 160) | (value << ((header - 8) * 8)))
                cursor = cursor + 1
                header = header + 1
                put(w, b + 96, get(w, b + 96) + 1)
            if get(w, b + 144) < 16 and header == 16:
                kind = get(w, b + 152)
                size = get(w, b + 160)
                if kind > 4 or (kind == 0 and size != 0) or ((kind == 1 or kind == 2) and size != 8):
                    return 0
                put(w, b + 168, size)
            put(w, b + 144, header)
            if header == 16:
                count = end - cursor
                if count > get(w, b + 168):
                    count = get(w, b + 168)
                cursor = cursor + count
                put(w, b + 96, get(w, b + 96) + count)
                put(w, b + 168, get(w, b + 168) - count)
                if get(w, b + 168) == 0:
                    complete_cell(w, b)
    return 1

def payload_complete(w:mutbuf, b:u64) -> u64:
    if get(w, b + 96) != get(w, b + 88) or get(w, b + 136) != get(w, b + 128) or get(w, b + 144) != 0:
        return 0
    if get(w, b + 64) == 2:
        return choose(get(w, b + 176) == 0, 1, 0)
    return choose(get(w, b + 176) == 8 and get(w, b + 184) == get(w, b + 128), 1, 0)

def decode_header(w:mutbuf, b:u64) -> u64:
    if get(w, b + 224) != RECORD_MAGIC_VALUE or get(w, b + 232) != 1 or get(w, b + 280) != 0:
        return 0
    kind = get(w, b + 240)
    table = get(w, b + 248)
    rowid = get(w, b + 256)
    size = get(w, b + 264)
    if metadata(kind, table, rowid, size) == 0 or get(w, b + 272) != 80 + size:
        return 0
    put(w, b + 64, kind)
    put(w, b + 72, table)
    put(w, b + 80, rowid)
    put(w, b + 88, size)
    put(w, b + 104, 80 + size)
    put(w, b + 128, choose(kind == 3, 1, choose(kind == 2, 0, row_width(table))))
    return 1

def decode_chunk(s:readbuf, w:mutbuf, b:u64) -> u64:
    cursor = 128
    while cursor < length(s):
        if get(w, b + 192) < 64:
            count = length(s) - cursor
            if count > 64 - get(w, b + 192):
                count = 64 - get(w, b + 192)
            copy_input(w, s, b + 224 + get(w, b + 192), cursor, count)
            cursor = cursor + count
            put(w, b + 192, get(w, b + 192) + count)
            put(w, b + 112, get(w, b + 112) + count)
            if get(w, b + 192) == 64 and decode_header(w, b) == 0:
                return 0
        elif get(w, b + 96) < get(w, b + 88):
            count = length(s) - cursor
            if count > get(w, b + 88) - get(w, b + 96):
                count = get(w, b + 88) - get(w, b + 96)
            if feed_payload(s, w, b, cursor, cursor + count) == 0:
                return 0
            cursor = cursor + count
            put(w, b + 112, get(w, b + 112) + count)
        else:
            if get(w, b + 200) == 16 or payload_complete(w, b) == 0:
                return 0
            count = length(s) - cursor
            if count > 16 - get(w, b + 200):
                count = 16 - get(w, b + 200)
            copy_input(w, s, b + 288 + get(w, b + 200), cursor, count)
            cursor = cursor + count
            put(w, b + 200, get(w, b + 200) + count)
            put(w, b + 112, get(w, b + 112) + count)
            if get(w, b + 200) == 16:
                if get(w, b + 288) != get(w, b + 104) or get(w, b + 296) != RECORD_MAGIC_VALUE:
                    return 0
    return 1

def emit(o:mutbuf, w:mutbuf, status:u64, emitted:u64) -> u64:
    if length(o) < 192:
        return 4294967293
    fill_range(o, 0, length(o), 0)
    put(o, 0, LOG_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 336))
    put(o, 24, get(w, 344))
    put(o, 32, get(w, 352))
    put(o, 40, get(w, 360))
    put(o, 48, get(w, 328))
    put(o, 56, get(w, 376))
    put(o, 64, get(w, 40))
    put(o, 72, get(w, 64))
    put(o, 80, get(w, 72))
    put(o, 88, get(w, 80))
    put(o, 96, get(w, 88))
    put(o, 104, get(w, 96))
    put(o, 112, get(w, 112))
    put(o, 120, get(w, 104))
    put(o, 128, emitted)
    put(o, 136, get(w, 456))
    put(o, 144, get(w, 120))
    put(o, 152, get(w, 8))
    put(o, 160, get(w, 128))
    put(o, 168, get(w, 136))
    put(o, 176, 1)
    return status
'''


def source_program():
    result = LOG.replace('RECORD_MAGIC_VALUE', str(RECORD_MAGIC)).replace('LOG_MAGIC', str(MAGIC))
    result += VALUES[VALUES.index('\ndef read64('):]
    result += '\ndef row_width(table:u64) -> u64:\n'
    for table in catalog()['tables']:
        result += '    if table == %d:\n        return %d\n' % (table['id'], len(table['columns']))
    return result + '    return 0\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate namespace log HIA symbol')
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ObjectBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_namespace_log', 'functions': functions})


def main():
    path = ROOT/'examples/hia_bootstrap/agent_namespace_log.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
