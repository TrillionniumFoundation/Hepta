"""Author the native Agent path-authority and exact-file-capture policy."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions


SOURCE = r'''
def authorize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or word(s, 0) != CAPTURE_TAG:
        return 64
    phase = word(s, 8)
    if phase == 1:
        return path(s, o)
    if phase == 2:
        if length(s) != 168:
            return 64
        limit = word(s, 16)
        if limit == 0 or limit > 8388608:
            return 64
        if (word(s, 48) & 61440) != 32768 or word(s, 72) > limit:
            return 67
        return 0
    if phase == 3:
        if length(s) != 312:
            return 64
        if word(s, 16) != word(s, 72):
            return 68
        if word(s, 24) != word(s, 168) or word(s, 32) != word(s, 176):
            return 68
        if word(s, 72) != word(s, 216) or word(s, 112) != word(s, 256):
            return 68
        if word(s, 120) != word(s, 264) or word(s, 128) != word(s, 272):
            return 68
        if word(s, 136) != word(s, 280):
            return 68
        return 0
    return 64

def path(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 40:
        return 64
    root_len = word(s, 16)
    user_len = word(s, 24)
    limit_len = word(s, 32)
    if root_len > 131071 or user_len > 131071 or limit_len == 0 or limit_len > 7:
        return 64
    root_end = 40 + root_len
    user_end = root_end + user_len
    if user_end + limit_len != length(s):
        return 64
    limit = decimal(s, user_end)
    if limit == 0 or limit > 8388608:
        return 64
    user_style = style(s, root_end, user_end)
    if user_style == 0:
        return 65
    if user_style == 3:
        return 69
    if root_len == 0:
        return 66
    root_style = style(s, 40, root_end)
    if root_style == 0 or root_style == 3:
        return 70
    if root_style != user_style:
        return 66
    if canonical_root(s, root_end, root_style) == 0:
        return 70
    root_at = 40
    user_at = root_end
    root_item = part(s, root_at, root_end)
    while root_item != 0:
        user_item = part(s, user_at, user_end)
        if user_item == 0 or equal_parts(s, root_item, user_item) == 0:
            return 66
        root_at = (root_item >> 32) + (root_item & 4294967295)
        user_at = (user_item >> 32) + (user_item & 4294967295)
        root_item = part(s, root_at, root_end)
    if part(s, user_at, user_end) == 0:
        return 66
    if length(o) < 16 + user_end - user_at + 1:
        return 64
    out = 16
    user_item = part(s, user_at, user_end)
    while user_item != 0:
        index = user_item >> 32
        size = user_item & 4294967295
        i = 0
        while i < size:
            store(o, out, byte(s, index + i))
            out = out + 1
            i = i + 1
        store(o, out, 0)
        out = out + 1
        user_at = index + size
        user_item = part(s, user_at, user_end)
    put(o, 0, limit)
    put(o, 8, out - 16)
    return 0

def style(s:readbuf, start:u64, end:u64) -> u64:
    if start == end or byte(s, start) != 47:
        return 0
    at = start
    while at < end:
        if byte(s, at) == 0:
            return 3
        at = at + 1
    next = start
    item = part(s, next, end)
    while item != 0:
        index = item >> 32
        width = item & 4294967295
        if width == 2 and byte(s, index) == 46 and byte(s, index + 1) == 46:
            return 3
        next = index + width
        item = part(s, next, end)
    if end - start >= 2 and byte(s, start + 1) == 47:
        if end - start == 2 or byte(s, start + 2) != 47:
            return 2
    return 1

def canonical_root(s:readbuf, end:u64, root_style:u64) -> u64:
    at = 40 + root_style
    while at < end:
        if byte(s, at) == 47:
            return 0
        first = at
        while at < end and byte(s, at) != 47:
            at = at + 1
        if at - first == 1 and byte(s, first) == 46:
            return 0
        if at < end:
            at = at + 1
            if at == end:
                return 0
    return 1

def part(s:readbuf, at:u64, end:u64) -> u64:
    while at < end:
        while at < end and byte(s, at) == 47:
            at = at + 1
        first = at
        while at < end and byte(s, at) != 47:
            at = at + 1
        count = at - first
        if count == 0:
            return 0
        if count != 1 or byte(s, first) != 46:
            return (first << 32) | count
    return 0

def equal_parts(s:readbuf, left:u64, right:u64) -> u64:
    width = left & 4294967295
    if width != (right & 4294967295):
        return 0
    a = left >> 32
    b = right >> 32
    i = 0
    while i < width:
        if byte(s, a + i) != byte(s, b + i):
            return 0
        i = i + 1
    return 1

def decimal(s:readbuf, at:u64) -> u64:
    value = 0
    while at < length(s):
        item = byte(s, at)
        if item < 48 or item > 57:
            return 0
        value = value * 10 + item - 48
        at = at + 1
    return value

def word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def put(o:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, index + i, value >> (i * 8))
        i = i + 1
    return 0
'''


def document():
    tag = int.from_bytes(b'HIACAP01', 'little')
    nodes = ast.parse(SOURCE.replace('CAPTURE_TAG', str(tag))).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_artifact_capture',
                                  'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/agent_artifact_capture.hepta'
    path.write_text(render_assembly(document()))


if __name__ == '__main__':
    main()
