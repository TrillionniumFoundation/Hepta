"""HIA authoring fragment for the fixed CPython exception-delivery mechanism.

Each owner composes this fragment into its selected HIA image and dispatches the
64-byte EMIT_REQUEST before its ordinary state ABI. Runtime production executes
the HIA image to obtain the adapter bytes; GNU assembly is reference-only.
"""
from __future__ import annotations

EMIT_MAGIC = int.from_bytes(b'HIACTP01', 'little')
FRAME_MAGIC = int.from_bytes(b'HIACTE01', 'little')
CODE = bytes.fromhex(
    '4885ff743a48b84849414354453031483907752b48837f0800742448837f1000741d'
    '48837f18007416534889fb488b7b18ff5308488b7b18ff531031c05bc3b801000000c3')
CODE_SHA256 = 'f2e2bd93e353f347940221d324ca6faf42957815c6ac410142a55d9a982163e8'


def _body():
    lines = ['def emit_exception_delivery(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
             '    if length(s) != 64:', '        return 4294967293',
             f'    if ed_read(s, 0) != {EMIT_MAGIC}:', '        return 4294967293',
             '    at = 8', '    while at < 64:',
             '        if ed_read(s, at) != 0:', '            return 4294967293',
             '        at = at + 8', f'    if length(o) < {len(CODE)}:',
             '        return 4294967294']
    for offset in range(0, len(CODE) // 8 * 8, 8):
        lines.append(f'    ed_put(o, {offset}, {int.from_bytes(CODE[offset:offset + 8], "little")})')
    for offset in range(len(CODE) // 8 * 8, len(CODE)):
        lines.append(f'    store(o, {offset}, {CODE[offset]})')
    lines.append(f'    return {len(CODE)}')
    return '\n'.join(lines) + r'''

def ed_read(s:readbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def ed_put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, value >> (i * 8))
        i = i + 1
    return value
'''


BODY = _body()
