"""Author HIA canonical JSON for the pinned MCP serde_json number profile.

Objects sort by decoded UTF-8 keys. Signed/unsigned 64-bit integer storage and
finite IEEE-754 conversion match serde_json without arbitrary_precision. The
shortest decimal algorithm is HIA-owned; only its presentation policy differs
from the existing CPython-compatible Worker serializer.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_worker_request import (
    canonical_program, data_source, decimal_program, format_program, replace_once,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'examples/hia_bootstrap/mcp_canonical.hepta'
LIMIT = 8 << 20
WORKSPACE_BYTES = 64 + 262144 * 56 + LIMIT + 16384

ENTRY = r'''
def canonical(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(o) != 8388608 or length(w) != WORKSPACE_CAP:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    result = widen(decode_json(s, w, o))
    if result >= 4294967292:
        return result
    index = 0
    while index < get(w, 8):
        row = 64 + index * 56
        if get(w, row) == 3:
            if stored_integer(s, get(w, row + 24), get(w, row + 32)) == 0:
                put(w, row, 7)
        index = index + 1
    return serialize(s, o, w)

def stored_integer(s:readbuf, start:u64, size:u64) -> u64:
    negative = choose(byte(s, start) == 45, 1, 0)
    if negative == 1 and size == 2 and byte(s, start + 1) == 48:
        return 0
    value = 0
    index = negative
    maximum = choose(negative == 1, 922337203685477580, 1844674407370955161)
    last = choose(negative == 1, 8, 5)
    while index < size:
        digit = byte(s, start + index) - 48
        if digit > 9 or value > maximum or (value == maximum and digit > last):
            return 0
        value = value * 10 + digit
        index = index + 1
    return 1
'''


def source_program():
    formatter = format_program()
    # serde_json 1.0.151 / zmij 1.0.23 use fixed decimals through 1e-5,
    # scientific decimals from 1e16, and an exponent without zero padding.
    formatter = replace_once(formatter, 'order < 2044 or order >= 2064',
                             'order < 2043 or order >= 2064')
    formatter = replace_once(formatter,
        '            cursor = format_emit(w, cursor, tens + 48)',
        '            if hundreds != 0 or tens != 0:\n'
        '                cursor = format_emit(w, cursor, tens + 48)')
    value = '\n'.join((ENTRY.replace('WORKSPACE_CAP', str(WORKSPACE_BYTES)),
                       canonical_program(), data_source(), decimal_program(), formatter))
    return value


def render():
    return render_assembly(document(source_program(), 'mcp_canonical'))


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render(), encoding='utf-8')
