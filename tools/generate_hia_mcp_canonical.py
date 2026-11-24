"""Author HIA canonical JSON for the pinned MCP serde_json number profile.

Objects sort by decoded UTF-8 keys. Signed/unsigned 64-bit integer storage and
finite IEEE-754 conversion match serde_json without arbitrary_precision. The
shortest decimal algorithm is HIA-owned; only its presentation policy differs
from the existing CPython-compatible Worker serializer.

This is the serde Value profile: duplicate decoded object keys retain the last
value. Typed-struct field rejection belongs to the independent typed owners.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_mcp_sdk_value import SOURCE as SDK_VALUE
from tools.generate_hia_worker_request import (
    canonical_program, data_source, decimal_program, format_program, replace_once,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'examples/hia_bootstrap/mcp_canonical.hepta'
LIMIT = 8 << 20
WORKSPACE_BYTES = 64 + 262144 * 56 + LIMIT + 16384

ENTRY = r'''
def canonical(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) == 8388609:
        if length(w) != WORKSPACE_CAP:
            return 4294967293
        return sdk_value(s, w)
    if length(s) > 8388608 or length(o) != 8388608 or length(w) != WORKSPACE_CAP:
        return 4294967293
    put(o, 48, MAXIMUM_NODES)
    put(o, 56, MAXIMUM_DEPTH)
    result = widen(decode_json(s, w, o))
    if result >= 4294967292:
        return result
    index = 0
    while index < get(w, 8):
        row = 64 + index * 56
        if get(w, row) == 3:
            if stored_integer(s, get(w, row + 24), get(w, row + 32)) == 0:
                put(w, row, 7)
        # serde parses every Value before insertion into its object map. A
        # non-finite value must still fail when a later duplicate overwrites it.
        if get(w, row) == 7:
            if widen(decimal_convert(s, w, get(w, row + 24), get(w, row + 32))) != 8:
                return 4294967280
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

LAST_WINS = r'''
def sort_object_last_wins(w:mutbuf, node:u64) -> u64:
    # The existing stable merge sort preserves source order for equal keys.
    # Select the last member of each equal run and relink only retained nodes.
    sort_object(w, node)
    record = 64 + node * 56
    child = get(w, record + 24)
    head = 18446744073709551615
    previous = 18446744073709551615
    size = 0
    while child != 18446744073709551615:
        following = next_node(w, child)
        while following != 18446744073709551615 and decoded_key_equal(w, child, following) == 1:
            child = following
            following = next_node(w, child)
        if previous == 18446744073709551615:
            head = child
        else:
            put(w, 64 + previous * 56 + 16, child)
        previous = child
        size = size + 1
        child = following
    if previous != 18446744073709551615:
        put(w, 64 + previous * 56 + 16, 18446744073709551615)
    put(w, record + 24, head)
    put(w, record + 32, size)
    return 0

def decoded_key_equal(w:mutbuf, left:u64, right:u64) -> u64:
    a = 64 + left * 56
    b = 64 + right * 56
    size = get(w, a + 48)
    if size != get(w, b + 48):
        return 0
    aa = get(w, a + 40)
    bb = get(w, b + 40)
    index = 0
    while index < size:
        if byte(w, aa + index) != byte(w, bb + index):
            return 0
        index = index + 1
    return 1
'''


def source_program(*, maximum_nodes=262144, maximum_depth=127, sdk_validation=True):
    if type(maximum_nodes) is not int or not 1 <= maximum_nodes <= 1048576:
        raise ValueError('invalid native Value node workspace')
    if type(maximum_depth) is not int or not 1 <= maximum_depth <= 127:
        raise ValueError('invalid serde Value recursion budget')
    formatter = format_program()
    # serde_json 1.0.151 / zmij 1.0.23 use fixed decimals through 1e-5,
    # scientific decimals from 1e16, and an exponent without zero padding.
    formatter = replace_once(formatter, 'order < 2044 or order >= 2064',
                             'order < 2043 or order >= 2064')
    formatter = replace_once(formatter,
        '            cursor = format_emit(w, cursor, tens + 48)',
        '            if hundreds != 0 or tens != 0:\n'
        '                cursor = format_emit(w, cursor, tens + 48)')
    decoder = replace_once(data_source(),
        'if same_key(s, item & 4294967295, start) == 1:\n                return 4',
        'if same_key(s, item & 4294967295, start) == 1:\n                return 0')
    serializer = replace_once(canonical_program(), '                sort_object(w, node)',
                              '                sort_object_last_wins(w, node)')
    selected_entry = ENTRY if sdk_validation else ENTRY.replace('    if length(o) == 8388609:\n        if length(w) != WORKSPACE_CAP:\n            return 4294967293\n        return sdk_value(s, w)\n', '')
    entry = selected_entry.replace('WORKSPACE_CAP', str(64 + maximum_nodes * 56 + LIMIT + 16384))
    entry = entry.replace('MAXIMUM_NODES', str(maximum_nodes)).replace('MAXIMUM_DEPTH', str(maximum_depth))
    value = '\n'.join((entry,
                       serializer, LAST_WINS, decoder, decimal_program(), formatter, SDK_VALUE if sdk_validation else ''))
    return value


def render():
    return render_assembly(document(source_program(), 'mcp_canonical'))


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render(), encoding='utf-8')
