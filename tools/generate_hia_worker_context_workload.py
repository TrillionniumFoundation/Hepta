"""Author the native Context workload observations after payload admission."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_exec_release import POLICY_SOURCE as RELEASE_POLICY
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table

SOURCE = Path('examples/hia_bootstrap/worker_context_workload.hepta')
FIELDS = ('schema', 'foreign_buffer_exports', 'function', 'max_buffer_bytes',
          'cases', 'arguments', 'bytes_hex', 'byte_length', 'fill_byte')
SCHEMAS = ('hepta.hia.agent.workload.v1', 'hepta.hia.agent.workload.v2')
NONE = '18446744073709551615'
POLICY = r'''
# Export admission and snapshot admission are returned separately, so the
# operation controller can preserve the existing precedence and stage.
def context_workload(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 8388608 or length(o) < 131072 or length(w) < 4096:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    decoded = widen(decode_json(s, w, o))
    order = length(w) - 1024
    if decoded >= 4294967292 or decoded > order or get(w, 64) != 6:
        return 4294967293
    schema = lookup(w, 64, 1)
    version = 0
    if schema != NONE and get(w, schema) == 4:
        version = schema_version(w, get(w, schema + 24), get(w, schema + 32))
    put(o, 0, FACTS)
    put(o, 8, version)
    put(o, 16, 0)
    put(o, 24, 0)
    put(o, 32, 0)
    put(o, 40, 0)
    if version == 0:
        put(o, 16, 1)
        return 48
    count = 0
    if version == 2:
        pairs = lookup(w, 64, 2)
        if pairs == NONE or get(w, pairs) != 5 or get(w, pairs + 32) > 128:
            return 4294967293
        count = get(w, pairs + 32)
        status = order_exports(s, w, get(w, pairs + 24), order)
        if status != 0:
            put(o, 16, status)
            return 48
    cases = lookup(w, 64, 5)
    if cases == NONE or get(w, cases) != 5:
        return 4294967293
    total = snapshot_total(s, w, get(w, cases + 24))
    if total >= NONE - 3:
        put(o, 24, NONE - total + 1)
    else:
        put(o, 32, total)
    end = export_json(s, w, o, order, count)
    put(o, 40, end - 48)
    return end

def order_exports(s:readbuf, w:mutbuf, item:u64, order:u64) -> u64:
    count = 0
    duplicate = False
    invalid = False
    while item != NONE:
        row = 64 + item * 72
        name = lookup(w, row, 3)
        value = lookup(w, row, 4)
        if name == NONE or get(w, name) != 4 or get(w, name + 32) == 0 or get(w, name + 32) > 512:
            return 3
        extent = uint(s, w, value, 1048576)
        if extent == NONE or extent == 0:
            invalid = True
        # The original identity policy refuses duplicate names before invalid
        # bounds; retain that precedence even for interleaved records.
        at = count
        searching = True
        while at > 0 and searching:
            previous = get(w, order + (at - 1) * 8)
            relation = name_order(w, lookup(w, previous, 3), name)
            if relation == 0:
                duplicate = True
            if relation != 2:
                searching = False
            else:
                put(w, order + at * 8, previous)
                at = at - 1
        put(w, order + at * 8, row)
        count = count + 1
        item = get(w, row + 16)
    return choose(duplicate, 2, choose(invalid, 3, 0))

def name_order(w:mutbuf, left:u64, right:u64) -> u64:
    a = get(w, left + 24)
    b = get(w, right + 24)
    a_size = get(w, left + 32)
    b_size = get(w, right + 32)
    index = 0
    while index < a_size and index < b_size:
        x = byte(w, a + index)
        y = byte(w, b + index)
        if x != y:
            return choose(x < y, 1, 2)
        index = index + 1
    return choose(a_size == b_size, 0, choose(a_size < b_size, 1, 2))

def snapshot_total(s:readbuf, w:mutbuf, item:u64) -> u64:
    total = 0
    while item != NONE:
        row = 64 + item * 72
        args = lookup(w, row, 6)
        if args == NONE or get(w, args) != 5:
            return NONE - 2
        value = get(w, args + 24)
        while value != NONE:
            record = 64 + value * 72
            if get(w, record) == 6:
                extent = snapshot(s, w, record)
                if extent >= NONE - 3:
                    return extent
                total = total + extent
            value = get(w, record + 16)
        item = get(w, row + 16)
    return total

def snapshot(s:readbuf, w:mutbuf, row:u64) -> u64:
    count = get(w, row + 32)
    hex_value = lookup(w, row, 7)
    if hex_value != NONE and count == 1:
        size = get(w, hex_value + 32)
        if get(w, hex_value) != 4 or (size & 1) != 0 or size > 2097152:
            return NONE
        at = get(w, hex_value + 24)
        end = at + size
        while at < end:
            ch = byte(w, at)
            if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
                return NONE
            at = at + 1
        return size >> 1
    size_value = lookup(w, row, 8)
    fill_value = lookup(w, row, 9)
    if size_value == NONE or fill_value == NONE or count != 2:
        return NONE - 2
    size = uint(s, w, size_value, 1048576)
    fill = uint(s, w, fill_value, 255)
    if size == NONE or fill == NONE:
        return NONE - 1
    return size

def uint(s:readbuf, w:mutbuf, node:u64, bound:u64) -> u64:
    if node == NONE or get(w, node) != 3:
        return NONE
    at = get(w, node + 24)
    size = get(w, node + 32)
    if size == 2 and byte(s, at) == 45 and byte(s, at + 1) == 48:
        return 0
    if size == 0 or size > 7:
        return NONE
    end = at + size
    value = 0
    while at < end:
        ch = byte(s, at)
        if ch < 48 or ch > 57:
            return NONE
        value = value * 10 + ch - 48
        at = at + 1
    return choose(value <= bound, value, NONE)

def export_json(s:readbuf, w:mutbuf, o:mutbuf, order:u64, count:u64) -> u64:
    cursor = 49
    store(o, 48, 91)
    index = 0
    while index < count:
        if index > 0:
            store(o, cursor, 44)
            cursor = cursor + 1
        row = get(w, order + index * 8)
        store(o, cursor, 91)
        name = lookup(w, row, 3)
        cursor = quoted(o, w, name, cursor + 1)
        store(o, cursor, 44)
        cursor = decimal(o, cursor + 1, uint(s, w, lookup(w, row, 4), 1048576))
        store(o, cursor, 93)
        cursor = cursor + 1
        index = index + 1
    store(o, cursor, 93)
    return cursor + 1

def quoted(o:mutbuf, w:mutbuf, name:u64, cursor:u64) -> u64:
    store(o, cursor, 34)
    cursor = cursor + 1
    at = get(w, name + 24)
    end = at + get(w, name + 32)
    while at < end:
        ch = byte(w, at)
        if ch == 34 or ch == 92 or ch < 32:
            store(o, cursor, 92)
            cursor = cursor + 1
        if ch < 32:
            escaped = control(ch)
            if escaped == 0:
                store(o, cursor, 117)
                store(o, cursor + 1, 48)
                store(o, cursor + 2, 48)
                store(o, cursor + 3, 48 + (ch >> 4))
                unit = ch & 15
                ch = choose(unit < 10, 48 + unit, 87 + unit)
                cursor = cursor + 4
            else:
                ch = escaped
        store(o, cursor, ch)
        cursor = cursor + 1
        at = at + 1
    store(o, cursor, 34)
    return cursor + 1

def control(ch:u64) -> u64:
    if ch == 8:
        return 98
    if ch == 9:
        return 116
    if ch == 10:
        return 110
    if ch == 12:
        return 102
    return choose(ch == 13, 114, 0)
'''


def program():
    policy = (POLICY.replace('NONE', NONE)
              .replace('FACTS', str(int.from_bytes(b'HIACTF01', 'little'))))
    return '\n'.join((policy, WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', NONE),
                     comparison_table('key_id', FIELDS), comparison_table('schema_version', SCHEMAS),
                     RELEASE_POLICY[RELEASE_POLICY.index('\ndef decimal('):RELEASE_POLICY.index('\ndef hex(')],
                     json_decoder(wire_spans=True)))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
