"""Author HIA JSON-RPC response framing for validated owner result objects.

The private input is a JSON object with an ID and exactly one result or
error object. The ID and response payload are copied from the received wire;
the encoder does not normalize numbers, Unicode, whitespace or object order.
"""
from __future__ import annotations

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import (
    INVALID_ENVELOPE, LIMIT, OUTPUT_BYTES, ROOT, WIRE_HELPERS, comparison_table,
)

SOURCE = 'examples/hia_bootstrap/mcp_reply_wire.hepta'
PREFIX = b'{"jsonrpc":"2.0","id":'
RESULT = b',"result":'
ERROR = b',"error":'
POLICY = r'''
def reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > WIRE_LIMIT or length(o) < OUTPUT_LIMIT or length(w) < 128:
        return 4294967293
    if single_line(s) == 0:
        return BAD_ENVELOPE
    put(o, 48, 262144)
    put(o, 56, 128)
    status = widen(decode_json(s, w, o))
    if status >= 4294967292:
        return status
    if get(w, 64) != 6 or get(w, 64 + 32) != 2:
        return BAD_ENVELOPE
    id = lookup(w, 64, 1)
    answer = lookup(w, 64, 2)
    failure = lookup(w, 64, 3)
    if id == NONE or (answer == NONE and failure == NONE):
        return BAD_ENVELOPE
    error = failure != NONE
    payload = answer
    if error:
        payload = failure
        if get(w, payload) != 6 or valid_error(s, w, payload) == 0:
            return BAD_ENVELOPE
    elif get(w, payload) != 6:
        return BAD_ENVELOPE
    kind = get(w, id)
    id_offset = 0
    id_size = 0
    if kind == 4:
        id_offset = get(w, id + 56)
        id_size = get(w, id + 64)
    elif kind == 3 or (kind == 0 and error):
        id_offset = get(w, id + 24)
        id_size = get(w, id + 32)
        if kind == 3 and signed_id(s, id_offset, id_size) == 0:
            return BAD_ENVELOPE
    else:
        return BAD_ENVELOPE
    body_offset = get(w, payload + 56)
    body_size = get(w, payload + 64)
    separator_size = choose(error, ERROR_SIZE, RESULT_SIZE)
    if PREFIX_SIZE + id_size + separator_size + body_size + 2 > length(o):
        return 4294967293
    prefix(o)
    cursor = copy_wire(s, o, PREFIX_SIZE, id_offset, id_size)
    cursor = separator(o, cursor, error)
    cursor = copy_wire(s, o, cursor, body_offset, body_size)
    store(o, cursor, 125)
    store(o, cursor + 1, 10)
    return cursor + 2

def single_line(s:readbuf) -> u64:
    offset = 0
    while offset < length(s):
        point = byte(s, offset)
        if point == 10 or point == 13:
            return 0
        offset = offset + 1
    return 1

def valid_error(s:readbuf, w:mutbuf, payload:u64) -> u64:
    code = lookup(w, payload, 4)
    message = lookup(w, payload, 5)
    if code == NONE or message == NONE or get(w, code) != 3 or get(w, message) != 4:
        return 0
    return signed_id(s, get(w, code + 24), get(w, code + 32))

def copy_wire(s:readbuf, o:mutbuf, at:u64, start:u64, size:u64) -> u64:
    offset = 0
    while offset < size:
        store(o, at + offset, byte(s, start + offset))
        offset = offset + 1
    return at + size
'''


def literal_writes(data, *, offset='at', indent='    '):
    """Generate writes into a prevalidated dynamic output span."""
    return '\n'.join(f'{indent}store(o, {offset} + {i}, {value})'
                     for i, value in enumerate(data))


def render():
    constants = {
        'PREFIX_SIZE': len(PREFIX), 'RESULT_SIZE': len(RESULT), 'ERROR_SIZE': len(ERROR),
        'WIRE_LIMIT': LIMIT, 'OUTPUT_LIMIT': OUTPUT_BYTES,
        'BAD_ENVELOPE': INVALID_ENVELOPE, 'NONE': (1 << 64) - 1,
    }
    policy = POLICY + WIRE_HELPERS
    for name, value in constants.items():
        policy = policy.replace(name, str(value))
    prefix = ('def prefix(o:mutbuf) -> u64:\n' + literal_writes(PREFIX, offset='0') + '\n    return 0\n')
    separator = ('def separator(o:mutbuf, at:u64, error:bool) -> u64:\n'
                 '    if error:\n' + literal_writes(ERROR, indent='        ') + '\n'
                 f'        return at + {len(ERROR)}\n' + literal_writes(RESULT) + '\n'
                 f'    return at + {len(RESULT)}\n')
    keys = comparison_table('key_id', ('id', 'result', 'error', 'code', 'message'))
    layout = '\n'.join((policy, prefix, separator, keys, json_decoder(wire_spans=True)))
    return render_assembly(document(layout, 'mcp_reply_wire'))


def main():
    path = ROOT / SOURCE
    path.write_text(render(), encoding='utf-8')
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
