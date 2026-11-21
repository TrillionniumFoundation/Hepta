"""Bind native ELF frame observations to verified Core function names."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import MAX_FUNCTIONS
from hepta.hia_program_native import MAX_FRAME_BYTES
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_exec_release import POLICY_SOURCE as RELEASE_POLICY
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_mcp_stdio_packer import INSPECTION_HEADER
from tools.generate_hia_worker_context_request import NONE, POLICY as CONTEXT_POLICY
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/inspection_lowering_frames.hepta')
TAG = int.from_bytes(b'HIAILF01', 'little')

POLICY = r'''
# The terminal control area contains the native ELF role's bounded facts.
# Only authenticated, admitted canonical Core is supplied as the JSON input.
# Its function order is the emitter's ordinal order. The generic native
# JSON renderer sorts the keys after this projection if canonical wire is needed.
def lowering_frames(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 8388608 or length(o) < 4194304 or length(w) < 27262976:
        return 4294967293
    fact = length(w) - HEADER
    if get(w, fact) != TAG:
        return 4294967293
    rows = get(w, fact + 24)
    if rows == 0 or rows > FN_LIMIT:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292:
        return 4294967293
    root = 64
    if get(w, root) != 6:
        return 4294967293
    functions = lookup(w, root, 1)
    if functions == NONE or get(w, functions) != 5 or get(w, functions + 32) != rows:
        return 4294967293
    store(o, 0, 123)
    cursor = 1
    index = 0
    child = get(w, functions + 24)
    while index < rows:
        if child == NONE:
            return 4294967293
        node = 64 + child * 72
        if get(w, node) != 6:
            return 4294967293
        name = lookup(w, node, 2)
        if name == NONE or get(w, name) != 4 or get(w, name + 64) > 514:
            return 4294967293
        frame = get(w, fact + 32 + index * 8)
        if frame < 16 or frame > FRAME_LIMIT or frame & 15 != 0:
            return 4294967293
        if index != 0:
            store(o, cursor, 44)
            cursor = cursor + 1
        cursor = copy_value(s, w, o, name, cursor)
        store(o, cursor, 58)
        cursor = decimal(o, cursor + 1, frame)
        child = get(w, node + 16)
        index = index + 1
    if child != NONE:
        return 4294967293
    store(o, cursor, 125)
    return cursor + 1
'''


def source_program():
    bindings = {'HEADER': INSPECTION_HEADER, 'TAG': TAG, 'FN_LIMIT': MAX_FUNCTIONS,
                'FRAME_LIMIT': MAX_FRAME_BYTES, 'NONE': NONE}
    policy = POLICY
    for key, value in bindings.items():
        policy = policy.replace(key, str(value))
    return '\n'.join((policy, function(CONTEXT_POLICY, 'copy_value'),
                      function(RELEASE_POLICY, 'decimal'), function(RELEASE_POLICY, 'divide10'),
                      WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', NONE),
                      comparison_table('key_id', ('functions', 'name')), json_decoder(wire_spans=True)))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
