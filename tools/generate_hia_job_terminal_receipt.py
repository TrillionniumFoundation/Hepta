"""Author HIA status classification from the exact captured exit receipt."""

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import ROOT, WIRE_HELPERS, comparison_table

SOURCE = 'examples/hia_bootstrap/job_terminal_receipt.hepta'
MAGIC = b'HIAJTV01'
FIELDS = ('effect_outcome', 'timed_out', 'cancelled', 'exit_code', 'output_complete', 'output_durable')
NONE = '18446744073709551615'

POLICY = r'''
def terminal_receipt(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 1048576 or length(o) < 8192 or length(w) < 128:
        return 4294967293
    put(o, 48, 65536)
    put(o, 56, 128)
    size = widen(decode_json(s, w, o))
    if size >= 4294967292:
        return size
    if get(w, 64) != 6:
        return 4294967280
    effect = lookup(w, 64, 1)
    timed = boolean_fact(w, lookup(w, 64, 2))
    cancelled = boolean_fact(w, lookup(w, 64, 3))
    result = exit_fact(s, w, lookup(w, 64, 4))
    complete = true_or_absent(w, lookup(w, 64, 5))
    durable = true_or_absent(w, lookup(w, 64, 6))
    if timed > 1 or cancelled > 1 or result > 2:
        return 4294967280
    state = 0
    if is_unknown(w, effect):
        state = 1
    elif timed == 1:
        state = 2
    elif cancelled == 1:
        state = 3
    elif result == 2 or (result == 1 and (complete == False or durable == False)):
        state = 4
    elif result == 1:
        state = 5
    put(o, 0, REPLY_MAGIC)
    put(o, 8, state)
    return 16

def is_unknown(w:mutbuf, field:u64) -> bool:
    if field == NONE or get(w, field) != 4 or get(w, field + 32) != 7:
        return False
    return match_word(w, get(w, field + 24), 7) == UNKNOWN

def boolean_fact(w:mutbuf, field:u64) -> u64:
    if field == NONE:
        return 0
    kind = get(w, field)
    if kind == 0 or kind == 1:
        return 0
    return choose(kind == 2, 1, 2)

def true_or_absent(w:mutbuf, field:u64) -> bool:
    return field == NONE or get(w, field) == 2

def exit_fact(s:readbuf, w:mutbuf, field:u64) -> u64:
    if field == NONE:
        return 2
    kind = get(w, field)
    if kind == 0:
        return 0
    if kind != 3:
        return 3
    at = get(w, field + 24)
    end = at + get(w, field + 32)
    if byte(s, at) == 45:
        at = at + 1
    nonzero = False
    while at < end:
        value = byte(s, at)
        if value < 48 or value > 57:
            return 3
        nonzero = nonzero or value != 48
        at = at + 1
    return choose(nonzero, 2, 1)
'''


def render():
    policy = (POLICY.replace('NONE', NONE)
              .replace('REPLY_MAGIC', str(int.from_bytes(MAGIC, 'little')))
              .replace('UNKNOWN', str(int.from_bytes(b'unknown', 'little'))))
    helpers = WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', NONE)
    source = '\n'.join((policy, helpers, comparison_table('key_id', FIELDS), json_decoder(wire_spans=True)))
    return render_assembly(document(source, 'job_terminal_receipt'))


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render(), encoding='utf-8')
