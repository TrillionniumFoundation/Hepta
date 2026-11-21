"""Author Context freeze effect decisions for the native continuation carrier."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_authority import source_program as primitives

SOURCE = Path('examples/hia_bootstrap/worker_context_effect.hepta')
POLICY = r'''
# The pinned phases have separate owner receipts. The platform can transport
# only the HIA decision for a claimed port, not substitute a budget predicate.
def context_effect(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 260 or length(s) > 1024 or length(o) < 48:
        return 4294967293
    extent = input_word(s, 8)
    if input_word(s, 0) != REQUEST or extent != length(s) - 256:
        return 4294967293
    if input_word(s, 16) != CLAIM or input_word(s, 24) != 0 or input_word(s, 40) == 0:
        return 4294967293
    if input_word(s, 48) != 2 or input_word(s, 56) != 1 or input_word(s, 72) != 0:
        return 4294967293
    if (input_word(s, 80) | input_word(s, 88)) == 0 or input_word(s, 96) != PLAN:
        return 4294967293
    port = input_word(s, 32)
    index = input_word(s, 64)
    if port == 8 or (port >= 9 and port <= 17):
        if input_word(s, 136) != WORKLOAD:
            return 4294967293
        return workload_effect(s, o, port)
    if port >= 21 and port <= 36:
        if input_word(s, 184) != COST or input_word(s, 232) != AMOUNT:
            return 4294967293
        return budget_effect(s, o, port, index)
    if port == 38:
        if extent == 4 and input_word(s, 256) & 4294967295 == NULL_LITERAL:
            return respond(o, 0)
        if byte(s, 256) != 123 or byte(s, length(s) - 1) != 125:
            return 4294967293
        return respond(o, 1)
    if port == 90 or port == 91 or port == 92:
        return refusal(o, 4, port - 89)
    if port == 94 or port == 95:
        return refusal(o, 4, port - 90)
    if (port >= 1 and port <= 7) or port == 18 or port == 19 or port == 39 or port == 40 or port == 41 or port == 42 or port == 43 or port == 44 or port == 45 or port == 46:
        return result(o, 0, port, 0)
    if port == 20 or port == 37:
        return respond(o, 0)
    return 4294967293

def workload_effect(s:readbuf, o:mutbuf, port:u64) -> u64:
    exports = input_word(s, 152)
    snapshots = input_word(s, 160)
    if exports > 3 or snapshots > 3:
        return 4294967293
    if port == 8 and exports != 0:
        return refusal(o, 6, exports)
    if port == 14:
        if snapshots == 0:
            return 4294967293
        return refusal(o, 6, 3 + snapshots)
    if port == 10:
        return respond(o, choose(snapshots == 0, 0, 1))
    if port == 12 or port == 13:
        return respond(o, 1)
    if port == 17:
        return respond(o, choose(input_word(s, 168) > 33554432, 1, 0))
    return respond(o, 0)

def budget_effect(s:readbuf, o:mutbuf, port:u64, index:u64) -> u64:
    flags = input_word(s, 192)
    memory = input_word(s, 248)
    if flags > 255 or input_word(s, 240) > 1:
        return 4294967293
    if port == 21 and (flags & 1) == 0:
        return refusal(o, 5, 1)
    if port == 22 and input_word(s, 240) == 0:
        return refusal(o, 5, 2)
    if port == 23:
        return respond(o, choose(memory >= 67108864, 1, 0))
    if port == 24:
        return respond(o, choose(memory <= 4294967296, 1, 0))
    if port == 25:
        return respond(o, choose(input_word(s, 128) > input_word(s, 120), 1, 0))
    if port == 27 or port == 28:
        if index > 1:
            return 4294967293
        wall = (flags >> (3 + index * 2)) & 3
        if port == 27:
            return respond(o, wall & 1)
        if wall != 3:
            return refusal(o, 5, 3 + index)
    if port == 31:
        return respond(o, (flags >> 1) & 1)
    if port == 32:
        if (flags & 6) != 6:
            return 4294967293
        return respond(o, choose(input_word(s, 208) > input_word(s, 112), 1, 0))
    if port == 33:
        return respond(o, flags >> 7)
    if port == 35 or port == 36:
        return respond(o, choose((flags & 42) != 42, 1, 0))
    return respond(o, 0)

def respond(o:mutbuf, observation:u64) -> u64:
    return result(o, 1, observation, 0)

def refusal(o:mutbuf, group:u64, reason:u64) -> u64:
    return result(o, 2, group, reason)

def result(o:mutbuf, action:u64, first:u64, second:u64) -> u64:
    put(o, 0, EFFECT)
    put(o, 8, action)
    put(o, 16, first)
    put(o, 24, second)
    return 32
'''


def program():
    tags = {'REQUEST': b'HIACTE01', 'CLAIM': b'HCTXRSP1', 'PLAN': b'HIACTP01',
            'WORKLOAD': b'HIACTF01', 'COST': b'HIACTC01', 'AMOUNT': b'HIACTM01',
            'NULL_LITERAL': b'null', 'EFFECT': b'HIACTE02'}
    source = re.sub(r'\b(' + '|'.join(tags) + r')\b',
                    lambda match: str(int.from_bytes(tags[match.group()], 'little')), POLICY)
    shared = primitives()
    for name in ('input_word', 'put'):
        begin = shared.index('\ndef ' + name + '(')
        end = shared.index('\ndef ', begin + 1)
        source += shared[begin:end] + '\n'
    return source


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
