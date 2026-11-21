"""Author the native projection of a retained, typed request-key observation."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_journal_records import RESPONSE_LIMIT, POLICY as RECORD_WRITER

SOURCE = 'examples/hia_bootstrap/worker_journal_observation.hepta'

POLICY = r'''
def journal_observation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 144 or length(o) < 130 or word(s, 0) != INPUT or valid_hex(s, 32) == False:
        return 4294967293
    row = word(s, 8)
    if row > RESPONSE_LIMIT + 512 or length(s) != 144 + row:
        return 4294967293
    footer = 96 + row
    if word(s, footer) != 5 or word(s, footer + 8) != row or word(s, footer + 24) != 0:
        return 4294967293
    if word(s, 16) == 0 or word(s, 16) != word(s, footer + 32) or word(s, 24) != word(s, footer + 40):
        return 4294967293
    count = word(s, footer + 16)
    if row == 0:
        if count != 0:
            return 4294967293
        result_header(o, 0, 4, 0)
        return no_row(o, 32)
    if count != 1 or row < 312 + TOOL_BYTES or word(s, 96) != ROW:
        return 4294967293
    if word(s, 104) != 1 or word(s, 112) != 4 or word(s, 120) != 6:
        return 4294967293
    if cell_matches(s, 128, 3, 176, 64) == False or cell_matches(s, 152, 3, 240, 64) == False:
        return 4294967293
    if cell_matches(s, 176, 3, 304, TOOL_BYTES) == False:
        return 4294967293
    if same_key(s) == False or valid_hex(s, 336) == False or has_tool(s, 400) == False:
        return 4294967293
    state_width = word(s, 216)
    if cell_matches(s, 200, 3, 304 + TOOL_BYTES, state_width) == False:
        return 4294967293
    stored = 0
    state = 0
    if state_width == 7 and has_running(s, 400 + TOOL_BYTES):
        if cell_matches(s, 224, 0, 311 + TOOL_BYTES, 0) == False:
            return 4294967293
        state = 1
    elif state_width == 9 and has_completed(s, 400 + TOOL_BYTES):
        stored = word(s, 240)
        if stored == 0 or stored > RESPONSE_LIMIT or row < 313 + TOOL_BYTES or stored > row - 313 - TOOL_BYTES:
            return 4294967293
        if cell_matches(s, 224, 3, 313 + TOOL_BYTES, stored) == False:
            return 4294967293
        state = 2
    else:
        return 4294967293
    started = 304 + TOOL_BYTES + state_width + stored
    if started >= row or row - started > 20:
        return 4294967293
    if cell_matches(s, 248, 3, started, row - started) == False:
        return 4294967293
    if canonical_time(s, 96 + started, row - started) == False:
        return 4294967293
    observation = 88 + state_width
    if length(o) < 32 + observation + stored:
        return 4294967293
    result_header(o, state, observation, stored)
    at = digest_prefix(o, 32)
    at = copy(s, o, 336, at, 64)
    at = state_prefix(o, at)
    at = copy(s, o, 400 + TOOL_BYTES, at, state_width)
    at = json_finish(o, at)
    return copy(s, o, 400 + TOOL_BYTES + state_width, at, stored)

def same_key(s:readbuf) -> bool:
    index = 0
    while index < 64:
        if byte(s, 32 + index) != byte(s, 272 + index):
            return False
        index = index + 1
    return True

def cell_matches(s:readbuf, at:u64, kind:u64, offset:u64, size:u64) -> bool:
    return word(s, at) == kind and word(s, at + 8) == offset and word(s, at + 16) == size

def result_header(o:mutbuf, state:u64, observation:u64, cached:u64) -> u64:
    put(o, 0, OUTPUT)
    put(o, 8, state)
    put(o, 16, observation)
    put(o, 24, cached)
    return 0
'''


def source_program(tool=b'hia_artifact'):
    tags = {'INPUT': b'HIARJO01', 'OUTPUT': b'HIARJO02', 'ROW': b'HIAROW01'}
    constants = {name: int.from_bytes(value, 'little') for name, value in tags.items()}
    constants.update(RESPONSE_LIMIT=RESPONSE_LIMIT, TOOL_BYTES=len(tool))
    source = POLICY
    for name, value in constants.items():
        source = re.sub(rf'\b{name}\b', str(value), source)
    source += RECORD_WRITER[RECORD_WRITER.index('\ndef canonical_time('):]
    for name, raw in (('has_tool', tool), ('has_running', b'running'), ('has_completed', b'completed')):
        source += f'\ndef {name}(s:readbuf, at:u64) -> bool:\n    return '
        source += ' and '.join(f'byte(s, at + {i}) == {value}' for i, value in enumerate(raw)) + '\n'
    for name, raw in (('no_row', b'null'), ('digest_prefix', b'{"digest":"'),
                      ('state_prefix', b'","state":"'), ('json_finish', b'"}')):
        source += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        for index, value in enumerate(raw):
            source += f'    store(o, {index} + at, {value})\n'
        source += f'    return at + {len(raw)}\n'
    return source


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'journal_observation')), encoding='utf-8')
