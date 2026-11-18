"""Author the typed Agent function/block view of an already checked Core."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_core_json_frontend import FRONTEND, packed
from tools.generate_hia_core_inspect_json import fragment_source
from tools.generate_hia_json_decode import source_program as decoder

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap/agent_inspection.hepta'
HEADER = 24
SELECTOR_BYTES = 512
TAIL = HEADER + 2 * SELECTOR_BYTES
NONE = (1 << 64) - 1

POLICY = '''
def inspect_part(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < TAIL + 64 or length(o) < 128:
        return 4294967293
    frame = length(w) - TAIL
    mode = get(w, frame)
    function_size = get(w, frame + 8)
    block_size = get(w, frame + 16)
    if (mode != 1 and mode != 2) or function_size > SELECTOR_BYTES or block_size > SELECTOR_BYTES:
        return 4294967293
    if function_size == 0:
        return 4294967288
    put(o, 48, 262144)
    put(o, 56, 64)
    decoded = widen(decode_json(s, w, o))
    if decoded >= 4294967292:
        return decoded
    if decoded > frame:
        return 4294967293
    functions = field(w, 0, FUNCTIONS)
    fn = named_element(w, functions, NAME, 4, frame + 24, function_size)
    if fn == NONE:
        return 4294967289
    node = fn
    if mode == 2:
        blocks = field(w, fn, BLOCKS)
        node = named_element(w, blocks, ID, 2, frame + 24 + SELECTOR_BYTES, block_size)
        if node == NONE:
            return 4294967290
    put(w, 56, 0)
    fragment(s, o, w, node, 0, 0)
    size = get(w, 56)
    if size > length(o):
        return 4294967294
    return size

def named_element(w:mutbuf, array:u64, name:u64, width:u64, at:u64, size:u64) -> u64:
    if array == NONE or size == 0 or get(w, 64 + array * 56) != 5:
        return NONE
    element = get(w, 64 + array * 56 + 24)
    while element != NONE:
        label = field(w, element, width, name, 0, 0)
        if label != NONE:
            record = 64 + label * 56
            if get(w, record) == 4 and get(w, record + 32) == size:
                if equal_bytes(w, get(w, record + 24), at, size) == 1:
                    return element
        element = get(w, 64 + element * 56 + 16)
    return NONE

def field(w:mutbuf, object:u64, width:u64, a:u64, b:u64, c:u64) -> u64:
    if object == NONE or get(w, 64 + object * 56) != 6:
        return NONE
    child = get(w, 64 + object * 56 + 24)
    while child != NONE:
        record = 64 + child * 56
        if same(w, get(w, record + 40), get(w, record + 48), width, a, b, c) == 1:
            return child
        child = get(w, record + 16)
    return NONE

def equal_bytes(w:mutbuf, left:u64, right:u64, size:u64) -> u64:
    index = 0
    while index < size:
        if byte(w, left + index) != byte(w, right + index):
            return 0
        index = index + 1
    return 1
'''


def source_program():
    words = {symbol: ', '.join(map(str, packed(key)))
             for symbol, key in (('FUNCTIONS', 'functions'), ('BLOCKS', 'blocks'))}
    words.update(NAME=str(int.from_bytes(b'name', 'little')), ID=str(int.from_bytes(b'id', 'little')),
                 NONE=str(NONE), SELECTOR_BYTES=str(SELECTOR_BYTES), TAIL=str(TAIL))
    same = FRONTEND[FRONTEND.index('def same('):FRONTEND.index('def text_is(')]
    source = '\n'.join((POLICY, same, fragment_source(), decoder()))
    return re.sub(r'\b(' + '|'.join(words) + r')\b', lambda match: words[match[0]], source)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), 'agent_inspection')))
