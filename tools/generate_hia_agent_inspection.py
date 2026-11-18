"""Author the Agent summary and typed views of already checked Core."""
import ast
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_core_inspect_json import KEYS, source_program as report_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap/agent_inspection.hepta'
HEADER = 24
SELECTOR_BYTES = 512
TAIL = HEADER + 2 * SELECTOR_BYTES + 8
VIEW_MODE = int.from_bytes(b'HIAVIEW1', 'little')
IMPORT_MODE = int.from_bytes(b'HIAADG01', 'little')
LOWERING_MODE = int.from_bytes(b'HIAVLOW1', 'little')
NONE = (1 << 64) - 1

POLICY = '''
def inspect_agent(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8:
        return 4294967293
    mode = get(w, length(w) - 8)
    if mode == VIEW_MODE:
        return inspect_part(s, o, w)
    if mode == IMPORT_MODE:
        return import_diagnostics(s, o, w)
    if mode == LOWERING_MODE:
        return render_lowering(s, o, w)
    return inspect_core(s, o, w)

def render_lowering(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 152 or length(w) < 9472:
        return 4294967293
    text_size = lowering_word(s, 0)
    frames_size = lowering_word(s, 8)
    profile_size = lowering_word(s, 16)
    if text_size == 0 or text_size > 16777216 or text_size > length(o):
        return 4294967293
    if frames_size < 2 or frames_size > 8388608 or profile_size < 2 or profile_size > 1024:
        return 4294967293
    frames = 152 + text_size
    profile = frames + frames_size
    object_ref = profile + profile_size
    if length(s) < object_ref + 2 or length(s) > object_ref + 1024:
        return 4294967293
    offset = 24
    while offset < 152:
        digit = byte(s, offset)
        if (digit < 48 or digit > 57) and (digit < 97 or digit > 102):
            return 4294967293
        offset = offset + 1
    index = 0
    while index < text_size:
        store(o, index, byte(s, 152 + index))
        index = index + 1
    digest(o, w, text_size)
    put(w, 56, 0)
    lit(o, w, '{"core_sha256":"')
    lowering_copy(s, o, w, 24, 64)
    lit(o, w, '","frames":')
    lowering_copy(s, o, w, frames, frames_size)
    lit(o, w, ',"lowering_profile":')
    lowering_copy(s, o, w, profile, profile_size)
    lit(o, w, ',"object":')
    lowering_copy(s, o, w, object_ref, length(s) - object_ref)
    lit(o, w, ',"object_sha256":"')
    lowering_copy(s, o, w, 88, 64)
    lit(o, w, '","optimizer_used":false,"schema":"hepta.hia.agent.lowering-view.v1","text_bytes":"')
    lowering_extent(o, w, text_size)
    lit(o, w, '","text_sha256":')
    quoted_hash(o, w)
    lit(o, w, '}')
    size = get(w, 56)
    if size > length(o) or size > 8388608:
        return 4294967294
    return size

def lowering_word(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def lowering_copy(s:readbuf, o:mutbuf, w:mutbuf, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        append_byte(o, w, byte(s, at + index))
        index = index + 1
    return 0

def lowering_extent(o:mutbuf, w:mutbuf, value:u64) -> u64:
    divisor = 10000000
    while divisor > value:
        divisor = lowering_next(divisor)
    while divisor != 0:
        digit = 0
        while value >= divisor:
            value = value - divisor
            digit = digit + 1
        append_byte(o, w, digit + 48)
        divisor = lowering_next(divisor)
    return 0

def lowering_next(power:u64) -> u64:
    if power == 10000000:
        return 1000000
    if power == 1000000:
        return 100000
    return quotient10(power)

def import_diagnostics(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 9472 or length(o) < 256 or nominal_profile(w) > 4:
        return 4294967293
    if widen(hash_canonical_input(s, o, w)) != 64:
        return 4294967293
    put(w, 56, 0)
    lit(o, w, '{"core_sha256":')
    quoted_hash(o, w)
    lit(o, w, ',"input_sha256":')
    quoted_input_hash(o, w)
    lit(o, w, ',"schema":"hepta.hia.agent.candidate-diagnostics.v1","whole_program_checked":true}')
    return get(w, 56)

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
    functions = field(w, 0, K_functions)
    fn = named_element(w, functions, K_name, frame + 24, function_size)
    if fn == NONE:
        return 4294967289
    node = fn
    if mode == 2:
        blocks = field(w, fn, K_blocks)
        node = named_element(w, blocks, K_id, frame + 24 + SELECTOR_BYTES, block_size)
        if node == NONE:
            return 4294967290
    put(w, 56, 0)
    fragment(s, o, w, node, 0, 0)
    size = get(w, 56)
    if size > length(o):
        return 4294967294
    return size

def named_element(w:mutbuf, array:u64, name:u64, at:u64, size:u64) -> u64:
    if array == NONE or size == 0 or get(w, 64 + array * 56) != 5:
        return NONE
    element = get(w, 64 + array * 56 + 24)
    while element != NONE:
        label = field(w, element, name)
        if label != NONE:
            record = 64 + label * 56
            if get(w, record) == 4 and get(w, record + 32) == size:
                if equal_bytes(w, get(w, record + 24), at, size) == 1:
                    return element
        element = get(w, 64 + element * 56 + 16)
    return NONE

def equal_bytes(w:mutbuf, left:u64, right:u64, size:u64) -> u64:
    index = 0
    while index < size:
        if byte(w, left + index) != byte(w, right + index):
            return 0
        index = index + 1
    return 1
'''


def reachable_source(source):
    """Keep only the functions reached by the Agent entry and its modes."""
    tree = ast.parse(source)
    functions = {node.name: node for node in tree.body}
    pending = ['inspect_agent']
    reached = set(pending)
    while pending:
        for node in ast.walk(functions[pending.pop()]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                name = node.func.id
                if name in functions and name not in reached:
                    reached.add(name)
                    pending.append(name)
    return ast.unparse(ast.Module(body=[node for node in tree.body if node.name in reached],
                                type_ignores=[]))


def source_program():
    words = {'K_' + name: 1 << index for index, name in enumerate(KEYS)}
    words.update(NONE=NONE, SELECTOR_BYTES=SELECTOR_BYTES, TAIL=TAIL,
                 VIEW_MODE=VIEW_MODE, IMPORT_MODE=IMPORT_MODE, LOWERING_MODE=LOWERING_MODE)
    lens = re.sub(r'\b(' + '|'.join(words) + r')\b', lambda match: str(words[match[0]]), POLICY)
    return reachable_source(report_source(nominal=True, compact=True, entry=lens + '\n'))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), 'agent_inspection')))
