"""Author the native public Inspection request projection after schema admission."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_nominal_json import SOURCE as NOMINAL_JSON
from tools.generate_hia_worker_context_request import NONE, POLICY as CONTEXT_POLICY, literal, literal_match
from tools.generate_hia_worker_inspection_effect import POLICY as INSPECTION_EFFECT, function

SOURCE = Path('examples/hia_bootstrap/worker_inspection_request.hepta')
FIELDS = ('catalog_sha256', 'context', 'program', 'view', 'selector', 'cursor',
          'function', 'block', 'output')
VIEWS = ('summary', 'function', 'block', 'dependencies', 'lowering')
TAG = int.from_bytes(b'HIAINR01', 'little')
QUERY = int.from_bytes(b'HIAINQ01', 'little')
FRAME = int.from_bytes(b'HIAICF01', 'little')
VIEW_BYTES = 9472

POLICY = r'''
# Input [installed catalog digest, schema-admitted public arguments].
# The disposition is applied only after Context and program resolution:
# 1 -> immutable cursor refusal, 2 -> incomplete dependency selector.
# The lengths and selector bytes follow the original reference fragments.
def inspect_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 16384 or length(o) < 16384 or length(w) < 65536:
        return 4294967293
    if length(s) >= 8 and input_word(s, 0) == QUERY:
        return query_selector(s, o)
    if length(s) >= 16 and input_word(s, 0) == FRAME:
        return inspection_frame(s, o)
    put(o, 48, 4096)
    put(o, 56, 32)
    if widen(decode_json(s, w, o)) >= 4294967292:
        return 4294967293
    root = 64
    if get(w, root) != 5:
        return 4294967293
    arity = get(w, root + 32)
    if arity != 2 and arity != 3:
        return 4294967293
    pinned = 64 + get(w, root + 24) * 72
    args = 64 + get(w, pinned + 16) * 72
    if get(w, args) != 6 or digest_text(w, pinned, False) == False:
        return 4294967293
    catalog = lookup(w, args, 1)
    if digest_text(w, catalog, True) == False:
        return 4294967293
    if arity == 3:
        # Private Journal mode uses a null marker and returns the two exact
        # original digest wires. The existing Journal admits or refuses them.
        marker = 64 + get(w, args + 16) * 72
        if get(w, marker) != 0:
            return 4294967293
        actual = copy_value(s, w, o, catalog, 24)
        end = copy_value(s, w, o, pinned, actual)
        put(o, 0, actual - 24)
        put(o, 8, end - actual)
        put(o, 16, 0)
        return end
    if equal_span(s, w, pinned, catalog) == False:
        return 4294967286
    context = lookup(w, args, 2)
    program = lookup(w, args, 3)
    if context == NONE or program == NONE or get(w, context) != 6 or get(w, program) != 6:
        return 4294967293
    view = view_id(w, lookup(w, args, 4))
    if view == 0:
        return 4294967293
    put(o, 0, TAG)
    put(o, 8, view)
    cursor = fragment(s, w, o, context, 24)
    cursor = fragment(s, w, o, program, cursor)
    if lookup(w, args, 6) != NONE:
        put(o, 16, 1)
        return cursor
    selector = lookup(w, args, 5)
    if selector != NONE and get(w, selector) != 6:
        return 4294967293
    put(o, 16, 0)
    if view == 1 or view == 5:
        return cursor
    fn = optional_selector(w, selector, 7)
    block = optional_selector(w, selector, 8)
    output = optional_selector(w, selector, 9)
    if view == 4 and (fn == NONE or block == NONE or output == NONE):
        put(o, 16, 2)
        return cursor
    cursor = selector_fragment(w, o, fn, cursor)
    cursor = selector_fragment(w, o, block, cursor)
    if view == 4:
        return selector_fragment(w, o, output, cursor)
    return cursor

def optional_selector(w:mutbuf, selector:u64, field:u64) -> u64:
    if selector == NONE:
        return NONE
    item = lookup(w, selector, field)
    if item == NONE or get(w, item) != 4 or get(w, item + 32) > 512:
        return NONE
    return item

def selector_fragment(w:mutbuf, o:mutbuf, item:u64, at:u64) -> u64:
    if item == NONE:
        put(o, at, 0)
        return at + 8
    width = get(w, item + 32)
    put(o, at, width)
    return copy_decoded(w, o, item, at + 8, width)

# Decode only the already selected three UTF-8 values. Use the shared lexical
# quoting kernel so the platform never interprets or rewrites selector text.
def query_selector(s:readbuf, o:mutbuf) -> u64:
    function_size = query_width(s, 8)
    if function_size == 0:
        return BAD_BUDGET
    block = 16 + function_size
    block_size = query_width(s, block)
    if block_size == 0:
        return BAD_BUDGET
    output = block + 8 + block_size
    output_size = query_width(s, output)
    if output_size == 0 or output + 8 + output_size != length(s):
        return BAD_BUDGET
    cursor = query_open(o, 0)
    cursor = njs_quote(s, o, block + 8, block + 8 + block_size, cursor, length(o))
    if cursor >= BAD_JSON:
        return cursor
    cursor = query_function(o, cursor)
    cursor = njs_quote(s, o, 16, 16 + function_size, cursor, length(o))
    if cursor >= BAD_JSON:
        return cursor
    cursor = query_output(o, cursor)
    cursor = njs_quote(s, o, output + 8, output + 8 + output_size, cursor, length(o))
    if cursor >= BAD_JSON:
        return cursor
    store(o, cursor, 125)
    return cursor + 1

def query_width(s:readbuf, at:u64) -> u64:
    if at > length(s) or length(s) - at < 8:
        return 0
    count = input_word(s, at)
    if count > 512 or count > length(s) - at - 8:
        return 0
    return count

def input_word(s:readbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value
'''

FRAME_POLICY = r'''
# The carrier supplies a closed mode and the untouched selector or facts
# span. Validate the complete input before producing the exact legacy packet.
def inspection_frame(s:readbuf, o:mutbuf) -> u64:
    mode = input_word(s, 8)
    end = length(s)
    if mode >= 2 and mode <= 4:
        return selector_frame(s, o, mode)
    if mode == 1 and end == 16:
        return zero_frame(o)
    if mode == 6 and end == 16:
        zero_frame(o)
        put(o, 9464, NOMINAL_PROBE)
        return VIEW_BYTES
    if mode == 7 and end == 88:
        version = input_word(s, 16)
        if version < 1 or version > 4 or frame_digest(s) == False:
            return BAD_BUDGET
        zero_frame(o)
        put(o, 0, NOMINAL_SUMMARY)
        put(o, 8, version)
        copy_bytes(s, o, 24, 16, 64)
        return VIEW_BYTES
    if mode == 8 and end == 16:
        zero_frame(o)
        put(o, 9464, LOWERING_VIEW)
        return VIEW_BYTES
    if mode == 9 and end >= 56 and end <= 8240:
        count = input_word(s, 40)
        if input_word(s, 16) != ELF_FACTS or count > 1024 or 48 + 8 * count != end:
            return BAD_BUDGET
        zero_frame(o)
        copy_bytes(s, o, 16, 0, end - 16)
        return VIEW_BYTES
    return BAD_BUDGET

def zero_frame(o:mutbuf) -> u64:
    at = 0
    while at < VIEW_BYTES:
        put(o, at, 0)
        at = at + 8
    return VIEW_BYTES

def frame_digest(s:readbuf) -> bool:
    at = 24
    while at < 88:
        value = byte(s, at)
        if (value < 48 or value > 57) and (value < 97 or value > 102):
            return False
        at = at + 1
    return True

def selector_frame(s:readbuf, o:mutbuf, mode:u64) -> u64:
    dependency = mode == 4
    total = choose(dependency, 3, 2)
    record = choose(dependency, 7904, 8416)
    target = record + 24
    if valid_selectors(s, 16, total, dependency) == False:
        return BAD_BUDGET
    zero_frame(o)
    if dependency == False:
        put(o, record, mode - 1)
        record = record + 8
    put(o, 9464, choose(dependency, DEPENDENCY_VIEW, CORE_VIEW))
    at = 16
    index = 0
    while index < total:
        width = input_word(s, at)
        put(o, record + 8 * index, width)
        copy_bytes(s, o, at + 8, target + 512 * index, width)
        at = at + 8 + width
        index = index + 1
    return VIEW_BYTES

def copy_bytes(s:readbuf, o:mutbuf, at:u64, target:u64, width:u64) -> u64:
    i = 0
    while i < width:
        store(o, target + i, byte(s, at + i))
        i = i + 1
    return i
'''


def program():
    choices = ['def view_id(w:mutbuf, node:u64) -> u64:']
    for index, view in enumerate(VIEWS, 1):
        choices.extend((f'    if matches_{view}(w, node):', f'        return {index}'))
    choices.append('    return 0')
    span = CONTEXT_POLICY[CONTEXT_POLICY.index('\ndef equal_span('):
                          CONTEXT_POLICY.index('\ndef profile_pin(')]
    decoded = CONTEXT_POLICY[CONTEXT_POLICY.index('\ndef copy_decoded('):
                             CONTEXT_POLICY.index('\ndef budget_integer(')]
    fragments = CONTEXT_POLICY[CONTEXT_POLICY.index('\ndef fragment('):]
    quote = '\n'.join(function(NOMINAL_JSON, name) for name in
                      ('njs_utf8', 'njs_quote', 'njs_quote_byte', 'njs_quote_control'))
    literals = (
        literal('query_open', '{"block":'),
        literal('query_function', ',"fields":["op","args","attrs"],"function":'),
        literal('query_output', ',"output":'),
    )
    policy = (POLICY.replace('TAG', str(TAG)).replace('QUERY', str(QUERY))
              .replace('FRAME', str(FRAME)).replace('NONE', NONE))
    packet_tags = {'NOMINAL_PROBE': b'HIAOSC01', 'NOMINAL_SUMMARY': b'HIAONC01',
                   'LOWERING_VIEW': b'HIAVLOW1', 'ELF_FACTS': b'HIAILF01',
                   'DEPENDENCY_VIEW': b'HIAVDEP1', 'CORE_VIEW': b'HIAVIEW1'}
    framing = FRAME_POLICY.replace('VIEW_BYTES', str(VIEW_BYTES))
    for name, raw in packet_tags.items():
        framing = framing.replace(name, str(int.from_bytes(raw, 'little')))
    return '\n'.join((policy, framing, function(INSPECTION_EFFECT, 'valid_selectors'),
                      (span + decoded + fragments).replace('NONE', NONE),
                      '\n'.join(choices), *(literal_match(f'matches_{view}', view) for view in VIEWS),
                      WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', NONE),
                      comparison_table('key_id', FIELDS), *literals,
                      quote.replace('BAD_JSON', '4294967292').replace('BAD_BUDGET', '4294967293'),
                      json_decoder(wire_spans=True))).replace('BAD_JSON', '4294967292').replace('BAD_BUDGET', '4294967293')


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
