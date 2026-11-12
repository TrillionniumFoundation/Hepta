"""Complete HIA text rendering from the actual Core failure context.

The second input is a borrowed immutable view of the actual checker workspace.
No source hash is treated as admission and no hosted verification is called.
The renderer measures the entire diagnostic before requesting output capacity.
"""
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent / 'Hepta-v66-restored'
sys.path[:0] = [str(ROOT), str(BASE)]
from tools.core_diagnostic_messages import IDS, MESSAGES, WHERE, MAGIC, TEXT_MAGIC
from tools.core_diagnostic_authoring import write
from hepta.hia_opcodes import OPCODES

PREFIXES = {
    0xfffffffb: 'E_HIA_FORMAT: ', 0xfffffffa: 'E_HIA_NAME: ',
    0xfffffff9: 'E_HIA_TYPE: ', 0xfffffff8: 'E_HIA_LOAN: ',
    0xfffffff7: 'E_HIA_EFFECT: ', 0xfffffff6: 'E_HIA_CFG: ',
    0xfffffff5: 'E_HIA_SSA: ', 0xfffffff4: 'E_HIA_SCHEMA: ',
    0xfffffff3: 'E_HIA_CALL: ', 0xfffffff2: 'E_HIA_TYPE: ',
    0xfffffff0: 'E_HIA_OPCODE: ', 0xffffffef: 'E_HIA_RESOURCE: ',
    0xffffffee: 'E_HIA_LOAN: ',
}
FRAGMENTS = {
    1101: ': expected parameter list', 1102: ': expected exactly name, type',
    1103: ': invalid/reserved ASCII identifier', 1104: ': duplicate parameter ',
    1105: ': expected value list', 1106: 'SSA value ', 1107: ' is defined more than once',
    1108: '/', 1109: ': undefined/nonlocal value ', 1110: 'use of consumed resource ',
    1111: ' may not alias one owner', 1112: 'call: output types must be [',
    1113: "'", 1114: ', ', 1115: ']', 1116: 'missing effects [',
    1117: ' requires HIA program v', 1118: 'unsupported opcode ',
    1119: ': expected exactly ', 1120: ' attributes', 1121: ': wrong operand count',
    1122: ': operand types must match ', 1123: ': wrong output count',
    1124: ': output types must match ',
    1125: "'alloc'", 1126: "'read'", 1127: "'trap'", 1128: "'write'",
}

COMMON = r'''
def render_core_diagnostic(s:readbuf, r:readbuf, o:mutbuf) -> u32:
    if length(s) < 64 or length(r) < 512 or length(o) < 64:
        return BAD
    base = length(r) - 512
    if uint(r, base) != CONTEXT_MAGIC or uint(r, base + 8) != 1:
        return BAD
    if uint(s, 0) != 5208772604367785521 or uint(s, 48) != 1 or uint(s, 56) != 0:
        return BAD
    nodes = uint(s, 8)
    if nodes == 0 or nodes > 262144 or uint(s, 16) != 64 + nodes * 56:
        return BAD
    extent = uint(s, 24)
    if extent < uint(s, 16) or extent > length(s) or uint(s, 32) != extent:
        return BAD
    source_bytes = uint(s, 40)
    if source_bytes > 8388608:
        return BAD
    if uint(r, base + 56) != source_bytes or uint(r, base + 64) != nodes or uint(r, base + 72) != extent:
        return BAD
    at = base + 88
    while at < length(r):
        if uint(r, at) != 0:
            return BAD
        at = at + 8
    code = uint(r, base + 16)
    message = uint(r, base + 24)
    accepted = uint(r, base + 80)
    if accepted > 1:
        return BAD
    if accepted != 0:
        if code != 0 or message != 0 or uint(r, base + 32) != 0 or uint(r, base + 40) != 0 or uint(r, base + 48) != 0:
            return BAD
        publish(o, 0, 0, 0, 64, nodes)
        return 64
    if message == 0 or message > MESSAGE_COUNT:
        return BAD
    prefix = code_prefix(code)
    if prefix == 0:
        return BAD
    # This is a derived text-storage bound, not a program rejection limit.
    # The largest varying list is a validated primitive return signature;
    # its quotes/content already occur in source and only spaces are added.
    put(o, 40, 64)
    put(o, 48, source_bytes + nodes + 1024)
    if literal(o, prefix, 1) == 0 or body(s, r, o, message, 1) == 0:
        return BAD
    needed = get(o, 40)
    if length(o) < needed:
        publish(o, code, message, needed - 64, needed, nodes)
        return NEED
    put(o, 40, 64)
    put(o, 48, source_bytes + nodes + 1024)
    if literal(o, prefix, 0) == 0 or body(s, r, o, message, 0) == 0:
        return BAD
    if get(o, 40) != needed:
        return BAD
    publish(o, code, message, needed - 64, needed, nodes)
    return needed

def publish(o:mutbuf, code:u64, message:u64, size:u64, needed:u64, nodes:u64) -> u64:
    put(o, 0, TEXT_MAGIC)
    put(o, 8, 1)
    put(o, 16, code)
    put(o, 24, message)
    put(o, 32, size)
    put(o, 40, needed)
    put(o, 48, nodes)
    put(o, 56, 0)
    return 0

def emit_word(o:mutbuf, word:u64, size:u64, measure:u64) -> u64:
    at = get(o, 40)
    limit = get(o, 48)
    if size > 8 or at > limit or size > limit - at:
        return 0
    if measure == 0:
        if at > length(o) or size > length(o) - at:
            return 0
        i = 0
        while i < size:
            store(o, at + i, word & 255)
            word = word >> 8
            i = i + 1
    put(o, 40, at + size)
    return 1

def reserve_literal(o:mutbuf, size:u64, measure:u64) -> u64:
    at = get(o, 40)
    limit = get(o, 48)
    if at > limit or size > limit - at:
        return NONE
    if measure == 0:
        if at > length(o) or size > length(o) - at:
            return NONE
    put(o, 40, at + size)
    return at

def putn(o:mutbuf, at:u64, word:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, word & 255)
        word = word >> 8
        i = i + 1
    return 0

def span(s:readbuf, o:mutbuf, at:u64, size:u64, measure:u64) -> u64:
    extent = uint(s, 24)
    if at < uint(s, 16) or at > extent or size > extent - at:
        return 0
    cursor = get(o, 40)
    limit = get(o, 48)
    if cursor > limit or size > limit - cursor:
        return 0
    if measure == 0:
        if cursor > length(o) or size > length(o) - cursor:
            return 0
        copy_range(o, s, cursor, at, size)
    put(o, 40, cursor + size)
    return 1

def text(s:readbuf, o:mutbuf, node:u64, measure:u64) -> u64:
    if node >= uint(s, 8):
        return 0
    row = 64 + node * 56
    if uint(s, row) != 4:
        return 0
    return span(s, o, uint(s, row + 24), uint(s, row + 32), measure)

def same(s:readbuf, at:u64, size:u64, expected:u64, a:u64, b:u64, c:u64) -> u64:
    if size != expected or at < uint(s, 16) or at > uint(s, 24) or size > uint(s, 24) - at:
        return 0
    i = 0
    while i < size:
        value = a
        shift = i * 8
        if i >= 8:
            value = b
            shift = (i - 8) * 8
        if i >= 16:
            value = c
            shift = (i - 16) * 8
        if byte(s, at + i) != ((value >> shift) & 255):
            return 0
        i = i + 1
    return 1

def text_is(s:readbuf, node:u64, size:u64, a:u64, b:u64, c:u64) -> u64:
    if node >= uint(s, 8):
        return 0
    at = 64 + node * 56
    if uint(s, at) != 4:
        return 0
    return same(s, uint(s, at + 24), uint(s, at + 32), size, a, b, c)

def named_field(s:readbuf, node:u64, key:u64) -> u64:
    nodes = uint(s, 8)
    if node >= nodes or uint(s, 64 + node * 56) != 6:
        return NONE
    count = uint(s, 64 + node * 56 + 32)
    if count > nodes:
        return NONE
    child = uint(s, 64 + node * 56 + 24)
    i = 0
    while i < count:
        if child >= nodes:
            return NONE
        row = 64 + child * 56
        start = uint(s, row + 40)
        size = uint(s, row + 48)
        if key == 1 and same(s, start, size, 4, 1701667182, 0, 0) != 0:
            return child
        if key == 2 and same(s, start, size, 2, 25705, 0, 0) != 0:
            return child
        child = uint(s, row + 16)
        i = i + 1
    return NONE

def returns_list(s:readbuf, o:mutbuf, node:u64, measure:u64) -> u64:
    nodes = uint(s, 8)
    if node >= nodes or uint(s, 64 + node * 56) != 5:
        return 0
    count = uint(s, 64 + node * 56 + 32)
    if count > nodes or literal(o, 1112, measure) == 0:
        return 0
    item = uint(s, 64 + node * 56 + 24)
    i = 0
    while i < count:
        if item >= nodes:
            return 0
        if i != 0:
            if literal(o, 1114, measure) == 0:
                return 0
        if literal(o, 1113, measure) == 0 or text(s, o, item, measure) == 0 or literal(o, 1113, measure) == 0:
            return 0
        item = uint(s, 64 + item * 56 + 16)
        i = i + 1
    if item != NONE:
        return 0
    return literal(o, 1115, measure)

def effects(o:mutbuf, mask:u64, measure:u64) -> u64:
    if mask == 0 or mask > 15 or literal(o, 1116, measure) == 0:
        return 0
    first = 1
    i = 0
    while i < 4:
        bit = 1 << i
        if i == 2:
            bit = 8
        if i == 3:
            bit = 4
        if (mask & bit) != 0:
            if first == 0:
                if literal(o, 1114, measure) == 0:
                    return 0
            if literal(o, 1125 + i, measure) == 0:
                return 0
            first = 0
        i = i + 1
    return literal(o, 1115, measure)

def uint(s:readbuf, offset:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, offset + i) << (i * 8))
        i = i + 1
    return value

def get(o:mutbuf, offset:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(o, offset + i) << (i * 8))
        i = i + 1
    return value

def put(o:mutbuf, offset:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, offset + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''


def packed(text):
    raw = text.encode()
    assert len(raw) <= 24
    return [len(raw)] + [int.from_bytes(raw[i:i + 8].ljust(8, b'\0'), 'little') for i in (0, 8, 16)]


def source_program():
    frozen = json.loads((ROOT / 'checkpoints/contract-r1/inventory.json').read_bytes())
    p = BASE / 'hepta/hia_opcodes.py'
    assert sha256(p.read_bytes()).hexdigest() == frozen['files'][str(p)]['sha256']
    literals = {IDS[name]: text for name, text in MESSAGES.items()}
    literals.update(FRAGMENTS)
    literals.update({1001 + i: text for i, text in enumerate(WHERE)})
    prefixes = {}
    for i, (code, value) in enumerate(PREFIXES.items()):
        prefixes[code] = 2001 + i
        literals[2001 + i] = value
    catalog = []
    tuples = {}
    attributes = {}
    for item in OPCODES.values():
        def tuple_id(value):
            if value is None:
                return 0
            text = repr(value)
            if text not in tuples:
                tuples[text] = 3001 + len(tuples)
                literals[tuples[text]] = text
            return tuples[text]
        attributes_text = ', '.join(item.attributes)
        if attributes_text not in attributes:
            attributes[attributes_text] = 4001 + len(attributes)
            literals[attributes[attributes_text]] = attributes_text
        policy = attributes[attributes_text] | (tuple_id(item.operands) << 16) | (tuple_id(item.results) << 32)
        catalog.append((item.name, policy))

    body = '''def body(s:readbuf, r:readbuf, o:mutbuf, message:u64, measure:u64) -> u64:
    base = length(r) - 512
    a = uint(r, base + 32)
    b = uint(r, base + 40)
    c = uint(r, base + 48)
'''
    fixed = ' or '.join(f'message == {IDS[name]}' for name in MESSAGES)
    body += f'    if {fixed}:\n        return literal(o, message, measure)\n'
    wheres = {'PARAMETER_LIST': 1101, 'PARAMETER_KEYS': 1102, 'WHERE_IDENT': 1103,
              'DUPLICATE_PARAMETER': 1104, 'VALUE_LIST': 1105}
    for name, suffix in wheres.items():
        body += f'''    if message == {IDS[name]}:
        if a < 1 or a > 7 or literal(o, 1000 + a, measure) == 0 or literal(o, {suffix}, measure) == 0:
            return 0
'''
        body += '        return text(s, o, b, measure)\n' if name == 'DUPLICATE_PARAMETER' else '        return 1\n'
    body += f'''    if message == {IDS['DUPLICATE_SSA']}:
        if literal(o, 1106, measure) == 0 or text(s, o, a, measure) == 0:
            return 0
        return literal(o, 1107, measure)
    if message == {IDS['UNDEFINED_VALUE']}:
        fn = named_field(s, b, 1)
        block = named_field(s, c, 2)
        if text(s, o, fn, measure) == 0 or literal(o, 1108, measure) == 0 or text(s, o, block, measure) == 0:
            return 0
        if literal(o, 1109, measure) == 0:
            return 0
        return text(s, o, a, measure)
    if message == {IDS['CONSUMED_RESOURCE']}:
        if literal(o, 1110, measure) == 0:
            return 0
        return text(s, o, a, measure)
    if message == {IDS['DISTINCT_OWNER']}:
        if text(s, o, a, measure) == 0:
            return 0
        return literal(o, 1111, measure)
    if message == {IDS['CALL_RETURN_TYPES']}:
        return returns_list(s, o, a, measure)
    if message == {IDS['MISSING_EFFECTS']}:
        return effects(o, a, measure)
    if message == {IDS['OPCODE_VERSION']}:
        if b < 1 or b > 8 or text(s, o, a, measure) == 0 or literal(o, 1117, measure) == 0:
            return 0
        return emit_word(o, b + 48, 1, measure)
    if message == {IDS['UNKNOWN_OPCODE']}:
        if literal(o, 1118, measure) == 0:
            return 0
        return text(s, o, a, measure)
'''
    for name, suffix in [('OPCODE_ATTRIBUTES', 1119), ('OPERAND_COUNT', 1121),
                         ('OPERAND_TYPES', 1122), ('OUTPUT_COUNT', 1123), ('OUTPUT_TYPES', 1124)]:
        body += f'''    if message == {IDS[name]}:
        policy = catalog_policy(s, a)
        if policy == 0 or text(s, o, a, measure) == 0 or literal(o, {suffix}, measure) == 0:
            return 0
'''
        if name == 'OPCODE_ATTRIBUTES':
            body += '        if literal(o, policy & 65535, measure) == 0:\n            return 0\n        return literal(o, 1120, measure)\n'
        elif name == 'OPERAND_TYPES':
            body += '        return literal(o, (policy >> 16) & 65535, measure)\n'
        elif name == 'OUTPUT_TYPES':
            body += '        return literal(o, (policy >> 32) & 65535, measure)\n'
        else:
            body += '        return 1\n'
    body += '    return 0\n'
    catalog_text = '\ndef catalog_policy(s:readbuf, node:u64) -> u64:\n'
    for name, policy in catalog:
        catalog_text += '    if text_is(s, node, ' + ', '.join(map(str, packed(name))) + f') != 0:\n        return {policy}\n'
    catalog_text += '    return 0\n'
    prefix_text = '\ndef code_prefix(code:u64) -> u64:\n'
    for code, identifier in prefixes.items():
        prefix_text += f'    if code == {code}:\n        return {identifier}\n'
    prefix_text += '    return 0\n'
    literal_text = '\ndef literal(o:mutbuf, identifier:u64, measure:u64) -> u64:\n'
    pairs = sorted(literals.items())
    groups = [pairs[i:i + 12] for i in range(0, len(pairs), 12)]
    for index, group in enumerate(groups):
        literal_text += f'    if identifier <= {group[-1][0]}:\n        return literals_{index}(o, identifier, measure)\n'
    literal_text += '    return 0\n'
    for index, group in enumerate(groups):
        literal_text += f'\ndef literals_{index}(o:mutbuf, identifier:u64, measure:u64) -> u64:\n'
        for identifier, value in group:
            literal_text += f'    if identifier == {identifier}:\n'
            raw = value.encode()
            literal_text += f'        at = reserve_literal(o, {len(raw)}, measure)\n        if at == 18446744073709551615:\n            return 0\n'
            if raw:
                literal_text += '        if measure == 0:\n'
            for at in range(0, len(raw), 8):
                part = raw[at:at + 8]
                literal_text += f'            putn(o, at + {at}, {int.from_bytes(part, "little")}, {len(part)})\n'
            literal_text += '        return 1\n'
        literal_text += '    return 0\n'
    constants = {'BAD': 0xfffffffd, 'NEED': 0xfffffffe, 'NONE': (1 << 64) - 1,
                 'CONTEXT_MAGIC': MAGIC, 'TEXT_MAGIC': TEXT_MAGIC, 'MESSAGE_COUNT': len(IDS)}
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node
    tree = Expand().visit(ast.parse(COMMON + body + catalog_text + prefix_text + literal_text))
    text = ast.unparse(ast.fix_missing_locations(tree)) + '\n'
    (ROOT / 'development/diagnostic-message-inventory.json').write_text(json.dumps({
        'ids': IDS, 'fixed_messages': MESSAGES, 'where': WHERE, 'literal_table': literals,
        'catalog': catalog, 'source_sha256': sha256(text.encode()).hexdigest(),
        'native_formatting': True, 'host_runtime_formatter': False}, indent=2, sort_keys=True) + '\n')
    return text


if __name__ == '__main__':
    write(source_program(), 'core_diagnostic_text', two_read=True)
