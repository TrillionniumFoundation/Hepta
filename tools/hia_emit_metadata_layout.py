"""Author the common outer layout checked on both sides of native Emit publication."""

EMIT_DOCUMENT_KINDS = (b'build-object', b'native', b'build-receipt')
METADATA_LIMIT = 8 << 20

# These are the field templates of the retained Agent data model. Nested
# schemas and immutable references are authorized by their owning HIA roles.
LAYOUTS = (
    (('core_sha256', 'digest'), ('installation', 'object'),
     ('machine_plan_sha256', 'null_digest'), ('schema', '"hepta.hia.agent.build-object.v1"')),
    (('candidate', 'object'), ('codegen', 'object'), ('context', 'object'),
     ('core_sha256', 'digest'), ('foreign_buffer_exports', 'array'),
     ('installation', 'object'), ('machine_plan', 'null_object'), ('object_artifact', 'object'),
     ('object_sha256', 'digest'), ('output_kind', 'output_kind'), ('signatures', 'object')),
)

SCANNER = r'''
def emit_metadata(s:readbuf, at:u64, size:u64, kind:u64) -> bool:
    if size < 2 or size > LIMIT or at > length(s) or size > length(s) - at:
        return False
    end = at + size
    if byte(s, at) != 123 or byte(s, end - 1) != 125:
        return False
    if kind == 12:
        return build_object_metadata(s, at + 1, end - 1)
    if kind == 13:
        return native_product_metadata(s, at + 1, end - 1)
    return kind == 14 and size == 2

# This walks exact top-level cells, preserving all bytes of nested typed
# fragments for Store hashing and byte equality. It is not a JSON decoder.
def emit_container(s:readbuf, at:u64, end:u64, opener:u64) -> u64:
    if at >= end or byte(s, at) != opener:
        return end + 1
    level = 0
    brackets = 0
    in_string = False
    while at < end:
        unit = byte(s, at)
        at = at + 1
        if in_string:
            if unit == 34:
                in_string = False
            elif unit == 92:
                if at >= end:
                    return end + 1
                at = at + 1
            elif unit < 32:
                return end + 1
        elif unit == 34:
            in_string = True
        elif unit == 123 or unit == 91:
            if level >= 64:
                return end + 1
            if unit == 91:
                brackets = brackets | (1 << level)
            level = level + 1
        elif unit == 125 or unit == 93:
            if level == 0:
                return end + 1
            level = level - 1
            bit = 1 << level
            if ((brackets & bit) != 0) != (unit == 93):
                return end + 1
            if level == 0:
                return at
            brackets = brackets & (18446744073709551615 ^ bit)
    return end + 1

def emit_digest(s:readbuf, at:u64, end:u64) -> u64:
    if at > end or end - at < 66 or byte(s, at) != 34 or byte(s, at + 65) != 34:
        return end + 1
    cursor = at + 1
    while cursor < at + 65:
        digit = byte(s, cursor)
        if (digit < 48 or digit > 57) and (digit < 97 or digit > 102):
            return end + 1
        cursor = cursor + 1
    return at + 66

def emit_word(s:readbuf, at:u64, count:u64) -> u64:
    result = 0
    index = 0
    while index < count:
        result = result | (byte(s, at + index) << (index * 8))
        index = index + 1
    return result

def emit_null(s:readbuf, at:u64, end:u64) -> bool:
    return at <= end and end - at >= 4 and emit_word(s, at, 4) == 1819047278

def emit_kind(s:readbuf, at:u64, end:u64) -> u64:
    if at > end or end - at < 8:
        return end + 1
    token = emit_word(s, at, 8)
    if token != OBJECT and token != SHARED:
        return end + 1
    return at + 8
'''


def literal(name, raw):
    lines = [f'def {name}(s:readbuf, at:u64, end:u64) -> u64:',
             f'    if at > end or end - at < {len(raw)}:',
             '        return end + 1', '    difference = 0']
    for at in range(0, len(raw), 8):
        word = raw[at:at + 8]
        lines.append(
            f'    difference = difference | (emit_word(s, at + {at}, {len(word)}) ^ '
            f'{int.from_bytes(word, "little")})')
    lines.extend(('    if difference != 0:', '        return end + 1', f'    return at + {len(raw)}'))
    return '\n'.join(lines)


def emit_metadata_source():
    words = SCANNER.replace('LIMIT', str(METADATA_LIMIT))
    words = words.replace('OBJECT', str(int.from_bytes(b'"object"', 'little')))
    words = words.replace('SHARED', str(int.from_bytes(b'"shared"', 'little')))
    values = {'digest': 'emit_digest(s, at, end)', 'object': 'emit_container(s, at, end, 123)',
              'array': 'emit_container(s, at, end, 91)', 'output_kind': 'emit_kind(s, at, end)',
              '"hepta.hia.agent.build-object.v1"': 'build_object_schema(s, at, end)'}
    helpers = [literal('build_object_schema', b'"hepta.hia.agent.build-object.v1"')]
    emitted = set()
    routes = []
    for name, fields in zip(('build_object_metadata', 'native_product_metadata'), LAYOUTS):
        code = [f'def {name}(s:readbuf, at:u64, end:u64) -> bool:']
        for index, (key, type_name) in enumerate(fields):
            symbol = ('first_' if index == 0 else 'next_') + key
            if symbol not in emitted:
                prefix = '' if index == 0 else ','
                helpers.append(literal(symbol, f'{prefix}"{key}":'.encode('ascii')))
                emitted.add(symbol)
            code.append(f'    at = {symbol}(s, at, end)')
            if type_name.startswith('null_'):
                code.extend(('    if emit_null(s, at, end):', '        at = at + 4', '    else:',
                             '        at = ' + values[type_name.removeprefix('null_')]))
            else:
                code.append('    at = ' + values[type_name])
        code.append('    return at == end')
        routes.append('\n'.join(code))
    return '\n\n'.join((words, *routes, *helpers))
