"""Specialize checked-in Agent input schemas into ordinary HIA Core."""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_elf_linker import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_worker_request import data_source, decimal_program

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json'
SOURCE = ROOT / 'examples/hia_bootstrap/agent_schema.hepta'
END = 18446744073709551615
TYPES = {'string': 4, 'array': 5, 'object': 6, 'null': 0}
PATTERNS = {
    '^(0|[1-9][0-9]{0,19})$': 1,
    '^[0-9a-f]{64}$': 2,
    '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$': 3,
    '^hia://artifacts/[A-Za-z0-9][A-Za-z0-9._~-]{0,191}$': 4,
}
KEYWORDS = frozenset(('$schema', 'description', 'title', 'type', 'properties', 'required',
                      'additionalProperties', 'minLength', 'maxLength', 'minimum', 'maximum',
                      'minItems', 'maxItems', 'items', 'contains', 'uniqueItems', 'pattern',
                      'const', 'enum', 'oneOf', 'anyOf', 'allOf', 'if', 'then', 'else'))

ENTRY = r'''
def agent_schema(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(w) < 8320 or length(o) < 128:
        return 4294967293
    role = get(w, 0)
    if pinned_catalog(w, 8, 64) == 0:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    size = widen(decode_json(s, w, o))
    if size >= 4294967292:
        return size
    if size > length(w) - 8192:
        return 4294967293
    return dispatch_schema(s, w, role)
'''

HELPERS = r'''
def ascii_word(w:mutbuf, start:u64, size:u64) -> u64:
    word = 0
    index = 0
    while index < size:
        word = word | (byte(w, start + index) << (index * 8))
        index = index + 1
    return word

def string_length(w:mutbuf, start:u64, size:u64) -> u64:
    count = 0
    index = 0
    while index < size:
        if (byte(w, start + index) & 192) != 128:
            count = count + 1
        index = index + 1
    return count

def digits(w:mutbuf, start:u64, size:u64) -> u64:
    index = 0
    while index < size:
        unit = byte(w, start + index)
        if unit < 48 or unit > 57:
            return 0
        index = index + 1
    return 1

def alnum(unit:u64) -> u64:
    return choose((unit >= 48 and unit <= 57) or (unit >= 65 and unit <= 90)
                  or (unit >= 97 and unit <= 122), 1, 0)

def pattern(w:mutbuf, start:u64, size:u64, role:u64) -> u64:
    # The hosted regex's final dollar sign also matches before a final LF.
    if size > 0 and byte(w, start + size - 1) == 10:
        size = size - 1
    if role == 1:
        if size == 0 or size > 20 or (size > 1 and byte(w, start) == 48):
            return 0
        return digits(w, start, size)
    if role == 2:
        if size != 64:
            return 0
        index = 0
        while index < size:
            unit = byte(w, start + index)
            if (unit < 48 or unit > 57) and (unit < 97 or unit > 102):
                return 0
            index = index + 1
        return 1
    if role == 4:
        if size < 16 or ascii_word(w, start, 8) != URI_HEAD or ascii_word(w, start + 8, 8) != URI_TAIL:
            return 0
        start = start + 16
        size = size - 16
    if size == 0 or size > 192 or alnum(byte(w, start)) == 0:
        return 0
    index = 1
    while index < size:
        unit = byte(w, start + index)
        if alnum(unit) == 0 and unit != 45 and unit != 46 and unit != 95:
            if role == 4 and unit != 126:
                return 0
            if role == 3 and unit != 58 and unit != 47:
                return 0
        index = index + 1
    return 1

def integer_between(s:readbuf, w:mutbuf, node:u64, low:u64, high:u64) -> u64:
    kind = get(w, node)
    start = get(w, node + 24)
    size = get(w, node + 32)
    value = 0
    if kind == 3:
        sign = byte(s, start) == 45
        if sign:
            start = start + 1
            size = size - 1
        index = 0
        while index < size:
            value = value * 10 + byte(s, start + index) - 48
            if value > high:
                return 0
            index = index + 1
        if sign and value != 0:
            return 0
    elif kind == 7:
        if widen(decimal_convert(s, w, start, size)) != 8:
            return 0
        bits = get(w, length(w) - 8192 + 8000)
        exponent = (bits >> 52) & 2047
        fraction = bits & 4503599627370495
        if exponent == 0:
            return choose(fraction == 0 and low == 0, 1, 0)
        if exponent < 1023 or exponent > 1053 or (bits >> 63) != 0:
            return 0
        shift = 1075 - exponent
        significand = 4503599627370496 | fraction
        value = significand >> shift
        if (value << shift) != significand:
            return 0
    else:
        return 0
    return choose(value >= low and value <= high, 1, 0)
'''


def table(name, entries):
    lines = [f'def {name}(w:mutbuf, start:u64, size:u64) -> u64:']
    for offset in range(0, max(len(text) for _, text in entries), 8):
        lines += [f'    word_{offset} = 0', f'    if size > {offset}:',
                  f'        remaining = size - {offset}',
                  f'        word_{offset} = ascii_word(w, start + {offset}, choose(remaining > 8, 8, remaining))']
    lines.append('    selected = 0')
    for value, text in entries:
        raw = text.encode('ascii')
        checks = [f'size == {len(raw)}']
        for offset in range(0, len(raw), 8):
            word = raw[offset:offset + 8]
            checks.append(f'word_{offset} == {int.from_bytes(word, "little")}')
        condition = ' and '.join(checks)
        lines.append(f'    selected = choose({condition}, {value}, selected)')
    lines.append('    return selected')
    return '\n'.join(lines) + '\n'


class Catalog:
    def __init__(self):
        self.rules = {}
        self.keys = {}
        self.symbols = {}

    def add(self, schema):
        if type(schema) is not dict or set(schema) - KEYWORDS:
            raise ValueError(f'unsupported Agent input schema: {schema!r}')
        schema = {name: value for name, value in schema.items()
                  if name not in ('$schema', 'description', 'title')}
        key = json.dumps(schema, sort_keys=True, separators=(',', ':'))
        if key not in self.rules:
            name = f'rule_{len(self.rules)}'
            self.rules[key] = [name, '']
            self.rules[key][1] = self.function(name, schema)
        return self.rules[key][0]

    @staticmethod
    def symbol(table, text):
        if type(text) is not str or not text or not text.isascii():
            raise ValueError(f'unsupported catalog literal: {text!r}')
        return table.setdefault(text, len(table) + 1)

    def function(self, name, schema):
        lines = [f'def {name}(s:readbuf, w:mutbuf, node:u64) -> u64:']

        def add(body, depth=1):
            lines.append('    ' * depth + body)

        def reject(condition, depth=1):
            add(f'if {condition}:', depth)
            add('return 0', depth + 1)

        def call(sub, node='node'):
            return f'{self.add(sub)}(s, w, {node})'

        kind = schema.get('type')
        if kind == 'integer':
            low, high = schema['minimum'], schema['maximum']
            if type(low) is not int or type(high) is not int or not 0 <= low <= high <= 1 << 30:
                raise ValueError('unsupported numeric bounds')
            reject(f'integer_between(s, w, node, {low}, {high}) == 0')
        elif kind is not None:
            reject(f'get(w, node) != {TYPES[kind]}')

        if 'const' in schema or 'enum' in schema:
            if 'const' in schema and 'enum' in schema:
                raise ValueError('overlapping catalog literals')
            values = [schema['const']] if 'const' in schema else schema['enum']
            symbols = [self.symbol(self.symbols, text) for text in values]
            if kind != 'string':
                reject('get(w, node) != 4')
            add('value = value_symbol(w, get(w, node + 24), get(w, node + 32))')
            reject(' and '.join(f'value != {n}' for n in symbols))

        for keyword in ('oneOf', 'anyOf'):
            if keyword in schema:
                add('matches = ' + ' + '.join(call(sub) for sub in schema[keyword]))
                reject('matches != 1' if keyword == 'oneOf' else 'matches == 0')
        for sub in schema.get('allOf', ()):
            reject(f'{call(sub)} == 0')
        if 'if' in schema:
            if 'then' in schema:
                reject(f'{call(schema["if"])} != 0 and {call(schema["then"])} == 0')
            if 'else' in schema:
                reject(f'{call(schema["if"])} == 0 and {call(schema["else"])} == 0')

        properties = schema.get('properties', {})
        req = schema.get('required', [])
        extra = schema.get('additionalProperties', True)
        if properties or req or extra is False:
            if type(extra) is not bool or not set(req) <= properties.keys():
                raise ValueError('unsupported Agent property rules')
            scope = 1
            if kind != 'object':
                add('if get(w, node) == 6:')
                scope = 2
            add('item = get(w, node + 24)', scope)
            add('seen = 0', scope)
            add(f'while item != {END}:', scope)
            add('record = 64 + item * 56', scope + 1)
            add('member = property_key(w, get(w, record + 40), get(w, record + 48))', scope + 1)
            must = 0
            for position, (key, child) in enumerate(properties.items()):
                code = self.symbol(self.keys, key)
                add(('if' if position == 0 else 'elif') + f' member == {code}:', scope + 1)
                reject(call(child, 'record') + ' == 0', scope + 2)
                if key in req:
                    bit = 1 << position
                    add(f'seen = seen | {bit}', scope + 2)
                    must |= bit
            if not properties and extra is False:
                add('return 0', scope + 1)
            elif extra is False:
                add('else:', scope + 1)
                add('return 0', scope + 2)
            add('item = get(w, record + 16)', scope + 1)
            if must:
                reject(f'seen != {must}', scope)

        if set(schema) & {'items', 'contains', 'uniqueItems', 'minItems', 'maxItems'}:
            scope = 1
            if kind != 'array':
                add('if get(w, node) == 5:')
                scope = 2
            if 'minItems' in schema or 'maxItems' in schema:
                add('count = get(w, node + 32)', scope)
                if 'minItems' in schema:
                    reject(f'count < {schema["minItems"]}', scope)
                if 'maxItems' in schema:
                    reject(f'count > {schema["maxItems"]}', scope)
            if 'items' in schema or 'contains' in schema or schema.get('uniqueItems'):
                choice = schema.get('uniqueItems')
                if choice and not (len(self.symbols) < 63 and 'enum' in schema.get('items', {})):
                    raise ValueError('unsupported non-enum uniqueness')
                add('item = get(w, node + 24)', scope)
                if choice:
                    add('seen = 0', scope)
                if 'contains' in schema:
                    add('contains = 0', scope)
                add(f'while item != {END}:', scope)
                add('record = 64 + item * 56', scope + 1)
                if 'items' in schema:
                    reject(call(schema['items'], 'record') + ' == 0', scope + 1)
                if choice:
                    add('bit = 1 << value_symbol(w, get(w, record + 24), get(w, record + 32))', scope + 1)
                    reject('(seen & bit) != 0', scope + 1)
                    add('seen = seen | bit', scope + 1)
                if 'contains' in schema:
                    add(f'contains = contains | {call(schema["contains"], "record")}', scope + 1)
                add('item = get(w, record + 16)', scope + 1)
                if 'contains' in schema:
                    reject('contains == 0', scope)

        if set(schema) & {'pattern', 'minLength', 'maxLength'}:
            scope = 1
            if kind != 'string':
                add('if get(w, node) == 4:')
                scope = 2
            add('start = get(w, node + 24)', scope)
            add('size = get(w, node + 32)', scope)
            if 'minLength' in schema or 'maxLength' in schema:
                add('count = string_length(w, start, size)', scope)
                if 'minLength' in schema:
                    reject(f'count < {schema["minLength"]}', scope)
                if 'maxLength' in schema:
                    reject(f'count > {schema["maxLength"]}', scope)
            if 'pattern' in schema:
                reject(f'pattern(w, start, size, {PATTERNS[schema["pattern"]]}) == 0', scope)
        add('return 1')
        return '\n'.join(lines) + '\n'


def source_program(raw):
    value = json.loads(raw)
    catalog = Catalog()
    roles = [catalog.add(tool['inputSchema']) for tool in value['tools']]
    dispatch = ['def dispatch_schema(s:readbuf, w:mutbuf, role:u64) -> u64:']
    for role, name in enumerate(roles, 1):
        dispatch += [f'    if role == {role}:', f'        return 1 - {name}(s, w, 64)']
    dispatch.append('    return 4294967293')
    uri = b'hia://artifacts/'
    helpers = HELPERS.replace('URI_HEAD', str(int.from_bytes(uri[:8], 'little')))
    helpers = helpers.replace('URI_TAIL', str(int.from_bytes(uri[8:], 'little')))
    if max(catalog.symbols.values()) >= 64:
        raise ValueError('catalog enum exceeds uniqueness bitmap')
    return '\n'.join((ENTRY, '\n'.join(dispatch),
        table('pinned_catalog', [(1, sha256(raw).hexdigest())]),
        table('property_key', [(code, key) for key, code in catalog.keys.items()]),
        table('value_symbol', [(code, value) for value, code in catalog.symbols.items()]),
        helpers, *(rule for _, rule in catalog.rules.values()), data_source(), decimal_program()))


def document(raw=None):
    nodes = ast.parse(source_program(CATALOG.read_bytes() if raw is None else raw)).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_schema',
                                  'functions': functions})


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document()))
