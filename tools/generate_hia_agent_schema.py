"""Specialize checked-in Agent input and response schemas into HIA Core."""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_contract import COST_POLICY_SCHEMA, OBJECTIVE_SCHEMA, PLAN_SCHEMA, WORKLOAD_SCHEMA
from hepta.hia_agent_payload_schema_native import COST_POLICY_ROLE, OBJECTIVE_ROLE, WORKLOAD_ROLE
from hepta.hia_agent_plan_schema_native import PLAN_ROLE, NativeAgentPlanSchema
from hepta.hia_agent_verify_response_schema_native import RETAINED_RECEIPT_ROLE
from tools.generate_hia_elf_linker import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_worker_request import data_source, decimal_program

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json'
SOURCE = ROOT / 'examples/hia_bootstrap/agent_schema.hepta'
RESPONSE_SOURCE = SOURCE.with_name('agent_response_schema.hepta')
VERIFY_RESPONSE_SOURCE = SOURCE.with_name('agent_verify_response_schema.hepta')
PAYLOAD_SOURCE = SOURCE.with_name('agent_payload_schema.hepta')
PLAN_SOURCE = SOURCE.with_name('agent_plan_schema.hepta')
END = 18446744073709551615
TYPES = {'string': 4, 'array': 5, 'object': 6, 'null': 0}
PATTERNS = {
    '^(0|[1-9][0-9]{0,19})$': 1,
    '^[0-9a-f]{64}$': 2,
    '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$': 3,
    '^hia://artifacts/[A-Za-z0-9][A-Za-z0-9._~-]{0,191}$': 4,
}
KEYWORDS = frozenset(('$schema', 'description', 'title', 'type', 'properties', 'required',
                      'additionalProperties', 'minProperties', 'maxProperties', 'minLength', 'maxLength', 'minimum', 'maximum',
                      'minItems', 'maxItems', 'items', 'contains', 'uniqueItems', 'pattern',
                      'const', 'enum', 'oneOf', 'anyOf', 'allOf', 'if', 'then', 'else', 'not'))

PROOF_RECEIPT = r'''
def proof_member(w:mutbuf, record:u64, key:u64) -> u64:
    if get(w, record) != 6:
        return 0
    item = get(w, record + 24)
    while item != ARENA_END:
        node = 64 + item * 56
        if property_key(w, get(w, node + 40), get(w, node + 48)) == key:
            return node
        item = get(w, node + 16)
    return 0

def retained_proof(s:readbuf, w:mutbuf) -> u64:
    checks = proof_member(w, 64, CHECKS_KEY)
    if checks == 0:
        return 1
    if CHECKS_RULE(s, w, checks) == 0:
        return 1
    seen = 0
    item = get(w, checks + 24)
    while item != ARENA_END:
        record = 64 + item * 56
        claim = proof_member(w, record, CLAIM_KEY)
        if claim == 0:
            return 1
        symbol = value_symbol(w, get(w, claim + 24), get(w, claim + 32))
        bit = 1 << symbol
        if symbol == 0 or (seen & bit) != 0:
            return 1
        seen = seen | bit
        item = get(w, record + 16)
    return 0
'''


ENTRY = r'''
def agent_schema(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(w) < SCHEMA_MINIMUM_WORKSPACE or length(o) < 128:
        return 4294967293
    role = get(w, 0)
    if pinned_catalog(w, 8, 64) == 0:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    size = widen(decode_json(s, w, o))
    if size >= 4294967292:
        return size
    if size > length(w) - SCHEMA_AUXILIARY_BYTES:
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

PAYLOAD_HELPERS = r'''
def hex_byte_pairs(w:mutbuf, start:u64, size:u64) -> u64:
    if size > 0 and byte(w, start + size - 1) == 10:
        size = size - 1
    if (size & 1) != 0:
        return 0
    index = 0
    while index < size:
        unit = byte(w, start + index)
        if (unit < 48 or unit > 57) and (unit < 97 or unit > 102):
            return 0
        index = index + 1
    return 1


def unrestricted_integer(s:readbuf, w:mutbuf, node:u64) -> u64:
    kind = get(w, node)
    if kind == 3:
        return 1
    if kind != 7 or widen(decimal_convert(s, w, get(w, node + 24), get(w, node + 32))) != 8:
        return 0
    bits = get(w, length(w) - 8192 + 8000)
    exponent = (bits >> 52) & 2047
    fraction = bits & 4503599627370495
    if exponent == 0:
        return choose(fraction == 0, 1, 0)
    if exponent < 1023 or exponent == 2047:
        return 0
    if exponent >= 1075:
        return 1
    mask = (1 << (1075 - exponent)) - 1
    return choose((fraction & mask) == 0, 1, 0)


def unit_number(s:readbuf, w:mutbuf, node:u64) -> u64:
    if get(w, node) != 7:
        return integer_between(s, w, node, 0, 1)
    if widen(decimal_convert(s, w, get(w, node + 24), get(w, node + 32))) != 8:
        return 0
    bits = get(w, length(w) - 8192 + 8000)
    magnitude = bits & 9223372036854775807
    return choose(magnitude == 0 or bits <= 4607182418800017408, 1, 0)
'''

PLAN_HELPERS = r'''
def integer_literal(s:readbuf, w:mutbuf, node:u64) -> u64:
    if get(w, node) != 3:
        return 0
    size = get(w, node + 32)
    if size == 0 or size > 2:
        return 0
    start = get(w, node + 24)
    first = byte(s, start)
    if first < 48 or first > 57:
        return 0
    if size == 1:
        return first - 48
    return (first - 48) * 10 + byte(s, start + 1) - 48

def compare_strings(w:mutbuf, left:u64, right:u64) -> u64:
    left_node = 64 + left * 56
    right_node = 64 + right * 56
    left_at = get(w, left_node + 24)
    right_at = get(w, right_node + 24)
    left_size = get(w, left_node + 32)
    right_size = get(w, right_node + 32)
    limit = choose(left_size < right_size, left_size, right_size)
    index = 0
    while index < limit:
        a = byte(w, left_at + index)
        b = byte(w, right_at + index)
        if a != b:
            return choose(a < b, 1, 2)
        index = index + 1
    if left_size == right_size:
        return 0
    return choose(left_size < right_size, 1, 2)

def merge_unique(w:mutbuf, source:u64, destination:u64, length_words:u64, run:u64) -> u64:
    start = 0
    while start < length_words:
        middle = choose(start + run < length_words, start + run, length_words)
        end = choose(middle + run < length_words, middle + run, length_words)
        left = start
        right = middle
        out = start
        while out < end:
            take_left = 0
            if right == end:
                take_left = 1
            elif left < middle:
                order = compare_strings(w, get(w, source + left * 8), get(w, source + right * 8))
                if order == 0:
                    return 0
                take_left = choose(order == 1, 1, 0)
            if take_left == 1:
                put(w, destination + out * 8, get(w, source + left * 8))
                left = left + 1
            else:
                put(w, destination + out * 8, get(w, source + right * 8))
                right = right + 1
            out = out + 1
        start = end
    return 1

def unique_strings(w:mutbuf, node:u64) -> u64:
    count = get(w, node + 32)
    if count <= 1:
        return 1
    if count > 4096:
        return 0
    source = length(w) - SCHEMA_AUXILIARY_BYTES
    destination = source + count * 8
    item = get(w, node + 24)
    index = 0
    while index < count:
        put(w, source + index * 8, item)
        item = get(w, 64 + item * 56 + 16)
        index = index + 1
    run = 1
    while run < count:
        if merge_unique(w, source, destination, count, run) == 0:
            return 0
        old_source = source
        source = destination
        destination = old_source
        run = run * 2
    return 1
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
        enum = schema.get('enum')
        numeric_enum = (kind == 'integer' and enum
                        and all(type(value) is int and 1 <= value <= 99 for value in enum))
        if numeric_enum:
            add('value = integer_literal(s, w, node)')
            reject(' and '.join(f'value != {value}' for value in enum))
        elif kind == 'integer':
            low, high = schema.get('minimum'), schema.get('maximum')
            if low is None and high is None:
                reject('unrestricted_integer(s, w, node) == 0')
            elif type(low) is int and type(high) is int and 0 <= low <= high <= 1 << 30:
                reject(f'integer_between(s, w, node, {low}, {high}) == 0')
            else:
                raise ValueError('unsupported numeric bounds')
        elif kind == 'number':
            if (schema.get('minimum'), schema.get('maximum')) != (0, 1):
                raise ValueError('unsupported Agent numeric interval')
            reject('unit_number(s, w, node) == 0')
        elif kind == 'boolean':
            add('kind = get(w, node)')
            reject('kind != 1 and kind != 2')
        elif kind is not None:
            reject(f'get(w, node) != {TYPES[kind]}')

        if type(schema.get('const')) is bool:
            reject(f'get(w, node) != {2 if schema["const"] else 1}')
        elif not numeric_enum and ('const' in schema or 'enum' in schema):
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
        if 'not' in schema:
            reject(f'{call(schema["not"])} != 0')
        if 'if' in schema:
            if 'then' in schema:
                reject(f'{call(schema["if"])} != 0 and {call(schema["then"])} == 0')
            if 'else' in schema:
                reject(f'{call(schema["if"])} == 0 and {call(schema["else"])} == 0')

        properties = schema.get('properties', {})
        req = schema.get('required', [])
        extra = schema.get('additionalProperties', True)
        if 'minProperties' in schema or 'maxProperties' in schema:
            if kind != 'object':
                raise ValueError('untagged object field count')
            add('property_count = get(w, node + 32)')
            if 'minProperties' in schema:
                reject(f'property_count < {schema["minProperties"]}')
            if 'maxProperties' in schema:
                reject(f'property_count > {schema["maxProperties"]}')
        if properties or req or type(extra) is dict or extra is False:
            if type(extra) not in (bool, dict):
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
            members = tuple(dict.fromkeys((*properties, *req)))
            for position, key in enumerate(members):
                code = self.symbol(self.keys, key)
                add(('if' if position == 0 else 'elif') + f' member == {code}:', scope + 1)
                if key in properties:
                    reject(call(properties[key], 'record') + ' == 0', scope + 2)
                elif extra is False:
                    add('return 0', scope + 2)
                if key in req:
                    bit = 1 << position
                    add(f'seen = seen | {bit}', scope + 2)
                    must |= bit
            if extra is False:
                if members:
                    add('else:', scope + 1)
                add('return 0', scope + (2 if members else 1))
            elif type(extra) is dict:
                if members:
                    add('else:', scope + 1)
                reject(call(extra, 'record') + ' == 0', scope + (2 if members else 1))
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
                unique = schema.get('uniqueItems')
                items = schema.get('items', {})
                choice = unique and 'enum' in items
                if choice and len(self.symbols) >= 63:
                    raise ValueError('catalog enum exceeds uniqueness bitmap')
                if unique and not choice and not (items.get('type') == 'string'
                                                  and schema.get('maxItems', 4097) <= 4096):
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
                if unique and not choice:
                    reject('unique_strings(w, node) == 0', scope)
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
            if schema.get('pattern') == '^(?:[0-9a-f]{2})*$':
                reject('hex_byte_pairs(w, start, size) == 0', scope)
            elif 'pattern' in schema:
                reject(f'pattern(w, start, size, {PATTERNS[schema["pattern"]]}) == 0', scope)
        add('return 1')
        return '\n'.join(lines) + '\n'


def plan_dispatch(catalog):
    # All four top-level variants have a different exact schema tag. Select it
    # first so large function/block permutations never execute unrelated rules.
    plans = []
    for schema in PLAN_SCHEMA['oneOf']:
        rule = catalog.add(schema)
        tag = catalog.symbols[schema['properties']['schema']['const']]
        plans.append((tag, rule))
    key = catalog.keys['schema']
    lines = ['def dispatch_schema(s:readbuf, w:mutbuf, role:u64) -> u64:',
              f'    if role != {PLAN_ROLE}:', '        return 4294967293',
              '    if get(w, 64) != 6:', '        return 1',
              '    item = get(w, 88)', f'    while item != {END}:',
              '        node = 64 + item * 56',
              f'        if property_key(w, get(w, node + 40), get(w, node + 48)) == {key}:',
              '            if get(w, node) != 4:', '                return 1',
              '            tag = value_symbol(w, get(w, node + 24), get(w, node + 32))']
    for tag, rule in plans:
        lines += [f'            if tag == {tag}:', f'                return 1 - {rule}(s, w, 64)']
    lines += ['            return 1', '        item = get(w, node + 16)', '    return 1']
    return '\n'.join(lines)


def source_program(raw, *, profile='input'):
    catalog = Catalog()
    receipt = ''
    if profile == 'plan':
        dispatch = plan_dispatch(catalog)
    else:
        if profile == 'payload':
            roles = [(role, catalog.add(schema)) for role, schema in (
                (WORKLOAD_ROLE, WORKLOAD_SCHEMA), (OBJECTIVE_ROLE, OBJECTIVE_SCHEMA),
                (COST_POLICY_ROLE, COST_POLICY_SCHEMA),
            )]
        else:
            field = 'inputSchema' if profile == 'input' else 'outputSchema'
            roles = []
            for role, tool in enumerate(json.loads(raw)['tools'], 1):
                if profile != 'input' and (tool['name'] == 'hia_verify') != (profile == 'verify'):
                    continue
                output = tool[field]
                roles.append((role, catalog.add(output)))
        lines = ['def dispatch_schema(s:readbuf, w:mutbuf, role:u64) -> u64:']
        for role, name in roles:
            lines += [f'    if role == {role}:', f'        return 1 - {name}(s, w, 64)']
        if profile == 'verify':
            checks = output['properties']['result']['properties']['checks']
            rule = catalog.add(checks)
            lines += [f'    if role == {RETAINED_RECEIPT_ROLE}:', '        return retained_proof(s, w)']
            receipt = (PROOF_RECEIPT.replace('ARENA_END', str(END)).replace('CHECKS_RULE', rule)
                       .replace('CHECKS_KEY', str(catalog.keys['checks']))
                       .replace('CLAIM_KEY', str(catalog.keys['claim'])))
        dispatch = '\n'.join(lines + ['    return 4294967293'])
    uri = b'hia://artifacts/'
    helpers = HELPERS.replace('URI_HEAD', str(int.from_bytes(uri[:8], 'little')))
    helpers = helpers.replace('URI_TAIL', str(int.from_bytes(uri[8:], 'little')))
    if max(catalog.symbols.values()) >= 64:
        raise ValueError('catalog enum exceeds uniqueness bitmap')
    rules = [rule for _, rule in catalog.rules.values()]
    numeric = any('integer_between(' in rule for rule in rules)
    if not numeric:
        helpers = helpers[:helpers.index('\ndef integer_between(')]
    extra = {'payload': PAYLOAD_HELPERS, 'plan': PLAN_HELPERS}.get(profile, '')
    scratch = NativeAgentPlanSchema.AUXILIARY_BYTES if profile == 'plan' else 8192
    source = '\n'.join((ENTRY, dispatch,
        table('pinned_catalog', [(1, sha256(raw).hexdigest())]),
        table('property_key', [(code, key) for key, code in catalog.keys.items()]),
        table('value_symbol', [(code, value) for value, code in catalog.symbols.items()]),
        helpers, extra, receipt, *rules, data_source(), decimal_program() if numeric else ''))
    return (source.replace('SCHEMA_AUXILIARY_BYTES', str(scratch))
            .replace('SCHEMA_MINIMUM_WORKSPACE', str(scratch + 128)))


def document(raw=None, *, profile='input'):
    nodes = ast.parse(source_program(CATALOG.read_bytes() if raw is None else raw,
                                     profile=profile)).body
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
    module = {'input': SOURCE.stem, 'response': RESPONSE_SOURCE.stem,
              'verify': VERIFY_RESPONSE_SOURCE.stem, 'payload': PAYLOAD_SOURCE.stem,
              'plan': PLAN_SOURCE.stem}[profile]
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': module,
                                  'functions': functions})


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document()))
    RESPONSE_SOURCE.write_text(render_assembly(document(profile='response')))
    VERIFY_RESPONSE_SOURCE.write_text(render_assembly(document(profile='verify')))
    PAYLOAD_SOURCE.write_text(render_assembly(document(profile='payload')))
    PLAN_SOURCE.write_text(render_assembly(document(profile='plan')))
