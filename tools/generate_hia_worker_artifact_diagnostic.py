"""Render the published artifact schema's first rejection entirely in HIA."""
from pathlib import Path
import ast
import json

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_schema import (
    CATALOG, END, HELPERS, PATTERNS, PAYLOAD_HELPERS, data_source, decimal_program, table,
)
from tools.generate_hia_agent_read_page import SOURCE as PAGE_POLICY
from tools.generate_hia_elf_linker import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

SOURCE = Path('examples/hia_bootstrap/worker_artifact_diagnostic.hepta')
PROLOGUE = r'''
def diagnose(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(o) < 25088 or length(w) < 8320:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    size = widen(decode_json(s, w, o))
    if size >= 4294967292:
        return size
    if size > length(w) - 8192:
        return 4294967293
    return MAIN(s, o, w, 64)

def diagnostic_field(w:mutbuf, record:u64, key:u64) -> u64:
    child = get(w, record + 24)
    while child != TERMINAL:
        at = 64 + child * 56
        if key_kind(w, get(w, at + 40), get(w, at + 48)) == key:
            return at
        child = get(w, at + 16)
    return 0

def unexpected_field(w:mutbuf, o:mutbuf, record:u64, at:u64, count:u64) -> u64:
    start = get(w, record + 40)
    size = get(w, record + 48)
    consumed = 0
    while consumed < size:
        unit = byte(w, start + consumed)
        if (unit & 192) != 128:
            if count == 4096:
                return diagnostic_close(o, emit_escaped(w, o, start, consumed, at))
            count = count + 1
        consumed = consumed + 1
    return diagnostic_close(o, emit_escaped(w, o, start, size, at))
'''


class Author:
    def __init__(self):
        self.rules = []
        self.literals = {}
        self.keys = {}
        self.values = {}

    def keyed(self, text):
        return self.keys.setdefault(text, len(self.keys) + 1)

    def symbol(self, text):
        return self.values.setdefault(text, len(self.values) + 1)

    def literal(self, raw):
        return self.literals.setdefault(raw, 'literal_' + str(len(self.literals)))

    def explain(self, label, message):
        return 'diagnostic_close(o, ' + self.literal(label + ': ' + message) + '(o, diagnostic_open(o, 0)))'

    def add(self, schema, label):
        index = len(self.rules)
        name = 'diagnose_' + str(index)
        self.rules.append('')
        lines = [f'def {name}(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:']

        def fail(test, reason):
            lines.extend((f'    if {test}:', '        return ' + self.explain(label, reason)))

        if 'oneOf' in schema:
            if set(schema) != {'oneOf'}:
                raise ValueError('unexpected artifact union schema')
            lines += ['    if get(w, node) == 6:',
                      f'        member = diagnostic_field(w, node, {self.keyed("kind")})',
                      '        if member != 0 and get(w, member) == 4:',
                      '            selected = symbol_kind(w, get(w, member + 24), get(w, member + 32))']
            for alternative in schema['oneOf']:
                tag = alternative['properties']['kind']['const']
                branch = self.add(alternative, label)
                lines += [f'            if selected == {self.symbol(tag)}:',
                          f'                return {branch}(s, o, w, node)']
            lines.append('    return ' + self.explain(label, 'does not match oneOf'))
        elif 'anyOf' in schema:
            if set(schema) != {'anyOf'} or sorted(x['type'] for x in schema['anyOf']) != ['null', 'string']:
                raise ValueError('unexpected artifact nullable schema')
            for alternative in schema['anyOf']:
                branch = self.add(alternative, label)
                lines += [f'    if {branch}(s, o, w, node) == 0:', '        return 0']
            lines.append('    return ' + self.explain(label, 'does not match anyOf'))
        else:
            typ = schema.get('type')
            fields = {
                'object': {'properties', 'required', 'additionalProperties'},
                'string': {'minLength', 'maxLength', 'pattern'},
                'integer': {'minimum', 'maximum'}, 'null': set(), None: {'const'},
            }
            if typ not in fields or set(schema) - fields[typ] - {'type', 'description', '$schema'}:
                raise ValueError('unrecognized published artifact schema constraint')
            if typ == 'object':
                fail('get(w, node) != 6', 'expected object')
                if schema.get('additionalProperties') is not False:
                    raise ValueError('artifact schema must be a closed object')
                self.object_rules(lines, schema, label)
            elif typ == 'string':
                fail('get(w, node) != 4', 'expected string')
                if 'minLength' in schema or 'maxLength' in schema:
                    lines.append('    size = string_length(w, get(w, node + 24), get(w, node + 32))')
                    low, high = schema.get('minLength', 0), schema.get('maxLength', 1 << 63)
                    fail(f'size < {low} or size > {high}', 'string length is outside limits')
                if 'pattern' in schema:
                    fail('pattern(w, get(w, node + 24), get(w, node + 32), '
                         f'{PATTERNS[schema["pattern"]]}) == 0', 'string does not match the declared pattern')
            elif typ == 'integer':
                fail('unrestricted_integer(s, w, node) == 0', 'expected integer')
                fail(f'integer_between(s, w, node, {schema["minimum"]}, {schema["maximum"]}) == 0',
                     'number is outside limits')
            elif typ == 'null':
                fail('get(w, node) != 0', 'expected null')
            elif typ is not None:
                raise ValueError(f'unrecognized artifact schema type: {typ}')
            if 'const' in schema:
                symbol = self.symbol(schema['const'])
                fail('get(w, node) != 4 or symbol_kind(w, get(w, node + 24), get(w, node + 32)) != '
                     + str(symbol), 'constant differs')
            lines.append('    return 0')
        self.rules[index] = '\n'.join(lines)
        return name

    def object_rules(self, lines, schema, label):
        fields = schema['properties']
        required = sorted(schema['required'])
        lines.append('    missing = 0')
        for index, key in enumerate(required):
            lines += [f'    if diagnostic_field(w, node, {self.keyed(key)}) == 0:',
                      f'        missing = missing | {1 << index}']
        lines += ['    if missing != 0:',
                  f'        return missing_{len(self.rules)}(o, missing)']
        helpers = [f'def missing_{len(self.rules)}(o:mutbuf, missing:u64) -> u64:',
                   '    at = diagnostic_open(o, 0)',
                   f'    at = {self.literal(label + ": missing fields ")}(o, at)',
                   '    count = 0']
        for index, field in enumerate(required):
            separator = self.literal(', ')
            emit = self.literal(field)
            helpers += [f'    if (missing & {1 << index}) != 0:',
                        '        if count != 0:', f'            at = {separator}(o, at)',
                        f'        at = {emit}(o, at)', '        count = count + 1']
        helpers.append('    return diagnostic_close(o, at)')
        self.rules.append('\n'.join(helpers))
        lines += ['    child = get(w, node + 24)', f'    while child != {END}:',
                  '        record = 64 + child * 56',
                  '        key = key_kind(w, get(w, record + 40), get(w, record + 48))',
                  '        problem = 0']
        start = label + ': unknown field '
        for index, (field, rule) in enumerate(fields.items()):
            child = self.add(rule, label + '.' + field)
            branch = 'if' if index == 0 else 'elif'
            lines += [f'        {branch} key == {self.keyed(field)}:',
                      f'            problem = {child}(s, o, w, record)']
        lines += ['        else:', f'            at = {self.literal(start)}(o, diagnostic_open(o, 0))',
                  f'            return unexpected_field(w, o, record, at, {len(start)})',
                  '        if problem != 0:', '            return problem',
                  '        child = get(w, record + 16)']

    def source(self, schema):
        main = self.add(schema, 'arguments')
        writer = {
            'diagnostic_open': '{"code":"E_HIA_SCHEMA","details_artifact":null,"message":"',
            'diagnostic_close': '","phase":"admission","retry_action":"correct_input"}',
        }
        writer.update((name, raw) for raw, name in self.literals.items())
        pieces = []
        for name, text in writer.items():
            raw = text.encode()
            lines = [f'def {name}(o:mutbuf, at:u64) -> u64:']
            whole = len(raw) - len(raw) % 8
            for offset in range(0, whole, 8):
                lines.append(f'    put(o, at + {offset}, {int.from_bytes(raw[offset:offset+8], "little")})')
            for offset in range(whole, len(raw)):
                lines.append(f'    store(o, at + {offset}, {raw[offset]})')
            pieces.append('\n'.join(lines + [f'    return at + {len(raw)}']))
        helpers = HELPERS[:HELPERS.index('\ndef integer_between(')]
        number = HELPERS[HELPERS.index('\ndef integer_between('):]
        numeric_type = PAYLOAD_HELPERS[PAYLOAD_HELPERS.index('\ndef unrestricted_integer('):PAYLOAD_HELPERS.index('\ndef unit_number(')]
        uri = b'hia://artifacts/'
        helpers = helpers.replace('URI_HEAD', str(int.from_bytes(uri[:8], 'little')))
        helpers = helpers.replace('URI_TAIL', str(int.from_bytes(uri[8:], 'little')))
        quoting = PAGE_POLICY[PAGE_POLICY.index('\ndef short_escape('):PAGE_POLICY.index('\ndef escaped_size(')]
        quoting += PAGE_POLICY[PAGE_POLICY.index('\ndef emit_escaped('):PAGE_POLICY.index('\ndef retain_cursor(')].replace('s:readbuf', 's:mutbuf')
        quote_hex = PAGE_POLICY[PAGE_POLICY.index('\ndef hex_digit('):].split('\ndef ', 2)[1]
        quoting += '\ndef ' + quote_hex
        return '\n'.join((PROLOGUE.replace('MAIN', main).replace('TERMINAL', str(END)),
                          *self.rules, *pieces,
                          table('key_kind', [(value, name) for name, value in self.keys.items()]),
                          table('symbol_kind', [(value, name) for name, value in self.values.items()]),
                          helpers, number, numeric_type, quoting, data_source(), decimal_program()))


def document():
    catalog = json.loads(CATALOG.read_bytes())
    schema, = (tool['inputSchema'] for tool in catalog['tools'] if tool['name'] == 'hia_artifact')
    nodes = ast.parse(Author().source(schema)).body
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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': SOURCE.stem,
                                  'functions': functions})


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document()), encoding='utf-8')
